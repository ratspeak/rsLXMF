//! Restricted app-container migration authority. This is not an arbitrary-path
//! alternative to the desktop process probe. All current host workers must be
//! joined by the application before acquisition; the same v2 OS lock additionally
//! rejects live current hosts. iOS's main-app/container lifecycle excludes an
//! older installed bundle from concurrently owning this private data container.
use super::*;

fn contained_store(legacy: &Path, root: &Path) -> io::Result<PathBuf> {
    let root = fs::canonicalize(root)?;
    let legacy = canonical_legacy(legacy)?;
    let parent = legacy
        .parent()
        .ok_or_else(|| invalid("store has no parent"))?;
    if parent == root || !parent.starts_with(&root) {
        return Err(invalid(
            "relay migration requires a nested private app-container path",
        ));
    }
    Ok(legacy)
}

/// Acquire migration authority only inside the current native iOS main app's
/// private data container. App groups, extensions, external directories, and
/// command-line processes are refused. No caller-supplied root or skip flag is
/// accepted. Hold the application's identity/session lifecycle guard, stop all
/// hosted and sync writers, and join their actual workers before calling this.
#[cfg(target_os = "ios")]
pub fn begin_ios_container_migration(legacy: &Path) -> io::Result<offline::OfflineMigrationGuard> {
    let root = native_ios_container()?;
    let legacy = contained_store(legacy, &root)?;
    let lock = offline::lock_store(&legacy)?;
    Ok(offline::OfflineMigrationGuard {
        legacy,
        _lock: lock,
    })
}

/// Acquire migration authority for the platform Context's single-package,
/// single-process private Android data directory. Shared UIDs, declared remote
/// processes, mismatched contexts and external/group-writable roots are refused.
/// The caller must hold its lifecycle guard and join all hosted/sync writers;
/// the returned guard also retains the same OS lock used by current v2 hosts.
#[cfg(target_os = "android")]
pub fn begin_android_container_migration<'a>(
    legacy: &Path,
    env: &jni::JNIEnv<'a>,
    context: jni::objects::JObject<'a>,
) -> io::Result<offline::OfflineMigrationGuard> {
    let root = android_container::private_root(env, context)?;
    let legacy = contained_store(legacy, &root)?;
    let lock = offline::lock_store(&legacy)?;
    Ok(offline::OfflineMigrationGuard {
        legacy,
        _lock: lock,
    })
}

#[cfg(target_os = "ios")]
fn native_ios_container() -> io::Result<PathBuf> {
    use objc2::{
        msg_send,
        rc::autoreleasepool,
        runtime::{AnyClass, AnyObject},
    };
    use std::ffi::CStr;
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {
        fn NSHomeDirectory() -> *mut AnyObject;
    }
    // SAFETY: both values are Foundation NSStrings, alive for the surrounding
    // autorelease pool; UTF8String is copied before leaving that pool.
    unsafe fn string(value: *mut AnyObject) -> io::Result<String> {
        if value.is_null() {
            return Err(invalid("native app-container metadata unavailable"));
        }
        let bytes: *const std::ffi::c_char = unsafe { msg_send![value, UTF8String] };
        if bytes.is_null() {
            return Err(invalid("native app-container path unavailable"));
        }
        unsafe { CStr::from_ptr(bytes) }
            .to_str()
            .map(str::to_owned)
            .map_err(err)
    }
    autoreleasepool(|_| {
        let class = AnyClass::get(c"NSBundle").ok_or_else(|| invalid("NSBundle unavailable"))?;
        // SAFETY: documented synchronous Foundation getters, no ownership transfer.
        let bundle: *mut AnyObject = unsafe { msg_send![class, mainBundle] };
        if bundle.is_null() {
            return Err(invalid("native main app bundle unavailable"));
        }
        let path: *mut AnyObject = unsafe { msg_send![bundle, bundlePath] };
        let identifier: *mut AnyObject = unsafe { msg_send![bundle, bundleIdentifier] };
        let bundle_path = PathBuf::from(unsafe { string(path)? });
        if bundle_path.extension().and_then(|s| s.to_str()) != Some("app")
            || unsafe { string(identifier)? }.is_empty()
        {
            return Err(invalid("relay migration requires an iOS main application"));
        }
        let root = fs::canonicalize(unsafe { string(NSHomeDirectory())? })?;
        if !ios_data_container_path(&root) {
            return Err(invalid(
                "native home is not a private iOS app data container",
            ));
        }
        Ok(root)
    })
}

// The native home API, not this shape alone, supplies authority. Reject future
// unknown layouts instead of silently certifying a shared or group container.
#[cfg(any(target_os = "ios", test))]
fn ios_data_container_path(root: &Path) -> bool {
    let Some(id) = root.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let valid_id = id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    valid_id
        && root
            .parent()
            .is_some_and(|p| p.ends_with("Containers/Data/Application"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_container_policy_rejects_groups_siblings_and_root_store() {
        assert!(ios_data_container_path(Path::new(
            "/private/var/mobile/Containers/Data/Application/01234567-89AB-CDEF-0123-456789abcdef"
        )));
        assert!(ios_data_container_path(Path::new(
            "/sim/device/data/Containers/Data/Application/01234567-89AB-CDEF-0123-456789abcdef"
        )));
        assert!(!ios_data_container_path(Path::new(
            "/private/var/mobile/Containers/Shared/AppGroup/01234567-89AB-CDEF-0123-456789abcdef"
        )));
        assert!(!ios_data_container_path(Path::new(
            "/private/var/mobile/Containers/Bundle/Application/01234567-89AB-CDEF-0123-456789abcdef"
        )));
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        let nested = root.join("Library/state");
        fs::create_dir_all(&nested).unwrap();
        assert!(contained_store(&nested.join("relay"), &root).is_ok());
        assert!(contained_store(&root.join("relay"), &root).is_err());
        assert!(contained_store(&temp.path().join("relay"), &root).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn private_container_policy_rejects_symlink_escape() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        let outside = temp.path().join("external");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        assert!(contained_store(&root.join("escape/relay"), &root).is_err());
    }
}
