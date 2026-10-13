//! Android framework metadata, rather than process-list visibility or guessed
//! /data prefixes, establishes a single-package private-container boundary.
use super::*;
use jni::{
    JNIEnv,
    objects::{JObject, JString, JValue},
};
use std::os::unix::fs::MetadataExt;

fn take_string(env: &JNIEnv<'_>, value: JObject<'_>) -> io::Result<String> {
    if value.is_null() {
        return Err(invalid("Android application metadata is missing"));
    }
    let result: String = env.get_string(JString::from(value)).map_err(err)?.into();
    env.delete_local_ref(value).map_err(err)?;
    Ok(result)
}

pub(super) fn private_root<'a>(env: &JNIEnv<'a>, context: JObject<'a>) -> io::Result<PathBuf> {
    let result = private_root_inner(env, context);
    // Return a Rust failure without leaving an unrelated pending Java exception
    // on the embedding application's worker thread.
    if result.is_err() && env.exception_check().unwrap_or(true) {
        let _ = env.exception_clear();
    }
    result
}

fn private_root_inner<'a>(env: &JNIEnv<'a>, context: JObject<'a>) -> io::Result<PathBuf> {
    if context.is_null()
        || !env
            .is_instance_of(context, "android/content/Context")
            .map_err(err)?
    {
        return Err(invalid(
            "an initialized Android application context is required",
        ));
    }
    let uid = env
        .call_static_method("android/os/Process", "myUid", "()I", &[])
        .map_err(err)?
        .i()
        .map_err(err)?;
    if uid < 0 || uid % 100_000 < 10_000 {
        return Err(invalid(
            "relay recovery requires a private Android application UID",
        ));
    }
    let manager = env
        .call_method(
            context,
            "getPackageManager",
            "()Landroid/content/pm/PackageManager;",
            &[],
        )
        .map_err(err)?
        .l()
        .map_err(err)?;
    let packages = env
        .call_method(
            manager,
            "getPackagesForUid",
            "(I)[Ljava/lang/String;",
            &[JValue::Int(uid)],
        )
        .map_err(err)?
        .l()
        .map_err(err)?;
    if packages.is_null() || env.get_array_length(packages.into_inner()).map_err(err)? != 1 {
        return Err(invalid(
            "shared or unknown Android UID cannot authorize relay migration",
        ));
    }
    let package = take_string(
        env,
        env.get_object_array_element(packages.into_inner(), 0)
            .map_err(err)?,
    )?;
    let context_package = take_string(
        env,
        env.call_method(context, "getPackageName", "()Ljava/lang/String;", &[])
            .map_err(err)?
            .l()
            .map_err(err)?,
    )?;
    if package != context_package {
        return Err(invalid("Android context does not own this application UID"));
    }
    let mut cmdline = Vec::new();
    File::open("/proc/self/cmdline")?
        .take(4097)
        .read_to_end(&mut cmdline)?;
    if cmdline.len() > 4096 || cmdline.split(|b| *b == 0).next() != Some(package.as_bytes()) {
        return Err(invalid(
            "relay migration is restricted to the default Android app process",
        ));
    }
    let package_string = env.new_string(&package).map_err(err)?;
    // Resolve all four component classes, including disabled declarations. A
    // secondary process can own the same private UID even if it is not running.
    const FLAGS: i32 = 1 | 2 | 4 | 8 | 512;
    let info = env
        .call_method(
            manager,
            "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
            &[JValue::Object(package_string.into()), JValue::Int(FLAGS)],
        )
        .map_err(err)?
        .l()
        .map_err(err)?;
    if !env
        .get_field(info, "sharedUserId", "Ljava/lang/String;")
        .map_err(err)?
        .l()
        .map_err(err)?
        .is_null()
    {
        return Err(invalid(
            "sharedUserId applications cannot authorize relay migration",
        ));
    }
    let application = env
        .get_field(
            info,
            "applicationInfo",
            "Landroid/content/pm/ApplicationInfo;",
        )
        .map_err(err)?
        .l()
        .map_err(err)?;
    if env
        .get_field(application, "uid", "I")
        .map_err(err)?
        .i()
        .map_err(err)?
        != uid
    {
        return Err(invalid("Android application UID changed"));
    }
    let process = take_string(
        env,
        env.get_field(application, "processName", "Ljava/lang/String;")
            .map_err(err)?
            .l()
            .map_err(err)?,
    )?;
    if process != package {
        return Err(invalid(
            "custom Android application process is not qualified",
        ));
    }
    for (field, signature) in [
        ("activities", "[Landroid/content/pm/ActivityInfo;"),
        ("receivers", "[Landroid/content/pm/ActivityInfo;"),
        ("services", "[Landroid/content/pm/ServiceInfo;"),
        ("providers", "[Landroid/content/pm/ProviderInfo;"),
    ] {
        let components = env
            .get_field(info, field, signature)
            .map_err(err)?
            .l()
            .map_err(err)?;
        if components.is_null() {
            continue;
        }
        let count = env.get_array_length(components.into_inner()).map_err(err)?;
        if !(0..=4096).contains(&count) {
            return Err(invalid(
                "Android component inventory exceeds migration bound",
            ));
        }
        for index in 0..count {
            let component = env
                .get_object_array_element(components.into_inner(), index)
                .map_err(err)?;
            let process = take_string(
                env,
                env.get_field(component, "processName", "Ljava/lang/String;")
                    .map_err(err)?
                    .l()
                    .map_err(err)?,
            )?;
            env.delete_local_ref(component).map_err(err)?;
            if process != package {
                return Err(invalid(
                    "multi-process Android apps cannot authorize relay migration",
                ));
            }
        }
        env.delete_local_ref(components).map_err(err)?;
    }
    let root = fs::canonicalize(take_string(
        env,
        env.get_field(application, "dataDir", "Ljava/lang/String;")
            .map_err(err)?
            .l()
            .map_err(err)?,
    )?)?;
    let metadata = fs::metadata(&root)?;
    if !metadata.is_dir() || metadata.uid() != uid as u32 || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "Android data directory lacks exclusive application ownership",
        ));
    }
    Ok(root)
}
