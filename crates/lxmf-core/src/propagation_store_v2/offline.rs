use super::*;
use std::process::{Command, Stdio};

/// Holds the same OS lock as every v2 host. Legacy binaries ignore this lock;
/// the mandatory supervisor assertion and known-process probe address that gap.
pub struct OfflineMigrationGuard {
    pub(super) legacy: PathBuf,
    pub(super) _lock: File,
}

pub(super) fn lock_store(legacy: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let path = sibling(legacy, ".store-lock")?;
    if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
        return Err(invalid("invalid relay store lock"));
    }
    let lock = options.open(path)?;
    rns_identity::persistence::try_lock_exclusive(&lock)?;
    Ok(lock)
}

/// The adapter must first stop its own hosting workers and service auto-restart.
/// This probes known app/daemon names and refuses if process enumeration fails.
/// Manually launching an old binary during migration remains unsupported.
pub fn begin_offline_migration(
    legacy: &Path,
    supervisor_writers_stopped: bool,
) -> io::Result<OfflineMigrationGuard> {
    if !supervisor_writers_stopped {
        return Err(invalid(
            "stop relay writers and their service supervisors before migration",
        ));
    }
    let legacy = canonical_legacy(legacy)?;
    let lock = lock_store(&legacy)?;
    refuse_known_relay_processes()?;
    Ok(OfflineMigrationGuard {
        legacy,
        _lock: lock,
    })
}
fn known_name(value: &str) -> bool {
    let value = value
        .trim_matches('"')
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase();
    matches!(
        value.as_str(),
        "ratspeak" | "ratspeak.exe" | "lxmd" | "lxmd.py" | "lxmd-rs" | "lxmd-rs.exe"
    )
}
fn refuse_known_relay_processes() -> io::Result<()> {
    #[cfg(unix)]
    let mut command = {
        let mut c = Command::new("ps");
        c.args(["-axo", "pid=,comm=,args="]);
        c
    };
    #[cfg(windows)]
    let mut command = {
        let mut c = Command::new("tasklist");
        c.args(["/FO", "CSV", "/NH"]);
        c
    };
    #[cfg(not(any(unix, windows)))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process exclusion cannot be verified on this platform",
    ));
    #[cfg(any(unix, windows))]
    {
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = command.spawn()?;
        let mut output = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or_else(|| invalid("process probe has no output"))?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut output);
        if read.is_err() || output.len() > 4 * 1024 * 1024 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid("process inventory exceeds safe bound"));
        }
        if !child.wait()?.success() {
            return Err(invalid(
                "process enumeration unavailable; relay writer exclusion unverified",
            ));
        }
        let listing = std::str::from_utf8(&output).map_err(err)?;
        check_listing(listing, std::process::id(), cfg!(windows))
    }
}
fn check_listing(listing: &str, own_pid: u32, windows: bool) -> io::Result<()> {
    for line in listing.lines().filter(|l| !l.trim().is_empty()) {
        if windows {
            let fields: Vec<_> = line.trim_matches('"').split("\",\"").collect();
            if fields.len() < 2 {
                return Err(invalid("unrecognized process inventory"));
            }
            let pid: u32 = fields[1].parse().map_err(err)?;
            if pid != own_pid && known_name(fields[0]) {
                return Err(invalid("a known relay app/daemon is still running"));
            }
        } else {
            let mut fields = line.split_whitespace();
            let pid: u32 = fields
                .next()
                .ok_or_else(|| invalid("missing process ID"))?
                .parse()
                .map_err(err)?;
            let Some(comm) = fields.next() else {
                return Err(invalid("missing process name"));
            };
            if pid == own_pid {
                continue;
            }
            // For interpreted daemons, inspect only the executable/script prefix,
            // not arbitrary argument text belonging to shells or other programs.
            let python = comm
                .rsplit('/')
                .next()
                .is_some_and(|c| c.starts_with("python"));
            if known_name(comm) || (python && fields.take(3).any(known_name)) {
                return Err(invalid("a known relay app/daemon is still running"));
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_process_probe_is_fail_closed_and_excludes_only_own_pid() {
        assert!(
            check_listing(
                "7 /Applications/Ratspeak /Applications/Ratspeak\n",
                8,
                false
            )
            .is_err()
        );
        assert!(
            check_listing(
                "7 /Applications/Ratspeak /Applications/Ratspeak\n",
                7,
                false
            )
            .is_ok()
        );
        assert!(check_listing("9 python3 python3 /usr/bin/lxmd --service\n", 7, false).is_err());
        assert!(check_listing("oops", 7, false).is_err());
        assert!(check_listing("\"lxmd-rs.exe\",\"9\",\"Console\"", 7, true).is_err());
    }
}
