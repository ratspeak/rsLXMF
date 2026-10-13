use super::*;
use rns_identity::persistence::{
    DurableFileReceipt, durable_create_dir_all, durable_reconcile_hash, durable_rename_directory,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_INVENTORY: usize = 65_536;
const MAX_JOURNAL: usize = 32 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct InventoryEntry {
    pub path: PathBuf,
    pub bytes: u64,
    pub hash: Option<[u8; 32]>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationJournal {
    version: u8,
    legacy: PathBuf,
    archive: PathBuf,
    v2: PathBuf,
    inventory: Vec<InventoryEntry>,
    had_legacy: bool,
    phase: u8,
    renewal: Option<PathBuf>,
    renewal_sequence: u64,
}
#[derive(Debug, Clone)]
pub struct MigrationReport {
    pub store: PathBuf,
    pub quarantine: QuarantineSummary,
}
#[derive(Debug, Clone)]
pub struct QuarantineSummary {
    pub files: usize,
    pub bytes: u64,
    pub reason: &'static str,
}
fn summary(j: &MigrationJournal) -> QuarantineSummary {
    QuarantineSummary {
        files: j.inventory.iter().filter(|e| e.hash.is_some()).count(),
        bytes: j
            .inventory
            .iter()
            .fold(0u64, |n, e| n.saturating_add(e.bytes)),
        reason: "Preserved legacy files have no trusted per-entry opaque-ingress provenance",
    }
}
fn encode(j: &MigrationJournal) -> io::Result<Vec<u8>> {
    let encoded = rmp_serde::to_vec_named(j).map_err(err)?;
    if encoded.len() > MAX_JOURNAL {
        return Err(invalid("migration inventory exceeds journal bound"));
    }
    Ok(encoded)
}
fn paths(legacy: &Path) -> io::Result<(PathBuf, PathBuf, PathBuf)> {
    Ok((
        sibling(legacy, ".migration")?,
        sibling(legacy, ".legacy-quarantine")?,
        sibling(legacy, ".v2")?,
    ))
}
fn save(j: &MigrationJournal) -> io::Result<DurableFileReceipt> {
    durable_write(&paths(&j.legacy)?.0, &encode(j)?).map_err(err)
}
fn read_journal(legacy: &Path) -> io::Result<MigrationJournal> {
    let (path, archive, v2) = paths(legacy)?;
    let j: MigrationJournal =
        rmp_serde::from_slice(&read_bounded(&path, MAX_JOURNAL)?).map_err(err)?;
    if j.version != 2
        || j.phase > 4
        || j.legacy != legacy
        || j.archive != archive
        || j.v2 != v2
        || j.inventory.len() > MAX_INVENTORY
    {
        return Err(invalid("migration journal path/version/phase mismatch"));
    }
    let mut unique = BTreeSet::new();
    for entry in &j.inventory {
        if !safe_relative(&entry.path) || !unique.insert(entry.path.clone()) {
            return Err(invalid("invalid inventory path"));
        }
    }
    if let Some(path) = &j.renewal
        && *path != sibling(&archive, &format!(".renewal-{}", j.renewal_sequence))?
    {
        return Err(invalid("directory renewal path mismatch"));
    }
    Ok(j)
}
pub fn quarantine_summary(legacy: &Path) -> io::Result<QuarantineSummary> {
    Ok(summary(&read_journal(&canonical_legacy(legacy)?)?))
}
fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path.as_os_str().len() <= 4096
        && path.components().count() <= 32
        && path
            .components()
            .all(|p| matches!(p, std::path::Component::Normal(_)))
}
fn hash_file(path: &Path) -> io::Result<(u64, [u8; 32])> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(invalid("legacy inventory contains a nonregular file"));
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or_else(|| invalid("legacy size overflow"))?;
        hash.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    if count != before.len() || after.len() != count || before.modified()? != after.modified()? {
        return Err(invalid("legacy file changed during inventory"));
    }
    Ok((count, hash.finalize().into()))
}
fn inventory(root: &Path) -> io::Result<Vec<InventoryEntry>> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("legacy root is not a real directory"));
    }
    let mut todo = vec![PathBuf::new()];
    let mut result = Vec::new();
    while let Some(relative) = todo.pop() {
        for entry in fs::read_dir(root.join(&relative))? {
            let entry = entry?;
            let relative = relative.join(entry.file_name());
            if !safe_relative(&relative) || result.len() >= MAX_INVENTORY {
                return Err(invalid("legacy inventory exceeds safe path/count bound"));
            }
            let m = fs::symlink_metadata(entry.path())?;
            if m.file_type().is_symlink() {
                return Err(invalid(
                    "legacy symbolic links require explicit operator recovery",
                ));
            }
            if m.is_dir() {
                result.push(InventoryEntry {
                    path: relative.clone(),
                    bytes: 0,
                    hash: None,
                });
                todo.push(relative);
            } else if m.is_file() {
                let (bytes, hash) = hash_file(&entry.path())?;
                result.push(InventoryEntry {
                    path: relative,
                    bytes,
                    hash: Some(hash),
                });
            } else {
                return Err(invalid(
                    "legacy special files require explicit operator recovery",
                ));
            }
        }
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}
fn verify_inventory(root: &Path, j: &MigrationJournal) -> io::Result<()> {
    if inventory(root)? != j.inventory {
        return Err(invalid(
            "legacy inventory changed; preserve original and investigate before recovery",
        ));
    }
    Ok(())
}
/// Startup only initializes a truly absent store. An incomplete journal or
/// historical directory requires the explicit offline recovery path.
pub fn open_store(legacy: &Path) -> io::Result<PathBuf> {
    Ok(open_locked_store(legacy)?.0)
}
pub(crate) fn open_locked_store(legacy: &Path) -> io::Result<(PathBuf, File)> {
    let legacy = canonical_legacy(legacy)?;
    let lock = offline::lock_store(&legacy)?;
    let (journal, archive, v2) = paths(&legacy)?;
    if journal.exists() {
        let j = read_journal(&legacy)?;
        if j.phase != 4 || j.renewal.is_some() {
            return Err(io::Error::other(MigrationRequired));
        }
        verify_published(&j)?;
        reconcile_deletions(&v2)?;
        return Ok((v2, lock));
    }
    if fs::symlink_metadata(&legacy).is_ok()
        || fs::symlink_metadata(&archive).is_ok()
        || fs::symlink_metadata(&v2).is_ok()
    {
        return Err(io::Error::other(MigrationRequired));
    }
    let j = MigrationJournal {
        version: 2,
        legacy: legacy.clone(),
        archive,
        v2,
        inventory: Vec::new(),
        had_legacy: false,
        phase: 0,
        renewal: None,
        renewal_sequence: 0,
    };
    save(&j)?;
    let report = run(j, None)?;
    Ok((report.store, lock))
}
fn verify_published(j: &MigrationJournal) -> io::Result<()> {
    if read_bounded(&j.legacy, 256)? != TOMBSTONE
        || read_bounded(&j.v2.join("FORMAT"), 256)? != FORMAT
    {
        return Err(invalid("v2 format or old-path guard mismatch"));
    }
    let objects = fs::symlink_metadata(j.v2.join("objects"))?;
    if !objects.is_dir() || objects.file_type().is_symlink() {
        return Err(invalid("v2 objects directory invalid"));
    }
    durable_reconcile(&j.legacy, TOMBSTONE).map_err(err)?;
    durable_reconcile(&j.v2.join("FORMAT"), FORMAT).map_err(err)?;
    Ok(())
}
/// The guard binds both path and verified writer exclusion. Neither a retry nor
/// operator approval promotes any legacy object without independent provenance.
pub fn migrate_store_offline(guard: &OfflineMigrationGuard) -> io::Result<MigrationReport> {
    migrate(&guard.legacy, None)
}
fn migrate(legacy: &Path, fault: Option<u8>) -> io::Result<MigrationReport> {
    let canonical = canonical_legacy(legacy)?;
    let legacy = canonical.as_path();
    let (journal, archive, v2) = paths(legacy)?;
    let j = if journal.exists() {
        read_journal(legacy)?
    } else {
        if archive.exists() || v2.exists() {
            return Err(invalid(
                "unowned archive/v2 path already exists; refusing overwrite",
            ));
        }
        let had_legacy = fs::symlink_metadata(legacy).is_ok();
        let inventory = if had_legacy {
            inventory(legacy)?
        } else {
            Vec::new()
        };
        let j = MigrationJournal {
            version: 2,
            legacy: legacy.to_owned(),
            archive,
            v2,
            inventory,
            had_legacy,
            phase: 0,
            renewal: None,
            renewal_sequence: 0,
        };
        save(&j)?;
        fail(fault, 0)?;
        j
    };
    run(j, fault)
}
fn fail(fault: Option<u8>, stage: u8) -> io::Result<()> {
    if fault == Some(stage) {
        Err(io::Error::other(format!(
            "injected migration boundary {stage}"
        )))
    } else {
        Ok(())
    }
}
/// Re-publish a renamed archive through two fresh sibling transitions. This is
/// valid on Windows WRITE_THROUGH and avoids pretending existing directories
/// can be acknowledged by a generic file flush. Every recovery target is journaled.
fn renew_archive(j: &mut MigrationJournal, fault: Option<u8>) -> io::Result<()> {
    if let Some(temporary) = j.renewal.clone() {
        match (j.archive.exists(), temporary.exists()) {
            (false, true) => {
                verify_inventory(&temporary, j)?;
                let witness = save(j)?;
                durable_rename_directory(&temporary, &j.archive, &witness).map_err(err)?;
                fail(fault, 6)?;
                j.renewal = None;
                save(j)?;
                return Ok(());
            }
            (true, false) => {
                j.renewal = None;
            }
            _ => {
                return Err(invalid(
                    "ambiguous archive renewal state; originals preserved",
                ));
            }
        }
    }
    verify_inventory(&j.archive, j)?;
    j.renewal_sequence = j
        .renewal_sequence
        .checked_add(1)
        .ok_or_else(|| invalid("renewal generation exhausted"))?;
    let temporary = sibling(&j.archive, &format!(".renewal-{}", j.renewal_sequence))?;
    if fs::symlink_metadata(&temporary).is_ok() {
        return Err(invalid("recovery target already exists"));
    }
    j.renewal = Some(temporary.clone());
    let witness = save(j)?;
    durable_rename_directory(&j.archive, &temporary, &witness).map_err(err)?;
    fail(fault, 5)?;
    // Rewrite the journal after the first acknowledged move; if this write is
    // uncertain the existing intent still describes both permitted locations.
    let witness = save(j)?;
    durable_rename_directory(&temporary, &j.archive, &witness).map_err(err)?;
    fail(fault, 6)?;
    j.renewal = None;
    save(j)?;
    Ok(())
}
fn run(mut j: MigrationJournal, fault: Option<u8>) -> io::Result<MigrationReport> {
    if j.had_legacy {
        if j.legacy.is_dir() {
            if j.phase != 0 || j.archive.exists() || j.renewal.is_some() {
                return Err(invalid("ambiguous legacy archive state"));
            }
            verify_inventory(&j.legacy, &j)?;
            // Renew barriers for every retained file before its directory move.
            for entry in j.inventory.iter().filter(|e| e.hash.is_some()) {
                let maximum = usize::try_from(entry.bytes).map_err(err)?;
                durable_reconcile_hash(&j.legacy.join(&entry.path), entry.hash.unwrap(), maximum)
                    .map_err(err)?;
            }
            let witness = save(&j)?;
            durable_rename_directory(&j.legacy, &j.archive, &witness).map_err(err)?;
            fail(fault, 1)?;
        } else {
            renew_archive(&mut j, fault)?;
        }
        verify_inventory(&j.archive, &j)?;
    } else if j.archive.exists() || j.renewal.is_some() {
        return Err(invalid("unexpected archive for a fresh store"));
    }
    if j.phase < 1 {
        j.phase = 1;
        save(&j)?;
    }
    match fs::symlink_metadata(&j.legacy) {
        Ok(_) if read_bounded(&j.legacy, 256)? != TOMBSTONE => {
            return Err(invalid("unknown old-path guard"));
        }
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    durable_write(&j.legacy, TOMBSTONE).map_err(err)?;
    fail(fault, 2)?;
    if j.phase < 2 {
        j.phase = 2;
        save(&j)?;
    }
    let witness = save(&j)?;
    durable_create_dir_all(&j.v2, &witness).map_err(err)?;
    durable_create_dir_all(&j.v2.join("objects"), &witness).map_err(err)?;
    durable_write(&j.v2.join("FORMAT"), FORMAT).map_err(err)?;
    fail(fault, 3)?;
    if j.phase < 3 {
        j.phase = 3;
        save(&j)?;
    }
    verify_published(&j)?;
    j.phase = 4;
    save(&j)?;
    fail(fault, 4)?;
    Ok(MigrationReport {
        store: j.v2.clone(),
        quarantine: summary(&j),
    })
}
pub(super) fn verified_archive(
    guard: &OfflineMigrationGuard,
) -> io::Result<(PathBuf, PathBuf, Vec<InventoryEntry>)> {
    let j = read_journal(&guard.legacy)?;
    if j.phase != 4 || j.renewal.is_some() {
        return Err(io::Error::other(MigrationRequired));
    }
    verify_published(&j)?;
    verify_inventory(&j.archive, &j)?;
    Ok((j.archive, j.v2, j.inventory))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migration_preserves_inventory_and_never_promotes_legacy_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = temp.path().join("store");
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("opaque"), [3; 200]).unwrap();
        fs::write(legacy.join("plaintext"), b"private message").unwrap();
        assert!(is_migration_required(&open_store(&legacy).unwrap_err()));
        let report = migrate(&legacy, None).unwrap();
        assert_eq!(report.quarantine.files, 2);
        assert_eq!(
            fs::read(
                sibling(&legacy, ".legacy-quarantine")
                    .unwrap()
                    .join("plaintext")
            )
            .unwrap(),
            b"private message"
        );
        assert_eq!(
            fs::read_dir(report.store.join("objects")).unwrap().count(),
            0
        );
        assert!(open_store(&legacy).is_ok());
    }
    #[test]
    fn every_migration_and_renewal_boundary_resumes_without_losing_originals() {
        for stage in 0..=6 {
            let temp = tempfile::tempdir().unwrap();
            let legacy = temp.path().join("store");
            fs::create_dir(&legacy).unwrap();
            fs::write(legacy.join("message"), b"untouched").unwrap();
            if stage >= 5 {
                assert!(migrate(&legacy, Some(1)).is_err());
            }
            assert!(migrate(&legacy, Some(stage)).is_err());
            let report = migrate(&legacy, None).unwrap();
            assert_eq!(report.quarantine.files, 1);
            assert_eq!(
                fs::read(
                    sibling(&legacy, ".legacy-quarantine")
                        .unwrap()
                        .join("message")
                )
                .unwrap(),
                b"untouched"
            );
            assert!(open_store(&legacy).is_ok());
        }
    }
    #[test]
    fn changed_inventory_and_unowned_targets_fail_without_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = temp.path().join("store");
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("message"), b"original").unwrap();
        assert!(migrate(&legacy, Some(0)).is_err());
        fs::write(legacy.join("message"), b"changed").unwrap();
        assert!(migrate(&legacy, None).is_err());
        assert!(legacy.is_dir());
        let other = temp.path().join("other");
        fs::create_dir(sibling(&other, ".v2").unwrap()).unwrap();
        assert!(open_store(&other).is_err());
        assert!(!other.exists());
    }
}
