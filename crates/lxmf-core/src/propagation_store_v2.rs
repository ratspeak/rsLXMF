//! Provenance-gated relay storage and conservative offline migration.
//!
//! Private local manifests record accepted opaque ingress. They are not an
//! encryption oracle, and old files acquire no authority from their names or
//! apparent envelope shape. Callers exclude external writers from these paths.
#[cfg(target_os = "android")]
mod android_container;
mod migration;
#[cfg(any(target_os = "ios", target_os = "android", test))]
mod mobile;
#[cfg(target_os = "android")]
pub use mobile::begin_android_container_migration;
#[cfg(target_os = "ios")]
pub use mobile::begin_ios_container_migration;
mod offline;
mod recovery;
pub(crate) use migration::open_locked_store;
pub use migration::{
    MigrationReport, QuarantineSummary, migrate_store_offline, open_store, quarantine_summary,
};
pub use offline::{OfflineMigrationGuard, begin_offline_migration};
pub use recovery::{
    RecoveryEntry, RecoveryPolicy, RecoveryReport, TrustedRecoveryManifest,
    import_trusted_recovery_manifest,
};

use rns_identity::persistence::{durable_reconcile, durable_remove, durable_write};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const TOMBSTONE: &[u8] =
    b"LXMF relay store moved to v2; legacy hosting and sync must remain disabled.\n";
const FORMAT: &[u8] = b"LXMF opaque relay store v2; objects and per-entry provenance\n";
const MAX_MANIFEST_BYTES: usize = 4096;
static STORE_MUTATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, thiserror::Error)]
#[error(
    "MigrationRequired: stop all legacy relay writers and run explicit offline store migration"
)]
pub struct MigrationRequired;
pub fn is_migration_required(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<MigrationRequired>())
}
fn err(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn sibling(path: &Path, suffix: &str) -> io::Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| invalid("store path has no file name"))?
        .to_os_string();
    name.push(suffix);
    Ok(path.with_file_name(name))
}
fn read_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum as u64 {
        return Err(invalid("store record is not a bounded regular file"));
    }
    let mut data = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > maximum {
        return Err(invalid("store record grew beyond its bound"));
    }
    Ok(data)
}
fn canonical_legacy(path: &Path) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("store path has no file name"))?;
    if name == "." || name == ".." {
        return Err(invalid("invalid store path"));
    }
    let path = parent.join(name);
    if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(invalid("store root cannot be a symbolic link"));
    }
    Ok(path)
}
pub(crate) fn manifest_path(path: &Path) -> PathBuf {
    sibling(path, ".entry").expect("validated object path")
}
pub(crate) fn deletion_path(path: &Path) -> PathBuf {
    sibling(path, ".delete").expect("validated object path")
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpaqueIngress {
    ValidatedPropagation,
    TrustedRecovery,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum AdmissionProtocol {
    StampedPropagation,
    ExplicitTrustedRecovery,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum PublicationState {
    Committed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EntryManifest {
    pub version: u8,
    admission_id: [u8; 16],
    pub transient_id: [u8; 32],
    pub content_hash: [u8; 32],
    pub destination: [u8; 16],
    pub size: usize,
    pub stamp_value: u8,
    pub stored_at: f64,
    pub stamped: bool,
    pub origin: OpaqueIngress,
    protocol: AdmissionProtocol,
    publication: PublicationState,
}
impl EntryManifest {
    pub(crate) fn from_entry(entry: &crate::propagation::PropagationEntry, bytes: &[u8]) -> Self {
        Self {
            version: 2,
            admission_id: rand::random(),
            transient_id: entry.transient_id,
            content_hash: rns_crypto::sha::full_hash(bytes),
            destination: entry.destination_hash,
            size: bytes.len(),
            stamp_value: entry.stamp_value,
            stored_at: entry.stored_at,
            stamped: entry.stamped,
            origin: OpaqueIngress::ValidatedPropagation,
            protocol: AdmissionProtocol::StampedPropagation,
            publication: PublicationState::Committed,
        }
    }
    pub(crate) fn validate(&self, data: &[u8]) -> bool {
        let tail = if self.stamped { 32 } else { 0 };
        self.version == 2
            && self.stored_at.is_finite()
            && self.stored_at >= 0.0
            && self.size <= rns_protocol::resource::MAX_RESOURCE_SIZE
            && data.len() == self.size
            && data.len() > 16 + tail
            && data[..16] == self.destination
            && rns_crypto::sha::full_hash(data) == self.content_hash
            && rns_crypto::sha::full_hash(&data[..data.len() - tail]) == self.transient_id
            && matches!(
                (self.origin, self.protocol),
                (
                    OpaqueIngress::ValidatedPropagation,
                    AdmissionProtocol::StampedPropagation
                ) | (
                    OpaqueIngress::TrustedRecovery,
                    AdmissionProtocol::ExplicitTrustedRecovery
                )
            )
            && (self.origin == OpaqueIngress::TrustedRecovery || self.stamped)
    }
    pub(crate) fn filename(&self) -> String {
        format!(
            "{}_{}",
            self.entry().filename(),
            hex::encode(self.admission_id)
        )
    }
    pub(crate) fn entry(&self) -> crate::propagation::PropagationEntry {
        let mut entry = crate::propagation::PropagationEntry::new(
            self.transient_id,
            self.transient_id,
            self.destination,
            self.size,
            self.stamp_value,
        );
        entry.stored_at = self.stored_at;
        entry.stamped = self.stamped;
        entry
    }
}
pub(crate) fn read_manifest(path: &Path) -> io::Result<(EntryManifest, Vec<u8>)> {
    let encoded = read_bounded(&manifest_path(path), MAX_MANIFEST_BYTES)?;
    let meta: EntryManifest = rmp_serde::from_slice(&encoded).map_err(err)?;
    if meta.filename() != path.file_name().and_then(|s| s.to_str()).unwrap_or("") {
        return Err(invalid(
            "relay object filename does not match its provenance record",
        ));
    }
    Ok((meta, encoded))
}
#[derive(Debug, Serialize, Deserialize)]
struct ActiveIndex {
    version: u8,
    object: String,
    manifest_hash: [u8; 32],
}
fn index_path(object: &Path, id: &[u8; 32]) -> io::Result<PathBuf> {
    Ok(object
        .parent()
        .ok_or_else(|| invalid("object has no parent"))?
        .join(format!("{}.active", hex::encode(id))))
}
fn check_index(object: &Path, meta: &EntryManifest, encoded: &[u8]) -> io::Result<()> {
    let index: ActiveIndex = rmp_serde::from_slice(&read_bounded(
        &index_path(object, &meta.transient_id)?,
        MAX_MANIFEST_BYTES,
    )?)
    .map_err(err)?;
    if index.version != 2
        || index.object != meta.filename()
        || index.manifest_hash != rns_crypto::sha::full_hash(encoded)
    {
        return Err(invalid(
            "object is not the active committed relay admission",
        ));
    }
    Ok(())
}
pub(crate) fn indexed_object(index_path: &Path) -> io::Result<PathBuf> {
    let index: ActiveIndex =
        rmp_serde::from_slice(&read_bounded(index_path, MAX_MANIFEST_BYTES)?).map_err(err)?;
    if index.version != 2
        || Path::new(&index.object).components().count() != 1
        || !matches!(
            Path::new(&index.object).components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(invalid("invalid relay active index"));
    }
    let object = index_path
        .parent()
        .ok_or_else(|| invalid("active index has no parent"))?
        .join(index.object);
    let (meta, encoded) = read_manifest(&object)?;
    if self::index_path(&object, &meta.transient_id)? != index_path {
        return Err(invalid("relay index TID mismatch"));
    }
    check_index(&object, &meta, &encoded)?;
    Ok(object)
}
/// Publish object, provenance, then its per-TID commit index. A cancelled
/// in-memory callback cannot cause retry to replace the first committed image.
pub(crate) fn publish_object(
    object: &Path,
    meta: &EntryManifest,
    data: &[u8],
) -> io::Result<(EntryManifest, PathBuf)> {
    let _guard = STORE_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let index = index_path(object, &meta.transient_id)?;
    match fs::symlink_metadata(&index) {
        Ok(_) => {
            let existing = indexed_object(&index)?;
            let (first, encoded) = read_manifest(&existing)?;
            let retained = read_validated_file(&existing)?;
            durable_reconcile(&existing, &retained).map_err(err)?;
            durable_reconcile(&manifest_path(&existing), &encoded).map_err(err)?;
            let index_bytes = read_bounded(&index, MAX_MANIFEST_BYTES)?;
            durable_reconcile(&index, &index_bytes).map_err(err)?;
            return Ok((first, existing));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if !meta.validate(data)
        || object.file_name().and_then(|s| s.to_str()) != Some(meta.filename().as_str())
    {
        return Err(invalid("invalid relay publication"));
    }
    let encoded = rmp_serde::to_vec_named(meta).map_err(err)?;
    durable_write(object, data).map_err(err)?;
    durable_write(&manifest_path(object), &encoded).map_err(err)?;
    let active = ActiveIndex {
        version: 2,
        object: meta.filename(),
        manifest_hash: rns_crypto::sha::full_hash(&encoded),
    };
    durable_write(&index, &rmp_serde::to_vec_named(&active).map_err(err)?).map_err(err)?;
    Ok((meta.clone(), object.to_owned()))
}

/// Verify the complete indexed admission and renew all three publication
/// barriers. Serialize against retirement so successful return has a concrete
/// committed point, even when a purge was prepared concurrently.
pub(crate) fn verify_committed_object(path: &Path) -> io::Result<()> {
    let _guard = STORE_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (meta, encoded) = read_manifest(path)?;
    let data = read_validated_file(path)?;
    durable_reconcile(path, &data).map_err(err)?;
    durable_reconcile(&manifest_path(path), &encoded).map_err(err)?;
    let index = index_path(path, &meta.transient_id)?;
    let bytes = read_bounded(&index, MAX_MANIFEST_BYTES)?;
    durable_reconcile(&index, &bytes).map_err(err)?;
    check_index(path, &meta, &encoded)
}

/// Startup check for an indexed record: readable, committed size and
/// destination prefix. Publication completed its barriers before any proof,
/// duplicates renew them, and every read revalidates the body, so restart must
/// not reread and re-flush the whole store.
pub(crate) fn check_committed_on_load(path: &Path, meta: &EntryManifest) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() != meta.size as u64 {
        return Err(invalid("relay object does not match its committed size"));
    }
    let mut destination = [0u8; 16];
    File::open(path)?.read_exact(&mut destination)?;
    if destination != meta.destination {
        return Err(invalid(
            "relay object does not match its committed destination",
        ));
    }
    Ok(())
}

/// Both the manifest and complete bytes are checked at the final read boundary.
/// An unresolved durable deletion always defeats a previously prepared read.
pub(crate) fn read_validated_file(path: &Path) -> io::Result<Vec<u8>> {
    read_validated_file_bounded(path, rns_protocol::resource::MAX_RESOURCE_SIZE)
}

/// Refuse oversized metadata before allocating or opening the payload. The
/// caller can therefore reserve its complete GET response budget first.
pub(crate) fn read_validated_file_bounded(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    if fs::symlink_metadata(deletion_path(path)).is_ok() {
        return Err(invalid("relay object has a pending durable deletion"));
    }
    let (meta, encoded) = read_manifest(path)?;
    check_index(path, &meta, &encoded)?;
    if meta.size > maximum.min(rns_protocol::resource::MAX_RESOURCE_SIZE) {
        return Err(invalid("relay object exceeds Resource capacity"));
    }
    let data = read_bounded(path, meta.size)?;
    if !meta.validate(&data) {
        return Err(invalid("relay object changed after validated admission"));
    }
    if fs::symlink_metadata(deletion_path(path)).is_ok() {
        return Err(invalid("relay object retired while being read"));
    }
    check_index(path, &meta, &encoded)?;
    Ok(data)
}

#[derive(Debug, Serialize, Deserialize)]
struct DeletionRecord {
    version: u8,
    object: String,
    content_hash: [u8; 32],
    transient_id: [u8; 32],
}
/// The durable deletion intent is committed before either indexed file is
/// removed. Keep it across every uncertain cleanup; startup resumes cleanup
/// before loading any active objects.
pub(crate) fn retire_object(path: &Path) -> io::Result<()> {
    retire_object_inner(path, false)
}
fn retire_object_inner(path: &Path, fail_after_intent: bool) -> io::Result<()> {
    let _guard = STORE_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let marker = deletion_path(path);
    let encoded = match read_bounded(&marker, MAX_MANIFEST_BYTES) {
        Ok(encoded) => encoded,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (meta, _) = read_manifest(path)?;
            let record = DeletionRecord {
                version: 2,
                object: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| invalid("invalid object name"))?
                    .to_string(),
                content_hash: meta.content_hash,
                transient_id: meta.transient_id,
            };
            rmp_serde::to_vec_named(&record).map_err(err)?
        }
        Err(e) => return Err(e),
    };
    let record: DeletionRecord = rmp_serde::from_slice(&encoded).map_err(err)?;
    if record.version != 2
        || Path::new(&record.object).components().count() != 1
        || path.file_name().and_then(|s| s.to_str()) != Some(&record.object)
    {
        return Err(invalid("deletion record path mismatch"));
    }
    let witness = durable_write(&marker, &encoded).map_err(err)?;
    if fail_after_intent {
        return Err(io::Error::other(
            "injected interruption after durable deletion intent",
        ));
    }
    let cleanup = (|| -> io::Result<()> {
        let index = index_path(path, &record.transient_id)?;
        if let Ok(active) = indexed_object(&index)
            && active == path
        {
            durable_remove(&index, &witness).map_err(err)?;
        }
        durable_remove(path, &witness).map_err(err)?;
        durable_remove(&manifest_path(path), &witness).map_err(err)?;
        // A separate, retained FORMAT witness may retire the journal only once both
        // removals have acknowledged barriers. Failure leaves the journal reusable.
        let root = path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| invalid("object outside v2 objects directory"))?;
        let format = durable_reconcile(&root.join("FORMAT"), FORMAT).map_err(err)?;
        durable_remove(&marker, &format).map_err(err)?;
        Ok(())
    })();
    if let Err(error) = cleanup {
        tracing::warn!(%error, "committed relay deletion retains pending cleanup evidence");
    }
    Ok(())
}
pub(crate) fn reconcile_deletions(root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(root.join("objects"))? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("delete") {
            continue;
        }
        let object = path.with_extension("");
        retire_object(&object)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deletion_intent_survives_interruption_and_revokes_all_read_authority() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = temp.path().join("store");
        let root = open_store(&legacy).unwrap();
        let mut data = [2; 16].to_vec();
        data.extend_from_slice(
            &rns_identity::identity::Identity::new()
                .encrypt(b"private payload", None)
                .unwrap(),
        );
        let tid = rns_crypto::sha::full_hash(&data);
        data.extend_from_slice(&[0; 32]);
        let mut entry = crate::propagation::PropagationEntry::new(tid, tid, [2; 16], data.len(), 0);
        entry.stamped = true;
        let meta = EntryManifest::from_entry(&entry, &data);
        let object = root.join("objects").join(meta.filename());
        publish_object(&object, &meta, &data).unwrap();
        assert_eq!(read_validated_file(&object).unwrap(), data);
        assert!(retire_object_inner(&object, true).is_err());
        assert!(object.exists());
        assert!(deletion_path(&object).exists());
        assert!(read_validated_file(&object).is_err());
        assert!(verify_committed_object(&object).is_err());
        open_store(&legacy).unwrap();
        assert!(!object.exists());
        assert!(!index_path(&object, &tid).unwrap().exists());
        assert!(!deletion_path(&object).exists());
    }
}
