use super::*;
use std::collections::{HashMap, HashSet};

/// A local owner's independently verified ingress record. The approved manifest
/// digest is supplied separately by the recovery UI/CLI; a location or blanket
/// 'recover all' action is never an origin assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedRecoveryManifest {
    pub version: u8,
    pub provenance: String,
    pub entries: Vec<RecoveryEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEntry {
    pub archive_relative_path: PathBuf,
    pub content_hash: [u8; 32],
    pub transient_id: [u8; 32],
    pub stamped: bool,
    pub stored_at: f64,
}
#[derive(Debug, Clone, Copy)]
pub struct RecoveryPolicy {
    pub maximum_store_bytes: usize,
    pub maximum_message_bytes: usize,
    pub minimum_stamp_cost: u8,
}
#[derive(Debug, Clone, Copy)]
pub struct RecoveryReport {
    pub imported: usize,
    pub already_present: usize,
}

fn validate(
    record: &RecoveryEntry,
    bytes: &[u8],
    minimum_stamp_cost: u8,
) -> io::Result<EntryManifest> {
    let tail = if record.stamped { 32 } else { 0 };
    if bytes.len() < 112 + tail
        || !record.stored_at.is_finite()
        || record.stored_at < 0.0
        || rns_crypto::sha::full_hash(bytes) != record.content_hash
    {
        return Err(invalid("recovery content hash/length/time mismatch"));
    }
    let opaque = &bytes[..bytes.len() - tail];
    if !(opaque.len() - 16 - 32 - rns_crypto::TOKEN_OVERHEAD).is_multiple_of(16)
        || rns_crypto::sha::full_hash(opaque) != record.transient_id
    {
        return Err(invalid("recovery envelope/TID mismatch"));
    }
    if crate::message::LxMessage::unpack(opaque).is_ok()
        || crate::message::LxMessage::unpack(bytes).is_ok()
    {
        return Err(invalid(
            "raw plaintext LXMF is never eligible for relay recovery",
        ));
    }
    let stamp_value = if record.stamped {
        let stamp: &[u8; 32] = bytes[bytes.len() - 32..].try_into().map_err(err)?;
        let workblock = crate::stamper::stamp_workblock(
            &record.transient_id,
            crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PN,
        );
        let value = crate::stamper::stamp_value(&workblock, stamp).min(255) as u8;
        if value < minimum_stamp_cost {
            return Err(invalid("recovered stamp does not meet node policy"));
        }
        value
    } else {
        if minimum_stamp_cost > 0 {
            return Err(invalid("unstamped recovery does not meet node policy"));
        }
        0
    };
    let mut destination = [0; 16];
    destination.copy_from_slice(&bytes[..16]);
    let mut entry = crate::propagation::PropagationEntry::new(
        record.transient_id,
        record.transient_id,
        destination,
        bytes.len(),
        stamp_value,
    );
    entry.stored_at = record.stored_at;
    entry.stamped = record.stamped;
    let mut manifest = EntryManifest::from_entry(&entry, bytes);
    manifest.origin = OpaqueIngress::TrustedRecovery;
    manifest.protocol = AdmissionProtocol::ExplicitTrustedRecovery;
    Ok(manifest)
}

/// Import exact positively attested archive entries under the same offline
/// guard. Every entry is checked before the first write, then rechecked at its
/// publication boundary. Partial IO completion is restart-safe and idempotent.
pub fn import_trusted_recovery_manifest(
    guard: &OfflineMigrationGuard,
    path: &Path,
    approved_manifest_sha256: [u8; 32],
    policy: RecoveryPolicy,
) -> io::Result<RecoveryReport> {
    let encoded = read_bounded(path, 32 * 1024 * 1024)?;
    if rns_crypto::sha::full_hash(&encoded) != approved_manifest_sha256 {
        return Err(invalid("recovery manifest changed after approval"));
    }
    let recovery: TrustedRecoveryManifest = rmp_serde::from_slice(&encoded).map_err(err)?;
    if recovery.version != 2
        || recovery.provenance.trim().is_empty()
        || recovery.provenance.len() > 4096
        || recovery.entries.len() > 65_536
    {
        return Err(invalid("invalid trusted recovery manifest"));
    }
    let (archive, root, inventory) = migration::verified_archive(guard)?;
    let known: HashMap<_, _> = inventory
        .into_iter()
        .filter_map(|e| e.hash.map(|h| (e.path, (e.bytes, h))))
        .collect();
    let mut existing = HashMap::new();
    let mut total = 0usize;
    reconcile_deletions(&root)?;
    for file in fs::read_dir(root.join("objects"))? {
        let path = file?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("active") {
            continue;
        }
        let object = indexed_object(&path)?;
        let (meta, _) = read_manifest(&object)?;
        let bytes = read_validated_file(&object)?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("relay size overflow"))?;
        if existing
            .insert(meta.transient_id, meta.content_hash)
            .is_some()
        {
            return Err(invalid("duplicate active relay TID"));
        }
    }
    let maximum = policy
        .maximum_message_bytes
        .min(rns_protocol::resource::MAX_RESOURCE_SIZE);
    let mut selected = HashSet::new();
    let mut plans = Vec::new();
    let mut already_present = 0;
    for record in &recovery.entries {
        if !selected.insert(record.transient_id) {
            return Err(invalid("duplicate recovery TID"));
        }
        let Some((length, hash)) = known.get(&record.archive_relative_path) else {
            return Err(invalid(
                "recovery entry is outside the committed legacy inventory",
            ));
        };
        if *hash != record.content_hash || *length > maximum as u64 {
            return Err(invalid("recovery inventory hash/size mismatch"));
        }
        let bytes = read_bounded(&archive.join(&record.archive_relative_path), maximum)?;
        let meta = validate(record, &bytes, policy.minimum_stamp_cost)?;
        if let Some(hash) = existing.get(&record.transient_id) {
            if *hash != record.content_hash {
                return Err(invalid(
                    "recovery would replace the first accepted relay image",
                ));
            }
            already_present += 1;
            continue;
        }
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("relay size overflow"))?;
        if total > policy.maximum_store_bytes {
            return Err(invalid(
                "trusted recovery exceeds active relay storage quota",
            ));
        }
        plans.push((record, meta));
    }
    let mut imported = 0;
    for (record, meta) in plans {
        let bytes = read_bounded(&archive.join(&record.archive_relative_path), maximum)?;
        validate(record, &bytes, policy.minimum_stamp_cost)?;
        let object = root.join("objects").join(meta.filename());
        if object.exists() && read_bounded(&object, maximum)? != bytes {
            return Err(invalid("recovery object target contains different bytes"));
        }
        publish_object(&object, &meta, &bytes)?;
        imported += 1;
    }
    Ok(RecoveryReport {
        imported,
        already_present,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(legacy: &Path) -> OfflineMigrationGuard {
        let legacy = canonical_legacy(legacy).unwrap();
        let lock = offline::lock_store(&legacy).unwrap();
        OfflineMigrationGuard {
            legacy,
            _lock: lock,
        }
    }
    fn write_manifest(path: &Path, manifest: &TrustedRecoveryManifest) -> [u8; 32] {
        let bytes = rmp_serde::to_vec_named(manifest).unwrap();
        fs::write(path, &bytes).unwrap();
        rns_crypto::sha::full_hash(&bytes)
    }
    fn policy() -> RecoveryPolicy {
        RecoveryPolicy {
            maximum_store_bytes: 8192,
            maximum_message_bytes: 4096,
            minimum_stamp_cost: 0,
        }
    }
    fn record(bytes: &[u8], name: &str) -> RecoveryEntry {
        RecoveryEntry {
            archive_relative_path: name.into(),
            content_hash: rns_crypto::sha::full_hash(bytes),
            transient_id: rns_crypto::sha::full_hash(bytes),
            stamped: false,
            stored_at: 1.0,
        }
    }
    #[test]
    fn only_exact_approved_inventory_entries_are_imported_and_retry_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = temp.path().join("store");
        fs::create_dir(&legacy).unwrap();
        let recipient = rns_identity::identity::Identity::new();
        let mut bytes = [2; 16].to_vec();
        bytes.extend_from_slice(
            &recipient
                .encrypt(b"private recovery payload", None)
                .unwrap(),
        );
        fs::write(legacy.join("opaque"), &bytes).unwrap();
        fs::write(legacy.join("unknown"), b"never infer eligibility").unwrap();
        let offline = guard(&legacy);
        let report = migrate_store_offline(&offline).unwrap();
        assert_eq!(report.quarantine.files, 2);
        assert_eq!(
            fs::read_dir(report.store.join("objects")).unwrap().count(),
            0
        );
        let manifest = TrustedRecoveryManifest {
            version: 2,
            provenance: "operator verified original opaque ingress record #42".into(),
            entries: vec![record(&bytes, "opaque")],
        };
        let path = temp.path().join("recovery.msgpack");
        let hash = write_manifest(&path, &manifest);
        assert!(import_trusted_recovery_manifest(&offline, &path, [0; 32], policy()).is_err());
        let first = import_trusted_recovery_manifest(&offline, &path, hash, policy()).unwrap();
        assert_eq!((first.imported, first.already_present), (1, 0));
        let retry = import_trusted_recovery_manifest(&offline, &path, hash, policy()).unwrap();
        assert_eq!((retry.imported, retry.already_present), (0, 1));
        assert_eq!(
            fs::read_dir(report.store.join("objects")).unwrap().count(),
            3
        );
        assert_eq!(
            fs::read(
                sibling(&legacy, ".legacy-quarantine")
                    .unwrap()
                    .join("unknown")
            )
            .unwrap(),
            b"never infer eligibility"
        );
        drop(offline);
        let reopened = crate::propagation_node::PropagationNode::with_storage(
            crate::propagation_node::PropagationNodeConfig::default(),
            [1; 16],
            legacy,
        )
        .unwrap();
        assert_eq!(reopened.message_count(), 1);
        assert_eq!(
            fs::read(&reopened.plan_message_reads(&[rns_crypto::sha::full_hash(&bytes)])[0].path)
                .unwrap(),
            bytes
        );
    }
    #[test]
    fn plaintext_or_outside_inventory_recovery_cannot_publish_any_entry() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = temp.path().join("store");
        fs::create_dir(&legacy).unwrap();
        let message = crate::message::test_message(
            [2; 16],
            [3; 16],
            "Private",
            "Do not relay cleartext",
            crate::constants::DeliveryMethod::Direct,
        );
        let bytes = message.wire_bytes();
        fs::write(legacy.join("plaintext"), bytes).unwrap();
        let offline = guard(&legacy);
        let report = migrate_store_offline(&offline).unwrap();
        let path = temp.path().join("recovery.msgpack");
        let mut manifest = TrustedRecoveryManifest {
            version: 2,
            provenance: "inaccurate assertion does not override positive plaintext decode".into(),
            entries: vec![record(bytes, "plaintext")],
        };
        let hash = write_manifest(&path, &manifest);
        assert!(import_trusted_recovery_manifest(&offline, &path, hash, policy()).is_err());
        manifest.entries[0].archive_relative_path = "../plaintext".into();
        let hash = write_manifest(&path, &manifest);
        assert!(import_trusted_recovery_manifest(&offline, &path, hash, policy()).is_err());
        assert_eq!(
            fs::read_dir(report.store.join("objects")).unwrap().count(),
            0
        );
        assert_eq!(
            fs::read(
                sibling(&legacy, ".legacy-quarantine")
                    .unwrap()
                    .join("plaintext")
            )
            .unwrap(),
            bytes
        );
    }
}
