//! File adapter for lxmd's durable download receipts and hook outbox.
//! The original ciphertext TID is journaled before publishing decrypted bytes.
use crate::admission::*;
use bytes::Bytes;
use rns_identity::persistence::{
    DurableCommitPhase, DurableWriteError, durable_create_dir_all, durable_reconcile,
    durable_remove, durable_write,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdmissionIntent {
    version: u8,
    admission_id: [u8; 32],
    record: AdmissionRecord,
    body_path: Option<PathBuf>,
    hook_event: Option<[u8; 32]>,
}

/// One atomic logical commit publishes both the receipt and pending hook event.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdmissionCommit {
    intent: AdmissionIntent,
    hook_completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserDeletedMessage {
    version: u8,
    identity: [u8; 16],
    message_id: [u8; 32],
    deleted_at: u64,
}

struct Inner {
    journal: PathBuf,
    bodies: PathBuf,
    committed: HashMap<AdmissionScope, AdmissionCommit>,
    deleted: HashMap<([u8; 16], [u8; 32]), UserDeletedMessage>,
}

#[derive(Clone)]
pub struct FileAdmissionStore {
    inner: Arc<Mutex<Inner>>,
}

fn error(e: DurableWriteError) -> AdmissionError {
    match e.phase {
        DurableCommitPhase::NotCommitted => AdmissionError::NotCommitted(e.to_string()),
        _ => AdmissionError::CommitUncertain(e.to_string()),
    }
}
fn other(e: impl std::fmt::Display) -> AdmissionError {
    AdmissionError::NotCommitted(e.to_string())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AdmissionError> {
    rmp_serde::to_vec_named(value).map_err(other)
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, AdmissionError> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(other)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(other)?;
    if bytes.len() > limit {
        return Err(other("admission artifact exceeds limit"));
    }
    Ok(bytes)
}
fn admission_id(scope: &AdmissionScope) -> Result<[u8; 32], AdmissionError> {
    Ok(rns_crypto::sha::full_hash(&encode(scope)?))
}

impl FileAdmissionStore {
    /// Parent is the daemon's already configured state directory. A strict
    /// outside bootstrap receipt witnesses creation of journal/body directories.
    pub fn open(state_dir: &Path, bodies: &Path) -> Result<Self, AdmissionError> {
        let journal = state_dir.join("download-admission-v1");
        let parent = state_dir
            .ancestors()
            .find(|parent| {
                bodies.starts_with(parent) && *parent != bodies && parent.parent().is_some()
            })
            .ok_or_else(|| other("admission state and bodies need a private common ancestor"))?;
        let scope = encode(&(1u8, state_dir, bodies))?;
        let bootstrap_path = parent.join(format!(
            "download-admission-{}.bootstrap",
            hex::encode(rns_crypto::sha::full_hash(&scope))
        ));
        let bootstrap = durable_write(&bootstrap_path, &scope).map_err(error)?;
        durable_create_dir_all(&journal, &bootstrap).map_err(error)?;
        durable_create_dir_all(bodies, &bootstrap).map_err(error)?;
        let mut inner = Inner {
            journal,
            bodies: bodies.to_owned(),
            committed: HashMap::new(),
            deleted: HashMap::new(),
        };
        inner.recover()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub fn prepare(
        &self,
        mut record: AdmissionRecord,
        wire: Bytes,
        run_hook: bool,
    ) -> FileAdmissionCommit {
        // The caller cannot mislabel the incoming image even for a duplicate.
        record.received_wire_hash = rns_crypto::sha::full_hash(&wire);
        FileAdmissionCommit {
            store: self.clone(),
            record,
            wire,
            run_hook,
        }
    }

    /// Durable visible receipts remain while their referenced message exists;
    /// invisible policy/TID accelerators expire after the local90-day policy.
    pub fn haves(&self, identity: [u8; 16], node: [u8; 16], now: u64) -> Vec<Vec<u8>> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .committed
            .values()
            .filter(|c| {
                c.intent.record.scope.identity == identity
                    && c.intent.record.scope.node == node
                    && live(&c.intent.record, now)
            })
            .map(|c| c.intent.record.scope.transient_id.to_vec())
            .collect()
    }

    pub fn durable_haves(
        &self,
        identity: [u8; 16],
        node: [u8; 16],
        now: u64,
    ) -> Vec<super::admission::DurableHave> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .committed
            .values()
            .filter(|c| {
                c.intent.record.scope.identity == identity
                    && c.intent.record.scope.node == node
                    && live(&c.intent.record, now)
            })
            .map(|c| super::admission::DurableHave::from_record(&c.intent.record))
            .collect()
    }

    /// Explicit user deletion is a permanent message-ID decision, separate
    /// from expiring per-node TID accelerators. No filesystem absence is treated
    /// as user authorization. Removing this tombstone requires explicit reset.
    pub fn mark_user_deleted(
        &self,
        identity: [u8; 16],
        message_id: [u8; 32],
        now: u64,
    ) -> Result<(), AdmissionError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let tombstone = UserDeletedMessage {
            version: 1,
            identity,
            message_id,
            deleted_at: now,
        };
        let path = inner.journal.join(format!(
            "{}-{}.deleted",
            hex::encode(identity),
            hex::encode(message_id)
        ));
        let witness = durable_write(&path, &encode(&tombstone)?).map_err(error)?;
        inner.deleted.insert((identity, message_id), tombstone);
        let targets = inner
            .committed
            .iter()
            .filter(|(_, c)| {
                c.intent.record.scope.identity == identity
                    && c.intent.record.message_id == message_id
            })
            .map(|(scope, c)| (*scope, c.clone()))
            .collect::<Vec<_>>();
        for (scope, mut commit) in targets {
            commit.intent.body_path = None;
            commit.intent.hook_event = None;
            commit.hook_completed = true;
            commit.intent.record.disposition = DurableDisposition::UserDeleted;
            commit.intent.record.stored_message_wire_hash = None;
            commit.intent.record.committed_at = now;
            durable_write(
                &inner.intent_path(&commit.intent.admission_id),
                &encode(&commit.intent)?,
            )
            .map_err(error)?;
            durable_write(
                &inner.commit_path(&commit.intent.admission_id),
                &encode(&commit)?,
            )
            .map_err(error)?;
            inner.committed.insert(scope, commit);
        }
        durable_remove(
            &inner
                .bodies
                .join(format!("{}.lxm", hex::encode(message_id))),
            &witness,
        )
        .map_err(error)?;
        Ok(())
    }

    /// Prune only expired invisible TID receipts. Visible archive authority and
    /// permanent UserDeleted message decisions are retained independently.
    pub fn maintain(&self, now: u64) -> Result<usize, AdmissionError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let expired = inner
            .committed
            .iter()
            .filter(|(_, c)| !live(&c.intent.record, now))
            .map(|(scope, c)| (*scope, c.intent.admission_id))
            .collect::<Vec<_>>();
        if expired.is_empty() {
            return Ok(0);
        }
        let witness = durable_write(
            &inner.journal.join("receipt-pruning-v1"),
            &encode(&(1u8, &expired))?,
        )
        .map_err(error)?;
        let mut removed = 0;
        for (scope, id) in expired {
            durable_remove(&inner.intent_path(&id), &witness).map_err(error)?;
            durable_remove(&inner.commit_path(&id), &witness).map_err(error)?;
            inner.committed.remove(&scope);
            removed += 1;
        }
        Ok(removed)
    }

    pub fn pending_hooks(&self) -> Vec<([u8; 32], PathBuf)> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .committed
            .values()
            .filter(|c| !c.hook_completed)
            .filter_map(|c| Some((c.intent.hook_event?, c.intent.body_path.clone()?)))
            .collect()
    }

    pub fn complete_hook(&self, event: [u8; 32]) -> Result<(), AdmissionError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(scope) = inner
            .committed
            .iter()
            .find_map(|(s, c)| (c.intent.hook_event == Some(event)).then_some(*s))
        else {
            return Ok(());
        };
        let mut updated = inner.committed[&scope].clone();
        updated.hook_completed = true;
        durable_write(
            &inner.commit_path(&updated.intent.admission_id),
            &encode(&updated)?,
        )
        .map_err(error)?;
        inner.committed.insert(scope, updated);
        Ok(())
    }
}

fn live(record: &AdmissionRecord, now: u64) -> bool {
    !matches!(
        record.disposition,
        DurableDisposition::PolicyDiscard | DurableDisposition::UserDeleted
    ) || now.saturating_sub(record.committed_at) < POLICY_RECEIPT_LIFETIME
}

pub struct FileAdmissionCommit {
    store: FileAdmissionStore,
    record: AdmissionRecord,
    wire: Bytes,
    run_hook: bool,
}
impl DurableAdmissionBackend for FileAdmissionCommit {
    fn commit(self) -> Result<AdmissionRecord, AdmissionError> {
        let mut inner = self.store.inner.lock().unwrap_or_else(|p| p.into_inner());
        let parsed = crate::message::LxMessage::unpack_owned(self.wire.clone(), Default::default())
            .map_err(other)?;
        if parsed.message_id() != self.record.message_id {
            return Err(other("admission message identity mismatch"));
        }
        if let Some(existing) = inner.committed.get(&self.record.scope) {
            if existing.intent.record.received_wire_hash != self.record.received_wire_hash {
                return Err(other("ciphertext TID receipt wire mismatch"));
            }
            if !inner
                .deleted
                .contains_key(&(self.record.scope.identity, self.record.message_id))
                && live(&existing.intent.record, self.record.committed_at)
                && matches!(
                    existing.intent.record.disposition,
                    DurableDisposition::Committed | DurableDisposition::Duplicate
                )
                && self.record.disposition == DurableDisposition::Committed
            {
                inner.validate_body(&existing.intent)?;
                let mut duplicate = existing.intent.record.clone();
                duplicate.disposition = DurableDisposition::Duplicate;
                return Ok(duplicate);
            }
        }
        let mut record = self.record;
        if inner
            .deleted
            .contains_key(&(record.scope.identity, record.message_id))
        {
            record.disposition = DurableDisposition::UserDeleted;
        }
        let invisible = matches!(
            record.disposition,
            DurableDisposition::PolicyDiscard | DurableDisposition::UserDeleted
        );
        if invisible {
            let existing = inner.committed.values().filter(|c| {
                matches!(
                    c.intent.record.disposition,
                    DurableDisposition::PolicyDiscard | DurableDisposition::UserDeleted
                ) && live(&c.intent.record, record.committed_at)
            });
            let global = existing.clone().count();
            let identity = existing
                .filter(|c| c.intent.record.scope.identity == record.scope.identity)
                .count();
            if global >= 65536 || identity >= 16384 {
                return Err(AdmissionError::DispositionLedgerFull);
            }
        }
        let body_path = (!invisible).then(|| {
            inner
                .bodies
                .join(format!("{}.lxm", hex::encode(record.message_id)))
        });
        let mut body = None;
        let mut newly_visible = false;
        if let Some(path) = &body_path {
            match std::fs::metadata(path) {
                Ok(_) => {
                    let existing = read_bounded(path, rns_protocol::resource::MAX_RESOURCE_SIZE)?;
                    // Keep the first immutable archive. Same message ID can have
                    // a different fifth-stamp image; record both hashes.
                    let parsed = crate::message::LxMessage::unpack(&existing).map_err(other)?;
                    if parsed.message_id() != record.message_id {
                        return Err(other("existing archive has a different message ID"));
                    }
                    record.stored_message_wire_hash = Some(rns_crypto::sha::full_hash(&existing));
                    record.disposition = DurableDisposition::Duplicate;
                    body = Some(Bytes::from(existing));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    record.stored_message_wire_hash = Some(record.received_wire_hash);
                    newly_visible = true;
                    body = Some(self.wire.clone());
                }
                Err(e) => return Err(other(e)),
            }
        }
        let admission_id = admission_id(&record.scope)?;
        let intent = AdmissionIntent {
            version: 1,
            admission_id,
            record: record.clone(),
            body_path,
            hook_event: (self.run_hook && newly_visible).then_some(admission_id),
        };
        durable_write(&inner.intent_path(&admission_id), &encode(&intent)?).map_err(error)?;
        if let (Some(path), Some(body)) = (&intent.body_path, body) {
            if newly_visible {
                durable_write(path, &body).map_err(error)?;
            } else {
                durable_reconcile(path, &body).map_err(error)?;
            }
        }
        let commit = AdmissionCommit {
            intent,
            hook_completed: false,
        };
        durable_write(&inner.commit_path(&admission_id), &encode(&commit)?).map_err(error)?;
        inner.committed.insert(record.scope, commit);
        Ok(record)
    }
}

impl Inner {
    fn intent_path(&self, id: &[u8; 32]) -> PathBuf {
        self.journal.join(format!("{}.intent", hex::encode(id)))
    }
    fn commit_path(&self, id: &[u8; 32]) -> PathBuf {
        self.journal.join(format!("{}.commit", hex::encode(id)))
    }
    fn validate_body(&self, intent: &AdmissionIntent) -> Result<(), AdmissionError> {
        if intent.version != 1 || admission_id(&intent.record.scope)? != intent.admission_id {
            return Err(other("unknown admission journal version or identity"));
        }
        if self
            .deleted
            .contains_key(&(intent.record.scope.identity, intent.record.message_id))
            && intent.record.disposition != DurableDisposition::UserDeleted
        {
            return Err(other("message was explicitly deleted"));
        }
        if let Some(path) = &intent.body_path {
            if path.parent() != Some(self.bodies.as_path())
                || path.file_name().and_then(|n| n.to_str())
                    != Some(format!("{}.lxm", hex::encode(intent.record.message_id)).as_str())
            {
                return Err(other("admission archive path escapes configured inbox"));
            }
            let body = read_bounded(path, rns_protocol::resource::MAX_RESOURCE_SIZE)?;
            if Some(rns_crypto::sha::full_hash(&body)) != intent.record.stored_message_wire_hash {
                return Err(other("admission archive content mismatch"));
            }
            // A previous CommitUncertain becomes authoritative only after all
            // native barriers succeed again, never merely after readback.
            durable_reconcile(path, &body).map_err(error)?;
        } else if !matches!(
            intent.record.disposition,
            DurableDisposition::PolicyDiscard | DurableDisposition::UserDeleted
        ) {
            return Err(other("visible admission is missing its archive"));
        }
        Ok(())
    }
    fn recover(&mut self) -> Result<(), AdmissionError> {
        // Stream directory passes: directory size must not itself allocate an
        // unbounded vector. Malformed artifacts remain private and unavailable.
        for file in std::fs::read_dir(&self.journal).map_err(other)? {
            let path = file.map_err(other)?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("deleted") {
                continue;
            }
            let data = read_bounded(&path, 2048)?;
            let tombstone: UserDeletedMessage = rmp_serde::from_slice(&data).map_err(other)?;
            if tombstone.version != 1
                || path.file_name().and_then(|s| s.to_str())
                    != Some(
                        format!(
                            "{}-{}.deleted",
                            hex::encode(tombstone.identity),
                            hex::encode(tombstone.message_id)
                        )
                        .as_str(),
                    )
            {
                return Err(other("invalid user deletion tombstone"));
            }
            let witness = durable_reconcile(&path, &data).map_err(error)?;
            durable_remove(
                &self
                    .bodies
                    .join(format!("{}.lxm", hex::encode(tombstone.message_id))),
                &witness,
            )
            .map_err(error)?;
            self.deleted
                .insert((tombstone.identity, tombstone.message_id), tombstone);
        }
        for file in std::fs::read_dir(&self.journal).map_err(other)? {
            let path = file.map_err(other)?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("commit") {
                continue;
            }
            let result = (|| {
                let data = read_bounded(&path, 16 * 1024)?;
                let commit: AdmissionCommit = rmp_serde::from_slice(&data).map_err(other)?;
                if path != self.commit_path(&commit.intent.admission_id) {
                    return Err(other("commit filename mismatch"));
                }
                self.validate_body(&commit.intent)?;
                durable_reconcile(&path, &data).map_err(error)?;
                Ok(commit)
            })();
            match result {
                Ok(commit) => {
                    self.committed.insert(commit.intent.record.scope, commit);
                }
                Err(error) => {
                    tracing::warn!(%error,path=%path.display(),"unavailable admission preserved without purge authority")
                }
            }
        }
        for file in std::fs::read_dir(&self.journal).map_err(other)? {
            let path = file.map_err(other)?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("intent") {
                continue;
            }
            let result = (|| {
                let data = read_bounded(&path, 16 * 1024)?;
                let intent: AdmissionIntent = rmp_serde::from_slice(&data).map_err(other)?;
                if path != self.intent_path(&intent.admission_id) {
                    return Err(other("intent filename mismatch"));
                }
                if self
                    .committed
                    .get(&intent.record.scope)
                    .is_some_and(|c| c.intent.record == intent.record)
                {
                    return Ok(None);
                }
                self.validate_body(&intent)?;
                durable_reconcile(&path, &data).map_err(error)?;
                let commit = AdmissionCommit {
                    intent,
                    hook_completed: false,
                };
                durable_write(
                    &self.commit_path(&commit.intent.admission_id),
                    &encode(&commit)?,
                )
                .map_err(error)?;
                Ok(Some(commit))
            })();
            match result {
                Ok(Some(commit)) => {
                    self.committed.insert(commit.intent.record.scope, commit);
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error,path=%path.display(),"uncommitted admission preserved without purge authority")
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn committed_receipt_survives_reopen_and_hook_is_in_same_commit() {
        let temp = tempfile::tempdir().unwrap();
        let bodies = temp.path().join("messages");
        let store = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
        let message = crate::message::test_message(
            [1; 16],
            [2; 16],
            "",
            "body",
            crate::constants::DeliveryMethod::Propagated,
        );
        let scope = AdmissionScope {
            identity: [3; 16],
            node: [4; 16],
            transient_id: [5; 32],
        };
        let record = AdmissionRecord {
            scope,
            message_id: message.message_id(),
            received_wire_hash: [0; 32],
            stored_message_wire_hash: None,
            disposition: DurableDisposition::Committed,
            committed_at: 100,
        };
        let receipt = DurableAdmissionReceipt::commit(store.prepare(
            record,
            Bytes::copy_from_slice(message.wire_bytes()),
            true,
        ))
        .unwrap();
        assert_eq!(
            receipt.record().received_wire_hash,
            rns_crypto::sha::full_hash(message.wire_bytes())
        );
        drop(store);
        let recovered = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
        assert_eq!(
            recovered.haves(scope.identity, scope.node, 101),
            vec![scope.transient_id.to_vec()]
        );
        assert_eq!(recovered.pending_hooks().len(), 1);
        recovered
            .complete_hook(recovered.pending_hooks()[0].0)
            .unwrap();
        assert!(recovered.pending_hooks().is_empty());
    }
}
