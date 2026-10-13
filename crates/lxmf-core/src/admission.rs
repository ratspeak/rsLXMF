//! Durable propagation-download admission and non-purging retry policy.
//!
//! A transport Resource proof is not an application receipt. The trusted local
//! adapter implements [`DurableAdmissionBackend`] and commits its body/effects
//! and receipt together before a download token can authorize remote deletion.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

pub const MAX_DOWNLOAD_ITEMS: usize = 4096;
pub const MAX_RETAINED_DOWNLOAD_BYTES: usize = 134_217_727;
pub const MAX_PROCESSING_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_PROCESSORS: usize = 4;
pub const POLICY_RECEIPT_LIFETIME: u64 = 90 * 86400;

/// Exact remote and local ownership of a ciphertext transient ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AdmissionScope {
    pub identity: [u8; 16],
    pub node: [u8; 16],
    pub transient_id: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurableDisposition {
    Committed,
    Duplicate,
    PolicyDiscard,
    UserDeleted,
}

/// Persisted effect identity. A duplicate need not have the same complete wire
/// hash: the optional recipient stamp is excluded from the signed message ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionRecord {
    pub scope: AdmissionScope,
    pub message_id: [u8; 32],
    pub received_wire_hash: [u8; 32],
    pub stored_message_wire_hash: Option<[u8; 32]>,
    pub disposition: DurableDisposition,
    pub committed_at: u64,
}

/// Verified local purge authority with its finite policy lifetime. Adapters
/// supply these only after checking the referenced durable effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableHave {
    pub transient_id: [u8; 32],
    pub expires_at: Option<u64>,
}
impl DurableHave {
    pub fn from_record(record: &AdmissionRecord) -> Self {
        Self {
            transient_id: record.scope.transient_id,
            expires_at: matches!(
                record.disposition,
                DurableDisposition::PolicyDiscard | DurableDisposition::UserDeleted
            )
            .then(|| record.committed_at.saturating_add(POLICY_RECEIPT_LIFETIME)),
        }
    }
    pub fn active(self, now: u64) -> bool {
        self.expires_at.is_none_or(|expiry| now < expiry)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("admission was not committed: {0}")]
    NotCommitted(String),
    #[error("admission publication is uncertain; reconcile all durability barriers: {0}")]
    CommitUncertain(String),
    #[error("durable disposition ledger is full")]
    DispositionLedgerFull,
    #[error("admission scope does not match the downloaded ciphertext")]
    WrongScope,
}

/// Trusted persistence adapter boundary. Implementations must atomically commit
/// the receipt with the message/effect, or reference a previously durable effect.
/// In particular, returning a record after a failed/uncertain filesystem or SQL
/// commit violates this contract. SQLite implementations use the dedicated FULL
/// connection; file implementations use the intent/body/commit journal.
pub trait DurableAdmissionBackend {
    fn commit(self) -> Result<AdmissionRecord, AdmissionError>;
}

#[derive(Debug)]
pub struct DurableAdmissionReceipt {
    record: AdmissionRecord,
}

impl DurableAdmissionReceipt {
    pub fn commit(backend: impl DurableAdmissionBackend) -> Result<Self, AdmissionError> {
        Ok(Self {
            record: backend.commit()?,
        })
    }

    pub fn record(&self) -> &AdmissionRecord {
        &self.record
    }
}

/// Persisted, deterministic epochs; never reset these to a process generation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionEpochs {
    pub policy: [u8; 32],
    pub keys: [u8; 32],
    pub budget: [u8; 32],
    pub storage_health: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuppressionReason {
    Malformed,
    WrongDestination,
    InvalidSignature,
    InvalidStamp,
    DecryptionFailed,
    TooLarge,
    MissingKey,
    StorageUnavailable,
    StorageBusy,
    Quota,
    WorkerUnavailable,
    DispositionLedgerFull,
    Cancelled,
}

impl SuppressionReason {
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            Self::MissingKey
                | Self::StorageUnavailable
                | Self::StorageBusy
                | Self::Quota
                | Self::WorkerUnavailable
                | Self::DispositionLedgerFull
                | Self::Cancelled
        )
    }

    fn epoch_matches(self, before: AdmissionEpochs, now: AdmissionEpochs) -> bool {
        match self {
            Self::DecryptionFailed | Self::MissingKey => before.keys == now.keys,
            Self::InvalidSignature => before.keys == now.keys && before.policy == now.policy,
            Self::TooLarge => before.budget == now.budget,
            Self::StorageUnavailable
            | Self::StorageBusy
            | Self::Quota
            | Self::DispositionLedgerFull => before.storage_health == now.storage_health,
            _ => before.policy == now.policy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRecord {
    pub scope: AdmissionScope,
    pub reason: SuppressionReason,
    pub epochs: AdmissionEpochs,
    pub attempts: u16,
    pub last_failure: u64,
    pub next_retry: u64,
    pub expires_at: u64,
}

impl SuppressionRecord {
    pub fn active(&self, now: u64, epochs: AdmissionEpochs) -> bool {
        now < self.expires_at
            && now < self.next_retry
            && self.reason.epoch_matches(self.epochs, epochs)
    }
}

/// Quotas bound metadata independently of message bytes. Full ledgers preserve
/// existing entries and pause new wants, rather than evicting into a retry loop.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuppressionLedger {
    records: HashMap<AdmissionScope, SuppressionRecord>,
}

impl SuppressionLedger {
    pub const PER_NODE: usize = 4096;
    pub const PER_IDENTITY: usize = 16384;
    pub const GLOBAL: usize = 65536;

    /// Restore typed rows only after duplicate and quota validation. Never
    /// silently overwrite persisted scope decisions during hydration.
    pub fn from_records(
        records: impl IntoIterator<Item = SuppressionRecord>,
    ) -> Result<Self, AdmissionError> {
        let mut ledger = Self::default();
        let mut identities = HashMap::<[u8; 16], usize>::new();
        let mut nodes = HashMap::<([u8; 16], [u8; 16]), usize>::new();
        for record in records {
            if ledger.records.contains_key(&record.scope) {
                return Err(AdmissionError::NotCommitted(
                    "duplicate suppression scope".into(),
                ));
            }
            if record.attempts == 0
                || record.next_retry < record.last_failure
                || record.expires_at <= record.last_failure
                || record.expires_at > record.last_failure.saturating_add(30 * 86400)
            {
                return Err(AdmissionError::NotCommitted(
                    "invalid suppression interval".into(),
                ));
            }
            let identity = identities.entry(record.scope.identity).or_default();
            let node = nodes
                .entry((record.scope.identity, record.scope.node))
                .or_default();
            if ledger.records.len() >= Self::GLOBAL
                || *identity >= Self::PER_IDENTITY
                || *node >= Self::PER_NODE
            {
                return Err(AdmissionError::DispositionLedgerFull);
            }
            *identity += 1;
            *node += 1;
            ledger.records.insert(record.scope, record);
        }
        Ok(ledger)
    }

    pub fn records(&self) -> impl Iterator<Item = &SuppressionRecord> {
        self.records.values()
    }
    pub fn get(&self, scope: &AdmissionScope) -> Option<&SuppressionRecord> {
        self.records.get(scope)
    }
    pub fn remove(&mut self, scope: &AdmissionScope) {
        self.records.remove(scope);
    }
    pub fn prune(&mut self, now: u64, epochs: AdmissionEpochs) {
        self.records.retain(|_, record| {
            now < record.expires_at && record.reason.epoch_matches(record.epochs, epochs)
        });
    }
    pub fn saturated(&self, identity: [u8; 16], node: [u8; 16]) -> bool {
        self.records.len() >= Self::GLOBAL
            || self
                .records
                .keys()
                .filter(|k| k.identity == identity)
                .count()
                >= Self::PER_IDENTITY
            || self
                .records
                .keys()
                .filter(|k| k.identity == identity && k.node == node)
                .count()
                >= Self::PER_NODE
    }
    pub fn record_failure(
        &mut self,
        scope: AdmissionScope,
        reason: SuppressionReason,
        epochs: AdmissionEpochs,
        now: u64,
    ) -> Result<&SuppressionRecord, AdmissionError> {
        self.prune(now, epochs);
        if !self.records.contains_key(&scope) && self.saturated(scope.identity, scope.node) {
            return Err(AdmissionError::DispositionLedgerFull);
        }
        let attempts = self
            .records
            .get(&scope)
            .filter(|r| r.reason == reason)
            .map_or(1, |r| r.attempts.saturating_add(1));
        let (next_retry, expires_at) = if reason.is_transient() {
            let base = (60u64 << attempts.saturating_sub(1).min(6)).min(3600);
            // Stable +/-10% jitter avoids synchronized retries after restart.
            let jitter =
                u16::from_be_bytes([scope.transient_id[0], scope.transient_id[1]]) as u64 % 21;
            (
                now.saturating_add(base * (90 + jitter) / 100),
                now.saturating_add(86400),
            )
        } else {
            (
                now.saturating_add(30 * 86400),
                now.saturating_add(30 * 86400),
            )
        };
        self.records.insert(
            scope,
            SuppressionRecord {
                scope,
                reason,
                epochs,
                attempts,
                last_failure: now,
                next_retry,
                expires_at,
            },
        );
        Ok(&self.records[&scope])
    }
}

#[derive(Debug)]
pub enum DownloadAdmissionOutcome {
    Accepted(DurableAdmissionReceipt),
    Rejected(SuppressionReason),
}

pub(crate) struct AdmissionResolution {
    pub generation: u64,
    pub scope: AdmissionScope,
    pub outcome: DownloadAdmissionOutcome,
}

/// Single-use, generation-bound authority. Dropping it reports a retryable
/// failure; cancelling its client generation cannot cancel a blocking commit.
pub struct DownloadAdmissionToken {
    scope: AdmissionScope,
    generation: u64,
    current_generation: Arc<AtomicU64>,
    tx: Option<mpsc::UnboundedSender<AdmissionResolution>>,
}

impl std::fmt::Debug for DownloadAdmissionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadAdmissionToken")
            .field("scope", &self.scope)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl DownloadAdmissionToken {
    pub(crate) fn new(
        scope: AdmissionScope,
        generation: u64,
        current_generation: Arc<AtomicU64>,
        tx: mpsc::UnboundedSender<AdmissionResolution>,
    ) -> Self {
        Self {
            scope,
            generation,
            current_generation,
            tx: Some(tx),
        }
    }
    pub fn scope(&self) -> AdmissionScope {
        self.scope
    }
    /// Check immediately after durable commit before publishing current-generation effects.
    /// Cancellation cannot stop an in-flight commit or release its memory lease.
    pub fn is_current(&self) -> bool {
        self.current_generation.load(Ordering::Acquire) == self.generation
    }
    pub fn resolve(mut self, outcome: DownloadAdmissionOutcome) -> Result<(), AdmissionError> {
        if let DownloadAdmissionOutcome::Accepted(receipt) = &outcome
            && receipt.record.scope != self.scope
        {
            return Err(AdmissionError::WrongScope);
        }
        if !self.is_current() {
            self.tx.take();
            return Err(AdmissionError::NotCommitted(
                "download generation was revoked".into(),
            ));
        }
        let tx = self.tx.take().ok_or_else(|| {
            AdmissionError::NotCommitted("download authority already consumed".into())
        })?;
        tx.send(AdmissionResolution {
            generation: self.generation,
            scope: self.scope,
            outcome,
        })
        .map_err(|_| AdmissionError::NotCommitted("download consumer is closed".into()))?;
        // The client rechecks the exact generation while consuming. This result
        // reports enqueue only; adapters need their lifecycle gate around any
        // current-generation UI effects, not an atomic-cancellation promise.
        if !self.is_current() {
            return Err(AdmissionError::NotCommitted(
                "download generation was revoked".into(),
            ));
        }
        Ok(())
    }
}

impl Drop for DownloadAdmissionToken {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(AdmissionResolution {
                generation: self.generation,
                scope: self.scope,
                outcome: DownloadAdmissionOutcome::Rejected(SuppressionReason::Cancelled),
            });
        }
    }
}

#[derive(Debug)]
pub struct DownloadedPropagationMessage {
    data: Bytes,
    token: DownloadAdmissionToken,
}

impl DownloadedPropagationMessage {
    pub(crate) fn new(data: Bytes, token: DownloadAdmissionToken) -> Self {
        Self { data, token }
    }
    pub fn data(&self) -> &Bytes {
        &self.data
    }
    pub fn scope(&self) -> AdmissionScope {
        self.token.scope
    }
    pub fn into_parts(self) -> (Bytes, DownloadAdmissionToken) {
        (self.data, self.token)
    }
}

fn raw_budget() -> &'static Arc<Semaphore> {
    static BUDGET: OnceLock<Arc<Semaphore>> = OnceLock::new();
    BUDGET.get_or_init(|| Arc::new(Semaphore::new(MAX_RETAINED_DOWNLOAD_BYTES)))
}

struct RetainedResponse {
    bytes: Bytes,
    _credit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for RetainedResponse {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Credit follows every Bytes clone/slice, including payloads in cancelled
/// blocking workers. Moving a response out of the client never releases it.
pub(crate) fn retain_response(
    bytes: Bytes,
    local_limit: usize,
) -> Result<Bytes, SuppressionReason> {
    if bytes.len() > local_limit.min(MAX_RETAINED_DOWNLOAD_BYTES) {
        return Err(SuppressionReason::TooLarge);
    }
    let credit = raw_budget()
        .clone()
        .try_acquire_many_owned(bytes.len() as u32)
        .map_err(|_| SuppressionReason::WorkerUnavailable)?;
    Ok(Bytes::from_owner(RetainedResponse {
        bytes,
        _credit: credit,
    }))
}

/// Full peak reservation is obtained before decrypting while raw ciphertext is
/// retained separately. Never wait for a partial reservation while holding the
/// parent response. This bounds Rust-owned buffers, not SQLite's native heap.
fn processing_budget() -> &'static Arc<Semaphore> {
    static BYTES: OnceLock<Arc<Semaphore>> = OnceLock::new();
    BYTES.get_or_init(|| Arc::new(Semaphore::new(MAX_PROCESSING_BYTES)))
}

/// Additional explicitly bounded adapter state, sharing the processing byte
/// budget without taking a second worker slot. Admission is always nonblocking.
pub struct ProcessingMemoryLease {
    _bytes: OwnedSemaphorePermit,
}
impl ProcessingMemoryLease {
    pub fn try_acquire(amount: usize) -> Result<Self, SuppressionReason> {
        if amount > MAX_PROCESSING_BYTES {
            return Err(SuppressionReason::TooLarge);
        }
        Ok(Self {
            _bytes: processing_budget()
                .clone()
                .try_acquire_many_owned(amount as u32)
                .map_err(|_| SuppressionReason::WorkerUnavailable)?,
        })
    }
}

pub struct ProcessingLease {
    _bytes: OwnedSemaphorePermit,
    _worker: OwnedSemaphorePermit,
}

impl ProcessingLease {
    pub fn try_acquire(cipher_len: usize) -> Result<Self, SuppressionReason> {
        static WORKERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let amount = cipher_len
            .checked_mul(4)
            .and_then(|v| v.checked_add(128 * 1024 + 256))
            .filter(|v| *v <= MAX_PROCESSING_BYTES)
            .ok_or(SuppressionReason::TooLarge)?;
        let bytes = processing_budget()
            .clone()
            .try_acquire_many_owned(amount as u32)
            .map_err(|_| SuppressionReason::WorkerUnavailable)?;
        let worker = WORKERS
            .get_or_init(|| Arc::new(Semaphore::new(MAX_PROCESSORS)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| SuppressionReason::WorkerUnavailable)?;
        Ok(Self {
            _bytes: bytes,
            _worker: worker,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope(n: u8) -> AdmissionScope {
        AdmissionScope {
            identity: [1; 16],
            node: [2; 16],
            transient_id: [n; 32],
        }
    }
    #[test]
    fn resolution_rejects_revoked_generation_and_closed_consumer() {
        let generation = Arc::new(AtomicU64::new(1));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let token = DownloadAdmissionToken::new(scope(1), 1, generation.clone(), tx.clone());
        generation.store(2, Ordering::Release);
        assert!(
            token
                .resolve(DownloadAdmissionOutcome::Rejected(
                    SuppressionReason::Cancelled
                ))
                .is_err()
        );
        assert!(rx.try_recv().is_err());
        let token = DownloadAdmissionToken::new(scope(2), 2, generation, tx);
        drop(rx);
        assert!(
            token
                .resolve(DownloadAdmissionOutcome::Rejected(
                    SuppressionReason::Cancelled
                ))
                .is_err()
        );
    }
    #[test]
    fn permanent_failures_revalidate_on_epoch_change_or_expiry() {
        let mut ledger = SuppressionLedger::default();
        let epoch = AdmissionEpochs::default();
        let r = ledger
            .record_failure(scope(1), SuppressionReason::DecryptionFailed, epoch, 100)
            .unwrap();
        assert!(r.active(101, epoch));
        let mut changed = epoch;
        changed.keys[0] = 1;
        assert!(!r.active(101, changed));
        assert!(!r.active(100 + 30 * 86400, epoch));
        assert!(rmp_serde::to_vec(r).unwrap().len() <= 512);
    }
    #[test]
    fn temporary_storage_failure_is_retryable_and_bounded() {
        let mut ledger = SuppressionLedger::default();
        for _ in 0..20 {
            ledger
                .record_failure(
                    scope(1),
                    SuppressionReason::StorageBusy,
                    AdmissionEpochs::default(),
                    100,
                )
                .unwrap();
        }
        let r = ledger.get(&scope(1)).unwrap();
        assert!((3340..=4060).contains(&r.next_retry));
        assert_eq!(r.expires_at, 86500);
    }
    #[test]
    fn full_node_ledger_does_not_evict_existing_suppression() {
        let mut ledger = SuppressionLedger::default();
        for n in 0..SuppressionLedger::PER_NODE {
            let mut s = scope(0);
            s.transient_id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            ledger
                .record_failure(
                    s,
                    SuppressionReason::Malformed,
                    AdmissionEpochs::default(),
                    100,
                )
                .unwrap();
        }
        assert!(
            ledger
                .record_failure(
                    scope(255),
                    SuppressionReason::Malformed,
                    AdmissionEpochs::default(),
                    100
                )
                .is_err()
        );
        assert_eq!(ledger.records().count(), SuppressionLedger::PER_NODE);
    }
    #[test]
    fn impossible_processing_size_rejects_without_partial_wait() {
        assert!(matches!(
            ProcessingLease::try_acquire(MAX_PROCESSING_BYTES),
            Err(SuppressionReason::TooLarge)
        ));
    }
}
