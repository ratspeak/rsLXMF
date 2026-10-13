//! Store-and-forward propagation node with optional disk persistence.
//!
//! Mirrors propagation node management in Python LXMRouter.py. Provides
//! message acceptance with size/duplicate checks, sync offer generation with
//! per-peer filtering, peer persistence (save/load with handled message sets),
//! and expired message culling with orphaned file cleanup.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::constants::*;
use crate::peer::{LxmPeer, OutboundOfferPolicy};
use crate::propagation::{PropagationEntry, PropagationStore, hex_encode};
use crate::propagation_admission::PnOfferCandidate;
use crate::propagation_offer::{PnOfferEvaluation, PnOfferEvaluationError};
use crate::sync::{OfferResponse, SyncGet, SyncOffer, SyncSession};
use crate::types::PropagationTransientId;

#[derive(Debug, Clone)]
pub struct PropagationNodeConfig {
    pub max_storage: usize,
    pub max_message_age: u64,
    /// Messages below this effective stamp value are rejected. Python derives
    /// this from `propagation_stamp_cost - propagation_stamp_cost_flexibility`.
    pub min_stamp_cost: u8,
    pub peering_cost: u8,
    pub max_message_size: usize,
    /// Maximum encoded inbound `/offer` request size. This follows the
    /// node's advertised propagation sync budget.
    pub max_offer_size: usize,
}

impl Default for PropagationNodeConfig {
    fn default() -> Self {
        Self {
            max_storage: PROPAGATION_LIMIT * 1024 * 1024,
            max_message_age: MESSAGE_EXPIRY,
            // Disabled by default; set to PROPAGATION_COST for production.
            min_stamp_cost: 0,
            peering_cost: PEERING_COST,
            max_message_size: DELIVERY_LIMIT * BYTES_PER_KILOBYTE,
            max_offer_size: SYNC_LIMIT * BYTES_PER_KILOBYTE,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OfferRequestContext<'a> {
    pub peer_hash: [u8; 16],
    pub identity_known: bool,
    pub is_throttled: bool,
    pub access_allowed: bool,
    pub local_identity_hash: Option<&'a [u8; 16]>,
    pub remote_identity_hash: Option<&'a [u8; 16]>,
}

/// Borrow the validated ID lists; never expand untrusted GET input to a Value tree.
struct BorrowedGetRequest<'a> {
    wants: Option<&'a [u8]>,
    haves: Option<&'a [u8]>,
    limit_bytes: Option<f64>,
}
fn parse_get_request(mut input: &[u8]) -> Option<BorrowedGetRequest<'_>> {
    let count = rmp::decode::read_array_len(&mut input).ok()?;
    if !(2..=3).contains(&count) {
        return None;
    }
    fn ids<'a>(input: &mut &'a [u8]) -> Option<Option<&'a [u8]>> {
        if input.first() == Some(&0xc0) {
            *input = &input[1..];
            return Some(None);
        }
        let count = rmp::decode::read_array_len(input).ok()? as usize;
        if count > input.len() / 34 {
            return None;
        }
        let start = *input;
        for _ in 0..count {
            if rmp::decode::read_bin_len(input).ok()? != 32 || input.len() < 32 {
                return None;
            }
            *input = &input[32..];
        }
        Some(Some(&start[..start.len() - input.len()]))
    }
    let wants = ids(&mut input)?;
    let haves = ids(&mut input)?;
    let limit_bytes = if count == 3 {
        // Only one scalar number is decoded; containers and strings are refused
        // before the general decoder can allocate.
        if !matches!(
            input.first(),
            Some(0x00..=0x7f | 0xca..=0xcf | 0xd0..=0xd3 | 0xe0..=0xff)
        ) {
            return None;
        }
        let value = rmpv::decode::read_value(&mut input).ok()?;
        let kb = value
            .as_f64()
            .or_else(|| value.as_u64().map(|v| v as f64))
            .or_else(|| value.as_i64().map(|v| v as f64))?;
        let bytes = kb * BYTES_PER_KILOBYTE as f64;
        if !kb.is_finite() || kb < 0.0 || !bytes.is_finite() {
            return None;
        }
        Some(bytes)
    } else {
        None
    };
    input.is_empty().then_some(BorrowedGetRequest {
        wants,
        haves,
        limit_bytes,
    })
}
fn get_ids(input: Option<&[u8]>) -> impl Iterator<Item = PropagationTransientId> + '_ {
    let mut input = input.unwrap_or_default();
    std::iter::from_fn(move || {
        if input.is_empty() {
            return None;
        }
        rmp::decode::read_bin_len(&mut input).expect("validated ID");
        let id = input[..32].try_into().expect("validated ID length");
        input = &input[32..];
        Some(id)
    })
}

/// Outcome of [`PropagationNode::handle_get_request`]. Phases 1/3 (and
/// malformed input) are answered from the store alone; phase 2 returns a
/// read plan so the embedder performs blocking file I/O after releasing
/// the node lock.
#[derive(Debug)]
pub enum GetRequestAction {
    Respond(Vec<u8>),
    ServeFiles(GetServePlan),
}

impl GetRequestAction {
    /// Resolve to response bytes, performing any planned file reads inline.
    /// Blocking; do not call while holding a shared node lock.
    pub fn into_response(self) -> Vec<u8> {
        self.into_response_with_served_count().0
    }

    /// Resolve the response and report how many messages were actually read
    /// and admitted by the client's transfer limit. This lets the daemon keep
    /// Python-compatible served-message accounting without repeating I/O.
    pub fn into_response_with_served_count(self) -> (Vec<u8>, u64) {
        self.into_response_with_served_count_bounded(rns_protocol::resource::MAX_RESOURCE_SIZE)
    }

    /// Resolve on a blocking worker with its previously reserved local response
    /// allowance. Complete messages are skipped when they cannot fit.
    pub fn into_response_with_served_count_bounded(self, maximum: usize) -> (Vec<u8>, u64) {
        match self {
            GetRequestAction::Respond(bytes) if bytes.len() <= maximum => (bytes, 0),
            GetRequestAction::Respond(_) => (vec![0xc0], 0),
            GetRequestAction::ServeFiles(plan) => plan.serve_with_count_bounded(maximum),
        }
    }
}

/// Phase-2 read plan: wants resolved and ownership-gated under the node
/// lock; [`GetServePlan::serve`] does the file reads outside it.
#[derive(Debug)]
pub struct GetServePlan {
    reads: Vec<PlannedRead>,
    retirements: PropagationRetirementPlan,
    /// Client transfer limit in bytes (wire value is kB ×1000, Python parity).
    limit_bytes: Option<f64>,
}

#[derive(Debug)]
struct PlannedRead {
    path: PathBuf,
    stamped: bool,
    stored_size: usize,
}

impl GetServePlan {
    /// Read planned files and encode the phase-2 response. Mirrors Python
    /// LXMRouter.message_get_request limit accounting (LXMRouter.py:1477-1494):
    /// 24-byte base + 16 bytes per message, full stored size counted,
    /// over-limit entries skipped (not a transfer abort), stamps stripped
    /// for client download. Unreadable files are skipped.
    pub fn serve(&self) -> Vec<u8> {
        self.serve_with_count().0
    }

    fn serve_with_count(&self) -> (Vec<u8>, u64) {
        self.serve_with_count_bounded(rns_protocol::resource::MAX_RESOURCE_SIZE)
    }

    fn serve_with_count_bounded(&self, maximum: usize) -> (Vec<u8>, u64) {
        let maximum = maximum.min(rns_protocol::resource::MAX_RESOURCE_SIZE);
        if maximum < 5 {
            return (vec![0xc0], 0);
        }

        if self.retirements.persist().is_err() {
            return (vec![0xc0], 0);
        }
        const PER_MESSAGE_OVERHEAD: f64 = 16.0;
        let mut cumulative_size: f64 = 24.0;
        // Reserve one fixed-size output image. A single bounded verified file
        // exists alongside it; no stripped copy or recursive Value tree does.
        let mut response = Vec::new();
        let allocation = self
            .reads
            .iter()
            .fold(5usize, |size, read| {
                size.saturating_add(read.stored_size).saturating_add(5)
            })
            .min(maximum);
        if response.try_reserve_exact(allocation).is_err() {
            return (vec![0xc0], 0);
        }
        let mut served = 0u32;

        for read in &self.reads {
            let Some(payload_size) =
                read.stored_size
                    .checked_sub(if read.stamped { 32 } else { 0 })
            else {
                continue;
            };
            let prefix = if payload_size <= u8::MAX as usize {
                2
            } else if payload_size <= u16::MAX as usize {
                3
            } else {
                5
            };
            let array_prefix = if served + 1 < 16 {
                1
            } else if served < u16::MAX as u32 {
                3
            } else {
                5
            };
            if payload_size
                .checked_add(prefix)
                .and_then(|size| response.len().checked_add(size))
                .and_then(|size| size.checked_add(array_prefix))
                .is_none_or(|size| size > maximum)
            {
                continue;
            }
            let next_size = cumulative_size + read.stored_size as f64 + PER_MESSAGE_OVERHEAD;
            if self.limit_bytes.is_some_and(|limit| next_size > limit) {
                continue;
            }
            let Ok(data) = crate::propagation_store_v2::read_validated_file_bounded(
                &read.path,
                read.stored_size,
            ) else {
                continue;
            };
            if data.len() != read.stored_size {
                continue;
            }
            cumulative_size = next_size;
            if prefix == 2 {
                response.extend_from_slice(&[0xc4, payload_size as u8]);
            } else if prefix == 3 {
                response.push(0xc5);
                response.extend_from_slice(&(payload_size as u16).to_be_bytes());
            } else {
                response.push(0xc6);
                response.extend_from_slice(&(payload_size as u32).to_be_bytes());
            }
            response.extend_from_slice(&data[..payload_size]);
            served += 1;
        }

        // Prepend the canonical array header in the already reserved buffer.
        let header: Vec<u8> = if served < 16 {
            vec![0x90 | served as u8]
        } else if served <= u16::MAX as u32 {
            let mut h = vec![0xdc];
            h.extend_from_slice(&(served as u16).to_be_bytes());
            h
        } else {
            let mut h = vec![0xdd];
            h.extend_from_slice(&served.to_be_bytes());
            h
        };
        let payload_len = response.len();
        let final_len = payload_len + header.len();
        response.resize(final_len, 0);
        response.copy_within(0..payload_len, header.len());
        response[..header.len()].copy_from_slice(&header);
        response.truncate(final_len);
        (response, u64::from(served))
    }
}

/// Committed retirements become invisible immediately, including to snapshots
/// captured while a blocking deletion worker was running. A node later reaps
/// counters under its short owner lock.
#[derive(Debug, Default)]
struct RetiredEntries {
    ids: std::sync::Mutex<HashSet<PathBuf>>,
    generation: std::sync::atomic::AtomicU64,
}
impl RetiredEntries {
    fn contains(&self, id: &PathBuf) -> bool {
        self.ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(id)
    }
    fn commit(&self, id: PathBuf) {
        if self
            .ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id)
        {
            // Rust 1.99 renamed this operation; keep the identical Rust 1.89 API.
            #[allow(deprecated)]
            let _ = self.generation.fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |v| Some(v.saturating_add(1)),
            );
        }
    }
}
/// Blocking durable cull/purge work. Capture under the node lock; run on a
/// bounded blocking worker after releasing it. Failed publication retains the
/// active entry and cannot authorize a successful remote purge response.
#[derive(Debug)]
pub struct PropagationRetirementPlan {
    entries: Vec<PathBuf>,
    retired: std::sync::Arc<RetiredEntries>,
}
impl PropagationRetirementPlan {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn persist(&self) -> std::io::Result<()> {
        for path in &self.entries {
            if self.retired.contains(path) {
                continue;
            }
            crate::propagation_store_v2::retire_object(path)?;
            self.retired.commit(path.clone());
        }
        Ok(())
    }
}

/// One pending store-file read produced by
/// [`PropagationNode::plan_message_reads`].
#[derive(Debug)]
pub struct PlannedMessageRead {
    pub transient_id: PropagationTransientId,
    pub path: PathBuf,
}

/// Blocking reads for a plan from [`PropagationNode::plan_message_reads`];
/// call without holding the node lock. Missing/unreadable files are skipped.
pub fn read_planned_messages(
    plan: &[PlannedMessageRead],
) -> Vec<(PropagationTransientId, Vec<u8>)> {
    plan.iter()
        .filter_map(|read| {
            crate::propagation_store_v2::read_validated_file(&read.path)
                .ok()
                .map(|data| (read.transient_id, data))
        })
        .collect()
}

/// An opaque stamped deposit with validated stamp work. Construction does not
/// claim the relay can decrypt or mathematically identify ciphertext.
#[derive(Debug)]
pub struct ValidatedOpaquePropagationBlob {
    bytes: bytes::Bytes,
    transient_id: PropagationTransientId,
    stamp_value: u8,
}
impl ValidatedOpaquePropagationBlob {
    pub fn validate(bytes: bytes::Bytes, minimum_stamp_cost: u8) -> Option<Self> {
        if bytes.len() < DESTINATION_LENGTH + 1 + 32
            || bytes.len() > rns_protocol::resource::MAX_RESOURCE_SIZE
        {
            return None;
        }
        let body = &bytes[..bytes.len() - 32];
        let stamp: &[u8; 32] = bytes[bytes.len() - 32..].try_into().ok()?;
        let transient_id = rns_crypto::sha::full_hash(body);
        let workblock =
            crate::stamper::stamp_workblock(&transient_id, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN);
        let stamp_value = crate::stamper::stamp_value(&workblock, stamp).min(255) as u8;
        (stamp_value >= minimum_stamp_cost).then_some(Self {
            bytes,
            transient_id,
            stamp_value,
        })
    }
    pub fn transient_id(&self) -> PropagationTransientId {
        self.transient_id
    }
    pub fn stamp_value(&self) -> u8 {
        self.stamp_value
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationAdmissionOutcome {
    Pending,
    Committed,
    Failed,
}
#[derive(Debug)]
struct AdmissionReservation {
    content_hash: [u8; 32],
    size: usize,
    result: tokio::sync::watch::Sender<PropagationAdmissionOutcome>,
}
impl Drop for AdmissionReservation {
    fn drop(&mut self) {
        if *self.result.borrow() == PropagationAdmissionOutcome::Pending {
            self.result
                .send_replace(PropagationAdmissionOutcome::Failed);
        }
    }
}
/// Await only outside validation/storage worker slots. This observer cannot
/// persist, commit, revoke, or manufacture another admission's authority.
#[derive(Debug)]
pub struct PropagationAdmissionWaiter {
    result: tokio::sync::watch::Receiver<PropagationAdmissionOutcome>,
}
impl PropagationAdmissionWaiter {
    pub async fn wait(mut self) -> PropagationAdmissionOutcome {
        loop {
            let current = *self.result.borrow_and_update();
            if current != PropagationAdmissionOutcome::Pending {
                return current;
            }
            if self.result.changed().await.is_err() {
                return PropagationAdmissionOutcome::Failed;
            }
        }
    }
}
/// Revalidate retained ciphertext and its committed provenance off the actor
/// before a duplicate can earn a proof.
#[derive(Debug)]
pub struct PropagationDuplicateCheck {
    path: PathBuf,
}
impl PropagationDuplicateCheck {
    pub fn verify(self) -> std::io::Result<()> {
        crate::propagation_store_v2::verify_committed_object(&self.path)
    }
}
#[derive(Debug)]
pub enum PropagationAdmission {
    Reserved(Box<PropagationStoreWritePlan>),
    CommittedDuplicate(PropagationDuplicateCheck),
    Pending(PropagationAdmissionWaiter),
    Rejected,
}

/// One propagation-store admission reserved under the node lock. Persist it
/// on a blocking worker, then commit the returned value under a short lock.
#[derive(Debug)]
pub struct PropagationStoreWritePlan {
    entry: PropagationEntry,
    data: Vec<u8>,
    manifest: crate::propagation_store_v2::EntryManifest,
    reservation: std::sync::Arc<AdmissionReservation>,
    path: Option<PathBuf>,
}

impl PropagationStoreWritePlan {
    pub fn transient_id(&self) -> PropagationTransientId {
        self.entry.transient_id
    }

    pub fn size(&self) -> usize {
        self.entry.size
    }

    /// Perform the potentially blocking durable write. Disk-backed nodes use
    /// strict platform publication; volatile nodes cannot acknowledge storage.
    pub fn persist(self) -> std::io::Result<PersistedPropagationStoreWrite> {
        let path = self.path.as_ref().ok_or_else(|| {
            std::io::Error::other("volatile propagation nodes cannot issue durable admission")
        })?;
        if crate::propagation_store_v2::deletion_path(path).exists() {
            return Err(std::io::Error::other(
                "prior relay deletion needs reconciliation before readmission",
            ));
        }
        let (manifest, path) =
            crate::propagation_store_v2::publish_object(path, &self.manifest, &self.data)?;
        Ok(PersistedPropagationStoreWrite {
            entry: manifest.entry(),
            path: Some(path),
            reservation: self.reservation,
        })
    }
}

/// Durable half of a propagation-store admission, ready for an in-memory
/// commit under the node lock.
#[derive(Debug)]
pub struct PersistedPropagationStoreWrite {
    entry: PropagationEntry,
    path: Option<PathBuf>,
    reservation: std::sync::Arc<AdmissionReservation>,
}

#[derive(Debug, Clone)]
pub(crate) struct SyncOfferCandidateSnapshot {
    transient_id: PropagationTransientId,
    weight: f64,
    size: usize,
    stamp_value: u8,
}

/// Cheap, owned view captured while the shared node lock is held. Expensive
/// peer-file loading and full-store sorting happen from this snapshot on a
/// blocking worker.
#[derive(Debug, Clone)]
pub(crate) struct SyncOfferPreparationSnapshot {
    pub policy: OutboundOfferPolicy,
    pub generation: u64,
    peer_path: Option<PathBuf>,
    candidates: Vec<SyncOfferCandidateSnapshot>,
}

#[derive(Debug)]
pub(crate) struct PreparedSyncOffer {
    pub policy: OutboundOfferPolicy,
    pub generation: u64,
    pub selected_ids: Vec<PropagationTransientId>,
    pub terminal_handled_ids: Vec<PropagationTransientId>,
    pub generation_exhausted: bool,
}

#[derive(Debug)]
pub(crate) enum InstallPreparedSyncOffer {
    Installed {
        offer: SyncOffer,
        generation: u64,
        terminal_handled_ids: Vec<PropagationTransientId>,
        generation_exhausted: bool,
    },
    Stale,
}

/// Blocking half of outbound-offer preparation. This function owns its input
/// and never touches a live `PropagationNode` or shared lock.
pub(crate) fn prepare_sync_offer_snapshot(
    snapshot: SyncOfferPreparationSnapshot,
) -> PreparedSyncOffer {
    const PER_MESSAGE_OVERHEAD: usize = 16;
    const INITIAL_STRUCTURE_OVERHEAD: usize = 24;

    let transfer_limit = snapshot
        .policy
        .propagation_transfer_limit
        .map(kilobytes_to_bytes_fail_closed);
    let sync_limit = snapshot
        .policy
        .propagation_sync_limit
        .map(kilobytes_to_bytes_fail_closed);
    let mut handled_messages = snapshot.policy.handled_messages.clone();
    if let Some(path) = snapshot.peer_path.as_ref()
        && let Ok(data) = std::fs::read(path)
        && let Some(peer) = LxmPeer::from_bytes_with_handled(&data)
    {
        handled_messages.extend(peer.handled_messages);
    }

    let mut candidates = snapshot.candidates;
    candidates.sort_by(|left, right| {
        left.weight
            .total_cmp(&right.weight)
            .then_with(|| left.transient_id.cmp(&right.transient_id))
    });

    let mut cumulative_size = INITIAL_STRUCTURE_OVERHEAD;
    let mut selected_ids = Vec::new();
    let mut terminal_handled_ids = Vec::new();
    let mut cumulative_deferred = false;
    for candidate in candidates {
        if handled_messages.contains(&candidate.transient_id) {
            continue;
        }
        if candidate.stamp_value < snapshot.policy.minimum_stamp_cost {
            terminal_handled_ids.push(candidate.transient_id);
            continue;
        }

        let transfer_size = candidate.size.saturating_add(PER_MESSAGE_OVERHEAD);
        if transfer_limit.is_some_and(|limit| transfer_size > limit) {
            terminal_handled_ids.push(candidate.transient_id);
            continue;
        }

        let next_size = cumulative_size.saturating_add(transfer_size);
        if sync_limit.is_some_and(|limit| next_size >= limit) {
            // The cumulative limit is session-local. Keep this candidate
            // pending so a later sync can offer it.
            cumulative_deferred = true;
            continue;
        }

        cumulative_size = next_size;
        selected_ids.push(candidate.transient_id);
    }

    // If not even one candidate fits the peer's cumulative limit, retrying
    // this unchanged generation would only establish another Link and reach
    // the same empty result. Treat that generation as scheduled-and-exhausted
    // for the current constraints. A store revision or material announce
    // policy change re-enables scheduling.
    let generation_exhausted = !cumulative_deferred || selected_ids.is_empty();
    PreparedSyncOffer {
        policy: snapshot.policy,
        generation: snapshot.generation,
        selected_ids,
        terminal_handled_ids,
        generation_exhausted,
    }
}

fn kilobytes_to_bytes_fail_closed(kilobytes: f64) -> usize {
    if !kilobytes.is_finite() || kilobytes <= 0.0 {
        return 0;
    }
    (kilobytes * BYTES_PER_KILOBYTE as f64).floor() as usize
}

pub struct PropagationNode {
    config: PropagationNodeConfig,
    store: PropagationStore,
    sync_sessions: HashMap<[u8; 16], SyncSession>,
    pub dest_hash: [u8; 16],
    storage_path: Option<PathBuf>,
    object_paths: HashMap<PropagationTransientId, PathBuf>,
    _store_lock: Option<std::fs::File>,
    /// Transitional pre-1.1 behavior; removed when the daemon-lifetime
    /// `PnInboundAdmission` becomes the live throttle owner.
    last_offer_times: HashMap<[u8; 16], f64>,
    /// Monotonic in-process revision of the propagation store. Outbound peer
    /// scheduling and offer-preparation revalidation use this to avoid both
    /// stale offers and repeated scans of an unchanged fully-handled store.
    offer_generation: u64,
    /// IDs and bytes reserved by off-lock store writes. Reservations prevent
    /// duplicate acceptance and storage-cap oversubscription while I/O is in
    /// flight.
    pending_write_ids: HashSet<PropagationTransientId>,
    pending_admissions: HashMap<PropagationTransientId, std::sync::Weak<AdmissionReservation>>,
    pending_write_bytes: usize,
    retired: std::sync::Arc<RetiredEntries>,
}

impl PropagationNode {
    /// In-memory node (no disk persistence).
    pub fn new(config: PropagationNodeConfig, dest_hash: [u8; 16]) -> Self {
        Self {
            config,
            store: PropagationStore::new(),
            sync_sessions: HashMap::new(),
            dest_hash,
            storage_path: None,
            object_paths: HashMap::new(),
            _store_lock: None,
            last_offer_times: HashMap::new(),
            offer_generation: 0,
            pending_write_ids: HashSet::new(),
            pending_admissions: HashMap::new(),
            pending_write_bytes: 0,
            retired: std::sync::Arc::new(RetiredEntries::default()),
        }
    }

    pub fn is_durable(&self) -> bool {
        self.storage_path.is_some()
    }

    pub fn min_stamp_cost(&self) -> u8 {
        self.config.min_stamp_cost
    }

    pub fn set_min_stamp_cost(&mut self, cost: u8) {
        self.config.min_stamp_cost = cost;
    }

    pub fn offer_generation(&self) -> u64 {
        self.offer_generation.saturating_add(
            self.retired
                .generation
                .load(std::sync::atomic::Ordering::Acquire),
        )
    }

    /// Apply the daemon's destination deny policy to the authoritative hosted
    /// store. The reusable router has its own optional store, so production
    /// wiring must configure this node explicitly as well.
    pub fn ignore_destination(&mut self, dest_hash: [u8; 16]) {
        self.store.ignore_destination(dest_hash);
    }

    pub fn unignore_destination(&mut self, dest_hash: &[u8; 16]) {
        self.store.unignore_destination(dest_hash);
    }

    pub fn is_destination_ignored(&self, dest_hash: &[u8; 16]) -> bool {
        self.store.is_destination_ignored(dest_hash)
    }

    /// Apply the daemon's culling-priority policy to the authoritative hosted
    /// store.
    pub fn prioritise_destination(&mut self, dest_hash: [u8; 16]) {
        self.store.prioritise_destination(dest_hash);
    }

    pub fn unprioritise_destination(&mut self, dest_hash: &[u8; 16]) {
        self.store.unprioritise_destination(dest_hash);
    }

    fn advance_offer_generation(&mut self) {
        self.offer_generation = self.offer_generation.saturating_add(1);
    }

    /// Disk-backed node. Loads existing messages from `storage_path` on startup.
    pub fn with_storage(
        config: PropagationNodeConfig,
        dest_hash: [u8; 16],
        storage_path: PathBuf,
    ) -> std::io::Result<Self> {
        let (storage_path, lock) = crate::propagation_store_v2::open_locked_store(&storage_path)?;
        let mut node = Self {
            config,
            store: PropagationStore::new(),
            sync_sessions: HashMap::new(),
            dest_hash,
            storage_path: Some(storage_path),
            object_paths: HashMap::new(),
            _store_lock: Some(lock),
            last_offer_times: HashMap::new(),
            offer_generation: 0,
            pending_write_ids: HashSet::new(),
            pending_admissions: HashMap::new(),
            pending_write_bytes: 0,
            retired: std::sync::Arc::new(RetiredEntries::default()),
        };
        node.load_from_disk()?;
        Ok(node)
    }

    fn reserve_store_write(
        &mut self,
        entry: PropagationEntry,
        data: Vec<u8>,
    ) -> Option<PropagationStoreWritePlan> {
        self.reap_retired();
        let transient_id = entry.transient_id;
        if self.store.contains(&transient_id) || self.pending_write_ids.contains(&transient_id) {
            return None;
        }
        // Python checks the current store size before inserting and permits
        // the message that crosses the cap; the next admission is rejected
        // until culling makes room. Include reservations in that current-size
        // view so concurrent writers cannot all pass the same preflight.
        let occupied = self
            .store
            .total_size()
            .saturating_add(self.pending_write_bytes);
        if occupied > self.config.max_storage {
            return None;
        }

        let (result, _) = tokio::sync::watch::channel(PropagationAdmissionOutcome::Pending);
        let reservation = std::sync::Arc::new(AdmissionReservation {
            content_hash: rns_crypto::sha::full_hash(&data),
            size: data.len(),
            result,
        });
        self.pending_admissions
            .insert(transient_id, std::sync::Arc::downgrade(&reservation));
        self.pending_write_ids.insert(transient_id);
        self.pending_write_bytes = self.pending_write_bytes.saturating_add(data.len());
        let manifest = crate::propagation_store_v2::EntryManifest::from_entry(&entry, &data);
        let path = self
            .storage_path
            .as_ref()
            .map(|dir| dir.join("objects").join(manifest.filename()));
        Some(PropagationStoreWritePlan {
            entry,
            data,
            manifest,
            reservation,
            path,
        })
    }

    /// Release a reservation after a failed blocking write.
    pub fn abort_store_write(&mut self, transient_id: &PropagationTransientId, size: usize) {
        if self
            .pending_admissions
            .get(transient_id)
            .is_some_and(|weak| weak.upgrade().is_some())
        {
            return;
        }
        self.pending_admissions.remove(transient_id);
        if self.pending_write_ids.remove(transient_id) {
            self.pending_write_bytes = self.pending_write_bytes.saturating_sub(size);
        }
    }

    /// Commit a successfully persisted admission. The normal path performs no
    /// filesystem I/O while holding the node lock.
    pub fn commit_store_write(&mut self, persisted: PersistedPropagationStoreWrite) -> bool {
        let transient_id = persisted.entry.transient_id;
        let size = persisted.entry.size;
        if self
            .pending_admissions
            .get(&transient_id)
            .and_then(|weak| weak.upgrade())
            .is_none_or(|owner| !std::sync::Arc::ptr_eq(&owner, &persisted.reservation))
        {
            return false;
        }
        self.pending_admissions.remove(&transient_id);
        if !self.pending_write_ids.remove(&transient_id) {
            return false;
        }
        self.pending_write_bytes = self.pending_write_bytes.saturating_sub(size);
        let inserted = !self.store.contains(&transient_id) && self.store.insert(persisted.entry);
        if inserted {
            if let Some(path) = persisted.path {
                self.object_paths.insert(transient_id, path);
            }
            self.advance_offer_generation();
        }
        persisted.reservation.result.send_replace(if inserted {
            PropagationAdmissionOutcome::Committed
        } else {
            PropagationAdmissionOutcome::Failed
        });
        inserted
    }

    fn persist_reserved(&mut self, plan: PropagationStoreWritePlan) -> bool {
        let transient_id = plan.transient_id();
        let size = plan.size();
        match plan.persist() {
            Ok(persisted) => self.commit_store_write(persisted),
            Err(error) => {
                self.abort_store_write(&transient_id, size);
                tracing::warn!(
                    transient_id = %hex::encode(transient_id),
                    %error,
                    "failed to persist propagation message"
                );
                false
            }
        }
    }

    /// Store a validated propagated LXMF blob with its propagation-node stamp.
    ///
    /// Canonical propagation-node storage mirrors upstream Python: keep
    /// `lxmf_data || stamp` on disk so peer sync can forward proof-carrying
    /// data. Client `/get` strips the final 32-byte stamp before returning
    /// messages to recipients.
    pub fn plan_accept_stamped_propagated_blob(
        &mut self,
        lxmf_data: &[u8],
        stamp_data: &[u8; 32],
        stamp_value: u8,
    ) -> Option<PropagationStoreWritePlan> {
        let mut bytes = Vec::with_capacity(lxmf_data.len().checked_add(32)?);
        if lxmf_data.len().checked_add(32)? > self.config.max_message_size {
            return None;
        }
        bytes.extend_from_slice(lxmf_data);
        bytes.extend_from_slice(stamp_data);
        let blob =
            ValidatedOpaquePropagationBlob::validate(bytes.into(), self.config.min_stamp_cost)?;
        if blob.stamp_value() != stamp_value {
            return None;
        }
        match self.plan_opaque_admission(blob) {
            PropagationAdmission::Reserved(plan) => Some(*plan),
            _ => None,
        }
    }
    /// Preferred network admission API. Same-TID exact-image duplicates share
    /// the original completion and never perform a second disk write.
    pub fn plan_opaque_admission(
        &mut self,
        blob: ValidatedOpaquePropagationBlob,
    ) -> PropagationAdmission {
        self.reap_retired();
        // Clear cancelled reservation accounting only after its actual owner
        // has exited; a weak observer never prolongs ownership or byte leases.
        let stale = self
            .pending_admissions
            .iter()
            .filter_map(|(id, weak)| weak.upgrade().is_none().then_some(*id))
            .collect::<Vec<_>>();
        for id in stale {
            self.pending_admissions.remove(&id);
            self.pending_write_ids.remove(&id);
        }
        self.pending_write_bytes = self
            .pending_admissions
            .values()
            .filter_map(|w| w.upgrade())
            .fold(0usize, |n, r| n.saturating_add(r.size));
        if !self.is_durable()
            || blob.stamp_value < self.config.min_stamp_cost
            || blob.bytes.len() > self.config.max_message_size
        {
            return PropagationAdmission::Rejected;
        }
        if self.contains(&blob.transient_id) {
            return self
                .object_paths
                .get(&blob.transient_id)
                .cloned()
                .map(|path| {
                    PropagationAdmission::CommittedDuplicate(PropagationDuplicateCheck { path })
                })
                .unwrap_or(PropagationAdmission::Rejected);
        }
        if let Some(owner) = self
            .pending_admissions
            .get(&blob.transient_id)
            .and_then(|w| w.upgrade())
        {
            if owner.content_hash != rns_crypto::sha::full_hash(&blob.bytes) {
                return PropagationAdmission::Rejected;
            }
            return PropagationAdmission::Pending(PropagationAdmissionWaiter {
                result: owner.result.subscribe(),
            });
        }
        let mut destination = [0; 16];
        destination.copy_from_slice(&blob.bytes[..16]);
        let entry = PropagationEntry::new_stamped(
            blob.transient_id,
            blob.transient_id,
            destination,
            blob.bytes.len(),
            blob.stamp_value,
        );
        match self.reserve_store_write(entry, blob.bytes.to_vec()) {
            Some(plan) => PropagationAdmission::Reserved(Box::new(plan)),
            None => PropagationAdmission::Rejected,
        }
    }

    pub fn accept_stamped_propagated_blob(
        &mut self,
        lxmf_data: &[u8],
        stamp_data: &[u8; 32],
        stamp_value: u8,
    ) -> bool {
        let Some(plan) =
            self.plan_accept_stamped_propagated_blob(lxmf_data, stamp_data, stamp_value)
        else {
            return false;
        };
        self.persist_reserved(plan)
    }

    fn load_from_disk(&mut self) -> std::io::Result<()> {
        let Some(root) = self.storage_path.as_ref() else {
            return Ok(());
        };
        crate::propagation_store_v2::reconcile_deletions(root)?;
        let objects = root.join("objects");
        for file in std::fs::read_dir(&objects)? {
            let path = file?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("active") {
                continue;
            }
            let object = crate::propagation_store_v2::indexed_object(&path)?;
            if crate::propagation_store_v2::deletion_path(&object).exists() {
                continue;
            }
            let (meta, _) = crate::propagation_store_v2::read_manifest(&object)?;
            crate::propagation_store_v2::verify_committed_object(&object)?;
            if self.store.contains(&meta.transient_id) {
                return Err(std::io::Error::other("duplicate relay TID"));
            }
            self.object_paths.insert(meta.transient_id, object);
            self.store.insert(meta.entry());
        }
        if !self.store.is_empty() {
            self.advance_offer_generation();
        }
        Ok(())
    }
    fn eligible(&self, id: &PropagationTransientId) -> bool {
        self.object_paths
            .get(id)
            .is_none_or(|path| !self.retired.contains(path))
    }
    fn reap_retired(&mut self) {
        let removed =
            std::mem::take(&mut *self.retired.ids.lock().unwrap_or_else(|e| e.into_inner()));
        let ids = self
            .object_paths
            .iter()
            .filter_map(|(id, path)| removed.contains(path).then_some(*id))
            .collect::<Vec<_>>();
        for id in ids {
            self.store.remove(&id);
            self.object_paths.remove(&id);
        }
    }
    fn retirement_plan(
        &self,
        ids: impl IntoIterator<Item = PropagationTransientId>,
    ) -> PropagationRetirementPlan {
        let entries = ids
            .into_iter()
            .filter(|id| self.eligible(id))
            .filter_map(|id| self.object_paths.get(&id).cloned())
            .collect();
        PropagationRetirementPlan {
            entries,
            retired: std::sync::Arc::clone(&self.retired),
        }
    }
    /// Select maintenance without filesystem IO. The caller runs persist off
    /// the actor and drops this plan after actual completion.
    pub fn plan_maintenance(&mut self) -> PropagationRetirementPlan {
        self.reap_retired();
        let now = crate::now_f64();
        let cutoff = now - self.config.max_message_age as f64;
        let mut ids = Vec::new();
        let mut remaining = self.store.total_size();
        let mut weighted = Vec::new();
        for entry in self.store.entries() {
            if entry.stored_at < cutoff {
                ids.push(entry.transient_id);
                remaining = remaining.saturating_sub(entry.size);
            } else {
                weighted.push((
                    entry.transient_id,
                    self.store.compute_weight(entry, now),
                    entry.size,
                ));
            }
        }
        weighted.sort_by(|a, b| b.1.total_cmp(&a.1));
        for (id, _, size) in weighted {
            if remaining <= self.config.max_storage {
                break;
            }
            ids.push(id);
            remaining = remaining.saturating_sub(size);
        }
        self.retirement_plan(ids)
    }
    /// Blocking compatibility wrapper. Async hosts use plan_maintenance and
    /// execute its durable operations on their bounded storage worker.
    pub fn tick(&mut self) {
        let plan = self.plan_maintenance();
        if let Err(error) = plan.persist() {
            tracing::warn!(%error,"relay maintenance remains pending");
        }
        self.reap_retired();
    }

    /// When `peer_min_stamp_cost` is `Some`, include only messages whose stamp
    /// value meets the peer's threshold, so we don't send messages the peer
    /// would reject for insufficient PoW.
    pub fn create_offer(
        &self,
        _peer_hash: [u8; 16],
        peer_min_stamp_cost: Option<u8>,
    ) -> Vec<PropagationTransientId> {
        match peer_min_stamp_cost {
            Some(min_cost) if min_cost > 0 => self
                .store
                .entries()
                .filter(|e| self.eligible(&e.transient_id) && e.stamp_value >= min_cost)
                .map(|e| e.transient_id)
                .collect(),
            _ => self
                .store
                .entries()
                .filter(|e| self.eligible(&e.transient_id))
                .map(|e| e.transient_id)
                .collect(),
        }
    }

    /// Returns only messages the peer has not already received.
    pub fn create_offer_filtered(
        &self,
        handled: &HashSet<PropagationTransientId>,
    ) -> Vec<PropagationTransientId> {
        self.store
            .transient_ids()
            .into_iter()
            .filter(|id| !handled.contains(id))
            .collect()
    }

    pub fn message_count(&self) -> usize {
        self.store
            .entries()
            .filter(|e| self.eligible(&e.transient_id))
            .count()
    }

    /// Count live store entries not yet handled by one peer. The daemon's
    /// generation scheduler does not maintain `LxmPeer`'s legacy cached
    /// unhandled counter, so control status must derive this from the same
    /// authoritative store used to prepare offers.
    pub fn unhandled_message_count(
        &self,
        handled_messages: &HashSet<PropagationTransientId>,
    ) -> usize {
        self.store
            .entries()
            .filter(|entry| {
                self.eligible(&entry.transient_id)
                    && !handled_messages.contains(&entry.transient_id)
            })
            .count()
    }

    pub fn total_size(&self) -> usize {
        self.store
            .entries()
            .filter(|e| self.eligible(&e.transient_id))
            .fold(0usize, |n, e| n.saturating_add(e.size))
    }

    pub fn contains(&self, transient_id: &PropagationTransientId) -> bool {
        self.eligible(transient_id) && self.store.contains(transient_id)
    }

    pub fn get_session(&self, peer_hash: &[u8; 16]) -> Option<&SyncSession> {
        self.sync_sessions.get(peer_hash)
    }

    pub fn get_session_mut(&mut self, peer_hash: &[u8; 16]) -> Option<&mut SyncSession> {
        self.sync_sessions.get_mut(peer_hash)
    }

    pub fn start_session(&mut self, peer_hash: [u8; 16]) -> &mut SyncSession {
        self.sync_sessions
            .entry(peer_hash)
            .or_insert_with(|| SyncSession::new(peer_hash))
    }

    pub fn remove_session(&mut self, peer_hash: &[u8; 16]) {
        self.sync_sessions.remove(peer_hash);
    }

    pub fn save_peer(&self, peer: &LxmPeer) -> std::io::Result<()> {
        if let Some(ref dir) = self.storage_path {
            let filename = format!("{}.peer", hex_encode(&peer.destination_hash));
            let path = dir.join(filename);
            let data = peer.to_bytes_with_handled();
            crate::persist::write_file_atomic(&path, &data)?;
        }
        Ok(())
    }

    /// Remove persisted state for an explicitly unpeered destination.
    pub fn delete_peer(&mut self, peer_hash: &[u8; 16]) -> std::io::Result<()> {
        self.remove_session(peer_hash);
        let Some(dir) = self.storage_path.as_ref() else {
            return Ok(());
        };
        let path = dir.join(format!("{}.peer", hex_encode(peer_hash)));
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Inverse-offer pattern: the peer lists what it has; we return the IDs
    /// we hold that the peer does not. Python reference:
    /// LXMRouter.offer_request_received().
    pub fn offer_request(
        &mut self,
        _peer_hash: [u8; 16],
        offered_ids: &[PropagationTransientId],
    ) -> Vec<PropagationTransientId> {
        let peer_has: HashSet<PropagationTransientId> = offered_ids.iter().copied().collect();

        self.store
            .transient_ids()
            .into_iter()
            .filter(|id| !peer_has.contains(id))
            .collect()
    }

    /// Wire format matches Python: Boolean for WantAll/HaveAll, integer for
    /// error codes, array of binary IDs for WantSome.
    pub fn encode_offer_response(response: &OfferResponse) -> Vec<u8> {
        use rmpv::Value;

        let value = match response {
            OfferResponse::WantAll => Value::Boolean(true),
            OfferResponse::HaveAll => Value::Boolean(false),
            OfferResponse::WantSome(ids) => {
                Value::Array(ids.iter().map(|id| Value::Binary(id.clone())).collect())
            }
            OfferResponse::ErrorNoIdentity => Value::from(PeerError::NoIdentity as u64),
            OfferResponse::ErrorNoAccess => Value::from(PeerError::NoAccess as u64),
            OfferResponse::ErrorInvalidKey => Value::from(PeerError::InvalidKey as u64),
            OfferResponse::ErrorThrottled => Value::from(PeerError::Throttled as u64),
            OfferResponse::ErrorInvalidData => Value::from(PeerError::InvalidData as u64),
            OfferResponse::ErrorInvalidStamp => Value::from(PeerError::InvalidStamp as u64),
            OfferResponse::Unknown => Value::Nil,
        };

        crate::encode_value(&value)
    }

    /// Handle a Link REQUEST at the `/offer` path. Python reference:
    /// LXMRouter.offer_request() (LXMRouter.py:2139-2189).
    ///
    /// `request_data` is msgpack `[peering_key, [transient_id_1, ...]]`.
    /// Transitional compatibility wrapper for callers that still compute the
    /// outer identity/access/throttle gates. New daemon code must preflight a
    /// long-lived `PnInboundAdmission` and call `evaluate_offer_request`
    /// directly before committing the exact candidate.
    pub fn handle_offer_request(
        &mut self,
        request_data: &[u8],
        ctx: OfferRequestContext<'_>,
    ) -> Vec<u8> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs_f64())
            .unwrap_or(0.0);
        if self
            .last_offer_times
            .get(&ctx.peer_hash)
            .is_some_and(|last_time| now - last_time < PN_STAMP_THROTTLE as f64)
        {
            return Self::encode_offer_response(&OfferResponse::ErrorThrottled);
        }

        let offer = match crate::propagation_offer::decode(request_data, self.config.max_offer_size)
        {
            Ok(offer) => offer,
            Err(error) => return Self::encode_offer_response(&error.wire_response()),
        };

        let response = if !ctx.identity_known {
            OfferResponse::ErrorNoIdentity
        } else if ctx.is_throttled {
            OfferResponse::ErrorThrottled
        } else if !ctx.access_allowed {
            OfferResponse::ErrorNoAccess
        } else if let (Some(local_hash), Some(remote_hash)) =
            (ctx.local_identity_hash, ctx.remote_identity_hash)
        {
            match crate::propagation_offer::evaluate_decoded(
                offer,
                local_hash,
                remote_hash,
                self.config.peering_cost,
                |transient_id| self.contains(transient_id),
            ) {
                Ok(evaluation) => evaluation.into_wire_response(),
                Err(error) => error.wire_response(),
            }
        } else {
            OfferResponse::ErrorInvalidKey
        };

        self.last_offer_times.insert(ctx.peer_hash, now);
        Self::encode_offer_response(&response)
    }

    /// Evaluate a preflighted `/offer` without mutating admission state.
    pub fn evaluate_offer_request(
        &self,
        request_data: &[u8],
        local_identity_hash: &[u8; 16],
        candidate: &PnOfferCandidate,
    ) -> Result<PnOfferEvaluation, PnOfferEvaluationError> {
        let remote_identity_hash = candidate.peer_identity_hash();
        crate::propagation_offer::evaluate(
            request_data,
            local_identity_hash,
            &remote_identity_hash,
            self.config.peering_cost,
            self.config.max_offer_size,
            |transient_id| self.contains(transient_id),
        )
    }

    /// Handle a Link REQUEST at the `/get` path for client download. Python
    /// reference: LXMRouter.message_get_request() (LXMRouter.py:1425-1499).
    ///
    /// Wire format is msgpack `[wants, haves]` or `[wants, haves, delivery_limit]`:
    /// - Phase 1 (list): `[None, None]` -> available transient IDs for the client,
    ///   smallest message first (Python sorts by file size ascending).
    /// - Phase 2 (get):  `[[wants...], [haves...]]` -> haves are purged first
    ///   (Python order), then wants resolve to a [`GetServePlan`] whose file
    ///   reads the embedder performs without holding the node lock.
    /// - Phase 3 (purge): `[None, [received_ids...]]` -> delete from store.
    pub fn handle_get_request(
        &mut self,
        request_data: &[u8],
        client_dest_hash: &[u8; 16],
    ) -> GetRequestAction {
        self.handle_get_request_bounded(
            request_data,
            client_dest_hash,
            rns_protocol::resource::MAX_RESOURCE_SIZE,
        )
    }

    /// Plan a GET under a caller-reserved transfer budget. No native I/O occurs
    /// here; resolve the plan on the worker retaining that reservation.
    pub fn handle_get_request_bounded(
        &mut self,
        request_data: &[u8],
        client_dest_hash: &[u8; 16],
        maximum_response_bytes: usize,
    ) -> GetRequestAction {
        let Some(request) = parse_get_request(request_data) else {
            return GetRequestAction::Respond(vec![0xc0]);
        };
        let maximum_response_bytes =
            maximum_response_bytes.min(rns_protocol::resource::MAX_RESOURCE_SIZE);
        if maximum_response_bytes < 5 {
            return GetRequestAction::Respond(vec![0xc0]);
        }
        if request.wants.is_none() && request.haves.is_none() {
            // Select only the smallest IDs that fit. A list request cannot
            // allocate an index proportional to the entire retained store.
            let count = maximum_response_bytes.saturating_sub(5) / 34;
            let mut available = std::collections::BinaryHeap::new();
            for entry in self.store.entries() {
                if entry.destination_hash != *client_dest_hash
                    || !self.eligible(&entry.transient_id)
                {
                    continue;
                }
                if available.len() < count {
                    available.push((entry.size, entry.transient_id));
                } else if available
                    .peek()
                    .is_some_and(|largest| (entry.size, entry.transient_id) < *largest)
                {
                    available.pop();
                    available.push((entry.size, entry.transient_id));
                }
            }
            let available = available.into_sorted_vec();
            let mut response = Vec::with_capacity(5 + 34 * available.len());
            rmp::encode::write_array_len(&mut response, available.len() as u32).expect("Vec write");
            for (_, id) in available {
                response.extend_from_slice(&[0xc4, 32]);
                response.extend_from_slice(&id);
            }
            return GetRequestAction::Respond(response);
        }
        // The deferred owner charges 16×raw input and 16 MiB scratch. Charge
        // every retained ID/path before cloning it; unusual long local paths
        // cannot exceed that reservation. Failure creates no retirement plan.
        let mut planning_left = request_data
            .len()
            .saturating_mul(8)
            .saturating_add(8 * 1024 * 1024);
        let mut retired_ids = HashSet::new();
        for tid in get_ids(request.haves) {
            if self
                .store
                .get(&tid)
                .is_some_and(|e| e.destination_hash == *client_dest_hash)
                && !retired_ids.contains(&tid)
            {
                let path_len = self
                    .object_paths
                    .get(&tid)
                    .map_or(0, |p| p.as_os_str().len());
                let charge = 256usize.saturating_add(path_len.saturating_mul(2));
                let Some(left) = planning_left.checked_sub(charge) else {
                    return GetRequestAction::Respond(vec![0xc0]);
                };
                planning_left = left;
                retired_ids.insert(tid);
            }
        }
        let mut reads = Vec::new();
        let mut seen = HashSet::new();
        for tid in get_ids(request.wants) {
            if let Some(entry) = self.store.get(&tid)
                && entry.destination_hash == *client_dest_hash
                && self.eligible(&tid)
                && !retired_ids.contains(&tid)
                && !seen.contains(&tid)
                && let Some(path) = self.object_paths.get(&tid)
            {
                let charge = 256usize.saturating_add(path.as_os_str().len().saturating_mul(2));
                let Some(left) = planning_left.checked_sub(charge) else {
                    return GetRequestAction::Respond(vec![0xc0]);
                };
                planning_left = left;
                seen.insert(tid);
                reads.push(PlannedRead {
                    path: path.clone(),
                    stamped: entry.stamped,
                    stored_size: entry.size,
                });
            }
        }
        let retirements = self.retirement_plan(retired_ids);
        GetRequestAction::ServeFiles(GetServePlan {
            reads,
            retirements,
            limit_bytes: request.limit_bytes,
        })
    }

    /// Resolve requested transient IDs into store-file read plans (no I/O).
    /// Perform the reads via [`read_planned_messages`] after releasing the
    /// node lock. Returns an empty vec when there is no disk storage.
    pub fn plan_message_reads(
        &self,
        requested_ids: &[PropagationTransientId],
    ) -> Vec<PlannedMessageRead> {
        let _dir = match &self.storage_path {
            Some(d) => d,
            None => return Vec::new(),
        };

        requested_ids
            .iter()
            .filter_map(|tid| {
                self.store
                    .get(tid)
                    .filter(|_| self.eligible(tid))
                    .map(|_entry| PlannedMessageRead {
                        transient_id: *tid,
                        path: self.object_paths[tid].clone(),
                    })
            })
            .collect()
    }

    /// Fetch raw packed message data for each requested transient ID. Python
    /// reference: LXMRouter.message_get_request_received(). Blocking
    /// convenience over [`Self::plan_message_reads`] — prefer the staged pair
    /// when the node sits behind a shared lock.
    pub fn message_get_request(
        &self,
        requested_ids: &[PropagationTransientId],
    ) -> Vec<(PropagationTransientId, Vec<u8>)> {
        read_planned_messages(&self.plan_message_reads(requested_ids))
    }

    /// Produce a `SyncOffer` listing message IDs the peer has not yet handled.
    /// The caller sends it over an established link. Python reference:
    /// LXMRouter.sync_request_received().
    pub fn prepare_sync_offer(&mut self, peer_hash: [u8; 16]) -> SyncOffer {
        let policy = self
            .load_peer(&peer_hash)
            .as_ref()
            .map(OutboundOfferPolicy::from)
            .unwrap_or_else(|| OutboundOfferPolicy::unrestricted(peer_hash));
        self.prepare_sync_offer_with_policy(&policy)
    }

    /// Capture an owned offer-preparation snapshot while holding the node lock.
    /// The returned value contains no references into the live store.
    pub(crate) fn snapshot_sync_offer_preparation(
        &self,
        policy: &OutboundOfferPolicy,
    ) -> SyncOfferPreparationSnapshot {
        let now = crate::now_f64();
        let candidates = self
            .store
            .entries()
            .filter(|entry| self.eligible(&entry.transient_id))
            .map(|entry| SyncOfferCandidateSnapshot {
                transient_id: entry.transient_id,
                weight: self.store.compute_weight(entry, now),
                size: entry.size,
                stamp_value: entry.stamp_value,
            })
            .collect();
        let peer_path = self
            .storage_path
            .as_ref()
            .map(|dir| dir.join(format!("{}.peer", hex_encode(&policy.peer_hash))));

        SyncOfferPreparationSnapshot {
            policy: policy.clone(),
            generation: self.offer_generation(),
            peer_path,
            candidates,
        }
    }

    /// Revalidate and install a prepared offer. A store mutation invalidates
    /// the entire result so weight ordering and limits are recomputed from a
    /// fresh snapshot instead of partially accepting stale work.
    pub(crate) fn install_prepared_sync_offer(
        &mut self,
        prepared: PreparedSyncOffer,
    ) -> InstallPreparedSyncOffer {
        if prepared.generation != self.offer_generation()
            || prepared
                .selected_ids
                .iter()
                .any(|transient_id| !self.contains(transient_id))
        {
            return InstallPreparedSyncOffer::Stale;
        }

        let session = self
            .sync_sessions
            .entry(prepared.policy.peer_hash)
            .or_insert_with(|| SyncSession::new(prepared.policy.peer_hash));
        let offer =
            session.prepare_offer(prepared.selected_ids, prepared.policy.peering_key.clone());
        InstallPreparedSyncOffer::Installed {
            offer,
            generation: prepared.generation,
            terminal_handled_ids: prepared.terminal_handled_ids,
            generation_exhausted: prepared.generation_exhausted,
        }
    }

    /// Prepare one offer from an authoritative peer-policy snapshot.
    ///
    /// Selection mirrors `LXMPeer.sync`: only existing, unhandled messages
    /// meeting the peer's stamp and transfer limits are eligible. Candidates
    /// are ordered by ascending store weight before the cumulative sync cap is
    /// applied. The chosen IDs are retained in the session so a subsequent
    /// response cannot request data outside this offer.
    pub fn prepare_sync_offer_with_policy(&mut self, policy: &OutboundOfferPolicy) -> SyncOffer {
        loop {
            let snapshot = self.snapshot_sync_offer_preparation(policy);
            let prepared = prepare_sync_offer_snapshot(snapshot);
            match self.install_prepared_sync_offer(prepared) {
                InstallPreparedSyncOffer::Installed {
                    offer,
                    terminal_handled_ids,
                    ..
                } => {
                    // Compatibility wrapper: production uses the staged task
                    // path and exposes this delta to the daemon for off-loop
                    // persistence.
                    if !terminal_handled_ids.is_empty()
                        && let Err(error) = self.persist_peer_handled(policy, &terminal_handled_ids)
                    {
                        tracing::warn!(%error, "failed to persist terminal offer dispositions");
                    }
                    return offer;
                }
                InstallPreparedSyncOffer::Stale => continue,
            }
        }
    }

    /// Compare a peer's `SyncOffer` against our store and return a `SyncGet`
    /// listing IDs we want. Python reference: LXMRouter.offer_request_received().
    pub fn process_sync_offer(&mut self, peer_hash: [u8; 16], offer: &SyncOffer) -> SyncGet {
        // process_offer needs &self.store; compute the get before mutating sync_sessions.
        let mut tmp_session = SyncSession::new(peer_hash);
        let result = tmp_session.process_offer(offer, &self.store);
        self.sync_sessions.insert(peer_hash, tmp_session);
        result
    }

    /// Return the packed message data for each ID in `get`. The caller
    /// transfers each blob as a Resource over the link. Python reference:
    /// LXMRouter.message_get_request_received().
    pub fn process_sync_get(&mut self, peer_hash: [u8; 16], get: &SyncGet) -> Vec<Vec<u8>> {
        if let Some(session) = self.sync_sessions.get_mut(&peer_hash) {
            session.process_get(get);
        } else {
            let mut session = SyncSession::new(peer_hash);
            session.process_get(get);
            self.sync_sessions.insert(peer_hash, session);
        }

        let wanted: Vec<PropagationTransientId> = get
            .wanted_ids
            .iter()
            .filter_map(|id_bytes| {
                if id_bytes.len() != 32 {
                    return None;
                }
                let mut tid = [0u8; 32];
                tid.copy_from_slice(id_bytes);
                Some(tid)
            })
            .collect();

        read_planned_messages(&self.plan_message_reads(&wanted))
            .into_iter()
            .map(|(_tid, data)| data)
            .collect()
    }

    /// Record a successful transfer for a peer. Loads the peer, adds the
    /// transient ID to its handled set, saves it, and records the transfer in
    /// the sync session. Python reference:
    /// LXMRouter.propagation_resource_concluded() (LXMRouter.py:2271) --
    /// `peer.queue_handled_message(transient_id)`.
    pub fn mark_peer_handled(
        &mut self,
        peer_hash: &[u8; 16],
        transient_id: &PropagationTransientId,
    ) {
        if let Some(mut peer) = self.load_peer(peer_hash) {
            peer.add_handled_message(transient_id);
            let _ = self.save_peer(&peer);
        }

        if let Some(session) = self.sync_sessions.get_mut(peer_hash) {
            session.record_transfer();
        }
    }

    /// Merge peer-handled observations into persisted state using the same
    /// authoritative policy that produced the offer.
    pub fn persist_peer_handled(
        &self,
        policy: &OutboundOfferPolicy,
        transient_ids: &[PropagationTransientId],
    ) -> std::io::Result<()> {
        let mut peer = self
            .load_peer(&policy.peer_hash)
            .unwrap_or_else(|| policy.to_peer());
        policy.apply_to_peer(&mut peer);
        for transient_id in transient_ids {
            peer.add_handled_message(transient_id);
        }
        self.save_peer(&peer)
    }

    pub fn complete_sync(&mut self, peer_hash: &[u8; 16]) {
        if let Some(session) = self.sync_sessions.get_mut(peer_hash) {
            session.mark_complete();
        }
        self.remove_session(peer_hash);
    }

    fn load_peer(&self, peer_hash: &[u8; 16]) -> Option<LxmPeer> {
        let dir = self.storage_path.as_ref()?;
        let filename = format!("{}.peer", hex_encode(peer_hash));
        let path = dir.join(filename);
        let data = std::fs::read(&path).ok()?;
        let mut peer = LxmPeer::from_bytes_with_handled(&data)?;
        self.prune_handled_against_store(&mut peer);
        Some(peer)
    }

    pub fn load_peers(&self) -> Vec<LxmPeer> {
        let dir = match &self.storage_path {
            Some(d) => d,
            None => return Vec::new(),
        };

        let mut peers = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "peer").unwrap_or(false)
                    && let Ok(data) = std::fs::read(&path)
                    && let Some(mut peer) = LxmPeer::from_bytes_with_handled(&data)
                {
                    self.prune_handled_against_store(&mut peer);
                    peers.push(peer);
                }
            }
        }
        peers
    }

    /// Drop handled-message IDs whose store entries no longer exist (Python
    /// `LXMPeer.from_dict` keeps only IDs in `router.propagation_entries`).
    /// Without this the per-peer sets — and the `.peer` files they round-trip
    /// through on every sync — grow with total propagated volume forever.
    /// Files converge lazily: the next `mark_peer_handled` saves the pruned set.
    fn prune_handled_against_store(&self, peer: &mut LxmPeer) {
        peer.handled_messages.retain(|id| self.contains(id));
    }
}

impl std::fmt::Debug for PropagationNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PropagationNode")
            .field("dest_hash", &hex_encode(&self.dest_hash))
            .field("message_count", &self.store.len())
            .field("total_size", &self.store.total_size())
            .field("sessions", &self.sync_sessions.len())
            .field("storage_path", &self.storage_path)
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::constants::DeliveryMethod;

    // Real opaque relay fixtures: ID derives from ciphertext, and stamp value is
    // measured from the exact retained blob. Timestamp below is a test arrival
    // clock, never a mutation of the signed message.
    #[derive(Clone)]
    pub(crate) struct OpaqueFixture {
        pub(crate) data: Vec<u8>,
        pub(crate) stamp: [u8; 32],
        pub(crate) value: u8,
        pub(crate) transient_id: Option<[u8; 32]>,
        pub(crate) hash: Option<[u8; 32]>,
        pub(crate) timestamp: f64,
    }
    impl OpaqueFixture {
        pub(crate) fn message_id(&self) -> [u8; 32] {
            self.transient_id.unwrap()
        }
    }
    pub(crate) fn fixture_stamp(data: &[u8], cost: u8) -> ([u8; 32], u32) {
        let id = rns_crypto::sha::full_hash(data);
        let block = crate::stamper::stamp_workblock(
            &id,
            crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PN,
        );
        // Exact value makes filtering fixtures deterministic (cost zero's public
        // generator shortcut is not a measured stamp strength).
        for counter in 0..u64::MAX {
            let mut stamp = [0; 32];
            stamp[..8].copy_from_slice(&counter.to_be_bytes());
            let value = crate::stamper::stamp_value(&block, &stamp);
            if value == u32::from(cost) {
                return (stamp, value);
            }
        }
        unreachable!()
    }
    pub(crate) fn opaque_message(
        dest: [u8; 16],
        src: [u8; 16],
        title: &str,
        content: &str,
        method: DeliveryMethod,
    ) -> OpaqueFixture {
        let message = crate::message::test_message(dest, src, title, content, method);
        let identity = rns_identity::identity::Identity::new();
        let mut data = dest.to_vec();
        data.extend(identity.encrypt(&message.wire_bytes()[16..], None).unwrap());
        let transient_id = rns_crypto::sha::full_hash(&data);
        let (stamp, value) = fixture_stamp(&data, 0);
        OpaqueFixture {
            data,
            stamp,
            value: value.min(255) as u8,
            transient_id: Some(transient_id),
            hash: Some(transient_id),
            timestamp: crate::now_f64(),
        }
    }
    pub(crate) fn make_signed_message(
        dest: [u8; 16],
        src: [u8; 16],
        title: &str,
        content: &str,
    ) -> OpaqueFixture {
        opaque_message(dest, src, title, content, DeliveryMethod::Propagated)
    }
    thread_local! { static FIXTURE_DIRECTORIES: std::cell::RefCell<Vec<tempfile::TempDir>>=const {std::cell::RefCell::new(Vec::new())}; }
    pub(crate) fn durable_test_node(
        config: PropagationNodeConfig,
        dest: [u8; 16],
    ) -> PropagationNode {
        let dir = tempfile::tempdir().unwrap();
        let node = PropagationNode::with_storage(config, dest, dir.path().join("store")).unwrap();
        FIXTURE_DIRECTORIES.with(|dirs| dirs.borrow_mut().push(dir));
        node
    }
    impl PropagationNode {
        pub(crate) fn plan_fixture(
            &mut self,
            fixture: &OpaqueFixture,
        ) -> Option<PropagationStoreWritePlan> {
            let mut plan = self.plan_accept_stamped_propagated_blob(
                &fixture.data,
                &fixture.stamp,
                fixture.value,
            )?;
            plan.entry.stored_at = fixture.timestamp;
            plan.manifest.stored_at = fixture.timestamp;
            plan.path = self
                .storage_path
                .as_ref()
                .map(|root| root.join("objects").join(plan.manifest.filename()));
            Some(plan)
        }
        pub(crate) fn accept_fixture(&mut self, fixture: &OpaqueFixture) -> bool {
            let Some(plan) = self.plan_fixture(fixture) else {
                return false;
            };
            self.persist_reserved(plan)
        }
        pub(crate) fn accept_blob_fixture(&mut self, data: &[u8], cost: u8) -> bool {
            let (stamp, value) = fixture_stamp(data, cost);
            self.accept_stamped_propagated_blob(data, &stamp, value.min(255) as u8)
        }
    }

    fn tid(byte: u8) -> PropagationTransientId {
        [byte; 32]
    }

    fn insert_offer_entry(
        node: &mut PropagationNode,
        transient_id: PropagationTransientId,
        size: usize,
        stamp_value: u8,
    ) {
        let entry =
            PropagationEntry::new(transient_id, transient_id, [0xDD; 16], size, stamp_value);
        assert!(node.store.insert(entry));
    }

    fn id(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn peering_key(local_identity: &[u8; 16], remote_identity: &[u8; 16], cost: u8) -> [u8; 32] {
        let mut peering_id = Vec::with_capacity(32);
        peering_id.extend_from_slice(local_identity);
        peering_id.extend_from_slice(remote_identity);
        crate::stamper::generate_stamp(
            &peering_id,
            cost,
            crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING,
        )
        .unwrap()
        .0
    }

    fn offer_ctx<'a>(
        peer_hash: [u8; 16],
        identity_known: bool,
        is_throttled: bool,
        access_allowed: bool,
        local_identity_hash: Option<&'a [u8; 16]>,
        remote_identity_hash: Option<&'a [u8; 16]>,
    ) -> OfferRequestContext<'a> {
        OfferRequestContext {
            peer_hash,
            identity_known,
            is_throttled,
            access_allowed,
            local_identity_hash,
            remote_identity_hash,
        }
    }

    #[test]
    fn test_new_propagation_node() {
        let config = PropagationNodeConfig::default();
        assert_eq!(config.max_message_size, 1_000_000);
        let node = PropagationNode::new(config, [0xAA; 16]);
        assert_eq!(node.message_count(), 0);
        assert_eq!(node.total_size(), 0);
        assert_eq!(node.dest_hash, [0xAA; 16]);
    }

    #[test]
    fn test_accept_message() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "content");
        assert!(msg.hash.is_some());
        assert!(node.accept_fixture(&msg));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn store_write_reservation_blocks_duplicates_until_durable_commit() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "reserved");
        let plan = node.plan_fixture(&msg).expect("first reservation");
        assert_eq!(node.message_count(), 0, "reservation is not served state");
        assert!(node.plan_fixture(&msg).is_none());

        let persisted = plan.persist().unwrap();
        assert!(node.commit_store_write(persisted));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn failed_store_write_is_not_inserted_and_releases_reservation() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let message =
            make_signed_message([0xBB; 16], [0xCC; 16], "write failure", "preserve retry");
        let plan = node.plan_fixture(&message).unwrap();
        let id = plan.transient_id();
        let size = plan.size();
        let objects = node.storage_path.as_ref().unwrap().join("objects");
        let saved = objects.with_extension("temporarily-unavailable");
        std::fs::rename(&objects, &saved).unwrap();
        std::fs::write(&objects, b"temporary non-directory").unwrap();
        assert!(plan.persist().is_err());
        node.abort_store_write(&id, size);
        assert_eq!(node.message_count(), 0);
        std::fs::remove_file(&objects).unwrap();
        std::fs::rename(&saved, &objects).unwrap();
        assert!(node.accept_fixture(&message));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn hosted_node_applies_ignored_destination_policy() {
        let destination = [0x44; 16];
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        node.ignore_destination(destination);
        assert!(node.is_destination_ignored(&destination));

        let mut blob = destination.to_vec();
        blob.extend_from_slice(b"encrypted-lxmf");
        assert!(!node.accept_blob_fixture(&blob, 0));
        assert_eq!(node.message_count(), 0);

        node.unignore_destination(&destination);
        assert!(node.accept_blob_fixture(&blob, 0));
    }

    #[test]
    fn unhandled_count_is_derived_from_live_store_and_peer_handled_set() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "content");
        let transient_id = msg.transient_id.or(msg.hash).unwrap();
        assert!(node.accept_fixture(&msg));

        let mut handled = HashSet::new();
        assert_eq!(node.unhandled_message_count(&handled), 1);
        handled.insert(transient_id);
        assert_eq!(node.unhandled_message_count(&handled), 0);
    }

    #[test]
    fn test_reject_duplicate() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "duplicate");
        assert!(node.accept_fixture(&msg));
        assert!(!node.accept_fixture(&msg));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_reject_no_hash() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        assert!(!node.accept_stamped_propagated_blob(&[0; 16], &[0; 32], 0));
        assert_eq!(node.message_count(), 0);
    }

    #[test]
    fn test_reject_store_full() {
        let config = PropagationNodeConfig {
            max_storage: 1,
            ..Default::default()
        };
        let mut node = durable_test_node(config, [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg1");
        assert!(node.accept_fixture(&msg1));

        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg2");
        assert!(!node.accept_fixture(&msg2));
    }

    #[test]
    fn test_create_offer() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg1");
        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg2");
        node.accept_fixture(&msg1);
        node.accept_fixture(&msg2);

        let offer = node.create_offer([0xFF; 16], None);
        assert_eq!(offer.len(), 2);
    }

    #[test]
    fn test_create_offer_filtered() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg1");
        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg2");

        let tid1 = msg1.transient_id.unwrap();
        node.accept_fixture(&msg1);
        node.accept_fixture(&msg2);

        let all = node.create_offer([0xFF; 16], None);
        assert_eq!(all.len(), 2);

        let mut handled = HashSet::new();
        handled.insert(tid1);

        let filtered = node.create_offer_filtered(&handled);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn authoritative_offer_policy_combines_all_filters_and_real_key() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        insert_offer_entry(&mut node, tid(0x01), 100, 20); // handled
        insert_offer_entry(&mut node, tid(0x02), 100, 12); // low stamp
        insert_offer_entry(&mut node, tid(0x03), 100, 13); // accepted
        insert_offer_entry(&mut node, tid(0x04), 985, 20); // 1001 B with overhead
        insert_offer_entry(&mut node, tid(0x05), 984, 13); // exact 1000 B

        let mut policy = OutboundOfferPolicy::unrestricted([0xBB; 16]);
        policy.handled_messages.insert(tid(0x01));
        policy.minimum_stamp_cost = 13;
        policy.propagation_transfer_limit = Some(1.0);
        policy.propagation_sync_limit = Some(10.0);
        policy.peering_key = vec![0x77; 32];

        let offer = node.prepare_sync_offer_with_policy(&policy);

        assert_eq!(offer.peering_key, vec![0x77; 32]);
        assert_eq!(
            offer.transient_ids,
            vec![tid(0x03).to_vec(), tid(0x05).to_vec()]
        );
        assert_eq!(
            node.get_session(&policy.peer_hash).unwrap().offered_ids,
            vec![tid(0x03), tid(0x05)]
        );
    }

    #[test]
    fn offer_cumulative_limit_is_decimal_and_excludes_exact_boundary() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        insert_offer_entry(&mut node, tid(0x01), 50, 0);
        insert_offer_entry(&mut node, tid(0x02), 50, 0);
        let mut policy = OutboundOfferPolicy::unrestricted([0xBB; 16]);
        // 24 initial + (50 + 16) + (50 + 16) = 156 bytes. The second
        // candidate is excluded because upstream uses next_size >= limit.
        policy.propagation_sync_limit = Some(0.156);

        let offer = node.prepare_sync_offer_with_policy(&policy);

        assert_eq!(offer.transient_ids, vec![tid(0x01).to_vec()]);
    }

    #[test]
    fn prepared_offer_distinguishes_terminal_filters_from_cumulative_deferral() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        insert_offer_entry(&mut node, tid(0x01), 10, 9); // terminal low stamp
        insert_offer_entry(&mut node, tid(0x02), 100, 20); // selected
        insert_offer_entry(&mut node, tid(0x03), 100, 20); // cumulative deferred
        insert_offer_entry(&mut node, tid(0x04), 1000, 20); // terminal oversize
        let mut policy = OutboundOfferPolicy::unrestricted([0xBB; 16]);
        policy.minimum_stamp_cost = 10;
        policy.propagation_transfer_limit = Some(0.5);
        policy.propagation_sync_limit = Some(0.2);

        let prepared = prepare_sync_offer_snapshot(node.snapshot_sync_offer_preparation(&policy));

        assert_eq!(prepared.selected_ids, vec![tid(0x02)]);
        assert_eq!(prepared.terminal_handled_ids, vec![tid(0x01), tid(0x04)]);
        assert!(
            !prepared.generation_exhausted,
            "cumulative-only skips must stay pending for another batch"
        );
    }

    #[test]
    fn all_cumulatively_deferred_candidates_exhaust_unchanged_generation() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        insert_offer_entry(&mut node, tid(0x01), 50, 20);
        insert_offer_entry(&mut node, tid(0x02), 50, 20);
        let mut policy = OutboundOfferPolicy::unrestricted([0xBB; 16]);
        // Initial overhead (24) + either transfer (50 + 16) exceeds this
        // generation's peer policy, so a reconnect cannot make progress.
        policy.propagation_sync_limit = Some(0.05);

        let prepared = prepare_sync_offer_snapshot(node.snapshot_sync_offer_preparation(&policy));

        assert!(prepared.selected_ids.is_empty());
        assert!(prepared.terminal_handled_ids.is_empty());
        assert!(
            prepared.generation_exhausted,
            "zero-progress cumulative deferral must not hot-loop the same generation"
        );
    }

    #[test]
    fn prepared_offer_revalidates_store_generation_before_install() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let mut first = vec![0x11; DESTINATION_LENGTH + 1];
        first[0] = 0x01;
        assert!(node.accept_blob_fixture(&first, 0));
        let policy = OutboundOfferPolicy::unrestricted([0xBB; 16]);
        let snapshot = node.snapshot_sync_offer_preparation(&policy);

        let mut second = vec![0x22; DESTINATION_LENGTH + 1];
        second[0] = 0x02;
        assert!(node.accept_blob_fixture(&second, 0));
        let prepared = prepare_sync_offer_snapshot(snapshot);

        assert!(matches!(
            node.install_prepared_sync_offer(prepared),
            InstallPreparedSyncOffer::Stale
        ));
    }

    #[test]
    fn passed_and_persisted_handled_sets_are_unioned() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();
        insert_offer_entry(&mut node, tid(0x01), 50, 0);
        insert_offer_entry(&mut node, tid(0x02), 50, 0);
        insert_offer_entry(&mut node, tid(0x03), 50, 0);

        let mut persisted = LxmPeer::new([0xBB; 16]);
        persisted.add_handled_message(&tid(0x01));
        node.save_peer(&persisted).unwrap();
        let mut policy = OutboundOfferPolicy::unrestricted([0xBB; 16]);
        policy.handled_messages.insert(tid(0x02));

        let offer = node.prepare_sync_offer_with_policy(&policy);
        assert_eq!(offer.transient_ids, vec![tid(0x03).to_vec()]);

        node.delete_peer(&[0xBB; 16]).unwrap();
        assert!(node.load_peers().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_propagation_disk_persistence() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        {
            let mut node = PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                [0xAA; 16],
                dir.clone(),
            )
            .unwrap();

            let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "persistent content");
            assert!(node.accept_fixture(&msg));
            assert_eq!(node.message_count(), 1);
        }

        // Fresh node reloads from disk.
        {
            let node = PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                [0xAA; 16],
                dir.clone(),
            )
            .unwrap();
            assert_eq!(node.message_count(), 1);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_disk_load_ignores_pre_fix_16_byte_transient_id_filenames() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("store");
        std::fs::create_dir(&legacy).unwrap();
        let path = legacy.join("aabbccddaabbccddaabbccddaabbccdd_1234567890_0");
        let evidence = vec![0xCC; 80];
        std::fs::write(&path, &evidence).unwrap();
        let error =
            PropagationNode::with_storage(PropagationNodeConfig::default(), [0xAA; 16], legacy)
                .unwrap_err();
        assert!(error.to_string().contains("MigrationRequired"));
        assert_eq!(std::fs::read(path).unwrap(), evidence);
    }

    /// T0-1: `/get` ownership gating — a client may only list, download, and
    /// purge messages addressed to itself (Python LXMRouter.py:1454/1479).
    #[test]
    fn test_get_request_ownership_gating() {
        use rmpv::Value;

        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let client_a = [0xCC; 16];
        let client_b = [0xDD; 16];
        let msg_a = make_signed_message(client_a, [0xBB; 16], "Test", "for A");
        let msg_b = make_signed_message(client_b, [0xBB; 16], "Test", "for B");
        assert!(node.accept_fixture(&msg_a));
        assert!(node.accept_fixture(&msg_b));

        let tid_a = node.store.entries_for_destination(&client_a)[0].transient_id;
        let tid_b = node.store.entries_for_destination(&client_b)[0].transient_id;

        let encode_req = |wants: Option<&[[u8; 32]]>, haves: Option<&[[u8; 32]]>| -> Vec<u8> {
            let to_val = |ids: Option<&[[u8; 32]]>| match ids {
                Some(list) => {
                    Value::Array(list.iter().map(|t| Value::Binary(t.to_vec())).collect())
                }
                None => Value::Nil,
            };
            crate::encode_value(&Value::Array(vec![to_val(wants), to_val(haves)]))
        };
        let decode_msgs = |resp: &[u8]| -> usize {
            match rmpv::decode::read_value(&mut &resp[..]).unwrap() {
                Value::Array(items) => items.len(),
                _ => panic!("expected array response"),
            }
        };

        // A requesting B's message gets nothing.
        let resp = node
            .handle_get_request(&encode_req(Some(&[tid_b]), Some(&[])), &client_a)
            .into_response();
        assert_eq!(decode_msgs(&resp), 0);
        assert!(node.store.get(&tid_b).is_some());

        // A's haves cannot purge B's entry (Phase 3).
        node.handle_get_request(&encode_req(None, Some(&[tid_b])), &client_a)
            .into_response();
        assert!(
            node.store.get(&tid_b).is_some(),
            "foreign purge must be ignored"
        );
        assert!(
            node.object_paths[&tid_b].exists(),
            "B's file must survive A's purge attempt"
        );

        // A can still fetch its own message...
        let resp = node
            .handle_get_request(&encode_req(Some(&[tid_a]), Some(&[])), &client_a)
            .into_response();
        assert_eq!(decode_msgs(&resp), 1);

        // ...and purge it.
        node.handle_get_request(&encode_req(None, Some(&[tid_a])), &client_a)
            .into_response();
        assert!(!node.contains(&tid_a), "own purge must work");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// T1-15: one unreadable file in the messagestore must not abort the
    /// whole store load — it is quarantined (renamed `.corrupt`) and the
    /// remaining entries load.
    #[cfg(unix)]
    #[test]
    fn test_disk_load_preserves_unreadable_evidence_and_blocks_hosting() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store");
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            path.clone(),
        )
        .unwrap();
        let good = make_signed_message([0xCC; 16], [0xBB; 16], "healthy", "retained");
        let bad = make_signed_message([0xDD; 16], [0xBB; 16], "unreadable", "evidence");
        assert!(node.accept_fixture(&good));
        assert!(node.accept_fixture(&bad));
        let good_path = node.object_paths[&good.message_id()].clone();
        let bad_path = node.object_paths[&bad.message_id()].clone();
        let good_bytes = std::fs::read(&good_path).unwrap();
        let bad_bytes = std::fs::read(&bad_path).unwrap();
        drop(node);
        std::fs::set_permissions(&bad_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            path.clone(),
        );
        std::fs::set_permissions(&bad_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            result.is_err(),
            "authoritative committed corruption must block hosting"
        );
        assert_eq!(std::fs::read(good_path).unwrap(), good_bytes);
        assert_eq!(std::fs::read(bad_path).unwrap(), bad_bytes);
        assert_eq!(
            PropagationNode::with_storage(PropagationNodeConfig::default(), [0xAA; 16], path)
                .unwrap()
                .message_count(),
            2
        );
    }

    #[test]
    fn test_tick_culls_expired() {
        let config = PropagationNodeConfig {
            max_message_age: 1,
            ..Default::default()
        };
        let mut node = durable_test_node(config, [0xAA; 16]);

        let mut msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "will expire");
        msg.timestamp = 1000.0;
        node.accept_fixture(&msg);
        assert_eq!(node.message_count(), 1);

        node.tick();
        assert_eq!(node.message_count(), 0);
    }

    /// After a message is culled (expired), the same message resurfacing
    /// must be accepted again — the node's "seen" memory is the store
    /// itself, not a separate dedup log. Otherwise a node that culled a
    /// message and then received it again from another peer would
    /// silently drop it, breaking store-and-forward semantics.
    #[test]
    fn test_reaccept_after_cull() {
        let config = PropagationNodeConfig {
            max_message_age: 1,
            ..Default::default()
        };
        let mut node = durable_test_node(config, [0xAA; 16]);

        let mut msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "cull then redeliver");
        msg.timestamp = 1000.0;
        assert!(node.accept_fixture(&msg), "first accept");
        assert_eq!(node.message_count(), 1);

        node.tick();
        assert_eq!(node.message_count(), 0, "culled by tick");

        // Fresh timestamp so the re-delivery isn't itself expired.
        msg.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        assert!(
            node.accept_fixture(&msg),
            "same message re-accepted after cull"
        );
        assert_eq!(node.message_count(), 1);
    }

    /// A store that was full and rejecting new messages must recover
    /// capacity after culling — the reject-store-full path is transient,
    /// not terminal. Exercises: fill → reject → cull expired → accept.
    #[test]
    fn test_accept_after_store_full_and_cull() {
        let config = PropagationNodeConfig {
            max_storage: 1,
            max_message_age: 1,
            ..Default::default()
        };
        let mut node = durable_test_node(config, [0xAA; 16]);

        let mut msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "first");
        msg1.timestamp = 1000.0; // ancient so tick will cull it
        assert!(node.accept_fixture(&msg1));

        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "rejected-while-full");
        assert!(
            !node.accept_fixture(&msg2),
            "store full, second message must reject"
        );

        node.tick();
        assert_eq!(node.message_count(), 0, "expired msg culled");

        let msg3 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "accepted-after-cull");
        assert!(
            node.accept_fixture(&msg3),
            "store has space after cull, next message accepted"
        );
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_tick_enforces_weight_cap() {
        let mut node = durable_test_node(
            PropagationNodeConfig {
                max_storage: 1,
                ..PropagationNodeConfig::default()
            },
            [0xAA; 16],
        );
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "weight-cull");
        assert!(
            node.accept_fixture(&msg),
            "ingest cap checks size before insert, first message is admitted"
        );
        assert_eq!(node.message_count(), 1);
        node.tick();
        assert_eq!(
            node.message_count(),
            0,
            "tick must cull the store down to the weight cap"
        );
    }

    #[test]
    fn test_peer_persistence() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        // Load-time prune (Python LXMPeer.from_dict parity): a handled ID
        // backed by a live store entry survives; one whose message is gone
        // from the store is dropped.
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "peer-persist");
        assert!(node.accept_fixture(&msg));
        let live_id = node.create_offer_filtered(&HashSet::new())[0];

        let mut peer = LxmPeer::new([0xBB; 16]);
        peer.add_handled_message(&live_id);
        peer.add_handled_message(&tid(0xCC));
        node.save_peer(&peer).unwrap();

        drop(node);
        let node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let loaded_peers = node.load_peers();
        assert_eq!(loaded_peers.len(), 1);
        assert!(loaded_peers[0].has_handled(&live_id));
        assert!(
            !loaded_peers[0].has_handled(&tid(0xCC)),
            "handled ID without a store entry must be pruned at load"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_peer_persistence_multiple() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut peer1 = LxmPeer::new([0xBB; 16]);
        peer1.add_handled_message(&tid(0x11));
        node.save_peer(&peer1).unwrap();

        let mut peer2 = LxmPeer::new([0xDD; 16]);
        peer2.add_handled_message(&tid(0x22));
        peer2.add_handled_message(&tid(0x33));
        node.save_peer(&peer2).unwrap();

        let loaded = node.load_peers();
        assert_eq!(loaded.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_no_persistence_without_storage_path() {
        let node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let peer = LxmPeer::new([0xBB; 16]);
        node.save_peer(&peer).unwrap();

        let loaded = node.load_peers();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_disk_cleanup_on_cull() {
        let mut node = durable_test_node(
            PropagationNodeConfig {
                max_message_age: 1,
                ..Default::default()
            },
            [0xAA; 16],
        );
        let mut message = make_signed_message([0xBB; 16], [0xCC; 16], "cull", "cleanup");
        message.timestamp = 1000.;
        assert!(node.accept_fixture(&message));
        let id = message.message_id();
        let object = node.object_paths[&id].clone();
        assert!(object.exists());
        assert!(object.with_extension("entry").exists());
        node.tick();
        assert_eq!(node.message_count(), 0);
        assert!(!object.exists());
        assert!(!object.with_extension("entry").exists());
    }

    #[test]
    fn test_sync_session_management() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let peer_hash = [0xBB; 16];

        assert!(node.get_session(&peer_hash).is_none());

        let session = node.start_session(peer_hash);
        assert_eq!(session.peer_hash, peer_hash);

        assert!(node.get_session(&peer_hash).is_some());

        node.remove_session(&peer_hash);
        assert!(node.get_session(&peer_hash).is_none());
    }

    #[test]
    fn test_offer_request_returns_missing() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg1");
        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg2");
        let msg3 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg3");

        let tid1 = msg1.transient_id.unwrap();
        let tid2 = msg2.transient_id.unwrap();
        let tid3 = msg3.transient_id.unwrap();

        node.accept_fixture(&msg1);
        node.accept_fixture(&msg2);
        node.accept_fixture(&msg3);

        let peer_has = [tid1, tid2];
        let missing = node.offer_request([0xDD; 16], &peer_has);

        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&tid3));
    }

    #[test]
    fn test_offer_request_peer_has_nothing() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "content");
        node.accept_fixture(&msg);

        let missing = node.offer_request([0xDD; 16], &[]);
        assert_eq!(missing.len(), 1);
    }

    #[test]
    fn test_offer_request_peer_has_everything() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "content");
        let tid = msg.transient_id.unwrap();
        node.accept_fixture(&msg);

        let missing = node.offer_request([0xDD; 16], &[tid]);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_message_get_request_with_storage() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "get request content");
        let tid = msg.transient_id.unwrap();
        node.accept_fixture(&msg);

        let results = node.message_get_request(&[tid]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, tid);
        assert!(!results[0].1.is_empty());

        let mut expected = msg.data.clone();
        expected.extend_from_slice(&msg.stamp);
        assert_eq!(results[0].1, expected);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_message_get_request_unknown_id() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let results = node.message_get_request(&[tid(0xFF)]);
        assert!(results.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_message_get_request_no_storage() {
        let node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let results = node.message_get_request(&[tid(0xFF)]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_prepare_sync_offer() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "sync1");
        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "sync2");
        node.accept_fixture(&msg1);
        node.accept_fixture(&msg2);

        let peer_hash = [0xDD; 16];
        let offer = node.prepare_sync_offer(peer_hash);

        assert_eq!(offer.transient_ids.len(), 2);
        assert!(node.get_session(&peer_hash).is_some());
    }

    #[test]
    fn test_process_sync_offer_and_get() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "has_this");
        let tid1 = msg1.transient_id.unwrap();
        node.accept_fixture(&msg1);

        let peer_hash = [0xDD; 16];
        let tid2 = tid(0xEE);
        let offer = crate::sync::SyncOffer {
            peering_key: Vec::new(),
            transient_ids: vec![tid1.to_vec(), tid2.to_vec()],
        };

        let get = node.process_sync_offer(peer_hash, &offer);
        assert_eq!(get.wanted_ids.len(), 1);
        assert_eq!(get.wanted_ids[0], tid2.to_vec());
    }

    #[test]
    fn test_sync_lifecycle_complete() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let peer_hash = [0xDD; 16];

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "lifecycle");
        node.accept_fixture(&msg);

        let _offer = node.prepare_sync_offer(peer_hash);
        assert!(node.get_session(&peer_hash).is_some());

        node.complete_sync(&peer_hash);
        assert!(node.get_session(&peer_hash).is_none());
    }

    #[test]
    fn test_process_sync_get_with_storage() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "sync get content");
        let tid = msg.transient_id.unwrap();
        node.accept_fixture(&msg);

        let get = crate::sync::SyncGet {
            wanted_ids: vec![tid.to_vec()],
        };
        let peer_hash = [0xDD; 16];
        let messages = node.process_sync_get(peer_hash, &get);

        assert_eq!(messages.len(), 1);
        assert!(!messages[0].is_empty());

        let mut expected = msg.data.clone();
        expected.extend_from_slice(&msg.stamp);
        assert_eq!(messages[0], expected);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_encode_offer_response_roundtrip() {
        let encoded = PropagationNode::encode_offer_response(&OfferResponse::WantAll);
        let parsed = OfferResponse::from_msgpack(&encoded);
        assert_eq!(parsed, OfferResponse::WantAll);

        let encoded = PropagationNode::encode_offer_response(&OfferResponse::HaveAll);
        let parsed = OfferResponse::from_msgpack(&encoded);
        assert_eq!(parsed, OfferResponse::HaveAll);

        let encoded = PropagationNode::encode_offer_response(&OfferResponse::ErrorNoIdentity);
        let parsed = OfferResponse::from_msgpack(&encoded);
        assert_eq!(parsed, OfferResponse::ErrorNoIdentity);

        let encoded = PropagationNode::encode_offer_response(&OfferResponse::ErrorThrottled);
        let parsed = OfferResponse::from_msgpack(&encoded);
        assert_eq!(parsed, OfferResponse::ErrorThrottled);

        let ids = vec![id(0xAA), id(0xBB)];
        let encoded = PropagationNode::encode_offer_response(&OfferResponse::WantSome(ids.clone()));
        let parsed = OfferResponse::from_msgpack(&encoded);
        match parsed {
            OfferResponse::WantSome(parsed_ids) => {
                assert_eq!(parsed_ids, ids);
            }
            _ => panic!("expected WantSome"),
        }
    }

    #[test]
    fn test_handle_offer_request_valid() {
        let cost = 8;
        let local_identity = [0xAA; 16];
        let remote_identity = [0xBB; 16];
        let config = PropagationNodeConfig {
            peering_cost: cost,
            ..Default::default()
        };
        let mut node = durable_test_node(config, [0xCC; 16]);
        let key = peering_key(&local_identity, &remote_identity, cost);

        use rmpv::Value;
        let offer = Value::Array(vec![
            Value::Binary(key.to_vec()),
            Value::Array(vec![Value::Binary(id(0x11)), Value::Binary(id(0x22))]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &offer).unwrap();

        let response_bytes = node.handle_offer_request(
            &buf,
            offer_ctx(
                [0xDD; 16],
                true,
                false,
                true,
                Some(&local_identity),
                Some(&remote_identity),
            ),
        );
        let response = OfferResponse::from_msgpack(&response_bytes);
        assert_eq!(response, OfferResponse::WantAll);
    }

    #[test]
    fn test_offer_evaluation_uses_preflight_candidate_identity() {
        let cost = 8;
        let local_identity = [0xAA; 16];
        let remote_identity = [0xBB; 16];
        let config = PropagationNodeConfig {
            peering_cost: cost,
            ..Default::default()
        };
        let node = durable_test_node(config, [0xCC; 16]);
        let mut admission = crate::propagation_admission::PnInboundAdmission::default();
        let candidate = admission
            .preflight_offer([0xDD; 16], Some(remote_identity), std::time::Duration::ZERO)
            .unwrap();
        let key = peering_key(&local_identity, &remote_identity, cost);
        let request = crate::encode_value(&rmpv::Value::Array(vec![
            rmpv::Value::Binary(key.to_vec()),
            rmpv::Value::Array(vec![rmpv::Value::Binary(id(0x11))]),
        ]));

        assert_eq!(
            node.evaluate_offer_request(&request, &local_identity, &candidate),
            Ok(PnOfferEvaluation::WantAll)
        );
    }

    #[test]
    fn test_handle_offer_request_rejects_empty_peering_key_when_cost_required() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);
        let local_identity = [0xAA; 16];
        let remote_identity = [0xBB; 16];

        use rmpv::Value;
        let offer = Value::Array(vec![
            Value::Binary(vec![]),
            Value::Array(vec![Value::Binary(id(0x11))]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &offer).unwrap();

        let response_bytes = node.handle_offer_request(
            &buf,
            offer_ctx(
                [0xDD; 16],
                true,
                false,
                true,
                Some(&local_identity),
                Some(&remote_identity),
            ),
        );
        let response = OfferResponse::from_msgpack(&response_bytes);
        assert_eq!(response, OfferResponse::ErrorInvalidKey);
    }

    #[test]
    fn test_handle_offer_request_rejects_wrong_peering_identity_order() {
        let cost = 8;
        let local_identity = [0xAA; 16];
        let remote_identity = [0xBB; 16];
        let config = PropagationNodeConfig {
            peering_cost: cost,
            ..Default::default()
        };
        let mut node = durable_test_node(config, [0xCC; 16]);
        // A cost-8 stamp for the reverse order can also satisfy the forward
        // order by chance. Select a deterministic witness for the distinction
        // this regression asserts, and verify both preconditions explicitly.
        let rounds = crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING;
        let reverse = crate::stamper::stamp_workblock(
            &[remote_identity.as_slice(), local_identity.as_slice()].concat(),
            rounds,
        );
        let forward = crate::stamper::stamp_workblock(
            &[local_identity.as_slice(), remote_identity.as_slice()].concat(),
            rounds,
        );
        let key = (0u64..1_000_000)
            .find_map(|counter| {
                let mut candidate = [0u8; 32];
                candidate[..8].copy_from_slice(&counter.to_le_bytes());
                (crate::stamper::stamp_valid(&candidate, cost, &reverse)
                    && !crate::stamper::stamp_valid(&candidate, cost, &forward))
                .then_some(candidate)
            })
            .expect("reverse-only deterministic peering stamp");
        assert!(crate::stamper::stamp_valid(&key, cost, &reverse));
        assert!(!crate::stamper::stamp_valid(&key, cost, &forward));

        use rmpv::Value;
        let offer = Value::Array(vec![
            Value::Binary(key.to_vec()),
            Value::Array(vec![Value::Binary(id(0x11))]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &offer).unwrap();

        let response_bytes = node.handle_offer_request(
            &buf,
            offer_ctx(
                [0xDD; 16],
                true,
                false,
                true,
                Some(&local_identity),
                Some(&remote_identity),
            ),
        );
        let response = OfferResponse::from_msgpack(&response_bytes);
        assert_eq!(response, OfferResponse::ErrorInvalidKey);
    }

    #[test]
    fn test_handle_offer_request_no_identity() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);

        use rmpv::Value;
        let offer = Value::Array(vec![Value::Binary(vec![]), Value::Array(vec![])]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &offer).unwrap();

        let response_bytes =
            node.handle_offer_request(&buf, offer_ctx([0xBB; 16], false, false, true, None, None));
        let response = OfferResponse::from_msgpack(&response_bytes);
        assert_eq!(response, OfferResponse::ErrorNoIdentity);
    }

    #[test]
    fn test_handle_offer_request_invalid_data() {
        let mut node = durable_test_node(
            PropagationNodeConfig {
                peering_cost: 0,
                ..Default::default()
            },
            [0xAA; 16],
        );
        let local_identity = [0xAA; 16];
        let remote_identity = [0xBB; 16];

        let response_bytes = node.handle_offer_request(
            &[0xFF, 0xFF],
            offer_ctx(
                [0xBB; 16],
                true,
                false,
                true,
                Some(&local_identity),
                Some(&remote_identity),
            ),
        );
        let response = OfferResponse::from_msgpack(&response_bytes);
        assert_eq!(response, OfferResponse::ErrorInvalidData);

        let valid_request = crate::encode_value(&rmpv::Value::Array(vec![
            rmpv::Value::Binary(vec![]),
            rmpv::Value::Array(vec![rmpv::Value::Binary(id(0x11))]),
        ]));
        let response_bytes = node.handle_offer_request(
            &valid_request,
            offer_ctx(
                [0xBB; 16],
                true,
                false,
                true,
                Some(&local_identity),
                Some(&remote_identity),
            ),
        );
        let response = OfferResponse::from_msgpack(&response_bytes);
        assert_eq!(response, OfferResponse::WantAll);
    }

    #[test]
    fn test_handle_get_request_list_phase() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "get list content");
        node.accept_fixture(&msg);

        use rmpv::Value;
        let request = Value::Array(vec![Value::Nil, Value::Nil]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &request).unwrap();

        let response_bytes = node.handle_get_request(&buf, &[0xBB; 16]).into_response();
        let response: rmpv::Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        let arr = response.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].as_slice().unwrap().len(), 32);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_handle_get_request_list_empty() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);

        use rmpv::Value;
        let request = Value::Array(vec![Value::Nil, Value::Nil]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &request).unwrap();

        let response_bytes = node.handle_get_request(&buf, &[0xBB; 16]).into_response();
        let response: rmpv::Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        let arr = response.as_array().unwrap();
        assert!(arr.is_empty());
    }

    #[test]
    fn test_accept_propagated_blob_and_get_with_full_hash_id() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut lxmf_data = vec![0xBB; 16];
        lxmf_data.extend_from_slice(&[0xCC; 128]);
        assert!(node.accept_blob_fixture(&lxmf_data, 0));

        let full_id = rns_crypto::sha::full_hash(&lxmf_data);
        use rmpv::Value;
        let list_request = Value::Array(vec![Value::Nil, Value::Nil]);
        let mut list_buf = Vec::new();
        rmpv::encode::write_value(&mut list_buf, &list_request).unwrap();
        let list_response = node
            .handle_get_request(&list_buf, &[0xBB; 16])
            .into_response();
        let list_value: Value = rmpv::decode::read_value(&mut &list_response[..]).unwrap();
        assert_eq!(list_value.as_array().unwrap().len(), 1);

        let get_request = Value::Array(vec![
            Value::Array(vec![Value::Binary(full_id.to_vec())]),
            Value::Array(vec![]),
        ]);
        let mut get_buf = Vec::new();
        rmpv::encode::write_value(&mut get_buf, &get_request).unwrap();
        let get_response = node
            .handle_get_request(&get_buf, &[0xBB; 16])
            .into_response();
        let get_value: Value = rmpv::decode::read_value(&mut &get_response[..]).unwrap();
        let messages = get_value.as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].as_slice().unwrap(), lxmf_data.as_slice());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_stamped_propagated_blob_strips_only_for_client_download() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut lxmf_data = vec![0xBB; 16];
        lxmf_data.extend_from_slice(&[0xCC; 128]);
        let stamp = [0x5A; 32];
        let full_id = rns_crypto::sha::full_hash(&lxmf_data);

        assert!(
            node.accept_stamped_propagated_blob(
                &lxmf_data,
                &stamp,
                crate::stamper::stamp_value(
                    &crate::stamper::stamp_workblock(
                        &rns_crypto::sha::full_hash(&lxmf_data),
                        STAMP_WORKBLOCK_EXPAND_ROUNDS_PN
                    ),
                    &stamp
                )
                .min(255) as u8
            )
        );

        let peer_results = node.message_get_request(&[full_id]);
        assert_eq!(peer_results.len(), 1);
        let mut expected_stamped = lxmf_data.clone();
        expected_stamped.extend_from_slice(&stamp);
        assert_eq!(peer_results[0].1, expected_stamped);

        use rmpv::Value;
        let get_request = Value::Array(vec![
            Value::Array(vec![Value::Binary(full_id.to_vec())]),
            Value::Array(vec![]),
        ]);
        let mut get_buf = Vec::new();
        rmpv::encode::write_value(&mut get_buf, &get_request).unwrap();
        let get_response = node
            .handle_get_request(&get_buf, &[0xBB; 16])
            .into_response();
        let get_value: Value = rmpv::decode::read_value(&mut &get_response[..]).unwrap();
        let messages = get_value.as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].as_slice().unwrap(), lxmf_data.as_slice());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reloaded_stamped_blob_strips_for_client_download() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut lxmf_data = vec![0xBB; 16];
        lxmf_data.extend_from_slice(&[0xCC; 128]);
        let stamp = [0x5A; 32];
        let full_id = rns_crypto::sha::full_hash(&lxmf_data);

        {
            let mut node = PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                [0xAA; 16],
                dir.clone(),
            )
            .unwrap();
            assert!(
                node.accept_stamped_propagated_blob(
                    &lxmf_data,
                    &stamp,
                    crate::stamper::stamp_value(
                        &crate::stamper::stamp_workblock(
                            &rns_crypto::sha::full_hash(&lxmf_data),
                            STAMP_WORKBLOCK_EXPAND_ROUNDS_PN
                        ),
                        &stamp
                    )
                    .min(255) as u8
                )
            );
        }

        let mut reloaded = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        use rmpv::Value;
        let get_request = Value::Array(vec![
            Value::Array(vec![Value::Binary(full_id.to_vec())]),
            Value::Array(vec![]),
        ]);
        let mut get_buf = Vec::new();
        rmpv::encode::write_value(&mut get_buf, &get_request).unwrap();
        let get_response = reloaded
            .handle_get_request(&get_buf, &[0xBB; 16])
            .into_response();
        let get_value: Value = rmpv::decode::read_value(&mut &get_response[..]).unwrap();
        let messages = get_value.as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].as_slice().unwrap(), lxmf_data.as_slice());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_propagated_blob_enforces_min_stamp_cost() {
        let config = PropagationNodeConfig {
            min_stamp_cost: 8,
            ..Default::default()
        };
        let mut node = durable_test_node(config, [0xAA; 16]);

        let mut lxmf_data = vec![0xBB; 16];
        lxmf_data.extend_from_slice(&[0xCC; 128]);

        assert!(!node.accept_blob_fixture(&lxmf_data, 7));
        assert_eq!(node.message_count(), 0);

        assert!(node.accept_blob_fixture(&lxmf_data, 8));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_opaque_propagated_blob_reload_preserves_destination() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut lxmf_data = vec![0xBB; 16];
        lxmf_data.extend_from_slice(&[0xCC; 128]);
        assert!(node.accept_blob_fixture(&lxmf_data, 0));
        drop(node);

        let mut reloaded = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        use rmpv::Value;
        let list_request = Value::Array(vec![Value::Nil, Value::Nil]);
        let mut list_buf = Vec::new();
        rmpv::encode::write_value(&mut list_buf, &list_request).unwrap();
        let response = reloaded
            .handle_get_request(&list_buf, &[0xBB; 16])
            .into_response();
        let value: Value = rmpv::decode::read_value(&mut &response[..]).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1);

        let full_id = rns_crypto::sha::full_hash(&lxmf_data);
        let get_request = Value::Array(vec![
            Value::Array(vec![Value::Binary(full_id.to_vec())]),
            Value::Array(vec![]),
        ]);
        let mut get_buf = Vec::new();
        rmpv::encode::write_value(&mut get_buf, &get_request).unwrap();
        let response = reloaded
            .handle_get_request(&get_buf, &[0xBB; 16])
            .into_response();
        let value: Value = rmpv::decode::read_value(&mut &response[..]).unwrap();
        assert_eq!(
            value.as_array().unwrap()[0].as_slice().unwrap(),
            lxmf_data.as_slice(),
            "legacy opaque blobs have no stamp to strip after restart"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_opaque_blob_reload_preserves_bytes_and_accounting_at_minimum_lengths() {
        use rmpv::Value;
        for len in [17, 31, 32, 33, 48, 49, 144] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("store");
            let mut node = PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                [0xAA; 16],
                path.clone(),
            )
            .unwrap();
            assert!(!node.accept_blob_fixture(&[0xBB; 16], 0));
            let mut blob = vec![0xBB; 16];
            blob.resize(len, 0xCC);
            let (stamp, value) = fixture_stamp(&blob, 0);
            let id = rns_crypto::sha::full_hash(&blob);
            let mut stored = blob.clone();
            stored.extend_from_slice(&stamp);
            assert!(node.accept_stamped_propagated_blob(&blob, &stamp, value as u8));
            let object = node.object_paths[&id].clone();
            assert_eq!(std::fs::read(&object).unwrap(), stored);
            drop(node);
            let mut node =
                PropagationNode::with_storage(PropagationNodeConfig::default(), [0xAA; 16], path)
                    .unwrap();
            assert_eq!(node.message_count(), 1);
            assert_eq!(node.total_size(), stored.len());
            assert!(node.store.get(&id).unwrap().stamped);
            assert!(!node.accept_stamped_propagated_blob(&blob, &stamp, value as u8));
            assert!(node.pending_write_ids.is_empty());
            assert_eq!(node.pending_write_bytes, 0);
            let request = crate::encode_value(&Value::Array(vec![
                Value::Array(vec![Value::Binary(id.to_vec())]),
                Value::Array(vec![]),
            ]));
            let response = node
                .handle_get_request(&request, &[0xBB; 16])
                .into_response();
            let decoded = rmpv::decode::read_value(&mut response.as_slice()).unwrap();
            assert_eq!(decoded.as_array().unwrap()[0].as_slice().unwrap(), blob);
            assert_eq!(node.message_get_request(&[id]), vec![(id, stored.clone())]);
            assert_eq!(std::fs::read(object).unwrap(), stored);
        }
    }

    #[test]
    fn test_reloaded_legacy_message_keeps_original_get_bytes() {
        // Ordinary startup never promotes a recognizable legacy plaintext LXMF
        // file into relay provenance, even when its filename uses a real ID.
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("store");
        std::fs::create_dir(&legacy).unwrap();
        let message = crate::message::test_message(
            [0xBB; 16],
            [0xCC; 16],
            "legacy",
            "full message",
            DeliveryMethod::Propagated,
        );
        let file = legacy.join(format!("{}_100_0", hex::encode(message.message_id())));
        std::fs::write(&file, message.wire_bytes()).unwrap();
        assert!(
            PropagationNode::with_storage(PropagationNodeConfig::default(), [0xAA; 16], legacy)
                .is_err()
        );
        assert_eq!(std::fs::read(file).unwrap(), message.wire_bytes());
    }

    #[test]
    fn test_handle_get_request_purge_phase() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "purge content");
        let tid = msg.transient_id.unwrap();
        node.accept_fixture(&msg);
        assert_eq!(node.message_count(), 1);

        use rmpv::Value;
        let request = Value::Array(vec![
            Value::Nil,
            Value::Array(vec![Value::Binary(tid.to_vec())]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &request).unwrap();

        let _response_bytes = node.handle_get_request(&buf, &[0xBB; 16]).into_response();
        assert_eq!(node.message_count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_handle_get_request_get_phase() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "get data content");
        let tid = msg.transient_id.unwrap();
        node.accept_fixture(&msg);

        use rmpv::Value;
        let request = Value::Array(vec![
            Value::Array(vec![Value::Binary(tid.to_vec())]),
            Value::Array(vec![]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &request).unwrap();

        let response_bytes = node.handle_get_request(&buf, &[0xBB; 16]).into_response();
        let response: rmpv::Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        let arr = response.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(!arr[0].as_slice().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// T2-8b: phase 2 must come back as a read plan (file I/O deferred until
    /// after the node lock is released); phases 1/3 answer immediately.
    #[test]
    fn test_get_request_phase2_returns_serve_plan() {
        use rmpv::Value;

        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut blob = vec![0xBB; 16];
        blob.extend_from_slice(&[0x11; 64]);
        assert!(node.accept_blob_fixture(&blob, 0));
        let tid = rns_crypto::sha::full_hash(&blob);

        let list_req = crate::encode_value(&Value::Array(vec![Value::Nil, Value::Nil]));
        assert!(matches!(
            node.handle_get_request(&list_req, &[0xBB; 16]),
            GetRequestAction::Respond(_)
        ));

        let purge_req = crate::encode_value(&Value::Array(vec![
            Value::Nil,
            Value::Array(vec![Value::Binary(vec![0xEE; 32])]),
        ]));
        assert!(matches!(
            node.handle_get_request(&purge_req, &[0xBB; 16]),
            GetRequestAction::ServeFiles(_)
        ));

        let get_req = crate::encode_value(&Value::Array(vec![
            Value::Array(vec![Value::Binary(tid.to_vec())]),
            Value::Array(vec![]),
        ]));
        let action = node.handle_get_request(&get_req, &[0xBB; 16]);
        let GetRequestAction::ServeFiles(plan) = action else {
            panic!("phase 2 must return a serve plan");
        };
        // Reads resolve after the node borrow ends (embedder drops the lock).
        drop(node);
        let (response_bytes, served) = plan.serve_with_count();
        let response: Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        let messages = response.as_array().unwrap();
        assert_eq!(served, 1);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].as_slice().unwrap(), blob.as_slice());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// T2-8b parity: haves are purged before wants resolve (Python
    /// LXMRouter.py:1451-1462) — an ID in both is purged, not served.
    #[test]
    fn test_get_phase_purges_haves_before_serving_wants() {
        use rmpv::Value;

        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut blob = vec![0xBB; 16];
        blob.extend_from_slice(&[0x22; 48]);
        assert!(node.accept_blob_fixture(&blob, 0));
        let tid = rns_crypto::sha::full_hash(&blob);

        let req = crate::encode_value(&Value::Array(vec![
            Value::Array(vec![Value::Binary(tid.to_vec())]),
            Value::Array(vec![Value::Binary(tid.to_vec())]),
        ]));
        let response_bytes = node.handle_get_request(&req, &[0xBB; 16]).into_response();
        let response: Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        assert!(
            response.as_array().unwrap().is_empty(),
            "ID in both wants and haves must be purged, not served"
        );
        assert_eq!(node.message_count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// T2-8b parity: transfer limit is kB ×1000 with 24-byte base and 16-byte
    /// per-message overhead, and over-limit entries are skipped rather than
    /// aborting the serve loop (Python LXMRouter.py:1471-1494).
    #[test]
    fn test_get_phase_transfer_limit_python_accounting() {
        use rmpv::Value;

        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let make_blob = |fill: u8, total_len: usize| {
            let mut blob = vec![0xBB; 16];
            blob.extend(std::iter::repeat_n(fill, total_len - 16));
            blob
        };
        // Cumulative starts at 24, +16 per message: a (100 B) -> 140;
        // b (350 B) -> 506 > 500 so skipped (would pass a 1024-unit limit of
        // 512, pinning the ×1000 wire unit); c (50 B) -> 206, still served.
        let blob_a = make_blob(0x01, 100);
        let blob_b = make_blob(0x02, 350);
        let blob_c = make_blob(0x03, 50);
        for blob in [&blob_a, &blob_b, &blob_c] {
            assert!(node.accept_blob_fixture(blob, 0));
        }

        let wants: Vec<Value> = [&blob_a, &blob_b, &blob_c]
            .iter()
            .map(|blob| Value::Binary(rns_crypto::sha::full_hash(blob).to_vec()))
            .collect();
        let req = crate::encode_value(&Value::Array(vec![
            Value::Array(wants),
            Value::Array(vec![]),
            Value::F64(0.5),
        ]));

        let response_bytes = node.handle_get_request(&req, &[0xBB; 16]).into_response();
        let response: Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        let messages = response.as_array().unwrap();
        assert_eq!(messages.len(), 2, "b is skipped, a and c are served");
        assert_eq!(messages[0].as_slice().unwrap(), blob_a.as_slice());
        assert_eq!(messages[1].as_slice().unwrap(), blob_c.as_slice());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// T2-8b parity: phase-1 listing is sorted smallest message first
    /// (Python LXMRouter.py:1437-1444).
    #[test]
    fn test_get_list_phase_sorted_smallest_first() {
        use rmpv::Value;

        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path().join("store");
        let _ = std::fs::remove_dir_all(&dir);
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let make_blob = |fill: u8, total_len: usize| {
            let mut blob = vec![0xBB; 16];
            blob.extend(std::iter::repeat_n(fill, total_len - 16));
            blob
        };
        let blob_large = make_blob(0x04, 300);
        let blob_small = make_blob(0x05, 100);
        let blob_mid = make_blob(0x06, 200);
        for blob in [&blob_large, &blob_small, &blob_mid] {
            assert!(node.accept_blob_fixture(blob, 0));
        }

        let list_req = crate::encode_value(&Value::Array(vec![Value::Nil, Value::Nil]));
        let response_bytes = node
            .handle_get_request(&list_req, &[0xBB; 16])
            .into_response();
        let response: Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        let ids: Vec<Vec<u8>> = response
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_slice().unwrap().to_vec())
            .collect();
        let expected: Vec<Vec<u8>> = [&blob_small, &blob_mid, &blob_large]
            .iter()
            .map(|blob| rns_crypto::sha::full_hash(blob).to_vec())
            .collect();
        assert_eq!(ids, expected);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_stamp_cost_validation_rejects_unstamped() {
        let config = PropagationNodeConfig {
            min_stamp_cost: 8,
            ..Default::default()
        };
        let mut node = durable_test_node(config, [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "unstamped");

        assert!(!node.accept_fixture(&msg));
        assert_eq!(node.message_count(), 0);
    }

    #[test]
    fn test_stamp_cost_zero_accepts_all() {
        let config = PropagationNodeConfig {
            min_stamp_cost: 0,
            ..Default::default()
        };
        let mut node = durable_test_node(config, [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "no_cost");

        assert!(node.accept_fixture(&msg));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_create_offer_with_stamp_filter() {
        let mut node = durable_test_node(PropagationNodeConfig::default(), [0xAA; 16]);

        let entry1 = crate::propagation::PropagationEntry {
            transient_id: tid(0x01),
            message_hash: [0x11; 32],
            destination_hash: [0xCC; 16],
            stored_at: 1000.0,
            stamp_value: 20,
            size: 100,
            collected: false,
            stamped: false,
        };
        let entry2 = crate::propagation::PropagationEntry {
            transient_id: tid(0x02),
            message_hash: [0x22; 32],
            destination_hash: [0xCC; 16],
            stored_at: 1000.0,
            stamp_value: 5,
            size: 100,
            collected: false,
            stamped: false,
        };
        node.store.insert(entry1);
        node.store.insert(entry2);

        let all = node.create_offer([0xFF; 16], None);
        assert_eq!(all.len(), 2);

        let filtered = node.create_offer([0xFF; 16], Some(10));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], tid(0x01));

        let all2 = node.create_offer([0xFF; 16], Some(0));
        assert_eq!(all2.len(), 2);
    }
    #[test]
    fn bounded_get_schema_rejects_amplification_and_nonfinite_limits_before_purge() {
        use rmpv::Value;
        let temporary = tempfile::tempdir().unwrap();
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [1; 16],
            temporary.path().join("store"),
        )
        .unwrap();
        let blob = vec![0xBB; 100];
        assert!(node.accept_blob_fixture(&blob, 0));
        let tid = rns_crypto::sha::full_hash(&blob);
        for limit in [
            Value::F64(f64::NAN),
            Value::F64(f64::INFINITY),
            Value::F64(-1.),
            Value::F64(f64::MAX),
            Value::from("bad"),
            Value::Nil,
        ] {
            let request = crate::encode_value(&Value::Array(vec![
                Value::Nil,
                Value::Array(vec![Value::Binary(tid.to_vec())]),
                limit,
            ]));
            assert_eq!(
                node.handle_get_request_bounded(&request, &[0xBB; 16], 1024)
                    .into_response_with_served_count_bounded(1024),
                (vec![0xc0], 0)
            );
            assert_eq!(node.message_count(), 1);
        }
        for malformed in [
            vec![0x92, 0xdd, 0xff, 0xff, 0xff, 0xff],
            vec![0x92, 0x91, 0x90, 0xc0],
            vec![0x92, 0xc0, 0xc0, 0xc0],
        ] {
            assert!(parse_get_request(&malformed).is_none());
            assert_eq!(node.message_count(), 1);
        }
        // More than the historical packet-sized ID count remains valid.
        let request = crate::encode_value(&Value::Array(vec![
            Value::Array(vec![Value::Binary(tid.to_vec()); 2048]),
            Value::Array(vec![]),
        ]));
        assert_eq!(
            get_ids(parse_get_request(&request).unwrap().wants).count(),
            2048
        );
    }

    #[test]
    fn bounded_get_deduplicates_and_fits_exact_encoded_boundary() {
        use rmpv::Value;
        let temporary = tempfile::tempdir().unwrap();
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [1; 16],
            temporary.path().join("store"),
        )
        .unwrap();
        let blob = vec![0xBB; 100];
        assert!(node.accept_blob_fixture(&blob, 0));
        let tid = rns_crypto::sha::full_hash(&blob);
        let request = crate::encode_value(&Value::Array(vec![
            Value::Array(vec![Value::Binary(tid.to_vec()); 4]),
            Value::Array(vec![]),
        ]));
        let (bytes, count) = node
            .handle_get_request_bounded(&request, &[0xBB; 16], 103)
            .into_response_with_served_count_bounded(103);
        assert_eq!(count, 1);
        assert_eq!(bytes.len(), 103);
        assert!(bytes.capacity() <= 103);
        assert_eq!(
            rmpv::decode::read_value(&mut bytes.as_slice()).unwrap(),
            Value::Array(vec![Value::Binary(blob)])
        );
        let (bytes, count) = node
            .handle_get_request_bounded(&request, &[0xBB; 16], 102)
            .into_response_with_served_count_bounded(102);
        assert_eq!(count, 0);
        assert_eq!(bytes, vec![0x90]);
        assert!(bytes.capacity() <= 102);
    }

    #[test]
    fn bounded_get_skips_corrupt_or_grown_file_without_reading_past_plan() {
        use rmpv::Value;
        let temporary = tempfile::tempdir().unwrap();
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [1; 16],
            temporary.path().join("store"),
        )
        .unwrap();
        let blob = vec![0xBB; 100];
        assert!(node.accept_blob_fixture(&blob, 0));
        let tid = rns_crypto::sha::full_hash(&blob);
        let request = crate::encode_value(&Value::Array(vec![
            Value::Array(vec![Value::Binary(tid.to_vec())]),
            Value::Array(vec![]),
        ]));
        let action = node.handle_get_request_bounded(&request, &[0xBB; 16], 103);
        std::fs::write(&node.object_paths[&tid], vec![0; 4096]).unwrap();
        assert_eq!(
            action.into_response_with_served_count_bounded(103),
            (vec![0x90], 0)
        );
    }

    #[test]
    fn bounded_get_listing_stays_within_reserved_output_capacity() {
        use rmpv::Value;
        let temporary = tempfile::tempdir().unwrap();
        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [1; 16],
            temporary.path().join("store"),
        )
        .unwrap();
        for n in 0..4 {
            let mut blob = vec![0xBB; 100 + n];
            blob[20] = n as u8;
            assert!(node.accept_blob_fixture(&blob, 0));
        }
        let (response, _) = node
            .handle_get_request_bounded(&[0x92, 0xc0, 0xc0], &[0xBB; 16], 73)
            .into_response_with_served_count_bounded(73);
        assert!(response.capacity() <= 73);
        assert!(
            matches!(rmpv::decode::read_value(&mut response.as_slice()).unwrap(),Value::Array(ids) if ids.len()==2)
        );
    }
}
