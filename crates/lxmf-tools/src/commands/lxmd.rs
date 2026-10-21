//! LXMF Daemon (lxmd) -- propagation node and message handler.
//!
//! Python reference: LXMF/Utilities/lxmd.py.

#[path = "lxmd_pn.rs"]
mod lxmd_pn;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::Parser;
use tokio::sync::{mpsc, oneshot};

use std::sync::{Arc, Mutex};

use lxmf_core::admission::{
    AdmissionEpochs, AdmissionRecord, DownloadAdmissionOutcome, DownloadAdmissionToken,
    DownloadedPropagationMessage, DurableAdmissionReceipt, DurableDisposition, ProcessingLease,
    SuppressionReason,
};
use lxmf_core::admission_store::FileAdmissionStore;
use lxmf_core::constants::{
    DELIVERY_RETRY_WAIT, DeliveryMethod, MAX_DELIVERY_ATTEMPTS, NODE_ANNOUNCE_DELAY,
    PATH_REQUEST_WAIT,
};
use lxmf_core::delivery_ratchet::{DELIVERY_APP_NAME, DeliveryAnnounceKind, DeliveryRatchetState};
use lxmf_core::inbound_resource::{
    InboundResourceCancelRequest, InboundResourceConclusion, InboundResourceEvent,
    InboundResourceKey,
};
use lxmf_core::link_delivery::{
    BackchannelSendCommand, BackchannelSendError, BackchannelSendReceipt, DeliveryResult,
    is_retryable_link_delivery_failure,
};
use lxmf_core::message::{LxMessage, LxMessageDraft, MessageError};
use lxmf_core::peer::{LxmPeer, OutboundOfferPolicy};
use lxmf_core::propagation_node::{
    PropagationNode, PropagationNodeConfig, PropagationStoreWritePlan,
};
use lxmf_core::propagation_send::{
    AdvertisedNodePolicy, MissingPropagationInput, PropagationEnvelope, propagation_readiness,
};
use lxmf_core::router::{
    AutopeerCandidate, DirectDeliveryPlan, DirectDeliveryPlanInput, DirectReusableLinkState,
    DirectRouteSnapshot, LxmRouter, OutboundAction, plan_direct_delivery,
};
use lxmf_tools::daemon::{DaemonConfig, create_router_with_transport, persist_inbound_and_execute};
use lxmf_tools::lxmd_cli::{
    Args, example_config, load_hash_list, normalize_hash_hex, parse_destination_hash,
    parse_send_fields_json,
};
use lxmf_tools::lxmd_control::{
    CONTROL_APP_NAME, ControlCommandKind, ControlResponse, decode_control_response,
    encode_control_success, encode_nil_response, encode_peer_error, encode_router_control_stats,
    exit_for_control_response, format_remote_status, print_control_link_error, query_control,
    resolve_remote_identity_hash,
};
use lxmf_tools::lxmd_runtime::{
    LxmdPaths, delivery_announce_app_data, preflight_control_command,
    propagation_announce_app_data, resolve_config_dirs,
};
use rns_identity::announce::AnnounceData;
use rns_identity::destination::Destination;
use rns_identity::identity::Identity;
use rns_identity::persistence::{
    durable_create_dir_all, durable_reconcile, durable_write, validate_durable_storage_directory,
};
use rns_identity::ratchet::{
    ReceivedRatchet, clean_received_ratchets_dir, purge_expired_ratchets_in_memory,
};
use rns_runtime::lifecycle::ShutdownSignal;
use rns_runtime::link_manager::{
    LinkManagerAccountingEvent, LinkManagerCommand, LinkResourceConclusion, LinkResourceDirection,
    LinkResourceEvent,
};
use rns_runtime::reticulum::{AnnounceSubscription, AnnounceSubscriptionError, ReticulumHandle};
use rns_transport::messages::{TransportMessage, TransportQuery, TransportQueryResponse};

use self::lxmd_pn::{
    PnInboundRuntime, PnValidationJob, PnValidationOutcome, PnValidationToken, logical_resource_id,
};

#[derive(Debug, Clone, Default)]
struct ControlSnapshot {
    allowed_control: Vec<[u8; 16]>,
    auth_required: bool,
    allowed_clients: Vec<[u8; 16]>,
    peer_hashes: HashSet<[u8; 16]>,
    stats_response: Option<Vec<u8>>,
}

fn propagation_client_allowed(
    snapshot: &ControlSnapshot,
    remote_identity_hash: Option<&[u8; 16]>,
) -> bool {
    !snapshot.auth_required
        || remote_identity_hash.is_some_and(|hash| snapshot.allowed_clients.contains(hash))
}

#[derive(Debug, Clone, Copy)]
enum ControlCommand {
    Sync([u8; 16]),
    Unpeer([u8; 16]),
}

fn queue_control_command(
    command_tx: &mpsc::UnboundedSender<ControlCommand>,
    command: ControlCommand,
) -> Vec<u8> {
    if command_tx.send(command).is_ok() {
        encode_control_success()
    } else {
        encode_peer_error(lxmf_core::constants::PeerError::Timeout)
    }
}

/// Synchronous LinkManager callbacks cannot await the bounded transport
/// mailbox. Keep only the newest announce for each destination until the
/// daemon actor can enqueue it. Repeated requests for the same destination
/// are equivalent, so coalescing is lossless at the protocol-operation level
/// while keeping memory bounded by the number of announce destinations.
#[derive(Clone, Default)]
struct AnnounceMailbox {
    pending: Arc<Mutex<HashMap<[u8; 16], TransportMessage>>>,
}

impl AnnounceMailbox {
    fn stage(&self, destination_hash: [u8; 16], message: TransportMessage) {
        match self.pending.lock() {
            Ok(mut pending) => {
                if pending.insert(destination_hash, message).is_some() {
                    tracing::debug!(
                        destination = %hex::encode(destination_hash),
                        "coalesced repeated required announce"
                    );
                }
            }
            Err(_) => tracing::error!(
                destination = %hex::encode(destination_hash),
                "required announce mailbox lock poisoned"
            ),
        }
    }

    fn take_pending(&self) -> Vec<([u8; 16], TransportMessage)> {
        match self.pending.lock() {
            Ok(mut pending) => pending.drain().collect(),
            Err(_) => {
                tracing::error!("required announce mailbox lock poisoned");
                Vec::new()
            }
        }
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending
            .lock()
            .map(|pending| pending.len())
            .unwrap_or_default()
    }
}

const LOSSLESS_QUEUE_WARN_DEPTH: usize = 1024;

#[derive(Debug, Default)]
struct LosslessQueueHighWater {
    control_commands: usize,
    link_packets: usize,
    delivery_accounting: usize,
    propagation_link_packets: usize,
    propagation_accounting: usize,
    store_commits: usize,
    store_write_tasks: usize,
    client_served: usize,
}

fn observe_lossless_queue_depth(queue: &'static str, depth: usize, high_water: &mut usize) {
    if depth <= *high_water {
        return;
    }
    *high_water = depth;
    if depth >= LOSSLESS_QUEUE_WARN_DEPTH {
        tracing::warn!(
            queue,
            depth,
            "lossless daemon queue reached a new high-water mark"
        );
    } else {
        tracing::debug!(
            queue,
            depth,
            "lossless daemon queue reached a new high-water mark"
        );
    }
}

fn round_robin_peer_order(
    mut peers: Vec<[u8; 16]>,
    last_selected: Option<[u8; 16]>,
) -> Vec<[u8; 16]> {
    peers.sort_unstable();
    if let (Some(last_selected), false) = (last_selected, peers.is_empty()) {
        let next = peers.partition_point(|peer| *peer <= last_selected);
        let peer_count = peers.len();
        peers.rotate_left(next % peer_count);
    }
    peers
}

#[derive(Debug)]
struct ValidatedPnEntry {
    lxmf_data: Vec<u8>,
    stamp_value: u32,
    stamp_data: [u8; 32],
}

#[derive(Debug)]
struct PnValidationWorkerResult {
    token: PnValidationToken,
    link_id: [u8; 16],
    outcome: PnValidationOutcome,
    entries: Vec<ValidatedPnEntry>,
    rejected: usize,
}

#[derive(Debug)]
struct PnPacketValidationWorkerResult {
    receipt: Option<rns_runtime::link_manager::LinkPacketReceipt>,
    payload_owner: Bytes,
    malformed: bool,
    stored: bool,
    committed: Vec<([u8; 32], u64)>,
    link_id: [u8; 16],
    #[cfg(test)]
    entries: Vec<ValidatedPnEntry>,
    #[cfg(test)]
    timing: Option<PnTestTiming>,
    rejected: usize,
}

#[derive(Debug)]
struct PnPacketValidationJob {
    link_id: [u8; 16],
    data: Bytes,
    receipt: Option<rns_runtime::link_manager::LinkPacketReceipt>,
    node: Arc<Mutex<PropagationNode>>,
    max_transfer_bytes: usize,
    min_cost: u8,
    #[cfg(test)]
    store_delay: Duration,
    #[cfg(test)]
    enqueued_at: Instant,
}

/// The request callback only admits a bounded blocking job. Closing this owner
/// excludes new jobs under the same lock used to register actual worker handles.
#[derive(Clone, Default)]
struct PnGetWorkers {
    state: Arc<Mutex<PnGetWorkerState>>,
    active: Arc<tokio::sync::RwLock<()>>,
    #[cfg(test)]
    pause: Arc<Mutex<Option<PathBuf>>>,
}
#[derive(Default)]
struct PnGetWorkerState {
    closed: bool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl PnGetWorkers {
    fn spawn(&self, job: impl FnOnce() + Send + 'static) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state.tasks.retain(|task| !task.is_finished());
        if state.closed || state.tasks.len() >= 4 {
            return false;
        }
        let Ok(active) = self.active.clone().try_read_owned() else {
            return false;
        };
        #[cfg(test)]
        let pause = self.pause.lock().unwrap().clone();
        state.tasks.push(tokio::task::spawn_blocking(move || {
            let _active = active;
            #[cfg(test)]
            if let Some(root) = pause {
                std::fs::write(root.join("get.entered"), b"worker owns request\n").unwrap();
                let deadline = Instant::now() + Duration::from_secs(15);
                while !root.join("get.release").exists() {
                    assert!(Instant::now() < deadline, "private get pause timed out");
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            job();
        }));
        true
    }
    async fn close_and_join(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        // A cancelled shutdown waiter does not lose ownership of live workers.
        let _quiescent = self.active.clone().write_owned().await;
        let tasks = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut state.tasks)
        };
        for task in tasks {
            if let Err(error) = task.await {
                tracing::warn!(%error, "PN get worker failed during shutdown");
            }
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct PnTestTiming {
    received_at: Instant,
    packet_hash: String,
    queue_ms: f64,
    validation_ms: f64,
    store_ms: f64,
}

#[derive(Debug)]
struct PendingOpportunisticDelivery {
    message: LxMessage,
    retry_at: f64,
}

#[derive(Debug, Clone, Copy)]
enum PropagationStoreWriteOrigin {
    Peer([u8; 16]),
    Client,
}

#[derive(Debug)]
struct PropagationStoreCommitResult {
    origin: PropagationStoreWriteOrigin,
    committed: Vec<([u8; 32], u64)>,
}

fn spawn_propagation_store_writes(
    node: Arc<Mutex<PropagationNode>>,
    plans: Vec<(PropagationStoreWritePlan, u64)>,
    origin: PropagationStoreWriteOrigin,
    commit_tx: mpsc::UnboundedSender<PropagationStoreCommitResult>,
    operation: &'static str,
) -> Option<tokio::task::JoinHandle<()>> {
    if plans.is_empty() {
        return None;
    }
    Some(tokio::task::spawn_blocking(move || {
        let mut committed = Vec::new();
        for (plan, accounted_bytes) in plans {
            let transient_id = plan.transient_id();
            let size = plan.size();
            match plan.persist() {
                Ok(persisted) => {
                    if node
                        .lock()
                        .map(|mut node| node.commit_store_write(persisted))
                        .unwrap_or(false)
                    {
                        committed.push((transient_id, accounted_bytes));
                    }
                }
                Err(error) => {
                    if let Ok(mut node) = node.lock() {
                        node.abort_store_write(&transient_id, size);
                    }
                    tracing::warn!(
                        transient_id = %hex::encode(transient_id),
                        %error,
                        operation,
                        "propagation store write failed"
                    );
                }
            }
        }
        tracing::debug!(
            accepted = committed.len(),
            operation,
            "propagation store writes committed"
        );
        if commit_tx
            .send(PropagationStoreCommitResult { origin, committed })
            .is_err()
        {
            tracing::debug!(operation, "propagation store commit receiver closed");
        }
    }))
}

fn apply_propagation_store_commit(
    router: &mut LxmRouter,
    node: Option<&Arc<Mutex<PropagationNode>>>,
    result: PropagationStoreCommitResult,
) {
    if result.committed.is_empty() {
        return;
    }
    let committed_count = result.committed.len() as u64;
    let committed_bytes = result
        .committed
        .iter()
        .map(|(_, bytes)| *bytes)
        .sum::<u64>();

    match result.origin {
        PropagationStoreWriteOrigin::Peer(peer_hash) => {
            if let Some(peer) = router.peers.get_mut(&peer_hash) {
                peer.incoming = peer.incoming.saturating_add(committed_count);
                peer.rx_bytes = peer.rx_bytes.saturating_add(committed_bytes);
                peer.heard();
                for (transient_id, _) in result.committed {
                    peer.add_handled_message(&transient_id);
                }
                if let Some(node) = node
                    && let Ok(node) = node.lock()
                    && let Err(error) = node.save_peer(peer)
                {
                    tracing::warn!(
                        peer = %hex::encode(peer_hash),
                        "failed to persist committed peer accounting: {error}"
                    );
                }
            } else {
                router.unpeered_propagation_incoming = router
                    .unpeered_propagation_incoming
                    .saturating_add(committed_count);
                router.unpeered_propagation_rx_bytes = router
                    .unpeered_propagation_rx_bytes
                    .saturating_add(committed_bytes);
            }
        }
        PropagationStoreWriteOrigin::Client => {
            router.client_propagation_messages_received = router
                .client_propagation_messages_received
                .saturating_add(committed_count);
        }
    }
}

const PN_PACKET_VALIDATION_QUEUE_DEPTH: usize = 256;
const PN_PACKET_VALIDATION_WORKERS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PnPacketValidationEnqueueError {
    Overloaded,
    Closed,
}

fn enqueue_pn_packet_validation(
    jobs: &mpsc::Sender<PnPacketValidationJob>,
    job: PnPacketValidationJob,
) -> Result<(), PnPacketValidationEnqueueError> {
    jobs.try_send(job).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => PnPacketValidationEnqueueError::Overloaded,
        mpsc::error::TrySendError::Closed(_) => PnPacketValidationEnqueueError::Closed,
    })
}

#[derive(Debug)]
struct PeeringKeyWorkerResult {
    peer_hash: [u8; 16],
    peering_cost: u8,
    peering_key: Option<([u8; 32], u32)>,
}

fn accepts_delivery_resource(data_size: usize, limit_kb: f64) -> bool {
    data_size as f64 <= limit_kb * lxmf_core::constants::BYTES_PER_KILOBYTE as f64
}

fn configured_kilobytes_to_bytes(kilobytes: usize) -> usize {
    kilobytes.saturating_mul(lxmf_core::constants::BYTES_PER_KILOBYTE)
}

fn delivery_resource_event_from_runtime(event: LinkResourceEvent) -> Option<InboundResourceEvent> {
    match event {
        LinkResourceEvent::Started {
            link_id,
            resource_id,
            direction: LinkResourceDirection::Inbound,
            data_size,
            total_segments,
        } => Some(InboundResourceEvent::Started {
            key: InboundResourceKey::new(link_id, resource_id),
            data_size,
            total_segments,
        }),
        LinkResourceEvent::Progress {
            link_id,
            resource_id,
            direction: LinkResourceDirection::Inbound,
            transferred,
            total,
        } => Some(InboundResourceEvent::Progress {
            key: InboundResourceKey::new(link_id, resource_id),
            transferred,
            total,
        }),
        LinkResourceEvent::Concluded {
            link_id,
            resource_id,
            direction: LinkResourceDirection::Inbound,
            conclusion,
        } => Some(InboundResourceEvent::Concluded {
            key: InboundResourceKey::new(link_id, resource_id),
            conclusion: match conclusion {
                LinkResourceConclusion::Complete => InboundResourceConclusion::Complete,
                LinkResourceConclusion::Cancelled => InboundResourceConclusion::Cancelled,
                LinkResourceConclusion::Rejected => InboundResourceConclusion::Rejected,
                LinkResourceConclusion::Failed(_) => InboundResourceConclusion::Failed,
            },
        }),
        LinkResourceEvent::Started { .. }
        | LinkResourceEvent::Progress { .. }
        | LinkResourceEvent::Concluded { .. } => None,
    }
}

async fn forward_inbound_resource_cancellations(
    mut cancel_rx: mpsc::Receiver<InboundResourceCancelRequest>,
    link_command_tx: mpsc::Sender<LinkManagerCommand>,
) {
    while let Some(request) = cancel_rx.recv().await {
        let key = request.key();
        if link_command_tx
            .send(LinkManagerCommand::CancelLinkResource {
                link_id: key.link_id,
                resource_id: key.resource_id,
                direction: LinkResourceDirection::Inbound,
                result_tx: None,
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct PeerOfferConstraints {
    transfer_limit: Option<f64>,
    sync_limit: Option<f64>,
    stamp_cost: Option<u8>,
    stamp_flexibility: Option<u8>,
    peering_cost: u8,
}

impl From<&LxmPeer> for PeerOfferConstraints {
    fn from(peer: &LxmPeer) -> Self {
        Self {
            transfer_limit: peer.propagation_transfer_limit,
            sync_limit: peer.propagation_sync_limit,
            stamp_cost: peer.stamp_cost,
            stamp_flexibility: peer.stamp_cost_flexibility,
            peering_cost: peer.peering_cost,
        }
    }
}

fn generate_peering_key_job(
    peer_hash: [u8; 16],
    peering_cost: u8,
    peer_identity_hash: [u8; 16],
    local_identity_hash: [u8; 16],
) -> PeeringKeyWorkerResult {
    let mut peer = LxmPeer::new(peer_hash);
    peer.peering_cost = peering_cost;
    let _ = peer.generate_peering_key(&peer_identity_hash, &local_identity_hash);
    PeeringKeyWorkerResult {
        peer_hash,
        peering_cost,
        peering_key: peer.peering_key,
    }
}

fn validate_pn_resource_job(
    job: PnValidationJob,
    max_transfer_bytes: usize,
    min_cost: u8,
) -> PnValidationWorkerResult {
    let token = job.token();
    let link_id = job.link_id();
    let allow_multiple = job.allow_multiple();
    let data = job.into_data();

    let (_, entries) =
        match LxMessage::unpack_propagation_wrapper_owned(data.into(), max_transfer_bytes) {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::warn!(
                    link_id = %hex::encode(link_id),
                    "failed to unpack propagation Resource: {error}"
                );
                return PnValidationWorkerResult {
                    token,
                    link_id,
                    outcome: PnValidationOutcome::Failed,
                    entries: Vec::new(),
                    rejected: 0,
                };
            }
        };

    if !allow_multiple && entries.len() > 1 {
        return PnValidationWorkerResult {
            token,
            link_id,
            outcome: PnValidationOutcome::UnauthorizedMultiple,
            entries: Vec::new(),
            rejected: entries.len(),
        };
    }

    let mut validated = Vec::with_capacity(entries.len());
    let mut rejected = 0usize;
    for entry in entries {
        match lxmf_core::stamper::validate_pn_stamp(&entry, min_cost) {
            Some((_transient_id, lxmf_data, stamp_value, stamp_data)) => {
                validated.push(ValidatedPnEntry {
                    lxmf_data,
                    stamp_value,
                    stamp_data,
                });
            }
            None => rejected += 1,
        }
    }

    PnValidationWorkerResult {
        token,
        link_id,
        outcome: if rejected == 0 {
            PnValidationOutcome::Valid
        } else {
            PnValidationOutcome::InvalidStamp
        },
        entries: validated,
        rejected,
    }
}

#[cfg(test)]
fn validate_pn_packet_job(
    link_id: [u8; 16],
    data: Bytes,
    max_transfer_bytes: usize,
    min_cost: u8,
) -> PnPacketValidationWorkerResult {
    let mut result = PnPacketValidationWorkerResult {
        link_id,
        receipt: None,
        payload_owner: data.clone(),
        malformed: false,
        stored: false,
        committed: Vec::new(),
        entries: Vec::new(),
        timing: None,
        rejected: 0,
    };
    let (_, entries) = match LxMessage::unpack_propagation_wrapper_owned(data, max_transfer_bytes) {
        Ok(parsed) => parsed,
        Err(_) => {
            result.malformed = true;
            return result;
        }
    };
    for entry in entries {
        match lxmf_core::stamper::validate_pn_stamp(&entry, min_cost) {
            Some((_, lxmf_data, stamp_value, stamp_data)) => {
                result.entries.push(ValidatedPnEntry {
                    lxmf_data,
                    stamp_value,
                    stamp_data,
                })
            }
            None => result.rejected += 1,
        }
    }
    result
}

/// Worker output may observe another packet's in-progress exact-image write.
/// Those observations retain packet ownership, but wait outside the four
/// validation/storage workers so duplicates cannot deadlock their original.
struct PnPacketExecution {
    result: PnPacketValidationWorkerResult,
    pending: Vec<lxmf_core::propagation_node::PropagationAdmissionWaiter>,
}

fn execute_pn_packet_job(job: PnPacketValidationJob) -> PnPacketExecution {
    use lxmf_core::propagation_node::{PropagationAdmission, ValidatedOpaquePropagationBlob};
    #[cfg(test)]
    let validation_started = Instant::now();
    #[cfg(test)]
    let timing = (!job.store_delay.is_zero()).then(|| PnTestTiming {
        received_at: job.enqueued_at,
        packet_hash: hex::encode(rns_crypto::sha::full_hash(&job.data)),
        queue_ms: job.enqueued_at.elapsed().as_secs_f64() * 1000.,
        validation_ms: 0.,
        store_ms: 0.,
    });
    let mut result = PnPacketValidationWorkerResult {
        link_id: job.link_id,
        receipt: job.receipt,
        payload_owner: job.data.clone(),
        malformed: false,
        stored: false,
        committed: Vec::new(),
        #[cfg(test)]
        entries: Vec::new(),
        #[cfg(test)]
        timing,
        rejected: 0,
    };
    let mut pending = Vec::new();
    let (_, entries) =
        match LxMessage::unpack_propagation_wrapper_owned(job.data, job.max_transfer_bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                result.malformed = true;
                return PnPacketExecution { result, pending };
            }
        };
    // Validate the complete packet before admitting even its first entry.
    let mut validated = Vec::with_capacity(entries.len());
    for entry in entries {
        match ValidatedOpaquePropagationBlob::validate(entry, job.min_cost) {
            Some(blob) => validated.push(blob),
            None => result.rejected += 1,
        }
    }
    if result.rejected != 0 {
        return PnPacketExecution { result, pending };
    }
    #[cfg(test)]
    if let Some(timing) = result.timing.as_mut() {
        timing.validation_ms = validation_started.elapsed().as_secs_f64() * 1000.;
    }
    #[cfg(test)]
    let store_started = Instant::now();
    result.stored = true;
    for blob in validated {
        let tid = blob.transient_id();
        let admission = job
            .node
            .lock()
            .map(|mut node| node.plan_opaque_admission(blob));
        match admission {
            Ok(PropagationAdmission::Reserved(plan)) => {
                let size = plan.size();
                #[cfg(test)]
                std::thread::sleep(job.store_delay);
                match plan.persist() {
                    Ok(persisted) => {
                        if job
                            .node
                            .lock()
                            .map(|mut node| node.commit_store_write(persisted))
                            .unwrap_or(false)
                        {
                            result.committed.push((tid, size.saturating_sub(32) as u64));
                        } else {
                            result.stored = false;
                            break;
                        }
                    }
                    Err(error) => {
                        if let Ok(mut node) = job.node.lock() {
                            node.abort_store_write(&tid, size);
                        }
                        tracing::warn!(%error, "PN packet store admission failed; withholding ordinary proof");
                        result.stored = false;
                        break;
                    }
                }
            }
            Ok(PropagationAdmission::CommittedDuplicate(check)) => {
                #[cfg(test)]
                std::thread::sleep(job.store_delay);
                if let Err(error) = check.verify() {
                    tracing::warn!(%error, "PN duplicate failed durable revalidation");
                    result.stored = false;
                    break;
                }
            }
            Ok(PropagationAdmission::Pending(waiter)) => pending.push(waiter),
            _ => {
                result.stored = false;
                break;
            }
        }
    }
    #[cfg(test)]
    if let Some(timing) = result.timing.as_mut() {
        timing.store_ms = store_started.elapsed().as_secs_f64() * 1000.;
    }
    PnPacketExecution { result, pending }
}

/// FIFO within each Link; one ready Link per round. Admission capacity and byte
/// leases belong to RNS and survive queue, worker, observation and dispatch.
async fn run_pn_packet_validation_pool(
    mut jobs: mpsc::Receiver<PnPacketValidationJob>,
    results: mpsc::Sender<PnPacketValidationWorkerResult>,
) {
    let mut queues: HashMap<[u8; 16], VecDeque<PnPacketValidationJob>> = HashMap::new();
    let mut ready = VecDeque::new();
    let mut running = tokio::task::JoinSet::new();
    let mut observers = tokio::task::JoinSet::new();
    let mut closed = false;
    loop {
        while running.len() < PN_PACKET_VALIDATION_WORKERS {
            let Some(link) = ready.pop_front() else {
                break;
            };
            let queue = queues.get_mut(&link).expect("ready Link queue");
            let job = queue.pop_front().expect("nonempty ready Link queue");
            if !queue.is_empty() {
                ready.push_back(link);
            } else {
                queues.remove(&link);
            }
            running.spawn_blocking(move || execute_pn_packet_job(job));
        }
        if closed && running.is_empty() && observers.is_empty() && ready.is_empty() {
            break;
        }
        tokio::select! {
            job = jobs.recv(), if !closed => match job {
                Some(job) => {
                    let link = job.link_id;
                    let queue = queues.entry(link).or_default();
                    if queue.is_empty() { ready.push_back(link); }
                    queue.push_back(job);
                }
                None => closed = true,
            },
            finished = running.join_next(), if !running.is_empty() => if let Some(Ok(execution)) = finished {
                if execution.pending.is_empty() || !execution.result.stored {
                    if results.send(execution.result).await.is_err() { return; }
                } else {
                    observers.spawn(async move {
                        let mut result = execution.result;
                        for waiter in execution.pending {
                            if waiter.wait().await != lxmf_core::propagation_node::PropagationAdmissionOutcome::Committed {
                                result.stored = false;
                            }
                        }
                        result
                    });
                }
            },
            finished = observers.join_next(), if !observers.is_empty() => if let Some(Ok(result)) = finished
                && results.send(result).await.is_err() { return; },
        }
    }
}

fn handle_pn_offer_request(
    runtime: &Arc<Mutex<PnInboundRuntime>>,
    node: &Arc<Mutex<PropagationNode>>,
    local_identity_hash: [u8; 16],
    link_id: [u8; 16],
    remote_identity_hash: Option<[u8; 16]>,
    data: &[u8],
) -> Option<Vec<u8>> {
    let candidate = runtime
        .lock()
        .ok()?
        .preflight_offer(link_id, remote_identity_hash);
    let candidate = match candidate {
        Ok(candidate) => candidate,
        Err(response) => return Some(PropagationNode::encode_offer_response(&response)),
    };

    let evaluation = match node.lock() {
        Ok(node) => node.evaluate_offer_request(data, &local_identity_hash, &candidate),
        Err(_) => {
            if let Ok(mut runtime) = runtime.lock() {
                runtime.discard_offer(candidate);
            }
            return None;
        }
    };

    match evaluation {
        Ok(evaluation) => {
            let response = match runtime.lock() {
                Ok(mut runtime) => match runtime.commit_offer(candidate, &evaluation) {
                    Ok(()) => evaluation.into_wire_response(),
                    Err(response) => response,
                },
                Err(_) => return None,
            };
            Some(PropagationNode::encode_offer_response(&response))
        }
        Err(error) => {
            if let Ok(mut runtime) = runtime.lock() {
                runtime.discard_offer(candidate);
            }
            Some(PropagationNode::encode_offer_response(
                &error.wire_response(),
            ))
        }
    }
}

fn setup_logging(verbose: u8, quiet: u8, service: bool) {
    let level = match (verbose, quiet) {
        (v, _) if v >= 3 => tracing::Level::TRACE,
        (2, _) => tracing::Level::DEBUG,
        (1, _) => tracing::Level::INFO,
        (0, 0) => {
            if service {
                tracing::Level::WARN
            } else {
                tracing::Level::INFO
            }
        }
        (_, q) if q >= 2 => tracing::Level::ERROR,
        (_, 1) => tracing::Level::WARN,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();
}

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

async fn sleep_or_shutdown(shutdown: &ShutdownSignal, duration: Duration) -> bool {
    tokio::select! {
        _ = shutdown.wait() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

async fn wait_for_online_interface(
    handle: &rns_runtime::reticulum::ReticulumHandle,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if handle
            .interface_stats()
            .await
            .ok()
            .is_some_and(|stats| stats.interfaces.iter().any(|interface| interface.online))
        {
            return true;
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
    }
}

fn mark_delivery_attempt(message: &mut LxMessage) -> u32 {
    let now = now_f64();
    message.delivery_attempts += 1;
    message.last_delivery_attempt = now;
    message.next_delivery_attempt = now + DELIVERY_RETRY_WAIT as f64;
    message.delivery_attempts
}

fn queue_path_request(
    transport_tx: &mpsc::Sender<TransportMessage>,
    request_hash: [u8; 16],
    drop_existing: bool,
    reason: &str,
) {
    if drop_existing {
        let (response_tx, _response_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = transport_tx.try_send(TransportMessage::Rpc {
            query: TransportQuery::DropPath { dest: request_hash },
            response_tx,
        }) {
            tracing::warn!(
                dest = %hex::encode(request_hash),
                error = %e,
                reason,
                "failed to queue path drop before LXMF retry"
            );
        }
    }

    if let Err(e) = transport_tx.try_send(TransportMessage::RequestPath {
        destination_hash: request_hash,
    }) {
        tracing::warn!(
            dest = %hex::encode(request_hash),
            error = %e,
            reason,
            "failed to queue path request before LXMF retry"
        );
    }
}

fn queue_unknown_propagation_node_path_request(
    transport_tx: &mpsc::Sender<TransportMessage>,
    node: [u8; 16],
    last_propagation_check: &mut f64,
    now: f64,
) -> bool {
    *last_propagation_check = now;
    if let Err(e) = transport_tx.try_send(TransportMessage::RequestPath {
        destination_hash: node,
    }) {
        tracing::warn!(
            node = %hex::encode(node),
            error = %e,
            "failed to queue propagation node path request before download"
        );
        return false;
    }
    true
}

fn requeue_after_path_request(
    router: &mut LxmRouter,
    transport_tx: &mpsc::Sender<TransportMessage>,
    mut message: LxMessage,
    request_hash: [u8; 16],
    reason: &str,
    increment_attempt: bool,
) {
    let now = now_f64();
    if increment_attempt {
        message.delivery_attempts += 1;
    }
    message.last_delivery_attempt = now;
    message.next_delivery_attempt = now + PATH_REQUEST_WAIT as f64;
    queue_path_request(transport_tx, request_hash, false, reason);
    tracing::warn!(
        dest = %hex::encode(message.destination_hash()),
        request_dest = %hex::encode(request_hash),
        attempts = message.delivery_attempts,
        reason,
        "re-queuing LXMF message after path request"
    );
    if let Err(error) = router.try_send(message) {
        tracing::warn!(%error, reason, "failed to re-queue LXMF message");
    }
}

fn link_failure_retryable(reason: &str) -> bool {
    is_retryable_link_delivery_failure(reason)
}

fn route_hops_for(route_hops: &HashMap<[u8; 16], u8>, dest_hash: [u8; 16]) -> u8 {
    route_hops.get(&dest_hash).copied().unwrap_or(1).max(1)
}

fn direct_route_snapshot(
    route_hops: &HashMap<[u8; 16], u8>,
    dest_hash: [u8; 16],
) -> Option<DirectRouteSnapshot> {
    route_hops
        .get(&dest_hash)
        .copied()
        .map(|hops| DirectRouteSnapshot::new(dest_hash, hops))
}

fn direct_reusable_link_state(
    link_delivery: Option<&lxmf_core::link_delivery::LinkDeliveryManager>,
    dest_hash: [u8; 16],
) -> DirectReusableLinkState {
    let Some(link_delivery) = link_delivery else {
        return DirectReusableLinkState::None;
    };

    if let Some(snapshot) = link_delivery.direct_link_snapshot(dest_hash) {
        return match snapshot.delivery_state {
            lxmf_core::link_delivery::DeliveryState::Idle => DirectReusableLinkState::Active,
            lxmf_core::link_delivery::DeliveryState::Failed => {
                DirectReusableLinkState::Closed { activated: false }
            }
            _ => DirectReusableLinkState::Pending,
        };
    }

    if let Some(snapshot) = link_delivery.backchannel_link_snapshot(dest_hash) {
        if snapshot.queued_deliveries > 0 || snapshot.in_flight_deliveries > 0 {
            DirectReusableLinkState::Pending
        } else {
            DirectReusableLinkState::Active
        }
    } else {
        DirectReusableLinkState::None
    }
}

async fn forward_backchannel_receipt(
    mut runtime_rx: tokio::sync::oneshot::Receiver<
        Result<
            rns_runtime::link_manager::LinkPayloadSendReceipt,
            rns_runtime::link_manager::LinkSendError,
        >,
    >,
    mut owner_tx: tokio::sync::oneshot::Sender<
        Result<BackchannelSendReceipt, BackchannelSendError>,
    >,
    abandon_tx: mpsc::Sender<BackchannelSendReceipt>,
) {
    let result = tokio::select! {
        biased;
        result = &mut runtime_rx => Some(result),
        _ = owner_tx.closed() => None,
        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => None,
    };
    let Some(result) = result else {
        // close preserves an already-published value and rejects future sends.
        // The runtime cancels exact admission if its receipt publication fails.
        runtime_rx.close();
        if let Ok(Ok(receipt)) = runtime_rx.try_recv() {
            let _ = abandon_tx
                .send(backchannel_receipt_from_runtime(receipt))
                .await;
        }
        let _ = owner_tx.send(Err(BackchannelSendError::TransportUnavailable));
        return;
    };
    let result = match result {
        Ok(Ok(receipt)) => Ok(backchannel_receipt_from_runtime(receipt)),
        Ok(Err(error)) => Err(backchannel_error_from_runtime(error)),
        Err(_) => Err(BackchannelSendError::TransportUnavailable),
    };
    if let Err(Ok(receipt)) = owner_tx.send(result) {
        let _ = abandon_tx.send(receipt).await;
    }
}

fn backchannel_receipt_from_runtime(
    receipt: rns_runtime::link_manager::LinkPayloadSendReceipt,
) -> BackchannelSendReceipt {
    match receipt {
        rns_runtime::link_manager::LinkPayloadSendReceipt::Packet(receipt) => {
            BackchannelSendReceipt::Packet {
                link_id: receipt.link_id,
                packet_hash: receipt.packet_hash,
            }
        }
        rns_runtime::link_manager::LinkPayloadSendReceipt::Resource(receipt) => {
            BackchannelSendReceipt::Resource {
                link_id: receipt.link_id,
                resource_hash: receipt.resource_hash,
            }
        }
    }
}

fn backchannel_error_from_runtime(
    err: rns_runtime::link_manager::LinkSendError,
) -> BackchannelSendError {
    match err {
        rns_runtime::link_manager::LinkSendError::LinkNotFound => {
            BackchannelSendError::LinkNotFound
        }
        rns_runtime::link_manager::LinkSendError::LinkNotActive => {
            BackchannelSendError::LinkNotActive
        }
        rns_runtime::link_manager::LinkSendError::NoSessionKeys => {
            BackchannelSendError::NoSessionKeys
        }
        err @ (rns_runtime::link_manager::LinkSendError::IdentityUnavailable
        | rns_runtime::link_manager::LinkSendError::IdentificationUnavailable) => {
            BackchannelSendError::Other(err.to_string())
        }
        rns_runtime::link_manager::LinkSendError::TransportUnavailable => {
            BackchannelSendError::TransportUnavailable
        }
        rns_runtime::link_manager::LinkSendError::ResourceStartFailed => {
            BackchannelSendError::ResourceStartFailed
        }
    }
}

fn create_control_announce_packet(
    identity: &Identity,
    control_dest_hash: [u8; 16],
) -> Result<Vec<u8>, String> {
    let announce = AnnounceData::create(identity, CONTROL_APP_NAME, None, None)
        .map_err(|e| format!("Failed to create control announce: {e}"))?;
    let payload = announce.pack();

    let flags = rns_wire::flags::PacketFlags {
        header_type: rns_wire::flags::HeaderType::Header1,
        context_flag: false,
        transport_type: rns_wire::flags::TransportType::Broadcast,
        destination_type: rns_wire::flags::DestinationType::Single,
        packet_type: rns_wire::flags::PacketType::Announce,
    };
    let header = rns_wire::header::PacketHeader {
        flags,
        hops: 0,
        transport_id: None,
        destination_hash: control_dest_hash,
        context: rns_wire::context::PacketContext::None,
    };

    let mut raw = header.pack();
    raw.extend_from_slice(&payload);
    Ok(raw)
}

fn send_control_announce_try(
    mailbox: &AnnounceMailbox,
    identity: &Identity,
    control_dest_hash: [u8; 16],
) {
    match create_control_announce_packet(identity, control_dest_hash) {
        Ok(raw) => {
            mailbox.stage(
                control_dest_hash,
                TransportMessage::Outbound(rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: control_dest_hash,
                }),
            );
        }
        Err(e) => tracing::warn!("{e}"),
    }
}

fn create_propagation_announce_packet_for(
    identity: &Identity,
    propagation_dest_hash: [u8; 16],
    config: &DaemonConfig,
) -> Result<Vec<u8>, String> {
    let mut pn_data = lxmf_core::handlers::PropagationNodeAnnounceData::new(
        config.propagation_enabled && !config.from_static_only,
        config.propagation_limit_kb as u64,
        config.sync_limit_kb as u64,
        config.propagation_stamp_cost,
        config.propagation_stamp_flex,
        config.peering_cost,
    );
    if let Some(ref name) = config.node_name {
        pn_data.set_name(name);
    }
    let app_data = propagation_announce_app_data(&pn_data);

    let announce = AnnounceData::create(
        identity,
        "lxmf.propagation",
        Some(app_data.as_slice()),
        None,
    )
    .map_err(|e| format!("Failed to create propagation announce: {e}"))?;

    let payload = announce.pack();

    let flags = rns_wire::flags::PacketFlags {
        header_type: rns_wire::flags::HeaderType::Header1,
        context_flag: false,
        transport_type: rns_wire::flags::TransportType::Broadcast,
        destination_type: rns_wire::flags::DestinationType::Single,
        packet_type: rns_wire::flags::PacketType::Announce,
    };
    let header = rns_wire::header::PacketHeader {
        flags,
        hops: 0,
        transport_id: None,
        destination_hash: propagation_dest_hash,
        context: rns_wire::context::PacketContext::None,
    };

    let mut raw = header.pack();
    raw.extend_from_slice(&payload);
    Ok(raw)
}

/// Soft cap on announce-learned identity keys. Python bounds its equivalent
/// store via Transport's known-destinations cleanup; lxmd has no last-use
/// signal, so over the cap it evicts entries without a live ratchet first,
/// then oldest-ratchet entries. Evicted keys re-learn from the next announce.
const KNOWN_IDENTITIES_SOFT_CAP: usize = 10_000;

/// Full path-table resync cadence for `route_hops`. Announce events keep the
/// map fresh in between; this only re-baselines and prunes expired paths.
const ROUTE_HOPS_REFRESH_SECS: f64 = 300.0;

/// Resolve a destination hash to its identity hash via the learned identity
/// keys — the lxmd equivalent of `RNS.Identity.recall` (LXMessage.py:776).
/// Identity hash = truncated hash of the 64-byte announce public key.
fn recall_identity_hash(
    known_identities: &HashMap<String, [u8; 64]>,
    dest_hash: &[u8; 16],
) -> Option<[u8; 16]> {
    known_identities
        .get(&hex::encode(dest_hash))
        .map(|pub_key| rns_crypto::sha::truncated_hash(pub_key))
}

fn prune_known_identities(
    known_identities: &mut HashMap<String, [u8; 64]>,
    received_ratchets: &HashMap<String, ReceivedRatchet>,
) -> usize {
    if known_identities.len() <= KNOWN_IDENTITIES_SOFT_CAP {
        return 0;
    }
    let mut excess = known_identities.len() - KNOWN_IDENTITIES_SOFT_CAP;
    let before = known_identities.len();

    let no_ratchet: Vec<String> = known_identities
        .keys()
        .filter(|k| !received_ratchets.contains_key(*k))
        .take(excess)
        .cloned()
        .collect();
    for k in &no_ratchet {
        known_identities.remove(k);
    }
    excess = known_identities
        .len()
        .saturating_sub(KNOWN_IDENTITIES_SOFT_CAP);

    if excess > 0 {
        let mut by_age: Vec<(String, f64)> = known_identities
            .keys()
            .filter_map(|k| {
                received_ratchets
                    .get(k)
                    .map(|rr| (k.clone(), rr.received_at))
            })
            .collect();
        by_age.sort_by(|a, b| a.1.total_cmp(&b.1));
        for (k, _) in by_age.into_iter().take(excess) {
            known_identities.remove(&k);
        }
    }
    before - known_identities.len()
}

fn send_propagation_announce_try(
    mailbox: &AnnounceMailbox,
    identity: &Identity,
    propagation_dest_hash: [u8; 16],
    config: &DaemonConfig,
) {
    match create_propagation_announce_packet_for(identity, propagation_dest_hash, config) {
        Ok(raw) => {
            mailbox.stage(
                propagation_dest_hash,
                TransportMessage::Outbound(rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: propagation_dest_hash,
                }),
            );
        }
        Err(e) => tracing::warn!("{e}"),
    }
}

/// Atomically reserve capacity for receipt tracking and packet dispatch.
/// Registering the receipt first prevents a fast proof from racing receipt
/// creation; reserving both slots prevents a packet from leaving untracked.
fn dispatch_opportunistic_packet(
    transport_tx: &mpsc::Sender<TransportMessage>,
    raw: Vec<u8>,
    destination_hash: [u8; 16],
    destination_public_key: [u8; 64],
    msg_hash: Option<[u8; 32]>,
) -> Result<(), String> {
    if let Some(msg_hash) = msg_hash {
        let receipt_permit = transport_tx
            .try_reserve()
            .map_err(|error| format!("receipt reservation failed: {error}"))?;
        let outbound_permit = transport_tx
            .try_reserve()
            .map_err(|error| format!("packet reservation failed: {error}"))?;
        let (full_hash, truncated_hash) =
            rns_wire::hash::packet_hash_pair(&raw, rns_wire::flags::HeaderType::Header1);
        receipt_permit.send(TransportMessage::RegisterReceipt {
            truncated_hash,
            full_hash,
            destination_hash,
            destination_public_key,
            msg_id: hex::encode(msg_hash),
            timeout: Some(Duration::from_secs(15)),
        });
        outbound_permit.send(TransportMessage::Outbound(
            rns_transport::messages::OutboundRequest {
                raw: Bytes::from(raw),
                destination_hash,
            },
        ));
    } else {
        transport_tx
            .try_reserve()
            .map_err(|error| format!("packet reservation failed: {error}"))?
            .send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash,
                },
            ));
    }
    Ok(())
}

fn queue_required_transport(
    transport_tx: &mpsc::Sender<TransportMessage>,
    message: TransportMessage,
    operation: &str,
) -> std::io::Result<()> {
    transport_tx
        .try_send(message)
        .map_err(|error| std::io::Error::other(format!("{operation} could not be queued: {error}")))
}

#[derive(Debug)]
enum PropagationPreparationError {
    Missing(MissingPropagationInput),
    Pending,
    Invalid(String),
}
struct PendingPropagationEnvelope {
    binding: [u8; 32],
    cost: u8,
    result: oneshot::Receiver<Result<PropagationEnvelope, MessageError>>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
}
impl Drop for PendingPropagationEnvelope {
    fn drop(&mut self) {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Release);
    }
}
fn propagation_preparation_slots() -> Arc<tokio::sync::Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
        .clone()
}

/// Pure decode stage used by the bounded download worker. Decryption failure is
/// final for this attempt; plaintext input never enters the admission path.
fn decode_download_payload(
    data: &[u8],
    identity: &Identity,
    destination: [u8; 16],
    ratchets: &[[u8; 32]],
    limits: lxmf_core::message::MessageDecodeLimits,
) -> Result<LxMessage, SuppressionReason> {
    if data.len() < 17 || data[..16] != destination {
        return Err(SuppressionReason::WrongDestination);
    }
    let refs = ratchets.iter().collect::<Vec<_>>();
    let plaintext = identity
        .decrypt(
            &data[16..],
            (!refs.is_empty()).then_some(refs.as_slice()),
            false,
        )
        .map_err(|_| SuppressionReason::DecryptionFailed)?;
    let mut full = Vec::with_capacity(16 + plaintext.len());
    full.extend_from_slice(&destination);
    full.extend_from_slice(&plaintext);
    drop(plaintext);
    let mut message = LxMessage::unpack_owned(Bytes::from(full), limits)
        .map_err(|_| SuppressionReason::Malformed)?;
    message.method = DeliveryMethod::Propagated;
    Ok(message)
}

/// Apply recipient policy before any durable receipt or hook can be created.
fn validate_download_policy(
    msg: &LxMessage,
    public_key: Option<[u8; 64]>,
    tickets: &[[u8; 16]],
    cost: u8,
) -> Result<(), SuppressionReason> {
    if public_key.is_some_and(|key| msg.verify(&key).is_err()) {
        return Err(SuppressionReason::InvalidSignature);
    }
    if cost > 0 {
        let Some(stamp) = msg.recipient_stamp().map(|s| s.as_bytes()) else {
            return Err(SuppressionReason::InvalidStamp);
        };
        let ticket_valid = tickets.iter().any(|ticket| {
            let mut material = [0u8; 48];
            material[..16].copy_from_slice(ticket);
            material[16..].copy_from_slice(&msg.message_id());
            stamp == rns_crypto::sha::truncated_hash(&material)
        });
        let pow_valid = <&[u8; 32]>::try_from(stamp).is_ok_and(|stamp| {
            lxmf_core::stamper::validate_stamp(
                &msg.message_id(),
                stamp,
                cost,
                lxmf_core::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS,
            )
        });
        if !ticket_valid && !pow_valid {
            return Err(SuppressionReason::InvalidStamp);
        }
    }
    Ok(())
}

struct DownloadDecoded {
    message: Result<LxMessage, SuppressionReason>,
    token: DownloadAdmissionToken,
    processing: ProcessingLease,
    ciphertext: Bytes,
}
struct SuppressionPersistResult {
    revision: u64,
    result: std::io::Result<()>,
}
struct SuppressionPersistTask {
    result: oneshot::Receiver<SuppressionPersistResult>,
    task: tokio::task::JoinHandle<()>,
}
enum DownloadWorkerError {
    Rejected(SuppressionReason),
    Storage(lxmf_core::admission::AdmissionError),
}
struct DownloadCommitResult {
    message: LxMessage,
    reservation: lxmf_core::router::InboundReservation,
    receipt: Result<DurableAdmissionReceipt, DownloadWorkerError>,
    token: DownloadAdmissionToken,
    _processing: ProcessingLease,
    _ciphertext: Bytes,
}

struct DaemonCheckpoint {
    ratchets: PathBuf,
    received: HashMap<String, ReceivedRatchet>,
    keys: HashMap<String, [u8; 64]>,
    state_dir: PathBuf,
    router: lxmf_core::router::RouterStateSnapshot,
    policies: HashMap<[u8; 16], AdvertisedNodePolicy>,
}
impl DaemonCheckpoint {
    fn persist(self) -> std::io::Result<()> {
        let received = self.ratchets.join("received");
        require_ratchet_directory(&received)?;
        for (hash, ratchet) in self.received {
            if !hex::decode(&hash).is_ok_and(|bytes| bytes.len() == 16) {
                return Err(std::io::Error::other("invalid ratchet destination"));
            }
            ratchet.save_durable(&received.join(format!("{hash}.ratchet")))?;
        }
        let mut keys = Vec::with_capacity(self.keys.len() * 80);
        for (hash, key) in self.keys {
            let hash = hex::decode(hash).map_err(std::io::Error::other)?;
            if hash.len() != 16 {
                return Err(std::io::Error::other("invalid identity destination"));
            }
            keys.extend_from_slice(&hash);
            keys.extend_from_slice(&key);
        }
        lxmf_core::persist::write_file_atomic(&self.ratchets.join("known_identities"), &keys)?;
        self.router.save_state(&self.state_dir)?;
        lxmf_core::persist::save_node_policies(&self.state_dir, &self.policies)
    }
}
struct DaemonCheckpointTask {
    result: oneshot::Receiver<std::io::Result<()>>,
    task: tokio::task::JoinHandle<()>,
}

/// Owns identity, router, and crypto state; drives the daemon main loop.
// Several fields are long-lived state handles that are intentionally retained
// even when the runner only touches them through setup or shutdown paths.
#[allow(dead_code)]
struct LxmdRunner {
    identity: Identity,
    identity_hash: String,
    lxmf_dest_hash: [u8; 16],
    propagation_dest_hash: [u8; 16],
    control_dest_hash: [u8; 16],
    router: LxmRouter,
    config: DaemonConfig,
    data_dir: PathBuf,
    messages_dir: PathBuf,
    admission_store: Option<FileAdmissionStore>,
    download_decode_tx: mpsc::UnboundedSender<DownloadDecoded>,
    download_decode_rx: mpsc::UnboundedReceiver<DownloadDecoded>,
    download_commit_tx: mpsc::UnboundedSender<DownloadCommitResult>,
    download_commit_rx: mpsc::UnboundedReceiver<DownloadCommitResult>,
    download_tasks: Vec<tokio::task::JoinHandle<()>>,
    pending_downloads: VecDeque<(Bytes, lxmf_core::admission::DownloadAdmissionToken)>,
    hook_task: Option<tokio::task::JoinHandle<()>>,
    hook_result_tx: mpsc::UnboundedSender<bool>,
    hook_result_rx: mpsc::UnboundedReceiver<bool>,
    maintenance_task: Option<tokio::task::JoinHandle<()>>,
    next_admission_maintenance: Instant,
    next_hook_attempt: Instant,
    suppression_task: Option<SuppressionPersistTask>,
    next_suppression_retry: Instant,
    node_policies: HashMap<[u8; 16], AdvertisedNodePolicy>,
    propagation_envelopes: HashMap<[u8; 32], PropagationEnvelope>,
    pending_propagation_envelopes: HashMap<[u8; 32], PendingPropagationEnvelope>,
    propagation_preparation_tasks: Vec<tokio::task::JoinHandle<()>>,
    ratchets_dir: PathBuf,
    delivery_ratchets: DeliveryRatchetState,
    received_ratchets: HashMap<String, ReceivedRatchet>,
    known_identities: HashMap<String, [u8; 64]>,
    route_hops: HashMap<[u8; 16], u8>,
    /// Transport blackhole table snapshot, refreshed per tick. Used to drop
    /// inbound LXMs from blackholed identities (LXMRouter.py:1739-1741).
    blackholed_identities: HashSet<[u8; 16]>,
    link_delivery: Option<lxmf_core::link_delivery::LinkDeliveryManager>,
    link_command_tx: mpsc::Sender<rns_runtime::link_manager::LinkManagerCommand>,
    link_identified_rx: mpsc::Receiver<([u8; 16], [u8; 16])>,
    link_packet_proof_rx: mpsc::Receiver<rns_runtime::link_manager::LinkPacketProof>,
    link_resource_proof_rx: mpsc::Receiver<rns_runtime::link_manager::LinkResourceProof>,
    destination_delivery_proof_rx:
        mpsc::UnboundedReceiver<rns_runtime::link_manager::DestinationDeliveryProof>,
    opportunistic_in_flight: HashMap<[u8; 32], PendingOpportunisticDelivery>,
    backchannel_command_rx: Option<mpsc::Receiver<BackchannelSendCommand>>,
    backchannel_abandon_tx: mpsc::Sender<BackchannelSendReceipt>,
    backchannel_abandon_rx: mpsc::Receiver<BackchannelSendReceipt>,
    pending_backchannel_abandon: Option<BackchannelSendReceipt>,
    backchannel_bridge_slots: Arc<tokio::sync::Semaphore>,
    pending_backchannel_resource_cancellations:
        VecDeque<lxmf_core::link_delivery::BackchannelResourceCancelRequest>,
    last_delivery_failure: Option<String>,
    propagation_sync: Option<lxmf_core::propagation_sync::PropagationSyncTask>,
    propagation_client: Option<lxmf_core::propagation_client::PropagationClient>,
    propagation_node: Option<Arc<Mutex<PropagationNode>>>,
    propagation_admission: Option<Arc<Mutex<PnInboundRuntime>>>,
    prop_link_command_tx: Option<mpsc::Sender<rns_runtime::link_manager::LinkManagerCommand>>,
    endpoint_dispatch: Option<rns_transport::link_endpoint_dispatch::LinkEndpointDispatchHandle>,
    transport_tx: mpsc::Sender<TransportMessage>,
    pending_runtime_transport: VecDeque<TransportMessage>,
    required_announces: AnnounceMailbox,
    lossless_queue_high_water: LosslessQueueHighWater,
    /// Plaintext application data decoded by the LinkManager.
    link_packet_rx: mpsc::UnboundedReceiver<(Vec<u8>, [u8; 16])>,
    /// Ordered, lossless ordinary delivery Resource starts/conclusions and
    /// payload completions used by delivery and the public inbound tracker.
    delivery_accounting_rx: mpsc::UnboundedReceiver<LinkManagerAccountingEvent>,
    /// Bounded best-effort delivery Resource progress. Starts/conclusions are
    /// consumed from `delivery_accounting_rx` instead.
    delivery_resource_event_rx: mpsc::Receiver<LinkResourceEvent>,
    /// Plaintext propagation-wrapper packets decoded by the propagation LinkManager.
    prop_link_packet_rx: mpsc::Receiver<rns_runtime::link_manager::InboundLinkPacket>,
    /// Ordered, lossless lifecycle and completion stream from the propagation LinkManager.
    prop_accounting_rx:
        mpsc::UnboundedReceiver<rns_runtime::link_manager::LinkManagerAccountingEvent>,
    /// Stamp-validation results returned from blocking workers.
    prop_validation_rx: mpsc::Receiver<PnValidationWorkerResult>,
    /// Retained sender used to dispatch bounded validation results.
    prop_validation_tx: mpsc::Sender<PnValidationWorkerResult>,
    /// Results for packet-sized client propagation validation workers.
    prop_packet_validation_rx: mpsc::Receiver<PnPacketValidationWorkerResult>,
    /// Bounded admission queue for the fixed packet-validation worker pool.
    prop_packet_validation_job_tx: mpsc::Sender<PnPacketValidationJob>,
    prop_packet_validation_pool: Option<tokio::task::JoinHandle<()>>,
    prop_get_workers: PnGetWorkers,
    #[cfg(test)]
    pn_packet_store_delay: Duration,
    prop_maintenance_task: Option<DaemonCheckpointTask>,
    /// Durable propagation-store commits. Accounting and handled IDs advance
    /// only after these events, never merely after validation/reservation.
    prop_store_commit_rx: mpsc::UnboundedReceiver<PropagationStoreCommitResult>,
    prop_store_commit_tx: mpsc::UnboundedSender<PropagationStoreCommitResult>,
    prop_store_write_tasks: Vec<tokio::task::JoinHandle<()>>,
    client_propagation_served_rx: mpsc::UnboundedReceiver<u64>,
    /// Peering keys are CPU-bound PoW and must never run on the daemon loop.
    peering_key_result_rx: mpsc::Receiver<PeeringKeyWorkerResult>,
    peering_key_result_tx: mpsc::Sender<PeeringKeyWorkerResult>,
    peering_key_jobs: HashSet<[u8; 16]>,
    pending_peer_syncs: HashSet<[u8; 16]>,
    peer_sync_cursor: Option<[u8; 16]>,
    /// Non-link inbound packets; still encrypted, need destination-level decrypt.
    inbound_raw_rx: mpsc::Receiver<Vec<u8>>,
    announce_subscriptions: Vec<AnnounceSubscription>,
    last_peer_announce: f64,
    last_node_announce: f64,
    /// Due times of triggered node announces. Like Python's
    /// `announce_propagation_node()`, each goes out `NODE_ANNOUNCE_DELAY` after
    /// its trigger, so a node never bursts all of its destinations at once.
    node_announces_due: VecDeque<f64>,
    startup_node_announce_pending: bool,
    last_propagation_check: f64,
    last_crypto_save: f64,
    checkpoint_task: Option<DaemonCheckpointTask>,
    last_cull: f64,
    last_ratchet_clean: f64,
    last_route_refresh: f64,
    received_ratchets_dir: PathBuf,
    control_state: Arc<Mutex<ControlSnapshot>>,
    control_command_rx: mpsc::UnboundedReceiver<ControlCommand>,
}

impl LxmdRunner {
    async fn install_announce_subscriptions(
        &mut self,
        rns_handle: &ReticulumHandle,
    ) -> Result<(), AnnounceSubscriptionError> {
        self.close_announce_subscriptions().await;

        let mut subscriptions = Vec::with_capacity(2);
        for aspect in [DELIVERY_APP_NAME, "lxmf.propagation"] {
            match rns_handle
                .subscribe_announces_with_capacity(Some(aspect.to_string()), true, 256)
                .await
            {
                Ok(subscription) => subscriptions.push(subscription),
                Err(error) => {
                    for subscription in &mut subscriptions {
                        let _ = subscription.close().await;
                    }
                    return Err(error);
                }
            }
        }
        self.announce_subscriptions = subscriptions;
        Ok(())
    }

    async fn close_announce_subscriptions(&mut self) {
        for subscription in &mut self.announce_subscriptions {
            let dropped_events = subscription.dropped_events();
            if dropped_events > 0 {
                tracing::warn!(
                    dropped_events,
                    "lxmd announce subscription omitted events under backpressure"
                );
            }
            if let Err(error) = subscription.close().await {
                tracing::warn!(%error, "failed to close lxmd announce subscription");
            }
        }
        self.announce_subscriptions.clear();
    }

    fn queue_router_message(&mut self, message: LxMessage, operation: &'static str) -> bool {
        match self.router.try_send(message) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, operation, "router rejected LXMF message");
                false
            }
        }
    }

    fn new(
        config: DaemonConfig,
        config_dir: &Path,
        transport_tx: mpsc::Sender<TransportMessage>,
        endpoint_dispatch: Option<
            rns_transport::link_endpoint_dispatch::LinkEndpointDispatchHandle,
        >,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let paths = LxmdPaths::new(config_dir);
        require_storage_namespace(&paths)?;

        let identity_path = paths.preferred_identity_path().to_path_buf();
        let identity = if identity_path.exists() {
            tracing::info!("Loading identity from {}", identity_path.display());
            Identity::from_file(&identity_path)?
        } else {
            tracing::info!("No identity found, generating new one");
            let id = Identity::new();
            id.to_file(&paths.identity_path)?;
            id
        };

        let identity_hash = hex::encode(identity.hash);

        let lxmf_dest_hash =
            Destination::hash_from_name_and_identity(DELIVERY_APP_NAME, Some(&identity.hash));
        let propagation_dest_hash =
            Destination::hash_from_name_and_identity("lxmf.propagation", Some(&identity.hash));
        let control_dest_hash =
            Destination::hash_from_name_and_identity(CONTROL_APP_NAME, Some(&identity.hash));

        tracing::info!(
            "Identity: {} (LXMF: {})",
            &identity_hash[..16],
            &hex::encode(lxmf_dest_hash)[..16],
        );

        let wall_now = now_f64() as u64;
        let delivery_ratchets = DeliveryRatchetState::load_or_initialize(
            &identity,
            lxmf_dest_hash,
            paths.ratchet_ring_path.clone(),
            paths.ratchet_control_path.clone(),
            wall_now,
        )?;

        // Mirrors Python `Identity._clean_ratchets()`: sweep the directory at
        // startup so stale entries don't survive a restart.
        let received_dir = paths.received_ratchets_dir.clone();
        let removed = clean_received_ratchets_dir(&received_dir);
        if removed > 0 {
            tracing::info!(removed, "swept expired received-ratchet files at startup");
        }
        let mut received_ratchets = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&received_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_stem().and_then(|n| n.to_str())
                    && let Ok(rr) = ReceivedRatchet::load(&path)
                {
                    received_ratchets.insert(name.to_string(), rr);
                }
            }
        }

        // known_identities format: concat of [dest_hash:16][pubkey:64]
        let ki_path = paths.known_identities_path.clone();
        let mut known_identities: HashMap<String, [u8; 64]> = HashMap::new();
        if ki_path.exists()
            && let Ok(data) = std::fs::read(&ki_path)
        {
            let mut pos = 0;
            while pos + 80 <= data.len() {
                let mut dh = [0u8; 16];
                dh.copy_from_slice(&data[pos..pos + 16]);
                let mut pk = [0u8; 64];
                pk.copy_from_slice(&data[pos + 16..pos + 80]);
                known_identities.insert(hex::encode(dh), pk);
                pos += 80;
            }
        }

        tracing::info!(
            ratchet_keys = delivery_ratchets.ring().len(),
            received_ratchets = received_ratchets.len(),
            known_identities = known_identities.len(),
            "Crypto state loaded"
        );

        let mut router = create_router_with_transport(&config, transport_tx.clone());

        // LinkManager handles link handshakes (ECDH), keepalive, identification,
        // and resource transfers; it forwards plaintext application data here.
        let (delivery_tx, delivery_rx) = mpsc::channel(256);
        let (backchannel_abandon_tx, backchannel_abandon_rx) = mpsc::channel(256);
        let (link_packet_tx, link_packet_rx) = mpsc::unbounded_channel::<(Vec<u8>, [u8; 16])>();
        let (delivery_accounting_tx, delivery_accounting_rx) =
            mpsc::unbounded_channel::<LinkManagerAccountingEvent>();
        let (delivery_resource_event_tx, delivery_resource_event_rx) =
            mpsc::channel::<LinkResourceEvent>(256);
        let (inbound_resource_cancel_tx, inbound_resource_cancel_rx) =
            mpsc::channel::<InboundResourceCancelRequest>(64);
        router.set_inbound_resource_cancel_sender(inbound_resource_cancel_tx);
        let (prop_link_packet_tx, prop_link_packet_rx) =
            mpsc::channel::<rns_runtime::link_manager::InboundLinkPacket>(256);
        let (prop_accounting_tx, prop_accounting_rx) =
            mpsc::unbounded_channel::<rns_runtime::link_manager::LinkManagerAccountingEvent>();
        let (prop_validation_tx, prop_validation_rx) =
            mpsc::channel::<PnValidationWorkerResult>(256);
        let (prop_packet_validation_result_tx, prop_packet_validation_rx) =
            mpsc::channel::<PnPacketValidationWorkerResult>(256);
        let (prop_packet_validation_job_tx, prop_packet_validation_job_rx) =
            mpsc::channel::<PnPacketValidationJob>(PN_PACKET_VALIDATION_QUEUE_DEPTH);
        let (prop_store_commit_tx, prop_store_commit_rx) =
            mpsc::unbounded_channel::<PropagationStoreCommitResult>();
        let prop_packet_validation_pool = Some(tokio::spawn(run_pn_packet_validation_pool(
            prop_packet_validation_job_rx,
            prop_packet_validation_result_tx,
        )));
        let (client_propagation_served_tx, client_propagation_served_rx) =
            mpsc::unbounded_channel::<u64>();
        let (peering_key_result_tx, peering_key_result_rx) =
            mpsc::channel::<PeeringKeyWorkerResult>(64);
        let (inbound_raw_tx, inbound_raw_rx) = mpsc::channel::<Vec<u8>>(256);
        let (link_command_tx, link_command_rx) =
            mpsc::channel::<rns_runtime::link_manager::LinkManagerCommand>(256);
        let (link_identified_tx, link_identified_rx) = mpsc::channel::<([u8; 16], [u8; 16])>(256);
        let (link_packet_proof_tx, link_packet_proof_rx) =
            mpsc::channel::<rns_runtime::link_manager::LinkPacketProof>(256);
        let (link_resource_proof_tx, link_resource_proof_rx) =
            mpsc::channel::<rns_runtime::link_manager::LinkResourceProof>(256);
        let (destination_delivery_proof_tx, destination_delivery_proof_rx) =
            mpsc::unbounded_channel::<rns_runtime::link_manager::DestinationDeliveryProof>();

        let signing_key = identity.get_signing_key();
        let mut link_mgr = rns_runtime::link_manager::LinkManager::with_destination(
            transport_tx.clone(),
            delivery_rx,
            &identity,
            DELIVERY_APP_NAME,
            signing_key,
        );
        if let Some(handle) = &endpoint_dispatch {
            link_mgr.set_link_endpoint_dispatch_handle(handle.clone());
        }
        // Direct LXMF keeps ordinary Link transport receipts. Only the separate
        // propagation destination defers its proofs until durable admission.
        link_mgr.set_ordinary_packet_proof_strategy(
            rns_identity::destination::ProofStrategy::ProveAll,
        )?;
        link_mgr.set_link_packet_channel(link_packet_tx)?;
        link_mgr.set_accounting_event_channel(delivery_accounting_tx);
        link_mgr.set_resource_event_channel(delivery_resource_event_tx);
        link_mgr.set_inbound_raw_channel(inbound_raw_tx);
        link_mgr.set_link_identified_channel(link_identified_tx);
        link_mgr.set_link_packet_proof_channel(link_packet_proof_tx);
        link_mgr.set_outbound_resource_proof_channel(link_resource_proof_tx);
        link_mgr.set_destination_delivery_proof_channel(destination_delivery_proof_tx);
        link_mgr.set_resource_strategy(rns_runtime::prelude::ResourceStrategy::AcceptApp);
        let delivery_limit_kb = config.delivery_transfer_max_accepted_size;
        link_mgr.set_resource_accept_handler(move |_, advertisement| {
            accepts_delivery_resource(advertisement.data_size, delivery_limit_kb)
        });

        queue_required_transport(
            &transport_tx,
            TransportMessage::RegisterDestination {
                hash: lxmf_dest_hash,
                app_name: DELIVERY_APP_NAME.to_string(),
                delivery_tx: Some(delivery_tx),
            },
            "delivery destination registration",
        )?;

        // Spawn the LinkManager as a background task
        let cancellation_command_tx = link_command_tx.clone();
        tokio::spawn(forward_inbound_resource_cancellations(
            inbound_resource_cancel_rx,
            cancellation_command_tx,
        ));
        tokio::spawn(async move {
            link_mgr.run_with_commands(link_command_rx).await;
        });

        let control_state = Arc::new(Mutex::new(ControlSnapshot {
            allowed_control: vec![identity.hash],
            auth_required: false,
            allowed_clients: Vec::new(),
            peer_hashes: HashSet::new(),
            stats_response: None,
        }));
        // Control requests are already access-controlled and low-volume. An
        // unbounded local hand-off lets the request handler acknowledge only
        // commands that the daemon has actually accepted, instead of silently
        // dropping `--sync`/`--unpeer` when a bounded queue is full.
        let (control_command_tx, control_command_rx) = mpsc::unbounded_channel::<ControlCommand>();
        // LinkManager announce callbacks are synchronous. Coalesce repeated
        // requests by destination until the daemon actor can preserve them
        // into the bounded transport mailbox.
        let required_announces = AnnounceMailbox::default();

        let mut propagation_admission = None;
        let prop_get_workers = PnGetWorkers::default();
        let mut prop_link_command_tx = None;
        let propagation_node: Option<Arc<Mutex<PropagationNode>>> = if config.propagation_enabled {
            let (prop_delivery_tx, prop_delivery_rx) = mpsc::channel(256);
            queue_required_transport(
                &transport_tx,
                TransportMessage::RegisterDestination {
                    hash: propagation_dest_hash,
                    app_name: "lxmf.propagation".to_string(),
                    delivery_tx: Some(prop_delivery_tx),
                },
                "propagation destination registration",
            )?;

            let static_peer_hashes = config
                .static_peers
                .iter()
                .filter_map(|peer| parse_destination_hash(peer).ok())
                .collect::<Vec<_>>();
            let pn_config = PropagationNodeConfig {
                max_storage: config
                    .message_storage_limit
                    .unwrap_or(configured_kilobytes_to_bytes(config.propagation_limit_kb)),
                max_message_size: configured_kilobytes_to_bytes(config.propagation_limit_kb),
                max_offer_size: configured_kilobytes_to_bytes(config.sync_limit_kb),
                max_message_age: lxmf_core::constants::MESSAGE_EXPIRY,
                min_stamp_cost: config
                    .propagation_stamp_cost
                    .saturating_sub(config.propagation_stamp_flex),
                ..Default::default()
            };
            let prop_storage_path = paths.propagation_store_dir.clone();
            let pn = Arc::new(Mutex::new(PropagationNode::with_storage(
                pn_config,
                propagation_dest_hash,
                prop_storage_path,
            )?));
            if let Ok(node) = pn.lock() {
                for mut peer in node.load_peers() {
                    peer.is_static = static_peer_hashes.contains(&peer.destination_hash);
                    let _ = router.add_peer(peer);
                }
            }

            let pn_admission = Arc::new(Mutex::new(PnInboundRuntime::new(
                config.to_inbound_admission_config(),
                static_peer_hashes,
                configured_kilobytes_to_bytes(config.sync_limit_kb),
            )));
            propagation_admission = Some(pn_admission.clone());

            // TODO(hardware-identity): route propagation link signing through the
            // backend-aware Identity path before supporting hardware-backed lxmd.
            let prop_signing_key = identity.get_signing_key().ok_or(
                "identity has no signing key; propagation link management requires a \
                 locally stored signing key (hardware-backed identities are not yet \
                 supported by lxmd)",
            )?;
            let mut prop_link_mgr = rns_runtime::link_manager::LinkManager::with_destination(
                transport_tx.clone(),
                prop_delivery_rx,
                &identity,
                "lxmf.propagation",
                Some(prop_signing_key),
            );
            if let Some(handle) = &endpoint_dispatch {
                prop_link_mgr.set_link_endpoint_dispatch_handle(handle.clone());
            }
            prop_link_mgr.set_inbound_link_packet_channel(prop_link_packet_tx)?;
            prop_link_mgr.set_ordinary_packet_proof_strategy(
                rns_identity::destination::ProofStrategy::ProveApp,
            )?;
            prop_link_mgr.set_accounting_event_channel(prop_accounting_tx);
            prop_link_mgr.set_resource_strategy(rns_runtime::prelude::ResourceStrategy::AcceptApp);

            let pn_for_handler = pn.clone();
            let offer_path_hash = rns_crypto::sha::truncated_hash(
                lxmf_core::constants::OFFER_REQUEST_PATH.as_bytes(),
            );
            let link_identities = prop_link_mgr.link_identities_handle();
            let accept_link_identities = link_identities.clone();
            let admission_for_resources = pn_admission.clone();
            prop_link_mgr.set_resource_accept_handler(move |link_id, advertisement| {
                let remote_identity_hash = accept_link_identities
                    .lock()
                    .ok()
                    .and_then(|identities| identities.get(&link_id).copied());
                let resource_id = logical_resource_id(
                    advertisement.resource_hash,
                    advertisement.original_hash,
                    advertisement.flags.split,
                    advertisement.total_segments,
                );
                admission_for_resources
                    .lock()
                    .map(|mut admission| {
                        admission.accept_resource(
                            link_id,
                            resource_id,
                            advertisement.data_size,
                            remote_identity_hash,
                        )
                    })
                    .unwrap_or(false)
            });

            let local_identity_hash = identity.hash;
            let admission_for_handler = pn_admission.clone();
            let get_node = pn_for_handler.clone();
            let get_admission = pn_admission.clone();
            let get_access = control_state.clone();
            let get_workers = prop_get_workers.clone();
            let get_served = client_propagation_served_tx.clone();
            let response_limit = configured_kilobytes_to_bytes(config.propagation_limit_kb)
                .clamp(1, 64 * 1024 * 1024);
            if !prop_link_mgr.register_deferred_request_handler(
                lxmf_core::constants::MESSAGE_GET_PATH,
                rns_identity::destination::AllowPolicy::AllowAll,
                None,
                false,
                response_limit,
                move |request, responder| {
                    let node = get_node.clone();
                    let admission = get_admission.clone();
                    let access = get_access.clone();
                    let served_tx = get_served.clone();
                    // The responder's byte/job reservation precedes request
                    // parsing and any durable haves retirement.
                    let accepted = get_workers.spawn(move || {
                        use rns_runtime::link_manager::{DeferredResponseOutcome, RequestOutcome};
                        if responder.is_cancelled() {
                            return;
                        }
                        let limit = responder.response_byte_limit();
                        let remote = request
                            .remote_identity
                            .as_ref()
                            .map(|identity| identity.hash);
                        let reply = if admission
                            .lock()
                            .map(|state| state.is_link_quarantined(&request.link_id))
                            .unwrap_or(true)
                        {
                            (None, 0)
                        } else {
                            let allowed = access
                                .lock()
                                .map(|state| propagation_client_allowed(&state, remote.as_ref()))
                                .unwrap_or(false);
                            if !allowed {
                                (
                                    Some(encode_peer_error(
                                        lxmf_core::constants::PeerError::NoAccess,
                                    )),
                                    0,
                                )
                            } else if let Some(remote) = remote {
                                let client = Destination::hash_from_name_and_identity(
                                    DELIVERY_APP_NAME,
                                    Some(&remote),
                                );
                                let action = node.lock().ok().map(|mut node| {
                                    node.handle_get_request_bounded(&request.data, &client, limit)
                                });
                                if responder.is_cancelled() {
                                    return;
                                }
                                action.map_or((None, 0), |action| {
                                    let (bytes, count) =
                                        action.into_response_with_served_count_bounded(limit);
                                    (Some(bytes), count)
                                })
                            } else {
                                (
                                    Some(encode_peer_error(
                                        lxmf_core::constants::PeerError::NoIdentity,
                                    )),
                                    0,
                                )
                            }
                        };
                        let (bytes, served) = reply;
                        let outcome = bytes.map_or(RequestOutcome::Drop, RequestOutcome::Reply);
                        // Retain the actual worker and request capability until
                        // exact-owner dispatch accepts or refuses the response.
                        if let Ok(dispatch) = responder.respond(outcome)
                            && matches!(dispatch.blocking_recv(), Ok(DeferredResponseOutcome::Sent))
                            && served > 0
                        {
                            let _ = served_tx.send(served);
                        }
                    });
                    if !accepted {
                        tracing::debug!("PN get not admitted by bounded worker owner");
                    }
                },
            ) {
                return Err("failed to register bounded propagation get handler".into());
            }
            prop_link_mgr.set_request_handler(move |link_id, path_hash, data| {
                let remote_identity_hash = link_identities
                    .lock()
                    .ok()
                    .and_then(|ids| ids.get(&link_id).copied());
                if path_hash == offer_path_hash {
                    tracing::info!("propagation: handling offer request");
                    handle_pn_offer_request(
                        &admission_for_handler,
                        &pn_for_handler,
                        local_identity_hash,
                        link_id,
                        remote_identity_hash,
                        &data,
                    )
                } else {
                    tracing::debug!(
                        path = hex::encode(path_hash),
                        "propagation: unknown request path"
                    );
                    None
                }
            });

            let prop_announce_mailbox = required_announces.clone();
            let prop_announce_identity = identity
                .get_private_key()
                .and_then(|key| Identity::from_private_key(&*key).ok());
            let prop_announce_config = config.clone();
            prop_link_mgr.set_announce_handler(move || {
                if let Some(ref identity) = prop_announce_identity {
                    send_propagation_announce_try(
                        &prop_announce_mailbox,
                        identity,
                        propagation_dest_hash,
                        &prop_announce_config,
                    );
                }
            });

            let (pn_link_command_tx, pn_link_command_rx) =
                mpsc::channel::<rns_runtime::link_manager::LinkManagerCommand>(256);
            prop_link_command_tx = Some(pn_link_command_tx);
            tokio::spawn(async move {
                prop_link_mgr.run_with_commands(pn_link_command_rx).await;
            });

            let (control_delivery_tx, control_delivery_rx) = mpsc::channel(256);
            queue_required_transport(
                &transport_tx,
                TransportMessage::RegisterDestination {
                    hash: control_dest_hash,
                    app_name: CONTROL_APP_NAME.to_string(),
                    delivery_tx: Some(control_delivery_tx),
                },
                "control destination registration",
            )?;

            // TODO(hardware-identity): route control link signing through the
            // backend-aware Identity path before supporting hardware-backed lxmd.
            let control_signing_key = identity.get_signing_key().ok_or(
                "identity has no signing key; control link management requires a \
                 locally stored signing key (hardware-backed identities are not yet \
                 supported by lxmd)",
            )?;
            let mut control_link_mgr = rns_runtime::link_manager::LinkManager::with_destination(
                transport_tx.clone(),
                control_delivery_rx,
                &identity,
                CONTROL_APP_NAME,
                Some(control_signing_key),
            );
            if let Some(handle) = &endpoint_dispatch {
                control_link_mgr.set_link_endpoint_dispatch_handle(handle.clone());
            }
            let control_link_identities = control_link_mgr.link_identities_handle();
            let stats_path_hash =
                rns_crypto::sha::truncated_hash(lxmf_core::constants::STATS_GET_PATH.as_bytes());
            let sync_path_hash =
                rns_crypto::sha::truncated_hash(lxmf_core::constants::SYNC_REQUEST_PATH.as_bytes());
            let unpeer_path_hash = rns_crypto::sha::truncated_hash(
                lxmf_core::constants::UNPEER_REQUEST_PATH.as_bytes(),
            );
            let control_state_for_handler = control_state.clone();
            let command_tx_for_handler = control_command_tx.clone();
            control_link_mgr.set_request_handler(move |link_id, path_hash, data| {
                let remote_identity_hash = control_link_identities
                    .lock()
                    .ok()
                    .and_then(|ids| ids.get(&link_id).copied());
                let snapshot = control_state_for_handler
                    .lock()
                    .map(|state| state.clone())
                    .unwrap_or_default();

                let Some(remote_hash) = remote_identity_hash else {
                    return Some(encode_peer_error(
                        lxmf_core::constants::PeerError::NoIdentity,
                    ));
                };
                if !snapshot.allowed_control.contains(&remote_hash) {
                    return Some(encode_peer_error(lxmf_core::constants::PeerError::NoAccess));
                }

                if path_hash == stats_path_hash {
                    tracing::info!("control: handling stats request");
                    Some(snapshot.stats_response.unwrap_or_else(encode_nil_response))
                } else if path_hash == sync_path_hash {
                    tracing::info!("control: handling peer sync request");
                    if data.len() != 16 {
                        return Some(encode_peer_error(
                            lxmf_core::constants::PeerError::InvalidData,
                        ));
                    }
                    let mut peer_hash = [0u8; 16];
                    peer_hash.copy_from_slice(&data);
                    if !snapshot.peer_hashes.contains(&peer_hash) {
                        return Some(encode_peer_error(lxmf_core::constants::PeerError::NotFound));
                    }
                    Some(queue_control_command(
                        &command_tx_for_handler,
                        ControlCommand::Sync(peer_hash),
                    ))
                } else if path_hash == unpeer_path_hash {
                    tracing::info!("control: handling unpeer request");
                    if data.len() != 16 {
                        return Some(encode_peer_error(
                            lxmf_core::constants::PeerError::InvalidData,
                        ));
                    }
                    let mut peer_hash = [0u8; 16];
                    peer_hash.copy_from_slice(&data);
                    if !snapshot.peer_hashes.contains(&peer_hash) {
                        return Some(encode_peer_error(lxmf_core::constants::PeerError::NotFound));
                    }
                    Some(queue_control_command(
                        &command_tx_for_handler,
                        ControlCommand::Unpeer(peer_hash),
                    ))
                } else {
                    tracing::debug!(
                        path = hex::encode(path_hash),
                        "control: unknown request path"
                    );
                    None
                }
            });

            let control_announce_mailbox = required_announces.clone();
            let control_announce_identity = identity
                .get_private_key()
                .and_then(|key| Identity::from_private_key(&*key).ok());
            control_link_mgr.set_announce_handler(move || {
                if let Some(ref identity) = control_announce_identity {
                    send_control_announce_try(
                        &control_announce_mailbox,
                        identity,
                        control_dest_hash,
                    );
                }
            });

            tokio::spawn(async move {
                control_link_mgr.run().await;
            });

            tracing::info!("propagation sync server ready for offer/get requests");
            Some(pn)
        } else {
            None
        };

        let messages_dir = paths.messages_dir.clone();
        std::fs::create_dir_all(&messages_dir)?;

        let admission_store = match FileAdmissionStore::open(&paths.router_state_dir, &messages_dir)
        {
            Ok(store) => Some(store),
            Err(error) => {
                tracing::error!(%error,"durable download storage unavailable; propagation downloads disabled");
                None
            }
        };
        let (hook_result_tx, hook_result_rx) = mpsc::unbounded_channel();
        let (download_decode_tx, download_decode_rx) = mpsc::unbounded_channel();
        let (download_commit_tx, download_commit_rx) = mpsc::unbounded_channel();
        let now = now_f64();

        let mut runner = Self {
            identity,
            identity_hash,
            lxmf_dest_hash,
            propagation_dest_hash,
            control_dest_hash,
            router,
            config,
            data_dir: paths.router_state_dir.clone(),
            messages_dir,
            admission_store,
            download_decode_tx,
            download_decode_rx,
            download_commit_tx,
            download_commit_rx,
            download_tasks: Vec::new(),
            pending_downloads: VecDeque::new(),
            hook_task: None,
            hook_result_tx,
            hook_result_rx,
            maintenance_task: None,
            next_admission_maintenance: Instant::now(),
            next_hook_attempt: Instant::now(),
            suppression_task: None,
            next_suppression_retry: Instant::now(),
            node_policies: lxmf_core::persist::load_node_policies(&paths.router_state_dir)
                .unwrap_or_default(),
            propagation_envelopes: HashMap::new(),
            pending_propagation_envelopes: HashMap::new(),
            propagation_preparation_tasks: Vec::new(),
            ratchets_dir: paths.ratchets_dir,
            delivery_ratchets,
            received_ratchets,
            known_identities,
            route_hops: HashMap::new(),
            blackholed_identities: HashSet::new(),
            link_delivery: None,
            link_command_tx,
            link_identified_rx,
            link_packet_proof_rx,
            link_resource_proof_rx,
            destination_delivery_proof_rx,
            opportunistic_in_flight: HashMap::new(),
            backchannel_command_rx: None,
            backchannel_abandon_tx,
            backchannel_abandon_rx,
            pending_backchannel_abandon: None,
            backchannel_bridge_slots: Arc::new(tokio::sync::Semaphore::new(256)),
            pending_backchannel_resource_cancellations: VecDeque::new(),
            last_delivery_failure: None,
            propagation_sync: None,
            propagation_client: None,
            propagation_node: None,
            propagation_admission,
            prop_link_command_tx,
            endpoint_dispatch,
            transport_tx: transport_tx.clone(),
            pending_runtime_transport: VecDeque::new(),
            required_announces,
            lossless_queue_high_water: LosslessQueueHighWater::default(),
            link_packet_rx,
            delivery_accounting_rx,
            delivery_resource_event_rx,
            prop_link_packet_rx,
            prop_accounting_rx,
            prop_validation_rx,
            prop_validation_tx,
            prop_packet_validation_rx,
            prop_packet_validation_job_tx,
            prop_packet_validation_pool,
            prop_get_workers,
            #[cfg(test)]
            pn_packet_store_delay: Duration::ZERO,
            prop_maintenance_task: None,
            prop_store_commit_rx,
            prop_store_commit_tx,
            prop_store_write_tasks: Vec::new(),
            client_propagation_served_rx,
            peering_key_result_rx,
            peering_key_result_tx,
            peering_key_jobs: HashSet::new(),
            pending_peer_syncs: HashSet::new(),
            peer_sync_cursor: None,
            inbound_raw_rx,
            announce_subscriptions: Vec::new(),
            last_peer_announce: 0.0,
            last_node_announce: 0.0,
            node_announces_due: VecDeque::new(),
            startup_node_announce_pending: false,
            last_propagation_check: 0.0,
            last_crypto_save: now,
            checkpoint_task: None,
            last_cull: now,
            last_ratchet_clean: now,
            last_route_refresh: 0.0,
            received_ratchets_dir: received_dir,
            control_state,
            control_command_rx,
        };

        if runner.config.propagation_enabled {
            if let Some(ref pn) = propagation_node {
                let mut sync = lxmf_core::propagation_sync::PropagationSyncTask::with_shared_node(
                    transport_tx.clone(),
                    pn.clone(),
                );
                if let Some(signing_key) = runner.identity.get_signing_key() {
                    sync.set_identity(runner.identity.get_public_key(), signing_key);
                } else {
                    tracing::error!(
                        "local identity has no signing key; outbound peer sync cannot identify"
                    );
                }
                runner.propagation_sync = Some(sync);
            }
            runner.propagation_node = propagation_node;

            tracing::info!("propagation sync server initialized");
        }

        if runner.config.propagation_enabled || runner.config.outbound_propagation_node.is_some() {
            let mut client = lxmf_core::propagation_client::PropagationClient::new(
                transport_tx.clone(),
                Some(runner.identity.get_public_key()),
                runner.identity.get_signing_key(),
            );
            client.set_delivery_limit(runner.config.delivery_transfer_max_accepted_size);
            if let Some(ref node_hex) = runner.config.outbound_propagation_node {
                match hex::decode(node_hex) {
                    Ok(bytes) if bytes.len() == 16 => {
                        let mut node = [0u8; 16];
                        node.copy_from_slice(&bytes);
                        client.set_propagation_node(node);
                        runner.router.outbound_propagation_node = Some(node);
                        let peer = runner
                            .router
                            .peers
                            .entry(node)
                            .or_insert_with(|| lxmf_core::peer::LxmPeer::new(node));
                        peer.is_static = true;
                        if !runner.router.static_peers.contains(&node) {
                            runner.router.static_peers.push(node);
                        }
                        tracing::info!(
                            node = %hex::encode(node),
                            "outbound propagation node configured"
                        );
                    }
                    _ => {
                        tracing::warn!(
                            node = %node_hex,
                            "ignoring invalid outbound propagation node hash"
                        );
                    }
                }
            }
            match lxmf_core::persist::load_suppression(&runner.data_dir) {
                Ok(ledger) => client.set_suppression_ledger(ledger, runner.download_epochs()),
                Err(error) => {
                    tracing::error!(%error,"suppression state unavailable; automatic downloads paused");
                    client.suppression_persistence_failed();
                }
            }
            runner.propagation_client = Some(client);

            tracing::info!("propagation client initialized");
        }

        Ok(runner)
    }

    fn apply_config(&mut self) {
        if self.config.propagation_enabled {
            self.router.set_propagation_enabled(true);
            if self.router.propagation_start_time.is_none() {
                self.router.propagation_start_time = Some(now_f64());
            }
            self.router.set_autopeer(self.config.autopeer);
            self.router.set_max_peers(self.config.max_peers);
            self.router
                .set_propagation_limit(self.config.propagation_limit_kb);
            self.router.set_stamp_requirements(
                self.config.propagation_stamp_cost,
                self.config.propagation_stamp_flex,
            );
        }

        self.router
            .set_message_storage_limit(self.config.message_storage_limit);
        self.router.set_authentication(self.config.auth_required);

        if let Some(cost) = self.config.stamp_cost {
            self.router.set_stamp_cost(self.lxmf_dest_hash, cost);
        }

        for configured in &self.config.control_allowed {
            match parse_destination_hash(configured) {
                Ok(hash) => self.router.allow_control(hash),
                Err(e) => {
                    tracing::warn!(hash = %configured, "ignoring invalid control_allowed hash: {e}")
                }
            }
        }
        for configured in &self.config.static_peers {
            match parse_destination_hash(configured) {
                Ok(hash) => {
                    if !self.router.static_peers.contains(&hash) {
                        self.router.static_peers.push(hash);
                    }
                    let peer = self
                        .router
                        .peers
                        .entry(hash)
                        .or_insert_with(|| lxmf_core::peer::LxmPeer::new(hash));
                    peer.is_static = true;
                }
                Err(e) => {
                    tracing::warn!(hash = %configured, "ignoring invalid static peer hash: {e}")
                }
            }
        }
        for configured in &self.config.prioritise_destinations {
            match parse_destination_hash(configured) {
                Ok(hash) => {
                    self.router.prioritise(hash, 1);
                    if let Some(ref node) = self.propagation_node
                        && let Ok(mut node) = node.lock()
                    {
                        node.prioritise_destination(hash);
                    }
                }
                Err(e) => {
                    tracing::warn!(hash = %configured, "ignoring invalid prioritised destination hash: {e}")
                }
            }
        }
    }

    fn refresh_control_state(&mut self) {
        let mut allowed_control = vec![self.identity.hash];
        for hash in &self.router.allowed_control {
            if !allowed_control.contains(hash) {
                allowed_control.push(*hash);
            }
        }

        let peer_hashes = self.router.peers.keys().copied().collect::<HashSet<_>>();
        let stats_response = if self.config.propagation_enabled {
            let node_guard = self
                .propagation_node
                .as_ref()
                .and_then(|node| node.lock().ok());
            Some(encode_router_control_stats(
                &self.router,
                self.identity.hash,
                self.propagation_dest_hash,
                node_guard.as_deref(),
                now_f64(),
            ))
        } else {
            None
        };

        if let Ok(mut state) = self.control_state.lock() {
            *state = ControlSnapshot {
                allowed_control,
                auth_required: self.router.requires_authentication(),
                allowed_clients: self.router.allowed.clone(),
                peer_hashes,
                stats_response,
            };
        }
    }

    fn create_announce_packet(&mut self) -> Result<Vec<u8>, String> {
        let app_data =
            delivery_announce_app_data(self.config.display_name.as_deref(), self.config.stamp_cost);
        let now = now_f64();
        self.delivery_ratchets
            .create_announce(
                &self.identity,
                &app_data,
                now as u64,
                now,
                DeliveryAnnounceKind::Broadcast,
            )
            .map_err(|error| error.to_string())
    }

    fn create_propagation_announce_packet(&mut self) -> Result<Vec<u8>, String> {
        create_propagation_announce_packet_for(
            &self.identity,
            self.propagation_dest_hash,
            &self.config,
        )
    }

    async fn send_announce(&mut self) -> Result<(), String> {
        let raw = self.create_announce_packet()?;
        self.transport_tx
            .send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: self.lxmf_dest_hash,
                },
            ))
            .await
            .map_err(|e| format!("Failed to send announce: {e}"))
    }

    #[cfg(test)]
    async fn send_propagation_announce(&mut self) -> Result<(), String> {
        let raw = self.create_propagation_announce_packet()?;
        self.transport_tx
            .send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: self.propagation_dest_hash,
                },
            ))
            .await
            .map_err(|e| format!("Failed to send propagation announce: {e}"))
    }

    fn should_announce_control(&self) -> bool {
        if !self.config.propagation_enabled {
            return false;
        }
        let mut allowed = HashSet::from([self.identity.hash]);
        allowed.extend(self.router.allowed_control.iter().copied());
        allowed.len() > 1
    }

    fn schedule_node_announce(&mut self, now: f64) {
        const MAX_PENDING: usize = 8;
        if self.node_announces_due.len() < MAX_PENDING {
            self.node_announces_due
                .push_back(now + NODE_ANNOUNCE_DELAY as f64);
        }
    }

    /// Stage the propagation and control announces once the earliest scheduled
    /// one is due; announces due together go out once.
    fn stage_due_node_announce(&mut self, now: f64) {
        if !self
            .node_announces_due
            .front()
            .is_some_and(|due| *due <= now)
        {
            return;
        }
        let Ok(raw) = self.create_propagation_announce_packet() else {
            return;
        };
        let dest = self.propagation_dest_hash;
        let node_staged = self.queue_runtime_transport(
            TransportMessage::Outbound(rns_transport::messages::OutboundRequest {
                raw: Bytes::from(raw),
                destination_hash: dest,
            }),
            "propagation announce",
        );
        let mut control_staged = true;
        if self.should_announce_control()
            && let Ok(raw) = create_control_announce_packet(&self.identity, self.control_dest_hash)
        {
            control_staged = self.queue_runtime_transport(
                TransportMessage::Outbound(rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: self.control_dest_hash,
                }),
                "control announce",
            );
        }
        if node_staged && control_staged {
            while self
                .node_announces_due
                .front()
                .is_some_and(|due| *due <= now)
            {
                self.node_announces_due.pop_front();
            }
            if std::mem::take(&mut self.startup_node_announce_pending) {
                tracing::info!("Startup propagation announce sent");
            } else {
                tracing::debug!("propagation node announce staged");
            }
        }
    }

    fn drain_control_commands(&mut self) {
        while let Ok(command) = self.control_command_rx.try_recv() {
            match command {
                ControlCommand::Sync(peer_hash) => {
                    if !self.router.peers.contains_key(&peer_hash) {
                        continue;
                    }
                    self.pending_peer_syncs.insert(peer_hash);
                    if let Some(peer) = self.router.peers.get_mut(&peer_hash) {
                        peer.next_sync_attempt = 0.0;
                        peer.alive = true;
                    }
                    tracing::info!(peer = %hex::encode(peer_hash), "control: queued peer sync");
                }
                ControlCommand::Unpeer(peer_hash) => {
                    self.pending_peer_syncs.remove(&peer_hash);
                    if let Some(sync) = self.propagation_sync.as_mut() {
                        sync.cancel_peer_sync(&peer_hash);
                    }
                    // Upstream control unpeer breaks the live peering without
                    // mutating the operator's configured static-peer set.
                    self.router.remove_peer(&peer_hash);
                    if let Some(ref node) = self.propagation_node
                        && let Ok(mut node) = node.lock()
                        && let Err(error) = node.delete_peer(&peer_hash)
                    {
                        tracing::warn!(
                            peer = %hex::encode(peer_hash),
                            "failed to remove persisted propagation peer: {error}"
                        );
                    }
                    if let Err(e) = self.router.save_state(&self.data_dir) {
                        tracing::warn!("Failed to save router state after control unpeer: {e}");
                    }
                    tracing::info!(peer = %hex::encode(peer_hash), "control: unpeered peer");
                }
            }
        }
    }

    fn drain_peering_key_results(&mut self) {
        while let Ok(result) = self.peering_key_result_rx.try_recv() {
            self.peering_key_jobs.remove(&result.peer_hash);

            let mut applied = false;
            let mut current_cost = false;
            if let Some(peer) = self.router.peers.get_mut(&result.peer_hash) {
                current_cost = peer.peering_cost == result.peering_cost;
                // Peering-key work binds only the two identities. A newer
                // announce timebase (or a lower current target) does not make
                // a completed key stale if its measured value is still high
                // enough for the current policy.
                if let Some((key, value)) = result.peering_key
                    && value >= peer.peering_cost as u32
                {
                    peer.peering_key = Some((key, value));
                    applied = true;
                }
            }

            if applied {
                if let (Some(node), Some(peer)) = (
                    self.propagation_node.as_ref(),
                    self.router.peers.get(&result.peer_hash),
                ) && let Ok(node) = node.lock()
                    && let Err(error) = node.save_peer(peer)
                {
                    tracing::warn!(
                        peer = %hex::encode(result.peer_hash),
                        "failed to persist generated peering key: {error}"
                    );
                }
            } else if current_cost {
                // A bounded key search can fail for an excessive advertised
                // cost. Put this policy generation into the normal peer
                // backoff instead of spinning a fresh CPU job every tick.
                self.pending_peer_syncs.remove(&result.peer_hash);
                if let Some(peer) = self.router.peers.get_mut(&result.peer_hash) {
                    peer.next_sync_attempt =
                        now_f64() + lxmf_core::constants::SYNC_BACKOFF_STEP as f64;
                }
                tracing::warn!(
                    peer = %hex::encode(result.peer_hash),
                    peering_cost = result.peering_cost,
                    "could not generate a peering key; sync remains postponed"
                );
            }
            // A result for a different cost that no longer satisfies policy
            // is ignored. The pending sync remains queued and dispatches a
            // new job for the current target.
        }
    }

    fn queue_due_peer_syncs(&mut self) {
        if self.propagation_sync.is_none() {
            return;
        }
        let Some(offer_generation) = self
            .propagation_node
            .as_ref()
            .and_then(|node| node.lock().ok().map(|node| node.offer_generation()))
        else {
            return;
        };

        for policy in self.router.sync_peer_policies_for_store(offer_generation) {
            self.pending_peer_syncs.insert(policy.peer_hash);
        }
    }

    fn drive_pending_peer_syncs(&mut self) {
        if self
            .propagation_sync
            .as_ref()
            .is_none_or(|sync| sync.state != lxmf_core::propagation_sync::SyncTaskState::Idle)
        {
            return;
        }

        let mut pending = self.pending_peer_syncs.iter().copied().collect::<Vec<_>>();
        // Match Python's preference for responsive peers. Peers that have
        // exhausted their backoff stay queued as a fallback when no live peer
        // is available.
        if pending.iter().any(|peer_hash| {
            self.router
                .peers
                .get(peer_hash)
                .is_some_and(|peer| peer.alive)
        }) {
            pending.retain(|peer_hash| {
                self.router
                    .peers
                    .get(peer_hash)
                    .is_some_and(|peer| peer.alive)
            });
        }
        let pending = round_robin_peer_order(pending, self.peer_sync_cursor);
        for peer_hash in pending {
            let Some(peer_identity_hash) = recall_identity_hash(&self.known_identities, &peer_hash)
            else {
                tracing::debug!(
                    peer = %hex::encode(peer_hash),
                    "peer sync postponed until its identity is known"
                );
                continue;
            };
            let policy = self.router.peers.get(&peer_hash).and_then(|peer| {
                (peer.stamp_costs_known() && (peer.peering_cost == 0 || peer.peering_key_ready()))
                    .then(|| OutboundOfferPolicy::from(peer))
            });
            if let Some(policy) = policy {
                if let Some(sync) = self.propagation_sync.as_mut()
                    && sync.request_sync_now_with_policy(policy)
                {
                    if let Some(peer) = self.router.peers.get_mut(&peer_hash) {
                        peer.begin_sync();
                    }
                    self.pending_peer_syncs.remove(&peer_hash);
                    self.peer_sync_cursor = Some(peer_hash);
                }
                return;
            }

            if self
                .router
                .peers
                .get(&peer_hash)
                .is_some_and(|peer| !peer.stamp_costs_known())
            {
                tracing::debug!(
                    peer = %hex::encode(peer_hash),
                    "peer sync postponed until its stamp policy is known"
                );
                continue;
            }

            if self.peering_key_jobs.contains(&peer_hash) {
                continue;
            }
            let Some(peer) = self.router.peers.get(&peer_hash) else {
                self.pending_peer_syncs.remove(&peer_hash);
                continue;
            };

            let peering_cost = peer.peering_cost;
            let local_identity_hash = self.identity.hash;
            let result_tx = self.peering_key_result_tx.clone();
            self.peering_key_jobs.insert(peer_hash);
            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    generate_peering_key_job(
                        peer_hash,
                        peering_cost,
                        peer_identity_hash,
                        local_identity_hash,
                    )
                })
                .await
                .unwrap_or(PeeringKeyWorkerResult {
                    peer_hash,
                    peering_cost,
                    peering_key: None,
                });
                let _ = result_tx.send(result).await;
            });
        }
    }

    fn drain_backchannel_events(&mut self) {
        let mut identified = Vec::new();
        while let Ok(item) = self.link_identified_rx.try_recv() {
            identified.push(item);
        }
        for (link_id, identity_hash) in identified {
            self.ensure_link_delivery();
            let dest_hash =
                Destination::hash_from_name_and_identity(DELIVERY_APP_NAME, Some(&identity_hash));
            if let Some(ref mut ld) = self.link_delivery {
                ld.register_backchannel(dest_hash, link_id);
            }
            tracing::info!(
                link_id = %hex::encode(link_id),
                identity = %hex::encode(identity_hash),
                dest = %hex::encode(dest_hash),
                "LXMF inbound Link identified; registered daemon backchannel"
            );
        }

        let mut packet_proofs = Vec::new();
        while let Ok(proof) = self.link_packet_proof_rx.try_recv() {
            packet_proofs.push(proof);
        }
        for proof in packet_proofs {
            if let Some(result) = self
                .link_delivery
                .as_mut()
                .and_then(|ld| ld.handle_backchannel_packet_proof(proof.link_id, proof.packet_hash))
            {
                self.handle_link_delivery_result(result);
            }
        }

        let mut resource_proofs = Vec::new();
        while let Ok(proof) = self.link_resource_proof_rx.try_recv() {
            resource_proofs.push(proof);
        }
        for proof in resource_proofs {
            if let Some(result) = self.link_delivery.as_mut().and_then(|ld| {
                ld.handle_backchannel_resource_proof(proof.link_id, proof.resource_hash)
            }) {
                self.handle_link_delivery_result(result);
            }
        }

        self.drain_core_backchannel_send_commands();
    }

    fn drain_core_backchannel_send_commands(&mut self) {
        while let Some(receipt) = self
            .pending_backchannel_abandon
            .take()
            .or_else(|| self.backchannel_abandon_rx.try_recv().ok())
        {
            match receipt {
                BackchannelSendReceipt::Packet {
                    link_id,
                    packet_hash,
                } => {
                    if let Some(ld) = &mut self.link_delivery
                        && !ld.abandon_backchannel_packet(link_id, packet_hash)
                    {
                        self.pending_backchannel_abandon = Some(BackchannelSendReceipt::Packet {
                            link_id,
                            packet_hash,
                        });
                        break;
                    }
                }
                BackchannelSendReceipt::Resource {
                    link_id,
                    resource_hash,
                } => {
                    self.pending_backchannel_resource_cancellations.push_back(
                        lxmf_core::link_delivery::BackchannelResourceCancelRequest {
                            link_id,
                            resource_hash,
                        },
                    );
                }
            }
        }
        if let Some(ld) = &mut self.link_delivery {
            self.pending_backchannel_resource_cancellations
                .extend(ld.take_backchannel_resource_cancellations());
        }
        while let Some(request) = self.pending_backchannel_resource_cancellations.front() {
            let command = LinkManagerCommand::CancelLinkResource {
                link_id: request.link_id,
                resource_id: request.resource_hash,
                direction: LinkResourceDirection::Outbound,
                result_tx: None,
            };
            match self.link_command_tx.try_send(command) {
                Ok(()) => {
                    self.pending_backchannel_resource_cancellations.pop_front();
                }
                Err(mpsc::error::TrySendError::Full(_)) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.pending_backchannel_resource_cancellations.clear();
                    break;
                }
            }
        }
        let Some(rx) = self.backchannel_command_rx.as_mut() else {
            return;
        };
        let command_tx = self.link_command_tx.clone();

        while let Ok(command) = rx.try_recv() {
            if command.result_tx.is_closed() {
                continue;
            }
            let Ok(bridge_slot) = self.backchannel_bridge_slots.clone().try_acquire_owned() else {
                let _ = command
                    .result_tx
                    .send(Err(BackchannelSendError::TransportUnavailable));
                continue;
            };
            let (result_tx, result_rx) = tokio::sync::oneshot::channel();
            let link_id = command.link_id;
            let link_command = rns_runtime::link_manager::LinkManagerCommand::SendLinkPayload {
                link_id,
                payload: command.payload,
                auto_compress: command.auto_compress,
                result_tx: Some(result_tx),
            };
            match command_tx.try_send(link_command) {
                Ok(()) => {
                    let abandon_tx = self.backchannel_abandon_tx.clone();
                    tokio::spawn(async move {
                        let _bridge_slot = bridge_slot;
                        forward_backchannel_receipt(result_rx, command.result_tx, abandon_tx).await;
                    });
                }
                Err(err) => {
                    tracing::warn!(
                        link_id = %hex::encode(link_id),
                        error = %err,
                        "failed to queue LXMF daemon backchannel send command"
                    );
                    let _ = command
                        .result_tx
                        .send(Err(BackchannelSendError::TransportUnavailable));
                }
            }
        }
    }

    fn handle_link_delivery_result(&mut self, result: DeliveryResult) {
        match result {
            DeliveryResult::Complete { msg_hash, .. } => {
                if let Some(hash) = msg_hash {
                    self.propagation_envelopes.remove(&hash);
                    self.pending_propagation_envelopes.remove(&hash);
                    let _ = self.router.mark_outbound_delivered(&hash);
                    tracing::info!(hash = %hex::encode(hash), "link delivery complete");
                }
            }
            DeliveryResult::Rejected {
                msg_hash,
                dest_hash,
                reason,
                ..
            } => {
                tracing::warn!(
                    dest = %hex::encode(dest_hash),
                    reason = %reason,
                    "link delivery rejected"
                );
                if let Some(hash) = msg_hash {
                    self.propagation_envelopes.remove(&hash);
                    self.pending_propagation_envelopes.remove(&hash);
                    let _ = self.router.mark_outbound_rejected(&hash);
                }
                self.last_delivery_failure = Some(reason);
            }
            DeliveryResult::Failed {
                msg_hash,
                dest_hash,
                message,
                reason,
                ..
            } => {
                tracing::warn!(
                    dest = %hex::encode(dest_hash),
                    reason = %reason,
                    attempts = message.delivery_attempts,
                    "link delivery failed"
                );
                let router_owned = msg_hash.is_some_and(|hash| {
                    self.router
                        .pending_outbound
                        .iter()
                        .any(|pending| pending.message_id() == hash)
                });
                if link_failure_retryable(&reason)
                    && message.delivery_attempts <= MAX_DELIVERY_ATTEMPTS
                {
                    if let Some(hash) = msg_hash {
                        tracing::warn!(
                            hash = %hex::encode(hash),
                            "retrying message after link delivery failure"
                        );
                    }
                    if router_owned {
                        queue_path_request(&self.transport_tx, dest_hash, false, &reason);
                        if let Some(hash) = msg_hash {
                            let _ = self
                                .router
                                .defer_outbound_for_path_request(&hash, now_f64());
                        }
                    } else {
                        requeue_after_path_request(
                            &mut self.router,
                            &self.transport_tx,
                            message,
                            dest_hash,
                            &reason,
                            false,
                        );
                    }
                } else {
                    if let Some(hash) = msg_hash {
                        self.propagation_envelopes.remove(&hash);
                        self.pending_propagation_envelopes.remove(&hash);
                        if router_owned {
                            let _ = self.router.mark_outbound_failed(&hash);
                        }
                        tracing::warn!(
                            hash = %hex::encode(hash),
                            "message delivery failed"
                        );
                    }
                    self.last_delivery_failure = Some(reason);
                }
            }
        }
    }

    /// Resync `route_hops` from the transport path table: boot seed plus a
    /// slow re-baseline that prunes destinations whose paths expired.
    /// Freshness between resyncs comes from announce events
    /// (`drain_announce_events`), so dumping the full table every tick was
    /// pure clone churn. Gated internally; call sites stay per-tick.
    async fn refresh_route_hops_from_transport(&mut self) {
        let now = now_f64();
        if now - self.last_route_refresh < ROUTE_HOPS_REFRESH_SECS && !self.route_hops.is_empty() {
            return;
        }
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = self.transport_tx.try_send(TransportMessage::Rpc {
            query: TransportQuery::GetPathTable,
            response_tx,
        }) {
            tracing::debug!(error = %e, "failed to request transport path table for LXMF routing");
            return;
        }

        let Ok(Ok(TransportQueryResponse::PathTable(entries))) =
            tokio::time::timeout(Duration::from_millis(100), response_rx).await
        else {
            return;
        };

        // Replace wholesale on success only — a failed query must not leave
        // routing blind, and replacement (vs insert) is what evicts dests
        // whose transport paths have expired.
        let mut fresh: HashMap<[u8; 16], u8> = HashMap::with_capacity(entries.len());
        for entry in entries {
            if entry.expires > now {
                fresh.insert(entry.hash, entry.hops.max(1));
            }
        }
        self.route_hops = fresh;
        self.last_route_refresh = now;
    }

    /// Snapshot the transport blackhole table. Ungated: the table is tiny and
    /// the per-tick roundtrip keeps drops close to Python's live
    /// `Reticulum.is_blackholed` query (LXMessage.py:803-805). Fail-open: on
    /// query failure the previous snapshot stays in effect.
    async fn refresh_blackholed_identities_from_transport(&mut self) {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = self.transport_tx.try_send(TransportMessage::Rpc {
            query: TransportQuery::GetBlackholedIdentities,
            response_tx,
        }) {
            tracing::warn!(error = %e, "could not determine message source blackhole status");
            return;
        }

        let Ok(Ok(TransportQueryResponse::BlackholeList(entries))) =
            tokio::time::timeout(Duration::from_millis(100), response_rx).await
        else {
            return;
        };

        self.blackholed_identities = entries.into_iter().map(|e| e.identity_hash).collect();
    }

    /// True when the source destination resolves to a blackholed identity.
    /// Unknown identities are never dropped, mirroring Python's recall-gated
    /// check (LXMessage.py:804 only runs with a recalled source identity).
    fn source_blackholed(&self, source_hash: &[u8; 16]) -> bool {
        match recall_identity_hash(&self.known_identities, source_hash) {
            Some(identity_hash) => self.blackholed_identities.contains(&identity_hash),
            None => false,
        }
    }

    /// Advance callback-driven propagation peer synchronization independently
    /// from the four-second router maintenance job loop.
    fn drive_propagation_sync(&mut self) {
        self.poll_download_commits();
        let mut peer_handled_updates = None;
        let mut peer_terminal_result = None;
        if let Some(ref mut sync) = self.propagation_sync {
            sync.drain_events(&self.known_identities);
            sync.tick();
            let updates = sync.take_handled_updates();
            if !updates.is_empty()
                && let Some(peer_hash) = sync.node_dest_hash()
            {
                peer_handled_updates = Some((peer_hash, updates));
            }
            peer_terminal_result = sync.take_terminal_peer_result();
        }

        let mut peers_to_persist = HashSet::new();
        if let Some((peer_hash, updates)) = peer_handled_updates
            && let Some(peer) = self.router.peers.get_mut(&peer_hash)
        {
            for transient_id in updates {
                peer.add_handled_message(&transient_id);
            }
            peers_to_persist.insert(peer_hash);
        }
        if let Some(result) = peer_terminal_result
            && let Some(peer) = self.router.peers.get_mut(&result.peer_hash)
        {
            if let Some(rate) = result.link_establishment_rate {
                peer.link_establishment_rate = rate;
                peer.heard();
            }
            match result.state {
                lxmf_core::propagation_sync::PeerSyncTerminalState::Complete => {
                    peer.offered = peer.offered.saturating_add(result.offered);
                    peer.outgoing = peer.outgoing.saturating_add(result.outgoing);
                    peer.tx_bytes = peer.tx_bytes.saturating_add(result.tx_bytes);
                    if let Some(rate) = result.sync_transfer_rate {
                        peer.sync_transfer_rate = rate;
                    }
                    peer.sync_complete();
                    if result.generation_exhausted
                        && let Some(generation) = result.offer_generation
                    {
                        peer.mark_offer_generation_processed(generation);
                    }
                }
                lxmf_core::propagation_sync::PeerSyncTerminalState::Failed => {
                    peer.sync_failed();
                }
            }
            peers_to_persist.insert(result.peer_hash);
        }
        for peer_hash in peers_to_persist {
            if let (Some(node), Some(peer)) = (
                self.propagation_node.as_ref(),
                self.router.peers.get(&peer_hash),
            ) && let Ok(node) = node.lock()
                && let Err(error) = node.save_peer(peer)
            {
                tracing::warn!(
                    peer = %hex::encode(peer_hash),
                    "failed to persist peer sync state: {error}"
                );
            }
        }
    }

    fn queue_runtime_transport(
        &mut self,
        message: TransportMessage,
        operation: &'static str,
    ) -> bool {
        self.queue_runtime_transport_recoverable(message, operation)
            .is_ok()
    }

    fn queue_runtime_transport_recoverable(
        &mut self,
        message: TransportMessage,
        operation: &'static str,
    ) -> Result<(), Box<TransportMessage>> {
        const LIMIT: usize = 1024;
        if self.pending_runtime_transport.is_empty() {
            match self.transport_tx.try_send(message) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(message)) => {
                    self.pending_runtime_transport.push_back(message);
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Closed(message)) => {
                    tracing::error!(operation, "transport channel closed");
                    return Err(Box::new(message));
                }
            }
        }
        if self.pending_runtime_transport.len() >= LIMIT {
            tracing::error!(
                operation,
                limit = LIMIT,
                "runtime transport staging queue full"
            );
            return Err(Box::new(message));
        }
        self.pending_runtime_transport.push_back(message);
        Ok(())
    }

    fn flush_runtime_transport(&mut self) {
        while let Some(message) = self.pending_runtime_transport.pop_front() {
            match self.transport_tx.try_send(message) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(message)) => {
                    self.pending_runtime_transport.push_front(message);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    let dropped = self.pending_runtime_transport.len() + 1;
                    self.pending_runtime_transport.clear();
                    tracing::error!(
                        dropped,
                        "transport channel closed with staged daemon traffic"
                    );
                    break;
                }
            }
        }
    }

    fn drain_destination_delivery_proofs(&mut self) {
        while let Ok(proof) = self.destination_delivery_proof_rx.try_recv() {
            let Ok(decoded) = hex::decode(&proof.msg_id) else {
                tracing::warn!(msg_id = %proof.msg_id, "ignored malformed destination delivery-proof id");
                continue;
            };
            let Ok(message_hash) = <[u8; 32]>::try_from(decoded.as_slice()) else {
                tracing::warn!(msg_id = %proof.msg_id, "ignored destination delivery-proof id with invalid length");
                continue;
            };
            let Some(pending) = self.opportunistic_in_flight.remove(&message_hash) else {
                tracing::debug!(msg_id = %proof.msg_id, "delivery proof does not match an in-flight opportunistic message");
                continue;
            };

            self.router.complete_outbound_message(pending.message);
            tracing::info!(
                msg_id = %proof.msg_id,
                rtt_ms = proof.rtt.map(|rtt| rtt.as_secs_f64() * 1000.0),
                "opportunistic message delivery confirmed"
            );
        }
    }

    fn retry_due_opportunistic_deliveries(&mut self, now: f64) {
        let due = self
            .opportunistic_in_flight
            .iter()
            .filter_map(|(hash, pending)| (pending.retry_at <= now).then_some(*hash))
            .collect::<Vec<_>>();

        for hash in due {
            let Some(pending) = self.opportunistic_in_flight.remove(&hash) else {
                continue;
            };
            tracing::debug!(
                msg_id = %hex::encode(hash),
                attempts = pending.message.delivery_attempts,
                "opportunistic delivery still awaiting proof; scheduling retry"
            );
            if let Err(error) = self.router.try_send(pending.message) {
                let reason = format!("failed to schedule opportunistic retry: {error}");
                tracing::warn!(msg_id = %hex::encode(hash), %reason);
                self.last_delivery_failure = Some(reason);
            }
        }
    }

    fn tick(&mut self) {
        self.prop_store_write_tasks
            .retain(|task| !task.is_finished());
        observe_lossless_queue_depth(
            "propagation_store_write_tasks",
            self.prop_store_write_tasks.len(),
            &mut self.lossless_queue_high_water.store_write_tasks,
        );
        self.observe_lossless_queue_depths();
        for (destination_hash, message) in self.required_announces.take_pending() {
            if let Err(message) =
                self.queue_runtime_transport_recoverable(message, "required announce")
            {
                self.required_announces.stage(destination_hash, *message);
            }
        }
        self.flush_runtime_transport();
        let now = now_f64();

        self.drain_destination_delivery_proofs();
        self.retry_due_opportunistic_deliveries(now);

        self.drain_control_commands();
        self.drain_peering_key_results();
        self.queue_due_peer_syncs();
        self.drive_pending_peer_syncs();
        self.drain_backchannel_events();

        self.router.process_deferred_stamps();
        // Per-destination plan inputs precomputed for pending Direct messages
        // only — avoids cloning route_hops/known_identities every tick.
        let direct_inputs = self
            .router
            .pending_outbound
            .iter()
            .filter(|message| message.method == DeliveryMethod::Direct)
            .map(|message| message.destination_hash())
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|dest| {
                (
                    dest,
                    DirectDeliveryPlanInput {
                        identity_known: self.known_identities.contains_key(&hex::encode(dest)),
                        route: direct_route_snapshot(&self.route_hops, dest),
                        reusable_link: direct_reusable_link_state(
                            self.link_delivery.as_ref(),
                            dest,
                        ),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let actions = self.router.process_outbound_with_direct(|message, _now| {
            direct_inputs
                .get(&message.destination_hash())
                .cloned()
                .unwrap_or(DirectDeliveryPlanInput {
                    identity_known: false,
                    route: None,
                    reusable_link: DirectReusableLinkState::None,
                })
        });
        if !actions.is_empty() {
            self.execute_encrypted_actions(actions);
            self.drain_core_backchannel_send_commands();
        }
        // Advance the router jobloop counters (transient-cache cleaning, store
        // cull, peer rotation at Python cadences). `process_outbound_with_direct`
        // does not drive these.
        self.router.run_jobs_tick();

        if let Some(ref mut ld) = self.link_delivery {
            ld.drain_events(&self.known_identities);
            let results = ld.tick();
            for result in results {
                self.handle_link_delivery_result(result);
            }
        }
        self.drain_core_backchannel_send_commands();

        self.drive_propagation_sync();

        // Drive propagation client (download from node)
        let mut downloaded_messages = Vec::new();
        let mut propagation_status = None;
        let mut acknowledge_propagation = false;
        let propagation_node_ready = self
            .router
            .outbound_propagation_node
            .map(|node| self.known_identities.contains_key(&hex::encode(node)))
            .unwrap_or(false);
        self.poll_download_commits();
        self.drive_hook_outbox();
        let locally_delivered_ids = self
            .admission_store
            .as_ref()
            .zip(self.router.outbound_propagation_node)
            .map(|(store, node)| store.durable_haves(self.identity.hash, node, now as u64))
            .unwrap_or_default();
        let retain_synced_on_node = self.router.retain_node_lxms();
        if let Some(ref mut client) = self.propagation_client {
            client.replace_durable_haves(locally_delivered_ids);
            client.set_retain_synced_on_node(retain_synced_on_node);
            client.drain_events(&self.known_identities);
            client.tick();

            downloaded_messages = client.take_downloaded_messages();
            let _ = client.take_suppression_updates();

            // Auto-download every 90s
            if now - self.last_propagation_check > 90.0
                && client.state() == lxmf_core::propagation_client::PropagationClientState::Idle
            {
                if propagation_node_ready && self.admission_store.is_some() {
                    client.start_download();
                    self.last_propagation_check = now;
                    tracing::debug!("auto-triggered propagation download");
                } else if let Some(node) = self.router.outbound_propagation_node
                    && queue_unknown_propagation_node_path_request(
                        &self.transport_tx,
                        node,
                        &mut self.last_propagation_check,
                        now,
                    )
                {
                    tracing::debug!(
                        node = %hex::encode(node),
                        "propagation node identity unknown; requesting path before download"
                    );
                }
            }
            let status = client.transfer_status();
            acknowledge_propagation = matches!(
                status.state,
                lxmf_core::propagation_client::PropagationClientState::Complete
                    | lxmf_core::propagation_client::PropagationClientState::Partial
                    | lxmf_core::propagation_client::PropagationClientState::Failed
            );
            propagation_status = Some(status);
        }
        if let Some(status) = propagation_status {
            self.router.update_propagation_transfer_status(status);
        }
        self.drive_suppression_persistence();
        // Borrow is released; process downloaded messages.
        for msg_data in downloaded_messages {
            self.handle_propagation_downloaded_message(msg_data);
        }
        if acknowledge_propagation && let Some(client) = self.propagation_client.as_mut() {
            client.acknowledge_transfer();
        }

        if let Some(interval) = self.config.announce_interval
            && now - self.last_peer_announce > interval as f64
            && let Ok(raw) = self.create_announce_packet()
        {
            let dest = self.lxmf_dest_hash;
            if self.queue_runtime_transport(
                TransportMessage::Outbound(rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: dest,
                }),
                "periodic delivery announce",
            ) {
                self.last_peer_announce = now;
                tracing::debug!("periodic peer announce staged");
            }
        }

        if self.config.propagation_enabled
            && let Some(interval) = self.config.node_announce_interval
            && now - self.last_node_announce > interval as f64
        {
            self.last_node_announce = now;
            self.schedule_node_announce(now);
        }
        self.stage_due_node_announce(now);

        if let Some(task) = self.prop_maintenance_task.as_mut() {
            match task.result.try_recv() {
                Ok(Ok(())) => self.prop_maintenance_task = None,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "relay maintenance remains pending");
                    self.prop_maintenance_task = None;
                    self.last_cull = now - 240.0;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.prop_maintenance_task = None;
                    self.last_cull = now - 240.0;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        if self.prop_maintenance_task.is_none() && now - self.last_cull > 300.0 {
            self.router.cull_stamp_costs();
            // Reserve only metadata under the lock. Native durable deletion
            // barriers run on one joined worker, away from receipt dispatch.
            if let Some(ref pn) = self.propagation_node
                && let Ok(mut node) = pn.lock()
            {
                let plan = node.plan_maintenance();
                if !plan.is_empty() {
                    let (tx, result) = oneshot::channel();
                    let task = tokio::task::spawn_blocking(move || {
                        let _ = tx.send(plan.persist());
                    });
                    self.prop_maintenance_task = Some(DaemonCheckpointTask { result, task });
                }
            }
            self.last_cull = now;
        }

        if let Some(task) = self.checkpoint_task.as_mut() {
            match task.result.try_recv() {
                Ok(result) => {
                    self.checkpoint_task = None;
                    if let Err(error) = result {
                        tracing::warn!(%error,"daemon checkpoint did not commit");
                        self.last_crypto_save = now - 240.0;
                    }
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.checkpoint_task = None;
                    self.last_crypto_save = now - 240.0;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        if self.checkpoint_task.is_none() && now - self.last_crypto_save > 300.0 {
            let checkpoint = DaemonCheckpoint {
                ratchets: self.ratchets_dir.clone(),
                received: self.received_ratchets.clone(),
                keys: self.known_identities.clone(),
                state_dir: self.data_dir.clone(),
                router: self.router.state_snapshot(),
                policies: self.node_policies.clone(),
            };
            let (tx, result) = oneshot::channel();
            let task = tokio::task::spawn_blocking(move || {
                let _ = tx.send(checkpoint.persist());
            });
            self.checkpoint_task = Some(DaemonCheckpointTask { result, task });
            self.last_crypto_save = now;
        }

        // 15-minute interval matches Python's CLEAN_INTERVAL.
        if now - self.last_ratchet_clean > 900.0 {
            let mem_dropped = purge_expired_ratchets_in_memory(&mut self.received_ratchets);
            let disk_dropped = clean_received_ratchets_dir(&self.received_ratchets_dir);
            let ids_dropped =
                prune_known_identities(&mut self.known_identities, &self.received_ratchets);
            if mem_dropped > 0 || disk_dropped > 0 || ids_dropped > 0 {
                tracing::debug!(
                    mem_dropped,
                    disk_dropped,
                    ids_dropped,
                    "crypto cache cleanup pass: removed expired entries"
                );
            }
            self.last_ratchet_clean = now;
        }

        self.refresh_control_state();
    }

    fn drain_announce_events(&mut self) -> Vec<[u8; 16]> {
        let mut seen = Vec::new();
        let delivery_name_hash = rns_identity::name_hash::name_hash(DELIVERY_APP_NAME);
        let propagation_name_hash = rns_identity::name_hash::name_hash("lxmf.propagation");
        let mut events = Vec::new();
        for subscription in &mut self.announce_subscriptions {
            while let Ok(event) = subscription.events().try_recv() {
                events.push(event);
            }
        }
        for event in events {
            seen.push(event.destination_hash);
            let dest_hex = hex::encode(event.destination_hash);
            tracing::info!(
                dest = %dest_hex,
                hops = event.hops,
                "received announce"
            );
            self.route_hops
                .insert(event.destination_hash, event.hops.max(1));

            if event.name_hash == delivery_name_hash {
                if let Some(ref data) = event.app_data
                    && let Some((display_name, stamp_cost)) =
                        lxmf_core::handlers::parse_announce_app_data(data)
                {
                    if let Some(name) = display_name {
                        tracing::info!(dest = %dest_hex, name = %name, "announce display name");
                    }
                    if let Some(cost) = stamp_cost {
                        self.router.set_stamp_cost(event.destination_hash, cost);
                        tracing::debug!(
                            dest = %dest_hex,
                            stamp_cost = cost,
                            "learned delivery stamp cost from announce"
                        );
                    }
                }
                let triggered = self
                    .router
                    .trigger_outbound_for_delivery_announce(event.destination_hash);
                if triggered > 0 {
                    tracing::debug!(
                        dest = %dest_hex,
                        triggered,
                        "delivery announce made pending outbound messages eligible"
                    );
                }
            } else if let Some((data, pn)) = event
                .app_data
                .as_deref()
                .filter(|_| event.name_hash == propagation_name_hash)
                .and_then(|data| {
                    lxmf_core::handlers::parse_pn_announce_data(data).map(|pn| (data, pn))
                })
            {
                self.router
                    .set_stamp_cost(event.destination_hash, pn.stamp_cost);
                self.node_policies.insert(
                    event.destination_hash,
                    AdvertisedNodePolicy {
                        stamp_cost: pn.stamp_cost,
                        transfer_limit_kb: pn.transfer_limit as f64,
                        recorded_at: now_f64(),
                    },
                );
                let is_static = self.router.static_peers.contains(&event.destination_hash);
                let previous_offer_constraints = self
                    .router
                    .peers
                    .get(&event.destination_hash)
                    .map(PeerOfferConstraints::from);
                let static_observation = is_static
                    && (!event.is_path_response
                        || self
                            .router
                            .peers
                            .get(&event.destination_hash)
                            .is_some_and(|peer| !peer.stamp_costs_known()));
                let autopeer_observation =
                    !is_static && self.config.autopeer && !event.is_path_response;
                let mut peer_changed = false;
                let mut peer_removed = false;
                if static_observation || (autopeer_observation && pn.node_state) {
                    let had_peer = self.router.peers.contains_key(&event.destination_hash);
                    peer_changed = self.router.autopeer(AutopeerCandidate {
                        destination_hash: event.destination_hash,
                        timebase: pn.timebase as f64,
                        transfer_limit: Some(pn.transfer_limit as f64),
                        sync_limit: Some(pn.sync_limit as f64),
                        stamp_cost: Some(pn.stamp_cost),
                        stamp_flexibility: Some(pn.stamp_flex),
                        peering_cost: Some(pn.peering_cost),
                        hops: Some(event.hops),
                        metadata: Some(pn.metadata.clone()),
                    });
                    peer_removed =
                        had_peer && !self.router.peers.contains_key(&event.destination_hash);
                } else if autopeer_observation
                    && !pn.node_state
                    && self
                        .router
                        .peers
                        .get(&event.destination_hash)
                        .is_some_and(|peer| {
                            !peer.is_static && pn.timebase as f64 >= peer.peering_timebase
                        })
                {
                    self.router.remove_peer(&event.destination_hash);
                    peer_removed = true;
                }

                if peer_removed {
                    self.pending_peer_syncs.remove(&event.destination_hash);
                    if let Some(sync) = self.propagation_sync.as_mut() {
                        sync.cancel_peer_sync(&event.destination_hash);
                    }
                    if let Some(node) = self.propagation_node.as_ref()
                        && let Ok(mut node) = node.lock()
                        && let Err(error) = node.delete_peer(&event.destination_hash)
                    {
                        tracing::warn!(
                            peer = %dest_hex,
                            "failed to remove retired propagation peer: {error}"
                        );
                    }
                } else if peer_changed {
                    let offer_constraints_changed =
                        previous_offer_constraints.is_some_and(|previous| {
                            self.router
                                .peers
                                .get(&event.destination_hash)
                                .map(PeerOfferConstraints::from)
                                != Some(previous)
                        });
                    if offer_constraints_changed
                        && self
                            .propagation_sync
                            .as_mut()
                            .is_some_and(|sync| sync.cancel_peer_sync(&event.destination_hash))
                    {
                        if let Some(peer) = self.router.peers.get_mut(&event.destination_hash) {
                            peer.link_closed();
                        }
                        self.pending_peer_syncs.insert(event.destination_hash);
                    }
                    if let (Some(node), Some(peer)) = (
                        self.propagation_node.as_ref(),
                        self.router.peers.get(&event.destination_hash),
                    ) && let Ok(node) = node.lock()
                        && let Err(error) = node.save_peer(peer)
                    {
                        tracing::warn!(
                            peer = %dest_hex,
                            "failed to persist propagation peer policy: {error}"
                        );
                    }
                }
                tracing::debug!(
                    dest = %dest_hex,
                    stamp_cost = pn.stamp_cost,
                    "learned propagation-node stamp cost from announce"
                );
                let triggered = self
                    .router
                    .trigger_outbound_for_propagation_node_announce(event.destination_hash, data);
                if triggered > 0 {
                    tracing::debug!(
                        dest = %dest_hex,
                        triggered,
                        "propagation-node announce made pending propagated messages eligible"
                    );
                }
            }
            if let Some(pub_key) = event.public_key
                && self.known_identities.get(&dest_hex) != Some(&pub_key)
            {
                self.known_identities.insert(dest_hex.clone(), pub_key);
                tracing::debug!(dest = %dest_hex, "learned identity key from announce");
            }
            // Python Identity._remember_ratchet: persist only the single
            // changed ratchet, off the daemon loop. Identity keys and the
            // ring stay on the periodic/shutdown saves.
            if let Some(ratchet_key) = event.ratchet
                && self
                    .received_ratchets
                    .get(&dest_hex)
                    .is_none_or(|rr| rr.ratchet_pub != ratchet_key)
            {
                let rr = ReceivedRatchet::new(ratchet_key);
                self.received_ratchets.insert(dest_hex.clone(), rr);
                tracing::debug!(dest = %dest_hex, "learned ratchet from announce");
                let path = self
                    .received_ratchets_dir
                    .join(format!("{dest_hex}.ratchet"));
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = rr.save_durable(&path) {
                        tracing::warn!("Failed to persist received ratchet: {e}");
                    }
                });
            }
        }
        seen
    }

    fn drain_link_packets(&mut self) {
        self.observe_lossless_queue_depths();
        while let Ok(event) = self.delivery_accounting_rx.try_recv() {
            self.handle_delivery_accounting_event(event);
        }

        while let Ok(event) = self.delivery_resource_event_rx.try_recv() {
            // Starts and conclusions are capacity-lossless on the accounting
            // stream. Only progress is intentionally consumed here.
            if matches!(
                &event,
                LinkResourceEvent::Progress {
                    direction: LinkResourceDirection::Inbound,
                    ..
                }
            ) && let Some(event) = delivery_resource_event_from_runtime(event)
            {
                self.router.handle_inbound_resource_event(event);
            }
        }

        while let Ok((plaintext, link_id)) = self.link_packet_rx.try_recv() {
            tracing::info!(
                link_id = %hex::encode(link_id),
                len = plaintext.len(),
                "received decrypted packet via link"
            );
            self.handle_link_delivered_data(&plaintext);
        }

        while let Ok(packet) = self.prop_link_packet_rx.try_recv() {
            self.handle_propagation_packet(packet);
        }

        while let Ok(event) = self.prop_accounting_rx.try_recv() {
            self.handle_propagation_accounting_event(event);
        }

        while let Ok(result) = self.prop_validation_rx.try_recv() {
            self.handle_propagation_validation_result(result);
        }

        while let Ok(result) = self.prop_packet_validation_rx.try_recv() {
            self.handle_propagation_packet_validation_result(result);
        }

        while let Ok(result) = self.prop_store_commit_rx.try_recv() {
            apply_propagation_store_commit(
                &mut self.router,
                self.propagation_node.as_ref(),
                result,
            );
        }

        while let Ok(served) = self.client_propagation_served_rx.try_recv() {
            self.record_client_propagation_served(served);
        }
    }

    fn record_client_propagation_served(&mut self, served: u64) {
        self.router.client_propagation_messages_served = self
            .router
            .client_propagation_messages_served
            .saturating_add(served);
    }

    fn observe_lossless_queue_depths(&mut self) {
        observe_lossless_queue_depth(
            "control_commands",
            self.control_command_rx.len(),
            &mut self.lossless_queue_high_water.control_commands,
        );
        observe_lossless_queue_depth(
            "link_packets",
            self.link_packet_rx.len(),
            &mut self.lossless_queue_high_water.link_packets,
        );
        observe_lossless_queue_depth(
            "delivery_accounting",
            self.delivery_accounting_rx.len(),
            &mut self.lossless_queue_high_water.delivery_accounting,
        );
        observe_lossless_queue_depth(
            "propagation_link_packets",
            self.prop_link_packet_rx.len(),
            &mut self.lossless_queue_high_water.propagation_link_packets,
        );
        observe_lossless_queue_depth(
            "propagation_accounting",
            self.prop_accounting_rx.len(),
            &mut self.lossless_queue_high_water.propagation_accounting,
        );
        observe_lossless_queue_depth(
            "propagation_store_commits",
            self.prop_store_commit_rx.len(),
            &mut self.lossless_queue_high_water.store_commits,
        );
        observe_lossless_queue_depth(
            "client_propagation_served",
            self.client_propagation_served_rx.len(),
            &mut self.lossless_queue_high_water.client_served,
        );
    }

    fn handle_delivery_accounting_event(&mut self, event: LinkManagerAccountingEvent) {
        match event {
            LinkManagerAccountingEvent::OutboundPacketWait {
                receipt,
                started_at,
                timeout,
                awaiting_admission,
                cancellation,
            } => {
                if let Some(ld) = &mut self.link_delivery {
                    ld.observe_backchannel_packet_wait(
                        receipt.link_id,
                        receipt.packet_hash,
                        started_at,
                        timeout,
                        awaiting_admission,
                        cancellation,
                    );
                }
            }
            LinkManagerAccountingEvent::OutboundResourceWait {
                link_id,
                resource_id,
                started_at,
                timeout,
            } => {
                if let Some(ld) = &mut self.link_delivery {
                    ld.observe_backchannel_resource_wait(link_id, resource_id, started_at, timeout);
                }
            }
            LinkManagerAccountingEvent::ResourceEvent(LinkResourceEvent::Concluded {
                link_id,
                resource_id,
                direction: LinkResourceDirection::Outbound,
                conclusion,
            }) => {
                let result = self.link_delivery.as_mut().and_then(|ld| match conclusion {
                    LinkResourceConclusion::Complete => {
                        ld.handle_backchannel_resource_proof(link_id, resource_id)
                    }
                    LinkResourceConclusion::Rejected => ld.handle_backchannel_resource_conclusion(
                        link_id,
                        resource_id,
                        lxmf_core::link_delivery::BackchannelResourceConclusion::Rejected,
                        "resource rejected",
                    ),
                    LinkResourceConclusion::Failed(reason) => ld
                        .handle_backchannel_resource_conclusion(
                            link_id,
                            resource_id,
                            lxmf_core::link_delivery::BackchannelResourceConclusion::Failed,
                            reason,
                        ),
                    LinkResourceConclusion::Cancelled => ld.handle_backchannel_resource_conclusion(
                        link_id,
                        resource_id,
                        lxmf_core::link_delivery::BackchannelResourceConclusion::Failed,
                        "resource cancelled",
                    ),
                });
                if let Some(result) = result {
                    self.handle_link_delivery_result(result);
                }
            }
            LinkManagerAccountingEvent::ResourceEvent(event) => {
                if let Some(event) = delivery_resource_event_from_runtime(event) {
                    self.router.handle_inbound_resource_event(event);
                }
            }
            LinkManagerAccountingEvent::LinkClosed { link_id } => {
                self.router
                    .handle_inbound_resource_event(InboundResourceEvent::LinkClosed { link_id });
            }
            LinkManagerAccountingEvent::ResourceCompletion(completion) => {
                tracing::info!(
                    link_id = %hex::encode(completion.link_id),
                    len = completion.data.len(),
                    "resource transfer completed on link"
                );
                self.handle_link_delivered_data(&completion.data);
            }
            _ => {}
        }
    }

    fn handle_link_delivered_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // LxMessage::unpack expects [dest_hash][lxm_data]; prepend if the
        // sender omitted it.
        let unpack_data = if data.len() >= 16 && data[..16] == self.lxmf_dest_hash {
            data.to_vec()
        } else {
            let mut full = self.lxmf_dest_hash.to_vec();
            full.extend_from_slice(data);
            full
        };

        match LxMessage::unpack(&unpack_data) {
            Ok(mut msg) => {
                tracing::info!(
                    from = %hex::encode(msg.source_hash()),
                    title = %msg.title_text(),
                    len = msg.content_bytes().len(),
                    "inbound LXMF message via link"
                );
                msg.source_blackholed = self.source_blackholed(&msg.source_hash());
                if msg.source_blackholed {
                    // LXMRouter.py:1739-1741.
                    tracing::debug!(
                        from = %hex::encode(msg.source_hash()),
                        "Dropping LXM from blackholed identity"
                    );
                    return;
                }
                if self.should_reject_for_signature(&mut msg) || self.should_reject_for_stamp(&msg)
                {
                    return;
                }
                self.handle_inbound_message(msg);
            }
            Err(e) => {
                tracing::debug!("link data not an LXMF message: {e}");
            }
        }
    }

    fn handle_propagation_accounting_event(
        &mut self,
        event: rns_runtime::link_manager::LinkManagerAccountingEvent,
    ) {
        let validation_job = self
            .propagation_admission
            .as_ref()
            .and_then(|admission| admission.lock().ok()?.handle_accounting_event(event));
        if let Some(job) = validation_job {
            self.spawn_propagation_validation(job);
        }
    }

    fn spawn_propagation_validation(&self, job: PnValidationJob) {
        let token = job.token();
        let link_id = job.link_id();
        let max_transfer_bytes = configured_kilobytes_to_bytes(self.config.sync_limit_kb);
        let min_cost = self
            .config
            .propagation_stamp_cost
            .saturating_sub(self.config.propagation_stamp_flex);
        let result_tx = self.prop_validation_tx.clone();

        tokio::spawn(async move {
            let result = match tokio::task::spawn_blocking(move || {
                validate_pn_resource_job(job, max_transfer_bytes, min_cost)
            })
            .await
            {
                Ok(result) => result,
                Err(error) => {
                    tracing::warn!(
                        link_id = %hex::encode(link_id),
                        "propagation validation worker failed: {error}"
                    );
                    PnValidationWorkerResult {
                        token,
                        link_id,
                        outcome: PnValidationOutcome::Failed,
                        entries: Vec::new(),
                        rejected: 0,
                    }
                }
            };

            if result_tx.send(result).await.is_err() {
                tracing::debug!("propagation validation receiver closed");
            }
        });
    }

    fn handle_propagation_validation_result(&mut self, result: PnValidationWorkerResult) {
        let claim = self.propagation_admission.as_ref().and_then(|admission| {
            admission
                .lock()
                .ok()?
                .conclude_validation(result.token, result.link_id, result.outcome)
        });
        let Some(claim) = claim else {
            tracing::debug!(
                link_id = %hex::encode(result.link_id),
                "ignoring stale or duplicate propagation validation result"
            );
            return;
        };

        let write_origin = claim
            .peer_destination_hash()
            .map(PropagationStoreWriteOrigin::Peer)
            .unwrap_or(PropagationStoreWriteOrigin::Client);
        let mut write_plans = Vec::new();
        if let Some(ref node) = self.propagation_node
            && let Ok(mut node) = node.lock()
        {
            for entry in &result.entries {
                let stamp_value = u8::try_from(entry.stamp_value).unwrap_or(u8::MAX);
                if let Some(plan) = node.plan_accept_stamped_propagated_blob(
                    &entry.lxmf_data,
                    &entry.stamp_data,
                    stamp_value,
                ) {
                    write_plans.push((plan, entry.lxmf_data.len() as u64));
                }
            }
        }
        let reserved = write_plans.len();
        if let Some(node) = self.propagation_node.clone()
            && let Some(task) = spawn_propagation_store_writes(
                node,
                write_plans,
                write_origin,
                self.prop_store_commit_tx.clone(),
                "propagation Resource ingress",
            )
        {
            self.prop_store_write_tasks.push(task);
        }

        tracing::info!(
            link_id = %hex::encode(claim.link_id()),
            reserved,
            rejected = result.rejected,
            outcome = ?claim.outcome(),
            "processed inbound propagation Resource"
        );

        if claim.should_close_link()
            && let Some(command_tx) = self.prop_link_command_tx.clone()
        {
            let link_id = claim.link_id();
            tokio::spawn(async move {
                if command_tx
                    .send(rns_runtime::link_manager::LinkManagerCommand::CloseLink {
                        link_id,
                        reason: rns_runtime::prelude::CloseReason::DestinationClosed,
                        send_teardown: true,
                    })
                    .await
                    .is_err()
                {
                    tracing::debug!(
                        link_id = %hex::encode(link_id),
                        "propagation Link already closed before validation teardown"
                    );
                }
            });
        }
    }

    fn handle_propagation_packet(&mut self, packet: rns_runtime::link_manager::InboundLinkPacket) {
        let link_id = packet.link_id();
        let Some(node) = self.propagation_node.clone() else {
            return;
        };
        let (data, receipt) = packet.into_parts();
        let job = PnPacketValidationJob {
            link_id,
            data,
            receipt,
            node,
            max_transfer_bytes: configured_kilobytes_to_bytes(self.config.propagation_limit_kb),
            min_cost: self
                .config
                .propagation_stamp_cost
                .saturating_sub(self.config.propagation_stamp_flex),
            #[cfg(test)]
            store_delay: self.pn_packet_store_delay,
            #[cfg(test)]
            enqueued_at: Instant::now(),
        };
        if let Err(reason) = enqueue_pn_packet_validation(&self.prop_packet_validation_job_tx, job)
        {
            // Drop only this unadmitted packet. Closing would revoke accepted
            // receipts on the same Link and turn bounded overload into loss.
            tracing::debug!(?reason, "PN packet not admitted by bounded worker queue");
        }
    }

    fn handle_propagation_packet_validation_result(
        &mut self,
        mut result: PnPacketValidationWorkerResult,
    ) {
        tracing::debug!(link_id=%hex::encode(result.link_id),stored=result.stored,rejected=result.rejected,malformed=result.malformed,"propagation packet admission completed");
        apply_propagation_store_commit(
            &mut self.router,
            self.propagation_node.as_ref(),
            PropagationStoreCommitResult {
                origin: PropagationStoreWriteOrigin::Client,
                committed: std::mem::take(&mut result.committed),
            },
        );
        let Some(receipt) = result.receipt.take() else {
            return;
        };
        if result.malformed {
            receipt.drop_without_proof();
        } else if result.rejected > 0 {
            let dispatch = receipt.reject_and_close(
                rns_runtime::link_manager::LinkPacketRejection::InvalidPropagationStamp,
            );
            tokio::spawn(async move {
                let _owner = result.payload_owner;
                let _ = dispatch.await;
            });
        } else if result.stored {
            #[cfg(test)]
            let dispatched_at = Instant::now();
            let dispatch = receipt.accept();
            tokio::spawn(async move {
                let _owner = result.payload_owner;
                let _outcome = dispatch.await;
                #[cfg(test)]
                if let Some(timing) = result.timing {
                    eprintln!(
                        "PN_RECEIPT_TIMING {}",
                        serde_json::json!({
                            "packet_hash": timing.packet_hash,
                            "queue_ms": timing.queue_ms,
                            "validation_ms": timing.validation_ms,
                            "store_ms": timing.store_ms,
                            "dispatch_ms": dispatched_at.elapsed().as_secs_f64() * 1000.,
                            "receive_to_dispatch_ms": timing.received_at.elapsed().as_secs_f64() * 1000.,
                            "outcome": format!("{_outcome:?}"),
                        })
                    );
                }
            });
        } else {
            // A valid packet that could not be durably admitted has no proof or
            // invalid-stamp authority. Close so the sender can retry promptly.
            let dispatch = receipt.close_without_proof();
            tokio::spawn(async move {
                let _owner = result.payload_owner;
                let _ = dispatch.await;
            });
        }
    }

    fn handle_propagation_downloaded_message(&mut self, item: DownloadedPropagationMessage) {
        let (data, token) = item.into_parts();
        if self.pending_downloads.len() >= lxmf_core::admission::MAX_DOWNLOAD_ITEMS {
            let _ = token.resolve(DownloadAdmissionOutcome::Rejected(SuppressionReason::Quota));
            return;
        }
        // The core raw-response lease follows these slices. Queued items hold
        // no partial processing reservation and never consume a worker slot.
        self.pending_downloads.push_back((data, token));
        self.drive_download_queue();
    }
    fn drive_download_queue(&mut self) {
        while let Some((data, token)) = self.pending_downloads.front() {
            if !token.is_current() {
                self.pending_downloads.pop_front();
                continue;
            }
            if self.admission_store.is_none() {
                let (_, token) = self.pending_downloads.pop_front().unwrap();
                let _ = token.resolve(DownloadAdmissionOutcome::Rejected(
                    SuppressionReason::StorageUnavailable,
                ));
                continue;
            }
            let processing = match ProcessingLease::try_acquire(data.len()) {
                Ok(lease) => lease,
                Err(SuppressionReason::WorkerUnavailable) => break,
                Err(reason) => {
                    let (_, token) = self.pending_downloads.pop_front().unwrap();
                    let _ = token.resolve(DownloadAdmissionOutcome::Rejected(reason));
                    continue;
                }
            };
            let (data, token) = self.pending_downloads.pop_front().unwrap();
            self.start_download_decode(data, token, processing);
        }
    }
    fn start_download_decode(
        &mut self,
        data: Bytes,
        token: lxmf_core::admission::DownloadAdmissionToken,
        processing: ProcessingLease,
    ) {
        let identity = self.identity.clone();
        let destination = self.lxmf_dest_hash;
        let ratchets =
            zeroize::Zeroizing::new(self.delivery_ratchets.ring().private_keys().to_vec());
        let limits = lxmf_core::message::MessageDecodeLimits {
            max_wire_bytes: (self.config.delivery_transfer_max_accepted_size * 1000.) as usize,
            ..Default::default()
        };
        let results = self.download_decode_tx.clone();
        self.download_tasks
            .push(tokio::task::spawn_blocking(move || {
                let message = (|| {
                    if !token.is_current() {
                        return Err(SuppressionReason::Cancelled);
                    }
                    decode_download_payload(&data, &identity, destination, &ratchets, limits)
                })();
                let _ = results.send(DownloadDecoded {
                    message,
                    token,
                    processing,
                    ciphertext: data,
                });
            }));
    }
    fn poll_download_decodes(&mut self) {
        while let Ok(decoded) = self.download_decode_rx.try_recv() {
            let DownloadDecoded {
                message,
                token,
                processing,
                ciphertext,
            } = decoded;
            let msg = match message {
                Ok(msg) => msg,
                Err(reason) => {
                    let _ = token.resolve(DownloadAdmissionOutcome::Rejected(reason));
                    continue;
                }
            };
            if !token.is_current() {
                continue;
            }
            let Some(store) = self.admission_store.clone() else {
                let _ = token.resolve(DownloadAdmissionOutcome::Rejected(
                    SuppressionReason::StorageUnavailable,
                ));
                continue;
            };
            let Some(reservation) = self.router.reserve_inbound(&msg) else {
                let _ = token.resolve(DownloadAdmissionOutcome::Rejected(
                    SuppressionReason::WorkerUnavailable,
                ));
                continue;
            };
            let public_key = self
                .known_identities
                .get(&hex::encode(msg.source_hash()))
                .copied();
            let tickets = self
                .router
                .ticket_store
                .inbound_tokens(&msg.source_hash(), now_f64());
            let cost = if self.config.enforce_stamps {
                self.config.stamp_cost.unwrap_or(0)
            } else {
                0
            };
            let disposition = if self.source_blackholed(&msg.source_hash()) {
                DurableDisposition::PolicyDiscard
            } else {
                DurableDisposition::Committed
            };
            let record = AdmissionRecord {
                scope: token.scope(),
                message_id: msg.message_id(),
                received_wire_hash: rns_crypto::sha::full_hash(msg.wire_bytes()),
                stored_message_wire_hash: None,
                disposition,
                committed_at: now_f64() as u64,
            };
            let hook = self.config.on_inbound_command.is_some();
            let results = self.download_commit_tx.clone();
            self.download_tasks
                .push(tokio::task::spawn_blocking(move || {
                    let receipt = (|| {
                        if !token.is_current() {
                            return Err(DownloadWorkerError::Rejected(
                                SuppressionReason::Cancelled,
                            ));
                        }
                        validate_download_policy(&msg, public_key, &tickets, cost)
                            .map_err(DownloadWorkerError::Rejected)?;
                        DurableAdmissionReceipt::commit(store.prepare(
                            record,
                            msg.wire_owned(),
                            hook,
                        ))
                        .map_err(DownloadWorkerError::Storage)
                    })();
                    let _ = results.send(DownloadCommitResult {
                        message: msg,
                        reservation,
                        receipt,
                        token,
                        _processing: processing,
                        _ciphertext: ciphertext,
                    });
                }));
        }
    }

    fn poll_download_commits(&mut self) {
        self.poll_download_decodes();
        self.download_tasks.retain(|task| !task.is_finished());
        while let Ok(result) = self.download_commit_rx.try_recv() {
            match result.receipt {
                Ok(receipt) => {
                    if !result.token.is_current() {
                        self.router.abort_inbound(result.reservation);
                        continue;
                    }
                    let verified = self
                        .known_identities
                        .get(&hex::encode(result.message.source_hash()))
                        .and_then(|key| result.message.verify(key).ok());
                    self.router.commit_inbound(
                        result.reservation,
                        &result.message,
                        &receipt,
                        verified.as_ref(),
                    );
                    let _ = result
                        .token
                        .resolve(DownloadAdmissionOutcome::Accepted(receipt));
                }
                Err(error) => {
                    self.router.abort_inbound(result.reservation);
                    let reason = match error {
                        DownloadWorkerError::Rejected(reason) => reason,
                        DownloadWorkerError::Storage(error) => {
                            tracing::warn!(%error,"download admission failed; ciphertext retained remotely");
                            SuppressionReason::StorageUnavailable
                        }
                    };
                    let _ = result
                        .token
                        .resolve(DownloadAdmissionOutcome::Rejected(reason));
                }
            }
        }
        self.drive_download_queue();
    }

    fn download_epochs(&self) -> AdmissionEpochs {
        let mut policy = b"lxmd admission policy v1".to_vec();
        policy.push(u8::from(self.config.enforce_stamps));
        policy.push(self.config.stamp_cost.unwrap_or(0));
        let mut blocked = self
            .blackholed_identities
            .iter()
            .copied()
            .collect::<Vec<_>>();
        blocked.sort_unstable();
        for hash in blocked {
            policy.extend_from_slice(&hash);
        }
        let mut identities = self.known_identities.iter().collect::<Vec<_>>();
        identities.sort_unstable_by(|a, b| a.0.cmp(b.0));
        let mut keys = b"lxmd admission keys v1".to_vec();
        for (dest, key) in identities {
            keys.extend_from_slice(dest.as_bytes());
            keys.extend_from_slice(key);
        }
        let mut ratchets = self
            .delivery_ratchets
            .ring()
            .private_keys()
            .iter()
            .map(rns_identity::ratchet::ratchet_public_bytes)
            .collect::<Vec<_>>();
        ratchets.sort_unstable();
        for key in ratchets {
            keys.extend_from_slice(&key);
        }
        let budget = format!(
            "lxmd file admission v1:{}:{}:{}",
            self.config.delivery_transfer_max_accepted_size,
            lxmf_core::admission::MAX_PROCESSING_BYTES,
            lxmf_core::admission::MAX_RETAINED_DOWNLOAD_BYTES
        );
        AdmissionEpochs {
            policy: rns_crypto::sha::full_hash(&policy),
            keys: rns_crypto::sha::full_hash(&keys),
            budget: rns_crypto::sha::full_hash(budget.as_bytes()),
            storage_health: rns_crypto::sha::full_hash(b"lxmd file admission storage schema v1"),
        }
    }
    fn drive_suppression_persistence(&mut self) {
        let epochs = self.download_epochs();
        let Some(client) = self.propagation_client.as_mut() else {
            return;
        };
        client.update_admission_epochs(epochs);
        if let Some(task) = self.suppression_task.as_mut() {
            match task.result.try_recv() {
                Ok(done) => {
                    self.suppression_task.take();
                    match done.result {
                        Ok(()) => {
                            let _ = client.acknowledge_suppression_persistence(done.revision);
                        }
                        Err(error) => {
                            tracing::warn!(%error,"suppression persistence failed; pausing wants until retry");
                            client.suppression_persistence_failed();
                            self.next_suppression_retry = Instant::now() + Duration::from_secs(60);
                        }
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => return,
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.suppression_task.take();
                    client.suppression_persistence_failed();
                    self.next_suppression_retry = Instant::now() + Duration::from_secs(60);
                }
            }
        }
        if !client.suppression_persistence_pending() || Instant::now() < self.next_suppression_retry
        {
            return;
        }
        let ledger = client.suppression_ledger().clone();
        let path = self.data_dir.clone();
        let revision = client.suppression_revision();
        let (tx, result) = oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            let result = lxmf_core::persist::save_suppression(&path, &ledger);
            let _ = tx.send(SuppressionPersistResult { revision, result });
        });
        self.suppression_task = Some(SuppressionPersistTask { result, task });
    }

    fn drive_hook_outbox(&mut self) {
        if Instant::now() >= self.next_admission_maintenance
            && self
                .maintenance_task
                .as_ref()
                .is_none_or(|task| task.is_finished())
        {
            self.next_admission_maintenance = Instant::now() + Duration::from_secs(3600);
            if let Some(store) = self.admission_store.clone() {
                self.maintenance_task = Some(tokio::task::spawn_blocking(move || {
                    if let Err(error) = store.maintain(now_f64() as u64) {
                        tracing::warn!(%error,"admission metadata cleanup pending");
                    }
                }));
            }
        }
        while let Ok(success) = self.hook_result_rx.try_recv() {
            self.next_hook_attempt =
                Instant::now() + Duration::from_secs(if success { 0 } else { 60 });
        }
        if self
            .hook_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
            || Instant::now() < self.next_hook_attempt
        {
            return;
        }
        let Some(store) = self.admission_store.clone() else {
            return;
        };
        let Some(command) = self.config.on_inbound_command.clone() else {
            return;
        };
        let Some((event, path)) = store.pending_hooks().into_iter().next() else {
            return;
        };
        let result_tx = self.hook_result_tx.clone();
        self.hook_task = Some(tokio::task::spawn_blocking(move || {
            match lxmf_tools::daemon::execute_on_inbound_with_event(
                &command,
                &path.to_string_lossy(),
                &hex::encode(event),
            ) {
                Ok(()) => {
                    let success = match store.complete_hook(event) {
                        Ok(()) => true,
                        Err(error) => {
                            tracing::warn!(%error,"hook completion persistence failed; event may replay");
                            false
                        }
                    };
                    let _ = result_tx.send(success);
                }
                Err(error) => {
                    tracing::warn!(%error,event=%hex::encode(event),"inbound hook failed; retained for retry");
                    let _ = result_tx.send(false);
                }
            }
        }));
    }

    fn handle_inbound_packet(&mut self, raw: &[u8]) {
        let (header, rest) = match rns_wire::header::PacketHeader::unpack(raw) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("failed to parse inbound packet header: {e}");
                return;
            }
        };

        let payload = &raw[rest..];
        if payload.is_empty() {
            return;
        }

        let plaintext = match self.decrypt_inbound(payload) {
            Some(pt) => pt,
            None => {
                tracing::warn!("failed to decrypt inbound packet");
                return;
            }
        };

        // Python strips the dest hash for opportunistic delivery; direct delivery
        // keeps it. Re-prepend if missing so LxMessage::unpack always sees the
        // [dest_hash][lxm_data] layout.
        let unpack_data = if plaintext.len() >= 16 && plaintext[..16] == self.lxmf_dest_hash {
            plaintext.clone()
        } else {
            let mut data = self.lxmf_dest_hash.to_vec();
            data.extend_from_slice(&plaintext);
            data
        };

        match LxMessage::unpack(&unpack_data) {
            Ok(mut msg) => {
                tracing::info!(
                    from = %hex::encode(msg.source_hash()),
                    title = %msg.title_text(),
                    len = msg.content_bytes().len(),
                    "inbound LXMF message received"
                );

                msg.source_blackholed = self.source_blackholed(&msg.source_hash());
                if msg.source_blackholed {
                    // LXMRouter.py:1739-1741.
                    tracing::debug!(
                        from = %hex::encode(msg.source_hash()),
                        "Dropping LXM from blackholed identity"
                    );
                    return;
                }

                // Reject on stamp failure BEFORE sending the delivery proof.
                if self.should_reject_for_signature(&mut msg) || self.should_reject_for_stamp(&msg)
                {
                    return;
                }

                if let Some(proof_raw) = self.create_delivery_proof(raw) {
                    let trunc =
                        rns_wire::hash::truncated_packet_hash(raw, header.flags.header_type);
                    if !self.queue_runtime_transport(
                        TransportMessage::Outbound(rns_transport::messages::OutboundRequest {
                            raw: Bytes::from(proof_raw),
                            destination_hash: trunc,
                        }),
                        "opportunistic delivery proof",
                    ) {
                        tracing::error!(
                            packet = %hex::encode(trunc),
                            "could not stage opportunistic delivery proof"
                        );
                    }
                }

                self.handle_inbound_message(msg);
            }
            Err(e) => {
                tracing::warn!("failed to unpack LXMF message: {e}");
            }
        }
    }

    /// Validate a recalled sender signature. Unknown senders remain deliverable
    /// like Python, but can never teach the router a ticket.
    fn should_reject_for_signature(&self, msg: &mut LxMessage) -> bool {
        let Some(public_key) = self.known_identities.get(&hex::encode(msg.source_hash())) else {
            return false;
        };
        if msg.verify(public_key).is_ok() {
            false
        } else {
            tracing::warn!(
                from = %hex::encode(msg.source_hash()),
                "inbound message rejected: invalid LXMF signature"
            );
            true
        }
    }

    /// Returns true if the message should be rejected.
    fn should_reject_for_stamp(&self, msg: &LxMessage) -> bool {
        if !self.config.enforce_stamps {
            return false;
        }
        let required_cost = match self.config.stamp_cost {
            Some(c) if c > 0 => c,
            _ => return false,
        };
        let stamp = match msg.recipient_stamp().map(|stamp| stamp.as_bytes()) {
            Some(s) => s,
            None => {
                tracing::warn!(
                    from = %hex::encode(msg.source_hash()),
                    required_cost,
                    "inbound message rejected: no stamp (enforce_stamps=true)"
                );
                return true;
            }
        };
        let message_id = match Some(msg.message_id()) {
            Some(id) => id,
            None => {
                tracing::warn!(
                    from = %hex::encode(msg.source_hash()),
                    "inbound message rejected: no message_id for stamp validation"
                );
                return true;
            }
        };
        if !self.router.validate_stamp_with_tickets(
            &message_id,
            stamp,
            required_cost,
            &msg.source_hash(),
        ) {
            tracing::warn!(
                from = %hex::encode(msg.source_hash()),
                required_cost,
                "inbound message rejected: stamp PoW invalid or below required cost"
            );
            return true;
        }
        false
    }

    /// Write a received LXMF message to disk and invoke `on_inbound`.
    fn handle_inbound_message(&mut self, msg: LxMessage) {
        // Direct/opportunistic admission has already checked the recipient's
        // policy. Ticket learning separately requires the source-bound proof;
        // deliver_inbound deliberately has no authentication authority. Learn
        // before deduplication so a retry after identity recall can teach its ticket.
        if let Some(public_key) = self.known_identities.get(&hex::encode(msg.source_hash()))
            && let Ok(verified) = msg.verify(public_key)
        {
            self.router.learn_ticket_from_inbound(&verified);
        }
        if !self.router.deliver_inbound(&msg, false) {
            tracing::debug!(
                message = %hex::encode(msg.message_id()),
                "ignoring already delivered inbound LXMF message"
            );
            return;
        }

        let messages_dir = self.messages_dir.clone();
        std::fs::create_dir_all(&messages_dir).ok();

        let msg_hash = hex::encode(msg.message_id());
        let msg_path = messages_dir.join(format!("{msg_hash}.lxm"));

        // Pack synchronously (CPU-bound, no IO) and offload the disk write
        // to the blocking pool so a slow disk doesn't stall the lxmd runner
        // task between inbound messages. Atomic tmp+rename write so readers
        // never see a partial file (LXMessage.py:674-696).
        match msg.pack() {
            Ok(packed) => {
                let write_path = msg_path.clone();
                let on_inbound = self.config.on_inbound_command.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) =
                        persist_inbound_and_execute(&write_path, &packed, on_inbound.as_deref())
                    {
                        tracing::error!(
                            "failed to persist/process inbound message {}: {e}",
                            write_path.display()
                        );
                    } else {
                        tracing::info!("message saved to {}", write_path.display());
                    }
                });
            }
            Err(e) => {
                tracing::error!("failed to pack message for storage: {e}");
                return;
            }
        }

        // Update known identity from sender
        // (The source_hash to public_key mapping comes from announce processing,
        // not directly from the message. Log for diagnostics.)
        tracing::debug!(
            from = %hex::encode(msg.source_hash()),
            "inbound message processed"
        );
    }

    fn execute_encrypted_actions(&mut self, actions: Vec<OutboundAction>) {
        for action in actions {
            let (mut message, dest_hash, is_opportunistic, direct_plan) = match action {
                OutboundAction::DeliverDirect { message, dest_hash } => {
                    (message, dest_hash, false, None)
                }
                OutboundAction::PlanDirect {
                    message,
                    dest_hash,
                    plan,
                } => (message, dest_hash, false, Some(plan)),
                OutboundAction::DeliverOpportunistic { message, dest_hash } => {
                    (message, dest_hash, true, None)
                }
                OutboundAction::DeliverPropagated { message, prop_hash } => {
                    let mut message = message;
                    let prop_hex = hex::encode(prop_hash);
                    tracing::info!(
                        dest = %hex::encode(message.destination_hash()),
                        prop = %hex::encode(prop_hash),
                        "routing message via propagation node"
                    );
                    match self.pack_message_for_propagation(&message, prop_hash) {
                        Ok(packed) => {
                            let attempts = mark_delivery_attempt(&mut message);
                            if attempts >= MAX_DELIVERY_ATTEMPTS {
                                tracing::warn!(
                                    prop = %prop_hex,
                                    attempts,
                                    max_attempts = MAX_DELIVERY_ATTEMPTS,
                                    "propagated delivery attempt budget reached; deferring terminal failure"
                                );
                                self.queue_router_message(message, "propagated retry deferral");
                                continue;
                            }
                            let hops = route_hops_for(&self.route_hops, prop_hash);
                            self.ensure_link_delivery();
                            if let Some(ref mut ld) = self.link_delivery
                                && let Err(err) = ld
                                    .start_packed_delivery(message, prop_hash, hops, packed, false)
                            {
                                let reason = err.error.to_string();
                                tracing::warn!(
                                    error = %reason,
                                    prop = %hex::encode(prop_hash),
                                    "failed to start propagated link delivery"
                                );
                                requeue_after_path_request(
                                    &mut self.router,
                                    &self.transport_tx,
                                    *err.message,
                                    prop_hash,
                                    &reason,
                                    false,
                                );
                            }
                        }
                        Err(PropagationPreparationError::Pending) => {
                            message.next_delivery_attempt = now_f64() + 0.5;
                            self.queue_router_message(message, "propagation envelope preparation");
                        }
                        Err(PropagationPreparationError::Missing(missing)) => {
                            let path = if missing == MissingPropagationInput::RecipientIdentity {
                                message.destination_hash()
                            } else {
                                prop_hash
                            };
                            requeue_after_path_request(
                                &mut self.router,
                                &self.transport_tx,
                                message,
                                path,
                                "propagation readiness incomplete",
                                true,
                            );
                        }
                        Err(PropagationPreparationError::Invalid(error)) => {
                            self.last_delivery_failure = Some(error);
                            message.mark_failed();
                            self.propagation_envelopes.remove(&message.message_id());
                        }
                    }
                    continue;
                }
                OutboundAction::Failed(message) => {
                    self.propagation_envelopes.remove(&message.message_id());
                    self.pending_propagation_envelopes
                        .remove(&message.message_id());
                    let reason = Some(message.message_id())
                        .map(|hash| {
                            format!("delivery attempts exhausted for {}", hex::encode(hash))
                        })
                        .unwrap_or_else(|| "delivery attempts exhausted".to_string());
                    self.last_delivery_failure = Some(reason);
                    continue;
                }
                OutboundAction::Expired(message) => {
                    self.propagation_envelopes.remove(&message.message_id());
                    self.pending_propagation_envelopes
                        .remove(&message.message_id());
                    let reason = Some(message.message_id())
                        .map(|hash| {
                            format!("message {} expired before delivery", hex::encode(hash))
                        })
                        .unwrap_or_else(|| "message expired before delivery".to_string());
                    self.last_delivery_failure = Some(reason);
                    continue;
                }
            };

            let dest_hex = hex::encode(dest_hash);
            if !is_opportunistic {
                let router_owned = direct_plan.is_some();
                let plan = direct_plan.unwrap_or_else(|| {
                    plan_direct_delivery(
                        &mut message,
                        DirectDeliveryPlanInput {
                            identity_known: self.known_identities.contains_key(&dest_hex),
                            route: direct_route_snapshot(&self.route_hops, dest_hash),
                            reusable_link: direct_reusable_link_state(
                                self.link_delivery.as_ref(),
                                dest_hash,
                            ),
                        },
                        now_f64(),
                    )
                });

                match plan {
                    DirectDeliveryPlan::RequestPath { drop_existing } => {
                        queue_path_request(
                            &self.transport_tx,
                            dest_hash,
                            drop_existing,
                            "direct delivery path request",
                        );
                        tracing::warn!(
                            dest = %dest_hex,
                            attempts = message.delivery_attempts,
                            drop_existing,
                            "direct delivery waiting for path"
                        );
                        if !router_owned {
                            self.queue_router_message(message, "direct path wait");
                        }
                    }
                    DirectDeliveryPlan::DeferTerminalFailure => {
                        tracing::warn!(
                            dest = %dest_hex,
                            attempts = message.delivery_attempts,
                            max_attempts = MAX_DELIVERY_ATTEMPTS,
                            "direct delivery attempt budget reached; deferring terminal failure"
                        );
                        if !router_owned {
                            self.queue_router_message(message, "direct terminal deferral");
                        }
                    }
                    DirectDeliveryPlan::WaitForReusableLink => {
                        tracing::debug!(
                            dest = %dest_hex,
                            attempts = message.delivery_attempts,
                            "direct delivery waiting for reusable Link"
                        );
                        if !router_owned {
                            self.queue_router_message(message, "reusable Link wait");
                        }
                    }
                    DirectDeliveryPlan::UseReusableLink
                    | DirectDeliveryPlan::StartNewLink { .. } => {
                        let planned_hops = match plan {
                            DirectDeliveryPlan::StartNewLink { hops } => hops,
                            _ => route_hops_for(&self.route_hops, dest_hash),
                        };
                        tracing::info!(
                            dest = %dest_hex,
                            hops = planned_hops,
                            plan = ?plan,
                            "routing Direct LXMF message over link delivery"
                        );
                        self.ensure_link_delivery();
                        if let Some(ref mut ld) = self.link_delivery {
                            if matches!(plan, DirectDeliveryPlan::UseReusableLink)
                                && ld.direct_link_snapshot(dest_hash).is_none()
                                && ld.backchannel_link_snapshot(dest_hash).is_some()
                            {
                                match ld.start_backchannel_delivery(message, dest_hash) {
                                    Ok(_) => {}
                                    Err(err) => {
                                        let reason = err.error.to_string();
                                        let returned_message = *err.message;
                                        tracing::warn!(
                                            error = %reason,
                                            dest = %dest_hex,
                                            "failed to start daemon backchannel delivery"
                                        );
                                        if router_owned {
                                            queue_path_request(
                                                &self.transport_tx,
                                                dest_hash,
                                                false,
                                                &reason,
                                            );
                                            if let Some(hash) = Some(returned_message.message_id())
                                            {
                                                let _ =
                                                    self.router.defer_outbound_for_path_request(
                                                        &hash,
                                                        now_f64(),
                                                    );
                                            }
                                        } else {
                                            requeue_after_path_request(
                                                &mut self.router,
                                                &self.transport_tx,
                                                returned_message,
                                                dest_hash,
                                                &reason,
                                                false,
                                            );
                                        }
                                    }
                                }
                                continue;
                            }

                            if let Err(err) =
                                ld.start_delivery_with_report(message, dest_hash, planned_hops)
                            {
                                let reason = err.error.to_string();
                                let returned_message = *err.message;
                                tracing::warn!(
                                    error = %reason,
                                    dest = %dest_hex,
                                    "failed to start direct link delivery"
                                );
                                if router_owned {
                                    queue_path_request(
                                        &self.transport_tx,
                                        dest_hash,
                                        false,
                                        &reason,
                                    );
                                    if let Some(hash) = Some(returned_message.message_id()) {
                                        let _ = self
                                            .router
                                            .defer_outbound_for_path_request(&hash, now_f64());
                                    }
                                } else {
                                    requeue_after_path_request(
                                        &mut self.router,
                                        &self.transport_tx,
                                        returned_message,
                                        dest_hash,
                                        &reason,
                                        false,
                                    );
                                }
                            }
                        }
                    }
                    DirectDeliveryPlan::Fail => {
                        tracing::warn!(
                            dest = %dest_hex,
                            attempts = message.delivery_attempts,
                            "direct delivery failed before link delivery"
                        );
                    }
                }
                continue;
            }

            let destination_public_key = self.known_identities.get(&dest_hex).copied();
            let mut missing_identity = false;
            let payload = match message.pack_opportunistic_encrypted(|plaintext| {
                self.encrypt_for_destination(&dest_hex, plaintext)
                    .ok_or_else(|| {
                        missing_identity = true;
                        lxmf_core::message::MessageError::PackFailed(format!(
                            "no identity key for destination {dest_hex}"
                        ))
                    })
            }) {
                Ok(ct) => {
                    tracing::info!(
                        dest = %dest_hex,
                        encrypted_len = ct.len(),
                        "outbound LXMF: encrypted opportunistic payload"
                    );
                    ct
                }
                Err(err) if missing_identity => {
                    tracing::warn!(
                        dest = %dest_hex,
                        attempts = message.delivery_attempts,
                        error = %err,
                        "destination key unknown, re-queuing"
                    );
                    requeue_after_path_request(
                        &mut self.router,
                        &self.transport_tx,
                        message,
                        dest_hash,
                        "opportunistic destination identity unknown",
                        true,
                    );
                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        dest = %dest_hex,
                        error = %err,
                        "failed to pack opportunistic LXMF message"
                    );
                    continue;
                }
            };
            let Some(destination_public_key) = destination_public_key else {
                tracing::error!(
                    dest = %dest_hex,
                    "opportunistic encryption succeeded without a retained destination identity"
                );
                continue;
            };
            let msg_hash = Some(message.message_id());

            let flags = rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Data,
            };
            let header = rns_wire::header::PacketHeader {
                flags,
                hops: 0,
                transport_id: None,
                destination_hash: dest_hash,
                context: rns_wire::context::PacketContext::None,
            };
            let mut raw = header.pack();
            raw.extend_from_slice(&payload);

            // Escalate oversize packets to link delivery.
            if raw.len() > rns_wire::constants::MTU {
                tracing::info!(
                    dest = %dest_hex,
                    packet_len = raw.len(),
                    "packet exceeds MTU; routing to link delivery"
                );
                let attempts = mark_delivery_attempt(&mut message);
                if attempts >= MAX_DELIVERY_ATTEMPTS {
                    tracing::warn!(
                        dest = %dest_hex,
                        attempts,
                        max_attempts = MAX_DELIVERY_ATTEMPTS,
                        "oversized direct delivery attempt budget reached; deferring terminal failure"
                    );
                    self.queue_router_message(message, "oversized direct retry deferral");
                    continue;
                }
                let hops = route_hops_for(&self.route_hops, dest_hash);
                self.ensure_link_delivery();
                if let Some(ref mut ld) = self.link_delivery
                    && let Err(err) = ld.start_delivery(message, dest_hash, hops)
                {
                    let reason = err.error.to_string();
                    tracing::warn!(
                        error = %reason,
                        dest = %dest_hex,
                        "failed to start oversized direct link delivery"
                    );
                    requeue_after_path_request(
                        &mut self.router,
                        &self.transport_tx,
                        *err.message,
                        dest_hash,
                        &reason,
                        false,
                    );
                }
                continue;
            }

            mark_delivery_attempt(&mut message);
            match dispatch_opportunistic_packet(
                &self.transport_tx,
                raw,
                dest_hash,
                destination_public_key,
                msg_hash,
            ) {
                Ok(()) => {
                    if let Some(hash) = msg_hash {
                        self.opportunistic_in_flight.insert(
                            hash,
                            PendingOpportunisticDelivery {
                                retry_at: message.next_delivery_attempt,
                                message,
                            },
                        );
                        tracing::info!(hash = %hex::encode(hash), "message sent; awaiting delivery proof");
                    } else {
                        tracing::warn!(
                            dest = %dest_hex,
                            "opportunistic message has no message id; delivery cannot be tracked"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        dest = %dest_hex,
                        error = %e,
                        "transport backpressure deferred opportunistic message"
                    );
                    self.queue_router_message(message, "opportunistic transport backpressure");
                }
            }
        }
    }

    fn ensure_link_delivery(&mut self) {
        if self.link_delivery.is_none() {
            let mut delivery = lxmf_core::link_delivery::LinkDeliveryManager::new(
                self.transport_tx.clone(),
                Some(self.identity.get_public_key()),
                self.identity.get_signing_key(),
            );
            if let Some(handle) = &self.endpoint_dispatch {
                delivery.set_link_endpoint_dispatch_handle(handle.clone());
            }
            self.link_delivery = Some(delivery);
        }
        self.ensure_backchannel_sender();
    }

    fn ensure_backchannel_sender(&mut self) {
        if self.backchannel_command_rx.is_some() || self.link_delivery.is_none() {
            return;
        }

        let (tx, rx) = mpsc::channel(256);
        if let Some(ref mut ld) = self.link_delivery {
            ld.set_cancellation_aware_backchannel_sender(tx);
            self.backchannel_command_rx = Some(rx);
        }
    }

    fn encrypt_for_destination(&self, dest_hash_hex: &str, plaintext: &[u8]) -> Option<Vec<u8>> {
        let pub_key = self.known_identities.get(dest_hash_hex)?;
        let remote = Identity::from_public_key(pub_key).ok()?;
        let ratchet_pub = self
            .received_ratchets
            .get(dest_hash_hex)
            .filter(|rr| !rr.is_expired())
            .map(|rr| &rr.ratchet_pub);
        remote.encrypt(plaintext, ratchet_pub).ok()
    }

    fn pack_message_for_propagation(
        &mut self,
        message: &LxMessage,
        prop_hash: [u8; 16],
    ) -> Result<Vec<u8>, PropagationPreparationError> {
        let dest_hex = hex::encode(message.destination_hash());
        let prepared = propagation_readiness(
            prop_hash,
            self.known_identities.contains_key(&hex::encode(prop_hash)),
            self.route_hops.contains_key(&prop_hash),
            self.node_policies.get(&prop_hash).copied(),
            self.known_identities.contains_key(&dest_hex),
            now_f64(),
        )
        .map_err(PropagationPreparationError::Missing)?;
        let key = self.known_identities[&dest_hex];
        let ratchet = self
            .received_ratchets
            .get(&dest_hex)
            .filter(|r| !r.is_expired())
            .map(|r| r.ratchet_pub);
        let mut binding = key.to_vec();
        if let Some(r) = ratchet {
            binding.extend_from_slice(&r);
        }
        let binding = rns_crypto::sha::full_hash(&binding);
        let id = message.message_id();
        self.propagation_preparation_tasks
            .retain(|task| !task.is_finished());
        if let Some(job) = self.pending_propagation_envelopes.get_mut(&id) {
            if job.binding != binding || job.cost != prepared.policy.stamp_cost {
                self.pending_propagation_envelopes.remove(&id);
            } else {
                match job.result.try_recv() {
                    Ok(Ok(envelope)) => {
                        self.pending_propagation_envelopes.remove(&id);
                        self.propagation_envelopes.insert(id, envelope);
                    }
                    Ok(Err(error)) => {
                        self.pending_propagation_envelopes.remove(&id);
                        return Err(PropagationPreparationError::Invalid(error.to_string()));
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {
                        return Err(PropagationPreparationError::Pending);
                    }
                    Err(oneshot::error::TryRecvError::Closed) => {
                        self.pending_propagation_envelopes.remove(&id);
                        return Err(PropagationPreparationError::Invalid(
                            "propagation worker unavailable".into(),
                        ));
                    }
                }
            }
        }
        if let Some(envelope) = self.propagation_envelopes.get_mut(&id)
            && envelope.matches(message, &binding)
            && envelope.stamp_value() >= u32::from(prepared.policy.stamp_cost)
        {
            return envelope
                .pack_for(prepared, now_f64())
                .map_err(|e| PropagationPreparationError::Invalid(e.to_string()));
        }
        let Ok(permit) = propagation_preparation_slots().try_acquire_owned() else {
            return Err(PropagationPreparationError::Pending);
        };
        let previous = self
            .propagation_envelopes
            .remove(&id)
            .filter(|envelope| envelope.matches(message, &binding));
        let message = message.clone();
        let cost = prepared.policy.stamp_cost;
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (tx, result) = oneshot::channel();
        self.propagation_preparation_tasks
            .push(tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let outcome = (|| {
                    let mut envelope = match previous {
                        Some(envelope) => envelope,
                        None => PropagationEnvelope::new_cancellable(
                            message,
                            binding,
                            cost,
                            |plaintext| {
                                let remote = Identity::from_public_key(&key)
                                    .map_err(|e| MessageError::PackFailed(e.to_string()))?;
                                remote
                                    .encrypt(plaintext, ratchet.as_ref())
                                    .map_err(|e| MessageError::PackFailed(e.to_string()))
                            },
                            &worker_cancel,
                        )?,
                    };
                    envelope.pack_for_cancellable(prepared, now_f64(), &worker_cancel)?;
                    Ok(envelope)
                })();
                let _ = tx.send(outcome);
            }));
        self.pending_propagation_envelopes.insert(
            id,
            PendingPropagationEnvelope {
                binding,
                cost,
                result,
                cancel,
            },
        );
        Err(PropagationPreparationError::Pending)
    }

    fn decrypt_inbound(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let prv_keys = self.delivery_ratchets.ring().private_keys();
        let refs: Vec<&[u8; 32]> = prv_keys.iter().collect();
        let ratchets = if refs.is_empty() {
            None
        } else {
            Some(refs.as_slice())
        };
        self.identity.decrypt(ciphertext, ratchets, false).ok()
    }

    fn create_delivery_proof(&self, raw_packet: &[u8]) -> Option<Vec<u8>> {
        let (header, _) = rns_wire::header::PacketHeader::unpack(raw_packet).ok()?;
        let full_hash = rns_wire::hash::packet_hash(raw_packet, header.flags.header_type);
        let trunc_hash =
            rns_wire::hash::truncated_packet_hash(raw_packet, header.flags.header_type);

        let signature = self.identity.sign(&full_hash)?;

        let proof_flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Proof,
        };
        let proof_header = rns_wire::header::PacketHeader {
            flags: proof_flags,
            hops: 0,
            transport_id: None,
            destination_hash: trunc_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&signature);
        Some(proof_raw)
    }

    fn save_crypto_state(&self) -> std::io::Result<()> {
        let ratchet_dir = self.ratchets_dir.clone();
        require_ratchet_directory(&ratchet_dir)?;
        let received_dir = ratchet_dir.join("received");
        require_ratchet_directory(&received_dir)?;

        self.delivery_ratchets.save_durable(&self.identity)?;

        for (hash_hex, rr) in &self.received_ratchets {
            let path = received_dir.join(format!("{hash_hex}.ratchet"));
            if !hex::decode(hash_hex).is_ok_and(|hash| hash.len() == 16) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid received ratchet destination",
                ));
            }
            rr.save_durable(&path)?;
        }

        // Flat binary: [dest_hash:16][pub:64] per entry.
        let ki_path = ratchet_dir.join("known_identities");
        let mut data = Vec::with_capacity(self.known_identities.len() * 80);
        for (hash_hex, pk) in &self.known_identities {
            if let Ok(hash_bytes) = hex::decode(hash_hex)
                && hash_bytes.len() == 16
            {
                data.extend_from_slice(&hash_bytes);
                data.extend_from_slice(pk);
            }
        }
        lxmf_core::persist::write_file_atomic(&ki_path, &data)
    }
}

const STORAGE_NAMESPACE_BYTES: &[u8] = b"lxmd-private-namespace-v1\n";

fn require_ratchet_directory(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daemon namespace must contain real directories",
        ));
    }
    validate_durable_storage_directory(path).map_err(std::io::Error::other)
}

fn require_storage_namespace(paths: &LxmdPaths) -> std::io::Result<()> {
    durable_reconcile(
        &paths.config_dir.join(".lxmd-namespace-ready"),
        STORAGE_NAMESPACE_BYTES,
    )
    .map_err(std::io::Error::other)?;
    for path in [
        &paths.config_dir,
        &paths.storage_dir,
        &paths.lxmf_storage_dir,
        &paths.ratchets_dir,
        &paths.received_ratchets_dir,
    ] {
        require_ratchet_directory(path)?;
    }
    Ok(())
}

/// Establish/reconcile the entire private ratchet namespace before config,
/// RNS or daemon storage users open handles. A live runner only validates this
/// completed marker and never republishes an existing root on Windows.
fn initialize_storage_namespace(config_dir: &Path) -> std::io::Result<()> {
    let target = std::path::absolute(config_dir)?;
    if target.join(".lxmd-namespace-ready").try_exists()? {
        require_storage_namespace(&LxmdPaths::new(&target))?;
    }
    let mut anchor = target.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daemon config directory needs an outside namespace anchor",
        )
    })?;
    while !anchor.try_exists()? {
        anchor = anchor.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "daemon namespace has no existing anchor",
            )
        })?;
    }
    let digest = hex::encode(rns_crypto::sha::sha256(
        target.as_os_str().as_encoded_bytes(),
    ));
    let witness = durable_write(
        &anchor.join(format!(".lxmd-root-{digest}.witness")),
        STORAGE_NAMESPACE_BYTES,
    )
    .map_err(std::io::Error::other)?;
    let paths = LxmdPaths::new(&target);
    for path in [
        &paths.config_dir,
        &paths.storage_dir,
        &paths.lxmf_storage_dir,
        &paths.ratchets_dir,
        &paths.received_ratchets_dir,
    ] {
        durable_create_dir_all(path, &witness).map_err(std::io::Error::other)?;
    }
    durable_write(
        &target.join(".lxmd-namespace-ready"),
        STORAGE_NAMESPACE_BYTES,
    )
    .map_err(std::io::Error::other)?;
    Ok(())
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();

    if args.exampleconfig {
        print!("{}", example_config());
        return;
    }

    setup_logging(args.verbose, args.quiet, args.service);

    let (config_dir, rns_config_dir) =
        resolve_config_dirs(args.config.as_deref(), args.rnsconfig.as_deref());

    if args.migrate_propagation_store {
        let result = (|| -> std::io::Result<()> {
            use lxmf_core::propagation_store_v2::{
                RecoveryPolicy, begin_offline_migration, import_trusted_recovery_manifest,
                migrate_store_offline,
            };
            let paths = LxmdPaths::new(config_dir.clone());
            let guard =
                begin_offline_migration(&paths.propagation_store_dir, args.relay_writers_stopped)?;
            let report = migrate_store_offline(&guard)?;
            println!(
                "Relay store v2 ready at {}. Preserved {} legacy files ({} bytes) in quarantine.",
                report.store.display(),
                report.quarantine.files,
                report.quarantine.bytes
            );
            if let Some(manifest) = args.recover_propagation_manifest.as_ref() {
                let digest = hex::decode(args.recovery_manifest_sha256.as_deref().unwrap_or(""))
                    .map_err(std::io::Error::other)?;
                let digest: [u8; 32] = digest.try_into().map_err(|_| {
                    std::io::Error::other(
                        "recovery manifest SHA-256 must be 64 hexadecimal characters",
                    )
                })?;
                let source = rns_runtime::config::Config::from_file(&config_dir.join("config"))
                    .map_err(std::io::Error::other)?;
                let config = DaemonConfig::from_config(&source);
                let policy = RecoveryPolicy {
                    maximum_store_bytes: config
                        .message_storage_limit
                        .unwrap_or(configured_kilobytes_to_bytes(config.propagation_limit_kb)),
                    maximum_message_bytes: configured_kilobytes_to_bytes(
                        config.propagation_limit_kb,
                    ),
                    minimum_stamp_cost: config
                        .propagation_stamp_cost
                        .saturating_sub(config.propagation_stamp_flex),
                };
                let recovered = import_trusted_recovery_manifest(&guard, manifest, digest, policy)?;
                println!(
                    "Recovered {} verified opaque entries; {} were already present.",
                    recovered.imported, recovered.already_present
                );
            }
            println!(
                "Keep legacy propagation hosting and sync disabled. Retry alone never promotes quarantined files."
            );
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("Relay migration unavailable: {error}");
            std::process::exit(1);
        }
        return;
    }

    let is_control_command =
        args.status || args.peers || args.sync.is_some() || args.unpeer.is_some();
    let control_preflight = if is_control_command {
        let peer_hash = if args.status || args.peers {
            None
        } else {
            args.sync.as_deref().or(args.unpeer.as_deref())
        };
        match preflight_control_command(
            &config_dir,
            args.identity.as_deref(),
            peer_hash,
            args.remote.as_deref(),
        ) {
            Ok(preflight) => Some(preflight),
            Err(e) => {
                println!("{}", e.message);
                std::process::exit(e.exit_code);
            }
        }
    } else {
        None
    };

    if !is_control_command && let Err(error) = initialize_storage_namespace(&config_dir) {
        tracing::error!(%error, "Failed to establish private daemon storage namespace");
        std::process::exit(1);
    }
    let config_path = config_dir.join("config");
    let config = match rns_runtime::config::Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "Could not load config from {}: {}",
                config_path.display(),
                e
            );
            tracing::info!("Using default configuration");
            rns_runtime::config::Config::parse(rns_runtime::config::Config::default_config())
                .expect("default config must parse")
        }
    };

    let mut daemon_config = DaemonConfig::from_config(&config);
    if args.propagation_node {
        daemon_config.propagation_enabled = true;
    }
    if let Some(ref on_inbound) = args.on_inbound {
        daemon_config.on_inbound_command = Some(on_inbound.clone());
    }

    tracing::info!("LXMF Daemon starting");
    if let Some(ref name) = daemon_config.display_name {
        tracing::info!("Display name: {}", name);
    }

    if daemon_config.propagation_enabled {
        tracing::info!(
            "Propagation node enabled (stamp_cost={}, max_peers={}, autopeer={})",
            daemon_config.propagation_stamp_cost,
            daemon_config.max_peers,
            daemon_config.autopeer,
        );
    }

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            tracing::info!("Received shutdown signal");
            shutdown_clone.trigger();
        }
    });

    let rns_config_dir_str = rns_config_dir.to_string_lossy().to_string();
    let is_foreground = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let rns_handle = match rns_runtime::reticulum::init(
        Some(&rns_config_dir_str),
        None,
        shutdown.clone(),
        is_foreground,
    )
    .await
    {
        Ok(h) => {
            tracing::info!(
                "RNS initialized: mode={:?}, interfaces={}",
                h.instance_mode,
                h.interface_configs.len(),
            );
            h
        }
        Err(e) => {
            tracing::error!("Failed to initialize RNS: {e:?}");
            return;
        }
    };
    rns_handle
        .enable_on_network_discovery(Arc::new(
            lxmf_core::discovery_stamper::LxmfDiscoveryStamper::default(),
        ))
        .await;

    let transport_tx = rns_handle.transport_tx.clone();

    if let Some(preflight) = control_preflight {
        let identity = match Identity::from_file(&preflight.identity_path) {
            Ok(identity) => identity,
            Err(_) => {
                println!(
                    "Could not load the Primary Identity from {}",
                    preflight.identity_path.display()
                );
                std::process::exit(4);
            }
        };
        let timeout = args
            .timeout
            .unwrap_or(if args.status || args.peers { 5.0 } else { 10.0 })
            .max(0.0);
        if !wait_for_online_interface(&rns_handle, Duration::from_secs_f64(timeout.min(5.0))).await
        {
            println!("No online Reticulum interface became available, exiting now");
            std::process::exit(200);
        }
        let target_identity_hash = match preflight.remote_hash {
            Some(remote_hash) => {
                match resolve_remote_identity_hash(transport_tx.clone(), remote_hash, 5.0).await {
                    Ok(identity_hash) => identity_hash,
                    Err(_) => {
                        println!("Resolving remote identity timed out, exiting now");
                        std::process::exit(200);
                    }
                }
            }
            None => identity.hash,
        };

        if args.status || args.peers {
            let response_bytes = match query_control(
                transport_tx.clone(),
                identity,
                target_identity_hash,
                lxmf_core::constants::STATS_GET_PATH,
                Vec::new(),
                timeout,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => print_control_link_error(ControlCommandKind::Status, &error),
            };
            let response = decode_control_response(&response_bytes);
            exit_for_control_response(ControlCommandKind::Status, &response);
            match response {
                ControlResponse::Stats(stats) => {
                    print!(
                        "{}",
                        format_remote_status(&stats, args.status, args.peers, now_f64())
                    );
                }
                _ => {
                    println!("Empty response received");
                    std::process::exit(207);
                }
            }
            return;
        }

        if args.sync.is_some() {
            let peer_hash = preflight
                .peer_hash
                .expect("sync preflight should include peer hash");
            let response_bytes = match query_control(
                transport_tx.clone(),
                identity,
                target_identity_hash,
                lxmf_core::constants::SYNC_REQUEST_PATH,
                peer_hash.to_vec(),
                timeout,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => print_control_link_error(ControlCommandKind::Sync, &error),
            };
            let response = decode_control_response(&response_bytes);
            exit_for_control_response(ControlCommandKind::Sync, &response);
            println!("Sync requested for peer <{}>", hex::encode(peer_hash));
            return;
        }

        if args.unpeer.is_some() {
            let peer_hash = preflight
                .peer_hash
                .expect("unpeer preflight should include peer hash");
            let response_bytes = match query_control(
                transport_tx.clone(),
                identity,
                target_identity_hash,
                lxmf_core::constants::UNPEER_REQUEST_PATH,
                peer_hash.to_vec(),
                timeout,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => print_control_link_error(ControlCommandKind::Unpeer, &error),
            };
            let response = decode_control_response(&response_bytes);
            exit_for_control_response(ControlCommandKind::Unpeer, &response);
            println!("Broke peering with <{}>", hex::encode(peer_hash));
            return;
        }
    }

    let mut runner = match LxmdRunner::new(
        daemon_config.clone(),
        &config_dir,
        transport_tx,
        Some(rns_handle.link_endpoint_dispatch_handle()),
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to initialize LXMF daemon: {e}");
            std::process::exit(1);
        }
    };
    if let Err(error) = runner.install_announce_subscriptions(&rns_handle).await {
        if shutdown.is_triggered() {
            tracing::info!("Startup announce cancelled by shutdown");
            return;
        }
        tracing::error!(%error, "failed to install lxmd announce subscriptions");
        std::process::exit(1);
    }

    runner.apply_config();

    if let Err(e) = runner.router.load_state(&runner.data_dir) {
        tracing::warn!("Failed to load persisted router state: {e}");
    } else {
        tracing::info!(
            "Loaded persisted router state from {}",
            runner.data_dir.display()
        );
    }

    let ignored = load_hash_list(&config_dir.join("ignored"));
    if !ignored.is_empty() {
        tracing::info!(
            "Loaded {} ignored destination(s) from ignored",
            ignored.len()
        );
        for destination in ignored {
            runner.router.ignore_destination(destination);
            if let Some(ref node) = runner.propagation_node
                && let Ok(mut node) = node.lock()
            {
                node.ignore_destination(destination);
            }
        }
    }
    let allowed = load_hash_list(&config_dir.join("allowed"));
    if !allowed.is_empty() {
        tracing::info!(
            "Loaded {} allowed destination(s) from allowed",
            allowed.len()
        );
        runner.router.allowed.extend(allowed);
    }

    runner.refresh_control_state();

    tracing::info!("LXMF router initialized");

    // Startup announce: wait until at least one interface is online, mirroring
    // Python's deferred_start_jobs() pattern.
    if daemon_config.announce_at_start {
        tracing::info!("Waiting for interfaces to come online before announcing...");
        let mut announced = false;
        for _ in 0..30 {
            if shutdown.is_triggered() {
                break;
            }
            let poll_started = Instant::now();
            let (otx, orx) = tokio::sync::oneshot::channel();
            tokio::select! {
                _ = shutdown.wait() => break,
                result = runner.transport_tx.send(TransportMessage::Rpc {
                    query: rns_transport::messages::TransportQuery::GetInterfaceStats,
                    response_tx: otx,
                }) => {
                    if result.is_err() {
                        break;
                    }
                }
            }

            let stats_result = tokio::select! {
                _ = shutdown.wait() => break,
                result = tokio::time::timeout(Duration::from_secs(1), orx) => result,
            };
            if let Ok(Ok(rns_transport::messages::TransportQueryResponse::InterfaceStats(stats))) =
                stats_result
            {
                // `online` is the readiness signal. Requiring traffic bytes
                // creates a circular startup gate on listening/server
                // interfaces and can postpone the daemon loop (including
                // accepted control commands) for the full 30 seconds.
                let any_online = stats.iter().any(|stats| stats.online);
                if any_online {
                    match runner.send_announce().await {
                        Ok(()) => {
                            tracing::info!("Startup announce sent (interface online)");
                            announced = true;
                        }
                        Err(e) => tracing::warn!("Failed to send startup announce: {e}"),
                    }
                    break;
                }
            }
            // The control LinkManager is already live during this wait. Never
            // acknowledge a command and then leave it dormant until startup
            // announcement polling finishes.
            runner.drain_control_commands();
            let elapsed = poll_started.elapsed();
            if elapsed < Duration::from_secs(1)
                && sleep_or_shutdown(&shutdown, Duration::from_secs(1) - elapsed).await
            {
                break;
            }
        }
        if shutdown.is_triggered() {
            tracing::info!("Startup announce cancelled by shutdown");
        } else if !announced {
            tracing::warn!("No online interface detected after 30s, announcing anyway");
            let _ = runner.send_announce().await;
        }
    }

    // As in Python's deferred start jobs, both announce clocks start here even
    // when nothing announced at start.
    let announce_clock_start = now_f64();
    runner.last_peer_announce = announce_clock_start;
    runner.last_node_announce = announce_clock_start;
    if !shutdown.is_triggered()
        && daemon_config.node_announce_at_start
        && daemon_config.propagation_enabled
    {
        runner.schedule_node_announce(announce_clock_start);
        runner.startup_node_announce_pending = true;
        tracing::info!("Startup propagation announce scheduled in {NODE_ANNOUNCE_DELAY}s");
    }

    if let Some(ref cmd) = daemon_config.on_inbound_command {
        tracing::info!("On-inbound command: {}", cmd);
    }

    let mut one_shot_status = None;
    if let Some(send_args) = args.send.as_ref().filter(|_| !shutdown.is_triggered()) {
        one_shot_status = Some(1);
        'one_shot: {
            let dest_hex = normalize_hash_hex(&send_args[0]);
            let content = match args.send_file.as_ref() {
                Some(path) => match std::fs::read_to_string(path) {
                    Ok(content) => content,
                    Err(e) => {
                        tracing::error!(path = %path.display(), error = %e, "failed to read --send-file");
                        break 'one_shot;
                    }
                },
                None => match send_args.get(1) {
                    Some(content) => content.clone(),
                    None => {
                        tracing::error!("--send requires CONTENT unless --send-file is provided");
                        break 'one_shot;
                    }
                },
            };

            let dest_hash = match parse_destination_hash(&dest_hex) {
                Ok(hash) => hash,
                Err(e) => {
                    tracing::error!("{e}");
                    break 'one_shot;
                }
            };

            tracing::info!(dest = %dest_hex, "sending message...");
            runner.last_delivery_failure = None;

            // Wait up to 15s for a fresh announce so we learn the destination's key and
            // install a current path before queueing. A persisted key alone is not enough
            // behind transport hubs: link delivery can start before the path exists.
            if !runner.known_identities.contains_key(&dest_hex) {
                queue_path_request(
                    &runner.transport_tx,
                    dest_hash,
                    false,
                    "one-shot recipient key discovery",
                );
            }
            if args.send_method.delivery_method() == DeliveryMethod::Propagated
                && let Some(node) = runner.router.outbound_propagation_node
            {
                queue_path_request(
                    &runner.transport_tx,
                    node,
                    false,
                    "one-shot propagation node readiness",
                );
            }
            let mut have_key = runner.known_identities.contains_key(&dest_hex);
            let mut saw_dest_announce = false;
            for _ in 0..30 {
                for announced in runner.drain_announce_events() {
                    if announced == dest_hash {
                        saw_dest_announce = true;
                    }
                }
                runner.refresh_route_hops_from_transport().await;
                runner.drain_link_packets();
                have_key = runner.known_identities.contains_key(&dest_hex);
                if have_key
                    && (saw_dest_announce
                        || args.send_method.delivery_method() == DeliveryMethod::Propagated)
                {
                    break;
                }
                if sleep_or_shutdown(&shutdown, Duration::from_millis(500)).await {
                    tracing::info!("message send interrupted by shutdown");
                    break 'one_shot;
                }
            }
            if !have_key {
                tracing::warn!(
                    dest = %dest_hex,
                    "no announce received for destination in 15s; sending anyway"
                );
            } else if !saw_dest_announce {
                tracing::warn!(
                    dest = %dest_hex,
                    "no fresh path announce received for destination in 15s; sending anyway"
                );
            }

            let mut msg = match LxMessageDraft::new(
                dest_hash,
                runner.lxmf_dest_hash,
                "",
                &content,
                args.send_method.delivery_method(),
            ) {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(%error,"invalid message size");
                    break 'one_shot;
                }
            };
            if let Some(raw) = args.send_fields_json.as_deref() {
                match parse_send_fields_json(raw) {
                    Ok(fields) => {
                        tracing::info!(count = fields.len(), "attaching custom fields to --send");
                        for (id, value) in fields {
                            if let Err(error) = msg.set_field(id, value) {
                                tracing::error!(%error,"invalid --send field");
                                break 'one_shot;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("--send-fields-json: {e}");
                        break 'one_shot;
                    }
                }
            }
            msg.include_ticket = true;
            let prepared = runner.router.prepare_outbound(&mut msg).and_then(|intent| {
                intent
                    .persist(&runner.data_dir, &mut msg)
                    .map_err(|e| lxmf_core::router::TicketPreparationError::Encode(e.to_string()))
            });
            if let Err(error) = prepared {
                tracing::error!(%error,"reply ticket persistence failed");
                break 'one_shot;
            }
            let Some(signing_key) = runner.identity.get_signing_key() else {
                tracing::error!("identity has no signing key");
                break 'one_shot;
            };
            let signed = match msg.sign(&signing_key) {
                Ok(value) => value,
                Err(error) => {
                    tracing::error!(%error,"failed to sign message");
                    break 'one_shot;
                }
            };
            if let Err(error) = runner.router.submit_signed(signed) {
                tracing::error!(%error,"failed to queue message");
                break 'one_shot;
            }

            // Completion phase: do not confuse queue acceptance with delivery.
            // Opportunistic messages leave the router queue while a validated
            // Reticulum delivery proof is outstanding, so both ownership sets
            // must converge before the command can report success.
            let mut drained = false;
            for _ in 0..args.send_timeout_secs {
                runner.drain_announce_events();
                runner.refresh_route_hops_from_transport().await;
                runner.drain_link_packets();
                runner.tick();
                if sleep_or_shutdown(&shutdown, Duration::from_secs(1)).await {
                    tracing::info!("message send interrupted by shutdown");
                    break 'one_shot;
                }

                let stats = runner.router.stats();
                if stats.pending_outbound == 0
                    && stats.pending_deferred_stamps == 0
                    && runner.opportunistic_in_flight.is_empty()
                {
                    drained = true;
                    break;
                }
            }

            if !drained {
                tracing::warn!("message send timed out before delivery completed");
                eprintln!("Error: send timed out (delivery was not confirmed)");
                break 'one_shot;
            }

            // Link-delivery completion phase: when escalated to link delivery
            // (Opportunistic>MTU auto-downgrade, Direct, or Propagated), the
            // router queue empties immediately but the transfer continues on the
            // link. Wait up to 90s so the proof can come back.
            if runner
                .link_delivery
                .as_ref()
                .is_some_and(|ld| ld.pending_count() > 0)
            {
                tracing::info!("waiting for link delivery to complete...");
                let mut link_done = false;
                for _ in 0..args.send_timeout_secs {
                    runner.drain_announce_events();
                    runner.refresh_route_hops_from_transport().await;
                    runner.drain_link_packets();
                    runner.tick();
                    if sleep_or_shutdown(&shutdown, Duration::from_secs(1)).await {
                        tracing::info!("message send interrupted by shutdown");
                        break 'one_shot;
                    }

                    if runner
                        .link_delivery
                        .as_ref()
                        .is_none_or(|ld| ld.pending_count() == 0)
                    {
                        link_done = true;
                        break;
                    }
                }
                if !link_done {
                    tracing::warn!(
                        timeout_secs = args.send_timeout_secs,
                        "link delivery did not complete before timeout"
                    );
                    eprintln!("Error: link delivery did not complete in time");
                    break 'one_shot;
                }
            }
            if let Some(reason) = runner.last_delivery_failure.as_ref() {
                tracing::warn!(reason = %reason, "message send failed during link delivery");
                eprintln!("Error: link delivery failed: {reason}");
                break 'one_shot;
            }

            tracing::info!("message sent successfully");
            println!("Message sent to {}", dest_hex);
            one_shot_status = Some(0);
        }
        shutdown.trigger();
    }

    if !shutdown.is_triggered() {
        tracing::info!("LXMF Daemon running. Press Ctrl+C to stop.");
    }

    // Event-driven for inbound, periodic for outbound and maintenance.
    let mut tick_timer = tokio::time::interval(Duration::from_secs(4));
    tick_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut propagation_sync_timer = tokio::time::interval(Duration::from_millis(25));
    propagation_sync_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            _ = propagation_sync_timer.tick() => {
                runner.drive_propagation_sync();
            }
            _ = tick_timer.tick() => {
                runner.drain_announce_events();
                runner.refresh_route_hops_from_transport().await;
                runner.refresh_blackholed_identities_from_transport().await;
                runner.drain_link_packets();
                runner.tick();
            }
            Some(raw) = runner.inbound_raw_rx.recv() => {
                runner.handle_inbound_packet(&raw);
            }
            Some((plaintext, _link_id)) = runner.link_packet_rx.recv() => {
                runner.handle_link_delivered_data(&plaintext);
                runner.drain_link_packets();
            }
            Some(event) = runner.delivery_accounting_rx.recv() => {
                runner.handle_delivery_accounting_event(event);
                runner.drain_link_packets();
            }
            Some(event) = runner.delivery_resource_event_rx.recv() => {
                if matches!(
                    &event,
                    LinkResourceEvent::Progress {
                        direction: LinkResourceDirection::Inbound,
                        ..
                    }
                )
                    && let Some(event) = delivery_resource_event_from_runtime(event) {
                        runner.router.handle_inbound_resource_event(event);
                    }
                runner.drain_link_packets();
            }
            Some(packet) = runner.prop_link_packet_rx.recv() => {
                runner.handle_propagation_packet(packet);
                runner.drain_link_packets();
            }
            Some(event) = runner.prop_accounting_rx.recv() => {
                runner.handle_propagation_accounting_event(event);
                runner.drain_link_packets();
            }
            Some(result) = runner.prop_validation_rx.recv() => {
                runner.handle_propagation_validation_result(result);
                runner.drain_link_packets();
            }
            Some(result) = runner.prop_packet_validation_rx.recv() => {
                runner.handle_propagation_packet_validation_result(result);
                runner.drain_link_packets();
            }
            Some(result) = runner.prop_store_commit_rx.recv() => {
                apply_propagation_store_commit(
                    &mut runner.router,
                    runner.propagation_node.as_ref(),
                    result,
                );
                runner.drain_link_packets();
            }
            Some(served) = runner.client_propagation_served_rx.recv() => {
                runner.record_client_propagation_served(served);
            }
        }
    }

    tracing::info!("LXMF Daemon shutting down");
    runner.close_announce_subscriptions().await;
    runner.prop_get_workers.close_and_join().await;
    // Revoke new packet admission, then retain and join every already admitted
    // owner through its actual validation/store completion before final state.
    runner.prop_link_packet_rx.close();
    while runner.prop_link_packet_rx.try_recv().is_ok() {}
    let (closed_sender, closed_receiver) = mpsc::channel(1);
    drop(closed_receiver);
    let old_sender = std::mem::replace(&mut runner.prop_packet_validation_job_tx, closed_sender);
    drop(old_sender);
    if let Some(task) = runner.prop_packet_validation_pool.take() {
        let _ = task.await;
    }
    while let Ok(result) = runner.prop_packet_validation_rx.try_recv() {
        runner.handle_propagation_packet_validation_result(result);
    }
    if let Some(task) = runner.prop_maintenance_task.take() {
        let _ = task.task.await;
        if !matches!(task.result.await, Ok(Ok(()))) && one_shot_status.is_some() {
            one_shot_status = Some(1);
        }
    }

    runner.pending_propagation_envelopes.clear();
    for task in std::mem::take(&mut runner.propagation_preparation_tasks) {
        let _ = task.await;
    }
    if let Some(client) = runner.propagation_client.as_mut() {
        client.cancel_download();
    }
    for task in std::mem::take(&mut runner.download_tasks) {
        let _ = task.await;
    }
    runner.pending_downloads.clear();
    runner.poll_download_commits();
    if let Some(task) = runner.suppression_task.take() {
        let _ = task.task.await;
    }
    if let Some(task) = runner.hook_task.take() {
        let _ = task.await;
    }
    if let Some(task) = runner.maintenance_task.take() {
        let _ = task.await;
    }
    for task in std::mem::take(&mut runner.prop_store_write_tasks) {
        if let Err(error) = task.await {
            tracing::warn!(%error, "propagation store write task failed during shutdown");
        }
    }
    while let Ok(result) = runner.prop_store_commit_rx.try_recv() {
        apply_propagation_store_commit(
            &mut runner.router,
            runner.propagation_node.as_ref(),
            result,
        );
    }
    if let Some(task) = runner.checkpoint_task.take() {
        let _ = task.task.await;
        if !matches!(task.result.await, Ok(Ok(()))) {
            tracing::warn!("pending daemon checkpoint did not commit at shutdown");
            if one_shot_status.is_some() {
                one_shot_status = Some(1);
            }
        }
    }
    if let Err(error) = runner.save_crypto_state() {
        tracing::warn!(%error,"crypto checkpoint did not commit on shutdown");
        if one_shot_status.is_some() {
            one_shot_status = Some(1);
        }
    }
    if let Err(error) =
        lxmf_core::persist::save_node_policies(&runner.data_dir, &runner.node_policies)
    {
        tracing::warn!(%error,"failed to persist propagation node policies");
        if one_shot_status.is_some() {
            one_shot_status = Some(1);
        }
    }
    if let Err(e) = runner.router.save_state(&runner.data_dir) {
        tracing::warn!("Failed to save router state on shutdown: {e}");
        if one_shot_status.is_some() {
            one_shot_status = Some(1);
        }
    }

    tracing::info!("LXMF Daemon stopped");
    if let Some(status) = one_shot_status {
        std::process::exit(status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn storage_namespace_fresh_restart_and_missing_parent_are_checked() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fresh/nested/config");
        initialize_storage_namespace(&root).unwrap();
        let (tx, _rx) = mpsc::channel(64);
        let first = LxmdRunner::new(DaemonConfig::default(), &root, tx, None).unwrap();
        let public = first.delivery_ratchets.ring().current_public_key();
        assert!(public.is_some());
        first.save_crypto_state().unwrap();
        drop(first);
        initialize_storage_namespace(&root).unwrap();
        let (tx, _rx) = mpsc::channel(64);
        let restarted = LxmdRunner::new(DaemonConfig::default(), &root, tx, None).unwrap();
        assert_eq!(
            restarted.delivery_ratchets.ring().current_public_key(),
            public
        );
        std::fs::remove_dir(&restarted.received_ratchets_dir).unwrap();
        assert!(restarted.save_crypto_state().is_err());
        assert!(!restarted.received_ratchets_dir.exists());
        drop(restarted);
        assert!(initialize_storage_namespace(&root).is_err());
    }

    #[tokio::test]
    async fn storage_namespace_barrier_failure_prevents_daemon_ratchet_creation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("config");
        let paths = LxmdPaths::new(&root);
        std::fs::create_dir_all(&paths.lxmf_storage_dir).unwrap();
        std::fs::write(&paths.ratchets_dir, b"preserve namespace blocker").unwrap();
        assert!(initialize_storage_namespace(&root).is_err());
        let (tx, _rx) = mpsc::channel(64);
        assert!(LxmdRunner::new(DaemonConfig::default(), &root, tx, None).is_err());
        assert_eq!(
            std::fs::read(&paths.ratchets_dir).unwrap(),
            b"preserve namespace blocker"
        );
        assert!(!paths.ratchet_ring_path.exists());
        assert!(!root.join("identity").exists());
    }

    #[tokio::test]
    async fn direct_ticket_requires_source_verification_and_survives_restart() {
        use lxmf_core::constants::FIELD_TICKET;
        use lxmf_core::message::{LxMessageDraft, RecipientStamp};
        use lxmf_core::ticket::Ticket;

        let temp = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(64);
        initialize_storage_namespace(temp.path()).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        let deliveries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = deliveries.clone();
        runner.router.register_delivery_callback(move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        let sender = Identity::new();
        let source =
            Destination::hash_from_name_and_identity(DELIVERY_APP_NAME, Some(&sender.hash));
        let token = [0xA7; 16];
        let mut draft = LxMessageDraft::new(
            runner.lxmf_dest_hash,
            source,
            "ticket",
            "reply after restart",
            DeliveryMethod::Direct,
        )
        .unwrap();
        draft
            .set_msgpack_field(
                FIELD_TICKET,
                Ticket::new(token, runner.lxmf_dest_hash, now_f64() + 3600.)
                    .encode_field()
                    .unwrap(),
            )
            .unwrap();
        let message = draft
            .sign(&sender.get_signing_key().unwrap())
            .unwrap()
            .finalize(None)
            .unwrap();

        // Unknown senders may be delivered, but cannot teach a ticket. An
        // invalid signature under a recalled full identity cannot do so either.
        runner.handle_link_delivered_data(message.wire_bytes());
        assert!(runner.router.get_outbound_ticket(&source).is_none());
        runner
            .known_identities
            .insert(hex::encode(source), sender.get_public_key());
        let mut invalid = message.wire_bytes().to_vec();
        invalid[32] ^= 1;
        runner.handle_link_delivered_data(&invalid);
        assert!(runner.router.get_outbound_ticket(&source).is_none());

        // The exact duplicate is authenticated after identity recall and must
        // still teach the ticket, without producing another delivery event.
        runner.handle_link_delivered_data(message.wire_bytes());
        assert_eq!(runner.router.get_outbound_ticket(&source), Some(token));
        assert_eq!(deliveries.load(std::sync::atomic::Ordering::Relaxed), 1);
        runner.router.save_state(&runner.data_dir).unwrap();
        let mut restored = LxmRouter::new(lxmf_core::router::RouterConfig::default());
        restored.load_state(&runner.data_dir).unwrap();
        assert_eq!(restored.get_outbound_ticket(&source), Some(token));
        let mut reply = LxMessageDraft::new(
            source,
            runner.lxmf_dest_hash,
            "reply",
            "uses the persisted ticket",
            DeliveryMethod::Direct,
        )
        .unwrap();
        restored.prepare_outbound(&mut reply).unwrap();
        restored
            .submit_signed(
                reply
                    .sign(&runner.identity.get_signing_key().unwrap())
                    .unwrap(),
            )
            .unwrap();
        let reply = &restored.pending_outbound[0];
        let mut material = token.to_vec();
        material.extend_from_slice(&reply.message_id());
        assert_eq!(
            reply.recipient_stamp(),
            Some(&RecipientStamp::Ticket(rns_crypto::sha::truncated_hash(
                &material
            )))
        );

        let archived = runner
            .messages_dir
            .join(format!("{}.lxm", hex::encode(message.message_id())));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !archived.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    fn signed_fixture(
        destination: [u8; 16],
        source: [u8; 16],
        title: &str,
        content: &str,
        method: DeliveryMethod,
    ) -> LxMessage {
        lxmf_core::message::LxMessageDraft::new(destination, source, title, content, method)
            .unwrap()
            .sign(&rns_crypto::ed25519::Ed25519PrivateKey::generate())
            .unwrap()
            .finalize(None)
            .unwrap()
    }

    #[tokio::test]
    async fn get_workers_are_bounded_and_cancelled_shutdown_keeps_actual_jobs_owned() {
        let workers = PnGetWorkers::default();
        let (entered_tx, mut entered_rx) = mpsc::channel(4);
        let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut releases = Vec::new();
        for _ in 0..4 {
            let (release, wait) = tokio::sync::oneshot::channel();
            releases.push(release);
            let entered = entered_tx.clone();
            let completed = completed.clone();
            assert!(workers.spawn(move || {
                entered.blocking_send(()).unwrap();
                wait.blocking_recv().unwrap();
                completed.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }));
        }
        for _ in 0..4 {
            entered_rx.recv().await.unwrap();
        }
        assert!(!workers.spawn(|| panic!("fifth worker must not execute")));
        // The current-thread async loop remains runnable while all four actual
        // blocking workers are parked, unlike the old inline request handler.
        tokio::time::timeout(Duration::from_secs(1), tokio::task::yield_now())
            .await
            .unwrap();
        let closing = workers.clone();
        let waiter = tokio::spawn(async move { closing.close_and_join().await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        waiter.abort();
        let _ = waiter.await;
        assert!(!workers.spawn(|| panic!("shutdown must remain closed")));
        assert_eq!(completed.load(std::sync::atomic::Ordering::Acquire), 0);
        for release in releases {
            release.send(()).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), workers.close_and_join())
            .await
            .unwrap();
        assert_eq!(completed.load(std::sync::atomic::Ordering::Acquire), 4);
        assert!(workers.state.lock().unwrap().tasks.is_empty());
    }

    #[tokio::test]
    #[ignore = "private live Python receipt harness supplies a temporary config"]
    async fn live_pn_packet_delay_endpoint() {
        let config_dir = PathBuf::from(
            std::env::var_os("RATSPEAK_PN_TEST_CONFIG").expect("private fixture config"),
        );
        let config = rns_runtime::config::Config::from_file(&config_dir.join("config")).unwrap();
        let config = DaemonConfig::from_config(&config);
        assert!(config.propagation_enabled);
        let shutdown = ShutdownSignal::new();
        let rns_config = config_dir.join("rns");
        initialize_storage_namespace(&config_dir).unwrap();
        eprintln!("PN_RECEIPT_START initializing Reticulum");
        let handle = rns_runtime::reticulum::init(
            Some(rns_config.to_str().unwrap()),
            None,
            shutdown.clone(),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        )
        .await
        .unwrap();
        eprintln!("PN_RECEIPT_START opening daemon storage");
        let mut runner = LxmdRunner::new(
            config,
            &config_dir,
            handle.transport_tx.clone(),
            Some(handle.link_endpoint_dispatch_handle()),
        )
        .unwrap();
        eprintln!("PN_RECEIPT_START installing daemon subscriptions");
        runner.pn_packet_store_delay = Duration::from_millis(100);
        *runner.prop_get_workers.pause.lock().unwrap() = Some(config_dir.clone());
        runner
            .install_announce_subscriptions(&handle)
            .await
            .unwrap();
        runner.apply_config();
        assert!(wait_for_online_interface(&handle, Duration::from_secs(30)).await);
        eprintln!("PN_RECEIPT_START interface online; announcing");
        runner.send_propagation_announce().await.unwrap();
        eprintln!("PN_RECEIPT_START announced");
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        loop {
            assert!(
                Instant::now() < deadline,
                "private receipt endpoint timed out"
            );
            tokio::select! {
                _ = tick.tick() => {
                    runner.drain_link_packets();
                    runner.drive_propagation_sync();
                }
                Some(packet) = runner.prop_link_packet_rx.recv() => {
                    runner.handle_propagation_packet(packet);
                    runner.drain_link_packets();
                }
                Some(result) = runner.prop_packet_validation_rx.recv() => {
                    runner.handle_propagation_packet_validation_result(result);
                    runner.drain_link_packets();
                }
                Some(event) = runner.prop_accounting_rx.recv() => {
                    runner.handle_propagation_accounting_event(event);
                    runner.drain_link_packets();
                }
            }
        }
    }

    #[tokio::test]
    async fn backchannel_accounting_retains_exact_windows_and_resource_cancellation() {
        use std::time::{Duration, Instant};
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = std::env::temp_dir().join(format!(
            "lxmd-backchannel-accounting-{}-{unique}",
            std::process::id()
        ));
        let (tx, _rx) = mpsc::channel(64);
        initialize_storage_namespace(&temp).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), &temp, tx, None).unwrap();
        runner.ensure_link_delivery();
        let (send_tx, mut send_rx) = mpsc::channel(8);
        runner
            .link_delivery
            .as_mut()
            .unwrap()
            .set_backchannel_sender(send_tx);
        let link_id = [0x61; 16];
        let dest = [0x62; 16];
        let resource_hash = [0x63; 32];
        let message = signed_fixture(
            dest,
            [0x64; 16],
            "accounting",
            "bounded",
            DeliveryMethod::Direct,
        );
        let hash = message.message_id();
        let ld = runner.link_delivery.as_mut().unwrap();
        ld.register_backchannel(dest, link_id);
        ld.start_backchannel_delivery(message, dest).unwrap();
        send_rx
            .try_recv()
            .unwrap()
            .result_tx
            .send(Ok(BackchannelSendReceipt::Resource {
                link_id,
                resource_hash,
            }))
            .unwrap();
        assert!(ld.tick().is_empty());
        let Some(original) = Instant::now().checked_sub(Duration::from_secs(400)) else {
            return; // Windows clocks count from boot; fresh runners can't backdate this far.
        };
        runner.handle_delivery_accounting_event(LinkManagerAccountingEvent::OutboundResourceWait {
            link_id,
            resource_id: resource_hash,
            started_at: original,
            timeout: Duration::from_secs(800),
        });
        let ld = runner.link_delivery.as_mut().unwrap();
        assert_eq!(
            ld.message_timeout_window(hash),
            Some((original, Duration::from_secs(980)))
        );
        assert!(ld.tick().is_empty());
        assert!(ld.cancel_delivery_by_message_hash(hash));
        let (command_tx, mut command_rx) = mpsc::channel(1);
        command_tx
            .try_send(LinkManagerCommand::CancelLinkResource {
                link_id: [0; 16],
                resource_id: [0; 32],
                direction: LinkResourceDirection::Outbound,
                result_tx: None,
            })
            .unwrap();
        runner.link_command_tx = command_tx;
        runner.drain_core_backchannel_send_commands();
        assert_eq!(runner.pending_backchannel_resource_cancellations.len(), 1);
        command_rx.try_recv().unwrap();
        runner.drain_core_backchannel_send_commands();
        assert!(
            matches!(command_rx.try_recv(), Ok(LinkManagerCommand::CancelLinkResource {
            link_id: observed_link, resource_id, direction: LinkResourceDirection::Outbound, ..
        }) if observed_link == link_id && resource_id == resource_hash)
        );
        runner.drain_core_backchannel_send_commands();
        assert!(runner.pending_backchannel_resource_cancellations.is_empty());
        assert!(command_rx.try_recv().is_err());
        // A late terminal is reconciled as already cancelled, not retried or
        // published a second time by the daemon's second notification path.
        runner.handle_delivery_accounting_event(LinkManagerAccountingEvent::ResourceEvent(
            LinkResourceEvent::Concluded {
                link_id,
                resource_id: resource_hash,
                direction: LinkResourceDirection::Outbound,
                conclusion: LinkResourceConclusion::Rejected,
            },
        ));
        assert_eq!(runner.link_delivery.as_ref().unwrap().pending_count(), 0);
        assert!(
            runner
                .link_delivery
                .as_ref()
                .unwrap()
                .message_timeout_window(hash)
                .is_none()
        );
        drop(runner);
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn propagation_download_auth_uses_live_allowed_identity_set() {
        let allowed = [0x11; 16];
        let denied = [0x22; 16];
        let open = ControlSnapshot::default();
        assert!(propagation_client_allowed(&open, None));
        assert!(propagation_client_allowed(&open, Some(&denied)));

        let restricted = ControlSnapshot {
            auth_required: true,
            allowed_clients: vec![allowed],
            ..Default::default()
        };
        assert!(propagation_client_allowed(&restricted, Some(&allowed)));
        assert!(!propagation_client_allowed(&restricted, Some(&denied)));
        assert!(!propagation_client_allowed(&restricted, None));
    }

    #[test]
    fn propagation_accounting_advances_only_for_durable_commits() {
        let peer_hash = [0x21; 16];
        let first_id = [0x31; 32];
        let second_id = [0x32; 32];
        let mut router = LxmRouter::new(Default::default());
        router.peers.insert(peer_hash, LxmPeer::new(peer_hash));

        apply_propagation_store_commit(
            &mut router,
            None,
            PropagationStoreCommitResult {
                origin: PropagationStoreWriteOrigin::Peer(peer_hash),
                committed: Vec::new(),
            },
        );
        let peer = router.peers.get(&peer_hash).unwrap();
        assert_eq!(peer.incoming, 0);
        assert_eq!(peer.rx_bytes, 0);

        apply_propagation_store_commit(
            &mut router,
            None,
            PropagationStoreCommitResult {
                origin: PropagationStoreWriteOrigin::Peer(peer_hash),
                committed: vec![(first_id, 120), (second_id, 180)],
            },
        );
        let peer = router.peers.get(&peer_hash).unwrap();
        assert_eq!(peer.incoming, 2);
        assert_eq!(peer.rx_bytes, 300);
        assert!(peer.handled_messages.contains(&first_id));
        assert!(peer.handled_messages.contains(&second_id));

        apply_propagation_store_commit(
            &mut router,
            None,
            PropagationStoreCommitResult {
                origin: PropagationStoreWriteOrigin::Client,
                committed: vec![([0x41; 32], 64)],
            },
        );
        assert_eq!(router.client_propagation_messages_received, 1);
    }

    #[test]
    fn announce_mailbox_coalesces_bursts_and_preserves_distinct_destinations() {
        let mailbox = AnnounceMailbox::default();
        let identity = Identity::new();
        let control_hash = [0x31; 16];
        let propagation_hash = [0x32; 16];
        let config = DaemonConfig::default();

        for _ in 0..64 {
            send_control_announce_try(&mailbox, &identity, control_hash);
            send_propagation_announce_try(&mailbox, &identity, propagation_hash, &config);
        }

        assert_eq!(mailbox.pending_len(), 2);
        let destinations = mailbox
            .take_pending()
            .into_iter()
            .map(|(hash, _)| hash)
            .collect::<HashSet<_>>();
        assert_eq!(
            destinations,
            HashSet::from([control_hash, propagation_hash])
        );
        assert_eq!(mailbox.pending_len(), 0);
    }

    #[test]
    fn lossless_queue_high_water_only_moves_forward() {
        let mut high_water = 0;
        observe_lossless_queue_depth("test", 7, &mut high_water);
        observe_lossless_queue_depth("test", 3, &mut high_water);
        assert_eq!(high_water, 7);
    }

    use lxmf_core::constants::DeliveryMethod;

    #[test]
    fn opportunistic_dispatch_is_atomic_with_receipt_registration() {
        let destination_hash = [0x41; 16];
        let public_key = [0x42; 64];
        let message_hash = [0x43; 32];
        let raw = vec![0x44; 64];
        let (tx, mut rx) = mpsc::channel(2);

        dispatch_opportunistic_packet(&tx, raw, destination_hash, public_key, Some(message_hash))
            .unwrap();

        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::RegisterReceipt {
                destination_hash: hash,
                destination_public_key: key,
                ..
            } if hash == destination_hash && key == public_key
        ));
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::Outbound(request) if request.destination_hash == destination_hash
        ));
    }

    #[test]
    fn opportunistic_dispatch_sends_nothing_when_both_slots_are_unavailable() {
        let (tx, mut rx) = mpsc::channel(2);
        tx.try_send(TransportMessage::DeregisterDestination { hash: [1; 16] })
            .unwrap();

        assert!(
            dispatch_opportunistic_packet(&tx, vec![0; 64], [2; 16], [3; 64], Some([4; 32]))
                .is_err()
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::DeregisterDestination { hash } if hash == [1; 16]
        ));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn required_runtime_registration_reports_transport_failure() {
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        assert!(
            queue_required_transport(
                &closed_tx,
                TransportMessage::DeregisterDestination { hash: [8; 16] },
                "test registration",
            )
            .is_err()
        );

        let (full_tx, _full_rx) = mpsc::channel(1);
        full_tx
            .try_send(TransportMessage::DeregisterDestination { hash: [9; 16] })
            .unwrap();
        assert!(
            queue_required_transport(
                &full_tx,
                TransportMessage::DeregisterDestination { hash: [10; 16] },
                "test registration",
            )
            .is_err()
        );
    }

    #[test]
    fn control_command_success_means_daemon_queue_accepted_it() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let peer_hash = [0x42; 16];

        let response = queue_control_command(&tx, ControlCommand::Sync(peer_hash));

        assert!(matches!(
            decode_control_response(&response),
            ControlResponse::Success
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(ControlCommand::Sync(hash)) if hash == peer_hash
        ));
    }

    #[test]
    fn control_command_reports_timeout_when_daemon_queue_is_closed() {
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);

        let response = queue_control_command(&tx, ControlCommand::Sync([0x24; 16]));

        assert!(matches!(
            decode_control_response(&response),
            ControlResponse::Error(lxmf_core::constants::PeerError::Timeout)
        ));
    }

    #[test]
    fn peer_sync_round_robin_does_not_starve_large_peer_sets() {
        let peers = (0u8..128).map(|byte| [byte; 16]).collect::<Vec<_>>();
        let mut cursor = None;
        let mut selected = HashSet::new();

        for _ in 0..peers.len() {
            let next = round_robin_peer_order(peers.clone(), cursor)[0];
            assert!(
                selected.insert(next),
                "selected a peer twice before a full pass"
            );
            cursor = Some(next);
        }

        assert_eq!(selected.len(), 128);
    }

    #[tokio::test]
    async fn inbound_resource_cancel_adapter_preserves_exact_owner_and_direction() {
        let (cancel_tx, cancel_rx) = mpsc::channel(2);
        let (link_command_tx, mut link_command_rx) = mpsc::channel(2);
        tokio::spawn(forward_inbound_resource_cancellations(
            cancel_rx,
            link_command_tx,
        ));

        let mut router = LxmRouter::new(lxmf_core::router::RouterConfig::default());
        router.set_inbound_resource_cancel_sender(cancel_tx);
        let key = InboundResourceKey::new([0x11; 16], [0x22; 32]);
        router.handle_inbound_resource_event(InboundResourceEvent::Started {
            key,
            data_size: 512,
            total_segments: 2,
        });

        assert_eq!(router.inbound_count(), 1);
        assert!(router.cancel_inbound_exact(key));
        let command = link_command_rx.recv().await.expect("cancellation command");
        let LinkManagerCommand::CancelLinkResource {
            link_id,
            resource_id,
            direction,
            result_tx,
        } = command
        else {
            panic!("expected exact LinkManager Resource cancellation");
        };
        assert_eq!(link_id, key.link_id);
        assert_eq!(resource_id, key.resource_id);
        assert_eq!(direction, LinkResourceDirection::Inbound);
        assert!(result_tx.is_none());
    }

    #[test]
    fn runtime_resource_projection_tracks_only_inbound_resources() {
        let key = InboundResourceKey::new([0x33; 16], [0x44; 32]);
        let projected = delivery_resource_event_from_runtime(LinkResourceEvent::Progress {
            link_id: key.link_id,
            resource_id: key.resource_id,
            direction: LinkResourceDirection::Inbound,
            transferred: 12,
            total: 24,
        });
        assert_eq!(
            projected,
            Some(InboundResourceEvent::Progress {
                key,
                transferred: 12,
                total: 24,
            })
        );

        assert!(
            delivery_resource_event_from_runtime(LinkResourceEvent::Progress {
                link_id: key.link_id,
                resource_id: key.resource_id,
                direction: LinkResourceDirection::Outbound,
                transferred: 12,
                total: 24,
            })
            .is_none()
        );
    }

    fn unpack_announce(raw: &[u8]) -> (rns_wire::header::PacketHeader, AnnounceData) {
        let (header, header_len) = rns_wire::header::PacketHeader::unpack(raw).unwrap();
        let announce = AnnounceData::unpack(&raw[header_len..], header.flags.context_flag).unwrap();
        (header, announce)
    }

    #[test]
    fn propagation_announce_is_never_ratcheted() {
        let identity = Identity::new();
        let destination =
            Destination::hash_from_name_and_identity("lxmf.propagation", Some(&identity.hash));
        let raw = create_propagation_announce_packet_for(
            &identity,
            destination,
            &DaemonConfig::default(),
        )
        .unwrap();
        let (header, announce) = unpack_announce(&raw);
        assert!(!header.flags.context_flag);
        assert_eq!(announce.ratchet, None);
    }

    #[tokio::test]
    async fn node_announces_follow_their_trigger_by_node_announce_delay() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = std::env::temp_dir().join(format!(
            "lxmd-node-announce-delay-{}-{unique}",
            std::process::id()
        ));
        let (tx, mut rx) = mpsc::channel(64);
        initialize_storage_namespace(&temp).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), &temp, tx, None).unwrap();
        // Announce scheduling needs no propagation runtime, only its config.
        runner.config.propagation_enabled = true;
        runner.config.node_announce_interval = Some(60);
        runner.router.allowed_control.push([0x55; 16]);
        let mut staged = || {
            std::iter::from_fn(|| rx.try_recv().ok())
                .filter_map(|message| match message {
                    TransportMessage::Outbound(request) => Some(request.destination_hash),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        staged();
        let (node, control) = (runner.propagation_dest_hash, runner.control_dest_hash);
        let delay = NODE_ANNOUNCE_DELAY as f64;

        // Triggers due together are announced once, never before the delay.
        runner.schedule_node_announce(1_000.0);
        runner.schedule_node_announce(1_000.5);
        runner.stage_due_node_announce(1_000.0 + delay - 0.1);
        assert!(staged().is_empty());
        runner.stage_due_node_announce(1_000.5 + delay);
        assert_eq!(staged(), vec![node, control]);
        runner.stage_due_node_announce(1_000.5 + 2.0 * delay);
        assert!(staged().is_empty());

        // An elapsed periodic interval schedules the announce rather than sending it.
        runner.last_node_announce = now_f64() - 61.0;
        runner.tick();
        assert!(!staged().contains(&node));
        assert_eq!(runner.node_announces_due.len(), 1);

        drop(runner);
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn delivery_resource_admission_uses_decimal_kilobytes_with_exact_boundary() {
        let default_limit = DaemonConfig::default().delivery_transfer_max_accepted_size;
        assert_eq!(default_limit, 1.0);
        assert!(accepts_delivery_resource(1_000, default_limit));
        assert!(!accepts_delivery_resource(1_001, default_limit));

        let explicit_limit = rns_runtime::config::Config::parse(
            "[lxmf]\ndelivery_transfer_max_accepted_size = 1000\n",
        )
        .map(|config| DaemonConfig::from_config(&config))
        .unwrap()
        .delivery_transfer_max_accepted_size;
        assert_eq!(explicit_limit, 1000.0);
        assert!(accepts_delivery_resource(4_114, explicit_limit));
        assert!(accepts_delivery_resource(1_000_000, explicit_limit));
        assert!(!accepts_delivery_resource(1_000_001, explicit_limit));

        assert!(accepts_delivery_resource(380, 0.38));
        assert!(!accepts_delivery_resource(381, 0.38));

        assert_eq!(configured_kilobytes_to_bytes(1), 1_000);
        assert_eq!(configured_kilobytes_to_bytes(256), 256_000);
        assert_eq!(configured_kilobytes_to_bytes(10_240), 10_240_000);
        assert_eq!(configured_kilobytes_to_bytes(usize::MAX), usize::MAX);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delivery_announce_stamp_cost_is_independent_of_enforcement() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for enforce_stamps in [false, true] {
            let temp = std::env::temp_dir().join(format!(
                "lxmd-delivery-announce-stamp-{}-{unique}-{enforce_stamps}",
                std::process::id()
            ));
            let (tx, _rx) = mpsc::channel::<TransportMessage>(64);
            let config = DaemonConfig {
                stamp_cost: Some(12),
                enforce_stamps,
                ..Default::default()
            };
            initialize_storage_namespace(&temp).unwrap();
            let mut runner = LxmdRunner::new(config, &temp, tx, None).expect("runner");
            let raw = runner.create_announce_packet().expect("delivery announce");
            let (_, announce) = unpack_announce(&raw);
            let (_, stamp_cost) = lxmf_core::handlers::parse_announce_app_data(
                announce.app_data.as_deref().expect("delivery app data"),
            )
            .expect("valid delivery app data");
            assert_eq!(stamp_cost, Some(12));
            drop(runner);
            let _ = std::fs::remove_dir_all(&temp);
        }
    }

    /// Blackhole gating mirrors LXMessage.py:804: only a recallable source
    /// identity can be matched against the blackhole table; unknown sources
    /// never drop.
    #[test]
    fn recall_identity_hash_resolves_known_destinations_only() {
        let identity = Identity::new();
        let dest_hash =
            Destination::hash_from_name_and_identity(DELIVERY_APP_NAME, Some(&identity.hash));
        let pub_key = identity.get_public_key();

        let mut known: HashMap<String, [u8; 64]> = HashMap::new();
        assert_eq!(recall_identity_hash(&known, &dest_hash), None);

        known.insert(hex::encode(dest_hash), pub_key);
        assert_eq!(
            recall_identity_hash(&known, &dest_hash),
            Some(identity.hash)
        );

        let mut blackholed: HashSet<[u8; 16]> = HashSet::new();
        blackholed.insert(identity.hash);
        let resolved = recall_identity_hash(&known, &dest_hash).unwrap();
        assert!(blackholed.contains(&resolved));
        assert_eq!(recall_identity_hash(&known, &[0xEE; 16]), None);
    }

    /// Cap eviction prefers entries without a live ratchet, then oldest
    /// ratchets; under the cap nothing is touched.
    #[test]
    fn prune_known_identities_respects_cap_and_recency() {
        let mut ids: HashMap<String, [u8; 64]> = HashMap::new();
        let mut ratchets: HashMap<String, ReceivedRatchet> = HashMap::new();
        for i in 0..KNOWN_IDENTITIES_SOFT_CAP + 10 {
            ids.insert(format!("id{i:05}"), [0u8; 64]);
        }
        // All but 4 of the overflow have ratchets; two ratchets are older.
        for (i, key) in ids.keys().cloned().enumerate().collect::<Vec<_>>() {
            if i >= 4 {
                let mut rr = ReceivedRatchet::new([1u8; 32]);
                rr.received_at = if i < 6 { 1.0 } else { 1000.0 };
                ratchets.insert(key, rr);
            }
        }

        let dropped = prune_known_identities(&mut ids, &ratchets);
        assert_eq!(dropped, 10);
        assert_eq!(ids.len(), KNOWN_IDENTITIES_SOFT_CAP);

        let mut under: HashMap<String, [u8; 64]> = HashMap::new();
        under.insert("only".into(), [0u8; 64]);
        assert_eq!(prune_known_identities(&mut under, &ratchets), 0);
        assert_eq!(under.len(), 1);
    }

    #[test]
    fn path_request_requeue_sets_path_wait_deadline() {
        let mut router = LxmRouter::new(Default::default());
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        let dest = [0x22; 16];
        let source = [0x11; 16];
        let message = signed_fixture(dest, source, "retry", "hello", DeliveryMethod::Direct);
        let before = now_f64();

        requeue_after_path_request(&mut router, &tx, message, dest, "test path wait", true);

        assert_eq!(router.pending_outbound.len(), 1);
        let queued = &router.pending_outbound[0];
        assert_eq!(queued.delivery_attempts, 1);
        assert!(queued.last_delivery_attempt >= before);
        assert!(
            queued.next_delivery_attempt >= before + PATH_REQUEST_WAIT as f64 - 1.0
                && queued.next_delivery_attempt <= now_f64() + PATH_REQUEST_WAIT as f64 + 1.0,
            "path-request retry should wait about {PATH_REQUEST_WAIT}s"
        );

        match rx.try_recv().expect("path request") {
            TransportMessage::RequestPath { destination_hash } => {
                assert_eq!(destination_hash, dest);
            }
            other => panic!("expected RequestPath, got {other:?}"),
        }
    }

    #[test]
    fn queue_path_request_can_drop_stale_path_before_requesting() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        let dest = [0x24; 16];

        queue_path_request(&tx, dest, true, "test rediscovery");

        match rx.try_recv().expect("drop path rpc") {
            TransportMessage::Rpc {
                query: TransportQuery::DropPath { dest: dropped },
                ..
            } => assert_eq!(dropped, dest),
            other => panic!("expected DropPath RPC, got {other:?}"),
        }
        match rx.try_recv().expect("path request") {
            TransportMessage::RequestPath { destination_hash } => {
                assert_eq!(destination_hash, dest);
            }
            other => panic!("expected RequestPath, got {other:?}"),
        }
    }

    #[test]
    fn unknown_propagation_node_path_request_updates_backoff_clock() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        let node = [0x26; 16];
        let mut last = 0.0;
        let now = 1234.5;

        assert!(queue_unknown_propagation_node_path_request(
            &tx, node, &mut last, now
        ));
        assert_eq!(last, now);
        match rx.try_recv().expect("path request") {
            TransportMessage::RequestPath { destination_hash } => {
                assert_eq!(destination_hash, node);
            }
            other => panic!("expected RequestPath, got {other:?}"),
        }
    }

    #[test]
    fn unknown_propagation_node_path_request_updates_backoff_clock_on_full_channel() {
        let (tx, _rx) = mpsc::channel::<TransportMessage>(1);
        let node = [0x27; 16];
        let mut last = 99.0;

        tx.try_send(TransportMessage::RequestPath {
            destination_hash: [0x28; 16],
        })
        .expect("fill test channel");

        assert!(!queue_unknown_propagation_node_path_request(
            &tx, node, &mut last, 1234.5
        ));
        assert_eq!(last, 1234.5);
    }

    #[test]
    fn path_request_requeue_can_preserve_attempt_count_after_link_start_failure() {
        let mut router = LxmRouter::new(Default::default());
        let (tx, _rx) = mpsc::channel::<TransportMessage>(4);
        let dest = [0x44; 16];
        let source = [0x33; 16];
        let mut message = signed_fixture(dest, source, "retry", "hello", DeliveryMethod::Direct);
        message.delivery_attempts = 3;

        requeue_after_path_request(&mut router, &tx, message, dest, "transport full", false);

        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(router.pending_outbound[0].delivery_attempts, 3);
        assert!(router.pending_outbound[0].next_delivery_attempt > now_f64());
    }

    #[test]
    fn delivery_attempt_uses_delivery_retry_deadline() {
        let dest = [0x66; 16];
        let source = [0x55; 16];
        let mut message = signed_fixture(dest, source, "direct", "hello", DeliveryMethod::Direct);
        let before = now_f64();

        let attempts = mark_delivery_attempt(&mut message);

        assert_eq!(attempts, 1);
        assert_eq!(message.delivery_attempts, 1);
        assert!(message.last_delivery_attempt >= before);
        assert!(
            message.next_delivery_attempt >= before + DELIVERY_RETRY_WAIT as f64 - 1.0
                && message.next_delivery_attempt <= now_f64() + DELIVERY_RETRY_WAIT as f64 + 1.0,
            "delivery retry should wait about {DELIVERY_RETRY_WAIT}s"
        );
    }

    #[test]
    fn link_failure_retry_policy_matches_pre_establishment_failures() {
        assert!(link_failure_retryable("link establishment timeout"));
        assert!(link_failure_retryable("link closed"));
        assert!(link_failure_retryable("transport full"));
        assert!(link_failure_retryable("transport closed"));
        assert!(link_failure_retryable("link is not active"));
        assert!(link_failure_retryable("link not found"));
        assert!(!link_failure_retryable("resource transfer failed"));
    }

    #[test]
    fn route_hops_for_uses_cached_announce_hops_with_one_hop_floor() {
        let dest = [0x77; 16];
        let mut hops = HashMap::new();

        assert_eq!(route_hops_for(&hops, dest), 1);

        hops.insert(dest, 4);
        assert_eq!(route_hops_for(&hops, dest), 4);

        hops.insert(dest, 0);
        assert_eq!(route_hops_for(&hops, dest), 1);
    }

    #[test]
    fn direct_route_snapshot_uses_cached_announce_hops() {
        let dest = [0x88; 16];
        let mut hops = HashMap::new();

        assert!(direct_route_snapshot(&hops, dest).is_none());

        hops.insert(dest, 5);
        let snapshot = direct_route_snapshot(&hops, dest).expect("route snapshot");
        assert_eq!(snapshot.destination_hash, dest);
        assert_eq!(snapshot.hops, 5);
    }

    /// Real encrypted downloads pass the same decode/policy stages as workers;
    /// only validated bytes can create an archive, purge receipt, or hook.
    #[test]
    fn propagation_downloaded_data_respects_stamp_enforcement() {
        use lxmf_core::admission::AdmissionScope;
        use lxmf_core::message::{LxMessageDraft, MessageDecodeLimits, RecipientStamp};
        let temp = tempfile::tempdir().unwrap();
        let bodies = temp.path().join("messages");
        let store = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
        let recipient = Identity::new();
        let sender = Identity::new();
        let destination =
            Destination::hash_from_name_and_identity(DELIVERY_APP_NAME, Some(&recipient.hash));
        let source =
            Destination::hash_from_name_and_identity(DELIVERY_APP_NAME, Some(&sender.hash));
        let mut draft = LxMessageDraft::new(
            destination,
            source,
            "title",
            "encrypted body",
            DeliveryMethod::Propagated,
        )
        .unwrap();
        draft.set_timestamp(100.).unwrap();
        let missing = draft
            .clone()
            .sign(&sender.get_signing_key().unwrap())
            .unwrap()
            .finalize(None)
            .unwrap();
        let signed = draft.sign(&sender.get_signing_key().unwrap()).unwrap();
        let encrypt = |message: &LxMessage| {
            let mut wire = destination.to_vec();
            wire.extend_from_slice(
                &recipient
                    .encrypt(&message.wire_bytes()[16..], None)
                    .unwrap(),
            );
            wire
        };
        let cipher = encrypt(&missing);
        let decoded = decode_download_payload(
            &cipher,
            &recipient,
            destination,
            &[],
            MessageDecodeLimits::default(),
        )
        .unwrap();
        assert_eq!(decoded.wire_bytes(), missing.wire_bytes());
        assert_eq!(
            validate_download_policy(&decoded, Some(sender.get_public_key()), &[], 8),
            Err(SuppressionReason::InvalidStamp)
        );
        assert!(store.haves(recipient.hash, [9; 16], 101).is_empty());
        assert!(store.pending_hooks().is_empty());
        assert!(
            !bodies
                .join(format!("{}.lxm", hex::encode(missing.message_id())))
                .exists()
        );
        assert_eq!(
            validate_download_policy(&decoded, Some(sender.get_public_key()), &[], 0),
            Ok(())
        );
        assert!(matches!(
            decode_download_payload(
                missing.wire_bytes(),
                &recipient,
                destination,
                &[],
                MessageDecodeLimits::default()
            ),
            Err(SuppressionReason::DecryptionFailed)
        ));
        let mut corrupt = missing.wire_bytes().to_vec();
        corrupt[32] ^= 1;
        let corrupt = LxMessage::unpack(&corrupt).unwrap();
        assert_eq!(
            validate_download_policy(&corrupt, Some(sender.get_public_key()), &[], 0),
            Err(SuppressionReason::InvalidSignature)
        );
        let ticket = [7u8; 16];
        let mut material = [0u8; 48];
        material[..16].copy_from_slice(&ticket);
        material[16..].copy_from_slice(&missing.message_id());
        let accepted = signed
            .finalize(Some(RecipientStamp::Ticket(
                rns_crypto::sha::truncated_hash(&material),
            )))
            .unwrap();
        let cipher = encrypt(&accepted);
        let accepted = decode_download_payload(
            &cipher,
            &recipient,
            destination,
            &[],
            MessageDecodeLimits::default(),
        )
        .unwrap();
        validate_download_policy(&accepted, Some(sender.get_public_key()), &[ticket], 8).unwrap();
        let scope = AdmissionScope {
            identity: recipient.hash,
            node: [9; 16],
            transient_id: rns_crypto::sha::full_hash(&cipher),
        };
        let record = AdmissionRecord {
            scope,
            message_id: accepted.message_id(),
            received_wire_hash: rns_crypto::sha::full_hash(accepted.wire_bytes()),
            stored_message_wire_hash: None,
            disposition: DurableDisposition::Committed,
            committed_at: 100,
        };
        let receipt =
            DurableAdmissionReceipt::commit(store.prepare(record, accepted.wire_owned(), true))
                .unwrap();
        assert_eq!(receipt.record().scope, scope);
        assert_eq!(
            std::fs::read(bodies.join(format!("{}.lxm", hex::encode(accepted.message_id()))))
                .unwrap(),
            accepted.wire_bytes()
        );
        assert_eq!(
            store.haves(recipient.hash, [9; 16], 101),
            vec![scope.transient_id.to_vec()]
        );
        assert_eq!(store.pending_hooks().len(), 1);
        drop(store);
        let reopened = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
        assert_eq!(
            reopened.haves(recipient.hash, [9; 16], 101),
            vec![scope.transient_id.to_vec()]
        );
        assert_eq!(reopened.pending_hooks().len(), 1);
    }

    #[tokio::test]
    async fn packet_then_link_resource_delivers_one_application_message() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp = std::env::temp_dir().join(format!(
            "lxmd-cross-path-dedup-{}-{unique}",
            std::process::id()
        ));
        let (tx, _rx) = mpsc::channel::<TransportMessage>(64);
        initialize_storage_namespace(&temp).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), &temp, tx, None).expect("runner");

        let deliveries = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&deliveries);
        runner.router.register_delivery_callback(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        });

        let message = signed_fixture(
            runner.lxmf_dest_hash,
            [0xCD; 16],
            "one",
            "delivery",
            DeliveryMethod::Direct,
        );
        let packed = message.pack().expect("pack");
        let message_id = LxMessage::unpack(&packed).expect("unpack").message_id();

        let ciphertext = runner
            .identity
            .encrypt(&packed[16..], None)
            .expect("encrypt opportunistic payload");
        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: runner.lxmf_dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut packet = header.pack();
        packet.extend_from_slice(&ciphertext);

        runner.handle_inbound_packet(&packet);
        runner.handle_link_delivered_data(&packed);

        assert_eq!(deliveries.load(Ordering::Relaxed), 1);
        assert!(runner.router.has_message(&message_id));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn direct_reusable_link_state_uses_registered_backchannel() {
        let (tx, _rx) = mpsc::channel(8);
        let mut manager = lxmf_core::link_delivery::LinkDeliveryManager::new(tx, None, None);
        let dest = [0x43; 16];
        let link_id = [0x44; 16];

        manager.register_backchannel(dest, link_id);

        assert_eq!(
            direct_reusable_link_state(Some(&manager), dest),
            DirectReusableLinkState::Active
        );
        assert_eq!(
            direct_reusable_link_state(Some(&manager), [0x45; 16]),
            DirectReusableLinkState::None
        );
    }

    fn pn_test_entry(stamp_byte: u8) -> Vec<u8> {
        let mut entry =
            vec![0x42; LxMessage::MIN_PROPAGATION_ENTRY_SIZE - lxmf_core::constants::STAMP_SIZE];
        entry.extend_from_slice(&[stamp_byte; lxmf_core::constants::STAMP_SIZE]);
        entry
    }

    fn pn_test_wrapper(entries: Vec<Vec<u8>>) -> Vec<u8> {
        let value = rmpv::Value::Array(vec![
            rmpv::Value::from(0.0f64),
            rmpv::Value::Array(entries.into_iter().map(rmpv::Value::Binary).collect()),
        ]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &value).expect("propagation wrapper");
        encoded
    }

    fn pn_test_offer(transient_ids: Vec<[u8; 32]>) -> Vec<u8> {
        let value = rmpv::Value::Array(vec![
            rmpv::Value::Binary(Vec::new()),
            rmpv::Value::Array(
                transient_ids
                    .into_iter()
                    .map(|id| rmpv::Value::Binary(id.to_vec()))
                    .collect(),
            ),
        ]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &value).expect("offer request");
        encoded
    }

    #[test]
    fn pn_offer_handler_uses_one_persistent_admission_owner() {
        let local_identity = [0x11; 16];
        let remote_identity = [0x22; 16];
        let link_id = [0x33; 16];
        let runtime = Arc::new(Mutex::new(PnInboundRuntime::new(
            lxmf_core::propagation_admission::PnInboundAdmissionConfig::default(),
            [],
            1_000,
        )));
        let temporary = tempfile::tempdir().unwrap();
        let node = Arc::new(Mutex::new(
            PropagationNode::with_storage(
                PropagationNodeConfig {
                    peering_cost: 0,
                    ..PropagationNodeConfig::default()
                },
                local_identity,
                temporary.path().join("store"),
            )
            .unwrap(),
        ));
        let offer = pn_test_offer(vec![[0x44; 32]]);

        let response = handle_pn_offer_request(
            &runtime,
            &node,
            local_identity,
            link_id,
            Some(remote_identity),
            &offer,
        )
        .unwrap();
        assert_eq!(
            response,
            PropagationNode::encode_offer_response(&lxmf_core::sync::OfferResponse::WantAll)
        );

        let repeated = handle_pn_offer_request(
            &runtime,
            &node,
            local_identity,
            link_id,
            Some(remote_identity),
            &offer,
        )
        .unwrap();
        assert_eq!(
            repeated,
            PropagationNode::encode_offer_response(&lxmf_core::sync::OfferResponse::ErrorThrottled)
        );
    }

    #[test]
    fn peer_key_worker_binds_remote_identity_before_local_identity() {
        let remote_identity = [0x21; 16];
        let local_identity = [0x43; 16];
        let result = generate_peering_key_job([0x65; 16], 1, remote_identity, local_identity);
        let (key, value) = result.peering_key.expect("cost-one key");
        assert!(value >= 1);

        let mut peering_id = [0u8; 32];
        peering_id[..16].copy_from_slice(&remote_identity);
        peering_id[16..].copy_from_slice(&local_identity);
        assert!(lxmf_core::stamper::validate_peering_key(
            &peering_id,
            &key,
            1
        ));
    }

    #[test]
    fn pn_validation_worker_enforces_client_batch_authorization() {
        let wrapper = pn_test_wrapper(vec![pn_test_entry(0), pn_test_entry(1)]);
        let result = validate_pn_resource_job(
            PnValidationJob::for_test(wrapper.clone(), false),
            wrapper.len(),
            0,
        );
        assert_eq!(result.outcome, PnValidationOutcome::UnauthorizedMultiple);
        assert!(result.entries.is_empty());
        assert_eq!(result.rejected, 2);

        let result = validate_pn_resource_job(
            PnValidationJob::for_test(wrapper.clone(), true),
            wrapper.len(),
            0,
        );
        assert_eq!(result.outcome, PnValidationOutcome::Valid);
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.rejected, 0);
    }

    #[test]
    fn packet_validation_worker_handles_hundred_plus_entries_off_loop() {
        let wrapper = pn_test_wrapper((0..128).map(pn_test_entry).collect());

        let result = validate_pn_packet_job([0x91; 16], wrapper.clone().into(), wrapper.len(), 0);

        assert_eq!(result.entries.len(), 128);
        assert_eq!(result.rejected, 0);
    }

    #[test]
    fn packet_validation_queue_rejects_overload_and_closed_workers() {
        let job = |link_byte| PnPacketValidationJob {
            link_id: [link_byte; 16],
            data: Bytes::from_static(&[0xc1]),
            receipt: None,
            node: Arc::new(Mutex::new(PropagationNode::new(
                Default::default(),
                [0; 16],
            ))),
            max_transfer_bytes: 1,
            min_cost: 0,
            store_delay: Duration::ZERO,
            enqueued_at: Instant::now(),
        };
        let (jobs, jobs_rx) = mpsc::channel(1);
        assert_eq!(enqueue_pn_packet_validation(&jobs, job(1)), Ok(()));
        assert_eq!(
            enqueue_pn_packet_validation(&jobs, job(2)),
            Err(PnPacketValidationEnqueueError::Overloaded)
        );

        drop(jobs_rx);
        assert_eq!(
            enqueue_pn_packet_validation(&jobs, job(3)),
            Err(PnPacketValidationEnqueueError::Closed)
        );
    }

    #[test]
    fn malformed_packet_validation_requests_link_teardown() {
        let result = validate_pn_packet_job([0x92; 16], Bytes::from_static(&[0xc1]), 1, 0);

        assert!(result.entries.is_empty());
        assert!(result.malformed);
        assert_eq!(result.rejected, 0);
    }

    #[test]
    fn pn_validation_worker_preserves_valid_siblings_in_invalid_batch() {
        let mut valid = None;
        let mut invalid = None;
        for stamp_byte in 0u8..=u8::MAX {
            let entry = pn_test_entry(stamp_byte);
            if lxmf_core::stamper::validate_pn_stamp(&entry, 1).is_some() {
                valid.get_or_insert(entry);
            } else {
                invalid.get_or_insert(entry);
            }
            if valid.is_some() && invalid.is_some() {
                break;
            }
        }
        let wrapper = pn_test_wrapper(vec![valid.unwrap(), invalid.unwrap()]);
        let result = validate_pn_resource_job(
            PnValidationJob::for_test(wrapper.clone(), true),
            wrapper.len(),
            1,
        );
        assert_eq!(result.outcome, PnValidationOutcome::InvalidStamp);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.rejected, 1);
    }

    #[test]
    fn pn_validation_worker_fails_malformed_or_oversized_wrapper() {
        let malformed = vec![0xc1];
        let result = validate_pn_resource_job(PnValidationJob::for_test(malformed, true), 100, 0);
        assert_eq!(result.outcome, PnValidationOutcome::Failed);

        let wrapper = pn_test_wrapper(vec![pn_test_entry(0)]);
        let result = validate_pn_resource_job(
            PnValidationJob::for_test(wrapper.clone(), true),
            wrapper.len() - 1,
            0,
        );
        assert_eq!(result.outcome, PnValidationOutcome::Failed);
    }
}
