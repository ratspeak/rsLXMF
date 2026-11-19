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
    DELIVERY_LINK_COST, DeliveryMethod, NODE_ANNOUNCE_DELAY, PROPAGATION_LINK_COST,
};
use lxmf_core::delivery_ratchet::{
    DELIVERY_APP_NAME, DeliveryAnnounceKind, DeliveryRatchetError, DeliveryRatchetState,
};
use lxmf_core::inbound_resource::{
    InboundResourceCancelRequest, InboundResourceConclusion, InboundResourceEvent,
    InboundResourceKey,
};
use lxmf_core::link_delivery::{
    BackchannelSendCommand, BackchannelSendError, BackchannelSendReceipt, DeliveryResult,
};
use lxmf_core::message::{LxMessage, LxMessageDraft, MessageError};
use lxmf_core::peer::{LxmPeer, OutboundOfferPolicy};
use lxmf_core::propagation_node::{
    PropagationNode, PropagationNodeConfig, PropagationStoreWritePlan,
};
use lxmf_core::propagation_send::{
    AdvertisedNodePolicy, EncryptionBinding, MissingPropagationInput, PropagationEnvelope,
    propagation_readiness,
};
use lxmf_core::router::{
    AutopeerCandidate, DirectReusableLinkState, LinkDeliveryPlan, LxmRouter, MediumSnapshot,
    OutboundAction, OutboundInputs, RouteInfo,
};
use lxmf_tools::daemon::{
    DaemonConfig, PythonLxmdConfig, create_router_with_transport, persist_inbound_and_execute,
};
use lxmf_tools::lxmd_cli::{
    Args, default_config_file_text, example_config, load_hash_list, normalize_hash_hex,
    parse_destination_hash, parse_send_fields_json,
};
use lxmf_tools::lxmd_control::{
    CONTROL_APP_NAME, ControlCommandKind, ControlResponse, decode_control_response,
    encode_control_success, encode_peer_error, encode_router_control_stats,
    exit_for_control_response, format_remote_status, print_control_link_error, query_control,
    resolve_remote_identity_hash,
};
use lxmf_tools::lxmd_runtime::{
    LxmdPaths, delivery_announce_app_data, preflight_control_command,
    propagation_announce_app_data, resolve_config_dirs,
};
use rns_identity::announce::AnnounceStampExt;
use rns_identity::destination::{DefaultAppData, Destination};
use rns_identity::identity::Identity;
use rns_identity::persistence::{
    durable_create_dir_all, durable_reconcile, durable_write, validate_durable_storage_directory,
};
use rns_runtime::destination_stamper::{Admission, DestinationStamps, StampOutcome};
use rns_runtime::lifecycle::ShutdownSignal;
use rns_runtime::link_manager::{
    LinkManagerAccountingEvent, LinkManagerCommand, LinkResourceConclusion, LinkResourceDirection,
    LinkResourceEvent,
};
use rns_runtime::reticulum::{AnnounceSubscription, AnnounceSubscriptionError, ReticulumHandle};
use rns_tools::format::pretty_hex_rep;
use rns_transport::link_messages::{AnnounceRequest, DestinationEvent};
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

/// A command the stopped runner cannot act on gets no response, so the client
/// times out instead of reading an unhandled code as success.
fn queue_control_command(
    command_tx: &mpsc::UnboundedSender<ControlCommand>,
    command: ControlCommand,
) -> Option<Vec<u8>> {
    if command_tx.send(command).is_ok() {
        Some(encode_control_success())
    } else {
        tracing::warn!(
            ?command,
            "control command not queued: daemon runner stopped"
        );
        None
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

#[derive(Debug)]
struct ValidatedPnEntry {
    lxmf_data: Vec<u8>,
    stamp_value: f64,
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
    accounted: Vec<([u8; 32], u64)>,
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
    min_cost: f64,
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

#[derive(Debug, Clone, Copy)]
enum PropagationStoreWriteOrigin {
    Peer([u8; 16]),
    Client,
}

#[derive(Debug)]
struct PropagationStoreCommitResult {
    origin: PropagationStoreWriteOrigin,
    /// Every stamp-validated entry and its message size, duplicates included.
    accounted: Vec<([u8; 32], u64)>,
    /// Entries newly stored by this write.
    committed: Vec<([u8; 32], u64)>,
}

fn spawn_propagation_store_writes(
    node: Arc<Mutex<PropagationNode>>,
    plans: Vec<(PropagationStoreWritePlan, u64)>,
    accounted: Vec<([u8; 32], u64)>,
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
            .send(PropagationStoreCommitResult {
                origin,
                accounted,
                committed,
            })
            .is_err()
        {
            tracing::debug!(operation, "propagation store commit receiver closed");
        }
    }))
}

/// Python counts every validated entry before deduplication
/// (`propagation_resource_concluded`, `propagation_packet`) and distributes
/// only newly stored ones (`lxmf_propagation`).
fn apply_propagation_store_commit(
    router: &mut LxmRouter,
    node: Option<&Arc<Mutex<PropagationNode>>>,
    distribution: &mut Vec<([u8; 32], Option<[u8; 16]>)>,
    result: PropagationStoreCommitResult,
) {
    let from_peer = match result.origin {
        PropagationStoreWriteOrigin::Peer(peer_hash) if router.peers.contains_key(&peer_hash) => {
            Some(peer_hash)
        }
        _ => None,
    };
    // LXMRouter keeps one processed-ID store; stored entries are claimed there at once.
    let now = now_f64();
    let mut claims = Vec::with_capacity(result.committed.len());
    for (transient_id, _) in &result.committed {
        router.propagation_store.claim_processed(*transient_id, now);
        claims.push((*transient_id, now));
    }
    router.record_processed_claims(&claims);
    distribution.extend(
        result
            .committed
            .iter()
            .map(|(transient_id, _)| (*transient_id, from_peer)),
    );
    if result.accounted.is_empty() {
        return;
    }
    let committed_count = result.accounted.len() as u64;
    let committed_bytes = result
        .accounted
        .iter()
        .map(|(_, bytes)| *bytes)
        .sum::<u64>();

    match result.origin {
        PropagationStoreWriteOrigin::Peer(peer_hash) => {
            if let Some(peer) = router.peers.get_mut(&peer_hash) {
                peer.incoming = peer.incoming.saturating_add(committed_count);
                peer.rx_bytes = peer.rx_bytes.saturating_add(committed_bytes);
                peer.heard();
                for (transient_id, _) in result.accounted {
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
    peering_cost: f64,
    peering_key: Option<([u8; 32], f64)>,
}

fn accepts_delivery_resource(data_size: usize, limit_kb: f64) -> bool {
    data_size as f64 <= limit_kb * lxmf_core::constants::BYTES_PER_KILOBYTE as f64
}

fn configured_kilobytes_to_bytes(kilobytes: f64) -> usize {
    (kilobytes.max(0.0) * lxmf_core::constants::BYTES_PER_KILOBYTE as f64) as usize
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
    stamp_cost: Option<f64>,
    stamp_flexibility: Option<f64>,
    peering_cost: f64,
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
    peering_cost: f64,
    peer_identity_hash: [u8; 16],
    local_identity_hash: [u8; 16],
) -> PeeringKeyWorkerResult {
    let mut peer = LxmPeer::new(peer_hash);
    peer.peering_cost = peering_cost;
    let _ = peer.generate_peering_key(
        &peer_identity_hash,
        &local_identity_hash,
        &lxmf_core::stamper::StampControl::default(),
    );
    PeeringKeyWorkerResult {
        peer_hash,
        peering_cost,
        peering_key: peer.peering_key,
    }
}

fn validate_pn_resource_job(
    job: PnValidationJob,
    max_transfer_bytes: usize,
    min_cost: f64,
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
    min_cost: f64,
) -> PnPacketValidationWorkerResult {
    let mut result = PnPacketValidationWorkerResult {
        link_id,
        receipt: None,
        payload_owner: data.clone(),
        malformed: false,
        stored: false,
        accounted: Vec::new(),
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
        accounted: Vec::new(),
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
    // Python stores every valid entry, then rejects the packet if any failed.
    let mut validated = Vec::with_capacity(entries.len());
    for entry in entries {
        match ValidatedOpaquePropagationBlob::validate(entry, job.min_cost) {
            Some(blob) => validated.push(blob),
            None => result.rejected += 1,
        }
    }
    #[cfg(test)]
    if let Some(timing) = result.timing.as_mut() {
        timing.validation_ms = validation_started.elapsed().as_secs_f64() * 1000.;
    }
    #[cfg(test)]
    let store_started = Instant::now();
    result.stored = true;
    result.accounted = validated
        .iter()
        .map(|blob| {
            let size = blob.len().saturating_sub(32) as u64;
            (blob.transient_id(), size)
        })
        .collect();
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
            // Python still proves a packet whose messages were filtered as duplicates.
            Ok(PropagationAdmission::AlreadyProcessed) => {}
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

/// Python `lxmd.program_setup`/`_remote_init`: the daemon starts from its own
/// config's `loglevel` and logs to `<configdir>/logfile` in service mode;
/// control commands never read the config and start at Notice on stdout.
fn setup_logging(
    args: &Args,
    configured: Option<i64>,
    service_log_dir: Option<&Path>,
    rns_config_dir: &Path,
) {
    let level = rns_tools::Utility::Lxmd.loglevel(configured, args.verbose, args.quiet, false);
    let timestamps = rns_tools::config_log_timestamps(rns_config_dir);
    match service_log_dir {
        Some(dir) => {
            let path = dir.join("logfile");
            rns_tools::init_tracing(level, timestamps, false, move || {
                PythonLogFile(path.clone())
            });
        }
        None => rns_tools::init_tracing(level, timestamps, true, std::io::stdout),
    }
}

/// Python `RNS.log` with `LOG_FILE`: append each line, rotate to
/// `logfile.1` past `LOG_MAXSIZE`, and fall back to the console on error.
struct PythonLogFile(PathBuf);

impl std::io::Write for PythonLogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        const LOG_MAXSIZE: u64 = 5 * 1024 * 1024;
        let written = (|| {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.0)?;
            file.write_all(buf)?;
            if file.metadata()?.len() > LOG_MAXSIZE {
                let previous = self.0.with_file_name("logfile.1");
                let _ = std::fs::remove_file(&previous);
                std::fs::rename(&self.0, previous)?;
            }
            std::io::Result::Ok(())
        })();
        match written {
            Ok(()) => Ok(buf.len()),
            Err(_) => std::io::stdout().write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Python `program_setup`: write the default config on first run, and
/// `RNS.panic()` when the file cannot be parsed. Returns whether it was created.
fn load_or_create_daemon_config(config_dir: &Path) -> (rns_runtime::config::Config, bool) {
    let config_path = config_dir.join("config");
    let created = !config_path.is_file();
    if created {
        let written = std::fs::create_dir_all(config_dir)
            .and_then(|()| std::fs::write(&config_path, default_config_file_text()));
        if let Err(error) = written {
            println!(
                "Could not create the default configuration file at {}: {error}",
                config_path.display()
            );
            std::process::exit(1);
        }
    }
    match rns_runtime::config::Config::from_file(&config_path) {
        Ok(config) => (config, created),
        Err(_) => {
            println!(
                "Could not parse the configuration at {}",
                config_path.display()
            );
            println!("Check your configuration file for errors!");
            std::process::exit(255);
        }
    }
}

/// Python adds the timeout to `time.time()`; an infinite or NaN timeout never expires.
fn control_timeout(args: &Args) -> f64 {
    match args.timeout {
        Some(timeout) if timeout != 0.0 => timeout,
        _ if args.status || args.peers => 5.0,
        _ => 10.0,
    }
}

const ADMISSION_BODIES_DIR: &str = "download-admission-bodies";

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

/// `lxmd.py` control helpers request a path to the control destination and
/// wait for it inside the command timeout before opening the link.
async fn wait_for_control_path(
    transport_tx: &mpsc::Sender<TransportMessage>,
    target_identity_hash: [u8; 16],
    deadline: tokio::time::Instant,
) -> bool {
    let dest =
        Destination::hash_from_name_and_identity(CONTROL_APP_NAME, Some(&target_identity_hash));
    let has_path = || async {
        let (response_tx, response_rx) = oneshot::channel();
        transport_tx
            .send(TransportMessage::Rpc {
                query: TransportQuery::HasPath { dest },
                response_tx,
            })
            .await
            .is_ok()
            && matches!(
                response_rx.await,
                Ok(TransportQueryResponse::BoolResult(true))
            )
    };
    if has_path().await {
        return true;
    }
    let _ = transport_tx
        .send(TransportMessage::RequestPath {
            destination_hash: dest,
        })
        .await;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if has_path().await {
            return true;
        }
    }
    false
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
    router: &mut LxmRouter,
    medium: &MediumSnapshot,
    node: [u8; 16],
    last_propagation_check: &mut f64,
    now: f64,
) -> bool {
    *last_propagation_check = now;
    if !router.request_path(node, medium, now) {
        return true;
    }
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

fn link_snapshot_state(
    snapshot: &lxmf_core::link_delivery::DirectLinkSnapshot,
) -> DirectReusableLinkState {
    if snapshot.link_closed() {
        // The failed session reports each carried message as a delivery result.
        return DirectReusableLinkState::Pending;
    }
    if snapshot.link_active() {
        DirectReusableLinkState::Active
    } else {
        DirectReusableLinkState::Pending
    }
}

/// Python `lxmf_delivery()` receive state: the delivery method, and Curve25519
/// transport encryption for SINGLE and LINK destinations (LXMRouter.py).
fn mark_received(msg: &mut LxMessage, method: DeliveryMethod) {
    let destination_type = match method {
        DeliveryMethod::Direct => rns_wire::flags::DestinationType::Link,
        _ => rns_wire::flags::DestinationType::Single,
    };
    msg.record_delivery(Some(destination_type), None, Some(method), None);
}

/// Write the stored propagated message as Python's `write_to_directory()` file,
/// `<messages_dir>/<hex message hash>` holding `packed_container()`.
fn write_propagated_container(
    body: &std::path::Path,
    messages_dir: &std::path::Path,
) -> std::io::Result<PathBuf> {
    let wire = std::fs::read(body)?;
    let mut msg = LxMessage::unpack(&wire).map_err(std::io::Error::other)?;
    mark_received(&mut msg, DeliveryMethod::Propagated);
    let container = msg.pack_container().map_err(std::io::Error::other)?;
    let path = messages_dir.join(hex::encode(msg.message_id()));
    lxmf_core::persist::write_file_atomic(&path, &container)?;
    Ok(path)
}

fn direct_reusable_link_state(
    link_delivery: Option<&lxmf_core::link_delivery::LinkDeliveryManager>,
    dest_hash: [u8; 16],
) -> DirectReusableLinkState {
    let Some(link_delivery) = link_delivery else {
        return DirectReusableLinkState::None;
    };
    if let Some(snapshot) = link_delivery.direct_link_snapshot(dest_hash) {
        return link_snapshot_state(&snapshot);
    }
    if link_delivery.backchannel_link_snapshot(dest_hash).is_some() {
        DirectReusableLinkState::Active
    } else {
        DirectReusableLinkState::None
    }
}

/// Python `Transport.medium_path_timeout()` for a known bitrate (Transport.py).
fn medium_path_timeout(lowest_bitrate: u64) -> f64 {
    let bits = (rns_wire::constants::MTU * 8) as f64;
    2.0 * (bits / lowest_bitrate.max(rns_runtime::constants::MINIMUM_BITRATE) as f64)
        + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
}

/// Drop the current path, then request a new one 0.5 s later, as Python's
/// opportunistic rediscovery does (LXMRouter.py).
fn queue_path_request_after_drop(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination: [u8; 16],
) {
    let (response_tx, _response_rx) = oneshot::channel();
    if let Err(error) = transport_tx.try_send(TransportMessage::Rpc {
        query: TransportQuery::DropPath { dest: destination },
        response_tx,
    }) {
        tracing::warn!(dest = %hex::encode(destination), %error, "failed to queue path drop");
    }
    let transport_tx = transport_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        queue_path_request(
            &transport_tx,
            destination,
            false,
            "opportunistic path rediscovery",
        );
    });
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

/// `LXMRouter.get_propagation_node_app_data`, the propagation destination's default app data.
fn propagation_node_app_data(config: &DaemonConfig) -> Vec<u8> {
    let mut pn_data = lxmf_core::handlers::PropagationNodeAnnounceData::new(
        config.propagation_enabled && !config.from_static_only,
        config.propagation_limit_kb,
        config.sync_limit_kb,
        config.propagation_stamp_cost,
        config.propagation_stamp_flex,
        config.peering_cost,
    );
    if let Some(ref name) = config.node_name {
        pn_data.set_name(name);
    }
    propagation_announce_app_data(&pn_data)
}

/// Announce requests the daemon has not served yet. A burst of path requests
/// past this is dropped; the requester asks again.
const DELIVERY_ANNOUNCE_BACKLOG: usize = 64;

/// Delivery destination events reach the LinkManager; announce requests go to
/// the daemon, which owns the delivery ratchets, app data and stamp.
async fn forward_delivery_events(
    mut events: mpsc::Receiver<DestinationEvent>,
    link_tx: mpsc::Sender<DestinationEvent>,
    announce_tx: mpsc::Sender<AnnounceRequest>,
) {
    while let Some(event) = events.recv().await {
        match event {
            DestinationEvent::AnnounceRequested(request) => {
                let _ = announce_tx.try_send(request);
            }
            event => {
                if link_tx.send(event).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Soft cap on the identity keys held for this session. Reticulum keeps the
/// durable copy (`Identity.recall`); a key dropped over the cap is recalled
/// again or re-learned from the next announce.
const KNOWN_IDENTITIES_SOFT_CAP: usize = 10_000;

/// Full path-table resync cadence for `route_hops`. Announce events keep the
/// map fresh in between; this only re-baselines and prunes expired paths.
const ROUTE_HOPS_REFRESH_SECS: f64 = 300.0;

/// Python lxmd `DEFFERED_JOBS_DELAY` and `JOBS_INTERVAL`, in seconds.
const DEFERRED_JOBS_DELAY: u64 = 10;
/// Python `LXMRouter.JOB_STAMPCOST_INTERVAL`, in router job passes.
const JOB_STAMPCOST_INTERVAL: u64 = 120;
/// `RNS.Transport.await_path` timeouts Python `enable_propagation()` gives a
/// loaded peer: 2.5 s, plus 5 s first for a static peer never heard.
const PEER_LOAD_PATH_WAIT: f64 = 2.5;
const PEER_LOAD_STATIC_PATH_WAIT: f64 = 7.5;

#[derive(Debug)]
struct PeerPathCheck {
    response: Option<oneshot::Receiver<TransportQueryResponse>>,
    grace_until: Option<f64>,
}

/// What `propagation_resource_concluded` reads before autopeering with an
/// unpeered sender: `Identity.recall_app_data` and `Transport.hops_to`.
#[derive(Debug)]
struct SyncAutopeerRecall {
    recalled: oneshot::Receiver<TransportQueryResponse>,
    hops: oneshot::Receiver<TransportQueryResponse>,
}
const JOBS_INTERVAL: u64 = 5;

/// Resolve a destination hash to its identity hash via the learned identity
/// keys — the lxmd equivalent of `RNS.Identity.recall` (LXMessage.py).
/// Identity hash = truncated hash of the 64-byte announce public key.
fn recall_identity_hash(
    known_identities: &HashMap<String, [u8; 64]>,
    dest_hash: &[u8; 16],
) -> Option<[u8; 16]> {
    known_identities
        .get(&hex::encode(dest_hash))
        .map(|pub_key| rns_crypto::sha::truncated_hash(pub_key))
}

/// Bound the daemon's working copy of recalled identity keys. Reticulum keeps
/// the known destinations; a dropped key is recalled again when it is needed.
/// The aspects whose identities the daemon keeps for the session.
const LXMF_ASPECTS: [&str; 2] = [DELIVERY_APP_NAME, "lxmf.propagation"];

/// Whether a listed announce is an LXMF destination. An entry whose facts are
/// unknown (a row upstream wrote) carries a placeholder name hash, so its
/// aspect is read from its destination hash, which is derived from the name
/// hash and the identity: a message from it must still verify after a restart.
fn is_lxmf_destination(
    announce: &rns_transport::messages::AnnounceRpcEntry,
    public_key: &[u8; 64],
) -> bool {
    if announce.facts_known {
        return LXMF_ASPECTS
            .iter()
            .any(|aspect| rns_identity::name_hash::name_hash(aspect) == announce.name_hash);
    }
    let identity = rns_crypto::sha::truncated_hash(public_key);
    LXMF_ASPECTS.iter().any(|aspect| {
        Destination::hash_from_name_and_identity(aspect, Some(&identity)) == announce.dest_hash
    })
}

fn prune_known_identities(known_identities: &mut HashMap<String, [u8; 64]>) -> usize {
    let excess = known_identities
        .len()
        .saturating_sub(KNOWN_IDENTITIES_SOFT_CAP);
    let dropped: Vec<String> = known_identities.keys().take(excess).cloned().collect();
    for key in &dropped {
        known_identities.remove(key);
    }
    dropped.len()
}

/// Atomically reserve capacity for receipt tracking and packet dispatch.
/// Registering the receipt first prevents a fast proof from racing receipt
/// creation; reserving both slots prevents a packet from leaving untracked.
fn dispatch_opportunistic_packet(
    transport_tx: &mpsc::Sender<TransportMessage>,
    raw: Vec<u8>,
    destination_hash: [u8; 16],
    destination_public_key: [u8; 64],
    msg_hash: [u8; 32],
    timeout: Duration,
) -> Result<(), String> {
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
        timeout: Some(timeout),
    });
    outbound_permit.send(TransportMessage::Outbound(
        rns_transport::messages::OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash,
        },
    ));
    Ok(())
}

/// `LXMessage.unpack_from_bytes` signature flags (LXMessage.py).
fn classify_signature(
    msg: &LxMessage,
    public_key: Option<&[u8; 64]>,
) -> Option<lxmf_core::constants::UnverifiedReason> {
    use lxmf_core::constants::UnverifiedReason;
    match public_key {
        None => Some(UnverifiedReason::SourceUnknown),
        Some(key) if msg.verify(key).is_ok() => None,
        Some(_) => Some(UnverifiedReason::SignatureInvalid),
    }
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
    binding: EncryptionBinding,
    cost: f64,
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
    tickets: &[[u8; 16]],
    cost: f64,
) -> Result<(), SuppressionReason> {
    if cost > 0.0 {
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
    state_dir: PathBuf,
    router: lxmf_core::router::RouterStateSnapshot,
    policies: HashMap<[u8; 16], AdvertisedNodePolicy>,
}
impl DaemonCheckpoint {
    fn persist(self) -> std::io::Result<()> {
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
    /// Propagated messages waiting for the node's stamp cost, with their failure deadline.
    node_cost_deadlines: HashMap<[u8; 32], f64>,
    propagation_preparation_tasks: Vec<tokio::task::JoinHandle<()>>,
    ratchets_dir: PathBuf,
    delivery_ratchets: DeliveryRatchetState,
    /// Identity keys Reticulum has reported this session; it keeps the known
    /// destinations, as `RNS.Identity.recall` answers for Python's LXMF.
    known_identities: HashMap<String, [u8; 64]>,
    /// What Reticulum answered this tick for each pending destination's
    /// ratchet (`RNS.Identity.get_ratchet`, read by `Destination.encrypt`).
    /// Reticulum alone keeps received ratchets; no entry means no answer yet.
    outbound_ratchets: HashMap<[u8; 16], Option<[u8; 32]>>,
    /// Identities asked of Transport's validated announce cache.
    identity_recalls: HashMap<[u8; 16], oneshot::Receiver<TransportQueryResponse>>,
    /// Outbound destinations whose persisted announce app data was recalled once.
    compression_recalled: HashSet<[u8; 16]>,
    /// Reaches the shared instance when attached to one.
    control_plane: Option<ReticulumHandle>,
    retain_task: Option<tokio::task::JoinHandle<()>>,
    route_hops: HashMap<[u8; 16], u8>,
    /// Transport blackhole table snapshot, refreshed per tick. Used to drop
    /// inbound LXMs from blackholed identities (LXMRouter.py).
    blackholed_identities: HashSet<[u8; 16]>,
    link_delivery: Option<lxmf_core::link_delivery::LinkDeliveryManager>,
    link_command_tx: mpsc::Sender<rns_runtime::link_manager::LinkManagerCommand>,
    link_identified_rx: mpsc::Receiver<([u8; 16], [u8; 16])>,
    link_packet_proof_rx: mpsc::Receiver<rns_runtime::link_manager::LinkPacketProof>,
    link_resource_proof_rx: mpsc::Receiver<rns_runtime::link_manager::LinkResourceProof>,
    destination_delivery_proof_rx:
        mpsc::UnboundedReceiver<rns_runtime::link_manager::DestinationDeliveryProof>,
    /// Reticulum's medium view for outbound planning, refreshed per tick.
    medium: MediumSnapshot,
    /// `Transport.next_hop_interface_hw_mtu` per routed outbound target.
    next_hop_hardware_mtus: HashMap<[u8; 16], u32>,
    backchannel_command_rx: Option<mpsc::Receiver<BackchannelSendCommand>>,
    backchannel_abandon_tx: mpsc::Sender<BackchannelSendReceipt>,
    backchannel_abandon_rx: mpsc::Receiver<BackchannelSendReceipt>,
    pending_backchannel_abandon: Option<BackchannelSendReceipt>,
    backchannel_bridge_slots: Arc<tokio::sync::Semaphore>,
    pending_backchannel_resource_cancellations:
        VecDeque<lxmf_core::link_delivery::BackchannelResourceCancelRequest>,
    last_delivery_failure: Option<String>,
    /// Outbound peer syncs in progress, one per peer, as Python runs one
    /// `LXMPeer` link per peer.
    peer_syncs: HashMap<[u8; 16], lxmf_core::propagation_sync::PropagationSyncTask>,
    /// Peers whose sync waits on a path check (Python `LXMPeer.sync()` path gate).
    peer_path_checks: HashMap<[u8; 16], PeerPathCheck>,
    /// Loaded peers whose identity must resolve within a path wait (seconds),
    /// and the deadline once the wait has started.
    peer_identity_deadlines: HashMap<[u8; 16], (f64, Option<f64>)>,
    /// Unpeered remotes whose announce data and path hops are asked of
    /// Reticulum for autopeering.
    sync_autopeer_recalls: HashMap<[u8; 16], SyncAutopeerRecall>,
    peer_state_dirty: bool,
    /// Python `peer_distribution_queue`: stored IDs and the peer they came from.
    peer_distribution_queue: Vec<([u8; 32], Option<[u8; 16]>)>,
    peer_jobs_count: u64,
    last_peer_jobs: f64,
    propagation_client: Option<lxmf_core::propagation_client::PropagationClient>,
    propagation_node: Option<Arc<Mutex<PropagationNode>>>,
    propagation_admission: Option<Arc<Mutex<PnInboundRuntime>>>,
    prop_link_command_tx: Option<mpsc::Sender<rns_runtime::link_manager::LinkManagerCommand>>,
    endpoint_dispatch: Option<rns_transport::link_endpoint_dispatch::LinkEndpointDispatchHandle>,
    transport_tx: mpsc::Sender<TransportMessage>,
    pending_runtime_transport: VecDeque<TransportMessage>,
    delivery_stamps: DestinationStamps<AnnounceRequest>,
    delivery_announce_rx: mpsc::Receiver<AnnounceRequest>,
    /// Path responses refused because wall time has not advanced past the last announce.
    coalesced_path_responses: VecDeque<AnnounceRequest>,
    control_link_command_tx: Option<mpsc::Sender<rns_runtime::link_manager::LinkManagerCommand>>,
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
    /// `wants_download_on_path_available_timeout`: start the download as soon
    /// as the node becomes known, until this time.
    download_on_path_until: Option<f64>,
    last_crypto_save: f64,
    checkpoint_task: Option<DaemonCheckpointTask>,
    last_cull: f64,
    last_identity_prune: f64,
    last_route_refresh: f64,
    control_state: Arc<Mutex<ControlSnapshot>>,
    control_command_rx: mpsc::UnboundedReceiver<ControlCommand>,
}

impl LxmdRunner {
    /// LXMF keeps one processed-ID store for local delivery and propagation intake.
    fn merge_processed_ids(&mut self) {
        let Some(node) = self.propagation_node.as_ref() else {
            return;
        };
        let Ok(mut node) = node.lock() else {
            return;
        };
        node.merge_processed_ids(self.router.propagation_store.locally_processed_ids());
        let claimed_by_node: Vec<_> = node
            .processed_ids()
            .iter()
            .filter(|(id, _)| !self.router.propagation_store.is_locally_processed(id))
            .map(|(id, seen)| (*id, *seen))
            .collect();
        drop(node);
        for (id, seen) in &claimed_by_node {
            self.router.propagation_store.claim_processed(*id, *seen);
        }
        self.router.record_processed_claims(&claimed_by_node);
    }

    /// A transient ID claimed by local delivery is a duplicate for propagation intake.
    fn share_processed_claim(&self, transient_id: [u8; 32]) {
        if let Some(node) = self.propagation_node.as_ref()
            && let Ok(mut node) = node.lock()
            && let Some(seen) = self
                .router
                .propagation_store
                .locally_processed_ids()
                .get(&transient_id)
        {
            node.merge_processed_ids([(&transient_id, seen)]);
        }
    }

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
        self.learn_validated_identities().await;
        Ok(())
    }

    /// Learn the LXMF identities Transport validated before these
    /// subscriptions existed; later ones arrive as announce events. Python's
    /// LXMF recalls them from `RNS.Identity` (Transport.py).
    async fn learn_validated_identities(&mut self) {
        let (response_tx, response_rx) = oneshot::channel();
        let query = TransportMessage::Rpc {
            query: TransportQuery::GetRecentAnnounces,
            response_tx,
        };
        if self.transport_tx.send(query).await.is_err() {
            return;
        }
        let Ok(Ok(TransportQueryResponse::Announces(announces))) =
            tokio::time::timeout(Duration::from_secs(5), response_rx).await
        else {
            tracing::warn!("Transport did not list its validated announces");
            return;
        };
        for announce in announces {
            if let Some(public_key) = announce.public_key
                && is_lxmf_destination(&announce, &public_key)
            {
                self.learn_identity(&announce.dest_hash, public_key);
            }
        }
    }

    /// Ask Transport for an identity this daemon lacks, as Python's LXMF
    /// calls `RNS.Identity.recall` wherever it needs one.
    fn recall_identity(&mut self, destination_hash: [u8; 16]) {
        if self
            .known_identities
            .contains_key(&hex::encode(destination_hash))
            || self.identity_recalls.contains_key(&destination_hash)
        {
            return;
        }
        let (response_tx, response_rx) = oneshot::channel();
        if self
            .transport_tx
            .try_send(TransportMessage::Rpc {
                query: TransportQuery::RecallDestination {
                    dest: destination_hash,
                },
                response_tx,
            })
            .is_ok()
        {
            self.identity_recalls.insert(destination_hash, response_rx);
        }
    }

    fn drain_identity_recalls(&mut self) {
        let mut answered = Vec::new();
        for (destination_hash, response) in &mut self.identity_recalls {
            match response.try_recv() {
                Ok(TransportQueryResponse::RecalledDestination(recalled)) => {
                    answered.push((*destination_hash, recalled));
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                _ => answered.push((*destination_hash, None)),
            }
        }
        for (destination_hash, recalled) in answered {
            self.identity_recalls.remove(&destination_hash);
            if let Some(recalled) = recalled {
                self.router
                    .update_compression_support(destination_hash, recalled.app_data.as_deref());
                self.learn_identity(&destination_hash, recalled.public_key);
            }
        }
    }

    /// Retain delivered destinations in Reticulum, through the shared
    /// instance when attached to one, as Python's router does
    /// (LXMRouter.py, Reticulum.py).
    fn forward_destination_retains(&mut self) {
        let Some(control_plane) = self.control_plane.clone() else {
            return;
        };
        if self
            .retain_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return;
        }
        let retains = self.router.take_destination_retains();
        if retains.is_empty() {
            return;
        }
        self.retain_task = Some(tokio::spawn(async move {
            for dest in retains {
                if control_plane
                    .query_control(TransportQuery::RetainDestination { dest })
                    .await
                    .is_none()
                {
                    tracing::debug!(
                        dest = %hex::encode(dest),
                        "Reticulum did not retain a delivered destination"
                    );
                }
            }
        }));
    }

    /// Keep an identity key Reticulum reported. An announced ratchet is not
    /// kept here: Reticulum remembers it (`Identity._remember_ratchet`).
    fn learn_identity(&mut self, destination_hash: &[u8; 16], public_key: [u8; 64]) {
        let dest_hex = hex::encode(destination_hash);
        if self.known_identities.get(&dest_hex) != Some(&public_key) {
            self.known_identities.insert(dest_hex.clone(), public_key);
            tracing::debug!(dest = %dest_hex, "learned identity key from announce");
        }
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
            rns_transport::notice!("Loading identity from {}", identity_path.display());
            let id = Identity::from_file(&identity_path)?;
            rns_transport::notice!("Loaded Primary Identity {}", pretty_hex_rep(&id.hash));
            id
        } else {
            rns_transport::notice!("No Primary Identity file found, creating new...");
            let id = Identity::new();
            id.to_file(&paths.identity_path)?;
            rns_transport::notice!("Created new Primary Identity {}", pretty_hex_rep(&id.hash));
            id
        };

        let identity_hash = hex::encode(identity.hash);

        let lxmf_dest_hash =
            Destination::hash_from_name_and_identity(DELIVERY_APP_NAME, Some(&identity.hash));
        let propagation_dest_hash =
            Destination::hash_from_name_and_identity("lxmf.propagation", Some(&identity.hash));
        let control_dest_hash =
            Destination::hash_from_name_and_identity(CONTROL_APP_NAME, Some(&identity.hash));

        let wall_now = now_f64() as u64;
        let delivery_ratchets = DeliveryRatchetState::load_or_initialize(
            &identity,
            lxmf_dest_hash,
            paths.ratchet_ring_path.clone(),
            paths.ratchet_control_path.clone(),
            wall_now,
        )?;
        let mut delivery_ratchets = delivery_ratchets;
        rns_runtime::destination_stamper::load_stored_stamp(
            delivery_ratchets.destination_mut(),
            &identity,
        );

        tracing::info!(
            ratchet_keys = delivery_ratchets.ring().len(),
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

        let (delivery_link_tx, delivery_link_rx) = mpsc::channel(256);
        let (delivery_announce_tx, delivery_announce_rx) = mpsc::channel(DELIVERY_ANNOUNCE_BACKLOG);
        tokio::spawn(forward_delivery_events(
            delivery_rx,
            delivery_link_tx,
            delivery_announce_tx,
        ));
        let signing_key = identity.get_signing_key();
        let mut link_mgr = rns_runtime::link_manager::LinkManager::with_destination(
            transport_tx.clone(),
            delivery_link_rx,
            &identity,
            DELIVERY_APP_NAME,
            signing_key,
        );
        if let Some(destination) = link_mgr.destination_mut() {
            destination.set_link_cost(DELIVERY_LINK_COST);
        }
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
        let mut control_link_command_tx = None;

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
            let pn_config =
                PropagationNodeConfig {
                    max_storage: config.message_storage_limit.unwrap_or(
                        configured_kilobytes_to_bytes(config.propagation_limit_kb.as_f64()),
                    ),
                    max_message_size: configured_kilobytes_to_bytes(
                        config.propagation_limit_kb.as_f64(),
                    ),
                    max_offer_size: configured_kilobytes_to_bytes(config.sync_limit_kb.as_f64()),
                    max_message_age: lxmf_core::constants::MESSAGE_EXPIRY,
                    min_stamp_cost: config.min_accepted_stamp_cost(),
                    peering_cost: config.peering_cost,
                };
            let prop_storage_path = paths.propagation_store_dir.clone();
            let pn = Arc::new(Mutex::new(PropagationNode::with_storage(
                pn_config,
                propagation_dest_hash,
                prop_storage_path,
            )?));
            if let Ok(node) = pn.lock() {
                // Python rebuilds every stored peer, without the max_peers cap.
                for mut peer in node.load_peers() {
                    peer.is_static = static_peer_hashes.contains(&peer.destination_hash);
                    router.peers.insert(peer.destination_hash, peer);
                }
            }

            let pn_admission = Arc::new(Mutex::new(PnInboundRuntime::new(
                config.to_inbound_admission_config(),
                static_peer_hashes,
                configured_kilobytes_to_bytes(config.sync_limit_kb.as_f64()),
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
            // LXMRouter.clean_links: idle propagation links are torn down.
            prop_link_mgr.set_data_inactivity_timeout(Some(std::time::Duration::from_secs(
                lxmf_core::constants::P_LINK_MAX_INACTIVITY,
            )));

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
                            advertisement.flags.app_flag,
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
            let response_limit =
                configured_kilobytes_to_bytes(config.propagation_limit_kb.as_f64())
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
                            if let Some(remote) = remote.filter(|_| allowed) {
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
                            } else if remote.is_none() {
                                (
                                    Some(encode_peer_error(
                                        lxmf_core::constants::PeerError::NoIdentity,
                                    )),
                                    0,
                                )
                            } else {
                                (
                                    Some(encode_peer_error(
                                        lxmf_core::constants::PeerError::NoAccess,
                                    )),
                                    0,
                                )
                            }
                        };
                        let (bytes, served) = reply;
                        let outcome =
                            bytes.map_or(RequestOutcome::Drop, RequestOutcome::ReplyValue);
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

            if let Some(destination) = prop_link_mgr.destination_mut() {
                destination.set_link_cost(PROPAGATION_LINK_COST);
                let app_data_config = config.clone();
                destination.set_default_app_data(DefaultAppData::Dynamic(Box::new(move || {
                    Some(propagation_node_app_data(&app_data_config))
                })));
            }

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

                // RNS ALLOW_LIST handlers deny unidentified and unlisted peers without a response.
                let remote_hash = remote_identity_hash?;
                if !snapshot.allowed_control.contains(&remote_hash) {
                    return None;
                }

                if path_hash == stats_path_hash {
                    tracing::info!("control: handling stats request");
                    // compile_stats returns None off a propagation node: no response.
                    snapshot.stats_response
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
                    queue_control_command(&command_tx_for_handler, ControlCommand::Sync(peer_hash))
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
                    queue_control_command(
                        &command_tx_for_handler,
                        ControlCommand::Unpeer(peer_hash),
                    )
                } else {
                    tracing::debug!(
                        path = hex::encode(path_hash),
                        "control: unknown request path"
                    );
                    None
                }
            });

            let (control_tx, control_rx) =
                mpsc::channel::<rns_runtime::link_manager::LinkManagerCommand>(8);
            control_link_command_tx = Some(control_tx);
            tokio::spawn(async move {
                control_link_mgr.run_with_commands(control_rx).await;
            });

            tracing::info!("propagation sync server ready for offer/get requests");
            Some(pn)
        } else {
            None
        };

        let messages_dir = paths.messages_dir.clone();
        std::fs::create_dir_all(&messages_dir)?;

        // Upstream's messages directory holds only write_to_directory containers
        // (lxmd.py); the admission store keeps its raw bodies privately.
        let admission_store = match FileAdmissionStore::open_moving_bodies_from(
            &paths.router_state_dir,
            &paths.router_state_dir.join(ADMISSION_BODIES_DIR),
            &messages_dir,
        ) {
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
            node_cost_deadlines: HashMap::new(),
            propagation_preparation_tasks: Vec::new(),
            ratchets_dir: paths.ratchets_dir,
            delivery_ratchets,
            known_identities: HashMap::new(),
            outbound_ratchets: HashMap::new(),
            identity_recalls: HashMap::new(),
            compression_recalled: HashSet::new(),
            control_plane: None,
            retain_task: None,
            route_hops: HashMap::new(),
            blackholed_identities: HashSet::new(),
            link_delivery: None,
            link_command_tx,
            link_identified_rx,
            link_packet_proof_rx,
            link_resource_proof_rx,
            destination_delivery_proof_rx,
            medium: MediumSnapshot::default(),
            next_hop_hardware_mtus: HashMap::new(),
            backchannel_command_rx: None,
            backchannel_abandon_tx,
            backchannel_abandon_rx,
            pending_backchannel_abandon: None,
            backchannel_bridge_slots: Arc::new(tokio::sync::Semaphore::new(256)),
            pending_backchannel_resource_cancellations: VecDeque::new(),
            last_delivery_failure: None,
            peer_syncs: HashMap::new(),
            peer_path_checks: HashMap::new(),
            peer_identity_deadlines: HashMap::new(),
            sync_autopeer_recalls: HashMap::new(),
            peer_state_dirty: false,
            peer_distribution_queue: Vec::new(),
            peer_jobs_count: 0,
            last_peer_jobs: 0.0,
            propagation_client: None,
            propagation_node: None,
            propagation_admission,
            prop_link_command_tx,
            endpoint_dispatch,
            transport_tx: transport_tx.clone(),
            pending_runtime_transport: VecDeque::new(),
            delivery_stamps: DestinationStamps::new(),
            delivery_announce_rx,
            coalesced_path_responses: VecDeque::new(),
            control_link_command_tx,
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
            inbound_raw_rx,
            announce_subscriptions: Vec::new(),
            last_peer_announce: 0.0,
            last_node_announce: 0.0,
            node_announces_due: VecDeque::new(),
            startup_node_announce_pending: false,
            last_propagation_check: 0.0,
            download_on_path_until: None,
            last_crypto_save: now,
            checkpoint_task: None,
            last_cull: now,
            last_identity_prune: now,
            last_route_refresh: 0.0,
            control_state,
            control_command_rx,
        };

        if runner.config.propagation_enabled {
            if runner.identity.get_signing_key().is_none() {
                tracing::error!(
                    "local identity has no signing key; outbound peer sync cannot identify"
                );
            }
            // Python enable_propagation(): a loaded peer whose identity cannot be
            // recalled after a short path wait is dropped.
            for (hash, peer) in &runner.router.peers {
                if !runner.known_identities.contains_key(&hex::encode(hash)) {
                    let wait = if peer.is_static && peer.last_heard == 0.0 {
                        PEER_LOAD_STATIC_PATH_WAIT
                    } else {
                        PEER_LOAD_PATH_WAIT
                    };
                    runner.peer_identity_deadlines.insert(*hash, (wait, None));
                }
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
            client.set_link_request_stamper(rns_runtime::link_stamp::blocking_stamper(
                transport_tx.clone(),
            ));
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
                    // Python enable_propagation() asks for a never-heard static peer's path.
                    if peer.last_heard == 0.0 && self.config.propagation_enabled {
                        queue_path_request(&self.transport_tx, hash, false, "static peer");
                    }
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
                |peer| {
                    self.route_hops
                        .get(peer)
                        .copied()
                        .unwrap_or(rns_transport::constants::PATHFINDER_M)
                },
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

    fn create_announce_packet(
        &mut self,
        kind: DeliveryAnnounceKind<'_>,
        stamp_ext: Option<&AnnounceStampExt>,
    ) -> Result<Vec<u8>, DeliveryRatchetError> {
        // Path responses carry the default app data, which LXMRouter.py sets only with a display name.
        let app_data = match (kind, self.config.display_name.as_deref()) {
            (DeliveryAnnounceKind::PathResponse { .. }, None) => Vec::new(),
            (_, name) => delivery_announce_app_data(name, self.config.stamp_cost),
        };
        let now = now_f64();
        self.delivery_ratchets.create_announce(
            &self.identity,
            &app_data,
            now as u64,
            now,
            kind,
            stamp_ext,
        )
    }

    /// `Destination.announce` for the delivery destination: parked while its
    /// stamp is generated when the policy stamps destinations.
    fn request_delivery_announce(&mut self, request: AnnounceRequest) -> Result<(), String> {
        let path_response = request.path_response;
        match self.delivery_stamps.admit(
            self.delivery_ratchets.destination(),
            &self.identity,
            path_response,
            request,
        ) {
            Admission::Ready(request, ext) => self.emit_delivery_announce(request, ext.as_ref()),
            Admission::Queued => Ok(()),
            Admission::Dropped(_) => Err("stamp queue full, announce dropped".to_string()),
        }
    }

    fn on_delivery_stamp(&mut self, outcome: StampOutcome) {
        let ready = self.delivery_stamps.complete(
            self.delivery_ratchets.destination_mut(),
            &self.identity,
            outcome,
        );
        for (request, ext) in ready {
            if let Err(error) = self.emit_delivery_announce(request, ext.as_ref()) {
                tracing::warn!("failed to send delivery announce after stamp generation: {error}");
            }
        }
    }

    fn emit_delivery_announce(
        &mut self,
        request: AnnounceRequest,
        stamp_ext: Option<&AnnounceStampExt>,
    ) -> Result<(), String> {
        let kind = if request.path_response {
            DeliveryAnnounceKind::PathResponse {
                tag: request.tag.as_deref(),
            }
        } else {
            DeliveryAnnounceKind::Broadcast
        };
        let raw = match self.create_announce_packet(kind, stamp_ext) {
            Ok(raw) => raw,
            Err(DeliveryRatchetError::Coalesced) if request.path_response => {
                if self.coalesced_path_responses.len() < 32 {
                    self.coalesced_path_responses.push_back(request);
                }
                return Ok(());
            }
            Err(error) => return Err(error.to_string()),
        };
        let outbound = rns_transport::messages::OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: self.lxmf_dest_hash,
        };
        let message = match request.attached_interface {
            Some(interface_id) => TransportMessage::OutboundAttached {
                request: outbound,
                interface_id,
            },
            None => TransportMessage::Outbound(outbound),
        };
        if self.queue_runtime_transport(message, "delivery announce") {
            Ok(())
        } else {
            Err("transport channel closed".to_string())
        }
    }

    #[cfg(test)]
    async fn send_propagation_announce(&mut self) -> Result<(), String> {
        let tx = self
            .prop_link_command_tx
            .as_ref()
            .ok_or("propagation node is not running")?;
        tx.send(LinkManagerCommand::Announce)
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

    /// Python lxmd `deferred_start_jobs()`: optional start-up announces, then
    /// both periodic announce clocks start.
    fn run_deferred_start_jobs(&mut self, announce_delivery: bool) {
        let now = now_f64();
        if announce_delivery {
            self.stage_delivery_announce("start-up delivery announce");
        }
        if self.config.propagation_enabled && self.config.node_announce_at_start {
            self.schedule_node_announce(now);
        }
        self.last_peer_announce = now;
        self.last_node_announce = now;
    }

    /// Python lxmd `jobs()`, run every `JOBS_INTERVAL` after the deferred start.
    fn announce_jobs(&mut self, now: f64) {
        if let Some(interval) = self.config.announce_interval
            && now > self.last_peer_announce + interval as f64
            && self.stage_delivery_announce("periodic delivery announce")
        {
            self.last_peer_announce = now;
        }
        if self.config.propagation_enabled
            && let Some(interval) = self.config.node_announce_interval
            && now > self.last_node_announce + interval as f64
        {
            self.last_node_announce = now;
            self.schedule_node_announce(now);
        }
        self.stage_due_node_announce(now);
    }

    fn stage_delivery_announce(&mut self, context: &'static str) -> bool {
        match self.request_delivery_announce(AnnounceRequest::normal(DELIVERY_APP_NAME.to_string()))
        {
            Ok(()) => {
                tracing::debug!("{context} staged");
                true
            }
            Err(error) => {
                tracing::warn!("{context} failed: {error}");
                false
            }
        }
    }

    /// Time until the earliest scheduled node announce that is not yet due;
    /// an overdue one is retried by the processing tick.
    fn next_node_announce_in(&self) -> Option<Duration> {
        let wait = self.node_announces_due.front()? - now_f64();
        (wait > 0.0).then(|| Duration::from_secs_f64(wait))
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
        let announce = |tx: &Option<mpsc::Sender<LinkManagerCommand>>| {
            tx.as_ref()
                .is_some_and(|tx| tx.try_send(LinkManagerCommand::Announce).is_ok())
        };
        let node_staged = announce(&self.prop_link_command_tx);
        let control_staged =
            !self.should_announce_control() || announce(&self.control_link_command_tx);
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
                    tracing::info!(peer = %hex::encode(peer_hash), "control: queued peer sync");
                    self.attempt_peer_sync(peer_hash, now_f64());
                }
                ControlCommand::Unpeer(peer_hash) => {
                    self.cancel_peer_sync(&peer_hash);
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
                    && value >= peer.peering_cost
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
            // is ignored; a later sync attempt dispatches a new job.
        }
    }

    /// The peer half of Python `LXMRouter.jobs()`, counted in 4 s passes.
    fn run_peer_jobs(&mut self, now: f64) {
        use lxmf_core::constants::{
            JOB_PEERINGEST_INTERVAL, JOB_PEERSYNC_INTERVAL, PROCESSING_INTERVAL,
        };
        if now - self.last_peer_jobs < PROCESSING_INTERVAL as f64 * 0.9 {
            return;
        }
        self.last_peer_jobs = now;
        self.peer_jobs_count += 1;
        let propagation = self.propagation_node.is_some();
        if propagation && self.peer_jobs_count.is_multiple_of(JOB_PEERINGEST_INTERVAL) {
            self.flush_peer_distribution_queue();
        }
        if propagation && self.peer_jobs_count.is_multiple_of(JOB_PEERSYNC_INTERVAL) {
            self.run_peer_sync_pass(now);
        }
        if self.peer_jobs_count.is_multiple_of(JOB_STAMPCOST_INTERVAL) {
            self.router.cull_stamp_costs();
        }
    }

    fn flush_peer_distribution_queue(&mut self) {
        if self.peer_distribution_queue.is_empty() || self.router.peers.is_empty() {
            return;
        }
        let entries = std::mem::take(&mut self.peer_distribution_queue);
        self.router.flush_peer_distribution(&entries);
        self.peer_state_dirty = true;
    }

    /// Python `LXMRouter.sync_peers()`, run every `JOB_PEERSYNC_INTERVAL` jobs.
    fn run_peer_sync_pass(&mut self, now: f64) {
        let Some(offer_generation) = self.propagation_node.as_ref().and_then(|node| {
            node.lock().ok().map(|node| {
                // Python derives each peer's unhandled set from the live store.
                for peer in self.router.peers.values_mut() {
                    peer.unhandled_messages.retain(|id| node.contains(id));
                }
                node.offer_generation()
            })
        }) else {
            return;
        };
        let pass = self.router.sync_peers(now, offer_generation);
        if let Some(peer_hash) = pass.selected {
            self.attempt_peer_sync(peer_hash, now);
        }
        for peer_hash in pass.culled {
            tracing::warn!(
                peer = %hex::encode(peer_hash),
                "removing peer due to excessive unreachability"
            );
            self.forget_peer(&peer_hash);
        }
        if std::mem::take(&mut self.peer_state_dirty) {
            self.save_all_peers();
        }
    }

    fn save_all_peers(&self) {
        let Some(node) = self.propagation_node.as_ref() else {
            return;
        };
        let Ok(node) = node.lock() else {
            return;
        };
        for peer in self.router.peers.values() {
            if let Err(error) = node.save_peer(peer) {
                tracing::warn!(
                    peer = %hex::encode(peer.destination_hash),
                    "failed to persist peer state: {error}"
                );
            }
        }
    }

    /// Cancel sync work for a peer the router no longer holds and delete its
    /// persisted state.
    fn forget_peer(&mut self, peer_hash: &[u8; 16]) {
        self.cancel_peer_sync(peer_hash);
        if let Some(node) = self.propagation_node.as_ref()
            && let Ok(mut node) = node.lock()
            && let Err(error) = node.delete_peer(peer_hash)
        {
            tracing::warn!(
                peer = %hex::encode(peer_hash),
                "failed to remove persisted propagation peer: {error}"
            );
        }
    }

    fn cancel_peer_sync(&mut self, peer_hash: &[u8; 16]) -> bool {
        self.peer_path_checks.remove(peer_hash);
        match self.peer_syncs.remove(peer_hash) {
            Some(mut sync) => {
                sync.cancel_peer_sync(peer_hash);
                true
            }
            None => false,
        }
    }

    /// Python `LXMPeer.sync()` up to its path check: postpone during backoff,
    /// until stamp costs are known and until a peering key exists.
    fn attempt_peer_sync(&mut self, peer_hash: [u8; 16], now: f64) {
        if self.peer_syncs.contains_key(&peer_hash)
            || self.peer_path_checks.contains_key(&peer_hash)
        {
            return;
        }
        let Some(peer) = self.router.peers.get_mut(&peer_hash) else {
            return;
        };
        if peer.state != lxmf_core::constants::PeerState::Idle {
            return;
        }
        self.peer_state_dirty = true;
        if !peer.sync_attempt(now) {
            tracing::debug!(
                peer = %hex::encode(peer_hash),
                "postponing peer sync due to previous failures"
            );
            return;
        }
        if !peer.stamp_costs_known() {
            tracing::debug!(
                peer = %hex::encode(peer_hash),
                "postponing peer sync since its required stamp costs are not yet known"
            );
            return;
        }
        if peer.peering_cost != 0.0 && !peer.peering_key_ready() {
            tracing::debug!(
                peer = %hex::encode(peer_hash),
                "postponing peer sync since a peering key has not been generated yet"
            );
            self.spawn_peering_key_job(peer_hash);
            return;
        }
        let (response_tx, response_rx) = oneshot::channel();
        if self
            .transport_tx
            .try_send(TransportMessage::Rpc {
                query: TransportQuery::HasPath { dest: peer_hash },
                response_tx,
            })
            .is_ok()
        {
            self.peer_path_checks.insert(
                peer_hash,
                PeerPathCheck {
                    response: Some(response_rx),
                    grace_until: None,
                },
            );
        }
    }

    fn spawn_peering_key_job(&mut self, peer_hash: [u8; 16]) {
        if self.peering_key_jobs.contains(&peer_hash) {
            return;
        }
        let Some(peer_identity_hash) = recall_identity_hash(&self.known_identities, &peer_hash)
        else {
            self.recall_identity(peer_hash);
            return;
        };
        let Some(peer) = self.router.peers.get(&peer_hash) else {
            return;
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

    /// Without a path, request one and wait `PATH_REQUEST_GRACE` before
    /// checking again; a path still missing defers the sync (`LXMPeer.sync()`).
    fn drive_peer_path_checks(&mut self, now: f64) {
        let mut ready = Vec::new();
        let mut failed = Vec::new();
        for (peer_hash, check) in &mut self.peer_path_checks {
            if let Some(response) = check.response.as_mut() {
                let has_path = match response.try_recv() {
                    Err(oneshot::error::TryRecvError::Empty) => continue,
                    Ok(TransportQueryResponse::BoolResult(has_path)) => has_path,
                    _ => false,
                };
                check.response = None;
                if has_path {
                    ready.push(*peer_hash);
                } else if check.grace_until.is_some() {
                    failed.push(*peer_hash);
                } else {
                    tracing::debug!(
                        peer = %hex::encode(peer_hash),
                        "no path to peer exists, requesting"
                    );
                    // LXMPeer.sync asks through the debounced LXMRouter.request_path.
                    if self.router.request_path(*peer_hash, &self.medium, now) {
                        queue_path_request(&self.transport_tx, *peer_hash, false, "peer sync");
                    }
                    check.grace_until = Some(now + lxmf_core::constants::PATH_REQUEST_GRACE);
                }
            } else if check.grace_until.is_some_and(|until| now >= until) {
                let (response_tx, response_rx) = oneshot::channel();
                if self
                    .transport_tx
                    .try_send(TransportMessage::Rpc {
                        query: TransportQuery::HasPath { dest: *peer_hash },
                        response_tx,
                    })
                    .is_ok()
                {
                    check.response = Some(response_rx);
                } else {
                    failed.push(*peer_hash);
                }
            }
        }
        for peer_hash in failed {
            self.peer_path_checks.remove(&peer_hash);
            if let Some(peer) = self.router.peers.get_mut(&peer_hash) {
                peer.path_request_failed(now);
                self.peer_state_dirty = true;
                tracing::debug!(
                    peer = %hex::encode(peer_hash),
                    "path request was not answered, retrying peer sync later"
                );
            }
        }
        for peer_hash in ready {
            self.peer_path_checks.remove(&peer_hash);
            self.start_peer_sync(peer_hash);
        }
    }

    /// The link half of Python `LXMPeer.sync()`, once a path exists.
    fn start_peer_sync(&mut self, peer_hash: [u8; 16]) {
        let Some(node) = self.propagation_node.clone() else {
            return;
        };
        if recall_identity_hash(&self.known_identities, &peer_hash).is_none() {
            self.recall_identity(peer_hash);
            tracing::error!(
                peer = %hex::encode(peer_hash),
                "could not request sync to peer since its identity could not be recalled"
            );
            return;
        }
        let Some(peer) = self.router.peers.get_mut(&peer_hash) else {
            return;
        };
        if peer.unhandled_message_count() == 0 {
            tracing::debug!(
                peer = %hex::encode(peer_hash),
                "sync requested, but no unhandled messages exist for peer"
            );
            return;
        }
        let mut sync = lxmf_core::propagation_sync::PropagationSyncTask::with_shared_node(
            self.transport_tx.clone(),
            node,
        );
        sync.set_link_request_stamper(rns_runtime::link_stamp::blocking_stamper(
            self.transport_tx.clone(),
        ));
        if let Some(signing_key) = self.identity.get_signing_key() {
            sync.set_identity(self.identity.get_public_key(), signing_key);
        }
        if sync.request_sync_now_with_policy(OutboundOfferPolicy::from(&*peer)) {
            peer.begin_sync();
            self.peer_syncs.insert(peer_hash, sync);
        }
    }

    /// Python `propagation_resource_concluded()` autopeers an identified,
    /// unpeered remote from its recalled propagation node announce.
    fn recall_sync_autopeer(&mut self, peer_hash: [u8; 16]) {
        if !self.config.autopeer
            || self.router.peers.contains_key(&peer_hash)
            || self.sync_autopeer_recalls.contains_key(&peer_hash)
        {
            return;
        }
        let (recalled_tx, recalled) = oneshot::channel();
        let (hops_tx, hops) = oneshot::channel();
        let asked = self
            .transport_tx
            .try_send(TransportMessage::Rpc {
                query: TransportQuery::RecallDestination { dest: peer_hash },
                response_tx: recalled_tx,
            })
            .is_ok()
            && self
                .transport_tx
                .try_send(TransportMessage::Rpc {
                    query: TransportQuery::HopsTo { dest: peer_hash },
                    response_tx: hops_tx,
                })
                .is_ok();
        if asked {
            self.sync_autopeer_recalls
                .insert(peer_hash, SyncAutopeerRecall { recalled, hops });
        }
    }

    fn drain_sync_autopeer_recalls(&mut self) {
        let mut answered = Vec::new();
        for (peer_hash, recall) in &mut self.sync_autopeer_recalls {
            // Reticulum answers in the order asked: the hop count comes last.
            let hops = match recall.hops.try_recv() {
                Err(oneshot::error::TryRecvError::Empty) => continue,
                Ok(TransportQueryResponse::IntResult(hops)) => u8::try_from(hops).ok(),
                _ => None,
            };
            let recalled = match recall.recalled.try_recv() {
                Ok(TransportQueryResponse::RecalledDestination(recalled)) => recalled,
                _ => None,
            };
            answered.push((*peer_hash, recalled, hops));
        }
        for (peer_hash, recalled, hops) in answered {
            self.sync_autopeer_recalls.remove(&peer_hash);
            let Some(recalled) = recalled else {
                continue;
            };
            // `Transport.hops_to`: the path's hops, never the remembered
            // announce's, which may be older than the path or unknown.
            let hops = hops.unwrap_or(rns_transport::constants::PATHFINDER_M);
            let Some(pn) = recalled
                .app_data
                .as_deref()
                .and_then(lxmf_core::handlers::parse_pn_announce_data)
            else {
                continue;
            };
            if !pn.node_state
                || !self.config.autopeer
                || self.router.peers.contains_key(&peer_hash)
                || usize::from(hops) > self.router.config.ext.autopeer_maxdepth
            {
                continue;
            }
            self.learn_identity(&peer_hash, recalled.public_key);
            tracing::debug!(
                peer = %hex::encode(peer_hash),
                "auto-peering with propagation node discovered via incoming sync"
            );
            if self.router.autopeer(AutopeerCandidate {
                destination_hash: peer_hash,
                timebase: pn.timebase as f64,
                transfer_limit: Some(pn.transfer_limit.as_f64()),
                sync_limit: Some(pn.sync_limit.as_f64()),
                stamp_cost: Some(pn.stamp_cost),
                stamp_flexibility: Some(pn.stamp_flex),
                peering_cost: Some(pn.peering_cost),
                hops: Some(hops),
                metadata: Some(pn.metadata.clone()),
            }) {
                self.peer_state_dirty = true;
            }
        }
    }

    /// Drop loaded peers whose identity did not resolve in time
    /// (Python `enable_propagation()`); static peers start over.
    fn drive_peer_identity_resolution(&mut self, now: f64) {
        if self.peer_identity_deadlines.is_empty() {
            return;
        }
        let pending = self.peer_identity_deadlines.clone();
        for (peer_hash, (wait, deadline)) in pending {
            if self.known_identities.contains_key(&hex::encode(peer_hash))
                || !self.router.peers.contains_key(&peer_hash)
            {
                self.peer_identity_deadlines.remove(&peer_hash);
            } else if deadline.is_none() {
                self.peer_identity_deadlines
                    .insert(peer_hash, (wait, Some(now + wait)));
                queue_path_request(&self.transport_tx, peer_hash, false, "loaded peer");
                self.recall_identity(peer_hash);
            } else if deadline.is_some_and(|deadline| now >= deadline) {
                self.peer_identity_deadlines.remove(&peer_hash);
                tracing::debug!(
                    peer = %hex::encode(peer_hash),
                    "peer could not be loaded, because its identity could not be recalled"
                );
                self.router.peers.remove(&peer_hash);
                self.forget_peer(&peer_hash);
                if self.router.static_peers.contains(&peer_hash) {
                    let mut peer = LxmPeer::new(peer_hash);
                    peer.is_static = true;
                    self.router.peers.insert(peer_hash, peer);
                    queue_path_request(&self.transport_tx, peer_hash, false, "static peer");
                }
            } else if !self.identity_recalls.contains_key(&peer_hash) {
                self.recall_identity(peer_hash);
            }
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
                    let propagated =
                        self.router.pending_outbound.iter().any(|m| {
                            m.message_id() == hash && m.method == DeliveryMethod::Propagated
                        });
                    if propagated {
                        self.router.mark_outbound_propagated(&hash);
                    } else {
                        self.router.mark_outbound_delivered(&hash);
                    }
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
                reason,
                link_activated,
                ..
            } => {
                tracing::warn!(
                    dest = %hex::encode(dest_hash),
                    reason = %reason,
                    link_activated,
                    "link delivery failed"
                );
                let Some(hash) = msg_hash else {
                    return;
                };
                // A failed transfer returns the message to OUTBOUND and the Link
                // is gone, as Python's CLOSED link branch handles it.
                let actions = self.router.outbound_link_closed(
                    &hash,
                    link_activated,
                    &self.medium,
                    now_f64(),
                );
                self.execute_outbound_actions(actions);
                if !self
                    .router
                    .pending_outbound
                    .iter()
                    .any(|pending| pending.message_id() == hash)
                {
                    self.propagation_envelopes.remove(&hash);
                    self.pending_propagation_envelopes.remove(&hash);
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
                fresh.insert(entry.hash, entry.hops);
            }
        }
        self.route_hops = fresh;
        self.last_route_refresh = now;
    }

    /// Snapshot the transport blackhole table. Ungated: the table is tiny and
    /// the per-tick roundtrip keeps drops close to Python's live
    /// `Reticulum.is_blackholed` query (LXMessage.py). Fail-open: on
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
    /// check (LXMessage.py only runs with a recalled source identity).
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
        let now = now_f64();
        self.drive_peer_path_checks(now);
        let mut peers_to_persist = HashSet::new();
        let mut finished = Vec::new();
        let mut resync = Vec::new();
        let mut unpeered = Vec::new();
        for (peer_hash, sync) in &mut self.peer_syncs {
            sync.drain_events(&self.known_identities);
            sync.tick();
            let handled = sync.take_handled_updates();
            let dropped = sync.take_dropped_unhandled_updates();
            let terminal = sync.take_terminal_peer_result();
            let Some(peer) = self.router.peers.get_mut(peer_hash) else {
                finished.push(*peer_hash);
                continue;
            };
            if !handled.is_empty() || !dropped.is_empty() {
                for transient_id in &handled {
                    peer.add_handled_message(transient_id);
                }
                for transient_id in &dropped {
                    peer.remove_unhandled_message(transient_id);
                }
                peers_to_persist.insert(*peer_hash);
            }
            let Some(result) = terminal else {
                continue;
            };
            finished.push(*peer_hash);
            if let Some(rate) = result.link_establishment_rate {
                // Python link_established() and the LINK_READY branch of sync().
                peer.link_establishment_rate = rate;
                peer.heard();
                peer.next_sync_attempt = 0.0;
            }
            match result.state {
                lxmf_core::propagation_sync::PeerSyncTerminalState::Complete => {
                    peer.offered = peer.offered.saturating_add(result.offered);
                    peer.outgoing = peer.outgoing.saturating_add(result.outgoing);
                    peer.tx_bytes = peer.tx_bytes.saturating_add(result.tx_bytes);
                    if let Some(rate) = result.sync_transfer_rate {
                        peer.sync_transfer_rate = rate;
                    }
                    if result.outgoing > 0 {
                        peer.heard();
                        if peer.sync_strategy == lxmf_core::constants::SyncStrategy::Persistent
                            && peer.unhandled_message_count() > 0
                        {
                            resync.push(result.peer_hash);
                        }
                    }
                    peer.sync_complete();
                    if result.generation_exhausted
                        && let Some(generation) = result.offer_generation
                    {
                        peer.mark_offer_generation_processed(generation);
                    }
                }
                lxmf_core::propagation_sync::PeerSyncTerminalState::NoPath => {
                    // LXMPeer.sync: no link was made; begin_sync already applied the backoff step.
                    peer.state = lxmf_core::constants::PeerState::Idle;
                    peer.alive = false;
                }
                lxmf_core::propagation_sync::PeerSyncTerminalState::Throttled => {
                    // LXMPeer.offer_response postpones by the class constant, not the configured throttle.
                    peer.state = lxmf_core::constants::PeerState::Idle;
                    peer.currently_transferring_messages = None;
                    peer.next_sync_attempt = now + lxmf_core::constants::PN_STAMP_THROTTLE as f64;
                }
                lxmf_core::propagation_sync::PeerSyncTerminalState::NoAccess => {
                    unpeered.push(result.peer_hash);
                }
                lxmf_core::propagation_sync::PeerSyncTerminalState::Failed => {
                    peer.sync_failed();
                }
            }
            peers_to_persist.insert(result.peer_hash);
        }
        for peer_hash in finished {
            self.peer_syncs.remove(&peer_hash);
        }
        for peer_hash in unpeered {
            // LXMRouter.unpeer drops the live peering only.
            tracing::info!(peer = %hex::encode(peer_hash), "remote denied access, broke peering");
            self.router.remove_peer(&peer_hash);
            peers_to_persist.remove(&peer_hash);
            if let Some(ref node) = self.propagation_node
                && let Ok(mut node) = node.lock()
                && let Err(error) = node.delete_peer(&peer_hash)
            {
                tracing::warn!(
                    peer = %hex::encode(peer_hash),
                    "failed to remove persisted propagation peer: {error}"
                );
            }
        }
        // Python resource_concluded(): a persistent peer with messages left syncs again.
        for peer_hash in resync {
            self.attempt_peer_sync(peer_hash, now);
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
            if !self.router.mark_outbound_delivered(&message_hash) {
                tracing::debug!(msg_id = %proof.msg_id, "delivery proof does not match a queued opportunistic message");
                continue;
            }
            tracing::info!(
                msg_id = %proof.msg_id,
                rtt_ms = proof.rtt.map(|rtt| rtt.as_secs_f64() * 1000.0),
                "opportunistic message delivery confirmed"
            );
        }
    }

    /// Refresh Reticulum's medium view for the destinations outbound planning
    /// needs: lowest online bitrate, medium path timeout, routes and first-hop
    /// timeouts (`LXMRouter.medium_path_timeout`, `destination_round_trip`).
    async fn refresh_outbound_medium(&mut self) {
        let mut targets: HashSet<[u8; 16]> = self
            .router
            .pending_outbound
            .iter()
            .map(|message| message.destination_hash())
            // A message leaves the stamp queue and is sent within one tick.
            .chain(
                self.router
                    .pending_deferred_stamps
                    .values()
                    .map(|message| message.destination_hash()),
            )
            .collect();
        if let Some(node) = self.router.outbound_propagation_node {
            targets.insert(node);
        }
        let query = |query| {
            let (response_tx, response_rx) = oneshot::channel();
            let sent = self
                .transport_tx
                .try_send(TransportMessage::Rpc { query, response_tx })
                .is_ok();
            async move {
                if !sent {
                    return None;
                }
                tokio::time::timeout(Duration::from_millis(100), response_rx)
                    .await
                    .ok()?
                    .ok()
            }
        };
        if let Some(TransportQueryResponse::InterfaceStats(interfaces)) =
            query(TransportQuery::GetInterfaceStats).await
            && let Some(lowest) = interfaces
                .iter()
                .filter(|interface| interface.online && interface.bitrate > 0)
                .map(|interface| interface.bitrate)
                .min()
        {
            // Transport keeps the last lowest bitrate when none qualifies (Transport.py).
            self.medium.lowest_interface_bitrate = Some(lowest);
        }
        self.medium.medium_path_timeout = self
            .medium
            .lowest_interface_bitrate
            .map(medium_path_timeout)
            .unwrap_or(0.0);
        let mut routes = HashMap::new();
        let mut hardware_mtus = HashMap::new();
        if !targets.is_empty()
            && let Some(TransportQueryResponse::PathTable(entries)) =
                query(TransportQuery::GetPathTable).await
        {
            let now = now_f64();
            for entry in entries {
                if entry.expires <= now || !targets.contains(&entry.hash) {
                    continue;
                }
                let first_hop_timeout =
                    match query(TransportQuery::FirstHopTimeout { dest: entry.hash }).await {
                        Some(TransportQueryResponse::FloatResult(Some(seconds))) => seconds,
                        _ => rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT,
                    };
                if let Some(TransportQueryResponse::IntResult(mtu)) =
                    query(TransportQuery::GetNextHopHardwareMtu { dest: entry.hash }).await
                    && let Ok(mtu) = u32::try_from(mtu)
                {
                    hardware_mtus.insert(entry.hash, mtu);
                }
                routes.insert(
                    entry.hash,
                    RouteInfo {
                        hops: entry.hops,
                        first_hop_timeout,
                    },
                );
            }
        }
        self.medium.routes = routes;
        self.next_hop_hardware_mtus = hardware_mtus;

        // `Destination.encrypt` reads `Identity.get_ratchet` at each send; the
        // daemon asks Reticulum for every destination this tick may encrypt for.
        let mut ratchets = HashMap::new();
        let mut recalled_keys = Vec::new();
        for destination in targets {
            if let Some(TransportQueryResponse::RecalledDestination(recalled)) =
                query(TransportQuery::RecallDestination { dest: destination }).await
            {
                ratchets.insert(destination, recalled.as_ref().and_then(|r| r.ratchet));
                if let Some(recalled) = recalled {
                    recalled_keys.push((destination, recalled.public_key));
                }
            }
        }
        self.outbound_ratchets = ratchets;
        for (destination, public_key) in recalled_keys {
            self.learn_identity(&destination, public_key);
        }
    }

    fn outbound_inputs(&self) -> OutboundInputs {
        let mut inputs = OutboundInputs {
            medium: self.medium.clone(),
            ..OutboundInputs::default()
        };
        for message in &self.router.pending_outbound {
            let destination = message.destination_hash();
            if self
                .link_delivery
                .as_ref()
                .is_some_and(|ld| ld.message_delivery_snapshot(message.message_id()).is_some())
            {
                inputs.link_owned.insert(message.message_id());
            }
            if self
                .known_identities
                .contains_key(&hex::encode(destination))
            {
                inputs.identities.insert(destination);
            }
            if message.method == DeliveryMethod::Direct {
                inputs.direct_links.insert(
                    destination,
                    direct_reusable_link_state(self.link_delivery.as_ref(), destination),
                );
            }
        }
        if let Some(node) = self.router.outbound_propagation_node {
            if self.known_identities.contains_key(&hex::encode(node)) {
                inputs.identities.insert(node);
            }
            inputs.propagation_link = self
                .link_delivery
                .as_ref()
                .and_then(|ld| ld.propagation_link_snapshot(node))
                .map(|snapshot| link_snapshot_state(&snapshot))
                .unwrap_or(DirectReusableLinkState::None);
        }
        inputs
    }

    /// `LXMessage.determine_compression_support` reads the recalled app data, which
    /// survives restarts in the transport's announce store.
    fn recall_outbound_app_data(&mut self) {
        let destinations: Vec<[u8; 16]> = self
            .router
            .pending_outbound
            .iter()
            .map(|message| message.destination_hash())
            .filter(|destination| !self.compression_recalled.contains(destination))
            .collect();
        for destination in destinations {
            if self.identity_recalls.contains_key(&destination) {
                continue;
            }
            let (response_tx, response_rx) = oneshot::channel();
            if self
                .transport_tx
                .try_send(TransportMessage::Rpc {
                    query: TransportQuery::RecallDestination { dest: destination },
                    response_tx,
                })
                .is_ok()
            {
                self.compression_recalled.insert(destination);
                self.identity_recalls.insert(destination, response_rx);
            }
        }
    }

    fn run_outbound(&mut self) {
        self.recall_outbound_app_data();
        let propagation_unready = self.prepare_propagation_envelopes();
        let mut inputs = self.outbound_inputs();
        inputs.propagation_unready = propagation_unready;
        let actions = self.router.process_outbound_with_inputs(&inputs, now_f64());
        if !actions.is_empty() {
            self.execute_outbound_actions(actions);
            self.drain_core_backchannel_send_commands();
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
        for request in std::mem::take(&mut self.coalesced_path_responses) {
            if let Err(error) = self.request_delivery_announce(request) {
                tracing::debug!("delivery path response not sent: {error}");
            }
        }
        self.flush_runtime_transport();
        let now = now_f64();

        self.drain_destination_delivery_proofs();
        self.forward_destination_retains();

        self.drain_control_commands();
        self.drain_identity_recalls();
        self.drain_peering_key_results();
        self.drain_sync_autopeer_recalls();
        self.drive_peer_identity_resolution(now);
        self.run_peer_jobs(now);
        self.drain_backchannel_events();

        self.router.process_deferred_stamps();
        self.run_outbound();
        // Advance the router jobloop counters (transient-cache cleaning, store
        // cull, peer rotation at Python cadences). `process_outbound_with_direct`
        // does not drive these.
        let peers_before = self.router.peers.keys().copied().collect::<Vec<_>>();
        self.router.run_jobs_tick();
        for peer_hash in peers_before {
            if !self.router.peers.contains_key(&peer_hash) {
                self.forget_peer(&peer_hash);
            }
        }

        if let Some(ref mut ld) = self.link_delivery {
            ld.drain_events(&self.known_identities);
            let results = ld.tick();
            for result in results {
                self.handle_link_delivery_result(result);
            }
        }
        self.drain_core_backchannel_send_commands();
        if self.router.take_outbound_kick() {
            self.run_outbound();
        }
        if self.router.take_propagation_announce() {
            self.schedule_node_announce(now_f64());
        }

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
        let mut unknown_propagation_node = None;
        if let Some(ref mut client) = self.propagation_client {
            // One outbound node serves uploads and downloads, as in LXMRouter.
            if let Some(node) = self.router.outbound_propagation_node {
                client.set_propagation_node(node);
            }
            client.replace_durable_haves(locally_delivered_ids);
            client.set_retain_synced_on_node(retain_synced_on_node);
            client.drain_events(&self.known_identities);
            client.tick();

            downloaded_messages = client.take_downloaded_messages();
            let _ = client.take_suppression_updates();

            // Auto-download every 90s
            let path_awaited = self
                .download_on_path_until
                .is_some_and(|until| now < until && propagation_node_ready);
            if (now - self.last_propagation_check > 90.0 || path_awaited)
                && client.state() == lxmf_core::propagation_client::PropagationClientState::Idle
            {
                if propagation_node_ready && self.admission_store.is_some() {
                    client.start_download();
                    self.last_propagation_check = now;
                    self.download_on_path_until = None;
                    tracing::debug!("auto-triggered propagation download");
                } else if let Some(node) = self.router.outbound_propagation_node
                    && queue_unknown_propagation_node_path_request(
                        &self.transport_tx,
                        &mut self.router,
                        &self.medium,
                        node,
                        &mut self.last_propagation_check,
                        now,
                    )
                {
                    // LXMRouter.request_messages_from_propagation_node path wait.
                    self.download_on_path_until = Some(
                        now + lxmf_core::propagation_client::PR_PATH_TIMEOUT
                            .max(lxmf_core::constants::PATH_REQUEST_WAIT)
                            as f64,
                    );
                    unknown_propagation_node = Some(node);
                    tracing::debug!(
                        node = %hex::encode(node),
                        "propagation node identity unknown; requesting path before download"
                    );
                }
            }
            let status = client.transfer_status();
            acknowledge_propagation = status.state.is_terminal();
            propagation_status = Some(status);
        }
        if let Some(node) = unknown_propagation_node {
            self.recall_identity(node);
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

        self.stage_due_node_announce(now);

        if let Some(task) = self.prop_maintenance_task.as_mut() {
            match task.result.try_recv() {
                Ok(Ok(())) => self.prop_maintenance_task = None,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "relay maintenance remains pending");
                    self.prop_maintenance_task = None;
                    self.last_cull = now - 420.0;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.prop_maintenance_task = None;
                    self.last_cull = now - 420.0;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        // JOB_STORE_INTERVAL * PROCESSING_INTERVAL, the cadence of LXMRouter.clean_message_store.
        if self.prop_maintenance_task.is_none() && now - self.last_cull > 480.0 {
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

        if now - self.last_identity_prune > 900.0 {
            let dropped = prune_known_identities(&mut self.known_identities);
            if dropped > 0 {
                tracing::debug!(dropped, "dropped recalled identity keys over the cap");
            }
            self.last_identity_prune = now;
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
            self.route_hops.insert(event.destination_hash, event.hops);

            if event.name_hash == delivery_name_hash {
                if let Some(name) = event
                    .app_data
                    .as_deref()
                    .and_then(lxmf_core::handlers::display_name_from_app_data)
                {
                    tracing::info!(dest = %dest_hex, name = %name, "announce display name");
                }
                // Python's handler records the announced cost, including none,
                // and keeps the cached cost when the data cannot be decoded.
                match lxmf_core::handlers::announced_stamp_cost(event.app_data.as_deref()) {
                    Ok(cost) => {
                        self.router.update_stamp_cost(event.destination_hash, cost);
                        tracing::debug!(
                            dest = %dest_hex,
                            stamp_cost = ?cost,
                            "updated delivery stamp cost from announce"
                        );
                    }
                    Err(error) => {
                        tracing::debug!(dest = %dest_hex, %error, "kept cached stamp cost");
                    }
                }
                self.router
                    .update_compression_support(event.destination_hash, event.app_data.as_deref());
                if !self.router.compression_supported(&event.destination_hash)
                    && let Some(ref mut ld) = self.link_delivery
                {
                    ld.disable_pending_direct_compression(event.destination_hash);
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
                // Outbound costs read slot 5 as given; peering reads int() of it.
                if let Some(policy) = AdvertisedNodePolicy::from_announce(data, now_f64()) {
                    self.node_policies.insert(event.destination_hash, policy);
                }
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
                        transfer_limit: Some(pn.transfer_limit.as_f64().trunc()),
                        sync_limit: Some(pn.sync_limit.as_f64().trunc()),
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
                    self.forget_peer(&event.destination_hash);
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
                        && self.cancel_peer_sync(&event.destination_hash)
                        && let Some(peer) = self.router.peers.get_mut(&event.destination_hash)
                    {
                        peer.link_closed();
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
            }
            // Python triggers on pn_announce_data_is_valid alone (Handlers.py).
            if event.name_hash == propagation_name_hash
                && let Some(data) = event.app_data.as_deref()
            {
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
            if let Some(public_key) = event.public_key {
                self.learn_identity(&event.destination_hash, public_key);
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
            // A link packet carries its Link ID as the ratchet ID (Link.py).
            self.handle_link_delivered_data_on(&plaintext, Some(link_id));
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
                &mut self.peer_distribution_queue,
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
                // A resource delivery records its Link ID as the ratchet ID (LXMRouter.py).
                self.handle_link_delivered_data_on(&completion.data, Some(completion.link_id));
            }
            _ => {}
        }
    }

    fn handle_link_delivered_data_on(&mut self, data: &[u8], link_id: Option<[u8; 16]>) {
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
            Ok(msg) => {
                tracing::info!(
                    from = %hex::encode(msg.source_hash()),
                    title = %msg.title_text(),
                    len = msg.content_bytes().len(),
                    "inbound LXMF message via link"
                );
                self.admit_inbound_message(
                    msg,
                    DeliveryMethod::Direct,
                    link_id.as_ref().map(|id| id.as_slice()),
                    None,
                );
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
        let max_transfer_bytes = configured_kilobytes_to_bytes(self.config.sync_limit_kb.as_f64());
        let min_cost = self.config.min_accepted_stamp_cost();
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
                if let Some(plan) = node.plan_accept_stamped_propagated_blob(
                    &entry.lxmf_data,
                    &entry.stamp_data,
                    entry.stamp_value,
                ) {
                    write_plans.push((plan, entry.lxmf_data.len() as u64));
                }
            }
        }
        let accounted = result
            .entries
            .iter()
            .map(|entry| {
                (
                    rns_crypto::sha::full_hash(&entry.lxmf_data),
                    entry.lxmf_data.len() as u64,
                )
            })
            .collect::<Vec<_>>();
        if let PropagationStoreWriteOrigin::Peer(peer_hash) = write_origin {
            self.recall_sync_autopeer(peer_hash);
        }
        let reserved = write_plans.len();
        if write_plans.is_empty() {
            apply_propagation_store_commit(
                &mut self.router,
                self.propagation_node.as_ref(),
                &mut self.peer_distribution_queue,
                PropagationStoreCommitResult {
                    origin: write_origin,
                    accounted,
                    committed: Vec::new(),
                },
            );
        } else if let Some(node) = self.propagation_node.clone()
            && let Some(task) = spawn_propagation_store_writes(
                node,
                write_plans,
                accounted,
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
            max_transfer_bytes: configured_kilobytes_to_bytes(
                self.config.propagation_limit_kb.as_f64(),
            ),
            min_cost: self.config.min_accepted_stamp_cost(),
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
            &mut self.peer_distribution_queue,
            PropagationStoreCommitResult {
                origin: PropagationStoreWriteOrigin::Client,
                accounted: std::mem::take(&mut result.accounted),
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
                .get_inbound_tickets(&msg.source_hash())
                .unwrap_or_default();
            let cost = if self.config.enforce_stamps {
                self.config.stamp_cost.unwrap_or(0.0)
            } else {
                0.0
            };
            let mut msg = msg;
            msg.unverified_reason = classify_signature(&msg, public_key.as_ref());
            let disposition = if self.source_blackholed(&msg.source_hash())
                || self.router.is_ignored(&msg.source_hash())
            {
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
                        validate_download_policy(&msg, &tickets, cost)
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
                    self.share_processed_claim(receipt.record().scope.transient_id);
                    if receipt.record().disposition == DurableDisposition::Committed {
                        self.store_propagated_container(result.message.clone());
                    }
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

    /// Python delivers propagated messages through the same callback as direct
    /// ones, so they land in the messages directory in the same format.
    fn store_propagated_container(&mut self, mut msg: LxMessage) {
        mark_received(&mut msg, DeliveryMethod::Propagated);
        let path = self.messages_dir.join(hex::encode(msg.message_id()));
        match msg.pack_container() {
            Ok(container) => {
                tokio::task::spawn_blocking(move || {
                    if let Err(error) = lxmf_core::persist::write_file_atomic(&path, &container) {
                        tracing::error!(%error, path = %path.display(), "failed to store propagated message");
                    }
                });
            }
            Err(error) => tracing::error!(%error, "failed to pack propagated message for storage"),
        }
    }

    fn download_epochs(&self) -> AdmissionEpochs {
        let mut policy = b"lxmd admission policy v1".to_vec();
        policy.push(u8::from(self.config.enforce_stamps));
        policy.extend_from_slice(&self.config.stamp_cost.unwrap_or(0.0).to_be_bytes());
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
        let messages_dir = self.messages_dir.clone();
        self.hook_task = Some(tokio::task::spawn_blocking(
            move || match write_propagated_container(&path, &messages_dir).and_then(|written| {
                lxmf_tools::daemon::execute_on_inbound_with_event(
                    &command,
                    &written.to_string_lossy(),
                    &hex::encode(event),
                )
            }) {
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
            },
        ));
    }

    /// `LXMRouter.delivery_packet` reads the packet's RSSI, SNR and Q from
    /// Reticulum's per-packet caches (LXMRouter.py).
    async fn inbound_packet_phy(&self, raw: &[u8]) -> Option<lxmf_core::message::PhyStats> {
        let (header, _) = rns_wire::header::PacketHeader::unpack(raw).ok()?;
        let packet_hash = rns_wire::hash::packet_hash(raw, header.flags.header_type);
        let query = |query| {
            let (response_tx, response_rx) = oneshot::channel();
            let sent = self
                .transport_tx
                .try_send(TransportMessage::Rpc { query, response_tx })
                .is_ok();
            async move {
                if !sent {
                    return None;
                }
                match tokio::time::timeout(Duration::from_millis(100), response_rx).await {
                    Ok(Ok(TransportQueryResponse::FloatResult(value))) => value,
                    _ => None,
                }
            }
        };
        let (rssi, snr, q) = tokio::join!(
            query(TransportQuery::GetPacketRssi { packet_hash }),
            query(TransportQuery::GetPacketSnr { packet_hash }),
            query(TransportQuery::GetPacketQ { packet_hash }),
        );
        (rssi.is_some() || snr.is_some() || q.is_some()).then_some(lxmf_core::message::PhyStats {
            rssi,
            snr,
            q,
        })
    }

    fn handle_inbound_packet(&mut self, raw: &[u8], phy: Option<lxmf_core::message::PhyStats>) {
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

        let (plaintext, ratchet_id) = match self.decrypt_inbound(payload) {
            Some(decrypted) => (decrypted.plaintext, decrypted.ratchet_id),
            None => {
                tracing::warn!("failed to decrypt inbound packet");
                return;
            }
        };

        // Python proves every delivery packet before unpacking or gating it
        // (LXMRouter.py).
        if let Some(proof_raw) = self.create_delivery_proof(raw) {
            let trunc = rns_wire::hash::truncated_packet_hash(raw, header.flags.header_type);
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
            Ok(msg) => {
                tracing::info!(
                    from = %hex::encode(msg.source_hash()),
                    title = %msg.title_text(),
                    len = msg.content_bytes().len(),
                    "inbound LXMF message received"
                );

                // LXMRouter.delivery_packet passes packet.ratchet_id (LXMRouter.py).
                self.admit_inbound_message(
                    msg,
                    DeliveryMethod::Opportunistic,
                    ratchet_id.as_ref().map(|id| id.as_slice()),
                    phy,
                );
            }
            Err(e) => {
                tracing::warn!("failed to unpack LXMF message: {e}");
            }
        }
    }

    /// Python `lxmf_delivery` gating (LXMRouter.py): blackholed
    /// source, ticket learning from a validated signature, stamp, ignored
    /// source, then delivery. Unknown or invalid signatures are delivered flagged.
    fn admit_inbound_message(
        &mut self,
        mut msg: LxMessage,
        method: DeliveryMethod,
        ratchet_id: Option<&[u8]>,
        phy: Option<lxmf_core::message::PhyStats>,
    ) {
        msg.record_delivery(None, ratchet_id, None, phy);
        msg.source_blackholed = self.source_blackholed(&msg.source_hash());
        if msg.source_blackholed {
            tracing::debug!(
                from = %hex::encode(msg.source_hash()),
                "Dropping LXM from blackholed identity"
            );
            return;
        }
        let public_key = self
            .known_identities
            .get(&hex::encode(msg.source_hash()))
            .copied();
        msg.unverified_reason = classify_signature(&msg, public_key.as_ref());
        if msg.unverified_reason.is_none()
            && let Some(key) = public_key
            && let Ok(verified) = msg.verify(&key)
        {
            self.router.learn_ticket_from_inbound(&verified);
        }
        if self.should_reject_for_stamp(&msg) {
            return;
        }
        self.handle_inbound_message(msg, method);
    }

    /// Returns true if the message should be rejected.
    fn should_reject_for_stamp(&self, msg: &LxMessage) -> bool {
        if !self.config.enforce_stamps {
            return false;
        }
        let required_cost = match self.config.stamp_cost {
            Some(c) if c > 0.0 => c,
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
    fn handle_inbound_message(&mut self, mut msg: LxMessage, method: DeliveryMethod) {
        if !self.router.deliver_inbound(&msg, false) {
            tracing::debug!(
                message = %hex::encode(msg.message_id()),
                "ignoring inbound LXMF message from an ignored source or already delivered"
            );
            return;
        }

        let messages_dir = self.messages_dir.clone();
        std::fs::create_dir_all(&messages_dir).ok();

        let msg_hash = hex::encode(msg.message_id());
        let msg_path = messages_dir.join(&msg_hash);

        // Pack synchronously (CPU-bound, no IO) and offload the disk write
        // to the blocking pool so a slow disk doesn't stall the lxmd runner
        // task between inbound messages. Atomic tmp+rename write so readers
        // never see a partial file (LXMessage.py).
        mark_received(&mut msg, method);
        match msg.pack_container() {
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

    /// Prepare propagation envelopes for queued propagated messages and return
    /// those not ready yet. Python generates the propagation stamp before a
    /// message enters the outbound queue, so these wait outside processing.
    fn prepare_propagation_envelopes(&mut self) -> HashSet<[u8; 32]> {
        let mut unready = HashSet::new();
        let Some(node) = self.router.outbound_propagation_node else {
            return unready;
        };
        let queued: Vec<LxMessage> = self
            .router
            .pending_outbound
            .iter()
            .filter(|message| {
                message.method == DeliveryMethod::Propagated
                    && message.state == lxmf_core::constants::MessageState::Outbound
            })
            .cloned()
            .collect();
        let now = now_f64();
        let queued_ids: HashSet<[u8; 32]> = queued.iter().map(|m| m.message_id()).collect();
        self.node_cost_deadlines
            .retain(|id, _| queued_ids.contains(id));
        for message in queued {
            let id = message.message_id();
            let prepared = self.pack_message_for_propagation(&message, node);
            if !matches!(
                prepared,
                Err(PropagationPreparationError::Missing(
                    MissingPropagationInput::NodePolicy
                ))
            ) {
                self.node_cost_deadlines.remove(&id);
            }
            match prepared {
                Ok(_) => {}
                // LXMRouter.get_outbound_propagation_cost waits path_request_wait, then the message fails.
                Err(PropagationPreparationError::Missing(MissingPropagationInput::NodePolicy))
                    if self
                        .node_cost_deadlines
                        .get(&id)
                        .is_some_and(|deadline| now >= *deadline) =>
                {
                    self.node_cost_deadlines.remove(&id);
                    self.propagation_envelopes.remove(&id);
                    self.pending_propagation_envelopes.remove(&id);
                    self.last_delivery_failure =
                        Some("propagation node stamp cost unavailable".to_string());
                    self.router.mark_outbound_failed(&id);
                }
                Err(PropagationPreparationError::Missing(
                    MissingPropagationInput::NodeIdentity | MissingPropagationInput::NodePath,
                )) => {}
                Err(PropagationPreparationError::Missing(missing)) => {
                    let wanted = if missing == MissingPropagationInput::RecipientIdentity {
                        message.destination_hash()
                    } else {
                        node
                    };
                    if missing == MissingPropagationInput::NodePolicy {
                        self.node_cost_deadlines
                            .entry(id)
                            .or_insert(now + self.medium.path_request_wait());
                    }
                    self.recall_identity(wanted);
                    if self.router.request_path(wanted, &self.medium, now) {
                        queue_path_request(
                            &self.transport_tx,
                            wanted,
                            false,
                            "propagation readiness incomplete",
                        );
                    }
                    unready.insert(id);
                }
                Err(PropagationPreparationError::Pending) => {
                    unready.insert(id);
                }
                Err(PropagationPreparationError::Invalid(error)) => {
                    self.last_delivery_failure = Some(error);
                    self.propagation_envelopes.remove(&id);
                    self.router.mark_outbound_failed(&id);
                }
            }
        }
        unready
    }

    fn execute_outbound_actions(&mut self, actions: Vec<OutboundAction>) {
        for action in actions {
            match action {
                OutboundAction::Failed(message) => {
                    let id = message.message_id();
                    self.propagation_envelopes.remove(&id);
                    self.pending_propagation_envelopes.remove(&id);
                    tracing::warn!(hash = %hex::encode(id), "message delivery failed");
                    self.last_delivery_failure = Some(format!(
                        "delivery attempts exhausted for {}",
                        hex::encode(id)
                    ));
                }
                OutboundAction::RequestPath {
                    destination,
                    drop_existing,
                } => {
                    self.recall_identity(destination);
                    if drop_existing {
                        queue_path_request_after_drop(&self.transport_tx, destination);
                    } else {
                        queue_path_request(
                            &self.transport_tx,
                            destination,
                            false,
                            "outbound path request",
                        );
                    }
                }
                OutboundAction::SendOpportunistic { message } => self.send_opportunistic(message),
                OutboundAction::DeliverOverLink {
                    message,
                    target,
                    plan,
                } => self.deliver_over_link(message, target, plan),
            }
        }
    }

    fn send_opportunistic(&mut self, message: LxMessage) {
        let dest_hash = message.destination_hash();
        let dest_hex = hex::encode(dest_hash);
        let msg_hash = message.message_id();
        let destination_public_key = self
            .known_identities
            .get(&dest_hex)
            .copied()
            .filter(|_| self.outbound_ratchets.contains_key(&dest_hash));
        let Some(destination_public_key) = destination_public_key else {
            tracing::warn!(dest = %dest_hex, "destination key unknown, waiting for path");
            self.recall_identity(dest_hash);
            let actions = self
                .router
                .await_outbound_path(&msg_hash, &self.medium, now_f64());
            self.execute_outbound_actions(actions);
            return;
        };
        let payload = match message.pack_opportunistic_encrypted(|plaintext| {
            self.encrypt_for_destination(&dest_hex, plaintext)
                .ok_or_else(|| MessageError::PackFailed("destination encryption failed".into()))
        }) {
            Ok(payload) => payload,
            Err(error) => {
                // A raising send() fails the message (LXMRouter.py).
                tracing::warn!(dest = %dest_hex, %error, "opportunistic LXMF send failed");
                self.last_delivery_failure = Some(error.to_string());
                self.router.mark_outbound_failed(&msg_hash);
                return;
            }
        };
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
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&payload);
        let timeout = lxmf_core::router::opportunistic_receipt_timeout(
            self.medium.route(&dest_hash),
            message.receipt_timeout,
        );
        match dispatch_opportunistic_packet(
            &self.transport_tx,
            raw,
            dest_hash,
            destination_public_key,
            msg_hash,
            timeout,
        ) {
            Ok(()) => {
                tracing::info!(hash = %hex::encode(msg_hash), "message sent; awaiting delivery proof")
            }
            Err(error) => tracing::warn!(
                dest = %dest_hex,
                %error,
                "transport backpressure deferred opportunistic message"
            ),
        }
    }

    fn deliver_over_link(&mut self, message: LxMessage, target: [u8; 16], plan: LinkDeliveryPlan) {
        let msg_hash = message.message_id();
        let hops = match plan {
            LinkDeliveryPlan::StartLink { hops } => hops,
            LinkDeliveryPlan::UseLink => self
                .medium
                .route(&target)
                .map(|route| route.hops.max(1))
                .unwrap_or(1),
        };
        self.ensure_link_delivery();
        let propagated = message.method == DeliveryMethod::Propagated;
        let packed = if propagated {
            match self.pack_message_for_propagation(&message, target) {
                Ok(packed) => Some(packed),
                Err(PropagationPreparationError::Invalid(error)) => {
                    self.last_delivery_failure = Some(error);
                    self.router.mark_outbound_failed(&msg_hash);
                    return;
                }
                Err(_) => {
                    // The envelope went stale since this pass prepared it.
                    if let Some(queued) = self
                        .router
                        .pending_outbound
                        .iter_mut()
                        .find(|queued| queued.message_id() == msg_hash)
                    {
                        queued.state = lxmf_core::constants::MessageState::Outbound;
                    }
                    return;
                }
            }
        } else {
            None
        };
        let Some(ld) = self.link_delivery.as_mut() else {
            return;
        };
        ld.provide_next_hop_hardware_mtu(target, self.next_hop_hardware_mtus.get(&target).copied());
        let started = if let Some(packed) = packed {
            ld.start_packed_delivery(message, target, hops, packed, true)
                .map(|_| ())
                .map_err(|failure| failure.error.to_string())
        } else if plan == LinkDeliveryPlan::UseLink
            && ld.direct_link_snapshot(target).is_none()
            && ld.backchannel_link_snapshot(target).is_some()
        {
            ld.start_backchannel_delivery(message, target)
                .map(|_| ())
                .map_err(|failure| failure.error.to_string())
        } else {
            ld.start_delivery_with_report(message, target, hops)
                .map(|_| ())
                .map_err(|failure| failure.error.to_string())
        };
        match started {
            Ok(()) => tracing::info!(
                target = %hex::encode(target),
                hops,
                plan = ?plan,
                propagated,
                "routing LXMF message over link delivery"
            ),
            Err(reason) => {
                tracing::warn!(target = %hex::encode(target), %reason, "failed to start link delivery");
                let activated = plan == LinkDeliveryPlan::UseLink;
                let actions =
                    self.router
                        .outbound_link_closed(&msg_hash, activated, &self.medium, now_f64());
                self.execute_outbound_actions(actions);
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
            delivery.set_link_request_stamper(rns_runtime::link_stamp::blocking_stamper(
                self.transport_tx.clone(),
            ));
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
        let destination: [u8; 16] = hex::decode(dest_hash_hex).ok()?.try_into().ok()?;
        // No answer this tick: the caller waits instead of sending unratcheted.
        let ratchet = self.outbound_ratchets.get(&destination)?;
        remote.encrypt(plaintext, ratchet.as_ref()).ok()
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
            // LXMRouter checks RNS.Transport.has_path; the medium snapshot is refreshed per tick.
            self.medium.has_path(&prop_hash),
            self.node_policies.get(&prop_hash).copied(),
            // The recipient is ready once Reticulum has answered for its key and ratchet.
            self.known_identities.contains_key(&dest_hex)
                && self
                    .outbound_ratchets
                    .contains_key(&message.destination_hash()),
            now_f64(),
        )
        .map_err(PropagationPreparationError::Missing)?;
        let key = self.known_identities[&dest_hex];
        let ratchet = self.outbound_ratchets[&message.destination_hash()];
        let binding = EncryptionBinding::for_recipient(&key, ratchet.as_ref());
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
            && envelope.meets(prepared.policy.stamp_cost)
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
        let worker_ctl = lxmf_core::stamper::StampControl::default();
        let cancel = worker_ctl.cancel.clone();
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
                            &worker_ctl,
                        )?,
                    };
                    envelope.pack_for_cancellable(prepared, now_f64(), &worker_ctl)?;
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

    fn decrypt_inbound(
        &self,
        ciphertext: &[u8],
    ) -> Option<rns_identity::identity::DecryptionResult> {
        let prv_keys = self.delivery_ratchets.ring().private_keys();
        let refs: Vec<&[u8; 32]> = prv_keys.iter().collect();
        let ratchets = if refs.is_empty() {
            None
        } else {
            Some(refs.as_slice())
        };
        self.identity
            .decrypt_with_ratchet_id(ciphertext, ratchets, false)
            .ok()
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
        self.delivery_ratchets.save_durable(&self.identity)
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
    ] {
        require_ratchet_directory(path)?;
    }
    Ok(())
}

/// Remove the received-ratchet and identity-key files earlier releases kept
/// under `storage/lxmf/ratchets`. Reticulum keeps received ratchets and known
/// destinations now and, as upstream, imports only its own legacy files; until
/// a recipient announces again, a message to it is encrypted to its identity
/// key. Python `lxmd` never had these files.
fn remove_earlier_ratchet_files(paths: &LxmdPaths) -> std::io::Result<()> {
    match std::fs::remove_dir_all(&paths.legacy_received_ratchets_dir) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    match std::fs::remove_file(&paths.legacy_known_identities_path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
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

/// Rust-only spellings the 1.3 and 1.4 releases accepted, kept for existing
/// scripts (lxmd.py has `--config` and `--version` only).
const DEPRECATED_SPELLINGS: &[(&str, &str)] = &[("-c", "--config"), ("-V", "--version")];

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();
    rns_tools::warn_deprecated_spellings("lxmd-rs", DEPRECATED_SPELLINGS);

    if args.version {
        println!(
            "{}",
            rns_tools::version_line(
                "lxmd-rs",
                env!("CARGO_PKG_VERSION"),
                &[("LXMF", lxmf_tools::lxmd_cli::LXMF_COMPAT_VERSION)],
            )
        );
        return;
    }

    if args.exampleconfig {
        println!("{}", example_config());
        return;
    }

    let (config_dir, rns_config_dir) =
        resolve_config_dirs(args.config.as_deref(), args.rnsconfig.as_deref());
    // Python tests the strings for truth, so an empty hash starts the daemon.
    let sync_hash = args.sync.as_deref().filter(|hash| !hash.is_empty());
    let unpeer_hash = args.unpeer.as_deref().filter(|hash| !hash.is_empty());
    let is_control_command =
        args.status || args.peers || sync_hash.is_some() || unpeer_hash.is_some();

    let daemon_setup = if is_control_command || args.migrate_propagation_store {
        None
    } else {
        // Python creates the storage directories before it reads the config.
        if let Err(error) = initialize_storage_namespace(&config_dir) {
            println!("Failed to establish private daemon storage namespace: {error}");
            std::process::exit(1);
        }
        if let Err(error) = remove_earlier_ratchet_files(&LxmdPaths::new(&config_dir)) {
            // Left in place, the files are removed at the next start.
            tracing::warn!(%error, "could not remove earlier ratchet files");
        }
        let (config, created) = load_or_create_daemon_config(&config_dir);
        let loaded = DaemonConfig::from_config(&config).and_then(|daemon_config| {
            Ok((
                daemon_config,
                PythonLxmdConfig::from_config(&config)?.target_loglevel,
            ))
        });
        match loaded {
            Ok((daemon_config, loglevel)) => Some((daemon_config, loglevel, created)),
            Err(error) => {
                println!(
                    "Could not apply LXM Daemon configuration. The contained exception was: {error}"
                );
                std::process::exit(1);
            }
        }
    };
    setup_logging(
        &args,
        daemon_setup.as_ref().and_then(|(_, loglevel, _)| *loglevel),
        daemon_setup
            .as_ref()
            .filter(|_| args.service)
            .map(|_| config_dir.as_path()),
        &rns_config_dir,
    );
    if daemon_setup
        .as_ref()
        .is_some_and(|(_, _, created)| *created)
    {
        tracing::info!("Could not load config file, creating default configuration file...");
        tracing::info!(
            "Default config file created. Make any necessary changes in {} and restart lxmd if needed.",
            config_dir.join("config").display()
        );
    }

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
                let config = DaemonConfig::from_config(&source).map_err(std::io::Error::other)?;
                let policy = RecoveryPolicy {
                    maximum_store_bytes: config.message_storage_limit.unwrap_or(
                        configured_kilobytes_to_bytes(config.propagation_limit_kb.as_f64()),
                    ),
                    maximum_message_bytes: configured_kilobytes_to_bytes(
                        config.propagation_limit_kb.as_f64(),
                    ),
                    minimum_stamp_cost: config.min_accepted_stamp_cost(),
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

    let control_preflight = if is_control_command {
        let peer_hash = if args.status || args.peers {
            None
        } else {
            sync_hash.or(unpeer_hash)
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

    let mut daemon_config = daemon_setup
        .map(|(daemon_config, _, _)| daemon_config)
        .unwrap_or_default();
    if args.propagation_node {
        daemon_config.propagation_enabled = true;
    }
    if let Some(ref on_inbound) = args.on_inbound {
        daemon_config.on_inbound_command = Some(on_inbound.clone());
    }

    if !is_control_command {
        rns_transport::notice!("LXMF Daemon starting");
        if let Some(ref name) = daemon_config.display_name {
            tracing::info!("Display name: {}", name);
        }
    }

    if !is_control_command && daemon_config.propagation_enabled {
        rns_transport::notice!(
            "Propagation node enabled (stamp_cost={}, max_peers={}, autopeer={})",
            daemon_config.propagation_stamp_cost,
            daemon_config.max_peers,
            daemon_config.autopeer,
        );
    }

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let _signal_rx = rns_runtime::lifecycle::install_signal_handlers(shutdown.clone());

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
            tracing::debug!(
                "RNS initialized: mode={:?}, interfaces={}",
                h.instance_mode,
                h.interface_configs.len(),
            );
            h
        }
        Err(e) => {
            tracing::error!("Failed to initialize RNS: {e:?}");
            if let rns_runtime::reticulum::ReticulumError::Config(
                rns_runtime::config::ConfigError::Parse { .. },
            ) = e
            {
                std::process::exit(255);
            }
            std::process::exit(1);
        }
    };
    rns_handle
        .enable_on_network_discovery(Arc::new(
            lxmf_core::discovery_stamper::LxmfDiscoveryStamper::default(),
        ))
        .await;

    let transport_tx = rns_handle.transport_tx.clone();

    if control_preflight.is_none() {
        // LXMRouter.REQUIRED_DESTINATION_TYPES, registered as the router starts.
        for destination_type in [DELIVERY_APP_NAME, "lxmf.propagation"] {
            rns_handle.wants_destination_type(destination_type).await;
        }
    }

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
        let timeout = control_timeout(&args);
        // Python's TCP client interfaces finish their initial connect (up to 5 s)
        // inside `RNS.Reticulum()`, before the control timeout starts.
        if !rns_handle.interface_configs.is_empty() {
            wait_for_online_interface(&rns_handle, Duration::from_secs(5)).await;
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
        let kind = if args.status || args.peers {
            ControlCommandKind::Status
        } else if sync_hash.is_some() {
            ControlCommandKind::Sync
        } else {
            ControlCommandKind::Unpeer
        };
        let started = tokio::time::Instant::now();
        // Python adds the timeout to `time.time()`: NaN and infinity never expire.
        let deadline = Duration::try_from_secs_f64(if timeout.is_nan() {
            f64::INFINITY
        } else {
            timeout.max(0.0)
        })
        .ok()
        .and_then(|limit| started.checked_add(limit))
        .unwrap_or_else(|| started + Duration::from_secs(u32::MAX as u64));
        if !wait_for_control_path(&transport_tx, target_identity_hash, deadline).await {
            println!("{}", kind.timeout_message());
            std::process::exit(200);
        }
        let timeout = if timeout.is_finite() {
            timeout - started.elapsed().as_secs_f64()
        } else {
            timeout
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

        if sync_hash.is_some() {
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

        if unpeer_hash.is_some() {
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

    // Python `program_setup` exits 4 when an existing identity file cannot be loaded.
    let identity_path = LxmdPaths::new(&config_dir)
        .preferred_identity_path()
        .to_path_buf();
    if identity_path.is_file() && Identity::from_file(&identity_path).is_err() {
        tracing::error!(
            "Could not load the Primary Identity from {}",
            identity_path.display()
        );
        std::process::exit(4);
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
    runner.control_plane = Some(rns_handle.clone());
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
        runner.merge_processed_ids();
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

    rns_transport::notice!(
        "LXMF Router ready to receive on {}",
        pretty_hex_rep(&runner.lxmf_dest_hash)
    );

    // Python's enable_propagation() always announces the node, independent of
    // the deferred start jobs.
    if daemon_config.propagation_enabled {
        runner.schedule_node_announce(now_f64());
        runner.startup_node_announce_pending = true;
        tracing::info!("Startup propagation announce scheduled in {NODE_ANNOUNCE_DELAY}s");
        rns_transport::notice!(
            "LXMF Propagation Node started on {}",
            pretty_hex_rep(&runner.propagation_dest_hash)
        );
    }
    let deferred_start = tokio::time::sleep(Duration::from_secs(DEFERRED_JOBS_DELAY));
    tokio::pin!(deferred_start);
    let mut deferred_start_done = false;

    if let Some(ref cmd) = daemon_config.on_inbound_command {
        tracing::info!("On-inbound command: {}", cmd);
    }

    let mut one_shot_status = None;
    if let Some(send_args) = args.send.as_ref().filter(|_| !shutdown.is_triggered()) {
        one_shot_status = Some(1);
        // A one-shot send runs the deferred start jobs before it sends.
        deferred_start_done = true;
        runner.run_deferred_start_jobs(daemon_config.announce_at_start);
        'one_shot: {
            let dest_hex = normalize_hash_hex(&send_args[0]);
            let contents = match args.send_file.as_ref() {
                Some(path) => match std::fs::read_to_string(path) {
                    Ok(content) => vec![content],
                    Err(e) => {
                        tracing::error!(path = %path.display(), error = %e, "failed to read --send-file");
                        break 'one_shot;
                    }
                },
                None if send_args.len() > 1 => send_args[1..].to_vec(),
                None => {
                    tracing::error!("--send requires CONTENT unless --send-file is provided");
                    break 'one_shot;
                }
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
                runner.refresh_outbound_medium().await;
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

            for content in &contents {
                let mut msg = match LxMessageDraft::new(
                    dest_hash,
                    runner.lxmf_dest_hash,
                    "",
                    content,
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
                            tracing::info!(
                                count = fields.len(),
                                "attaching custom fields to --send"
                            );
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
                if let Err(error) = runner.router.prepare_outbound(&mut msg) {
                    tracing::error!(%error, "reply ticket preparation failed");
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
            }

            // Completion phase: do not confuse queue acceptance with delivery.
            // Opportunistic messages leave the router queue while a validated
            // Reticulum delivery proof is outstanding, so both ownership sets
            // must converge before the command can report success.
            let mut drained = false;
            for _ in 0..args.send_timeout_secs {
                runner.drain_announce_events();
                runner.refresh_route_hops_from_transport().await;
                runner.refresh_outbound_medium().await;
                runner.drain_link_packets();
                runner.tick();
                if sleep_or_shutdown(&shutdown, Duration::from_secs(1)).await {
                    tracing::info!("message send interrupted by shutdown");
                    break 'one_shot;
                }

                let stats = runner.router.stats();
                if stats.pending_outbound == 0 && stats.pending_deferred_stamps == 0 {
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
                    runner.refresh_outbound_medium().await;
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
        rns_transport::notice!("LXMF Daemon running. Press Ctrl+C to stop.");
    }

    // Event-driven for inbound, periodic for outbound and maintenance.
    let mut tick_timer = tokio::time::interval(Duration::from_secs(4));
    tick_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut jobs_timer = tokio::time::interval(Duration::from_secs(JOBS_INTERVAL));
    jobs_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut propagation_sync_timer = tokio::time::interval(Duration::from_millis(25));
    propagation_sync_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            _ = propagation_sync_timer.tick() => {
                runner.drive_propagation_sync();
            }
            _ = &mut deferred_start, if !deferred_start_done => {
                deferred_start_done = true;
                runner.run_deferred_start_jobs(daemon_config.announce_at_start);
            }
            _ = jobs_timer.tick(), if deferred_start_done => {
                runner.announce_jobs(now_f64());
            }
            // Recreated on every loop pass, so it is a deadline rather than a delay.
            _ = tokio::time::sleep(runner.next_node_announce_in().unwrap_or(Duration::from_secs(3600))),
                if runner.next_node_announce_in().is_some() => {
                runner.stage_due_node_announce(now_f64());
            }
            _ = tick_timer.tick() => {
                runner.drain_announce_events();
                runner.refresh_route_hops_from_transport().await;
                runner.refresh_outbound_medium().await;
                runner.refresh_blackholed_identities_from_transport().await;
                runner.drain_link_packets();
                runner.tick();
            }
            Some(raw) = runner.inbound_raw_rx.recv() => {
                let phy = runner.inbound_packet_phy(&raw).await;
                runner.handle_inbound_packet(&raw, phy);
            }
            Some(request) = runner.delivery_announce_rx.recv() => {
                if let Err(error) = runner.request_delivery_announce(request) {
                    tracing::debug!("delivery announce not sent: {error}");
                }
            }
            outcome = runner.delivery_stamps.recv() => {
                runner.on_delivery_stamp(outcome);
            }
            Some((plaintext, link_id)) = runner.link_packet_rx.recv() => {
                runner.handle_link_delivered_data_on(&plaintext, Some(link_id));
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
                    &mut runner.peer_distribution_queue,
                    result,
                );
                runner.drain_link_packets();
            }
            Some(served) = runner.client_propagation_served_rx.recv() => {
                runner.record_client_propagation_served(served);
            }
        }
    }

    rns_transport::notice!("LXMF Daemon shutting down");
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
            &mut runner.peer_distribution_queue,
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
    // Python exit_handler() saves every peer's synchronisation state.
    runner.flush_peer_distribution_queue();
    runner.save_all_peers();
    runner.merge_processed_ids();
    if let Err(e) = runner.router.save_state(&runner.data_dir) {
        tracing::warn!("Failed to save router state on shutdown: {e}");
        if one_shot_status.is_some() {
            one_shot_status = Some(1);
        }
    }

    // Reticulum's exit handler: runtime shutdown deregisters this process's
    // destination types once, then persists transport state.
    rns_handle.shutdown_and_wait().await;
    tracing::info!("LXMF Daemon stopped");
    if let Some(status) = one_shot_status {
        std::process::exit(status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `announce` to `transport` as heard on a new interface `id`.
    async fn hear(
        transport: &mpsc::Sender<TransportMessage>,
        id: u64,
        announce: &[u8],
    ) -> mpsc::Receiver<Bytes> {
        let (driver_tx, driver_rx) = mpsc::channel(64);
        let entry = rns_transport::messages::InterfaceEntry::new(
            "heard".into(),
            rns_transport::constants::InterfaceMode::Full,
            rns_transport::constants::InterfaceDirection::bidirectional(),
            10_000_000,
            500,
            driver_tx,
        );
        let owner = entry.owner.clone();
        transport
            .send(TransportMessage::RegisterInterface { id, entry })
            .await
            .unwrap();
        transport
            .send(TransportMessage::InterfaceEvent {
                interface_id: id,
                owner,
                message: Box::new(TransportMessage::Inbound(
                    rns_transport::messages::InboundPacket {
                        raw: Bytes::copy_from_slice(announce),
                        interface_id: id,
                        rssi: None,
                        snr: None,
                        q: None,
                    },
                )),
            })
            .await
            .unwrap();
        driver_rx
    }

    /// A transport that validated `announce` before any daemon subscribed.
    async fn transport_that_heard(
        announce: &[u8],
    ) -> (mpsc::Sender<TransportMessage>, mpsc::Receiver<Bytes>) {
        let (actor, tx) = rns_transport::actor::TransportActor::new();
        tokio::spawn(actor.run());
        let driver_rx = hear(&tx, 1, announce).await;
        (tx, driver_rx)
    }

    fn lxmf_announce(
        identity: &Identity,
        aspect: &str,
        app_data: Option<&[u8]>,
    ) -> (Vec<u8>, String) {
        let mut destination = Destination::new(
            Some(identity),
            rns_identity::destination::Direction::In,
            rns_identity::destination::DestType::Single,
            aspect,
        )
        .unwrap();
        let raw = destination
            .announce_packet(identity, app_data, None, false, None, now_f64())
            .unwrap();
        (raw, hex::encode(destination.hash))
    }

    fn propagation_node_announce(node: &Identity) -> (Vec<u8>, String) {
        lxmf_announce(node, "lxmf.propagation", None)
    }

    /// A standalone Reticulum with no interfaces, whose control plane is its
    /// own transport.
    async fn standalone_reticulum(dir: &Path) -> (ReticulumHandle, ShutdownSignal) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("config"),
            "[reticulum]\nshare_instance = No\nenable_transport = No\n\
             respond_to_probes = No\npanic_on_interface_error = No\n\
             discover_interfaces = No\n\n[interfaces]\n",
        )
        .unwrap();
        let shutdown = ShutdownSignal::new();
        let handle = rns_runtime::reticulum::init(
            Some(dir.to_str().unwrap()),
            None,
            shutdown.clone(),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        )
        .await
        .unwrap();
        (handle, shutdown)
    }

    /// Python's router retains a destination's announce data once a message
    /// to it is delivered (LXMRouter.py), on the shared instance when
    /// attached to one (Reticulum.py).
    #[tokio::test]
    async fn delivered_destinations_are_retained_through_the_control_plane() {
        let temp = tempfile::tempdir().unwrap();
        let (reticulum, shutdown) = standalone_reticulum(&temp.path().join("rns")).await;
        let recipient = Identity::new();
        let (announce, recipient_hex) = lxmf_announce(&recipient, DELIVERY_APP_NAME, None);
        let _driver = hear(&reticulum.transport_tx, 9001, &announce).await;
        let recipient_hash: [u8; 16] = hex::decode(&recipient_hex).unwrap().try_into().unwrap();
        let lxmf_dir = temp.path().join("lxmf");
        initialize_storage_namespace(&lxmf_dir).unwrap();
        let mut runner = LxmdRunner::new(
            DaemonConfig::default(),
            &lxmf_dir,
            reticulum.transport_tx.clone(),
            None,
        )
        .unwrap();
        runner.control_plane = Some(reticulum.clone());
        let delivered = LxMessageDraft::new(
            recipient_hash,
            runner.lxmf_dest_hash,
            "",
            "delivered",
            DeliveryMethod::Opportunistic,
        )
        .unwrap()
        .sign(&runner.identity.get_signing_key().unwrap())
        .unwrap()
        .finalize(None)
        .unwrap();
        runner.router.complete_outbound_message(delivered);

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            runner.tick();
            tokio::time::sleep(Duration::from_millis(20)).await;
            let retained = match reticulum
                .query_transport(TransportQuery::GetRecentAnnounces)
                .await
            {
                Some(TransportQueryResponse::Announces(announces)) => announces
                    .iter()
                    .any(|entry| entry.dest_hash == recipient_hash && entry.retained),
                _ => false,
            };
            if retained {
                break;
            }
            assert!(Instant::now() < deadline, "the recipient is retained");
        }
        shutdown.trigger();
    }

    #[test]
    fn received_ratchet_files_of_earlier_releases_are_removed() {
        let temp = tempfile::tempdir().unwrap();
        let rns = temp.path().join("rns");
        let paths = LxmdPaths::new(temp.path().join("lxmd"));
        let received = &paths.legacy_received_ratchets_dir;
        std::fs::create_dir_all(received).unwrap();
        let import_dir = rns.join("storage/ratchets");
        std::fs::create_dir_all(&import_dir).unwrap();
        let destination = hex::encode([0x11; 16]);
        std::fs::write(received.join(format!("{destination}.ratchet")), b"earlier").unwrap();
        std::fs::write(received.join("notes.txt"), b"not a ratchet").unwrap();
        std::fs::write(import_dir.join(&destination), b"reticulum's own").unwrap();
        std::fs::write(&paths.legacy_known_identities_path, [0u8; 80]).unwrap();
        std::fs::write(&paths.ratchet_ring_path, b"own keys").unwrap();

        remove_earlier_ratchet_files(&paths).unwrap();

        assert!(!received.exists());
        assert!(!paths.legacy_known_identities_path.exists());
        assert_eq!(
            std::fs::read(&paths.ratchet_ring_path).unwrap(),
            b"own keys"
        );
        // Reticulum's own legacy files are its import's, not this one's.
        assert_eq!(
            std::fs::read(import_dir.join(&destination)).unwrap(),
            b"reticulum's own"
        );
        // Nothing left to remove.
        remove_earlier_ratchet_files(&paths).unwrap();
    }

    /// A recipient's delivery announce, with `ratchet` as its ratchet key, emitted at `emitted`.
    fn recipient_announce(
        recipient: &Identity,
        ratchet: Option<&[u8; 32]>,
        emitted: f64,
    ) -> (Vec<u8>, [u8; 16]) {
        let mut destination = Destination::new(
            Some(recipient),
            rns_identity::destination::Direction::In,
            rns_identity::destination::DestType::Single,
            DELIVERY_APP_NAME,
        )
        .unwrap();
        let raw = destination
            .announce_packet(recipient, None, ratchet, false, None, emitted)
            .unwrap();
        (raw, destination.hash)
    }

    /// Reticulum hears `announce` and the recipient's destination becomes recallable.
    async fn hear_and_recall(
        reticulum: &ReticulumHandle,
        announce: &[u8],
        recipient_hash: [u8; 16],
        ratchet: Option<[u8; 32]>,
    ) -> mpsc::Receiver<Bytes> {
        let driver = hear(&reticulum.transport_tx, 9001, announce).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(
            reticulum
                .query_transport(TransportQuery::RecallDestination {
                    dest: recipient_hash
                })
                .await,
            Some(TransportQueryResponse::RecalledDestination(Some(ref recalled)))
                if recalled.ratchet == ratchet
        ) {
            assert!(
                Instant::now() < deadline,
                "Reticulum validates the announce"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        driver
    }

    /// Submit a message to the recipient and encrypt it as a tick does.
    async fn encrypt_next_message(
        runner: &mut LxmdRunner,
        recipient_hash: [u8; 16],
        content: &str,
    ) -> Vec<u8> {
        let message = LxMessageDraft::new(
            recipient_hash,
            runner.lxmf_dest_hash,
            "",
            content,
            DeliveryMethod::Opportunistic,
        )
        .unwrap()
        .sign(&runner.identity.get_signing_key().unwrap())
        .unwrap();
        runner.router.submit_signed(message).unwrap();
        runner.refresh_outbound_medium().await;
        runner
            .encrypt_for_destination(&hex::encode(recipient_hash), content.as_bytes())
            .expect("recipient key recalled from Reticulum")
    }

    /// Reticulum hears the recipient's announce and stops. After a restart in
    /// which nothing is heard, the daemon must encrypt for the recipient with
    /// `ratchet`.
    #[tokio::test]
    async fn a_ratchet_learned_before_a_restart_encrypts_the_next_message() {
        let temp = tempfile::tempdir().unwrap();
        let rns = temp.path().join("rns");
        let lxmf_dir = temp.path().join("lxmf");
        initialize_storage_namespace(&lxmf_dir).unwrap();
        let recipient = Identity::new();
        let ratchet_key = rns_crypto::x25519::X25519PrivateKey::generate().to_bytes();
        let ratchet = rns_identity::ratchet::ratchet_public_bytes(&ratchet_key);
        let (announce, recipient_hash) = recipient_announce(&recipient, Some(&ratchet), now_f64());

        let (reticulum, _shutdown) = standalone_reticulum(&rns).await;
        let _driver = hear_and_recall(&reticulum, &announce, recipient_hash, Some(ratchet)).await;
        reticulum.shutdown_and_wait().await;

        let (reticulum, _shutdown) = standalone_reticulum(&rns).await;
        let mut runner = LxmdRunner::new(
            DaemonConfig::default(),
            &lxmf_dir,
            reticulum.transport_tx.clone(),
            None,
        )
        .unwrap();
        // Before Reticulum has answered for this tick nothing is encrypted.
        assert!(
            runner
                .encrypt_for_destination(&hex::encode(recipient_hash), b"x")
                .is_none()
        );
        let ciphertext =
            encrypt_next_message(&mut runner, recipient_hash, "after the restart").await;
        assert_eq!(
            runner.outbound_ratchets.get(&recipient_hash),
            Some(&Some(ratchet))
        );
        // Enforcing ratchets, the recipient opens it only with that ratchet key.
        let opened = recipient
            .decrypt_with_ratchet_id(&ciphertext, Some(&[&ratchet_key]), true)
            .unwrap();
        assert_eq!(opened.plaintext, b"after the restart");
        assert!(opened.ratchet_id.is_some());
        reticulum.shutdown_and_wait().await;
    }

    /// An earlier release kept the recipient's ratchet in its own file, which
    /// Reticulum, as upstream, does not import: the file goes at the next
    /// start, a message sent before the recipient announces again is encrypted
    /// to its identity key, and the next announce's ratchet encrypts the one after.
    #[tokio::test]
    async fn an_earlier_release_ratchet_file_goes_and_the_next_announce_brings_the_ratchet() {
        let temp = tempfile::tempdir().unwrap();
        let rns = temp.path().join("rns");
        let lxmf_dir = temp.path().join("lxmf");
        initialize_storage_namespace(&lxmf_dir).unwrap();
        let recipient = Identity::new();
        let emitted = now_f64();
        let (announce, recipient_hash) = recipient_announce(&recipient, None, emitted);

        let (reticulum, _shutdown) = standalone_reticulum(&rns).await;
        let _driver = hear_and_recall(&reticulum, &announce, recipient_hash, None).await;
        reticulum.shutdown_and_wait().await;

        let paths = LxmdPaths::new(&lxmf_dir);
        std::fs::create_dir_all(&paths.legacy_received_ratchets_dir).unwrap();
        let earlier_key = rns_crypto::x25519::X25519PrivateKey::generate().to_bytes();
        rns_identity::ratchet::ReceivedRatchet::new(rns_identity::ratchet::ratchet_public_bytes(
            &earlier_key,
        ))
        .save(
            &paths
                .legacy_received_ratchets_dir
                .join(format!("{}.ratchet", hex::encode(recipient_hash))),
        )
        .unwrap();
        remove_earlier_ratchet_files(&paths).unwrap();
        assert!(!paths.legacy_received_ratchets_dir.exists());

        let (reticulum, _shutdown) = standalone_reticulum(&rns).await;
        let mut runner = LxmdRunner::new(
            DaemonConfig::default(),
            &lxmf_dir,
            reticulum.transport_tx.clone(),
            None,
        )
        .unwrap();
        let ciphertext =
            encrypt_next_message(&mut runner, recipient_hash, "before it announces").await;
        assert_eq!(runner.outbound_ratchets.get(&recipient_hash), Some(&None));
        assert!(
            recipient
                .decrypt_with_ratchet_id(&ciphertext, Some(&[&earlier_key]), true)
                .is_err(),
            "the earlier release's ratchet is not used"
        );
        let opened = recipient
            .decrypt_with_ratchet_id(&ciphertext, None, false)
            .unwrap();
        assert_eq!(opened.plaintext, b"before it announces");
        assert!(opened.ratchet_id.is_none(), "encrypted to the identity key");

        let ratchet_key = rns_crypto::x25519::X25519PrivateKey::generate().to_bytes();
        let ratchet = rns_identity::ratchet::ratchet_public_bytes(&ratchet_key);
        // A later second: Reticulum's prefilter drops a same-second re-announce on the same path.
        let (announce, _) = recipient_announce(&recipient, Some(&ratchet), emitted + 1.0);
        let _driver = hear_and_recall(&reticulum, &announce, recipient_hash, Some(ratchet)).await;
        let ciphertext =
            encrypt_next_message(&mut runner, recipient_hash, "after it announces").await;
        let opened = recipient
            .decrypt_with_ratchet_id(&ciphertext, Some(&[&ratchet_key]), true)
            .unwrap();
        assert_eq!(opened.plaintext, b"after it announces");
        assert!(opened.ratchet_id.is_some());
        reticulum.shutdown_and_wait().await;
    }

    /// Python's LXMF recalls identities that Transport validated before the
    /// router registered its handlers (Transport.py, Identity.recall).
    #[tokio::test]
    async fn identities_validated_before_the_daemon_subscribed_are_learned() {
        let node = Identity::new();
        let (announce, node_hex) = propagation_node_announce(&node);
        let (tx, _driver) = transport_that_heard(&announce).await;
        let temp = tempfile::tempdir().unwrap();
        initialize_storage_namespace(temp.path()).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        assert!(!runner.known_identities.contains_key(&node_hex));

        runner.learn_validated_identities().await;

        assert_eq!(
            runner.known_identities.get(&node_hex),
            Some(&node.get_public_key())
        );
    }

    /// Python `LXMPeer.sync()`: with no path a sync requests one and waits
    /// `PATH_REQUEST_GRACE`; a path still missing defers the sync without a link.
    #[tokio::test]
    async fn peer_sync_without_a_path_requests_one_and_backs_off_without_a_link() {
        let temp = tempfile::tempdir().unwrap();
        initialize_storage_namespace(temp.path()).unwrap();
        let (tx, mut rx) = mpsc::channel(1024);
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        while rx.try_recv().is_ok() {}
        let peer_hash = [0x77; 16];
        let mut peer = LxmPeer::new(peer_hash);
        peer.alive = true;
        peer.last_heard = now_f64();
        peer.stamp_cost = Some(0.0);
        peer.stamp_cost_flexibility = Some(0.0);
        peer.peering_cost = 0.0;
        peer.add_unhandled_message(&[0x31; 32]);
        runner.router.peers.insert(peer_hash, peer);

        let answer_no_path = |rx: &mut mpsc::Receiver<TransportMessage>| {
            let mut requested_path = false;
            while let Ok(message) = rx.try_recv() {
                match message {
                    TransportMessage::Rpc {
                        query: TransportQuery::HasPath { dest },
                        response_tx,
                    } if dest == peer_hash => {
                        let _ = response_tx.send(TransportQueryResponse::BoolResult(false));
                    }
                    TransportMessage::RequestPath { destination_hash } => {
                        assert_eq!(destination_hash, peer_hash);
                        requested_path = true;
                    }
                    TransportMessage::SendLinkRequest { .. } => {
                        panic!("link opened without a path")
                    }
                    _ => {}
                }
            }
            requested_path
        };

        let now = now_f64();
        runner.attempt_peer_sync(peer_hash, now);
        assert!(!answer_no_path(&mut rx));
        runner.drive_peer_path_checks(now);
        assert!(answer_no_path(&mut rx), "a path request is sent");
        assert!(runner.peer_syncs.is_empty());

        runner.drive_peer_path_checks(now + 1.0);
        assert!(
            runner.peer_path_checks.contains_key(&peer_hash),
            "still within the grace"
        );
        let after_grace = now + lxmf_core::constants::PATH_REQUEST_GRACE;
        runner.drive_peer_path_checks(after_grace);
        answer_no_path(&mut rx);
        runner.drive_peer_path_checks(after_grace);
        assert!(runner.peer_syncs.is_empty());
        let peer = &runner.router.peers[&peer_hash];
        assert!(!peer.alive);
        assert_eq!(
            peer.sync_backoff,
            lxmf_core::constants::SYNC_BACKOFF_STEP as f64
        );
        assert!(!answer_no_path(&mut rx));
    }

    /// Python `propagation_resource_concluded()` peers with an unpeered sender
    /// whose recalled announce shows an enabled propagation node.
    #[tokio::test]
    async fn sync_from_unpeered_propagation_node_autopeers_from_recalled_announce() {
        let node = Identity::new();
        let app_data =
            propagation_announce_app_data(&lxmf_core::handlers::PropagationNodeAnnounceData::new(
                true, 256, 10240, 16.0, 3.0, 18.0,
            ));
        let (announce, node_hex) = lxmf_announce(&node, "lxmf.propagation", Some(&app_data));
        let (tx, _driver) = transport_that_heard(&announce).await;
        let temp = tempfile::tempdir().unwrap();
        initialize_storage_namespace(temp.path()).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        let node_hash: [u8; 16] = hex::decode(&node_hex).unwrap().try_into().unwrap();

        runner.recall_sync_autopeer(node_hash);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !runner.router.peers.contains_key(&node_hash) {
            assert!(Instant::now() < deadline, "the sending node is peered");
            runner.drain_sync_autopeer_recalls();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(runner.router.peers[&node_hash].autopeered);
    }

    /// `propagation_resource_concluded()` reads `Transport.hops_to`: the hops of
    /// the remembered announce, which a restored destination may not carry,
    /// decide nothing.
    #[tokio::test]
    async fn sync_autopeering_goes_by_the_path_hops_not_the_recalled_announce() {
        let app_data =
            propagation_announce_app_data(&lxmf_core::handlers::PropagationNodeAnnounceData::new(
                true, 256, 10240, 16.0, 3.0, 18.0,
            ));
        // (hops of the path, hops of the recalled announce and whether known, peered)
        let cases = [
            (rns_transport::constants::PATHFINDER_M, 0, false, false),
            (rns_transport::constants::PATHFINDER_M, 1, true, false),
            (2, 0, false, true),
            (2, 9, true, true),
        ];
        for (path_hops, announce_hops, hops_known, peered) in cases {
            let node = Identity::new();
            let node_hash = [path_hops, announce_hops, u8::from(hops_known), 7].repeat(4);
            let node_hash: [u8; 16] = node_hash.try_into().unwrap();
            let temp = tempfile::tempdir().unwrap();
            initialize_storage_namespace(temp.path()).unwrap();
            let (tx, mut rx) = mpsc::channel(64);
            let mut runner =
                LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
            while rx.try_recv().is_ok() {}

            runner.recall_sync_autopeer(node_hash);
            runner.drain_sync_autopeer_recalls();
            assert!(runner.router.peers.is_empty(), "nothing is answered yet");
            let mut asked = Vec::new();
            while let Ok(message) = rx.try_recv() {
                let TransportMessage::Rpc { query, response_tx } = message else {
                    continue;
                };
                match query {
                    TransportQuery::RecallDestination { dest } if dest == node_hash => {
                        let mut entry =
                            rns_transport::messages::RecalledDestinationRpcEntry::default();
                        entry.dest_hash = node_hash;
                        entry.public_key = node.get_public_key();
                        entry.app_data = Some(app_data.clone());
                        entry.hops = announce_hops;
                        entry.hops_known = hops_known;
                        let _ = response_tx
                            .send(TransportQueryResponse::RecalledDestination(Some(entry)));
                        asked.push("recall");
                    }
                    TransportQuery::HopsTo { dest } if dest == node_hash => {
                        let _ = response_tx
                            .send(TransportQueryResponse::IntResult(i64::from(path_hops)));
                        asked.push("hops");
                    }
                    _ => {}
                }
            }
            assert_eq!(asked, ["recall", "hops"]);
            runner.drain_sync_autopeer_recalls();
            assert!(runner.sync_autopeer_recalls.is_empty());
            assert_eq!(
                runner.router.peers.contains_key(&node_hash),
                peered,
                "path hops {path_hops}, announce hops {announce_hops} (known: {hops_known})"
            );
        }
    }

    /// A destination restored from a store that does not carry its announce's
    /// facts has a placeholder name hash. Its aspect is read from its
    /// destination hash, so an LXMF identity heard before the restart is kept
    /// and another destination of the same identity is not.
    #[tokio::test]
    async fn a_listed_destination_with_unknown_facts_is_matched_by_its_hash() {
        let identity = Identity::new();
        let destination =
            |aspect: &str| Destination::hash_from_name_and_identity(aspect, Some(&identity.hash));
        let entry = |dest_hash: [u8; 16], name_hash: [u8; 10], facts_known: bool| {
            let mut entry = rns_transport::messages::AnnounceRpcEntry::default();
            entry.dest_hash = dest_hash;
            entry.public_key = Some(identity.get_public_key());
            entry.name_hash = name_hash;
            entry.facts_known = facts_known;
            entry
        };
        let delivery = rns_identity::name_hash::name_hash(DELIVERY_APP_NAME);
        let propagation = rns_identity::name_hash::name_hash("lxmf.propagation");
        let other = rns_identity::name_hash::name_hash("nomadnetwork.node");
        let unknown = [0u8; 10];
        let listed = vec![
            // Heard this session: taken at the announce's word.
            (entry([1; 16], delivery, true), true),
            (entry([2; 16], propagation, true), true),
            (entry([3; 16], other, true), false),
            (entry(destination(DELIVERY_APP_NAME), unknown, true), false),
            // Restored without facts: matched by destination hash.
            (entry(destination(DELIVERY_APP_NAME), unknown, false), true),
            (entry(destination("lxmf.propagation"), unknown, false), true),
            (
                entry(destination("nomadnetwork.node"), unknown, false),
                false,
            ),
            (entry([4; 16], delivery, false), false),
        ];
        for (announce, lxmf) in &listed {
            assert_eq!(
                is_lxmf_destination(announce, &identity.get_public_key()),
                *lxmf,
                "{} (facts known: {})",
                hex::encode(announce.dest_hash),
                announce.facts_known
            );
        }

        let temp = tempfile::tempdir().unwrap();
        initialize_storage_namespace(temp.path()).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        while rx.try_recv().is_ok() {}
        let mut expected: Vec<String> = listed
            .iter()
            .filter(|(_, lxmf)| *lxmf)
            .map(|(announce, _)| hex::encode(announce.dest_hash))
            .collect();
        expected.sort();
        expected.dedup();
        let announces = listed.into_iter().map(|(announce, _)| announce).collect();
        let responder = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let TransportMessage::Rpc {
                    query: TransportQuery::GetRecentAnnounces,
                    response_tx,
                } = message
                {
                    let _ = response_tx.send(TransportQueryResponse::Announces(announces));
                    return;
                }
            }
        });
        runner.learn_validated_identities().await;
        responder.await.unwrap();
        let mut learned: Vec<String> = runner.known_identities.keys().cloned().collect();
        learned.sort();
        assert_eq!(learned, expected);
    }

    /// A propagation node the daemon never heard announced is recalled from
    /// Transport before the download, as Python's LXMF does
    /// (LXMRouter.request_messages_from_propagation_node, Identity.recall).
    #[tokio::test]
    async fn a_missing_propagation_node_identity_is_recalled_from_transport() {
        let node = Identity::new();
        let (announce, node_hex) = propagation_node_announce(&node);
        let (tx, _driver) = transport_that_heard(&announce).await;
        let temp = tempfile::tempdir().unwrap();
        initialize_storage_namespace(temp.path()).unwrap();
        let mut config = DaemonConfig::default();
        config.outbound_propagation_node = Some(node_hex.clone());
        let mut runner = LxmdRunner::new(config, temp.path(), tx, None).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !runner.known_identities.contains_key(&node_hex) {
            assert!(Instant::now() < deadline, "the node's identity is recalled");
            runner.tick();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(runner.known_identities[&node_hex], node.get_public_key());
    }

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
        std::fs::remove_dir_all(&restarted.ratchets_dir).unwrap();
        assert!(restarted.save_crypto_state().is_err());
        assert!(!restarted.ratchets_dir.exists());
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
        let data_dir = runner.data_dir.clone();
        runner.router.load_state(&data_dir).unwrap();
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
        runner.handle_link_delivered_data_on(message.wire_bytes(), None);
        assert!(runner.router.get_outbound_ticket(&source).is_none());
        runner
            .known_identities
            .insert(hex::encode(source), sender.get_public_key());
        let mut invalid = message.wire_bytes().to_vec();
        invalid[32] ^= 1;
        runner.handle_link_delivered_data_on(&invalid, None);
        assert!(runner.router.get_outbound_ticket(&source).is_none());

        // The exact duplicate is authenticated after identity recall and must
        // still teach the ticket, without producing another delivery event.
        runner.handle_link_delivered_data_on(message.wire_bytes(), None);
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

        let archived = runner.messages_dir.join(hex::encode(message.message_id()));
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
    async fn a_directly_connected_peer_keeps_its_zero_hop_distance() {
        let temp = tempfile::tempdir().unwrap();
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(64);
        initialize_storage_namespace(temp.path()).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        let neighbour = [0x0D; 16];
        let responder = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let TransportMessage::Rpc {
                    query: TransportQuery::GetPathTable,
                    response_tx,
                } = message
                {
                    let mut entry = rns_transport::messages::PathTableRpcEntry::default();
                    entry.hash = neighbour;
                    entry.timestamp = now_f64();
                    entry.via = Some(neighbour);
                    entry.hops = 0;
                    entry.expires = now_f64() + 600.0;
                    entry.value = None;
                    entry.used = 0.0;
                    entry.lr_cost = None;
                    entry.interface = String::new();
                    entry.interface_id = 1;
                    entry.interface_mode = rns_transport::constants::InterfaceMode::Full;
                    entry.interface_role = Default::default();
                    let _ = response_tx.send(TransportQueryResponse::PathTable(vec![entry]));
                    return;
                }
            }
        });
        runner.refresh_route_hops_from_transport().await;
        responder.abort();
        // Transport.hops_to reports the path table's hop count unchanged.
        assert_eq!(runner.route_hops.get(&neighbour), Some(&0));
    }

    #[tokio::test]
    async fn outbound_compression_support_comes_from_recalled_app_data_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(64);
        initialize_storage_namespace(temp.path()).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        while rx.try_recv().is_ok() {}
        let recipient = Identity::new();
        let recipient_hash = [0x7E; 16];
        let draft = LxMessageDraft::new(
            recipient_hash,
            runner.lxmf_dest_hash,
            "",
            "after restart",
            DeliveryMethod::Direct,
        )
        .unwrap();
        runner
            .router
            .submit_signed(
                draft
                    .sign(&runner.identity.get_signing_key().unwrap())
                    .unwrap(),
            )
            .unwrap();
        assert!(runner.router.compression_supported(&recipient_hash));

        runner.recall_outbound_app_data();
        let mut answered = false;
        while let Ok(message) = rx.try_recv() {
            if let TransportMessage::Rpc {
                query: TransportQuery::RecallDestination { dest },
                response_tx,
            } = message
                && dest == recipient_hash
            {
                // Announce app data whose feature list lacks SF_COMPRESSION.
                let mut entry = rns_transport::messages::RecalledDestinationRpcEntry::default();
                entry.dest_hash = recipient_hash;
                entry.public_key = recipient.get_public_key();
                entry.app_data = Some(vec![0x93, 0xc4, 0x01, b'n', 0xc0, 0x90]);
                entry.ratchet = None;
                entry.hops = 1;
                entry.timestamp = now_f64();
                let _ = response_tx.send(TransportQueryResponse::RecalledDestination(Some(entry)));
                answered = true;
            }
        }
        assert!(
            answered,
            "outbound processing recalls the destination's app data"
        );
        runner.drain_identity_recalls();
        assert!(!runner.router.compression_supported(&recipient_hash));
    }

    #[tokio::test]
    async fn an_opportunistic_message_records_its_ratchet_and_packet_phy_stats() {
        let temp = tempfile::tempdir().unwrap();
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(64);
        initialize_storage_namespace(temp.path()).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        if runner
            .delivery_ratchets
            .ring()
            .current_public_key()
            .is_none()
        {
            let _ = runner.create_announce_packet(DeliveryAnnounceKind::Broadcast, None);
        }
        let ratchet_pub = runner
            .delivery_ratchets
            .ring()
            .current_public_key()
            .expect("delivery ratchet");
        let seen = Arc::new(Mutex::new(None));
        let observed = Arc::clone(&seen);
        runner.router.register_delivery_callback(move |message| {
            *observed.lock().unwrap() = Some((
                message.ratchet_id.clone(),
                message.rssi,
                message.snr,
                message.q,
            ));
        });
        let message = signed_fixture(
            runner.lxmf_dest_hash,
            [0xCE; 16],
            "",
            "ratchet",
            DeliveryMethod::Opportunistic,
        );
        let packed = message.pack().unwrap();
        let ciphertext = runner
            .identity
            .encrypt(&packed[16..], Some(&ratchet_pub))
            .unwrap();
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

        while rx.try_recv().is_ok() {}
        let packet_hash =
            rns_wire::hash::packet_hash(&packet, rns_wire::flags::HeaderType::Header1);
        let responder = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let TransportMessage::Rpc { query, response_tx } = message {
                    let value = match query {
                        TransportQuery::GetPacketRssi { packet_hash: h } if h == packet_hash => {
                            Some(-91.0)
                        }
                        TransportQuery::GetPacketSnr { packet_hash: h } if h == packet_hash => {
                            Some(4.5)
                        }
                        TransportQuery::GetPacketQ { packet_hash: h } if h == packet_hash => None,
                        _ => continue,
                    };
                    let _ = response_tx.send(TransportQueryResponse::FloatResult(value));
                }
            }
        });
        let phy = runner.inbound_packet_phy(&packet).await;
        responder.abort();
        runner.handle_inbound_packet(&packet, phy);

        assert_eq!(
            seen.lock().unwrap().clone(),
            Some((
                Some(Identity::ratchet_id(&ratchet_pub).to_vec()),
                Some(-91.0),
                Some(4.5),
                None
            ))
        );
    }

    #[tokio::test]
    async fn a_propagated_message_fails_when_the_node_cost_stays_unknown() {
        let temp = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel::<TransportMessage>(64);
        initialize_storage_namespace(temp.path()).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        let node_hash = [0x5B; 16];
        let recipient = [0x6C; 16];
        for hash in [node_hash, recipient] {
            runner
                .known_identities
                .insert(hex::encode(hash), Identity::new().get_public_key());
        }
        runner.medium.routes.insert(
            node_hash,
            RouteInfo {
                hops: 1,
                first_hop_timeout: 6.0,
            },
        );
        runner.router.outbound_propagation_node = Some(node_hash);
        let draft = LxMessageDraft::new(
            recipient,
            runner.lxmf_dest_hash,
            "",
            "no node cost",
            DeliveryMethod::Propagated,
        )
        .unwrap();
        runner
            .router
            .submit_signed(
                draft
                    .sign(&runner.identity.get_signing_key().unwrap())
                    .unwrap(),
            )
            .unwrap();
        let id = runner.router.pending_outbound[0].message_id();

        assert!(runner.prepare_propagation_envelopes().contains(&id));
        assert_eq!(runner.router.pending_outbound.len(), 1);
        // The path_request_wait deadline passes with no announce carrying the cost.
        *runner.node_cost_deadlines.get_mut(&id).unwrap() = now_f64() - 1.0;
        runner.prepare_propagation_envelopes();
        assert!(runner.router.pending_outbound.is_empty());
    }

    #[tokio::test]
    async fn propagated_readiness_needs_a_current_transport_path_to_the_node() {
        let temp = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel::<TransportMessage>(64);
        initialize_storage_namespace(temp.path()).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        let node = Identity::new();
        let node_hash = [0x5A; 16];
        runner
            .known_identities
            .insert(hex::encode(node_hash), node.get_public_key());
        // A cached hop count outlives the transport path it was learned from.
        runner.route_hops.insert(node_hash, 1);
        let message = signed_fixture(
            [0x6B; 16],
            runner.lxmf_dest_hash,
            "",
            "propagated",
            DeliveryMethod::Propagated,
        );
        assert!(matches!(
            runner.pack_message_for_propagation(&message, node_hash),
            Err(PropagationPreparationError::Missing(
                MissingPropagationInput::NodePath
            ))
        ));
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
        let config = DaemonConfig::from_config(&config).unwrap();
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

    #[tokio::test]
    async fn announce_request_bursts_are_bounded_and_do_not_hold_link_events() {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (link_tx, mut link_rx) = mpsc::channel(16);
        let (announce_tx, mut announce_rx) = mpsc::channel(DELIVERY_ANNOUNCE_BACKLOG);
        let forwarder = tokio::spawn(forward_delivery_events(events_rx, link_tx, announce_tx));

        // Nothing drains the announce backlog while the burst arrives.
        for tag in 0..(DELIVERY_ANNOUNCE_BACKLOG as u32 * 4) {
            let mut request = AnnounceRequest::normal(DELIVERY_APP_NAME.to_string());
            request.path_response = true;
            request.tag = Some(tag.to_be_bytes().to_vec());
            events_tx
                .send(DestinationEvent::AnnounceRequested(request))
                .await
                .unwrap();
        }
        events_tx
            .send(DestinationEvent::LinkEstablished { link_id: [7; 16] })
            .await
            .unwrap();
        assert!(matches!(
            link_rx.recv().await,
            Some(DestinationEvent::LinkEstablished { link_id }) if link_id == [7; 16]
        ));

        drop(events_tx);
        forwarder.await.unwrap();
        let mut kept = Vec::new();
        while let Some(request) = announce_rx.recv().await {
            kept.push(request.tag.unwrap());
        }
        // The oldest requests are kept, in order; the overflow is dropped.
        assert_eq!(kept.len(), DELIVERY_ANNOUNCE_BACKLOG);
        assert_eq!(kept[0], 0u32.to_be_bytes());
        assert_eq!(kept[1], 1u32.to_be_bytes());
    }

    #[test]
    fn propagation_accounting_counts_duplicates_and_distributes_only_new_entries() {
        let peer_hash = [0x21; 16];
        let first_id = [0x31; 32];
        let second_id = [0x32; 32];
        let mut router = LxmRouter::new(Default::default());
        router.peers.insert(peer_hash, LxmPeer::new(peer_hash));
        let mut distribution = Vec::new();

        apply_propagation_store_commit(
            &mut router,
            None,
            &mut distribution,
            PropagationStoreCommitResult {
                origin: PropagationStoreWriteOrigin::Peer(peer_hash),
                accounted: vec![(first_id, 120), (second_id, 180)],
                committed: vec![(first_id, 120)],
            },
        );
        let peer = router.peers.get(&peer_hash).unwrap();
        assert_eq!(peer.incoming, 2);
        assert_eq!(peer.rx_bytes, 300);
        assert!(peer.handled_messages.contains(&first_id));
        assert!(peer.handled_messages.contains(&second_id));
        assert_eq!(distribution, vec![(first_id, Some(peer_hash))]);
        assert!(router.propagation_store.is_locally_processed(&first_id));

        apply_propagation_store_commit(
            &mut router,
            None,
            &mut distribution,
            PropagationStoreCommitResult {
                origin: PropagationStoreWriteOrigin::Client,
                accounted: vec![([0x41; 32], 64), ([0x41; 32], 64)],
                committed: vec![([0x41; 32], 64)],
            },
        );
        assert_eq!(router.client_propagation_messages_received, 2);
        assert_eq!(distribution.last(), Some(&([0x41; 32], None)));
    }

    #[tokio::test]
    async fn a_locally_processed_id_is_a_duplicate_for_propagation_intake_at_once() {
        let temp = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel::<TransportMessage>(64);
        initialize_storage_namespace(temp.path()).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), temp.path(), tx, None).unwrap();
        let node = Arc::new(Mutex::new(
            PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                [0xAA; 16],
                temp.path().join("store"),
            )
            .unwrap(),
        ));
        runner.propagation_node = Some(Arc::clone(&node));
        let mut blob = vec![0x42; 16 + 64];
        let transient_id = rns_crypto::sha::full_hash(&blob);
        blob.extend_from_slice(&[0; 32]);
        runner
            .router
            .propagation_store
            .claim_processed(transient_id, now_f64());

        runner.share_processed_claim(transient_id);

        let blob =
            lxmf_core::propagation_node::ValidatedOpaquePropagationBlob::validate(blob.into(), 0.0)
                .unwrap();
        assert!(matches!(
            node.lock().unwrap().plan_opaque_admission(blob),
            lxmf_core::propagation_node::PropagationAdmission::AlreadyProcessed
        ));
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

        dispatch_opportunistic_packet(
            &tx,
            raw,
            destination_hash,
            public_key,
            message_hash,
            Duration::from_secs(12),
        )
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
            dispatch_opportunistic_packet(
                &tx,
                vec![0; 64],
                [2; 16],
                [3; 64],
                [4; 32],
                Duration::from_secs(12)
            )
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

        let response = queue_control_command(&tx, ControlCommand::Sync(peer_hash)).unwrap();

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
    fn control_command_is_unanswered_when_daemon_queue_is_closed() {
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);

        assert!(queue_control_command(&tx, ControlCommand::Sync([0x24; 16])).is_none());
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

    fn unpack_announce(
        raw: &[u8],
    ) -> (
        rns_wire::header::PacketHeader,
        rns_identity::announce::AnnounceData,
    ) {
        let (header, header_len) = rns_wire::header::PacketHeader::unpack(raw).unwrap();
        let announce = rns_identity::announce::AnnounceData::unpack(
            &raw[header_len..],
            header.flags.context_flag,
        )
        .unwrap();
        (header, announce)
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
        let (tx, _rx) = mpsc::channel(64);
        initialize_storage_namespace(&temp).unwrap();
        let mut runner = LxmdRunner::new(DaemonConfig::default(), &temp, tx, None).unwrap();
        // Announce scheduling needs no propagation runtime, only its config
        // and the two destinations' command channels.
        runner.config.propagation_enabled = true;
        runner.config.node_announce_interval = Some(60);
        runner.router.allowed_control.push([0x55; 16]);
        let (node_tx, mut node_rx) = mpsc::channel(8);
        let (control_tx, mut control_rx) = mpsc::channel(8);
        runner.prop_link_command_tx = Some(node_tx);
        runner.control_link_command_tx = Some(control_tx);
        let (node, control) = (runner.propagation_dest_hash, runner.control_dest_hash);
        let mut staged = || {
            let mut out = Vec::new();
            while let Ok(LinkManagerCommand::Announce) = node_rx.try_recv() {
                out.push(node);
            }
            while let Ok(LinkManagerCommand::Announce) = control_rx.try_recv() {
                out.push(control);
            }
            out
        };
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
        runner.announce_jobs(now_f64());
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
        .map(|config| DaemonConfig::from_config(&config).unwrap())
        .unwrap()
        .delivery_transfer_max_accepted_size;
        assert_eq!(explicit_limit, 1000.0);
        assert!(accepts_delivery_resource(4_114, explicit_limit));
        assert!(accepts_delivery_resource(1_000_000, explicit_limit));
        assert!(!accepts_delivery_resource(1_000_001, explicit_limit));

        assert!(accepts_delivery_resource(380, 0.38));
        assert!(!accepts_delivery_resource(381, 0.38));

        assert_eq!(configured_kilobytes_to_bytes(1.0), 1_000);
        assert_eq!(configured_kilobytes_to_bytes(0.5), 500);
        assert_eq!(configured_kilobytes_to_bytes(10_240.0), 10_240_000);
        assert_eq!(configured_kilobytes_to_bytes(f64::MAX), usize::MAX);
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
            let mut config = DaemonConfig::default();
            config.stamp_cost = Some(12.0);
            config.enforce_stamps = enforce_stamps;
            initialize_storage_namespace(&temp).unwrap();
            let mut runner = LxmdRunner::new(config, &temp, tx, None).expect("runner");
            let raw = runner
                .create_announce_packet(DeliveryAnnounceKind::Broadcast, None)
                .expect("delivery announce");
            let (_, announce) = unpack_announce(&raw);
            let (_, stamp_cost) = lxmf_core::handlers::parse_announce_app_data(
                announce.app_data.as_deref().expect("delivery app data"),
            )
            .expect("valid delivery app data");
            assert_eq!(stamp_cost, Some(12.0));
            drop(runner);
            let _ = std::fs::remove_dir_all(&temp);
        }
    }

    /// Blackhole gating mirrors LXMessage.py: only a recallable source
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

    #[test]
    fn prune_known_identities_keeps_the_working_copy_under_its_cap() {
        let mut ids: HashMap<String, [u8; 64]> = HashMap::new();
        for i in 0..KNOWN_IDENTITIES_SOFT_CAP + 10 {
            ids.insert(format!("id{i:05}"), [0u8; 64]);
        }
        assert_eq!(prune_known_identities(&mut ids), 10);
        assert_eq!(ids.len(), KNOWN_IDENTITIES_SOFT_CAP);

        let mut under: HashMap<String, [u8; 64]> = HashMap::new();
        under.insert("only".into(), [0u8; 64]);
        assert_eq!(prune_known_identities(&mut under), 0);
        assert_eq!(under.len(), 1);
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

        let mut router = LxmRouter::new(Default::default());
        let medium = MediumSnapshot::default();

        assert!(queue_unknown_propagation_node_path_request(
            &tx,
            &mut router,
            &medium,
            node,
            &mut last,
            now
        ));
        assert_eq!(last, now);
        match rx.try_recv().expect("path request") {
            TransportMessage::RequestPath { destination_hash } => {
                assert_eq!(destination_hash, node);
            }
            other => panic!("expected RequestPath, got {other:?}"),
        }
        // LXMRouter.request_path debounces a repeat inside path_request_wait.
        assert!(queue_unknown_propagation_node_path_request(
            &tx,
            &mut router,
            &medium,
            node,
            &mut last,
            now + 1.0
        ));
        assert!(rx.try_recv().is_err());
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
            &tx,
            &mut LxmRouter::new(Default::default()),
            &MediumSnapshot::default(),
            node,
            &mut last,
            1234.5
        ));
        assert_eq!(last, 1234.5);
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
            validate_download_policy(&decoded, &[], 8.0),
            Err(SuppressionReason::InvalidStamp)
        );
        assert!(store.haves(recipient.hash, [9; 16], 101).is_empty());
        assert!(store.pending_hooks().is_empty());
        assert!(
            !bodies
                .join(format!("{}.lxm", hex::encode(missing.message_id())))
                .exists()
        );
        assert_eq!(validate_download_policy(&decoded, &[], 0.0), Ok(()));
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
        // An invalid signature is delivered flagged, as lxmf_delivery does.
        assert_eq!(validate_download_policy(&corrupt, &[], 0.0), Ok(()));
        assert_eq!(
            classify_signature(&corrupt, Some(&sender.get_public_key())),
            Some(lxmf_core::constants::UnverifiedReason::SignatureInvalid)
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
        validate_download_policy(&accepted, &[ticket], 8.0).unwrap();
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

        runner.handle_inbound_packet(&packet, None);
        runner.handle_link_delivered_data_on(&packed, None);

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
                    peering_cost: 0.0,
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
        let result = generate_peering_key_job([0x65; 16], 1.0, remote_identity, local_identity);
        let (key, value) = result.peering_key.expect("cost-one key");
        assert!(value >= 1.0);

        let mut peering_id = [0u8; 32];
        peering_id[..16].copy_from_slice(&remote_identity);
        peering_id[16..].copy_from_slice(&local_identity);
        assert!(lxmf_core::stamper::validate_peering_key(
            &peering_id,
            &key,
            1.0
        ));
    }

    #[test]
    fn pn_validation_worker_enforces_client_batch_authorization() {
        let wrapper = pn_test_wrapper(vec![pn_test_entry(0), pn_test_entry(1)]);
        let result = validate_pn_resource_job(
            PnValidationJob::for_test(wrapper.clone(), false),
            wrapper.len(),
            0.0,
        );
        assert_eq!(result.outcome, PnValidationOutcome::UnauthorizedMultiple);
        assert!(result.entries.is_empty());
        assert_eq!(result.rejected, 2);

        let result = validate_pn_resource_job(
            PnValidationJob::for_test(wrapper.clone(), true),
            wrapper.len(),
            0.0,
        );
        assert_eq!(result.outcome, PnValidationOutcome::Valid);
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.rejected, 0);
    }

    #[test]
    fn packet_validation_worker_handles_hundred_plus_entries_off_loop() {
        let wrapper = pn_test_wrapper((0..128).map(pn_test_entry).collect());

        let result = validate_pn_packet_job([0x91; 16], wrapper.clone().into(), wrapper.len(), 0.0);

        assert_eq!(result.entries.len(), 128);
        assert_eq!(result.rejected, 0);
    }

    #[test]
    fn mixed_packet_stores_valid_entries_then_rejects() {
        let mut valid = None;
        let mut invalid = None;
        for stamp_byte in 0u8..=u8::MAX {
            let entry = pn_test_entry(stamp_byte);
            if lxmf_core::stamper::validate_pn_stamp(&entry, 1.0).is_some() {
                valid.get_or_insert(entry);
            } else {
                invalid.get_or_insert(entry);
            }
            if valid.is_some() && invalid.is_some() {
                break;
            }
        }
        let valid = valid.unwrap();
        let valid_id = rns_crypto::sha::full_hash(&valid[..valid.len() - 32]);
        let wrapper = pn_test_wrapper(vec![valid, invalid.unwrap()]);
        let temporary = tempfile::tempdir().unwrap();
        let node = Arc::new(Mutex::new(
            PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                [0x11; 16],
                temporary.path().join("store"),
            )
            .unwrap(),
        ));
        let execution = execute_pn_packet_job(PnPacketValidationJob {
            link_id: [0x93; 16],
            data: wrapper.clone().into(),
            receipt: None,
            node: node.clone(),
            max_transfer_bytes: wrapper.len(),
            min_cost: 1.0,
            store_delay: Duration::ZERO,
            enqueued_at: Instant::now(),
        });
        assert_eq!(execution.result.rejected, 1);
        assert!(execution.result.stored);
        assert_eq!(execution.result.committed.len(), 1);
        assert_eq!(execution.result.committed[0].0, valid_id);
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
            min_cost: 0.0,
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
        let result = validate_pn_packet_job([0x92; 16], Bytes::from_static(&[0xc1]), 1, 0.0);

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
            if lxmf_core::stamper::validate_pn_stamp(&entry, 1.0).is_some() {
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
            1.0,
        );
        assert_eq!(result.outcome, PnValidationOutcome::InvalidStamp);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.rejected, 1);
    }

    #[test]
    fn pn_validation_worker_fails_malformed_or_oversized_wrapper() {
        let malformed = vec![0xc1];
        let result = validate_pn_resource_job(PnValidationJob::for_test(malformed, true), 100, 0.0);
        assert_eq!(result.outcome, PnValidationOutcome::Failed);

        let wrapper = pn_test_wrapper(vec![pn_test_entry(0)]);
        let result = validate_pn_resource_job(
            PnValidationJob::for_test(wrapper.clone(), true),
            wrapper.len() - 1,
            0.0,
        );
        assert_eq!(result.outcome, PnValidationOutcome::Failed);
    }
}
