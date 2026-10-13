//! Client-side propagation node download protocol.
//!
//! Python reference: LXMRouter.py:484-587.
//!
//! Protocol flow:
//! 1. Establish link to the propagation node destination.
//! 2. Identify on the link (LinkIdentify).
//! 3. Request `/get` with `[None, None]` -- server returns available transient IDs.
//! 4. Client sorts into wants/haves.
//! 5. Purge known haves, then request bounded wants chunks with a per-transfer limit.
//! 6. Server returns `[lxmf_data_1, lxmf_data_2, ...]`.
//! 7. Client processes received messages.
//! 8. `/get` with `[None, received_ids]` purges each downloaded batch before the next chunk.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_link::link::{CloseReason, Link, LinkAction};
use rns_protocol::resource::{
    InboundTransfer, MAX_EFFICIENT_SIZE, MAX_RESOURCE_SIZE, MAX_SEGMENTS, MultiSegmentInbound,
    OutboundTransfer, RANDOM_HASH_SIZE, ResourceError, TransferAction,
};
use rns_protocol::resource_adv::ResourceAdvertisement;
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    InterfaceId, LinkEndpointBindResult, LinkEndpointBinding, LinkEndpointLifecycleEvent,
    LinkEndpointRole, LinkEndpointSendResult, LinkEndpointUnbindResult, OutboundRequest,
    TransportMessage,
};
use tokio::sync::{mpsc, oneshot};

use crate::admission::{
    AdmissionEpochs, AdmissionResolution, AdmissionScope, DownloadAdmissionOutcome,
    DownloadAdmissionToken, DownloadedPropagationMessage, MAX_DOWNLOAD_ITEMS, SuppressionLedger,
    SuppressionRecord, retain_response,
};
use crate::constants::*;
use crate::propagation::hex_encode;
use crate::types::PropagationTransientId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationClientState {
    Idle,
    LinkEstablishing,
    LinkEstablished,
    /// `/get` with `[None, None]` sent.
    ListRequested,
    /// `/get` with `[wants, haves, limit]` sent.
    GetRequested,
    /// A Resource response is actively transferring.
    Receiving,
    /// `/get` with `[None, received_ids]` sent.
    PurgeRequested,
    /// Download bytes await a durable local application decision.
    AwaitingAdmission,
    /// At least one item was retained remotely for retry/revalidation.
    Partial,
    Complete,
    Failed,
}

/// Local admission/backoff status; none of these records authorize purge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PropagationAdmissionStatus {
    pub suppressed_count: usize,
    pub deferred_count: usize,
    pub next_retry: Option<u64>,
    pub node_records: usize,
    pub node_capacity: usize,
    pub ledger_full: bool,
    pub admission_paused: bool,
}

/// Per-cycle outcomes distinguish received ciphertext from durable local effects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PropagationAdmissionCounts {
    pub downloaded: usize,
    pub committed: usize,
    pub duplicate: usize,
    pub policy_discarded: usize,
    pub user_deleted: usize,
    pub rejected: usize,
    /// Subset of rejected items eligible for transient backoff retry.
    pub retryable: usize,
}

/// One coherent public snapshot of a propagation-node download.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PropagationTransferStatus {
    pub state: PropagationClientState,
    pub progress: f64,
    pub data_size: Option<usize>,
    /// Number of durably accepted decisions, including duplicates/discards.
    pub result: Option<usize>,
    pub admission: PropagationAdmissionCounts,
}

impl Default for PropagationTransferStatus {
    fn default() -> Self {
        Self {
            state: PropagationClientState::Idle,
            progress: 0.0,
            data_size: None,
            result: None,
            admission: PropagationAdmissionCounts::default(),
        }
    }
}

struct SegmentRoute {
    original_hash: [u8; 32],
    segment_index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestKind {
    List,
    Haves(usize),
    Get(usize),
    Purge(usize),
}

impl RequestKind {
    fn state(self) -> PropagationClientState {
        match self {
            Self::List => PropagationClientState::ListRequested,
            Self::Get(_) => PropagationClientState::GetRequested,
            Self::Haves(_) | Self::Purge(_) => PropagationClientState::PurgeRequested,
        }
    }
}

struct ResponseResource {
    logical_hash: [u8; 32],
    total_segments: usize,
    next_segment: usize,
    data_size: usize,
    assembled_bytes: usize,
    waiting_since: Instant,
    current_segment: Option<[u8; 32]>,
}

/// Exactly one logical request owns the phase, independently of Link's receipt
/// reaper. Resource watchdogs own transfer time; only response waiting uses the
/// request deadline. Generation matching also scopes deferred endpoint results.
struct PendingRequest {
    link_id: [u8; 16],
    generation: u64,
    id: [u8; 16],
    kind: RequestKind,
    sender_active: bool,
    outbound: Option<OutboundTransfer>,
    response: Option<ResponseResource>,
    waiting_since: Option<Instant>,
    timeout: Duration,
}

#[derive(Clone, Copy)]
struct EndpointRequestOwner {
    generation: u64,
    sender: bool,
}

struct PendingEndpointBind {
    interface_id: InterfaceId,
    rtt_request: OutboundRequest,
    result_rx: oneshot::Receiver<LinkEndpointBindResult>,
}

enum EndpointSendSuccess {
    None,
    RequestPacket,
    ResourceProof {
        assembled: Vec<u8>,
        route: Option<SegmentRoute>,
        metadata: Option<Vec<u8>>,
    },
}

struct PendingEndpointSend {
    link_id: [u8; 16],
    final_send: bool,
    success: EndpointSendSuccess,
    owner: Option<EndpointRequestOwner>,
    queued_at: Instant,
    result_rx: oneshot::Receiver<LinkEndpointSendResult>,
}

struct PendingEndpointCleanup {
    link_id: [u8; 16],
    result_rx: oneshot::Receiver<LinkEndpointUnbindResult>,
}

pub struct PropagationClient {
    transport_tx: mpsc::Sender<TransportMessage>,
    event_tx: mpsc::Sender<DestinationEvent>,
    event_rx: mpsc::Receiver<DestinationEvent>,
    outbound_propagation_node: Option<[u8; 16]>,
    link: Option<Link>,
    link_id: Option<[u8; 16]>,
    link_request_result: Option<
        oneshot::Receiver<Result<(), rns_transport::link_messages::LinkRequestDispatchError>>,
    >,
    attached_interface: Option<InterfaceId>,
    endpoint_release_queued: bool,
    pending_endpoint_bind: Option<PendingEndpointBind>,
    pending_endpoint_sends: Vec<PendingEndpointSend>,
    pending_endpoint_cleanups: Vec<PendingEndpointCleanup>,
    endpoint_lifecycle_tx: mpsc::UnboundedSender<LinkEndpointLifecycleEvent>,
    endpoint_lifecycle_rx: mpsc::UnboundedReceiver<LinkEndpointLifecycleEvent>,
    status: PropagationTransferStatus,
    /// Request phase whose response is currently arriving as a Resource.
    receiving_for: Option<PropagationClientState>,
    identity_pub: Option<[u8; 64]>,
    identity_key: Option<Ed25519PrivateKey>,
    /// Phase 1 response: transient IDs the server has.
    available_messages: Vec<Vec<u8>>,
    /// Messages we already have locally.
    local_messages: HashSet<Vec<u8>>,
    local_message_expiry: HashMap<Vec<u8>, u64>,
    /// Phase 2 response: downloaded LXMF message data.
    received_messages: Vec<DownloadedPropagationMessage>,
    admission_tx: mpsc::UnboundedSender<AdmissionResolution>,
    admission_rx: mpsc::UnboundedReceiver<AdmissionResolution>,
    admission_generation: u64,
    current_admission_generation: Arc<AtomicU64>,
    pending_admissions: HashSet<AdmissionScope>,
    admission_started: Option<Instant>,
    admission_progress: Option<Instant>,
    admission_failures: usize,
    suppression: SuppressionLedger,
    admission_epochs: AdmissionEpochs,
    suppression_updates: Vec<SuppressionRecord>,
    suppression_persist_failed: bool,
    suppression_dirty: bool,
    suppression_revision: u64,
    /// IDs of messages successfully received (drives the Phase 3 purge).
    received_ids: Vec<Vec<u8>>,
    pending_haves: VecDeque<Vec<u8>>,
    pending_wants: VecDeque<Vec<u8>>,
    request: Option<PendingRequest>,
    next_request_generation: u64,
    unread_bytes: usize,
    unread_limit: usize,
    inbound_resources: HashMap<[u8; 32], InboundTransfer>,
    inbound_split_resources: HashMap<[u8; 32], MultiSegmentInbound>,
    segment_routing: HashMap<[u8; 32], SegmentRoute>,
    /// Ordered, bounded staging for transport backpressure.
    pending_transport: VecDeque<TransportMessage>,
    /// KB per transfer; `None` means unlimited.
    delivery_limit: Option<f64>,
    /// `None` means all messages; Python's `PR_ALL_MESSAGES` value is zero.
    max_messages: Option<usize>,
    retain_synced_on_node: bool,
    started_at: Option<Instant>,
    timeout: Duration,
    identified: bool,
}

impl PropagationClient {
    pub fn new(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity_pub: Option<[u8; 64]>,
        identity_key: Option<Ed25519PrivateKey>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(256);
        let (admission_tx, admission_rx) = mpsc::unbounded_channel();
        let (endpoint_lifecycle_tx, endpoint_lifecycle_rx) = mpsc::unbounded_channel();
        Self {
            transport_tx,
            event_tx,
            event_rx,
            outbound_propagation_node: None,
            link: None,
            link_id: None,
            link_request_result: None,
            attached_interface: None,
            endpoint_release_queued: false,
            pending_endpoint_bind: None,
            pending_endpoint_sends: Vec::new(),
            pending_endpoint_cleanups: Vec::new(),
            endpoint_lifecycle_tx,
            endpoint_lifecycle_rx,
            status: PropagationTransferStatus::default(),
            receiving_for: None,
            identity_pub,
            identity_key,
            available_messages: Vec::new(),
            local_messages: HashSet::new(),
            local_message_expiry: HashMap::new(),
            received_messages: Vec::new(),
            admission_tx,
            admission_rx,
            admission_generation: 0,
            current_admission_generation: Arc::new(AtomicU64::new(0)),
            pending_admissions: HashSet::new(),
            admission_started: None,
            admission_progress: None,
            admission_failures: 0,
            suppression: SuppressionLedger::default(),
            admission_epochs: AdmissionEpochs::default(),
            suppression_updates: Vec::new(),
            suppression_persist_failed: false,
            suppression_dirty: false,
            suppression_revision: 0,
            received_ids: Vec::new(),
            pending_haves: VecDeque::new(),
            pending_wants: VecDeque::new(),
            request: None,
            next_request_generation: 0,
            unread_bytes: 0,
            unread_limit: MAX_RESOURCE_SIZE,
            inbound_resources: HashMap::new(),
            inbound_split_resources: HashMap::new(),
            segment_routing: HashMap::new(),
            pending_transport: VecDeque::new(),
            delivery_limit: Some(DELIVERY_LIMIT as f64),
            max_messages: None,
            retain_synced_on_node: false,
            started_at: None,
            timeout: Duration::from_secs(120),
            identified: false,
        }
    }

    pub fn set_propagation_node(&mut self, dest_hash: [u8; 16]) {
        self.outbound_propagation_node = Some(dest_hash);
    }

    /// KB per transfer.
    pub fn set_delivery_limit(&mut self, limit_kb: f64) {
        self.delivery_limit = Some(limit_kb);
    }

    pub fn add_local_message(&mut self, transient_id: PropagationTransientId) {
        self.local_message_expiry.remove(transient_id.as_slice());
        self.local_messages.insert(transient_id.to_vec());
    }

    pub fn add_local_message_id(&mut self, transient_id: Vec<u8>) {
        self.local_message_expiry.remove(&transient_id);
        self.local_messages.insert(transient_id);
    }

    pub fn replace_local_message_ids<I>(&mut self, transient_ids: I)
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        self.local_messages = transient_ids.into_iter().collect();
        self.local_message_expiry.clear();
    }

    pub fn replace_durable_haves(
        &mut self,
        haves: impl IntoIterator<Item = crate::admission::DurableHave>,
    ) {
        self.local_messages.clear();
        self.local_message_expiry.clear();
        for have in haves {
            self.remember_durable_have(have);
        }
        self.prune_expired_haves(crate::now_f64() as u64);
    }
    fn remember_durable_have(&mut self, have: crate::admission::DurableHave) {
        self.local_messages.insert(have.transient_id.to_vec());
        match have.expires_at {
            Some(expiry) => {
                self.local_message_expiry
                    .insert(have.transient_id.to_vec(), expiry);
            }
            None => {
                self.local_message_expiry
                    .remove(have.transient_id.as_slice());
            }
        }
    }
    fn prune_expired_haves(&mut self, now: u64) {
        self.local_message_expiry.retain(|id, expiry| {
            if now >= *expiry {
                self.local_messages.remove(id);
                false
            } else {
                true
            }
        });
        // Recheck immediately before the next purge, including long cycles.
        if self.request.is_none() {
            self.pending_haves
                .retain(|id| self.local_messages.contains(id));
            self.received_ids
                .retain(|id| self.local_messages.contains(id));
        }
    }

    pub fn set_retain_synced_on_node(&mut self, retain: bool) {
        self.retain_synced_on_node = retain;
    }

    pub fn available_messages(&self) -> &[Vec<u8>] {
        &self.available_messages
    }

    /// Move payloads and their single-use admission tokens into the durable
    /// adapter. Raw-byte credit follows every Bytes clone across cancellation.
    pub fn take_downloaded_messages(&mut self) -> Vec<DownloadedPropagationMessage> {
        self.unread_bytes = 0;
        std::mem::take(&mut self.received_messages)
    }

    /// Install only persisted suppression state. It never supplies purge authority.
    pub fn set_suppression_ledger(&mut self, ledger: SuppressionLedger, epochs: AdmissionEpochs) {
        self.suppression = ledger;
        self.suppression_revision = self.suppression_revision.wrapping_add(1);
        self.admission_epochs = epochs;
        self.suppression_persist_failed = false;
        self.suppression_dirty = false;
        self.suppression_updates.clear();
    }
    pub fn update_admission_epochs(&mut self, epochs: AdmissionEpochs) {
        if self.admission_epochs != epochs {
            self.suppression_revision = self.suppression_revision.wrapping_add(1);
        }
        self.admission_epochs = epochs;
        self.prune_suppression();
    }
    fn prune_suppression(&mut self) {
        let before = self.suppression.records().count();
        self.suppression
            .prune(crate::now_f64() as u64, self.admission_epochs);
        if self.suppression.records().count() != before {
            self.suppression_dirty = true;
            self.suppression_revision = self.suppression_revision.wrapping_add(1);
        }
    }
    pub fn admission_status(&self) -> PropagationAdmissionStatus {
        let identity = self.identity_hash();
        let node = self.outbound_propagation_node.unwrap_or([0; 16]);
        let now = crate::now_f64() as u64;
        let mut status = PropagationAdmissionStatus {
            node_capacity: SuppressionLedger::PER_NODE,
            ledger_full: self.suppression.saturated(identity, node),
            ..Default::default()
        };
        for record in self
            .suppression
            .records()
            .filter(|record| record.scope.identity == identity && record.scope.node == node)
        {
            status.node_records += 1;
            if record.active(now, self.admission_epochs) {
                if record.reason.is_transient() {
                    status.deferred_count += 1;
                } else {
                    status.suppressed_count += 1;
                }
                status.next_retry = Some(
                    status
                        .next_retry
                        .map_or(record.next_retry, |n| n.min(record.next_retry)),
                );
            }
        }
        status.admission_paused =
            self.suppression_persist_failed || self.suppression_dirty || status.ledger_full;
        status
    }
    pub fn suppression_ledger(&self) -> &SuppressionLedger {
        &self.suppression
    }
    /// Covers inserts, removals, expiry, epoch changes and restored snapshots.
    pub fn suppression_revision(&self) -> u64 {
        self.suppression_revision
    }
    /// A slow checkpoint must never reinstall an older ledger over new state.
    pub fn acknowledge_suppression_persistence(&mut self, revision: u64) -> bool {
        if revision != self.suppression_revision {
            return false;
        }
        self.suppression_dirty = false;
        self.suppression_persist_failed = false;
        self.suppression_updates.clear();
        true
    }
    pub fn suppression_persistence_pending(&self) -> bool {
        self.suppression_dirty
    }
    pub fn take_suppression_updates(&mut self) -> Vec<SuppressionRecord> {
        std::mem::take(&mut self.suppression_updates)
    }
    /// The adapter must report a failed durable suppression update. Automatic
    /// new wants pause until persisted state is installed after recovery.
    pub fn suppression_persistence_failed(&mut self) {
        self.suppression_persist_failed = true;
    }

    fn identity_hash(&self) -> [u8; 16] {
        self.identity_pub
            .as_ref()
            .map(|key| rns_crypto::sha::truncated_hash(key))
            .unwrap_or([0; 16])
    }

    pub const fn state(&self) -> PropagationClientState {
        self.status.state
    }

    pub const fn transfer_status(&self) -> PropagationTransferStatus {
        self.status
    }

    /// Clear a terminal presentation snapshot after the caller has consumed
    /// its result. Active transfers are never reset by acknowledgement.
    pub fn acknowledge_transfer(&mut self) -> bool {
        if !matches!(
            self.status.state,
            PropagationClientState::Complete
                | PropagationClientState::Partial
                | PropagationClientState::Failed
        ) {
            return false;
        }
        self.cleanup();
        self.status = PropagationTransferStatus::default();
        true
    }

    pub fn start_download(&mut self) -> bool {
        self.start_download_with_limit(None)
    }

    /// Start a propagation download, limiting newly requested messages.
    /// `None` and zero mirror Python's `PR_ALL_MESSAGES`.
    /// Move live downloads into the durable adapter before restarting. Failure
    /// or cancellation drops the client-owned queue and revokes its tokens;
    /// already moved payload/worker owners retain their memory leases.
    pub fn start_download_with_limit(&mut self, max_messages: Option<usize>) -> bool {
        self.prune_suppression();
        if !self.received_messages.is_empty()
            || self.suppression_persist_failed
            || self.suppression_dirty
        {
            return false;
        }
        let node_hash = match self.outbound_propagation_node {
            Some(h) => h,
            None => return false,
        };
        if !matches!(
            self.status.state,
            PropagationClientState::Idle
                | PropagationClientState::Complete
                | PropagationClientState::Partial
                | PropagationClientState::Failed
        ) {
            return false;
        }
        if matches!(
            self.status.state,
            PropagationClientState::Complete
                | PropagationClientState::Partial
                | PropagationClientState::Failed
        ) {
            self.cleanup();
        }
        self.flush_pending_transport();
        if !self.pending_transport.is_empty() {
            return false;
        }

        let (link, request_data) = Link::new_initiator(node_hash, 1);
        let link_id = link.link_id;

        if !self.queue_transport(TransportMessage::RegisterDestination {
            hash: link_id,
            app_name: "lxmf.propagation.client".to_string(),
            delivery_tx: Some(self.event_tx.clone()),
        }) {
            tracing::warn!("failed to register propagation client destination");
            return false;
        }

        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: node_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&request_data);

        let (request_tx, request_rx) = oneshot::channel();
        if !self.queue_transport(TransportMessage::SendLinkRequest {
            request: OutboundRequest {
                raw: Bytes::from(raw),
                destination_hash: node_hash,
            },
            result_tx: request_tx,
        }) {
            tracing::warn!("failed to stage propagation client Link request");
            self.pending_transport.clear();
            return false;
        }

        self.link_request_result = Some(request_rx);

        self.status = PropagationTransferStatus {
            state: PropagationClientState::LinkEstablishing,
            ..PropagationTransferStatus::default()
        };
        self.receiving_for = None;
        self.link = Some(link);
        self.link_id = Some(link_id);
        self.attached_interface = None;
        self.endpoint_release_queued = false;
        self.pending_endpoint_bind = None;
        self.started_at = Some(Instant::now());
        self.max_messages = max_messages.filter(|limit| *limit > 0);
        self.identified = false;
        self.available_messages.clear();
        self.received_messages.clear();
        self.admission_generation = self.admission_generation.wrapping_add(1);
        self.current_admission_generation
            .store(self.admission_generation, Ordering::Release);
        self.pending_admissions.clear();
        self.admission_failures = 0;
        self.admission_started = None;
        self.admission_progress = None;
        self.received_ids.clear();
        self.pending_haves.clear();
        self.pending_wants.clear();
        self.unread_bytes = 0;
        self.inbound_resources.clear();
        self.inbound_split_resources.clear();
        self.segment_routing.clear();
        true
    }

    /// Cancel an active request and return to the idle state.
    pub fn cancel_download(&mut self) {
        self.cleanup();
        self.status = PropagationTransferStatus::default();
    }

    const PENDING_TRANSPORT_LIMIT: usize = 256;

    fn queue_transport(&mut self, message: TransportMessage) -> bool {
        if self.pending_transport.is_empty() {
            match self.transport_tx.try_send(message) {
                Ok(()) => return true,
                Err(mpsc::error::TrySendError::Full(message)) => {
                    self.pending_transport.push_back(message);
                    return true;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return false,
            }
        }
        if self.pending_transport.len() >= Self::PENDING_TRANSPORT_LIMIT {
            return false;
        }
        self.pending_transport.push_back(message);
        true
    }

    fn flush_pending_transport(&mut self) {
        while let Some(message) = self.pending_transport.pop_front() {
            match self.transport_tx.try_send(message) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(message)) => {
                    self.pending_transport.push_front(message);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.pending_transport.clear();
                    self.fail();
                    break;
                }
            }
        }
    }

    fn queue_link_endpoint(&mut self, request: OutboundRequest) -> bool {
        let success = if self.request.is_some()
            && rns_wire::header::PacketHeader::unpack(&request.raw).is_ok_and(|(header, _)| {
                header.context == rns_wire::context::PacketContext::Request
            }) {
            EndpointSendSuccess::RequestPacket
        } else {
            EndpointSendSuccess::None
        };
        self.queue_link_endpoint_with_success(request, success)
    }

    fn queue_link_endpoint_with_success(
        &mut self,
        request: OutboundRequest,
        success: EndpointSendSuccess,
    ) -> bool {
        let Some(link_id) = self.link_id else {
            return false;
        };
        let owner = self.request.as_ref().and_then(|pending| {
            let (header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).ok()?;
            use rns_wire::context::PacketContext;
            if matches!(
                header.context,
                PacketContext::Keepalive | PacketContext::LinkClose
            ) {
                return None;
            }
            Some(EndpointRequestOwner {
                generation: pending.generation,
                sender: matches!(
                    header.context,
                    PacketContext::Request
                        | PacketContext::ResourceAdv
                        | PacketContext::Resource
                        | PacketContext::ResourceHmu
                        | PacketContext::ResourceIcl
                ),
            })
        });
        let (result_tx, result_rx) = oneshot::channel();
        if !self.queue_transport(TransportMessage::SendLinkEndpoint {
            link_id,
            role: LinkEndpointRole::Initiator,
            request,
            result_tx,
        }) {
            return false;
        }
        self.pending_endpoint_sends.push(PendingEndpointSend {
            link_id,
            final_send: false,
            success,
            owner,
            queued_at: Instant::now(),
            result_rx,
        });
        true
    }

    fn queue_link_endpoint_and_unbind(&mut self, request: OutboundRequest) -> bool {
        let Some(link_id) = self.link_id else {
            return false;
        };
        let (result_tx, result_rx) = oneshot::channel();
        if !self.queue_transport(TransportMessage::SendLinkEndpointAndUnbind {
            link_id,
            role: LinkEndpointRole::Initiator,
            request,
            result_tx,
        }) {
            return false;
        }
        self.pending_endpoint_sends.push(PendingEndpointSend {
            link_id,
            final_send: true,
            success: EndpointSendSuccess::None,
            owner: None,
            queued_at: Instant::now(),
            result_rx,
        });
        true
    }

    fn queue_endpoint_cleanup(&mut self, link_id: [u8; 16]) {
        let (result_tx, result_rx) = oneshot::channel();
        if self.queue_transport(TransportMessage::UnbindLinkEndpoint {
            link_id,
            role: LinkEndpointRole::Initiator,
            result_tx,
        }) {
            self.pending_endpoint_cleanups
                .push(PendingEndpointCleanup { link_id, result_rx });
        }
    }

    fn poll_endpoint_send_results(&mut self) {
        let mut still_pending = Vec::new();
        let mut endpoint_sends = std::mem::take(&mut self.pending_endpoint_sends);
        for mut pending in endpoint_sends.drain(..) {
            let current = self.link_id == Some(pending.link_id)
                && pending.owner.is_none_or(|owner| {
                    self.request.as_ref().is_some_and(|request| {
                        request.generation == owner.generation
                            && (!owner.sender || request.sender_active)
                    })
                });
            match pending.result_rx.try_recv() {
                Ok(LinkEndpointSendResult::Sent | LinkEndpointSendResult::Queued { .. }) => {
                    if current && self.status.state != PropagationClientState::Failed {
                        match pending.success {
                            EndpointSendSuccess::None => {}
                            EndpointSendSuccess::RequestPacket => {
                                if let Some(request) = self.request.as_mut() {
                                    request.waiting_since.get_or_insert_with(Instant::now);
                                }
                            }
                            EndpointSendSuccess::ResourceProof {
                                assembled,
                                route,
                                metadata,
                            } => self.finish_completed_resource(assembled, route, metadata),
                        }
                    }
                }
                Ok(result) => {
                    tracing::warn!(
                        link_id = %hex::encode(pending.link_id),
                        ?result,
                        final_send = pending.final_send,
                        "propagation client Link endpoint send rejected"
                    );
                    if current {
                        self.fail();
                    }
                    if pending.final_send {
                        self.queue_endpoint_cleanup(pending.link_id);
                    }
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    if current {
                        self.fail();
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    if current && pending.queued_at.elapsed() >= Duration::from_secs(120) {
                        self.fail();
                    } else if current || pending.final_send {
                        still_pending.push(pending);
                    }
                }
            }
        }
        still_pending.append(&mut self.pending_endpoint_sends);
        self.pending_endpoint_sends = still_pending;

        let mut cleanup_pending = Vec::new();
        let mut cleanups = std::mem::take(&mut self.pending_endpoint_cleanups);
        for mut pending in cleanups.drain(..) {
            match pending.result_rx.try_recv() {
                Ok(LinkEndpointUnbindResult::Unbound | LinkEndpointUnbindResult::NotBound) => {
                    let _ = self.queue_transport(TransportMessage::DeregisterDestination {
                        hash: pending.link_id,
                    });
                }
                Ok(LinkEndpointUnbindResult::RoleMismatch) => {
                    tracing::warn!(
                        link_id = %hex::encode(pending.link_id),
                        "refusing to deregister a propagation Link owned by the opposite role"
                    );
                }
                Err(oneshot::error::TryRecvError::Closed) => {}
                Err(oneshot::error::TryRecvError::Empty) => cleanup_pending.push(pending),
            }
        }
        self.pending_endpoint_cleanups = cleanup_pending;
    }

    fn poll_endpoint_control(&mut self) {
        self.poll_endpoint_send_results();
        while let Ok(event) = self.endpoint_lifecycle_rx.try_recv() {
            if self.link_id == Some(event.binding.link_id)
                && event.binding.role == LinkEndpointRole::Initiator
            {
                tracing::warn!(
                    link_id = %hex::encode(event.binding.link_id),
                    interface_id = event.binding.interface_id,
                    reason = ?event.reason,
                    dropped_packets = event.dropped_packets,
                    "propagation client Link endpoint terminated"
                );
                self.attached_interface = None;
                self.pending_endpoint_bind = None;
                self.fail();
            }
        }

        let Some(mut pending) = self.pending_endpoint_bind.take() else {
            return;
        };
        match pending.result_rx.try_recv() {
            Ok(LinkEndpointBindResult::Bound | LinkEndpointBindResult::AlreadyBound) => {
                self.attached_interface = Some(pending.interface_id);
                if self.queue_link_endpoint(pending.rtt_request) {
                    self.status.state = PropagationClientState::LinkEstablished;
                    self.started_at = Some(Instant::now());
                } else {
                    self.fail();
                }
            }
            Ok(
                LinkEndpointBindResult::Conflict { .. }
                | LinkEndpointBindResult::InterfaceUnavailable,
            )
            | Err(oneshot::error::TryRecvError::Closed) => {
                self.fail();
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                self.pending_endpoint_bind = Some(pending);
            }
        }
    }

    fn poll_link_request(&mut self) {
        let Some(mut receiver) = self.link_request_result.take() else {
            return;
        };
        match receiver.try_recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error,"Link request rejected by transport");
                self.fail();
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                self.fail();
            }
            Err(oneshot::error::TryRecvError::Empty) => self.link_request_result = Some(receiver),
        }
    }

    pub fn drain_events(&mut self, known_identities: &std::collections::HashMap<String, [u8; 64]>) {
        self.poll_link_request();
        self.poll_endpoint_control();
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }

        for event in events {
            if self.status.state == PropagationClientState::Failed {
                break;
            }
            match event {
                DestinationEvent::LinkClosed { link_id } => {
                    self.handle_link_closed(link_id, None);
                }
                DestinationEvent::InboundPacket {
                    raw,
                    interface_id,
                    interface_owner,
                    ..
                } => {
                    let (header, data_offset) = match rns_wire::header::PacketHeader::unpack(&raw) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };
                    if self.link_id != Some(header.destination_hash) {
                        continue;
                    }
                    let is_link_proof = matches!(
                        header.context,
                        rns_wire::context::PacketContext::Lrproof
                            | rns_wire::context::PacketContext::None
                    ) && (header.flags.packet_type
                        == rns_wire::flags::PacketType::Proof
                        || header.context == rns_wire::context::PacketContext::Lrproof);
                    if is_link_proof {
                        if self.pending_endpoint_bind.is_some()
                            || self.status.state != PropagationClientState::LinkEstablishing
                        {
                            continue;
                        }
                    } else if self.attached_interface != Some(interface_id) {
                        tracing::warn!(
                            link_id = %hex::encode(header.destination_hash),
                            interface_id,
                            attached_interface = ?self.attached_interface,
                            "rejected propagation client packet from wrong Link interface"
                        );
                        continue;
                    }
                    let data = if raw.len() > data_offset {
                        &raw[data_offset..]
                    } else {
                        &[]
                    };
                    if let Some(link) = self.link.as_mut() {
                        link.record_inbound();
                        link.record_rx(data.len());
                    }

                    match header.context {
                        rns_wire::context::PacketContext::Lrproof
                        | rns_wire::context::PacketContext::None
                            if header.flags.packet_type == rns_wire::flags::PacketType::Proof
                                || header.context == rns_wire::context::PacketContext::Lrproof =>
                        {
                            if self.status.state != PropagationClientState::LinkEstablishing {
                                continue;
                            }
                            let node_hex = self.outbound_propagation_node.map(|h| hex_encode(&h));
                            if let Some(node_hex) = node_hex
                                && let Some(pub_key) = known_identities.get(&node_hex)
                            {
                                let ed25519_bytes: [u8; 32] = pub_key[32..64]
                                        .try_into()
                                        .expect("known_identities values are [u8; 64]; slice [32..64] is always 32 bytes");
                                if let Ok(verify_key) = Ed25519PublicKey::from_bytes(&ed25519_bytes)
                                {
                                    self.handle_link_proof_with_owner(
                                        data,
                                        &verify_key,
                                        &ed25519_bytes,
                                        interface_id,
                                        interface_owner,
                                    );
                                }
                            }
                        }
                        rns_wire::context::PacketContext::Response => {
                            if let Some(plaintext) =
                                self.link.as_ref().and_then(|link| link.decrypt(data).ok())
                            {
                                self.handle_response_owned(Bytes::from(plaintext));
                            }
                        }
                        rns_wire::context::PacketContext::ResourceReq => {
                            self.handle_outbound_request(data)
                        }
                        rns_wire::context::PacketContext::ResourcePrf => {
                            self.handle_outbound_proof(data)
                        }
                        rns_wire::context::PacketContext::ResourceAdv => {
                            self.handle_resource_advertisement(data);
                        }
                        rns_wire::context::PacketContext::Resource => {
                            self.handle_resource_part(data);
                        }
                        rns_wire::context::PacketContext::ResourceHmu => {
                            self.handle_resource_hmu(data);
                        }
                        rns_wire::context::PacketContext::ResourceIcl
                        | rns_wire::context::PacketContext::ResourceRcl => {
                            self.handle_resource_cancel(data, header.context);
                        }
                        rns_wire::context::PacketContext::LinkClose => {
                            self.handle_link_closed(header.destination_hash, Some(data));
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    fn handle_link_closed(&mut self, link_id: [u8; 16], encrypted_teardown: Option<&[u8]>) -> bool {
        if self.link_id != Some(link_id) {
            return false;
        }

        let Some(link) = self.link.as_mut() else {
            return false;
        };

        let verified = match encrypted_teardown {
            Some(data) => link.receive_teardown(data),
            None => {
                link.mark_closed(CloseReason::DestinationClosed);
                true
            }
        };

        if verified {
            self.inbound_resources.clear();
            self.inbound_split_resources.clear();
            self.segment_routing.clear();
            self.fail();
        }

        verified
    }

    #[cfg(test)]
    fn handle_link_proof(
        &mut self,
        proof_data: &[u8],
        verify_key: &Ed25519PublicKey,
        ed25519_pub: &[u8; 32],
        interface_id: InterfaceId,
    ) {
        self.handle_link_proof_with_owner(proof_data, verify_key, ed25519_pub, interface_id, None)
    }
    fn handle_link_proof_with_owner(
        &mut self,
        proof_data: &[u8],
        verify_key: &Ed25519PublicKey,
        ed25519_pub: &[u8; 32],
        interface_id: InterfaceId,
        interface_owner: Option<rns_transport::InterfaceOwnerId>,
    ) {
        let link = match self.link.as_mut() {
            Some(l) => l,
            None => return,
        };

        if let Ok(rtt_data) = link.validate_proof(proof_data, verify_key, ed25519_pub)
            && let Some(link_id) = self.link_id
        {
            let rtt_header = rns_wire::header::PacketHeader {
                flags: rns_wire::flags::PacketFlags {
                    header_type: rns_wire::flags::HeaderType::Header1,
                    context_flag: false,
                    transport_type: rns_wire::flags::TransportType::Broadcast,
                    destination_type: rns_wire::flags::DestinationType::Link,
                    packet_type: rns_wire::flags::PacketType::Data,
                },
                hops: 0,
                transport_id: None,
                destination_hash: link_id,
                context: rns_wire::context::PacketContext::Lrrtt,
            };
            let mut rtt_raw = rtt_header.pack();
            rtt_raw.extend_from_slice(&rtt_data);

            let rtt_request = OutboundRequest {
                raw: Bytes::from(rtt_raw),
                destination_hash: link_id,
            };
            let (result_tx, result_rx) = oneshot::channel();
            if !self.queue_transport(TransportMessage::BindLinkEndpoint {
                binding: LinkEndpointBinding {
                    interface_owner,
                    link_id,
                    interface_id,
                    role: LinkEndpointRole::Initiator,
                },
                lifecycle_tx: self.endpoint_lifecycle_tx.clone(),
                result_tx,
            }) {
                self.fail();
                return;
            }
            self.pending_endpoint_bind = Some(PendingEndpointBind {
                interface_id,
                rtt_request,
                result_rx,
            });
        }
    }

    fn handle_response_data(&mut self, response_data: &[u8]) {
        let response_phase = if let Some(request) = self.request.as_ref() {
            request.kind.state()
        } else if self.status.state == PropagationClientState::Receiving {
            let Some(phase) = self.receiving_for.take() else {
                return;
            };
            phase
        } else {
            self.status.state
        };

        match response_phase {
            PropagationClientState::ListRequested => {
                self.handle_list_response(response_data);
            }
            PropagationClientState::GetRequested => {
                self.handle_get_response_owned(Bytes::copy_from_slice(response_data));
            }
            PropagationClientState::PurgeRequested => {
                self.handle_purge_response(response_data);
            }
            _ => {}
        }
    }

    fn handle_resource_advertisement(&mut self, data: &[u8]) {
        let Some(link) = self.link.as_ref() else {
            return;
        };
        let Ok(plaintext) = link.decrypt(data) else {
            return;
        };
        let Ok(adv) = ResourceAdvertisement::unpack(&plaintext) else {
            return;
        };

        let Some(request) = self.request.as_ref() else {
            return;
        };
        if !adv.flags.is_response || adv.request_id.as_deref() != Some(request.id.as_slice()) {
            return;
        }

        if adv.flags.is_request
            || !adv.flags.encrypted
            || adv.flags.has_metadata
            || adv.data_size > MAX_RESOURCE_SIZE
            || adv.total_segments == 0
            || adv.total_segments > MAX_SEGMENTS
            || adv.segment_index == 0
            || adv.segment_index > adv.total_segments
            || (adv.total_segments > 1 && !adv.flags.split)
            || adv.random_hash.len() != RANDOM_HASH_SIZE
        {
            self.fail();
            return;
        }
        let logical_hash = if adv.flags.split {
            adv.original_hash
        } else {
            adv.resource_hash
        };
        if let Some(response) = request.response.as_ref() {
            if response.logical_hash != logical_hash
                || response.total_segments != adv.total_segments
                || response.data_size != adv.data_size
            {
                self.fail();
                return;
            }
            if adv.segment_index < response.next_segment
                || response.current_segment == Some(adv.resource_hash)
            {
                return;
            }
            if adv.segment_index != response.next_segment || response.current_segment.is_some() {
                self.fail();
                return;
            }
        } else if adv.segment_index != 1 {
            self.fail();
            return;
        }

        if self.status.state != PropagationClientState::Receiving {
            if !matches!(
                self.status.state,
                PropagationClientState::ListRequested
                    | PropagationClientState::GetRequested
                    | PropagationClientState::PurgeRequested
            ) {
                return;
            }
            self.receiving_for = Some(self.status.state);
        } else if self.receiving_for.is_none() {
            self.fail();
            return;
        }
        self.status.state = PropagationClientState::Receiving;
        self.status.data_size = Some(self.status.data_size.unwrap_or_default().max(adv.data_size));

        if adv.total_segments > 1 {
            if adv.total_segments > MAX_SEGMENTS
                || adv.segment_index == 0
                || adv.segment_index > adv.total_segments
            {
                self.fail();
                return;
            }

            let entry = self
                .inbound_split_resources
                .entry(adv.original_hash)
                .or_insert_with(|| MultiSegmentInbound::new(adv.total_segments, adv.original_hash));
            if entry.total_segments != adv.total_segments {
                self.fail();
                return;
            }
            self.segment_routing.insert(
                adv.resource_hash,
                SegmentRoute {
                    original_hash: adv.original_hash,
                    segment_index: adv.segment_index,
                },
            );
        }

        let map_hashes = adv.get_map_hashes();
        let rtt = self
            .link
            .as_ref()
            .and_then(|l| l.rtt)
            .unwrap_or(Duration::from_millis(500));
        let mut random_hash = [0u8; RANDOM_HASH_SIZE];
        let copy_len = adv.random_hash.len().min(random_hash.len());
        random_hash[..copy_len].copy_from_slice(&adv.random_hash[..copy_len]);

        let Ok(mut transfer) = InboundTransfer::from_advertisement(
            adv.num_parts,
            adv.transfer_size,
            adv.data_size,
            random_hash,
            adv.resource_hash,
            adv.flags,
            map_hashes,
            rtt,
        ) else {
            self.fail();
            return;
        };

        self.retire_request_sender();
        let request = self
            .request
            .as_mut()
            .expect("response matched request above");
        request.waiting_since = None;
        let response = request.response.get_or_insert_with(|| ResponseResource {
            logical_hash,
            total_segments: adv.total_segments,
            next_segment: 1,
            data_size: adv.data_size,
            assembled_bytes: 0,
            waiting_since: Instant::now(),
            current_segment: None,
        });
        response.current_segment = Some(adv.resource_hash);
        response.waiting_since = Instant::now();

        if let TransferAction::SendRequest(req_data) = transfer.request_next() {
            self.send_encrypted_resource_control(
                rns_wire::context::PacketContext::ResourceReq,
                &req_data,
            );
        }

        if let Some(link) = self.link.as_mut() {
            link.track_incoming_resource(adv.resource_hash);
        }
        self.inbound_resources.insert(adv.resource_hash, transfer);
    }

    fn handle_resource_part(&mut self, data: &[u8]) {
        let mut control_actions = Vec::new();
        let mut completed = None;
        let mut observed_progress = None;

        for (resource_hash, transfer) in &mut self.inbound_resources {
            let action = transfer.receive_part(data.to_vec());
            match action {
                TransferAction::SendHmu(hmu) => {
                    control_actions.push((rns_wire::context::PacketContext::ResourceHmu, hmu));
                }
                TransferAction::SendRequest(req) => {
                    control_actions.push((rns_wire::context::PacketContext::ResourceReq, req));
                }
                TransferAction::Failed(_) => {
                    self.fail();
                    return;
                }
                _ => {}
            }

            if transfer.resource.is_complete() {
                completed = Some(*resource_hash);
            }
            observed_progress = Some((*resource_hash, transfer.resource.progress()));

            if completed.is_some() || !control_actions.is_empty() {
                break;
            }
        }

        for (context, payload) in control_actions {
            self.send_encrypted_resource_control(context, &payload);
        }

        if let Some((resource_hash, segment_progress)) = observed_progress {
            let progress = self
                .segment_routing
                .get(&resource_hash)
                .and_then(|route| {
                    self.inbound_split_resources
                        .get(&route.original_hash)
                        .map(|coordinator| {
                            (coordinator.assembled_count() as f64 + segment_progress)
                                / coordinator.total_segments.max(1) as f64
                        })
                })
                .unwrap_or(segment_progress);
            self.status.state = PropagationClientState::Receiving;
            self.status.progress = self.status.progress.max(progress.clamp(0.0, 1.0));
        }

        if let Some(resource_hash) = completed {
            self.complete_resource(resource_hash);
        }
    }

    fn handle_resource_hmu(&mut self, data: &[u8]) {
        let Some(link) = self.link.as_ref() else {
            return;
        };
        let Ok(plaintext) = link.decrypt(data) else {
            return;
        };
        if plaintext.len() < 32 {
            return;
        }

        let mut resource_hash = [0u8; 32];
        resource_hash.copy_from_slice(&plaintext[..32]);
        let value = match rmpv::decode::read_value(&mut &plaintext[32..]) {
            Ok(v) => v,
            Err(_) => return,
        };
        let Some(arr) = value.as_array() else {
            return;
        };
        if arr.len() < 2 {
            return;
        }
        let Some(segment) = arr[0].as_u64().map(|v| v as usize) else {
            return;
        };
        let Some(hashmap_data) = arr[1].as_slice() else {
            return;
        };

        let action = {
            let Some(transfer) = self.inbound_resources.get_mut(&resource_hash) else {
                return;
            };
            transfer.hashmap_update(segment, hashmap_data)
        };
        match action {
            TransferAction::SendRequest(req) => {
                self.send_encrypted_resource_control(
                    rns_wire::context::PacketContext::ResourceReq,
                    &req,
                );
            }
            TransferAction::Failed(_) => {
                self.fail();
            }
            _ => {}
        }
    }

    fn handle_resource_cancel(&mut self, data: &[u8], context: rns_wire::context::PacketContext) {
        let Some(link) = self.link.as_ref() else {
            return;
        };
        let Ok(plaintext) = link.decrypt(data) else {
            return;
        };
        if plaintext.len() != 32 {
            return;
        }
        let mut resource_hash = [0u8; 32];
        resource_hash.copy_from_slice(&plaintext[..32]);
        let matches = self.request.as_ref().is_some_and(|request| {
            if context == rns_wire::context::PacketContext::ResourceRcl {
                request
                    .outbound
                    .as_ref()
                    .is_some_and(|transfer| transfer.resource.resource_hash == resource_hash)
            } else {
                request
                    .response
                    .as_ref()
                    .is_some_and(|response| response.current_segment == Some(resource_hash))
            }
        });
        if !matches {
            return;
        }
        self.inbound_resources.remove(&resource_hash);
        if let Some(route) = self.segment_routing.remove(&resource_hash) {
            self.inbound_split_resources.remove(&route.original_hash);
        }
        if let Some(link) = self.link.as_mut() {
            link.untrack_resource(&resource_hash);
        }
        self.fail();
    }

    fn complete_resource(&mut self, resource_hash: [u8; 32]) {
        let (assembled, proof) = {
            let Some(link) = self.link.as_ref() else {
                return;
            };
            let decrypt_fn = |ciphertext: &[u8]| -> Result<Vec<u8>, ResourceError> {
                link.decrypt(ciphertext).map_err(|_| ResourceError::Corrupt)
            };

            let Some(transfer) = self.inbound_resources.get_mut(&resource_hash) else {
                return;
            };
            match transfer.complete(Some(&decrypt_fn)) {
                Ok(result) => result,
                Err(_) => {
                    self.fail();
                    return;
                }
            }
        };
        if !self.send_resource_proof(&proof) {
            self.fail();
            return;
        }
        let route = self.segment_routing.remove(&resource_hash);
        if let Some(link) = self.link.as_mut() {
            link.untrack_resource(&resource_hash);
        }
        let metadata = self
            .inbound_resources
            .get(&resource_hash)
            .and_then(|transfer| transfer.resource.metadata.clone());
        self.inbound_resources.remove(&resource_hash);
        // Transfer duration does not consume the transport-result/intersegment
        // wait. In particular, a healthy slow segment can exceed this timeout.
        if let Some(response) = self
            .request
            .as_mut()
            .and_then(|request| request.response.as_mut())
        {
            response.waiting_since = Instant::now();
        }

        let Some(pending) = self.pending_endpoint_sends.last_mut() else {
            self.fail();
            return;
        };
        pending.success = EndpointSendSuccess::ResourceProof {
            assembled,
            route,
            metadata,
        };
    }

    fn finish_completed_resource(
        &mut self,
        assembled: Vec<u8>,
        route: Option<SegmentRoute>,
        metadata: Option<Vec<u8>>,
    ) {
        let Some(response) = self
            .request
            .as_mut()
            .and_then(|request| request.response.as_mut())
        else {
            return;
        };
        let Some(total) = response
            .assembled_bytes
            .checked_add(assembled.len())
            .filter(|total| *total <= MAX_RESOURCE_SIZE && *total <= response.data_size)
        else {
            self.fail();
            return;
        };
        response.assembled_bytes = total;
        response.current_segment = None;
        response.next_segment += 1;
        response.waiting_since = Instant::now();
        if response.next_segment > response.total_segments && total != response.data_size {
            self.fail();
            return;
        }
        if let Some(route) = route {
            let mut complete_payload = None;
            if let Some(coord) = self.inbound_split_resources.get_mut(&route.original_hash) {
                if coord
                    .set_segment_data(route.segment_index, assembled)
                    .is_err()
                {
                    self.fail();
                    return;
                }
                if let Some(meta) = metadata {
                    coord.set_metadata(meta);
                }
                if coord.is_complete() {
                    match coord.reassemble() {
                        Ok(payload) => complete_payload = Some(payload),
                        Err(_) => {
                            self.fail();
                            return;
                        }
                    }
                }
            }
            if let Some(payload) = complete_payload {
                self.inbound_split_resources.remove(&route.original_hash);
                self.handle_resource_response_owned(Bytes::from(payload));
            }
        } else {
            self.handle_resource_response_owned(Bytes::from(assembled));
        }
    }

    fn handle_resource_response_owned(&mut self, payload: Bytes) {
        if !self.handle_response_owned(payload) {
            self.fail();
        }
    }

    fn send_encrypted_resource_control(
        &mut self,
        context: rns_wire::context::PacketContext,
        plaintext: &[u8],
    ) {
        let encrypted = self
            .link
            .as_ref()
            .and_then(|link| link.encrypt(plaintext).ok());
        if let Some(encrypted) = encrypted {
            self.send_link_packet(context, rns_wire::flags::PacketType::Data, &encrypted);
        }
    }

    fn send_resource_proof(&mut self, proof: &[u8]) -> bool {
        self.send_link_packet(
            rns_wire::context::PacketContext::ResourcePrf,
            rns_wire::flags::PacketType::Proof,
            proof,
        )
    }

    fn send_link_packet(
        &mut self,
        context: rns_wire::context::PacketContext,
        packet_type: rns_wire::flags::PacketType,
        payload: &[u8],
    ) -> bool {
        let Some(link_id) = self.link_id else {
            return false;
        };
        let raw = Self::link_packet_bytes(link_id, context, packet_type, payload);
        if !self.queue_link_endpoint(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: link_id,
        }) {
            self.fail();
            false
        } else if let Some(link) = self.link.as_mut() {
            link.record_tx(payload.len());
            true
        } else {
            false
        }
    }

    fn link_packet_bytes(
        link_id: [u8; 16],
        context: rns_wire::context::PacketContext,
        packet_type: rns_wire::flags::PacketType,
        payload: &[u8],
    ) -> Vec<u8> {
        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type,
            },
            hops: 0,
            transport_id: None,
            destination_hash: link_id,
            context,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(payload);
        raw
    }

    fn send_final_link_packet(
        &mut self,
        context: rns_wire::context::PacketContext,
        packet_type: rns_wire::flags::PacketType,
        payload: &[u8],
    ) -> bool {
        let Some(link_id) = self.link_id else {
            return false;
        };
        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type,
            },
            hops: 0,
            transport_id: None,
            destination_hash: link_id,
            context,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(payload);
        self.queue_link_endpoint_and_unbind(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: link_id,
        })
    }

    /// Phase 1: parse available transient IDs from the server.
    fn handle_list_response(&mut self, response_data: &[u8]) {
        let value: rmpv::Value = match Self::decode_response_value(response_data) {
            Ok(v) => v,
            Err(_) => {
                self.fail();
                return;
            }
        };

        if let Some(arr) = value.as_array() {
            self.finish_request(response_data);
            self.available_messages.clear();
            for item in arr {
                if let Some(id_bytes) = item.as_slice()
                    && id_bytes.len() == 32
                {
                    self.available_messages.push(id_bytes.to_vec());
                }
            }

            if self.available_messages.is_empty() {
                self.status.state = PropagationClientState::Complete;
                self.status.progress = 1.0;
                self.status.result = Some(0);
            } else {
                self.send_get_request();
            }
        } else {
            self.fail();
        }
    }

    /// Validate type/count, exact requested TID membership, duplicates and full
    /// byte budget before publishing any item. Payload ranges borrow one owner.
    fn handle_get_response_owned(&mut self, response_data: Bytes) {
        let count = match self.request.as_ref().map(|request| request.kind) {
            Some(RequestKind::Get(count)) => count,
            _ => {
                self.fail();
                return;
            }
        };
        let parsed = (|| {
            let mut cursor = std::io::Cursor::new(response_data.as_ref());
            let n = rmp::decode::read_array_len(&mut cursor).map_err(|_| ())? as usize;
            if n > count || n > MAX_DOWNLOAD_ITEMS {
                return Err(());
            }
            let wanted: HashSet<_> = self
                .pending_wants
                .iter()
                .take(count)
                .map(Vec::as_slice)
                .collect();
            let mut seen = HashSet::new();
            let mut ranges = Vec::with_capacity(n);
            for _ in 0..n {
                let len = rmp::decode::read_bin_len(&mut cursor).map_err(|_| ())? as usize;
                let start = cursor.position() as usize;
                let end = start
                    .checked_add(len)
                    .filter(|end| *end <= response_data.len())
                    .ok_or(())?;
                let tid = rns_crypto::sha::full_hash(&response_data[start..end]);
                if !wanted.contains(tid.as_slice()) || !seen.insert(tid) {
                    return Err(());
                }
                ranges.push((start..end, tid));
                cursor.set_position(end as u64);
            }
            if cursor.position() as usize != response_data.len() {
                return Err(());
            }
            Ok(ranges)
        })();
        let Ok(ranges) = parsed else {
            self.fail();
            return;
        };
        let Ok(data) = retain_response(response_data, self.unread_limit) else {
            self.fail();
            return;
        };
        self.finish_request(&[]);
        self.pending_wants.drain(..count);
        self.admission_generation = self.admission_generation.wrapping_add(1);
        self.current_admission_generation
            .store(self.admission_generation, Ordering::Release);
        let identity = self.identity_hash();
        let node = self.outbound_propagation_node.unwrap_or([0; 16]);
        self.unread_bytes = data.len();
        self.status.admission.downloaded = self
            .status
            .admission
            .downloaded
            .saturating_add(ranges.len());
        for (range, transient_id) in ranges {
            let scope = AdmissionScope {
                identity,
                node,
                transient_id,
            };
            self.pending_admissions.insert(scope);
            let token = DownloadAdmissionToken::new(
                scope,
                self.admission_generation,
                self.current_admission_generation.clone(),
                self.admission_tx.clone(),
            );
            self.received_messages
                .push(DownloadedPropagationMessage::new(data.slice(range), token));
        }
        if self.pending_admissions.is_empty() {
            self.send_next_chunk();
        } else {
            self.status.state = PropagationClientState::AwaitingAdmission;
            self.admission_started = Some(Instant::now());
            self.admission_progress = self.admission_started;
        }
    }

    #[cfg(test)]
    fn handle_get_response(&mut self, data: &[u8]) {
        self.handle_get_response_owned(Bytes::copy_from_slice(data));
    }

    fn poll_admissions(&mut self) {
        while let Ok(result) = self.admission_rx.try_recv() {
            if result.generation != self.admission_generation
                || !self.pending_admissions.remove(&result.scope)
            {
                continue;
            }
            self.admission_progress = Some(Instant::now());
            match result.outcome {
                DownloadAdmissionOutcome::Accepted(receipt) => {
                    match receipt.record().disposition {
                        crate::admission::DurableDisposition::Committed => {
                            self.status.admission.committed += 1
                        }
                        crate::admission::DurableDisposition::Duplicate => {
                            self.status.admission.duplicate += 1
                        }
                        crate::admission::DurableDisposition::PolicyDiscard => {
                            self.status.admission.policy_discarded += 1
                        }
                        crate::admission::DurableDisposition::UserDeleted => {
                            self.status.admission.user_deleted += 1
                        }
                    }
                    self.remember_durable_have(crate::admission::DurableHave::from_record(
                        receipt.record(),
                    ));
                    self.received_ids.push(result.scope.transient_id.to_vec());
                    self.status.result = Some(self.status.result.unwrap_or(0).saturating_add(1));
                    if self.suppression.get(&receipt.record().scope).is_some() {
                        self.suppression.remove(&receipt.record().scope);
                        self.suppression_dirty = true;
                        self.suppression_revision = self.suppression_revision.wrapping_add(1);
                    }
                }
                DownloadAdmissionOutcome::Rejected(reason) => {
                    self.admission_failures += 1;
                    self.status.admission.rejected += 1;
                    self.status.admission.retryable += usize::from(reason.is_transient());
                    let now = crate::now_f64() as u64;
                    match self.suppression.record_failure(
                        result.scope,
                        reason,
                        self.admission_epochs,
                        now,
                    ) {
                        Ok(record) => {
                            self.suppression_updates.push(record.clone());
                            self.suppression_dirty = true;
                            self.suppression_revision = self.suppression_revision.wrapping_add(1);
                        }
                        Err(_) => self.suppression_persist_failed = true,
                    }
                }
            }
        }
        if self.status.state == PropagationClientState::AwaitingAdmission {
            if self.pending_admissions.is_empty() {
                self.admission_started = None;
                self.admission_progress = None;
                self.send_next_chunk();
            } else if self
                .admission_started
                .is_some_and(|t| t.elapsed() >= Duration::from_secs(600))
                || self
                    .admission_progress
                    .is_some_and(|t| t.elapsed() >= Duration::from_secs(120))
            {
                // Revokes authority only. External payload/worker leases remain live.
                self.admission_generation = self.admission_generation.wrapping_add(1);
                self.current_admission_generation
                    .store(self.admission_generation, Ordering::Release);
                self.admission_failures += self.pending_admissions.len();
                self.status.admission.rejected += self.pending_admissions.len();
                self.status.admission.retryable += self.pending_admissions.len();
                self.pending_admissions.clear();
                self.received_messages.clear();
                self.send_next_chunk();
            }
        }
    }

    fn decode_response_value(data: &[u8]) -> Result<rmpv::Value, ()> {
        let mut remaining = data;
        let value = rmpv::decode::read_value(&mut remaining).map_err(|_| ())?;
        if !remaining.is_empty() {
            return Err(());
        }
        Ok(value)
    }

    /// A successful purge is the empty array returned by Rust and Python
    /// nodes. In particular a peer error code or nil must not advance a cursor.
    fn handle_purge_response(&mut self, response_data: &[u8]) {
        if !matches!(Self::decode_response_value(response_data), Ok(rmpv::Value::Array(items)) if items.is_empty())
        {
            self.fail();
            return;
        }
        match self.finish_request(response_data) {
            Some(RequestKind::Haves(count)) => {
                self.pending_haves.drain(..count);
            }
            Some(RequestKind::Purge(count)) => {
                self.received_ids.drain(..count);
            }
            _ => {}
        }
        self.send_next_chunk();
    }

    pub fn tick(&mut self) {
        self.prune_suppression();
        self.poll_link_request();
        self.flush_pending_transport();
        self.poll_endpoint_control();
        if self.status.state == PropagationClientState::Failed {
            self.cleanup();
            return;
        }
        self.poll_admissions();

        if let Some(started) = self.started_at
            && started.elapsed() > self.timeout
            && self.status.state == PropagationClientState::LinkEstablishing
        {
            self.cleanup();
            self.fail();
            return;
        }

        if self.request.as_ref().is_some_and(|request| {
            request
                .waiting_since
                .is_some_and(|started| started.elapsed() > request.timeout)
                || request.response.as_ref().is_some_and(|response| {
                    self.inbound_resources.is_empty()
                        && response.waiting_since.elapsed() > request.timeout
                })
        }) {
            self.fail();
            self.cleanup();
            return;
        }

        let link_action = self.link.as_mut().map(Link::tick);
        match link_action {
            Some(LinkAction::SendKeepalive) | Some(LinkAction::TransitionedToStale) => {
                self.send_link_packet(
                    rns_wire::context::PacketContext::Keepalive,
                    rns_wire::flags::PacketType::Data,
                    &[rns_link::constants::KEEPALIVE_REQUEST],
                );
            }
            Some(LinkAction::SendTeardownAndClose(payload)) => {
                self.endpoint_release_queued = self.send_final_link_packet(
                    rns_wire::context::PacketContext::LinkClose,
                    rns_wire::flags::PacketType::Data,
                    &payload,
                );
                self.fail();
            }
            Some(LinkAction::Closed(_)) => self.fail(),
            Some(LinkAction::None) | None => {}
        }

        if self.status.state != PropagationClientState::Failed {
            self.drive_outbound_request();
        }

        if self.status.state == PropagationClientState::Receiving {
            let mut retry_requests = Vec::new();
            for transfer in self.inbound_resources.values_mut() {
                match transfer.check_timeout() {
                    TransferAction::SendRequest(request) => retry_requests.push(request),
                    TransferAction::Failed(_) => {
                        self.fail();
                        break;
                    }
                    _ => {}
                }
            }
            for request in retry_requests {
                self.send_encrypted_resource_control(
                    rns_wire::context::PacketContext::ResourceReq,
                    &request,
                );
            }
        }

        match self.status.state {
            PropagationClientState::Idle => {}
            PropagationClientState::LinkEstablishing => {}
            PropagationClientState::LinkEstablished => {
                if !self.identified {
                    self.send_identify();
                    if self.status.state == PropagationClientState::Failed {
                        return;
                    }
                    self.identified = true;
                }
                self.send_list_request();
            }
            PropagationClientState::ListRequested
            | PropagationClientState::GetRequested
            | PropagationClientState::Receiving
            | PropagationClientState::PurgeRequested
            | PropagationClientState::AwaitingAdmission => {}
            PropagationClientState::Complete
            | PropagationClientState::Partial
            | PropagationClientState::Failed => {
                self.cleanup();
            }
        }
    }

    fn send_identify(&mut self) {
        let outbound = if let (Some(link), Some(link_id)) = (&mut self.link, self.link_id) {
            if let (Some(pub_key), Some(sign_key)) = (&self.identity_pub, &self.identity_key) {
                if let Ok(identify_data) = link.identify(pub_key, sign_key) {
                    let id_header = rns_wire::header::PacketHeader {
                        flags: rns_wire::flags::PacketFlags {
                            header_type: rns_wire::flags::HeaderType::Header1,
                            context_flag: false,
                            transport_type: rns_wire::flags::TransportType::Broadcast,
                            destination_type: rns_wire::flags::DestinationType::Link,
                            packet_type: rns_wire::flags::PacketType::Data,
                        },
                        hops: 0,
                        transport_id: None,
                        destination_hash: link_id,
                        context: rns_wire::context::PacketContext::LinkIdentify,
                    };
                    let mut id_raw = id_header.pack();
                    id_raw.extend_from_slice(&identify_data);
                    Some(OutboundRequest {
                        raw: Bytes::from(id_raw),
                        destination_hash: link_id,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(outbound) = outbound
            && !self.queue_link_endpoint(outbound)
        {
            self.fail();
        }
    }

    /// Phase 1: `/get` with `[None, None]`.
    fn send_list_request(&mut self) {
        let data = crate::encode_value(&rmpv::Value::Array(vec![rmpv::Value::Nil; 2]));
        self.send_get_path_request(&data, RequestKind::List);
    }

    /// Snapshot selection once per cycle. Haves are purged before any wants;
    /// the configured message count limits the entire cycle, not each chunk.
    fn send_get_request(&mut self) {
        self.prune_expired_haves(crate::now_f64() as u64);
        self.pending_haves.clear();
        self.pending_wants.clear();
        let mut seen = HashSet::new();
        for id in &self.available_messages {
            if !seen.insert(id.clone()) {
                continue;
            }
            if self.local_messages.contains(id) {
                if !self.retain_synced_on_node {
                    self.pending_haves.push_back(id.clone());
                }
            } else if self.pending_wants.len() < self.max_messages.unwrap_or(usize::MAX) {
                let Ok(transient_id) = <[u8; 32]>::try_from(id.as_slice()) else {
                    continue;
                };
                let scope = AdmissionScope {
                    identity: self.identity_hash(),
                    node: self.outbound_propagation_node.unwrap_or([0; 16]),
                    transient_id,
                };
                if self.suppression_persist_failed
                    || self.suppression.saturated(scope.identity, scope.node)
                    || self
                        .suppression
                        .get(&scope)
                        .is_some_and(|r| r.active(crate::now_f64() as u64, self.admission_epochs))
                {
                    continue;
                }
                self.pending_wants.push_back(id.clone());
            }
        }
        self.status.result = Some(0);
        self.send_next_chunk();
    }

    fn chunk_body(&self, ids: &[Vec<u8>], get: bool) -> Vec<u8> {
        use rmpv::Value;
        let ids = Value::Array(ids.iter().cloned().map(Value::Binary).collect());
        let mut fields = if get {
            vec![ids, Value::Array(Vec::new())]
        } else {
            vec![Value::Nil, ids]
        };
        if get && let Some(limit) = self.delivery_limit {
            fields.push(Value::F64(limit));
        }
        crate::encode_value(&Value::Array(fields))
    }

    /// Fit the complete canonical request, not an assumed ID count. The
    /// timestamp/path portion is encoded with the same Value types as Link's
    /// prepare_request; its timestamp value does not change its wire length.
    fn bounded_chunk(&self, ids: &[Vec<u8>], get: bool) -> (usize, Vec<u8>) {
        use rmpv::Value;
        let overhead = crate::encode_value(&Value::Array(vec![
            Value::F64(0.0),
            Value::Binary(vec![0; 16]),
            Value::Nil,
        ]))
        .len()
            - 1;
        let mut low = 0;
        // Every valid transient ID consumes at least its 32 payload bytes.
        let mut high = ids
            .len()
            .min(MAX_DOWNLOAD_ITEMS)
            .min(MAX_EFFICIENT_SIZE / 32);
        while low < high {
            let count = low + (high - low).div_ceil(2);
            if self.chunk_body(&ids[..count], get).len() <= MAX_EFFICIENT_SIZE - overhead {
                low = count;
            } else {
                high = count - 1;
            }
        }
        (low, self.chunk_body(&ids[..low], get))
    }

    fn send_next_chunk(&mut self) {
        if self.request.is_some()
            || !self.pending_admissions.is_empty()
            || self.status.state == PropagationClientState::Failed
        {
            return;
        }
        self.prune_expired_haves(crate::now_f64() as u64);
        if !self.received_ids.is_empty() {
            self.send_purge_request();
        } else if !self.pending_haves.is_empty() {
            let ids: Vec<_> = self
                .pending_haves
                .iter()
                .take(MAX_EFFICIENT_SIZE / 32)
                .cloned()
                .collect();
            let (count, data) = self.bounded_chunk(&ids, false);
            self.send_get_path_request(&data, RequestKind::Haves(count));
        } else if self.suppression_dirty || self.suppression_persist_failed {
            self.status.state = PropagationClientState::AwaitingAdmission;
        } else if !self.pending_wants.is_empty() {
            let ids: Vec<_> = self
                .pending_wants
                .iter()
                .take(MAX_EFFICIENT_SIZE / 32)
                .cloned()
                .collect();
            let (count, data) = self.bounded_chunk(&ids, true);
            self.status.progress = 0.0;
            self.status.data_size = None;
            self.send_get_path_request(&data, RequestKind::Get(count));
        } else {
            self.status.state = if self.admission_failures == 0 {
                PropagationClientState::Complete
            } else {
                PropagationClientState::Partial
            };
            self.status.progress = 1.0;
            self.status.result.get_or_insert(0);
        }
    }

    fn send_purge_request(&mut self) {
        let (count, data) = self.bounded_chunk(&self.received_ids, false);
        self.send_get_path_request(&data, RequestKind::Purge(count));
    }

    fn send_get_path_request(&mut self, request_data: &[u8], kind: RequestKind) -> bool {
        if self.request.is_some() {
            self.fail();
            return false;
        }
        let Some(link) = self.link.as_mut() else {
            self.fail();
            return false;
        };
        let timeout = link.default_request_timeout().max(Duration::from_secs(60));
        let Ok((packed, id)) = link.prepare_request(MESSAGE_GET_PATH, Some(request_data), timeout)
        else {
            self.fail();
            return false;
        };
        if packed.len() > MAX_EFFICIENT_SIZE {
            link.fail_pending_request(&id);
            self.fail();
            return false;
        }
        let Some(generation) = self.next_request_generation.checked_add(1) else {
            link.fail_pending_request(&id);
            self.fail();
            return false;
        };
        self.next_request_generation = generation;
        let resource = packed.len() > link.mdu;
        let mut packed = Some(packed);
        let outbound = if resource {
            let Some(keys) = link.session_keys() else {
                link.fail_pending_request(&id);
                self.fail();
                return false;
            };
            let Ok(mut transfer) = OutboundTransfer::new_encrypted(
                packed.take().unwrap(),
                true,
                link.rtt.unwrap_or(Duration::from_millis(500)),
                keys,
            ) else {
                link.fail_pending_request(&id);
                self.fail();
                return false;
            };
            transfer.resource.flags.is_request = true;
            transfer.resource.request_id = Some(id.to_vec());
            link.mark_request_resource_sending(&id);
            link.track_outgoing_resource(transfer.resource.resource_hash);
            Some(transfer)
        } else {
            None
        };
        // Packet encryption is deliberately separate from prepare_request so
        // the size decision precedes ciphertext construction and MTU admission.
        let packet = if !resource {
            let body = packed.take().unwrap();
            match link.encrypt(&body) {
                Ok(data) => Some(data),
                Err(_) => {
                    link.fail_pending_request(&id);
                    self.fail();
                    return false;
                }
            }
        } else {
            None
        };
        self.request = Some(PendingRequest {
            link_id: link.link_id,
            generation,
            id,
            kind,
            sender_active: true,
            outbound,
            response: None,
            waiting_since: None,
            timeout,
        });
        self.receiving_for = None;
        self.status.state = kind.state();
        if let Some(packet) = packet {
            // Hash the exact header/ciphertext that send_link_packet emits.
            let raw = Self::link_packet_bytes(
                link.link_id,
                rns_wire::context::PacketContext::Request,
                rns_wire::flags::PacketType::Data,
                &packet,
            );
            let packet_id =
                rns_wire::hash::truncated_packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
            link.update_pending_request_id(&id, packet_id);
            self.request.as_mut().unwrap().id = packet_id;
            self.send_link_packet(
                rns_wire::context::PacketContext::Request,
                rns_wire::flags::PacketType::Data,
                &packet,
            );
        } else {
            self.drive_outbound_request();
        }
        self.status.state != PropagationClientState::Failed
    }

    fn drive_outbound_request(&mut self) {
        let action = self
            .request
            .as_mut()
            .and_then(|request| request.outbound.as_mut())
            .map(OutboundTransfer::tick);
        match action {
            Some(TransferAction::SendAdvertisement(data)) => {
                self.send_encrypted_resource_control(
                    rns_wire::context::PacketContext::ResourceAdv,
                    &data,
                );
            }
            Some(TransferAction::Failed(_)) => self.fail(),
            _ => {}
        }
    }

    fn handle_outbound_request(&mut self, data: &[u8]) {
        let Some(plaintext) = self.link.as_ref().and_then(|link| link.decrypt(data).ok()) else {
            return;
        };
        let offset = if plaintext.first() == Some(&rns_protocol::resource::HASHMAP_IS_EXHAUSTED) {
            1 + rns_protocol::resource::MAPHASH_LEN
        } else if plaintext.first() == Some(&rns_protocol::resource::HASHMAP_IS_NOT_EXHAUSTED) {
            1
        } else {
            return;
        };
        let Some(transfer) = self
            .request
            .as_mut()
            .and_then(|request| request.outbound.as_mut())
        else {
            return;
        };
        if plaintext.get(offset..offset + 32) != Some(transfer.resource.resource_hash.as_slice()) {
            return;
        }
        for action in transfer.handle_request(&plaintext) {
            match action {
                TransferAction::SendPart(_, data) => {
                    self.send_link_packet(
                        rns_wire::context::PacketContext::Resource,
                        rns_wire::flags::PacketType::Data,
                        &data,
                    );
                }
                TransferAction::SendHmu(data) => self.send_encrypted_resource_control(
                    rns_wire::context::PacketContext::ResourceHmu,
                    &data,
                ),
                TransferAction::SendCancel(_, hash) => {
                    self.send_encrypted_resource_control(
                        rns_wire::context::PacketContext::ResourceIcl,
                        &hash,
                    );
                    self.fail();
                }
                TransferAction::Failed(_) => self.fail(),
                _ => {}
            }
            if self.status.state == PropagationClientState::Failed {
                break;
            }
        }
    }

    fn handle_outbound_proof(&mut self, proof: &[u8]) {
        if self
            .request
            .as_mut()
            .and_then(|request| request.outbound.as_mut())
            .is_some_and(|transfer| transfer.handle_proof(proof))
        {
            self.retire_request_sender();
            if let Some(request) = self.request.as_mut() {
                request.waiting_since = Some(Instant::now());
                if let Some(link) = self.link.as_mut() {
                    link.mark_request_resource_sent(&request.id);
                }
            }
        }
    }

    fn retire_request_sender(&mut self) {
        let Some(request) = self.request.as_mut() else {
            return;
        };
        request.sender_active = false;
        if let Some(transfer) = request.outbound.take()
            && let Some(link) = self.link.as_mut()
        {
            link.untrack_resource(&transfer.resource.resource_hash);
        }
        let link_id = request.link_id;
        // Remove bytes still owned by our local staging queue. Actor/driver
        // admitted bytes are non-recallable; generation-scoped outcomes below
        // cannot settle a different phase.
        self.pending_transport.retain(|message| {
            let TransportMessage::SendLinkEndpoint { request, .. } = message else {
                return true;
            };
            let Ok((header, _)) = rns_wire::header::PacketHeader::unpack(&request.raw) else {
                return true;
            };
            use rns_wire::context::PacketContext;
            header.destination_hash != link_id
                || !matches!(
                    header.context,
                    PacketContext::Request
                        | PacketContext::ResourceAdv
                        | PacketContext::Resource
                        | PacketContext::ResourceHmu
                        | PacketContext::ResourceIcl
                )
        });
    }

    fn finish_request(&mut self, data: &[u8]) -> Option<RequestKind> {
        self.retire_request_sender();
        let request = self.request.take()?;
        if let Some(link) = self.link.as_mut() {
            link.deliver_response_data(&request.id, data.to_vec());
            for hash in self.inbound_resources.keys() {
                link.untrack_resource(hash);
            }
        }
        self.inbound_resources.clear();
        self.inbound_split_resources.clear();
        self.segment_routing.clear();
        self.receiving_for = None;
        Some(request.kind)
    }

    fn handle_response_owned(&mut self, data: Bytes) -> bool {
        let mut cursor = std::io::Cursor::new(data.as_ref());
        if rmp::decode::read_array_len(&mut cursor).ok() != Some(2)
            || rmp::decode::read_bin_len(&mut cursor).ok() != Some(16)
        {
            return false;
        }
        let start = cursor.position() as usize;
        let Some(id) = data.get(start..start + 16) else {
            return false;
        };
        if !self.request.as_ref().is_some_and(|request| {
            request.id.as_slice() == id && Some(request.link_id) == self.link_id
        }) {
            return false;
        }
        let payload = data.slice(start + 16..);
        if matches!(
            self.request.as_ref().map(|r| r.kind),
            Some(RequestKind::Get(_))
        ) {
            self.handle_get_response_owned(payload);
        } else {
            self.handle_response_data(&payload);
        }
        true
    }

    fn revoke_admissions(&mut self) {
        self.admission_generation = self.admission_generation.wrapping_add(1);
        self.current_admission_generation
            .store(self.admission_generation, Ordering::Release);
        self.pending_admissions.clear();
        self.received_messages.clear();
        self.unread_bytes = 0;
        self.admission_started = None;
        self.admission_progress = None;
    }
    fn fail(&mut self) {
        // Revoke at the failure observation, before an adapter or later tick
        // could accept a completed blocking worker under the old generation.
        self.revoke_admissions();
        self.status.state = PropagationClientState::Failed;
    }

    fn cleanup(&mut self) {
        self.link_request_result = None;
        self.pending_transport
            .retain(|message| !matches!(message, TransportMessage::SendLinkRequest { .. }));
        self.revoke_admissions();
        self.request = None;
        if let Some(link_id) = self.link_id {
            self.pending_transport.retain(|message| {
                !matches!(message,
                TransportMessage::SendLinkEndpoint { link_id: id, .. } if *id == link_id)
            });
        }
        let graceful_release = self.endpoint_release_queued || self.send_teardown();
        if let Some(link_id) = self.link_id.take()
            && !graceful_release
        {
            self.queue_endpoint_cleanup(link_id);
        }
        self.attached_interface = None;
        self.endpoint_release_queued = false;
        self.pending_endpoint_bind = None;
        self.link = None;
        self.inbound_resources.clear();
        self.inbound_split_resources.clear();
        self.segment_routing.clear();
        self.receiving_for = None;
        self.started_at = None;
    }

    fn send_teardown(&mut self) -> bool {
        let Some(link_id) = self.link_id else {
            return false;
        };
        let teardown_data = self
            .link
            .as_mut()
            .and_then(|link| link.teardown(CloseReason::InitiatorClosed));
        if let Some(teardown_data) = teardown_data {
            let retained = self.send_final_link_packet(
                rns_wire::context::PacketContext::LinkClose,
                rns_wire::flags::PacketType::Data,
                &teardown_data,
            );
            tracing::debug!(
                link_id = hex::encode(link_id),
                "propagation client link closed"
            );
            retained
        } else {
            false
        }
    }

    pub fn received_count(&self) -> usize {
        self.received_messages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn fixture_download(
        client: &PropagationClient,
        data: Vec<u8>,
    ) -> DownloadedPropagationMessage {
        let scope = AdmissionScope {
            identity: client.identity_hash(),
            node: client.outbound_propagation_node.unwrap_or([0; 16]),
            transient_id: rns_crypto::sha::full_hash(&data),
        };
        let token = DownloadAdmissionToken::new(
            scope,
            client.admission_generation,
            client.current_admission_generation.clone(),
            client.admission_tx.clone(),
        );
        DownloadedPropagationMessage::new(
            retain_response(data.into(), client.unread_limit).unwrap(),
            token,
        )
    }
    pub(super) fn downloaded_bytes(messages: &[DownloadedPropagationMessage]) -> Vec<Vec<u8>> {
        messages.iter().map(|m| m.data().to_vec()).collect()
    }

    use rns_protocol::resource::OutboundTransfer;

    fn prime_get(client: &mut PropagationClient, messages: &[Vec<u8>]) {
        client.pending_wants = messages
            .iter()
            .map(|bytes| rns_crypto::sha::full_hash(bytes).to_vec())
            .collect();
        client.status.state = PropagationClientState::GetRequested;
        client.request = Some(PendingRequest {
            link_id: [1; 16],
            generation: 1,
            id: [2; 16],
            kind: RequestKind::Get(messages.len()),
            sender_active: false,
            outbound: None,
            response: None,
            waiting_since: Some(Instant::now()),
            timeout: Duration::from_secs(60),
        });
    }
    fn next_link_request(rx: &mut mpsc::Receiver<TransportMessage>) -> OutboundRequest {
        while let Ok(message) = rx.try_recv() {
            match message {
                TransportMessage::Outbound(request) => return request,
                TransportMessage::SendLinkRequest { request, result_tx } => {
                    let _ = result_tx.send(Ok(()));
                    return request;
                }

                TransportMessage::SendLinkEndpoint {
                    request, result_tx, ..
                } => {
                    let _ = result_tx.send(LinkEndpointSendResult::Sent);
                    return request;
                }
                _ => {}
            }
        }
        panic!("expected Link packet");
    }

    fn complete_client_cleanup(
        client: &mut PropagationClient,
        rx: &mut mpsc::Receiver<TransportMessage>,
    ) -> bool {
        let mut saw_deregister = false;
        while let Ok(message) = rx.try_recv() {
            match message {
                TransportMessage::UnbindLinkEndpoint { result_tx, .. } => {
                    let _ = result_tx.send(LinkEndpointUnbindResult::Unbound);
                }
                TransportMessage::DeregisterDestination { .. } => saw_deregister = true,
                _ => {}
            }
        }
        client.poll_endpoint_control();
        while let Ok(message) = rx.try_recv() {
            saw_deregister |= matches!(message, TransportMessage::DeregisterDestination { .. });
        }
        saw_deregister
    }

    fn active_link_pair(dest_hash: [u8; 16]) -> (Link, Link) {
        let responder_key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let responder_pub = responder_key.public_key();
        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &responder_key, dest_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &responder_pub, &responder_pub.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();
        (initiator, responder)
    }

    fn link_data_packet(
        link_id: [u8; 16],
        context: rns_wire::context::PacketContext,
        payload: &[u8],
    ) -> Bytes {
        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: link_id,
            context,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(payload);
        Bytes::from(raw)
    }

    #[test]
    fn test_client_creation() {
        let (tx, _rx) = mpsc::channel(16);
        let client = PropagationClient::new(tx, None, None);
        assert_eq!(client.status.state, PropagationClientState::Idle);
        assert_eq!(client.received_count(), 0);
    }

    #[test]
    fn test_set_propagation_node() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        assert!(client.outbound_propagation_node.is_none());

        client.set_propagation_node([0xAA; 16]);
        assert_eq!(client.outbound_propagation_node, Some([0xAA; 16]));
    }

    #[test]
    fn test_start_download_no_node() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        assert!(!client.start_download());
        assert_eq!(client.status.state, PropagationClientState::Idle);
    }

    #[test]
    fn test_start_download_sends_link_request() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xBB; 16]);

        assert!(client.start_download());
        assert_eq!(
            client.status.state,
            PropagationClientState::LinkEstablishing
        );
        assert!(client.link_id.is_some());

        let reg = rx.try_recv();
        assert!(matches!(
            reg.unwrap(),
            TransportMessage::RegisterDestination { .. }
        ));
        let outbound = rx.try_recv();
        assert!(matches!(
            outbound.unwrap(),
            TransportMessage::SendLinkRequest { .. }
        ));
    }

    #[test]
    fn start_download_rejects_a_closed_transport_instead_of_false_success() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xB0; 16]);

        assert!(!client.start_download());
        assert_eq!(client.state(), PropagationClientState::Idle);
        assert!(client.link.is_none());
        assert!(client.pending_transport.is_empty());
    }

    #[test]
    fn start_download_preserves_register_before_request_under_backpressure() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(TransportMessage::DeregisterDestination { hash: [1; 16] })
            .unwrap();
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xB2; 16]);

        assert!(client.start_download());
        assert_eq!(client.pending_transport.len(), 2);
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::DeregisterDestination { .. }
        ));
        client.tick();
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::RegisterDestination { .. }
        ));
        client.tick();
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::SendLinkRequest { .. }
        ));
        assert!(client.pending_transport.is_empty());
    }

    #[test]
    fn invalid_client_lrproof_allows_later_valid_binding_before_lrrtt() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        let node_hash = [0xB4; 16];
        let (link, request_data) = Link::new_initiator(node_hash, 1);
        let link_id = link.link_id;
        let responder_key = Ed25519PrivateKey::generate();
        let responder_public = responder_key.public_key();
        let (_responder, proof) =
            Link::new_responder(&request_data, &responder_key, node_hash, 1).unwrap();
        client.link = Some(link);
        client.link_id = Some(link_id);
        client.status.state = PropagationClientState::LinkEstablishing;

        client.handle_link_proof(
            &[0u8; 99],
            &responder_public,
            &responder_public.to_bytes(),
            7,
        );
        assert_eq!(client.state(), PropagationClientState::LinkEstablishing);
        assert!(client.pending_endpoint_bind.is_none());
        assert!(rx.try_recv().is_err());

        client.handle_link_proof(&proof, &responder_public, &responder_public.to_bytes(), 8);
        let TransportMessage::BindLinkEndpoint {
            binding, result_tx, ..
        } = rx.try_recv().unwrap()
        else {
            panic!("valid proof must bind before LRRTT");
        };
        assert_eq!(binding.interface_id, 8);
        assert!(rx.try_recv().is_err());
        result_tx.send(LinkEndpointBindResult::Bound).unwrap();
        client.poll_endpoint_control();
        let TransportMessage::SendLinkEndpoint { request, role, .. } = rx.try_recv().unwrap()
        else {
            panic!("bound endpoint must carry LRRTT");
        };
        assert_eq!(role, LinkEndpointRole::Initiator);
        let (header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(header.context, rns_wire::context::PacketContext::Lrrtt);
    }

    #[test]
    fn test_start_download_rejects_an_active_transfer() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xBC; 16]);

        assert!(client.start_download());
        while rx.try_recv().is_ok() {}

        assert!(!client.start_download());
        assert!(rx.try_recv().is_err());
        assert_eq!(client.state(), PropagationClientState::LinkEstablishing);
    }

    #[test]
    fn test_add_local_messages() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);

        client.add_local_message([0xAA; 32]);
        client.add_local_message([0xBB; 32]);
        assert_eq!(client.local_messages.len(), 2);
        assert!(client.local_messages.contains(&vec![0xAA; 32]));
        client.add_local_message_id(vec![0xCC; 32]);
        assert!(client.local_messages.contains(&vec![0xCC; 32]));
    }

    #[test]
    fn test_set_delivery_limit() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_delivery_limit(512.0);
        assert_eq!(client.delivery_limit, Some(512.0));
    }

    #[test]
    fn get_request_honours_max_messages_and_retain_policy() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        let (initiator, responder) = active_link_pair([0xB3; 16]);
        client.link_id = Some(initiator.link_id);
        client.link = Some(initiator);
        client.max_messages = Some(1);
        client.retain_synced_on_node = true;
        client.available_messages = vec![vec![1; 32], vec![2; 32], vec![3; 32]];
        client.local_messages.insert(vec![1; 32]);

        client.send_get_request();
        let request = next_link_request(&mut rx);
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        let (_, _, _, request_data) = responder.handle_request(&request.raw[offset..]).unwrap();
        let value = rmpv::decode::read_value(&mut &request_data[..]).unwrap();
        let fields = value.as_array().unwrap();
        assert_eq!(
            fields[0].as_array().unwrap(),
            &[rmpv::Value::Binary(vec![2; 32])]
        );
        assert!(fields[1].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_take_received_messages() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);

        client
            .received_messages
            .push(fixture_download(&client, vec![0x01, 0x02]));
        client
            .received_messages
            .push(fixture_download(&client, vec![0x03, 0x04]));
        assert_eq!(client.received_count(), 2);

        let messages = client.take_downloaded_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(client.received_count(), 0);
    }

    #[test]
    fn test_handle_list_response_empty() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.status.state = PropagationClientState::ListRequested;

        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &rmpv::Value::Array(vec![])).unwrap();

        client.handle_list_response(&buf);
        assert_eq!(client.status.state, PropagationClientState::Complete);
    }

    #[test]
    fn test_handle_list_response_invalid() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.status.state = PropagationClientState::ListRequested;

        client.handle_list_response(&[0xFF, 0xFF]);
        assert_eq!(client.status.state, PropagationClientState::Failed);
    }

    #[test]
    fn test_handle_list_response_accepts_python_full_hash_ids() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.status.state = PropagationClientState::ListRequested;

        let id32 = vec![0xAB; 32];
        let response = rmpv::Value::Array(vec![rmpv::Value::Binary(id32.clone())]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &response).unwrap();

        client.handle_list_response(&buf);
        assert_eq!(client.available_messages, vec![id32]);
        // It accepted the 32-byte ID, then failed only because this unit test
        // has no live link on which to send the follow-up `/get`.
        assert_eq!(client.status.state, PropagationClientState::Failed);
    }

    #[test]
    fn test_handle_list_response_rejects_pre_fix_16_byte_ids() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.status.state = PropagationClientState::ListRequested;

        let response = rmpv::Value::Array(vec![rmpv::Value::Binary(vec![0xAB; 16])]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &response).unwrap();

        client.handle_list_response(&buf);
        assert!(client.available_messages.is_empty());
        assert_eq!(client.status.state, PropagationClientState::Complete);
    }

    #[test]
    fn test_handle_get_response_parses_messages() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xBB; 16]);
        client.start_download();
        client.status.state = PropagationClientState::GetRequested;

        let msg1 = vec![0xAA; 100];
        let msg2 = vec![0xBB; 200];
        let response = rmpv::Value::Array(vec![
            rmpv::Value::Binary(msg1.clone()),
            rmpv::Value::Binary(msg2.clone()),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &response).unwrap();

        prime_get(&mut client, &[msg1.clone(), msg2.clone()]);
        client.handle_get_response(&buf);
        assert_eq!(client.received_messages.len(), 2);
        assert_eq!(client.received_messages[0].data().as_ref(), msg1);
        assert_eq!(client.received_messages[1].data().as_ref(), msg2);
        assert!(
            client.received_ids.is_empty(),
            "uncommitted bytes grant no purge authority"
        );
        assert_eq!(
            client.received_messages[0].scope().transient_id,
            rns_crypto::sha::full_hash(&msg1)
        );
        assert_eq!(client.state(), PropagationClientState::AwaitingAdmission);
        assert_eq!(client.transfer_status().result, None);
    }

    #[test]
    fn test_handle_get_response_empty() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.status.state = PropagationClientState::GetRequested;

        prime_get(&mut client, &[]);
        let response = rmpv::Value::Array(vec![]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &response).unwrap();

        client.handle_get_response(&buf);
        assert_eq!(client.status.state, PropagationClientState::Complete);
    }

    #[test]
    fn resource_response_retains_the_request_phase() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.status.state = PropagationClientState::Receiving;
        client.receiving_for = Some(PropagationClientState::GetRequested);

        prime_get(&mut client, &[]);
        let response = rmpv::Value::Array(vec![]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &response).unwrap();
        client.status.state = PropagationClientState::Receiving;
        client.handle_response_data(&buf);

        assert_eq!(client.status.state, PropagationClientState::Complete);
        assert_eq!(client.status.progress, 1.0);
        assert_eq!(client.status.result, Some(0));
        assert!(client.receiving_for.is_none());
    }

    #[test]
    fn resource_response_reports_size_and_monotonic_progress() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        let (initiator, responder) = active_link_pair([0xE3; 16]);
        client.link_id = Some(initiator.link_id);
        client.link = Some(initiator);
        client.status.state = PropagationClientState::GetRequested;
        client.request = Some(PendingRequest {
            link_id: client.link_id.unwrap(),
            generation: 1,
            id: [0x44; 16],
            kind: RequestKind::Get(0),
            sender_active: false,
            outbound: None,
            response: None,
            waiting_since: Some(Instant::now()),
            timeout: Duration::from_secs(60),
        });

        let payload = vec![0xAB; 3_000];
        let mut sender = OutboundTransfer::new_encrypted(
            payload.clone(),
            false,
            Duration::from_millis(50),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        sender.resource.flags.is_response = true;
        sender.resource.request_id = Some(vec![0x44; 16]);
        let advertisement = match sender.tick() {
            TransferAction::SendAdvertisement(data) => data,
            other => panic!("expected Resource advertisement, got {other:?}"),
        };
        let encrypted_advertisement = responder.encrypt(&advertisement).unwrap();

        client.handle_resource_advertisement(&encrypted_advertisement);
        assert_eq!(client.status.state, PropagationClientState::Receiving);
        assert_eq!(client.status.data_size, Some(payload.len()));
        assert_eq!(
            client.receiving_for,
            Some(PropagationClientState::GetRequested)
        );

        let request = next_link_request(&mut rx);
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        let request_data = responder.decrypt(&request.raw[offset..]).unwrap();
        let first_part = sender
            .handle_request(&request_data)
            .into_iter()
            .find_map(|action| match action {
                TransferAction::SendPart(_, data) => Some(data),
                _ => None,
            })
            .expect("sender emits at least one requested part");

        client.handle_resource_part(&first_part);
        assert!(client.status.progress > 0.0);
        assert!(client.status.progress < 1.0);
        let first_progress = client.status.progress;
        client.handle_resource_part(&first_part);
        assert!(client.status.progress >= first_progress);
    }

    #[test]
    fn resource_response_is_not_published_when_its_proof_cannot_be_retained() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        let (initiator, responder) = active_link_pair([0xE5; 16]);
        client.link_id = Some(initiator.link_id);
        client.link = Some(initiator);
        client.attached_interface = Some(0);
        client.status.state = PropagationClientState::GetRequested;
        client.request = Some(PendingRequest {
            link_id: client.link_id.unwrap(),
            generation: 1,
            id: [0x44; 16],
            kind: RequestKind::Get(0),
            sender_active: false,
            outbound: None,
            response: None,
            waiting_since: Some(Instant::now()),
            timeout: Duration::from_secs(60),
        });

        let response = rmpv::Value::Array(vec![rmpv::Value::Binary(vec![0xAB; 32])]);
        let payload = crate::encode_value(&response);
        let mut sender = OutboundTransfer::new_encrypted(
            payload,
            false,
            Duration::from_millis(50),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        sender.resource.flags.is_response = true;
        sender.resource.request_id = Some(vec![0x44; 16]);
        let advertisement = match sender.tick() {
            TransferAction::SendAdvertisement(data) => data,
            other => panic!("expected Resource advertisement, got {other:?}"),
        };
        client.handle_resource_advertisement(&responder.encrypt(&advertisement).unwrap());
        let request = next_link_request(&mut rx);
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        let request_data = responder.decrypt(&request.raw[offset..]).unwrap();
        let parts: Vec<Vec<u8>> = sender
            .handle_request(&request_data)
            .into_iter()
            .filter_map(|action| match action {
                TransferAction::SendPart(_, data) => Some(data),
                _ => None,
            })
            .collect();
        drop(rx);
        for part in parts {
            client.handle_resource_part(&part);
        }

        assert_eq!(client.state(), PropagationClientState::Failed);
        assert!(client.received_messages.is_empty());
    }

    #[test]
    fn resource_response_is_not_published_when_transport_rejects_its_proof() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        let (initiator, responder) = active_link_pair([0xE6; 16]);
        client.link_id = Some(initiator.link_id);
        client.link = Some(initiator);
        client.attached_interface = Some(0);
        client.status.state = PropagationClientState::GetRequested;
        client.request = Some(PendingRequest {
            link_id: client.link_id.unwrap(),
            generation: 1,
            id: [0x44; 16],
            kind: RequestKind::Get(0),
            sender_active: false,
            outbound: None,
            response: None,
            waiting_since: Some(Instant::now()),
            timeout: Duration::from_secs(60),
        });

        let response = rmpv::Value::Array(vec![rmpv::Value::Binary(vec![0xAC; 32])]);
        let mut sender = OutboundTransfer::new_encrypted(
            crate::encode_value(&response),
            false,
            Duration::from_millis(50),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        sender.resource.flags.is_response = true;
        sender.resource.request_id = Some(vec![0x44; 16]);
        let advertisement = match sender.tick() {
            TransferAction::SendAdvertisement(data) => data,
            other => panic!("expected Resource advertisement, got {other:?}"),
        };
        client.handle_resource_advertisement(&responder.encrypt(&advertisement).unwrap());
        let request = next_link_request(&mut rx);
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        let request_data = responder.decrypt(&request.raw[offset..]).unwrap();
        for part in sender
            .handle_request(&request_data)
            .into_iter()
            .filter_map(|action| match action {
                TransferAction::SendPart(_, data) => Some(data),
                _ => None,
            })
        {
            client.handle_resource_part(&part);
        }

        let TransportMessage::SendLinkEndpoint { result_tx, .. } =
            rx.try_recv().expect("Resource proof send")
        else {
            panic!("expected typed Resource proof send");
        };
        result_tx
            .send(LinkEndpointSendResult::InvalidPacket)
            .unwrap();
        client.poll_endpoint_control();

        assert_eq!(client.state(), PropagationClientState::Failed);
        assert!(client.received_messages.is_empty());
        assert!(client.received_ids.is_empty());
    }

    #[test]
    fn test_handle_purge_response() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.status.state = PropagationClientState::PurgeRequested;

        client.handle_purge_response(&[0x90]);
        assert_eq!(client.status.state, PropagationClientState::Complete);
    }

    #[test]
    fn test_timeout_fails() {
        let (tx, _rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xCC; 16]);
        client.start_download();
        assert_eq!(
            client.status.state,
            PropagationClientState::LinkEstablishing
        );

        client.timeout = Duration::ZERO;

        client.tick();
        assert_eq!(client.status.state, PropagationClientState::Failed);

        client.tick();
        assert_eq!(client.status.state, PropagationClientState::Failed);
        assert!(client.acknowledge_transfer());
        assert_eq!(client.status.state, PropagationClientState::Idle);
    }

    #[test]
    fn progressive_resource_phase_is_not_killed_by_absolute_operation_timeout() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        let (initiator, _responder) = active_link_pair([0xC1; 16]);
        client.link_id = Some(initiator.link_id);
        client.link = Some(initiator);
        client.status.state = PropagationClientState::Receiving;
        client.started_at = Some(Instant::now() - Duration::from_secs(600));
        client.timeout = Duration::ZERO;

        client.tick();

        assert_eq!(client.state(), PropagationClientState::Receiving);
        assert!(client.link.is_some());
    }

    #[test]
    fn test_cleanup_deregisters() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xDD; 16]);
        client.start_download();
        while rx.try_recv().is_ok() {}

        client.status.state = PropagationClientState::Complete;
        client.tick();

        let saw_deregister = complete_client_cleanup(&mut client, &mut rx);
        assert!(saw_deregister);
    }

    #[test]
    fn failed_final_send_unbinds_before_deregistering_client_link() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        let (initiator, _) = active_link_pair([0xD9; 16]);
        let link_id = initiator.link_id;
        client.link_id = Some(link_id);
        client.link = Some(initiator);
        client.status.state = PropagationClientState::ListRequested;

        assert!(client.send_final_link_packet(
            rns_wire::context::PacketContext::LinkClose,
            rns_wire::flags::PacketType::Data,
            &[0x01],
        ));
        let TransportMessage::SendLinkEndpointAndUnbind { result_tx, .. } =
            rx.try_recv().expect("final Link send")
        else {
            panic!("expected atomic final Link send");
        };
        result_tx
            .send(LinkEndpointSendResult::InvalidPacket)
            .unwrap();
        client.poll_endpoint_control();
        assert_eq!(client.state(), PropagationClientState::Failed);

        let TransportMessage::UnbindLinkEndpoint { result_tx, .. } =
            rx.try_recv().expect("role-safe fallback unbind")
        else {
            panic!("failed final send must fall back to exact-owner unbind");
        };
        assert!(rx.try_recv().is_err(), "deregister must wait for unbind");
        result_tx.send(LinkEndpointUnbindResult::Unbound).unwrap();
        client.poll_endpoint_control();
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::DeregisterDestination { hash } if hash == link_id
        ));
    }

    #[test]
    fn test_authenticated_remote_link_close_fails_and_cleans_up() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        let node_hash = [0xE1; 16];
        let (link, mut responder_link) = active_link_pair(node_hash);
        let link_id = link.link_id;
        client.link = Some(link);
        client.link_id = Some(link_id);
        client.attached_interface = Some(0);
        client.status.state = PropagationClientState::ListRequested;
        client.started_at = Some(Instant::now());

        let close_body = responder_link
            .teardown(CloseReason::InitiatorClosed)
            .expect("remote active link emits authenticated teardown");
        client
            .event_tx
            .try_send(DestinationEvent::InboundPacket {
                interface_owner: None,
                raw: link_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::LinkClose,
                    &close_body,
                ),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();

        client.drain_events(&std::collections::HashMap::new());
        assert_eq!(client.status.state, PropagationClientState::Failed);

        client.tick();
        assert_eq!(client.status.state, PropagationClientState::Failed);
        assert!(client.link.is_none());
        let saw_deregister = complete_client_cleanup(&mut client, &mut rx);
        assert!(saw_deregister);
        assert!(client.acknowledge_transfer());
        assert_eq!(client.status.state, PropagationClientState::Idle);
    }

    #[test]
    fn test_unauthenticated_link_close_is_ignored() {
        let (tx, _rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        let node_hash = [0xE2; 16];
        let (link, _responder_link) = active_link_pair(node_hash);
        let link_id = link.link_id;
        client.link = Some(link);
        client.link_id = Some(link_id);
        client.attached_interface = Some(0);
        client.status.state = PropagationClientState::ListRequested;

        client
            .event_tx
            .try_send(DestinationEvent::InboundPacket {
                interface_owner: None,
                raw: link_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &[0u8]),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();

        client.drain_events(&std::collections::HashMap::new());
        assert_eq!(client.status.state, PropagationClientState::ListRequested);
        assert!(client.link.is_some());
    }

    #[test]
    fn client_rejects_authenticated_packet_from_wrong_interface_before_state_change() {
        let (tx, _rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        let node_hash = [0xE6; 16];
        let (link, mut responder) = active_link_pair(node_hash);
        let link_id = link.link_id;
        client.link = Some(link);
        client.link_id = Some(link_id);
        client.attached_interface = Some(4);
        client.status.state = PropagationClientState::ListRequested;
        let close_body = responder
            .teardown(CloseReason::InitiatorClosed)
            .expect("active responder teardown");
        client
            .event_tx
            .try_send(DestinationEvent::InboundPacket {
                interface_owner: None,
                raw: link_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::LinkClose,
                    &close_body,
                ),
                interface_id: 5,
                metrics: Default::default(),
            })
            .unwrap();

        client.drain_events(&std::collections::HashMap::new());
        assert_eq!(client.state(), PropagationClientState::ListRequested);
        assert!(client.link.as_ref().is_some_and(Link::is_active));
    }
}

#[cfg(test)]
#[path = "propagation_client_tests.rs"]
mod lifecycle_tests;

impl Drop for PropagationClient {
    fn drop(&mut self) {
        self.current_admission_generation
            .fetch_add(1, Ordering::AcqRel);
    }
}
