//! LXMF Router: message delivery engine and propagation node.
//!
//! Python reference: LXMF/LXMRouter.py. Actor pattern — a single tokio task owns
//! all mutable state.

use crate::now_f64;
use std::collections::{HashMap, VecDeque};
use std::fmt;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::constants::*;
use crate::inbound_resource::{
    InboundResourceCancelRequest, InboundResourceEvent, InboundResourceHandle, InboundResourceKey,
    InboundResourceTracker,
};
use crate::message::{
    LxMessage, LxMessageDraft, MessageError, MessageMetadata, RecipientStamp, ResumableLxMessage,
    SignedLxMessage, VerifiedLxMessage,
};
use crate::peer::{LxmPeer, OutboundOfferPolicy};
use crate::propagation::PropagationStore;
use crate::propagation_client::PropagationTransferStatus;
use crate::stamper;
use crate::ticket::{Ticket, TicketStore};
use crate::types::PropagationTransientId;

/// Outstanding actor-owned admission. Only this router can match its nonce.
#[derive(Debug)]
pub struct InboundReservation {
    message_id: [u8; 32],
    nonce: u64,
}

/// Durable barrier for router-minted reply tickets. Signing the marked draft
/// fails until this exact intent has committed its immutable ticket snapshot.
pub struct OutboundTicketIntent {
    barrier: Option<std::sync::Arc<()>>,
    snapshot: Option<crate::persist::TicketPersistenceSnapshot>,
    required_ticket: Option<Ticket>,
}
impl OutboundTicketIntent {
    pub fn requires_persistence(&self) -> bool {
        self.snapshot.is_some()
    }
    pub fn persist(
        self,
        state_dir: &std::path::Path,
        draft: &mut LxMessageDraft,
    ) -> std::io::Result<()> {
        if let Some(snapshot) = self.snapshot {
            snapshot.save(state_dir, self.required_ticket.as_ref())?;
            if !draft.release_ticket_barrier(self.barrier.as_ref().expect("snapshot barrier")) {
                return Err(std::io::Error::other(
                    "reply ticket intent belongs to a different draft",
                ));
            }
        }
        Ok(())
    }
}

/// Router configuration.
///
/// Core fields are stable for downstream compatibility; additional Python
/// `LXMRouter.__init__` knobs live in [`RouterConfigExt`] behind the `ext` field.
#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub propagation_enabled: bool,
    pub autopeer: bool,
    pub max_peers: usize,
    pub propagation_limit_kb: usize,
    pub delivery_limit_kb: f64,
    pub sync_limit_kb: usize,
    pub propagation_stamp_cost: u8,
    pub propagation_stamp_flex: u8,
    pub stamp_cost: Option<u8>,
    pub ext: RouterConfigExt,
}

/// Extended router configuration.
///
/// Additional `LXMRouter.__init__` fields; all have sensible defaults.
#[derive(Debug, Clone)]
pub struct RouterConfigExt {
    pub autopeer_maxdepth: usize,
    pub propagation_cost_min: u8,
    pub peering_cost: u8,
    pub max_peering_cost: u8,
    pub processing_outbound: bool,
    /// Maximum outbound messages to process per tick (`None` = unlimited).
    pub processing_limit: Option<usize>,
    pub retain_synced_on_node: bool,
    pub auth_required: bool,
    /// Generate outbound message PoW stamps through the router deferred-stamp queue.
    pub defer_stamp_generation: bool,
    /// Propagation storage cap in bytes (`None` = unlimited).
    pub message_storage_limit: Option<usize>,
    /// Name advertised in propagation announce metadata.
    pub name: Option<String>,
    pub from_static_only: bool,
}

impl Default for RouterConfigExt {
    fn default() -> Self {
        Self {
            autopeer_maxdepth: AUTOPEER_MAXDEPTH,
            propagation_cost_min: PROPAGATION_COST_MIN,
            peering_cost: PEERING_COST,
            max_peering_cost: MAX_PEERING_COST,
            processing_outbound: true,
            processing_limit: None,
            retain_synced_on_node: false,
            auth_required: false,
            defer_stamp_generation: true,
            message_storage_limit: None,
            name: None,
            from_static_only: false,
        }
    }
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            propagation_enabled: false,
            autopeer: AUTOPEER,
            max_peers: MAX_PEERS,
            propagation_limit_kb: PROPAGATION_LIMIT,
            delivery_limit_kb: DELIVERY_LIMIT as f64,
            sync_limit_kb: SYNC_LIMIT,
            propagation_stamp_cost: PROPAGATION_COST,
            propagation_stamp_flex: PROPAGATION_COST_FLEX,
            stamp_cost: None,
            ext: RouterConfigExt::default(),
        }
    }
}

pub struct DeferredStampJob {
    pub message_hash: [u8; 32],
    handle: stamper::DeferredStampHandle,
    rx: oneshot::Receiver<stamper::DeferredStampResult>,
}

#[derive(Debug)]
pub enum SendError {
    MissingOutboundPropagationNode(Box<LxMessage>),
    TicketPreparation {
        message: Box<LxMessage>,
        source: TicketPreparationError,
    },
}

impl SendError {
    pub fn message(&self) -> &LxMessage {
        match self {
            Self::MissingOutboundPropagationNode(message) => message,
            Self::TicketPreparation { message, .. } => message,
        }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingOutboundPropagationNode(_) => f.write_str(
                "attempt to send propagated message with no outbound propagation node configured",
            ),
            Self::TicketPreparation { source, .. } => source.fmt(f),
        }
    }
}

impl std::error::Error for SendError {}

#[derive(Debug, thiserror::Error)]
pub enum TicketPreparationError {
    #[error("reply ticket must be added before the LXMF message is signed")]
    AlreadySigned,
    #[error("another reply-ticket draft is awaiting durable persistence")]
    PendingPersistence,
    #[error("failed to encode LXMF reply ticket: {0}")]
    Encode(String),
}

/// Current route metadata for an LXMF Direct delivery destination.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectRouteSnapshot {
    pub destination_hash: [u8; 16],
    pub hops: u8,
    pub interface_name: Option<String>,
    pub learned_at: Option<f64>,
    pub expires_at: Option<f64>,
}

impl DirectRouteSnapshot {
    pub fn new(destination_hash: [u8; 16], hops: u8) -> Self {
        Self {
            destination_hash,
            hops: hops.max(1),
            interface_name: None,
            learned_at: None,
            expires_at: None,
        }
    }
}

/// Reusable Direct/backchannel Link state visible to the router-level policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectReusableLinkState {
    None,
    Pending,
    Active,
    Closed { activated: bool },
}

/// Input snapshot for core Direct-delivery planning.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectDeliveryPlanInput {
    pub identity_known: bool,
    pub route: Option<DirectRouteSnapshot>,
    pub reusable_link: DirectReusableLinkState,
}

/// Core Direct-delivery policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectDeliveryPlan {
    UseReusableLink,
    WaitForReusableLink,
    StartNewLink { hops: u8 },
    RequestPath { drop_existing: bool },
    DeferTerminalFailure,
    Fail,
}

/// Apply upstream LXMF Direct delivery attempt/path/link policy to one message.
///
/// This is a policy primitive for embedders that still own transport adapters.
/// It mutates the same attempt/progress fields Python mutates in
/// `LXMRouter.process_outbound`, but leaves actual path requests and Link
/// creation to the caller.
pub fn plan_direct_delivery(
    message: &mut LxMessage,
    input: DirectDeliveryPlanInput,
    now: f64,
) -> DirectDeliveryPlan {
    if message.delivery_attempts > MAX_DELIVERY_ATTEMPTS {
        message.mark_failed();
        return DirectDeliveryPlan::Fail;
    }

    match input.reusable_link {
        DirectReusableLinkState::Active => {
            if message.progress < 0.05 {
                message.progress = 0.05;
            }
            if message.state != MessageState::Sending {
                message.mark_sending();
            }
            return DirectDeliveryPlan::UseReusableLink;
        }
        DirectReusableLinkState::Pending => {
            return DirectDeliveryPlan::WaitForReusableLink;
        }
        DirectReusableLinkState::Closed { .. } => {
            message.next_delivery_attempt = now + PATH_REQUEST_WAIT as f64;
            if message.progress < 0.01 {
                message.progress = 0.01;
            }
            return DirectDeliveryPlan::RequestPath {
                drop_existing: true,
            };
        }
        DirectReusableLinkState::None => {}
    }

    if !input.identity_known {
        message.delivery_attempts += 1;
        message.last_delivery_attempt = now;
        message.next_delivery_attempt = now + PATH_REQUEST_WAIT as f64;
        if message.progress < 0.01 {
            message.progress = 0.01;
        }
        return DirectDeliveryPlan::RequestPath {
            drop_existing: false,
        };
    }

    message.delivery_attempts += 1;
    message.last_delivery_attempt = now;
    message.next_delivery_attempt = now + DELIVERY_RETRY_WAIT as f64;

    if message.delivery_attempts >= MAX_DELIVERY_ATTEMPTS {
        return DirectDeliveryPlan::DeferTerminalFailure;
    }

    if let Some(route) = input.route {
        if message.progress < 0.03 {
            message.progress = 0.03;
        }
        DirectDeliveryPlan::StartNewLink {
            hops: route.hops.max(1),
        }
    } else {
        message.next_delivery_attempt = now + PATH_REQUEST_WAIT as f64;
        if message.progress < 0.01 {
            message.progress = 0.01;
        }
        DirectDeliveryPlan::RequestPath {
            drop_existing: false,
        }
    }
}

/// LXMF router — owns all mutable state under the actor pattern.
pub struct LxmRouter {
    pub config: RouterConfig,
    pub pending_outbound: Vec<LxMessage>,
    /// Messages awaiting deferred stamp generation, keyed by message hash.
    pub pending_deferred_stamps: HashMap<[u8; 32], SignedLxMessage>,
    /// Order in which `defer_stamp` queued the deferred messages, so stamps
    /// are generated first in, first out.
    deferred_stamp_order: VecDeque<[u8; 32]>,
    /// Captured at construction so deferred-stamp PoW can spawn onto the
    /// blocking pool even when the caller is itself on a `spawn_blocking`
    /// thread, where `Handle::try_current()` fails. Without it the tick grinds
    /// stamps inline while holding the manager lock (observed 53 s stall).
    pub runtime_handle: Option<tokio::runtime::Handle>,
    pub active_deferred_stamp: Option<DeferredStampJob>,
    /// Identities allowed for delivery. An empty list means "all allowed".
    pub allowed: Vec<[u8; 16]>,
    pub blocked: Vec<[u8; 16]>,
    pub allowed_control: Vec<[u8; 16]>,
    pub ignored: Vec<[u8; 16]>,
    pub peers: HashMap<[u8; 16], LxmPeer>,
    /// Peers that will never be rotated out.
    pub static_peers: Vec<[u8; 16]>,
    pub propagation_store: PropagationStore,
    /// Cached stamp costs keyed by destination hash.
    pub outbound_stamp_costs: HashMap<[u8; 16], StampCostEntry>,
    pub ticket_store: TicketStore,
    ticket_intent_in_flight: std::sync::Weak<()>,
    /// Identity hash → priority level.
    pub prioritized: HashMap<[u8; 16], u8>,
    pub delivery_callback: Option<DeliveryCallback>,
    pub transport_tx: Option<mpsc::Sender<rns_transport::messages::TransportMessage>>,
    /// Throttled peers → expiry timestamp (seconds since UNIX epoch).
    pub throttled_peers: HashMap<[u8; 16], f64>,
    pub propagation_start_time: Option<f64>,
    pub processing_count: u64,
    /// Wall-clock gate for `run_jobs_tick`, decoupling jobloop cadence from
    /// the embedder's loop rate.
    last_jobs_tick: f64,
    pub outbound_propagation_node: Option<[u8; 16]>,
    /// Last coherent propagation-client transfer snapshot.
    pub propagation_transfer_status: PropagationTransferStatus,
    pub client_propagation_messages_received: u64,
    pub client_propagation_messages_served: u64,
    pub unpeered_propagation_incoming: u64,
    pub unpeered_propagation_rx_bytes: u64,
    /// Active ordinary delivery Resources. The embedding Reticulum runtime
    /// remains the transfer owner and feeds this registry lifecycle events.
    inbound_resource_tracker: InboundResourceTracker,
    inbound_reservations: HashMap<[u8; 32], u64>,
    next_inbound_reservation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectOutboundHandling {
    EmitLegacyAction,
    LeavePending,
}

/// Callback invoked when a message is delivered locally.
pub type DeliveryCallback = Box<dyn Fn(&LxMessage) + Send>;

/// Announce-derived data used to create an autopeered propagation peer.
pub struct AutopeerCandidate {
    pub destination_hash: [u8; 16],
    pub timebase: f64,
    pub transfer_limit: Option<f64>,
    pub sync_limit: Option<f64>,
    pub stamp_cost: Option<u8>,
    pub stamp_flexibility: Option<u8>,
    pub peering_cost: Option<u8>,
    /// Parsed propagation-node announce metadata. The peer layer applies
    /// deterministic entry/value/aggregate bounds before retaining it.
    pub metadata: Option<std::collections::HashMap<u8, Vec<u8>>>,
    pub hops: Option<u8>,
}

/// Cached stamp cost for a destination.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StampCostEntry {
    pub cost: u8,
    pub recorded_at: f64,
}

/// Owned, coherent snapshot of the router state written by [`LxmRouter::save_state`].
///
/// Creating the snapshot only clones in-memory state. The caller can therefore
/// release any lock that protects the router before calling [`Self::save_state`],
/// keeping filesystem I/O out of the router's critical section.
#[derive(Debug, Clone)]
pub struct RouterStateSnapshot {
    outbound_stamp_costs: HashMap<[u8; 16], StampCostEntry>,
    tickets: crate::persist::TicketPersistenceSnapshot,
    local_deliveries: HashMap<PropagationTransientId, f64>,
    locally_processed: HashMap<PropagationTransientId, f64>,
    node_stats: crate::persist::PersistedNodeStats,
}

impl RouterStateSnapshot {
    /// Persist this owned snapshot using the router's MessagePack layout.
    ///
    /// Each file is written atomically via rename, matching
    /// [`LxmRouter::save_state`].
    pub fn save_state(&self, state_dir: &std::path::Path) -> std::io::Result<()> {
        use crate::persist;

        persist::save_stamp_costs(state_dir, &self.outbound_stamp_costs)?;
        self.tickets.save(state_dir, None)?;
        persist::save_local_deliveries(state_dir, &self.local_deliveries)?;
        persist::save_locally_processed(state_dir, &self.locally_processed)?;
        persist::save_node_stats(state_dir, &self.node_stats)?;
        Ok(())
    }
}

impl LxmRouter {
    pub fn new(config: RouterConfig) -> Self {
        Self {
            config,
            pending_outbound: Vec::new(),
            pending_deferred_stamps: HashMap::new(),
            deferred_stamp_order: VecDeque::new(),
            runtime_handle: tokio::runtime::Handle::try_current().ok(),
            active_deferred_stamp: None,
            allowed: Vec::new(),
            blocked: Vec::new(),
            allowed_control: Vec::new(),
            ignored: Vec::new(),
            peers: HashMap::new(),
            static_peers: Vec::new(),
            propagation_store: PropagationStore::new(),
            outbound_stamp_costs: HashMap::new(),
            ticket_store: TicketStore::new(),
            ticket_intent_in_flight: std::sync::Weak::new(),
            prioritized: HashMap::new(),
            delivery_callback: None,
            transport_tx: None,
            throttled_peers: HashMap::new(),
            propagation_start_time: None,
            processing_count: 0,
            last_jobs_tick: 0.0,
            outbound_propagation_node: None,
            propagation_transfer_status: PropagationTransferStatus::default(),
            client_propagation_messages_received: 0,
            client_propagation_messages_served: 0,
            unpeered_propagation_incoming: 0,
            unpeered_propagation_rx_bytes: 0,
            inbound_resource_tracker: InboundResourceTracker::default(),
            inbound_reservations: HashMap::new(),
            next_inbound_reservation: 0,
        }
    }

    pub fn set_transport(&mut self, tx: mpsc::Sender<rns_transport::messages::TransportMessage>) {
        self.transport_tx = Some(tx);
    }

    /// Replace the public propagation transfer snapshot from its actor owner.
    pub fn update_propagation_transfer_status(&mut self, status: PropagationTransferStatus) {
        self.propagation_transfer_status = status;
    }

    pub fn has_transport(&self) -> bool {
        self.transport_tx.is_some()
    }

    /// Install the bounded adapter used to request cancellation from the
    /// embedding Reticulum Resource owner.
    pub fn set_inbound_resource_cancel_sender(
        &mut self,
        tx: mpsc::Sender<InboundResourceCancelRequest>,
    ) {
        self.inbound_resource_tracker.set_cancel_sender(tx);
    }

    /// Project one transport-neutral Resource lifecycle event into the
    /// router-owned public registry.
    pub fn handle_inbound_resource_event(&mut self, event: InboundResourceEvent) {
        self.inbound_resource_tracker.handle_event(event);
    }

    /// Number of active ordinary inbound delivery Resources.
    ///
    /// Python reference: `LXMRouter.inbound_count` — LXMRouter.py:466.
    pub fn inbound_count(&self) -> usize {
        self.inbound_resource_tracker.inbound_count()
    }

    /// Owned handles for all active ordinary inbound delivery Resources.
    ///
    /// Python reference: `LXMRouter.inbound_resources` — LXMRouter.py:474.
    pub fn inbound_resources(&self) -> Vec<InboundResourceHandle> {
        self.inbound_resource_tracker.inbound_resources()
    }

    /// Return one unique active logical Resource.
    pub fn inbound_resource(&self, resource_id: &[u8; 32]) -> Option<InboundResourceHandle> {
        self.inbound_resource_tracker.inbound_resource(resource_id)
    }

    /// Return one exact active `(Link, Resource)` owner.
    pub fn inbound_resource_exact(&self, key: InboundResourceKey) -> Option<InboundResourceHandle> {
        self.inbound_resource_tracker.inbound_resource_exact(key)
    }

    /// Queue cancellation for one unique active logical Resource.
    ///
    /// Python reference: `LXMRouter.cancel_inbound` — LXMRouter.py:484.
    pub fn cancel_inbound(&self, resource_id: &[u8; 32]) -> bool {
        self.inbound_resource_tracker.cancel_inbound(resource_id)
    }

    /// Queue cancellation for one exact active Resource owner.
    pub fn cancel_inbound_exact(&self, key: InboundResourceKey) -> bool {
        self.inbound_resource_tracker.cancel_inbound_exact(key)
    }

    /// Queue cancellation for a stable snapshot of all active Resources.
    ///
    /// Python reference: `LXMRouter.cancel_all_inbound` — LXMRouter.py:505.
    pub fn cancel_all_inbound(&self) -> usize {
        self.inbound_resource_tracker.cancel_all_inbound()
    }

    /// Queue a message for outbound delivery.
    ///
    /// Opportunistic messages that exceed the single-packet ceiling are
    /// transparently downgraded to Direct delivery.
    #[tracing::instrument(
        level = "debug",
        name = "router.send",
        skip_all,
        fields(
            destination_hash = %hex::encode(&message.destination_hash()[..8]),
            method = ?message.method,
            content_len = message.content_bytes().len(),
        ),
    )]
    #[deprecated(note = "use try_send() and handle the immediate routing result")]
    pub fn send(&mut self, message: LxMessage) {
        let _ = self.try_send(message);
    }

    /// Queue a message for outbound delivery and report immediate routing errors.
    ///
    /// Mirrors Python LXMF 0.9.8's explicit `IOError` when a caller attempts
    /// `PROPAGATED` delivery without configuring an outbound propagation node.
    /// The legacy [`send`](Self::send) wrapper preserves older Rust call-sites
    /// while still marking the message failed and firing its callback.
    pub fn try_send(&mut self, mut message: LxMessage) -> Result<(), SendError> {
        if message.method == DeliveryMethod::Propagated && self.outbound_propagation_node.is_none()
        {
            message.progress = 0.0;
            if message.state != MessageState::Rejected {
                message.mark_failed();
            } else {
                message.notify_failed();
            }
            return Err(SendError::MissingOutboundPropagationNode(Box::new(message)));
        }

        if message.method == DeliveryMethod::Opportunistic
            && let Ok(packed) = message.pack_payload()
        {
            let content_size = packed
                .len()
                .saturating_sub(TIMESTAMP_SIZE + STRUCT_OVERHEAD);
            if content_size > ENCRYPTED_PACKET_MAX_CONTENT {
                message.method = DeliveryMethod::Direct;
            }
        }

        message.state = MessageState::Outbound;
        self.pending_outbound.push(message);
        Ok(())
    }

    /// Apply router-owned ticket state before a caller signs `message`.
    ///
    /// Learned outbound tickets do not change signed fields and can be
    /// attached at any time. A requested reply ticket is a signed LXMF field,
    /// so it must be inserted before signing. The method is deliberately
    /// signer-agnostic: callers may subsequently use either `sign` or
    /// `sign_with` without exposing private key material to the router.
    pub fn prepare_outbound(
        &mut self,
        message: &mut LxMessageDraft,
    ) -> Result<OutboundTicketIntent, TicketPreparationError> {
        let now = now_f64();
        let destination = message.destination_hash();
        if message.outbound_ticket.is_none() {
            message.outbound_ticket = self
                .ticket_store
                .find_outbound(&destination, now)
                .map(|t| t.token);
        }
        if message.stamp_cost.is_none() {
            message.stamp_cost = self.get_stamp_cost(&destination).filter(|v| *v > 0);
        }
        if message.include_ticket
            && message.get_field(FIELD_TICKET).is_none()
            && self.ticket_intent_in_flight.upgrade().is_some()
        {
            return Err(TicketPreparationError::PendingPersistence);
        }
        let mut intent = OutboundTicketIntent {
            barrier: None,
            snapshot: None,
            required_ticket: None,
        };
        if message.include_ticket
            && message.get_field(FIELD_TICKET).is_none()
            && let Some(ticket) = self.ticket_store.issue_for(destination, TICKET_EXPIRY, now)
        {
            let encoded = ticket
                .encode_field()
                .map_err(|e| TicketPreparationError::Encode(e.to_string()))?;
            message
                .set_msgpack_field(FIELD_TICKET, encoded)
                .map_err(|e| TicketPreparationError::Encode(e.to_string()))?;
            let barrier = std::sync::Arc::new(());
            message.mark_ticket_pending(barrier.clone());
            self.ticket_intent_in_flight = std::sync::Arc::downgrade(&barrier);
            intent.barrier = Some(barrier);
            intent.required_ticket = Some(ticket);
            intent.snapshot = Some(crate::persist::TicketPersistenceSnapshot::capture(
                self.ticket_store.snapshot(),
            ));
        }
        Ok(intent)
    }

    /// Signatures freeze the body before recipient work; only finalized messages
    /// enter outbound queues. Deferred completion can never mutate another body.
    ///
    /// A message whose id is already queued, awaiting either its stamp or
    /// delivery, is refused with [`MessageError::AlreadyQueued`].
    pub fn submit_signed(&mut self, message: SignedLxMessage) -> Result<(), MessageError> {
        let id = message.message_id();
        if self.pending_deferred_stamps.contains_key(&id)
            || self.pending_outbound.iter().any(|m| m.message_id() == id)
        {
            return Err(MessageError::AlreadyQueued);
        }
        if message.method == DeliveryMethod::Propagated && self.outbound_propagation_node.is_none()
        {
            return Err(MessageError::PackFailed(
                "outbound propagation node is not configured".into(),
            ));
        }
        if self.config.ext.defer_stamp_generation
            && message.outbound_ticket().is_none()
            && message.stamp_cost().unwrap_or(0) > 0
        {
            self.defer_stamp(message);
            return Ok(());
        }
        let stamp = message.generate_recipient_stamp()?;
        self.try_send(message.finalize(stamp)?)
            .map_err(|e| MessageError::PackFailed(e.to_string()))
    }

    /// Restore a stored message for another delivery under the same id.
    ///
    /// `source_public_key` is the active identity's: the message must verify
    /// as sent by it. The outbound ticket is the current one, and the stamp
    /// cost is the larger of the cost the message was signed under and the
    /// destination's current cost. Finish the message as for a fresh send,
    /// then pass it to [`Self::submit_signed`].
    pub fn restore_signed(
        &self,
        stored: &ResumableLxMessage,
        source_public_key: &[u8; 64],
        method: DeliveryMethod,
    ) -> Result<SignedLxMessage, MessageError> {
        let mut message = stored.unverified_message()?;
        message.verify(source_public_key)?;
        message.metadata = MessageMetadata {
            state: MessageState::Outbound,
            method,
            ..MessageMetadata::default()
        };
        let destination = message.destination_hash();
        let outbound_ticket = self.get_outbound_ticket(&destination);
        let current_cost = self.get_stamp_cost(&destination).filter(|cost| *cost > 0);
        let stamp_cost = stored.stamp_cost_floor().max(current_cost);
        Ok(SignedLxMessage::restored(
            message,
            outbound_ticket,
            stamp_cost,
        ))
    }

    /// Queue a message for stamp generation, after those already deferred.
    /// Replacing a queued message keeps its place.
    pub fn defer_stamp(&mut self, mut message: SignedLxMessage) {
        message.state = MessageState::Outbound;
        let id = message.message_id();
        if self.pending_deferred_stamps.insert(id, message).is_none() {
            self.deferred_stamp_order.retain(|queued| *queued != id);
            self.deferred_stamp_order.push_back(id);
        }
    }

    /// The oldest deferred message, as Python's insertion-ordered dict yields
    /// it (LXMRouter.py:2655-2662).
    fn next_deferred_stamp(&mut self) -> Option<[u8; 32]> {
        while let Some(id) = self.deferred_stamp_order.front() {
            if self.pending_deferred_stamps.contains_key(id) {
                return Some(*id);
            }
            self.deferred_stamp_order.pop_front();
        }
        // Entries placed directly in the public map have no recorded order.
        self.pending_deferred_stamps.keys().next().copied()
    }

    pub fn process_deferred_stamps(&mut self) {
        self.poll_active_deferred_stamp();
        if self.active_deferred_stamp.is_some() {
            return;
        }
        let Some(message_hash) = self.next_deferred_stamp() else {
            return;
        };
        let message = &self.pending_deferred_stamps[&message_hash];
        let cost = message.stamp_cost().unwrap_or(0);
        if cost == 0 || message.outbound_ticket().is_some() {
            if let Some(message) = self.pending_deferred_stamps.remove(&message_hash) {
                let stamp = message.generate_recipient_stamp();
                match stamp.and_then(|stamp| message.finalize(stamp)) {
                    Ok(message) => {
                        let _ = self.try_send(message);
                    }
                    Err(error) => tracing::warn!(%error,"recipient stamp finalization failed"),
                }
            }
            return;
        }
        let runtime = tokio::runtime::Handle::try_current()
            .ok()
            .or_else(|| self.runtime_handle.clone());
        if let Some(runtime) = runtime {
            let (handle, rx) = stamper::spawn_deferred_stamp_on(
                &runtime,
                message_hash,
                cost,
                STAMP_WORKBLOCK_EXPAND_ROUNDS,
            );
            self.active_deferred_stamp = Some(DeferredStampJob {
                message_hash,
                handle,
                rx,
            });
        } else if let Some(message) = self.pending_deferred_stamps.remove(&message_hash) {
            let stamp = message.generate_recipient_stamp();
            match stamp.and_then(|stamp| message.finalize(stamp)) {
                Ok(message) => {
                    let _ = self.try_send(message);
                }
                Err(error) => tracing::warn!(%error,"recipient stamp generation failed"),
            }
        }
    }

    fn poll_active_deferred_stamp(&mut self) {
        let Some(mut job) = self.active_deferred_stamp.take() else {
            return;
        };
        match job.rx.try_recv() {
            Ok(stamper::DeferredStampResult::Success { stamp, .. }) => {
                if let Some(message) = self.pending_deferred_stamps.remove(&job.message_hash) {
                    match message.finalize(Some(RecipientStamp::ProofOfWork(stamp))) {
                        Ok(message) => {
                            let _ = self.try_send(message);
                        }
                        Err(error) => tracing::warn!(%error,"recipient stamp finalization failed"),
                    }
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => self.active_deferred_stamp = Some(job),
            _ => {
                self.pending_deferred_stamps.remove(&job.message_hash);
            }
        }
    }

    pub fn allow(&mut self, identity_hash: [u8; 16]) {
        if !self.allowed.contains(&identity_hash) {
            self.allowed.push(identity_hash);
        }
    }

    pub fn disallow(&mut self, identity_hash: &[u8; 16]) {
        self.allowed.retain(|h| h != identity_hash);
    }

    pub fn allow_control(&mut self, identity_hash: [u8; 16]) {
        if !self.allowed_control.contains(&identity_hash) {
            self.allowed_control.push(identity_hash);
        }
    }

    pub fn disallow_control(&mut self, identity_hash: &[u8; 16]) {
        self.allowed_control.retain(|h| h != identity_hash);
    }

    pub fn ignore_destination(&mut self, dest_hash: [u8; 16]) {
        if !self.ignored.contains(&dest_hash) {
            self.ignored.push(dest_hash);
        }
        self.propagation_store.ignore_destination(dest_hash);
    }

    pub fn unignore_destination(&mut self, dest_hash: &[u8; 16]) {
        self.ignored.retain(|h| h != dest_hash);
        self.propagation_store.unignore_destination(dest_hash);
    }

    pub fn prioritise(&mut self, identity_hash: [u8; 16], level: u8) {
        self.prioritized.insert(identity_hash, level);
        self.propagation_store.prioritise_destination(identity_hash);
    }

    pub fn unprioritise(&mut self, identity_hash: &[u8; 16]) {
        self.prioritized.remove(identity_hash);
        self.propagation_store
            .unprioritise_destination(identity_hash);
    }

    pub fn block(&mut self, identity_hash: [u8; 16]) {
        if !self.blocked.contains(&identity_hash) {
            self.blocked.push(identity_hash);
        }
    }

    pub fn unblock(&mut self, identity_hash: &[u8; 16]) {
        self.blocked.retain(|h| h != identity_hash);
    }

    /// An empty allow-list means "everyone not blocked is allowed".
    pub fn is_allowed(&self, identity_hash: &[u8; 16]) -> bool {
        if !self.blocked.contains(identity_hash) {
            self.allowed.is_empty() || self.allowed.contains(identity_hash)
        } else {
            false
        }
    }

    pub fn is_control_allowed(&self, identity_hash: &[u8; 16]) -> bool {
        self.allowed_control.contains(identity_hash)
    }

    /// Whether delivery requires an entry in the allow-list.
    ///
    /// Python reference: `LXMRouter.requires_authentication` — LXMRouter.py:415-417.
    pub fn requires_authentication(&self) -> bool {
        self.config.ext.auth_required
    }

    /// Toggle whether delivery requires an entry in the allow-list.
    ///
    /// Python reference: `LXMRouter.set_authentication` — LXMRouter.py:409-413.
    pub fn set_authentication(&mut self, required: bool) {
        self.config.ext.auth_required = required;
    }

    /// Whether the node keeps synchronized messages in its propagation store.
    pub fn retain_node_lxms(&self) -> bool {
        self.config.ext.retain_synced_on_node
    }

    /// Toggle whether the node keeps synchronized messages in its propagation store.
    ///
    /// Python reference: `LXMRouter.set_retain_node_lxms` — LXMRouter.py:419-420.
    pub fn set_retain_node_lxms(&mut self, retain: bool) {
        self.config.ext.retain_synced_on_node = retain;
    }

    /// Propagation storage cap in bytes (`None` = unlimited).
    pub fn message_storage_limit(&self) -> Option<usize> {
        self.config.ext.message_storage_limit
    }

    /// Set the propagation storage cap in bytes (`None` = unlimited).
    ///
    /// Python reference: `LXMRouter.set_message_storage_limit` — LXMRouter.py:423-424.
    pub fn set_message_storage_limit(&mut self, limit: Option<usize>) {
        self.config.ext.message_storage_limit = limit;
    }

    /// Current on-disk-equivalent size of the propagation store, in bytes.
    ///
    /// Python reference: `LXMRouter.message_storage_size` — LXMRouter.py:437-441.
    pub fn message_storage_size(&self) -> usize {
        self.propagation_store.total_size()
    }

    /// Generate a fresh random ticket for `destination_hash` and add it to the ticket store.
    ///
    /// The returned token can be shared with a peer that should bypass stamp PoW when sending
    /// to this router. Default expiry is [`TICKET_EXPIRY`] seconds.
    ///
    /// Python reference: `LXMRouter.generate_ticket` — LXMRouter.py:1094-1108.
    pub fn generate_ticket(
        &mut self,
        destination_hash: [u8; 16],
        expiry_secs: Option<u64>,
    ) -> [u8; 16] {
        use rand::RngCore;
        let mut token = [0u8; TICKET_LENGTH];
        rand::thread_rng().fill_bytes(&mut token);
        let expires = now_f64() + expiry_secs.unwrap_or(TICKET_EXPIRY) as f64;
        self.ticket_store
            .add_inbound(Ticket::new(token, destination_hash, expires));
        token
    }

    /// Record an externally-provided outbound ticket so the router can use it when sending.
    ///
    /// Python reference: `LXMRouter.remember_ticket` — LXMRouter.py:1110-1113.
    pub fn remember_ticket(&mut self, destination_hash: [u8; 16], token: [u8; 16], expires: f64) {
        self.ticket_store
            .remember_outbound(Ticket::new(token, destination_hash, expires));
    }

    /// Returns the token of the first valid ticket for `destination_hash`.
    ///
    /// Python reference: `LXMRouter.get_outbound_ticket` — LXMRouter.py:1058-1064.
    pub fn get_outbound_ticket(&self, destination_hash: &[u8; 16]) -> Option<[u8; 16]> {
        let now = now_f64();
        self.ticket_store
            .find_outbound(destination_hash, now)
            .map(|t| t.token)
    }

    /// Returns the expiry (Unix epoch seconds) of the valid ticket for `destination_hash`.
    ///
    /// Python reference: `LXMRouter.get_outbound_ticket_expiry` — LXMRouter.py:1125-1131.
    pub fn get_outbound_ticket_expiry(&self, destination_hash: &[u8; 16]) -> Option<f64> {
        let now = now_f64();
        self.ticket_store
            .find_outbound(destination_hash, now)
            .map(|t| t.expires)
    }

    /// Snapshot of all stored tickets (including expired / used entries).
    ///
    /// Python reference: `LXMRouter.get_inbound_tickets` — LXMRouter.py:1133-1136.
    pub fn get_inbound_tickets(&self) -> &[Ticket] {
        self.ticket_store.inbound()
    }

    /// Cancel an outbound message before it is sent.
    ///
    /// Removes the message from `pending_outbound` (or `pending_deferred_stamps`) if it is still
    /// in a cancellable state. Returns `true` if the message was found and cancelled.
    ///
    /// Python reference: `LXMRouter.cancel_outbound` — LXMRouter.py:474-487.
    pub fn cancel_outbound(&mut self, message_hash: &[u8; 32]) -> bool {
        if let Some(pos) = self
            .pending_outbound
            .iter()
            .position(|m| &m.message_id() == message_hash)
        {
            let msg = &mut self.pending_outbound[pos];
            msg.cancel();
            self.pending_outbound.remove(pos);
            return true;
        }

        if let Some(msg) = self.pending_deferred_stamps.remove(message_hash) {
            if let Ok(mut message) = msg.finalize(None) {
                message.cancel();
            }
            let active_matches = self
                .active_deferred_stamp
                .as_ref()
                .is_some_and(|job| job.message_hash == *message_hash);
            if active_matches && let Some(job) = self.active_deferred_stamp.take() {
                job.handle.cancel();
            }
            return true;
        }

        false
    }

    /// Mark a pending outbound message delivered and remove it from the
    /// outbound queue.
    pub fn mark_outbound_delivered(&mut self, message_hash: &[u8; 32]) -> bool {
        let Some(pos) = self
            .pending_outbound
            .iter()
            .position(|m| &m.message_id() == message_hash)
        else {
            return false;
        };

        let msg = self.pending_outbound.remove(pos);
        self.complete_outbound_message(msg);
        true
    }

    /// Complete an outbound message whose in-flight ownership moved from the
    /// router queue into an embedding runtime.
    ///
    /// Opportunistic packet delivery is asynchronous: the network accepts the
    /// packet first and authenticates a delivery proof later. Embedders retain
    /// the message between those events and return it here only after proof so
    /// ticket-delivery accounting and callbacks reflect the observable result.
    pub fn complete_outbound_message(&mut self, mut msg: LxMessage) {
        if msg.fields().contains(FIELD_TICKET) {
            self.ticket_store
                .mark_ticket_delivered(msg.destination_hash(), now_f64());
        }
        msg.mark_delivered();
    }

    /// Mark a pending outbound message failed and remove it from the outbound
    /// queue.
    pub fn mark_outbound_failed(&mut self, message_hash: &[u8; 32]) -> bool {
        let Some(pos) = self
            .pending_outbound
            .iter()
            .position(|m| &m.message_id() == message_hash)
        else {
            return false;
        };

        let mut msg = self.pending_outbound.remove(pos);
        msg.mark_failed();
        true
    }

    /// Mark a pending outbound message rejected and remove it from the
    /// outbound queue.
    pub fn mark_outbound_rejected(&mut self, message_hash: &[u8; 32]) -> bool {
        let Some(pos) = self
            .pending_outbound
            .iter()
            .position(|m| &m.message_id() == message_hash)
        else {
            return false;
        };

        let mut msg = self.pending_outbound.remove(pos);
        msg.mark_rejected();
        true
    }

    /// Re-arm a pending outbound message after a path request without adding a
    /// duplicate queue entry.
    pub fn defer_outbound_for_path_request(&mut self, message_hash: &[u8; 32], now: f64) -> bool {
        let Some(msg) = self
            .pending_outbound
            .iter_mut()
            .find(|m| &m.message_id() == message_hash)
        else {
            return false;
        };

        msg.next_delivery_attempt = now + PATH_REQUEST_WAIT as f64;
        if msg.progress < 0.01 {
            msg.progress = 0.01;
        }
        true
    }

    /// Get the outbound-delivery progress (0.0..=1.0) for a pending message.
    ///
    /// Python reference: `LXMRouter.get_outbound_progress` — LXMRouter.py:489-495.
    pub fn get_outbound_progress(&self, message_hash: &[u8; 32]) -> Option<f64> {
        self.pending_outbound
            .iter()
            .find(|m| &m.message_id() == message_hash)
            .map(|m| m.progress)
            .or_else(|| {
                self.pending_deferred_stamps
                    .get(message_hash)
                    .map(|m| m.progress)
            })
    }

    /// Get the cached required stamp cost for a destination (delivery).
    ///
    /// Returns `None` if no announce has advertised a cost for this destination.
    ///
    /// Python reference: `LXMRouter.get_outbound_lxm_stamp_cost` — LXMRouter.py:1138-1147.
    pub fn get_outbound_lxm_stamp_cost(&self, destination_hash: &[u8; 16]) -> Option<u8> {
        self.outbound_stamp_costs
            .get(destination_hash)
            .map(|e| e.cost)
    }

    /// Get the propagation stamp cost for a message queued for propagation-node delivery.
    ///
    /// Returns the per-message `stamp_cost` recorded on the pending message when it was enqueued.
    ///
    /// Python reference: `LXMRouter.get_outbound_lxm_propagation_stamp_cost` — LXMRouter.py:1149-1156.
    pub fn get_outbound_lxm_propagation_stamp_cost(&self, message_hash: &[u8; 32]) -> Option<u8> {
        self.pending_deferred_stamps
            .get(message_hash)
            .and_then(|m| m.stamp_cost())
    }

    /// Return whether a message or propagation transient ID has already been
    /// delivered locally.
    ///
    /// Python reference: `LXMRouter.has_message` — LXMRouter.py:1667-1669.
    pub fn has_message(&self, transient_id: &PropagationTransientId) -> bool {
        self.propagation_store.is_locally_delivered(transient_id)
    }

    /// Atomically admit one already-decoded inbound message and invoke the
    /// router callback at most once.
    ///
    /// Both ordinary packet/Resource delivery and propagation download must
    /// use this actor-owned gate before any application-visible side effect.
    /// A propagation message may carry a ciphertext-derived `transient_id`
    /// distinct from its signed message hash; both identifiers are retained
    /// so a later delivery through another representation is still deduped.
    pub fn deliver_inbound(&mut self, message: &LxMessage, allow_duplicate: bool) -> bool {
        let message_id = message.message_id();
        if !allow_duplicate && self.propagation_store.is_locally_delivered(&message_id) {
            return false;
        }
        self.propagation_store.mark_locally_delivered(message_id);
        if let Some(ref callback) = self.delivery_callback {
            callback(message);
        }
        true
    }

    /// Reserve before local disk/DB work; no ticket learning, dedupe publication
    /// or callback occurs until commit. An aborted write leaves retries possible.
    pub fn reserve_inbound(&mut self, message: &LxMessage) -> Option<InboundReservation> {
        let message_id = message.message_id();
        if self.inbound_reservations.contains_key(&message_id) {
            return None;
        }
        self.next_inbound_reservation = self.next_inbound_reservation.wrapping_add(1);
        let nonce = self.next_inbound_reservation;
        self.inbound_reservations.insert(message_id, nonce);
        Some(InboundReservation { message_id, nonce })
    }

    pub fn abort_inbound(&mut self, reservation: InboundReservation) {
        if self.inbound_reservations.get(&reservation.message_id) == Some(&reservation.nonce) {
            self.inbound_reservations.remove(&reservation.message_id);
        }
    }

    pub fn commit_inbound(
        &mut self,
        reservation: InboundReservation,
        message: &LxMessage,
        receipt: &crate::admission::DurableAdmissionReceipt,
        verified: Option<&VerifiedLxMessage<'_>>,
    ) -> bool {
        if reservation.message_id != message.message_id()
            || receipt.record().message_id != message.message_id()
            || self.inbound_reservations.get(&reservation.message_id) != Some(&reservation.nonce)
        {
            return false;
        }
        self.inbound_reservations.remove(&reservation.message_id);
        if matches!(
            receipt.record().disposition,
            crate::admission::DurableDisposition::Committed
                | crate::admission::DurableDisposition::Duplicate
        ) && let Some(verified) = verified
            && verified.message().wire_bytes() == message.wire_bytes()
        {
            self.learn_ticket_from_inbound(verified);
        }
        self.propagation_store
            .mark_locally_delivered(receipt.record().scope.transient_id);
        self.propagation_store
            .mark_locally_processed(receipt.record().scope.transient_id);
        let new_message = !self
            .propagation_store
            .is_locally_delivered(&message.message_id());
        self.propagation_store
            .mark_locally_delivered(message.message_id());
        if new_message
            && receipt.record().disposition == crate::admission::DurableDisposition::Committed
        {
            if let Some(ref callback) = self.delivery_callback {
                callback(message);
            }
            true
        } else {
            false
        }
    }

    pub fn learn_ticket_from_inbound(&mut self, verified: &VerifiedLxMessage<'_>) -> bool {
        let message = verified.message();
        let Some(encoded) = message.fields().get(FIELD_TICKET) else {
            return false;
        };
        let Some(ticket) =
            Ticket::decode_field(message.source_hash(), encoded.encoded(), now_f64())
        else {
            return false;
        };
        self.ticket_store.remember_outbound(ticket);
        true
    }

    pub fn ingest_lxm_uri<F>(
        &mut self,
        uri: &str,
        decrypt_fn: F,
    ) -> Result<LxMessage, crate::message::MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, crate::message::MessageError>,
    {
        let message = LxMessage::from_paper_uri(uri, decrypt_fn)?;
        self.deliver_inbound(&message, false);
        Ok(message)
    }

    /// Register a router-wide callback fired on every inbound message delivery.
    ///
    /// Python reference: `LXMRouter.register_delivery_callback` — LXMRouter.py:358-359.
    pub fn register_delivery_callback<F>(&mut self, callback: F)
    where
        F: Fn(&LxMessage) + Send + 'static,
    {
        self.delivery_callback = Some(Box::new(callback));
    }

    /// Load persisted runtime state (stamp costs, tickets, dedup sets) from
    /// `state_dir`. Missing files are treated as empty state. Dedup-cache
    /// timestamps are restored as persisted so age-based expiry survives
    /// restarts.
    pub fn load_state(&mut self, state_dir: &std::path::Path) -> std::io::Result<()> {
        use crate::persist;
        self.outbound_stamp_costs = persist::load_stamp_costs(state_dir)?;
        let (snapshot, legacy) = persist::load_tickets(state_dir)?;
        if let Some(legacy) = legacy {
            self.ticket_store.replace_legacy(legacy);
        } else {
            self.ticket_store.replace_snapshot(snapshot);
        }
        self.propagation_store
            .replace_locally_delivered(persist::load_local_deliveries(state_dir)?);
        self.propagation_store
            .replace_locally_processed(persist::load_locally_processed(state_dir)?);
        let stats = persist::load_node_stats(state_dir)?;
        self.client_propagation_messages_received = stats.client_propagation_messages_received;
        self.client_propagation_messages_served = stats.client_propagation_messages_served;
        self.unpeered_propagation_incoming = stats.unpeered_propagation_incoming;
        self.unpeered_propagation_rx_bytes = stats.unpeered_propagation_rx_bytes;
        // Python cleans tickets and stamp costs at load (LXMRouter.py:258-284).
        let now = now_f64();
        self.ticket_store.cull(now);
        self.outbound_stamp_costs
            .retain(|_, e| now - e.recorded_at < STAMP_COST_EXPIRY as f64);
        Ok(())
    }

    /// Clone all runtime state written by [`Self::save_state`] into one owned
    /// value. Embedders can take this snapshot while holding the router lock,
    /// release the lock, and perform persistence through
    /// [`RouterStateSnapshot::save_state`].
    pub fn state_snapshot(&self) -> RouterStateSnapshot {
        RouterStateSnapshot {
            outbound_stamp_costs: self.outbound_stamp_costs.clone(),
            tickets: crate::persist::TicketPersistenceSnapshot::capture(
                self.ticket_store.snapshot(),
            ),
            local_deliveries: self.propagation_store.locally_delivered_ids().clone(),
            locally_processed: self.propagation_store.locally_processed_ids().clone(),
            node_stats: crate::persist::PersistedNodeStats {
                client_propagation_messages_received: self.client_propagation_messages_received,
                client_propagation_messages_served: self.client_propagation_messages_served,
                unpeered_propagation_incoming: self.unpeered_propagation_incoming,
                unpeered_propagation_rx_bytes: self.unpeered_propagation_rx_bytes,
            },
        }
    }

    /// Persist runtime state to `state_dir` using MessagePack. Safe to call
    /// periodically; each file is written atomically via rename.
    pub fn save_state(&self, state_dir: &std::path::Path) -> std::io::Result<()> {
        self.state_snapshot().save_state(state_dir)
    }

    /// Return peer destination hashes that are due for sync and mark each as
    /// `LinkEstablishing` so concurrent calls don't double-schedule.
    ///
    /// Python's `LXMRouter.sync_peers()` drives network I/O directly; in Rust
    /// network I/O lives outside the router, so callers (e.g. `lxmd`) feed this
    /// list into whatever sync task manages link establishment.
    pub fn sync_peers(&mut self) -> Vec<[u8; 16]> {
        let mut due = Vec::new();
        for (hash, peer) in self.peers.iter_mut() {
            if peer.alive
                && peer.state == PeerState::Idle
                && peer.unhandled_messages() > 0
                && peer.should_sync()
            {
                peer.begin_sync();
                due.push(*hash);
            }
        }
        due
    }

    /// Return authoritative policies for peers that have not processed the
    /// current propagation-store generation. This is an O(peers) scheduler
    /// query; exact message eligibility is intentionally deferred to the
    /// sync task's off-loop offer preparation.
    ///
    /// The method does not mutate peer state, allowing a single shared sync
    /// task to accept one policy before the daemon marks that peer started.
    pub fn sync_peer_policies_for_store(&self, offer_generation: u64) -> Vec<OutboundOfferPolicy> {
        let eligible = self
            .peers
            .values()
            .filter(|peer| {
                peer.state == PeerState::Idle
                    && peer.should_sync()
                    && peer.needs_offer_generation(offer_generation)
            })
            .collect::<Vec<_>>();
        let has_alive = eligible.iter().any(|peer| peer.alive);
        let mut policies = eligible
            .into_iter()
            .filter(|peer| peer.alive == has_alive)
            .map(OutboundOfferPolicy::from)
            .collect::<Vec<_>>();
        policies.sort_by_key(|policy| policy.peer_hash);
        policies
    }

    pub fn add_peer(&mut self, peer: LxmPeer) -> bool {
        if self.peers.len() >= self.config.max_peers {
            return false;
        }
        self.peers.insert(peer.destination_hash, peer);
        true
    }

    /// Add a peer from announce data.
    ///
    /// The peer is added only when autopeer is enabled, the router is below
    /// `max_peers`, and the announce hop count is within `autopeer_maxdepth`.
    pub fn autopeer(&mut self, candidate: AutopeerCandidate) -> bool {
        let AutopeerCandidate {
            destination_hash,
            timebase,
            transfer_limit,
            sync_limit,
            stamp_cost,
            stamp_flexibility,
            peering_cost,
            metadata,
            hops,
        } = candidate;
        let configured_static = self.static_peers.contains(&destination_hash);

        // Python LXMRouter.peer() (LXMRouter.py:1896-1901): a peering cost
        // above our accepted maximum refuses the peering — and breaks an
        // existing one only when that policy announce is not stale.
        if peering_cost.unwrap_or(0) > self.config.ext.max_peering_cost {
            if self
                .peers
                .get(&destination_hash)
                .is_some_and(|peer| timebase >= peer.peering_timebase)
            {
                self.remove_peer(&destination_hash);
            }
            return false;
        }

        // Configured static peers always consume newer policy announces.
        // Automatically discovered peers remain governed by the live
        // autopeer/range policy, matching the upstream announce handler.
        if let Some(peer) = self.peers.get(&destination_hash) {
            let static_peer = configured_static || peer.is_static;
            if !static_peer && !self.config.autopeer {
                return false;
            }
            if !static_peer && hops.is_some_and(|h| h as usize > self.config.ext.autopeer_maxdepth)
            {
                if timebase >= peer.peering_timebase {
                    self.remove_peer(&destination_hash);
                }
                return false;
            }
        }
        if let Some(peer) = self.peers.get_mut(&destination_hash) {
            let refreshed = peer.refresh_from_announce_with_metadata(
                timebase,
                transfer_limit,
                sync_limit,
                stamp_cost,
                stamp_flexibility,
                peering_cost,
                metadata,
            );
            if configured_static {
                peer.is_static = true;
                peer.autopeered = false;
            }
            return refreshed;
        }

        if !configured_static && !self.config.autopeer {
            return false;
        }
        if !configured_static
            && hops.is_some_and(|h| h as usize > self.config.ext.autopeer_maxdepth)
        {
            return false;
        }

        let mut peer = LxmPeer::from_announce_with_metadata(
            destination_hash,
            timebase,
            transfer_limit,
            sync_limit,
            stamp_cost,
            stamp_flexibility,
            peering_cost,
            metadata,
        );
        if configured_static {
            peer.is_static = true;
            peer.autopeered = false;
        }
        self.add_peer(peer)
    }

    pub fn remove_peer(&mut self, destination_hash: &[u8; 16]) {
        self.peers.remove(destination_hash);
    }

    /// Remove a peer from both the active and static peer sets.
    pub fn unpeer(&mut self, destination_hash: &[u8; 16]) {
        self.peers.remove(destination_hash);
        self.static_peers.retain(|h| h != destination_hash);
    }

    /// Get a cached outbound stamp cost, or `None` if missing or expired.
    pub fn get_stamp_cost(&self, destination_hash: &[u8; 16]) -> Option<u8> {
        let entry = self.outbound_stamp_costs.get(destination_hash)?;
        let now = now_f64();
        if now - entry.recorded_at < STAMP_COST_EXPIRY as f64 {
            Some(entry.cost)
        } else {
            None
        }
    }

    pub fn set_stamp_cost(&mut self, destination_hash: [u8; 16], cost: u8) {
        let now = now_f64();
        self.outbound_stamp_costs.insert(
            destination_hash,
            StampCostEntry {
                cost,
                recorded_at: now,
            },
        );
    }

    pub fn set_propagation_enabled(&mut self, enabled: bool) {
        self.config.propagation_enabled = enabled;
    }

    /// Set the singular outbound propagation node used for `PROPAGATED`
    /// message delivery.
    pub fn set_outbound_propagation_node(&mut self, destination_hash: Option<[u8; 16]>) {
        self.outbound_propagation_node = destination_hash;
    }

    /// Mark pending messages due after a destination announce.
    ///
    /// Python's delivery announce handler sets `next_delivery_attempt = time.time()`
    /// and triggers outbound processing. Rust tracks the previous attempt time,
    /// so setting it beyond the retry window makes the message eligible on the
    /// next scheduler tick.
    pub fn trigger_outbound_for_delivery_announce(&mut self, destination_hash: [u8; 16]) -> usize {
        let now = now_f64();
        let due_now = now - DELIVERY_RETRY_WAIT as f64;
        let mut triggered = 0;
        for message in &mut self.pending_outbound {
            if message.destination_hash() == destination_hash {
                message.last_delivery_attempt = due_now;
                message.next_delivery_attempt = now;
                triggered += 1;
            }
        }
        triggered
    }

    /// Mark pending propagated messages due after the configured propagation node announces.
    ///
    /// Mirrors LXMF 0.9.8's propagation announce handler. The announce app_data
    /// must be a valid propagation-node announce before any retry backoff is
    /// cleared.
    pub fn trigger_outbound_for_propagation_node_announce(
        &mut self,
        destination_hash: [u8; 16],
        app_data: &[u8],
    ) -> usize {
        if self.outbound_propagation_node != Some(destination_hash) {
            return 0;
        }
        if crate::handlers::parse_pn_announce_data(app_data).is_none() {
            return 0;
        }

        let now = now_f64();
        let due_now = now - DELIVERY_RETRY_WAIT as f64;
        let mut triggered = 0;
        for message in &mut self.pending_outbound {
            if message.method == DeliveryMethod::Propagated {
                message.last_delivery_attempt = due_now;
                message.next_delivery_attempt = now;
                triggered += 1;
            }
        }
        triggered
    }

    pub fn set_autopeer(&mut self, enabled: bool) {
        self.config.autopeer = enabled;
    }

    pub fn set_max_peers(&mut self, max: usize) {
        self.config.max_peers = max;
    }

    /// Propagation storage limit in kilobytes.
    pub fn set_propagation_limit(&mut self, limit_kb: usize) {
        self.config.propagation_limit_kb = limit_kb;
    }

    pub fn set_stamp_requirements(&mut self, cost: u8, flex: u8) {
        self.config.propagation_stamp_cost = cost;
        self.config.propagation_stamp_flex = flex;
    }

    /// Build propagation-node announce app_data (msgpack).
    ///
    /// Python reference: LXMRouter.get_propagation_node_app_data — LXMRouter.py:306-318.
    pub fn get_propagation_node_app_data(&self) -> Vec<u8> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut metadata = std::collections::HashMap::new();
        if let Some(ref name) = self.config.ext.name {
            metadata.insert(0u8, name.as_bytes().to_vec());
        }

        let data = crate::handlers::PropagationNodeAnnounceData {
            legacy: false,
            node_state: self.config.propagation_enabled && !self.config.ext.from_static_only,
            timebase: now,
            transfer_limit: self.config.propagation_limit_kb as u64,
            sync_limit: self.config.sync_limit_kb as u64,
            stamp_cost: self.config.propagation_stamp_cost,
            stamp_flex: self.config.propagation_stamp_flex,
            peering_cost: self.config.ext.peering_cost,
            metadata,
        };

        crate::handlers::get_propagation_node_app_data(&data)
    }

    /// Validate a PoW stamp on an incoming message.
    pub fn validate_stamp(
        &self,
        message_hash: &[u8; 32],
        stamp: &[u8; 32],
        required_cost: u8,
    ) -> bool {
        stamper::validate_stamp(
            message_hash,
            stamp,
            required_cost,
            STAMP_WORKBLOCK_EXPAND_ROUNDS,
        )
    }

    /// Validate a stamp, accepting a matching ticket hash as a bypass.
    ///
    /// A ticket is matched by comparing the first 16 bytes of
    /// `SHA-256(ticket.token || message_id)` against the stamp prefix;
    /// otherwise falls back to PoW validation.
    pub fn validate_stamp_with_tickets(
        &self,
        message_id: &[u8; 32],
        stamp: &[u8],
        required_cost: u8,
        destination_hash: &[u8; 16],
    ) -> bool {
        let now = now_f64();
        for token in self.ticket_store.inbound_tokens(destination_hash, now) {
            let mut material = Vec::with_capacity(16 + 32);
            material.extend_from_slice(&token);
            material.extend_from_slice(message_id);
            let expected = rns_crypto::sha::truncated_hash(&material);
            if stamp == expected.as_ref() {
                return true;
            }
        }

        let Ok(pow_stamp) = <&[u8; 32]>::try_from(stamp) else {
            return false;
        };
        self.validate_stamp(message_id, pow_stamp, required_cost)
    }

    /// Called when a propagation transfer resource completes.
    pub fn handle_resource_concluded(&mut self, peer_hash: &[u8; 16], success: bool) {
        if let Some(peer) = self.peers.get_mut(peer_hash) {
            if success {
                if let Some(transferring) = peer.currently_transferring_messages.take() {
                    peer.outgoing += transferring.len() as u64;
                    peer.offered += transferring.len() as u64;
                }
                peer.heard();
                peer.sync_complete();
            } else {
                peer.sync_failed();
            }
        }
    }

    /// Summarise propagation-node state for a control status request.
    ///
    /// Python reference: LXMRouter.compile_stats.
    pub fn control_status(&self) -> Option<NodeStats> {
        if !self.config.propagation_enabled {
            return None;
        }

        let peer_stats: HashMap<[u8; 16], PeerStats> = self
            .peers
            .iter()
            .map(|(hash, peer)| {
                (
                    *hash,
                    PeerStats {
                        peer_type: if self.static_peers.contains(hash) {
                            "static".to_string()
                        } else {
                            "discovered".to_string()
                        },
                        state: peer.state as u8,
                        alive: peer.alive,
                        last_heard: peer.last_heard,
                        sync_transfer_rate: peer.sync_transfer_rate,
                        transfer_limit: peer.propagation_transfer_limit,
                        stamp_cost: peer.stamp_cost,
                        offered: peer.offered,
                        outgoing: peer.outgoing,
                        incoming: peer.incoming,
                        unhandled: peer.unhandled_messages(),
                    },
                )
            })
            .collect();

        Some(NodeStats {
            uptime: self
                .propagation_start_time
                .map(|t| now_f64() - t)
                .unwrap_or(0.0),
            delivery_limit: self.config.delivery_limit_kb,
            propagation_limit: self.config.propagation_limit_kb,
            sync_limit: self.config.sync_limit_kb,
            stamp_cost: self.config.propagation_stamp_cost,
            stamp_flex: self.config.propagation_stamp_flex,
            peering_cost: self.config.ext.peering_cost,
            message_count: self.propagation_store.len(),
            message_size: self.propagation_store.total_size(),
            storage_limit: self.config.ext.message_storage_limit,
            total_peers: self.peers.len(),
            max_peers: self.config.max_peers,
            peer_stats,
        })
    }

    pub fn clean_throttled_peers(&mut self) {
        let now = now_f64();
        self.throttled_peers.retain(|_, expiry| now < *expiry);
    }

    pub fn is_peer_throttled(&self, peer_hash: &[u8; 16]) -> bool {
        if let Some(expiry) = self.throttled_peers.get(peer_hash) {
            now_f64() < *expiry
        } else {
            false
        }
    }

    /// Throttle a peer for [`PN_STAMP_THROTTLE`] seconds.
    pub fn throttle_peer(&mut self, peer_hash: [u8; 16]) {
        self.throttled_peers
            .insert(peer_hash, now_f64() + PN_STAMP_THROTTLE as f64);
    }

    /// Drop idle, non-static peers with the lowest acceptance rates.
    ///
    /// Python reference: LXMRouter.rotate_peers.
    pub fn rotate_peers(&mut self) {
        let rotation_headroom = (self.config.max_peers * ROTATION_HEADROOM_PCT / 100).max(1);
        let required_drops = self.peers.len() as isize
            - (self.config.max_peers as isize - rotation_headroom as isize);

        if required_drops <= 0 || self.peers.len() <= 1 {
            return;
        }

        // Postpone rotation while a full headroom of peers has never been sync-tested.
        let untested_count = self
            .peers
            .values()
            .filter(|p| p.last_sync_attempt == 0.0)
            .count();
        if untested_count >= rotation_headroom {
            return;
        }

        let mut drop_candidates: Vec<([u8; 16], f64)> = self
            .peers
            .iter()
            .filter(|(hash, peer)| {
                !self.static_peers.contains(hash)
                    && peer.state == PeerState::Idle
                    && peer.offered > 0
            })
            .map(|(hash, peer)| (*hash, peer.acceptance_rate()))
            .collect();

        drop_candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let drop_count = (required_drops as usize).min(drop_candidates.len());
        for (hash, ar) in drop_candidates.into_iter().take(drop_count) {
            if ar < ROTATION_AR_MAX {
                self.unpeer(&hash);
            }
        }
    }

    /// Drain pending outbound messages into [`OutboundAction`]s.
    ///
    /// A delivery that later fails externally (e.g. unknown destination key)
    /// should be re-queued via [`send`][Self::send] with `delivery_attempts`
    /// incremented.
    #[tracing::instrument(
        level = "debug",
        name = "router.process_outbound",
        skip_all,
        fields(pending_count = self.pending_outbound.len()),
    )]
    pub fn process_outbound(&mut self) -> Vec<OutboundAction> {
        self.process_outbound_inner(DirectOutboundHandling::EmitLegacyAction)
    }

    fn process_outbound_without_direct(&mut self) -> Vec<OutboundAction> {
        self.process_outbound_inner(DirectOutboundHandling::LeavePending)
    }

    fn process_outbound_inner(
        &mut self,
        direct_handling: DirectOutboundHandling,
    ) -> Vec<OutboundAction> {
        if !self.config.ext.processing_outbound {
            return Vec::new();
        }

        let mut actions = Vec::new();
        let mut processed = 0usize;

        let mut i = 0;
        while i < self.pending_outbound.len() {
            if self
                .config
                .ext
                .processing_limit
                .is_some_and(|limit| processed >= limit)
            {
                break;
            }

            let msg = &self.pending_outbound[i];

            let now = now_f64();

            // Python fails only when delivery_attempts > MAX (outer guard is
            // `<= MAX`, LXMRouter.py:2597/2671); match that boundary exactly.
            if msg.delivery_attempts > MAX_DELIVERY_ATTEMPTS {
                let mut msg = self.pending_outbound.remove(i);
                msg.mark_failed();
                actions.push(OutboundAction::Failed(msg));
                processed += 1;
                continue;
            }

            // Python LXMF gates on an absolute `next_delivery_attempt`. Honor an
            // explicit deadline when set (path request -> now+7s, etc.);
            // otherwise fall back to the legacy
            // last_delivery_attempt + DELIVERY_RETRY_WAIT (10s) rule.
            let due_at = if msg.next_delivery_attempt > 0.0 {
                msg.next_delivery_attempt
            } else if msg.last_delivery_attempt > 0.0 {
                msg.last_delivery_attempt + DELIVERY_RETRY_WAIT as f64
            } else {
                0.0
            };
            if now < due_at {
                i += 1;
                continue;
            }

            let age = now - msg.timestamp();
            if age > MESSAGE_EXPIRY as f64 {
                let mut msg = self.pending_outbound.remove(i);
                msg.mark_failed();
                actions.push(OutboundAction::Expired(msg));
                processed += 1;
                continue;
            }

            // State transitions match Python LXMessage.py:476-499:
            //   Opportunistic -> Sent immediately; the embedding runtime keeps
            //   receipt ownership until an authenticated packet proof arrives.
            //   Direct / Propagated -> Sending (multi-step).
            match msg.method {
                DeliveryMethod::Direct => {
                    match direct_handling {
                        DirectOutboundHandling::EmitLegacyAction => {
                            let mut msg = self.pending_outbound.remove(i);
                            msg.mark_sending();
                            let dest_hash = msg.destination_hash();
                            actions.push(OutboundAction::DeliverDirect {
                                message: msg,
                                dest_hash,
                            });
                            processed += 1;
                            // The next element has shifted into index i, so do not advance.
                        }
                        DirectOutboundHandling::LeavePending => {
                            i += 1;
                        }
                    }
                }
                DeliveryMethod::Propagated => {
                    if let Some(peer_hash) = self.outbound_propagation_node {
                        let mut msg = self.pending_outbound.remove(i);
                        msg.mark_sending();
                        actions.push(OutboundAction::DeliverPropagated {
                            message: msg,
                            prop_hash: peer_hash,
                        });
                        processed += 1;
                    } else {
                        i += 1;
                    }
                }
                DeliveryMethod::Opportunistic => {
                    let mut msg = self.pending_outbound.remove(i);
                    msg.mark_sent();
                    msg.progress = 0.50;
                    let dest_hash = msg.destination_hash();
                    actions.push(OutboundAction::DeliverOpportunistic {
                        message: msg,
                        dest_hash,
                    });
                    processed += 1;
                }
                _ => {
                    i += 1;
                }
            }
        }

        actions
    }

    /// Process outbound messages while keeping Direct deliveries in the router
    /// queue until LinkDeliveryManager reports a terminal result.
    ///
    /// This mirrors Python's `LXMRouter.process_outbound` ownership model for
    /// Direct messages while preserving [`Self::process_outbound`] for older
    /// embedders that still take ownership of Direct messages themselves.
    pub fn process_outbound_with_direct<F>(&mut self, mut direct_input: F) -> Vec<OutboundAction>
    where
        F: FnMut(&LxMessage, f64) -> DirectDeliveryPlanInput,
    {
        if !self.config.ext.processing_outbound {
            return Vec::new();
        }

        let mut actions = Vec::new();
        let mut processed = 0usize;
        let mut i = 0;

        while i < self.pending_outbound.len() {
            if self
                .config
                .ext
                .processing_limit
                .is_some_and(|limit| processed >= limit)
            {
                break;
            }

            let now = now_f64();

            if self.pending_outbound[i].delivery_attempts > MAX_DELIVERY_ATTEMPTS {
                let mut msg = self.pending_outbound.remove(i);
                msg.mark_failed();
                actions.push(OutboundAction::Failed(msg));
                processed += 1;
                continue;
            }

            let age = now - self.pending_outbound[i].timestamp();
            if age > MESSAGE_EXPIRY as f64 {
                let mut msg = self.pending_outbound.remove(i);
                msg.mark_failed();
                actions.push(OutboundAction::Expired(msg));
                processed += 1;
                continue;
            }

            match self.pending_outbound[i].method {
                DeliveryMethod::Direct => {
                    let input = direct_input(&self.pending_outbound[i], now);
                    if input.reusable_link == DirectReusableLinkState::None {
                        let msg = &self.pending_outbound[i];
                        let due_at = if msg.next_delivery_attempt > 0.0 {
                            msg.next_delivery_attempt
                        } else if msg.last_delivery_attempt > 0.0 {
                            msg.last_delivery_attempt + DELIVERY_RETRY_WAIT as f64
                        } else {
                            0.0
                        };
                        if now < due_at {
                            i += 1;
                            continue;
                        }
                    }

                    if self.pending_outbound[i].state != MessageState::Sending {
                        self.pending_outbound[i].mark_sending();
                    }
                    let plan = plan_direct_delivery(&mut self.pending_outbound[i], input, now);
                    match plan {
                        DirectDeliveryPlan::Fail => {
                            let mut msg = self.pending_outbound.remove(i);
                            msg.mark_failed();
                            actions.push(OutboundAction::Failed(msg));
                            processed += 1;
                            continue;
                        }
                        DirectDeliveryPlan::DeferTerminalFailure => {
                            processed += 1;
                            i += 1;
                        }
                        _ => {
                            let msg = self.pending_outbound[i].clone();
                            let dest_hash = msg.destination_hash();
                            actions.push(OutboundAction::PlanDirect {
                                message: msg,
                                dest_hash,
                                plan,
                            });
                            processed += 1;
                            i += 1;
                        }
                    }
                }
                DeliveryMethod::Propagated => {
                    let msg = &self.pending_outbound[i];
                    let due_at = if msg.next_delivery_attempt > 0.0 {
                        msg.next_delivery_attempt
                    } else if msg.last_delivery_attempt > 0.0 {
                        msg.last_delivery_attempt + DELIVERY_RETRY_WAIT as f64
                    } else {
                        0.0
                    };
                    if now < due_at {
                        i += 1;
                        continue;
                    }

                    if let Some(peer_hash) = self.outbound_propagation_node {
                        let mut msg = self.pending_outbound.remove(i);
                        msg.mark_sending();
                        actions.push(OutboundAction::DeliverPropagated {
                            message: msg,
                            prop_hash: peer_hash,
                        });
                        processed += 1;
                    } else {
                        i += 1;
                    }
                }
                DeliveryMethod::Opportunistic => {
                    let msg = &self.pending_outbound[i];
                    let due_at = if msg.next_delivery_attempt > 0.0 {
                        msg.next_delivery_attempt
                    } else if msg.last_delivery_attempt > 0.0 {
                        msg.last_delivery_attempt + DELIVERY_RETRY_WAIT as f64
                    } else {
                        0.0
                    };
                    if now < due_at {
                        i += 1;
                        continue;
                    }

                    let mut msg = self.pending_outbound.remove(i);
                    msg.mark_sent();
                    msg.progress = 0.50;
                    let dest_hash = msg.destination_hash();
                    actions.push(OutboundAction::DeliverOpportunistic {
                        message: msg,
                        dest_hash,
                    });
                    processed += 1;
                }
                DeliveryMethod::Paper => {
                    i += 1;
                }
            }
        }

        actions
    }

    pub fn cull_stamp_costs(&mut self) {
        let now = now_f64();
        self.outbound_stamp_costs
            .retain(|_, e| now - e.recorded_at < STAMP_COST_EXPIRY as f64);
    }

    pub fn cull_propagation(&mut self) {
        self.propagation_store.cull_expired(MESSAGE_EXPIRY);
        if let Some(limit) = self.config.ext.message_storage_limit {
            self.propagation_store.cull_by_weight(limit);
        }
    }

    /// Send single-packet opportunistic actions via the configured transport.
    ///
    /// Direct and Propagated actions require a Reticulum link and are handled by
    /// `LinkDeliveryManager` / propagation helpers in the embedding runtime.
    pub fn execute_actions(&mut self, actions: Vec<OutboundAction>) {
        self.execute_actions_with_encryptor(actions, |dest_hash, _plaintext| {
            Err(MessageError::PackFailed(format!(
                "no destination encryptor configured for opportunistic delivery to {}",
                hex::encode(dest_hash)
            )))
        });
    }

    /// Send single-packet opportunistic actions with caller-supplied
    /// destination encryption.
    ///
    /// Python encrypts Opportunistic LXMF packet payloads with the recipient
    /// destination identity before handing bytes to Reticulum. Core cannot
    /// infer destination keys, so embeddings must provide the encryptor.
    pub fn execute_actions_with_encryptor<F>(
        &mut self,
        actions: Vec<OutboundAction>,
        mut encrypt_fn: F,
    ) where
        F: FnMut([u8; 16], &[u8]) -> Result<Vec<u8>, MessageError>,
    {
        let transport_tx = match &self.transport_tx {
            Some(tx) => tx.clone(),
            None => return,
        };

        for action in actions {
            match action {
                OutboundAction::DeliverOpportunistic {
                    mut message,
                    dest_hash,
                } => {
                    match message
                        .pack_opportunistic_encrypted(|plaintext| encrypt_fn(dest_hash, plaintext))
                    {
                        Ok(packet_payload) => {
                            // Python LXMessage.__as_packet strips the destination
                            // hash before encryption because the RNS packet
                            // header already carries it.
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
                            raw.extend_from_slice(&packet_payload);

                            let dispatched = transport_tx
                                .try_send(rns_transport::messages::TransportMessage::Outbound(
                                    rns_transport::messages::OutboundRequest {
                                        raw: Bytes::from(raw),
                                        destination_hash: dest_hash,
                                    },
                                ))
                                .is_ok();
                            if dispatched
                                && matches!(
                                    message.state,
                                    MessageState::Sending | MessageState::Sent
                                )
                            {
                                message.mark_sent();
                                message.progress = 1.0;
                            } else {
                                tracing::warn!(
                                    dest = %hex::encode(dest_hash),
                                    "transport backpressure deferred opportunistic LXMF delivery"
                                );
                                self.pending_outbound.push(message);
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                dest = %hex::encode(dest_hash),
                                error = %err,
                                "cannot execute opportunistic LXMF action; re-queueing"
                            );
                            self.pending_outbound.push(message);
                        }
                    }
                }
                OutboundAction::DeliverDirect { .. } | OutboundAction::PlanDirect { .. } => {
                    tracing::warn!(
                        "Direct LXMF delivery requires LinkDeliveryManager; action left for embedding runtime"
                    );
                }
                OutboundAction::DeliverPropagated { .. } => {
                    // Requires a link to a propagation node; handled outside this layer.
                }
                OutboundAction::Failed(_) | OutboundAction::Expired(_) => {}
            }
        }
    }

    /// Advance one scheduler tick: drain outbound, then run periodic jobs.
    pub fn tick(&mut self) {
        self.processing_count += 1;

        self.process_deferred_stamps();
        let actions = self.process_outbound_without_direct();
        if !actions.is_empty() {
            self.execute_actions(actions);
        }

        self.run_periodic_jobs();
    }

    /// Advance one scheduler tick using caller-supplied destination encryption
    /// for Opportunistic packet actions.
    pub fn tick_with_encryptor<F>(&mut self, encrypt_fn: F)
    where
        F: FnMut([u8; 16], &[u8]) -> Result<Vec<u8>, MessageError>,
    {
        self.processing_count += 1;

        self.process_deferred_stamps();
        let actions = self.process_outbound_without_direct();
        if !actions.is_empty() {
            self.execute_actions_with_encryptor(actions, encrypt_fn);
        }

        self.run_periodic_jobs();
    }

    /// Drive the periodic job machinery for embedders that process outbound
    /// themselves via `process_outbound_with_direct` instead of calling
    /// [`Self::tick`]. Without this the jobloop counters never advance and
    /// transient-cache cleaning, store culls, and peer rotation never run.
    /// Time-gated to Python's `PROCESSING_INTERVAL` so callers may invoke it
    /// every loop pass regardless of their tick rate (lxmd: 4 s, Ratspeak:
    /// 500 ms) without skewing the jobloop cadences.
    pub fn run_jobs_tick(&mut self) {
        let now = now_f64();
        if now - self.last_jobs_tick < PROCESSING_INTERVAL as f64 * 0.9 {
            return;
        }
        self.last_jobs_tick = now;
        self.processing_count += 1;
        self.run_periodic_jobs();
    }

    fn run_periodic_jobs(&mut self) {
        // Job cadences match the Python LXMRouter jobloop.
        if self.processing_count.is_multiple_of(JOB_TRANSIENT_INTERVAL) {
            self.propagation_store.clean_transient_caches(now_f64());
        }
        if self.processing_count.is_multiple_of(JOB_STORE_INTERVAL)
            && self.config.propagation_enabled
        {
            self.cull_propagation();
        }
        if self.processing_count.is_multiple_of(JOB_PEERSYNC_INTERVAL) {
            self.clean_throttled_peers();
        }
        if self.processing_count.is_multiple_of(JOB_ROTATE_INTERVAL)
            && self.config.propagation_enabled
        {
            self.rotate_peers();
        }
    }

    /// Get summary statistics.
    pub fn stats(&self) -> RouterStats {
        RouterStats {
            pending_outbound: self.pending_outbound.len(),
            pending_deferred_stamps: self.pending_deferred_stamps.len(),
            peers: self.peers.len(),
            propagation_entries: self.propagation_store.len(),
            propagation_size: self.propagation_store.total_size(),
            stamp_costs_cached: self.outbound_stamp_costs.len(),
        }
    }
}

/// Action to take on an outbound message.
#[derive(Debug)]
pub enum OutboundAction {
    /// Exhausted delivery attempts.
    Failed(LxMessage),
    /// Exceeded [`MESSAGE_EXPIRY`].
    Expired(LxMessage),
    DeliverDirect {
        message: LxMessage,
        dest_hash: [u8; 16],
    },
    /// Direct delivery planned without removing the message from
    /// `pending_outbound`.
    PlanDirect {
        message: LxMessage,
        dest_hash: [u8; 16],
        plan: DirectDeliveryPlan,
    },
    DeliverPropagated {
        message: LxMessage,
        prop_hash: [u8; 16],
    },
    /// Small enough for single-packet delivery.
    DeliverOpportunistic {
        message: LxMessage,
        dest_hash: [u8; 16],
    },
}

/// Router statistics.
#[derive(Debug)]
pub struct RouterStats {
    pub pending_outbound: usize,
    pub pending_deferred_stamps: usize,
    pub peers: usize,
    pub propagation_entries: usize,
    pub propagation_size: usize,
    pub stamp_costs_cached: usize,
}

/// Per-peer stats for control status.
#[derive(Debug, Clone)]
pub struct PeerStats {
    pub peer_type: String,
    pub state: u8,
    pub alive: bool,
    pub last_heard: f64,
    pub sync_transfer_rate: f64,
    pub transfer_limit: Option<f64>,
    pub stamp_cost: Option<u8>,
    pub offered: u64,
    pub outgoing: u64,
    pub incoming: u64,
    pub unhandled: u32,
}

/// Propagation node stats.
#[derive(Debug)]
pub struct NodeStats {
    pub uptime: f64,
    pub delivery_limit: f64,
    pub propagation_limit: usize,
    pub sync_limit: usize,
    pub stamp_cost: u8,
    pub stamp_flex: u8,
    pub peering_cost: u8,
    pub message_count: usize,
    pub message_size: usize,
    pub storage_limit: Option<usize>,
    pub total_peers: usize,
    pub max_peers: usize,
    pub peer_stats: HashMap<[u8; 16], PeerStats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_policy_message() -> LxMessage {
        let message = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Direct",
            "hello",
            DeliveryMethod::Direct,
        );
        message.compute_hash().unwrap();
        message
    }

    #[test]
    fn test_router_creation() {
        let router = LxmRouter::new(RouterConfig::default());
        assert!(router.pending_outbound.is_empty());
        assert!(router.peers.is_empty());
        assert!(router.propagation_store.is_empty());
    }

    #[test]
    fn run_jobs_tick_gates_on_processing_interval() {
        let mut router = LxmRouter::new(RouterConfig::default());
        router.run_jobs_tick();
        assert_eq!(router.processing_count, 1);
        // Second call inside the PROCESSING_INTERVAL window must not advance
        // the jobloop — embedders may call this at arbitrary loop rates.
        router.run_jobs_tick();
        assert_eq!(router.processing_count, 1);
        // Backdating the gate simulates the interval elapsing.
        router.last_jobs_tick = now_f64() - PROCESSING_INTERVAL as f64;
        router.run_jobs_tick();
        assert_eq!(router.processing_count, 2);
    }

    #[test]
    fn run_jobs_tick_cleans_transient_caches_at_job_interval() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let ancient = 1.0; // far older than MESSAGE_EXPIRY * 6
        let mut delivered = std::collections::HashMap::new();
        delivered.insert([0xAB; 32], ancient);
        router
            .propagation_store
            .replace_locally_delivered(delivered);

        // Land exactly on the transient-cache job multiple.
        router.processing_count = JOB_TRANSIENT_INTERVAL - 1;
        router.last_jobs_tick = now_f64() - PROCESSING_INTERVAL as f64;
        router.run_jobs_tick();

        assert!(
            !router
                .propagation_store
                .locally_delivered_ids()
                .contains_key(&[0xAB; 32]),
            "expired dedup id must be aged out by the jobloop"
        );
    }

    #[test]
    fn test_router_config_defaults() {
        let config = RouterConfig::default();
        assert!(config.autopeer);
        assert_eq!(config.ext.autopeer_maxdepth, 4);
        assert_eq!(config.ext.propagation_cost_min, 13);
        assert_eq!(config.ext.max_peering_cost, 26);
        assert!(config.ext.processing_outbound);
        assert!(config.ext.defer_stamp_generation);
        assert!(config.ext.processing_limit.is_none());
    }

    #[test]
    fn test_direct_delivery_plan_starts_link_with_current_path() {
        let mut msg = direct_policy_message();
        let dest = msg.destination_hash();
        let now = 1000.0;
        let plan = plan_direct_delivery(
            &mut msg,
            DirectDeliveryPlanInput {
                identity_known: true,
                route: Some(DirectRouteSnapshot::new(dest, 4)),
                reusable_link: DirectReusableLinkState::None,
            },
            now,
        );

        assert_eq!(plan, DirectDeliveryPlan::StartNewLink { hops: 4 });
        assert_eq!(msg.delivery_attempts, 1);
        assert_eq!(msg.last_delivery_attempt, now);
        assert_eq!(msg.next_delivery_attempt, now + DELIVERY_RETRY_WAIT as f64);
        assert_eq!(msg.progress, 0.03);
    }

    #[test]
    fn test_direct_delivery_plan_requests_path_for_unknown_identity() {
        let mut msg = direct_policy_message();
        let now = 1000.0;
        let plan = plan_direct_delivery(
            &mut msg,
            DirectDeliveryPlanInput {
                identity_known: false,
                route: None,
                reusable_link: DirectReusableLinkState::None,
            },
            now,
        );

        assert_eq!(
            plan,
            DirectDeliveryPlan::RequestPath {
                drop_existing: false
            }
        );
        assert_eq!(msg.delivery_attempts, 1);
        assert_eq!(msg.last_delivery_attempt, now);
        assert_eq!(msg.next_delivery_attempt, now + PATH_REQUEST_WAIT as f64);
        assert_eq!(msg.progress, 0.01);
    }

    #[test]
    fn test_direct_delivery_plan_reuses_active_link_without_attempt_increment() {
        let mut msg = direct_policy_message();
        let plan = plan_direct_delivery(
            &mut msg,
            DirectDeliveryPlanInput {
                identity_known: true,
                route: None,
                reusable_link: DirectReusableLinkState::Active,
            },
            1000.0,
        );

        assert_eq!(plan, DirectDeliveryPlan::UseReusableLink);
        assert_eq!(msg.delivery_attempts, 0);
        assert_eq!(msg.state, MessageState::Sending);
        assert_eq!(msg.progress, 0.05);
    }

    #[test]
    fn test_direct_delivery_plan_waits_for_pending_link() {
        let mut msg = direct_policy_message();
        let dest = msg.destination_hash();
        let plan = plan_direct_delivery(
            &mut msg,
            DirectDeliveryPlanInput {
                identity_known: true,
                route: Some(DirectRouteSnapshot::new(dest, 2)),
                reusable_link: DirectReusableLinkState::Pending,
            },
            1000.0,
        );

        assert_eq!(plan, DirectDeliveryPlan::WaitForReusableLink);
        assert_eq!(msg.delivery_attempts, 0);
        assert_eq!(msg.next_delivery_attempt, 0.0);
    }

    #[test]
    fn test_direct_delivery_plan_defers_terminal_failure_at_attempt_boundary() {
        let mut msg = direct_policy_message();
        let dest = msg.destination_hash();
        msg.delivery_attempts = MAX_DELIVERY_ATTEMPTS - 1;
        let now = 1000.0;
        let plan = plan_direct_delivery(
            &mut msg,
            DirectDeliveryPlanInput {
                identity_known: true,
                route: Some(DirectRouteSnapshot::new(dest, 1)),
                reusable_link: DirectReusableLinkState::None,
            },
            now,
        );

        assert_eq!(plan, DirectDeliveryPlan::DeferTerminalFailure);
        assert_eq!(msg.delivery_attempts, MAX_DELIVERY_ATTEMPTS);
        assert_eq!(msg.next_delivery_attempt, now + DELIVERY_RETRY_WAIT as f64);
    }

    #[test]
    fn test_direct_delivery_plan_requests_rediscovery_for_closed_link() {
        let mut msg = direct_policy_message();
        let dest = msg.destination_hash();
        let now = 1000.0;
        let plan = plan_direct_delivery(
            &mut msg,
            DirectDeliveryPlanInput {
                identity_known: true,
                route: Some(DirectRouteSnapshot::new(dest, 3)),
                reusable_link: DirectReusableLinkState::Closed { activated: false },
            },
            now,
        );

        assert_eq!(
            plan,
            DirectDeliveryPlan::RequestPath {
                drop_existing: true
            }
        );
        assert_eq!(msg.delivery_attempts, 0);
        assert_eq!(msg.next_delivery_attempt, now + PATH_REQUEST_WAIT as f64);
        assert_eq!(msg.progress, 0.01);
    }

    #[test]
    fn test_direct_delivery_plan_fails_above_max_attempts() {
        let mut msg = direct_policy_message();
        let dest = msg.destination_hash();
        msg.delivery_attempts = MAX_DELIVERY_ATTEMPTS + 1;
        let plan = plan_direct_delivery(
            &mut msg,
            DirectDeliveryPlanInput {
                identity_known: true,
                route: Some(DirectRouteSnapshot::new(dest, 1)),
                reusable_link: DirectReusableLinkState::None,
            },
            1000.0,
        );

        assert_eq!(plan, DirectDeliveryPlan::Fail);
        assert_eq!(msg.state, MessageState::Failed);
    }

    #[test]
    fn test_process_outbound_with_direct_keeps_message_pending() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = direct_policy_message();
        let msg_hash = Some(msg.message_id());
        let dest = msg.destination_hash();
        router.try_send(msg).unwrap();

        let actions =
            router.process_outbound_with_direct(|message, _now| DirectDeliveryPlanInput {
                identity_known: true,
                route: Some(DirectRouteSnapshot::new(message.destination_hash(), 4)),
                reusable_link: DirectReusableLinkState::None,
            });

        assert_eq!(router.pending_outbound.len(), 1);
        let pending = &router.pending_outbound[0];
        assert_eq!(Some(pending.message_id()), msg_hash);
        assert_eq!(pending.state, MessageState::Sending);
        assert_eq!(pending.delivery_attempts, 1);
        assert_eq!(pending.progress, 0.03);
        match actions.as_slice() {
            [
                OutboundAction::PlanDirect {
                    message,
                    dest_hash,
                    plan,
                },
            ] => {
                assert_eq!(*dest_hash, dest);
                assert_eq!(Some(message.message_id()), msg_hash);
                assert_eq!(*plan, DirectDeliveryPlan::StartNewLink { hops: 4 });
            }
            other => panic!("expected PlanDirect StartNewLink, got {other:?}"),
        }
    }

    #[test]
    fn test_process_outbound_with_direct_polls_pending_link_despite_retry_deadline() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = direct_policy_message();
        msg.next_delivery_attempt = now_f64() + 3600.0;
        let msg_hash = Some(msg.message_id());
        router.try_send(msg).unwrap();

        let actions =
            router.process_outbound_with_direct(|_message, _now| DirectDeliveryPlanInput {
                identity_known: true,
                route: None,
                reusable_link: DirectReusableLinkState::Pending,
            });

        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(Some(router.pending_outbound[0].message_id()), msg_hash);
        assert_eq!(router.pending_outbound[0].delivery_attempts, 0);
        match actions.as_slice() {
            [OutboundAction::PlanDirect { plan, .. }] => {
                assert_eq!(*plan, DirectDeliveryPlan::WaitForReusableLink);
            }
            other => panic!("expected PlanDirect WaitForReusableLink, got {other:?}"),
        }
    }

    #[test]
    fn test_outbound_terminal_helpers_update_pending_queue() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let first = direct_policy_message();
        let first_hash = first.message_id();
        router.try_send(first).unwrap();

        assert!(router.defer_outbound_for_path_request(&first_hash, 1000.0));
        assert_eq!(
            router.pending_outbound[0].next_delivery_attempt,
            1000.0 + PATH_REQUEST_WAIT as f64
        );
        assert_eq!(router.pending_outbound[0].progress, 0.01);

        assert!(router.mark_outbound_delivered(&first_hash));
        assert!(router.pending_outbound.is_empty());

        let second = direct_policy_message();
        let second_hash = second.message_id();
        router.try_send(second).unwrap();
        assert!(router.mark_outbound_failed(&second_hash));
        assert!(router.pending_outbound.is_empty());
    }

    #[test]
    fn test_allow_disallow() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let hash = [0xAA; 16];

        // Empty allow-list means all allowed.
        assert!(router.is_allowed(&hash));

        router.allow(hash);
        assert!(router.is_allowed(&hash));
        assert!(!router.is_allowed(&[0xBB; 16]));

        router.disallow(&hash);
        assert!(router.is_allowed(&hash));
    }

    #[test]
    fn test_block_unblock() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let hash = [0xAA; 16];

        assert!(router.is_allowed(&hash));

        router.block(hash);
        assert!(!router.is_allowed(&hash));

        router.unblock(&hash);
        assert!(router.is_allowed(&hash));
    }

    #[test]
    fn test_prioritise_unprioritise() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let hash = [0xAA; 16];

        router.prioritise(hash, 5);
        assert_eq!(router.prioritized.get(&hash), Some(&5));

        router.unprioritise(&hash);
        assert!(!router.prioritized.contains_key(&hash));
    }

    #[test]
    fn test_add_peer() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let peer = LxmPeer::new([0xAA; 16]);
        assert!(router.add_peer(peer));
        assert_eq!(router.peers.len(), 1);
    }

    #[test]
    fn test_max_peers() {
        let config = RouterConfig {
            max_peers: 2,
            ..Default::default()
        };
        let mut router = LxmRouter::new(config);

        assert!(router.add_peer(LxmPeer::new([0x01; 16])));
        assert!(router.add_peer(LxmPeer::new([0x02; 16])));
        assert!(!router.add_peer(LxmPeer::new([0x03; 16])));
    }

    #[test]
    fn test_stamp_cost_cache() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];

        assert!(router.get_stamp_cost(&dest).is_none());

        router.set_stamp_cost(dest, 12);
        assert_eq!(router.get_stamp_cost(&dest), Some(12));
    }

    #[test]
    fn test_send_uses_outbound_ticket_stamp_immediately() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];
        router.remember_ticket(dest, [0x42; 16], now_f64() + 60.0);
        router.set_stamp_cost(dest, 16);

        let mut msg = crate::message::LxMessageDraft::new(
            dest,
            [0xBB; 16],
            "ticket",
            "stamp",
            DeliveryMethod::Direct,
        )
        .unwrap();
        router.prepare_outbound(&mut msg).unwrap();
        let msg = msg.sign(&key).unwrap();
        router.submit_signed(msg).unwrap();

        assert!(router.pending_deferred_stamps.is_empty());
        assert_eq!(router.pending_outbound.len(), 1);
        let queued = &router.pending_outbound[0];
        assert_eq!(
            queued.recipient_stamp().map(|s| s.as_bytes().len()),
            Some(TICKET_LENGTH)
        );
        assert!(matches!(
            queued.recipient_stamp(),
            Some(RecipientStamp::Ticket(_))
        ));
    }

    #[test]
    fn prepare_outbound_issues_native_reply_ticket_before_signing() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut router = LxmRouter::new(RouterConfig::default());
        let dir = tempfile::tempdir().unwrap();
        let dest = [0xAA; 16];
        let mut msg =
            LxMessageDraft::new(dest, [0xBB; 16], "ticket", "reply", DeliveryMethod::Direct)
                .unwrap();
        msg.include_ticket = true;
        let intent = router.prepare_outbound(&mut msg).unwrap();
        assert!(intent.requires_persistence());
        let crate::message::FieldValue::MessagePack(field) = msg.get_field(FIELD_TICKET).unwrap()
        else {
            panic!("native ticket field required")
        };
        let value = rmpv::decode::read_value(&mut field.encoded()).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 2);
        assert!(msg.clone().sign(&key).is_err());
        intent.persist(dir.path(), &mut msg).unwrap();
        router.submit_signed(msg.sign(&key).unwrap()).unwrap();
        let hash = router.pending_outbound[0].message_id();
        assert!(router.mark_outbound_delivered(&hash));
        let mut next =
            LxMessageDraft::new(dest, [0xBB; 16], "ticket", "later", DeliveryMethod::Direct)
                .unwrap();
        next.include_ticket = true;
        let intent = router.prepare_outbound(&mut next).unwrap();
        assert!(!next.fields().contains_key(&FIELD_TICKET.into()));
        assert!(!intent.requires_persistence());
    }

    #[test]
    fn externally_retained_message_updates_ticket_only_when_completed() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut router = LxmRouter::new(RouterConfig::default());
        let dir = tempfile::tempdir().unwrap();
        let dest = [0xAC; 16];
        let mut in_flight = LxMessageDraft::new(
            dest,
            [0xBD; 16],
            "ticket",
            "proof",
            DeliveryMethod::Opportunistic,
        )
        .unwrap();
        in_flight.include_ticket = true;
        router
            .prepare_outbound(&mut in_flight)
            .unwrap()
            .persist(dir.path(), &mut in_flight)
            .unwrap();
        let in_flight = in_flight.sign(&key).unwrap().finalize(None).unwrap();
        let mut before_proof =
            LxMessageDraft::new(dest, [0xBD; 16], "ticket", "before", DeliveryMethod::Direct)
                .unwrap();
        before_proof.include_ticket = true;
        router
            .prepare_outbound(&mut before_proof)
            .unwrap()
            .persist(dir.path(), &mut before_proof)
            .unwrap();
        assert!(before_proof.get_field(FIELD_TICKET).is_some());
        router.complete_outbound_message(in_flight);
        let mut after_proof =
            LxMessageDraft::new(dest, [0xBD; 16], "ticket", "after", DeliveryMethod::Direct)
                .unwrap();
        after_proof.include_ticket = true;
        let intent = router.prepare_outbound(&mut after_proof).unwrap();
        assert!(after_proof.get_field(FIELD_TICKET).is_none());
        assert!(!intent.requires_persistence());
    }

    #[test]
    fn signed_message_requesting_ticket_fails_instead_of_invalidating_signature() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut draft = LxMessageDraft::new(
            [0xAA; 16],
            [0xBB; 16],
            "ticket",
            "pending",
            DeliveryMethod::Direct,
        )
        .unwrap();
        draft.include_ticket = true;
        let intent = router.prepare_outbound(&mut draft).unwrap();
        assert!(intent.requires_persistence());
        assert!(matches!(
            draft.sign(&key),
            Err(MessageError::TicketNotCommitted)
        ));
        assert!(router.pending_outbound.is_empty());
    }

    #[test]
    fn deliver_inbound_learns_ticket_only_after_signature_validation() {
        let identity = rns_identity::identity::Identity::new();
        let key = identity.get_signing_key().unwrap();
        let source = rns_identity::destination::Destination::hash_from_name_and_identity(
            "lxmf.delivery",
            Some(&identity.hash),
        );
        let mut sender = LxmRouter::new(RouterConfig::default());
        let dir = tempfile::tempdir().unwrap();
        let mut draft = LxMessageDraft::new(
            [0xAA; 16],
            source,
            "ticket",
            "learn",
            DeliveryMethod::Direct,
        )
        .unwrap();
        draft.include_ticket = true;
        sender
            .prepare_outbound(&mut draft)
            .unwrap()
            .persist(dir.path(), &mut draft)
            .unwrap();
        let message = draft.sign(&key).unwrap().finalize(None).unwrap();
        let mut receiver = LxmRouter::new(RouterConfig::default());
        assert!(receiver.deliver_inbound(&message, false));
        assert!(receiver.get_outbound_ticket(&source).is_none());
        let verified = message.verify(&identity.get_public_key()).unwrap();
        assert!(receiver.learn_ticket_from_inbound(&verified));
        assert!(receiver.get_outbound_ticket(&source).is_some());
    }

    #[tokio::test]
    async fn test_deferred_stamp_queue_completes_before_outbound_processing() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];
        router.set_stamp_cost(dest, 1);

        let mut msg = crate::message::LxMessageDraft::new(
            dest,
            [0xBB; 16],
            "defer",
            "stamp",
            DeliveryMethod::Direct,
        )
        .unwrap();
        router.prepare_outbound(&mut msg).unwrap();
        let msg = msg.sign(&key).unwrap();
        let message_id = msg.message_id();
        router.submit_signed(msg).unwrap();

        assert!(router.pending_outbound.is_empty());
        assert!(router.pending_deferred_stamps.contains_key(&message_id));

        for _ in 0..100 {
            router.process_deferred_stamps();
            if router.pending_outbound.len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert!(router.pending_deferred_stamps.is_empty());
        assert_eq!(router.pending_outbound.len(), 1);
        let queued = &router.pending_outbound[0];
        assert_eq!(
            queued.recipient_stamp().map(|s| s.as_bytes().len()),
            Some(32)
        );
        let Some(RecipientStamp::ProofOfWork(stamp)) = queued.recipient_stamp() else {
            panic!("PoW stamp required")
        };
        assert!(stamper::validate_stamp(
            &queued.message_id(),
            stamp,
            1,
            STAMP_WORKBLOCK_EXPAND_ROUNDS
        ));
    }

    /// Production shape: the manager tick runs on `spawn_blocking`, where
    /// `Handle::try_current()` fails. The router's stored handle must still
    /// spawn the PoW worker instead of grinding inline under the caller.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deferred_stamps_spawn_from_blocking_thread_via_stored_handle() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        // Constructed inside the runtime: handle captured.
        let mut router = LxmRouter::new(RouterConfig::default());
        assert!(
            router.runtime_handle.is_some(),
            "handle captured at construction"
        );
        let dest = [0xAA; 16];
        router.set_stamp_cost(dest, 1);

        let mut msg = crate::message::LxMessageDraft::new(
            dest,
            [0xBB; 16],
            "defer",
            "blocking",
            DeliveryMethod::Direct,
        )
        .unwrap();
        router.prepare_outbound(&mut msg).unwrap();
        let msg = msg.sign(&key).unwrap();
        let message_id = msg.message_id();
        router.submit_signed(msg).unwrap();
        assert!(router.pending_deferred_stamps.contains_key(&message_id));

        // Drive entirely from a blocking thread (no implicit runtime).
        let mut router = tokio::task::spawn_blocking(move || {
            router.process_deferred_stamps();
            assert!(
                router.active_deferred_stamp.is_some(),
                "must spawn a worker, not grind inline"
            );
            router
        })
        .await
        .unwrap();

        for _ in 0..200 {
            router.process_deferred_stamps();
            if router.pending_outbound.len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(
            router.pending_outbound[0]
                .recipient_stamp()
                .map(|s| s.as_bytes().len()),
            Some(32)
        );
    }

    /// Delivery-time deferral: a message that reaches the outbound executor
    /// without a stamp goes back through the deferred queue instead of
    /// blocking the caller.
    #[tokio::test]
    async fn defer_stamp_queues_message_with_id() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = crate::message::LxMessageDraft::new(
            [0xAA; 16],
            [0xBB; 16],
            "d",
            "s",
            DeliveryMethod::Direct,
        )
        .unwrap();
        msg.stamp_cost = Some(1);
        router.prepare_outbound(&mut msg).unwrap();
        let msg = msg.sign(&key).unwrap();
        let id = msg.message_id();

        router.defer_stamp(msg);
        assert!(router.pending_deferred_stamps.contains_key(&id));
    }

    #[tokio::test]
    async fn test_cancel_outbound_cancels_deferred_stamp_job() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];
        router.set_stamp_cost(dest, 8);

        let mut msg = crate::message::LxMessageDraft::new(
            dest,
            [0xBB; 16],
            "cancel",
            "stamp",
            DeliveryMethod::Direct,
        )
        .unwrap();
        router.prepare_outbound(&mut msg).unwrap();
        let msg = msg.sign(&key).unwrap();
        let message_id = msg.message_id();
        router.submit_signed(msg).unwrap();
        router.process_deferred_stamps();

        assert!(router.active_deferred_stamp.is_some());
        assert!(router.cancel_outbound(&message_id));
        assert!(router.pending_deferred_stamps.is_empty());
        assert!(router.active_deferred_stamp.is_none());
    }

    #[test]
    fn test_authentication_accessors() {
        let mut router = LxmRouter::new(RouterConfig::default());
        assert!(!router.requires_authentication());
        router.set_authentication(true);
        assert!(router.requires_authentication());
    }

    #[test]
    fn test_retain_node_lxms_accessors() {
        let mut router = LxmRouter::new(RouterConfig::default());
        assert!(!router.retain_node_lxms());
        router.set_retain_node_lxms(true);
        assert!(router.retain_node_lxms());
    }

    #[test]
    fn test_message_storage_limit_accessors() {
        let mut router = LxmRouter::new(RouterConfig::default());
        assert!(router.message_storage_limit().is_none());
        assert_eq!(router.message_storage_size(), 0);

        router.set_message_storage_limit(Some(1024 * 1024));
        assert_eq!(router.message_storage_limit(), Some(1024 * 1024));
    }

    #[test]
    fn test_ticket_api() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];

        assert!(router.get_outbound_ticket(&dest).is_none());
        assert!(router.get_outbound_ticket_expiry(&dest).is_none());
        assert!(router.get_inbound_tickets().is_empty());

        let token = router.generate_ticket(dest, None);
        assert!(router.get_outbound_ticket(&dest).is_none());
        assert_eq!(router.get_inbound_tickets().len(), 1);
        assert_eq!(router.get_inbound_tickets()[0].token, token);

        // A remembered peer ticket is outbound and does not alter the
        // locally-issued inbound set.
        router.remember_ticket(dest, [0x55; 16], now_f64() + 1000.0);
        assert_eq!(router.get_inbound_tickets().len(), 1);
        assert_eq!(router.get_outbound_ticket(&dest), Some([0x55; 16]));
        assert!(router.get_outbound_ticket_expiry(&dest).unwrap() > now_f64());
    }

    #[test]
    fn test_validate_stamp_checks_all_tickets() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];
        let expires = now_f64() + 1000.0;
        router
            .ticket_store
            .add_inbound(Ticket::new([0x01; 16], dest, expires));
        router
            .ticket_store
            .add_inbound(Ticket::new([0x02; 16], dest, expires));

        // Stamp derived from the SECOND ticket must still validate.
        let message_id = [0x33u8; 32];
        let mut material = Vec::with_capacity(16 + 32);
        material.extend_from_slice(&[0x02; 16]);
        material.extend_from_slice(&message_id);
        let stamp = rns_crypto::sha::truncated_hash(&material);

        assert!(router.validate_stamp_with_tickets(&message_id, stamp.as_ref(), 16, &dest));
    }

    #[test]
    fn test_cancel_outbound() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg =
            crate::message::test_message([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);
        msg.state = MessageState::Outbound;
        let hash = msg.message_id();
        router.pending_outbound.push(msg);

        assert!(router.cancel_outbound(&hash));
        assert!(router.pending_outbound.is_empty());
        assert!(!router.cancel_outbound(&hash));
    }

    #[test]
    fn test_get_outbound_progress() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg =
            crate::message::test_message([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);
        msg.progress = 0.42;
        let hash = msg.message_id();
        router.pending_outbound.push(msg);

        assert_eq!(router.get_outbound_progress(&hash), Some(0.42));
        assert_eq!(router.get_outbound_progress(&[0u8; 32]), None);
    }

    #[test]
    fn test_register_delivery_callback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut router = LxmRouter::new(RouterConfig::default());
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();
        router.register_delivery_callback(move |_| {
            fired_clone.store(true, Ordering::Relaxed);
        });

        let msg =
            crate::message::test_message([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);
        assert!(router.deliver_inbound(&msg, false));
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn inbound_delivery_is_deduped_across_packet_and_resource_representations() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut router = LxmRouter::new(RouterConfig::default());
        let deliveries = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&deliveries);
        router.register_delivery_callback(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        });

        let packet = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "same",
            "message",
            DeliveryMethod::Opportunistic,
        );
        let mut resource = packet.clone();
        resource.method = DeliveryMethod::Direct;

        assert!(router.deliver_inbound(&packet, false));
        assert!(!router.deliver_inbound(&resource, false));
        assert_eq!(deliveries.load(Ordering::Relaxed), 1);
        assert!(router.has_message(&packet.message_id()));
    }

    #[test]
    fn propagated_delivery_records_ciphertext_and_signed_message_ids() {
        use crate::admission::{
            AdmissionRecord, AdmissionScope, DurableAdmissionReceipt, DurableDisposition,
        };
        let mut router = LxmRouter::new(RouterConfig::default());
        let message = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "propagated",
            "message",
            DeliveryMethod::Propagated,
        );
        let temp = tempfile::tempdir().unwrap();
        let store = crate::admission_store::FileAdmissionStore::open(
            temp.path(),
            &temp.path().join("messages"),
        )
        .unwrap();
        let tid = [0x44; 32];
        let record = AdmissionRecord {
            scope: AdmissionScope {
                identity: [1; 16],
                node: [2; 16],
                transient_id: tid,
            },
            message_id: message.message_id(),
            received_wire_hash: rns_crypto::sha::full_hash(message.wire_bytes()),
            stored_message_wire_hash: None,
            disposition: DurableDisposition::Committed,
            committed_at: 100,
        };
        let reservation = router.reserve_inbound(&message).unwrap();
        let receipt =
            DurableAdmissionReceipt::commit(store.prepare(record, message.wire_owned(), false))
                .unwrap();
        assert!(router.commit_inbound(reservation, &message, &receipt, None));
        assert!(router.has_message(&message.message_id()));
        assert!(router.has_message(&tid));
        assert!(router.propagation_store.is_locally_processed(&tid));
        let mut direct = message.clone();
        direct.method = DeliveryMethod::Direct;
        assert!(!router.deliver_inbound(&direct, false));
    }

    #[test]
    fn test_ingest_lxm_uri() {
        use rns_crypto::ed25519::Ed25519PrivateKey;

        let mut router = LxmRouter::new(RouterConfig::default());
        let key = Ed25519PrivateKey::generate();
        let msg = crate::message::LxMessageDraft::new(
            [0xAA; 16],
            [0xBB; 16],
            "paper",
            "hello",
            DeliveryMethod::Paper,
        )
        .unwrap();
        let msg = msg.sign(&key).unwrap().finalize(None).unwrap();
        let uri = msg
            .to_paper_uri(|plaintext| Ok(plaintext.to_vec()))
            .unwrap();

        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();
        router.register_delivery_callback(move |_| {
            fired_clone.store(true, Ordering::Relaxed);
        });

        let decoded = router
            .ingest_lxm_uri(&uri, |ciphertext| Ok(ciphertext.to_vec()))
            .unwrap();
        assert_eq!(decoded.title_text(), "paper");
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn test_save_and_load_state_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dest_a = [0xAA; 16];
        let transient_a = [0x11; 32];

        let mut r1 = LxmRouter::new(RouterConfig::default());
        r1.set_stamp_cost(dest_a, 8);
        // Far-future expiry so get_outbound_ticket (which uses wall-clock now) matches.
        r1.remember_ticket(dest_a, [0x01; 16], 4_102_444_800.0);
        r1.propagation_store.mark_locally_delivered(transient_a);
        r1.propagation_store.mark_locally_processed(transient_a);
        r1.client_propagation_messages_received = 10;
        r1.client_propagation_messages_served = 11;
        r1.unpeered_propagation_incoming = 12;
        r1.unpeered_propagation_rx_bytes = 13;
        r1.save_state(tmp.path()).unwrap();

        let mut r2 = LxmRouter::new(RouterConfig::default());
        r2.load_state(tmp.path()).unwrap();
        assert_eq!(
            r2.outbound_stamp_costs.get(&dest_a).map(|e| e.cost),
            Some(8)
        );
        assert_eq!(r2.get_outbound_ticket(&dest_a), Some([0x01; 16]));
        assert!(r2.propagation_store.is_locally_delivered(&transient_a));
        assert!(r2.propagation_store.is_locally_processed(&transient_a));
        assert_eq!(r2.client_propagation_messages_received, 10);
        assert_eq!(r2.client_propagation_messages_served, 11);
        assert_eq!(r2.unpeered_propagation_incoming, 12);
        assert_eq!(r2.unpeered_propagation_rx_bytes, 13);
    }

    #[test]
    fn test_state_snapshot_is_an_owned_coherent_copy() {
        let dest = [0xA1; 16];
        let transient = [0xB2; 32];

        let mut router = LxmRouter::new(RouterConfig::default());
        router.set_stamp_cost(dest, 8);
        router.remember_ticket(dest, [0xC3; 16], 4_102_444_800.0);
        router.propagation_store.mark_locally_delivered(transient);
        router.propagation_store.mark_locally_processed(transient);
        router.client_propagation_messages_received = 10;
        router.client_propagation_messages_served = 11;
        router.unpeered_propagation_incoming = 12;
        router.unpeered_propagation_rx_bytes = 13;

        let snapshot = router.state_snapshot();

        // Mutating every persisted router dataset after capture must not alter
        // the snapshot that a background persistence task owns.
        router.set_stamp_cost(dest, 42);
        router.remember_ticket(dest, [0xD4; 16], 4_102_444_800.0);
        router
            .propagation_store
            .replace_locally_delivered(HashMap::new());
        router
            .propagation_store
            .replace_locally_processed(HashMap::new());
        router.client_propagation_messages_received = 20;
        router.client_propagation_messages_served = 21;
        router.unpeered_propagation_incoming = 22;
        router.unpeered_propagation_rx_bytes = 23;

        assert_eq!(snapshot.outbound_stamp_costs[&dest].cost, 8);
        let dir = tempfile::tempdir().unwrap();
        snapshot.tickets.save(dir.path(), None).unwrap();
        let (tickets, _) = crate::persist::load_tickets(dir.path()).unwrap();
        assert_eq!(tickets.outbound.len(), 1);
        assert_eq!(tickets.outbound[0].token, [0xC3; 16]);
        assert!(snapshot.local_deliveries.contains_key(&transient));
        assert!(snapshot.locally_processed.contains_key(&transient));
        assert_eq!(snapshot.node_stats.client_propagation_messages_received, 10);
        assert_eq!(snapshot.node_stats.client_propagation_messages_served, 11);
        assert_eq!(snapshot.node_stats.unpeered_propagation_incoming, 12);
        assert_eq!(snapshot.node_stats.unpeered_propagation_rx_bytes, 13);
    }

    #[test]
    fn test_state_snapshot_persists_after_router_is_dropped() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dest = [0xA5; 16];
        let transient = [0xB6; 32];

        let snapshot = {
            let mut router = LxmRouter::new(RouterConfig::default());
            router.set_stamp_cost(dest, 9);
            router.remember_ticket(dest, [0xC7; 16], 4_102_444_800.0);
            router.propagation_store.mark_locally_delivered(transient);
            router.propagation_store.mark_locally_processed(transient);
            router.client_propagation_messages_received = 30;
            router.client_propagation_messages_served = 31;
            router.unpeered_propagation_incoming = 32;
            router.unpeered_propagation_rx_bytes = 33;
            router.state_snapshot()
        };

        snapshot.save_state(tmp.path()).unwrap();

        let mut restored = LxmRouter::new(RouterConfig::default());
        restored.load_state(tmp.path()).unwrap();
        assert_eq!(restored.outbound_stamp_costs[&dest].cost, 9);
        assert_eq!(restored.get_outbound_ticket(&dest), Some([0xC7; 16]));
        assert!(restored.propagation_store.is_locally_delivered(&transient));
        assert!(restored.propagation_store.is_locally_processed(&transient));
        assert_eq!(restored.client_propagation_messages_received, 30);
        assert_eq!(restored.client_propagation_messages_served, 31);
        assert_eq!(restored.unpeered_propagation_incoming, 32);
        assert_eq!(restored.unpeered_propagation_rx_bytes, 33);
    }

    /// T1-10: persisted dedup timestamps are the REAL first-seen times —
    /// restored on load (not reset to save-time), so age-based expiry is
    /// stable across arbitrarily many save/load cycles.
    #[test]
    fn test_dedup_cache_timestamps_survive_save_load_cycles() {
        let tmp = tempfile::TempDir::new().unwrap();
        let transient = [0x42; 32];

        let mut router = LxmRouter::new(RouterConfig::default());
        router.propagation_store.mark_locally_delivered(transient);
        let original_ts = *router
            .propagation_store
            .locally_delivered_ids()
            .get(&transient)
            .unwrap();

        // Multiple save/load cycles must not refresh the timestamp.
        for _ in 0..3 {
            router.save_state(tmp.path()).unwrap();
            let mut reloaded = LxmRouter::new(RouterConfig::default());
            reloaded.load_state(tmp.path()).unwrap();
            let loaded_ts = *reloaded
                .propagation_store
                .locally_delivered_ids()
                .get(&transient)
                .unwrap();
            assert_eq!(loaded_ts, original_ts, "timestamp must survive reload");
            router = reloaded;
        }
        assert_eq!(router.propagation_store.locally_delivered_ids().len(), 1);

        // An aged-out entry is gone after the periodic clean, and stays gone
        // through persistence (growth bounded).
        let expiry = crate::constants::MESSAGE_EXPIRY as f64 * 6.0;
        router
            .propagation_store
            .clean_transient_caches(original_ts + expiry + 1.0);
        assert!(!router.propagation_store.is_locally_delivered(&transient));
        router.save_state(tmp.path()).unwrap();
        let mut fresh = LxmRouter::new(RouterConfig::default());
        fresh.load_state(tmp.path()).unwrap();
        assert!(fresh.propagation_store.locally_delivered_ids().is_empty());
    }

    #[test]
    fn test_load_state_missing_dir_is_ok() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut r = LxmRouter::new(RouterConfig::default());
        r.load_state(tmp.path()).unwrap();
        assert!(r.outbound_stamp_costs.is_empty());
    }

    #[test]
    fn test_sync_peers_picks_due_peers() {
        let mut router = LxmRouter::new(RouterConfig::default());

        let mut peer_due = LxmPeer::new([0x01; 16]);
        peer_due.add_unhandled_message();
        router.add_peer(peer_due);

        let peer_idle_no_msgs = LxmPeer::new([0x02; 16]);
        router.add_peer(peer_idle_no_msgs);

        let mut peer_in_flight = LxmPeer::new([0x03; 16]);
        peer_in_flight.add_unhandled_message();
        peer_in_flight.begin_sync();
        router.add_peer(peer_in_flight);

        let due = router.sync_peers();
        assert_eq!(due, vec![[0x01; 16]]);

        // Subsequent call returns empty — the due peer is now LinkEstablishing.
        assert!(router.sync_peers().is_empty());
    }

    #[test]
    fn store_generation_scheduler_skips_unchanged_and_reenables_on_store_or_policy_change() {
        let peer_hash = [0x11; 16];
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut peer = LxmPeer::from_announce(
            peer_hash,
            10.0,
            Some(1.0),
            Some(2.0),
            Some(16),
            Some(3),
            Some(18),
        );
        peer.mark_offer_generation_processed(5);
        router.add_peer(peer);

        assert!(router.sync_peer_policies_for_store(5).is_empty());
        let due = router.sync_peer_policies_for_store(6);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].peer_hash, peer_hash);
        assert_eq!(router.peers[&peer_hash].state, PeerState::Idle);

        router
            .peers
            .get_mut(&peer_hash)
            .unwrap()
            .mark_offer_generation_processed(6);
        assert!(router.sync_peer_policies_for_store(6).is_empty());
        assert!(router.autopeer(AutopeerCandidate {
            destination_hash: peer_hash,
            timebase: 11.0,
            transfer_limit: Some(1.0),
            sync_limit: Some(2.0),
            stamp_cost: Some(12),
            stamp_flexibility: Some(3),
            peering_cost: Some(18),
            metadata: Some(std::collections::HashMap::new()),
            hops: Some(1),
        }));
        assert_eq!(router.sync_peer_policies_for_store(6).len(), 1);
    }

    #[test]
    fn store_generation_scheduler_falls_back_to_backoff_expired_unresponsive_peers() {
        let alive_hash = [0x21; 16];
        let fallback_hash = [0x22; 16];
        let mut router = LxmRouter::new(RouterConfig::default());
        let alive = LxmPeer::new(alive_hash);
        let mut fallback = LxmPeer::new(fallback_hash);
        fallback.alive = false;
        fallback.next_sync_attempt = 0.0;
        assert!(router.add_peer(alive));
        assert!(router.add_peer(fallback));

        let policies = router.sync_peer_policies_for_store(1);
        assert_eq!(
            policies
                .iter()
                .map(|policy| policy.peer_hash)
                .collect::<Vec<_>>(),
            vec![alive_hash]
        );

        router.peers.get_mut(&alive_hash).unwrap().begin_sync();
        let policies = router.sync_peer_policies_for_store(1);
        assert_eq!(
            policies
                .iter()
                .map(|policy| policy.peer_hash)
                .collect::<Vec<_>>(),
            vec![fallback_hash]
        );
    }

    #[test]
    fn test_validate_stamp() {
        let router = LxmRouter::new(RouterConfig::default());
        let msg_id = rns_crypto::sha::sha256(b"test message");
        let stamp =
            stamper::generate_stamp_limited(&msg_id, 4, STAMP_WORKBLOCK_EXPAND_ROUNDS, 1_000_000);
        if let Some(stamp) = stamp {
            assert!(router.validate_stamp(&msg_id, &stamp, 4));
        }
    }

    #[test]
    fn test_send_message() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Content",
            DeliveryMethod::Direct,
        );
        router.try_send(msg).unwrap();
        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(router.pending_outbound[0].state, MessageState::Outbound);
    }

    /// LXMF 1.2.0 keeps a message opportunistic only while its content fits
    /// one encrypted packet, 287 bytes (LXMessage.py:64-79, :402-406).
    #[test]
    fn opportunistic_content_over_one_packet_falls_back_to_direct() {
        let mut router = LxmRouter::new(RouterConfig::default());
        for (content_size, method) in [
            (287, DeliveryMethod::Opportunistic),
            (288, DeliveryMethod::Direct),
        ] {
            let message = crate::message::test_message(
                [0xAA; 16],
                [0xBB; 16],
                "",
                &"x".repeat(content_size),
                DeliveryMethod::Opportunistic,
            );
            let packed = message.pack_payload().unwrap();
            assert_eq!(
                packed.len() - TIMESTAMP_SIZE - STRUCT_OVERHEAD,
                content_size
            );
            router.try_send(message).unwrap();
            assert_eq!(
                router.pending_outbound.last().unwrap().method,
                method,
                "content of {content_size} bytes"
            );
        }
    }

    #[test]
    fn test_try_send_propagated_without_node_fails_immediately() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );

        let err = router.try_send(msg).unwrap_err();
        assert!(matches!(err, SendError::MissingOutboundPropagationNode(_)));
        assert_eq!(err.message().state, MessageState::Failed);
        assert!(router.pending_outbound.is_empty());
    }

    /// Python fails a message only when delivery_attempts > MAX_DELIVERY_ATTEMPTS
    /// (outer guard is `<= MAX`, LXMRouter.py:2597/2671). Pin that boundary.
    #[test]
    fn test_process_outbound_fails_only_above_max_attempts() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.delivery_attempts = MAX_DELIVERY_ATTEMPTS + 1;
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], OutboundAction::Failed(_)));
        assert!(router.pending_outbound.is_empty());
    }

    /// At exactly MAX the message is still attempted (dispatched), not failed.
    #[test]
    fn test_process_outbound_at_max_attempts_not_failed() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.delivery_attempts = MAX_DELIVERY_ATTEMPTS;
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        assert_eq!(actions.len(), 1);
        assert!(
            !matches!(actions[0], OutboundAction::Failed(_)),
            "at exactly MAX the message is still attempted, not failed"
        );
    }

    #[test]
    fn test_stats() {
        let router = LxmRouter::new(RouterConfig::default());
        let stats = router.stats();
        assert_eq!(stats.pending_outbound, 0);
        assert_eq!(stats.peers, 0);
        assert_eq!(stats.propagation_entries, 0);
    }

    #[test]
    fn test_allow_control() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let hash = [0xCC; 16];

        router.allow_control(hash);
        assert!(router.is_control_allowed(&hash));
        assert!(!router.is_control_allowed(&[0xDD; 16]));

        router.disallow_control(&hash);
        assert!(!router.is_control_allowed(&hash));
    }

    #[test]
    fn test_set_transport() {
        let mut router = LxmRouter::new(RouterConfig::default());
        assert!(!router.has_transport());
        assert!(router.transport_tx.is_none());

        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        router.set_transport(tx);
        assert!(router.has_transport());
        assert!(router.transport_tx.is_some());
    }

    #[test]
    fn test_process_outbound_direct_delivery() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Direct",
            "Content",
            DeliveryMethod::Direct,
        );
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        let has_direct = actions
            .iter()
            .any(|a| matches!(a, OutboundAction::DeliverDirect { .. }));
        assert!(has_direct);
    }

    #[test]
    fn test_process_outbound_propagated_delivery() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let peer_hash = [0x11; 16];
        let peer = crate::peer::LxmPeer::new(peer_hash);
        router.add_peer(peer);
        router.set_outbound_propagation_node(Some(peer_hash));

        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        let has_propagated = actions
            .iter()
            .any(|a| matches!(a, OutboundAction::DeliverPropagated { .. }));
        assert!(has_propagated);
    }

    #[test]
    fn test_process_outbound_opportunistic_delivery() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Opportunistic",
            "Content",
            DeliveryMethod::Opportunistic,
        );
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        let has_opportunistic = actions
            .iter()
            .any(|a| matches!(a, OutboundAction::DeliverOpportunistic { .. }));
        assert!(has_opportunistic);
    }

    #[test]
    fn test_process_outbound_propagated_no_node() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        assert!(matches!(
            router.try_send(msg),
            Err(SendError::MissingOutboundPropagationNode(_))
        ));

        assert!(
            router.pending_outbound.is_empty(),
            "propagated messages without an outbound node fail at queue time"
        );
    }

    #[test]
    fn test_delivery_announce_trigger_clears_direct_retry_backoff() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];
        let mut msg = crate::message::test_message(
            dest,
            [0xBB; 16],
            "Direct",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.delivery_attempts = 1;
        msg.last_delivery_attempt = now_f64();
        msg.next_delivery_attempt = now_f64() + PATH_REQUEST_WAIT as f64;
        router.try_send(msg).unwrap();

        assert!(router.process_outbound().is_empty());
        assert_eq!(router.trigger_outbound_for_delivery_announce(dest), 1);
        assert!(matches!(
            router.process_outbound().as_slice(),
            [OutboundAction::DeliverDirect { .. }]
        ));
    }

    #[test]
    fn test_delivery_announce_trigger_clears_propagated_recipient_backoff() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];
        let node = [0xCC; 16];
        router.set_outbound_propagation_node(Some(node));
        let mut msg = crate::message::test_message(
            dest,
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        msg.delivery_attempts = 1;
        msg.last_delivery_attempt = now_f64();
        msg.next_delivery_attempt = now_f64() + PATH_REQUEST_WAIT as f64;
        router.try_send(msg).unwrap();

        assert!(router.process_outbound().is_empty());
        assert_eq!(router.trigger_outbound_for_delivery_announce(dest), 1);
        assert!(matches!(
            router.process_outbound().as_slice(),
            [OutboundAction::DeliverPropagated { .. }]
        ));
    }

    #[test]
    fn test_propagation_node_announce_trigger_clears_propagated_retry_backoff() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let node = [0xCC; 16];
        router.set_outbound_propagation_node(Some(node));
        let mut msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        msg.delivery_attempts = 1;
        msg.last_delivery_attempt = now_f64();
        msg.next_delivery_attempt = now_f64() + PATH_REQUEST_WAIT as f64;
        router.try_send(msg).unwrap();

        assert!(router.process_outbound().is_empty());

        let pn_data = crate::handlers::get_propagation_node_app_data(
            &crate::handlers::PropagationNodeAnnounceData::new(true, 256, 10240, 16, 3, 18),
        );
        assert_eq!(
            router.trigger_outbound_for_propagation_node_announce(node, &pn_data),
            1
        );
        assert!(matches!(
            router.process_outbound().as_slice(),
            [OutboundAction::DeliverPropagated { .. }]
        ));
    }

    #[test]
    fn test_propagation_node_announce_trigger_requires_configured_valid_node() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let node = [0xCC; 16];
        router.set_outbound_propagation_node(Some(node));
        router
            .try_send(crate::message::test_message(
                [0xAA; 16],
                [0xBB; 16],
                "Propagated",
                "Content",
                DeliveryMethod::Propagated,
            ))
            .unwrap();

        assert_eq!(
            router.trigger_outbound_for_propagation_node_announce([0xDD; 16], b"not-msgpack"),
            0
        );
        assert_eq!(
            router.trigger_outbound_for_propagation_node_announce(node, b"not-msgpack"),
            0
        );
    }

    /// A queued message older than `MESSAGE_EXPIRY` must be flushed as
    /// `Expired` on the next `process_outbound`, marked Failed, and not
    /// held indefinitely. Mirrors Python LXMRouter.process_outbound where
    /// the age check runs before any delivery attempt.
    #[test]
    fn test_process_outbound_expired_message_marked_failed() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = crate::message::LxMessageDraft::new(
            [0xAA; 16],
            [0xBB; 16],
            "Stale",
            "Content",
            DeliveryMethod::Direct,
        )
        .unwrap();
        // Anchor the timestamp comfortably past the expiry window.
        msg.set_timestamp(now_f64() - (MESSAGE_EXPIRY as f64) - 60.0)
            .unwrap();
        let msg = msg
            .sign(&rns_crypto::ed25519::Ed25519PrivateKey::generate())
            .unwrap()
            .finalize(None)
            .unwrap();
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(&actions[0], OutboundAction::Expired(m) if m.state == MessageState::Failed),
            "expired message surfaces as Expired with state=Failed, got {:?}",
            actions[0]
        );
        assert!(
            router.pending_outbound.is_empty(),
            "expired message removed from queue"
        );
    }

    /// A message that has attempted delivery within the last
    /// `DELIVERY_RETRY_WAIT` seconds must be skipped by `process_outbound`
    /// rather than immediately retried. Prevents tight-loop reattempt
    /// storms when a transport has a transient failure.
    #[test]
    fn test_process_outbound_retry_backoff_defers_within_window() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Backoff",
            "Content",
            DeliveryMethod::Direct,
        );
        // Simulate one failed attempt very recently.
        msg.delivery_attempts = 1;
        msg.last_delivery_attempt = now_f64() - 1.0; // 1 s ago, inside the 10 s window.
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        assert!(
            actions.is_empty(),
            "inside retry-wait window: no action emitted, got {:?}",
            actions
        );
        assert_eq!(
            router.pending_outbound.len(),
            1,
            "message stays queued for the next tick"
        );
    }

    /// Waiting for route or metadata preconditions is not itself a failed
    /// delivery attempt, but it still needs the same retry backoff to avoid
    /// tight request-path loops.
    #[test]
    fn test_process_outbound_retry_backoff_uses_last_attempt_timestamp() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Backoff",
            "Content",
            DeliveryMethod::Propagated,
        );
        msg.last_delivery_attempt = now_f64() - 1.0;
        router.set_outbound_propagation_node(Some([0xCC; 16]));
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        assert!(
            actions.is_empty(),
            "metadata waits should stay queued inside retry-wait window"
        );
        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(router.pending_outbound[0].delivery_attempts, 0);
    }

    /// The state machine contract: a Direct message picked up by
    /// `process_outbound` must be emitted as `DeliverDirect` with the
    /// message state transitioned to `Sending` before it leaves the queue.
    /// Complements `test_process_outbound_direct_delivery`, which only
    /// covers the action variant without asserting on state.
    #[test]
    fn test_process_outbound_direct_transitions_to_sending() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Direct",
            "Content",
            DeliveryMethod::Direct,
        );
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            OutboundAction::DeliverDirect { message, .. } => {
                assert_eq!(
                    message.state,
                    MessageState::Sending,
                    "Direct message enters Sending on dequeue"
                );
            }
            other => panic!("expected DeliverDirect, got {:?}", other),
        }
    }

    #[test]
    fn test_tick_sends_to_transport() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        router.set_transport(tx);

        let signing_key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let msg = crate::message::LxMessageDraft::new(
            [0xAA; 16],
            [0xBB; 16],
            "Tick Test",
            "Content",
            DeliveryMethod::Opportunistic,
        )
        .unwrap();
        let msg = msg.sign(&signing_key).unwrap().finalize(None).unwrap();
        router.try_send(msg).unwrap();

        router.tick_with_encryptor(|_dest, plaintext| Ok(plaintext.to_vec()));

        let received = rx.try_recv();
        assert!(received.is_ok(), "expected outbound packet from tick()");
        assert!(
            router.pending_outbound.is_empty(),
            "a successful fire-and-forget tick must not requeue the sent packet"
        );
    }

    #[test]
    fn test_execute_actions_no_transport() {
        let mut router = LxmRouter::new(RouterConfig::default());
        // No transport set — execute_actions must be a no-op.
        let actions = vec![OutboundAction::DeliverDirect {
            message: crate::message::test_message(
                [0; 16],
                [0; 16],
                "t",
                "c",
                DeliveryMethod::Direct,
            ),
            dest_hash: [0; 16],
        }];
        router.execute_actions(actions);
    }

    #[test]
    fn test_execute_actions_only_sends_opportunistic_packet_payload_shape() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let dest_hash = [0xAA; 16];
        let src_hash = [0xBB; 16];

        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let mut router = LxmRouter::new(RouterConfig::default());
        router.set_transport(tx);

        let direct = crate::message::LxMessageDraft::new(
            dest_hash,
            src_hash,
            "Direct",
            "d",
            DeliveryMethod::Direct,
        )
        .unwrap();
        let direct = direct.sign(&key).unwrap().finalize(None).unwrap();

        let opportunistic = crate::message::LxMessageDraft::new(
            dest_hash,
            src_hash,
            "Opp",
            "o",
            DeliveryMethod::Opportunistic,
        )
        .unwrap();
        let opportunistic = opportunistic.sign(&key).unwrap().finalize(None).unwrap();
        let opportunistic_packed = opportunistic.pack().unwrap();

        router.execute_actions_with_encryptor(
            vec![
                OutboundAction::DeliverDirect {
                    message: direct,
                    dest_hash,
                },
                OutboundAction::DeliverOpportunistic {
                    message: opportunistic,
                    dest_hash,
                },
            ],
            |_dest, plaintext| {
                let mut out = vec![0xEE];
                out.extend_from_slice(plaintext);
                Ok(out)
            },
        );

        let opportunistic_raw = match rx.try_recv().expect("opportunistic outbound request") {
            rns_transport::messages::TransportMessage::Outbound(req) => req.raw,
            other => panic!("expected outbound request, got {other:?}"),
        };
        let (_, opportunistic_data_offset) =
            rns_wire::header::PacketHeader::unpack(&opportunistic_raw).unwrap();
        assert_eq!(
            &opportunistic_raw[opportunistic_data_offset..],
            [&[0xEE], &opportunistic_packed[DESTINATION_LENGTH..]].concat(),
            "Opportunistic delivery encrypts the LXMF tail after the destination hash"
        );
        assert!(
            rx.try_recv().is_err(),
            "Direct actions require LinkDeliveryManager and must not be sent as destination packets"
        );
    }

    #[test]
    fn opportunistic_transport_backpressure_requeues_instead_of_dropping() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let dest_hash = [0xA1; 16];
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(
            rns_transport::messages::TransportMessage::DeregisterDestination { hash: [0xF0; 16] },
        )
        .unwrap();
        let mut router = LxmRouter::new(RouterConfig::default());
        router.set_transport(tx);
        let message = crate::message::LxMessageDraft::new(
            dest_hash,
            [0xB1; 16],
            "defer",
            "payload",
            DeliveryMethod::Opportunistic,
        )
        .unwrap();
        let message = message.sign(&key).unwrap().finalize(None).unwrap();
        let message_hash = Some(message.message_id());

        router.execute_actions_with_encryptor(
            vec![OutboundAction::DeliverOpportunistic { message, dest_hash }],
            |_dest, plaintext| Ok(plaintext.to_vec()),
        );

        assert!(matches!(
            rx.try_recv().unwrap(),
            rns_transport::messages::TransportMessage::DeregisterDestination { .. }
        ));
        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(
            Some(router.pending_outbound.first().unwrap().message_id()),
            message_hash
        );
    }

    #[test]
    fn test_execute_actions_without_encryptor_does_not_send_opportunistic_plaintext() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let dest_hash = [0xAA; 16];
        let src_hash = [0xBB; 16];

        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let mut router = LxmRouter::new(RouterConfig::default());
        router.set_transport(tx);

        let direct = crate::message::LxMessageDraft::new(
            dest_hash,
            src_hash,
            "Direct",
            "d",
            DeliveryMethod::Direct,
        )
        .unwrap();
        let direct = direct.sign(&key).unwrap().finalize(None).unwrap();

        let opportunistic = crate::message::LxMessageDraft::new(
            dest_hash,
            src_hash,
            "Opp",
            "o",
            DeliveryMethod::Opportunistic,
        )
        .unwrap();
        let opportunistic = opportunistic.sign(&key).unwrap().finalize(None).unwrap();

        router.execute_actions(vec![
            OutboundAction::DeliverDirect {
                message: direct,
                dest_hash,
            },
            OutboundAction::DeliverOpportunistic {
                message: opportunistic,
                dest_hash,
            },
        ]);

        assert!(
            rx.try_recv().is_err(),
            "execute_actions without an encryptor must not send raw opportunistic payloads"
        );
    }

    #[test]
    fn test_ignore_destination() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];

        router.ignore_destination(dest);
        assert!(router.ignored.contains(&dest));
        assert!(router.propagation_store.is_destination_ignored(&dest));

        router.unignore_destination(&dest);
        assert!(!router.ignored.contains(&dest));
        assert!(!router.propagation_store.is_destination_ignored(&dest));
    }

    #[test]
    fn test_autopeer() {
        let mut router = LxmRouter::new(RouterConfig::default());
        assert!(router.autopeer(AutopeerCandidate {
            destination_hash: [0xAA; 16],
            timebase: 1000.0,
            transfer_limit: Some(256.0),
            sync_limit: Some(10240.0),
            stamp_cost: Some(16),
            stamp_flexibility: Some(3),
            peering_cost: Some(18),
            metadata: None,
            hops: Some(2),
        }));
        assert_eq!(router.peers.len(), 1);

        assert!(!router.autopeer(AutopeerCandidate {
            destination_hash: [0xAA; 16],
            timebase: 1000.0,
            transfer_limit: None,
            sync_limit: None,
            stamp_cost: None,
            stamp_flexibility: None,
            peering_cost: None,
            metadata: None,
            hops: None,
        }));
        assert!(!router.autopeer(AutopeerCandidate {
            destination_hash: [0xBB; 16],
            timebase: 1000.0,
            transfer_limit: None,
            sync_limit: None,
            stamp_cost: None,
            stamp_flexibility: None,
            peering_cost: None,
            metadata: None,
            hops: Some(10),
        }));
    }

    #[test]
    fn existing_static_peer_accepts_only_newer_policy_when_autopeer_is_disabled() {
        let peer_hash = [0xAA; 16];
        let mut router = LxmRouter::new(RouterConfig {
            autopeer: false,
            ..Default::default()
        });
        let mut peer = LxmPeer::new(peer_hash);
        peer.is_static = true;
        peer.peering_timebase = 100.0;
        peer.stamp_cost = Some(8);
        router.add_peer(peer);

        let candidate = |timebase, stamp_cost| AutopeerCandidate {
            destination_hash: peer_hash,
            timebase,
            transfer_limit: Some(2.0),
            sync_limit: Some(8.0),
            stamp_cost: Some(stamp_cost),
            stamp_flexibility: Some(3),
            peering_cost: Some(18),
            metadata: None,
            hops: Some(99),
        };

        assert!(router.autopeer(candidate(101.0, 16)));
        let refreshed = router.peers.get(&peer_hash).unwrap();
        assert_eq!(refreshed.stamp_cost, Some(16));
        assert_eq!(refreshed.propagation_sync_limit, Some(8.0));
        assert!(refreshed.is_static);

        assert!(!router.autopeer(candidate(100.0, 4)));
        assert_eq!(router.peers.get(&peer_hash).unwrap().stamp_cost, Some(16));

        assert!(!router.autopeer(AutopeerCandidate {
            destination_hash: [0xBB; 16],
            timebase: 101.0,
            transfer_limit: Some(2.0),
            sync_limit: Some(8.0),
            stamp_cost: Some(16),
            stamp_flexibility: Some(3),
            peering_cost: Some(18),
            metadata: None,
            hops: Some(1),
        }));
        assert!(!router.peers.contains_key(&[0xBB; 16]));
    }

    #[test]
    fn configured_static_announce_recreates_missing_peer_with_autopeer_disabled() {
        let peer_hash = [0xA5; 16];
        let mut router = LxmRouter::new(RouterConfig {
            autopeer: false,
            ext: RouterConfigExt {
                autopeer_maxdepth: 1,
                ..Default::default()
            },
            ..Default::default()
        });
        router.static_peers.push(peer_hash);
        router.remove_peer(&peer_hash);

        assert!(router.autopeer(AutopeerCandidate {
            destination_hash: peer_hash,
            timebase: 101.0,
            transfer_limit: Some(2.0),
            sync_limit: Some(8.0),
            stamp_cost: Some(16),
            stamp_flexibility: Some(3),
            peering_cost: Some(18),
            metadata: Some(std::collections::HashMap::from([(
                crate::constants::PN_META_NAME,
                b"static".to_vec(),
            )])),
            hops: Some(99),
        }));
        let peer = router.peers.get(&peer_hash).unwrap();
        assert!(peer.is_static);
        assert!(!peer.autopeered);
        assert_eq!(
            peer.metadata
                .as_ref()
                .and_then(|metadata| metadata.get(&crate::constants::PN_META_NAME)),
            Some(&b"static".to_vec())
        );
    }

    #[test]
    fn stale_over_cost_announce_does_not_remove_newer_peer() {
        let peer_hash = [0xAA; 16];
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut peer = LxmPeer::new(peer_hash);
        peer.peering_timebase = 200.0;
        router.add_peer(peer);
        let max = router.config.ext.max_peering_cost;

        assert!(!router.autopeer(AutopeerCandidate {
            destination_hash: peer_hash,
            timebase: 199.0,
            transfer_limit: None,
            sync_limit: None,
            stamp_cost: None,
            stamp_flexibility: None,
            peering_cost: Some(max + 1),
            metadata: None,
            hops: None,
        }));
        assert!(router.peers.contains_key(&peer_hash));
    }

    #[test]
    fn nonstatic_peer_still_obeys_autopeer_and_range_on_refresh() {
        let peer_hash = [0xAA; 16];
        let candidate = |timebase, hops| AutopeerCandidate {
            destination_hash: peer_hash,
            timebase,
            transfer_limit: Some(2.0),
            sync_limit: Some(8.0),
            stamp_cost: Some(16),
            stamp_flexibility: Some(3),
            peering_cost: Some(18),
            metadata: None,
            hops: Some(hops),
        };

        let mut disabled = LxmRouter::new(RouterConfig {
            autopeer: false,
            ..Default::default()
        });
        let mut peer = LxmPeer::new(peer_hash);
        peer.peering_timebase = 100.0;
        disabled.add_peer(peer);
        assert!(!disabled.autopeer(candidate(101.0, 1)));
        assert_eq!(
            disabled.peers.get(&peer_hash).unwrap().peering_timebase,
            100.0
        );

        let mut ranged = LxmRouter::new(RouterConfig {
            ext: RouterConfigExt {
                autopeer_maxdepth: 1,
                ..Default::default()
            },
            ..Default::default()
        });
        let mut peer = LxmPeer::new(peer_hash);
        peer.peering_timebase = 100.0;
        ranged.add_peer(peer);
        assert!(!ranged.autopeer(candidate(101.0, 2)));
        assert!(!ranged.peers.contains_key(&peer_hash));
    }

    /// T0-4: peering cost above `max_peering_cost` refuses peering, and an
    /// existing peering breaks when the peer raises its cost beyond the cap
    /// (Python LXMRouter.py:1896-1901).
    #[test]
    fn test_autopeer_enforces_max_peering_cost() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let max = router.config.ext.max_peering_cost;

        let candidate = |cost: Option<u8>| AutopeerCandidate {
            destination_hash: [0xAA; 16],
            timebase: 1000.0,
            transfer_limit: Some(256.0),
            sync_limit: None,
            stamp_cost: Some(16),
            stamp_flexibility: Some(3),
            peering_cost: cost,
            metadata: None,
            hops: Some(2),
        };

        // Over-cost announce: refused outright.
        assert!(!router.autopeer(candidate(Some(max + 1))));
        assert!(router.peers.is_empty());

        // At-cost announce: accepted.
        assert!(router.autopeer(candidate(Some(max))));
        assert_eq!(router.peers.len(), 1);

        // Existing peer raising its cost beyond the cap: peering breaks.
        assert!(!router.autopeer(candidate(Some(max + 1))));
        assert!(router.peers.is_empty(), "over-cost announce must unpeer");
    }

    #[test]
    fn test_autopeer_respects_configured_maxdepth() {
        let mut router = LxmRouter::new(RouterConfig {
            ext: RouterConfigExt {
                autopeer_maxdepth: 1,
                ..Default::default()
            },
            ..Default::default()
        });

        assert!(!router.autopeer(AutopeerCandidate {
            destination_hash: [0xAA; 16],
            timebase: 1000.0,
            transfer_limit: None,
            sync_limit: None,
            stamp_cost: None,
            stamp_flexibility: None,
            peering_cost: None,
            metadata: None,
            hops: Some(2),
        }));
        assert!(router.autopeer(AutopeerCandidate {
            destination_hash: [0xBB; 16],
            timebase: 1000.0,
            transfer_limit: None,
            sync_limit: None,
            stamp_cost: None,
            stamp_flexibility: None,
            peering_cost: None,
            metadata: None,
            hops: Some(1),
        }));
    }

    #[test]
    fn test_resource_concluded() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let peer_hash = [0xAA; 16];
        let mut peer = LxmPeer::new(peer_hash);
        peer.currently_transferring_messages = Some(vec![[0x01; 32], [0x02; 32]]);
        peer.state = PeerState::ResourceTransferring;
        router.add_peer(peer);

        router.handle_resource_concluded(&peer_hash, true);

        let peer = router.peers.get(&peer_hash).unwrap();
        assert_eq!(peer.state, PeerState::Idle);
        assert_eq!(peer.outgoing, 2);
        assert!(peer.currently_transferring_messages.is_none());
    }

    #[test]
    fn test_control_status() {
        let config = RouterConfig {
            propagation_enabled: true,
            ..Default::default()
        };
        let mut router = LxmRouter::new(config);
        router.propagation_start_time = Some(now_f64());

        let stats = router.control_status();
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.total_peers, 0);
        assert_eq!(stats.message_count, 0);
    }

    #[test]
    fn test_processing_limit() {
        let mut config = RouterConfig::default();
        config.ext.processing_limit = Some(1);
        let mut router = LxmRouter::new(config);

        router
            .try_send(crate::message::test_message(
                [0x01; 16],
                [0; 16],
                "a",
                "b",
                DeliveryMethod::Direct,
            ))
            .unwrap();
        router
            .try_send(crate::message::test_message(
                [0x02; 16],
                [0; 16],
                "c",
                "d",
                DeliveryMethod::Direct,
            ))
            .unwrap();

        let actions = router.process_outbound();
        assert_eq!(actions.len(), 1);
        assert_eq!(router.pending_outbound.len(), 1);
    }

    #[test]
    fn test_throttle_peer() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let hash = [0xAA; 16];

        assert!(!router.is_peer_throttled(&hash));
        router.throttle_peer(hash);
        assert!(router.is_peer_throttled(&hash));
    }

    #[test]
    fn test_opportunistic_fallback_to_direct() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let large_content = "x".repeat(500);
        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Large",
            &large_content,
            DeliveryMethod::Opportunistic,
        );
        router.try_send(msg).unwrap();

        assert_eq!(router.pending_outbound[0].method, DeliveryMethod::Direct);
    }

    #[test]
    fn test_direct_message_state_sending() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Direct",
            "Content",
            DeliveryMethod::Direct,
        );
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            OutboundAction::DeliverDirect { message, .. } => {
                assert_eq!(message.state, MessageState::Sending);
            }
            _ => panic!("expected DeliverDirect"),
        }
    }

    #[test]
    fn test_propagated_message_state_sending() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let peer_hash = [0x11; 16];
        let peer = crate::peer::LxmPeer::new(peer_hash);
        router.add_peer(peer);
        router.set_outbound_propagation_node(Some(peer_hash));

        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            OutboundAction::DeliverPropagated { message, .. } => {
                assert_eq!(message.state, MessageState::Sending);
            }
            _ => panic!("expected DeliverPropagated"),
        }
    }

    #[test]
    fn test_opportunistic_message_state_sent() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = crate::message::test_message(
            [0xAA; 16],
            [0xBB; 16],
            "Opportunistic",
            "Content",
            DeliveryMethod::Opportunistic,
        );
        router.try_send(msg).unwrap();

        let actions = router.process_outbound();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            OutboundAction::DeliverOpportunistic { message, .. } => {
                assert_eq!(message.state, MessageState::Sent);
                assert_eq!(message.progress, 0.50);
            }
            _ => panic!("expected DeliverOpportunistic"),
        }
    }

    #[test]
    fn test_direct_message_left_for_link_delivery_after_execute() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        router.set_transport(tx);

        let signing_key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let msg = crate::message::LxMessageDraft::new(
            [0xAA; 16],
            [0xBB; 16],
            "Direct Sent",
            "Content",
            DeliveryMethod::Direct,
        )
        .unwrap();
        let msg = msg.sign(&signing_key).unwrap().finalize(None).unwrap();
        router.try_send(msg).unwrap();

        router.tick();

        assert!(
            rx.try_recv().is_err(),
            "Direct delivery requires LinkDeliveryManager, not router.execute_actions"
        );
        assert_eq!(
            router.pending_outbound.len(),
            1,
            "core tick must leave Direct messages queued for LinkDeliveryManager"
        );
        assert_eq!(
            router.pending_outbound[0].state,
            MessageState::Outbound,
            "core tick without a Direct adapter must not claim link sending started"
        );
    }

    fn resumable_sender() -> (rns_identity::identity::Identity, [u8; 16]) {
        let identity = rns_identity::identity::Identity::new();
        let source = rns_identity::destination::Destination::hash_from_name_and_identity(
            "lxmf.delivery",
            Some(&identity.hash),
        );
        (identity, source)
    }

    fn resumable_draft(source: [u8; 16], content: &str) -> LxMessageDraft {
        LxMessageDraft::new(
            [0xA7; 16],
            source,
            "resume",
            content,
            DeliveryMethod::Direct,
        )
        .unwrap()
    }

    fn stored_form(
        router: &mut LxmRouter,
        identity: &rns_identity::identity::Identity,
        draft: &mut LxMessageDraft,
    ) -> crate::message::ResumableLxMessage {
        router.prepare_outbound(draft).unwrap();
        let signed = draft
            .clone()
            .sign(&identity.get_signing_key().unwrap())
            .unwrap();
        let stored = signed.to_resumable();
        crate::message::ResumableLxMessage::from_bytes(stored.as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn restored_message_keeps_its_id_and_signed_wire() {
        let (identity, source) = resumable_sender();
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut draft = resumable_draft(source, "same bytes");
        router.prepare_outbound(&mut draft).unwrap();
        let signed = draft.sign(&identity.get_signing_key().unwrap()).unwrap();
        let stored = signed.to_resumable();
        let original = signed.finalize(None).unwrap();

        // Only the public key is needed to restore and finish the message.
        let public_key = identity.get_public_key();
        let restarted = LxmRouter::new(RouterConfig::default());
        let restored = restarted
            .restore_signed(&stored, &public_key, DeliveryMethod::Opportunistic)
            .unwrap();
        assert_eq!(restored.message_id(), original.message_id());
        assert_eq!(restored.method, DeliveryMethod::Opportunistic);
        assert_eq!(restored.state, MessageState::Outbound);
        assert!(!restored.incoming);
        let finished = restored.finalize(None).unwrap();
        assert_eq!(finished.wire_bytes(), original.wire_bytes());
        assert!(finished.verify(&public_key).is_ok());
    }

    #[test]
    fn restore_refuses_another_identity_and_a_bad_signature() {
        let (identity, source) = resumable_sender();
        let mut router = LxmRouter::new(RouterConfig::default());
        let stored = stored_form(&mut router, &identity, &mut resumable_draft(source, "x"));

        let other = rns_identity::identity::Identity::new();
        assert!(matches!(
            router.restore_signed(&stored, &other.get_public_key(), DeliveryMethod::Direct),
            Err(MessageError::SourceMismatch)
        ));

        let mut forged = stored.as_bytes().to_vec();
        forged[40] ^= 0x01;
        let at = forged.len() - 16;
        let digest = rns_crypto::sha::sha256(&forged[..at]);
        forged[at..].copy_from_slice(&digest[..16]);
        let forged = crate::message::ResumableLxMessage::from_bytes(forged).unwrap();
        assert!(matches!(
            router.restore_signed(&forged, &identity.get_public_key(), DeliveryMethod::Direct),
            Err(MessageError::InvalidSignature)
        ));
    }

    #[test]
    fn restore_refreshes_the_ticket_and_keeps_the_signing_cost_as_a_floor() {
        let (identity, source) = resumable_sender();
        let destination = [0xA7; 16];
        let mut sender = LxmRouter::new(RouterConfig::default());
        sender.remember_ticket(destination, [0x42; 16], now_f64() + 60.0);
        sender.set_stamp_cost(destination, 8);
        let mut draft = resumable_draft(source, "ticketed");
        sender.prepare_outbound(&mut draft).unwrap();
        assert!(draft.outbound_ticket.is_some());
        let stored = draft
            .sign(&identity.get_signing_key().unwrap())
            .unwrap()
            .to_resumable();
        let public_key = identity.get_public_key();

        // After a restart the ticket has expired and the cost entry is gone:
        // the message proves work at the cost it was signed under.
        let mut restarted = LxmRouter::new(RouterConfig::default());
        restarted.remember_ticket(destination, [0x42; 16], now_f64() - 1.0);
        let restored = restarted
            .restore_signed(&stored, &public_key, DeliveryMethod::Direct)
            .unwrap();
        assert_eq!(restored.outbound_ticket(), None);
        assert_eq!(restored.stamp_cost(), Some(8));
        let id = restored.message_id();
        restarted.submit_signed(restored).unwrap();
        assert!(restarted.pending_deferred_stamps.contains_key(&id));

        restarted.set_stamp_cost(destination, 12);
        let raised = restarted
            .restore_signed(&stored, &public_key, DeliveryMethod::Direct)
            .unwrap();
        assert_eq!(raised.stamp_cost(), Some(12));
        restarted.set_stamp_cost(destination, 4);
        let lowered = restarted
            .restore_signed(&stored, &public_key, DeliveryMethod::Direct)
            .unwrap();
        assert_eq!(lowered.stamp_cost(), Some(8));

        restarted.remember_ticket(destination, [0x43; 16], now_f64() + 60.0);
        let ticketed = restarted
            .restore_signed(&stored, &public_key, DeliveryMethod::Direct)
            .unwrap();
        assert_eq!(ticketed.outbound_ticket(), Some([0x43; 16]));
    }

    #[test]
    fn submit_signed_refuses_a_message_already_queued() {
        let (identity, source) = resumable_sender();
        let key = identity.get_signing_key().unwrap();
        let mut router = LxmRouter::new(RouterConfig::default());
        let draft = resumable_draft(source, "once");
        router
            .submit_signed(draft.clone().sign(&key).unwrap())
            .unwrap();
        assert!(matches!(
            router.submit_signed(draft.sign(&key).unwrap()),
            Err(MessageError::AlreadyQueued)
        ));
        assert_eq!(router.pending_outbound.len(), 1);

        let mut stamped = resumable_draft(source, "stamped once");
        stamped.stamp_cost = Some(8);
        router
            .submit_signed(stamped.clone().sign(&key).unwrap())
            .unwrap();
        assert!(matches!(
            router.submit_signed(stamped.sign(&key).unwrap()),
            Err(MessageError::AlreadyQueued)
        ));
        assert_eq!(router.pending_deferred_stamps.len(), 1);
        assert_eq!(router.pending_outbound.len(), 1);
    }

    #[test]
    fn restoring_one_message_twice_queues_it_once() {
        let (identity, source) = resumable_sender();
        let mut router = LxmRouter::new(RouterConfig::default());
        let stored = stored_form(
            &mut router,
            &identity,
            &mut resumable_draft(source, "twice"),
        );
        let public_key = identity.get_public_key();
        for _ in 0..2 {
            let restored = router
                .restore_signed(&stored, &public_key, DeliveryMethod::Direct)
                .unwrap();
            let _ = router.submit_signed(restored);
        }
        assert_eq!(router.pending_outbound.len(), 1);
    }

    /// Python's deferred-stamp dict keeps insertion order (LXMRouter.py:2655-2662).
    #[test]
    fn deferred_stamps_are_generated_in_submission_order() {
        let (identity, source) = resumable_sender();
        let key = identity.get_signing_key().unwrap();
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut submitted = Vec::new();
        for n in 0..12 {
            let mut draft = resumable_draft(source, &format!("deferred {n}"));
            draft.stamp_cost = Some(1);
            let signed = draft.sign(&key).unwrap();
            submitted.push(signed.message_id());
            router.submit_signed(signed).unwrap();
        }
        assert!(router.cancel_outbound(&submitted.remove(3)));
        while !router.pending_deferred_stamps.is_empty() {
            router.process_deferred_stamps();
        }
        let stamped: Vec<_> = router
            .pending_outbound
            .iter()
            .map(|message| message.message_id())
            .collect();
        assert_eq!(stamped, submitted);
    }
}
