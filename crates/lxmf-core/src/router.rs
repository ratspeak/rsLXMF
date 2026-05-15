//! LXMF Router: message delivery engine and propagation node.
//!
//! Python reference: LXMF/LXMRouter.py. Actor pattern — a single tokio task owns
//! all mutable state.

use std::collections::HashMap;
use std::fmt;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::constants::*;
use crate::message::{LxMessage, MessageError};
use crate::peer::LxmPeer;
use crate::propagation::PropagationStore;
use crate::stamper;
use crate::ticket::{Ticket, TicketStore};
use crate::types::PropagationTransientId;

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
    pub delivery_limit_kb: usize,
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
    /// Maximum message size in bytes (`None` = unlimited).
    pub max_message_size: Option<usize>,
    pub enforce_ratchets: bool,
    pub enforce_stamps: bool,
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
            max_message_size: None,
            enforce_ratchets: false,
            enforce_stamps: false,
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
            delivery_limit_kb: DELIVERY_LIMIT,
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
}

impl SendError {
    pub fn message(&self) -> &LxMessage {
        match self {
            Self::MissingOutboundPropagationNode(message) => message,
        }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingOutboundPropagationNode(_) => f.write_str(
                "attempt to send propagated message with no outbound propagation node configured",
            ),
        }
    }
}

impl std::error::Error for SendError {}

/// LXMF router — owns all mutable state under the actor pattern.
pub struct LxmRouter {
    pub config: RouterConfig,
    pub pending_outbound: Vec<LxMessage>,
    /// Messages awaiting deferred stamp generation, keyed by message hash.
    pub pending_deferred_stamps: HashMap<[u8; 32], LxMessage>,
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
    /// Identity hash → priority level.
    pub prioritized: HashMap<[u8; 16], u8>,
    pub delivery_callback: Option<DeliveryCallback>,
    pub transport_tx: Option<mpsc::Sender<rns_transport::messages::TransportMessage>>,
    /// Throttled peers → expiry timestamp (seconds since UNIX epoch).
    pub throttled_peers: HashMap<[u8; 16], f64>,
    pub propagation_start_time: Option<f64>,
    pub processing_count: u64,
    pub outbound_propagation_node: Option<[u8; 16]>,
    /// Progress in the range 0.0..=1.0.
    pub propagation_transfer_progress: f64,
    pub client_propagation_messages_received: u64,
    pub client_propagation_messages_served: u64,
    pub unpeered_propagation_incoming: u64,
    pub unpeered_propagation_rx_bytes: u64,
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
    pub hops: Option<u8>,
}

/// Cached stamp cost for a destination.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StampCostEntry {
    pub cost: u8,
    pub recorded_at: f64,
}

impl LxmRouter {
    pub fn new(config: RouterConfig) -> Self {
        Self {
            config,
            pending_outbound: Vec::new(),
            pending_deferred_stamps: HashMap::new(),
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
            prioritized: HashMap::new(),
            delivery_callback: None,
            transport_tx: None,
            throttled_peers: HashMap::new(),
            propagation_start_time: None,
            processing_count: 0,
            outbound_propagation_node: None,
            propagation_transfer_progress: 0.0,
            client_propagation_messages_received: 0,
            client_propagation_messages_served: 0,
            unpeered_propagation_incoming: 0,
            unpeered_propagation_rx_bytes: 0,
        }
    }

    pub fn set_transport(&mut self, tx: mpsc::Sender<rns_transport::messages::TransportMessage>) {
        self.transport_tx = Some(tx);
    }

    pub fn has_transport(&self) -> bool {
        self.transport_tx.is_some()
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
            destination_hash = %hex::encode(&message.destination_hash[..8]),
            method = ?message.method,
            content_len = message.content.len(),
        ),
    )]
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

        let now = now_f64();
        if message.outbound_ticket.is_none()
            && let Some(ticket) = self.ticket_store.find(&message.destination_hash, now)
        {
            message.outbound_ticket = Some(ticket.token);
        }

        if message.stamp.is_none() && message.stamp_cost.is_none() {
            message.stamp_cost = self
                .get_stamp_cost(&message.destination_hash)
                .filter(|cost| *cost > 0);
        }

        if message.stamp.is_none()
            && message.outbound_ticket.is_some()
            && (message.message_id.is_some() || message.compute_hash().is_ok())
        {
            message.get_stamp();
        }

        if message.stamp.is_none()
            && message.stamp_cost.unwrap_or(0) > 0
            && (message.message_id.is_some() || message.compute_hash().is_ok())
        {
            if self.config.ext.defer_stamp_generation {
                if let Some(message_hash) = message.message_id.or(message.hash) {
                    message.state = MessageState::Outbound;
                    self.pending_deferred_stamps.insert(message_hash, message);
                    return Ok(());
                }
            } else {
                message.get_stamp();
            }
        }

        if message.method == DeliveryMethod::Opportunistic
            && let Ok(packed) = message.pack_payload()
        {
            let content_size = packed
                .len()
                .saturating_sub(TIMESTAMP_SIZE + STRUCT_OVERHEAD);
            // Approximates ENCRYPTED_PACKET_MAX_CONTENT for default RNS parameters.
            let max_content = 295;
            if content_size > max_content {
                message.method = DeliveryMethod::Direct;
            }
        }

        message.state = MessageState::Outbound;
        self.pending_outbound.push(message);
        Ok(())
    }

    /// Process deferred outbound message stamp generation.
    ///
    /// Python reference: `LXMRouter.process_deferred_stamps` — LXMRouter.py:2407-2498.
    pub fn process_deferred_stamps(&mut self) {
        self.poll_active_deferred_stamp();
        if self.active_deferred_stamp.is_some() {
            return;
        }

        let Some((&message_hash, message)) = self.pending_deferred_stamps.iter().next() else {
            return;
        };
        let cost = message.stamp_cost.unwrap_or(0);
        if cost == 0 {
            if let Some(mut message) = self.pending_deferred_stamps.remove(&message_hash) {
                message.get_stamp();
                self.pending_outbound.push(message);
            }
            return;
        }

        if tokio::runtime::Handle::try_current().is_ok() {
            let (handle, rx) =
                stamper::spawn_deferred_stamp(message_hash, cost, STAMP_WORKBLOCK_EXPAND_ROUNDS);
            self.active_deferred_stamp = Some(DeferredStampJob {
                message_hash,
                handle,
                rx,
            });
        } else if let Some(mut message) = self.pending_deferred_stamps.remove(&message_hash) {
            match stamper::generate_stamp(&message_hash, cost, STAMP_WORKBLOCK_EXPAND_ROUNDS) {
                Some((stamp, value)) => {
                    message.stamp = Some(stamp.to_vec());
                    message.stamp_value = Some(value as u16);
                    self.pending_outbound.push(message);
                }
                None => {
                    message.mark_failed();
                }
            }
        }
    }

    fn poll_active_deferred_stamp(&mut self) {
        let Some(mut job) = self.active_deferred_stamp.take() else {
            return;
        };

        match job.rx.try_recv() {
            Ok(stamper::DeferredStampResult::Success { stamp, value }) => {
                if let Some(mut message) = self.pending_deferred_stamps.remove(&job.message_hash) {
                    message.stamp = Some(stamp.to_vec());
                    message.stamp_value = Some(value as u16);
                    self.pending_outbound.push(message);
                }
            }
            Ok(stamper::DeferredStampResult::Cancelled) => {
                if let Some(mut message) = self.pending_deferred_stamps.remove(&job.message_hash) {
                    message.cancel();
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                self.active_deferred_stamp = Some(job);
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                if let Some(mut message) = self.pending_deferred_stamps.remove(&job.message_hash) {
                    message.mark_failed();
                }
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
            .add(Ticket::new(token, destination_hash, expires));
        token
    }

    /// Record an externally-provided outbound ticket so the router can use it when sending.
    ///
    /// Python reference: `LXMRouter.remember_ticket` — LXMRouter.py:1110-1113.
    pub fn remember_ticket(&mut self, destination_hash: [u8; 16], token: [u8; 16], expires: f64) {
        self.ticket_store
            .add(Ticket::new(token, destination_hash, expires));
    }

    /// Returns the token of the most-recently-added valid ticket for `destination_hash`.
    ///
    /// Python reference: `LXMRouter.get_outbound_ticket` — LXMRouter.py:1115-1123.
    pub fn get_outbound_ticket(&self, destination_hash: &[u8; 16]) -> Option<[u8; 16]> {
        let now = now_f64();
        self.ticket_store
            .find(destination_hash, now)
            .map(|t| t.token)
    }

    /// Returns the expiry (Unix epoch seconds) of the valid ticket for `destination_hash`.
    ///
    /// Python reference: `LXMRouter.get_outbound_ticket_expiry` — LXMRouter.py:1125-1131.
    pub fn get_outbound_ticket_expiry(&self, destination_hash: &[u8; 16]) -> Option<f64> {
        let now = now_f64();
        self.ticket_store
            .find(destination_hash, now)
            .map(|t| t.expires)
    }

    /// Snapshot of all stored tickets (including expired / used entries).
    ///
    /// Python reference: `LXMRouter.get_inbound_tickets` — LXMRouter.py:1133-1136.
    pub fn get_inbound_tickets(&self) -> &[Ticket] {
        self.ticket_store.all()
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
            .position(|m| m.hash.as_ref() == Some(message_hash))
        {
            let msg = &mut self.pending_outbound[pos];
            msg.cancel();
            self.pending_outbound.remove(pos);
            return true;
        }

        if let Some(mut msg) = self.pending_deferred_stamps.remove(message_hash) {
            msg.cancel();
            if self
                .active_deferred_stamp
                .as_ref()
                .is_some_and(|job| job.message_hash == *message_hash)
                && let Some(job) = self.active_deferred_stamp.take()
            {
                job.handle.cancel();
            }
            return true;
        }

        false
    }

    /// Get the outbound-delivery progress (0.0..=1.0) for a pending message.
    ///
    /// Python reference: `LXMRouter.get_outbound_progress` — LXMRouter.py:489-495.
    pub fn get_outbound_progress(&self, message_hash: &[u8; 32]) -> Option<f64> {
        self.pending_outbound
            .iter()
            .chain(self.pending_deferred_stamps.values())
            .find(|m| m.hash.as_ref() == Some(message_hash))
            .map(|m| m.progress)
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
        self.pending_outbound
            .iter()
            .chain(self.pending_deferred_stamps.values())
            .find(|m| m.hash.as_ref() == Some(message_hash))
            .and_then(|m| m.stamp_cost)
    }

    /// Ingest an encrypted paper (`lxm://...`) URI and invoke the delivery callback as if the
    /// message had arrived via the network.
    ///
    /// Python reference: `LXMRouter.ingest_lxm_uri` — LXMRouter.py:2370-2385.
    pub fn ingest_lxm_uri<F>(
        &self,
        uri: &str,
        decrypt_fn: F,
    ) -> Result<LxMessage, crate::message::MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, crate::message::MessageError>,
    {
        let message = LxMessage::from_paper_uri(uri, decrypt_fn)?;
        if let Some(ref cb) = self.delivery_callback {
            cb(&message);
        }
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
    /// `state_dir`. Missing files are treated as empty state.
    pub fn load_state(&mut self, state_dir: &std::path::Path) -> std::io::Result<()> {
        use crate::persist;
        self.outbound_stamp_costs = persist::load_stamp_costs(state_dir)?;
        self.ticket_store
            .replace_all(persist::load_tickets(state_dir)?);
        let delivered = persist::load_local_deliveries(state_dir)?;
        let processed = persist::load_locally_processed(state_dir)?;
        self.propagation_store
            .replace_locally_delivered(delivered.keys().copied().collect());
        self.propagation_store
            .replace_locally_processed(processed.keys().copied().collect());
        Ok(())
    }

    /// Persist runtime state to `state_dir` using MessagePack. Safe to call
    /// periodically; each file is written atomically via rename.
    pub fn save_state(&self, state_dir: &std::path::Path) -> std::io::Result<()> {
        use crate::persist;
        use std::time::{SystemTime, UNIX_EPOCH};

        persist::save_stamp_costs(state_dir, &self.outbound_stamp_costs)?;
        persist::save_tickets(state_dir, self.ticket_store.all())?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let delivered: std::collections::HashMap<PropagationTransientId, f64> = self
            .propagation_store
            .locally_delivered_ids()
            .iter()
            .map(|id| (*id, now))
            .collect();
        let processed: std::collections::HashMap<PropagationTransientId, f64> = self
            .propagation_store
            .locally_processed_ids()
            .iter()
            .map(|id| (*id, now))
            .collect();
        persist::save_local_deliveries(state_dir, &delivered)?;
        persist::save_locally_processed(state_dir, &processed)?;
        Ok(())
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
            hops,
        } = candidate;

        if !self.config.autopeer {
            return false;
        }
        if self.peers.contains_key(&destination_hash) {
            return false;
        }
        if let Some(h) = hops
            && h as usize > self.config.ext.autopeer_maxdepth
        {
            return false;
        }

        let peer = LxmPeer::from_announce(
            destination_hash,
            timebase,
            transfer_limit,
            sync_limit,
            stamp_cost,
            stamp_flexibility,
            peering_cost,
        );
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
            if message.destination_hash == destination_hash {
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

    pub fn set_enforce_ratchets(&mut self, enforce: bool) {
        self.config.ext.enforce_ratchets = enforce;
    }

    pub fn set_enforce_stamps(&mut self, enforce: bool) {
        self.config.ext.enforce_stamps = enforce;
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
        if let Some(ticket) = self.ticket_store.find(destination_hash, now) {
            let mut material = Vec::with_capacity(16 + 32);
            material.extend_from_slice(&ticket.token);
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
        if !self.config.ext.processing_outbound {
            return Vec::new();
        }

        let mut actions = Vec::new();
        let mut processed = 0usize;

        let mut i = 0;
        while i < self.pending_outbound.len() {
            if let Some(limit) = self.config.ext.processing_limit
                && processed >= limit
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

            let age = now - msg.timestamp;
            if age > MESSAGE_EXPIRY as f64 {
                let mut msg = self.pending_outbound.remove(i);
                msg.mark_failed();
                actions.push(OutboundAction::Expired(msg));
                processed += 1;
                continue;
            }

            // State transitions match Python LXMessage.py:476-499:
            //   Opportunistic -> Sent immediately (single packet, fire-and-forget).
            //   Direct / Propagated -> Sending (multi-step).
            match msg.method {
                DeliveryMethod::Direct => {
                    let mut msg = self.pending_outbound.remove(i);
                    msg.mark_sending();
                    let dest_hash = msg.destination_hash;
                    actions.push(OutboundAction::DeliverDirect {
                        message: msg,
                        dest_hash,
                    });
                    processed += 1;
                    // The next element has shifted into index i, so do not advance.
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
                    let dest_hash = msg.destination_hash;
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

                            if transport_tx
                                .try_send(rns_transport::messages::TransportMessage::Outbound(
                                    rns_transport::messages::OutboundRequest {
                                        raw: Bytes::from(raw),
                                        destination_hash: dest_hash,
                                    },
                                ))
                                .is_ok()
                                && message.state == MessageState::Sending
                            {
                                message.mark_sent();
                                message.progress = 1.0;
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                dest = %hex::encode(dest_hash),
                                error = %err,
                                "cannot execute opportunistic LXMF action"
                            );
                        }
                    }
                }
                OutboundAction::DeliverDirect { .. } => {
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
        let actions = self.process_outbound();
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
        let actions = self.process_outbound();
        if !actions.is_empty() {
            self.execute_actions_with_encryptor(actions, encrypt_fn);
        }

        self.run_periodic_jobs();
    }

    fn run_periodic_jobs(&mut self) {
        // Job cadences match the Python LXMRouter jobloop.
        if self.processing_count.is_multiple_of(JOB_TRANSIENT_INTERVAL) {
            self.propagation_store.clean_transient_caches();
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
    pub delivery_limit: usize,
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

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_creation() {
        let router = LxmRouter::new(RouterConfig::default());
        assert!(router.pending_outbound.is_empty());
        assert!(router.peers.is_empty());
        assert!(router.propagation_store.is_empty());
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
        assert!(config.ext.max_message_size.is_none());
        assert!(!config.ext.enforce_ratchets);
        assert!(!config.ext.enforce_stamps);
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

        let mut msg = LxMessage::new(dest, [0xBB; 16], "ticket", "stamp", DeliveryMethod::Direct);
        msg.sign(&key).unwrap();
        router.send(msg);

        assert!(router.pending_deferred_stamps.is_empty());
        assert_eq!(router.pending_outbound.len(), 1);
        let queued = &router.pending_outbound[0];
        assert_eq!(queued.stamp.as_ref().map(Vec::len), Some(TICKET_LENGTH));
        assert_eq!(queued.stamp_value, Some(COST_TICKET));
    }

    #[tokio::test]
    async fn test_deferred_stamp_queue_completes_before_outbound_processing() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];
        router.set_stamp_cost(dest, 1);

        let mut msg = LxMessage::new(dest, [0xBB; 16], "defer", "stamp", DeliveryMethod::Direct);
        msg.sign(&key).unwrap();
        let message_id = msg.message_id.unwrap();
        router.send(msg);

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
        assert_eq!(queued.stamp.as_ref().map(Vec::len), Some(32));
        assert!(queued.stamp_value.unwrap_or(0) >= 1);
    }

    #[tokio::test]
    async fn test_cancel_outbound_cancels_deferred_stamp_job() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];
        router.set_stamp_cost(dest, 8);

        let mut msg = LxMessage::new(dest, [0xBB; 16], "cancel", "stamp", DeliveryMethod::Direct);
        msg.sign(&key).unwrap();
        let message_id = msg.message_id.unwrap();
        router.send(msg);
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
        assert_eq!(router.get_outbound_ticket(&dest), Some(token));
        assert!(router.get_outbound_ticket_expiry(&dest).unwrap() > now_f64());
        assert_eq!(router.get_inbound_tickets().len(), 1);

        // remember_ticket adds another entry for the same dest.
        router.remember_ticket(dest, [0x55; 16], now_f64() + 1000.0);
        assert_eq!(router.get_inbound_tickets().len(), 2);
    }

    #[test]
    fn test_cancel_outbound() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = LxMessage::new([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);
        msg.state = MessageState::Outbound;
        let hash = [0x11u8; 32];
        msg.hash = Some(hash);
        router.pending_outbound.push(msg);

        assert!(router.cancel_outbound(&hash));
        assert!(router.pending_outbound.is_empty());
        assert!(!router.cancel_outbound(&hash));
    }

    #[test]
    fn test_get_outbound_progress() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = LxMessage::new([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);
        msg.progress = 0.42;
        let hash = [0x22u8; 32];
        msg.hash = Some(hash);
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

        let msg = LxMessage::new([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);
        (router.delivery_callback.as_ref().unwrap())(&msg);
        assert!(fired.load(Ordering::Relaxed));
    }

    #[test]
    fn test_ingest_lxm_uri() {
        use rns_crypto::ed25519::Ed25519PrivateKey;

        let mut router = LxmRouter::new(RouterConfig::default());
        let key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "paper",
            "hello",
            DeliveryMethod::Paper,
        );
        msg.sign(&key).unwrap();
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
        assert_eq!(decoded.title, "paper");
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
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Content",
            DeliveryMethod::Direct,
        );
        router.send(msg);
        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(router.pending_outbound[0].state, MessageState::Outbound);
    }

    #[test]
    fn test_try_send_propagated_without_node_fails_immediately() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = LxMessage::new(
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
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.delivery_attempts = MAX_DELIVERY_ATTEMPTS + 1;
        router.send(msg);

        let actions = router.process_outbound();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], OutboundAction::Failed(_)));
        assert!(router.pending_outbound.is_empty());
    }

    /// At exactly MAX the message is still attempted (dispatched), not failed.
    #[test]
    fn test_process_outbound_at_max_attempts_not_failed() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.delivery_attempts = MAX_DELIVERY_ATTEMPTS;
        router.send(msg);

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
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Direct",
            "Content",
            DeliveryMethod::Direct,
        );
        router.send(msg);

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

        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        router.send(msg);

        let actions = router.process_outbound();
        let has_propagated = actions
            .iter()
            .any(|a| matches!(a, OutboundAction::DeliverPropagated { .. }));
        assert!(has_propagated);
    }

    #[test]
    fn test_process_outbound_opportunistic_delivery() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Opportunistic",
            "Content",
            DeliveryMethod::Opportunistic,
        );
        router.send(msg);

        let actions = router.process_outbound();
        let has_opportunistic = actions
            .iter()
            .any(|a| matches!(a, OutboundAction::DeliverOpportunistic { .. }));
        assert!(has_opportunistic);
    }

    #[test]
    fn test_process_outbound_propagated_no_node() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        router.send(msg);

        assert!(
            router.pending_outbound.is_empty(),
            "propagated messages without an outbound node fail at queue time"
        );
    }

    #[test]
    fn test_delivery_announce_trigger_clears_direct_retry_backoff() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let dest = [0xAA; 16];
        let mut msg = LxMessage::new(
            dest,
            [0xBB; 16],
            "Direct",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.delivery_attempts = 1;
        msg.last_delivery_attempt = now_f64();
        msg.next_delivery_attempt = now_f64() + PATH_REQUEST_WAIT as f64;
        router.send(msg);

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
        let mut msg = LxMessage::new(
            dest,
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        msg.delivery_attempts = 1;
        msg.last_delivery_attempt = now_f64();
        msg.next_delivery_attempt = now_f64() + PATH_REQUEST_WAIT as f64;
        router.send(msg);

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
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        msg.delivery_attempts = 1;
        msg.last_delivery_attempt = now_f64();
        msg.next_delivery_attempt = now_f64() + PATH_REQUEST_WAIT as f64;
        router.send(msg);

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
        router.send(LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        ));

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
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Stale",
            "Content",
            DeliveryMethod::Direct,
        );
        // Anchor the timestamp comfortably past the expiry window.
        msg.timestamp = now_f64() - (MESSAGE_EXPIRY as f64) - 60.0;
        router.send(msg);

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
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backoff",
            "Content",
            DeliveryMethod::Direct,
        );
        // Simulate one failed attempt very recently.
        msg.delivery_attempts = 1;
        msg.last_delivery_attempt = now_f64() - 1.0; // 1 s ago, inside the 10 s window.
        router.send(msg);

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
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backoff",
            "Content",
            DeliveryMethod::Propagated,
        );
        msg.last_delivery_attempt = now_f64() - 1.0;
        router.set_outbound_propagation_node(Some([0xCC; 16]));
        router.send(msg);

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
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Direct",
            "Content",
            DeliveryMethod::Direct,
        );
        router.send(msg);

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
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Tick Test",
            "Content",
            DeliveryMethod::Opportunistic,
        );
        msg.sign(&signing_key).unwrap();
        router.send(msg);

        router.tick_with_encryptor(|_dest, plaintext| Ok(plaintext.to_vec()));

        let received = rx.try_recv();
        assert!(received.is_ok(), "expected outbound packet from tick()");
    }

    #[test]
    fn test_execute_actions_no_transport() {
        let mut router = LxmRouter::new(RouterConfig::default());
        // No transport set — execute_actions must be a no-op.
        let actions = vec![OutboundAction::DeliverDirect {
            message: LxMessage::new([0; 16], [0; 16], "t", "c", DeliveryMethod::Direct),
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

        let mut direct = LxMessage::new(dest_hash, src_hash, "Direct", "d", DeliveryMethod::Direct);
        direct.sign(&key).unwrap();

        let mut opportunistic = LxMessage::new(
            dest_hash,
            src_hash,
            "Opp",
            "o",
            DeliveryMethod::Opportunistic,
        );
        opportunistic.sign(&key).unwrap();
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
    fn test_execute_actions_without_encryptor_does_not_send_opportunistic_plaintext() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let dest_hash = [0xAA; 16];
        let src_hash = [0xBB; 16];

        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let mut router = LxmRouter::new(RouterConfig::default());
        router.set_transport(tx);

        let mut direct = LxMessage::new(dest_hash, src_hash, "Direct", "d", DeliveryMethod::Direct);
        direct.sign(&key).unwrap();

        let mut opportunistic = LxMessage::new(
            dest_hash,
            src_hash,
            "Opp",
            "o",
            DeliveryMethod::Opportunistic,
        );
        opportunistic.sign(&key).unwrap();

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
            hops: Some(10),
        }));
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

        router.send(LxMessage::new(
            [0x01; 16],
            [0; 16],
            "a",
            "b",
            DeliveryMethod::Direct,
        ));
        router.send(LxMessage::new(
            [0x02; 16],
            [0; 16],
            "c",
            "d",
            DeliveryMethod::Direct,
        ));

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
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Large",
            &large_content,
            DeliveryMethod::Opportunistic,
        );
        router.send(msg);

        assert_eq!(router.pending_outbound[0].method, DeliveryMethod::Direct);
    }

    #[test]
    fn test_direct_message_state_sending() {
        let mut router = LxmRouter::new(RouterConfig::default());
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Direct",
            "Content",
            DeliveryMethod::Direct,
        );
        router.send(msg);

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

        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated",
            "Content",
            DeliveryMethod::Propagated,
        );
        router.send(msg);

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
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Opportunistic",
            "Content",
            DeliveryMethod::Opportunistic,
        );
        router.send(msg);

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
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Direct Sent",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.sign(&signing_key).unwrap();
        router.send(msg);

        router.tick();

        assert!(
            rx.try_recv().is_err(),
            "Direct delivery requires LinkDeliveryManager, not router.execute_actions"
        );
    }
}
