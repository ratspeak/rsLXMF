//! Propagation sync background task.
//!
//! Outbound sync to a configured propagation node using the Link
//! REQUEST/RESPONSE pattern. Python reference: LXMPeer.py:381-386.
//!
//! Flow:
//! 1. Establish a link to the node.
//! 2. Send link.request("/offer", [peering_key, transient_ids]).
//! 3. Receive a Response packet (context 0x0A) with OfferResponse.
//! 4. Transfer requested messages as a Resource.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_link::link::{CloseReason, Link, LinkAction};
use rns_protocol::resource::{
    MAX_EFFICIENT_SIZE, MultiSegmentOutbound, OutboundTransfer, ResourceError, TransferAction,
};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{OutboundRequest, TransportMessage};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};

use crate::constants::OFFER_REQUEST_PATH;
use crate::peer::{LxmPeer, OutboundOfferPolicy};
use crate::propagation::hex_encode;
use crate::propagation_node::{
    InstallPreparedSyncOffer, PreparedSyncOffer, PropagationNode, PropagationNodeConfig,
    prepare_sync_offer_snapshot, read_planned_messages,
};
use crate::sync::OfferResponse;
use crate::types::PropagationTransientId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncTaskState {
    Idle,
    Establishing,
    Offering,
    AwaitingResponse,
    Transferring,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSyncTerminalState {
    Complete,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeerSyncTerminalResult {
    pub peer_hash: [u8; 16],
    pub state: PeerSyncTerminalState,
    /// Store generation used by successful offer preparation. Failures leave
    /// this unset so unchanged-store work remains retryable after backoff.
    pub offer_generation: Option<u64>,
    /// True only when no cumulative-limit or vanished-file work remains for
    /// this generation.
    pub generation_exhausted: bool,
    /// Peer accounting deltas matching Python `LXMPeer.offer_response()` and
    /// `resource_concluded()` semantics.
    pub offered: u64,
    pub outgoing: u64,
    pub tx_bytes: u64,
    pub link_establishment_rate: Option<f64>,
    pub sync_transfer_rate: Option<f64>,
}

#[derive(Debug)]
struct PreparedTransferBatch {
    requested_count: usize,
    transient_ids: Vec<PropagationTransientId>,
    payload: Vec<u8>,
}

fn prepare_outbound_resource_transfers(
    payload: Vec<u8>,
    auto_compress: bool,
    rtt: Duration,
    link_keys: rns_link::key_derivation::LinkKeys,
) -> Result<VecDeque<OutboundTransfer>, ResourceError> {
    if payload.len() <= MAX_EFFICIENT_SIZE {
        return Ok(VecDeque::from([OutboundTransfer::new_encrypted(
            payload,
            auto_compress,
            rtt,
            link_keys,
        )?]));
    }

    // Reticulum encrypts each logical Resource segment as one assembled blob
    // before chunking it into raw RESOURCE packets. MultiSegmentOutbound also
    // enforces the protocol's MAX_RESOURCE_SIZE / MAX_SEGMENTS bounds.
    let encrypt = |plaintext: &[u8]| {
        rns_link::encryption::link_encrypt(&link_keys, plaintext)
            .unwrap_or_else(|_| plaintext.to_vec())
    };
    let resources =
        MultiSegmentOutbound::with_encrypt(payload, auto_compress, Some(&encrypt))?.segments;
    Ok(resources
        .into_iter()
        .map(|resource| OutboundTransfer::from_prebuilt(resource, rtt))
        .collect())
}

pub struct PropagationSyncTask {
    transport_tx: mpsc::Sender<TransportMessage>,
    event_tx: mpsc::Sender<DestinationEvent>,
    event_rx: mpsc::Receiver<DestinationEvent>,
    node_dest_hash: Option<[u8; 16]>,
    pub propagation_node: Arc<Mutex<PropagationNode>>,
    link: Option<Link>,
    link_id: Option<[u8; 16]>,
    pub state: SyncTaskState,
    last_sync: Instant,
    sync_interval: Duration,
    sync_started: Option<Instant>,
    sync_timeout: Duration,
    active_transfer: Option<OutboundTransfer>,
    active_transfer_requested: bool,
    pending_transfer_segments: VecDeque<OutboundTransfer>,
    active_transfer_ids: Vec<PropagationTransientId>,
    transfer_preparation_rx: Option<oneshot::Receiver<PreparedTransferBatch>>,
    ready_transfer_batch: Option<PreparedTransferBatch>,
    peer: Option<LxmPeer>,
    offer_policy: Option<OutboundOfferPolicy>,
    offer_preparation_rx: Option<oneshot::Receiver<PreparedSyncOffer>>,
    ready_prepared_offer: Option<PreparedSyncOffer>,
    handled_updates: Vec<PropagationTransientId>,
    runtime_handle: Option<tokio::runtime::Handle>,
    identity_pub: Option<[u8; 64]>,
    identity_key: Option<Ed25519PrivateKey>,
    active_offer_generation: Option<u64>,
    generation_exhausted: bool,
    terminal_result: Option<PeerSyncTerminalResult>,
    pending_transport: VecDeque<TransportMessage>,
    preserve_pending_on_cleanup: bool,
    offered_count: u64,
    outgoing_count: u64,
    transfer_data_size: u64,
    transfer_wire_size: u64,
    transfer_started: Option<Instant>,
    link_establishment_rate: Option<f64>,
}

impl PropagationSyncTask {
    pub fn new(transport_tx: mpsc::Sender<TransportMessage>, dest_hash: [u8; 16]) -> Self {
        let (event_tx, event_rx) = mpsc::channel(256);
        Self {
            transport_tx,
            event_tx,
            event_rx,
            node_dest_hash: None,
            propagation_node: Arc::new(Mutex::new(PropagationNode::new(
                PropagationNodeConfig::default(),
                dest_hash,
            ))),
            link: None,
            link_id: None,
            state: SyncTaskState::Idle,
            last_sync: Instant::now(),
            sync_interval: Duration::from_secs(300),
            sync_started: None,
            sync_timeout: Duration::from_secs(120),
            active_transfer: None,
            active_transfer_requested: false,
            pending_transfer_segments: VecDeque::new(),
            active_transfer_ids: Vec::new(),
            transfer_preparation_rx: None,
            ready_transfer_batch: None,
            peer: None,
            offer_policy: None,
            offer_preparation_rx: None,
            ready_prepared_offer: None,
            handled_updates: Vec::new(),
            runtime_handle: tokio::runtime::Handle::try_current().ok(),
            identity_pub: None,
            identity_key: None,
            active_offer_generation: None,
            generation_exhausted: false,
            terminal_result: None,
            pending_transport: VecDeque::new(),
            preserve_pending_on_cleanup: false,
            offered_count: 0,
            outgoing_count: 0,
            transfer_data_size: 0,
            transfer_wire_size: 0,
            transfer_started: None,
            link_establishment_rate: None,
        }
    }

    /// Create a sync task with disk-backed propagation storage.
    pub fn with_storage(
        transport_tx: mpsc::Sender<TransportMessage>,
        dest_hash: [u8; 16],
        storage_path: std::path::PathBuf,
    ) -> std::io::Result<Self> {
        let (event_tx, event_rx) = mpsc::channel(256);
        Ok(Self {
            transport_tx,
            event_tx,
            event_rx,
            node_dest_hash: None,
            propagation_node: Arc::new(Mutex::new(PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                dest_hash,
                storage_path,
            )?)),
            link: None,
            link_id: None,
            state: SyncTaskState::Idle,
            last_sync: Instant::now(),
            sync_interval: Duration::from_secs(300),
            sync_started: None,
            sync_timeout: Duration::from_secs(120),
            active_transfer: None,
            active_transfer_requested: false,
            pending_transfer_segments: VecDeque::new(),
            active_transfer_ids: Vec::new(),
            transfer_preparation_rx: None,
            ready_transfer_batch: None,
            peer: None,
            offer_policy: None,
            offer_preparation_rx: None,
            ready_prepared_offer: None,
            handled_updates: Vec::new(),
            runtime_handle: tokio::runtime::Handle::try_current().ok(),
            identity_pub: None,
            identity_key: None,
            active_offer_generation: None,
            generation_exhausted: false,
            terminal_result: None,
            pending_transport: VecDeque::new(),
            preserve_pending_on_cleanup: false,
            offered_count: 0,
            outgoing_count: 0,
            transfer_data_size: 0,
            transfer_wire_size: 0,
            transfer_started: None,
            link_establishment_rate: None,
        })
    }

    /// Create a sync task backed by a propagation node shared with live
    /// submissions and client retrieval handlers.
    pub fn with_shared_node(
        transport_tx: mpsc::Sender<TransportMessage>,
        propagation_node: Arc<Mutex<PropagationNode>>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(256);
        Self {
            transport_tx,
            event_tx,
            event_rx,
            node_dest_hash: None,
            propagation_node,
            link: None,
            link_id: None,
            state: SyncTaskState::Idle,
            last_sync: Instant::now(),
            sync_interval: Duration::from_secs(300),
            sync_started: None,
            sync_timeout: Duration::from_secs(120),
            active_transfer: None,
            active_transfer_requested: false,
            pending_transfer_segments: VecDeque::new(),
            active_transfer_ids: Vec::new(),
            transfer_preparation_rx: None,
            ready_transfer_batch: None,
            peer: None,
            offer_policy: None,
            offer_preparation_rx: None,
            ready_prepared_offer: None,
            handled_updates: Vec::new(),
            runtime_handle: tokio::runtime::Handle::try_current().ok(),
            identity_pub: None,
            identity_key: None,
            active_offer_generation: None,
            generation_exhausted: false,
            terminal_result: None,
            pending_transport: VecDeque::new(),
            preserve_pending_on_cleanup: false,
            offered_count: 0,
            outgoing_count: 0,
            transfer_data_size: 0,
            transfer_wire_size: 0,
            transfer_started: None,
            link_establishment_rate: None,
        }
    }

    pub fn set_node(&mut self, dest_hash: [u8; 16]) {
        if self.state != SyncTaskState::Idle && self.node_dest_hash != Some(dest_hash) {
            return;
        }
        if self.node_dest_hash != Some(dest_hash) {
            self.offer_policy = None;
        }
        self.node_dest_hash = Some(dest_hash);
    }

    /// Force an immediate sync attempt with `dest_hash`.
    ///
    /// Python `LXMPeer.sync()` is called directly by lxmd control requests;
    /// this public shim preserves that behavior without waiting for the
    /// periodic sync interval.
    pub fn request_sync_now(&mut self, dest_hash: [u8; 16]) -> bool {
        if self.state != SyncTaskState::Idle || self.terminal_result.is_some() {
            return false;
        }
        self.node_dest_hash = Some(dest_hash);
        self.offer_policy = None;
        if !self.start_sync(dest_hash) {
            return false;
        }
        self.last_sync = Instant::now();
        true
    }

    /// Force an immediate sync using an authoritative peer-policy snapshot.
    pub fn request_sync_now_with_policy(&mut self, policy: OutboundOfferPolicy) -> bool {
        if self.state != SyncTaskState::Idle || self.terminal_result.is_some() {
            return false;
        }
        let dest_hash = policy.peer_hash;
        self.node_dest_hash = Some(dest_hash);
        self.offer_policy = Some(policy);
        if !self.start_sync(dest_hash) {
            return false;
        }
        self.last_sync = Instant::now();
        true
    }

    /// Configure the local identity used for Link identification. Production
    /// peer sync must set this before requesting a sync; compatibility callers
    /// without identity material retain the historical unidentified behavior.
    pub fn set_identity(&mut self, identity_pub: [u8; 64], identity_key: Ed25519PrivateKey) {
        self.identity_pub = Some(identity_pub);
        self.identity_key = Some(identity_key);
    }

    /// Drain peer-handled updates discovered during offer negotiation or
    /// proven Resource transfer. The daemon merges these into its authoritative
    /// `LxmPeer` and persists that peer.
    pub fn take_handled_updates(&mut self) -> Vec<PropagationTransientId> {
        std::mem::take(&mut self.handled_updates)
    }

    pub fn take_terminal_peer_result(&mut self) -> Option<PeerSyncTerminalResult> {
        self.terminal_result.take()
    }

    /// Cancel all active and pending work for one peer. Dropping the bounded
    /// worker receivers makes late preparation results inert, and clearing
    /// handled deltas prevents an explicit unpeer from recreating persistence.
    pub fn cancel_peer_sync(&mut self, peer_hash: &[u8; 16]) -> bool {
        let matches_active = self.node_dest_hash.as_ref() == Some(peer_hash);
        let matches_policy = self
            .offer_policy
            .as_ref()
            .is_some_and(|policy| &policy.peer_hash == peer_hash);
        if !matches_active && !matches_policy {
            return false;
        }

        if matches_active && self.state != SyncTaskState::Idle {
            self.cleanup_sync();
        }
        if let Ok(mut node) = self.propagation_node.lock() {
            node.remove_session(peer_hash);
        }
        self.node_dest_hash = None;
        self.offer_policy = None;
        self.offer_preparation_rx = None;
        self.ready_prepared_offer = None;
        self.transfer_preparation_rx = None;
        self.ready_transfer_batch = None;
        self.active_transfer = None;
        self.active_transfer_requested = false;
        self.pending_transfer_segments.clear();
        self.active_transfer_ids.clear();
        self.active_offer_generation = None;
        self.generation_exhausted = false;
        self.handled_updates.clear();
        self.terminal_result = None;
        self.reset_attempt_accounting();
        self.state = SyncTaskState::Idle;
        true
    }

    pub fn node_dest_hash(&self) -> Option<[u8; 16]> {
        self.node_dest_hash
    }

    fn blocking_runtime(&mut self) -> Option<tokio::runtime::Handle> {
        if self.runtime_handle.is_none() {
            self.runtime_handle = tokio::runtime::Handle::try_current().ok();
        }
        self.runtime_handle.clone()
    }

    /// Preserve protocol packet ordering while tolerating temporary pressure
    /// on the bounded Reticulum transport actor mailbox. A full mailbox is a
    /// retryable local condition, not packet loss.
    fn queue_transport(&mut self, message: TransportMessage) -> bool {
        if !self.pending_transport.is_empty() {
            self.pending_transport.push_back(message);
            return true;
        }

        match self.transport_tx.try_send(message) {
            Ok(()) => true,
            Err(TrySendError::Full(message)) => {
                self.pending_transport.push_back(message);
                true
            }
            Err(TrySendError::Closed(_)) => false,
        }
    }

    fn flush_pending_transport(&mut self) -> bool {
        while let Some(message) = self.pending_transport.pop_front() {
            match self.transport_tx.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(message)) => {
                    self.pending_transport.push_front(message);
                    break;
                }
                Err(TrySendError::Closed(_)) => {
                    self.pending_transport.clear();
                    return false;
                }
            }
        }
        true
    }

    fn reset_attempt_accounting(&mut self) {
        self.offered_count = 0;
        self.outgoing_count = 0;
        self.transfer_data_size = 0;
        self.transfer_wire_size = 0;
        self.transfer_started = None;
        self.link_establishment_rate = None;
    }

    pub fn accept_message(&mut self, msg: &crate::message::LxMessage) -> bool {
        self.propagation_node
            .lock()
            .map(|mut node| node.accept_message(msg))
            .unwrap_or(false)
    }

    /// Drain inbound events from transport.
    ///
    /// `known_identities` maps dest_hash_hex -> 64-byte public key, used for link proof validation.
    pub fn drain_events(&mut self, known_identities: &HashMap<String, [u8; 64]>) {
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }

        for event in events {
            match event {
                DestinationEvent::LinkClosed { link_id } => {
                    self.handle_link_closed(link_id, None);
                }
                DestinationEvent::InboundPacket { raw, .. } => {
                    let (header, data_offset) = match rns_wire::header::PacketHeader::unpack(&raw) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };
                    if self.link_id != Some(header.destination_hash) {
                        continue;
                    }
                    let data = if raw.len() > data_offset {
                        &raw[data_offset..]
                    } else {
                        &[]
                    };

                    match header.context {
                        rns_wire::context::PacketContext::Lrproof
                        | rns_wire::context::PacketContext::None
                            if header.flags.packet_type == rns_wire::flags::PacketType::Proof
                                || header.context == rns_wire::context::PacketContext::Lrproof =>
                        {
                            if self.state != SyncTaskState::Establishing {
                                continue;
                            }
                            let node_hex = self.node_dest_hash.map(|h| hex_encode(&h));
                            if let Some(node_hex) = node_hex {
                                if let Some(pub_key) = known_identities.get(&node_hex) {
                                    let ed25519_bytes: [u8; 32] =
                                        pub_key[32..64].try_into().unwrap();
                                    if let Ok(verify_key) =
                                        Ed25519PublicKey::from_bytes(&ed25519_bytes)
                                    {
                                        self.handle_link_proof(data, &verify_key, &ed25519_bytes);
                                    }
                                }
                            }
                        }
                        rns_wire::context::PacketContext::ResourceHmu => {
                            if let Some(ref link) = self.link {
                                if let Ok(plaintext) = link.decrypt(data) {
                                    if let Some(ref mut transfer) = self.active_transfer {
                                        transfer.handle_hmu(&plaintext);
                                    }
                                }
                            }
                        }
                        rns_wire::context::PacketContext::ResourceReq => {
                            self.handle_resource_request(data);
                        }
                        rns_wire::context::PacketContext::ResourcePrf => {
                            // Python Packet.pack() sends PROOF+RESOURCE_PRF as
                            // plaintext (Packet.py:195-197) on PacketType::Proof.
                            // Body = resource_hash(32) || proof(32).
                            let completed = self
                                .active_transfer
                                .as_mut()
                                .is_some_and(|transfer| transfer.handle_proof(data));
                            if completed {
                                self.complete_active_transfer_segment();
                            }
                        }
                        rns_wire::context::PacketContext::Response => {
                            if self.state == SyncTaskState::AwaitingResponse {
                                if let Some(ref mut link) = self.link {
                                    if let Ok((_request_id, response_data)) =
                                        link.handle_response(data)
                                    {
                                        let offer_response =
                                            OfferResponse::from_msgpack(&response_data);
                                        self.handle_offer_response(offer_response);
                                    }
                                }
                            }
                        }
                        rns_wire::context::PacketContext::ResourceRcl
                        | rns_wire::context::PacketContext::ResourceIcl => {
                            self.handle_resource_cancel(data);
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

    fn handle_resource_request(&mut self, encrypted_data: &[u8]) {
        let Some(plaintext) = self
            .link
            .as_ref()
            .and_then(|link| link.decrypt(encrypted_data).ok())
        else {
            return;
        };
        let resource_hash_start =
            if plaintext.first().copied() == Some(rns_protocol::resource::HASHMAP_IS_EXHAUSTED) {
                1 + rns_protocol::resource::MAPHASH_LEN
            } else {
                1
            };
        let Some(requested_resource_hash) =
            plaintext.get(resource_hash_start..resource_hash_start + 32)
        else {
            return;
        };
        let Some(transfer) = self.active_transfer.as_mut() else {
            return;
        };
        if requested_resource_hash != transfer.resource.resource_hash {
            return;
        }
        let actions = transfer.handle_request(&plaintext);
        self.active_transfer_requested = true;

        for action in actions {
            match action {
                TransferAction::SendPart(_, part_data) => {
                    if !self.send_resource_packet(
                        &part_data,
                        rns_wire::context::PacketContext::Resource,
                    ) {
                        self.fail_active_transfer();
                        break;
                    }
                }
                TransferAction::SendHmu(hmu_data) => {
                    if !self.send_resource_packet(
                        &hmu_data,
                        rns_wire::context::PacketContext::ResourceHmu,
                    ) {
                        self.fail_active_transfer();
                        break;
                    }
                }
                TransferAction::SendCancel(cancel_type, resource_hash) => {
                    let context = match cancel_type {
                        rns_protocol::resource::CancelType::Icl => {
                            rns_wire::context::PacketContext::ResourceIcl
                        }
                        rns_protocol::resource::CancelType::Rcl => {
                            rns_wire::context::PacketContext::ResourceRcl
                        }
                    };
                    let _ = self.send_resource_packet(&resource_hash, context);
                    self.fail_active_transfer();
                    break;
                }
                TransferAction::Failed(_) => {
                    self.fail_active_transfer();
                    break;
                }
                TransferAction::Complete => {
                    self.complete_active_transfer_segment();
                    break;
                }
                // OutboundTransfer::handle_request currently emits only
                // parts, hashmap updates, or initiator-cancel. Ignore actions
                // belonging to other Resource lifecycle roles.
                TransferAction::None
                | TransferAction::SendAdvertisement(_)
                | TransferAction::SendProof(_)
                | TransferAction::SendRequest(_) => {}
            }
        }
    }

    fn handle_resource_cancel(&mut self, encrypted_data: &[u8]) {
        let Some(plaintext) = self
            .link
            .as_ref()
            .and_then(|link| link.decrypt(encrypted_data).ok())
        else {
            return;
        };
        let Ok(resource_hash) = <[u8; 32]>::try_from(plaintext.as_slice()) else {
            return;
        };
        let matches_active = self
            .active_transfer
            .as_ref()
            .is_some_and(|transfer| transfer.resource.resource_hash == resource_hash);
        if matches_active {
            self.fail_active_transfer();
        }
    }

    fn fail_active_transfer(&mut self) {
        self.active_transfer = None;
        self.active_transfer_requested = false;
        self.pending_transfer_segments.clear();
        self.active_transfer_ids.clear();
        self.state = SyncTaskState::Failed;
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
            self.active_transfer = None;
            self.active_transfer_requested = false;
            self.pending_transfer_segments.clear();
            self.active_transfer_ids.clear();
            self.transfer_preparation_rx = None;
            self.ready_transfer_batch = None;
            self.state = SyncTaskState::Failed;
        }

        verified
    }

    fn handle_link_proof(
        &mut self,
        proof_data: &[u8],
        verify_key: &Ed25519PublicKey,
        ed25519_pub: &[u8; 32],
    ) {
        let proof_result = match self.link.as_mut() {
            Some(link) => link.validate_proof(proof_data, verify_key, ed25519_pub),
            None => return,
        };

        match proof_result {
            Ok(rtt_data) => {
                // RTT packet = message 3 of the link handshake.
                if let Some(link_id) = self.link_id {
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

                    if !self.queue_transport(TransportMessage::Outbound(OutboundRequest {
                        raw: Bytes::from(rtt_raw),
                        destination_hash: link_id,
                    })) {
                        self.state = SyncTaskState::Failed;
                        return;
                    }

                    // Python LXMPeer.py:530-538
                    let establishment_rate =
                        self.link.as_ref().and_then(|link| link.establishment_rate);
                    self.link_establishment_rate = establishment_rate;
                    if let Some(ref mut peer) = self.peer {
                        peer.link_established(link_id, establishment_rate);
                    }
                }
                if !self.send_identify() {
                    self.state = SyncTaskState::Failed;
                    return;
                }
                self.state = SyncTaskState::Offering;
                self.sync_started = Some(Instant::now());
            }
            Err(_) => {
                self.state = SyncTaskState::Failed;
            }
        }
    }

    /// Python reference: LXMPeer.py:396-439 (offer_response).
    fn handle_offer_response(&mut self, response: OfferResponse) {
        let node_hash = match self.node_dest_hash {
            Some(h) => h,
            None => return,
        };

        let offered_ids = self
            .propagation_node
            .lock()
            .ok()
            .and_then(|node| {
                node.get_session(&node_hash)
                    .map(|session| session.offered_ids.clone())
            })
            .unwrap_or_default();

        match response {
            OfferResponse::WantAll => self.prepare_transfer_for_ids(&offered_ids),
            OfferResponse::HaveAll => {
                self.record_handled_updates(&offered_ids);
                if let Ok(mut node) = self.propagation_node.lock() {
                    node.complete_sync(&node_hash);
                }
                self.state = SyncTaskState::Complete;
            }
            OfferResponse::WantSome(wanted_id_bytes) => {
                let offered = offered_ids.iter().copied().collect::<HashSet<_>>();
                let mut seen = HashSet::new();
                let wanted_ids: Vec<PropagationTransientId> = wanted_id_bytes
                    .iter()
                    .filter_map(|id| {
                        if id.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(id);
                            (offered.contains(&arr) && seen.insert(arr)).then_some(arr)
                        } else {
                            None
                        }
                    })
                    .collect();
                let already_handled = offered_ids
                    .iter()
                    .copied()
                    .filter(|id| !seen.contains(id))
                    .collect::<Vec<_>>();
                self.record_handled_updates(&already_handled);
                self.prepare_transfer_for_ids(&wanted_ids);
            }
            _ => {
                self.state = SyncTaskState::Failed;
            }
        }
    }

    fn prepare_transfer_for_ids(&mut self, ids: &[PropagationTransientId]) {
        if ids.is_empty() {
            if let Some(node_hash) = self.node_dest_hash {
                if let Ok(mut node) = self.propagation_node.lock() {
                    node.complete_sync(&node_hash);
                }
            }
            self.state = SyncTaskState::Complete;
            return;
        }

        // Resolve paths under the node lock; read the files after dropping it.
        let plan = match self.propagation_node.lock() {
            Ok(node) => node.plan_message_reads(ids),
            Err(_) => {
                self.state = SyncTaskState::Failed;
                return;
            }
        };
        let requested_count = ids.len();
        let prepare = move || {
            let messages = read_planned_messages(&plan);
            let transient_ids = messages.iter().map(|(id, _)| *id).collect::<Vec<_>>();
            let payload = {
                use rmpv::Value;
                let blobs = messages
                    .into_iter()
                    .map(|(_, data)| Value::Binary(data))
                    .collect::<Vec<_>>();
                crate::encode_value(&Value::Array(vec![
                    Value::from(crate::now_f64()),
                    Value::Array(blobs),
                ]))
            };
            PreparedTransferBatch {
                requested_count,
                transient_ids,
                payload,
            }
        };

        if let Some(runtime) = self.blocking_runtime() {
            let (tx, rx) = oneshot::channel();
            runtime.spawn_blocking(move || {
                let _ = tx.send(prepare());
            });
            self.transfer_preparation_rx = Some(rx);
        } else {
            self.ready_transfer_batch = Some(prepare());
        }
        self.state = SyncTaskState::Transferring;
    }

    pub fn tick(&mut self) {
        if !self.flush_pending_transport() && self.state != SyncTaskState::Idle {
            self.state = SyncTaskState::Failed;
        }

        // Link establishment and offer requests retain a bounded phase
        // timeout. Resource transfers deliberately do not have an absolute
        // wall-clock deadline: Python RNS advances them by activity/retry
        // watchdogs and permits a large, healthy sync to run to completion.
        if matches!(
            self.state,
            SyncTaskState::Establishing | SyncTaskState::AwaitingResponse
        ) && self
            .sync_started
            .is_some_and(|started| started.elapsed() > self.sync_timeout)
        {
            self.state = SyncTaskState::Failed;
        }

        if !self.pending_transport.is_empty()
            && !matches!(self.state, SyncTaskState::Complete | SyncTaskState::Failed)
        {
            return;
        }

        if !matches!(
            self.state,
            SyncTaskState::Idle | SyncTaskState::Complete | SyncTaskState::Failed
        ) {
            self.drive_link_watchdog();
        }

        match self.state {
            SyncTaskState::Idle => {
                if self.terminal_result.is_none()
                    && self.offer_policy.is_none()
                    && self.last_sync.elapsed() >= self.sync_interval
                {
                    if let Some(node_hash) = self.node_dest_hash {
                        if self.message_count() > 0 {
                            let _ = self.start_sync(node_hash);
                        } else {
                            self.last_sync = Instant::now();
                        }
                    }
                }
            }
            SyncTaskState::Establishing | SyncTaskState::AwaitingResponse => {}
            SyncTaskState::Offering => {
                self.send_offer_request();
            }
            SyncTaskState::Transferring => {
                self.drive_transfers();
            }
            SyncTaskState::Complete | SyncTaskState::Failed => {
                if self.terminal_result.is_none() {
                    if let Some(peer_hash) = self.node_dest_hash {
                        let complete = self.state == SyncTaskState::Complete;
                        self.terminal_result = Some(PeerSyncTerminalResult {
                            peer_hash,
                            state: if complete {
                                PeerSyncTerminalState::Complete
                            } else {
                                PeerSyncTerminalState::Failed
                            },
                            offer_generation: complete
                                .then_some(self.active_offer_generation)
                                .flatten(),
                            generation_exhausted: complete && self.generation_exhausted,
                            offered: if complete { self.offered_count } else { 0 },
                            outgoing: if complete { self.outgoing_count } else { 0 },
                            tx_bytes: if complete { self.transfer_data_size } else { 0 },
                            link_establishment_rate: self.link_establishment_rate,
                            sync_transfer_rate: (complete && self.outgoing_count > 0)
                                .then(|| {
                                    self.transfer_started.map(|started| {
                                        let elapsed = started.elapsed().as_secs_f64();
                                        if elapsed > 0.0 {
                                            self.transfer_wire_size as f64 * 8.0 / elapsed
                                        } else {
                                            0.0
                                        }
                                    })
                                })
                                .flatten(),
                        });
                    }
                }
                self.cleanup_sync();
                self.last_sync = Instant::now();
                self.state = SyncTaskState::Idle;
            }
        }
    }

    fn drive_link_watchdog(&mut self) {
        let (Some(link_id), Some(link)) = (self.link_id, self.link.as_mut()) else {
            self.state = SyncTaskState::Failed;
            return;
        };
        let action = link.tick();
        match action {
            LinkAction::SendKeepalive | LinkAction::TransitionedToStale => {
                if !self.queue_plain_link_packet(
                    link_id,
                    &[rns_link::constants::KEEPALIVE_REQUEST],
                    rns_wire::context::PacketContext::Keepalive,
                ) {
                    self.state = SyncTaskState::Failed;
                }
            }
            LinkAction::SendTeardownAndClose(teardown_data) => {
                if !teardown_data.is_empty() {
                    self.preserve_pending_on_cleanup = self.queue_plain_link_packet(
                        link_id,
                        &teardown_data,
                        rns_wire::context::PacketContext::LinkClose,
                    );
                }
                self.state = SyncTaskState::Failed;
            }
            LinkAction::Closed(_) => self.state = SyncTaskState::Failed,
            LinkAction::None => {}
        }
    }

    /// Python reference: LXMPeer.py:381-386.
    fn send_offer_request(&mut self) {
        let node_hash = match self.node_dest_hash {
            Some(h) => h,
            None => {
                self.state = SyncTaskState::Failed;
                return;
            }
        };

        // Compatibility callers without an authoritative policy keep the
        // synchronous wrapper. Production always uses the staged snapshot ->
        // bounded blocking worker -> generation revalidation path below.
        let offer = if self.offer_policy.is_none() {
            match self.propagation_node.lock() {
                Ok(mut node) => {
                    let generation = node.offer_generation();
                    let offer = node.prepare_sync_offer(node_hash);
                    self.active_offer_generation = Some(generation);
                    self.generation_exhausted = true;
                    if offer.transient_ids.is_empty() {
                        node.complete_sync(&node_hash);
                    }
                    offer
                }
                Err(_) => {
                    self.state = SyncTaskState::Failed;
                    return;
                }
            }
        } else {
            if self.offer_preparation_rx.is_none() && self.ready_prepared_offer.is_none() {
                let policy = self.offer_policy.as_ref().expect("policy checked above");
                if policy.peer_hash != node_hash {
                    self.state = SyncTaskState::Failed;
                    return;
                }
                let snapshot = match self.propagation_node.lock() {
                    Ok(node) => node.snapshot_sync_offer_preparation(policy),
                    Err(_) => {
                        self.state = SyncTaskState::Failed;
                        return;
                    }
                };
                if let Some(runtime) = self.blocking_runtime() {
                    let (tx, rx) = oneshot::channel();
                    runtime.spawn_blocking(move || {
                        let _ = tx.send(prepare_sync_offer_snapshot(snapshot));
                    });
                    self.offer_preparation_rx = Some(rx);
                    return;
                }
                self.ready_prepared_offer = Some(prepare_sync_offer_snapshot(snapshot));
            }

            let prepared = if let Some(prepared) = self.ready_prepared_offer.take() {
                prepared
            } else {
                let Some(receiver) = self.offer_preparation_rx.as_mut() else {
                    self.state = SyncTaskState::Failed;
                    return;
                };
                match receiver.try_recv() {
                    Ok(prepared) => {
                        self.offer_preparation_rx = None;
                        prepared
                    }
                    Err(oneshot::error::TryRecvError::Empty) => return,
                    Err(oneshot::error::TryRecvError::Closed) => {
                        self.offer_preparation_rx = None;
                        self.state = SyncTaskState::Failed;
                        return;
                    }
                }
            };

            let installed = match self.propagation_node.lock() {
                Ok(mut node) => node.install_prepared_sync_offer(prepared),
                Err(_) => {
                    self.state = SyncTaskState::Failed;
                    return;
                }
            };
            match installed {
                InstallPreparedSyncOffer::Stale => return,
                InstallPreparedSyncOffer::Installed {
                    offer,
                    generation,
                    terminal_handled_ids,
                    generation_exhausted,
                } => {
                    self.active_offer_generation = Some(generation);
                    self.generation_exhausted = generation_exhausted;
                    self.record_handled_updates(&terminal_handled_ids);
                    if offer.transient_ids.is_empty() {
                        if let Ok(mut node) = self.propagation_node.lock() {
                            node.complete_sync(&node_hash);
                        }
                    }
                    offer
                }
            }
        };
        if offer.transient_ids.is_empty() {
            self.state = SyncTaskState::Complete;
            return;
        }
        self.offered_count = offer.transient_ids.len() as u64;
        let offer_data = {
            use rmpv::Value;
            let ids: Vec<Value> = offer
                .transient_ids
                .iter()
                .map(|id| Value::Binary(id.clone()))
                .collect();
            let array = Value::Array(vec![
                Value::Binary(offer.peering_key.clone()),
                Value::Array(ids),
            ]);
            crate::encode_value(&array)
        };

        if let Some(ref mut link) = self.link {
            match link.request(
                OFFER_REQUEST_PATH,
                Some(&offer_data),
                Duration::from_secs(60),
            ) {
                Ok((encrypted, _request_id)) => {
                    if let Some(link_id) = self.link_id {
                        let req_header = rns_wire::header::PacketHeader {
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
                            context: rns_wire::context::PacketContext::Request,
                        };
                        let mut req_raw = req_header.pack();
                        req_raw.extend_from_slice(&encrypted);
                        let packet_request_id = rns_wire::hash::truncated_packet_hash(
                            &req_raw,
                            rns_wire::flags::HeaderType::Header1,
                        );
                        link.update_pending_request_id(&_request_id, packet_request_id);
                        if !self.queue_transport(TransportMessage::Outbound(OutboundRequest {
                            raw: Bytes::from(req_raw),
                            destination_hash: link_id,
                        })) {
                            self.state = SyncTaskState::Failed;
                            return;
                        }
                    }
                    self.state = SyncTaskState::AwaitingResponse;
                    self.sync_started = Some(Instant::now());
                }
                Err(_) => {
                    self.state = SyncTaskState::Failed;
                }
            }
        } else {
            self.state = SyncTaskState::Failed;
        }
    }

    fn start_sync(&mut self, node_hash: [u8; 16]) -> bool {
        self.pending_transport.clear();
        self.preserve_pending_on_cleanup = false;
        self.reset_attempt_accounting();
        self.offer_preparation_rx = None;
        self.ready_prepared_offer = None;
        self.transfer_preparation_rx = None;
        self.ready_transfer_batch = None;
        self.active_transfer = None;
        self.active_transfer_requested = false;
        self.pending_transfer_segments.clear();
        self.active_transfer_ids.clear();
        self.active_offer_generation = None;
        self.generation_exhausted = false;
        let (link, request_data) = Link::new_initiator(node_hash, 1);
        let link_id = link.link_id;

        self.link = Some(link);
        self.link_id = Some(link_id);

        if !self.queue_transport(TransportMessage::RegisterDestination {
            hash: link_id,
            app_name: "lxmf.propagation.sync".to_string(),
            delivery_tx: Some(self.event_tx.clone()),
        }) {
            tracing::warn!("propagation sync transport is closed");
            self.state = SyncTaskState::Failed;
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

        if !self.queue_transport(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: node_hash,
        })) {
            tracing::warn!("propagation sync transport closed before Link request");
            self.state = SyncTaskState::Failed;
            return false;
        }

        let mut peer = LxmPeer::new(node_hash);
        peer.begin_sync();

        self.peer = Some(peer);
        self.state = SyncTaskState::Establishing;
        self.sync_started = Some(Instant::now());
        true
    }

    fn drive_transfers(&mut self) {
        if self.active_transfer.is_none() {
            let batch = if let Some(batch) = self.ready_transfer_batch.take() {
                Some(batch)
            } else if let Some(receiver) = self.transfer_preparation_rx.as_mut() {
                match receiver.try_recv() {
                    Ok(batch) => {
                        self.transfer_preparation_rx = None;
                        Some(batch)
                    }
                    Err(oneshot::error::TryRecvError::Empty) => return,
                    Err(oneshot::error::TryRecvError::Closed) => {
                        self.transfer_preparation_rx = None;
                        self.state = SyncTaskState::Failed;
                        return;
                    }
                }
            } else {
                None
            };

            if let Some(batch) = batch {
                if batch.transient_ids.len() != batch.requested_count {
                    // Requested files that vanished between offer and read are
                    // not treated as remotely handled; retry this generation.
                    self.generation_exhausted = false;
                }
                if batch.transient_ids.is_empty() {
                    // The offer named data that the disk read could not
                    // produce. Treat this as a failed attempt so the daemon's
                    // peer backoff applies; reporting a successful but
                    // unexhausted generation would reconnect every tick.
                    self.state = SyncTaskState::Failed;
                    return;
                }
                let Some(link) = self.link.as_ref() else {
                    self.state = SyncTaskState::Failed;
                    return;
                };
                let rtt = link.rtt.unwrap_or(Duration::from_millis(500));
                let Some(link_keys) = link.session_keys() else {
                    self.state = SyncTaskState::Failed;
                    return;
                };
                let data_size = batch.payload.len() as u64;
                let Ok(mut transfers) =
                    prepare_outbound_resource_transfers(batch.payload, true, rtt, link_keys)
                else {
                    self.state = SyncTaskState::Failed;
                    return;
                };
                let Some(first) = transfers.pop_front() else {
                    self.state = SyncTaskState::Failed;
                    return;
                };
                self.outgoing_count = batch.transient_ids.len() as u64;
                self.transfer_data_size = data_size;
                self.transfer_wire_size = first.resource.total_size as u64
                    + transfers
                        .iter()
                        .map(|transfer| transfer.resource.total_size as u64)
                        .sum::<u64>();
                self.transfer_started = Some(Instant::now());
                self.active_transfer = Some(first);
                self.active_transfer_requested = false;
                self.pending_transfer_segments = transfers;
                self.active_transfer_ids = batch.transient_ids;
            } else {
                // Transferring without either a live Resource or a pending
                // preparation is an internal failure, never a successful sync.
                self.state = SyncTaskState::Failed;
                return;
            }
        }

        // Keep a Resource window moving at protocol speed. The daemon's fast
        // driver calls this frequently, and one call may fill a whole window;
        // local transport backpressure stops the loop without dropping data.
        for _ in 0..16 {
            let Some(transfer) = self.active_transfer.as_mut() else {
                break;
            };
            let action = if transfer.advertised && !self.active_transfer_requested {
                transfer.check_timeout()
            } else {
                transfer.tick()
            };
            match action {
                TransferAction::SendAdvertisement(adv_data) => {
                    if !self.send_resource_packet(
                        &adv_data,
                        rns_wire::context::PacketContext::ResourceAdv,
                    ) {
                        self.fail_active_transfer();
                    }
                    // Wait for the receiver's first RESOURCE_REQ. While
                    // waiting, check_timeout() retries a lost advertisement.
                    break;
                }
                TransferAction::SendPart(_, part_data) => {
                    if !self.send_resource_packet(
                        &part_data,
                        rns_wire::context::PacketContext::Resource,
                    ) {
                        self.fail_active_transfer();
                        break;
                    }
                    if !self.pending_transport.is_empty() {
                        break;
                    }
                }
                TransferAction::Complete => {
                    self.complete_active_transfer_segment();
                    break;
                }
                TransferAction::Failed(_) => {
                    self.fail_active_transfer();
                    break;
                }
                TransferAction::None => break,
                _ => break,
            }
        }
    }

    fn complete_active_transfer_segment(&mut self) {
        self.active_transfer = None;
        self.active_transfer_requested = false;
        if let Some(next) = self.pending_transfer_segments.pop_front() {
            self.active_transfer = Some(next);
            return;
        }

        let completed_ids = std::mem::take(&mut self.active_transfer_ids);
        self.record_handled_updates(&completed_ids);
        if let Some(node_hash) = self.node_dest_hash {
            if let Ok(mut node) = self.propagation_node.lock() {
                node.complete_sync(&node_hash);
            }
        }
        self.state = SyncTaskState::Complete;
    }

    fn queue_plain_link_packet(
        &mut self,
        link_id: [u8; 16],
        data: &[u8],
        context: rns_wire::context::PacketContext,
    ) -> bool {
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
        raw.extend_from_slice(data);
        self.queue_transport(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: link_id,
        }))
    }

    fn send_resource_packet(
        &mut self,
        data: &[u8],
        context: rns_wire::context::PacketContext,
    ) -> bool {
        let link_id = match self.link_id {
            Some(id) => id,
            None => return false,
        };
        let link = match self.link.as_ref() {
            Some(l) => l,
            None => return false,
        };

        // Resource ADVs and control frames use ordinary Link encryption. The
        // assembled Resource itself was already encrypted before chunking, so
        // RESOURCE parts must ride raw or their advertised map hashes will no
        // longer match.
        let body = if context == rns_wire::context::PacketContext::Resource {
            data.to_vec()
        } else if let Ok(encrypted) = link.encrypt(data) {
            encrypted
        } else {
            return false;
        };
        self.queue_plain_link_packet(link_id, &body, context)
    }

    fn send_identify(&mut self) -> bool {
        let (Some(link), Some(link_id), Some(identity_pub), Some(identity_key)) = (
            self.link.as_mut(),
            self.link_id,
            self.identity_pub.as_ref(),
            self.identity_key.as_ref(),
        ) else {
            return true;
        };
        let Ok(identify_data) = link.identify(identity_pub, identity_key) else {
            return false;
        };
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
            context: rns_wire::context::PacketContext::LinkIdentify,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&identify_data);
        self.queue_transport(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: link_id,
        }))
    }

    /// Python LXMPeer.py:540-542.
    fn cleanup_sync(&mut self) {
        // No transfer packet should survive the attempt it belongs to. The
        // teardown and deregistration below form a new ordered tail. Preserve
        // a teardown already emitted by Link::tick() when it closed the link.
        if !self.preserve_pending_on_cleanup {
            self.pending_transport.clear();
        }
        self.preserve_pending_on_cleanup = false;
        self.send_teardown();
        if let Some(ref mut peer) = self.peer {
            peer.link_closed();
        }

        if let Some(link_id) = self.link_id.take() {
            let _ = self.queue_transport(TransportMessage::DeregisterDestination { hash: link_id });
        }
        self.link = None;
        self.peer = None;
        self.active_transfer = None;
        self.active_transfer_requested = false;
        self.pending_transfer_segments.clear();
        self.active_transfer_ids.clear();
        self.offer_preparation_rx = None;
        self.ready_prepared_offer = None;
        self.transfer_preparation_rx = None;
        self.ready_transfer_batch = None;
        self.sync_started = None;
    }

    fn send_teardown(&mut self) {
        let Some(link_id) = self.link_id else {
            return;
        };
        let teardown_data = self
            .link
            .as_mut()
            .and_then(|link| link.teardown(CloseReason::InitiatorClosed));
        if let Some(teardown_data) = teardown_data {
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
                context: rns_wire::context::PacketContext::LinkClose,
            };
            let mut raw = header.pack();
            raw.extend_from_slice(&teardown_data);
            let _ = self.queue_transport(TransportMessage::Outbound(OutboundRequest {
                raw: Bytes::from(raw),
                destination_hash: link_id,
            }));
        }
    }

    pub fn message_count(&self) -> usize {
        self.propagation_node
            .lock()
            .map(|node| node.message_count())
            .unwrap_or(0)
    }

    pub fn peer(&self) -> Option<&LxmPeer> {
        self.peer.as_ref()
    }

    fn record_handled_updates(&mut self, transient_ids: &[PropagationTransientId]) {
        if transient_ids.is_empty() {
            return;
        }
        for transient_id in transient_ids {
            if !self.handled_updates.contains(transient_id) {
                self.handled_updates.push(*transient_id);
            }
            if let Some(peer) = self.peer.as_mut() {
                peer.add_handled_message(transient_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn resource_is_encrypted_before_chunking_and_advertisement_maps_raw_parts() {
        let (initiator, responder) = active_link_pair([0x41; 16]);
        let initiator_keys = initiator.session_keys().unwrap();
        let responder_keys = responder.session_keys().unwrap();
        let payload = (0..8192)
            .map(|index| ((index * 31) % 251) as u8)
            .collect::<Vec<_>>();

        let mut transfers = prepare_outbound_resource_transfers(
            payload.clone(),
            false,
            Duration::from_millis(500),
            initiator_keys,
        )
        .unwrap();
        assert_eq!(transfers.len(), 1);
        let mut transfer = transfers.pop_front().unwrap();
        assert!(transfer.resource.flags.encrypted);

        let advertisement = match transfer.tick() {
            TransferAction::SendAdvertisement(data) => {
                rns_protocol::resource_adv::ResourceAdvertisement::unpack(&data).unwrap()
            }
            other => panic!("expected Resource advertisement, got {other:?}"),
        };
        assert!(advertisement.flags.encrypted);
        assert_eq!(advertisement.resource_hash, transfer.resource.resource_hash);
        assert_eq!(advertisement.random_hash, transfer.resource.random_hash);
        let advertised_hashes = advertisement.get_map_hashes();
        assert_eq!(
            advertised_hashes,
            transfer.resource.map_hashes[..advertised_hashes.len()]
        );

        for (part, expected_hash) in transfer
            .resource
            .parts
            .iter()
            .zip(&transfer.resource.map_hashes)
        {
            assert_eq!(
                rns_protocol::resource::get_map_hash(part, &transfer.resource.random_hash),
                *expected_hash
            );
        }

        let encrypted_stream = transfer.resource.parts.concat();
        assert_ne!(encrypted_stream, payload);
        let plaintext =
            rns_link::encryption::link_decrypt(&responder_keys, &encrypted_stream).unwrap();
        assert_eq!(
            &plaintext[..rns_protocol::resource::RANDOM_HASH_SIZE],
            &transfer.resource.random_hash
        );
        assert_eq!(
            &plaintext[rns_protocol::resource::RANDOM_HASH_SIZE..],
            payload
        );
    }

    #[test]
    fn resource_packets_are_raw_while_advertisements_use_link_encryption() {
        let (tx, mut rx) = mpsc::channel(4);
        let (initiator, responder) = active_link_pair([0x42; 16]);
        let link_id = initiator.link_id;
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.link_id = Some(link_id);
        task.link = Some(initiator);

        let resource_part = b"already-encrypted-resource-part";
        task.send_resource_packet(resource_part, rns_wire::context::PacketContext::Resource);
        let TransportMessage::Outbound(part_request) = rx.try_recv().unwrap() else {
            panic!("expected outbound Resource packet");
        };
        let (part_header, part_offset) =
            rns_wire::header::PacketHeader::unpack(&part_request.raw).unwrap();
        assert_eq!(
            part_header.context,
            rns_wire::context::PacketContext::Resource
        );
        assert_eq!(&part_request.raw[part_offset..], resource_part);

        let advertisement = b"resource-advertisement";
        task.send_resource_packet(advertisement, rns_wire::context::PacketContext::ResourceAdv);
        let TransportMessage::Outbound(adv_request) = rx.try_recv().unwrap() else {
            panic!("expected outbound Resource advertisement");
        };
        let (adv_header, adv_offset) =
            rns_wire::header::PacketHeader::unpack(&adv_request.raw).unwrap();
        assert_eq!(
            adv_header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );
        assert_ne!(&adv_request.raw[adv_offset..], advertisement);
        assert_eq!(
            responder.decrypt(&adv_request.raw[adv_offset..]).unwrap(),
            advertisement
        );
    }

    fn deliver_encrypted_resource_control(
        task: &PropagationSyncTask,
        responder: &Link,
        context: rns_wire::context::PacketContext,
        plaintext: &[u8],
    ) {
        let link_id = task.link_id.unwrap();
        let encrypted = responder.encrypt(plaintext).unwrap();
        task.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(link_id, context, &encrypted),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();
    }

    #[test]
    fn encrypted_resource_request_retransmits_map_compatible_part_raw() {
        let (tx, mut rx) = mpsc::channel(4);
        let (initiator, responder) = active_link_pair([0x44; 16]);
        let link_id = initiator.link_id;
        let mut transfers = prepare_outbound_resource_transfers(
            (0..4096).map(|index| (index % 251) as u8).collect(),
            false,
            Duration::from_millis(500),
            initiator.session_keys().unwrap(),
        )
        .unwrap();
        let transfer = transfers.pop_front().unwrap();
        let requested_index = 1;
        let expected_part = transfer.resource.parts[requested_index].clone();
        let requested_hash = transfer.resource.map_hashes[requested_index];
        let random_hash = transfer.resource.random_hash;
        let resource_hash = transfer.resource.resource_hash;

        let mut request = vec![rns_protocol::resource::HASHMAP_IS_NOT_EXHAUSTED];
        request.extend_from_slice(&resource_hash);
        request.extend_from_slice(&requested_hash);

        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.link_id = Some(link_id);
        task.link = Some(initiator);
        task.active_transfer = Some(transfer);
        task.state = SyncTaskState::Transferring;
        let mut stale_request = request.clone();
        stale_request[1..33].fill(0xFF);
        deliver_encrypted_resource_control(
            &task,
            &responder,
            rns_wire::context::PacketContext::ResourceReq,
            &stale_request,
        );
        task.drain_events(&HashMap::new());
        assert!(rx.try_recv().is_err());
        assert_eq!(task.active_transfer.as_ref().unwrap().sent_parts, 0);

        deliver_encrypted_resource_control(
            &task,
            &responder,
            rns_wire::context::PacketContext::ResourceReq,
            &request,
        );

        task.drain_events(&HashMap::new());

        let TransportMessage::Outbound(response) = rx.try_recv().unwrap() else {
            panic!("expected requested Resource part");
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&response.raw).unwrap();
        assert_eq!(header.context, rns_wire::context::PacketContext::Resource);
        assert_eq!(&response.raw[offset..], expected_part);
        assert_eq!(
            rns_protocol::resource::get_map_hash(&response.raw[offset..], &random_hash),
            requested_hash
        );
        assert_eq!(task.state, SyncTaskState::Transferring);
        assert_eq!(task.active_transfer.as_ref().unwrap().sent_parts, 1);
    }

    #[test]
    fn exhausted_resource_request_sends_link_encrypted_hmu() {
        let (tx, mut rx) = mpsc::channel(4);
        let (initiator, responder) = active_link_pair([0x45; 16]);
        let link_id = initiator.link_id;
        let hashmap_len =
            rns_protocol::resource_adv::hashmap_max_len(rns_wire::constants::LINK_MDU);
        let mut transfers = prepare_outbound_resource_transfers(
            vec![0xA7; (hashmap_len + 8) * rns_protocol::resource::SDU],
            false,
            Duration::from_millis(500),
            initiator.session_keys().unwrap(),
        )
        .unwrap();
        let transfer = transfers.pop_front().unwrap();
        assert!(transfer.resource.parts.len() > hashmap_len);
        let resource_hash = transfer.resource.resource_hash;

        let mut request = vec![rns_protocol::resource::HASHMAP_IS_EXHAUSTED];
        request.extend_from_slice(&transfer.resource.map_hashes[hashmap_len - 1]);
        request.extend_from_slice(&resource_hash);

        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.link_id = Some(link_id);
        task.link = Some(initiator);
        task.active_transfer = Some(transfer);
        task.state = SyncTaskState::Transferring;
        deliver_encrypted_resource_control(
            &task,
            &responder,
            rns_wire::context::PacketContext::ResourceReq,
            &request,
        );

        task.drain_events(&HashMap::new());

        let TransportMessage::Outbound(response) = rx.try_recv().unwrap() else {
            panic!("expected Resource hashmap update");
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&response.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceHmu
        );
        let plaintext = responder.decrypt(&response.raw[offset..]).unwrap();
        assert_eq!(&plaintext[..32], resource_hash);
        let update: rmpv::Value = rmpv::decode::read_value(&mut &plaintext[32..]).unwrap();
        assert_eq!(update.as_array().unwrap()[0].as_u64(), Some(1));
        assert_eq!(task.state, SyncTaskState::Transferring);
    }

    #[test]
    fn invalid_exhausted_request_sends_encrypted_cancel_and_fails_closed() {
        let (tx, mut rx) = mpsc::channel(4);
        let (initiator, responder) = active_link_pair([0x46; 16]);
        let link_id = initiator.link_id;
        let mut transfers = prepare_outbound_resource_transfers(
            vec![0xB8; 20_000],
            false,
            Duration::from_millis(500),
            initiator.session_keys().unwrap(),
        )
        .unwrap();
        let transfer = transfers.pop_front().unwrap();
        let resource_hash = transfer.resource.resource_hash;
        let mut request = vec![rns_protocol::resource::HASHMAP_IS_EXHAUSTED];
        request.extend_from_slice(&transfer.resource.map_hashes[0]);
        request.extend_from_slice(&resource_hash);

        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.link_id = Some(link_id);
        task.link = Some(initiator);
        task.active_transfer = Some(transfer);
        task.active_transfer_ids = vec![[0x66; 32]];
        task.state = SyncTaskState::Transferring;
        deliver_encrypted_resource_control(
            &task,
            &responder,
            rns_wire::context::PacketContext::ResourceReq,
            &request,
        );

        task.drain_events(&HashMap::new());

        let TransportMessage::Outbound(response) = rx.try_recv().unwrap() else {
            panic!("expected initiator Resource cancel");
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&response.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceIcl
        );
        assert_eq!(
            responder.decrypt(&response.raw[offset..]).unwrap(),
            resource_hash
        );
        assert_eq!(task.state, SyncTaskState::Failed);
        assert!(task.active_transfer.is_none());
        assert!(task.active_transfer_ids.is_empty());
    }

    #[test]
    fn inbound_resource_cancels_require_exact_active_segment_hash() {
        for context in [
            rns_wire::context::PacketContext::ResourceRcl,
            rns_wire::context::PacketContext::ResourceIcl,
        ] {
            let (tx, _rx) = mpsc::channel(4);
            let (initiator, responder) = active_link_pair([0x47; 16]);
            let link_id = initiator.link_id;
            let mut transfers = prepare_outbound_resource_transfers(
                b"cancelled Resource".to_vec(),
                false,
                Duration::from_millis(500),
                initiator.session_keys().unwrap(),
            )
            .unwrap();
            let transfer = transfers.pop_front().unwrap();
            let resource_hash = transfer.resource.resource_hash;
            let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
            task.link_id = Some(link_id);
            task.link = Some(initiator);
            task.active_transfer = Some(transfer);
            task.active_transfer_ids = vec![[0x77; 32]];
            task.state = SyncTaskState::Transferring;

            deliver_encrypted_resource_control(&task, &responder, context, &[0xEE; 31]);
            deliver_encrypted_resource_control(&task, &responder, context, &[0xEF; 32]);
            task.drain_events(&HashMap::new());
            assert_eq!(task.state, SyncTaskState::Transferring);
            assert!(task.active_transfer.is_some());

            deliver_encrypted_resource_control(&task, &responder, context, &resource_hash);
            task.drain_events(&HashMap::new());
            assert_eq!(task.state, SyncTaskState::Failed);
            assert!(task.active_transfer.is_none());
            assert!(task.active_transfer_ids.is_empty());
        }
    }

    #[test]
    fn aggregate_above_single_resource_limit_uses_ordered_encrypted_segments() {
        let (initiator, responder) = active_link_pair([0x43; 16]);
        let initiator_keys = initiator.session_keys().unwrap();
        let responder_keys = responder.session_keys().unwrap();
        let payload_len = MAX_EFFICIENT_SIZE + 4096;
        let payload = (0..payload_len)
            .map(|index| ((index * 17) % 251) as u8)
            .collect::<Vec<_>>();

        let mut transfers = prepare_outbound_resource_transfers(
            payload.clone(),
            false,
            Duration::from_millis(500),
            initiator_keys,
        )
        .unwrap();
        assert_eq!(transfers.len(), 2);

        let mut reassembled = Vec::with_capacity(payload.len());
        let mut shared_original_hash = None;
        for (index, transfer) in transfers.iter().enumerate() {
            let resource = &transfer.resource;
            assert!(resource.flags.encrypted);
            assert!(resource.flags.split);
            assert_eq!(resource.segment_index, index + 1);
            assert_eq!(resource.total_segments, 2);
            assert_eq!(resource.advertisement_data_size, payload.len());
            match shared_original_hash {
                Some(expected) => assert_eq!(resource.original_hash, Some(expected)),
                None => shared_original_hash = resource.original_hash,
            }

            let encrypted_stream = resource.parts.concat();
            let plaintext =
                rns_link::encryption::link_decrypt(&responder_keys, &encrypted_stream).unwrap();
            assert_eq!(
                &plaintext[..rns_protocol::resource::RANDOM_HASH_SIZE],
                &resource.random_hash
            );
            reassembled.extend_from_slice(&plaintext[rns_protocol::resource::RANDOM_HASH_SIZE..]);
        }
        assert_eq!(reassembled, payload);

        let (tx, _rx) = mpsc::channel(4);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.state = SyncTaskState::Transferring;
        task.node_dest_hash = Some([0x43; 16]);
        task.active_transfer = transfers.pop_front();
        task.pending_transfer_segments = transfers;
        task.active_transfer_ids = vec![[0x55; 32]];

        task.complete_active_transfer_segment();
        assert_eq!(task.state, SyncTaskState::Transferring);
        assert!(task.take_handled_updates().is_empty());
        assert!(task.pending_transfer_segments.is_empty());
        assert!(task.active_transfer.is_some());

        task.complete_active_transfer_segment();
        assert_eq!(task.state, SyncTaskState::Complete);
        assert_eq!(task.take_handled_updates(), vec![[0x55; 32]]);
        assert!(task.active_transfer.is_none());
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

    fn make_sync_due(task: &mut PropagationSyncTask) {
        task.sync_interval = Duration::ZERO;
        task.last_sync = Instant::now();
    }

    #[test]
    fn test_sync_task_creation() {
        let (tx, _rx) = mpsc::channel(16);
        let task = PropagationSyncTask::new(tx, [0xAA; 16]);
        assert_eq!(task.state, SyncTaskState::Idle);
        assert_eq!(task.message_count(), 0);
    }

    #[test]
    fn test_set_node() {
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        assert!(task.node_dest_hash.is_none());

        task.set_node([0xBB; 16]);
        assert_eq!(task.node_dest_hash, Some([0xBB; 16]));
    }

    #[test]
    fn test_accept_message() {
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "sync test content",
            crate::constants::DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();

        assert!(task.accept_message(&msg));
        assert_eq!(task.message_count(), 1);
    }

    #[test]
    fn test_shared_node_store_is_live() {
        let (tx, mut rx) = mpsc::channel(64);
        let shared_node = Arc::new(Mutex::new(PropagationNode::new(
            PropagationNodeConfig::default(),
            [0xAA; 16],
        )));
        let mut task = PropagationSyncTask::with_shared_node(tx, shared_node.clone());
        task.set_node([0xBB; 16]);
        make_sync_due(&mut task);

        assert_eq!(task.message_count(), 0);

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "shared node content",
            crate::constants::DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();
        assert!(shared_node.lock().unwrap().accept_message(&msg));

        assert_eq!(task.message_count(), 1);
        task.tick();
        assert_eq!(task.state, SyncTaskState::Establishing);
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::RegisterDestination { .. }
        ));
    }

    #[test]
    fn test_idle_no_node_configured() {
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.tick();
        assert_eq!(task.state, SyncTaskState::Idle);
    }

    #[test]
    fn test_idle_no_messages() {
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        make_sync_due(&mut task);
        task.tick();
        assert_eq!(task.state, SyncTaskState::Idle);
    }

    #[test]
    fn test_starts_sync_when_ready() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        make_sync_due(&mut task);

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "content",
            crate::constants::DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();
        task.accept_message(&msg);

        task.tick();
        assert_eq!(task.state, SyncTaskState::Establishing);
        assert!(task.link_id.is_some());

        let reg = rx.try_recv();
        assert!(matches!(
            reg.unwrap(),
            TransportMessage::RegisterDestination { .. }
        ));
        let outbound = rx.try_recv();
        assert!(matches!(outbound.unwrap(), TransportMessage::Outbound(_)));
    }

    #[test]
    fn test_sync_timeout() {
        let (tx, _rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        make_sync_due(&mut task);

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "content",
            crate::constants::DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();
        task.accept_message(&msg);

        task.tick();
        assert_eq!(task.state, SyncTaskState::Establishing);

        task.sync_timeout = Duration::ZERO;

        task.tick();
        assert_eq!(task.state, SyncTaskState::Idle);
        assert_eq!(
            task.take_terminal_peer_result().unwrap().state,
            PeerSyncTerminalState::Failed
        );
    }

    #[test]
    fn healthy_resource_transfer_has_no_absolute_whole_sync_timeout() {
        let (tx, mut rx) = mpsc::channel(64);
        let (initiator, _) = active_link_pair([0x31; 16]);
        let link_id = initiator.link_id;
        let link_keys = initiator.session_keys().unwrap();
        let transfer = OutboundTransfer::new_encrypted(
            vec![0xAB; 4096],
            false,
            Duration::from_millis(100),
            link_keys,
        )
        .unwrap();
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.link = Some(initiator);
        task.link_id = Some(link_id);
        task.active_transfer = Some(transfer);
        task.state = SyncTaskState::Transferring;
        task.sync_started = Some(Instant::now() - Duration::from_secs(600));
        task.sync_timeout = Duration::ZERO;

        task.tick();

        assert_eq!(task.state, SyncTaskState::Transferring);
        let TransportMessage::Outbound(advertisement) = rx.try_recv().unwrap() else {
            panic!("expected Resource advertisement");
        };
        let (header, _) = rns_wire::header::PacketHeader::unpack(&advertisement.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );
    }

    #[test]
    fn resource_advertisement_is_retried_while_waiting_for_first_request() {
        let (tx, mut rx) = mpsc::channel(64);
        let (initiator, _) = active_link_pair([0x32; 16]);
        let link_id = initiator.link_id;
        let link_keys = initiator.session_keys().unwrap();
        let transfer = OutboundTransfer::new_encrypted(
            vec![0xCD; 4096],
            false,
            Duration::from_millis(10),
            link_keys,
        )
        .unwrap();
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.link = Some(initiator);
        task.link_id = Some(link_id);
        task.active_transfer = Some(transfer);
        task.state = SyncTaskState::Transferring;

        task.tick();
        let _first_advertisement = rx.try_recv().unwrap();
        task.active_transfer.as_mut().unwrap().started_at =
            Instant::now() - Duration::from_secs(60);

        task.tick();

        let TransportMessage::Outbound(retry) = rx.try_recv().unwrap() else {
            panic!("expected retried Resource advertisement");
        };
        let (header, _) = rns_wire::header::PacketHeader::unpack(&retry.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );
        assert_eq!(task.active_transfer.as_ref().unwrap().retries, 1);
    }

    #[test]
    fn full_transport_mailbox_stages_link_setup_without_packet_loss() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(TransportMessage::DeregisterDestination { hash: [0x01; 16] })
            .unwrap();
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);

        assert!(task.request_sync_now([0xBB; 16]));
        assert_eq!(task.pending_transport.len(), 2);

        let _blocker = rx.try_recv().unwrap();
        task.tick();
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::RegisterDestination { .. }
        ));
        assert_eq!(task.pending_transport.len(), 1);

        task.tick();
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::Outbound(_)
        ));
        assert!(task.pending_transport.is_empty());
    }

    #[test]
    fn test_cleanup_deregisters() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        make_sync_due(&mut task);

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "content",
            crate::constants::DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();
        task.accept_message(&msg);

        task.tick();
        while rx.try_recv().is_ok() {}

        task.state = SyncTaskState::Complete;
        task.tick();

        let dereg = rx.try_recv();
        assert!(matches!(
            dereg.unwrap(),
            TransportMessage::DeregisterDestination { .. }
        ));
    }

    #[test]
    fn test_authenticated_remote_link_close_fails_and_cleans_up() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        let node_hash = [0xE3; 16];
        let (link, mut responder_link) = active_link_pair(node_hash);
        let link_id = link.link_id;
        task.set_node(node_hash);
        task.link = Some(link);
        task.link_id = Some(link_id);
        task.state = SyncTaskState::AwaitingResponse;
        task.sync_started = Some(Instant::now());
        let mut peer = LxmPeer::new(node_hash);
        peer.begin_sync();
        task.peer = Some(peer);

        let close_body = responder_link
            .teardown(CloseReason::InitiatorClosed)
            .expect("remote active link emits authenticated teardown");
        task.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::LinkClose,
                    &close_body,
                ),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();

        task.drain_events(&HashMap::new());
        assert_eq!(task.state, SyncTaskState::Failed);

        task.tick();
        assert_eq!(task.state, SyncTaskState::Idle);
        assert!(task.link.is_none());
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::DeregisterDestination { hash } if hash == link_id
        ));
    }

    #[test]
    fn test_unauthenticated_link_close_is_ignored() {
        let (tx, _rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        let node_hash = [0xE4; 16];
        let (link, _responder_link) = active_link_pair(node_hash);
        let link_id = link.link_id;
        task.set_node(node_hash);
        task.link = Some(link);
        task.link_id = Some(link_id);
        task.state = SyncTaskState::AwaitingResponse;

        task.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &[0u8]),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();

        task.drain_events(&HashMap::new());
        assert_eq!(task.state, SyncTaskState::AwaitingResponse);
        assert!(task.link.is_some());
    }

    #[test]
    fn test_handle_offer_response_have_all() {
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        task.state = SyncTaskState::AwaitingResponse;

        task.handle_offer_response(OfferResponse::HaveAll);
        assert_eq!(task.state, SyncTaskState::Complete);
    }

    #[test]
    fn empty_policy_selection_completes_without_sending_offer_request() {
        let (tx, mut rx) = mpsc::channel(16);
        let shared_node = Arc::new(Mutex::new(PropagationNode::new(
            PropagationNodeConfig::default(),
            [0xAA; 16],
        )));
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut message = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "already handled",
            crate::constants::DeliveryMethod::Propagated,
        );
        message.sign(&key).unwrap();
        let transient_id = message.transient_id.unwrap();
        assert!(shared_node.lock().unwrap().accept_message(&message));

        let node_hash = [0xDD; 16];
        let (link, _responder) = active_link_pair(node_hash);
        let mut task = PropagationSyncTask::with_shared_node(tx, shared_node);
        task.set_node(node_hash);
        task.link_id = Some(link.link_id);
        task.link = Some(link);
        task.state = SyncTaskState::Offering;
        let mut policy = OutboundOfferPolicy::unrestricted(node_hash);
        policy.handled_messages.insert(transient_id);
        task.offer_policy = Some(policy);

        task.send_offer_request();

        assert_eq!(task.state, SyncTaskState::Complete);
        assert!(
            rx.try_recv().is_err(),
            "empty offer must not emit a request"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn production_policy_preparation_runs_through_bounded_worker() {
        let (tx, mut rx) = mpsc::channel(16);
        let shared_node = Arc::new(Mutex::new(PropagationNode::new(
            PropagationNodeConfig::default(),
            [0xAA; 16],
        )));
        let key = Ed25519PrivateKey::generate();
        let mut message = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "already handled async",
            crate::constants::DeliveryMethod::Propagated,
        );
        message.sign(&key).unwrap();
        let transient_id = message.transient_id.unwrap();
        assert!(shared_node.lock().unwrap().accept_message(&message));

        let node_hash = [0xDD; 16];
        let mut task = PropagationSyncTask::with_shared_node(tx, shared_node);
        task.set_node(node_hash);
        task.state = SyncTaskState::Offering;
        let mut policy = OutboundOfferPolicy::unrestricted(node_hash);
        policy.handled_messages.insert(transient_id);
        task.offer_policy = Some(policy);

        task.send_offer_request();
        assert!(task.offer_preparation_rx.is_some());
        tokio::time::timeout(Duration::from_secs(2), async {
            while task.state == SyncTaskState::Offering {
                tokio::time::sleep(Duration::from_millis(1)).await;
                task.send_offer_request();
            }
        })
        .await
        .expect("bounded offer-preparation worker did not complete");

        assert_eq!(task.state, SyncTaskState::Complete);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn terminal_offer_filters_are_exposed_and_complete_without_wire_offer() {
        let (tx, mut rx) = mpsc::channel(16);
        let node_hash = [0xDD; 16];
        let shared_node = Arc::new(Mutex::new(PropagationNode::new(
            PropagationNodeConfig::default(),
            [0xAA; 16],
        )));
        let low = vec![0x11; 64];
        let oversized = vec![0x22; 700];
        assert!(shared_node.lock().unwrap().accept_propagated_blob(&low, 9));
        assert!(
            shared_node
                .lock()
                .unwrap()
                .accept_propagated_blob(&oversized, 20)
        );
        let mut policy = OutboundOfferPolicy::unrestricted(node_hash);
        policy.minimum_stamp_cost = 10;
        policy.propagation_transfer_limit = Some(0.5);
        let mut task = PropagationSyncTask::with_shared_node(tx, shared_node);
        task.set_node(node_hash);
        task.offer_policy = Some(policy);
        task.state = SyncTaskState::Offering;

        task.send_offer_request();

        let mut updates = task.take_handled_updates();
        updates.sort();
        let mut expected = vec![
            rns_crypto::sha::full_hash(&low),
            rns_crypto::sha::full_hash(&oversized),
        ];
        expected.sort();
        assert_eq!(updates, expected);
        assert_eq!(task.state, SyncTaskState::Complete);
        assert!(task.generation_exhausted);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn have_all_exposes_every_offered_id_for_authoritative_persistence() {
        let dir = std::env::temp_dir().join("lxmf_sync_have_all_persist");
        let _ = std::fs::remove_dir_all(&dir);
        let node_hash = [0xBB; 16];
        let node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();
        let shared_node = Arc::new(Mutex::new(node));
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        for content in ["first", "second"] {
            let mut message = crate::message::LxMessage::new(
                [0xCC; 16],
                [0xDD; 16],
                "Test",
                content,
                crate::constants::DeliveryMethod::Propagated,
            );
            message.sign(&key).unwrap();
            assert!(shared_node.lock().unwrap().accept_message(&message));
        }
        let policy = OutboundOfferPolicy::unrestricted(node_hash);
        let offered = {
            let mut node = shared_node.lock().unwrap();
            node.prepare_sync_offer_with_policy(&policy);
            node.get_session(&node_hash).unwrap().offered_ids.clone()
        };
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::with_shared_node(tx, shared_node.clone());
        task.set_node(node_hash);
        task.offer_policy = Some(policy);

        task.handle_offer_response(OfferResponse::HaveAll);

        assert_eq!(task.state, SyncTaskState::Complete);
        let mut updates = task.take_handled_updates();
        updates.sort();
        let mut expected = offered.clone();
        expected.sort();
        assert_eq!(updates, expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn want_some_is_intersected_with_offer_and_marks_complement_handled() {
        let dir = std::env::temp_dir().join("lxmf_sync_want_some_bound");
        let _ = std::fs::remove_dir_all(&dir);
        let node_hash = [0xBB; 16];
        let node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();
        let shared_node = Arc::new(Mutex::new(node));
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        for content in ["first", "second"] {
            let mut message = crate::message::LxMessage::new(
                [0xCC; 16],
                [0xDD; 16],
                "Test",
                content,
                crate::constants::DeliveryMethod::Propagated,
            );
            message.sign(&key).unwrap();
            assert!(shared_node.lock().unwrap().accept_message(&message));
        }
        let policy = OutboundOfferPolicy::unrestricted(node_hash);
        let offered = {
            let mut node = shared_node.lock().unwrap();
            node.prepare_sync_offer_with_policy(&policy);
            node.get_session(&node_hash).unwrap().offered_ids.clone()
        };
        assert_eq!(offered.len(), 2);
        let wanted = offered[0];
        let already_handled = offered[1];
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::with_shared_node(tx, shared_node);
        task.set_node(node_hash);
        task.offer_policy = Some(policy);

        task.handle_offer_response(OfferResponse::WantSome(vec![
            wanted.to_vec(),
            vec![0xEF; 32],
            wanted.to_vec(),
        ]));

        assert_eq!(task.state, SyncTaskState::Transferring);
        let batch = task.ready_transfer_batch.as_ref().unwrap();
        assert_eq!(batch.transient_ids, vec![wanted]);
        assert_eq!(task.take_handled_updates(), vec![already_handled]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_handle_offer_response_error() {
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        task.state = SyncTaskState::AwaitingResponse;

        task.handle_offer_response(OfferResponse::ErrorNoAccess);
        assert_eq!(task.state, SyncTaskState::Failed);
    }

    #[test]
    fn test_handle_offer_response_want_all_no_storage() {
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        task.state = SyncTaskState::AwaitingResponse;

        // In-memory store -- message_get_request returns empty, so WantAll -> Complete.
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "content",
            crate::constants::DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();
        task.accept_message(&msg);

        task.handle_offer_response(OfferResponse::WantAll);
        assert_eq!(task.state, SyncTaskState::Complete);
    }

    #[test]
    fn test_handle_offer_response_want_some() {
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        task.state = SyncTaskState::AwaitingResponse;

        let wanted = vec![vec![0x11; 32], vec![0x22; 32]];
        task.handle_offer_response(OfferResponse::WantSome(wanted));
        assert_eq!(task.state, SyncTaskState::Complete);
    }

    #[test]
    fn test_handle_offer_response_want_some_with_storage() {
        let dir = std::env::temp_dir().join("lxmf_test_sync_want_some");
        let _ = std::fs::remove_dir_all(&dir);

        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::with_storage(tx, [0xAA; 16], dir.clone()).unwrap();
        task.set_node([0xBB; 16]);
        task.state = SyncTaskState::AwaitingResponse;

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "want some content",
            crate::constants::DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();
        let tid = msg.transient_id.unwrap();
        task.accept_message(&msg);

        let policy = OutboundOfferPolicy::unrestricted([0xBB; 16]);
        task.propagation_node
            .lock()
            .unwrap()
            .prepare_sync_offer_with_policy(&policy);
        task.offer_policy = Some(policy);

        let wanted = vec![tid.to_vec()];
        task.handle_offer_response(OfferResponse::WantSome(wanted));
        assert_eq!(task.state, SyncTaskState::Transferring);
        let batch = task.ready_transfer_batch.as_ref().unwrap();
        assert_eq!(batch.transient_ids, vec![tid]);
        let decoded: rmpv::Value = rmpv::decode::read_value(&mut &batch.payload[..]).unwrap();
        let outer = decoded.as_array().unwrap();
        assert_eq!(outer.len(), 2);
        assert!(outer[0].as_f64().is_some());
        let blobs = outer[1].as_array().unwrap();
        assert_eq!(blobs.len(), 1, "one Resource carries the exact blob batch");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn want_all_builds_one_timestamped_resource_batch_and_waits_for_proof() {
        let dir = std::env::temp_dir().join("lxmf_test_sync_one_batch");
        let _ = std::fs::remove_dir_all(&dir);
        let node_hash = [0xBB; 16];
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::with_storage(tx, [0xAA; 16], dir.clone()).unwrap();
        task.set_node(node_hash);
        let key = Ed25519PrivateKey::generate();
        for content in ["one", "two"] {
            let mut message = crate::message::LxMessage::new(
                [0xCC; 16],
                [0xDD; 16],
                "Test",
                content,
                crate::constants::DeliveryMethod::Propagated,
            );
            message.sign(&key).unwrap();
            assert!(task.accept_message(&message));
        }
        let policy = OutboundOfferPolicy::unrestricted(node_hash);
        task.propagation_node
            .lock()
            .unwrap()
            .prepare_sync_offer_with_policy(&policy);
        task.offer_policy = Some(policy);
        task.state = SyncTaskState::AwaitingResponse;

        task.handle_offer_response(OfferResponse::WantAll);

        let batch = task.ready_transfer_batch.as_ref().unwrap();
        assert_eq!(batch.transient_ids.len(), 2);
        let decoded: rmpv::Value = rmpv::decode::read_value(&mut &batch.payload[..]).unwrap();
        let outer = decoded.as_array().unwrap();
        assert_eq!(outer.len(), 2);
        assert!(outer[0].as_f64().is_some());
        assert_eq!(outer[1].as_array().unwrap().len(), 2);
        assert!(
            task.take_handled_updates().is_empty(),
            "wanted IDs converge only after the batch Resource is proven"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vanished_requested_file_fails_retryably_for_peer_backoff() {
        let dir = std::env::temp_dir().join("lxmf_test_sync_vanished_batch");
        let _ = std::fs::remove_dir_all(&dir);
        let node_hash = [0xBB; 16];
        let (tx, _rx) = mpsc::channel(16);
        let mut task = PropagationSyncTask::with_storage(tx, [0xAA; 16], dir.clone()).unwrap();
        task.set_node(node_hash);
        let key = Ed25519PrivateKey::generate();
        let mut message = crate::message::LxMessage::new(
            [0xCC; 16],
            [0xDD; 16],
            "Test",
            "vanish",
            crate::constants::DeliveryMethod::Propagated,
        );
        message.sign(&key).unwrap();
        assert!(task.accept_message(&message));
        let policy = OutboundOfferPolicy::unrestricted(node_hash);
        let (generation, reads) = {
            let mut node = task.propagation_node.lock().unwrap();
            let offer = node.prepare_sync_offer_with_policy(&policy);
            let ids = offer
                .transient_ids
                .iter()
                .map(|id| id.clone().try_into().unwrap())
                .collect::<Vec<PropagationTransientId>>();
            (node.offer_generation(), node.plan_message_reads(&ids))
        };
        assert_eq!(reads.len(), 1);
        std::fs::remove_file(&reads[0].path).unwrap();
        task.offer_policy = Some(policy);
        task.active_offer_generation = Some(generation);
        task.generation_exhausted = true;
        task.state = SyncTaskState::AwaitingResponse;

        task.handle_offer_response(OfferResponse::WantAll);
        task.drive_transfers();

        assert_eq!(task.state, SyncTaskState::Failed);
        assert!(!task.generation_exhausted);
        assert!(task.take_handled_updates().is_empty());
        task.tick();
        assert_eq!(
            task.take_terminal_peer_result(),
            Some(PeerSyncTerminalResult {
                peer_hash: node_hash,
                state: PeerSyncTerminalState::Failed,
                offer_generation: None,
                generation_exhausted: false,
                offered: 0,
                outgoing: 0,
                tx_bytes: 0,
                link_establishment_rate: None,
                sync_transfer_rate: None,
            })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_peer_created_on_sync_start() {
        let (tx, _rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        make_sync_due(&mut task);

        assert!(task.peer().is_none());

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "content",
            crate::constants::DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();
        task.accept_message(&msg);

        task.tick();
        assert_eq!(task.state, SyncTaskState::Establishing);

        let peer = task.peer().expect("peer should exist after sync start");
        assert_eq!(peer.destination_hash, [0xBB; 16]);
        assert_eq!(peer.state, crate::constants::PeerState::LinkEstablishing);
    }

    #[test]
    fn request_sync_now_starts_without_waiting_for_interval() {
        let (tx, _rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);

        task.request_sync_now([0xBB; 16]);

        assert_eq!(task.node_dest_hash(), Some([0xBB; 16]));
        assert_eq!(task.state, SyncTaskState::Establishing);
        let peer = task.peer().expect("peer should exist after forced sync");
        assert_eq!(peer.destination_hash, [0xBB; 16]);
    }

    #[test]
    fn active_sync_rejects_different_request_without_mutating_target_or_policy() {
        let (tx, _rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        let policy_a = OutboundOfferPolicy::unrestricted([0xA1; 16]);
        let policy_b = OutboundOfferPolicy::unrestricted([0xB2; 16]);

        assert!(task.request_sync_now_with_policy(policy_a.clone()));
        assert!(!task.request_sync_now_with_policy(policy_b));
        assert_eq!(task.node_dest_hash(), Some(policy_a.peer_hash));
        assert_eq!(task.offer_policy, Some(policy_a));
    }

    #[test]
    fn cancel_peer_sync_clears_active_pending_and_session_state() {
        let (tx, _rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        let peer_hash = [0xA1; 16];
        assert!(task.request_sync_now_with_policy(OutboundOfferPolicy::unrestricted(peer_hash)));
        task.handled_updates.push([0x44; 32]);
        task.propagation_node
            .lock()
            .unwrap()
            .start_session(peer_hash);

        assert!(task.cancel_peer_sync(&peer_hash));
        assert_eq!(task.state, SyncTaskState::Idle);
        assert_eq!(task.node_dest_hash(), None);
        assert!(task.offer_policy.is_none());
        assert!(task.take_handled_updates().is_empty());
        assert!(
            task.propagation_node
                .lock()
                .unwrap()
                .get_session(&peer_hash)
                .is_none()
        );
    }

    #[test]
    fn terminal_results_advance_generation_only_on_success_and_must_be_drained() {
        let (tx, _rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.node_dest_hash = Some([0xA1; 16]);
        task.active_offer_generation = Some(7);
        task.generation_exhausted = false;
        task.state = SyncTaskState::Complete;
        task.tick();

        assert!(!task.request_sync_now([0xB2; 16]));
        assert_eq!(
            task.take_terminal_peer_result(),
            Some(PeerSyncTerminalResult {
                peer_hash: [0xA1; 16],
                state: PeerSyncTerminalState::Complete,
                offer_generation: Some(7),
                generation_exhausted: false,
                offered: 0,
                outgoing: 0,
                tx_bytes: 0,
                link_establishment_rate: None,
                sync_transfer_rate: None,
            })
        );
        assert!(task.request_sync_now([0xB2; 16]));
        task.state = SyncTaskState::Failed;
        task.tick();
        assert_eq!(
            task.take_terminal_peer_result(),
            Some(PeerSyncTerminalResult {
                peer_hash: [0xB2; 16],
                state: PeerSyncTerminalState::Failed,
                offer_generation: None,
                generation_exhausted: false,
                offered: 0,
                outgoing: 0,
                tx_bytes: 0,
                link_establishment_rate: None,
                sync_transfer_rate: None,
            })
        );
    }

    #[test]
    fn terminal_result_carries_python_peer_accounting_deltas() {
        let (tx, _rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.node_dest_hash = Some([0xC3; 16]);
        task.offered_count = 11;
        task.outgoing_count = 7;
        task.transfer_data_size = 4096;
        task.transfer_wire_size = 1000;
        task.transfer_started = Some(Instant::now() - Duration::from_secs(2));
        task.link_establishment_rate = Some(1234.0);
        task.state = SyncTaskState::Complete;

        task.tick();

        let result = task.take_terminal_peer_result().unwrap();
        assert_eq!(result.offered, 11);
        assert_eq!(result.outgoing, 7);
        assert_eq!(result.tx_bytes, 4096);
        assert_eq!(result.link_establishment_rate, Some(1234.0));
        assert!(result.sync_transfer_rate.is_some_and(|rate| rate > 3_900.0));
    }

    #[test]
    fn link_identify_is_emitted_after_rtt_and_before_offer_request() {
        let (tx, mut rx) = mpsc::channel(64);
        let node_hash = [0xB2; 16];
        let responder_key = Ed25519PrivateKey::generate();
        let responder_pub = responder_key.public_key();
        let (link, request_data) = Link::new_initiator(node_hash, 1);
        let (_responder, proof_data) =
            Link::new_responder(&request_data, &responder_key, node_hash, 1).unwrap();

        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        let local_key = Ed25519PrivateKey::generate();
        let mut local_pub = [0x33; 64];
        local_pub[32..].copy_from_slice(&local_key.public_key().to_bytes());
        task.set_identity(local_pub, local_key);
        task.node_dest_hash = Some(node_hash);
        task.link_id = Some(link.link_id);
        task.link = Some(link);
        task.peer = Some(LxmPeer::new(node_hash));
        task.state = SyncTaskState::Establishing;

        let message_key = Ed25519PrivateKey::generate();
        let mut message = crate::message::LxMessage::new(
            [0xCC; 16],
            [0xDD; 16],
            "Test",
            "identify ordering",
            crate::constants::DeliveryMethod::Propagated,
        );
        message.sign(&message_key).unwrap();
        assert!(task.accept_message(&message));
        task.offer_policy = Some(OutboundOfferPolicy::unrestricted(node_hash));

        task.handle_link_proof(&proof_data, &responder_pub, &responder_pub.to_bytes());
        task.send_offer_request();

        let mut contexts = Vec::new();
        while let Ok(TransportMessage::Outbound(request)) = rx.try_recv() {
            let (header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
            contexts.push(header.context);
        }
        assert_eq!(
            contexts,
            vec![
                rns_wire::context::PacketContext::Lrrtt,
                rns_wire::context::PacketContext::LinkIdentify,
                rns_wire::context::PacketContext::Request,
            ]
        );
    }

    #[test]
    fn test_peer_cleared_on_cleanup() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.set_node([0xBB; 16]);
        make_sync_due(&mut task);

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = crate::message::LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "content",
            crate::constants::DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();
        task.accept_message(&msg);

        task.tick();
        while rx.try_recv().is_ok() {}

        assert!(task.peer().is_some());

        task.state = SyncTaskState::Complete;
        task.tick();

        assert!(task.peer().is_none());
    }
}
