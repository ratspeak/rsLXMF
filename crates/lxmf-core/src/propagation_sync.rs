//! Propagation sync background task.
//!
//! Outbound sync to a configured propagation node using the Link
//! REQUEST/RESPONSE pattern. Python reference: LXMPeer.py:381-386.
//!
//! Flow:
//! 1. Establish a link to the node.
//! 2. Identify on the link (LinkIdentify) so the PN knows our identity.
//! 3. Send link.request("/offer", [peering_key, transient_ids]).
//! 4. Receive a Response packet (context 0x0A) with OfferResponse.
//! 5. Transfer requested messages as a Resource.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_link::link::{CloseReason, Link};
use rns_protocol::resource::{OutboundTransfer, TransferAction};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{OutboundRequest, TransportMessage};
use tokio::sync::mpsc;

use crate::constants::{OFFER_REQUEST_PATH, STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING};
use crate::peer::LxmPeer;
use crate::propagation::hex_encode;
use crate::propagation_node::{PropagationNode, PropagationNodeConfig};
use crate::stamper::generate_stamp;
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
    transfer_queue: Vec<Vec<u8>>,
    active_transfer: Option<OutboundTransfer>,
    peer: Option<LxmPeer>,
    /// Client identity hash for peering_id = pn_identity || client_identity.
    local_identity_hash: Option<[u8; 16]>,
    /// Propagation-node identity hash (not destination hash).
    peer_identity_hash: Option<[u8; 16]>,
    /// Peering stamp cost advertised by the remote PN (0 = empty key allowed).
    peer_peering_cost: u8,
    /// Precomputed peering key (preferred) — avoids PoW on the maintenance tick.
    outbound_peering_key: Option<Vec<u8>>,
    /// Last `/offer` response error label (cleared on successful sync start).
    pub last_offer_error: Option<&'static str>,
    /// Sticky outcome after Complete/Failed → Idle (for progress emitters).
    pub last_finished_ok: Option<bool>,
    /// Local identity material for LinkIdentify (required before `/offer`).
    identity_pub: Option<[u8; 64]>,
    identity_key: Option<Ed25519PrivateKey>,
    identified: bool,
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
            transfer_queue: Vec::new(),
            active_transfer: None,
            peer: None,
            local_identity_hash: None,
            peer_identity_hash: None,
            peer_peering_cost: 0,
            outbound_peering_key: None,
            last_offer_error: None,
            last_finished_ok: None,
            identity_pub: None,
            identity_key: None,
            identified: false,
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
            transfer_queue: Vec::new(),
            active_transfer: None,
            peer: None,
            local_identity_hash: None,
            peer_identity_hash: None,
            peer_peering_cost: 0,
            outbound_peering_key: None,
            last_offer_error: None,
            last_finished_ok: None,
            identity_pub: None,
            identity_key: None,
            identified: false,
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
            transfer_queue: Vec::new(),
            active_transfer: None,
            peer: None,
            local_identity_hash: None,
            peer_identity_hash: None,
            peer_peering_cost: 0,
            outbound_peering_key: None,
            last_offer_error: None,
            last_finished_ok: None,
            identity_pub: None,
            identity_key: None,
            identified: false,
        }
    }

    /// Provide local identity for LinkIdentify before `/offer`.
    pub fn set_local_identity(
        &mut self,
        identity_pub: [u8; 64],
        identity_key: Ed25519PrivateKey,
    ) {
        self.identity_pub = Some(identity_pub);
        self.identity_key = Some(identity_key);
    }

    /// Configure peering material used for `/offer` after link establish.
    pub fn configure_peering(
        &mut self,
        local_identity_hash: [u8; 16],
        peer_identity_hash: [u8; 16],
        peering_cost: u8,
        precomputed_key: Option<Vec<u8>>,
    ) {
        self.local_identity_hash = Some(local_identity_hash);
        self.peer_identity_hash = Some(peer_identity_hash);
        self.peer_peering_cost = peering_cost;
        self.outbound_peering_key = precomputed_key;
    }

    pub fn set_node(&mut self, dest_hash: [u8; 16]) {
        self.node_dest_hash = Some(dest_hash);
    }

    /// Force an immediate sync attempt with `dest_hash`.
    ///
    /// Python `LXMPeer.sync()` is called directly by lxmd control requests;
    /// this public shim preserves that behavior without waiting for the
    /// periodic sync interval.
    pub fn request_sync_now(&mut self, dest_hash: [u8; 16]) {
        self.node_dest_hash = Some(dest_hash);
        self.last_offer_error = None;
        self.last_finished_ok = None;
        self.identified = false;
        if self.state == SyncTaskState::Idle {
            self.start_sync(dest_hash);
            self.last_sync = Instant::now();
        }
    }

    pub fn node_dest_hash(&self) -> Option<[u8; 16]> {
        self.node_dest_hash
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
                            if let Some(node_hex) = node_hex
                                && let Some(pub_key) = known_identities.get(&node_hex)
                            {
                                let ed25519_bytes: [u8; 32] = pub_key[32..64].try_into().unwrap();
                                if let Ok(verify_key) = Ed25519PublicKey::from_bytes(&ed25519_bytes)
                                {
                                    self.handle_link_proof(data, &verify_key, &ed25519_bytes);
                                }
                            }
                        }
                        rns_wire::context::PacketContext::ResourceHmu => {
                            if let Some(ref link) = self.link
                                && let Ok(plaintext) = link.decrypt(data)
                                && let Some(ref mut transfer) = self.active_transfer
                            {
                                transfer.handle_hmu(&plaintext);
                            }
                        }
                        rns_wire::context::PacketContext::ResourcePrf => {
                            // Python Packet.pack() sends PROOF+RESOURCE_PRF as
                            // plaintext (Packet.py:195-197) on PacketType::Proof.
                            // Body = resource_hash(32) || proof(32).
                            if let Some(ref mut transfer) = self.active_transfer
                                && transfer.handle_proof(data)
                            {
                                self.active_transfer = None;
                            }
                        }
                        rns_wire::context::PacketContext::Response => {
                            if self.state == SyncTaskState::AwaitingResponse
                                && let Some(ref mut link) = self.link
                                && let Ok((_request_id, response_data)) = link.handle_response(data)
                            {
                                let offer_response = OfferResponse::from_msgpack(&response_data);
                                self.handle_offer_response(offer_response);
                            }
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
            self.active_transfer = None;
            self.transfer_queue.clear();
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
        let link = match self.link.as_mut() {
            Some(l) => l,
            None => return,
        };

        match link.validate_proof(proof_data, verify_key, ed25519_pub) {
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

                    let _ =
                        self.transport_tx
                            .try_send(TransportMessage::Outbound(OutboundRequest {
                                raw: Bytes::from(rtt_raw),
                                destination_hash: link_id,
                            }));

                    // Python LXMPeer.py:530-538
                    let establishment_rate = link.rtt.map(|d| {
                        let secs = d.as_secs_f64();
                        if secs > 0.0 { 1.0 / secs } else { 0.0 }
                    });
                    if let Some(ref mut peer) = self.peer {
                        peer.link_established(link_id, establishment_rate);
                    }
                }
                self.state = SyncTaskState::Offering;
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

        match response {
            OfferResponse::WantAll => {
                let all_ids = self
                    .propagation_node
                    .lock()
                    .map(|node| node.create_offer(node_hash, None))
                    .unwrap_or_default();
                self.queue_messages_for_ids(&all_ids);
            }
            OfferResponse::HaveAll => {
                self.state = SyncTaskState::Complete;
            }
            OfferResponse::WantSome(wanted_id_bytes) => {
                let wanted_ids: Vec<PropagationTransientId> = wanted_id_bytes
                    .iter()
                    .filter_map(|id| {
                        if id.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(id);
                            Some(arr)
                        } else {
                            None
                        }
                    })
                    .collect();
                self.queue_messages_for_ids(&wanted_ids);
            }
            OfferResponse::ErrorNoIdentity => {
                self.last_offer_error = Some("ErrorNoIdentity");
                self.state = SyncTaskState::Failed;
            }
            OfferResponse::ErrorNoAccess => {
                self.last_offer_error = Some("ErrorNoAccess");
                self.state = SyncTaskState::Failed;
            }
            OfferResponse::ErrorInvalidKey => {
                self.last_offer_error = Some("ErrorInvalidKey");
                self.state = SyncTaskState::Failed;
            }
            OfferResponse::ErrorThrottled => {
                self.last_offer_error = Some("ErrorThrottled");
                self.state = SyncTaskState::Failed;
            }
            OfferResponse::ErrorInvalidData => {
                self.last_offer_error = Some("ErrorInvalidData");
                self.state = SyncTaskState::Failed;
            }
            OfferResponse::ErrorInvalidStamp => {
                self.last_offer_error = Some("ErrorInvalidStamp");
                self.state = SyncTaskState::Failed;
            }
            OfferResponse::Unknown => {
                self.last_offer_error = Some("Unknown");
                self.state = SyncTaskState::Failed;
            }
        }
    }

    fn queue_messages_for_ids(&mut self, ids: &[PropagationTransientId]) {
        // Resolve paths under the node lock; read the files after dropping it.
        let plan = match self.propagation_node.lock() {
            Ok(node) => node.plan_message_reads(ids),
            Err(_) => {
                self.state = SyncTaskState::Failed;
                return;
            }
        };
        let results = crate::propagation_node::read_planned_messages(&plan);
        self.transfer_queue = results.into_iter().map(|(_tid, data)| data).collect();

        if self.transfer_queue.is_empty() {
            self.state = SyncTaskState::Complete;
        } else {
            self.state = SyncTaskState::Transferring;
        }
    }

    pub fn tick(&mut self) {
        if let Some(started) = self.sync_started
            && started.elapsed() > self.sync_timeout
            && self.state != SyncTaskState::Idle
        {
            self.cleanup_sync();
            self.state = SyncTaskState::Failed;
            return;
        }

        match self.state {
            SyncTaskState::Idle => {
                if self.last_sync.elapsed() >= self.sync_interval
                    && let Some(node_hash) = self.node_dest_hash
                {
                    if self.message_count() > 0 {
                        self.start_sync(node_hash);
                    } else {
                        self.last_sync = Instant::now();
                    }
                }
            }
            SyncTaskState::Establishing | SyncTaskState::AwaitingResponse => {}
            SyncTaskState::Offering => {
                // PN serve-side `/offer` rejects with ErrorNoIdentity unless
                // remote_identity_hash is known — LinkIdentify supplies it.
                if !self.identified {
                    if !self.send_identify() {
                        self.state = SyncTaskState::Failed;
                        self.last_offer_error = Some("ErrorNoIdentity");
                        return;
                    }
                    self.identified = true;
                }
                self.send_offer_request();
            }
            SyncTaskState::Transferring => {
                self.drive_transfers();
            }
            SyncTaskState::Complete | SyncTaskState::Failed => {
                self.last_finished_ok = Some(self.state == SyncTaskState::Complete);
                self.cleanup_sync();
                self.last_sync = Instant::now();
                self.state = SyncTaskState::Idle;
            }
        }
    }

    /// Reveal initiator identity to the remote PN (required before `/offer`).
    fn send_identify(&mut self) -> bool {
        let (Some(link), Some(link_id)) = (&self.link, self.link_id) else {
            return false;
        };
        let (Some(pub_key), Some(sign_key)) = (&self.identity_pub, &self.identity_key) else {
            tracing::warn!("propagation sync missing identity for LinkIdentify");
            return false;
        };
        let Ok(identify_data) = link.identify(pub_key, sign_key) else {
            return false;
        };
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
        let _ = self
            .transport_tx
            .try_send(TransportMessage::Outbound(OutboundRequest {
                raw: Bytes::from(id_raw),
                destination_hash: link_id,
            }));
        true
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

        // Wire: msgpack([peering_key, [transient_id_1, transient_id_2, ...]])
        let mut offer = match self.propagation_node.lock() {
            Ok(mut node) => node.prepare_sync_offer(node_hash),
            Err(_) => {
                self.state = SyncTaskState::Failed;
                return;
            }
        };
        // prepare_sync_offer currently leaves peering_key empty; PNs with peering_cost > 0
        // reject that as ErrorInvalidKey. Prefer a precomputed key from the caller.
        if offer.peering_key.is_empty() {
            if let Some(key) = self.outbound_peering_key.clone() {
                offer.peering_key = key;
            } else if let (Some(local), Some(peer)) =
                (self.local_identity_hash, self.peer_identity_hash)
            {
                // PN validates peering_id = pn_identity || client_identity.
                let mut peering_id = Vec::with_capacity(32);
                peering_id.extend_from_slice(&peer);
                peering_id.extend_from_slice(&local);
                if let Some((key, _)) = generate_stamp(
                    &peering_id,
                    self.peer_peering_cost,
                    STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING,
                ) {
                    offer.peering_key = key.to_vec();
                } else if self.peer_peering_cost > 0 {
                    tracing::warn!(
                        cost = self.peer_peering_cost,
                        "failed to generate peering stamp; remote PN will reject /offer"
                    );
                }
            }
        }
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
                        let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                            OutboundRequest {
                                raw: Bytes::from(req_raw),
                                destination_hash: link_id,
                            },
                        ));
                    }
                    self.state = SyncTaskState::AwaitingResponse;
                }
                Err(_) => {
                    self.state = SyncTaskState::Failed;
                }
            }
        } else {
            self.state = SyncTaskState::Failed;
        }
    }

    fn start_sync(&mut self, node_hash: [u8; 16]) {
        let (link, request_data) = Link::new_initiator(node_hash, 1);
        let link_id = link.link_id;

        if let Err(e) = self
            .transport_tx
            .try_send(TransportMessage::RegisterDestination {
                hash: link_id,
                app_name: "lxmf.propagation.sync".to_string(),
                delivery_tx: Some(self.event_tx.clone()),
            })
        {
            tracing::warn!(err = %e,
                "failed to register propagation sync destination; sync will fail");
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

        let _ = self
            .transport_tx
            .try_send(TransportMessage::Outbound(OutboundRequest {
                raw: Bytes::from(raw),
                destination_hash: node_hash,
            }));

        let mut peer = LxmPeer::new(node_hash);
        peer.begin_sync();

        self.link = Some(link);
        self.link_id = Some(link_id);
        self.peer = Some(peer);
        self.state = SyncTaskState::Establishing;
        self.sync_started = Some(Instant::now());
    }

    fn drive_transfers(&mut self) {
        if self.active_transfer.is_none() {
            if let Some(msg_data) = self.transfer_queue.pop() {
                let rtt = self
                    .link
                    .as_ref()
                    .and_then(|l| l.rtt)
                    .unwrap_or(Duration::from_millis(500));
                match OutboundTransfer::new(msg_data, true, rtt) {
                    Ok(transfer) => {
                        self.active_transfer = Some(transfer);
                    }
                    Err(_) => return,
                }
            } else {
                self.state = SyncTaskState::Complete;
                return;
            }
        }

        if let Some(ref mut transfer) = self.active_transfer {
            let action = transfer.tick();
            match action {
                TransferAction::SendAdvertisement(adv_data) => {
                    self.send_resource_packet(
                        &adv_data,
                        rns_wire::context::PacketContext::ResourceAdv,
                    );
                }
                TransferAction::SendPart(_, part_data) => {
                    self.send_resource_packet(
                        &part_data,
                        rns_wire::context::PacketContext::Resource,
                    );
                }
                TransferAction::Complete => {
                    self.active_transfer = None;
                }
                TransferAction::Failed(_) => {
                    self.active_transfer = None;
                    self.state = SyncTaskState::Failed;
                }
                _ => {}
            }
        }
    }

    fn send_resource_packet(&self, data: &[u8], context: rns_wire::context::PacketContext) {
        let link_id = match self.link_id {
            Some(id) => id,
            None => return,
        };
        let link = match self.link.as_ref() {
            Some(l) => l,
            None => return,
        };

        if let Ok(encrypted) = link.encrypt(data) {
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
            raw.extend_from_slice(&encrypted);
            let _ = self
                .transport_tx
                .try_send(TransportMessage::Outbound(OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: link_id,
                }));
        }
    }

    /// Python LXMPeer.py:540-542.
    fn cleanup_sync(&mut self) {
        self.send_teardown();
        if let Some(ref mut peer) = self.peer {
            peer.link_closed();
        }

        if let Some(link_id) = self.link_id.take() {
            let _ = self
                .transport_tx
                .try_send(TransportMessage::DeregisterDestination { hash: link_id });
        }
        self.link = None;
        self.peer = None;
        self.active_transfer = None;
        self.transfer_queue.clear();
        self.sync_started = None;
        self.identified = false;
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
            let _ = self
                .transport_tx
                .try_send(TransportMessage::Outbound(OutboundRequest {
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
        assert_eq!(task.state, SyncTaskState::Failed);

        task.tick();
        assert_eq!(task.state, SyncTaskState::Idle);
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

        let wanted = vec![tid.to_vec()];
        task.handle_offer_response(OfferResponse::WantSome(wanted));
        assert_eq!(task.state, SyncTaskState::Transferring);
        assert_eq!(task.transfer_queue.len(), 1);

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
