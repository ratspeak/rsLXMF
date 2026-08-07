//! Client-side propagation node download protocol.
//!
//! Python reference: LXMRouter.py:484-587.
//!
//! Protocol flow:
//! 1. Establish link to the propagation node destination.
//! 2. Identify on the link (LinkIdentify).
//! 3. Request `/get` with `[None, None]` -- server returns available transient IDs.
//! 4. Client sorts into wants/haves.
//! 5. Request `/get` with `[wants, haves, delivery_limit]`.
//! 6. Server returns `[lxmf_data_1, lxmf_data_2, ...]`.
//! 7. Client processes received messages.
//! 8. Final `/get` with `[None, received_ids]` purges them from the server.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_link::link::{CloseReason, Link};
use rns_protocol::resource::{
    InboundTransfer, MAX_SEGMENTS, MultiSegmentInbound, RANDOM_HASH_SIZE, ResourceError,
    TransferAction,
};
use rns_protocol::resource_adv::ResourceAdvertisement;
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{OutboundRequest, TransportMessage};
use tokio::sync::mpsc;

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
    Complete,
    Failed,
}

/// One coherent public snapshot of a propagation-node download.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PropagationTransferStatus {
    pub state: PropagationClientState,
    pub progress: f64,
    pub data_size: Option<usize>,
    /// Number of message blobs decoded from the completed response.
    pub result: Option<usize>,
}

impl Default for PropagationTransferStatus {
    fn default() -> Self {
        Self {
            state: PropagationClientState::Idle,
            progress: 0.0,
            data_size: None,
            result: None,
        }
    }
}

struct SegmentRoute {
    original_hash: [u8; 32],
    segment_index: usize,
}

pub struct PropagationClient {
    transport_tx: mpsc::Sender<TransportMessage>,
    event_tx: mpsc::Sender<DestinationEvent>,
    event_rx: mpsc::Receiver<DestinationEvent>,
    outbound_propagation_node: Option<[u8; 16]>,
    link: Option<Link>,
    link_id: Option<[u8; 16]>,
    status: PropagationTransferStatus,
    /// Request phase whose response is currently arriving as a Resource.
    receiving_for: Option<PropagationClientState>,
    identity_pub: Option<[u8; 64]>,
    identity_key: Option<Ed25519PrivateKey>,
    /// Phase 1 response: transient IDs the server has.
    available_messages: Vec<Vec<u8>>,
    /// Messages we already have locally.
    local_messages: HashSet<Vec<u8>>,
    /// Phase 2 response: downloaded LXMF message data.
    received_messages: Vec<Vec<u8>>,
    /// IDs of messages successfully received (drives the Phase 3 purge).
    received_ids: Vec<Vec<u8>>,
    inbound_resources: HashMap<[u8; 32], InboundTransfer>,
    inbound_split_resources: HashMap<[u8; 32], MultiSegmentInbound>,
    segment_routing: HashMap<[u8; 32], SegmentRoute>,
    /// KB per transfer; `None` means unlimited.
    delivery_limit: Option<f64>,
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
        Self {
            transport_tx,
            event_tx,
            event_rx,
            outbound_propagation_node: None,
            link: None,
            link_id: None,
            status: PropagationTransferStatus::default(),
            receiving_for: None,
            identity_pub,
            identity_key,
            available_messages: Vec::new(),
            local_messages: HashSet::new(),
            received_messages: Vec::new(),
            received_ids: Vec::new(),
            inbound_resources: HashMap::new(),
            inbound_split_resources: HashMap::new(),
            segment_routing: HashMap::new(),
            delivery_limit: Some(DELIVERY_LIMIT as f64),
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
        self.local_messages.insert(transient_id.to_vec());
    }

    pub fn add_local_message_id(&mut self, transient_id: Vec<u8>) {
        self.local_messages.insert(transient_id);
    }

    pub fn available_messages(&self) -> &[Vec<u8>] {
        &self.available_messages
    }

    pub fn take_received_messages(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.received_messages)
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
            PropagationClientState::Complete | PropagationClientState::Failed
        ) {
            return false;
        }
        self.cleanup();
        self.status = PropagationTransferStatus::default();
        true
    }

    pub fn start_download(&mut self) -> bool {
        let node_hash = match self.outbound_propagation_node {
            Some(h) => h,
            None => return false,
        };
        if !matches!(
            self.status.state,
            PropagationClientState::Idle
                | PropagationClientState::Complete
                | PropagationClientState::Failed
        ) {
            return false;
        }
        if matches!(
            self.status.state,
            PropagationClientState::Complete | PropagationClientState::Failed
        ) {
            self.cleanup();
        }

        let (link, request_data) = Link::new_initiator(node_hash, 1);
        let link_id = link.link_id;

        if let Err(e) = self
            .transport_tx
            .try_send(TransportMessage::RegisterDestination {
                hash: link_id,
                app_name: "lxmf.propagation.client".to_string(),
                delivery_tx: Some(self.event_tx.clone()),
            })
        {
            tracing::warn!(err = %e,
                "failed to register propagation client destination; download will fail");
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

        self.status = PropagationTransferStatus {
            state: PropagationClientState::LinkEstablishing,
            ..PropagationTransferStatus::default()
        };
        self.receiving_for = None;
        self.link = Some(link);
        self.link_id = Some(link_id);
        self.started_at = Some(Instant::now());
        self.identified = false;
        self.available_messages.clear();
        self.received_messages.clear();
        self.received_ids.clear();
        self.inbound_resources.clear();
        self.inbound_split_resources.clear();
        self.segment_routing.clear();
        true
    }

    pub fn drain_events(&mut self, known_identities: &std::collections::HashMap<String, [u8; 64]>) {
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
                            if self.status.state != PropagationClientState::LinkEstablishing {
                                continue;
                            }
                            let node_hex = self.outbound_propagation_node.map(|h| hex_encode(&h));
                            if let Some(node_hex) = node_hex {
                                if let Some(pub_key) = known_identities.get(&node_hex) {
                                    let ed25519_bytes: [u8; 32] = pub_key[32..64]
                                        .try_into()
                                        .expect("known_identities values are [u8; 64]; slice [32..64] is always 32 bytes");
                                    if let Ok(verify_key) =
                                        Ed25519PublicKey::from_bytes(&ed25519_bytes)
                                    {
                                        self.handle_link_proof(data, &verify_key, &ed25519_bytes);
                                    }
                                }
                            }
                        }
                        rns_wire::context::PacketContext::Response => {
                            if let Some(ref mut link) = self.link {
                                if let Ok((_request_id, response_data)) = link.handle_response(data)
                                {
                                    self.handle_response_data(&response_data);
                                }
                            }
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
            self.status.state = PropagationClientState::Failed;
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
                }
                self.status.state = PropagationClientState::LinkEstablished;
            }
            Err(_) => {
                self.status.state = PropagationClientState::Failed;
            }
        }
    }

    fn handle_response_data(&mut self, response_data: &[u8]) {
        let response_phase = if self.status.state == PropagationClientState::Receiving {
            let Some(phase) = self.receiving_for.take() else {
                self.status.state = PropagationClientState::Failed;
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
                self.handle_get_response(response_data);
            }
            PropagationClientState::PurgeRequested => {
                self.handle_purge_response();
            }
            _ => {}
        }
    }

    fn handle_resource_advertisement(&mut self, data: &[u8]) {
        let Some(link) = self.link.as_ref() else {
            return;
        };
        let Ok(plaintext) = link.decrypt(data) else {
            self.status.state = PropagationClientState::Failed;
            return;
        };
        let Ok(adv) = ResourceAdvertisement::unpack(&plaintext) else {
            self.status.state = PropagationClientState::Failed;
            return;
        };

        if !adv.flags.is_response {
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
            self.status.state = PropagationClientState::Failed;
            return;
        }
        self.status.state = PropagationClientState::Receiving;
        self.status.data_size = Some(self.status.data_size.unwrap_or_default().max(adv.data_size));

        if adv.total_segments > 1 {
            if adv.total_segments > MAX_SEGMENTS
                || adv.segment_index == 0
                || adv.segment_index > adv.total_segments
            {
                self.status.state = PropagationClientState::Failed;
                return;
            }

            let entry = self
                .inbound_split_resources
                .entry(adv.original_hash)
                .or_insert_with(|| MultiSegmentInbound::new(adv.total_segments, adv.original_hash));
            if entry.total_segments != adv.total_segments {
                self.status.state = PropagationClientState::Failed;
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
            self.status.state = PropagationClientState::Failed;
            return;
        };

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
                    self.status.state = PropagationClientState::Failed;
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

        let Some(transfer) = self.inbound_resources.get_mut(&resource_hash) else {
            return;
        };
        match transfer.hashmap_update(segment, hashmap_data) {
            TransferAction::SendRequest(req) => {
                self.send_encrypted_resource_control(
                    rns_wire::context::PacketContext::ResourceReq,
                    &req,
                );
            }
            TransferAction::Failed(_) => {
                self.status.state = PropagationClientState::Failed;
            }
            _ => {}
        }
    }

    fn handle_resource_cancel(&mut self, data: &[u8]) {
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
        self.inbound_resources.remove(&resource_hash);
        if let Some(route) = self.segment_routing.remove(&resource_hash) {
            self.inbound_split_resources.remove(&route.original_hash);
        }
        if let Some(link) = self.link.as_mut() {
            link.untrack_resource(&resource_hash);
        }
        self.status.state = PropagationClientState::Failed;
    }

    fn complete_resource(&mut self, resource_hash: [u8; 32]) {
        let assembled = {
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
                Ok((assembled, proof)) => {
                    self.send_resource_proof(&proof);
                    assembled
                }
                Err(_) => {
                    self.status.state = PropagationClientState::Failed;
                    return;
                }
            }
        };

        let route = self.segment_routing.remove(&resource_hash);
        if let Some(link) = self.link.as_mut() {
            link.untrack_resource(&resource_hash);
        }
        let metadata = self
            .inbound_resources
            .get(&resource_hash)
            .and_then(|transfer| transfer.resource.metadata.clone());
        self.inbound_resources.remove(&resource_hash);

        if let Some(route) = route {
            let mut complete_payload = None;
            if let Some(coord) = self.inbound_split_resources.get_mut(&route.original_hash) {
                if coord
                    .set_segment_data(route.segment_index, assembled)
                    .is_err()
                {
                    self.status.state = PropagationClientState::Failed;
                    return;
                }
                if let Some(meta) = metadata {
                    coord.set_metadata(meta);
                }
                if coord.is_complete() {
                    match coord.reassemble() {
                        Ok(payload) => complete_payload = Some(payload),
                        Err(_) => {
                            self.status.state = PropagationClientState::Failed;
                            return;
                        }
                    }
                }
            }
            if let Some(payload) = complete_payload {
                self.inbound_split_resources.remove(&route.original_hash);
                self.handle_resource_response_payload(&payload);
            }
        } else {
            self.handle_resource_response_payload(&assembled);
        }
    }

    fn handle_resource_response_payload(&mut self, payload: &[u8]) {
        let response_data = {
            let Some(link) = self.link.as_mut() else {
                return;
            };
            match link.handle_response_plaintext(payload) {
                Ok((_request_id, response_data)) => response_data,
                Err(_) => {
                    self.status.state = PropagationClientState::Failed;
                    return;
                }
            }
        };
        self.handle_response_data(&response_data);
    }

    fn send_encrypted_resource_control(
        &self,
        context: rns_wire::context::PacketContext,
        plaintext: &[u8],
    ) {
        if let Some(link) = self.link.as_ref() {
            if let Ok(encrypted) = link.encrypt(plaintext) {
                self.send_link_packet(context, rns_wire::flags::PacketType::Data, &encrypted);
            }
        }
    }

    fn send_resource_proof(&self, proof: &[u8]) {
        self.send_link_packet(
            rns_wire::context::PacketContext::ResourcePrf,
            rns_wire::flags::PacketType::Proof,
            proof,
        );
    }

    fn send_link_packet(
        &self,
        context: rns_wire::context::PacketContext,
        packet_type: rns_wire::flags::PacketType,
        payload: &[u8],
    ) {
        let Some(link_id) = self.link_id else {
            return;
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
        let _ = self
            .transport_tx
            .try_send(TransportMessage::Outbound(OutboundRequest {
                raw: Bytes::from(raw),
                destination_hash: link_id,
            }));
    }

    /// Phase 1: parse available transient IDs from the server.
    fn handle_list_response(&mut self, response_data: &[u8]) {
        let value: rmpv::Value = match rmpv::decode::read_value(&mut &response_data[..]) {
            Ok(v) => v,
            Err(_) => {
                self.status.state = PropagationClientState::Failed;
                return;
            }
        };

        if let Some(arr) = value.as_array() {
            self.available_messages.clear();
            for item in arr {
                if let Some(id_bytes) = item.as_slice() {
                    if id_bytes.len() == 32 {
                        self.available_messages.push(id_bytes.to_vec());
                    }
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
            self.status.state = PropagationClientState::Failed;
        }
    }

    /// Phase 2: parse received message data.
    fn handle_get_response(&mut self, response_data: &[u8]) {
        let value: rmpv::Value = match rmpv::decode::read_value(&mut &response_data[..]) {
            Ok(v) => v,
            Err(_) => {
                self.status.state = PropagationClientState::Failed;
                return;
            }
        };

        if let Some(arr) = value.as_array() {
            let mut received = 0usize;
            for item in arr {
                if let Some(msg_data) = item.as_slice() {
                    let tid = rns_crypto::sha::full_hash(msg_data);
                    self.received_ids.push(tid.to_vec());
                    self.received_messages.push(msg_data.to_vec());
                    received += 1;
                }
            }
            self.status.progress = 1.0;
            self.status.result = Some(received);

            if !self.received_ids.is_empty() {
                self.send_purge_request();
            } else {
                self.status.state = PropagationClientState::Complete;
            }
        } else {
            self.status.state = PropagationClientState::Failed;
        }
    }

    /// Phase 3: mark the download complete.
    fn handle_purge_response(&mut self) {
        self.status.state = PropagationClientState::Complete;
        self.status.progress = 1.0;
    }

    pub fn tick(&mut self) {
        if let Some(started) = self.started_at {
            if started.elapsed() > self.timeout
                && self.status.state != PropagationClientState::Idle
                && self.status.state != PropagationClientState::Complete
            {
                self.cleanup();
                self.status.state = PropagationClientState::Failed;
                return;
            }
        }

        match self.status.state {
            PropagationClientState::Idle => {}
            PropagationClientState::LinkEstablishing => {}
            PropagationClientState::LinkEstablished => {
                if !self.identified {
                    self.send_identify();
                    self.identified = true;
                }
                self.send_list_request();
            }
            PropagationClientState::ListRequested
            | PropagationClientState::GetRequested
            | PropagationClientState::Receiving
            | PropagationClientState::PurgeRequested => {}
            PropagationClientState::Complete | PropagationClientState::Failed => {
                self.cleanup();
            }
        }
    }

    fn send_identify(&mut self) {
        if let (Some(link), Some(link_id)) = (&mut self.link, self.link_id) {
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
                    let _ =
                        self.transport_tx
                            .try_send(TransportMessage::Outbound(OutboundRequest {
                                raw: Bytes::from(id_raw),
                                destination_hash: link_id,
                            }));
                }
            }
        }
    }

    /// Phase 1: `/get` with `[None, None]`.
    fn send_list_request(&mut self) {
        use rmpv::Value;

        self.receiving_for = None;
        let request_data = {
            let array = Value::Array(vec![Value::Nil, Value::Nil]);
            crate::encode_value(&array)
        };

        if self.send_get_path_request(&request_data) {
            self.status.state = PropagationClientState::ListRequested;
        } else {
            self.status.state = PropagationClientState::Failed;
        }
    }

    /// Phase 2: `/get` with `[wants, haves, delivery_limit]`.
    fn send_get_request(&mut self) {
        use rmpv::Value;

        self.status.progress = 0.0;
        self.status.data_size = None;
        self.status.result = None;
        self.receiving_for = None;

        let wants: Vec<Value> = self
            .available_messages
            .iter()
            .filter(|id| !self.local_messages.contains(*id))
            .map(|id| Value::Binary(id.clone()))
            .collect();

        // haves are messages we already hold; sending them lets the server purge.
        let haves: Vec<Value> = self
            .available_messages
            .iter()
            .filter(|id| self.local_messages.contains(*id))
            .map(|id| Value::Binary(id.clone()))
            .collect();

        if wants.is_empty() {
            if haves.is_empty() {
                self.status.state = PropagationClientState::Complete;
                self.status.progress = 1.0;
                self.status.result = Some(0);
                return;
            }
            let array = Value::Array(vec![Value::Nil, Value::Array(haves)]);
            let buf = crate::encode_value(&array);
            if self.send_get_path_request(&buf) {
                self.status.state = PropagationClientState::PurgeRequested;
            } else {
                self.status.state = PropagationClientState::Failed;
            }
            return;
        }

        let mut elements = vec![Value::Array(wants), Value::Array(haves)];
        if let Some(limit) = self.delivery_limit {
            elements.push(Value::F64(limit));
        }

        let array = Value::Array(elements);
        let buf = crate::encode_value(&array);

        if self.send_get_path_request(&buf) {
            self.status.state = PropagationClientState::GetRequested;
        } else {
            self.status.state = PropagationClientState::Failed;
        }
    }

    /// Phase 3: `/get` with `[None, received_ids]`.
    fn send_purge_request(&mut self) {
        use rmpv::Value;

        self.receiving_for = None;
        let received: Vec<Value> = self
            .received_ids
            .iter()
            .map(|id| Value::Binary(id.clone()))
            .collect();

        let array = Value::Array(vec![Value::Nil, Value::Array(received)]);
        let buf = crate::encode_value(&array);

        if self.send_get_path_request(&buf) {
            self.status.state = PropagationClientState::PurgeRequested;
        } else {
            self.status.state = PropagationClientState::Failed;
        }
    }

    /// Send a msgpack request to the `MESSAGE_GET_PATH` endpoint; returns `true`
    /// if the request was dispatched successfully.
    fn send_get_path_request(&mut self, request_data: &[u8]) -> bool {
        if let Some(ref mut link) = self.link {
            match link.request(
                MESSAGE_GET_PATH,
                Some(request_data),
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
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
        false
    }

    fn cleanup(&mut self) {
        self.send_teardown();
        if let Some(link_id) = self.link_id.take() {
            let _ = self
                .transport_tx
                .try_send(TransportMessage::DeregisterDestination { hash: link_id });
        }
        self.link = None;
        self.inbound_resources.clear();
        self.inbound_split_resources.clear();
        self.segment_routing.clear();
        self.receiving_for = None;
        self.started_at = None;
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
            self.send_link_packet(
                rns_wire::context::PacketContext::LinkClose,
                rns_wire::flags::PacketType::Data,
                &teardown_data,
            );
            tracing::debug!(
                link_id = hex::encode(link_id),
                "propagation client link closed"
            );
        }
    }

    pub fn received_count(&self) -> usize {
        self.received_messages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_protocol::resource::OutboundTransfer;

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
        assert!(matches!(outbound.unwrap(), TransportMessage::Outbound(_)));
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
    fn test_take_received_messages() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);

        client.received_messages.push(vec![0x01, 0x02]);
        client.received_messages.push(vec![0x03, 0x04]);
        assert_eq!(client.received_count(), 2);

        let messages = client.take_received_messages();
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

        client.handle_get_response(&buf);
        assert_eq!(client.received_messages.len(), 2);
        assert_eq!(client.received_messages[0], msg1);
        assert_eq!(client.received_messages[1], msg2);
        assert_eq!(client.received_ids.len(), 2);
        assert_eq!(
            client.received_ids[0],
            rns_crypto::sha::full_hash(&msg1).to_vec()
        );
        assert_eq!(client.received_ids[0].len(), 32);
        assert_eq!(client.transfer_status().progress, 1.0);
        assert_eq!(client.transfer_status().result, Some(2));
    }

    #[test]
    fn test_handle_get_response_empty() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.status.state = PropagationClientState::GetRequested;

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

        let response = rmpv::Value::Array(vec![]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &response).unwrap();
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

        let payload = vec![0xAB; 3_000];
        let mut sender = OutboundTransfer::new_encrypted(
            payload.clone(),
            false,
            Duration::from_millis(50),
            responder.session_keys().unwrap(),
        )
        .unwrap();
        sender.resource.flags.is_response = true;
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

        let request = match rx.try_recv().unwrap() {
            TransportMessage::Outbound(request) => request,
            other => panic!("expected Resource request, got {other:?}"),
        };
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
    fn test_handle_purge_response() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.status.state = PropagationClientState::PurgeRequested;

        client.handle_purge_response();
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
    fn test_cleanup_deregisters() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xDD; 16]);
        client.start_download();
        while rx.try_recv().is_ok() {}

        client.status.state = PropagationClientState::Complete;
        client.tick();

        let dereg = rx.try_recv();
        assert!(matches!(
            dereg.unwrap(),
            TransportMessage::DeregisterDestination { .. }
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
        client.status.state = PropagationClientState::ListRequested;
        client.started_at = Some(Instant::now());

        let close_body = responder_link
            .teardown(CloseReason::InitiatorClosed)
            .expect("remote active link emits authenticated teardown");
        client
            .event_tx
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

        client.drain_events(&std::collections::HashMap::new());
        assert_eq!(client.status.state, PropagationClientState::Failed);

        client.tick();
        assert_eq!(client.status.state, PropagationClientState::Failed);
        assert!(client.link.is_none());
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::DeregisterDestination { hash } if hash == link_id
        ));
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
        client.status.state = PropagationClientState::ListRequested;

        client
            .event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &[0u8]),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();

        client.drain_events(&std::collections::HashMap::new());
        assert_eq!(client.status.state, PropagationClientState::ListRequested);
        assert!(client.link.is_some());
    }
}
