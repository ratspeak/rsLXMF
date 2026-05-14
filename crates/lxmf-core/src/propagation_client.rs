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
    /// `/get` with `[None, received_ids]` sent.
    PurgeRequested,
    Complete,
    Failed,
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
    pub state: PropagationClientState,
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
            state: PropagationClientState::Idle,
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

    pub fn start_download(&mut self) -> bool {
        let node_hash = match self.outbound_propagation_node {
            Some(h) => h,
            None => return false,
        };

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

        self.link = Some(link);
        self.link_id = Some(link_id);
        self.state = PropagationClientState::LinkEstablishing;
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
                            if self.state != PropagationClientState::LinkEstablishing {
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
                                    self.handle_link_proof(data, &verify_key, &ed25519_bytes);
                                }
                            }
                        }
                        rns_wire::context::PacketContext::Response => {
                            if let Some(ref mut link) = self.link
                                && let Ok((_request_id, response_data)) = link.handle_response(data)
                            {
                                self.handle_response_data(&response_data);
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
            self.state = PropagationClientState::Failed;
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
                self.state = PropagationClientState::LinkEstablished;
            }
            Err(_) => {
                self.state = PropagationClientState::Failed;
            }
        }
    }

    fn handle_response_data(&mut self, response_data: &[u8]) {
        match self.state {
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
            self.state = PropagationClientState::Failed;
            return;
        };
        let Ok(adv) = ResourceAdvertisement::unpack(&plaintext) else {
            self.state = PropagationClientState::Failed;
            return;
        };

        if !adv.flags.is_response {
            return;
        }

        if adv.total_segments > 1 {
            if adv.total_segments > MAX_SEGMENTS
                || adv.segment_index == 0
                || adv.segment_index > adv.total_segments
            {
                self.state = PropagationClientState::Failed;
                return;
            }

            let entry = self
                .inbound_split_resources
                .entry(adv.original_hash)
                .or_insert_with(|| MultiSegmentInbound::new(adv.total_segments, adv.original_hash));
            if entry.total_segments != adv.total_segments {
                self.state = PropagationClientState::Failed;
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
            self.state = PropagationClientState::Failed;
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
                    self.state = PropagationClientState::Failed;
                    return;
                }
                _ => {}
            }

            if transfer.resource.is_complete() {
                completed = Some(*resource_hash);
            }

            if completed.is_some() || !control_actions.is_empty() {
                break;
            }
        }

        for (context, payload) in control_actions {
            self.send_encrypted_resource_control(context, &payload);
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
                self.state = PropagationClientState::Failed;
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
        self.state = PropagationClientState::Failed;
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
                    self.state = PropagationClientState::Failed;
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
                    self.state = PropagationClientState::Failed;
                    return;
                }
                if let Some(meta) = metadata {
                    coord.set_metadata(meta);
                }
                if coord.is_complete() {
                    match coord.reassemble() {
                        Ok(payload) => complete_payload = Some(payload),
                        Err(_) => {
                            self.state = PropagationClientState::Failed;
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
                    self.state = PropagationClientState::Failed;
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
        if let Some(link) = self.link.as_ref()
            && let Ok(encrypted) = link.encrypt(plaintext)
        {
            self.send_link_packet(context, rns_wire::flags::PacketType::Data, &encrypted);
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
                self.state = PropagationClientState::Failed;
                return;
            }
        };

        if let Some(arr) = value.as_array() {
            self.available_messages.clear();
            for item in arr {
                if let Some(id_bytes) = item.as_slice()
                    && id_bytes.len() == 32
                {
                    self.available_messages.push(id_bytes.to_vec());
                }
            }

            if self.available_messages.is_empty() {
                self.state = PropagationClientState::Complete;
            } else {
                self.send_get_request();
            }
        } else {
            self.state = PropagationClientState::Failed;
        }
    }

    /// Phase 2: parse received message data.
    fn handle_get_response(&mut self, response_data: &[u8]) {
        let value: rmpv::Value = match rmpv::decode::read_value(&mut &response_data[..]) {
            Ok(v) => v,
            Err(_) => {
                self.state = PropagationClientState::Failed;
                return;
            }
        };

        if let Some(arr) = value.as_array() {
            for item in arr {
                if let Some(msg_data) = item.as_slice() {
                    let tid = rns_crypto::sha::full_hash(msg_data);
                    self.received_ids.push(tid.to_vec());
                    self.received_messages.push(msg_data.to_vec());
                }
            }

            if !self.received_ids.is_empty() {
                self.send_purge_request();
            } else {
                self.state = PropagationClientState::Complete;
            }
        } else {
            self.state = PropagationClientState::Failed;
        }
    }

    /// Phase 3: mark the download complete.
    fn handle_purge_response(&mut self) {
        self.state = PropagationClientState::Complete;
    }

    pub fn tick(&mut self) {
        if let Some(started) = self.started_at
            && started.elapsed() > self.timeout
            && self.state != PropagationClientState::Idle
            && self.state != PropagationClientState::Complete
        {
            self.cleanup();
            self.state = PropagationClientState::Failed;
            return;
        }

        match self.state {
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
            | PropagationClientState::PurgeRequested => {}
            PropagationClientState::Complete | PropagationClientState::Failed => {
                self.cleanup();
                self.state = PropagationClientState::Idle;
            }
        }
    }

    fn send_identify(&mut self) {
        if let (Some(link), Some(link_id)) = (&mut self.link, self.link_id)
            && let (Some(pub_key), Some(sign_key)) = (&self.identity_pub, &self.identity_key)
            && let Ok(identify_data) = link.identify(pub_key, sign_key)
        {
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
        }
    }

    /// Phase 1: `/get` with `[None, None]`.
    fn send_list_request(&mut self) {
        use rmpv::Value;

        let request_data = {
            let array = Value::Array(vec![Value::Nil, Value::Nil]);
            crate::encode_value(&array)
        };

        if self.send_get_path_request(&request_data) {
            self.state = PropagationClientState::ListRequested;
        } else {
            self.state = PropagationClientState::Failed;
        }
    }

    /// Phase 2: `/get` with `[wants, haves, delivery_limit]`.
    fn send_get_request(&mut self) {
        use rmpv::Value;

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
                self.state = PropagationClientState::Complete;
                return;
            }
            let array = Value::Array(vec![Value::Nil, Value::Array(haves)]);
            let buf = crate::encode_value(&array);
            if self.send_get_path_request(&buf) {
                self.state = PropagationClientState::PurgeRequested;
            } else {
                self.state = PropagationClientState::Failed;
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
            self.state = PropagationClientState::GetRequested;
        } else {
            self.state = PropagationClientState::Failed;
        }
    }

    /// Phase 3: `/get` with `[None, received_ids]`.
    fn send_purge_request(&mut self) {
        use rmpv::Value;

        let received: Vec<Value> = self
            .received_ids
            .iter()
            .map(|id| Value::Binary(id.clone()))
            .collect();

        let array = Value::Array(vec![Value::Nil, Value::Array(received)]);
        let buf = crate::encode_value(&array);

        if self.send_get_path_request(&buf) {
            self.state = PropagationClientState::PurgeRequested;
        } else {
            self.state = PropagationClientState::Failed;
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
        assert_eq!(client.state, PropagationClientState::Idle);
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
        assert_eq!(client.state, PropagationClientState::Idle);
    }

    #[test]
    fn test_start_download_sends_link_request() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xBB; 16]);

        assert!(client.start_download());
        assert_eq!(client.state, PropagationClientState::LinkEstablishing);
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
        client.state = PropagationClientState::ListRequested;

        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &rmpv::Value::Array(vec![])).unwrap();

        client.handle_list_response(&buf);
        assert_eq!(client.state, PropagationClientState::Complete);
    }

    #[test]
    fn test_handle_list_response_invalid() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.state = PropagationClientState::ListRequested;

        client.handle_list_response(&[0xFF, 0xFF]);
        assert_eq!(client.state, PropagationClientState::Failed);
    }

    #[test]
    fn test_handle_list_response_accepts_python_full_hash_ids() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.state = PropagationClientState::ListRequested;

        let id32 = vec![0xAB; 32];
        let response = rmpv::Value::Array(vec![rmpv::Value::Binary(id32.clone())]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &response).unwrap();

        client.handle_list_response(&buf);
        assert_eq!(client.available_messages, vec![id32]);
        // It accepted the 32-byte ID, then failed only because this unit test
        // has no live link on which to send the follow-up `/get`.
        assert_eq!(client.state, PropagationClientState::Failed);
    }

    #[test]
    fn test_handle_get_response_parses_messages() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xBB; 16]);
        client.start_download();
        client.state = PropagationClientState::GetRequested;

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
    }

    #[test]
    fn test_handle_get_response_empty() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.state = PropagationClientState::GetRequested;

        let response = rmpv::Value::Array(vec![]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &response).unwrap();

        client.handle_get_response(&buf);
        assert_eq!(client.state, PropagationClientState::Complete);
    }

    #[test]
    fn test_handle_purge_response() {
        let (tx, _rx) = mpsc::channel(16);
        let mut client = PropagationClient::new(tx, None, None);
        client.state = PropagationClientState::PurgeRequested;

        client.handle_purge_response();
        assert_eq!(client.state, PropagationClientState::Complete);
    }

    #[test]
    fn test_timeout_fails() {
        let (tx, _rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xCC; 16]);
        client.start_download();
        assert_eq!(client.state, PropagationClientState::LinkEstablishing);

        client.timeout = Duration::ZERO;

        client.tick();
        assert_eq!(client.state, PropagationClientState::Failed);

        client.tick();
        assert_eq!(client.state, PropagationClientState::Idle);
    }

    #[test]
    fn test_cleanup_deregisters() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut client = PropagationClient::new(tx, None, None);
        client.set_propagation_node([0xDD; 16]);
        client.start_download();
        while rx.try_recv().is_ok() {}

        client.state = PropagationClientState::Complete;
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
        client.state = PropagationClientState::ListRequested;
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
            })
            .unwrap();

        client.drain_events(&std::collections::HashMap::new());
        assert_eq!(client.state, PropagationClientState::Failed);

        client.tick();
        assert_eq!(client.state, PropagationClientState::Idle);
        assert!(client.link.is_none());
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::DeregisterDestination { hash } if hash == link_id
        ));
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
        client.state = PropagationClientState::ListRequested;

        client
            .event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &[0u8]),
                interface_id: 0,
            })
            .unwrap();

        client.drain_events(&std::collections::HashMap::new());
        assert_eq!(client.state, PropagationClientState::ListRequested);
        assert!(client.link.is_some());
    }
}
