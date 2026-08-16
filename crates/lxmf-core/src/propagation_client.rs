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

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_link::link::{CloseReason, Link, LinkAction};
use rns_protocol::resource::{
    InboundTransfer, MAX_SEGMENTS, MultiSegmentInbound, RANDOM_HASH_SIZE, ResourceError,
    TransferAction,
};
use rns_protocol::resource_adv::ResourceAdvertisement;
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    InterfaceId, LinkEndpointBindResult, LinkEndpointBinding, LinkEndpointLifecycleEvent,
    LinkEndpointRole, LinkEndpointSendResult, LinkEndpointUnbindResult, OutboundRequest,
    TransportMessage,
};
use tokio::sync::{mpsc, oneshot};

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

struct PendingEndpointBind {
    interface_id: InterfaceId,
    rtt_request: OutboundRequest,
    result_rx: oneshot::Receiver<LinkEndpointBindResult>,
}

enum EndpointSendSuccess {
    None,
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
    /// Phase 2 response: downloaded LXMF message data.
    received_messages: Vec<Vec<u8>>,
    /// IDs of messages successfully received (drives the Phase 3 purge).
    received_ids: Vec<Vec<u8>>,
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
        let (endpoint_lifecycle_tx, endpoint_lifecycle_rx) = mpsc::unbounded_channel();
        Self {
            transport_tx,
            event_tx,
            event_rx,
            outbound_propagation_node: None,
            link: None,
            link_id: None,
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
            received_messages: Vec::new(),
            received_ids: Vec::new(),
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
        self.local_messages.insert(transient_id.to_vec());
    }

    pub fn add_local_message_id(&mut self, transient_id: Vec<u8>) {
        self.local_messages.insert(transient_id);
    }

    pub fn replace_local_message_ids<I>(&mut self, transient_ids: I)
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        self.local_messages = transient_ids.into_iter().collect();
    }

    pub fn set_retain_synced_on_node(&mut self, retain: bool) {
        self.retain_synced_on_node = retain;
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
        self.start_download_with_limit(None)
    }

    /// Start a propagation download, limiting newly requested messages.
    /// `None` and zero mirror Python's `PR_ALL_MESSAGES`.
    pub fn start_download_with_limit(&mut self, max_messages: Option<usize>) -> bool {
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

        if !self.queue_transport(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: node_hash,
        })) {
            tracing::warn!("failed to stage propagation client Link request");
            self.pending_transport.clear();
            return false;
        }

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
        self.received_ids.clear();
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
                    self.status.state = PropagationClientState::Failed;
                    break;
                }
            }
        }
    }

    fn queue_link_endpoint(&mut self, request: OutboundRequest) -> bool {
        self.queue_link_endpoint_with_success(request, EndpointSendSuccess::None)
    }

    fn queue_link_endpoint_with_success(
        &mut self,
        request: OutboundRequest,
        success: EndpointSendSuccess,
    ) -> bool {
        let Some(link_id) = self.link_id else {
            return false;
        };
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
            match pending.result_rx.try_recv() {
                Ok(LinkEndpointSendResult::Sent | LinkEndpointSendResult::Queued { .. }) => {
                    if self.link_id == Some(pending.link_id)
                        && self.status.state != PropagationClientState::Failed
                    {
                        match pending.success {
                            EndpointSendSuccess::None => {}
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
                    if self.link_id == Some(pending.link_id) {
                        self.status.state = PropagationClientState::Failed;
                    }
                    if pending.final_send {
                        self.queue_endpoint_cleanup(pending.link_id);
                    }
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    if self.link_id == Some(pending.link_id) {
                        self.status.state = PropagationClientState::Failed;
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => still_pending.push(pending),
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
                self.status.state = PropagationClientState::Failed;
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
                    self.status.state = PropagationClientState::Failed;
                }
            }
            Ok(
                LinkEndpointBindResult::Conflict { .. }
                | LinkEndpointBindResult::InterfaceUnavailable,
            )
            | Err(oneshot::error::TryRecvError::Closed) => {
                self.status.state = PropagationClientState::Failed;
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                self.pending_endpoint_bind = Some(pending);
            }
        }
    }

    pub fn drain_events(&mut self, known_identities: &std::collections::HashMap<String, [u8; 64]>) {
        self.poll_endpoint_control();
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }

        for event in events {
            match event {
                DestinationEvent::LinkClosed { link_id } => {
                    self.handle_link_closed(link_id, None);
                }
                DestinationEvent::InboundPacket {
                    raw, interface_id, ..
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
                            if let Some(node_hex) = node_hex {
                                if let Some(pub_key) = known_identities.get(&node_hex) {
                                    let ed25519_bytes: [u8; 32] = pub_key[32..64]
                                        .try_into()
                                        .expect("known_identities values are [u8; 64]; slice [32..64] is always 32 bytes");
                                    if let Ok(verify_key) =
                                        Ed25519PublicKey::from_bytes(&ed25519_bytes)
                                    {
                                        self.handle_link_proof(
                                            data,
                                            &verify_key,
                                            &ed25519_bytes,
                                            interface_id,
                                        );
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
        interface_id: InterfaceId,
    ) {
        let link = match self.link.as_mut() {
            Some(l) => l,
            None => return,
        };

        if let Ok(rtt_data) = link.validate_proof(proof_data, verify_key, ed25519_pub) {
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

                let rtt_request = OutboundRequest {
                    raw: Bytes::from(rtt_raw),
                    destination_hash: link_id,
                };
                let (result_tx, result_rx) = oneshot::channel();
                if !self.queue_transport(TransportMessage::BindLinkEndpoint {
                    binding: LinkEndpointBinding {
                        link_id,
                        interface_id,
                        role: LinkEndpointRole::Initiator,
                    },
                    lifecycle_tx: self.endpoint_lifecycle_tx.clone(),
                    result_tx,
                }) {
                    self.status.state = PropagationClientState::Failed;
                    return;
                }
                self.pending_endpoint_bind = Some(PendingEndpointBind {
                    interface_id,
                    rtt_request,
                    result_rx,
                });
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
                    self.status.state = PropagationClientState::Failed;
                    return;
                }
            }
        };
        if !self.send_resource_proof(&proof) {
            self.status.state = PropagationClientState::Failed;
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

        let Some(pending) = self.pending_endpoint_sends.last_mut() else {
            self.status.state = PropagationClientState::Failed;
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
        if !self.queue_link_endpoint(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: link_id,
        }) {
            self.status.state = PropagationClientState::Failed;
            false
        } else if let Some(link) = self.link.as_mut() {
            link.record_tx(payload.len());
            true
        } else {
            false
        }
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
        self.flush_pending_transport();
        self.poll_endpoint_control();
        if self.status.state == PropagationClientState::Failed {
            self.cleanup();
            return;
        }

        if let Some(started) = self.started_at {
            if started.elapsed() > self.timeout
                && matches!(
                    self.status.state,
                    PropagationClientState::LinkEstablishing
                        | PropagationClientState::ListRequested
                        | PropagationClientState::GetRequested
                        | PropagationClientState::PurgeRequested
                )
            {
                self.cleanup();
                self.status.state = PropagationClientState::Failed;
                return;
            }
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
                self.status.state = PropagationClientState::Failed;
            }
            Some(LinkAction::Closed(_)) => self.status.state = PropagationClientState::Failed,
            Some(LinkAction::None) | None => {}
        }

        if self.status.state == PropagationClientState::Receiving {
            let mut retry_requests = Vec::new();
            for transfer in self.inbound_resources.values_mut() {
                match transfer.check_timeout() {
                    TransferAction::SendRequest(request) => retry_requests.push(request),
                    TransferAction::Failed(_) => {
                        self.status.state = PropagationClientState::Failed;
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
            | PropagationClientState::PurgeRequested => {}
            PropagationClientState::Complete | PropagationClientState::Failed => {
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
        if let Some(outbound) = outbound {
            if !self.queue_link_endpoint(outbound) {
                self.status.state = PropagationClientState::Failed;
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
            self.started_at = Some(Instant::now());
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
            .take(self.max_messages.unwrap_or(usize::MAX))
            .map(|id| Value::Binary(id.clone()))
            .collect();

        // haves are messages we already hold; sending them lets the server purge.
        let haves: Vec<Value> = self
            .available_messages
            .iter()
            .filter(|id| !self.retain_synced_on_node && self.local_messages.contains(*id))
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
                self.started_at = Some(Instant::now());
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
            self.started_at = Some(Instant::now());
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
            self.started_at = Some(Instant::now());
        } else {
            self.status.state = PropagationClientState::Failed;
        }
    }

    /// Send a msgpack request to the `MESSAGE_GET_PATH` endpoint; returns `true`
    /// if the request was dispatched successfully.
    fn send_get_path_request(&mut self, request_data: &[u8]) -> bool {
        let outbound = if let Some(ref mut link) = self.link {
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
                        Some(OutboundRequest {
                            raw: Bytes::from(req_raw),
                            destination_hash: link_id,
                        })
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        } else {
            None
        };
        outbound.is_some_and(|request| self.queue_link_endpoint(request))
    }

    fn cleanup(&mut self) {
        let graceful_release = self.endpoint_release_queued || self.send_teardown();
        if let Some(link_id) = self.link_id.take() {
            if !graceful_release {
                self.queue_endpoint_cleanup(link_id);
            }
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
    use rns_protocol::resource::OutboundTransfer;

    fn next_link_request(rx: &mut mpsc::Receiver<TransportMessage>) -> OutboundRequest {
        while let Ok(message) = rx.try_recv() {
            match message {
                TransportMessage::Outbound(request) => return request,
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
        assert!(matches!(outbound.unwrap(), TransportMessage::Outbound(_)));
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
            TransportMessage::Outbound(_)
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

        let response = rmpv::Value::Array(vec![rmpv::Value::Binary(vec![0xAC; 32])]);
        let mut sender = OutboundTransfer::new_encrypted(
            crate::encode_value(&response),
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
