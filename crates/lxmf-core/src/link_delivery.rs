//! Link-based LXMF message delivery (Python's Direct delivery mode).
//!
//! Establishes a link to the recipient, identifies the sender, and transfers the message either
//! as a single encrypted link packet or as a Resource over the link. Enables larger-than-MDU
//! messages via resource segmentation, delivery confirmation via link-level proofs, and sender
//! identity verification via link identification.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_link::constants::{ESTABLISHMENT_TIMEOUT_PER_HOP, KEEPALIVE_DEFAULT};
use rns_link::link::{CloseReason, Link, LinkAction, LinkState};
use rns_protocol::resource::{
    MAX_EFFICIENT_SIZE, MultiSegmentOutbound, OutboundResource, OutboundTransfer, ResourceError,
    TransferAction,
};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{OutboundRequest, TransportMessage};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::constants::{DeliveryRepresentation, LXMF_OVERHEAD};
use crate::message::LxMessage;
use crate::propagation::hex_encode;

/// Upstream LXMF keeps reusable Direct links open for ten minutes of data
/// inactivity before tearing them down (`LXMRouter.LINK_MAX_INACTIVITY`).
const LINK_MAX_INACTIVITY: Duration = Duration::from_secs(600);

/// State of a link-based delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    Idle,
    Establishing,
    Identifying,
    Transferring,
    AwaitingProof,
    Complete,
    Failed,
}

/// An in-progress link-based delivery.
pub struct PendingDelivery {
    pub message: LxMessage,
    pub dest_hash: [u8; 16],
    pub packed_override: Option<Vec<u8>>,
    pub auto_compress: bool,
    pub link: Link,
    pub state: DeliveryState,
    pub started_at: Instant,
    /// Resource transfer, populated after the link establishes.
    pub transfer: Option<OutboundTransfer>,
    /// Remaining Reticulum resource segments for payloads larger than one
    /// efficient resource. Segment 1 is stored in `transfer`.
    pub remaining_segments: Vec<OutboundResource>,
    /// Full packet hash of a single link-packet LXMF delivery awaiting LINKPROOF.
    pub packet_proof_hash: Option<[u8; 32]>,
    /// Link establishment timeout. This intentionally excludes keepalive time:
    /// an initiator that never receives LRPROOF should fail on the Link
    /// establishment clock, not on the active-link inactivity clock.
    pub establishment_timeout: Duration,
    /// Full delivery timeout after the link has moved beyond establishment.
    pub timeout: Duration,
    pub msg_hash: Option<[u8; 32]>,
    pub failure_reason: Option<String>,
    /// Keep successful Direct links open for additional messages. Propagation
    /// deposits currently keep the old one-shot behavior.
    pub reusable: bool,
    /// Upstream identifies the initiator after the first successful Direct
    /// delivery, making the link usable as a peer backchannel.
    pub backchannel_identified: bool,
    queued: VecDeque<QueuedDelivery>,
}

/// Message payload waiting for an existing Direct link to become active/idle.
struct QueuedDelivery {
    message: LxMessage,
    packed_override: Option<Vec<u8>>,
    auto_compress: bool,
    msg_hash: Option<[u8; 32]>,
    queued_at: Instant,
}

impl QueuedDelivery {
    fn new(message: LxMessage, packed_override: Option<Vec<u8>>, auto_compress: bool) -> Self {
        let msg_hash = message.hash;
        Self {
            message,
            packed_override,
            auto_compress,
            msg_hash,
            queued_at: Instant::now(),
        }
    }
}

impl PendingDelivery {
    fn active_delivery_count(&self) -> usize {
        let current = if self.state == DeliveryState::Idle {
            0
        } else {
            1
        };
        current + self.queued.len()
    }

    fn queue_delivery(
        &mut self,
        message: LxMessage,
        packed_override: Option<Vec<u8>>,
        auto_compress: bool,
    ) {
        self.queued
            .push_back(QueuedDelivery::new(message, packed_override, auto_compress));
    }

    fn start_queued_delivery(&mut self) -> bool {
        let Some(next) = self.queued.pop_front() else {
            return false;
        };
        self.message = next.message;
        self.packed_override = next.packed_override;
        self.auto_compress = next.auto_compress;
        self.transfer = None;
        self.remaining_segments.clear();
        self.packet_proof_hash = None;
        self.started_at = Instant::now();
        self.msg_hash = next.msg_hash;
        self.failure_reason = None;
        self.state = DeliveryState::Identifying;
        tracing::debug!(
            link_id = %hex_encode(&self.link.link_id),
            dest = %hex_encode(&self.dest_hash),
            queued_for_secs = next.queued_at.elapsed().as_secs_f64(),
            remaining_queue = self.queued.len(),
            "starting queued Direct link delivery"
        );
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkDeliveryStartError {
    TransportFull,
    TransportClosed,
}

impl fmt::Display for LinkDeliveryStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportFull => f.write_str("transport full"),
            Self::TransportClosed => f.write_str("transport closed"),
        }
    }
}

impl std::error::Error for LinkDeliveryStartError {}

#[derive(Debug)]
pub struct LinkDeliveryStartFailure {
    pub error: LinkDeliveryStartError,
    pub message: LxMessage,
}

/// How a Direct delivery was attached to Link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectLinkStartKind {
    /// A new outbound Direct LinkRequest was queued.
    NewDirect,
    /// An existing active Link accepted the message immediately.
    ReusedActiveDirect,
    /// The message was queued behind a pending or busy reusable Link.
    QueuedOnDirect,
}

/// Start result with enough detail for callers to surface upstream-like Direct
/// delivery stages without reimplementing LinkDeliveryManager policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectLinkStartReport {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub kind: DirectLinkStartKind,
    pub link_state: LinkState,
    pub delivery_state: DeliveryState,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

/// Snapshot of a reusable Direct Link session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectLinkSnapshot {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub link_state: LinkState,
    pub delivery_state: DeliveryState,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

/// Aggregate LinkDeliveryManager state for diagnostics and UI event mapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkDeliveryStats {
    pub sessions: usize,
    pub direct_sessions: usize,
    pub one_shot_sessions: usize,
    pub establishing_direct_sessions: usize,
    pub active_direct_sessions: usize,
    pub idle_direct_sessions: usize,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

impl fmt::Display for LinkDeliveryStartFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for LinkDeliveryStartFailure {}

fn start_error_from_reserve(err: TrySendError<()>) -> LinkDeliveryStartError {
    match err {
        TrySendError::Full(_) => LinkDeliveryStartError::TransportFull,
        TrySendError::Closed(_) => LinkDeliveryStartError::TransportClosed,
    }
}

/// Driver for outbound link-based LXMF deliveries.
///
/// Callers invoke [`Self::start_delivery`] to begin, [`Self::drain_events`] to route inbound
/// packets, and [`Self::tick`] periodically to advance transfers and enforce timeouts.
pub struct LinkDeliveryManager {
    transport_tx: mpsc::Sender<TransportMessage>,
    /// Reusable upstream-style Direct links keyed by LXMF delivery destination hash.
    direct_links: HashMap<[u8; 16], [u8; 16]>,
    pending: HashMap<[u8; 16], PendingDelivery>,
    identity_pub: Option<[u8; 64]>,
    identity_key: Option<Ed25519PrivateKey>,
    event_tx: mpsc::Sender<DestinationEvent>,
    event_rx: mpsc::Receiver<DestinationEvent>,
}

impl LinkDeliveryManager {
    pub fn new(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity_pub: Option<[u8; 64]>,
        identity_key: Option<Ed25519PrivateKey>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(256);
        Self {
            transport_tx,
            direct_links: HashMap::new(),
            pending: HashMap::new(),
            identity_pub,
            identity_key,
            event_tx,
            event_rx,
        }
    }

    /// Start a direct delivery and return the tracking `link_id`.
    pub fn start_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
    ) -> Result<[u8; 16], LinkDeliveryStartFailure> {
        self.start_delivery_with_report(message, dest_hash, hops)
            .map(|report| report.link_id)
    }

    /// Start a Direct delivery and return whether it created, reused, or queued
    /// on reusable Link state.
    pub fn start_delivery_with_report(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
    ) -> Result<DirectLinkStartReport, LinkDeliveryStartFailure> {
        self.start_direct_delivery(message, dest_hash, hops)
    }

    /// Start a link delivery with an already-packed payload.
    ///
    /// This is used for LXMF propagation deposits, whose link payload is the
    /// propagation wrapper rather than the regular signed LXMF representation.
    pub fn start_packed_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
        packed_payload: Vec<u8>,
        auto_compress: bool,
    ) -> Result<[u8; 16], LinkDeliveryStartFailure> {
        self.start_delivery_inner(
            message,
            dest_hash,
            hops,
            Some(packed_payload),
            auto_compress,
            false,
        )
    }

    fn start_direct_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
    ) -> Result<DirectLinkStartReport, LinkDeliveryStartFailure> {
        if let Some(link_id) = self.direct_links.get(&dest_hash).copied() {
            if let Some(delivery) = self.pending.get_mut(&link_id)
                && delivery.reusable
            {
                let state = delivery.state;
                let link_state = delivery.link.state;
                let kind = if state == DeliveryState::Idle && delivery.link.is_active() {
                    delivery.queue_delivery(message, None, true);
                    let _ = delivery.start_queued_delivery();
                    DirectLinkStartKind::ReusedActiveDirect
                } else {
                    delivery.queue_delivery(message, None, true);
                    DirectLinkStartKind::QueuedOnDirect
                };
                tracing::debug!(
                    link_id = %hex_encode(&link_id),
                    dest = %hex_encode(&dest_hash),
                    state = ?state,
                    link_state = ?link_state,
                    queued = delivery.queued.len(),
                    pending_count = delivery.active_delivery_count(),
                    "reusing cached Direct link delivery session"
                );
                return Ok(DirectLinkStartReport {
                    link_id,
                    dest_hash,
                    kind,
                    link_state,
                    delivery_state: delivery.state,
                    queued_deliveries: delivery.queued.len(),
                    in_flight_deliveries: usize::from(delivery.state != DeliveryState::Idle),
                });
            }

            self.direct_links.remove(&dest_hash);
        }

        let link_id = self.start_delivery_inner(message, dest_hash, hops, None, true, true)?;
        let snapshot = self.direct_link_snapshot(dest_hash);
        Ok(DirectLinkStartReport {
            link_id,
            dest_hash,
            kind: DirectLinkStartKind::NewDirect,
            link_state: snapshot.map(|s| s.link_state).unwrap_or(LinkState::Pending),
            delivery_state: snapshot
                .map(|s| s.delivery_state)
                .unwrap_or(DeliveryState::Establishing),
            queued_deliveries: 0,
            in_flight_deliveries: 1,
        })
    }

    fn start_delivery_inner(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
        packed_override: Option<Vec<u8>>,
        auto_compress: bool,
        reusable: bool,
    ) -> Result<[u8; 16], LinkDeliveryStartFailure> {
        let msg_hash = message.hash;
        let (link, request_data) = Link::new_initiator(dest_hash, hops);
        let link_id = link.link_id;
        let pending_count = self.pending_count();

        let register_permit = match self.transport_tx.try_reserve() {
            Ok(permit) => permit,
            Err(err) => {
                let error = start_error_from_reserve(err);
                tracing::warn!(
                    link_id = %hex_encode(&link_id),
                    dest = %hex_encode(&dest_hash),
                    hops = hops.max(1),
                    pending_count,
                    register_result = %error,
                    outbound_result = "not_attempted",
                    "failed to start link delivery"
                );
                return Err(LinkDeliveryStartFailure { error, message });
            }
        };

        let outbound_permit = match self.transport_tx.try_reserve() {
            Ok(permit) => permit,
            Err(err) => {
                let error = start_error_from_reserve(err);
                tracing::warn!(
                    link_id = %hex_encode(&link_id),
                    dest = %hex_encode(&dest_hash),
                    hops = hops.max(1),
                    pending_count,
                    register_result = "reserved",
                    outbound_result = %error,
                    "failed to start link delivery"
                );
                return Err(LinkDeliveryStartFailure { error, message });
            }
        };

        // Register the ephemeral link_id so proofs and data route back to us.
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
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&request_data);

        register_permit.send(TransportMessage::RegisterDestination {
            hash: link_id,
            app_name: "lxmf.delivery.link".to_string(),
            delivery_tx: Some(self.event_tx.clone()),
        });
        outbound_permit.send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: dest_hash,
        }));

        let establishment_timeout_secs = ESTABLISHMENT_TIMEOUT_PER_HOP * (hops.max(1) as f64);
        // Full transfer timeout keeps the previous keepalive allowance once
        // establishment has succeeded.
        let timeout_secs = establishment_timeout_secs + KEEPALIVE_DEFAULT;
        self.pending.insert(
            link_id,
            PendingDelivery {
                message,
                dest_hash,
                packed_override,
                auto_compress,
                link,
                state: DeliveryState::Establishing,
                started_at: Instant::now(),
                transfer: None,
                remaining_segments: Vec::new(),
                packet_proof_hash: None,
                establishment_timeout: Duration::from_secs_f64(establishment_timeout_secs),
                timeout: Duration::from_secs_f64(timeout_secs),
                msg_hash,
                failure_reason: None,
                reusable,
                backchannel_identified: false,
                queued: VecDeque::new(),
            },
        );
        if reusable {
            self.direct_links.insert(dest_hash, link_id);
        }

        tracing::debug!(
            link_id = %hex_encode(&link_id),
            dest = %hex_encode(&dest_hash),
            hops = hops.max(1),
            pending_count,
            reusable,
            register_result = "ok",
            outbound_result = "ok",
            establishment_timeout_secs,
            delivery_timeout_secs = timeout_secs,
            "link delivery started"
        );

        Ok(link_id)
    }

    /// Drain inbound transport events and dispatch by packet context.
    ///
    /// Call before [`Self::tick`] each cycle. Routes `LRPROOF`, `ResourceHmu`, `ResourceReq`,
    /// and `ResourcePrf` contexts to their handlers.
    pub fn drain_events(&mut self, known_identities: &HashMap<String, [u8; 64]>) {
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }

        for event in events {
            match event {
                DestinationEvent::LinkClosed { link_id } => {
                    self.handle_link_closed(&link_id, None);
                }
                DestinationEvent::InboundPacket { raw, .. } => {
                    let (header, data_offset) = match rns_wire::header::PacketHeader::unpack(&raw) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };
                    let data = if raw.len() > data_offset {
                        &raw[data_offset..]
                    } else {
                        &[]
                    };
                    let link_id = header.destination_hash;

                    match header.context {
                        rns_wire::context::PacketContext::Lrproof
                            if header.flags.packet_type == rns_wire::flags::PacketType::Proof =>
                        {
                            let dest_hex =
                                self.pending.get(&link_id).map(|d| hex_encode(&d.dest_hash));

                            if let Some(dest_hex) = dest_hex {
                                if let Some(pub_key) = known_identities.get(&dest_hex) {
                                    let ed25519_bytes: [u8; 32] = pub_key[32..64]
                                        .try_into()
                                        .expect("known_identities values are [u8; 64]; slice [32..64] is always 32 bytes");
                                    if let Ok(verify_key) =
                                        Ed25519PublicKey::from_bytes(&ed25519_bytes)
                                    {
                                        self.handle_link_proof(
                                            &link_id,
                                            data,
                                            &verify_key,
                                            &ed25519_bytes,
                                        );
                                    }
                                } else {
                                    tracing::warn!(
                                        link_id = %hex_encode(&link_id),
                                        dest = %dest_hex,
                                        "LRPROOF received but destination identity key is not cached; ignoring proof"
                                    );
                                }
                            }
                        }
                        rns_wire::context::PacketContext::None
                            if header.flags.packet_type == rns_wire::flags::PacketType::Proof =>
                        {
                            // Python `Link.prove_packet()` sends packet proofs on a LINK
                            // destination with PROOF type and the default/None context. LRPROOF
                            // handling also accepts None on some older paths, so disambiguate by
                            // the delivery state.
                            if self
                                .pending
                                .get(&link_id)
                                .is_some_and(|d| d.state == DeliveryState::AwaitingProof)
                            {
                                self.handle_link_packet_proof(&link_id, data);
                            } else {
                                let dest_hex =
                                    self.pending.get(&link_id).map(|d| hex_encode(&d.dest_hash));

                                if let Some(dest_hex) = dest_hex {
                                    if let Some(pub_key) = known_identities.get(&dest_hex) {
                                        let ed25519_bytes: [u8; 32] = pub_key[32..64]
                                            .try_into()
                                            .expect("known_identities values are [u8; 64]; slice [32..64] is always 32 bytes");
                                        if let Ok(verify_key) =
                                            Ed25519PublicKey::from_bytes(&ed25519_bytes)
                                        {
                                            self.handle_link_proof(
                                                &link_id,
                                                data,
                                                &verify_key,
                                                &ed25519_bytes,
                                            );
                                        }
                                    } else {
                                        tracing::warn!(
                                            link_id = %hex_encode(&link_id),
                                            dest = %dest_hex,
                                            "LRPROOF received but destination identity key is not cached; ignoring proof"
                                        );
                                    }
                                }
                            }
                        }
                        rns_wire::context::PacketContext::LinkProof
                            if header.flags.packet_type == rns_wire::flags::PacketType::Proof =>
                        {
                            self.handle_link_packet_proof(&link_id, data);
                        }
                        rns_wire::context::PacketContext::ResourceHmu => {
                            let plaintext = self
                                .pending
                                .get(&link_id)
                                .and_then(|d| d.link.decrypt(data).ok());
                            if let Some(pt) = plaintext {
                                self.handle_hmu(&link_id, &pt);
                            }
                        }
                        rns_wire::context::PacketContext::ResourceReq => {
                            // Python `Resource.request_next` may arrive before any HMU and be the
                            // only signal to advance the transfer, so drive it here directly.
                            let plaintext = self
                                .pending
                                .get(&link_id)
                                .and_then(|d| d.link.decrypt(data).ok());
                            if let Some(pt) = plaintext {
                                self.handle_request(&link_id, &pt);
                            }
                        }
                        rns_wire::context::PacketContext::ResourcePrf => {
                            // PROOF+RESOURCE_PRF is plaintext on a Proof packet (Packet.py:195-197).
                            // Body = resource_hash(32) || proof(32); pass through without decrypt.
                            self.handle_resource_proof(&link_id, data);
                        }
                        rns_wire::context::PacketContext::ResourceRcl => {
                            // Receiver-cancel/reject packets are link-encrypted and carry
                            // the rejected resource_hash.
                            let plaintext = self
                                .pending
                                .get(&link_id)
                                .and_then(|d| d.link.decrypt(data).ok());
                            if let Some(pt) = plaintext {
                                self.handle_resource_reject(&link_id, &pt);
                            }
                        }
                        rns_wire::context::PacketContext::Keepalive => {
                            if let Some(delivery) = self.pending.get_mut(&link_id) {
                                delivery.link.record_inbound();
                            }
                        }
                        rns_wire::context::PacketContext::LinkClose => {
                            self.handle_link_closed(&link_id, Some(data));
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    /// Validate an inbound `LRPROOF`, complete the handshake, and transition to
    /// [`DeliveryState::Identifying`].
    pub fn handle_link_proof(
        &mut self,
        link_id: &[u8; 16],
        proof_data: &[u8],
        identity_verify_key: &Ed25519PublicKey,
        identity_ed25519_pub: &[u8; 32],
    ) -> bool {
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };

        if delivery.state != DeliveryState::Establishing {
            return false;
        }

        match delivery
            .link
            .validate_proof(proof_data, identity_verify_key, identity_ed25519_pub)
        {
            Ok(rtt_data) => {
                // Message 3 of the handshake: RTT.
                let rtt_flags = rns_wire::flags::PacketFlags {
                    header_type: rns_wire::flags::HeaderType::Header1,
                    context_flag: false,
                    transport_type: rns_wire::flags::TransportType::Broadcast,
                    destination_type: rns_wire::flags::DestinationType::Link,
                    packet_type: rns_wire::flags::PacketType::Data,
                };
                let rtt_header = rns_wire::header::PacketHeader {
                    flags: rtt_flags,
                    hops: 0,
                    transport_id: None,
                    destination_hash: *link_id,
                    context: rns_wire::context::PacketContext::Lrrtt,
                };
                let mut rtt_raw = rtt_header.pack();
                rtt_raw.extend_from_slice(&rtt_data);

                let _ = self
                    .transport_tx
                    .try_send(TransportMessage::Outbound(OutboundRequest {
                        raw: Bytes::from(rtt_raw),
                        destination_hash: *link_id,
                    }));

                delivery.state = DeliveryState::Identifying;
                true
            }
            Err(e) => {
                let _ = e;
                delivery.state = DeliveryState::Failed;
                delivery.failure_reason = Some("link proof validation failed".to_string());
                false
            }
        }
    }

    /// Drive pending deliveries forward; call periodically after [`Self::drain_events`].
    pub fn tick(&mut self) -> Vec<DeliveryResult> {
        let mut results = Vec::new();
        let mut to_remove = Vec::new();

        for (link_id, delivery) in &mut self.pending {
            let mut remove_session = false;

            if delivery.state == DeliveryState::Idle
                && !delivery.queued.is_empty()
                && delivery.link.is_active()
            {
                let _ = delivery.start_queued_delivery();
            }

            if matches!(
                delivery.state,
                DeliveryState::Establishing
                    | DeliveryState::Identifying
                    | DeliveryState::Transferring
                    | DeliveryState::AwaitingProof
            ) {
                let elapsed = delivery.started_at.elapsed();
                let (timed_out, timeout, reason) = if delivery.state == DeliveryState::Establishing
                {
                    (
                        elapsed > delivery.establishment_timeout,
                        delivery.establishment_timeout,
                        "link establishment timeout",
                    )
                } else {
                    (
                        elapsed > delivery.timeout,
                        delivery.timeout,
                        "delivery timeout",
                    )
                };

                if timed_out {
                    let state = delivery.state;
                    delivery.state = DeliveryState::Failed;
                    delivery.failure_reason = Some(reason.to_string());
                    tracing::warn!(
                        link_id = %hex_encode(link_id),
                        dest = %hex_encode(&delivery.dest_hash),
                        state = ?state,
                        age_secs = elapsed.as_secs_f64(),
                        timeout_secs = timeout.as_secs_f64(),
                        reason,
                        queued = delivery.queued.len(),
                        "link delivery timed out"
                    );
                    push_failed_delivery_and_queue(&mut results, *link_id, delivery, reason);
                    remove_session = true;
                }
            }

            if !remove_session {
                match delivery.state {
                    DeliveryState::Idle => {}
                    DeliveryState::Identifying if delivery.link.is_active() => {
                        if !delivery.reusable
                            && let (Some(pub_key), Some(sign_key)) =
                                (&self.identity_pub, &self.identity_key)
                            && let Ok(identify_data) = delivery.link.identify(pub_key, sign_key)
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
                                destination_hash: *link_id,
                                context: rns_wire::context::PacketContext::LinkIdentify,
                            };
                            let mut id_raw = id_header.pack();
                            id_raw.extend_from_slice(&identify_data);
                            let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                                OutboundRequest {
                                    raw: Bytes::from(id_raw),
                                    destination_hash: *link_id,
                                },
                            ));
                        }
                        // Reusable Direct links follow upstream LXMF and identify
                        // after a successful delivery, not before the transfer.
                        // One-shot propagation links keep the previous pre-transfer
                        // identify behavior for compatibility with existing callers.
                        delivery.state = DeliveryState::Transferring;

                        let packed = if let Some(ref packed) = delivery.packed_override {
                            Ok(packed.clone())
                        } else {
                            delivery.message.pack()
                        };
                        if let Ok(packed) = packed {
                            let packet_limit = if delivery.packed_override.is_some() {
                                delivery.link.mdu.saturating_sub(LXMF_OVERHEAD)
                            } else {
                                delivery.link.mdu
                            };
                            if packed.len() <= packet_limit {
                                // Python LXMessage sends Direct messages that fit in Link.MDU
                                // as a single encrypted link packet, then waits for LINKPROOF.
                                delivery.message.representation = DeliveryRepresentation::Packet;
                                match send_link_packet(
                                    link_id,
                                    delivery,
                                    &self.transport_tx,
                                    &packed,
                                ) {
                                    Some(packet_hash) => {
                                        delivery.packet_proof_hash = Some(packet_hash);
                                        delivery.state = DeliveryState::AwaitingProof;
                                    }
                                    None => {
                                        delivery.state = DeliveryState::Failed;
                                        delivery.failure_reason =
                                            Some("link packet encryption failed".to_string());
                                    }
                                }
                            } else {
                                delivery.message.representation = DeliveryRepresentation::Resource;
                                // Python's Resource encrypts the blob with link session keys
                                // BEFORE chunking (Resource.py:424), and resource parts are sent
                                // on the wire WITHOUT additional packet-layer encryption
                                // (Packet.py:201-204).
                                let rtt = delivery.link.rtt.unwrap_or(Duration::from_millis(500));
                                let auto_compress = if delivery.packed_override.is_some() {
                                    delivery.auto_compress
                                } else {
                                    delivery.message.auto_compress
                                };
                                let transfer_result = build_resource_transfer(
                                    &delivery.link,
                                    packed,
                                    auto_compress,
                                    rtt,
                                );
                                match transfer_result {
                                    Ok((transfer, remaining_segments)) => {
                                        delivery.transfer = Some(transfer);
                                        delivery.remaining_segments = remaining_segments;
                                    }
                                    Err(e) => {
                                        let _ = e;
                                        delivery.state = DeliveryState::Failed;
                                        delivery.failure_reason =
                                            Some("resource transfer build failed".to_string());
                                    }
                                }
                            }
                        }
                    }
                    DeliveryState::Identifying => {}
                    DeliveryState::Transferring => {
                        // Process up to a full window of actions per tick so the 500ms tick rate
                        // doesn't throttle us below link speed.
                        let max_actions = 16;
                        for _ in 0..max_actions {
                            if delivery.state != DeliveryState::Transferring {
                                break;
                            }
                            let Some(ref mut transfer) = delivery.transfer else {
                                break;
                            };
                            let action = transfer.tick();
                            match dispatch_action(link_id, delivery, &self.transport_tx, action) {
                                ActionOutcome::Continue => continue,
                                ActionOutcome::Break => break,
                                ActionOutcome::Complete => {
                                    results.push(DeliveryResult::Complete {
                                        link_id: *link_id,
                                        msg_hash: delivery.msg_hash,
                                    });
                                    if delivery.reusable && delivery.link.state != LinkState::Closed
                                    {
                                        finish_reusable_delivery(
                                            &self.transport_tx,
                                            &self.identity_pub,
                                            &self.identity_key,
                                            link_id,
                                            delivery,
                                        );
                                    } else {
                                        fail_queued_deliveries(
                                            &mut results,
                                            *link_id,
                                            delivery,
                                            "link closed",
                                        );
                                        remove_session = true;
                                    }
                                }
                                ActionOutcome::Fail(reason) => {
                                    push_failed_delivery_and_queue(
                                        &mut results,
                                        *link_id,
                                        delivery,
                                        &reason,
                                    );
                                    remove_session = true;
                                }
                            }
                        }
                    }
                    DeliveryState::Complete => {
                        results.push(DeliveryResult::Complete {
                            link_id: *link_id,
                            msg_hash: delivery.msg_hash,
                        });
                        if delivery.reusable && delivery.link.state != LinkState::Closed {
                            finish_reusable_delivery(
                                &self.transport_tx,
                                &self.identity_pub,
                                &self.identity_key,
                                link_id,
                                delivery,
                            );
                        } else {
                            fail_queued_deliveries(&mut results, *link_id, delivery, "link closed");
                            remove_session = true;
                        }
                    }
                    DeliveryState::Failed => {
                        let reason = delivery
                            .failure_reason
                            .take()
                            .unwrap_or_else(|| "delivery failed".to_string());
                        push_failed_delivery_and_queue(&mut results, *link_id, delivery, &reason);
                        remove_session = true;
                    }
                    DeliveryState::Establishing | DeliveryState::AwaitingProof => {}
                }
            }

            if !remove_session && delivery.reusable {
                if delivery.link.state == LinkState::Closed {
                    fail_queued_deliveries(&mut results, *link_id, delivery, "link closed");
                    remove_session = true;
                } else if delivery.state == DeliveryState::Idle
                    && delivery.queued.is_empty()
                    && delivery.link.is_active()
                    && link_data_idle_for(&delivery.link) > LINK_MAX_INACTIVITY
                {
                    tracing::debug!(
                        link_id = %hex_encode(link_id),
                        dest = %hex_encode(&delivery.dest_hash),
                        idle_secs = link_data_idle_for(&delivery.link).as_secs_f64(),
                        "tearing down inactive Direct link"
                    );
                    send_link_teardown(&self.transport_tx, link_id, &mut delivery.link);
                    remove_session = true;
                } else if drive_link_action(&self.transport_tx, link_id, delivery.link.tick()) {
                    if !matches!(
                        delivery.state,
                        DeliveryState::Idle | DeliveryState::Complete
                    ) {
                        push_failed_delivery_and_queue(
                            &mut results,
                            *link_id,
                            delivery,
                            "link closed",
                        );
                    } else {
                        fail_queued_deliveries(&mut results, *link_id, delivery, "link closed");
                    }
                    remove_session = true;
                }
            }

            if remove_session {
                to_remove.push(*link_id);
            }
        }

        for link_id in to_remove {
            if let Some(mut delivery) = self.pending.remove(&link_id) {
                if delivery.reusable {
                    self.direct_links.remove(&delivery.dest_hash);
                }
                send_link_teardown(&self.transport_tx, &link_id, &mut delivery.link);
                let _ = self
                    .transport_tx
                    .try_send(TransportMessage::DeregisterDestination { hash: link_id });
            }
        }

        results
    }

    pub fn handle_hmu(&mut self, link_id: &[u8; 16], hmu_data: &[u8]) {
        if let Some(delivery) = self.pending.get_mut(link_id)
            && let Some(ref mut transfer) = delivery.transfer
        {
            transfer.handle_hmu(hmu_data);
        }
    }

    /// Handle an inbound `RESOURCE_REQ` (receiver's `request_next`).
    ///
    /// The request returns a list of parts the receiver still needs; dispatch the resulting
    /// `SendPart` actions immediately rather than waiting for the next [`Self::tick`], since
    /// the receiver may time out and retry first.
    pub fn handle_request(&mut self, link_id: &[u8; 16], request_data: &[u8]) {
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return;
        };
        let Some(ref mut transfer) = delivery.transfer else {
            return;
        };
        let actions = transfer.handle_request(request_data);
        for action in actions {
            match dispatch_action(link_id, delivery, &self.transport_tx, action) {
                ActionOutcome::Continue | ActionOutcome::Break => {}
                ActionOutcome::Complete => {
                    break;
                }
                ActionOutcome::Fail(reason) => {
                    delivery.failure_reason = Some(reason);
                    // Terminal state is surfaced on the next tick() via delivery.state.
                    break;
                }
            }
        }
    }

    /// Apply an inbound resource proof; returns `true` when the proof was accepted.
    pub fn handle_resource_proof(&mut self, link_id: &[u8; 16], proof_data: &[u8]) -> bool {
        if let Some(delivery) = self.pending.get_mut(link_id)
            && let Some(ref mut transfer) = delivery.transfer
            && transfer.handle_proof(proof_data)
        {
            if delivery.remaining_segments.is_empty() {
                delivery.state = DeliveryState::Complete;
            } else {
                let rtt = delivery.link.rtt.unwrap_or(Duration::from_millis(500));
                let next_segment = delivery.remaining_segments.remove(0);
                delivery.transfer = Some(OutboundTransfer::from_prebuilt(next_segment, rtt));
                delivery.state = DeliveryState::Transferring;
            }
            return true;
        }
        false
    }

    /// Apply an inbound receiver-cancel/reject for the current outbound resource.
    pub fn handle_resource_reject(&mut self, link_id: &[u8; 16], reject_data: &[u8]) -> bool {
        if reject_data.len() < 32 {
            return false;
        }

        let mut rejected_hash = [0u8; 32];
        rejected_hash.copy_from_slice(&reject_data[..32]);

        if let Some(delivery) = self.pending.get_mut(link_id)
            && let Some(ref mut transfer) = delivery.transfer
            && transfer.resource.resource_hash == rejected_hash
        {
            transfer.handle_cancel();
            delivery.remaining_segments.clear();
            delivery.state = DeliveryState::Failed;
            delivery.failure_reason = Some("resource rejected".to_string());
            return true;
        }

        false
    }

    fn handle_link_closed(
        &mut self,
        link_id: &[u8; 16],
        encrypted_teardown: Option<&[u8]>,
    ) -> bool {
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };

        let verified = match encrypted_teardown {
            Some(data) => delivery.link.receive_teardown(data),
            None => {
                delivery.link.mark_closed(CloseReason::DestinationClosed);
                true
            }
        };

        if verified {
            if delivery.state == DeliveryState::Complete {
                return true;
            }
            if delivery.state == DeliveryState::Idle {
                delivery.failure_reason = Some("link closed".to_string());
                return true;
            }
            delivery.transfer = None;
            delivery.remaining_segments.clear();
            delivery.packet_proof_hash = None;
            delivery.state = DeliveryState::Failed;
            delivery.failure_reason = Some("link closed".to_string());
        }

        verified
    }

    /// Apply an inbound link-packet proof; returns `true` when the packet delivery is complete.
    pub fn handle_link_packet_proof(&mut self, link_id: &[u8; 16], proof_data: &[u8]) -> bool {
        if let Some(delivery) = self.pending.get_mut(link_id)
            && delivery.state == DeliveryState::AwaitingProof
            && let Some(packet_hash) = delivery.packet_proof_hash
            && delivery
                .link
                .validate_packet_proof(&packet_hash, proof_data)
        {
            delivery.state = DeliveryState::Complete;
            return true;
        }
        false
    }

    pub fn pending_count(&self) -> usize {
        self.pending
            .values()
            .map(PendingDelivery::active_delivery_count)
            .sum()
    }

    pub fn delivery_link_available(&self, dest_hash: &[u8; 16]) -> bool {
        self.direct_links
            .get(dest_hash)
            .and_then(|link_id| self.pending.get(link_id))
            .is_some_and(|delivery| delivery.reusable && delivery.link.state != LinkState::Closed)
    }

    pub fn direct_link_snapshot(&self, dest_hash: [u8; 16]) -> Option<DirectLinkSnapshot> {
        let link_id = *self.direct_links.get(&dest_hash)?;
        let delivery = self.pending.get(&link_id)?;
        Some(DirectLinkSnapshot {
            link_id,
            dest_hash,
            link_state: delivery.link.state,
            delivery_state: delivery.state,
            queued_deliveries: delivery.queued.len(),
            in_flight_deliveries: usize::from(delivery.state != DeliveryState::Idle),
        })
    }

    pub fn stats(&self) -> LinkDeliveryStats {
        let mut stats = LinkDeliveryStats {
            sessions: self.pending.len(),
            direct_sessions: self.pending.values().filter(|d| d.reusable).count(),
            one_shot_sessions: self.pending.values().filter(|d| !d.reusable).count(),
            ..LinkDeliveryStats::default()
        };
        for delivery in self.pending.values() {
            stats.queued_deliveries += delivery.queued.len();
            if delivery.state != DeliveryState::Idle {
                stats.in_flight_deliveries += 1;
            }
            if delivery.reusable {
                if delivery.state == DeliveryState::Establishing {
                    stats.establishing_direct_sessions += 1;
                }
                if delivery.link.is_active() {
                    stats.active_direct_sessions += 1;
                }
                if delivery.state == DeliveryState::Idle {
                    stats.idle_direct_sessions += 1;
                }
            }
        }
        stats
    }

    pub fn session_count(&self) -> usize {
        self.pending.len()
    }
}

fn finish_reusable_delivery(
    transport_tx: &mpsc::Sender<TransportMessage>,
    identity_pub: &Option<[u8; 64]>,
    identity_key: &Option<Ed25519PrivateKey>,
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
) {
    if !delivery.backchannel_identified
        && let (Some(pub_key), Some(sign_key)) = (identity_pub, identity_key)
    {
        delivery.backchannel_identified =
            send_link_identify(transport_tx, link_id, &delivery.link, pub_key, sign_key);
    }

    delivery.transfer = None;
    delivery.remaining_segments.clear();
    delivery.packet_proof_hash = None;
    delivery.failure_reason = None;

    if delivery.link.is_active() && delivery.start_queued_delivery() {
        return;
    }

    delivery.state = DeliveryState::Idle;
}

fn push_failed_delivery_and_queue(
    results: &mut Vec<DeliveryResult>,
    link_id: [u8; 16],
    delivery: &mut PendingDelivery,
    reason: &str,
) {
    delivery.transfer = None;
    delivery.remaining_segments.clear();
    delivery.packet_proof_hash = None;
    results.push(DeliveryResult::Failed {
        link_id,
        msg_hash: delivery.msg_hash,
        dest_hash: delivery.dest_hash,
        message: delivery.message.clone(),
        reason: reason.to_string(),
    });
    fail_queued_deliveries(results, link_id, delivery, reason);
}

fn fail_queued_deliveries(
    results: &mut Vec<DeliveryResult>,
    link_id: [u8; 16],
    delivery: &mut PendingDelivery,
    reason: &str,
) {
    for queued in delivery.queued.drain(..) {
        results.push(DeliveryResult::Failed {
            link_id,
            msg_hash: queued.msg_hash,
            dest_hash: delivery.dest_hash,
            message: queued.message,
            reason: reason.to_string(),
        });
    }
}

fn send_link_identify(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    link: &Link,
    identity_pub: &[u8; 64],
    identity_key: &Ed25519PrivateKey,
) -> bool {
    let Ok(identify_data) = link.identify(identity_pub, identity_key) else {
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
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::LinkIdentify,
    };
    let mut id_raw = id_header.pack();
    id_raw.extend_from_slice(&identify_data);
    transport_tx
        .try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(id_raw),
            destination_hash: *link_id,
        }))
        .is_ok()
}

fn drive_link_action(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    action: LinkAction,
) -> bool {
    match action {
        LinkAction::SendKeepalive => {
            send_keepalive_packet(transport_tx, link_id);
            false
        }
        LinkAction::TransitionedToStale => {
            // Python sends one more keepalive when an initiator transitions stale.
            send_keepalive_packet(transport_tx, link_id);
            false
        }
        LinkAction::SendTeardownAndClose(teardown_data) => {
            if !teardown_data.is_empty() {
                send_link_close_payload(transport_tx, link_id, &teardown_data);
            }
            true
        }
        LinkAction::Closed(_) => true,
        LinkAction::None => false,
    }
}

fn send_keepalive_packet(transport_tx: &mpsc::Sender<TransportMessage>, link_id: &[u8; 16]) {
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
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::Keepalive,
    };
    let mut raw = header.pack();
    raw.push(rns_link::constants::KEEPALIVE_REQUEST);
    let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: *link_id,
    }));
}

fn send_link_close_payload(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    teardown_data: &[u8],
) {
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
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::LinkClose,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(teardown_data);
    let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: *link_id,
    }));
}

fn link_data_idle_for(link: &Link) -> Duration {
    link.no_data_for().min(link.no_outbound_for())
}

fn build_resource_transfer(
    link: &Link,
    packed: Vec<u8>,
    auto_compress: bool,
    rtt: Duration,
) -> Result<(OutboundTransfer, Vec<OutboundResource>), ResourceError> {
    if packed.len() <= MAX_EFFICIENT_SIZE {
        let transfer = match link.session_keys() {
            Some(keys) => {
                OutboundTransfer::new_encrypted(packed, auto_compress, rtt, keys.clone())?
            }
            None => OutboundTransfer::new(packed, auto_compress, rtt)?,
        };
        return Ok((transfer, Vec::new()));
    }

    let multi = match link.session_keys() {
        Some(keys) => {
            let keys = keys.clone();
            let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
                rns_link::encryption::link_encrypt(&keys, plaintext)
                    .unwrap_or_else(|_| plaintext.to_vec())
            };
            MultiSegmentOutbound::with_encrypt(packed, auto_compress, Some(&encrypt_fn))?
        }
        None => MultiSegmentOutbound::new(packed, auto_compress)?,
    };

    let mut segments = multi.segments.into_iter();
    let first = segments.next().ok_or(ResourceError::Incomplete)?;
    Ok((
        OutboundTransfer::from_prebuilt(first, rtt),
        segments.collect(),
    ))
}

/// Result of a delivery tick.
#[derive(Debug)]
pub enum DeliveryResult {
    Complete {
        link_id: [u8; 16],
        msg_hash: Option<[u8; 32]>,
    },
    Failed {
        link_id: [u8; 16],
        msg_hash: Option<[u8; 32]>,
        dest_hash: [u8; 16],
        message: LxMessage,
        reason: String,
    },
}

/// Outcome of dispatching one [`TransferAction`] onto the wire.
enum ActionOutcome {
    /// Action dispatched, continue draining.
    Continue,
    /// No-op; stop draining for this cycle.
    Break,
    /// Transfer completed; `delivery.state` is already [`DeliveryState::Complete`].
    Complete,
    /// Transfer failed; `delivery.state` is already [`DeliveryState::Failed`].
    Fail(String),
}

/// Send a single LXMF packet over an active link and return the full packet hash that the peer
/// must prove with `LINKPROOF`.
fn send_link_packet(
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
    transport_tx: &mpsc::Sender<TransportMessage>,
    packed: &[u8],
) -> Option<[u8; 32]> {
    let encrypted = delivery.link.encrypt(packed).ok()?;
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
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&encrypted);
    let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
    let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: *link_id,
    }));
    delivery.link.record_tx(encrypted.len());
    Some(packet_hash)
}

fn send_link_teardown(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    link: &mut Link,
) {
    let Some(teardown_data) = link.teardown(CloseReason::InitiatorClosed) else {
        return;
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
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::LinkClose,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&teardown_data);
    let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: *link_id,
    }));
}

/// Serialize a [`TransferAction`] onto the link and enqueue it for transport.
///
/// Kept as a free function so it can be called from [`LinkDeliveryManager::tick`] and
/// [`LinkDeliveryManager::handle_request`] without double-mutable-borrow conflicts on the
/// manager.
fn dispatch_action(
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
    transport_tx: &mpsc::Sender<TransportMessage>,
    action: TransferAction,
) -> ActionOutcome {
    let base_flags = rns_wire::flags::PacketFlags {
        header_type: rns_wire::flags::HeaderType::Header1,
        context_flag: false,
        transport_type: rns_wire::flags::TransportType::Broadcast,
        destination_type: rns_wire::flags::DestinationType::Link,
        packet_type: rns_wire::flags::PacketType::Data,
    };
    let make_header = |context, packet_type| rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            packet_type,
            ..base_flags
        },
        hops: 0,
        transport_id: None,
        destination_hash: *link_id,
        context,
    };
    let send = |header: rns_wire::header::PacketHeader, body: &[u8]| {
        let mut raw = header.pack();
        raw.extend_from_slice(body);
        let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        }));
    };

    match action {
        TransferAction::SendAdvertisement(adv_data) => {
            if let Ok(encrypted) = delivery.link.encrypt(&adv_data) {
                send(
                    make_header(
                        rns_wire::context::PacketContext::ResourceAdv,
                        rns_wire::flags::PacketType::Data,
                    ),
                    &encrypted,
                );
                delivery.link.record_tx(encrypted.len());
            }
            ActionOutcome::Continue
        }
        TransferAction::SendPart(_, part_data) => {
            // Parts are already ciphertext (pre-chunk blob encryption). `context=Resource`
            // packets are not packet-layer encrypted (Packet.py:201-204).
            send(
                make_header(
                    rns_wire::context::PacketContext::Resource,
                    rns_wire::flags::PacketType::Data,
                ),
                &part_data,
            );
            delivery.link.record_tx(part_data.len());
            ActionOutcome::Continue
        }
        TransferAction::SendHmu(hmu_data) => {
            if let Ok(encrypted) = delivery.link.encrypt(&hmu_data) {
                send(
                    make_header(
                        rns_wire::context::PacketContext::ResourceHmu,
                        rns_wire::flags::PacketType::Data,
                    ),
                    &encrypted,
                );
                delivery.link.record_tx(encrypted.len());
            }
            ActionOutcome::Continue
        }
        TransferAction::SendRequest(req_data) => {
            if let Ok(encrypted) = delivery.link.encrypt(&req_data) {
                send(
                    make_header(
                        rns_wire::context::PacketContext::ResourceReq,
                        rns_wire::flags::PacketType::Data,
                    ),
                    &encrypted,
                );
                delivery.link.record_tx(encrypted.len());
            }
            ActionOutcome::Continue
        }
        TransferAction::SendProof(proof_data) => {
            // PROOF+RESOURCE_PRF is plaintext on a Proof packet (Packet.py:195-197). Body =
            // resource_hash(32) || proof(32).
            send(
                make_header(
                    rns_wire::context::PacketContext::ResourcePrf,
                    rns_wire::flags::PacketType::Proof,
                ),
                &proof_data,
            );
            delivery.link.record_tx(proof_data.len());
            ActionOutcome::Continue
        }
        TransferAction::Complete => {
            delivery.state = DeliveryState::Complete;
            ActionOutcome::Complete
        }
        TransferAction::Failed(reason) => {
            delivery.state = DeliveryState::Failed;
            ActionOutcome::Fail(reason)
        }
        TransferAction::SendCancel(cancel_type, resource_hash) => {
            if let Ok(encrypted) = delivery.link.encrypt(&resource_hash) {
                let context = match cancel_type {
                    rns_protocol::resource::CancelType::Icl => {
                        rns_wire::context::PacketContext::ResourceIcl
                    }
                    rns_protocol::resource::CancelType::Rcl => {
                        rns_wire::context::PacketContext::ResourceRcl
                    }
                };
                send(
                    make_header(context, rns_wire::flags::PacketType::Data),
                    &encrypted,
                );
                delivery.link.record_tx(encrypted.len());
            }
            delivery.state = DeliveryState::Failed;
            ActionOutcome::Fail("resource transfer cancelled".to_string())
        }
        TransferAction::None => ActionOutcome::Break,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn next_outbound(rx: &mut mpsc::Receiver<TransportMessage>) -> Vec<u8> {
        while let Ok(message) = rx.try_recv() {
            if let TransportMessage::Outbound(request) = message {
                return request.raw.to_vec();
            }
        }
        panic!("expected outbound transport message");
    }

    fn establish_active_delivery(
        mgr: &mut LinkDeliveryManager,
        rx: &mut mpsc::Receiver<TransportMessage>,
        msg: LxMessage,
        responder_key: &Ed25519PrivateKey,
        dest_hash: [u8; 16],
    ) -> ([u8; 16], Link) {
        let link_id = mgr.start_delivery(msg, dest_hash, 1).unwrap();

        let request_raw = next_outbound(rx);
        let (request_header, request_offset) =
            rns_wire::header::PacketHeader::unpack(&request_raw).unwrap();
        assert_eq!(
            request_header.flags.packet_type,
            rns_wire::flags::PacketType::LinkRequest
        );

        let (mut responder_link, proof_data) =
            Link::new_responder(&request_raw[request_offset..], responder_key, dest_hash, 1)
                .unwrap();
        let responder_pub = responder_key.public_key();
        assert!(mgr.handle_link_proof(
            &link_id,
            &proof_data,
            &responder_pub,
            &responder_pub.to_bytes()
        ));

        let rtt_raw = next_outbound(rx);
        let (rtt_header, rtt_offset) = rns_wire::header::PacketHeader::unpack(&rtt_raw).unwrap();
        assert_eq!(rtt_header.context, rns_wire::context::PacketContext::Lrrtt);
        responder_link
            .receive_rtt_packet(&rtt_raw[rtt_offset..])
            .unwrap();

        (link_id, responder_link)
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

    fn complete_next_link_packet(
        mgr: &mut LinkDeliveryManager,
        rx: &mut mpsc::Receiver<TransportMessage>,
        link_id: [u8; 16],
        responder_link: &Link,
        responder_key: &Ed25519PrivateKey,
    ) {
        let packet_raw = next_outbound(rx);
        let (packet_header, _) = rns_wire::header::PacketHeader::unpack(&packet_raw).unwrap();
        assert_eq!(
            packet_header.flags.packet_type,
            rns_wire::flags::PacketType::Data
        );
        assert_eq!(
            packet_header.flags.destination_type,
            rns_wire::flags::DestinationType::Link
        );
        assert_eq!(packet_header.destination_hash, link_id);
        assert_eq!(
            packet_header.context,
            rns_wire::context::PacketContext::None
        );

        let packet_hash = rns_wire::hash::packet_hash(&packet_raw, packet_header.flags.header_type);
        let proof_data = responder_link
            .prove_packet(&packet_hash, responder_key)
            .unwrap();
        let proof_header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Proof,
            },
            hops: 0,
            transport_id: None,
            destination_hash: link_id,
            context: rns_wire::context::PacketContext::None,
        };
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&proof_data);
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: proof_raw.into(),
                interface_id: 0,
            })
            .unwrap();
        mgr.drain_events(&HashMap::new());
    }

    #[test]
    fn test_link_delivery_manager_creation() {
        let (tx, _rx) = mpsc::channel(16);
        let mgr = LinkDeliveryManager::new(tx, None, None);
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_start_delivery_registers_with_transport() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Test Subject",
            "test message for link delivery",
            crate::constants::DeliveryMethod::Direct,
        );
        let dest_hash = [0xCC; 16];

        let report = mgr.start_delivery_with_report(msg, dest_hash, 1).unwrap();
        let link_id = report.link_id;
        assert_eq!(report.kind, DirectLinkStartKind::NewDirect);
        assert_eq!(report.dest_hash, dest_hash);
        assert_eq!(report.delivery_state, DeliveryState::Establishing);
        assert_eq!(report.queued_deliveries, 0);
        assert_eq!(report.in_flight_deliveries, 1);
        assert_eq!(mgr.pending_count(), 1);
        assert!(mgr.delivery_link_available(&dest_hash));
        assert_eq!(mgr.stats().direct_sessions, 1);
        assert_eq!(mgr.stats().one_shot_sessions, 0);

        let register = rx.try_recv();
        assert!(register.is_ok(), "RegisterDestination should be queued");
        assert!(matches!(
            register.unwrap(),
            TransportMessage::RegisterDestination { .. }
        ));

        let outbound = rx.try_recv();
        assert!(outbound.is_ok(), "link request should be queued");

        let delivery = mgr.pending.get(&link_id).unwrap();
        assert_eq!(delivery.state, DeliveryState::Establishing);
        assert_eq!(delivery.dest_hash, dest_hash);
    }

    #[test]
    fn test_direct_delivery_queues_on_pending_link_without_second_link_request() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let dest_hash = [0xCD; 16];

        let first = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "First",
            "first queued message",
            crate::constants::DeliveryMethod::Direct,
        );
        let second = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Second",
            "second queued message",
            crate::constants::DeliveryMethod::Direct,
        );

        let link_id = mgr.start_delivery(first, dest_hash, 1).unwrap();
        let report = mgr
            .start_delivery_with_report(second, dest_hash, 1)
            .unwrap();
        assert_eq!(report.link_id, link_id);
        assert_eq!(report.kind, DirectLinkStartKind::QueuedOnDirect);
        assert_eq!(report.delivery_state, DeliveryState::Establishing);
        assert_eq!(report.queued_deliveries, 1);
        assert_eq!(report.in_flight_deliveries, 1);
        assert_eq!(mgr.pending_count(), 2);
        assert_eq!(mgr.session_count(), 1);
        assert_eq!(mgr.stats().queued_deliveries, 1);
        assert_eq!(mgr.stats().establishing_direct_sessions, 1);

        let register = rx.try_recv().unwrap();
        assert!(matches!(
            register,
            TransportMessage::RegisterDestination { .. }
        ));
        let request = rx.try_recv().unwrap();
        assert!(matches!(request, TransportMessage::Outbound(_)));
        assert!(
            rx.try_recv().is_err(),
            "second message must wait on the cached pending link"
        );

        if let Some(delivery) = mgr.pending.get_mut(&link_id) {
            delivery.establishment_timeout = Duration::ZERO;
        }
        let results = mgr.tick();
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, DeliveryResult::Failed { .. }))
                .count(),
            2
        );
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_packed_delivery_is_one_shot_not_direct_session() {
        let (tx, _rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let dest_hash = [0xC1; 16];
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Propagation",
            "deposit",
            crate::constants::DeliveryMethod::Propagated,
        );

        let link_id = mgr
            .start_packed_delivery(msg, dest_hash, 1, b"packed propagation".to_vec(), false)
            .unwrap();

        assert_eq!(mgr.pending_count(), 1);
        assert_eq!(mgr.session_count(), 1);
        assert_eq!(mgr.stats().direct_sessions, 0);
        assert_eq!(mgr.stats().one_shot_sessions, 1);
        assert!(!mgr.delivery_link_available(&dest_hash));
        assert!(mgr.direct_link_snapshot(dest_hash).is_none());
        assert!(!mgr.pending.get(&link_id).unwrap().reusable);
    }

    #[test]
    fn test_direct_delivery_reuses_active_link_without_second_link_request() {
        let (tx, mut rx) = mpsc::channel(128);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let responder_key = Ed25519PrivateKey::generate();
        let sign_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCE; 16];

        let mut first = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "First",
            "first direct message",
            crate::constants::DeliveryMethod::Direct,
        );
        first.sign(&sign_key).unwrap();
        let (link_id, responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, first, &responder_key, dest_hash);

        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        let results = mgr.tick();
        assert!(
            results
                .iter()
                .any(|r| matches!(r, DeliveryResult::Complete { .. }))
        );
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.session_count(), 1);
        assert_eq!(
            mgr.pending.get(&link_id).unwrap().state,
            DeliveryState::Idle
        );

        let mut second = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Second",
            "second direct message",
            crate::constants::DeliveryMethod::Direct,
        );
        second.sign(&sign_key).unwrap();
        let report = mgr
            .start_delivery_with_report(second, dest_hash, 1)
            .unwrap();
        assert_eq!(report.link_id, link_id);
        assert_eq!(report.kind, DirectLinkStartKind::ReusedActiveDirect);
        assert_eq!(report.link_state, LinkState::Active);
        assert_eq!(report.delivery_state, DeliveryState::Identifying);
        assert_eq!(report.queued_deliveries, 0);
        assert_eq!(report.in_flight_deliveries, 1);
        assert!(
            rx.try_recv().is_err(),
            "reusing an idle Direct link must not emit a new LINKREQUEST"
        );
        let snapshot = mgr.direct_link_snapshot(dest_hash).unwrap();
        assert_eq!(snapshot.link_id, link_id);
        assert_eq!(snapshot.delivery_state, DeliveryState::Identifying);
        assert_eq!(mgr.stats().active_direct_sessions, 1);

        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        let results = mgr.tick();
        assert!(
            results
                .iter()
                .any(|r| matches!(r, DeliveryResult::Complete { .. }))
        );
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn test_direct_delivery_identifies_after_success_not_before_packet() {
        let (tx, mut rx) = mpsc::channel(128);
        let local_key = Ed25519PrivateKey::generate();
        let mut local_pub = [0u8; 64];
        local_pub[32..64].copy_from_slice(&local_key.public_key().to_bytes());
        let mut mgr = LinkDeliveryManager::new(tx, Some(local_pub), Some(local_key));
        let responder_key = Ed25519PrivateKey::generate();
        let sign_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCF; 16];

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Identify",
            "identify after delivery",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let (link_id, mut responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        let results = mgr.tick();
        assert!(
            results
                .iter()
                .any(|r| matches!(r, DeliveryResult::Complete { .. }))
        );

        let identify_raw = next_outbound(&mut rx);
        let (identify_header, identify_offset) =
            rns_wire::header::PacketHeader::unpack(&identify_raw).unwrap();
        assert_eq!(
            identify_header.context,
            rns_wire::context::PacketContext::LinkIdentify
        );
        let identified_pub = responder_link
            .handle_identification(&identify_raw[identify_offset..])
            .unwrap();
        assert_eq!(identified_pub, local_pub);
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn test_start_delivery_does_not_partially_register_when_second_slot_unavailable() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let msg = LxMessage::new(
            [0; 16],
            [0; 16],
            "Full",
            "transport full",
            crate::constants::DeliveryMethod::Direct,
        );

        let result = mgr.start_delivery(msg, [0xDD; 16], 1);
        assert!(matches!(
            result,
            Err(LinkDeliveryStartFailure {
                error: LinkDeliveryStartError::TransportFull,
                ..
            })
        ));
        assert_eq!(mgr.pending_count(), 0);
        assert!(
            rx.try_recv().is_err(),
            "no RegisterDestination should be queued without a LinkRequest slot"
        );
    }

    #[test]
    fn test_start_delivery_closed_transport_fails_without_pending_delivery() {
        let (tx, rx) = mpsc::channel(2);
        drop(rx);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let msg = LxMessage::new(
            [0; 16],
            [0; 16],
            "Closed",
            "transport closed",
            crate::constants::DeliveryMethod::Direct,
        );

        let result = mgr.start_delivery(msg, [0xDD; 16], 1);
        assert!(matches!(
            result,
            Err(LinkDeliveryStartFailure {
                error: LinkDeliveryStartError::TransportClosed,
                ..
            })
        ));
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_establishment_timeout_deregisters() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let msg = LxMessage::new(
            [0; 16],
            [0; 16],
            "Timeout",
            "timeout test",
            crate::constants::DeliveryMethod::Direct,
        );
        let link_id = mgr.start_delivery(msg, [0xDD; 16], 1).unwrap();

        while rx.try_recv().is_ok() {}

        if let Some(delivery) = mgr.pending.get_mut(&link_id) {
            delivery.establishment_timeout = Duration::ZERO;
        }

        let results = mgr.tick();
        assert!(
            results
                .iter()
                .any(|r| matches!(r, DeliveryResult::Failed { .. }))
        );
        assert!(results.iter().any(|r| matches!(
            r,
            DeliveryResult::Failed { reason, .. } if reason == "link establishment timeout"
        )));
        assert_eq!(mgr.pending_count(), 0);

        let deregister = rx.try_recv();
        assert!(deregister.is_ok(), "DeregisterDestination should be queued");
        assert!(matches!(
            deregister.unwrap(),
            TransportMessage::DeregisterDestination { .. }
        ));
    }

    #[test]
    fn test_over_mtu_message_tracks_hash() {
        let (tx, _rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Large Message",
            &"x".repeat(1000),
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();
        let expected_hash = msg.hash;

        let link_id = mgr.start_delivery(msg, [0xCC; 16], 1).unwrap();
        let delivery = mgr.pending.get(&link_id).unwrap();
        assert_eq!(delivery.msg_hash, expected_hash);
    }

    #[test]
    fn test_over_efficient_limit_direct_uses_split_resources() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Split Direct",
            &"x".repeat(MAX_EFFICIENT_SIZE + 256),
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        assert!(msg.pack().unwrap().len() > MAX_EFFICIENT_SIZE);

        let responder_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCC; 16];
        let (link_id, _responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        let results = mgr.tick();
        assert!(results.is_empty());

        let delivery = mgr.pending.get(&link_id).unwrap();
        let transfer = delivery.transfer.as_ref().expect("first segment transfer");
        assert!(transfer.resource.flags.split);
        assert_eq!(transfer.resource.segment_index, 1);
        assert!(transfer.resource.total_segments >= 2);
        assert_eq!(
            delivery.remaining_segments.len(),
            transfer.resource.total_segments - 1
        );
    }

    #[test]
    fn test_split_resource_proof_advances_to_next_segment() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Split Direct",
            &"y".repeat(MAX_EFFICIENT_SIZE + 128),
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();

        let responder_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCC; 16];
        let (link_id, _responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        let results = mgr.tick();
        assert!(results.is_empty());

        let first_proof = {
            let delivery = mgr.pending.get(&link_id).unwrap();
            let transfer = delivery.transfer.as_ref().unwrap();
            assert!(transfer.resource.total_segments >= 2);
            let mut proof = Vec::new();
            proof.extend_from_slice(&transfer.resource.resource_hash);
            proof.extend_from_slice(&transfer.resource.expected_proof);
            proof
        };
        assert!(mgr.handle_resource_proof(&link_id, &first_proof));

        let delivery = mgr.pending.get(&link_id).unwrap();
        assert_eq!(delivery.state, DeliveryState::Transferring);
        assert_eq!(
            delivery.transfer.as_ref().unwrap().resource.segment_index,
            2
        );

        let mut terminal_proofs = Vec::new();
        loop {
            let delivery = mgr.pending.get(&link_id).unwrap();
            let transfer = delivery.transfer.as_ref().unwrap();
            let mut proof = Vec::new();
            proof.extend_from_slice(&transfer.resource.resource_hash);
            proof.extend_from_slice(&transfer.resource.expected_proof);
            terminal_proofs.push(proof);
            if delivery.remaining_segments.is_empty() {
                break;
            }
            let proof = terminal_proofs.pop().unwrap();
            assert!(mgr.handle_resource_proof(&link_id, &proof));
        }

        let final_proof = terminal_proofs.pop().unwrap();
        assert!(mgr.handle_resource_proof(&link_id, &final_proof));
        let results = mgr.tick();
        assert!(
            results
                .iter()
                .any(|r| matches!(r, DeliveryResult::Complete { .. }))
        );
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_resource_reject_fails_delivery() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Resource Reject",
            &"z".repeat(1000),
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();

        let responder_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCC; 16];
        let (link_id, _responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        let results = mgr.tick();
        assert!(results.is_empty());

        let resource_hash = mgr
            .pending
            .get(&link_id)
            .unwrap()
            .transfer
            .as_ref()
            .unwrap()
            .resource
            .resource_hash;

        assert!(mgr.handle_resource_reject(&link_id, &resource_hash));
        let results = mgr.tick();
        assert!(
            results
                .iter()
                .any(|r| matches!(r, DeliveryResult::Failed { .. }))
        );
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_authenticated_remote_link_close_fails_and_deregisters() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Remote Close",
            "close before delivery proof",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();

        let responder_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCD; 16];
        let (link_id, mut responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        while rx.try_recv().is_ok() {}

        let close_body = responder_link
            .teardown(CloseReason::InitiatorClosed)
            .expect("remote active link emits authenticated teardown");
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::LinkClose,
                    &close_body,
                ),
                interface_id: 0,
            })
            .unwrap();

        mgr.drain_events(&HashMap::new());
        let results = mgr.tick();

        assert!(results.iter().any(|r| matches!(
            r,
            DeliveryResult::Failed { reason, .. } if reason == "link closed"
        )));
        assert_eq!(mgr.pending_count(), 0);
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::DeregisterDestination { hash } if hash == link_id
        ));
    }

    #[test]
    fn test_unauthenticated_link_close_is_ignored() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Bad Close",
            "ignore invalid close packet",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();

        let responder_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCE; 16];
        let (link_id, _responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &[0u8]),
                interface_id: 0,
            })
            .unwrap();

        mgr.drain_events(&HashMap::new());
        assert_eq!(mgr.pending_count(), 1);
        assert_ne!(
            mgr.pending.get(&link_id).unwrap().state,
            DeliveryState::Failed
        );
    }

    #[test]
    fn test_small_direct_uses_link_packet_and_accepts_python_style_proof() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Small Direct",
            "fits in one link packet",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let packed = msg.pack().unwrap();

        let responder_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCC; 16];
        let (link_id, mut responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        let results = mgr.tick();
        assert!(results.is_empty());

        let packet_raw = next_outbound(&mut rx);
        let (packet_header, packet_offset) =
            rns_wire::header::PacketHeader::unpack(&packet_raw).unwrap();
        assert_eq!(
            packet_header.flags.destination_type,
            rns_wire::flags::DestinationType::Link
        );
        assert_eq!(
            packet_header.flags.packet_type,
            rns_wire::flags::PacketType::Data
        );
        assert_eq!(
            packet_header.context,
            rns_wire::context::PacketContext::None
        );

        let decrypted = responder_link
            .decrypt(&packet_raw[packet_offset..])
            .unwrap();
        assert_eq!(decrypted, packed);

        let packet_hash = rns_wire::hash::packet_hash(&packet_raw, packet_header.flags.header_type);
        let delivery = mgr.pending.get(&link_id).unwrap();
        assert_eq!(delivery.state, DeliveryState::AwaitingProof);
        assert_eq!(delivery.packet_proof_hash, Some(packet_hash));

        let proof_data = responder_link
            .prove_packet(&packet_hash, &responder_key)
            .unwrap();
        let proof_header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Proof,
            },
            hops: 0,
            transport_id: None,
            destination_hash: link_id,
            context: rns_wire::context::PacketContext::None,
        };
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&proof_data);
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: proof_raw.into(),
                interface_id: 0,
            })
            .unwrap();
        let close_body = responder_link
            .teardown(CloseReason::InitiatorClosed)
            .expect("remote active link emits authenticated teardown after proof");
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::LinkClose,
                    &close_body,
                ),
                interface_id: 0,
            })
            .unwrap();

        mgr.drain_events(&HashMap::new());
        let results = mgr.tick();
        assert!(
            results
                .iter()
                .any(|r| matches!(r, DeliveryResult::Complete { .. }))
        );
        assert_eq!(mgr.pending_count(), 0);
    }
}
