//! Link-based LXMF message delivery (Python's Direct delivery mode).
//!
//! Establishes a link to the recipient, identifies the sender, and transfers the message either
//! as a single encrypted link packet or as a Resource over the link. Enables larger-than-MDU
//! messages via resource segmentation, delivery confirmation via link-level proofs, and sender
//! identity verification via link identification.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_link::constants::ESTABLISHMENT_TIMEOUT_PER_HOP;
use rns_link::link::{CloseReason, Link, LinkAction, LinkState};
use rns_protocol::resource::{
    InboundTransfer, LazyMultiSegmentOutbound, MAX_EFFICIENT_SIZE, MAX_RESOURCE_SIZE, MAX_SEGMENTS,
    MultiSegmentInbound, OutboundResource, OutboundTransfer, ResourceError, TransferAction,
};
use rns_protocol::resource_adv::ResourceAdvertisement;
use rns_transport::link_endpoint_dispatch::{
    LINK_ENDPOINT_ADMISSION_TIMEOUT_MAX, LinkEndpointDispatchBindReceipt,
    LinkEndpointDispatchCancellation, LinkEndpointDispatchHandle, LinkEndpointDispatchOutcome,
    LinkEndpointDispatchToken,
};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    InterfaceId, LinkEndpointBindResult, LinkEndpointBinding, LinkEndpointLifecycleEvent,
    LinkEndpointRole, LinkEndpointSendResult, LinkEndpointUnbindResult, OutboundRequest,
    TransportMessage,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};

use crate::constants::{BYTES_PER_KILOBYTE, DELIVERY_LIMIT, DeliveryRepresentation, LXMF_OVERHEAD};
use crate::message::LxMessage;
use crate::propagation::hex_encode;

/// Upstream LXMF keeps reusable Direct links open for ten minutes of data
/// inactivity before tearing them down (`LXMRouter.LINK_MAX_INACTIVITY`).
const LINK_MAX_INACTIVITY: Duration = Duration::from_secs(600);
const BACKCHANNEL_SEND_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const BACKCHANNEL_DELIVERY_TIMEOUT: Duration = Duration::from_secs(360);
// External Resource clocks cross an asynchronous accounting adapter. Let a
// queued renewal/terminal observation arrive after the original protocol
// deadline, bounded by the app's existing 180s orphan policy. This never alters
// the Resource engine's own retries or starts a timer at observation time.
const BACKCHANNEL_RESOURCE_OBSERVATION_GRACE: Duration = Duration::from_secs(180);
const BACKCHANNEL_EARLY_PROOF_LIMIT: usize = 256;
const LINK_PENDING_TRANSPORT_LIMIT: usize = 1024;
/// Local FIFO ownership is finite even when the interface stops draining.
const LINK_PACKET_DISPATCH_TIMEOUT: Duration = LINK_ENDPOINT_ADMISSION_TIMEOUT_MAX;

/// Authority-derived first-hop timing for an outbound Link.
///
/// Python Reticulum computes an initiator's establishment deadline as the
/// first-hop timeout plus six seconds for every hop to the destination. The
/// first-hop timeout is one full Reticulum MTU at the next-hop interface's
/// bitrate, plus the same six-second baseline. When no authoritative bitrate
/// is available, Reticulum falls back to the baseline alone.
///
/// Keeping this input independent of interface type is intentional: BLE,
/// serial, TCP and every future adapter use the same Link timing rule. It does
/// not pause or reset the protocol clock when an interface goes offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkEstablishmentTiming {
    first_hop_timeout: Duration,
}

impl LinkEstablishmentTiming {
    /// Construct timing from an already-authoritative Reticulum first-hop
    /// timeout (for example `ReticulumHandle::first_hop_timeout`).
    pub const fn from_first_hop_timeout(first_hop_timeout: Duration) -> Self {
        Self { first_hop_timeout }
    }

    /// Derive Python-compatible first-hop timing from the effective next-hop
    /// interface bitrate. A zero bitrate has the standard six-second fallback.
    pub fn from_first_hop_bitrate(bitrate: u64) -> Self {
        Self::from_first_hop_bitrate_and_mtu(bitrate, rns_wire::constants::MTU as u32)
    }

    /// Derive first-hop timing from the effective next-hop bitrate and an
    /// already-normalised Reticulum protocol MTU.
    ///
    /// Callers normally want [`Self::from_first_hop_bitrate`], which uses the
    /// canonical 500-byte Reticulum MTU exactly like Python Reticulum and the
    /// trusted rsReticulum runtime. `normalised_mtu` exists for callers that
    /// already have an authoritative *protocol* MTU. It must never be a BLE
    /// ATT MTU, an RNode serial chunk size, or a raw hardware-interface MTU.
    pub fn from_first_hop_bitrate_and_mtu(bitrate: u64, normalised_mtu: u32) -> Self {
        let serialization_secs = if bitrate == 0 {
            0.0
        } else {
            (f64::from(normalised_mtu.min(rns_wire::constants::MTU as u32)) * 8.0) / bitrate as f64
        };
        Self {
            first_hop_timeout: Duration::from_secs_f64(
                serialization_secs + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT,
            ),
        }
    }

    pub const fn first_hop_timeout(self) -> Duration {
        self.first_hop_timeout
    }

    pub fn timeout_for_hops(self, hops: u8) -> Duration {
        self.first_hop_timeout
            + Duration::from_secs_f64(ESTABLISHMENT_TIMEOUT_PER_HOP * f64::from(hops.max(1)))
    }
}

impl Default for LinkEstablishmentTiming {
    fn default() -> Self {
        Self::from_first_hop_bitrate(0)
    }
}

struct LinkDeliveryStartOptions {
    timing: LinkEstablishmentTiming,
    packed_override: Option<Vec<u8>>,
    auto_compress: bool,
    reusable: bool,
}

impl LinkDeliveryStartOptions {
    fn direct(timing: LinkEstablishmentTiming) -> Self {
        Self {
            timing,
            packed_override: None,
            auto_compress: true,
            reusable: true,
        }
    }

    fn packed(
        timing: LinkEstablishmentTiming,
        packed_payload: Vec<u8>,
        auto_compress: bool,
    ) -> Self {
        Self {
            timing,
            packed_override: Some(packed_payload),
            auto_compress,
            reusable: false,
        }
    }
}

type InboundResourceAcceptHandler =
    Arc<dyn Fn([u8; 16], &ResourceAdvertisement) -> bool + Send + Sync>;
type InboundResourceConcludedHandler = Arc<dyn Fn([u8; 16], [u8; 32]) + Send + Sync>;
type InboundResourceCompletionHandler = Arc<dyn Fn([u8; 16], [u8; 32], Vec<u8>) + Send + Sync>;

#[derive(Debug, Clone, Copy)]
struct InboundSegmentRoute {
    original_hash: [u8; 32],
    segment_index: usize,
}

#[derive(Debug, Clone, Copy)]
struct InboundResourceLifecycle {
    data_size: usize,
    total_segments: usize,
    next_segment: usize,
    inter_segment_deadline: Option<Instant>,
}

struct PendingEndpointBind {
    interface_id: InterfaceId,
    rtt_request: OutboundRequest,
    result_rx: EndpointBindReceiver,
}

enum EndpointBindReceiver {
    Legacy(oneshot::Receiver<LinkEndpointBindResult>),
    Exact(LinkEndpointDispatchBindReceipt),
}

impl EndpointBindReceiver {
    fn try_recv(
        &mut self,
    ) -> Result<
        (LinkEndpointBindResult, Option<LinkEndpointDispatchToken>),
        oneshot::error::TryRecvError,
    > {
        match self {
            Self::Legacy(rx) => rx.try_recv().map(|result| (result, None)),
            Self::Exact(rx) => rx.try_recv().map(|result| match result {
                Ok(token) => (LinkEndpointBindResult::Bound, Some(token)),
                Err(result) => (result, None),
            }),
        }
    }
}

struct PendingPacketDispatch {
    link_id: [u8; 16],
    packet_hash: [u8; 32],
    result_rx: oneshot::Receiver<LinkEndpointDispatchOutcome>,
}

enum EndpointSendSuccess {
    None,
    FinishHandshake,
    StartPacketProofClock([u8; 32]),
    PublishInboundPacket(Vec<u8>),
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

/// State of a link-based delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    Idle,
    Establishing,
    Identifying,
    Transferring,
    AwaitingProof,
    Complete,
    Rejected,
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
    /// Sequential Reticulum Resource plan for payloads larger than one
    /// efficient resource. Segment 1 is stored in `transfer`; later segments
    /// are materialised only after the preceding proof arrives.
    pub remaining_segments: Option<LazyMultiSegmentOutbound>,
    /// Full packet hash of a single link-packet LXMF delivery awaiting LINKPROOF.
    pub packet_proof_hash: Option<[u8; 32]>,
    /// Link establishment timeout. This intentionally excludes keepalive time:
    /// an initiator that never receives LRPROOF should fail on the Link
    /// establishment clock, not on the active-link inactivity clock.
    pub establishment_timeout: Duration,
    /// Ordinary Link-packet proof window, installed when the packet is
    /// locally admitted. Resource transfers use their own progress watchdog.
    pub timeout: Duration,
    pub msg_hash: Option<[u8; 32]>,
    pub failure_reason: Option<String>,
    /// Immutable ingress/egress interface learned from the authenticated
    /// LRPROOF. No established-Link traffic is accepted before this is set.
    attached_interface: Option<InterfaceId>,
    endpoint_dispatch_token: Option<LinkEndpointDispatchToken>,
    packet_awaiting_dispatch: bool,
    pretransfer_identify_staged: bool,
    endpoint_release_queued: bool,
    /// Keep successful Direct links open for additional messages. Propagation
    /// deposits currently keep the old one-shot behavior.
    pub reusable: bool,
    /// Upstream identifies the initiator after the first successful Direct
    /// delivery, making the link usable as a peer backchannel.
    pub backchannel_identified: bool,
    queued: VecDeque<QueuedDelivery>,
    /// Resources arriving in the reverse direction on this initiator-owned
    /// reusable Link. Ordinary Link packets and Resources must share the same
    /// Link owner; otherwise a peer can reply with packets but every larger
    /// reply advertisement is silently dropped.
    inbound_resources: HashMap<[u8; 32], InboundTransfer>,
    inbound_split_resources: HashMap<[u8; 32], MultiSegmentInbound>,
    inbound_segment_routing: HashMap<[u8; 32], InboundSegmentRoute>,
    inbound_resource_lifecycles: HashMap<[u8; 32], InboundResourceLifecycle>,
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
        self.remaining_segments = None;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BackchannelProofKey {
    Packet([u8; 16], [u8; 32]),
    Resource([u8; 16], [u8; 32]),
}

impl BackchannelProofKey {
    fn link_id(self) -> [u8; 16] {
        match self {
            Self::Packet(link_id, _) | Self::Resource(link_id, _) => link_id,
        }
    }
}

struct PendingBackchannelStart {
    receiver: oneshot::Receiver<Result<BackchannelSendReceipt, BackchannelSendError>>,
    message: LxMessage,
    dest_hash: [u8; 16],
    link_id: [u8; 16],
    requested_at: Instant,
    /// Explicit cancellation cannot discard this owner until the asynchronous
    /// send receipt identifies whether the external send was a non-recallable
    /// Packet or a cancellable Resource.
    cancelled: bool,
    cancellation_aware: bool,
    /// A validated proof may be observed before the send receipt and then be
    /// followed by Link closure on a separate adapter channel. Keep the receipt
    /// owner for its original bounded window so the exact proof can still win.
    closed_reason: Option<String>,
}

struct PendingBackchannelDelivery {
    message: LxMessage,
    dest_hash: [u8; 16],
    link_id: [u8; 16],
    representation: DeliveryRepresentation,
    started_at: Instant,
    link_closed: bool,
    wait: Option<BackchannelWaitWindow>,
    packet_cancellation: Option<LinkEndpointDispatchCancellation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackchannelWaitWindow {
    started_at: Instant,
    timeout: Duration,
    awaiting_admission: bool,
}

struct EarlyBackchannelResourceConclusion {
    conclusion: BackchannelResourceConclusion,
    reason: String,
    observed_at: Instant,
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
    pub message: Box<LxMessage>,
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

/// A proof-tracked send over an already-authenticated inbound delivery Link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackchannelSendReceipt {
    Packet {
        link_id: [u8; 16],
        packet_hash: [u8; 32],
    },
    Resource {
        link_id: [u8; 16],
        resource_hash: [u8; 32],
    },
}

/// Terminal state for an externally-owned outbound backchannel Resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackchannelResourceConclusion {
    /// The receiver explicitly rejected the Resource. The authenticated Link
    /// remains eligible for a later delivery, matching native Direct Resource
    /// rejection semantics.
    Rejected,
    /// The Resource failed or was cancelled below LXMF. The cached backchannel
    /// is no longer considered reusable.
    Failed,
}

/// Exact external Resource cancellation requested by LXMF ownership cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackchannelResourceCancelRequest {
    pub link_id: [u8; 16],
    pub resource_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackchannelSendError {
    LinkNotFound,
    LinkNotActive,
    NoSessionKeys,
    TransportUnavailable,
    ResourceStartFailed,
    Other(String),
}

impl fmt::Display for BackchannelSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkNotFound => f.write_str("link not found"),
            Self::LinkNotActive => f.write_str("link is not active"),
            Self::NoSessionKeys => f.write_str("link session keys are unavailable"),
            Self::TransportUnavailable => f.write_str("transport channel is full or closed"),
            Self::ResourceStartFailed => f.write_str("resource transfer could not be started"),
            Self::Other(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for BackchannelSendError {}

/// Whether a link-delivery failure should be treated like upstream LXMF's
/// closed/pending Link path, where the message remains eligible for Direct
/// rediscovery instead of being terminally failed.
pub fn is_retryable_link_delivery_failure(reason: &str) -> bool {
    // Only concrete local endpoint terminal outcomes, not malformed packet,
    // role mismatch or arbitrary peer rejection text, trigger rediscovery.
    let endpoint_reason = reason
        .strip_prefix("Link endpoint terminated: ")
        .or_else(|| {
            reason
                .strip_prefix("Link endpoint send rejected: Terminated(")?
                .strip_suffix(')')
        });
    if matches!(
        endpoint_reason,
        Some(
            "Unbound"
                | "InterfaceRemoved"
                | "InterfaceClosed"
                | "InterfaceOffline"
                | "InterfaceNotOutbound"
                | "EgressQueueExhausted"
                | "TransportShutdown"
        )
    ) {
        return true;
    }
    matches!(
        reason,
        "link establishment timeout"
            | "link closed"
            | "transport full"
            | "transport closed"
            | "transport channel closed"
            | "transport staging queue full"
            // Backchannel adapters discover these only after asking the
            // embedding runtime to send over an externally-owned inbound Link.
            // They are equivalent to Python seeing direct_link.status == CLOSED.
            | "link not found"
            | "link is not active"
            | "link session keys are unavailable"
            | "transport channel is full or closed"
            | "backchannel send command timeout"
            | "backchannel send command closed"
            | "delivery timeout"
            | "Link endpoint admission timeout"
            | "backchannel delivery timeout"
            | "resource advertisement timed out"
            | "resource part requests timed out"
            | "resource proof timed out"
            | "resource transfer timed out"
            | "resource cancelled"
            | "Link endpoint binding failed"
            | "Link endpoint send result channel closed"
            | "Link endpoint send rejected: NotBound"
            | "Link endpoint send rejected: DroppedBackpressure"
    )
}

/// Command bridge used by embedders to send an LXMF payload over an inbound
/// authenticated Link that is owned by their Reticulum runtime.
pub struct BackchannelSendCommand {
    pub link_id: [u8; 16],
    pub payload: Vec<u8>,
    pub auto_compress: bool,
    pub result_tx: oneshot::Sender<Result<BackchannelSendReceipt, BackchannelSendError>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackchannelStartError {
    NoBackchannel,
    SenderUnavailable,
    CommandFull,
    CommandClosed,
    PackFailed,
}

impl fmt::Display for BackchannelStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBackchannel => f.write_str("backchannel link not found"),
            Self::SenderUnavailable => f.write_str("backchannel sender unavailable"),
            Self::CommandFull => f.write_str("backchannel command channel full"),
            Self::CommandClosed => f.write_str("backchannel command channel closed"),
            Self::PackFailed => f.write_str("failed to pack LXMF payload"),
        }
    }
}

impl std::error::Error for BackchannelStartError {}

#[derive(Debug)]
pub struct BackchannelStartFailure {
    pub error: BackchannelStartError,
    pub message: Box<LxMessage>,
}

impl fmt::Display for BackchannelStartFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for BackchannelStartFailure {}

/// Start result for a reusable inbound backchannel Link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackchannelStartReport {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

/// Which link-delivery path emitted an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LxmfDeliveryEventMethod {
    Direct,
    PropagationDeposit,
}

/// Semantic delivery stages surfaced by [`LinkDeliveryManager`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LxmfDeliveryEventKind {
    LinkEstablishing,
    LinkEstablished,
    DirectLinkPending,
    DirectLinkReused,
    BackchannelLinkReused,
    TransferStarted,
    TransferProgress,
    AwaitingProof,
    Delivered,
    Rejected,
    Failed,
}

/// Upstream-like delivery progress event for embedders and UI adapters.
#[derive(Debug, Clone, PartialEq)]
pub struct LxmfDeliveryEvent {
    pub kind: LxmfDeliveryEventKind,
    pub method: LxmfDeliveryEventMethod,
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub msg_hash: Option<[u8; 32]>,
    pub attempts: u32,
    pub progress: Option<f64>,
    pub representation: DeliveryRepresentation,
    pub link_state: LinkState,
    pub delivery_state: DeliveryState,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
    pub reason: Option<String>,
}

/// Snapshot of a reusable Direct Link session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectLinkSnapshot {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub link_state: LinkState,
    pub delivery_state: DeliveryState,
    pub idle_expired: bool,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

/// Snapshot of a message currently owned by link delivery.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MessageDeliverySnapshot {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub link_state: LinkState,
    pub delivery_state: DeliveryState,
    pub representation: DeliveryRepresentation,
    pub progress: f64,
    pub queued: bool,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackchannelLinkSnapshot {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

/// Aggregate LinkDeliveryManager state for diagnostics and UI event mapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkDeliveryStats {
    pub sessions: usize,
    pub direct_sessions: usize,
    pub one_shot_sessions: usize,
    pub backchannel_sessions: usize,
    pub establishing_direct_sessions: usize,
    pub active_direct_sessions: usize,
    pub idle_direct_sessions: usize,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
    pub pending_backchannel_starts: usize,
    pub pending_backchannel_deliveries: usize,
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
    endpoint_dispatch: Option<LinkEndpointDispatchHandle>,
    pending_packet_dispatches: Vec<PendingPacketDispatch>,
    transport_tx: mpsc::Sender<TransportMessage>,
    /// Ordered staging for temporary transport backpressure. Resource state
    /// can advance only after frames are accepted here or by the actor.
    pending_transport: VecDeque<TransportMessage>,
    pending_endpoint_binds: HashMap<[u8; 16], PendingEndpointBind>,
    pending_endpoint_sends: Vec<PendingEndpointSend>,
    pending_endpoint_cleanups: Vec<PendingEndpointCleanup>,
    endpoint_lifecycle_tx: mpsc::UnboundedSender<LinkEndpointLifecycleEvent>,
    endpoint_lifecycle_rx: mpsc::UnboundedReceiver<LinkEndpointLifecycleEvent>,
    /// Reusable upstream-style Direct links keyed by LXMF delivery destination hash.
    direct_links: HashMap<[u8; 16], [u8; 16]>,
    /// Reusable upstream-style inbound backchannels keyed by remote LXMF delivery destination hash.
    backchannel_links: HashMap<[u8; 16], [u8; 16]>,
    pending: HashMap<[u8; 16], PendingDelivery>,
    backchannel_tx: Option<mpsc::Sender<BackchannelSendCommand>>,
    backchannel_cancellation_aware: bool,
    /// Unbounded: inbound link data is proved to the peer on receipt, so
    /// local delivery must not drop.
    inbound_packet_tx: Option<mpsc::UnboundedSender<(Vec<u8>, [u8; 16])>>,
    /// Maximum decoded size accepted for a reverse Resource on an
    /// initiator-owned reusable Link. Defaults to the LXMF delivery limit and
    /// can be tightened or expanded by the embedding router.
    inbound_resource_limit_bytes: usize,
    inbound_resource_accept_handler: Option<InboundResourceAcceptHandler>,
    inbound_resource_concluded_handler: Option<InboundResourceConcludedHandler>,
    inbound_resource_completion_handler: Option<InboundResourceCompletionHandler>,
    pending_backchannel_starts: Vec<PendingBackchannelStart>,
    pending_backchannel_deliveries: HashMap<BackchannelProofKey, PendingBackchannelDelivery>,
    pending_backchannel_resource_cancellations: VecDeque<BackchannelResourceCancelRequest>,
    /// Authenticated proofs can cross the async application adapter before
    /// the corresponding send receipt is observed. Retain only exact proof
    /// keys for Links that still have a pending send receipt, then reconcile
    /// them when that receipt installs delivery ownership.
    early_backchannel_proofs: HashMap<BackchannelProofKey, Instant>,
    early_backchannel_waits: HashMap<BackchannelProofKey, BackchannelWaitWindow>,
    early_backchannel_packet_cancellations:
        HashMap<BackchannelProofKey, (LinkEndpointDispatchCancellation, Instant)>,
    cancelled_backchannel_packets: HashMap<BackchannelProofKey, Instant>,
    early_backchannel_resource_conclusions:
        HashMap<BackchannelProofKey, EarlyBackchannelResourceConclusion>,
    identity_pub: Option<[u8; 64]>,
    identity_key: Option<Ed25519PrivateKey>,
    event_tx: mpsc::Sender<DestinationEvent>,
    event_rx: mpsc::Receiver<DestinationEvent>,
    delivery_events: VecDeque<LxmfDeliveryEvent>,
}

impl LinkDeliveryManager {
    pub fn new(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity_pub: Option<[u8; 64]>,
        identity_key: Option<Ed25519PrivateKey>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(256);
        let (endpoint_lifecycle_tx, endpoint_lifecycle_rx) = mpsc::unbounded_channel();
        Self {
            endpoint_dispatch: None,
            pending_packet_dispatches: Vec::new(),
            transport_tx,
            pending_transport: VecDeque::new(),
            pending_endpoint_binds: HashMap::new(),
            pending_endpoint_sends: Vec::new(),
            pending_endpoint_cleanups: Vec::new(),
            endpoint_lifecycle_tx,
            endpoint_lifecycle_rx,
            direct_links: HashMap::new(),
            backchannel_links: HashMap::new(),
            pending: HashMap::new(),
            backchannel_tx: None,
            backchannel_cancellation_aware: false,
            inbound_packet_tx: None,
            inbound_resource_limit_bytes: DELIVERY_LIMIT * BYTES_PER_KILOBYTE,
            inbound_resource_accept_handler: None,
            inbound_resource_concluded_handler: None,
            inbound_resource_completion_handler: None,
            pending_backchannel_starts: Vec::new(),
            pending_backchannel_deliveries: HashMap::new(),
            pending_backchannel_resource_cancellations: VecDeque::new(),
            early_backchannel_proofs: HashMap::new(),
            early_backchannel_waits: HashMap::new(),
            early_backchannel_packet_cancellations: HashMap::new(),
            cancelled_backchannel_packets: HashMap::new(),
            early_backchannel_resource_conclusions: HashMap::new(),
            identity_pub,
            identity_key,
            event_tx,
            event_rx,
            delivery_events: VecDeque::new(),
        }
    }

    /// Use exact generation-bound driver-admission receipts for subsequently
    /// established Links. Existing Links retain their original binding path.
    /// The handle must belong to the same transport as this manager.
    pub fn set_link_endpoint_dispatch_handle(&mut self, handle: LinkEndpointDispatchHandle) {
        self.endpoint_dispatch = Some(handle);
    }

    /// Install the adapter used to send LXMF payloads over inbound
    /// authenticated backchannel Links owned by the embedding runtime.
    pub fn set_backchannel_sender(&mut self, tx: mpsc::Sender<BackchannelSendCommand>) {
        self.backchannel_tx = Some(tx);
        self.backchannel_cancellation_aware = false;
    }

    /// Install an adapter that fences closed receipt publication and retains
    /// exact cleanup ownership. New starts close/drain their receipt immediately
    /// on user cancellation; existing starts retain their captured policy.
    /// Legacy adapters must continue using `set_backchannel_sender` instead.
    pub fn set_cancellation_aware_backchannel_sender(
        &mut self,
        tx: mpsc::Sender<BackchannelSendCommand>,
    ) {
        self.backchannel_tx = Some(tx);
        self.backchannel_cancellation_aware = true;
    }

    /// Install the adapter used to deliver inbound LXMF payloads that arrive
    /// over outbound reusable Direct links. This is required for peer
    /// backchannels: the outbound Direct manager owns the link_id destination,
    /// so ordinary link DATA replies route back here rather than to the
    /// responder-side LinkManager.
    pub fn set_inbound_packet_sender(&mut self, tx: mpsc::UnboundedSender<(Vec<u8>, [u8; 16])>) {
        self.inbound_packet_tx = Some(tx);
    }

    pub fn set_inbound_resource_limit_bytes(&mut self, limit: usize) {
        self.inbound_resource_limit_bytes = limit.min(MAX_RESOURCE_SIZE);
    }

    pub fn set_inbound_resource_accept_handler<F>(&mut self, handler: F)
    where
        F: Fn([u8; 16], &ResourceAdvertisement) -> bool + Send + Sync + 'static,
    {
        self.inbound_resource_accept_handler = Some(Arc::new(handler));
    }

    pub fn set_inbound_resource_concluded_handler<F>(&mut self, handler: F)
    where
        F: Fn([u8; 16], [u8; 32]) + Send + Sync + 'static,
    {
        self.inbound_resource_concluded_handler = Some(Arc::new(handler));
    }

    /// Hand off one completed reverse Resource while its application admission
    /// ownership is still live. The ordinary concluded callback runs afterwards.
    /// This replaces only Resource payload delivery through the packet sender;
    /// ordinary packets are unchanged. A handler can move an exact Resource
    /// admission lease and this Vec into one retained application envelope.
    pub fn set_inbound_resource_completion_handler<F>(&mut self, handler: F)
    where
        F: Fn([u8; 16], [u8; 32], Vec<u8>) + Send + Sync + 'static,
    {
        self.inbound_resource_completion_handler = Some(Arc::new(handler));
    }

    /// Register an inbound authenticated Link as a reusable backchannel for a
    /// remote LXMF delivery destination.
    pub fn register_backchannel(&mut self, dest_hash: [u8; 16], link_id: [u8; 16]) {
        self.backchannel_links.insert(dest_hash, link_id);
        tracing::info!(
            link_id = %hex_encode(&link_id),
            dest = %hex_encode(&dest_hash),
            "registered LXMF delivery backchannel"
        );
    }

    pub fn remove_backchannel(&mut self, dest_hash: &[u8; 16]) -> Option<[u8; 16]> {
        self.backchannel_links.remove(dest_hash)
    }

    fn remove_backchannel_owner(&mut self, dest_hash: [u8; 16], link_id: [u8; 16]) {
        if self.backchannel_links.get(&dest_hash) == Some(&link_id) {
            self.backchannel_links.remove(&dest_hash);
        }
    }

    fn retain_failed_backchannel_start(
        &mut self,
        mut start: PendingBackchannelStart,
        reason: String,
    ) -> DeliveryResult {
        let result = fail_backchannel_start_in_place(&mut self.delivery_events, &mut start, reason);
        if start.cancellation_aware {
            start.receiver.close();
            if let Ok(receipt) = start.receiver.try_recv() {
                if let Ok(receipt) = receipt {
                    self.cancel_backchannel_receipt(receipt);
                }
                return result;
            }
        }
        // The bridge may still own a raced receipt. Keep only its original,
        // finite reservation, never the failed message bytes or visible work.
        self.pending_backchannel_starts.push(start);
        result
    }

    /// Remove cached backchannel state for a closed Link and fail any
    /// in-flight backchannel sends that were using it.
    pub fn fail_backchannel_link(
        &mut self,
        link_id: [u8; 16],
        reason: &str,
    ) -> Vec<DeliveryResult> {
        let mut results = Vec::new();
        let has_early_settlement = self
            .early_backchannel_proofs
            .keys()
            .chain(self.early_backchannel_resource_conclusions.keys())
            .any(|key| key.link_id() == link_id);
        let removed_destinations: Vec<_> = self
            .backchannel_links
            .iter()
            .filter_map(|(dest_hash, cached_link)| (*cached_link == link_id).then_some(*dest_hash))
            .collect();
        for dest_hash in &removed_destinations {
            self.backchannel_links.remove(dest_hash);
        }

        let starts = std::mem::take(&mut self.pending_backchannel_starts);
        for mut start in starts {
            if start.link_id == link_id {
                if start.cancelled || has_early_settlement {
                    // The Link is unavailable for all new work immediately, but
                    // authenticated settlement event already observed on another
                    // adapter channel must be allowed to meet its exact receipt.
                    // A cancelled start likewise needs the receipt to learn
                    // whether an external Resource must be cancelled.
                    start.closed_reason = Some(reason.to_string());
                    self.pending_backchannel_starts.push(start);
                } else {
                    results.push(self.retain_failed_backchannel_start(start, reason.to_string()));
                }
            } else {
                self.pending_backchannel_starts.push(start);
            }
        }

        let delivery_keys: Vec<_> = self
            .pending_backchannel_deliveries
            .iter()
            .filter_map(|(key, delivery)| (delivery.link_id == link_id).then_some(*key))
            .collect();
        for key in delivery_keys {
            if let Some(delivery) = self.pending_backchannel_deliveries.remove(&key) {
                self.cancel_backchannel_packet_key(key, delivery.packet_cancellation);
                self.delivery_events.push_back(backchannel_delivery_event(
                    BackchannelDeliveryEventInput {
                        kind: LxmfDeliveryEventKind::Failed,
                        message: &delivery.message,
                        dest_hash: delivery.dest_hash,
                        link_id: delivery.link_id,
                        representation: delivery.representation,
                        progress: Some(delivery.message.progress),
                        reason: Some(reason.to_string()),
                        link_state: LinkState::Closed,
                        delivery_state: DeliveryState::Failed,
                    },
                ));
                results.push(DeliveryResult::Failed {
                    link_id: delivery.link_id,
                    msg_hash: delivery.message.hash,
                    dest_hash: delivery.dest_hash,
                    message: delivery.message,
                    reason: reason.to_string(),
                });
            }
        }
        self.prune_early_backchannel_settlement();

        if !removed_destinations.is_empty()
            || !results.is_empty()
            || self
                .pending_backchannel_starts
                .iter()
                .any(|start| start.link_id == link_id)
        {
            tracing::debug!(
                link_id = %hex_encode(&link_id),
                removed_backchannels = removed_destinations.len(),
                failed_deliveries = results.len(),
                settling_receipts = self
                    .pending_backchannel_starts
                    .iter()
                    .filter(|start| start.link_id == link_id)
                    .count(),
                reason,
                "removed closed LXMF backchannel Link"
            );
        }

        results
    }

    /// Start a direct delivery and return the tracking `link_id`.
    pub fn start_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
    ) -> Result<[u8; 16], LinkDeliveryStartFailure> {
        self.start_delivery_with_timing(
            message,
            dest_hash,
            hops,
            LinkEstablishmentTiming::default(),
        )
    }

    /// Start a direct delivery with authoritative first-hop timing and return
    /// the tracking `link_id`.
    pub fn start_delivery_with_timing(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
        timing: LinkEstablishmentTiming,
    ) -> Result<[u8; 16], LinkDeliveryStartFailure> {
        self.start_delivery_with_report_and_timing(message, dest_hash, hops, timing)
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
        self.start_delivery_with_report_and_timing(
            message,
            dest_hash,
            hops,
            LinkEstablishmentTiming::default(),
        )
    }

    /// Start a Direct delivery with authoritative first-hop timing and return
    /// whether it created, reused, or queued on reusable Link state.
    pub fn start_delivery_with_report_and_timing(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
        timing: LinkEstablishmentTiming,
    ) -> Result<DirectLinkStartReport, LinkDeliveryStartFailure> {
        self.start_direct_delivery(message, dest_hash, hops, timing)
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
        self.start_packed_delivery_with_timing(
            message,
            dest_hash,
            hops,
            packed_payload,
            auto_compress,
            LinkEstablishmentTiming::default(),
        )
    }

    /// Start a packed Link delivery with authoritative first-hop timing.
    pub fn start_packed_delivery_with_timing(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
        packed_payload: Vec<u8>,
        auto_compress: bool,
        timing: LinkEstablishmentTiming,
    ) -> Result<[u8; 16], LinkDeliveryStartFailure> {
        self.start_delivery_inner(
            message,
            dest_hash,
            hops,
            LinkDeliveryStartOptions::packed(timing, packed_payload, auto_compress),
        )
    }

    /// Start a Direct delivery over a registered inbound backchannel Link.
    pub fn start_backchannel_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
    ) -> Result<BackchannelStartReport, BackchannelStartFailure> {
        self.prune_early_backchannel_settlement();
        // Reserve reconciliation space before a runtime command can exist.
        // Cancelled keys are never evicted while their exact packet could
        // still be in the driver's admission FIFO.
        if self.pending_backchannel_starts.len()
            + self.pending_backchannel_deliveries.len()
            + self.cancelled_backchannel_packets.len()
            >= BACKCHANNEL_EARLY_PROOF_LIMIT
        {
            return Err(BackchannelStartFailure {
                error: BackchannelStartError::CommandFull,
                message: Box::new(message),
            });
        }
        let Some(link_id) = self.backchannel_links.get(&dest_hash).copied() else {
            return Err(BackchannelStartFailure {
                error: BackchannelStartError::NoBackchannel,
                message: Box::new(message),
            });
        };
        let Some(command_tx) = self.backchannel_tx.clone() else {
            return Err(BackchannelStartFailure {
                error: BackchannelStartError::SenderUnavailable,
                message: Box::new(message),
            });
        };

        let payload = match message.pack() {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    dest = %hex_encode(&dest_hash),
                    error = ?error,
                    "failed to pack LXMF for backchannel delivery"
                );
                return Err(BackchannelStartFailure {
                    error: BackchannelStartError::PackFailed,
                    message: Box::new(message),
                });
            }
        };
        let auto_compress = message.auto_compress;
        let msg_hash = message.hash;
        let attempts = message.delivery_attempts;
        let (result_tx, result_rx) = oneshot::channel();
        let command = BackchannelSendCommand {
            link_id,
            payload,
            auto_compress,
            result_tx,
        };
        let command_permit = match command_tx.try_reserve_owned() {
            Ok(permit) => permit,
            Err(err) => {
                self.remove_backchannel_owner(dest_hash, link_id);
                let error = match err {
                    TrySendError::Full(_) => BackchannelStartError::CommandFull,
                    TrySendError::Closed(_) => BackchannelStartError::CommandClosed,
                };
                tracing::warn!(
                    link_id = %hex_encode(&link_id),
                    dest = %hex_encode(&dest_hash),
                    error = %error,
                    "failed to reserve LXMF backchannel send command"
                );
                return Err(BackchannelStartFailure {
                    error,
                    message: Box::new(message),
                });
            }
        };

        tracing::info!(
            link_id = %hex_encode(&link_id),
            dest = %hex_encode(&dest_hash),
            "routing Direct LXMF message over authenticated backchannel Link"
        );
        self.delivery_events.push_back(LxmfDeliveryEvent {
            kind: LxmfDeliveryEventKind::BackchannelLinkReused,
            method: LxmfDeliveryEventMethod::Direct,
            link_id,
            dest_hash,
            msg_hash,
            attempts,
            progress: Some(0.05),
            representation: DeliveryRepresentation::Unknown,
            link_state: LinkState::Active,
            delivery_state: DeliveryState::Transferring,
            queued_deliveries: self
                .backchannel_link_snapshot(dest_hash)
                .unwrap()
                .queued_deliveries,
            in_flight_deliveries: self
                .backchannel_link_snapshot(dest_hash)
                .unwrap()
                .in_flight_deliveries
                + 1,
            reason: None,
        });
        self.pending_backchannel_starts
            .push(PendingBackchannelStart {
                receiver: result_rx,
                message,
                dest_hash,
                link_id,
                requested_at: Instant::now(),
                cancelled: false,
                cancellation_aware: self.backchannel_cancellation_aware,
                closed_reason: None,
            });
        let report = BackchannelStartReport {
            link_id,
            dest_hash,
            queued_deliveries: self
                .backchannel_link_snapshot(dest_hash)
                .unwrap()
                .queued_deliveries,
            in_flight_deliveries: self
                .backchannel_link_snapshot(dest_hash)
                .unwrap()
                .in_flight_deliveries
                + 1,
        };
        command_permit.send(command);
        Ok(report)
    }

    fn start_direct_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
        timing: LinkEstablishmentTiming,
    ) -> Result<DirectLinkStartReport, LinkDeliveryStartFailure> {
        if let Some(link_id) = self.direct_links.get(&dest_hash).copied() {
            let idle_expired = self
                .pending
                .get(&link_id)
                .is_some_and(|delivery| delivery.reusable && direct_link_idle_expired(delivery));
            if idle_expired {
                tracing::debug!(
                    link_id = %hex_encode(&link_id),
                    dest = %hex_encode(&dest_hash),
                    "discarding inactive cached Direct link before reuse"
                );
                if let Some(mut delivery) = self.pending.remove(&link_id) {
                    let graceful_release = send_link_teardown(
                        &self.transport_tx,
                        &mut self.pending_transport,
                        &mut self.pending_endpoint_sends,
                        &link_id,
                        &mut delivery.link,
                    );
                    if !graceful_release {
                        let _ = stage_link_endpoint_unbind(
                            &self.transport_tx,
                            &mut self.pending_transport,
                            &mut self.pending_endpoint_cleanups,
                            link_id,
                        );
                    }
                }
                self.pending_endpoint_binds.remove(&link_id);
                self.direct_links.remove(&dest_hash);
            } else if let Some(delivery) = self
                .pending
                .get_mut(&link_id)
                .filter(|delivery| delivery.reusable)
            {
                let msg_hash = message.hash;
                let attempts = message.delivery_attempts;
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
                let report = DirectLinkStartReport {
                    link_id,
                    dest_hash,
                    kind,
                    link_state,
                    delivery_state: delivery.state,
                    queued_deliveries: delivery.queued.len(),
                    in_flight_deliveries: usize::from(delivery.state != DeliveryState::Idle),
                };
                self.delivery_events.push_back(LxmfDeliveryEvent {
                    kind: match kind {
                        DirectLinkStartKind::ReusedActiveDirect => {
                            LxmfDeliveryEventKind::DirectLinkReused
                        }
                        DirectLinkStartKind::QueuedOnDirect => {
                            LxmfDeliveryEventKind::DirectLinkPending
                        }
                        DirectLinkStartKind::NewDirect => LxmfDeliveryEventKind::LinkEstablishing,
                    },
                    method: LxmfDeliveryEventMethod::Direct,
                    link_id,
                    dest_hash,
                    msg_hash,
                    attempts,
                    progress: Some(if link_state == LinkState::Active {
                        0.05
                    } else {
                        0.03
                    }),
                    representation: DeliveryRepresentation::Unknown,
                    link_state: report.link_state,
                    delivery_state: report.delivery_state,
                    queued_deliveries: report.queued_deliveries,
                    in_flight_deliveries: report.in_flight_deliveries,
                    reason: None,
                });
                return Ok(report);
            } else {
                self.direct_links.remove(&dest_hash);
            }
        }

        let msg_hash = message.hash;
        let attempts = message.delivery_attempts;
        let link_id = self.start_delivery_inner(
            message,
            dest_hash,
            hops,
            LinkDeliveryStartOptions::direct(timing),
        )?;
        let snapshot = self.direct_link_snapshot(dest_hash);
        let report = DirectLinkStartReport {
            link_id,
            dest_hash,
            kind: DirectLinkStartKind::NewDirect,
            link_state: snapshot.map(|s| s.link_state).unwrap_or(LinkState::Pending),
            delivery_state: snapshot
                .map(|s| s.delivery_state)
                .unwrap_or(DeliveryState::Establishing),
            queued_deliveries: 0,
            in_flight_deliveries: 1,
        };
        self.delivery_events.push_back(LxmfDeliveryEvent {
            kind: LxmfDeliveryEventKind::LinkEstablishing,
            method: LxmfDeliveryEventMethod::Direct,
            link_id,
            dest_hash,
            msg_hash,
            attempts,
            progress: Some(0.03),
            representation: DeliveryRepresentation::Unknown,
            link_state: report.link_state,
            delivery_state: report.delivery_state,
            queued_deliveries: report.queued_deliveries,
            in_flight_deliveries: report.in_flight_deliveries,
            reason: None,
        });
        Ok(report)
    }

    fn start_delivery_inner(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
        options: LinkDeliveryStartOptions,
    ) -> Result<[u8; 16], LinkDeliveryStartFailure> {
        let LinkDeliveryStartOptions {
            timing,
            packed_override,
            auto_compress,
            reusable,
        } = options;
        let msg_hash = message.hash;
        let (mut link, request_data) = Link::new_initiator(dest_hash, hops);
        link.extend_establishment_timeout(timing.first_hop_timeout().as_secs_f64());
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
                return Err(LinkDeliveryStartFailure {
                    error,
                    message: Box::new(message),
                });
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
                return Err(LinkDeliveryStartFailure {
                    error,
                    message: Box::new(message),
                });
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

        let establishment_timeout = timing.timeout_for_hops(hops);
        let establishment_timeout_secs = establishment_timeout.as_secs_f64();
        // Bound local pre-send preparation separately from the packet proof
        // clock, which starts only when the packet is locally admitted.
        let timeout_secs = BACKCHANNEL_SEND_COMMAND_TIMEOUT.as_secs_f64();
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
                remaining_segments: None,
                packet_proof_hash: None,
                establishment_timeout,
                timeout: Duration::from_secs_f64(timeout_secs),
                msg_hash,
                failure_reason: None,
                attached_interface: None,
                endpoint_dispatch_token: None,
                packet_awaiting_dispatch: false,
                pretransfer_identify_staged: false,
                endpoint_release_queued: false,
                reusable,
                backchannel_identified: false,
                queued: VecDeque::new(),
                inbound_resources: HashMap::new(),
                inbound_split_resources: HashMap::new(),
                inbound_segment_routing: HashMap::new(),
                inbound_resource_lifecycles: HashMap::new(),
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

    fn poll_packet_dispatches(&mut self) {
        self.pending_packet_dispatches.retain_mut(|pending| {
            let Some(delivery) = self.pending.get_mut(&pending.link_id) else {
                return false;
            };
            if delivery.state != DeliveryState::AwaitingProof
                || delivery.packet_proof_hash != Some(pending.packet_hash)
            {
                // Dropping a not-yet-admitted receipt cancels its exact FIFO item.
                return false;
            }
            match pending.result_rx.try_recv() {
                Ok(LinkEndpointDispatchOutcome::Sent {
                    packet_hash,
                    dispatched_at,
                }) if packet_hash == pending.packet_hash => {
                    delivery.packet_awaiting_dispatch = false;
                    delivery.started_at = dispatched_at;
                    delivery.timeout = delivery.link.packet_proof_timeout();
                }
                Ok(LinkEndpointDispatchOutcome::Rejected(result)) => {
                    delivery.state = DeliveryState::Failed;
                    delivery.failure_reason =
                        Some(format!("Link endpoint send rejected: {result:?}"));
                }
                Ok(LinkEndpointDispatchOutcome::Expired) => {
                    delivery.state = DeliveryState::Failed;
                    delivery.failure_reason = Some("Link endpoint admission timeout".to_string());
                }
                Ok(_) | Err(oneshot::error::TryRecvError::Closed) => {
                    delivery.state = DeliveryState::Failed;
                    delivery.failure_reason =
                        Some("Link endpoint send result channel closed".to_string());
                }
                Err(oneshot::error::TryRecvError::Empty) => return true,
            }
            false
        });
    }

    fn poll_endpoint_send_results(&mut self) {
        self.poll_packet_dispatches();
        let mut still_pending = Vec::new();
        let mut endpoint_sends = std::mem::take(&mut self.pending_endpoint_sends);
        for mut pending in endpoint_sends.drain(..) {
            match pending.result_rx.try_recv() {
                Ok(
                    result @ (LinkEndpointSendResult::Sent | LinkEndpointSendResult::Queued { .. }),
                ) => {
                    if self.pending.contains_key(&pending.link_id) {
                        match pending.success {
                            EndpointSendSuccess::None | EndpointSendSuccess::FinishHandshake => {}
                            EndpointSendSuccess::StartPacketProofClock(packet_hash) => {
                                let delivery = self.pending.get_mut(&pending.link_id).unwrap();
                                // A proof or cancellation can beat this acknowledgement.
                                // Never rearm a terminal owner or the next queued message.
                                if delivery.state == DeliveryState::AwaitingProof
                                    && delivery.packet_proof_hash == Some(packet_hash)
                                {
                                    delivery.started_at = Instant::now();
                                    delivery.packet_awaiting_dispatch =
                                        !matches!(result, LinkEndpointSendResult::Sent);
                                    delivery.timeout = delivery
                                        .link
                                        .packet_proof_timeout()
                                        .saturating_add(if delivery.packet_awaiting_dispatch {
                                            BACKCHANNEL_SEND_COMMAND_TIMEOUT
                                        } else {
                                            Duration::ZERO
                                        });
                                }
                            }
                            EndpointSendSuccess::PublishInboundPacket(plaintext) => {
                                if let Some(ref tx) = self.inbound_packet_tx {
                                    let _ = tx.send((plaintext, pending.link_id));
                                }
                            }
                        }
                    }
                }
                Ok(result) => {
                    let reason = format!("Link endpoint send rejected: {result:?}");
                    tracing::warn!(
                        link_id = %hex_encode(&pending.link_id),
                        ?result,
                        final_send = pending.final_send,
                        "Direct Link endpoint send rejected"
                    );
                    if let Some(delivery) = self.pending.get_mut(&pending.link_id) {
                        delivery.state = DeliveryState::Failed;
                        delivery.failure_reason = Some(reason);
                    }
                    if pending.final_send {
                        let _ = stage_link_endpoint_unbind(
                            &self.transport_tx,
                            &mut self.pending_transport,
                            &mut self.pending_endpoint_cleanups,
                            pending.link_id,
                        );
                    }
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    if let Some(delivery) = self.pending.get_mut(&pending.link_id) {
                        delivery.state = DeliveryState::Failed;
                        delivery.failure_reason =
                            Some("Link endpoint send result channel closed".to_string());
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => still_pending.push(pending),
            }
        }
        self.pending_endpoint_sends = still_pending;

        let mut cleanup_pending = Vec::new();
        let mut cleanups = std::mem::take(&mut self.pending_endpoint_cleanups);
        for mut pending in cleanups.drain(..) {
            match pending.result_rx.try_recv() {
                Ok(LinkEndpointUnbindResult::Unbound | LinkEndpointUnbindResult::NotBound) => {
                    let _ = stage_transport(
                        &self.transport_tx,
                        &mut self.pending_transport,
                        TransportMessage::DeregisterDestination {
                            hash: pending.link_id,
                        },
                    );
                }
                Ok(LinkEndpointUnbindResult::RoleMismatch) => {
                    tracing::warn!(
                        link_id = %hex_encode(&pending.link_id),
                        "refusing to deregister a Direct Link owned by the opposite role"
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
            if event.binding.role != LinkEndpointRole::Initiator {
                continue;
            }
            if let Some(delivery) = self.pending.get_mut(&event.binding.link_id) {
                if delivery.attached_interface == Some(event.binding.interface_id)
                    || self
                        .pending_endpoint_binds
                        .get(&event.binding.link_id)
                        .is_some_and(|pending| pending.interface_id == event.binding.interface_id)
                {
                    tracing::warn!(
                        link_id = %hex_encode(&event.binding.link_id),
                        interface_id = event.binding.interface_id,
                        reason = ?event.reason,
                        dropped_packets = event.dropped_packets,
                        "Direct Link endpoint terminated"
                    );
                    delivery.attached_interface = None;
                    delivery.state = DeliveryState::Failed;
                    delivery.failure_reason =
                        Some(format!("Link endpoint terminated: {:?}", event.reason));
                    self.pending_endpoint_binds.remove(&event.binding.link_id);
                }
            }
        }

        let link_ids: Vec<[u8; 16]> = self.pending_endpoint_binds.keys().copied().collect();
        for link_id in link_ids {
            if !self
                .pending
                .get(&link_id)
                .is_some_and(|delivery| delivery.state == DeliveryState::Establishing)
            {
                // Do not publish an exact bind token after its delivery has
                // failed/cancelled. Dropping the unread bind receipt retires
                // only that unpublished transport binding.
                self.pending_endpoint_binds.remove(&link_id);
                continue;
            }
            let outcome = {
                let Some(pending) = self.pending_endpoint_binds.get_mut(&link_id) else {
                    continue;
                };
                match pending.result_rx.try_recv() {
                    Ok(result) => Some(Ok(result)),
                    Err(oneshot::error::TryRecvError::Closed) => Some(Err(())),
                    Err(oneshot::error::TryRecvError::Empty) => None,
                }
            };
            let Some(outcome) = outcome else {
                continue;
            };
            let Some(pending) = self.pending_endpoint_binds.remove(&link_id) else {
                continue;
            };
            match outcome {
                Ok((
                    LinkEndpointBindResult::Bound | LinkEndpointBindResult::AlreadyBound,
                    token,
                )) => {
                    if let Some(delivery) = self.pending.get_mut(&link_id) {
                        delivery.attached_interface = Some(pending.interface_id);
                        delivery.endpoint_dispatch_token = token;
                    }
                    let success = if self.endpoint_dispatch.is_some() {
                        EndpointSendSuccess::FinishHandshake
                    } else {
                        EndpointSendSuccess::None
                    };
                    if let Err(reason) = stage_link_endpoint_with_success(
                        &self.transport_tx,
                        &mut self.pending_transport,
                        &mut self.pending_endpoint_sends,
                        link_id,
                        pending.rtt_request,
                        success,
                    ) {
                        if let Some(delivery) = self.pending.get_mut(&link_id) {
                            delivery.state = DeliveryState::Failed;
                            delivery.failure_reason = Some(reason.to_string());
                        }
                    } else if let Some(delivery) = self.pending.get_mut(&link_id) {
                        delivery.state = DeliveryState::Identifying;
                        delivery.started_at = Instant::now();
                    }
                }
                Ok((
                    LinkEndpointBindResult::Conflict { .. }
                    | LinkEndpointBindResult::InterfaceUnavailable,
                    _,
                ))
                | Err(()) => {
                    if let Some(delivery) = self.pending.get_mut(&link_id) {
                        delivery.state = DeliveryState::Failed;
                        delivery.failure_reason = Some("Link endpoint binding failed".to_string());
                    }
                }
            }
        }
    }

    /// Drain inbound transport events and dispatch by packet context.
    ///
    /// Call before [`Self::tick`] each cycle. Routes `LRPROOF`, `ResourceHmu`, `ResourceReq`,
    /// and `ResourcePrf` contexts to their handlers.
    pub fn drain_events(&mut self, known_identities: &HashMap<String, [u8; 64]>) {
        self.poll_endpoint_control();
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }

        for event in events {
            match event {
                DestinationEvent::LinkClosed { link_id } => {
                    self.handle_link_closed(&link_id, None);
                }
                DestinationEvent::InboundPacket {
                    raw, interface_id, ..
                } => {
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
                    let is_link_proof =
                        matches!(
                            header.context,
                            rns_wire::context::PacketContext::Lrproof
                                | rns_wire::context::PacketContext::None
                        ) && header.flags.packet_type == rns_wire::flags::PacketType::Proof
                            && self.pending.get(&link_id).is_some_and(|delivery| {
                                delivery.state == DeliveryState::Establishing
                            });
                    if is_link_proof {
                        if self.pending_endpoint_binds.contains_key(&link_id) {
                            continue;
                        }
                    } else if self
                        .pending
                        .get(&link_id)
                        .is_none_or(|delivery| delivery.attached_interface != Some(interface_id))
                    {
                        tracing::warn!(
                            link_id = %hex_encode(&link_id),
                            interface_id,
                            attached_interface = ?self
                                .pending
                                .get(&link_id)
                                .and_then(|delivery| delivery.attached_interface),
                            "rejected Direct Link packet from wrong interface"
                        );
                        continue;
                    }

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
                                            interface_id,
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
                                                interface_id,
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
                        rns_wire::context::PacketContext::None
                            if header.flags.packet_type == rns_wire::flags::PacketType::Data =>
                        {
                            self.handle_inbound_link_packet(
                                &link_id,
                                &raw,
                                header.flags.header_type,
                                data,
                            );
                        }
                        rns_wire::context::PacketContext::ResourceAdv
                            if header.flags.packet_type == rns_wire::flags::PacketType::Data =>
                        {
                            self.handle_inbound_resource_advertisement(&link_id, data);
                        }
                        rns_wire::context::PacketContext::Resource
                            if header.flags.packet_type == rns_wire::flags::PacketType::Data =>
                        {
                            self.handle_inbound_resource_part(&link_id, data);
                        }
                        rns_wire::context::PacketContext::ResourceHmu => {
                            let plaintext = self
                                .pending
                                .get(&link_id)
                                .and_then(|d| d.link.decrypt(data).ok());
                            if let Some(pt) = plaintext {
                                if !self.handle_inbound_resource_hmu(&link_id, &pt) {
                                    self.handle_hmu(&link_id, &pt);
                                }
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
                        rns_wire::context::PacketContext::ResourceIcl => {
                            let plaintext = self
                                .pending
                                .get(&link_id)
                                .and_then(|d| d.link.decrypt(data).ok());
                            if let Some(pt) = plaintext {
                                self.handle_inbound_resource_cancel(&link_id, &pt);
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
        interface_id: InterfaceId,
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

                let rtt_request = OutboundRequest {
                    raw: Bytes::from(rtt_raw),
                    destination_hash: *link_id,
                };
                let binding = LinkEndpointBinding {
                    link_id: *link_id,
                    interface_id,
                    role: LinkEndpointRole::Initiator,
                };
                let result_rx = if let Some(handle) = &self.endpoint_dispatch {
                    match handle.try_bind(binding, self.endpoint_lifecycle_tx.clone()) {
                        Ok(receipt) => EndpointBindReceiver::Exact(receipt),
                        Err(_) => {
                            delivery.state = DeliveryState::Failed;
                            delivery.failure_reason =
                                Some("Link endpoint binding failed".to_string());
                            return false;
                        }
                    }
                } else {
                    let (result_tx, result_rx) = oneshot::channel();
                    if let Err(reason) = stage_transport(
                        &self.transport_tx,
                        &mut self.pending_transport,
                        TransportMessage::BindLinkEndpoint {
                            binding,
                            lifecycle_tx: self.endpoint_lifecycle_tx.clone(),
                            result_tx,
                        },
                    ) {
                        delivery.state = DeliveryState::Failed;
                        delivery.failure_reason = Some(reason.to_string());
                        return false;
                    }
                    EndpointBindReceiver::Legacy(result_rx)
                };
                self.pending_endpoint_binds.insert(
                    *link_id,
                    PendingEndpointBind {
                        interface_id,
                        rtt_request,
                        result_rx,
                    },
                );
                true
            }
            Err(_) => false,
        }
    }

    fn handle_inbound_link_packet(
        &mut self,
        link_id: &[u8; 16],
        raw: &[u8],
        header_type: rns_wire::flags::HeaderType,
        encrypted_data: &[u8],
    ) -> bool {
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };
        if !delivery.reusable || !delivery.link.is_active() {
            return false;
        }

        let packet_hash = rns_wire::hash::packet_hash(raw, header_type);
        let Ok(proof_data) = delivery.link.prove_packet_with_local_signer(&packet_hash) else {
            return false;
        };
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
            destination_hash: *link_id,
            context: rns_wire::context::PacketContext::LinkProof,
        };
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&proof_data);
        delivery.link.record_inbound();
        delivery.link.record_rx(encrypted_data.len());
        let Ok(plaintext) = delivery.link.decrypt(encrypted_data) else {
            return false;
        };

        if let Err(reason) = stage_link_endpoint_with_success(
            &self.transport_tx,
            &mut self.pending_transport,
            &mut self.pending_endpoint_sends,
            *link_id,
            OutboundRequest {
                raw: Bytes::from(proof_raw),
                destination_hash: *link_id,
            },
            EndpointSendSuccess::PublishInboundPacket(plaintext),
        ) {
            delivery.state = DeliveryState::Failed;
            delivery.failure_reason = Some(reason.to_string());
            return false;
        }

        true
    }

    fn handle_inbound_resource_advertisement(
        &mut self,
        link_id: &[u8; 16],
        encrypted_data: &[u8],
    ) -> bool {
        let accept_handler = self.inbound_resource_accept_handler.clone();
        let concluded_handler = self.inbound_resource_concluded_handler.clone();
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };
        if !delivery.reusable || !delivery.link.is_active() {
            return false;
        }

        delivery.link.record_inbound();
        delivery.link.record_rx(encrypted_data.len());
        let Ok(plaintext) = delivery.link.decrypt(encrypted_data) else {
            return false;
        };
        let Ok(adv) = ResourceAdvertisement::unpack(&plaintext) else {
            return false;
        };

        let is_split = adv.flags.split || adv.total_segments > 1;
        let resource_id = if is_split {
            adv.original_hash
        } else {
            adv.resource_hash
        };
        let structurally_valid = adv.total_segments > 0
            && adv.total_segments <= MAX_SEGMENTS
            && adv.segment_index > 0
            && adv.segment_index <= adv.total_segments
            && !adv.flags.is_request
            && !adv.flags.is_response;
        let lifecycle_valid = delivery
            .inbound_resource_lifecycles
            .get(&resource_id)
            .map(|lifecycle| {
                lifecycle.data_size == adv.data_size
                    && lifecycle.total_segments == adv.total_segments
                    && lifecycle.next_segment == adv.segment_index
            })
            .unwrap_or(adv.segment_index == 1);
        let competing_resource = !delivery.inbound_resource_lifecycles.is_empty()
            && !delivery
                .inbound_resource_lifecycles
                .contains_key(&resource_id);
        if !structurally_valid
            || !lifecycle_valid
            || competing_resource
            || adv.data_size == 0
            || adv.data_size > self.inbound_resource_limit_bytes
        {
            let _ = dispatch_inbound_resource_action(
                link_id,
                delivery,
                &self.transport_tx,
                &mut self.pending_transport,
                &mut self.pending_endpoint_sends,
                TransferAction::SendCancel(
                    rns_protocol::resource::CancelType::Rcl,
                    adv.resource_hash,
                ),
            );
            tracing::warn!(
                link_id = %hex_encode(link_id),
                resource = %hex_encode(&resource_id[..8]),
                data_size = adv.data_size,
                limit = self.inbound_resource_limit_bytes,
                "rejected reverse Resource advertisement on reusable Direct link"
            );
            return false;
        }

        if let Some(transfer) = delivery.inbound_resources.get_mut(&adv.resource_hash) {
            // A retransmitted advertisement can mean the original request was
            // lost. Re-issue the exact current request without allocating a
            // second owner or refreshing transfer state.
            let action = transfer.request_next();
            return dispatch_inbound_resource_action(
                link_id,
                delivery,
                &self.transport_tx,
                &mut self.pending_transport,
                &mut self.pending_endpoint_sends,
                action,
            )
            .is_ok();
        }

        if !inbound_resource_accepted(accept_handler.as_ref(), *link_id, &adv) {
            let _ = dispatch_inbound_resource_action(
                link_id,
                delivery,
                &self.transport_tx,
                &mut self.pending_transport,
                &mut self.pending_endpoint_sends,
                TransferAction::SendCancel(
                    rns_protocol::resource::CancelType::Rcl,
                    adv.resource_hash,
                ),
            );
            return false;
        }

        let map_hashes = adv.get_map_hashes();
        let mut random_hash = [0u8; rns_protocol::resource::RANDOM_HASH_SIZE];
        let copy_len = adv.random_hash.len().min(random_hash.len());
        random_hash[..copy_len].copy_from_slice(&adv.random_hash[..copy_len]);
        let rtt = delivery.link.rtt.unwrap_or(Duration::from_millis(500));
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
            let _ = dispatch_inbound_resource_action(
                link_id,
                delivery,
                &self.transport_tx,
                &mut self.pending_transport,
                &mut self.pending_endpoint_sends,
                TransferAction::SendCancel(
                    rns_protocol::resource::CancelType::Rcl,
                    adv.resource_hash,
                ),
            );
            notify_inbound_resource_concluded(concluded_handler.as_ref(), *link_id, resource_id);
            return false;
        };

        let action = transfer.request_next();
        delivery
            .inbound_resources
            .insert(adv.resource_hash, transfer);
        delivery.link.track_incoming_resource(adv.resource_hash);
        delivery
            .inbound_resource_lifecycles
            .entry(resource_id)
            .or_insert(InboundResourceLifecycle {
                data_size: adv.data_size,
                total_segments: adv.total_segments,
                next_segment: 1,
                inter_segment_deadline: None,
            });
        if let Some(lifecycle) = delivery.inbound_resource_lifecycles.get_mut(&resource_id) {
            lifecycle.inter_segment_deadline = None;
        }
        if is_split {
            delivery
                .inbound_split_resources
                .entry(adv.original_hash)
                .or_insert_with(|| MultiSegmentInbound::new(adv.total_segments, adv.original_hash));
            delivery.inbound_segment_routing.insert(
                adv.resource_hash,
                InboundSegmentRoute {
                    original_hash: adv.original_hash,
                    segment_index: adv.segment_index,
                },
            );
        }

        if let Err(reason) = dispatch_inbound_resource_action(
            link_id,
            delivery,
            &self.transport_tx,
            &mut self.pending_transport,
            &mut self.pending_endpoint_sends,
            action,
        ) {
            let resource_id = drop_inbound_resource(delivery, adv.resource_hash);
            notify_inbound_resource_concluded(concluded_handler.as_ref(), *link_id, resource_id);
            tracing::warn!(
                link_id = %hex_encode(link_id),
                resource = %hex_encode(&resource_id[..8]),
                reason,
                "could not retain initial reverse Resource request"
            );
            return false;
        }

        tracing::info!(
            link_id = %hex_encode(link_id),
            resource = %hex_encode(&resource_id[..8]),
            segment = adv.segment_index,
            total_segments = adv.total_segments,
            "accepted reverse Resource on reusable Direct link"
        );
        true
    }

    fn handle_inbound_resource_part(&mut self, link_id: &[u8; 16], data: &[u8]) -> bool {
        let concluded_handler = self.inbound_resource_concluded_handler.clone();
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };
        if !delivery.reusable || !delivery.link.is_active() {
            return false;
        }
        delivery.link.record_inbound();
        delivery.link.record_rx(data.len());

        let mut selected = None;
        let mut action = TransferAction::None;
        for (resource_hash, transfer) in &mut delivery.inbound_resources {
            let before = transfer.resource.received_count();
            let candidate = transfer.receive_part(data.to_vec());
            if transfer.resource.received_count() > before
                || matches!(candidate, TransferAction::Complete)
            {
                selected = Some(*resource_hash);
                action = candidate;
                break;
            }
        }
        let Some(resource_hash) = selected else {
            return false;
        };

        if !matches!(action, TransferAction::Complete) {
            if !matches!(action, TransferAction::None)
                && dispatch_inbound_resource_action(
                    link_id,
                    delivery,
                    &self.transport_tx,
                    &mut self.pending_transport,
                    &mut self.pending_endpoint_sends,
                    action,
                )
                .is_err()
            {
                let resource_id = drop_inbound_resource(delivery, resource_hash);
                notify_inbound_resource_concluded(
                    concluded_handler.as_ref(),
                    *link_id,
                    resource_id,
                );
                return false;
            }
            return true;
        }

        let completion = {
            let link = &delivery.link;
            let decrypt = |ciphertext: &[u8]| {
                link.decrypt(ciphertext)
                    .map_err(|_| ResourceError::DecryptFailed)
            };
            delivery
                .inbound_resources
                .get_mut(&resource_hash)
                .map(|transfer| transfer.complete(Some(&decrypt)))
        };
        let Some(Ok((assembled, proof))) = completion else {
            let _ = dispatch_inbound_resource_action(
                link_id,
                delivery,
                &self.transport_tx,
                &mut self.pending_transport,
                &mut self.pending_endpoint_sends,
                TransferAction::SendCancel(rns_protocol::resource::CancelType::Rcl, resource_hash),
            );
            let resource_id = drop_inbound_resource(delivery, resource_hash);
            notify_inbound_resource_concluded(concluded_handler.as_ref(), *link_id, resource_id);
            return false;
        };

        // Retain the authenticated Resource proof before publishing plaintext
        // to the application. This mirrors packet delivery and prevents local
        // acceptance from outrunning sender confirmation under backpressure.
        if dispatch_inbound_resource_action(
            link_id,
            delivery,
            &self.transport_tx,
            &mut self.pending_transport,
            &mut self.pending_endpoint_sends,
            TransferAction::SendProof(proof),
        )
        .is_err()
        {
            let resource_id = drop_inbound_resource(delivery, resource_hash);
            notify_inbound_resource_concluded(concluded_handler.as_ref(), *link_id, resource_id);
            return false;
        }

        let payload = if let Some(route) = delivery
            .inbound_segment_routing
            .get(&resource_hash)
            .copied()
        {
            let assembled_payload = delivery
                .inbound_split_resources
                .get_mut(&route.original_hash)
                .and_then(|coordinator| {
                    coordinator
                        .set_segment_data(route.segment_index, assembled)
                        .ok()?;
                    if coordinator.is_complete() {
                        coordinator.reassemble().ok()
                    } else {
                        None
                    }
                });
            delivery.link.untrack_resource(&resource_hash);
            delivery.inbound_resources.remove(&resource_hash);
            delivery.inbound_segment_routing.remove(&resource_hash);
            let split_wait_timeout = inbound_split_wait_timeout(&delivery.link);
            if let Some(lifecycle) = delivery
                .inbound_resource_lifecycles
                .get_mut(&route.original_hash)
            {
                lifecycle.next_segment = lifecycle.next_segment.saturating_add(1);
                if assembled_payload.is_none() {
                    lifecycle.inter_segment_deadline =
                        Instant::now().checked_add(split_wait_timeout).or_else(|| {
                            Instant::now().checked_add(Duration::from_secs(u32::MAX as u64))
                        });
                }
            }
            if assembled_payload.is_some() {
                delivery
                    .inbound_resource_lifecycles
                    .remove(&route.original_hash);
                delivery
                    .inbound_split_resources
                    .remove(&route.original_hash);
            }
            assembled_payload.map(|payload| (route.original_hash, payload))
        } else {
            let resource_id = drop_inbound_resource(delivery, resource_hash);
            Some((resource_id, assembled))
        };

        if let Some((resource_id, payload)) = payload {
            if let Some(handler) = &self.inbound_resource_completion_handler {
                // The owning handoff has the same isolation as admission and
                // conclusion callbacks. Unwinding drops the moved payload (and
                // any application lease); never publish a second legacy copy.
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handler(*link_id, resource_id, payload);
                }))
                .is_err()
                {
                    tracing::error!("reverse Resource completion callback panicked");
                }
                notify_inbound_resource_concluded(
                    concluded_handler.as_ref(),
                    *link_id,
                    resource_id,
                );
            } else {
                notify_inbound_resource_concluded(
                    concluded_handler.as_ref(),
                    *link_id,
                    resource_id,
                );
                if let Some(tx) = &self.inbound_packet_tx {
                    let _ = tx.send((payload, *link_id));
                }
            }
        }
        true
    }

    fn handle_inbound_resource_hmu(&mut self, link_id: &[u8; 16], data: &[u8]) -> bool {
        let concluded_handler = self.inbound_resource_concluded_handler.clone();
        let Ok((resource_hash, segment, hashmap)) =
            rns_protocol::resource::parse_hashmap_update(data)
        else {
            return false;
        };
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };
        let Some(transfer) = delivery.inbound_resources.get_mut(&resource_hash) else {
            return false;
        };
        let action = transfer.hashmap_update(segment, &hashmap);
        let cancelled = matches!(
            action,
            TransferAction::SendCancel(rns_protocol::resource::CancelType::Rcl, _)
        );
        let retained = dispatch_inbound_resource_action(
            link_id,
            delivery,
            &self.transport_tx,
            &mut self.pending_transport,
            &mut self.pending_endpoint_sends,
            action,
        )
        .is_ok();
        if cancelled || !retained {
            let resource_id = drop_inbound_resource(delivery, resource_hash);
            notify_inbound_resource_concluded(concluded_handler.as_ref(), *link_id, resource_id);
        }
        retained
    }

    fn handle_inbound_resource_cancel(&mut self, link_id: &[u8; 16], data: &[u8]) -> bool {
        let concluded_handler = self.inbound_resource_concluded_handler.clone();
        if data.len() < 32 {
            return false;
        }
        let mut resource_hash = [0u8; 32];
        resource_hash.copy_from_slice(&data[..32]);
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };
        if !delivery.inbound_resources.contains_key(&resource_hash) {
            return false;
        }
        if let Some(transfer) = delivery.inbound_resources.get_mut(&resource_hash) {
            transfer.handle_cancel();
        }
        let resource_id = drop_inbound_resource(delivery, resource_hash);
        notify_inbound_resource_concluded(concluded_handler.as_ref(), *link_id, resource_id);
        true
    }

    /// Drive pending deliveries forward; call periodically after [`Self::drain_events`].
    pub fn tick(&mut self) -> Vec<DeliveryResult> {
        let mut results = self.tick_backchannels();
        self.poll_endpoint_control();
        if let Err(reason) = flush_staged_transport(&self.transport_tx, &mut self.pending_transport)
        {
            for delivery in self.pending.values_mut() {
                delivery.state = DeliveryState::Failed;
                delivery.failure_reason = Some(reason.to_string());
            }
        }
        let mut to_remove = Vec::new();

        for (link_id, delivery) in &mut self.pending {
            let mut remove_session = false;

            if delivery.reusable && delivery.link.is_active() {
                drive_inbound_resource_watchdogs(
                    link_id,
                    delivery,
                    &self.transport_tx,
                    &mut self.pending_transport,
                    &mut self.pending_endpoint_sends,
                    self.inbound_resource_concluded_handler.as_ref(),
                );
            }

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
                } else if delivery.state == DeliveryState::Identifying {
                    (
                        elapsed > BACKCHANNEL_SEND_COMMAND_TIMEOUT,
                        BACKCHANNEL_SEND_COMMAND_TIMEOUT,
                        "Link endpoint admission timeout",
                    )
                } else {
                    (
                        elapsed > delivery.timeout,
                        delivery.timeout,
                        if delivery.packet_awaiting_dispatch {
                            "Link endpoint admission timeout"
                        } else {
                            "delivery timeout"
                        },
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
                    push_failed_delivery_and_queue(
                        &mut results,
                        &mut self.delivery_events,
                        *link_id,
                        delivery,
                        reason,
                    );
                    remove_session = true;
                }
            }

            if !remove_session {
                match delivery.state {
                    DeliveryState::Idle => {}
                    DeliveryState::Identifying if delivery.link.is_active() => {
                        // The exact send lane is independent of the legacy
                        // mailbox. LRRRTT must reach the driver/actor FIFO
                        // before payload bytes enter that lane.
                        if delivery.endpoint_dispatch_token.is_some()
                            && self.pending_endpoint_sends.iter().any(|pending| {
                                pending.link_id == *link_id
                                    && matches!(
                                        pending.success,
                                        EndpointSendSuccess::FinishHandshake
                                    )
                            })
                        {
                            continue;
                        }
                        if !delivery.reusable && !delivery.pretransfer_identify_staged {
                            if let (Some(pub_key), Some(sign_key)) =
                                (&self.identity_pub, &self.identity_key)
                            {
                                if let Ok(identify_data) = delivery.link.identify(pub_key, sign_key)
                                {
                                    let id_header = rns_wire::header::PacketHeader {
                                        flags: rns_wire::flags::PacketFlags {
                                            header_type: rns_wire::flags::HeaderType::Header1,
                                            context_flag: false,
                                            transport_type:
                                                rns_wire::flags::TransportType::Broadcast,
                                            destination_type:
                                                rns_wire::flags::DestinationType::Link,
                                            packet_type: rns_wire::flags::PacketType::Data,
                                        },
                                        hops: 0,
                                        transport_id: None,
                                        destination_hash: *link_id,
                                        context: rns_wire::context::PacketContext::LinkIdentify,
                                    };
                                    let mut id_raw = id_header.pack();
                                    id_raw.extend_from_slice(&identify_data);
                                    if let Err(reason) = stage_link_endpoint_with_success(
                                        &self.transport_tx,
                                        &mut self.pending_transport,
                                        &mut self.pending_endpoint_sends,
                                        *link_id,
                                        OutboundRequest {
                                            raw: Bytes::from(id_raw),
                                            destination_hash: *link_id,
                                        },
                                        EndpointSendSuccess::FinishHandshake,
                                    ) {
                                        delivery.state = DeliveryState::Failed;
                                        delivery.failure_reason = Some(reason.to_string());
                                        continue;
                                    }
                                    delivery.pretransfer_identify_staged = true;
                                    if delivery.endpoint_dispatch_token.is_some() {
                                        continue;
                                    }
                                }
                            }
                        }
                        // Reusable Direct links follow upstream LXMF and identify
                        // after a successful delivery, not before the transfer.
                        // One-shot propagation links keep the previous pre-transfer
                        // identify behavior for compatibility with existing callers.
                        delivery.state = DeliveryState::Transferring;
                        if delivery.message.progress < 0.05 {
                            delivery.message.progress = 0.05;
                        }
                        self.delivery_events.push_back(delivery_event(
                            LxmfDeliveryEventKind::LinkEstablished,
                            *link_id,
                            delivery,
                            Some(0.05),
                            None,
                        ));

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
                                    &mut self.pending_transport,
                                    &mut self.pending_endpoint_sends,
                                    &mut self.pending_packet_dispatches,
                                    &packed,
                                ) {
                                    Ok(packet_hash) => {
                                        delivery.packet_proof_hash = Some(packet_hash);
                                        delivery.timeout =
                                            if delivery.endpoint_dispatch_token.is_some() {
                                                LINK_PACKET_DISPATCH_TIMEOUT
                                            } else {
                                                BACKCHANNEL_SEND_COMMAND_TIMEOUT
                                            };
                                        delivery.packet_awaiting_dispatch = true;
                                        delivery.state = DeliveryState::AwaitingProof;
                                        delivery.message.progress = 0.50;
                                        self.delivery_events.push_back(delivery_event(
                                            LxmfDeliveryEventKind::AwaitingProof,
                                            *link_id,
                                            delivery,
                                            Some(0.50),
                                            None,
                                        ));
                                    }
                                    Err(reason) => {
                                        delivery.state = DeliveryState::Failed;
                                        delivery.failure_reason = Some(reason.to_string());
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
                                        delivery.message.progress = 0.10;
                                        self.delivery_events.push_back(delivery_event(
                                            LxmfDeliveryEventKind::TransferStarted,
                                            *link_id,
                                            delivery,
                                            Some(0.10),
                                            None,
                                        ));
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
                            let action = match transfer.check_timeout() {
                                TransferAction::None => transfer.tick(),
                                action => action,
                            };
                            let reports_resource_progress =
                                matches!(&action, TransferAction::SendPart(_, _));
                            match dispatch_action(
                                link_id,
                                delivery,
                                &self.transport_tx,
                                &mut self.pending_transport,
                                &mut self.pending_endpoint_sends,
                                action,
                            ) {
                                ActionOutcome::Continue => {
                                    if reports_resource_progress {
                                        maybe_push_resource_progress_event(
                                            &mut self.delivery_events,
                                            *link_id,
                                            delivery,
                                        );
                                    }
                                    continue;
                                }
                                ActionOutcome::Break => break,
                                ActionOutcome::Complete => {
                                    delivery.message.progress = 1.0;
                                    self.delivery_events.push_back(delivery_event(
                                        LxmfDeliveryEventKind::Delivered,
                                        *link_id,
                                        delivery,
                                        Some(1.0),
                                        None,
                                    ));
                                    results.push(DeliveryResult::Complete {
                                        link_id: *link_id,
                                        msg_hash: delivery.msg_hash,
                                    });
                                    if delivery.reusable && delivery.link.state != LinkState::Closed
                                    {
                                        finish_reusable_delivery(
                                            &self.transport_tx,
                                            &mut self.pending_transport,
                                            &mut self.pending_endpoint_sends,
                                            &self.identity_pub,
                                            &self.identity_key,
                                            link_id,
                                            delivery,
                                        );
                                    } else {
                                        fail_queued_deliveries(
                                            &mut results,
                                            &mut self.delivery_events,
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
                                        &mut self.delivery_events,
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
                        delivery.message.progress = 1.0;
                        self.delivery_events.push_back(delivery_event(
                            LxmfDeliveryEventKind::Delivered,
                            *link_id,
                            delivery,
                            Some(1.0),
                            None,
                        ));
                        results.push(DeliveryResult::Complete {
                            link_id: *link_id,
                            msg_hash: delivery.msg_hash,
                        });
                        if delivery.reusable && delivery.link.state != LinkState::Closed {
                            finish_reusable_delivery(
                                &self.transport_tx,
                                &mut self.pending_transport,
                                &mut self.pending_endpoint_sends,
                                &self.identity_pub,
                                &self.identity_key,
                                link_id,
                                delivery,
                            );
                        } else {
                            fail_queued_deliveries(
                                &mut results,
                                &mut self.delivery_events,
                                *link_id,
                                delivery,
                                "link closed",
                            );
                            remove_session = true;
                        }
                    }
                    DeliveryState::Rejected => {
                        let reason = delivery
                            .failure_reason
                            .take()
                            .unwrap_or_else(|| "resource rejected".to_string());
                        self.delivery_events.push_back(delivery_event(
                            LxmfDeliveryEventKind::Rejected,
                            *link_id,
                            delivery,
                            Some(delivery.message.progress),
                            Some(reason.clone()),
                        ));
                        let message = take_current_delivery_message(delivery);
                        results.push(DeliveryResult::Rejected {
                            link_id: *link_id,
                            msg_hash: delivery.msg_hash,
                            dest_hash: delivery.dest_hash,
                            message,
                            reason,
                        });
                        if delivery.reusable && delivery.link.state != LinkState::Closed {
                            finish_unsuccessful_reusable_delivery(delivery);
                        } else {
                            fail_queued_deliveries(
                                &mut results,
                                &mut self.delivery_events,
                                *link_id,
                                delivery,
                                "link closed",
                            );
                            remove_session = true;
                        }
                    }
                    DeliveryState::Failed => {
                        let reason = delivery
                            .failure_reason
                            .take()
                            .unwrap_or_else(|| "delivery failed".to_string());
                        push_failed_delivery_and_queue(
                            &mut results,
                            &mut self.delivery_events,
                            *link_id,
                            delivery,
                            &reason,
                        );
                        remove_session = true;
                    }
                    DeliveryState::Establishing | DeliveryState::AwaitingProof => {}
                }
            }

            if !remove_session && delivery.reusable {
                if delivery.link.state == LinkState::Closed {
                    fail_queued_deliveries(
                        &mut results,
                        &mut self.delivery_events,
                        *link_id,
                        delivery,
                        "link closed",
                    );
                    remove_session = true;
                } else if delivery.state == DeliveryState::Idle
                    && delivery.queued.is_empty()
                    && delivery.link.is_active()
                    && direct_link_idle_expired(delivery)
                {
                    tracing::debug!(
                        link_id = %hex_encode(link_id),
                        dest = %hex_encode(&delivery.dest_hash),
                        idle_secs = link_data_idle_for(&delivery.link).as_secs_f64(),
                        "tearing down inactive Direct link"
                    );
                    delivery.endpoint_release_queued = send_link_teardown(
                        &self.transport_tx,
                        &mut self.pending_transport,
                        &mut self.pending_endpoint_sends,
                        link_id,
                        &mut delivery.link,
                    );
                    remove_session = true;
                } else if drive_link_action(
                    &self.transport_tx,
                    &mut self.pending_transport,
                    &mut self.pending_endpoint_sends,
                    link_id,
                    delivery.link.tick(),
                    &mut delivery.endpoint_release_queued,
                ) {
                    if !matches!(
                        delivery.state,
                        DeliveryState::Idle | DeliveryState::Complete
                    ) {
                        push_failed_delivery_and_queue(
                            &mut results,
                            &mut self.delivery_events,
                            *link_id,
                            delivery,
                            "link closed",
                        );
                    } else {
                        fail_queued_deliveries(
                            &mut results,
                            &mut self.delivery_events,
                            *link_id,
                            delivery,
                            "link closed",
                        );
                    }
                    remove_session = true;
                }
            }

            if remove_session {
                to_remove.push(*link_id);
            }
        }

        for link_id in to_remove {
            self.pending_endpoint_binds.remove(&link_id);
            if let Some(mut delivery) = self.pending.remove(&link_id) {
                for resource_id in drop_all_inbound_resources(&mut delivery) {
                    notify_inbound_resource_concluded(
                        self.inbound_resource_concluded_handler.as_ref(),
                        link_id,
                        resource_id,
                    );
                }
                if delivery.reusable {
                    self.direct_links.remove(&delivery.dest_hash);
                }
                let graceful_release = delivery.endpoint_release_queued
                    || send_link_teardown(
                        &self.transport_tx,
                        &mut self.pending_transport,
                        &mut self.pending_endpoint_sends,
                        &link_id,
                        &mut delivery.link,
                    );
                if !graceful_release {
                    let _ = stage_link_endpoint_unbind(
                        &self.transport_tx,
                        &mut self.pending_transport,
                        &mut self.pending_endpoint_cleanups,
                        link_id,
                    );
                }
            }
        }

        results
    }

    fn tick_backchannels(&mut self) -> Vec<DeliveryResult> {
        let mut results = Vec::new();
        self.prune_early_backchannel_settlement();

        let starts = std::mem::take(&mut self.pending_backchannel_starts);
        let mut still_waiting = Vec::new();
        for mut start in starts {
            match start.receiver.try_recv() {
                Ok(Ok(receipt)) => {
                    let (key, representation, progress, kind) = match receipt {
                        BackchannelSendReceipt::Packet {
                            link_id,
                            packet_hash,
                        } => (
                            BackchannelProofKey::Packet(link_id, packet_hash),
                            DeliveryRepresentation::Packet,
                            0.50,
                            LxmfDeliveryEventKind::AwaitingProof,
                        ),
                        BackchannelSendReceipt::Resource {
                            link_id,
                            resource_hash,
                        } => (
                            BackchannelProofKey::Resource(link_id, resource_hash),
                            DeliveryRepresentation::Resource,
                            0.10,
                            LxmfDeliveryEventKind::TransferStarted,
                        ),
                    };

                    if start.cancelled {
                        self.cancel_backchannel_packet_key(key, None);
                        self.early_backchannel_waits.remove(&key);
                        self.early_backchannel_proofs.remove(&key);
                        self.early_backchannel_resource_conclusions.remove(&key);
                        if let BackchannelProofKey::Resource(link_id, resource_hash) = key {
                            self.pending_backchannel_resource_cancellations.push_back(
                                BackchannelResourceCancelRequest {
                                    link_id,
                                    resource_hash,
                                },
                            );
                        }
                        continue;
                    }

                    let proof_observed = self.early_backchannel_proofs.remove(&key).is_some();
                    let early_conclusion = self.early_backchannel_resource_conclusions.remove(&key);
                    let settlement_observed = proof_observed || early_conclusion.is_some();
                    if let Some(reason) =
                        start.closed_reason.clone().filter(|_| !settlement_observed)
                    {
                        results.push(fail_backchannel_start(
                            &mut self.delivery_events,
                            start,
                            reason,
                        ));
                        continue;
                    }

                    let link_closed = start.closed_reason.is_some();
                    self.delivery_events.push_back(backchannel_delivery_event(
                        BackchannelDeliveryEventInput {
                            kind,
                            message: &start.message,
                            dest_hash: start.dest_hash,
                            link_id: start.link_id,
                            representation,
                            progress: Some(progress),
                            reason: None,
                            link_state: if link_closed {
                                LinkState::Closed
                            } else {
                                LinkState::Active
                            },
                            delivery_state: DeliveryState::AwaitingProof,
                        },
                    ));
                    self.pending_backchannel_deliveries.insert(
                        key,
                        PendingBackchannelDelivery {
                            message: start.message,
                            dest_hash: start.dest_hash,
                            link_id: start.link_id,
                            representation,
                            started_at: Instant::now(),
                            link_closed,
                            wait: self.early_backchannel_waits.remove(&key),
                            packet_cancellation: self
                                .early_backchannel_packet_cancellations
                                .remove(&key)
                                .map(|(cancel, _)| cancel),
                        },
                    );
                    if let Some(early_conclusion) = early_conclusion {
                        if let Some(result) = self.finish_backchannel_resource_conclusion(
                            key,
                            early_conclusion.conclusion,
                            early_conclusion.reason,
                        ) {
                            results.push(result);
                        }
                    } else if proof_observed {
                        if let Some(result) = self.complete_backchannel_delivery(key) {
                            results.push(result);
                        }
                    }
                }
                Ok(Err(err)) => {
                    let reason = err.to_string();
                    if start.cancelled {
                        continue;
                    }
                    if self.backchannel_links.get(&start.dest_hash) == Some(&start.link_id) {
                        self.backchannel_links.remove(&start.dest_hash);
                    }
                    tracing::warn!(
                        link_id = %hex_encode(&start.link_id),
                        dest = %hex_encode(&start.dest_hash),
                        reason = %reason,
                        "LXMF backchannel send failed"
                    );
                    results.push(fail_backchannel_start(
                        &mut self.delivery_events,
                        start,
                        reason,
                    ));
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    if start.requested_at.elapsed() > BACKCHANNEL_SEND_COMMAND_TIMEOUT {
                        let reason = start
                            .closed_reason
                            .clone()
                            .unwrap_or_else(|| "backchannel send command timeout".to_string());
                        if !start.cancelled
                            && self.backchannel_links.get(&start.dest_hash) == Some(&start.link_id)
                        {
                            self.backchannel_links.remove(&start.dest_hash);
                        }
                        // Close BEFORE draining: a receipt published after our
                        // earlier Empty poll is still recoverable; later bridge
                        // sends fail and retain exact abandonment metadata.
                        start.receiver.close();
                        let raced_receipt = start.receiver.try_recv().ok().and_then(Result::ok);
                        if !start.cancelled {
                            results.push(fail_backchannel_start_in_place(
                                &mut self.delivery_events,
                                &mut start,
                                reason,
                            ));
                        }
                        if let Some(receipt) = raced_receipt {
                            self.cancel_backchannel_receipt(receipt);
                        } else if start.requested_at.elapsed()
                            < BACKCHANNEL_SEND_COMMAND_TIMEOUT + LINK_PACKET_DISPATCH_TIMEOUT
                        {
                            // Small hidden reservation; release original message
                            // bytes while a bridge still owns publication cleanup.
                            start.cancelled = true;
                            still_waiting.push(start);
                        }
                    } else {
                        still_waiting.push(start);
                    }
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    let reason = "backchannel send command closed".to_string();
                    if !start.cancelled {
                        if self.backchannel_links.get(&start.dest_hash) == Some(&start.link_id) {
                            self.backchannel_links.remove(&start.dest_hash);
                        }
                        results.push(fail_backchannel_start_in_place(
                            &mut self.delivery_events,
                            &mut start,
                            reason,
                        ));
                    }
                    if start.requested_at.elapsed()
                        < BACKCHANNEL_SEND_COMMAND_TIMEOUT + LINK_PACKET_DISPATCH_TIMEOUT
                    {
                        still_waiting.push(start);
                    }
                }
            }
        }
        self.pending_backchannel_starts = still_waiting;
        self.prune_early_backchannel_settlement();

        let expired: Vec<_> = self
            .pending_backchannel_deliveries
            .iter()
            .filter_map(|(key, delivery)| {
                let mut wait = delivery.wait.unwrap_or(BackchannelWaitWindow {
                    started_at: delivery.started_at,
                    timeout: BACKCHANNEL_DELIVERY_TIMEOUT,
                    awaiting_admission: false,
                });
                if delivery.wait.is_some() && matches!(key, BackchannelProofKey::Resource(..)) {
                    wait.timeout = wait
                        .timeout
                        .saturating_add(BACKCHANNEL_RESOURCE_OBSERVATION_GRACE);
                }
                (wait.started_at.elapsed() > wait.timeout).then_some(*key)
            })
            .collect();
        for key in expired {
            if let Some(delivery) = self.pending_backchannel_deliveries.remove(&key) {
                if let BackchannelProofKey::Resource(link_id, resource_hash) = key {
                    self.pending_backchannel_resource_cancellations.push_back(
                        BackchannelResourceCancelRequest {
                            link_id,
                            resource_hash,
                        },
                    );
                }
                self.remove_backchannel_owner(delivery.dest_hash, delivery.link_id);
                self.cancel_backchannel_packet_key(key, delivery.packet_cancellation);
                let reason = if delivery.wait.is_some_and(|wait| wait.awaiting_admission) {
                    "Link endpoint admission timeout"
                } else {
                    "backchannel delivery timeout"
                }
                .to_string();
                self.delivery_events.push_back(backchannel_delivery_event(
                    BackchannelDeliveryEventInput {
                        kind: LxmfDeliveryEventKind::Failed,
                        message: &delivery.message,
                        dest_hash: delivery.dest_hash,
                        link_id: delivery.link_id,
                        representation: delivery.representation,
                        progress: Some(delivery.message.progress),
                        reason: Some(reason.clone()),
                        link_state: LinkState::Closed,
                        delivery_state: DeliveryState::Failed,
                    },
                ));
                results.push(DeliveryResult::Failed {
                    link_id: delivery.link_id,
                    msg_hash: delivery.message.hash,
                    dest_hash: delivery.dest_hash,
                    message: delivery.message,
                    reason,
                });
            }
        }

        results
    }

    pub fn handle_hmu(&mut self, link_id: &[u8; 16], hmu_data: &[u8]) {
        let event = if let Some(delivery) = self.pending.get_mut(link_id) {
            if let Some(ref mut transfer) = delivery.transfer {
                transfer.handle_hmu(hmu_data);
                let progress = delivery_resource_progress(delivery);
                if let Some(progress) = progress {
                    if should_update_resource_progress(delivery.message.progress, progress) {
                        delivery.message.progress = progress;
                    }
                }
                progress.map(|_| {
                    delivery_event(
                        LxmfDeliveryEventKind::TransferProgress,
                        *link_id,
                        delivery,
                        Some(delivery.message.progress),
                        None,
                    )
                })
            } else {
                None
            }
        } else {
            None
        };
        if let Some(event) = event {
            self.delivery_events.push_back(event);
        }
    }

    /// Handle an inbound `RESOURCE_REQ` (receiver's `request_next`).
    ///
    /// The request returns a list of parts the receiver still needs; dispatch the resulting
    /// `SendPart` actions immediately rather than waiting for the next [`Self::tick`], since
    /// the receiver may time out and retry first.
    pub fn handle_request(&mut self, link_id: &[u8; 16], request_data: &[u8]) {
        let event = {
            let Some(delivery) = self.pending.get_mut(link_id) else {
                return;
            };
            let Some(ref mut transfer) = delivery.transfer else {
                return;
            };
            let actions = transfer.handle_request(request_data);
            for action in actions {
                match dispatch_action(
                    link_id,
                    delivery,
                    &self.transport_tx,
                    &mut self.pending_transport,
                    &mut self.pending_endpoint_sends,
                    action,
                ) {
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
            let progress = delivery_resource_progress(delivery);
            if let Some(progress) = progress {
                if should_update_resource_progress(delivery.message.progress, progress) {
                    delivery.message.progress = progress;
                }
            }
            progress.map(|_| {
                delivery_event(
                    LxmfDeliveryEventKind::TransferProgress,
                    *link_id,
                    delivery,
                    Some(delivery.message.progress),
                    None,
                )
            })
        };
        if let Some(event) = event {
            self.delivery_events.push_back(event);
        }
    }

    /// Apply an inbound resource proof; returns `true` when the proof was accepted.
    pub fn handle_resource_proof(&mut self, link_id: &[u8; 16], proof_data: &[u8]) -> bool {
        let mut event = None;
        let accepted = if let Some(delivery) = self.pending.get_mut(link_id) {
            if delivery
                .transfer
                .as_mut()
                .is_some_and(|transfer| transfer.handle_proof(proof_data))
            {
                let progress = delivery_resource_proof_progress(delivery).unwrap_or(1.0);
                delivery.message.progress = progress;
                event = Some(delivery_event(
                    LxmfDeliveryEventKind::TransferProgress,
                    *link_id,
                    delivery,
                    Some(progress),
                    None,
                ));
                let rtt = delivery.link.rtt.unwrap_or(Duration::from_millis(500));
                let next_segment = delivery
                    .remaining_segments
                    .as_mut()
                    .map(|remaining| next_resource_segment(&delivery.link, remaining))
                    .transpose();
                match next_segment {
                    Ok(Some(Some(segment))) => {
                        let exhausted = delivery
                            .remaining_segments
                            .as_ref()
                            .is_none_or(|remaining| remaining.remaining_segments() == 0);
                        if exhausted {
                            delivery.remaining_segments = None;
                        }
                        delivery.transfer = Some(OutboundTransfer::from_prebuilt(segment, rtt));
                        delivery.state = DeliveryState::Transferring;
                    }
                    Ok(Some(None)) | Ok(None) => {
                        delivery.remaining_segments = None;
                        delivery.state = DeliveryState::Complete;
                    }
                    Err(_) => {
                        delivery.remaining_segments = None;
                        delivery.state = DeliveryState::Failed;
                        delivery.failure_reason =
                            Some("resource transfer build failed".to_string());
                    }
                }
                true
            } else {
                false
            }
        } else {
            false
        };
        if let Some(event) = event {
            self.delivery_events.push_back(event);
        }
        accepted
    }

    /// Apply an inbound receiver-cancel/reject for the current outbound resource.
    pub fn handle_resource_reject(&mut self, link_id: &[u8; 16], reject_data: &[u8]) -> bool {
        if reject_data.len() < 32 {
            return false;
        }

        let mut rejected_hash = [0u8; 32];
        rejected_hash.copy_from_slice(&reject_data[..32]);

        if let Some(delivery) = self.pending.get_mut(link_id) {
            if let Some(ref mut transfer) = delivery.transfer {
                if transfer.resource.resource_hash == rejected_hash {
                    transfer.handle_cancel();
                    delivery.remaining_segments = None;
                    delivery.message.mark_rejected();
                    delivery.state = DeliveryState::Rejected;
                    delivery.failure_reason = Some("resource rejected".to_string());
                    return true;
                }
            }
        }

        false
    }

    fn handle_link_closed(
        &mut self,
        link_id: &[u8; 16],
        encrypted_teardown: Option<&[u8]>,
    ) -> bool {
        let concluded_handler = self.inbound_resource_concluded_handler.clone();
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
            for resource_id in drop_all_inbound_resources(delivery) {
                notify_inbound_resource_concluded(
                    concluded_handler.as_ref(),
                    *link_id,
                    resource_id,
                );
            }
            if delivery.state == DeliveryState::Complete {
                return true;
            }
            if delivery.state == DeliveryState::Idle {
                delivery.failure_reason = Some("link closed".to_string());
                return true;
            }
            delivery.transfer = None;
            delivery.remaining_segments = None;
            delivery.packet_proof_hash = None;
            delivery.state = DeliveryState::Failed;
            delivery.failure_reason = Some("link closed".to_string());
        }

        verified
    }

    /// Apply an inbound link-packet proof; returns `true` when the packet delivery is complete.
    pub fn handle_link_packet_proof(&mut self, link_id: &[u8; 16], proof_data: &[u8]) -> bool {
        if let Some(delivery) = self.pending.get_mut(link_id) {
            if delivery.state == DeliveryState::AwaitingProof {
                if let Some(packet_hash) = delivery.packet_proof_hash {
                    if delivery
                        .link
                        .validate_packet_proof(&packet_hash, proof_data)
                    {
                        delivery.state = DeliveryState::Complete;
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn handle_backchannel_packet_proof(
        &mut self,
        link_id: [u8; 16],
        packet_hash: [u8; 32],
    ) -> Option<DeliveryResult> {
        self.complete_backchannel_delivery(BackchannelProofKey::Packet(link_id, packet_hash))
    }

    /// Mirror the exact bounded packet wait observed by the authenticated Link
    /// owner. `awaiting_admission` separates local staging from the RTT proof
    /// window installed after endpoint acceptance. Call before or after its send receipt;
    /// delayed observations retain the original start instant. Unowned,
    /// cancelled and completed sends cannot be installed by this method.
    pub fn observe_backchannel_packet_wait(
        &mut self,
        link_id: [u8; 16],
        packet_hash: [u8; 32],
        started_at: Instant,
        timeout: Duration,
        awaiting_admission: bool,
        cancellation: Option<LinkEndpointDispatchCancellation>,
    ) -> bool {
        let key = BackchannelProofKey::Packet(link_id, packet_hash);
        if let Some(cancellation) = cancellation {
            if self.cancelled_backchannel_packets.contains_key(&key) {
                cancellation.cancel();
                return false;
            }
            if let Some(delivery) = self.pending_backchannel_deliveries.get_mut(&key) {
                delivery.packet_cancellation = Some(cancellation);
            } else if self
                .pending_backchannel_starts
                .iter()
                .any(|start| start.link_id == link_id)
            {
                if self.early_backchannel_packet_cancellations.len() < BACKCHANNEL_EARLY_PROOF_LIMIT
                    || self
                        .early_backchannel_packet_cancellations
                        .contains_key(&key)
                {
                    self.early_backchannel_packet_cancellations
                        .entry(key)
                        .or_insert((cancellation, Instant::now()));
                } else {
                    // Local accounting backpressure is not a route fault.
                    cancellation.cancel();
                    return false;
                }
            }
        }
        self.observe_backchannel_wait(
            key,
            BackchannelWaitWindow {
                started_at,
                timeout,
                awaiting_admission,
            },
        )
    }

    /// Mirror an exact bounded Resource wait from its protocol owner. The
    /// owner must drive advertisement/window/proof exhaustion and report
    /// terminal results. Only real protocol progress/retry may update this
    /// window; keepalives or generic UI progress must not extend it. This
    /// replaces the finite legacy adapter fallback for this exact send only.
    /// A bounded 180-second observation grace follows the original deadline to
    /// tolerate asynchronous accounting delivery; terminal results still settle
    /// immediately and duplicate observations do not restart that envelope.
    pub fn observe_backchannel_resource_wait(
        &mut self,
        link_id: [u8; 16],
        resource_hash: [u8; 32],
        started_at: Instant,
        timeout: Duration,
    ) -> bool {
        self.observe_backchannel_wait(
            BackchannelProofKey::Resource(link_id, resource_hash),
            BackchannelWaitWindow {
                started_at,
                timeout,
                awaiting_admission: false,
            },
        )
    }

    fn observe_backchannel_wait(
        &mut self,
        key: BackchannelProofKey,
        wait: BackchannelWaitWindow,
    ) -> bool {
        if let Some(delivery) = self.pending_backchannel_deliveries.get_mut(&key) {
            if delivery.link_closed
                || delivery
                    .wait
                    .is_some_and(|old| old.started_at > wait.started_at)
            {
                return false;
            }
            delivery.wait = Some(wait);
            return true;
        }
        if !self.pending_backchannel_starts.iter().any(|start| {
            start.link_id == key.link_id() && !start.cancelled && start.closed_reason.is_none()
        }) {
            return false;
        }
        if self
            .early_backchannel_waits
            .get(&key)
            .is_some_and(|old| old.started_at > wait.started_at)
        {
            return false;
        }
        if !self.early_backchannel_waits.contains_key(&key)
            && self.early_backchannel_waits.len() >= BACKCHANNEL_EARLY_PROOF_LIMIT
        {
            // A missing observation retains the finite legacy fallback; it
            // never drops an authenticated proof or creates an unbounded wait.
            return false;
        }
        self.early_backchannel_waits.insert(key, wait);
        true
    }

    pub fn handle_backchannel_resource_proof(
        &mut self,
        link_id: [u8; 16],
        resource_hash: [u8; 32],
    ) -> Option<DeliveryResult> {
        self.complete_backchannel_delivery(BackchannelProofKey::Resource(link_id, resource_hash))
    }

    /// Apply a terminal conclusion from a Resource transfer owned by the
    /// embedding runtime's authenticated backchannel Link.
    pub fn handle_backchannel_resource_conclusion(
        &mut self,
        link_id: [u8; 16],
        resource_hash: [u8; 32],
        conclusion: BackchannelResourceConclusion,
        reason: impl Into<String>,
    ) -> Option<DeliveryResult> {
        let key = BackchannelProofKey::Resource(link_id, resource_hash);
        let reason = reason.into();
        if !self.pending_backchannel_deliveries.contains_key(&key) {
            self.remember_early_backchannel_resource_conclusion(key, conclusion, reason);
            return None;
        }
        self.finish_backchannel_resource_conclusion(key, conclusion, reason)
    }

    fn finish_backchannel_resource_conclusion(
        &mut self,
        key: BackchannelProofKey,
        conclusion: BackchannelResourceConclusion,
        reason: String,
    ) -> Option<DeliveryResult> {
        let mut delivery = self.pending_backchannel_deliveries.remove(&key)?;
        self.early_backchannel_proofs.remove(&key);
        self.early_backchannel_resource_conclusions.remove(&key);

        match conclusion {
            BackchannelResourceConclusion::Rejected => {
                delivery.message.mark_rejected();
                self.delivery_events.push_back(backchannel_delivery_event(
                    BackchannelDeliveryEventInput {
                        kind: LxmfDeliveryEventKind::Rejected,
                        message: &delivery.message,
                        dest_hash: delivery.dest_hash,
                        link_id: delivery.link_id,
                        representation: DeliveryRepresentation::Resource,
                        progress: Some(delivery.message.progress),
                        reason: Some(reason.clone()),
                        link_state: if delivery.link_closed {
                            LinkState::Closed
                        } else {
                            LinkState::Active
                        },
                        delivery_state: DeliveryState::Rejected,
                    },
                ));
                Some(DeliveryResult::Rejected {
                    link_id: delivery.link_id,
                    msg_hash: delivery.message.hash,
                    dest_hash: delivery.dest_hash,
                    message: delivery.message,
                    reason,
                })
            }
            BackchannelResourceConclusion::Failed => {
                if self.backchannel_links.get(&delivery.dest_hash) == Some(&delivery.link_id) {
                    self.backchannel_links.remove(&delivery.dest_hash);
                }
                self.delivery_events.push_back(backchannel_delivery_event(
                    BackchannelDeliveryEventInput {
                        kind: LxmfDeliveryEventKind::Failed,
                        message: &delivery.message,
                        dest_hash: delivery.dest_hash,
                        link_id: delivery.link_id,
                        representation: DeliveryRepresentation::Resource,
                        progress: Some(delivery.message.progress),
                        reason: Some(reason.clone()),
                        link_state: LinkState::Closed,
                        delivery_state: DeliveryState::Failed,
                    },
                ));
                Some(DeliveryResult::Failed {
                    link_id: delivery.link_id,
                    msg_hash: delivery.message.hash,
                    dest_hash: delivery.dest_hash,
                    message: delivery.message,
                    reason,
                })
            }
        }
    }

    fn complete_backchannel_delivery(
        &mut self,
        key: BackchannelProofKey,
    ) -> Option<DeliveryResult> {
        let Some(delivery) = self.pending_backchannel_deliveries.remove(&key) else {
            self.remember_early_backchannel_proof(key);
            return None;
        };
        self.early_backchannel_proofs.remove(&key);
        self.early_backchannel_resource_conclusions.remove(&key);
        self.delivery_events
            .push_back(backchannel_delivery_event(BackchannelDeliveryEventInput {
                kind: LxmfDeliveryEventKind::Delivered,
                message: &delivery.message,
                dest_hash: delivery.dest_hash,
                link_id: delivery.link_id,
                representation: delivery.representation,
                progress: Some(1.0),
                reason: None,
                link_state: if delivery.link_closed {
                    LinkState::Closed
                } else {
                    LinkState::Active
                },
                delivery_state: DeliveryState::Complete,
            }));
        tracing::info!(
            link_id = %hex_encode(&delivery.link_id),
            dest = %hex_encode(&delivery.dest_hash),
            age_secs = delivery.started_at.elapsed().as_secs_f64(),
            "LXMF backchannel delivery proved"
        );
        Some(DeliveryResult::Complete {
            link_id: delivery.link_id,
            msg_hash: delivery.message.hash,
        })
    }

    fn remember_early_backchannel_proof(&mut self, key: BackchannelProofKey) {
        let link_id = key.link_id();
        if !self
            .pending_backchannel_starts
            .iter()
            .any(|start| start.link_id == link_id)
        {
            return;
        }

        self.prune_early_backchannel_settlement();
        if self.early_backchannel_proofs.contains_key(&key) {
            return;
        }
        self.make_room_for_early_backchannel_settlement();
        self.early_backchannel_proofs.insert(key, Instant::now());
    }

    fn remember_early_backchannel_resource_conclusion(
        &mut self,
        key: BackchannelProofKey,
        conclusion: BackchannelResourceConclusion,
        reason: String,
    ) {
        let link_id = key.link_id();
        if !self
            .pending_backchannel_starts
            .iter()
            .any(|start| start.link_id == link_id)
        {
            return;
        }

        self.prune_early_backchannel_settlement();
        if self
            .early_backchannel_resource_conclusions
            .contains_key(&key)
        {
            // A duplicate terminal notification must not extend settlement TTL
            // or replace the actor's first ordered conclusion.
            return;
        }
        self.make_room_for_early_backchannel_settlement();
        self.early_backchannel_resource_conclusions.insert(
            key,
            EarlyBackchannelResourceConclusion {
                conclusion,
                reason,
                observed_at: Instant::now(),
            },
        );
    }

    fn make_room_for_early_backchannel_settlement(&mut self) {
        while self.early_backchannel_proofs.len()
            + self.early_backchannel_resource_conclusions.len()
            >= BACKCHANNEL_EARLY_PROOF_LIMIT
        {
            let oldest_proof = self
                .early_backchannel_proofs
                .iter()
                .min_by_key(|(_, observed_at)| *observed_at)
                .map(|(key, observed_at)| (*key, *observed_at));
            let oldest_conclusion = self
                .early_backchannel_resource_conclusions
                .iter()
                .min_by_key(|(_, conclusion)| conclusion.observed_at)
                .map(|(key, conclusion)| (*key, conclusion.observed_at));
            match (oldest_proof, oldest_conclusion) {
                (Some((key, proof_at)), Some((conclusion_key, conclusion_at))) => {
                    if proof_at <= conclusion_at {
                        self.early_backchannel_proofs.remove(&key);
                    } else {
                        self.early_backchannel_resource_conclusions
                            .remove(&conclusion_key);
                    }
                }
                (Some((key, _)), None) => {
                    self.early_backchannel_proofs.remove(&key);
                }
                (None, Some((key, _))) => {
                    self.early_backchannel_resource_conclusions.remove(&key);
                }
                (None, None) => break,
            }
        }
    }

    fn prune_early_backchannel_settlement(&mut self) {
        self.cancelled_backchannel_packets
            .retain(|_, cancelled_at| cancelled_at.elapsed() <= LINK_PACKET_DISPATCH_TIMEOUT);
        self.early_backchannel_packet_cancellations
            .retain(|key, (cancel, observed_at)| {
                let retain = observed_at.elapsed() <= LINK_PACKET_DISPATCH_TIMEOUT
                    && (self.pending_backchannel_deliveries.contains_key(key)
                        || self
                            .pending_backchannel_starts
                            .iter()
                            .any(|start| start.link_id == key.link_id()));
                if !retain {
                    cancel.cancel();
                }
                retain
            });
        self.early_backchannel_waits.retain(|key, _| {
            self.pending_backchannel_starts.iter().any(|start| {
                start.link_id == key.link_id()
                    && !start.cancelled
                    && start.closed_reason.is_none()
                    && start.requested_at.elapsed() <= BACKCHANNEL_SEND_COMMAND_TIMEOUT
            })
        });
        let now = Instant::now();
        let pending_links = self
            .pending_backchannel_starts
            .iter()
            .map(|start| start.link_id)
            .collect::<Vec<_>>();
        self.early_backchannel_proofs.retain(|key, observed_at| {
            now.duration_since(*observed_at) <= BACKCHANNEL_SEND_COMMAND_TIMEOUT
                && pending_links.contains(&key.link_id())
        });
        self.early_backchannel_resource_conclusions
            .retain(|key, conclusion| {
                now.duration_since(conclusion.observed_at) <= BACKCHANNEL_SEND_COMMAND_TIMEOUT
                    && pending_links.contains(&key.link_id())
            });
    }

    pub fn pending_count(&self) -> usize {
        self.pending
            .values()
            .map(PendingDelivery::active_delivery_count)
            .sum::<usize>()
            + self
                .pending_backchannel_starts
                .iter()
                .filter(|start| !start.cancelled)
                .count()
            + self.pending_backchannel_deliveries.len()
    }

    pub fn fail_delivery_by_message_hash(
        &mut self,
        msg_hash: [u8; 32],
        reason: &str,
    ) -> Vec<DeliveryResult> {
        let mut results = Vec::new();
        let mut remove_direct_session = None;

        for (link_id, delivery) in &mut self.pending {
            if delivery.msg_hash == Some(msg_hash) {
                push_failed_delivery_and_queue(
                    &mut results,
                    &mut self.delivery_events,
                    *link_id,
                    delivery,
                    reason,
                );
                remove_direct_session = Some((*link_id, delivery.dest_hash));
                break;
            }

            if let Some(pos) = delivery
                .queued
                .iter()
                .position(|queued| queued.msg_hash == Some(msg_hash))
            {
                if let Some(queued) = delivery.queued.remove(pos) {
                    self.delivery_events.push_back(queued_delivery_event(
                        LxmfDeliveryEventKind::Failed,
                        *link_id,
                        delivery.dest_hash,
                        &queued,
                        Some(reason.to_string()),
                    ));
                    results.push(DeliveryResult::Failed {
                        link_id: *link_id,
                        msg_hash: queued.msg_hash,
                        dest_hash: delivery.dest_hash,
                        message: queued.message,
                        reason: reason.to_string(),
                    });
                }
                break;
            }
        }

        if let Some((link_id, dest_hash)) = remove_direct_session {
            let mut graceful_release = false;
            if let Some(mut delivery) = self.pending.remove(&link_id) {
                graceful_release = send_link_teardown(
                    &self.transport_tx,
                    &mut self.pending_transport,
                    &mut self.pending_endpoint_sends,
                    &link_id,
                    &mut delivery.link,
                );
            }
            self.pending_endpoint_binds.remove(&link_id);
            if !graceful_release {
                let _ = stage_link_endpoint_unbind(
                    &self.transport_tx,
                    &mut self.pending_transport,
                    &mut self.pending_endpoint_cleanups,
                    link_id,
                );
            }
            if self.direct_links.get(&dest_hash) == Some(&link_id) {
                self.direct_links.remove(&dest_hash);
            }
        }

        if !results.is_empty() {
            self.poll_packet_dispatches();
            return results;
        }

        if let Some(pos) = self
            .pending_backchannel_starts
            .iter()
            .position(|start| !start.cancelled && start.message.hash == Some(msg_hash))
        {
            let start = self.pending_backchannel_starts.remove(pos);
            self.remove_backchannel_owner(start.dest_hash, start.link_id);
            results.push(self.retain_failed_backchannel_start(start, reason.to_string()));
            self.prune_early_backchannel_settlement();
            return results;
        }

        let pending_key = self
            .pending_backchannel_deliveries
            .iter()
            .find_map(|(key, delivery)| (delivery.message.hash == Some(msg_hash)).then_some(*key));
        if let Some(key) = pending_key {
            if let Some(delivery) = self.pending_backchannel_deliveries.remove(&key) {
                self.remove_backchannel_owner(delivery.dest_hash, delivery.link_id);
                self.cancel_backchannel_packet_key(key, delivery.packet_cancellation);
                if let BackchannelProofKey::Resource(link_id, resource_hash) = key {
                    self.pending_backchannel_resource_cancellations.push_back(
                        BackchannelResourceCancelRequest {
                            link_id,
                            resource_hash,
                        },
                    );
                }
                self.delivery_events.push_back(backchannel_delivery_event(
                    BackchannelDeliveryEventInput {
                        kind: LxmfDeliveryEventKind::Failed,
                        message: &delivery.message,
                        dest_hash: delivery.dest_hash,
                        link_id: delivery.link_id,
                        representation: delivery.representation,
                        progress: Some(delivery.message.progress),
                        reason: Some(reason.to_string()),
                        link_state: LinkState::Closed,
                        delivery_state: DeliveryState::Failed,
                    },
                ));
                results.push(DeliveryResult::Failed {
                    link_id: delivery.link_id,
                    msg_hash: delivery.message.hash,
                    dest_hash: delivery.dest_hash,
                    message: delivery.message,
                    reason: reason.to_string(),
                });
            }
        }

        results
    }

    pub fn cancel_delivery_by_message_hash(&mut self, msg_hash: [u8; 32]) -> bool {
        let mut remove_direct_session = None;
        let mut cancelled = false;

        for (link_id, delivery) in &mut self.pending {
            if delivery.state != DeliveryState::Idle && delivery.msg_hash == Some(msg_hash) {
                let establishing = delivery.state == DeliveryState::Establishing;
                let establishment_started = delivery.started_at;
                cancel_current_delivery(
                    &self.transport_tx,
                    &mut self.pending_transport,
                    &mut self.pending_endpoint_sends,
                    link_id,
                    delivery,
                );
                if establishing && delivery.reusable && delivery.start_queued_delivery() {
                    // The shared handshake belongs to the following queued
                    // messages too. Cancel only this message, preserve the
                    // original LR clock and any unpublished exact bind.
                    delivery.state = DeliveryState::Establishing;
                    delivery.started_at = establishment_started;
                } else if delivery.reusable
                    && delivery.link.is_active()
                    && delivery.attached_interface.is_some()
                {
                    finish_unsuccessful_reusable_delivery(delivery);
                } else {
                    remove_direct_session = Some((*link_id, delivery.dest_hash));
                }
                cancelled = true;
                break;
            }

            if let Some(pos) = delivery
                .queued
                .iter()
                .position(|queued| queued.msg_hash == Some(msg_hash))
            {
                delivery.queued.remove(pos);
                cancelled = true;
                break;
            }
        }

        if let Some((link_id, dest_hash)) = remove_direct_session {
            let mut graceful_release = false;
            if let Some(mut delivery) = self.pending.remove(&link_id) {
                graceful_release = send_link_teardown(
                    &self.transport_tx,
                    &mut self.pending_transport,
                    &mut self.pending_endpoint_sends,
                    &link_id,
                    &mut delivery.link,
                );
            }
            self.pending_endpoint_binds.remove(&link_id);
            if !graceful_release {
                let _ = stage_link_endpoint_unbind(
                    &self.transport_tx,
                    &mut self.pending_transport,
                    &mut self.pending_endpoint_cleanups,
                    link_id,
                );
            }
            if self.direct_links.get(&dest_hash) == Some(&link_id) {
                self.direct_links.remove(&dest_hash);
            }
        }

        if cancelled {
            self.poll_packet_dispatches();
            return true;
        }

        if let Some(index) = self
            .pending_backchannel_starts
            .iter()
            .position(|start| start.message.hash == Some(msg_hash))
        {
            let start = &mut self.pending_backchannel_starts[index];
            if start.cancelled {
                return false;
            }
            start.cancelled = true;
            let mut placeholder = LxMessage::new(
                start.dest_hash,
                start.message.source_hash,
                "",
                "",
                start.message.method,
            );
            placeholder.hash = start.message.hash;
            start.message = placeholder;
            if start.cancellation_aware {
                start.receiver.close();
                if let Ok(receipt) = start.receiver.try_recv() {
                    if let Ok(receipt) = receipt {
                        self.cancel_backchannel_receipt(receipt);
                    }
                    self.pending_backchannel_starts.remove(index);
                }
            }
            return true;
        }

        let pending_key = self
            .pending_backchannel_deliveries
            .iter()
            .find_map(|(key, delivery)| (delivery.message.hash == Some(msg_hash)).then_some(*key));
        if let Some(key) = pending_key {
            let delivery = self.pending_backchannel_deliveries.remove(&key).unwrap();
            self.cancel_backchannel_packet_key(key, delivery.packet_cancellation);
            self.early_backchannel_proofs.remove(&key);
            if let BackchannelProofKey::Resource(link_id, resource_hash) = key {
                self.pending_backchannel_resource_cancellations.push_back(
                    BackchannelResourceCancelRequest {
                        link_id,
                        resource_hash,
                    },
                );
            }
            return true;
        }

        false
    }

    fn cancel_backchannel_packet_key(
        &mut self,
        key: BackchannelProofKey,
        cancellation: Option<LinkEndpointDispatchCancellation>,
    ) -> bool {
        if !matches!(key, BackchannelProofKey::Packet(..)) {
            return true;
        }
        if !self.cancelled_backchannel_packets.contains_key(&key)
            && self.cancelled_backchannel_packets.len() >= BACKCHANNEL_EARLY_PROOF_LIMIT
        {
            return false;
        }
        if let Some(cancellation) = cancellation.or_else(|| {
            self.early_backchannel_packet_cancellations
                .remove(&key)
                .map(|(cancel, _)| cancel)
        }) {
            cancellation.cancel();
        }
        self.cancelled_backchannel_packets
            .entry(key)
            .or_insert_with(Instant::now);
        true
    }

    fn cancel_backchannel_receipt(&mut self, receipt: BackchannelSendReceipt) {
        match receipt {
            BackchannelSendReceipt::Packet {
                link_id,
                packet_hash,
            } => {
                self.cancel_backchannel_packet_key(
                    BackchannelProofKey::Packet(link_id, packet_hash),
                    None,
                );
            }
            BackchannelSendReceipt::Resource {
                link_id,
                resource_hash,
            } => {
                self.pending_backchannel_resource_cancellations.push_back(
                    BackchannelResourceCancelRequest {
                        link_id,
                        resource_hash,
                    },
                );
            }
        }
    }

    /// Abandon one exact packet whose send receipt could not be handed to its
    /// LXMF owner. Adapters close and drain their receipt pipe first, then retain
    /// any raced receipt here until its exact cleanup ownership is accepted.
    /// It cancels only pre-driver admission; transmitted packets are not recalled.
    /// Returns false on bounded reconciliation pressure; the adapter must retain
    /// and retry this small exact receipt rather than discard its ownership.
    pub fn abandon_backchannel_packet(&mut self, link_id: [u8; 16], packet_hash: [u8; 32]) -> bool {
        let key = BackchannelProofKey::Packet(link_id, packet_hash);
        let reservation = (!self.cancelled_backchannel_packets.contains_key(&key))
            .then(|| {
                self.pending_backchannel_starts.iter().position(|start| {
                    start.link_id == link_id && start.cancelled && start.receiver.is_terminated()
                })
            })
            .flatten();
        if reservation.is_none()
            && !self.cancelled_backchannel_packets.contains_key(&key)
            && !self.pending_backchannel_deliveries.contains_key(&key)
            && !self
                .early_backchannel_packet_cancellations
                .contains_key(&key)
            && self.pending_backchannel_starts.len()
                + self.pending_backchannel_deliveries.len()
                + self.cancelled_backchannel_packets.len()
                >= BACKCHANNEL_EARLY_PROOF_LIMIT
        {
            return false;
        }
        let cancellation = self
            .pending_backchannel_deliveries
            .get_mut(&key)
            .and_then(|delivery| delivery.packet_cancellation.take());
        if !self.cancel_backchannel_packet_key(key, cancellation) {
            return false;
        }
        if let Some(index) = reservation {
            self.pending_backchannel_starts.remove(index);
        }
        true
    }

    pub fn take_delivery_events(&mut self) -> Vec<LxmfDeliveryEvent> {
        self.delivery_events.drain(..).collect()
    }

    /// Drain exact cancellation requests for Resources owned by an embedding
    /// runtime's authenticated backchannel Link.
    pub fn take_backchannel_resource_cancellations(
        &mut self,
    ) -> Vec<BackchannelResourceCancelRequest> {
        self.pending_backchannel_resource_cancellations
            .drain(..)
            .collect()
    }

    /// Return the finite delivery-owner envelope currently owning this message.
    ///
    /// Queued messages have no independent clock. Packet waits start at local
    /// admission; Resource waits belong to the progress engine, not total
    /// message age. Observed backchannel bounds preserve the external owner's
    /// original instant, with a 180-second accounting observation grace for
    /// externally owned Resources only. Direct Resource and packet protocol
    /// clocks are unchanged. Legacy adapters without observations retain the
    /// finite fallback, never an unlimited exemption from an orphan watchdog.
    pub fn message_timeout_window(&self, msg_hash: [u8; 32]) -> Option<(Instant, Duration)> {
        for delivery in self.pending.values() {
            if delivery.msg_hash != Some(msg_hash) {
                continue;
            }
            return match delivery.state {
                DeliveryState::Establishing => {
                    Some((delivery.started_at, delivery.establishment_timeout))
                }
                DeliveryState::Identifying => {
                    Some((delivery.started_at, BACKCHANNEL_SEND_COMMAND_TIMEOUT))
                }
                DeliveryState::AwaitingProof => Some((delivery.started_at, delivery.timeout)),
                DeliveryState::Transferring => delivery
                    .transfer
                    .as_ref()
                    .and_then(OutboundTransfer::timeout_window),
                _ => None,
            };
        }
        for start in &self.pending_backchannel_starts {
            if !start.cancelled
                && start.closed_reason.is_none()
                && start.message.hash == Some(msg_hash)
            {
                return Some((start.requested_at, BACKCHANNEL_SEND_COMMAND_TIMEOUT));
            }
        }
        self.pending_backchannel_deliveries
            .iter()
            .find_map(|(key, delivery)| {
                (!delivery.link_closed && delivery.message.hash == Some(msg_hash)).then(|| {
                    let mut wait = delivery.wait.unwrap_or(BackchannelWaitWindow {
                        started_at: delivery.started_at,
                        timeout: BACKCHANNEL_DELIVERY_TIMEOUT,
                        awaiting_admission: false,
                    });
                    if delivery.wait.is_some() && matches!(key, BackchannelProofKey::Resource(..)) {
                        wait.timeout = wait
                            .timeout
                            .saturating_add(BACKCHANNEL_RESOURCE_OBSERVATION_GRACE);
                    }
                    (wait.started_at, wait.timeout)
                })
            })
    }

    pub fn message_delivery_snapshot(&self, msg_hash: [u8; 32]) -> Option<MessageDeliverySnapshot> {
        for (link_id, delivery) in &self.pending {
            let in_flight_deliveries = delivery.active_delivery_count();
            if delivery.state != DeliveryState::Idle && delivery.msg_hash == Some(msg_hash) {
                return Some(MessageDeliverySnapshot {
                    link_id: *link_id,
                    dest_hash: delivery.dest_hash,
                    link_state: delivery.link.state,
                    delivery_state: delivery.state,
                    representation: delivery.message.representation,
                    progress: delivery.message.progress,
                    queued: false,
                    queued_deliveries: delivery.queued.len(),
                    in_flight_deliveries,
                });
            }

            if let Some(queued) = delivery
                .queued
                .iter()
                .find(|queued| queued.msg_hash == Some(msg_hash))
            {
                return Some(MessageDeliverySnapshot {
                    link_id: *link_id,
                    dest_hash: delivery.dest_hash,
                    link_state: delivery.link.state,
                    delivery_state: delivery.state,
                    representation: queued.message.representation,
                    progress: queued.message.progress,
                    queued: true,
                    queued_deliveries: delivery.queued.len(),
                    in_flight_deliveries,
                });
            }
        }

        for start in &self.pending_backchannel_starts {
            if !start.cancelled && start.message.hash == Some(msg_hash) {
                return Some(MessageDeliverySnapshot {
                    link_id: start.link_id,
                    dest_hash: start.dest_hash,
                    link_state: if start.closed_reason.is_some() {
                        LinkState::Closed
                    } else {
                        LinkState::Active
                    },
                    delivery_state: DeliveryState::Transferring,
                    representation: DeliveryRepresentation::Unknown,
                    progress: start.message.progress,
                    queued: true,
                    queued_deliveries: 1,
                    in_flight_deliveries: 0,
                });
            }
        }

        for (key, delivery) in &self.pending_backchannel_deliveries {
            if delivery.message.hash == Some(msg_hash) {
                let link_id = match key {
                    BackchannelProofKey::Packet(link_id, _)
                    | BackchannelProofKey::Resource(link_id, _) => *link_id,
                };
                return Some(MessageDeliverySnapshot {
                    link_id,
                    dest_hash: delivery.dest_hash,
                    link_state: if delivery.link_closed {
                        LinkState::Closed
                    } else {
                        LinkState::Active
                    },
                    delivery_state: DeliveryState::AwaitingProof,
                    representation: delivery.representation,
                    progress: delivery.message.progress,
                    queued: false,
                    queued_deliveries: 0,
                    in_flight_deliveries: 1,
                });
            }
        }

        None
    }

    pub fn delivery_link_available(&self, dest_hash: &[u8; 16]) -> bool {
        self.direct_links
            .get(dest_hash)
            .and_then(|link_id| self.pending.get(link_id))
            .is_some_and(|delivery| {
                delivery.reusable
                    && delivery.link.state != LinkState::Closed
                    && !direct_link_idle_expired(delivery)
            })
            || self.backchannel_links.contains_key(dest_hash)
    }

    pub fn direct_link_snapshot(&self, dest_hash: [u8; 16]) -> Option<DirectLinkSnapshot> {
        let link_id = *self.direct_links.get(&dest_hash)?;
        let delivery = self.pending.get(&link_id)?;
        Some(DirectLinkSnapshot {
            link_id,
            dest_hash,
            link_state: delivery.link.state,
            delivery_state: delivery.state,
            idle_expired: direct_link_idle_expired(delivery),
            queued_deliveries: delivery.queued.len(),
            in_flight_deliveries: usize::from(delivery.state != DeliveryState::Idle),
        })
    }

    pub fn backchannel_link_snapshot(
        &self,
        dest_hash: [u8; 16],
    ) -> Option<BackchannelLinkSnapshot> {
        let link_id = *self.backchannel_links.get(&dest_hash)?;
        let queued_deliveries = self
            .pending_backchannel_starts
            .iter()
            .filter(|start| {
                start.dest_hash == dest_hash
                    && start.link_id == link_id
                    && !start.cancelled
                    && start.closed_reason.is_none()
            })
            .count();
        let in_flight_deliveries = self
            .pending_backchannel_deliveries
            .values()
            .filter(|delivery| {
                delivery.dest_hash == dest_hash
                    && delivery.link_id == link_id
                    && !delivery.link_closed
            })
            .count();
        Some(BackchannelLinkSnapshot {
            link_id,
            dest_hash,
            queued_deliveries,
            in_flight_deliveries,
        })
    }

    pub fn stats(&self) -> LinkDeliveryStats {
        let mut stats = LinkDeliveryStats {
            sessions: self.pending.len(),
            direct_sessions: self.pending.values().filter(|d| d.reusable).count(),
            one_shot_sessions: self.pending.values().filter(|d| !d.reusable).count(),
            backchannel_sessions: self.backchannel_links.len(),
            pending_backchannel_starts: self
                .pending_backchannel_starts
                .iter()
                .filter(|start| !start.cancelled)
                .count(),
            pending_backchannel_deliveries: self.pending_backchannel_deliveries.len(),
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
        stats.queued_deliveries += stats.pending_backchannel_starts;
        stats.in_flight_deliveries += stats.pending_backchannel_deliveries;
        stats
    }

    pub fn session_count(&self) -> usize {
        self.pending.len()
    }
}

fn delivery_event(
    kind: LxmfDeliveryEventKind,
    link_id: [u8; 16],
    delivery: &PendingDelivery,
    progress: Option<f64>,
    reason: Option<String>,
) -> LxmfDeliveryEvent {
    LxmfDeliveryEvent {
        kind,
        method: if delivery.reusable {
            LxmfDeliveryEventMethod::Direct
        } else {
            LxmfDeliveryEventMethod::PropagationDeposit
        },
        link_id,
        dest_hash: delivery.dest_hash,
        msg_hash: delivery.msg_hash,
        attempts: delivery.message.delivery_attempts,
        progress,
        representation: delivery.message.representation,
        link_state: delivery.link.state,
        delivery_state: delivery.state,
        queued_deliveries: delivery.queued.len(),
        in_flight_deliveries: usize::from(delivery.state != DeliveryState::Idle),
        reason,
    }
}

fn queued_delivery_event(
    kind: LxmfDeliveryEventKind,
    link_id: [u8; 16],
    dest_hash: [u8; 16],
    queued: &QueuedDelivery,
    reason: Option<String>,
) -> LxmfDeliveryEvent {
    LxmfDeliveryEvent {
        kind,
        method: LxmfDeliveryEventMethod::Direct,
        link_id,
        dest_hash,
        msg_hash: queued.msg_hash,
        attempts: queued.message.delivery_attempts,
        progress: Some(queued.message.progress),
        representation: queued.message.representation,
        link_state: LinkState::Closed,
        delivery_state: DeliveryState::Failed,
        queued_deliveries: 0,
        in_flight_deliveries: 0,
        reason,
    }
}

struct BackchannelDeliveryEventInput<'a> {
    kind: LxmfDeliveryEventKind,
    message: &'a LxMessage,
    dest_hash: [u8; 16],
    link_id: [u8; 16],
    representation: DeliveryRepresentation,
    progress: Option<f64>,
    reason: Option<String>,
    link_state: LinkState,
    delivery_state: DeliveryState,
}

fn backchannel_delivery_event(input: BackchannelDeliveryEventInput<'_>) -> LxmfDeliveryEvent {
    LxmfDeliveryEvent {
        kind: input.kind,
        method: LxmfDeliveryEventMethod::Direct,
        link_id: input.link_id,
        dest_hash: input.dest_hash,
        msg_hash: input.message.hash,
        attempts: input.message.delivery_attempts,
        progress: input.progress,
        representation: input.representation,
        link_state: input.link_state,
        delivery_state: input.delivery_state,
        queued_deliveries: 0,
        in_flight_deliveries: usize::from(matches!(
            input.delivery_state,
            DeliveryState::Transferring | DeliveryState::AwaitingProof
        )),
        reason: input.reason,
    }
}

fn fail_backchannel_start(
    events: &mut VecDeque<LxmfDeliveryEvent>,
    mut start: PendingBackchannelStart,
    reason: String,
) -> DeliveryResult {
    fail_backchannel_start_in_place(events, &mut start, reason)
}

fn fail_backchannel_start_in_place(
    events: &mut VecDeque<LxmfDeliveryEvent>,
    start: &mut PendingBackchannelStart,
    reason: String,
) -> DeliveryResult {
    events.push_back(backchannel_delivery_event(BackchannelDeliveryEventInput {
        kind: LxmfDeliveryEventKind::Failed,
        message: &start.message,
        dest_hash: start.dest_hash,
        link_id: start.link_id,
        representation: DeliveryRepresentation::Unknown,
        progress: Some(start.message.progress),
        reason: Some(reason.clone()),
        link_state: LinkState::Closed,
        delivery_state: DeliveryState::Failed,
    }));
    let placeholder = LxMessage::new(
        start.dest_hash,
        start.message.source_hash,
        "",
        "",
        start.message.method,
    );
    let message = std::mem::replace(&mut start.message, placeholder);
    start.cancelled = true;
    DeliveryResult::Failed {
        link_id: start.link_id,
        msg_hash: message.hash,
        dest_hash: start.dest_hash,
        message,
        reason,
    }
}

fn delivery_resource_progress(delivery: &PendingDelivery) -> Option<f64> {
    let transfer = delivery.transfer.as_ref()?;
    let total_segments = transfer.resource.total_segments.max(1);
    let completed_segments = transfer.resource.segment_index.saturating_sub(1);
    let aggregate = (completed_segments as f64 + transfer.progress()) / total_segments as f64;
    Some((0.10 + aggregate * 0.90).clamp(0.10, 0.99))
}

fn delivery_resource_proof_progress(delivery: &PendingDelivery) -> Option<f64> {
    let transfer = delivery.transfer.as_ref()?;
    let total_segments = transfer.resource.total_segments.max(1);
    let completed_segments = transfer.resource.segment_index.min(total_segments);
    let aggregate = completed_segments as f64 / total_segments as f64;
    Some((0.10 + aggregate * 0.90).clamp(0.10, 1.0))
}

fn should_update_resource_progress(current: f64, next: f64) -> bool {
    next > current && ((next * 100.0).floor() > (current * 100.0).floor() || next >= 0.99)
}

fn maybe_push_resource_progress_event(
    events: &mut VecDeque<LxmfDeliveryEvent>,
    link_id: [u8; 16],
    delivery: &mut PendingDelivery,
) {
    let Some(progress) = delivery_resource_progress(delivery) else {
        return;
    };
    if !should_update_resource_progress(delivery.message.progress, progress) {
        return;
    }
    delivery.message.progress = progress;
    events.push_back(delivery_event(
        LxmfDeliveryEventKind::TransferProgress,
        link_id,
        delivery,
        Some(progress),
        None,
    ));
}

fn finish_reusable_delivery(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
    identity_pub: &Option<[u8; 64]>,
    identity_key: &Option<Ed25519PrivateKey>,
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
) {
    if !delivery.backchannel_identified {
        if let (Some(pub_key), Some(sign_key)) = (identity_pub, identity_key) {
            delivery.backchannel_identified = send_link_identify(
                transport_tx,
                pending_transport,
                pending_endpoint_sends,
                link_id,
                &delivery.link,
                pub_key,
                sign_key,
            );
        }
    }

    delivery.transfer = None;
    delivery.remaining_segments = None;
    delivery.packet_proof_hash = None;
    delivery.failure_reason = None;

    if delivery.link.is_active() && delivery.start_queued_delivery() {
        return;
    }

    delivery.state = DeliveryState::Idle;
}

fn finish_unsuccessful_reusable_delivery(delivery: &mut PendingDelivery) {
    delivery.transfer = None;
    delivery.remaining_segments = None;
    delivery.packet_proof_hash = None;
    delivery.failure_reason = None;

    if delivery.link.is_active() && delivery.start_queued_delivery() {
        return;
    }

    delivery.state = DeliveryState::Idle;
}

fn cancel_current_delivery(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
) {
    if let Some(resource_hash) = delivery
        .transfer
        .as_ref()
        .map(|transfer| transfer.resource.resource_hash)
    {
        let _ = dispatch_action(
            link_id,
            delivery,
            transport_tx,
            pending_transport,
            pending_endpoint_sends,
            TransferAction::SendCancel(rns_protocol::resource::CancelType::Icl, resource_hash),
        );
    }
}

fn push_failed_delivery_and_queue(
    results: &mut Vec<DeliveryResult>,
    events: &mut VecDeque<LxmfDeliveryEvent>,
    link_id: [u8; 16],
    delivery: &mut PendingDelivery,
    reason: &str,
) {
    delivery.transfer = None;
    delivery.remaining_segments = None;
    delivery.packet_proof_hash = None;
    events.push_back(delivery_event(
        LxmfDeliveryEventKind::Failed,
        link_id,
        delivery,
        Some(delivery.message.progress),
        Some(reason.to_string()),
    ));
    let message = take_current_delivery_message(delivery);
    results.push(DeliveryResult::Failed {
        link_id,
        msg_hash: delivery.msg_hash,
        dest_hash: delivery.dest_hash,
        message,
        reason: reason.to_string(),
    });
    fail_queued_deliveries(results, events, link_id, delivery, reason);
}

/// Move the potentially large attachment-bearing message into its terminal
/// result. Reusable Link sessions retain only a tiny placeholder until the
/// next queued message replaces it, avoiding a full deep clone on failure.
fn take_current_delivery_message(delivery: &mut PendingDelivery) -> LxMessage {
    let placeholder = LxMessage::new(
        delivery.dest_hash,
        delivery.message.source_hash,
        "",
        "",
        delivery.message.method,
    );
    std::mem::replace(&mut delivery.message, placeholder)
}

fn fail_queued_deliveries(
    results: &mut Vec<DeliveryResult>,
    events: &mut VecDeque<LxmfDeliveryEvent>,
    link_id: [u8; 16],
    delivery: &mut PendingDelivery,
    reason: &str,
) {
    for queued in delivery.queued.drain(..) {
        events.push_back(queued_delivery_event(
            LxmfDeliveryEventKind::Failed,
            link_id,
            delivery.dest_hash,
            &queued,
            Some(reason.to_string()),
        ));
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
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
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
    stage_link_endpoint_with_success(
        transport_tx,
        pending_transport,
        pending_endpoint_sends,
        *link_id,
        OutboundRequest {
            raw: Bytes::from(id_raw),
            destination_hash: *link_id,
        },
        EndpointSendSuccess::FinishHandshake,
    )
    .is_ok()
}

fn drive_link_action(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
    link_id: &[u8; 16],
    action: LinkAction,
    endpoint_release_queued: &mut bool,
) -> bool {
    match action {
        LinkAction::SendKeepalive => {
            send_keepalive_packet(
                transport_tx,
                pending_transport,
                pending_endpoint_sends,
                link_id,
            );
            false
        }
        LinkAction::TransitionedToStale => {
            // Python sends one more keepalive when an initiator transitions stale.
            send_keepalive_packet(
                transport_tx,
                pending_transport,
                pending_endpoint_sends,
                link_id,
            );
            false
        }
        LinkAction::SendTeardownAndClose(teardown_data) => {
            if !teardown_data.is_empty() {
                *endpoint_release_queued = send_link_close_payload(
                    transport_tx,
                    pending_transport,
                    pending_endpoint_sends,
                    link_id,
                    &teardown_data,
                );
            }
            true
        }
        LinkAction::Closed(_) => true,
        LinkAction::None => false,
    }
}

fn send_keepalive_packet(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
    link_id: &[u8; 16],
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
        context: rns_wire::context::PacketContext::Keepalive,
    };
    let mut raw = header.pack();
    raw.push(rns_link::constants::KEEPALIVE_REQUEST);
    let _ = stage_link_endpoint(
        transport_tx,
        pending_transport,
        pending_endpoint_sends,
        *link_id,
        OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        },
    );
}

fn send_link_close_payload(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
    link_id: &[u8; 16],
    teardown_data: &[u8],
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
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::LinkClose,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(teardown_data);
    stage_link_endpoint_and_unbind(
        transport_tx,
        pending_transport,
        pending_endpoint_sends,
        *link_id,
        OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        },
    )
    .is_ok()
}

fn link_data_idle_for(link: &Link) -> Duration {
    link.no_data_for().min(link.no_outbound_for())
}

fn direct_link_idle_expired(delivery: &PendingDelivery) -> bool {
    delivery.state == DeliveryState::Idle
        && delivery.queued.is_empty()
        && delivery.link.is_active()
        && link_data_idle_for(&delivery.link) > LINK_MAX_INACTIVITY
}

fn build_resource_transfer(
    link: &Link,
    packed: Vec<u8>,
    auto_compress: bool,
    rtt: Duration,
) -> Result<(OutboundTransfer, Option<LazyMultiSegmentOutbound>), ResourceError> {
    if packed.len() <= MAX_EFFICIENT_SIZE {
        let transfer = match link.session_keys() {
            Some(keys) => {
                OutboundTransfer::new_encrypted(packed, auto_compress, rtt, keys.clone())?
            }
            None => OutboundTransfer::new(packed, auto_compress, rtt)?,
        };
        return Ok((transfer, None));
    }

    let mut remaining = LazyMultiSegmentOutbound::new(packed, auto_compress)?;
    let first = next_resource_segment(link, &mut remaining)?.ok_or(ResourceError::Incomplete)?;
    let remaining = (remaining.remaining_segments() > 0).then_some(remaining);
    Ok((OutboundTransfer::from_prebuilt(first, rtt), remaining))
}

fn next_resource_segment(
    link: &Link,
    remaining: &mut LazyMultiSegmentOutbound,
) -> Result<Option<OutboundResource>, ResourceError> {
    match link.session_keys() {
        Some(keys) => {
            let keys = keys.clone();
            let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
                rns_link::encryption::link_encrypt(&keys, plaintext)
                    .unwrap_or_else(|_| plaintext.to_vec())
            };
            remaining.next_segment(Some(&encrypt_fn))
        }
        None => remaining.next_segment(None),
    }
}

/// Result of a delivery tick.
#[derive(Debug)]
pub enum DeliveryResult {
    Complete {
        link_id: [u8; 16],
        msg_hash: Option<[u8; 32]>,
    },
    Rejected {
        link_id: [u8; 16],
        msg_hash: Option<[u8; 32]>,
        dest_hash: [u8; 16],
        message: LxMessage,
        reason: String,
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

fn stage_transport(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending: &mut VecDeque<TransportMessage>,
    message: TransportMessage,
) -> Result<(), &'static str> {
    if pending.is_empty() {
        match transport_tx.try_send(message) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(message)) => pending.push_back(message),
            Err(TrySendError::Closed(_)) => return Err("transport channel closed"),
        }
    } else {
        if pending.len() >= LINK_PENDING_TRANSPORT_LIMIT {
            return Err("transport staging queue full");
        }
        pending.push_back(message);
    }
    Ok(())
}

fn stage_link_endpoint(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending: &mut VecDeque<TransportMessage>,
    pending_sends: &mut Vec<PendingEndpointSend>,
    link_id: [u8; 16],
    request: OutboundRequest,
) -> Result<(), &'static str> {
    stage_link_endpoint_with_success(
        transport_tx,
        pending,
        pending_sends,
        link_id,
        request,
        EndpointSendSuccess::None,
    )
}

fn stage_link_endpoint_with_success(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending: &mut VecDeque<TransportMessage>,
    pending_sends: &mut Vec<PendingEndpointSend>,
    link_id: [u8; 16],
    request: OutboundRequest,
    success: EndpointSendSuccess,
) -> Result<(), &'static str> {
    let (result_tx, result_rx) = oneshot::channel();
    stage_transport(
        transport_tx,
        pending,
        TransportMessage::SendLinkEndpoint {
            link_id,
            role: LinkEndpointRole::Initiator,
            request,
            result_tx,
        },
    )?;
    pending_sends.push(PendingEndpointSend {
        link_id,
        final_send: false,
        success,
        result_rx,
    });
    Ok(())
}

fn stage_link_endpoint_unbind(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending: &mut VecDeque<TransportMessage>,
    pending_cleanups: &mut Vec<PendingEndpointCleanup>,
    link_id: [u8; 16],
) -> Result<(), &'static str> {
    let (result_tx, result_rx) = oneshot::channel();
    stage_transport(
        transport_tx,
        pending,
        TransportMessage::UnbindLinkEndpoint {
            link_id,
            role: LinkEndpointRole::Initiator,
            result_tx,
        },
    )?;
    pending_cleanups.push(PendingEndpointCleanup { link_id, result_rx });
    Ok(())
}

fn stage_link_endpoint_and_unbind(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending: &mut VecDeque<TransportMessage>,
    pending_sends: &mut Vec<PendingEndpointSend>,
    link_id: [u8; 16],
    request: OutboundRequest,
) -> Result<(), &'static str> {
    let (result_tx, result_rx) = oneshot::channel();
    stage_transport(
        transport_tx,
        pending,
        TransportMessage::SendLinkEndpointAndUnbind {
            link_id,
            role: LinkEndpointRole::Initiator,
            request,
            result_tx,
        },
    )?;
    pending_sends.push(PendingEndpointSend {
        link_id,
        final_send: true,
        success: EndpointSendSuccess::None,
        result_rx,
    });
    Ok(())
}

fn flush_staged_transport(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending: &mut VecDeque<TransportMessage>,
) -> Result<(), &'static str> {
    while let Some(message) = pending.pop_front() {
        match transport_tx.try_send(message) {
            Ok(()) => {}
            Err(TrySendError::Full(message)) => {
                pending.push_front(message);
                break;
            }
            Err(TrySendError::Closed(_)) => {
                pending.clear();
                return Err("transport channel closed");
            }
        }
    }
    Ok(())
}

fn inbound_resource_accepted(
    handler: Option<&InboundResourceAcceptHandler>,
    link_id: [u8; 16],
    advertisement: &ResourceAdvertisement,
) -> bool {
    handler.is_none_or(|handler| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler(link_id, advertisement)
        }))
        .unwrap_or_else(|_| {
            tracing::error!(
                link_id = %hex_encode(&link_id),
                resource = %hex_encode(&advertisement.resource_hash[..8]),
                "reverse Resource admission callback panicked"
            );
            false
        })
    })
}

fn notify_inbound_resource_concluded(
    handler: Option<&InboundResourceConcludedHandler>,
    link_id: [u8; 16],
    resource_id: [u8; 32],
) {
    let Some(handler) = handler else {
        return;
    };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handler(link_id, resource_id)
    }))
    .is_err()
    {
        tracing::error!(
            link_id = %hex_encode(&link_id),
            resource = %hex_encode(&resource_id[..8]),
            "reverse Resource conclusion callback panicked"
        );
    }
}

fn dispatch_inbound_resource_action(
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
    action: TransferAction,
) -> Result<(), &'static str> {
    let (context, payload, encrypted, packet_type) = match action {
        TransferAction::SendProof(payload) => (
            rns_wire::context::PacketContext::ResourcePrf,
            payload,
            false,
            rns_wire::flags::PacketType::Proof,
        ),
        TransferAction::SendHmu(payload) => (
            rns_wire::context::PacketContext::ResourceHmu,
            payload,
            true,
            rns_wire::flags::PacketType::Data,
        ),
        TransferAction::SendRequest(payload) => (
            rns_wire::context::PacketContext::ResourceReq,
            payload,
            true,
            rns_wire::flags::PacketType::Data,
        ),
        TransferAction::SendCancel(cancel_type, resource_hash) => (
            match cancel_type {
                rns_protocol::resource::CancelType::Icl => {
                    rns_wire::context::PacketContext::ResourceIcl
                }
                rns_protocol::resource::CancelType::Rcl => {
                    rns_wire::context::PacketContext::ResourceRcl
                }
            },
            resource_hash.to_vec(),
            true,
            rns_wire::flags::PacketType::Data,
        ),
        TransferAction::None | TransferAction::Complete | TransferAction::Failed(_) => {
            return Ok(());
        }
        TransferAction::SendAdvertisement(_) | TransferAction::SendPart(_, _) => {
            return Err("invalid inbound Resource action");
        }
    };
    let body = if encrypted {
        delivery
            .link
            .encrypt(&payload)
            .map_err(|_| "link Resource encryption failed")?
    } else {
        payload
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
        destination_hash: *link_id,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&body);
    stage_link_endpoint(
        transport_tx,
        pending_transport,
        pending_endpoint_sends,
        *link_id,
        OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        },
    )?;
    delivery.link.record_tx(body.len());
    Ok(())
}

fn drop_inbound_resource(delivery: &mut PendingDelivery, resource_hash: [u8; 32]) -> [u8; 32] {
    let resource_id = delivery
        .inbound_segment_routing
        .get(&resource_hash)
        .map(|route| route.original_hash)
        .unwrap_or(resource_hash);
    let segment_hashes: Vec<[u8; 32]> = delivery
        .inbound_segment_routing
        .iter()
        .filter_map(|(segment_hash, route)| {
            (route.original_hash == resource_id).then_some(*segment_hash)
        })
        .collect();
    if segment_hashes.is_empty() {
        delivery.inbound_resources.remove(&resource_hash);
        delivery.link.untrack_resource(&resource_hash);
    } else {
        for segment_hash in segment_hashes {
            delivery.inbound_resources.remove(&segment_hash);
            delivery.inbound_segment_routing.remove(&segment_hash);
            delivery.link.untrack_resource(&segment_hash);
        }
    }
    delivery.inbound_split_resources.remove(&resource_id);
    delivery.inbound_resource_lifecycles.remove(&resource_id);
    resource_id
}

fn drop_all_inbound_resources(delivery: &mut PendingDelivery) -> Vec<[u8; 32]> {
    let resource_ids: Vec<[u8; 32]> = delivery
        .inbound_resource_lifecycles
        .keys()
        .copied()
        .collect();
    let segment_hashes: Vec<[u8; 32]> = delivery.inbound_resources.keys().copied().collect();
    for segment_hash in segment_hashes {
        delivery.link.untrack_resource(&segment_hash);
    }
    delivery.inbound_resources.clear();
    delivery.inbound_segment_routing.clear();
    delivery.inbound_split_resources.clear();
    delivery.inbound_resource_lifecycles.clear();
    resource_ids
}

fn drive_inbound_resource_watchdogs(
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
    concluded_handler: Option<&InboundResourceConcludedHandler>,
) {
    let actions: Vec<([u8; 32], TransferAction)> = delivery
        .inbound_resources
        .iter_mut()
        .filter_map(|(resource_hash, transfer)| {
            let action = transfer.check_timeout();
            (!matches!(action, TransferAction::None)).then_some((*resource_hash, action))
        })
        .collect();
    for (resource_hash, action) in actions {
        if !delivery.inbound_resources.contains_key(&resource_hash) {
            continue;
        }
        match action {
            TransferAction::Failed(reason) => {
                tracing::warn!(
                    link_id = %hex_encode(link_id),
                    resource = %hex_encode(&resource_hash[..8]),
                    %reason,
                    "reverse Resource receive watchdog exhausted"
                );
                let resource_id = drop_inbound_resource(delivery, resource_hash);
                notify_inbound_resource_concluded(concluded_handler, *link_id, resource_id);
            }
            retry => {
                if dispatch_inbound_resource_action(
                    link_id,
                    delivery,
                    transport_tx,
                    pending_transport,
                    pending_endpoint_sends,
                    retry,
                )
                .is_err()
                {
                    let resource_id = drop_inbound_resource(delivery, resource_hash);
                    notify_inbound_resource_concluded(concluded_handler, *link_id, resource_id);
                }
            }
        }
    }

    let now = Instant::now();
    let expired: Vec<[u8; 32]> = delivery
        .inbound_resource_lifecycles
        .iter()
        .filter_map(|(resource_id, lifecycle)| {
            lifecycle
                .inter_segment_deadline
                .is_some_and(|deadline| now >= deadline)
                .then_some(*resource_id)
        })
        .collect();
    for resource_id in expired {
        tracing::warn!(
            link_id = %hex_encode(link_id),
            resource = %hex_encode(&resource_id[..8]),
            "timed out waiting for the next reverse Resource segment"
        );
        let resource_id = drop_inbound_resource(delivery, resource_id);
        notify_inbound_resource_concluded(concluded_handler, *link_id, resource_id);
    }
}

fn inbound_split_wait_timeout(link: &Link) -> Duration {
    link.rtt
        .unwrap_or(Duration::from_millis(500))
        .saturating_mul(rns_link::constants::TRAFFIC_TIMEOUT_FACTOR as u32)
        .saturating_add(Duration::from_secs_f64(
            rns_protocol::resource::PROCESSING_GRACE,
        ))
        .saturating_mul((rns_protocol::resource::MAX_ADV_RETRIES + 1) as u32)
        .saturating_add(Duration::from_secs_f64(
            rns_protocol::resource::SENDER_GRACE_TIME,
        ))
        .max(Duration::from_secs(30))
}

/// Send a single LXMF packet over an active link and return the full packet hash that the peer
/// must prove with `LINKPROOF`.
fn send_link_packet(
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
    pending_packet_dispatches: &mut Vec<PendingPacketDispatch>,
    packed: &[u8],
) -> Result<[u8; 32], &'static str> {
    let encrypted = delivery
        .link
        .encrypt(packed)
        .map_err(|_| "link packet encryption failed")?;
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
    delivery.started_at = Instant::now();
    if let Some(token) = &delivery.endpoint_dispatch_token {
        let result_rx = token
            .try_send(
                OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: *link_id,
                },
                delivery.started_at + LINK_PACKET_DISPATCH_TIMEOUT,
            )
            .map_err(|_| "transport channel is full or closed")?;
        pending_packet_dispatches.push(PendingPacketDispatch {
            link_id: *link_id,
            packet_hash,
            result_rx,
        });
        delivery.link.record_tx(encrypted.len());
        return Ok(packet_hash);
    }
    stage_link_endpoint_with_success(
        transport_tx,
        pending_transport,
        pending_endpoint_sends,
        *link_id,
        OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        },
        EndpointSendSuccess::StartPacketProofClock(packet_hash),
    )?;
    delivery.link.record_tx(encrypted.len());
    Ok(packet_hash)
}

fn send_link_teardown(
    transport_tx: &mpsc::Sender<TransportMessage>,
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
    link_id: &[u8; 16],
    link: &mut Link,
) -> bool {
    let Some(teardown_data) = link.teardown(CloseReason::InitiatorClosed) else {
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
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::LinkClose,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&teardown_data);
    stage_link_endpoint_and_unbind(
        transport_tx,
        pending_transport,
        pending_endpoint_sends,
        *link_id,
        OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        },
    )
    .is_ok()
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
    pending_transport: &mut VecDeque<TransportMessage>,
    pending_endpoint_sends: &mut Vec<PendingEndpointSend>,
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
    let mut send = |header: rns_wire::header::PacketHeader, body: &[u8]| {
        let mut raw = header.pack();
        raw.extend_from_slice(body);
        stage_link_endpoint(
            transport_tx,
            pending_transport,
            pending_endpoint_sends,
            *link_id,
            OutboundRequest {
                raw: Bytes::from(raw),
                destination_hash: *link_id,
            },
        )
    };

    match action {
        TransferAction::SendAdvertisement(adv_data) => {
            if let Ok(encrypted) = delivery.link.encrypt(&adv_data) {
                if let Err(reason) = send(
                    make_header(
                        rns_wire::context::PacketContext::ResourceAdv,
                        rns_wire::flags::PacketType::Data,
                    ),
                    &encrypted,
                ) {
                    delivery.state = DeliveryState::Failed;
                    return ActionOutcome::Fail(reason.to_string());
                }
                delivery.link.record_tx(encrypted.len());
            }
            ActionOutcome::Continue
        }
        TransferAction::SendPart(_, part_data) => {
            // Parts are already ciphertext (pre-chunk blob encryption). `context=Resource`
            // packets are not packet-layer encrypted (Packet.py:201-204).
            if let Err(reason) = send(
                make_header(
                    rns_wire::context::PacketContext::Resource,
                    rns_wire::flags::PacketType::Data,
                ),
                &part_data,
            ) {
                delivery.state = DeliveryState::Failed;
                return ActionOutcome::Fail(reason.to_string());
            }
            delivery.link.record_tx(part_data.len());
            ActionOutcome::Continue
        }
        TransferAction::SendHmu(hmu_data) => {
            if let Ok(encrypted) = delivery.link.encrypt(&hmu_data) {
                if let Err(reason) = send(
                    make_header(
                        rns_wire::context::PacketContext::ResourceHmu,
                        rns_wire::flags::PacketType::Data,
                    ),
                    &encrypted,
                ) {
                    delivery.state = DeliveryState::Failed;
                    return ActionOutcome::Fail(reason.to_string());
                }
                delivery.link.record_tx(encrypted.len());
            }
            ActionOutcome::Continue
        }
        TransferAction::SendRequest(req_data) => {
            if let Ok(encrypted) = delivery.link.encrypt(&req_data) {
                if let Err(reason) = send(
                    make_header(
                        rns_wire::context::PacketContext::ResourceReq,
                        rns_wire::flags::PacketType::Data,
                    ),
                    &encrypted,
                ) {
                    delivery.state = DeliveryState::Failed;
                    return ActionOutcome::Fail(reason.to_string());
                }
                delivery.link.record_tx(encrypted.len());
            }
            ActionOutcome::Continue
        }
        TransferAction::SendProof(proof_data) => {
            // PROOF+RESOURCE_PRF is plaintext on a Proof packet (Packet.py:195-197). Body =
            // resource_hash(32) || proof(32).
            if let Err(reason) = send(
                make_header(
                    rns_wire::context::PacketContext::ResourcePrf,
                    rns_wire::flags::PacketType::Proof,
                ),
                &proof_data,
            ) {
                delivery.state = DeliveryState::Failed;
                return ActionOutcome::Fail(reason.to_string());
            }
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
                if let Err(reason) = send(
                    make_header(context, rns_wire::flags::PacketType::Data),
                    &encrypted,
                ) {
                    delivery.state = DeliveryState::Failed;
                    return ActionOutcome::Fail(reason.to_string());
                }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn link_establishment_timing_matches_upstream_medium_fast_one_and_multi_hop() {
        // RNode Firmware's Medium Fast preset is SF9/BW250/CR5. The firmware's
        // integer bitrate calculation yields 3515 bit/s, while Reticulum uses
        // its normalised 500-byte protocol MTU for first-hop timing.
        let timing = LinkEstablishmentTiming::from_first_hop_bitrate(3_515);
        let expected_first_hop = 6.0 + (500.0 * 8.0 / 3_515.0);
        let expected_one_hop = expected_first_hop + 6.0;
        let expected_three_hops = expected_first_hop + 18.0;

        assert!((timing.first_hop_timeout().as_secs_f64() - expected_first_hop).abs() < 1e-9);
        assert!((timing.timeout_for_hops(1).as_secs_f64() - expected_one_hop).abs() < 1e-9);
        assert!((timing.timeout_for_hops(3).as_secs_f64() - expected_three_hops).abs() < 1e-9);
        assert!((timing.timeout_for_hops(1).as_secs_f64() - 13.137_980_085).abs() < 1e-9);

        // The explicit constructor accepts a *normalised Reticulum protocol*
        // MTU, never a raw BLE ATT or hardware-interface MTU. Values above the
        // protocol maximum normalise back to the canonical 500-byte boundary.
        assert_eq!(
            timing,
            LinkEstablishmentTiming::from_first_hop_bitrate_and_mtu(3_515, 1_024)
        );

        let unknown_interface = LinkEstablishmentTiming::default();
        assert_eq!(
            unknown_interface.first_hop_timeout(),
            Duration::from_secs(6)
        );
        assert_eq!(
            unknown_interface.timeout_for_hops(1),
            Duration::from_secs(12)
        );
        assert_eq!(
            unknown_interface.timeout_for_hops(3),
            Duration::from_secs(24)
        );
    }

    #[test]
    fn timed_start_applies_one_clock_and_preserves_establishing_cancel() {
        let (tx, _rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let signing_key = Ed25519PrivateKey::generate();
        let mut message = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Timed",
            "cancel remains local",
            crate::constants::DeliveryMethod::Direct,
        );
        message.sign(&signing_key).unwrap();
        let message_hash = message.hash.unwrap();
        let timing = LinkEstablishmentTiming::from_first_hop_bitrate(3_515);
        let expected = timing.timeout_for_hops(3);

        let link_id = mgr
            .start_delivery_with_timing(message, [0xCC; 16], 3, timing)
            .unwrap();
        let pending = mgr.pending.get(&link_id).unwrap();
        assert_eq!(pending.establishment_timeout, expected);
        assert_eq!(pending.link.establishment_timeout, expected);

        assert!(mgr.cancel_delivery_by_message_hash(message_hash));
        assert!(!mgr.cancel_delivery_by_message_hash(message_hash));
        assert_eq!(mgr.pending_count(), 0);
        assert!(
            mgr.take_delivery_events()
                .iter()
                .all(|event| event.kind != LxmfDeliveryEventKind::Failed)
        );
    }

    fn next_outbound(rx: &mut mpsc::Receiver<TransportMessage>) -> Vec<u8> {
        while let Ok(message) = rx.try_recv() {
            match message {
                TransportMessage::Outbound(request) => return request.raw.to_vec(),
                TransportMessage::SendLinkEndpoint {
                    request, result_tx, ..
                } => {
                    let _ = result_tx.send(LinkEndpointSendResult::Sent);
                    return request.raw.to_vec();
                }
                _ => {}
            }
        }
        panic!("expected outbound transport message");
    }

    fn complete_direct_cleanup(
        mgr: &mut LinkDeliveryManager,
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
        mgr.poll_endpoint_control();
        while let Ok(message) = rx.try_recv() {
            saw_deregister |= matches!(message, TransportMessage::DeregisterDestination { .. });
        }
        saw_deregister
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
            &responder_pub.to_bytes(),
            0,
        ));

        let bind = rx.try_recv().expect("endpoint binding request");
        let TransportMessage::BindLinkEndpoint {
            binding, result_tx, ..
        } = bind
        else {
            panic!("expected endpoint binding request");
        };
        assert_eq!(binding.link_id, link_id);
        assert_eq!(binding.interface_id, 0);
        result_tx.send(LinkEndpointBindResult::Bound).unwrap();
        mgr.poll_endpoint_control();

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
        link_data_packet_with_header(
            link_id,
            rns_wire::flags::HeaderType::Header1,
            context,
            payload,
        )
    }

    fn link_data_packet_with_header(
        link_id: [u8; 16],
        header_type: rns_wire::flags::HeaderType,
        context: rns_wire::context::PacketContext,
        payload: &[u8],
    ) -> Bytes {
        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Link,
                packet_type: rns_wire::flags::PacketType::Data,
            },
            hops: 0,
            transport_id: (header_type == rns_wire::flags::HeaderType::Header2)
                .then_some([0xEE; 16]),
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
        _responder_key: &Ed25519PrivateKey,
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
            .prove_packet_with_local_signer(&packet_hash)
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
                metrics: Default::default(),
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

    fn timing_message(label: &str) -> LxMessage {
        let mut message = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            label,
            "bounded delivery",
            crate::constants::DeliveryMethod::Direct,
        );
        message.sign(&Ed25519PrivateKey::generate()).unwrap();
        message
    }

    #[tokio::test]
    async fn exact_packet_dispatch_waits_for_driver_and_preserves_original_proof_clock() {
        exact_packet_driver_fixture(false, false).await;
    }

    #[tokio::test]
    async fn exact_packet_cancel_before_driver_admission_never_sends_payload() {
        exact_packet_driver_fixture(true, false).await;
    }

    #[tokio::test]
    async fn exact_packed_packet_preserves_rtt_identify_and_payload_order() {
        exact_packet_driver_fixture(false, true).await;
    }

    #[tokio::test]
    async fn exact_cancel_before_bind_receipt_cannot_revive_delivery_or_leak_binding() {
        use rns_transport::actor::TransportActor;
        use rns_transport::constants::{InterfaceDirection, InterfaceMode};
        use rns_transport::messages::InterfaceEntry;
        let (mut actor, actor_tx) = TransportActor::new();
        let (driver_tx, _driver_rx) = mpsc::channel(8);
        actor.interfaces.insert(
            7,
            InterfaceEntry::new(
                "bind cancellation".to_string(),
                InterfaceMode::Full,
                InterfaceDirection::bidirectional(),
                3_515,
                500,
                driver_tx,
            ),
        );
        let dispatch = actor.link_endpoint_dispatch_handle();
        let (tx, mut rx) = mpsc::channel(32);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_link_endpoint_dispatch_handle(dispatch.clone());
        let message = timing_message("cancel before exact bind");
        let hash = message.hash.unwrap();
        let dest = [0x95; 16];
        let link_id = mgr.start_delivery(message, dest, 1).unwrap();
        let raw = next_outbound(&mut rx);
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        let key = Ed25519PrivateKey::generate();
        let (_, proof) = Link::new_responder(&raw[offset..], &key, dest, 1).unwrap();
        let public = key.public_key();
        assert!(mgr.handle_link_proof(&link_id, &proof, &public, &public.to_bytes(), 7));
        assert!(mgr.pending[&link_id].link.is_active());
        assert!(mgr.cancel_delivery_by_message_hash(hash));
        assert!(mgr.pending_endpoint_binds.is_empty());
        assert!(!mgr.pending.contains_key(&link_id));
        let task = tokio::spawn(actor.run());
        let (lifecycle_tx, _lifecycle_rx) = mpsc::unbounded_channel();
        let receipt = dispatch
            .try_bind(
                LinkEndpointBinding {
                    link_id,
                    interface_id: 7,
                    role: LinkEndpointRole::Initiator,
                },
                lifecycle_tx,
            )
            .unwrap();
        let token = tokio::time::timeout(Duration::from_secs(2), receipt)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            token.binding().link_id,
            link_id,
            "unread old bind was retired"
        );
        mgr.poll_endpoint_control();
        assert!(mgr.tick().is_empty());
        assert!(mgr.message_timeout_window(hash).is_none());
        actor_tx.send(TransportMessage::Shutdown).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn exact_establishing_cancellation_preserves_only_uncancelled_followers() {
        use rns_transport::actor::TransportActor;
        use rns_transport::constants::{InterfaceDirection, InterfaceMode};
        use rns_transport::messages::InterfaceEntry;
        use rns_transport::path_table::PathEntry;
        // Cancel the first before LRPROOF, after LRPROOF but before exact bind
        // publication, or cancel only the middle queued message.
        for mode in 0..3 {
            let (mut actor, tx) = TransportActor::new();
            let (driver_tx, mut driver_rx) = mpsc::channel(8);
            let dest = [0x38; 16];
            actor.interfaces.insert(
                7,
                InterfaceEntry::new(
                    "queued cancellation".into(),
                    InterfaceMode::Full,
                    InterfaceDirection::bidirectional(),
                    3_515,
                    500,
                    driver_tx,
                ),
            );
            actor
                .path_table
                .insert(dest, PathEntry::new(None, 1, 7, InterfaceMode::Full));
            let dispatch = actor.link_endpoint_dispatch_handle();
            let task = tokio::spawn(actor.run());
            let mut mgr = LinkDeliveryManager::new(tx.clone(), None, None);
            mgr.set_link_endpoint_dispatch_handle(dispatch);
            let mut messages = [
                timing_message("first"),
                timing_message("second"),
                timing_message("third"),
            ];
            let hashes = messages.each_ref().map(|message| message.hash.unwrap());
            let payloads = messages.each_mut().map(|message| message.pack().unwrap());
            let [first, second, third] = messages;
            let link_id = mgr.start_delivery(first, dest, 1).unwrap();
            assert_eq!(mgr.start_delivery(second, dest, 1).unwrap(), link_id);
            assert_eq!(mgr.start_delivery(third, dest, 1).unwrap(), link_id);
            let original_start = mgr.pending[&link_id].started_at;
            let raw = tokio::time::timeout(Duration::from_secs(2), driver_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let (_, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
            let key = Ed25519PrivateKey::generate();
            let (mut peer, proof) = Link::new_responder(&raw[offset..], &key, dest, 1).unwrap();
            let public = key.public_key();
            let cancelled_index = if mode == 2 { 1 } else { 0 };
            if mode != 1 {
                assert!(mgr.cancel_delivery_by_message_hash(hashes[cancelled_index]));
            }
            assert!(mgr.handle_link_proof(&link_id, &proof, &public, &public.to_bytes(), 7));
            if mode == 1 {
                assert!(mgr.cancel_delivery_by_message_hash(hashes[0]));
                assert!(mgr.pending_endpoint_binds.contains_key(&link_id));
            }
            assert_eq!(mgr.pending[&link_id].started_at, original_start);
            assert_eq!(mgr.pending[&link_id].state, DeliveryState::Establishing);
            assert!(
                mgr.message_delivery_snapshot(hashes[cancelled_index])
                    .is_none()
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                while mgr.pending[&link_id].state == DeliveryState::Establishing {
                    mgr.poll_endpoint_control();
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            mgr.pending.get_mut(&link_id).unwrap().link.rtt = Some(Duration::from_secs(1));
            let rtt = tokio::time::timeout(Duration::from_secs(2), driver_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&rtt).unwrap();
            assert_eq!(header.context, rns_wire::context::PacketContext::Lrrtt);
            peer.receive_rtt_packet(&rtt[offset..]).unwrap();
            for index in (0..3).filter(|index| *index != cancelled_index) {
                let raw = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        assert!(mgr.tick().is_empty());
                        if let Ok(raw) = driver_rx.try_recv() {
                            break raw;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let (header, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
                assert_eq!(header.context, rns_wire::context::PacketContext::None);
                assert_eq!(peer.decrypt(&raw[offset..]).unwrap(), payloads[index]);
                let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                let proof = peer.prove_packet_with_local_signer(&packet_hash).unwrap();
                assert!(mgr.handle_link_packet_proof(&link_id, &proof));
                assert!(
                    matches!(mgr.tick().as_slice(), [DeliveryResult::Complete {msg_hash: Some(hash), ..}] if *hash == hashes[index])
                );
            }
            assert_eq!(mgr.pending_count(), 0);
            assert!(mgr.tick().is_empty());
            assert!(driver_rx.try_recv().is_err());
            tx.send(TransportMessage::Shutdown).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    async fn exact_packet_driver_fixture(cancel: bool, packed: bool) {
        use rns_transport::actor::TransportActor;
        use rns_transport::constants::{InterfaceDirection, InterfaceMode};
        use rns_transport::messages::{InterfaceEntry, TimerTick};
        use rns_transport::path_table::PathEntry;

        let (mut actor, tx) = TransportActor::new();
        let (driver_tx, mut driver_rx) = mpsc::channel(1);
        let dest = [0x94; 16];
        actor.interfaces.insert(
            7,
            InterfaceEntry::new(
                "bounded test driver".to_string(),
                InterfaceMode::Full,
                InterfaceDirection::bidirectional(),
                3_515,
                500,
                driver_tx,
            ),
        );
        actor
            .path_table
            .insert(dest, PathEntry::new(None, 1, 7, InterfaceMode::Full));
        let handle = actor.link_endpoint_dispatch_handle();
        let actor_task = tokio::spawn(actor.run());
        let identity = Ed25519PrivateKey::generate();
        let mut identity_pub = [0; 64];
        identity_pub[32..].copy_from_slice(&identity.public_key().to_bytes());
        let mut mgr = LinkDeliveryManager::new(
            tx.clone(),
            packed.then_some(identity_pub),
            packed.then_some(identity),
        );
        mgr.set_link_endpoint_dispatch_handle(handle);
        let message = timing_message("exact driver admission");
        let message_hash = message.hash.unwrap();
        let link_id = if packed {
            mgr.start_packed_delivery(message, dest, 1, b"packed propagation".to_vec(), false)
                .unwrap()
        } else {
            mgr.start_delivery(message, dest, 1).unwrap()
        };
        let raw = tokio::time::timeout(Duration::from_secs(2), driver_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        let key = Ed25519PrivateKey::generate();
        let (mut responder, proof) = Link::new_responder(&raw[offset..], &key, dest, 1).unwrap();
        let public = key.public_key();
        assert!(mgr.handle_link_proof(&link_id, &proof, &public, &public.to_bytes(), 7));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                mgr.poll_endpoint_control();
                if mgr.pending[&link_id].state == DeliveryState::Identifying {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(mgr.pending[&link_id].endpoint_dispatch_token.is_some());
        mgr.pending.get_mut(&link_id).unwrap().link.rtt = Some(Duration::from_millis(1));
        assert!(mgr.tick().is_empty());
        // LRRRTT occupies the only driver slot. The ordinary packet is retained
        // in the actor's actual FIFO, not a fabricated Queued acknowledgement.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            mgr.tick().is_empty(),
            "5ms proof floor must not run before driver admission"
        );
        if packed {
            assert_eq!(mgr.pending[&link_id].state, DeliveryState::Identifying);
            let rtt = driver_rx.recv().await.unwrap();
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&rtt).unwrap();
            assert_eq!(header.context, rns_wire::context::PacketContext::Lrrtt);
            responder.receive_rtt_packet(&rtt[offset..]).unwrap();
            tx.send(TransportMessage::Tick(TimerTick {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64(),
            }))
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    assert!(mgr.tick().is_empty());
                    if mgr.pending[&link_id].state == DeliveryState::AwaitingProof {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert!(mgr.tick().is_empty());
        }
        assert!(mgr.pending[&link_id].packet_awaiting_dispatch);
        assert_eq!(
            mgr.message_timeout_window(message_hash).unwrap().1,
            Duration::from_secs(120)
        );
        if cancel {
            assert!(mgr.cancel_delivery_by_message_hash(message_hash));
            assert!(mgr.pending_packet_dispatches.is_empty());
        }
        let rtt = driver_rx.recv().await.unwrap();
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&rtt).unwrap();
        if packed {
            assert_eq!(
                header.context,
                rns_wire::context::PacketContext::LinkIdentify
            );
            assert_eq!(
                responder.handle_identification(&rtt[offset..]).unwrap(),
                identity_pub
            );
        } else {
            assert_eq!(header.context, rns_wire::context::PacketContext::Lrrtt);
            responder.receive_rtt_packet(&rtt[offset..]).unwrap();
        }
        tx.send(TransportMessage::Tick(TimerTick {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        }))
        .await
        .unwrap();
        if cancel {
            assert!(
                tokio::time::timeout(Duration::from_millis(50), driver_rx.recv())
                    .await
                    .is_err()
            );
            assert!(mgr.tick().is_empty());
            assert!(mgr.message_timeout_window(message_hash).is_none());
        } else {
            let packet = tokio::time::timeout(Duration::from_secs(2), driver_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&packet).unwrap();
            assert_eq!(header.context, rns_wire::context::PacketContext::None);
            assert!(!responder.decrypt(&packet[offset..]).unwrap().is_empty());
            let before_observation = Instant::now();
            tokio::time::sleep(Duration::from_millis(30)).await;
            mgr.poll_endpoint_control();
            let (dispatched, timeout) = mgr.message_timeout_window(message_hash).unwrap();
            assert!(dispatched <= before_observation);
            assert_eq!(timeout, Duration::from_millis(6));
            assert!(!mgr.pending[&link_id].packet_awaiting_dispatch);
            assert!(
                matches!(mgr.tick().as_slice(), [DeliveryResult::Failed { reason, .. }] if reason == "delivery timeout")
            );
            assert!(mgr.tick().is_empty());
        }
        tx.send(TransportMessage::Shutdown).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), actor_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn reused_packet_waits_for_admission_then_rtt_and_releases_queue_after_fade() {
        for rtt in [Duration::from_millis(1), Duration::from_secs(2)] {
            let (tx, mut rx) = mpsc::channel(128);
            let mut mgr = LinkDeliveryManager::new(tx, None, None);
            let responder_key = Ed25519PrivateKey::generate();
            let dest = [0x92; 16];
            let (link_id, responder) = establish_active_delivery(
                &mut mgr,
                &mut rx,
                timing_message("warmup"),
                &responder_key,
                dest,
            );
            assert!(mgr.tick().is_empty());
            complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder, &responder_key);
            assert!(matches!(
                mgr.tick().as_slice(),
                [DeliveryResult::Complete { .. }]
            ));
            mgr.pending.get_mut(&link_id).unwrap().link.rtt = Some(rtt);
            let fading = timing_message("fade");
            let fading_hash = fading.hash.unwrap();
            assert_eq!(mgr.start_delivery(fading, dest, 1).unwrap(), link_id);
            assert!(mgr.tick().is_empty());
            let TransportMessage::SendLinkEndpoint { result_tx, .. } = rx.try_recv().unwrap()
            else {
                panic!("ordinary packet must use its exact endpoint")
            };
            // Local transport staging can outlast a fast Link's proof window.
            mgr.pending.get_mut(&link_id).unwrap().started_at =
                Instant::now() - Duration::from_secs(4);
            assert!(mgr.tick().is_empty());
            assert_eq!(
                mgr.message_timeout_window(fading_hash).unwrap().1,
                Duration::from_secs(10)
            );
            result_tx.send(LinkEndpointSendResult::Sent).unwrap();
            mgr.poll_endpoint_control();
            let proof_window = mgr.message_timeout_window(fading_hash).unwrap();
            assert_eq!(
                proof_window.1,
                rtt.saturating_mul(6).max(Duration::from_millis(5))
            );
            assert!(proof_window.0.elapsed() < Duration::from_secs(1));

            let queued = timing_message("queued behind fade");
            let queued_hash = queued.hash.unwrap();
            assert_eq!(mgr.start_delivery(queued, dest, 1).unwrap(), link_id);
            assert!(mgr.message_timeout_window(queued_hash).is_none());
            // Even a still-active Link must not hide the missing packet proof.
            mgr.pending.get_mut(&link_id).unwrap().started_at =
                Instant::now() - proof_window.1 - Duration::from_secs(1);
            let failures = mgr.tick();
            assert_eq!(failures.len(), 2);
            let mut recovered_messages = Vec::new();
            for failure in failures {
                let DeliveryResult::Failed {
                    message, reason, ..
                } = failure
                else {
                    panic!()
                };
                assert!(is_retryable_link_delivery_failure(&reason));
                assert_eq!(reason, "delivery timeout");
                recovered_messages.push(message);
            }
            assert!(mgr.direct_link_snapshot(dest).is_none());
            assert!(mgr.message_timeout_window(fading_hash).is_none());
            // A fresh authenticated Link can deliver the exact failed messages.
            // Endpoint cleanup belongs to the old generation, not the retry.
            complete_direct_cleanup(&mut mgr, &mut rx);
            let (new_id, new_peer) = establish_active_delivery(
                &mut mgr,
                &mut rx,
                recovered_messages.remove(0),
                &responder_key,
                dest,
            );
            assert_ne!(new_id, link_id);
            mgr.start_delivery(recovered_messages.remove(0), dest, 1)
                .unwrap();
            for _ in 0..2 {
                assert!(mgr.tick().is_empty());
                complete_next_link_packet(&mut mgr, &mut rx, new_id, &new_peer, &responder_key);
                assert!(matches!(
                    mgr.tick().as_slice(),
                    [DeliveryResult::Complete { .. }]
                ));
            }
            assert_eq!(mgr.pending_count(), 0);
        }
    }

    #[test]
    fn late_packet_admission_does_not_rearm_next_message_or_cancelled_owner() {
        let (tx, mut rx) = mpsc::channel(128);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let responder_key = Ed25519PrivateKey::generate();
        let dest = [0x93; 16];
        let first = timing_message("proof beats local acknowledgement");
        let first_hash = first.hash.unwrap();
        let (link_id, responder) =
            establish_active_delivery(&mut mgr, &mut rx, first, &responder_key, dest);
        mgr.tick();
        let TransportMessage::SendLinkEndpoint {
            request, result_tx, ..
        } = rx.try_recv().unwrap()
        else {
            panic!()
        };
        let packet_hash =
            rns_wire::hash::packet_hash(&request.raw, rns_wire::flags::HeaderType::Header1);
        let proof = responder
            .prove_packet_with_local_signer(&packet_hash)
            .unwrap();
        assert!(mgr.handle_link_packet_proof(&link_id, &proof));
        assert!(matches!(
            mgr.tick().as_slice(),
            [DeliveryResult::Complete { .. }]
        ));
        assert!(mgr.message_timeout_window(first_hash).is_none());
        let next = timing_message("next packet");
        let next_hash = next.hash.unwrap();
        mgr.start_delivery(next, dest, 1).unwrap();
        mgr.tick();
        let next_window = mgr.message_timeout_window(next_hash).unwrap();
        result_tx.send(LinkEndpointSendResult::Sent).unwrap();
        mgr.poll_endpoint_control();
        assert_eq!(mgr.message_timeout_window(next_hash), Some(next_window));
        assert!(mgr.cancel_delivery_by_message_hash(next_hash));
        assert!(mgr.message_timeout_window(next_hash).is_none());
        let TransportMessage::SendLinkEndpoint { result_tx, .. } = rx.try_recv().unwrap() else {
            panic!()
        };
        result_tx.send(LinkEndpointSendResult::Sent).unwrap();
        mgr.poll_endpoint_control();
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn release_regression_prior_authenticated_packet_proof_cannot_settle_following_message() {
        for cancel_first in [false, true] {
            let (tx, mut rx) = mpsc::channel(128);
            let mut mgr = LinkDeliveryManager::new(tx, None, None);
            let peer_key = Ed25519PrivateKey::generate();
            let dest = [0x25; 16];
            let first = timing_message("old packet proof owner");
            let first_hash = first.hash.unwrap();
            let (link_id, peer) =
                establish_active_delivery(&mut mgr, &mut rx, first, &peer_key, dest);
            mgr.pending.get_mut(&link_id).unwrap().link.rtt = Some(Duration::from_secs(1));
            assert!(mgr.tick().is_empty());
            let first_packet = next_outbound(&mut rx);
            let (header, _) = rns_wire::header::PacketHeader::unpack(&first_packet).unwrap();
            let old_proof = peer
                .prove_packet_with_local_signer(&rns_wire::hash::packet_hash(
                    &first_packet,
                    header.flags.header_type,
                ))
                .unwrap();
            let next = timing_message("new packet proof owner");
            let next_hash = next.hash.unwrap();
            let next_packed = next.pack().unwrap();
            assert_eq!(mgr.start_delivery(next, dest, 1).unwrap(), link_id);
            if cancel_first {
                assert!(mgr.cancel_delivery_by_message_hash(first_hash));
            } else {
                assert!(mgr.handle_link_packet_proof(&link_id, &old_proof));
                assert!(matches!(mgr.tick().as_slice(), [DeliveryResult::Complete {
                    msg_hash: Some(hash), ..
                }] if *hash == first_hash));
            }
            assert!(mgr.tick().is_empty());
            let next_packet = next_outbound(&mut rx);
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&next_packet).unwrap();
            assert_eq!(peer.decrypt(&next_packet[offset..]).unwrap(), next_packed);
            mgr.poll_endpoint_control();
            let original_window = mgr.message_timeout_window(next_hash).unwrap();
            for _ in 0..3 {
                assert!(!mgr.handle_link_packet_proof(&link_id, &old_proof));
                assert!(mgr.tick().is_empty());
                assert_eq!(mgr.message_timeout_window(next_hash), Some(original_window));
                assert_eq!(mgr.pending_count(), 1);
            }
            let next_proof = peer
                .prove_packet_with_local_signer(&rns_wire::hash::packet_hash(
                    &next_packet,
                    header.flags.header_type,
                ))
                .unwrap();
            assert!(mgr.handle_link_packet_proof(&link_id, &next_proof));
            assert!(matches!(mgr.tick().as_slice(), [DeliveryResult::Complete {
                msg_hash: Some(hash), ..
            }] if *hash == next_hash));
            assert!(!mgr.handle_link_packet_proof(&link_id, &old_proof));
            assert!(!mgr.handle_link_packet_proof(&link_id, &next_proof));
            assert!(mgr.tick().is_empty());
            assert_eq!(mgr.pending_count(), 0);
            let events = mgr.take_delivery_events();
            let delivered: Vec<_> = events
                .iter()
                .filter(|event| event.kind == LxmfDeliveryEventKind::Delivered)
                .map(|event| event.msg_hash.unwrap())
                .collect();
            assert_eq!(
                delivered,
                if cancel_first {
                    vec![next_hash]
                } else {
                    vec![first_hash, next_hash]
                }
            );
            assert!(
                events
                    .iter()
                    .all(|event| event.kind != LxmfDeliveryEventKind::Failed)
            );
        }
    }

    #[test]
    fn release_regression_cancel_active_resource_preserves_two_queued_payloads() {
        let (tx, mut rx) = mpsc::channel(128);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let peer_key = Ed25519PrivateKey::generate();
        let dest = [0x26; 16];
        let mut resource = timing_message("cancel active Resource");
        resource.content = "resource body".repeat(1_000);
        resource.sign(&Ed25519PrivateKey::generate()).unwrap();
        let cancelled_hash = resource.hash.unwrap();
        let (link_id, peer) =
            establish_active_delivery(&mut mgr, &mut rx, resource, &peer_key, dest);
        mgr.pending.get_mut(&link_id).unwrap().link.rtt = Some(Duration::from_secs(1));
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.pending[&link_id].state, DeliveryState::Transferring);
        assert!(mgr.tick().is_empty());
        let advertisement = next_outbound(&mut rx);
        let (header, _) = rns_wire::header::PacketHeader::unpack(&advertisement).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );
        // Capture the old transfer's valid proof identity. This is a private
        // coordinator seam, not a claim that this receiver has finished it.
        let transfer = mgr.pending[&link_id].transfer.as_ref().unwrap();
        let resource_hash = transfer.resource.resource_hash;
        let old_proof = [
            resource_hash.as_slice(),
            transfer.resource.expected_proof.as_slice(),
        ]
        .concat();
        let mut followers = [
            timing_message("queued after Resource one"),
            timing_message("queued after Resource two"),
        ];
        let hashes = followers.each_ref().map(|message| message.hash.unwrap());
        let packed = followers.each_mut().map(|message| message.pack().unwrap());
        for message in followers {
            assert_eq!(mgr.start_delivery(message, dest, 1).unwrap(), link_id);
        }
        assert_eq!(mgr.pending_count(), 3);
        assert!(mgr.cancel_delivery_by_message_hash(cancelled_hash));
        assert_eq!(mgr.pending_count(), 2);
        assert!(!mgr.cancel_delivery_by_message_hash(cancelled_hash));
        assert!(!mgr.handle_resource_proof(&link_id, &old_proof));
        let cancel_packet = next_outbound(&mut rx);
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&cancel_packet).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceIcl
        );
        assert_eq!(
            peer.decrypt(&cancel_packet[offset..]).unwrap(),
            resource_hash
        );
        for (index, expected) in packed.iter().enumerate() {
            assert!(mgr.tick().is_empty());
            let packet = next_outbound(&mut rx);
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&packet).unwrap();
            assert_eq!(header.context, rns_wire::context::PacketContext::None);
            assert_eq!(&peer.decrypt(&packet[offset..]).unwrap(), expected);
            mgr.poll_endpoint_control();
            let window = mgr.message_timeout_window(hashes[index]).unwrap();
            assert!(!mgr.handle_resource_proof(&link_id, &old_proof));
            assert_eq!(mgr.message_timeout_window(hashes[index]), Some(window));
            let proof = peer
                .prove_packet_with_local_signer(&rns_wire::hash::packet_hash(
                    &packet,
                    header.flags.header_type,
                ))
                .unwrap();
            assert!(mgr.handle_link_packet_proof(&link_id, &proof));
            assert!(matches!(mgr.tick().as_slice(), [DeliveryResult::Complete {
                msg_hash: Some(hash), ..
            }] if *hash == hashes[index]));
        }
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.pending_count(), 0);
        assert!(mgr.delivery_link_available(&dest));
        let events = mgr.take_delivery_events();
        let delivered: Vec<_> = events
            .iter()
            .filter(|event| event.kind == LxmfDeliveryEventKind::Delivered)
            .map(|event| event.msg_hash.unwrap())
            .collect();
        assert_eq!(delivered, hashes);
        assert!(
            events
                .iter()
                .all(|event| event.kind != LxmfDeliveryEventKind::Failed)
        );
    }

    #[test]
    fn release_regression_retired_resource_events_cannot_poison_same_link_successor() {
        for cancel_first in [false, true] {
            let (tx, _rx) = mpsc::channel(16);
            let (commands, mut command_rx) = mpsc::channel(16);
            let mut mgr = LinkDeliveryManager::new(tx, None, None);
            mgr.set_cancellation_aware_backchannel_sender(commands);
            let dest = [0x27; 16];
            let link_id = [0x28; 16];
            let old_resource = [0x29; 32];
            let new_resource = [0x2A; 32];
            mgr.register_backchannel(dest, link_id);
            let first = timing_message("old same-Link Resource");
            let first_hash = first.hash.unwrap();
            mgr.start_backchannel_delivery(first, dest).unwrap();
            command_rx
                .try_recv()
                .unwrap()
                .result_tx
                .send(Ok(BackchannelSendReceipt::Resource {
                    link_id,
                    resource_hash: old_resource,
                }))
                .unwrap();
            assert!(mgr.tick().is_empty());
            if cancel_first {
                assert!(mgr.cancel_delivery_by_message_hash(first_hash));
                let cancels = mgr.take_backchannel_resource_cancellations();
                assert_eq!(cancels.len(), 1);
                assert_eq!(
                    (cancels[0].link_id, cancels[0].resource_hash),
                    (link_id, old_resource)
                );
            } else {
                assert!(
                    matches!(mgr.handle_backchannel_resource_proof(link_id, old_resource),
                    Some(DeliveryResult::Complete { msg_hash: Some(hash), .. }) if hash == first_hash)
                );
            }
            let next = timing_message("new same-Link Resource");
            let next_hash = next.hash.unwrap();
            mgr.start_backchannel_delivery(next, dest).unwrap();
            let next_receipt = command_rx.try_recv().unwrap();
            let command_window = mgr.message_timeout_window(next_hash).unwrap();
            // Receipt publication is still outstanding, so the adapter cannot
            // yet know which Resource ID belongs to this pending command.
            assert!(
                mgr.handle_backchannel_resource_proof(link_id, old_resource)
                    .is_none()
            );
            assert!(
                mgr.handle_backchannel_resource_conclusion(
                    link_id,
                    old_resource,
                    BackchannelResourceConclusion::Rejected,
                    "late old rejection"
                )
                .is_none()
            );
            let _ = mgr.observe_backchannel_resource_wait(
                link_id,
                old_resource,
                Instant::now(),
                Duration::MAX,
            );
            assert_eq!(mgr.message_timeout_window(next_hash), Some(command_window));
            next_receipt
                .result_tx
                .send(Ok(BackchannelSendReceipt::Resource {
                    link_id,
                    resource_hash: new_resource,
                }))
                .unwrap();
            assert!(mgr.tick().is_empty());
            let started = Instant::now();
            assert!(mgr.observe_backchannel_resource_wait(
                link_id,
                new_resource,
                started,
                Duration::from_secs(17)
            ));
            let window = Some((started, Duration::from_secs(197)));
            assert_eq!(mgr.message_timeout_window(next_hash), window);
            for _ in 0..3 {
                assert!(
                    mgr.handle_backchannel_resource_proof(link_id, old_resource)
                        .is_none()
                );
                assert!(
                    mgr.handle_backchannel_resource_conclusion(
                        link_id,
                        old_resource,
                        BackchannelResourceConclusion::Failed,
                        "late old failure"
                    )
                    .is_none()
                );
                assert!(!mgr.observe_backchannel_resource_wait(
                    link_id,
                    old_resource,
                    Instant::now(),
                    Duration::MAX
                ));
                assert_eq!(mgr.message_timeout_window(next_hash), window);
                assert!(mgr.tick().is_empty());
                assert_eq!(mgr.pending_count(), 1);
                assert_eq!(
                    mgr.backchannel_link_snapshot(dest)
                        .unwrap()
                        .in_flight_deliveries,
                    1
                );
            }
            assert!(
                matches!(mgr.handle_backchannel_resource_proof(link_id, new_resource),
                Some(DeliveryResult::Complete { msg_hash: Some(hash), .. }) if hash == next_hash)
            );
            assert!(
                mgr.handle_backchannel_resource_proof(link_id, new_resource)
                    .is_none()
            );
            assert!(mgr.tick().is_empty());
            assert!(mgr.take_backchannel_resource_cancellations().is_empty());
            assert_eq!(mgr.pending_count(), 0);
            assert_eq!(mgr.backchannel_links.get(&dest), Some(&link_id));
            let events = mgr.take_delivery_events();
            let delivered: Vec<_> = events
                .iter()
                .filter(|event| event.kind == LxmfDeliveryEventKind::Delivered)
                .map(|event| event.msg_hash.unwrap())
                .collect();
            assert_eq!(
                delivered,
                if cancel_first {
                    vec![next_hash]
                } else {
                    vec![first_hash, next_hash]
                }
            );
            assert!(events.iter().all(|event| !matches!(
                event.kind,
                LxmfDeliveryEventKind::Failed | LxmfDeliveryEventKind::Rejected
            )));
        }
    }

    #[test]
    fn release_regression_idle_historical_hash_is_not_a_live_cancellation_owner() {
        for cancel_first in [false, true] {
            let (tx, mut rx) = mpsc::channel(128);
            let mut mgr = LinkDeliveryManager::new(tx, None, None);
            let peer_key = Ed25519PrivateKey::generate();
            let dest = [0x2B; 16];
            let first = timing_message("historical idle delivery");
            let historical_hash = first.hash.unwrap();
            let retry_same_hash = first.clone();
            let (link_id, peer) =
                establish_active_delivery(&mut mgr, &mut rx, first, &peer_key, dest);
            mgr.pending.get_mut(&link_id).unwrap().link.rtt = Some(Duration::from_secs(1));
            assert!(mgr.tick().is_empty());
            let first_packet = next_outbound(&mut rx);
            mgr.poll_endpoint_control();
            if cancel_first {
                assert!(mgr.cancel_delivery_by_message_hash(historical_hash));
            } else {
                let (header, _) = rns_wire::header::PacketHeader::unpack(&first_packet).unwrap();
                let proof = peer
                    .prove_packet_with_local_signer(&rns_wire::hash::packet_hash(
                        &first_packet,
                        header.flags.header_type,
                    ))
                    .unwrap();
                assert!(mgr.handle_link_packet_proof(&link_id, &proof));
                assert!(matches!(mgr.tick().as_slice(), [DeliveryResult::Complete {
                    msg_hash: Some(hash), ..
                }] if *hash == historical_hash));
            }
            assert_eq!(mgr.pending[&link_id].state, DeliveryState::Idle);
            assert_eq!(mgr.pending[&link_id].msg_hash, Some(historical_hash));
            assert_eq!(mgr.pending_count(), 0);
            mgr.take_delivery_events();
            for _ in 0..3 {
                assert!(!mgr.cancel_delivery_by_message_hash(historical_hash));
                assert!(mgr.tick().is_empty());
                assert!(mgr.take_delivery_events().is_empty());
                assert!(
                    rx.try_recv().is_err(),
                    "idle cancellation emits no wire control"
                );
            }
            assert!(mgr.delivery_link_available(&dest));

            // The same logical hash is not globally blacklisted: a new queued
            // attempt is a live owner and remains independently cancellable.
            let next = timing_message("future distinct owner");
            let next_hash = next.hash.unwrap();
            let next_packed = next.pack().unwrap();
            assert_eq!(mgr.start_delivery(next, dest, 1).unwrap(), link_id);
            assert_eq!(
                mgr.start_delivery(retry_same_hash, dest, 1).unwrap(),
                link_id
            );
            assert_eq!(mgr.pending_count(), 2);
            let next_window = mgr.message_timeout_window(next_hash).unwrap();
            assert!(mgr.cancel_delivery_by_message_hash(historical_hash));
            assert!(!mgr.cancel_delivery_by_message_hash(historical_hash));
            assert_eq!(mgr.pending_count(), 1);
            assert_eq!(mgr.message_timeout_window(next_hash), Some(next_window));
            assert!(mgr.tick().is_empty());
            let packet = next_outbound(&mut rx);
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&packet).unwrap();
            assert_eq!(peer.decrypt(&packet[offset..]).unwrap(), next_packed);
            let proof = peer
                .prove_packet_with_local_signer(&rns_wire::hash::packet_hash(
                    &packet,
                    header.flags.header_type,
                ))
                .unwrap();
            assert!(mgr.handle_link_packet_proof(&link_id, &proof));
            assert!(matches!(mgr.tick().as_slice(), [DeliveryResult::Complete {
                msg_hash: Some(hash), ..
            }] if *hash == next_hash));
            assert!(!mgr.cancel_delivery_by_message_hash(next_hash));
            assert!(mgr.tick().is_empty());
            assert_eq!(mgr.pending_count(), 0);
            assert!(
                mgr.take_delivery_events()
                    .iter()
                    .all(|event| event.kind != LxmfDeliveryEventKind::Failed)
            );
        }
    }

    #[test]
    fn backchannel_observation_is_exact_bounded_and_not_restarted_by_late_receipt() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);
        let dest = [0x94; 16];
        let link_id = [0x95; 16];
        let resource_hash = [0x96; 32];
        mgr.register_backchannel(dest, link_id);
        let message = timing_message("slow resource");
        let hash = message.hash.unwrap();
        mgr.start_backchannel_delivery(message, dest).unwrap();
        let command = cmd_rx.try_recv().unwrap();
        let original = Instant::now() - Duration::from_secs(400);
        // A healthy slow transfer is older than the legacy 360s cap but has
        // a real finite owner deadline. An unrelated Link cannot claim it.
        assert!(!mgr.observe_backchannel_resource_wait(
            [0x97; 16],
            resource_hash,
            original,
            Duration::from_secs(800)
        ));
        assert!(mgr.observe_backchannel_resource_wait(
            link_id,
            resource_hash,
            original,
            Duration::from_secs(800)
        ));
        command
            .result_tx
            .send(Ok(BackchannelSendReceipt::Resource {
                link_id,
                resource_hash,
            }))
            .unwrap();
        assert!(mgr.tick().is_empty());
        assert_eq!(
            mgr.message_timeout_window(hash),
            Some((original, Duration::from_secs(980)))
        );
        assert!(!mgr.observe_backchannel_resource_wait(
            link_id,
            resource_hash,
            original - Duration::from_secs(1),
            Duration::MAX
        ));
        // A late observation gets only the remainder of the fixed envelope,
        // never another timeout from observation time.
        let expired = Instant::now() - Duration::from_secs(200);
        assert!(mgr.observe_backchannel_resource_wait(
            link_id,
            resource_hash,
            expired,
            Duration::from_secs(10)
        ));
        let result = mgr.tick();
        assert!(
            matches!(result.as_slice(), [DeliveryResult::Failed { reason, .. }] if reason == "backchannel delivery timeout")
        );
        assert_eq!(
            mgr.take_backchannel_resource_cancellations(),
            vec![BackchannelResourceCancelRequest {
                link_id,
                resource_hash
            }]
        );
        assert!(mgr.tick().is_empty());
        assert!(mgr.take_backchannel_resource_cancellations().is_empty());
        assert!(mgr.message_timeout_window(hash).is_none());
        assert!(!mgr.observe_backchannel_resource_wait(
            link_id,
            resource_hash,
            Instant::now(),
            Duration::MAX
        ));
    }

    #[test]
    fn cancellation_aware_sender_policy_is_captured_and_closes_before_receipt() {
        let (tx, _rx) = mpsc::channel(8);
        let (command_tx, mut commands) = mpsc::channel(8);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let dest = [0x49; 16];
        let link_id = [0x4A; 16];
        mgr.register_backchannel(dest, link_id);
        mgr.set_backchannel_sender(command_tx.clone());
        let legacy = timing_message("legacy cancellation policy");
        let legacy_hash = legacy.hash.unwrap();
        mgr.start_backchannel_delivery(legacy, dest).unwrap();
        let legacy_command = commands.try_recv().unwrap();
        mgr.set_cancellation_aware_backchannel_sender(command_tx.clone());
        assert!(mgr.cancel_delivery_by_message_hash(legacy_hash));
        assert!(
            !legacy_command.result_tx.is_closed(),
            "replacement setter must not alter old adapter contract"
        );
        legacy_command
            .result_tx
            .send(Ok(BackchannelSendReceipt::Packet {
                link_id,
                packet_hash: [1; 32],
            }))
            .unwrap();
        assert!(mgr.tick().is_empty());
        let aware = timing_message("cancellation-aware command not yet issued");
        let aware_hash = aware.hash.unwrap();
        mgr.start_backchannel_delivery(aware, dest).unwrap();
        let aware_command = commands.try_recv().unwrap();
        mgr.set_backchannel_sender(command_tx.clone());
        assert!(mgr.cancel_delivery_by_message_hash(aware_hash));
        assert!(
            aware_command.result_tx.is_closed(),
            "canonical bridge must know immediately not to issue this command"
        );
        assert!(mgr.message_delivery_snapshot(aware_hash).is_none());
        let already_published = timing_message("published before cancellation close");
        let published_hash = already_published.hash.unwrap();
        mgr.set_cancellation_aware_backchannel_sender(command_tx);
        mgr.start_backchannel_delivery(already_published, dest)
            .unwrap();
        commands
            .try_recv()
            .unwrap()
            .result_tx
            .send(Ok(BackchannelSendReceipt::Packet {
                link_id,
                packet_hash: [2; 32],
            }))
            .unwrap();
        assert!(mgr.cancel_delivery_by_message_hash(published_hash));
        assert!(
            mgr.cancelled_backchannel_packets
                .contains_key(&BackchannelProofKey::Packet(link_id, [2; 32]))
        );
        assert!(
            mgr.pending_backchannel_starts
                .iter()
                .all(|start| start.message.hash != Some(published_hash))
        );
        assert!(mgr.tick().is_empty());
    }

    #[test]
    fn cancelled_bridge_reservations_are_small_bounded_idempotent_and_generation_scoped() {
        let (tx, _rx) = mpsc::channel(16);
        let (command_tx, _command_rx) = mpsc::channel(256);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(command_tx);
        let dest = [0x53; 16];
        let old_link = [0x54; 16];
        mgr.register_backchannel(dest, old_link);
        for _ in 0..256 {
            mgr.start_backchannel_delivery(timing_message("bounded receipt reservation"), dest)
                .unwrap();
        }
        let cancelled_hash = mgr.pending_backchannel_starts[0].message.hash.unwrap();
        mgr.pending_backchannel_starts[0].message.content =
            "large cancelled payload".repeat(100_000);
        assert!(mgr.cancel_delivery_by_message_hash(cancelled_hash));
        assert!(mgr.pending_backchannel_starts[0].message.content.is_empty());
        for start in &mut mgr.pending_backchannel_starts {
            start.requested_at = Instant::now() - Duration::from_secs(11);
        }
        assert_eq!(mgr.tick().len(), 255);
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.pending_backchannel_starts.len(), 256);
        assert!(
            mgr.pending_backchannel_starts
                .iter()
                .all(|start| start.message.content.is_empty())
        );
        let new_link = [0x55; 16];
        mgr.register_backchannel(dest, new_link);
        assert!(mgr.tick().is_empty());
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.backchannel_links.get(&dest), Some(&new_link));
        let snapshot = mgr.backchannel_link_snapshot(dest).unwrap();
        assert_eq!(
            (snapshot.queued_deliveries, snapshot.in_flight_deliveries),
            (0, 0)
        );
        assert!(mgr.message_delivery_snapshot(cancelled_hash).is_none());
        let stats = mgr.stats();
        assert_eq!(
            (
                stats.pending_backchannel_starts,
                stats.pending_backchannel_deliveries,
                stats.queued_deliveries,
                stats.in_flight_deliveries
            ),
            (0, 0, 0, 0)
        );
        let refused = mgr
            .start_backchannel_delivery(timing_message("full reservation owner"), dest)
            .unwrap_err();
        assert_eq!(refused.error, BackchannelStartError::CommandFull);
        for n in 0..256u16 {
            let mut packet_hash = [0; 32];
            packet_hash[..2].copy_from_slice(&n.to_be_bytes());
            assert!(mgr.abandon_backchannel_packet(old_link, packet_hash));
            let remaining = mgr.pending_backchannel_starts.len();
            let original = mgr.cancelled_backchannel_packets
                [&BackchannelProofKey::Packet(old_link, packet_hash)];
            assert!(mgr.abandon_backchannel_packet(old_link, packet_hash));
            assert_eq!(
                mgr.pending_backchannel_starts.len(),
                remaining,
                "duplicate cannot consume another reservation"
            );
            assert_eq!(
                mgr.cancelled_backchannel_packets
                    [&BackchannelProofKey::Packet(old_link, packet_hash)],
                original
            );
            assert_eq!(
                mgr.pending_backchannel_starts.len() + mgr.cancelled_backchannel_packets.len(),
                256
            );
        }
        assert!(!mgr.abandon_backchannel_packet(old_link, [0xFF; 32]));
        assert_eq!(mgr.cancelled_backchannel_packets.len(), 256);
        for instant in mgr.cancelled_backchannel_packets.values_mut() {
            *instant = Instant::now() - Duration::from_secs(121);
        }
        mgr.prune_early_backchannel_settlement();
        assert!(mgr.cancelled_backchannel_packets.is_empty());
        assert_eq!(mgr.backchannel_links.get(&dest), Some(&new_link));
    }

    #[test]
    fn retired_backchannel_owners_never_evict_replacement_or_remain_visible() {
        // Pending command, installed Packet, installed Resource; timeout,
        // targeted failure, user cancel, or old-Link failure for each owner.
        for representation in 0..3 {
            for retirement in 0..4 {
                let (tx, _rx) = mpsc::channel(16);
                let (command_tx, mut commands) = mpsc::channel(16);
                let mut mgr = LinkDeliveryManager::new(tx, None, None);
                mgr.set_cancellation_aware_backchannel_sender(command_tx);
                let dest = [0x31; 16];
                let old_link = [0x32; 16];
                let replacement = [0x33; 16];
                let message = timing_message("old owner must not evict replacement");
                let hash = message.hash.unwrap();
                mgr.register_backchannel(dest, old_link);
                mgr.start_backchannel_delivery(message, dest).unwrap();
                let command = commands.try_recv().unwrap();
                if representation != 0 {
                    let receipt = if representation == 1 {
                        BackchannelSendReceipt::Packet {
                            link_id: old_link,
                            packet_hash: [1; 32],
                        }
                    } else {
                        BackchannelSendReceipt::Resource {
                            link_id: old_link,
                            resource_hash: [2; 32],
                        }
                    };
                    command.result_tx.send(Ok(receipt)).unwrap();
                    assert!(mgr.tick().is_empty());
                }
                mgr.register_backchannel(dest, replacement);
                let snapshot = mgr.backchannel_link_snapshot(dest).unwrap();
                assert_eq!(
                    (snapshot.queued_deliveries, snapshot.in_flight_deliveries),
                    (0, 0)
                );
                match retirement {
                    0 => {
                        for start in &mut mgr.pending_backchannel_starts {
                            start.requested_at = Instant::now() - Duration::from_secs(11);
                        }
                        for delivery in mgr.pending_backchannel_deliveries.values_mut() {
                            delivery.started_at = Instant::now() - Duration::from_secs(400);
                        }
                        assert_eq!(mgr.tick().len(), 1);
                    }
                    1 => assert_eq!(
                        mgr.fail_delivery_by_message_hash(hash, "delivery timeout")
                            .len(),
                        1
                    ),
                    2 => assert!(mgr.cancel_delivery_by_message_hash(hash)),
                    _ => assert_eq!(mgr.fail_backchannel_link(old_link, "link closed").len(), 1),
                }
                assert!(mgr.tick().is_empty());
                assert!(mgr.tick().is_empty());
                assert!(
                    mgr.fail_delivery_by_message_hash(hash, "duplicate failure")
                        .is_empty()
                );
                assert!(mgr.message_delivery_snapshot(hash).is_none());
                assert_eq!(mgr.pending_count(), 0);
                assert_eq!(mgr.backchannel_links.get(&dest), Some(&replacement));
                let snapshot = mgr.backchannel_link_snapshot(dest).unwrap();
                assert_eq!(
                    (snapshot.queued_deliveries, snapshot.in_flight_deliveries),
                    (0, 0)
                );
                // A new event/report must not count hidden cleanup owners.
                let report = mgr
                    .start_backchannel_delivery(timing_message("replacement work"), dest)
                    .unwrap();
                assert_eq!(
                    (report.queued_deliveries, report.in_flight_deliveries),
                    (1, 1)
                );
                let event = mgr.take_delivery_events().pop().unwrap();
                assert_eq!(
                    (event.queued_deliveries, event.in_flight_deliveries),
                    (0, 1)
                );
            }
        }
    }

    #[tokio::test]
    async fn backchannel_packet_cancel_reconciles_before_receipt_and_after_late_observation() {
        use rns_transport::actor::TransportActor;
        use rns_transport::constants::{InterfaceDirection, InterfaceMode};
        use rns_transport::messages::{InterfaceEntry, TimerTick};
        for mode in 0..4 {
            let (mut actor, tx) = TransportActor::new();
            let (driver_tx, mut driver_rx) = mpsc::channel(1);
            driver_tx.try_send(Bytes::from_static(b"occupied")).unwrap();
            actor.interfaces.insert(
                7,
                InterfaceEntry::new(
                    "cancelled backchannel driver".to_string(),
                    InterfaceMode::Full,
                    InterfaceDirection::bidirectional(),
                    3_515,
                    500,
                    driver_tx,
                ),
            );
            let dispatch = actor.link_endpoint_dispatch_handle();
            let actor_task = tokio::spawn(actor.run());
            let link_id = [0x59; 16];
            let dest = [0x5A; 16];
            let (lifecycle_tx, _lifecycle_rx) = mpsc::unbounded_channel();
            let token = dispatch
                .try_bind(
                    LinkEndpointBinding {
                        link_id,
                        interface_id: 7,
                        role: LinkEndpointRole::Responder,
                    },
                    lifecycle_tx,
                )
                .unwrap()
                .await
                .unwrap()
                .unwrap();
            let mut mgr = LinkDeliveryManager::new(tx.clone(), None, None);
            let (command_tx, mut command_rx) = mpsc::channel(8);
            if mode == 3 {
                mgr.set_cancellation_aware_backchannel_sender(command_tx);
            } else {
                mgr.set_backchannel_sender(command_tx);
            }
            mgr.register_backchannel(dest, link_id);
            let message = timing_message("cancel exact actor packet");
            let hash = message.hash.unwrap();
            mgr.start_backchannel_delivery(message, dest).unwrap();
            let command = command_rx.try_recv().unwrap();
            let raw = link_data_packet(
                link_id,
                rns_wire::context::PacketContext::None,
                &command.payload,
            );
            let packet_hash =
                rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
            let started = Instant::now();
            let (outcome, cancellation) = token
                .try_send_cancellable(
                    OutboundRequest {
                        raw,
                        destination_hash: link_id,
                    },
                    started + Duration::from_secs(120),
                )
                .unwrap();
            if mode != 0 {
                assert!(mgr.cancel_delivery_by_message_hash(hash));
            }
            if mode != 2 {
                mgr.observe_backchannel_packet_wait(
                    link_id,
                    packet_hash,
                    started,
                    Duration::from_secs(120),
                    true,
                    Some(cancellation.clone()),
                );
            }
            let published = command.result_tx.send(Ok(BackchannelSendReceipt::Packet {
                link_id,
                packet_hash,
            }));
            if mode == 3 {
                assert!(published.is_err());
                assert!(mgr.abandon_backchannel_packet(link_id, packet_hash));
            } else {
                published.unwrap();
            }
            assert!(mgr.tick().is_empty());
            if mode == 0 {
                assert!(mgr.cancel_delivery_by_message_hash(hash));
            }
            if mode == 2 {
                assert!(!mgr.observe_backchannel_packet_wait(
                    link_id,
                    packet_hash,
                    started,
                    Duration::from_secs(120),
                    true,
                    Some(cancellation)
                ));
            }
            let other_raw = link_data_packet(
                link_id,
                rns_wire::context::PacketContext::None,
                b"unrelated packet survives",
            );
            let other = token
                .try_send(
                    OutboundRequest {
                        raw: other_raw.clone(),
                        destination_hash: link_id,
                    },
                    Instant::now() + Duration::from_secs(120),
                )
                .unwrap();
            assert_eq!(driver_rx.recv().await.unwrap(), b"occupied"[..]);
            tx.send(TransportMessage::Tick(TimerTick {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64(),
            }))
            .await
            .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), driver_rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                other_raw
            );
            assert_eq!(
                outcome.await.unwrap(),
                LinkEndpointDispatchOutcome::Cancelled
            );
            assert!(matches!(
                other.await.unwrap(),
                LinkEndpointDispatchOutcome::Sent { .. }
            ));
            assert!(mgr.tick().is_empty());
            assert_eq!(mgr.backchannel_links.get(&dest), Some(&link_id));
            assert!(mgr.message_timeout_window(hash).is_none());
            tx.send(TransportMessage::Shutdown).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), actor_task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn legacy_queued_packet_stays_finite_local_uncertainty_not_network_proof() {
        let (tx, mut rx) = mpsc::channel(128);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let key = Ed25519PrivateKey::generate();
        let message = timing_message("legacy queued packet");
        let hash = message.hash.unwrap();
        let (link_id, _) = establish_active_delivery(&mut mgr, &mut rx, message, &key, [0x63; 16]);
        mgr.pending.get_mut(&link_id).unwrap().link.rtt = Some(Duration::from_millis(1));
        assert!(mgr.tick().is_empty());
        let TransportMessage::SendLinkEndpoint { result_tx, .. } = rx.try_recv().unwrap() else {
            panic!()
        };
        result_tx
            .send(LinkEndpointSendResult::Queued { depth: 1 })
            .unwrap();
        mgr.poll_endpoint_control();
        let window = mgr.message_timeout_window(hash).unwrap();
        assert_eq!(window.1, Duration::from_secs(10) + Duration::from_millis(6));
        assert!(mgr.pending[&link_id].packet_awaiting_dispatch);
        mgr.pending.get_mut(&link_id).unwrap().started_at =
            Instant::now() - window.1 - Duration::from_secs(1);
        assert!(
            matches!(mgr.tick().as_slice(), [DeliveryResult::Failed { reason, .. }]
            if reason == "Link endpoint admission timeout" && is_retryable_link_delivery_failure(reason))
        );
        assert!(mgr.tick().is_empty());
    }

    #[test]
    fn external_resource_observation_grace_handles_queued_renewal_without_resetting_deadline() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);
        let dest = [0x64; 16];
        let link_id = [0x65; 16];
        let resource_hash = [0x66; 32];
        mgr.register_backchannel(dest, link_id);
        let message = timing_message("queued resource phase renewal");
        let hash = message.hash.unwrap();
        mgr.start_backchannel_delivery(message, dest).unwrap();
        cmd_rx
            .try_recv()
            .unwrap()
            .result_tx
            .send(Ok(BackchannelSendReceipt::Resource {
                link_id,
                resource_hash,
            }))
            .unwrap();
        assert!(mgr.tick().is_empty());
        let old = Instant::now() - Duration::from_secs(20);
        assert!(mgr.observe_backchannel_resource_wait(
            link_id,
            resource_hash,
            old,
            Duration::from_secs(10)
        ));
        let old_window = Some((old, Duration::from_secs(190)));
        // A real renewal is still upstream in the accounting adapter. Crossing
        // its previous protocol deadline must not orphan an active Resource.
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.message_timeout_window(hash), old_window);
        assert!(mgr.observe_backchannel_resource_wait(
            link_id,
            resource_hash,
            old,
            Duration::from_secs(10)
        ));
        mgr.register_backchannel(dest, link_id); // Generic Link activity is not progress.
        assert_eq!(mgr.message_timeout_window(hash), old_window);
        let renewed = Instant::now() - Duration::from_secs(5);
        assert!(mgr.observe_backchannel_resource_wait(
            link_id,
            resource_hash,
            renewed,
            Duration::from_secs(10)
        ));
        assert_eq!(
            mgr.message_timeout_window(hash),
            Some((renewed, Duration::from_secs(190)))
        );
        assert!(mgr.tick().is_empty());
        assert!(matches!(
            mgr.handle_backchannel_resource_proof(link_id, resource_hash),
            Some(DeliveryResult::Complete { .. })
        ));
        assert!(mgr.message_timeout_window(hash).is_none());
        assert!(
            mgr.handle_backchannel_resource_proof(link_id, resource_hash)
                .is_none()
        );
        assert!(!mgr.observe_backchannel_resource_wait(
            link_id,
            resource_hash,
            Instant::now(),
            Duration::MAX
        ));
        assert!(mgr.take_backchannel_resource_cancellations().is_empty());
    }

    #[test]
    fn backchannel_packet_admission_expiry_is_not_network_proof_expiry() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);
        let dest = [0x98; 16];
        let link_id = [0x99; 16];
        let packet_hash = [0x9A; 32];
        mgr.register_backchannel(dest, link_id);
        mgr.start_backchannel_delivery(timing_message("admission expires"), dest)
            .unwrap();
        assert!(mgr.observe_backchannel_packet_wait(
            link_id,
            packet_hash,
            Instant::now() - Duration::from_secs(11),
            Duration::from_secs(10),
            true,
            None
        ));
        cmd_rx
            .try_recv()
            .unwrap()
            .result_tx
            .send(Ok(BackchannelSendReceipt::Packet {
                link_id,
                packet_hash,
            }))
            .unwrap();
        assert!(
            matches!(mgr.tick().as_slice(), [DeliveryResult::Failed { reason, .. }] if reason == "Link endpoint admission timeout")
        );
        assert!(mgr.take_backchannel_resource_cancellations().is_empty());
    }

    #[test]
    fn test_backchannel_delivery_uses_registered_link_and_packet_proof() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD1; 16];
        let link_id = [0xE1; 16];
        let packet_hash = [0xF1; 32];
        mgr.register_backchannel(dest_hash, link_id);
        assert!(mgr.delivery_link_available(&dest_hash));
        assert_eq!(
            mgr.backchannel_link_snapshot(dest_hash).unwrap().link_id,
            link_id
        );

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "packet proof",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        let report = mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        assert_eq!(report.link_id, link_id);
        assert_eq!(mgr.pending_count(), 1);
        let events = mgr.take_delivery_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, LxmfDeliveryEventKind::BackchannelLinkReused);
        assert_eq!(events[0].progress, Some(0.05));

        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert_eq!(command.link_id, link_id);
        assert!(!command.payload.is_empty());
        assert!(
            command
                .result_tx
                .send(Ok(BackchannelSendReceipt::Packet {
                    link_id,
                    packet_hash,
                }))
                .is_ok()
        );

        assert!(mgr.tick().is_empty());
        let events = mgr.take_delivery_events();
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::AwaitingProof
                && event.progress == Some(0.50)
                && event.representation == DeliveryRepresentation::Packet
        }));
        assert_eq!(mgr.pending_count(), 1);
        assert_eq!(mgr.stats().pending_backchannel_deliveries, 1);

        let result = mgr
            .handle_backchannel_packet_proof(link_id, packet_hash)
            .expect("packet proof completes backchannel delivery");
        assert!(matches!(
            result,
            DeliveryResult::Complete {
                link_id: id,
                msg_hash: hash,
            } if id == link_id && hash == msg_hash
        ));
        let events = mgr.take_delivery_events();
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::Delivered && event.progress == Some(1.0)
        }));
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.stats().backchannel_sessions, 1);
    }

    #[test]
    fn backchannel_packet_proof_before_send_receipt_completes_and_releases_link() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD8; 16];
        let link_id = [0xE8; 16];
        let packet_hash = [0xF8; 32];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "proof raced receipt",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");

        assert!(
            mgr.handle_backchannel_packet_proof(link_id, packet_hash)
                .is_none(),
            "the receipt still owns the message until its exact proof key is known"
        );
        assert_eq!(mgr.early_backchannel_proofs.len(), 1);
        assert!(
            command
                .result_tx
                .send(Ok(BackchannelSendReceipt::Packet {
                    link_id,
                    packet_hash,
                }))
                .is_ok()
        );

        let results = mgr.tick();
        assert!(matches!(
            results.as_slice(),
            [DeliveryResult::Complete {
                link_id: id,
                msg_hash: hash,
            }] if *id == link_id && *hash == msg_hash
        ));
        let events = mgr.take_delivery_events();
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::AwaitingProof
                && event.representation == DeliveryRepresentation::Packet
        }));
        assert!(
            events
                .iter()
                .any(|event| event.kind == LxmfDeliveryEventKind::Delivered)
        );
        assert!(mgr.early_backchannel_proofs.is_empty());
        assert_eq!(mgr.pending_count(), 0);

        let mut next = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "next delivery is not blocked",
            crate::constants::DeliveryMethod::Direct,
        );
        next.sign(&sign_key).unwrap();
        mgr.start_backchannel_delivery(next, dest_hash).unwrap();
        assert!(cmd_rx.try_recv().is_ok());
    }

    #[test]
    fn backchannel_proof_before_close_and_receipt_completes_without_reusing_closed_link() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD9; 16];
        let link_id = [0xE9; 16];
        let packet_hash = [0xF9; 32];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "proof then close then receipt",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert!(
            mgr.handle_backchannel_packet_proof(link_id, packet_hash)
                .is_none()
        );
        assert!(mgr.fail_backchannel_link(link_id, "link closed").is_empty());
        assert!(!mgr.delivery_link_available(&dest_hash));
        assert_eq!(mgr.pending_count(), 1);
        assert_eq!(mgr.early_backchannel_proofs.len(), 1);
        let settling = mgr.message_delivery_snapshot(msg_hash.unwrap()).unwrap();
        assert_eq!(settling.link_state, LinkState::Closed);
        assert_eq!(mgr.stats().pending_backchannel_starts, 1);

        command
            .result_tx
            .send(Ok(BackchannelSendReceipt::Packet {
                link_id,
                packet_hash,
            }))
            .unwrap();
        let results = mgr.tick();
        assert!(matches!(
            results.as_slice(),
            [DeliveryResult::Complete {
                link_id: id,
                msg_hash: hash,
            }] if *id == link_id && *hash == msg_hash
        ));
        assert_eq!(
            mgr.take_delivery_events()
                .iter()
                .filter(|event| event.kind == LxmfDeliveryEventKind::Delivered)
                .count(),
            1
        );
        assert!(
            mgr.handle_backchannel_packet_proof(link_id, packet_hash)
                .is_none()
        );
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.pending_count(), 0);
        assert!(!mgr.delivery_link_available(&dest_hash));
        assert!(mgr.early_backchannel_proofs.is_empty());
    }

    #[test]
    fn cancel_backchannel_before_resource_receipt_queues_exact_external_cancel_once() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xDA; 16];
        let link_id = [0xEA; 16];
        let resource_hash = [0xFA; 32];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "cancel before resource receipt",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash.unwrap();

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert!(mgr.cancel_delivery_by_message_hash(msg_hash));
        assert!(!mgr.cancel_delivery_by_message_hash(msg_hash));
        assert!(mgr.take_backchannel_resource_cancellations().is_empty());

        command
            .result_tx
            .send(Ok(BackchannelSendReceipt::Resource {
                link_id,
                resource_hash,
            }))
            .unwrap();
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(
            mgr.take_backchannel_resource_cancellations(),
            vec![BackchannelResourceCancelRequest {
                link_id,
                resource_hash,
            }]
        );
        assert!(mgr.take_backchannel_resource_cancellations().is_empty());
        assert!(mgr.delivery_link_available(&dest_hash));
    }

    #[test]
    fn cancel_backchannel_before_packet_receipt_discards_non_recallable_send() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xDD; 16];
        let link_id = [0xED; 16];
        let packet_hash = [0xFD; 32];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "cancel before packet receipt",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash.unwrap();

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert!(mgr.cancel_delivery_by_message_hash(msg_hash));
        command
            .result_tx
            .send(Ok(BackchannelSendReceipt::Packet {
                link_id,
                packet_hash,
            }))
            .unwrap();

        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.pending_count(), 0);
        assert!(mgr.take_backchannel_resource_cancellations().is_empty());
        assert!(
            mgr.handle_backchannel_packet_proof(link_id, packet_hash)
                .is_none()
        );
        assert!(mgr.delivery_link_available(&dest_hash));
    }

    #[test]
    fn cancel_installed_backchannel_resource_queues_exact_external_cancel_once() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xDB; 16];
        let link_id = [0xEB; 16];
        let resource_hash = [0xFB; 32];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "cancel installed resource",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash.unwrap();

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        cmd_rx
            .try_recv()
            .expect("backchannel send command")
            .result_tx
            .send(Ok(BackchannelSendReceipt::Resource {
                link_id,
                resource_hash,
            }))
            .unwrap();
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.stats().pending_backchannel_deliveries, 1);

        assert!(mgr.cancel_delivery_by_message_hash(msg_hash));
        assert!(!mgr.cancel_delivery_by_message_hash(msg_hash));
        assert_eq!(
            mgr.take_backchannel_resource_cancellations(),
            vec![BackchannelResourceCancelRequest {
                link_id,
                resource_hash,
            }]
        );
        assert!(mgr.take_backchannel_resource_cancellations().is_empty());
        assert_eq!(mgr.pending_count(), 0);
        assert!(mgr.delivery_link_available(&dest_hash));
    }

    #[test]
    fn rejected_backchannel_resource_returns_rejected_and_preserves_link() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xDC; 16];
        let link_id = [0xEC; 16];
        let resource_hash = [0xFC; 32];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "resource rejected",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        cmd_rx
            .try_recv()
            .expect("backchannel send command")
            .result_tx
            .send(Ok(BackchannelSendReceipt::Resource {
                link_id,
                resource_hash,
            }))
            .unwrap();
        assert!(mgr.tick().is_empty());

        let result = mgr
            .handle_backchannel_resource_conclusion(
                link_id,
                resource_hash,
                BackchannelResourceConclusion::Rejected,
                "resource rejected",
            )
            .expect("exact Resource conclusion");
        assert!(matches!(
            result,
            DeliveryResult::Rejected {
                link_id: id,
                msg_hash: hash,
                dest_hash: dest,
                reason,
                ..
            } if id == link_id
                && hash == msg_hash
                && dest == dest_hash
                && reason == "resource rejected"
        ));
        assert!(
            mgr.handle_backchannel_resource_conclusion(
                link_id,
                resource_hash,
                BackchannelResourceConclusion::Rejected,
                "duplicate",
            )
            .is_none()
        );
        assert_eq!(mgr.pending_count(), 0);
        assert!(mgr.delivery_link_available(&dest_hash));
        assert!(mgr.take_delivery_events().iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::Rejected
                && event.reason.as_deref() == Some("resource rejected")
        }));
    }

    #[test]
    fn backchannel_resource_rejection_before_receipt_reconciles_exactly_once() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xC1; 16];
        let link_id = [0xD1; 16];
        let resource_hash = [0xE1; 32];
        let key = BackchannelProofKey::Resource(link_id, resource_hash);
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "rejection before resource receipt",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert!(
            mgr.handle_backchannel_resource_conclusion(
                link_id,
                resource_hash,
                BackchannelResourceConclusion::Rejected,
                "early rejection",
            )
            .is_none()
        );
        let first_observed_at = mgr
            .early_backchannel_resource_conclusions
            .get(&key)
            .expect("staged early conclusion")
            .observed_at;

        assert!(
            mgr.handle_backchannel_resource_conclusion(
                link_id,
                resource_hash,
                BackchannelResourceConclusion::Failed,
                "duplicate must not replace first conclusion",
            )
            .is_none()
        );
        let staged = mgr
            .early_backchannel_resource_conclusions
            .get(&key)
            .expect("first conclusion remains staged");
        assert_eq!(staged.observed_at, first_observed_at);
        assert_eq!(staged.conclusion, BackchannelResourceConclusion::Rejected);
        assert_eq!(staged.reason, "early rejection");

        command
            .result_tx
            .send(Ok(BackchannelSendReceipt::Resource {
                link_id,
                resource_hash,
            }))
            .unwrap();
        let results = mgr.tick();
        assert!(matches!(
            results.as_slice(),
            [DeliveryResult::Rejected {
                link_id: id,
                msg_hash: hash,
                dest_hash: dest,
                reason,
                ..
            }] if *id == link_id
                && *hash == msg_hash
                && *dest == dest_hash
                && reason == "early rejection"
        ));
        assert_eq!(mgr.pending_count(), 0);
        assert!(mgr.early_backchannel_resource_conclusions.is_empty());
        assert!(mgr.delivery_link_available(&dest_hash));

        assert!(
            mgr.handle_backchannel_resource_conclusion(
                link_id,
                resource_hash,
                BackchannelResourceConclusion::Rejected,
                "late duplicate",
            )
            .is_none()
        );
        assert!(mgr.early_backchannel_resource_conclusions.is_empty());
        assert!(mgr.tick().is_empty());
    }

    #[test]
    fn backchannel_resource_rejection_before_close_and_receipt_wins_exactly() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xC2; 16];
        let link_id = [0xD2; 16];
        let resource_hash = [0xE2; 32];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "rejection then close then receipt",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert!(
            mgr.handle_backchannel_resource_conclusion(
                link_id,
                resource_hash,
                BackchannelResourceConclusion::Rejected,
                "receiver rejected resource",
            )
            .is_none()
        );
        assert!(mgr.fail_backchannel_link(link_id, "link closed").is_empty());
        assert_eq!(mgr.pending_count(), 1);
        assert!(!mgr.delivery_link_available(&dest_hash));
        let settling = mgr.message_delivery_snapshot(msg_hash.unwrap()).unwrap();
        assert_eq!(settling.link_state, LinkState::Closed);
        assert_eq!(mgr.stats().pending_backchannel_starts, 1);

        command
            .result_tx
            .send(Ok(BackchannelSendReceipt::Resource {
                link_id,
                resource_hash,
            }))
            .unwrap();
        let results = mgr.tick();
        assert!(matches!(
            results.as_slice(),
            [DeliveryResult::Rejected {
                link_id: id,
                msg_hash: hash,
                dest_hash: dest,
                reason,
                ..
            }] if *id == link_id
                && *hash == msg_hash
                && *dest == dest_hash
                && reason == "receiver rejected resource"
        ));
        assert_eq!(mgr.pending_count(), 0);
        assert!(mgr.early_backchannel_resource_conclusions.is_empty());
        assert!(!mgr.delivery_link_available(&dest_hash));
        assert!(mgr.take_delivery_events().iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::Rejected
                && event.link_state == LinkState::Closed
                && event.reason.as_deref() == Some("receiver rejected resource")
        }));
    }

    #[test]
    fn test_backchannel_send_error_removes_link_and_fails_message() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD2; 16];
        let link_id = [0xE2; 16];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "send failure",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert!(
            command
                .result_tx
                .send(Err(BackchannelSendError::LinkNotActive))
                .is_ok()
        );

        let results = mgr.tick();
        assert!(results.iter().any(|result| matches!(
            result,
            DeliveryResult::Failed {
                link_id: id,
                msg_hash: hash,
                dest_hash: dest,
                reason,
                ..
            } if *id == link_id
                && *hash == msg_hash
                && *dest == dest_hash
                && reason == "link is not active"
                && is_retryable_link_delivery_failure(reason)
        )));
        assert!(!mgr.delivery_link_available(&dest_hash));
        let events = mgr.take_delivery_events();
        assert!(
            events
                .iter()
                .any(|event| event.kind == LxmfDeliveryEventKind::Failed)
        );
    }

    #[test]
    fn test_fail_backchannel_link_removes_cached_link() {
        let (tx, _rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let link_id = [0xEA; 16];
        let first_dest = [0xD4; 16];
        let second_dest = [0xD5; 16];
        let other_dest = [0xD6; 16];
        mgr.register_backchannel(first_dest, link_id);
        mgr.register_backchannel(second_dest, link_id);
        mgr.register_backchannel(other_dest, [0xEB; 16]);

        let results = mgr.fail_backchannel_link(link_id, "link closed");

        assert!(results.is_empty());
        assert!(!mgr.delivery_link_available(&first_dest));
        assert!(!mgr.delivery_link_available(&second_dest));
        assert!(mgr.delivery_link_available(&other_dest));
    }

    #[test]
    fn test_fail_backchannel_link_fails_pending_delivery() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD7; 16];
        let link_id = [0xE7; 16];
        let packet_hash = [0xF7; 32];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "closed while awaiting proof",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert!(
            command
                .result_tx
                .send(Ok(BackchannelSendReceipt::Packet {
                    link_id,
                    packet_hash,
                }))
                .is_ok()
        );
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.stats().pending_backchannel_deliveries, 1);

        let results = mgr.fail_backchannel_link(link_id, "link closed");

        assert!(matches!(
            results.as_slice(),
            [DeliveryResult::Failed {
                link_id: id,
                msg_hash: hash,
                dest_hash: dest,
                reason,
                ..
            }] if *id == link_id
                && *hash == msg_hash
                && *dest == dest_hash
                && reason == "link closed"
        ));
        assert!(!mgr.delivery_link_available(&dest_hash));
        assert_eq!(mgr.stats().pending_backchannel_deliveries, 0);
    }

    #[test]
    fn test_retryable_link_delivery_failure_includes_stale_backchannels() {
        for reason in [
            "delivery timeout",
            "backchannel delivery timeout",
            "resource proof timed out",
            "resource part requests timed out",
            "resource advertisement timed out",
            "resource cancelled",
            "Link endpoint admission timeout",
            "Link endpoint terminated: InterfaceOffline",
            "Link endpoint send rejected: Terminated(EgressQueueExhausted)",
            "transport channel closed",
            "transport staging queue full",
        ] {
            assert!(is_retryable_link_delivery_failure(reason), "{reason}");
        }
        for reason in [
            "resource rejected",
            "cancelled by user",
            "resource transfer cancelled",
            "Link endpoint send rejected: InvalidPacket",
            "Link endpoint send rejected: RoleMismatch",
            "Link endpoint terminated: untrusted invented reason",
        ] {
            assert!(!is_retryable_link_delivery_failure(reason), "{reason}");
        }
        let (mut link, _) = Link::new_initiator([0x33; 16], 1);
        link.rtt = Some(Duration::MAX);
        assert_eq!(inbound_split_wait_timeout(&link), Duration::MAX);
        assert!(is_retryable_link_delivery_failure(
            "link establishment timeout"
        ));
        assert!(is_retryable_link_delivery_failure("link closed"));
        assert!(is_retryable_link_delivery_failure("link not found"));
        assert!(is_retryable_link_delivery_failure("link is not active"));
        assert!(is_retryable_link_delivery_failure(
            "link session keys are unavailable"
        ));
        assert!(is_retryable_link_delivery_failure(
            "transport channel is full or closed"
        ));
        assert!(is_retryable_link_delivery_failure(
            "backchannel send command timeout"
        ));
        assert!(!is_retryable_link_delivery_failure(
            "resource transfer could not be started"
        ));
    }

    #[test]
    fn test_fail_delivery_by_message_hash_aborts_direct_session() {
        let (tx, _rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let dest_hash = [0xD3; 16];
        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Direct",
            "stale reusable delivery",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash.unwrap();

        let link_id = mgr.start_delivery(msg, dest_hash, 1).unwrap();
        if let Some(delivery) = mgr.pending.get_mut(&link_id) {
            delivery.state = DeliveryState::AwaitingProof;
        }

        let results = mgr.fail_delivery_by_message_hash(msg_hash, "direct fallback timeout");
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            DeliveryResult::Failed {
                link_id: id,
                msg_hash: Some(hash),
                dest_hash: dest,
                reason,
                ..
            } if *id == link_id
                && *hash == msg_hash
                && *dest == dest_hash
                && reason == "direct fallback timeout"
        ));
        assert_eq!(mgr.pending_count(), 0);
        assert!(!mgr.delivery_link_available(&dest_hash));
        let events = mgr.take_delivery_events();
        assert!(
            events
                .iter()
                .any(|event| event.kind == LxmfDeliveryEventKind::Failed)
        );
    }

    #[test]
    fn test_fail_delivery_by_message_hash_aborts_backchannel_start() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, _cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD4; 16];
        let link_id = [0xE4; 16];
        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "stale backchannel delivery",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash.unwrap();

        mgr.register_backchannel(dest_hash, link_id);
        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();

        let results = mgr.fail_delivery_by_message_hash(msg_hash, "direct fallback timeout");
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            DeliveryResult::Failed {
                link_id: id,
                msg_hash: Some(hash),
                dest_hash: dest,
                reason,
                ..
            } if *id == link_id
                && *hash == msg_hash
                && *dest == dest_hash
                && reason == "direct fallback timeout"
        ));
        assert_eq!(mgr.pending_count(), 0);
        assert!(!mgr.delivery_link_available(&dest_hash));
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
        let events = mgr.take_delivery_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, LxmfDeliveryEventKind::LinkEstablishing);
        assert_eq!(events[0].method, LxmfDeliveryEventMethod::Direct);
        assert_eq!(events[0].link_id, link_id);
        assert_eq!(events[0].dest_hash, dest_hash);
        assert_eq!(events[0].progress, Some(0.03));

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
    fn test_outbound_direct_link_accepts_backchannel_packet() {
        let (tx, mut rx) = mpsc::channel(128);
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_inbound_packet_sender(inbound_tx);

        let responder_key = Ed25519PrivateKey::generate();
        let sign_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xC7; 16];

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Initial",
            "initial direct message",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let (link_id, responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        let results = mgr.tick();
        assert!(
            results
                .iter()
                .any(|r| matches!(r, DeliveryResult::Complete { .. }))
        );

        let payload = b"reply over first direct link";
        let encrypted = responder_link.encrypt(payload).unwrap();
        let raw = link_data_packet(link_id, rns_wire::context::PacketContext::None, &encrypted);
        let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: raw.clone(),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();

        mgr.drain_events(&HashMap::new());

        assert!(
            inbound_rx.try_recv().is_err(),
            "plaintext must wait for successful proof admission"
        );
        let proof_raw = next_outbound(&mut rx);
        mgr.poll_endpoint_control();
        let (delivered, delivered_link_id) = inbound_rx.try_recv().unwrap();
        assert_eq!(delivered, payload);
        assert_eq!(delivered_link_id, link_id);

        let (proof_header, proof_offset) =
            rns_wire::header::PacketHeader::unpack(&proof_raw).unwrap();
        assert_eq!(
            proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );
        assert_eq!(proof_header.destination_hash, link_id);
        assert_eq!(
            proof_header.context,
            rns_wire::context::PacketContext::LinkProof
        );
        assert!(
            responder_link.validate_packet_proof(&packet_hash, &proof_raw[proof_offset..]),
            "initiator-side proof must be signed with the link key"
        );
    }

    #[test]
    fn reusable_initiator_link_receives_reverse_resource_and_proves_before_delivery() {
        reverse_resource_completion_handoff(false, false, false);
    }

    #[test]
    fn reverse_resource_owned_handoff_precedes_admission_release() {
        reverse_resource_completion_handoff(true, false, false);
    }

    #[test]
    fn reverse_split_resource_owned_handoff_uses_logical_id_once() {
        reverse_resource_completion_handoff(true, true, false);
    }

    #[test]
    fn reverse_resource_panicking_handoff_cleans_up_once_without_legacy_delivery() {
        reverse_resource_completion_handoff(true, false, true);
    }

    fn reverse_resource_completion_handoff(owned: bool, split: bool, panics: bool) {
        let (tx, mut rx) = mpsc::channel(512);
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_inbound_packet_sender(inbound_tx.clone());
        let admissions = Arc::new(AtomicUsize::new(0));
        let conclusions = Arc::new(AtomicUsize::new(0));
        let handoffs = Arc::new(AtomicUsize::new(0));
        let logical_id = [0x71; 32];
        if owned {
            let observed_conclusions = conclusions.clone();
            let observed_handoffs = handoffs.clone();
            mgr.set_inbound_resource_completion_handler(move |link_id, resource_id, data| {
                assert_eq!(
                    observed_conclusions.load(Ordering::Relaxed),
                    0,
                    "application admission is still live while the payload is handed off"
                );
                if split {
                    assert_eq!(resource_id, logical_id);
                }
                observed_handoffs.fetch_add(1, Ordering::Relaxed);
                assert!(!panics, "intentional completion handoff failure");
                inbound_tx.send((data, link_id)).unwrap();
            });
        }
        let admission_counter = Arc::clone(&admissions);
        mgr.set_inbound_resource_accept_handler(move |_, _| {
            admission_counter.fetch_add(1, Ordering::Relaxed);
            true
        });
        let conclusion_counter = Arc::clone(&conclusions);
        mgr.set_inbound_resource_concluded_handler(move |_, _| {
            conclusion_counter.fetch_add(1, Ordering::Relaxed);
        });

        let responder_key = Ed25519PrivateKey::generate();
        let sign_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xE7; 16];
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Initial",
            "establish reusable link",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let (link_id, responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);
        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        assert!(
            mgr.tick()
                .iter()
                .any(|result| matches!(result, DeliveryResult::Complete { .. }))
        );
        while rx.try_recv().is_ok() {}

        let payload = vec![0x5A; 4_096];
        let count = if split { 2 } else { 1 };
        for segment_index in 1..=count {
            let segment_size = payload.len() / count;
            let (mut transfer, remaining) = build_resource_transfer(
                &responder_link,
                payload[(segment_index - 1) * segment_size..segment_index * segment_size].to_vec(),
                false,
                Duration::from_millis(25),
            )
            .unwrap();
            assert!(remaining.is_none());
            if split {
                transfer.resource.flags.split = true;
                transfer.resource.original_hash = Some(logical_id);
                transfer.resource.advertisement_data_size = payload.len();
                transfer.resource.segment_index = segment_index;
                transfer.resource.total_segments = count;
            }
            let resource_hash = transfer.resource.resource_hash;
            let TransferAction::SendAdvertisement(advertisement) = transfer.tick() else {
                panic!("first Resource action must be an advertisement");
            };
            let encrypted_advertisement = responder_link.encrypt(&advertisement).unwrap();
            mgr.event_tx
                .try_send(DestinationEvent::InboundPacket {
                    raw: link_data_packet(
                        link_id,
                        rns_wire::context::PacketContext::ResourceAdv,
                        &encrypted_advertisement,
                    ),
                    interface_id: 0,
                    metrics: Default::default(),
                })
                .unwrap();
            mgr.drain_events(&HashMap::new());

            assert!(
                mgr.pending[&link_id]
                    .inbound_resources
                    .contains_key(&resource_hash)
            );
            assert!(inbound_rx.try_recv().is_err());

            let mut proof_seen = false;
            for _ in 0..128 {
                let raw = next_outbound(&mut rx);
                let (header, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
                match header.context {
                    rns_wire::context::PacketContext::ResourceReq => {
                        let request = responder_link.decrypt(&raw[offset..]).unwrap();
                        for action in transfer.handle_request(&request) {
                            if let TransferAction::SendPart(_, part) = action {
                                mgr.event_tx
                                    .try_send(DestinationEvent::InboundPacket {
                                        raw: link_data_packet(
                                            link_id,
                                            rns_wire::context::PacketContext::Resource,
                                            &part,
                                        ),
                                        interface_id: 0,
                                        metrics: Default::default(),
                                    })
                                    .unwrap();
                            }
                        }
                        mgr.drain_events(&HashMap::new());
                    }
                    rns_wire::context::PacketContext::ResourcePrf => {
                        assert_eq!(header.flags.packet_type, rns_wire::flags::PacketType::Proof);
                        assert!(transfer.handle_proof(&raw[offset..]));
                        proof_seen = true;
                        break;
                    }
                    other => panic!("unexpected reverse Resource control packet: {other:?}"),
                }
            }
            assert!(proof_seen);
            if segment_index < count {
                assert!(inbound_rx.try_recv().is_err());
                assert_eq!(conclusions.load(Ordering::Relaxed), 0);
                assert_eq!(handoffs.load(Ordering::Relaxed), 0);
            }
        }
        if !panics {
            let (delivered, delivered_link_id) = inbound_rx.try_recv().unwrap();
            assert_eq!(delivered, payload);
            assert_eq!(delivered_link_id, link_id);
        }
        assert!(inbound_rx.try_recv().is_err());
        assert!(mgr.pending[&link_id].inbound_resources.is_empty());
        assert_eq!(admissions.load(Ordering::Relaxed), count);
        assert_eq!(conclusions.load(Ordering::Relaxed), 1);
        assert_eq!(handoffs.load(Ordering::Relaxed), usize::from(owned));
    }

    #[test]
    fn reusable_initiator_link_rejects_oversize_reverse_resource() {
        let (tx, mut rx) = mpsc::channel(128);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_inbound_resource_limit_bytes(64);

        let responder_key = Ed25519PrivateKey::generate();
        let sign_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xE8; 16];
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Initial",
            "establish reusable link",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let (link_id, responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);
        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        let _ = mgr.tick();
        while rx.try_recv().is_ok() {}

        let (mut transfer, _) = build_resource_transfer(
            &responder_link,
            vec![0x44; 128],
            false,
            Duration::from_millis(25),
        )
        .unwrap();
        let resource_hash = transfer.resource.resource_hash;
        let TransferAction::SendAdvertisement(advertisement) = transfer.tick() else {
            unreachable!();
        };
        let encrypted = responder_link.encrypt(&advertisement).unwrap();
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::ResourceAdv,
                    &encrypted,
                ),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();
        mgr.drain_events(&HashMap::new());

        let reject = next_outbound(&mut rx);
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&reject).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceRcl
        );
        assert_eq!(
            responder_link.decrypt(&reject[offset..]).unwrap(),
            resource_hash
        );
        assert!(mgr.pending[&link_id].inbound_resources.is_empty());
    }

    #[test]
    fn reusable_initiator_link_releases_reverse_resource_on_sender_cancel() {
        let (tx, mut rx) = mpsc::channel(128);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let responder_key = Ed25519PrivateKey::generate();
        let sign_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xE9; 16];
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Initial",
            "establish reusable link",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let (link_id, responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);
        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        let _ = mgr.tick();
        while rx.try_recv().is_ok() {}

        let (mut transfer, _) = build_resource_transfer(
            &responder_link,
            vec![0x33; 4_096],
            false,
            Duration::from_millis(25),
        )
        .unwrap();
        let resource_hash = transfer.resource.resource_hash;
        let TransferAction::SendAdvertisement(advertisement) = transfer.tick() else {
            unreachable!();
        };
        let encrypted_advertisement = responder_link.encrypt(&advertisement).unwrap();
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::ResourceAdv,
                    &encrypted_advertisement,
                ),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();
        mgr.drain_events(&HashMap::new());
        assert!(
            mgr.pending[&link_id]
                .inbound_resources
                .contains_key(&resource_hash)
        );
        let _ = next_outbound(&mut rx);

        let encrypted_cancel = responder_link.encrypt(&resource_hash).unwrap();
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::ResourceIcl,
                    &encrypted_cancel,
                ),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();
        mgr.drain_events(&HashMap::new());
        assert!(mgr.pending[&link_id].inbound_resources.is_empty());
        assert!(mgr.pending[&link_id].inbound_resource_lifecycles.is_empty());
    }

    #[test]
    fn reusable_initiator_link_withholds_reverse_resource_if_proof_cannot_be_retained() {
        let (tx, mut rx) = mpsc::channel(128);
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_inbound_packet_sender(inbound_tx);
        let responder_key = Ed25519PrivateKey::generate();
        let sign_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xEA; 16];
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Initial",
            "establish reusable link",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let (link_id, responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);
        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        let _ = mgr.tick();
        while rx.try_recv().is_ok() {}

        let (mut transfer, _) = build_resource_transfer(
            &responder_link,
            vec![0x22; 128],
            false,
            Duration::from_millis(25),
        )
        .unwrap();
        let resource_hash = transfer.resource.resource_hash;
        let TransferAction::SendAdvertisement(advertisement) = transfer.tick() else {
            unreachable!();
        };
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::ResourceAdv,
                    &responder_link.encrypt(&advertisement).unwrap(),
                ),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();
        mgr.drain_events(&HashMap::new());
        let request = next_outbound(&mut rx);
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&request).unwrap();
        let plaintext_request = responder_link.decrypt(&request[offset..]).unwrap();
        let part = transfer
            .handle_request(&plaintext_request)
            .into_iter()
            .find_map(|action| match action {
                TransferAction::SendPart(_, part) => Some(part),
                _ => None,
            })
            .expect("single requested Resource part");

        for index in 0..LINK_PENDING_TRANSPORT_LIMIT {
            mgr.pending_transport
                .push_back(TransportMessage::DeregisterDestination {
                    hash: [(index & 0xFF) as u8; 16],
                });
        }
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(link_id, rns_wire::context::PacketContext::Resource, &part),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();
        mgr.drain_events(&HashMap::new());

        assert!(inbound_rx.try_recv().is_err());
        assert!(
            !mgr.pending[&link_id]
                .inbound_resources
                .contains_key(&resource_hash)
        );
    }

    #[test]
    fn reusable_initiator_link_expires_abandoned_split_resource_between_segments() {
        let (tx, mut rx) = mpsc::channel(128);
        let conclusions = Arc::new(AtomicUsize::new(0));
        let conclusion_counter = Arc::clone(&conclusions);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_inbound_resource_concluded_handler(move |_, _| {
            conclusion_counter.fetch_add(1, Ordering::Relaxed);
        });
        let responder_key = Ed25519PrivateKey::generate();
        let sign_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xEB; 16];
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Initial",
            "establish reusable link",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let (link_id, responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);
        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        let _ = mgr.tick();

        let resource_id = [0xD4; 32];
        let delivery = mgr.pending.get_mut(&link_id).unwrap();
        delivery
            .inbound_split_resources
            .insert(resource_id, MultiSegmentInbound::new(2, resource_id));
        delivery.inbound_resource_lifecycles.insert(
            resource_id,
            InboundResourceLifecycle {
                data_size: MAX_EFFICIENT_SIZE + 1,
                total_segments: 2,
                next_segment: 2,
                inter_segment_deadline: Some(Instant::now() - Duration::from_millis(1)),
            },
        );

        let _ = mgr.tick();
        assert!(mgr.pending[&link_id].inbound_resource_lifecycles.is_empty());
        assert!(mgr.pending[&link_id].inbound_split_resources.is_empty());
        assert_eq!(conclusions.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_outbound_direct_backchannel_proof_uses_received_header_type() {
        let (tx, mut rx) = mpsc::channel(128);
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_inbound_packet_sender(inbound_tx);

        let responder_key = Ed25519PrivateKey::generate();
        let sign_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xD7; 16];

        let mut msg = LxMessage::new(
            [0xAC; 16],
            [0xBC; 16],
            "Initial",
            "header2 direct reply",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let (link_id, responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        assert!(mgr.tick().is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
        assert!(
            mgr.tick()
                .iter()
                .any(|r| matches!(r, DeliveryResult::Complete { .. }))
        );

        let payload = b"reply carried in transported header2 packet";
        let encrypted = responder_link.encrypt(payload).unwrap();
        let raw = link_data_packet_with_header(
            link_id,
            rns_wire::flags::HeaderType::Header2,
            rns_wire::context::PacketContext::None,
            &encrypted,
        );
        let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header2);
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: raw.clone(),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();

        mgr.drain_events(&HashMap::new());

        let proof_raw = next_outbound(&mut rx);
        mgr.poll_endpoint_control();
        let (delivered, delivered_link_id) = inbound_rx.try_recv().unwrap();
        assert_eq!(delivered, payload);
        assert_eq!(delivered_link_id, link_id);

        let (proof_header, proof_offset) =
            rns_wire::header::PacketHeader::unpack(&proof_raw).unwrap();
        assert_eq!(
            proof_header.context,
            rns_wire::context::PacketContext::LinkProof
        );
        assert!(
            responder_link.validate_packet_proof(&packet_hash, &proof_raw[proof_offset..]),
            "link proof must hash the received Header2 packet shape"
        );
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
    fn test_establishment_timeout_deregisters_and_remains_retryable() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let msg = LxMessage::new(
            [0; 16],
            [0; 16],
            "Timeout",
            "timeout test",
            crate::constants::DeliveryMethod::Direct,
        );
        let timing = LinkEstablishmentTiming::from_first_hop_bitrate(3_515);
        let link_id = mgr
            .start_delivery_with_timing(msg, [0xDD; 16], 1, timing)
            .unwrap();

        let delivery = mgr.pending.get(&link_id).unwrap();
        assert_eq!(delivery.establishment_timeout, timing.timeout_for_hops(1));
        assert_eq!(
            delivery.link.establishment_timeout,
            timing.timeout_for_hops(1)
        );

        while let Ok(message) = rx.try_recv() {
            if let TransportMessage::SendLinkEndpoint { result_tx, .. } = message {
                let _ = result_tx.send(LinkEndpointSendResult::Sent);
            }
        }

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
            DeliveryResult::Failed { reason, .. }
                if reason == "link establishment timeout"
                    && is_retryable_link_delivery_failure(reason)
        )));
        assert_eq!(mgr.pending_count(), 0);

        let saw_deregister = complete_direct_cleanup(&mut mgr, &mut rx);
        assert!(saw_deregister, "DeregisterDestination should be queued");
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
        let _ = mgr.take_delivery_events();

        let results = mgr.tick();
        assert!(results.is_empty());
        let events = mgr.take_delivery_events();
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::LinkEstablished && event.progress == Some(0.05)
        }));
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::TransferStarted && event.progress == Some(0.10)
        }));

        let delivery = mgr.pending.get(&link_id).unwrap();
        let transfer = delivery.transfer.as_ref().expect("first segment transfer");
        assert!(transfer.resource.flags.split);
        assert_eq!(transfer.resource.segment_index, 1);
        assert!(transfer.resource.total_segments >= 2);
        assert_eq!(
            delivery
                .remaining_segments
                .as_ref()
                .map_or(0, LazyMultiSegmentOutbound::remaining_segments),
            transfer.resource.total_segments - 1
        );
    }

    #[test]
    fn link_handshake_backpressure_stages_rtt_and_delivery_in_order() {
        let (tx, mut rx) = mpsc::channel(2);
        let mut mgr = LinkDeliveryManager::new(tx.clone(), None, None);
        let signing_key = Ed25519PrivateKey::generate();
        let mut message = LxMessage::new(
            [0xA0; 16],
            [0xB0; 16],
            "backpressure",
            "payload",
            crate::constants::DeliveryMethod::Direct,
        );
        message.sign(&signing_key).unwrap();
        let destination_hash = [0xC0; 16];
        let link_id = mgr.start_delivery(message, destination_hash, 1).unwrap();
        let request_raw = next_outbound(&mut rx);
        let (_, request_offset) = rns_wire::header::PacketHeader::unpack(&request_raw).unwrap();
        let responder_key = Ed25519PrivateKey::generate();
        let (_responder, proof) = Link::new_responder(
            &request_raw[request_offset..],
            &responder_key,
            destination_hash,
            1,
        )
        .unwrap();

        tx.try_send(TransportMessage::DeregisterDestination { hash: [1; 16] })
            .unwrap();
        tx.try_send(TransportMessage::DeregisterDestination { hash: [2; 16] })
            .unwrap();
        let responder_public = responder_key.public_key();
        assert!(mgr.handle_link_proof(
            &link_id,
            &proof,
            &responder_public,
            &responder_public.to_bytes(),
            0,
        ));
        assert_eq!(mgr.pending_transport.len(), 1);
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::DeregisterDestination { hash } if hash == [1; 16]
        ));
        assert!(matches!(
            rx.try_recv().unwrap(),
            TransportMessage::DeregisterDestination { hash } if hash == [2; 16]
        ));

        assert!(mgr.tick().is_empty());
        let bind = rx.try_recv().expect("staged endpoint bind");
        let TransportMessage::BindLinkEndpoint { result_tx, .. } = bind else {
            panic!("expected endpoint bind before LRRTT");
        };
        result_tx.send(LinkEndpointBindResult::Bound).unwrap();
        assert!(mgr.tick().is_empty());
        let rtt = next_outbound(&mut rx);
        let (rtt_header, _) = rns_wire::header::PacketHeader::unpack(&rtt).unwrap();
        assert_eq!(rtt_header.context, rns_wire::context::PacketContext::Lrrtt);
        let packet = next_outbound(&mut rx);
        let (packet_header, _) = rns_wire::header::PacketHeader::unpack(&packet).unwrap();
        assert_eq!(
            packet_header.context,
            rns_wire::context::PacketContext::None
        );
        assert!(mgr.pending_transport.is_empty());
    }

    #[test]
    fn rejected_endpoint_send_fails_only_the_direct_owner() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let signing_key = Ed25519PrivateKey::generate();
        let mut message = LxMessage::new(
            [0xA8; 16],
            [0xB8; 16],
            "endpoint result",
            "must fail closed",
            crate::constants::DeliveryMethod::Direct,
        );
        message.sign(&signing_key).unwrap();
        let responder_key = Ed25519PrivateKey::generate();
        let (link_id, _) =
            establish_active_delivery(&mut mgr, &mut rx, message, &responder_key, [0xC8; 16]);

        assert!(mgr.tick().is_empty());
        let result_tx = loop {
            let message = rx.try_recv().expect("Direct packet send command");
            if let TransportMessage::SendLinkEndpoint { result_tx, .. } = message {
                break result_tx;
            }
        };
        result_tx
            .send(LinkEndpointSendResult::InvalidPacket)
            .unwrap();
        mgr.poll_endpoint_control();

        assert_eq!(
            mgr.pending.get(&link_id).unwrap().state,
            DeliveryState::Failed
        );
    }

    #[test]
    fn direct_rejects_wrong_interface_before_proof_or_plaintext_publication() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
        mgr.set_inbound_packet_sender(inbound_tx);
        let signing_key = Ed25519PrivateKey::generate();
        let mut message = LxMessage::new(
            [0xA1; 16],
            [0xB1; 16],
            "interface",
            "gate",
            crate::constants::DeliveryMethod::Direct,
        );
        message.sign(&signing_key).unwrap();
        let responder_key = Ed25519PrivateKey::generate();
        let (link_id, responder) =
            establish_active_delivery(&mut mgr, &mut rx, message, &responder_key, [0xC1; 16]);
        let _ = mgr.tick();
        while let Ok(message) = rx.try_recv() {
            if let TransportMessage::SendLinkEndpoint { result_tx, .. } = message {
                let _ = result_tx.send(LinkEndpointSendResult::Sent);
            }
        }

        let encrypted = responder.encrypt(b"wrong-interface").unwrap();
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(link_id, rns_wire::context::PacketContext::None, &encrypted),
                interface_id: 99,
                metrics: Default::default(),
            })
            .unwrap();
        mgr.drain_events(&HashMap::new());

        assert!(inbound_rx.try_recv().is_err());
        assert!(rx.try_recv().is_err());
        assert_ne!(
            mgr.pending.get(&link_id).unwrap().state,
            DeliveryState::Failed
        );
    }

    #[test]
    fn direct_withholds_plaintext_when_reverse_packet_proof_cannot_be_retained() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel();
        mgr.set_inbound_packet_sender(inbound_tx);
        let signing_key = Ed25519PrivateKey::generate();
        let mut message = LxMessage::new(
            [0xA2; 16],
            [0xB2; 16],
            "proof",
            "before plaintext",
            crate::constants::DeliveryMethod::Direct,
        );
        message.sign(&signing_key).unwrap();
        let responder_key = Ed25519PrivateKey::generate();
        let (link_id, responder) =
            establish_active_delivery(&mut mgr, &mut rx, message, &responder_key, [0xC2; 16]);
        let _ = mgr.tick();
        while rx.try_recv().is_ok() {}
        drop(rx);

        let encrypted = responder.encrypt(b"must-not-publish").unwrap();
        mgr.event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: link_data_packet(link_id, rns_wire::context::PacketContext::None, &encrypted),
                interface_id: 0,
                metrics: Default::default(),
            })
            .unwrap();
        mgr.drain_events(&HashMap::new());

        assert!(inbound_rx.try_recv().is_err());
        assert_eq!(
            mgr.pending.get(&link_id).unwrap().state,
            DeliveryState::Failed
        );
    }

    #[test]
    fn invalid_direct_lrproof_does_not_block_later_valid_interface_binding() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let message = LxMessage::new(
            [0xA3; 16],
            [0xB3; 16],
            "proof",
            "retry",
            crate::constants::DeliveryMethod::Direct,
        );
        let destination_hash = [0xC3; 16];
        let link_id = mgr.start_delivery(message, destination_hash, 1).unwrap();
        let request_raw = next_outbound(&mut rx);
        let (_, request_offset) = rns_wire::header::PacketHeader::unpack(&request_raw).unwrap();
        let responder_key = Ed25519PrivateKey::generate();
        let (_responder, proof) = Link::new_responder(
            &request_raw[request_offset..],
            &responder_key,
            destination_hash,
            1,
        )
        .unwrap();
        let responder_public = responder_key.public_key();

        assert!(!mgr.handle_link_proof(
            &link_id,
            &[0u8; 99],
            &responder_public,
            &responder_public.to_bytes(),
            7,
        ));
        assert_eq!(
            mgr.pending.get(&link_id).unwrap().state,
            DeliveryState::Establishing
        );
        assert!(mgr.pending_endpoint_binds.is_empty());

        assert!(mgr.handle_link_proof(
            &link_id,
            &proof,
            &responder_public,
            &responder_public.to_bytes(),
            8,
        ));
        let TransportMessage::BindLinkEndpoint { binding, .. } = rx.try_recv().unwrap() else {
            panic!("valid proof must bind its ingress interface");
        };
        assert_eq!(binding.interface_id, 8);
    }

    #[test]
    fn endpoint_lifecycle_failure_is_scoped_to_its_direct_owner() {
        let (tx, mut rx) = mpsc::channel(128);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let responder_key = Ed25519PrivateKey::generate();
        let first = establish_active_delivery(
            &mut mgr,
            &mut rx,
            LxMessage::new(
                [1; 16],
                [2; 16],
                "first",
                "owner",
                crate::constants::DeliveryMethod::Direct,
            ),
            &responder_key,
            [3; 16],
        )
        .0;
        let second = establish_active_delivery(
            &mut mgr,
            &mut rx,
            LxMessage::new(
                [4; 16],
                [5; 16],
                "second",
                "owner",
                crate::constants::DeliveryMethod::Direct,
            ),
            &responder_key,
            [6; 16],
        )
        .0;

        mgr.endpoint_lifecycle_tx
            .send(LinkEndpointLifecycleEvent {
                binding: LinkEndpointBinding {
                    link_id: first,
                    interface_id: 0,
                    role: LinkEndpointRole::Initiator,
                },
                reason: rns_transport::messages::LinkEndpointTerminalReason::InterfaceRemoved,
                dropped_packets: 1,
            })
            .unwrap();
        mgr.poll_endpoint_control();

        assert_eq!(
            mgr.pending.get(&first).unwrap().state,
            DeliveryState::Failed
        );
        assert_ne!(
            mgr.pending.get(&second).unwrap().state,
            DeliveryState::Failed
        );
    }

    #[test]
    fn progressive_direct_resource_uses_watchdog_not_absolute_delivery_age() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let signing_key = Ed25519PrivateKey::generate();
        let mut message = LxMessage::new(
            [0xA4; 16],
            [0xB4; 16],
            "progressive resource",
            &"x".repeat(4_000),
            crate::constants::DeliveryMethod::Direct,
        );
        message.sign(&signing_key).unwrap();
        let responder_key = Ed25519PrivateKey::generate();
        let destination_hash = [0xC4; 16];
        let (link_id, _responder) =
            establish_active_delivery(&mut mgr, &mut rx, message, &responder_key, destination_hash);
        assert!(mgr.tick().is_empty());
        {
            let delivery = mgr.pending.get_mut(&link_id).unwrap();
            assert_eq!(delivery.state, DeliveryState::Transferring);
            delivery.started_at = Instant::now() - Duration::from_secs(600);
            delivery.timeout = Duration::ZERO;
        }

        assert!(mgr.tick().is_empty());
        let delivery = mgr.pending.get(&link_id).unwrap();
        assert_eq!(delivery.state, DeliveryState::Transferring);
        assert!(delivery.transfer.is_some());
        let advertisement = next_outbound(&mut rx);
        let (header, _) = rns_wire::header::PacketHeader::unpack(&advertisement).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourceAdv
        );
    }

    #[test]
    fn test_message_delivery_snapshot_reports_active_resource() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Snapshot Direct",
            &"x".repeat(MAX_EFFICIENT_SIZE + 256),
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash.unwrap();

        let responder_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCC; 16];
        let (link_id, _responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);
        let _ = mgr.take_delivery_events();
        assert!(mgr.tick().is_empty());

        let snapshot = mgr
            .message_delivery_snapshot(msg_hash)
            .expect("snapshot for active direct resource");
        assert_eq!(snapshot.link_id, link_id);
        assert_eq!(snapshot.dest_hash, dest_hash);
        assert_eq!(snapshot.delivery_state, DeliveryState::Transferring);
        assert_eq!(snapshot.representation, DeliveryRepresentation::Resource);
        assert_eq!(snapshot.progress, 0.10);
        assert!(!snapshot.queued);
        assert_eq!(snapshot.in_flight_deliveries, 1);
    }

    #[test]
    fn test_cancel_delivery_by_message_hash_sends_resource_icl_and_reuses_link() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Cancel Direct",
            &"x".repeat(MAX_EFFICIENT_SIZE + 256),
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash.unwrap();

        let responder_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xC8; 16];
        let (link_id, _responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);
        let _ = mgr.take_delivery_events();
        assert!(mgr.tick().is_empty());
        let _ = mgr.take_delivery_events();

        assert!(mgr.cancel_delivery_by_message_hash(msg_hash));
        assert_eq!(mgr.pending_count(), 0);
        assert!(!mgr.cancel_delivery_by_message_hash(msg_hash));
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.delivery_link_available(&dest_hash));
        assert_eq!(
            mgr.pending.get(&link_id).unwrap().state,
            DeliveryState::Idle
        );
        assert!(
            mgr.take_delivery_events()
                .iter()
                .all(|event| event.kind != LxmfDeliveryEventKind::Failed)
        );

        let mut saw_icl = false;
        while let Ok(message) = rx.try_recv() {
            let request = match message {
                TransportMessage::Outbound(request) => request,
                TransportMessage::SendLinkEndpoint {
                    request, result_tx, ..
                } => {
                    let _ = result_tx.send(LinkEndpointSendResult::Sent);
                    request
                }
                _ => continue,
            };
            let (header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
            if header.context == rns_wire::context::PacketContext::ResourceIcl {
                assert_eq!(header.destination_hash, link_id);
                saw_icl = true;
            }
        }
        assert!(saw_icl, "resource cancellation must emit RESOURCE_ICL");
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
        let _ = mgr.take_delivery_events();

        let results = mgr.tick();
        assert!(results.is_empty());
        let _ = mgr.take_delivery_events();

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
        let events = mgr.take_delivery_events();
        let progress = events
            .iter()
            .find(|event| event.kind == LxmfDeliveryEventKind::TransferProgress)
            .and_then(|event| event.progress)
            .expect("resource proof emits transfer progress");
        assert!(progress > 0.10 && progress < 1.0);

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
            if delivery.remaining_segments.is_none() {
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
    fn test_resource_reject_marks_delivery_rejected_without_retry() {
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
                .any(|r| matches!(r, DeliveryResult::Rejected { .. }))
        );
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(
            mgr.pending.get(&link_id).unwrap().state,
            DeliveryState::Idle
        );
        let events = mgr.take_delivery_events();
        assert!(
            events
                .iter()
                .any(|event| event.kind == LxmfDeliveryEventKind::Rejected
                    && event.reason.as_deref() == Some("resource rejected"))
        );
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
                metrics: Default::default(),
            })
            .unwrap();

        mgr.drain_events(&HashMap::new());
        let results = mgr.tick();

        assert!(results.iter().any(|r| matches!(
            r,
            DeliveryResult::Failed { reason, .. } if reason == "link closed"
        )));
        assert_eq!(mgr.pending_count(), 0);
        let saw_deregister = complete_direct_cleanup(&mut mgr, &mut rx);
        assert!(saw_deregister);
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
                metrics: Default::default(),
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
        let (link_id, responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);
        let _ = mgr.take_delivery_events();

        let results = mgr.tick();
        assert!(results.is_empty());
        let events = mgr.take_delivery_events();
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::LinkEstablished && event.progress == Some(0.05)
        }));
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::AwaitingProof && event.progress == Some(0.50)
        }));

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
            .prove_packet_with_local_signer(&packet_hash)
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
                metrics: Default::default(),
            })
            .unwrap();
        mgr.drain_events(&HashMap::new());
        let results = mgr.tick();
        assert!(
            results
                .iter()
                .any(|r| matches!(r, DeliveryResult::Complete { .. }))
        );
        let events = mgr.take_delivery_events();
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::Delivered && event.progress == Some(1.0)
        }));
    }

    #[test]
    fn test_small_direct_ignores_unauthenticated_close_after_proof() {
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

        let responder_key = Ed25519PrivateKey::generate();
        let dest_hash = [0xCC; 16];
        let (link_id, mut responder_link) =
            establish_active_delivery(&mut mgr, &mut rx, msg, &responder_key, dest_hash);

        let results = mgr.tick();
        assert!(results.is_empty());
        complete_next_link_packet(&mut mgr, &mut rx, link_id, &responder_link, &responder_key);
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
                metrics: Default::default(),
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
