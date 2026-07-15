//! LXMF protocol constants.
//!
//! Python reference: LXMF/LXMF.py.

pub const FIELD_EMBEDDED_LXMS: u8 = 0x01;
pub const FIELD_TELEMETRY: u8 = 0x02;
pub const FIELD_TELEMETRY_STREAM: u8 = 0x03;
pub const FIELD_ICON_APPEARANCE: u8 = 0x04;
pub const FIELD_FILE_ATTACHMENTS: u8 = 0x05;
pub const FIELD_IMAGE: u8 = 0x06;
pub const FIELD_AUDIO: u8 = 0x07;
/// Bytes, full thread ID hash.
pub const FIELD_THREAD: u8 = 0x08;
pub const FIELD_COMMANDS: u8 = 0x09;
pub const FIELD_RESULTS: u8 = 0x0A;
pub const FIELD_GROUP: u8 = 0x0B;
pub const FIELD_TICKET: u8 = 0x0C;
pub const FIELD_EVENT: u8 = 0x0D;
pub const FIELD_RNR_REFS: u8 = 0x0E;
pub const FIELD_RENDERER: u8 = 0x0F;
/// Bytes, full `LXMessage` hash. Python reference: LXMF.py:23.
pub const FIELD_REPLY_TO: u8 = 0x30;
/// Bytes, quoted content in UTF-8 encoding. Python reference: LXMF.py:24.
pub const FIELD_REPLY_QUOTE: u8 = 0x31;
/// Dict keyed by [`REACTION_TO`] / [`REACTION_CONTENT`]. Python reference: LXMF.py:25.
pub const FIELD_REACTION: u8 = 0x40;
/// Dict keyed by [`COMMENT_FOR`]. Python reference: LXMF.py:26.
pub const FIELD_COMMENT: u8 = 0x41;
/// Dict keyed by [`CONTINUATION_OF`]. Python reference: LXMF.py:27.
pub const FIELD_CONTINUATION: u8 = 0x42;

// Unallocated fields between 0x00 and 0x80, both included, should be
// considered reserved for future extensibility. For experimental and
// unstable features, it is recommended to use fields above 0xFF.
// Python reference: LXMF.py:29-32.

pub const FIELD_CUSTOM_TYPE: u8 = 0xFB;
pub const FIELD_CUSTOM_DATA: u8 = 0xFC;
pub const FIELD_CUSTOM_META: u8 = 0xFD;
pub const FIELD_NON_SPECIFIC: u8 = 0xFE;
pub const FIELD_DEBUG: u8 = 0xFF;

pub const AM_CODEC2_450PWB: u8 = 0x01;
pub const AM_CODEC2_450: u8 = 0x02;
pub const AM_CODEC2_700C: u8 = 0x03;
pub const AM_CODEC2_1200: u8 = 0x04;
pub const AM_CODEC2_1300: u8 = 0x05;
pub const AM_CODEC2_1400: u8 = 0x06;
pub const AM_CODEC2_1600: u8 = 0x07;
pub const AM_CODEC2_2400: u8 = 0x08;
pub const AM_CODEC2_3200: u8 = 0x09;
pub const AM_OPUS_OGG: u8 = 0x10;
pub const AM_OPUS_LBW: u8 = 0x11;
pub const AM_OPUS_MBW: u8 = 0x12;
pub const AM_OPUS_PTT: u8 = 0x13;
pub const AM_OPUS_RT_HDX: u8 = 0x14;
pub const AM_OPUS_RT_FDX: u8 = 0x15;
pub const AM_OPUS_STANDARD: u8 = 0x16;
pub const AM_OPUS_HQ: u8 = 0x17;
pub const AM_OPUS_BROADCAST: u8 = 0x18;
pub const AM_OPUS_LOSSLESS: u8 = 0x19;
pub const AM_CUSTOM: u8 = 0xFF;

pub const RENDERER_PLAIN: u8 = 0x00;
pub const RENDERER_MICRON: u8 = 0x01;
pub const RENDERER_MARKDOWN: u8 = 0x02;
pub const RENDERER_BBCODE: u8 = 0x03;

// Clients choose how to handle reaction content, if at all. While reactions
// are typically a single unicode emoji or similar, the exact implementation
// and sanitization is left up to the client. FIELD_REACTION dict keys —
// Python reference: LXMF.py:104-110.
/// Bytes, full `LXMessage` hash.
pub const REACTION_TO: u8 = 0x00;
/// Bytes, the reaction content in UTF-8 encoding.
pub const REACTION_CONTENT: u8 = 0x01;

// Comment content is carried as the normal LXM content, so clients that do
// not support comments display them as normal messages. FIELD_COMMENT dict
// key — Python reference: LXMF.py:112-118.
/// Bytes, full `LXMessage` hash.
pub const COMMENT_FOR: u8 = 0x00;

// Continuation content is carried as the normal LXM content, so clients that
// do not support continuations display them as normal messages.
// FIELD_CONTINUATION dict key — Python reference: LXMF.py:120-126.
/// Bytes, full `LXMessage` hash.
pub const CONTINUATION_OF: u8 = 0x00;

pub const PN_META_VERSION: u8 = 0x00;
pub const PN_META_NAME: u8 = 0x01;
pub const PN_META_SYNC_STRATUM: u8 = 0x02;
pub const PN_META_SYNC_THROTTLE: u8 = 0x03;
pub const PN_META_AUTH_BAND: u8 = 0x04;
pub const PN_META_UTIL_PRESSURE: u8 = 0x05;
pub const PN_META_CUSTOM: u8 = 0xFF;

pub const SF_COMPRESSION: u8 = 0x00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageState {
    Generating = 0x00,
    Outbound = 0x01,
    Sending = 0x02,
    Sent = 0x04,
    Delivered = 0x08,
    Rejected = 0xFD,
    Cancelled = 0xFE,
    Failed = 0xFF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMethod {
    Opportunistic = 0x01,
    Direct = 0x02,
    Propagated = 0x03,
    Paper = 0x05,
}

impl DeliveryMethod {
    /// Paper is a local-only generation method and cannot be transmitted.
    pub fn is_sendable(&self) -> bool {
        !matches!(self, DeliveryMethod::Paper)
    }
}

/// How a message is represented on the wire. Values match Python LXMessage.py.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryRepresentation {
    Unknown = 0x00,
    Packet = 0x01,
    Resource = 0x02,
    Paper = 0x05,
}

/// Reason a message could not be verified. Values match Python LXMessage.py.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnverifiedReason {
    SourceUnknown = 0x01,
    SignatureInvalid = 0x02,
}

pub const DESTINATION_LENGTH: usize = 16;
pub const SIGNATURE_LENGTH: usize = 64;
pub const TICKET_LENGTH: usize = 16;
pub const TIMESTAMP_SIZE: usize = 8;
pub const STRUCT_OVERHEAD: usize = 8;
/// 2 * dest(16) + sig(64) + timestamp(8) + struct(8) = 112.
pub const LXMF_OVERHEAD: usize =
    2 * DESTINATION_LENGTH + SIGNATURE_LENGTH + TIMESTAMP_SIZE + STRUCT_OVERHEAD;
pub const PAPER_MDU: usize = 2210;

pub const TICKET_EXPIRY: u64 = 21 * 24 * 60 * 60;
pub const TICKET_GRACE: u64 = 5 * 24 * 60 * 60;
pub const TICKET_RENEW: u64 = 14 * 24 * 60 * 60;
pub const TICKET_INTERVAL: u64 = 24 * 60 * 60;
/// Sentinel cost value that always exceeds the maximum PoW cost.
pub const COST_TICKET: u16 = 0x100;

pub const MAX_DELIVERY_ATTEMPTS: u32 = 5;
/// Interval between router job ticks (seconds).
pub const PROCESSING_INTERVAL: u64 = 4;
pub const DELIVERY_RETRY_WAIT: u64 = 10;
pub const PATH_REQUEST_WAIT: u64 = 7;
pub const MAX_PATHLESS_TRIES: u32 = 1;
/// Maximum link inactivity before teardown (seconds).
pub const LINK_MAX_INACTIVITY: u64 = 10 * 60;
/// Maximum propagation link inactivity (seconds).
pub const P_LINK_MAX_INACTIVITY: u64 = 3 * 60;
pub const MESSAGE_EXPIRY: u64 = 30 * 24 * 60 * 60;
pub const STAMP_COST_EXPIRY: u64 = 45 * 24 * 60 * 60;
/// Delay before announcing propagation node (seconds).
pub const NODE_ANNOUNCE_DELAY: u64 = 20;
pub const PROPAGATION_LIMIT: usize = 256;
pub const DELIVERY_LIMIT: usize = 1000;
/// PROPAGATION_LIMIT * 40, in KB.
pub const SYNC_LIMIT: usize = 10240;
pub const PROPAGATION_COST_MIN: u8 = 13;
pub const PROPAGATION_COST: u8 = 16;
pub const PROPAGATION_COST_FLEX: u8 = 3;
pub const PEERING_COST: u8 = 18;
pub const MAX_PEERING_COST: u8 = 26;
pub const MAX_PEERS: usize = 20;
pub const PN_STAMP_THROTTLE: u64 = 180;

pub const AUTOPEER: bool = true;
pub const AUTOPEER_MAXDEPTH: usize = 4;
/// When selecting peers for sync, pick from the N fastest.
pub const FASTEST_N_RANDOM_POOL: usize = 2;
/// Percentage of max_peers kept as headroom for rotation.
pub const ROTATION_HEADROOM_PCT: usize = 10;
/// Acceptance rate below which peers become rotation candidates.
pub const ROTATION_AR_MAX: f64 = 0.5;

pub const STATS_GET_PATH: &str = "/pn/get/stats";
pub const SYNC_REQUEST_PATH: &str = "/pn/peer/sync";
pub const UNPEER_REQUEST_PATH: &str = "/pn/peer/unpeer";
/// Sentinel value meaning "download all messages".
pub const PR_ALL_MESSAGES: u32 = 0x00;
/// Signal value for duplicate detection during sync.
pub const DUPLICATE_SIGNAL: &str = "lxmf_duplicate";

pub const OFFER_REQUEST_PATH: &str = "/offer";
pub const MESSAGE_GET_PATH: &str = "/get";
/// Maximum time a peer can be unreachable before removal (14 days).
pub const MAX_UNREACHABLE: u64 = 14 * 24 * 60 * 60;
/// Sync backoff step per consecutive failure (12 minutes).
pub const SYNC_BACKOFF_STEP: u64 = 12 * 60;
pub const PATH_REQUEST_GRACE: f64 = 7.5;
/// Maximum time a peer can be stale before rotation (14 days).
pub const PEER_STALE_TIME: u64 = 14 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerState {
    Idle = 0x00,
    LinkEstablishing = 0x01,
    LinkReady = 0x02,
    RequestSent = 0x03,
    ResponseReceived = 0x04,
    ResourceTransferring = 0x05,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerError {
    NoIdentity = 0xF0,
    NoAccess = 0xF1,
    // 0xF2 is unused (gap in numbering).
    InvalidKey = 0xF3,
    InvalidData = 0xF4,
    InvalidStamp = 0xF5,
    Throttled = 0xF6,
    NotFound = 0xFD,
    Timeout = 0xFE,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum SyncStrategy {
    Lazy = 0x01,
    #[default]
    Persistent = 0x02,
}

/// Default expand rounds for message stamps. Matches Python WORKBLOCK_EXPAND_ROUNDS.
pub const STAMP_WORKBLOCK_EXPAND_ROUNDS: usize = 3000;
/// Expand rounds for propagation node stamps. Matches Python WORKBLOCK_EXPAND_ROUNDS_PN.
pub const STAMP_WORKBLOCK_EXPAND_ROUNDS_PN: usize = 1000;
/// Expand rounds for peering key generation. Matches Python WORKBLOCK_EXPAND_ROUNDS_PEERING.
pub const STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING: usize = 25;
/// SHA-256 output length.
pub const STAMP_SIZE: usize = 32;
/// Minimum batch size before using parallel validation pool.
pub const PN_VALIDATION_POOL_MIN_SIZE: usize = 256;

/// Interval (in ticks) for processing outbound messages.
pub const JOB_OUTBOUND_INTERVAL: u64 = 1;
/// Interval (in ticks) for processing deferred stamps.
pub const JOB_STAMPS_INTERVAL: u64 = 1;
/// Interval (in ticks) for cleaning inactive links.
pub const JOB_LINKS_INTERVAL: u64 = 1;
/// Interval (in ticks) for cleaning transient ID caches.
pub const JOB_TRANSIENT_INTERVAL: u64 = 60;
/// Interval (in ticks) for cleaning the message store.
pub const JOB_STORE_INTERVAL: u64 = 120;
/// Interval (in ticks) for syncing peers.
pub const JOB_PEERSYNC_INTERVAL: u64 = 6;
/// Interval (in ticks) for ingesting peer distribution queues.
pub const JOB_PEERINGEST_INTERVAL: u64 = 6;
/// 56 * JOB_PEERINGEST_INTERVAL.
pub const JOB_ROTATE_INTERVAL: u64 = 56 * 6;

pub const APP_NAME: &str = "lxmf";
pub const DELIVERY_ASPECT: &str = "delivery";
pub const PROPAGATION_ASPECT: &str = "propagation";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lxmf_overhead() {
        assert_eq!(LXMF_OVERHEAD, 112);
    }

    #[test]
    fn test_message_states_distinct() {
        assert_ne!(MessageState::Generating as u8, MessageState::Outbound as u8);
        assert_ne!(MessageState::Sent as u8, MessageState::Delivered as u8);
        assert_ne!(MessageState::Rejected as u8, MessageState::Failed as u8);
    }

    #[test]
    fn test_delivery_method_sendable() {
        assert!(DeliveryMethod::Opportunistic.is_sendable());
        assert!(DeliveryMethod::Direct.is_sendable());
        assert!(DeliveryMethod::Propagated.is_sendable());
        assert!(!DeliveryMethod::Paper.is_sendable());
    }

    #[test]
    fn test_state_and_method_no_overlap() {
        // PAPER (0x05) delivery method must not collide with any MessageState value.
        let paper = DeliveryMethod::Paper as u8;
        assert_ne!(paper, MessageState::Generating as u8);
        assert_ne!(paper, MessageState::Outbound as u8);
        assert_ne!(paper, MessageState::Sending as u8);
        assert_ne!(paper, MessageState::Sent as u8);
        assert_ne!(paper, MessageState::Delivered as u8);
    }

    #[test]
    fn test_ticket_constants() {
        assert_eq!(TICKET_EXPIRY, 1_814_400);
        assert_eq!(TICKET_GRACE, 432_000);
        assert_eq!(TICKET_RENEW, 1_209_600);
        assert_eq!(TICKET_INTERVAL, 86_400);
        assert_eq!(COST_TICKET, 256);
    }

    #[test]
    fn test_peer_states_sequential() {
        assert_eq!(PeerState::Idle as u8, 0);
        assert_eq!(PeerState::LinkEstablishing as u8, 1);
        assert_eq!(PeerState::LinkReady as u8, 2);
        assert_eq!(PeerState::RequestSent as u8, 3);
        assert_eq!(PeerState::ResponseReceived as u8, 4);
        assert_eq!(PeerState::ResourceTransferring as u8, 5);
    }

    #[test]
    fn test_sync_strategy_default() {
        assert_eq!(SyncStrategy::default(), SyncStrategy::Persistent);
    }

    #[test]
    fn test_unverified_reason_values() {
        assert_eq!(UnverifiedReason::SourceUnknown as u8, 0x01);
        assert_eq!(UnverifiedReason::SignatureInvalid as u8, 0x02);
    }

    #[test]
    fn test_delivery_representation_values() {
        assert_eq!(DeliveryRepresentation::Unknown as u8, 0x00);
        assert_eq!(DeliveryRepresentation::Packet as u8, 0x01);
        assert_eq!(DeliveryRepresentation::Resource as u8, 0x02);
        assert_eq!(DeliveryRepresentation::Paper as u8, 0x05);
    }

    #[test]
    fn test_router_constants_match_python() {
        assert_eq!(PROCESSING_INTERVAL, 4);
        assert_eq!(LINK_MAX_INACTIVITY, 600);
        assert_eq!(P_LINK_MAX_INACTIVITY, 180);
        assert_eq!(NODE_ANNOUNCE_DELAY, 20);
        assert_eq!(SYNC_LIMIT, 10240);
        assert_eq!(PROPAGATION_COST_MIN, 13);
        assert_eq!(MAX_PEERING_COST, 26);
        assert_eq!(AUTOPEER_MAXDEPTH, 4);
        assert_eq!(FASTEST_N_RANDOM_POOL, 2);
    }

    #[test]
    fn test_stamp_expand_rounds_match_python() {
        assert_eq!(STAMP_WORKBLOCK_EXPAND_ROUNDS, 3000);
        assert_eq!(STAMP_WORKBLOCK_EXPAND_ROUNDS_PN, 1000);
        assert_eq!(STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING, 25);
        assert_eq!(PN_VALIDATION_POOL_MIN_SIZE, 256);
    }

    #[test]
    fn test_peer_constants_match_python() {
        assert_eq!(MAX_UNREACHABLE, 14 * 24 * 60 * 60);
        assert_eq!(SYNC_BACKOFF_STEP, 12 * 60);
    }

    #[test]
    fn test_field_standards_match_python_101() {
        // LXMF.py:23-27 field allocations plus dict-key constants (LXMF.py:104-126).
        assert_eq!(FIELD_REPLY_TO, 0x30);
        assert_eq!(FIELD_REPLY_QUOTE, 0x31);
        assert_eq!(FIELD_REACTION, 0x40);
        assert_eq!(FIELD_COMMENT, 0x41);
        assert_eq!(FIELD_CONTINUATION, 0x42);
        assert_eq!(REACTION_TO, 0x00);
        assert_eq!(REACTION_CONTENT, 0x01);
        assert_eq!(COMMENT_FOR, 0x00);
        assert_eq!(CONTINUATION_OF, 0x00);
    }
}
