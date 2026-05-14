//! LXMF Propagation Sync Protocol -- Offer/Get between peers.
//!
//! 1. Peer A opens a Link to Peer B.
//! 2. A sends Offer { transient_ids }.
//! 3. B responds with one of:
//!    - `true`: peer wants ALL offered messages.
//!    - `false`: peer already has everything.
//!    - list of transient IDs: wants those specific messages.
//!    - integer error code: 0xF0 NoIdentity, 0xF1 NoAccess, 0xF3 InvalidKey,
//!      0xF4 InvalidData, 0xF5 InvalidStamp, 0xF6 Throttled.
//! 4. A sends requested messages via Resource transfer.
//! 5. B stores and sends proof.
//!
//! Python reference: LXMPeer.py (offer_response).

use rns_protocol::channel_message::{ChannelMessageError, MessageBase};
use serde::{Deserialize, Serialize};

use crate::constants::PeerError;
use crate::propagation::PropagationStore;
use crate::types::PropagationTransientId;

pub const SYNC_MSG_OFFER: u16 = 0x0001;
pub const SYNC_MSG_GET: u16 = 0x0002;

/// Offer message: "I have these messages".
///
/// Python wire: `[peering_key, unhandled_ids]`. `peering_key` is the raw stamp
/// bytes (Python `self.peering_key[0]`), required by the receiver for access control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncOffer {
    pub peering_key: Vec<u8>,
    pub transient_ids: Vec<Vec<u8>>,
}

impl SyncOffer {
    pub fn new() -> Self {
        Self {
            peering_key: Vec::new(),
            transient_ids: Vec::new(),
        }
    }
}

impl Default for SyncOffer {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageBase for SyncOffer {
    fn msg_type(&self) -> u16 {
        SYNC_MSG_OFFER
    }

    fn pack(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).unwrap_or_default()
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        let offer: SyncOffer =
            rmp_serde::from_slice(raw).map_err(|_| ChannelMessageError::UnpackFailed)?;
        self.peering_key = offer.peering_key;
        self.transient_ids = offer.transient_ids;
        Ok(())
    }
}

/// Get message: "Send me these messages".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncGet {
    pub wanted_ids: Vec<Vec<u8>>,
}

impl SyncGet {
    pub fn new() -> Self {
        Self {
            wanted_ids: Vec::new(),
        }
    }
}

impl Default for SyncGet {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageBase for SyncGet {
    fn msg_type(&self) -> u16 {
        SYNC_MSG_GET
    }

    fn pack(&self) -> Vec<u8> {
        rmp_serde::to_vec(self).unwrap_or_default()
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        let get: SyncGet =
            rmp_serde::from_slice(raw).map_err(|_| ChannelMessageError::UnpackFailed)?;
        self.wanted_ids = get.wanted_ids;
        Ok(())
    }
}

/// Parsed offer response from a propagation node. Python: LXMPeer.py:396-439.
#[derive(Debug, Clone, PartialEq)]
pub enum OfferResponse {
    WantAll,
    HaveAll,
    WantSome(Vec<Vec<u8>>),
    ErrorNoIdentity,
    ErrorNoAccess,
    ErrorInvalidKey,
    ErrorThrottled,
    ErrorInvalidData,
    ErrorInvalidStamp,
    Unknown,
}

impl OfferResponse {
    pub fn from_msgpack(data: &[u8]) -> Self {
        let value: rmpv::Value = match rmpv::decode::read_value(&mut &data[..]) {
            Ok(v) => v,
            Err(_) => return OfferResponse::Unknown,
        };

        Self::from_value(&value)
    }

    pub fn from_value(value: &rmpv::Value) -> Self {
        if let Some(b) = value.as_bool() {
            return if b {
                OfferResponse::WantAll
            } else {
                OfferResponse::HaveAll
            };
        }

        if let Some(code) = value.as_u64() {
            return match code as u8 {
                0xF0 => OfferResponse::ErrorNoIdentity,
                0xF1 => OfferResponse::ErrorNoAccess,
                0xF3 => OfferResponse::ErrorInvalidKey,
                0xF4 => OfferResponse::ErrorInvalidData,
                0xF5 => OfferResponse::ErrorInvalidStamp,
                0xF6 => OfferResponse::ErrorThrottled,
                _ => OfferResponse::Unknown,
            };
        }

        if let Some(arr) = value.as_array() {
            let ids: Vec<Vec<u8>> = arr
                .iter()
                .filter_map(|v| v.as_slice().map(|s| s.to_vec()))
                .collect();
            if !ids.is_empty() {
                return OfferResponse::WantSome(ids);
            }
            return OfferResponse::HaveAll;
        }

        OfferResponse::Unknown
    }

    pub fn is_error(&self) -> bool {
        matches!(
            self,
            OfferResponse::ErrorNoIdentity
                | OfferResponse::ErrorNoAccess
                | OfferResponse::ErrorInvalidKey
                | OfferResponse::ErrorThrottled
                | OfferResponse::ErrorInvalidData
                | OfferResponse::ErrorInvalidStamp
        )
    }

    pub fn as_peer_error(&self) -> Option<PeerError> {
        match self {
            OfferResponse::ErrorNoIdentity => Some(PeerError::NoIdentity),
            OfferResponse::ErrorNoAccess => Some(PeerError::NoAccess),
            OfferResponse::ErrorInvalidKey => Some(PeerError::InvalidKey),
            OfferResponse::ErrorThrottled => Some(PeerError::Throttled),
            OfferResponse::ErrorInvalidData => Some(PeerError::InvalidData),
            OfferResponse::ErrorInvalidStamp => Some(PeerError::InvalidStamp),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct SyncSession {
    pub peer_hash: [u8; 16],
    pub state: SyncState,
    pub offered_ids: Vec<PropagationTransientId>,
    pub wanted_ids: Vec<PropagationTransientId>,
    pub transferred: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    OfferSent,
    Receiving,
    Sending,
    Complete,
    Failed,
}

impl SyncSession {
    pub fn new(peer_hash: [u8; 16]) -> Self {
        Self {
            peer_hash,
            state: SyncState::Idle,
            offered_ids: Vec::new(),
            wanted_ids: Vec::new(),
            transferred: 0,
        }
    }

    pub fn prepare_offer(
        &mut self,
        our_ids: Vec<PropagationTransientId>,
        peering_key: Vec<u8>,
    ) -> SyncOffer {
        self.offered_ids = our_ids.clone();
        self.state = SyncState::OfferSent;
        SyncOffer {
            peering_key,
            transient_ids: our_ids.into_iter().map(|id| id.to_vec()).collect(),
        }
    }

    /// Process a received offer; returns a SyncGet for IDs we don't have.
    pub fn process_offer(&mut self, offer: &SyncOffer, our_store: &PropagationStore) -> SyncGet {
        let wanted: Vec<Vec<u8>> = offer
            .transient_ids
            .iter()
            .filter(|id| {
                if id.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(id);
                    !our_store.contains(&arr)
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        self.state = SyncState::Receiving;
        SyncGet { wanted_ids: wanted }
    }

    pub fn process_get(&mut self, get: &SyncGet) {
        self.wanted_ids = get
            .wanted_ids
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
        self.state = SyncState::Sending;
    }

    pub fn mark_complete(&mut self) {
        self.state = SyncState::Complete;
    }

    pub fn mark_failed(&mut self) {
        self.state = SyncState::Failed;
    }

    pub fn record_transfer(&mut self) {
        self.transferred += 1;
    }

    pub fn is_finished(&self) -> bool {
        self.state == SyncState::Complete || self.state == SyncState::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::propagation::{PropagationEntry, PropagationStore};

    fn tid(byte: u8) -> PropagationTransientId {
        [byte; 32]
    }

    fn id(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn test_sync_offer_pack_unpack() {
        let offer = SyncOffer {
            peering_key: vec![0xDD; 32],
            transient_ids: vec![id(0xAA), id(0xBB), id(0xCC)],
        };

        let packed = offer.pack();
        assert!(!packed.is_empty());

        let mut unpacked = SyncOffer::new();
        unpacked.unpack(&packed).unwrap();
        assert_eq!(unpacked.peering_key, vec![0xDD; 32]);
        assert_eq!(unpacked.transient_ids.len(), 3);
        assert_eq!(unpacked.transient_ids[0], id(0xAA));
        assert_eq!(unpacked.transient_ids[1], id(0xBB));
        assert_eq!(unpacked.transient_ids[2], id(0xCC));
    }

    #[test]
    fn test_sync_get_pack_unpack() {
        let get = SyncGet {
            wanted_ids: vec![id(0x11), id(0x22)],
        };

        let packed = get.pack();
        assert!(!packed.is_empty());

        let mut unpacked = SyncGet::new();
        unpacked.unpack(&packed).unwrap();
        assert_eq!(unpacked.wanted_ids.len(), 2);
        assert_eq!(unpacked.wanted_ids[0], id(0x11));
        assert_eq!(unpacked.wanted_ids[1], id(0x22));
    }

    #[test]
    fn test_sync_offer_msg_type() {
        let offer = SyncOffer::new();
        assert_eq!(offer.msg_type(), SYNC_MSG_OFFER);
    }

    #[test]
    fn test_sync_get_msg_type() {
        let get = SyncGet::new();
        assert_eq!(get.msg_type(), SYNC_MSG_GET);
    }

    #[test]
    fn test_sync_session_offer_flow() {
        let peer_hash = [0xAA; 16];
        let mut session = SyncSession::new(peer_hash);
        assert_eq!(session.state, SyncState::Idle);

        let ids = vec![tid(0x01), tid(0x02), tid(0x03)];
        let offer = session.prepare_offer(ids.clone(), vec![0xFF; 32]);
        assert_eq!(session.state, SyncState::OfferSent);
        assert_eq!(offer.transient_ids.len(), 3);
        assert_eq!(session.offered_ids.len(), 3);
    }

    #[test]
    fn test_sync_session_process_offer() {
        let peer_hash = [0xBB; 16];
        let mut session = SyncSession::new(peer_hash);

        let mut store = PropagationStore::new();
        store.insert(PropagationEntry::new(tid(0x01), [0; 32], [0; 16], 100, 0));

        let offer = SyncOffer {
            peering_key: vec![0xFF; 32],
            transient_ids: vec![id(0x01), id(0x02), id(0x03)],
        };

        let get = session.process_offer(&offer, &store);
        assert_eq!(session.state, SyncState::Receiving);
        assert_eq!(get.wanted_ids.len(), 2);
        assert_eq!(get.wanted_ids[0], id(0x02));
        assert_eq!(get.wanted_ids[1], id(0x03));
    }

    #[test]
    fn test_sync_session_process_get() {
        let peer_hash = [0xCC; 16];
        let mut session = SyncSession::new(peer_hash);
        session.state = SyncState::OfferSent;

        let get = SyncGet {
            wanted_ids: vec![id(0x01), id(0x02)],
        };

        session.process_get(&get);
        assert_eq!(session.state, SyncState::Sending);
        assert_eq!(session.wanted_ids.len(), 2);
    }

    #[test]
    fn test_sync_session_complete() {
        let mut session = SyncSession::new([0xDD; 16]);
        session.state = SyncState::Sending;
        assert!(!session.is_finished());

        session.mark_complete();
        assert_eq!(session.state, SyncState::Complete);
        assert!(session.is_finished());
    }

    #[test]
    fn test_sync_session_failed() {
        let mut session = SyncSession::new([0xEE; 16]);
        session.state = SyncState::OfferSent;

        session.mark_failed();
        assert_eq!(session.state, SyncState::Failed);
        assert!(session.is_finished());
    }

    #[test]
    fn test_sync_session_transfer_tracking() {
        let mut session = SyncSession::new([0xFF; 16]);
        assert_eq!(session.transferred, 0);

        session.record_transfer();
        session.record_transfer();
        session.record_transfer();
        assert_eq!(session.transferred, 3);
    }

    #[test]
    fn test_sync_offer_empty() {
        let offer = SyncOffer::new();
        assert!(offer.transient_ids.is_empty());

        let packed = offer.pack();
        let mut unpacked = SyncOffer::new();
        unpacked.unpack(&packed).unwrap();
        assert!(unpacked.transient_ids.is_empty());
    }

    #[test]
    fn test_sync_get_empty() {
        let get = SyncGet::new();
        assert!(get.wanted_ids.is_empty());

        let packed = get.pack();
        let mut unpacked = SyncGet::new();
        unpacked.unpack(&packed).unwrap();
        assert!(unpacked.wanted_ids.is_empty());
    }

    #[test]
    fn test_sync_session_process_offer_empty_store() {
        let mut session = SyncSession::new([0xAA; 16]);
        let store = PropagationStore::new();

        let offer = SyncOffer {
            peering_key: vec![0xFF; 32],
            transient_ids: vec![id(0x01), id(0x02)],
        };

        let get = session.process_offer(&offer, &store);
        assert_eq!(get.wanted_ids.len(), 2);
    }

    #[test]
    fn test_sync_offer_invalid_length_ids() {
        let mut session = SyncSession::new([0xBB; 16]);
        let store = PropagationStore::new();

        let offer = SyncOffer {
            peering_key: vec![0xFF; 32],
            transient_ids: vec![vec![0x01; 16], vec![0x02; 8], id(0x03)],
        };

        let get = session.process_offer(&offer, &store);
        assert_eq!(get.wanted_ids.len(), 1);
    }

    #[test]
    fn test_sync_get_invalid_length_ids() {
        let mut session = SyncSession::new([0xCC; 16]);

        let get = SyncGet {
            wanted_ids: vec![id(0x01), vec![0x02; 10]],
        };

        session.process_get(&get);
        assert_eq!(session.wanted_ids.len(), 1);
    }

    #[test]
    fn test_offer_response_true() {
        // msgpack true = 0xC3
        let data = [0xC3];
        let resp = OfferResponse::from_msgpack(&data);
        assert_eq!(resp, OfferResponse::WantAll);
        assert!(!resp.is_error());
    }

    #[test]
    fn test_offer_response_false() {
        // msgpack false = 0xC2
        let data = [0xC2];
        let resp = OfferResponse::from_msgpack(&data);
        assert_eq!(resp, OfferResponse::HaveAll);
        assert!(!resp.is_error());
    }

    #[test]
    fn test_offer_response_error_no_identity() {
        // msgpack uint8 0xF0 = [0xCC, 0xF0]
        let data = [0xCC, 0xF0];
        let resp = OfferResponse::from_msgpack(&data);
        assert_eq!(resp, OfferResponse::ErrorNoIdentity);
        assert!(resp.is_error());
        assert_eq!(resp.as_peer_error(), Some(PeerError::NoIdentity));
    }

    #[test]
    fn test_offer_response_error_no_access() {
        let data = [0xCC, 0xF1];
        let resp = OfferResponse::from_msgpack(&data);
        assert_eq!(resp, OfferResponse::ErrorNoAccess);
        assert!(resp.is_error());
    }

    #[test]
    fn test_offer_response_error_invalid_key() {
        let data = [0xCC, 0xF3];
        let resp = OfferResponse::from_msgpack(&data);
        assert_eq!(resp, OfferResponse::ErrorInvalidKey);
        assert!(resp.is_error());
    }

    #[test]
    fn test_offer_response_error_throttled() {
        let data = [0xCC, 0xF6];
        let resp = OfferResponse::from_msgpack(&data);
        assert_eq!(resp, OfferResponse::ErrorThrottled);
        assert!(resp.is_error());
    }

    #[test]
    fn test_offer_response_want_some() {
        let id1 = id(0xAA);
        let id2 = id(0xBB);
        let value = rmpv::Value::Array(vec![
            rmpv::Value::Binary(id1.clone()),
            rmpv::Value::Binary(id2.clone()),
        ]);
        let resp = OfferResponse::from_value(&value);
        match resp {
            OfferResponse::WantSome(ids) => {
                assert_eq!(ids.len(), 2);
                assert_eq!(ids[0], id1);
                assert_eq!(ids[1], id2);
            }
            _ => panic!("expected WantSome"),
        }
    }

    #[test]
    fn test_offer_response_nil() {
        // msgpack nil = 0xC0
        let data = [0xC0];
        let resp = OfferResponse::from_msgpack(&data);
        assert_eq!(resp, OfferResponse::Unknown);
    }
}
