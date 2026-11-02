//! Announce handlers for `lxmf.delivery` and `lxmf.propagation` destinations, plus the
//! propagation-node control endpoint dispatcher.
//!
//! Related Python code: LXMF/Handlers.py, the announce helpers in LXMF.py,
//! and the request handlers in LXMRouter.py.

use std::collections::HashMap;

use crate::constants::*;
use crate::presentation::{MAX_ADVERTISED_NAME_CHARS, sanitize_name};

/// Announce handler type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerType {
    Delivery,
    Propagation,
}

impl HandlerType {
    /// Aspect filter for matching RNS destinations.
    pub fn aspect_filter(&self) -> &'static str {
        match self {
            HandlerType::Delivery => DELIVERY_ASPECT,
            HandlerType::Propagation => PROPAGATION_ASPECT,
        }
    }

    /// Fully-qualified `app_name.aspect` string.
    pub fn full_aspect(&self) -> String {
        format!("{}.{}", APP_NAME, self.aspect_filter())
    }
}

/// Outcome of processing an announce.
#[derive(Debug)]
pub enum AnnounceResult {
    Accepted,
    Ignored,
    Rejected(String),
}

/// Advertised delivery compression support from LXMF delivery-announce app data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionSupport {
    /// No explicit supported-functionality metadata was present or parseable.
    Unknown,
    /// A supported-functionality list was present and omitted `SF_COMPRESSION`.
    Unsupported,
    /// A supported-functionality list was present and included `SF_COMPRESSION`.
    Supported,
}

/// Parsed propagation-node announce data.
///
/// Wire layout is a 7-element msgpack array:
/// `[false, timebase, node_state, transfer_limit_kb, sync_limit_kb,
/// [stamp_cost, stamp_flex, peering_cost], metadata]`.
///
/// Python reference: `LXMRouter.get_propagation_node_app_data`.
#[derive(Debug, Clone)]
pub struct PropagationNodeAnnounceData {
    /// Compatibility field. The constructor/parser set it to false, and the
    /// encoder always writes false regardless of this field.
    pub legacy: bool,
    /// Node timebase as Unix seconds.
    pub timebase: i64,
    /// True when the node is actively serving propagation.
    pub node_state: bool,
    /// Per-transfer limit in decimal kilobytes (1 kB = 1000 bytes).
    pub transfer_limit: u64,
    /// Per-sync limit in decimal kilobytes (1 kB = 1000 bytes).
    pub sync_limit: u64,
    pub stamp_cost: u8,
    pub stamp_flex: u8,
    pub peering_cost: u8,
    pub metadata: HashMap<u8, Vec<u8>>,
}

impl PropagationNodeAnnounceData {
    pub fn new(
        node_state: bool,
        transfer_limit: u64,
        sync_limit: u64,
        stamp_cost: u8,
        stamp_flex: u8,
        peering_cost: u8,
    ) -> Self {
        Self {
            legacy: false,
            timebase: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            node_state,
            transfer_limit,
            sync_limit,
            stamp_cost,
            stamp_flex,
            peering_cost,
            metadata: HashMap::new(),
        }
    }

    pub fn set_name(&mut self, name: &str) {
        let name = sanitize_name(name, MAX_ADVERTISED_NAME_CHARS);
        if name.is_empty() {
            self.metadata.remove(&PN_META_NAME);
        } else {
            self.metadata.insert(PN_META_NAME, name.into_bytes());
        }
    }
}

/// Encode propagation-node announce `app_data` as msgpack.
///
/// Python reference: `LXMRouter.get_propagation_node_app_data`.
pub fn get_propagation_node_app_data(data: &PropagationNodeAnnounceData) -> Vec<u8> {
    use rmpv::Value;

    let stamp_costs = Value::Array(vec![
        Value::from(data.stamp_cost as u64),
        Value::from(data.stamp_flex as u64),
        Value::from(data.peering_cost as u64),
    ]);

    let metadata = {
        let mut map = Vec::new();
        for (k, v) in &data.metadata {
            map.push((Value::from(*k as u64), Value::Binary(v.clone())));
        }
        Value::Map(map)
    };

    let announce_data = Value::Array(vec![
        Value::Boolean(false),
        Value::from(data.timebase),
        Value::Boolean(data.node_state),
        Value::from(data.transfer_limit),
        Value::from(data.sync_limit),
        stamp_costs,
        metadata,
    ]);

    crate::encode_value(&announce_data)
}

/// Parse a propagation-node announce array with at least seven elements.
///
/// Requires a boolean state, numeric timebase, nonnegative finite limits/costs,
/// a cost array with at least three values, and a metadata map. Rust casts apply; costs must
/// fit in `u8` after conversion. The legacy slot is ignored. Only metadata with
/// `u8` keys and binary values is retained. Extra array elements and trailing
/// MessagePack bytes are not rejected.
///
/// This parser does not authenticate the announce or enforce timebase freshness.
/// Its coercion and filtering rules differ from Python `pn_announce_data_is_valid`.
pub fn parse_pn_announce_data(data: &[u8]) -> Option<PropagationNodeAnnounceData> {
    fn nonnegative_u64(value: &rmpv::Value) -> Option<u64> {
        value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|number| number.try_into().ok()))
            .or_else(|| {
                value.as_f64().and_then(|number| {
                    (number.is_finite() && number >= 0.0).then_some(number as u64)
                })
            })
    }

    let value: rmpv::Value = rmpv::decode::read_value(&mut &data[..]).ok()?;
    let arr = value.as_array()?;
    if arr.len() < 7 {
        return None;
    }

    let timebase = arr[1]
        .as_i64()
        .or_else(|| arr[1].as_u64().map(|u| u as i64))
        .or_else(|| arr[1].as_f64().map(|f| f as i64))?;
    let node_state = arr[2].as_bool()?;
    let transfer_limit = nonnegative_u64(&arr[3])?;
    let sync_limit = nonnegative_u64(&arr[4])?;

    let costs = arr[5].as_array()?;
    if costs.len() < 3 {
        return None;
    }
    let stamp_cost = u8::try_from(nonnegative_u64(&costs[0])?).ok()?;
    let stamp_flex = u8::try_from(nonnegative_u64(&costs[1])?).ok()?;
    let peering_cost = u8::try_from(nonnegative_u64(&costs[2])?).ok()?;

    // Python's `pn_announce_data_is_valid()` requires the metadata element to
    // be a map. Unknown keys and non-binary values are ignored here because
    // the typed Rust API can only retain metadata it can represent safely.
    let mut metadata = HashMap::new();
    for (k, v) in arr[6].as_map()? {
        if let (Some(key), Some(val)) = (
            k.as_u64().and_then(|number| number.try_into().ok()),
            v.as_slice().map(|s| s.to_vec()),
        ) {
            metadata.insert(key, val);
        }
    }

    Some(PropagationNodeAnnounceData {
        legacy: false,
        timebase,
        node_state,
        transfer_limit,
        sync_limit,
        stamp_cost,
        stamp_flex,
        peering_cost,
        metadata,
    })
}

/// Extract stamp cost from propagation-node announce data.
///
/// Uses [`parse_pn_announce_data`] and its numeric conversion rules.
pub fn pn_stamp_cost_from_app_data(data: &[u8]) -> Option<u8> {
    parse_pn_announce_data(data).map(|p| p.stamp_cost)
}

/// Encode delivery-announce `app_data` as msgpack
/// `[display_name, stamp_cost, supported_functionality]` where the feature
/// list advertises [`SF_COMPRESSION`].
///
/// `stamp_cost` must be in `1..=254`; out-of-range or `None` values are encoded as nil.
///
/// Names are sanitized and limited to [`MAX_ADVERTISED_NAME_CHARS`] characters.
/// Python reference: `LXMRouter.get_announce_app_data`.
pub fn get_announce_app_data(display_name: Option<&str>, stamp_cost: Option<u8>) -> Vec<u8> {
    use rmpv::Value;

    let name_val = display_name
        .map(|name| sanitize_name(name, MAX_ADVERTISED_NAME_CHARS))
        .filter(|name| !name.is_empty())
        .map_or(Value::Nil, |name| Value::Binary(name.into_bytes()));

    let cost_val = match stamp_cost {
        Some(cost) if cost > 0 && cost < 255 => Value::from(cost as u64),
        _ => Value::Nil,
    };

    let supported_functionality =
        Value::Array(vec![Value::from(crate::constants::SF_COMPRESSION as u64)]);

    let peer_data = Value::Array(vec![name_val, cost_val, supported_functionality]);

    crate::encode_value(&peer_data)
}

/// Parse delivery-announce `app_data`, returning `(display_name, stamp_cost)`.
///
/// Requires an array with at least two elements; later elements are ignored.
/// A binary UTF-8 name is sanitized and bounded. Unsigned stamp costs are cast
/// to `u8`, retaining the low byte; this does not apply the encoder's `1..=254`
/// filter. Original raw-text announce names are not parsed by this helper.
pub fn parse_announce_app_data(data: &[u8]) -> Option<(Option<String>, Option<u8>)> {
    let value: rmpv::Value = rmpv::decode::read_value(&mut &data[..]).ok()?;
    let arr = value.as_array()?;
    if arr.len() < 2 {
        return None;
    }

    let display_name = arr[0]
        .as_slice()
        .and_then(|b| String::from_utf8(b.to_vec()).ok())
        .map(|name| sanitize_name(&name, MAX_ADVERTISED_NAME_CHARS))
        .filter(|name| !name.is_empty());

    let stamp_cost = arr[1].as_u64().map(|c| c as u8);

    Some((display_name, stamp_cost))
}

/// Extract just the display name from delivery-announce `app_data`.
///
/// Uses [`parse_announce_app_data`], including its name sanitization and array-only format.
pub fn display_name_from_app_data(data: &[u8]) -> Option<String> {
    parse_announce_app_data(data).and_then(|(name, _)| name)
}

/// Extract just the stamp cost from delivery-announce `app_data`.
///
/// Uses [`parse_announce_app_data`], including its unsigned-to-`u8` cast.
pub fn stamp_cost_from_app_data(data: &[u8]) -> Option<u8> {
    parse_announce_app_data(data).and_then(|(_, cost)| cost)
}

/// Parse advertised `SF_COMPRESSION` support in delivery-announce `app_data`.
///
/// Legacy 2-element app_data, malformed data, and missing feature lists are
/// treated as unknown. A present feature list is authoritative.
///
/// Related Python helper: `compression_support_from_app_data`.
pub fn compression_support_state_from_app_data(data: &[u8]) -> CompressionSupport {
    let Ok(value) = rmpv::decode::read_value(&mut &data[..]) else {
        return CompressionSupport::Unknown;
    };
    let Some(arr) = value.as_array() else {
        return CompressionSupport::Unknown;
    };
    if arr.len() < 3 {
        return CompressionSupport::Unknown;
    }
    let Some(features) = arr[2].as_array() else {
        return CompressionSupport::Unknown;
    };

    if features
        .iter()
        .any(|f| f.as_u64() == Some(crate::constants::SF_COMPRESSION as u64))
    {
        CompressionSupport::Supported
    } else {
        CompressionSupport::Unsupported
    }
}

/// Check whether a peer advertises `SF_COMPRESSION` support in its delivery-announce `app_data`.
///
/// Returns true for Supported or Unknown, including empty/malformed input and
/// missing or non-list feature metadata. Only a present feature list without
/// `SF_COMPRESSION` returns false. This boolean default differs from Python
/// helper cases that return `None` or raise a decode error.
pub fn compression_support_from_app_data(data: &[u8]) -> bool {
    compression_support_state_from_app_data(data) != CompressionSupport::Unsupported
}

/// Extract the advertised name from propagation-node announce data.
///
/// Reads binary [`PN_META_NAME`] metadata, decodes UTF-8, then sanitizes and
/// bounds the name. Returns `None` if parsing fails or the result is empty.
pub fn pn_name_from_app_data(data: &[u8]) -> Option<String> {
    let parsed = parse_pn_announce_data(data)?;
    let name_bytes = parsed.metadata.get(&crate::constants::PN_META_NAME)?;
    String::from_utf8(name_bytes.clone())
        .ok()
        .map(|name| sanitize_name(&name, MAX_ADVERTISED_NAME_CHARS))
        .filter(|name| !name.is_empty())
}

/// Outcome of a resource transfer, matching Python `resource_concluded` /
/// `propagation_resource_concluded` callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceResult {
    Complete,
    Rejected,
    Failed,
}

/// Propagation-node control endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlEndpoint {
    Stats,
    PeerSync,
    PeerUnpeer,
}

impl ControlEndpoint {
    pub fn path(&self) -> &'static str {
        match self {
            ControlEndpoint::Stats => STATS_GET_PATH,
            ControlEndpoint::PeerSync => SYNC_REQUEST_PATH,
            ControlEndpoint::PeerUnpeer => UNPEER_REQUEST_PATH,
        }
    }
}

/// Outcome of a control-endpoint request.
#[derive(Debug)]
pub enum ControlResult {
    Success(Vec<u8>),
    NoIdentity,
    NoAccess,
    InvalidData,
    NotFound,
}

/// Propagation-node request handler.
///
/// Provides handlers for `/pn/get/stats`, `/offer`, `/get`, `/pn/peer/sync` and
/// `/pn/peer/unpeer`. The embedder must supply identities already verified by
/// the Link; these methods accept identity hashes and do not authenticate them.
/// Sync/unpeer handlers authorize a request; the caller performs those actions.
pub struct PropagationRequestHandler {
    pub local_identity_hash: [u8; 16],
    pub control_allowed: Vec<[u8; 16]>,
    /// When true, offers require the supplied remote identity hash to be in
    /// [`static_peers`](Self::static_peers). This helper uses identity hashes.
    pub from_static_only: bool,
    pub static_peers: std::collections::HashSet<[u8; 16]>,
    /// Supplied remote identity hashes mapped to throttle-expiry Unix timestamps.
    pub throttled_peers: HashMap<[u8; 16], f64>,
}

impl PropagationRequestHandler {
    /// Create a handler with the local identity hash in its initial control allowlist.
    /// The allowlist remains mutable, including removal of that identity.
    pub fn new(identity_hash: [u8; 16]) -> Self {
        Self {
            local_identity_hash: identity_hash,
            control_allowed: vec![identity_hash],
            from_static_only: false,
            static_peers: std::collections::HashSet::new(),
            throttled_peers: HashMap::new(),
        }
    }

    /// Return MessagePack stats when the supplied verified identity is control-allowed.
    ///
    /// Related Python handler: `LXMRouter.stats_get_request`.
    pub fn handle_stats_request(
        &self,
        remote_identity_hash: Option<&[u8; 16]>,
        node: &crate::propagation_node::PropagationNode,
        peers: &HashMap<[u8; 16], crate::peer::LxmPeer>,
    ) -> ControlResult {
        let identity_hash = match remote_identity_hash {
            Some(h) => h,
            None => return ControlResult::NoIdentity,
        };

        if !self.control_allowed.contains(identity_hash) {
            return ControlResult::NoAccess;
        }

        let stats = self.compile_stats(node, peers);
        ControlResult::Success(stats)
    }

    /// Handle an `/offer` request from a syncing peer.
    ///
    /// Build identity-presence, throttle and static-access context, then delegate
    /// decoding and peering-key checks to
    /// [`crate::propagation_node::PropagationNode::handle_offer_request`].
    /// Supply an already verified remote identity; this helper does not verify it.
    pub fn handle_offer_request(
        &self,
        remote_identity_hash: Option<&[u8; 16]>,
        request_data: &[u8],
        node: &mut crate::propagation_node::PropagationNode,
    ) -> Vec<u8> {
        let identity_known = remote_identity_hash.is_some();

        let is_throttled = remote_identity_hash
            .map(|h| {
                self.throttled_peers
                    .get(h)
                    .map(|expiry| now_f64() < *expiry)
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        let access_allowed = if self.from_static_only {
            remote_identity_hash
                .map(|h| self.static_peers.contains(h))
                .unwrap_or(false)
        } else {
            true
        };

        node.handle_offer_request(
            request_data,
            crate::propagation_node::OfferRequestContext {
                peer_hash: remote_identity_hash.copied().unwrap_or([0u8; 16]),
                identity_known,
                is_throttled,
                access_allowed,
                local_identity_hash: Some(&self.local_identity_hash),
                remote_identity_hash,
            },
        )
    }

    /// Handle a `/get` request from a client downloading messages. Phase-2
    /// responses come back as a
    /// [`GetRequestAction::ServeFiles`](crate::propagation_node::GetRequestAction::ServeFiles)
    /// plan — the embedder resolves it after releasing the node lock.
    ///
    /// The caller must derive `client_dest_hash` from the verified remote identity
    /// and enforce its access policy. This helper checks only that an identity
    /// was supplied; it does not bind the two arguments.
    pub fn handle_message_get_request(
        &self,
        remote_identity_hash: Option<&[u8; 16]>,
        client_dest_hash: &[u8; 16],
        request_data: &[u8],
        node: &mut crate::propagation_node::PropagationNode,
    ) -> crate::propagation_node::GetRequestAction {
        use crate::propagation_node::GetRequestAction;
        use rmpv::Value;

        let _identity_hash = match remote_identity_hash {
            Some(h) => h,
            None => {
                let error = Value::from(PeerError::NoIdentity as u64);
                return GetRequestAction::Respond(crate::encode_value(&error));
            }
        };

        node.handle_get_request(request_data, client_dest_hash)
    }

    /// Handle a `/pn/peer/sync` request. Returns msgpack `true` on success; the caller performs
    /// the actual sync trigger.
    ///
    /// Related Python handler: `LXMRouter.peer_sync_request`.
    pub fn handle_peer_sync_request(
        &self,
        remote_identity_hash: Option<&[u8; 16]>,
        request_data: &[u8],
        peers: &HashMap<[u8; 16], crate::peer::LxmPeer>,
    ) -> ControlResult {
        let identity_hash = match remote_identity_hash {
            Some(h) => h,
            None => return ControlResult::NoIdentity,
        };

        if !self.control_allowed.contains(identity_hash) {
            return ControlResult::NoAccess;
        }

        if request_data.len() != 16 {
            return ControlResult::InvalidData;
        }

        let mut peer_hash = [0u8; 16];
        peer_hash.copy_from_slice(request_data);

        if !peers.contains_key(&peer_hash) {
            return ControlResult::NotFound;
        }

        ControlResult::Success(crate::encode_value(&rmpv::Value::Boolean(true)))
    }

    /// Handle a `/pn/peer/unpeer` request. Returns msgpack `true` on success; the caller performs
    /// the actual peer removal.
    ///
    /// Related Python handler: `LXMRouter.peer_unpeer_request`.
    pub fn handle_peer_unpeer_request(
        &self,
        remote_identity_hash: Option<&[u8; 16]>,
        request_data: &[u8],
        peers: &HashMap<[u8; 16], crate::peer::LxmPeer>,
    ) -> ControlResult {
        let identity_hash = match remote_identity_hash {
            Some(h) => h,
            None => return ControlResult::NoIdentity,
        };

        if !self.control_allowed.contains(identity_hash) {
            return ControlResult::NoAccess;
        }

        if request_data.len() != 16 {
            return ControlResult::InvalidData;
        }

        let mut peer_hash = [0u8; 16];
        peer_hash.copy_from_slice(request_data);

        if !peers.contains_key(&peer_hash) {
            return ControlResult::NotFound;
        }

        ControlResult::Success(crate::encode_value(&rmpv::Value::Boolean(true)))
    }

    pub fn cleanup_throttled_peers(&mut self) {
        let now = now_f64();
        self.throttled_peers.retain(|_, expiry| *expiry > now);
    }

    /// Throttle `peer_hash` for `duration_secs` starting now.
    ///
    /// Related Python handler: `LXMRouter.propagation_resource_concluded`.
    pub fn throttle_peer(&mut self, peer_hash: [u8; 16], duration_secs: f64) {
        let expiry = now_f64() + duration_secs;
        self.throttled_peers.insert(peer_hash, expiry);
    }

    pub fn is_peer_throttled(&self, peer_hash: &[u8; 16]) -> bool {
        self.throttled_peers
            .get(peer_hash)
            .map(|expiry| now_f64() < *expiry)
            .unwrap_or(false)
    }

    pub fn allow_control(&mut self, identity_hash: [u8; 16]) {
        if !self.control_allowed.contains(&identity_hash) {
            self.control_allowed.push(identity_hash);
        }
    }

    pub fn disallow_control(&mut self, identity_hash: &[u8; 16]) {
        self.control_allowed.retain(|h| h != identity_hash);
    }

    /// Compile propagation-node statistics as msgpack.
    ///
    /// Python reference: `LXMRouter.compile_stats` — LXMRouter.py:750-817.
    fn compile_stats(
        &self,
        node: &crate::propagation_node::PropagationNode,
        peers: &HashMap<[u8; 16], crate::peer::LxmPeer>,
    ) -> Vec<u8> {
        use rmpv::Value;

        let mut peer_entries = Vec::new();
        for (hash, peer) in peers {
            let peer_map = Value::Map(vec![
                (
                    Value::String("state".into()),
                    Value::from(peer.state as u64),
                ),
                (Value::String("alive".into()), Value::Boolean(peer.alive)),
                (
                    Value::String("last_heard".into()),
                    Value::from(peer.last_heard as i64),
                ),
                (
                    Value::String("str".into()),
                    Value::from(peer.sync_transfer_rate as i64),
                ),
                (Value::String("rx_bytes".into()), Value::from(peer.rx_bytes)),
                (Value::String("tx_bytes".into()), Value::from(peer.tx_bytes)),
                (Value::String("offered".into()), Value::from(peer.offered)),
                (Value::String("outgoing".into()), Value::from(peer.outgoing)),
                (Value::String("incoming".into()), Value::from(peer.incoming)),
                (
                    Value::String("unhandled".into()),
                    Value::from(peer.unhandled_messages() as u64),
                ),
            ]);
            peer_entries.push((Value::Binary(hash.to_vec()), peer_map));
        }

        let stats = Value::Map(vec![
            (
                Value::String("destination_hash".into()),
                Value::Binary(node.dest_hash.to_vec()),
            ),
            (
                Value::String("message_count".into()),
                Value::from(node.message_count() as u64),
            ),
            (
                Value::String("message_size".into()),
                Value::from(node.total_size() as u64),
            ),
            (
                Value::String("total_peers".into()),
                Value::from(peers.len() as u64),
            ),
            (Value::String("peers".into()), Value::Map(peer_entries)),
        ]);

        crate::encode_value(&stats)
    }
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
    fn test_handler_aspects() {
        assert_eq!(HandlerType::Delivery.aspect_filter(), "delivery");
        assert_eq!(HandlerType::Propagation.aspect_filter(), "propagation");
        assert_eq!(HandlerType::Delivery.full_aspect(), "lxmf.delivery");
        assert_eq!(HandlerType::Propagation.full_aspect(), "lxmf.propagation");
    }

    #[test]
    fn test_pn_announce_data_roundtrip() {
        let mut data = PropagationNodeAnnounceData::new(
            true,
            PROPAGATION_LIMIT as u64,
            SYNC_LIMIT as u64,
            PROPAGATION_COST,
            PROPAGATION_COST_FLEX,
            PEERING_COST,
        );
        data.set_name("TestNode");

        let packed = get_propagation_node_app_data(&data);
        let parsed = parse_pn_announce_data(&packed).unwrap();
        assert!(!parsed.legacy);
        assert!(parsed.node_state);
        assert_eq!(parsed.transfer_limit, PROPAGATION_LIMIT as u64);
        assert_eq!(parsed.sync_limit, SYNC_LIMIT as u64);
        assert_eq!(parsed.stamp_cost, PROPAGATION_COST);
        assert_eq!(parsed.stamp_flex, PROPAGATION_COST_FLEX);
        assert_eq!(parsed.peering_cost, PEERING_COST);
        assert_eq!(
            parsed.metadata.get(&PN_META_NAME),
            Some(&b"TestNode".to_vec())
        );
    }

    #[test]
    fn test_pn_announce_data_accepts_python_float_fields() {
        use rmpv::Value;

        let value = Value::Array(vec![
            Value::Boolean(false),
            Value::F64(1_777_716_440.197976),
            Value::Boolean(true),
            Value::F64(10240.0),
            Value::F64(10240.0),
            Value::Array(vec![Value::from(16), Value::from(3), Value::from(18)]),
            Value::Map(vec![]),
        ]);
        let mut packed = Vec::new();
        rmpv::encode::write_value(&mut packed, &value).unwrap();

        let parsed = parse_pn_announce_data(&packed).unwrap();
        assert!(parsed.node_state);
        assert_eq!(parsed.transfer_limit, 10240);
        assert_eq!(parsed.sync_limit, 10240);
        assert_eq!(parsed.stamp_cost, 16);
    }

    #[test]
    fn test_pn_announce_data_invalid() {
        // Empty bytes, 1-element array, single int — all rejected by the
        // parser (same rejection set as Python's pn_announce_data_is_valid).
        assert!(parse_pn_announce_data(&[]).is_none());
        assert!(parse_pn_announce_data(&[0x91, 0xC2]).is_none());
        assert!(parse_pn_announce_data(&[0x01]).is_none());

        let non_map_metadata = rmpv::Value::Array(vec![
            rmpv::Value::Boolean(false),
            rmpv::Value::from(1_777_716_440u64),
            rmpv::Value::Boolean(true),
            rmpv::Value::from(10_240),
            rmpv::Value::from(10_240),
            rmpv::Value::Array(vec![
                rmpv::Value::from(16),
                rmpv::Value::from(3),
                rmpv::Value::from(18),
            ]),
            rmpv::Value::Array(Vec::new()),
        ]);
        assert!(
            parse_pn_announce_data(&crate::encode_value(&non_map_metadata)).is_none(),
            "Python rejects propagation announces whose metadata is not a map"
        );
    }

    #[test]
    fn test_pn_announce_data_rejects_wrapping_policy_values() {
        use rmpv::Value;

        let encode = |transfer_limit: Value, stamp_cost: Value| {
            let value = Value::Array(vec![
                Value::Boolean(false),
                Value::from(1_777_716_440u64),
                Value::Boolean(true),
                transfer_limit,
                Value::from(10240),
                Value::Array(vec![stamp_cost, Value::from(3), Value::from(18)]),
                Value::Map(vec![]),
            ]);
            let mut packed = Vec::new();
            rmpv::encode::write_value(&mut packed, &value).unwrap();
            packed
        };

        assert!(parse_pn_announce_data(&encode(Value::from(-1), Value::from(16))).is_none());
        assert!(parse_pn_announce_data(&encode(Value::from(10240), Value::from(256))).is_none());
    }

    #[test]
    fn test_pn_stamp_cost_extraction() {
        let data = PropagationNodeAnnounceData::new(
            true,
            PROPAGATION_LIMIT as u64,
            SYNC_LIMIT as u64,
            20,
            3,
            18,
        );
        let packed = get_propagation_node_app_data(&data);
        assert_eq!(pn_stamp_cost_from_app_data(&packed), Some(20));
    }

    #[test]
    fn test_delivery_announce_data_roundtrip() {
        let packed = get_announce_app_data(Some("Alice"), Some(12));
        let (name, cost) = parse_announce_app_data(&packed).unwrap();
        assert_eq!(name, Some("Alice".to_string()));
        assert_eq!(cost, Some(12));
    }

    #[test]
    fn test_delivery_announce_data_matches_python_101_bytes() {
        // Python 1.0.1 oracle: msgpack([b"Test", 16, [SF_COMPRESSION]]) — LXMRouter.py:999-1001.
        assert_eq!(
            hex::encode(get_announce_app_data(Some("Test"), Some(16))),
            "93c40454657374109100"
        );
        assert_eq!(hex::encode(get_announce_app_data(None, None)), "93c0c09100");
    }

    #[test]
    fn test_delivery_announce_data_no_name() {
        let packed = get_announce_app_data(None, Some(8));
        let (name, cost) = parse_announce_app_data(&packed).unwrap();
        assert!(name.is_none());
        assert_eq!(cost, Some(8));
    }

    #[test]
    fn test_delivery_announce_data_no_cost() {
        let packed = get_announce_app_data(Some("Bob"), None);
        let (name, cost) = parse_announce_app_data(&packed).unwrap();
        assert_eq!(name, Some("Bob".to_string()));
        assert!(cost.is_none());
    }

    #[test]
    fn test_delivery_announce_data_empty() {
        let packed = get_announce_app_data(None, None);
        let (name, cost) = parse_announce_app_data(&packed).unwrap();
        assert!(name.is_none());
        assert!(cost.is_none());
    }

    #[test]
    fn test_delivery_announce_data_cost_zero_treated_as_none() {
        let packed = get_announce_app_data(Some("Test"), Some(0));
        let (name, cost) = parse_announce_app_data(&packed).unwrap();
        assert_eq!(name, Some("Test".to_string()));
        assert!(cost.is_none());
    }

    #[test]
    fn test_display_name_from_app_data() {
        let packed = get_announce_app_data(Some("Alice"), Some(12));
        assert_eq!(
            display_name_from_app_data(&packed),
            Some("Alice".to_string())
        );

        let packed = get_announce_app_data(None, Some(12));
        assert_eq!(display_name_from_app_data(&packed), None);
    }

    #[test]
    fn test_display_name_from_app_data_strips_null_bytes_and_whitespace() {
        let packed = get_announce_app_data(Some(" \0Alice\0 "), Some(12));
        assert_eq!(
            display_name_from_app_data(&packed),
            Some("Alice".to_string())
        );
    }

    #[test]
    fn test_display_name_from_app_data_sanitizes_untrusted_unicode() {
        let packed = get_announce_app_data(
            Some("  Ａlice\u{202e}\u{e000}\u{1f680}\nNetwork  "),
            Some(12),
        );
        assert_eq!(
            display_name_from_app_data(&packed),
            Some("AliceNetwork".to_string())
        );
    }

    #[test]
    fn test_stamp_cost_from_app_data() {
        let packed = get_announce_app_data(Some("Alice"), Some(12));
        assert_eq!(stamp_cost_from_app_data(&packed), Some(12));

        let packed = get_announce_app_data(Some("Alice"), None);
        assert_eq!(stamp_cost_from_app_data(&packed), None);
    }

    #[test]
    fn test_compression_support_from_app_data() {
        // Legacy <=0.9.8 2-element app_data: unknown state, fail-open true
        // (Python returns True for len < 3 — LXMF.py:161).
        let python_098 = {
            use rmpv::Value;
            let arr = Value::Array(vec![Value::Binary(b"Alice".to_vec()), Value::from(12u64)]);
            crate::encode_value(&arr)
        };
        assert_eq!(
            compression_support_state_from_app_data(&python_098),
            CompressionSupport::Unknown
        );
        assert!(compression_support_from_app_data(&python_098));

        let supported = {
            use rmpv::Value;
            let arr = Value::Array(vec![
                Value::Binary(b"Alice".to_vec()),
                Value::from(12u64),
                Value::Array(vec![Value::from(crate::constants::SF_COMPRESSION as u64)]),
            ]);
            crate::encode_value(&arr)
        };
        assert_eq!(
            compression_support_state_from_app_data(&supported),
            CompressionSupport::Supported
        );
        assert!(compression_support_from_app_data(&supported));

        let ratspeak_extended_supported = {
            use rmpv::Value;
            let arr = Value::Array(vec![
                Value::Binary(b"Alice".to_vec()),
                Value::from(12u64),
                Value::Array(vec![Value::from(crate::constants::SF_COMPRESSION as u64)]),
                Value::Map(vec![]),
            ]);
            crate::encode_value(&arr)
        };
        assert_eq!(
            compression_support_state_from_app_data(&ratspeak_extended_supported),
            CompressionSupport::Supported
        );
        assert!(compression_support_from_app_data(
            &ratspeak_extended_supported
        ));

        // 3-element form with empty feature list -> unsupported.
        let empty_features = {
            use rmpv::Value;
            let arr = Value::Array(vec![
                Value::Binary(b"Alice".to_vec()),
                Value::from(12u64),
                Value::Array(vec![]),
            ]);
            crate::encode_value(&arr)
        };
        assert_eq!(
            compression_support_state_from_app_data(&empty_features),
            CompressionSupport::Unsupported
        );
        assert!(!compression_support_from_app_data(&empty_features));

        // Malformed data: unknown state, fail-open true (Python treats the
        // original non-msgpack announce format as supported — LXMF.py:167).
        assert_eq!(
            compression_support_state_from_app_data(&[0xc1]),
            CompressionSupport::Unknown
        );
        assert!(compression_support_from_app_data(&[0xc1]));

        // Our own 1.0.1 emission round-trips as explicitly supported.
        let own = get_announce_app_data(Some("Alice"), Some(12));
        assert_eq!(
            compression_support_state_from_app_data(&own),
            CompressionSupport::Supported
        );
    }

    #[test]
    fn test_pn_name_from_app_data() {
        let mut data = PropagationNodeAnnounceData::new(
            true,
            PROPAGATION_LIMIT as u64,
            SYNC_LIMIT as u64,
            20,
            3,
            18,
        );
        data.metadata
            .insert(crate::constants::PN_META_NAME, b"HubNode".to_vec());
        let packed = get_propagation_node_app_data(&data);
        assert_eq!(pn_name_from_app_data(&packed), Some("HubNode".to_string()));
    }

    #[test]
    fn test_pn_node_state_false() {
        let data = PropagationNodeAnnounceData::new(false, 256, 10240, 16, 3, 18);
        let packed = get_propagation_node_app_data(&data);
        let parsed = parse_pn_announce_data(&packed).unwrap();
        assert!(!parsed.node_state);
    }

    #[test]
    fn test_pn_empty_metadata() {
        let data = PropagationNodeAnnounceData::new(true, 256, 10240, 16, 3, 18);
        let packed = get_propagation_node_app_data(&data);
        let parsed = parse_pn_announce_data(&packed).unwrap();
        assert!(parsed.metadata.is_empty());
    }

    #[test]
    fn test_resource_result() {
        assert_ne!(ResourceResult::Complete, ResourceResult::Rejected);
        assert_ne!(ResourceResult::Complete, ResourceResult::Failed);
    }

    #[test]
    fn test_control_endpoint_paths() {
        assert_eq!(ControlEndpoint::Stats.path(), "/pn/get/stats");
        assert_eq!(ControlEndpoint::PeerSync.path(), "/pn/peer/sync");
        assert_eq!(ControlEndpoint::PeerUnpeer.path(), "/pn/peer/unpeer");
    }

    #[test]
    fn test_propagation_handler_creation() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        assert_eq!(handler.control_allowed.len(), 1);
        assert_eq!(handler.control_allowed[0], [0xAA; 16]);
        assert!(!handler.from_static_only);
        assert!(handler.static_peers.is_empty());
        assert!(handler.throttled_peers.is_empty());
    }

    #[test]
    fn test_stats_request_no_identity() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        let node = crate::propagation_node::PropagationNode::new(
            crate::propagation_node::PropagationNodeConfig::default(),
            [0xBB; 16],
        );
        let peers = HashMap::new();

        let result = handler.handle_stats_request(None, &node, &peers);
        assert!(matches!(result, ControlResult::NoIdentity));
    }

    #[test]
    fn test_stats_request_no_access() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        let node = crate::propagation_node::PropagationNode::new(
            crate::propagation_node::PropagationNodeConfig::default(),
            [0xBB; 16],
        );
        let peers = HashMap::new();
        let unauthorized = [0xCC; 16];

        let result = handler.handle_stats_request(Some(&unauthorized), &node, &peers);
        assert!(matches!(result, ControlResult::NoAccess));
    }

    #[test]
    fn test_stats_request_success() {
        let identity = [0xAA; 16];
        let handler = PropagationRequestHandler::new(identity);
        let node = crate::propagation_node::PropagationNode::new(
            crate::propagation_node::PropagationNodeConfig::default(),
            [0xBB; 16],
        );
        let peers = HashMap::new();

        let result = handler.handle_stats_request(Some(&identity), &node, &peers);
        match result {
            ControlResult::Success(data) => {
                let value: rmpv::Value = rmpv::decode::read_value(&mut &data[..]).unwrap();
                assert!(value.is_map());
            }
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn test_offer_request_handler_no_identity() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        let mut node = crate::propagation_node::PropagationNode::new(
            crate::propagation_node::PropagationNodeConfig::default(),
            [0xBB; 16],
        );

        let offer_data = {
            use rmpv::Value;
            let arr = Value::Array(vec![Value::Binary(vec![]), Value::Array(vec![])]);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &arr).unwrap();
            buf
        };

        let response = handler.handle_offer_request(None, &offer_data, &mut node);
        let value: rmpv::Value = rmpv::decode::read_value(&mut &response[..]).unwrap();
        assert_eq!(value.as_u64(), Some(PeerError::NoIdentity as u64));
    }

    #[test]
    fn test_offer_request_handler_success() {
        let local_identity = [0xAA; 16];
        let peer_hash = [0xCC; 16];
        let cost = 8;
        let handler = PropagationRequestHandler::new(local_identity);
        let mut node = crate::propagation_node::PropagationNode::new(
            crate::propagation_node::PropagationNodeConfig {
                peering_cost: cost,
                ..Default::default()
            },
            [0xBB; 16],
        );

        let peering_key = {
            let mut peering_id = Vec::with_capacity(32);
            peering_id.extend_from_slice(&local_identity);
            peering_id.extend_from_slice(&peer_hash);
            crate::stamper::generate_stamp(
                &peering_id,
                cost,
                crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING,
            )
            .unwrap()
            .0
        };

        let offer_data = {
            use rmpv::Value;
            let arr = Value::Array(vec![
                Value::Binary(peering_key.to_vec()),
                Value::Array(vec![]),
            ]);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &arr).unwrap();
            buf
        };

        let response = handler.handle_offer_request(Some(&peer_hash), &offer_data, &mut node);
        // Empty offer against empty store -> HaveAll (false).
        let value: rmpv::Value = rmpv::decode::read_value(&mut &response[..]).unwrap();
        assert_eq!(value.as_bool(), Some(false));
    }

    #[test]
    fn test_message_get_request_no_identity() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        let mut node = crate::propagation_node::PropagationNode::new(
            crate::propagation_node::PropagationNodeConfig::default(),
            [0xBB; 16],
        );
        let client_dest = [0xCC; 16];

        let request_data = {
            use rmpv::Value;
            let arr = Value::Array(vec![Value::Nil, Value::Nil]);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &arr).unwrap();
            buf
        };

        let response = handler
            .handle_message_get_request(None, &client_dest, &request_data, &mut node)
            .into_response();
        let value: rmpv::Value = rmpv::decode::read_value(&mut &response[..]).unwrap();
        assert_eq!(value.as_u64(), Some(PeerError::NoIdentity as u64));
    }

    #[test]
    fn test_message_get_request_list_phase() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        let mut node = crate::propagation_node::PropagationNode::new(
            crate::propagation_node::PropagationNodeConfig::default(),
            [0xBB; 16],
        );
        let identity = [0xDD; 16];
        let client_dest = [0xCC; 16];

        // List phase request: [nil, nil].
        let request_data = {
            use rmpv::Value;
            let arr = Value::Array(vec![Value::Nil, Value::Nil]);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &arr).unwrap();
            buf
        };

        let response = handler
            .handle_message_get_request(Some(&identity), &client_dest, &request_data, &mut node)
            .into_response();
        let value: rmpv::Value = rmpv::decode::read_value(&mut &response[..]).unwrap();
        let arr = value.as_array().unwrap();
        assert!(arr.is_empty());
    }

    #[test]
    fn test_peer_sync_request_no_identity() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        let peers = HashMap::new();

        let result = handler.handle_peer_sync_request(None, &[0xBB; 16], &peers);
        assert!(matches!(result, ControlResult::NoIdentity));
    }

    #[test]
    fn test_peer_sync_request_no_access() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        let peers = HashMap::new();
        let unauthorized = [0xCC; 16];

        let result = handler.handle_peer_sync_request(Some(&unauthorized), &[0xBB; 16], &peers);
        assert!(matches!(result, ControlResult::NoAccess));
    }

    #[test]
    fn test_peer_sync_request_invalid_data() {
        let identity = [0xAA; 16];
        let handler = PropagationRequestHandler::new(identity);
        let peers = HashMap::new();

        let result = handler.handle_peer_sync_request(Some(&identity), &[0xBB; 8], &peers);
        assert!(matches!(result, ControlResult::InvalidData));
    }

    #[test]
    fn test_peer_sync_request_not_found() {
        let identity = [0xAA; 16];
        let handler = PropagationRequestHandler::new(identity);
        let peers = HashMap::new();

        let result = handler.handle_peer_sync_request(Some(&identity), &[0xBB; 16], &peers);
        assert!(matches!(result, ControlResult::NotFound));
    }

    #[test]
    fn test_peer_sync_request_success() {
        let identity = [0xAA; 16];
        let handler = PropagationRequestHandler::new(identity);
        let peer_hash = [0xBB; 16];
        let mut peers = HashMap::new();
        peers.insert(peer_hash, crate::peer::LxmPeer::new(peer_hash));

        let result = handler.handle_peer_sync_request(Some(&identity), &peer_hash, &peers);
        match result {
            ControlResult::Success(data) => {
                let value: rmpv::Value = rmpv::decode::read_value(&mut &data[..]).unwrap();
                assert_eq!(value.as_bool(), Some(true));
            }
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn test_peer_unpeer_request_no_identity() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        let peers = HashMap::new();

        let result = handler.handle_peer_unpeer_request(None, &[0xBB; 16], &peers);
        assert!(matches!(result, ControlResult::NoIdentity));
    }

    #[test]
    fn test_peer_unpeer_request_no_access() {
        let handler = PropagationRequestHandler::new([0xAA; 16]);
        let peers = HashMap::new();
        let unauthorized = [0xCC; 16];

        let result = handler.handle_peer_unpeer_request(Some(&unauthorized), &[0xBB; 16], &peers);
        assert!(matches!(result, ControlResult::NoAccess));
    }

    #[test]
    fn test_peer_unpeer_request_not_found() {
        let identity = [0xAA; 16];
        let handler = PropagationRequestHandler::new(identity);
        let peers = HashMap::new();

        let result = handler.handle_peer_unpeer_request(Some(&identity), &[0xBB; 16], &peers);
        assert!(matches!(result, ControlResult::NotFound));
    }

    #[test]
    fn test_peer_unpeer_request_success() {
        let identity = [0xAA; 16];
        let handler = PropagationRequestHandler::new(identity);
        let peer_hash = [0xBB; 16];
        let mut peers = HashMap::new();
        peers.insert(peer_hash, crate::peer::LxmPeer::new(peer_hash));

        let result = handler.handle_peer_unpeer_request(Some(&identity), &peer_hash, &peers);
        match result {
            ControlResult::Success(data) => {
                let value: rmpv::Value = rmpv::decode::read_value(&mut &data[..]).unwrap();
                assert_eq!(value.as_bool(), Some(true));
            }
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn test_throttle_peer() {
        let mut handler = PropagationRequestHandler::new([0xAA; 16]);
        let peer = [0xBB; 16];

        assert!(!handler.is_peer_throttled(&peer));
        handler.throttle_peer(peer, 60.0);
        assert!(handler.is_peer_throttled(&peer));
    }

    #[test]
    fn test_cleanup_throttled_peers() {
        let mut handler = PropagationRequestHandler::new([0xAA; 16]);
        let peer = [0xBB; 16];

        handler.throttled_peers.insert(peer, 0.0);
        assert!(!handler.is_peer_throttled(&peer));
        handler.cleanup_throttled_peers();
        assert!(handler.throttled_peers.is_empty());
    }

    #[test]
    fn test_allow_disallow_control() {
        let mut handler = PropagationRequestHandler::new([0xAA; 16]);
        let new_identity = [0xBB; 16];

        assert_eq!(handler.control_allowed.len(), 1);
        handler.allow_control(new_identity);
        assert_eq!(handler.control_allowed.len(), 2);

        handler.allow_control(new_identity);
        assert_eq!(handler.control_allowed.len(), 2);

        handler.disallow_control(&new_identity);
        assert_eq!(handler.control_allowed.len(), 1);
        assert_eq!(handler.control_allowed[0], [0xAA; 16]);
    }
}
