//! Announce handlers for `lxmf.delivery` and `lxmf.propagation` destinations, plus the
//! propagation-node control endpoint dispatcher.
//!
//! Related Python code: LXMF/Handlers.py, the announce helpers in LXMF.py,
//! and the request handlers in LXMRouter.py.

use std::collections::HashMap;

use crate::constants::*;

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

    /// Set the advertised node name unchanged; an empty name is not advertised.
    pub fn set_name(&mut self, name: &str) {
        if name.is_empty() {
            self.metadata.remove(&PN_META_NAME);
        } else {
            self.metadata.insert(PN_META_NAME, name.as_bytes().to_vec());
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

/// Decode MessagePack with the acceptance rules of Python's umsgpack decoder.
fn decode_python(data: &[u8]) -> Option<rmpv::Value> {
    crate::message::canonical::validate_leading(data).ok()?;
    rmpv::decode::read_value(&mut &data[..]).ok()
}

/// Python `==` between a decoded value and an integer.
fn python_equals_int(value: &rmpv::Value, target: i64) -> bool {
    match value {
        rmpv::Value::Integer(n) => n.as_i64() == Some(target),
        rmpv::Value::Boolean(b) => i64::from(*b) == target,
        rmpv::Value::F32(f) => f64::from(*f) == target as f64,
        rmpv::Value::F64(f) => *f == target as f64,
        _ => false,
    }
}

/// Python `len()`; `None` where Python raises `TypeError`.
fn python_len(value: &rmpv::Value) -> Option<usize> {
    match value {
        rmpv::Value::Array(items) => Some(items.len()),
        rmpv::Value::Map(entries) => Some(entries.len()),
        rmpv::Value::String(text) => text.as_str().map(|t| t.chars().count()),
        rmpv::Value::Binary(bytes) => Some(bytes.len()),
        _ => None,
    }
}

/// Python `value[index]` for a non-negative integer index.
fn python_index(value: &rmpv::Value, index: usize) -> Option<rmpv::Value> {
    match value {
        rmpv::Value::Array(items) => items.get(index).cloned(),
        rmpv::Value::Binary(bytes) => bytes.get(index).map(|b| rmpv::Value::from(*b)),
        rmpv::Value::String(text) => text
            .as_str()?
            .chars()
            .nth(index)
            .map(|c| rmpv::Value::from(c.to_string())),
        rmpv::Value::Map(entries) => entries
            .iter()
            .rev()
            .find(|(k, _)| python_equals_int(k, index as i64))
            .map(|(_, v)| v.clone()),
        _ => None,
    }
}

/// Characters stripped by Python `bytes.strip()` / skipped by `int(bytes)`.
fn is_ascii_python_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

/// Decimal value of a digit accepted by Python `int(str)` (`Nd` characters).
fn decimal_digit(c: char, unicode: bool) -> Option<u32> {
    if let Some(d) = c.to_digit(10) {
        return Some(d);
    }
    if !unicode || c.is_ascii() {
        return None;
    }
    use unicode_general_category::{GeneralCategory, get_general_category};
    let is_nd = |c: char| get_general_category(c) == GeneralCategory::DecimalNumber;
    if !is_nd(c) {
        return None;
    }
    // Unicode assigns Nd characters in contiguous runs that start at zero.
    let mut start = c as u32;
    while start > 0 && char::from_u32(start - 1).is_some_and(is_nd) {
        start -= 1;
    }
    Some((c as u32 - start) % 10)
}

/// Text of a str/bytes value with Python's surrounding whitespace removed.
fn python_numeric_text(value: &rmpv::Value) -> Option<(String, bool)> {
    match value {
        rmpv::Value::String(text) => Some((
            crate::presentation::python_strip(text.as_str()?).to_string(),
            true,
        )),
        rmpv::Value::Binary(bytes) => {
            let text = std::str::from_utf8(bytes).ok().filter(|t| t.is_ascii())?;
            Some((text.trim_matches(is_ascii_python_space).to_string(), false))
        }
        _ => None,
    }
}

/// Digits with single underscores between them, mapped to ASCII.
fn python_digit_run(text: &str, unicode: bool) -> Option<String> {
    let mut out = String::new();
    let mut previous_digit = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '_' {
            let next_digit = chars
                .peek()
                .is_some_and(|n| decimal_digit(*n, unicode).is_some());
            if !previous_digit || !next_digit {
                return None;
            }
            previous_digit = false;
            continue;
        }
        let digit = decimal_digit(c, unicode)?;
        out.push(char::from_digit(digit, 10).expect("decimal digit"));
        previous_digit = true;
    }
    (!out.is_empty()).then_some(out)
}

/// Python `int(value)`; `None` where Python raises. Saturates outside `i128`.
fn python_int(value: &rmpv::Value) -> Option<i128> {
    match value {
        rmpv::Value::Integer(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from)),
        rmpv::Value::Boolean(b) => Some(i128::from(*b)),
        rmpv::Value::F32(f) => f.is_finite().then(|| f.trunc() as i128),
        rmpv::Value::F64(f) => f.is_finite().then(|| f.trunc() as i128),
        rmpv::Value::String(_) | rmpv::Value::Binary(_) => {
            let (text, unicode) = python_numeric_text(value)?;
            let (negative, digits) = match text.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, text.strip_prefix('+').unwrap_or(&text)),
            };
            let digits = python_digit_run(digits, unicode)?;
            let magnitude = digits.bytes().fold(0i128, |acc, d| {
                acc.saturating_mul(10).saturating_add(i128::from(d - b'0'))
            });
            Some(if negative { -magnitude } else { magnitude })
        }
        _ => None,
    }
}

/// Python `float(value)`; `None` where Python raises.
fn python_float(value: &rmpv::Value) -> Option<f64> {
    match value {
        rmpv::Value::Integer(n) => n
            .as_i64()
            .map(|i| i as f64)
            .or_else(|| n.as_u64().map(|u| u as f64)),
        rmpv::Value::Boolean(b) => Some(f64::from(u8::from(*b))),
        rmpv::Value::F32(f) => Some(f64::from(*f)),
        rmpv::Value::F64(f) => Some(*f),
        rmpv::Value::String(_) | rmpv::Value::Binary(_) => {
            let (text, unicode) = python_numeric_text(value)?;
            let body = text.strip_prefix(['+', '-']).unwrap_or(&text);
            let lower = body.to_ascii_lowercase();
            if matches!(lower.as_str(), "inf" | "infinity" | "nan") {
                return text.to_ascii_lowercase().parse::<f64>().ok();
            }
            let sign = &text[..text.len() - body.len()];
            let (mantissa, exponent) = match body.find(['e', 'E']) {
                Some(at) => (&body[..at], Some(&body[at + 1..])),
                None => (body, None),
            };
            let (whole, fraction) = match mantissa.split_once('.') {
                Some((w, f)) => (w, Some(f)),
                None => (mantissa, None),
            };
            let run = |part: &str| {
                if part.is_empty() {
                    Some(String::new())
                } else {
                    python_digit_run(part, unicode)
                }
            };
            let whole = run(whole)?;
            let fraction = match fraction {
                Some(part) => Some(run(part)?),
                None => None,
            };
            if whole.is_empty() && fraction.as_deref().is_none_or(str::is_empty) {
                return None;
            }
            let mut normalized = format!("{sign}{whole}");
            if let Some(fraction) = fraction {
                normalized.push('.');
                normalized.push_str(&fraction);
            }
            if let Some(exponent) = exponent {
                let exponent_body = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
                let exponent_sign = &exponent[..exponent.len() - exponent_body.len()];
                normalized.push('e');
                normalized.push_str(exponent_sign);
                normalized.push_str(&python_digit_run(exponent_body, unicode)?);
            }
            normalized.parse::<f64>().ok()
        }
        _ => None,
    }
}

/// `Some(state)` when Python's `value == True` or `value == False` holds.
fn python_bool_state(value: &rmpv::Value) -> Option<bool> {
    if python_equals_int(value, 1) {
        Some(true)
    } else if python_equals_int(value, 0) {
        Some(false)
    } else {
        None
    }
}

fn python_floats(list: &rmpv::Value) -> Option<()> {
    if !list.is_array() {
        return None;
    }
    for i in 0..3 {
        python_float(&python_index(list, i)?)?;
    }
    Some(())
}

/// The decoded announce when Python `pn_announce_data_is_valid` accepts it.
fn valid_pn_announce(data: &[u8]) -> Option<rmpv::Value> {
    let value = decode_python(data)?;
    let length = python_len(&value)?;
    if length < 7 {
        return None;
    }
    python_int(&python_index(&value, 1)?)?;
    python_bool_state(&python_index(&value, 2)?)?;
    python_int(&python_index(&value, 3)?)?;
    python_int(&python_index(&value, 4)?)?;
    python_floats(&python_index(&value, 5)?)?;
    if !python_index(&value, 6)?.is_map() {
        return None;
    }
    if length > 7 {
        python_floats(&python_index(&value, 7)?)?;
    }
    Some(value)
}

/// Python `pn_announce_data_is_valid`, including its `int()`/`float()`
/// coercions and the transitional slot 7 check.
pub fn pn_announce_data_is_valid(data: &[u8]) -> bool {
    valid_pn_announce(data).is_some()
}

/// Parse propagation-node announce data that [`pn_announce_data_is_valid`] accepts.
///
/// Values are extracted with `int()` as the Python announce handler does; it
/// returns `None` where that handler's conversion raises. Limits below zero
/// become zero and costs saturate to the `u8` range. Fractional costs in slot
/// 7 are not read. Only metadata with `u8` keys and binary values is retained.
pub fn parse_pn_announce_data(data: &[u8]) -> Option<PropagationNodeAnnounceData> {
    let value = valid_pn_announce(data)?;
    let int_at = |index: usize| python_int(&python_index(&value, index)?);
    let timebase = int_at(1)?.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    let node_state = python_bool_state(&python_index(&value, 2)?)?;
    let limit = |raw: i128| raw.clamp(0, i128::from(u64::MAX)) as u64;
    let transfer_limit = limit(int_at(3)?);
    let sync_limit = limit(int_at(4)?);
    let costs = python_index(&value, 5)?;
    let cost =
        |index: usize| python_int(&python_index(&costs, index)?).map(|raw| raw.clamp(0, 255) as u8);
    let (stamp_cost, stamp_flex, peering_cost) = (cost(0)?, cost(1)?, cost(2)?);

    let mut metadata = HashMap::new();
    for (k, v) in python_index(&value, 6)?.as_map()? {
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

/// Extract the integer stamp cost from propagation-node announce data.
///
/// Uses [`parse_pn_announce_data`]; the fractional slot 7 is not read.
pub fn pn_stamp_cost_from_app_data(data: &[u8]) -> Option<u8> {
    parse_pn_announce_data(data).map(|p| p.stamp_cost)
}

/// Encode delivery-announce `app_data` as msgpack
/// `[display_name, stamp_cost, supported_functionality]` where the feature
/// list advertises [`SF_COMPRESSION`].
///
/// `stamp_cost` must be in `1..=254`; out-of-range or `None` values are encoded as nil.
/// The name is encoded unchanged, as Python `LXMRouter.get_announce_app_data` does.
pub fn get_announce_app_data(display_name: Option<&str>, stamp_cost: Option<u8>) -> Vec<u8> {
    use rmpv::Value;

    let name_val = display_name.map_or(Value::Nil, |name| Value::Binary(name.as_bytes().to_vec()));

    let cost_val = match stamp_cost {
        Some(cost) if cost > 0 && cost < 255 => Value::from(cost as u64),
        _ => Value::Nil,
    };

    let supported_functionality =
        Value::Array(vec![Value::from(crate::constants::SF_COMPRESSION as u64)]);

    let peer_data = Value::Array(vec![name_val, cost_val, supported_functionality]);

    crate::encode_value(&peer_data)
}

/// First byte of the MessagePack delivery-announce format (fixarray or array16);
/// anything else is the original raw-name format.
fn is_announce_array_marker(byte: u8) -> bool {
    matches!(byte, 0x90..=0x9f | 0xdc)
}

/// The decoded list of MessagePack-format delivery-announce data.
fn announce_list(data: &[u8]) -> Option<Vec<rmpv::Value>> {
    match decode_python(data)? {
        rmpv::Value::Array(items) => Some(items),
        _ => None,
    }
}

/// Parse delivery-announce `app_data`, returning `(display_name, stamp_cost)`
/// as [`display_name_from_app_data`] and [`stamp_cost_from_app_data`] return them.
/// Returns `None` for empty data.
pub fn parse_announce_app_data(data: &[u8]) -> Option<(Option<String>, Option<u8>)> {
    if data.is_empty() {
        return None;
    }
    Some((
        display_name_from_app_data(data),
        stamp_cost_from_app_data(data),
    ))
}

/// Python `display_name_from_app_data`: the raw name with NUL characters and
/// surrounding whitespace removed. Original-format data is decoded as UTF-8.
/// The name is not filtered for display; see [`crate::presentation::sanitize_name`].
pub fn display_name_from_app_data(data: &[u8]) -> Option<String> {
    let first = *data.first()?;
    if !is_announce_array_marker(first) {
        return std::str::from_utf8(data).ok().map(str::to_string);
    }
    let items = announce_list(data)?;
    // A str element has no .decode() in Python and yields None.
    let rmpv::Value::Binary(bytes) = items.first()? else {
        return None;
    };
    let name = std::str::from_utf8(bytes).ok()?;
    Some(crate::presentation::python_strip(&name.replace('\0', "")).to_string())
}

/// Python `stamp_cost_from_app_data`: element 3 when it is an integer, else
/// element 1, as a `u8` when representable. A fractional element 3 is not
/// read; element 1 carries its ceiling.
pub fn stamp_cost_from_app_data(data: &[u8]) -> Option<u8> {
    if !is_announce_array_marker(*data.first()?) {
        return None;
    }
    let items = announce_list(data)?;
    if items.len() < 2 {
        return None;
    }
    let cost = match items.get(3) {
        Some(rmpv::Value::Integer(n)) if items.len() > 3 => n.as_i64(),
        _ => match &items[1] {
            rmpv::Value::Integer(n) => n.as_i64(),
            rmpv::Value::F64(f) if f.fract() == 0.0 => Some(*f as i64),
            rmpv::Value::F32(f) if f.fract() == 0.0 => Some(*f as i64),
            _ => None,
        },
    };
    cost.and_then(|c| u8::try_from(c).ok())
}

/// Parse advertised `SF_COMPRESSION` support in delivery-announce `app_data`.
///
/// Original-format, malformed and list-less data are `Unknown`. A present
/// feature list is authoritative; members compare with Python `==`, so
/// `false` and `0.0` count as `SF_COMPRESSION`.
///
/// Related Python helper: `compression_support_from_app_data`.
pub fn compression_support_state_from_app_data(data: &[u8]) -> CompressionSupport {
    if !data.first().is_some_and(|b| is_announce_array_marker(*b)) {
        return CompressionSupport::Unknown;
    }
    let Some(items) = announce_list(data) else {
        return CompressionSupport::Unknown;
    };
    let Some(rmpv::Value::Array(features)) = items.get(2) else {
        return CompressionSupport::Unknown;
    };
    if features
        .iter()
        .any(|f| python_equals_int(f, i64::from(crate::constants::SF_COMPRESSION)))
    {
        CompressionSupport::Supported
    } else {
        CompressionSupport::Unsupported
    }
}

/// Python `compression_support_from_app_data` as a boolean: only a present
/// feature list without `SF_COMPRESSION` returns false. Empty or undecodable
/// data, where Python returns `None` or raises, returns true.
pub fn compression_support_from_app_data(data: &[u8]) -> bool {
    compression_support_state_from_app_data(data) != CompressionSupport::Unsupported
}

/// Python `pn_name_from_app_data`: the raw UTF-8 [`PN_META_NAME`] metadata of
/// valid propagation-node announce data, not filtered for display.
pub fn pn_name_from_app_data(data: &[u8]) -> Option<String> {
    let value = valid_pn_announce(data)?;
    let metadata = python_index(&value, 6)?;
    let name = python_index(&metadata, usize::from(crate::constants::PN_META_NAME))?;
    let rmpv::Value::Binary(bytes) = name else {
        return None;
    };
    String::from_utf8(bytes).ok()
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
    fn test_pn_announce_data_clamps_out_of_range_policy_values() {
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

        // Python accepts these (int() succeeds); the typed values are clamped.
        let negative = parse_pn_announce_data(&encode(Value::from(-1), Value::from(16))).unwrap();
        assert_eq!(negative.transfer_limit, 0);
        let large = parse_pn_announce_data(&encode(Value::from(10240), Value::from(256))).unwrap();
        assert_eq!(large.stamp_cost, 255);
        // int(nan) raises in the Python announce handler although validity passes.
        let nan = encode(Value::from(10240), Value::F64(f64::NAN));
        assert!(pn_announce_data_is_valid(&nan));
        assert!(parse_pn_announce_data(&nan).is_none());
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
    fn test_display_name_from_app_data_returns_raw_unicode() {
        let packed = get_announce_app_data(
            Some("  Ａlice\u{202e}\u{e000}\u{1f680}\nNetwork  "),
            Some(12),
        );
        assert_eq!(
            display_name_from_app_data(&packed),
            Some("Ａlice\u{202e}\u{e000}\u{1f680}\nNetwork".to_string())
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
