//! Python-compatible `lxmd` propagation-control client and output helpers.
//!
//! Python reference: `LXMF/Utilities/lxmd.py` `query_status`,
//! `request_sync`, `request_unpeer`, and `get_status`.

use std::time::Duration;

use lxmf_core::constants::PeerError;
use lxmf_core::propagation_node::PropagationNode;
use lxmf_core::router::LxmRouter;
use rmpv::Value;
use rns_identity::identity::Identity;
use rns_runtime::link_client::{LinkClient, LinkClientError};
use rns_transport::messages::{AnnounceHandlerEvent, TransportMessage};
use tokio::sync::mpsc;

pub const CONTROL_APP_NAME: &str = "lxmf.propagation.control";
pub const PROPAGATION_APP_NAME: &str = "lxmf.propagation";

#[derive(Debug)]
pub enum ControlResponse {
    Stats(Value),
    Success,
    Error(PeerError),
    Empty,
}

#[derive(Debug, Clone, Copy)]
pub enum ControlCommandKind {
    Status,
    Sync,
    Unpeer,
}

impl ControlCommandKind {
    pub fn timeout_message(self) -> &'static str {
        match self {
            Self::Status => "Getting lxmd statistics timed out, exiting now",
            Self::Sync => "Requesting lxmd peer sync timed out, exiting now",
            Self::Unpeer => "Requesting lxmd peering break timed out, exiting now",
        }
    }
}

pub async fn query_control(
    transport_tx: tokio::sync::mpsc::Sender<rns_transport::messages::TransportMessage>,
    identity: Identity,
    target_identity_hash: [u8; 16],
    path: &str,
    payload: Vec<u8>,
    timeout_secs: f64,
) -> Result<Vec<u8>, LinkClientError> {
    let client = LinkClient::new(transport_tx, identity);
    client
        .query(
            target_identity_hash,
            CONTROL_APP_NAME,
            path,
            payload,
            0,
            Duration::from_secs_f64(timeout_secs.max(0.0)),
        )
        .await
}

pub async fn resolve_remote_identity_hash(
    transport_tx: mpsc::Sender<TransportMessage>,
    remote_destination_hash: [u8; 16],
    timeout_secs: f64,
) -> Result<[u8; 16], LinkClientError> {
    let (ann_tx, mut ann_rx) = mpsc::channel::<AnnounceHandlerEvent>(64);
    transport_tx
        .send(TransportMessage::RegisterAnnounceHandler {
            aspect_filter: Some(PROPAGATION_APP_NAME.to_string()),
            receive_path_responses: true,
            callback_tx: ann_tx,
        })
        .await
        .map_err(|_| LinkClientError::TransportUnavailable)?;

    let send_result = transport_tx
        .send(TransportMessage::RequestPath {
            destination_hash: remote_destination_hash,
        })
        .await;
    if send_result.is_err() {
        let _ = transport_tx.try_send(TransportMessage::DeregisterAnnounceHandler {
            aspect_filter: Some(PROPAGATION_APP_NAME.to_string()),
        });
        return Err(LinkClientError::TransportUnavailable);
    }

    let wait = async {
        while let Some(event) = ann_rx.recv().await {
            if event.destination_hash == remote_destination_hash {
                if let Some(identity_hash) = event.identity_hash {
                    return Ok(identity_hash);
                }
            }
        }
        Err(LinkClientError::PubkeyNotDiscovered)
    };

    let result =
        match tokio::time::timeout(Duration::from_secs_f64(timeout_secs.max(0.0)), wait).await {
            Ok(result) => result,
            Err(_) => Err(LinkClientError::Timeout("remote identity resolution")),
        };

    let _ = transport_tx.try_send(TransportMessage::DeregisterAnnounceHandler {
        aspect_filter: Some(PROPAGATION_APP_NAME.to_string()),
    });

    result
}

pub fn decode_control_response(response: &[u8]) -> ControlResponse {
    if response.is_empty() {
        return ControlResponse::Empty;
    }

    let Ok(value) = rmpv::decode::read_value(&mut &response[..]) else {
        return ControlResponse::Success;
    };

    if let Some(code) = value.as_u64() {
        if let Some(error) = peer_error_from_code(code as u8) {
            return ControlResponse::Error(error);
        }
    }

    if value.is_nil() {
        ControlResponse::Empty
    } else if value.as_map().is_some() {
        ControlResponse::Stats(value)
    } else {
        ControlResponse::Success
    }
}

pub fn peer_error_from_code(code: u8) -> Option<PeerError> {
    match code {
        0xF0 => Some(PeerError::NoIdentity),
        0xF1 => Some(PeerError::NoAccess),
        0xF4 => Some(PeerError::InvalidData),
        0xFD => Some(PeerError::NotFound),
        0xFE => Some(PeerError::Timeout),
        _ => None,
    }
}

pub fn encode_peer_error(error: PeerError) -> Vec<u8> {
    encode_value(&Value::from(error as u64))
}

pub fn encode_control_success() -> Vec<u8> {
    encode_value(&Value::Boolean(true))
}

pub fn encode_nil_response() -> Vec<u8> {
    encode_value(&Value::Nil)
}

pub fn encode_router_control_stats(
    router: &LxmRouter,
    identity_hash: [u8; 16],
    propagation_destination_hash: [u8; 16],
    node: Option<&PropagationNode>,
    now: f64,
) -> Vec<u8> {
    let message_count = node
        .map(PropagationNode::message_count)
        .unwrap_or_else(|| router.propagation_store.len());
    let message_size = node
        .map(PropagationNode::total_size)
        .unwrap_or_else(|| router.propagation_store.total_size());
    let storage_limit = router.config.ext.message_storage_limit;

    let mut peer_entries = Vec::new();
    for (hash, peer) in &router.peers {
        let peer_type = if router.static_peers.contains(hash) || peer.is_static {
            "static"
        } else {
            "discovered"
        };
        let acceptance_rate = if peer.offered == 0 {
            0.0
        } else {
            peer.outgoing as f64 / peer.offered as f64
        };
        let peering_key_value = peer
            .peering_key
            .as_ref()
            .map(|(_, value)| Value::from(*value as u64))
            .unwrap_or(Value::Nil);
        let unhandled = node
            .map(|node| node.unhandled_message_count(&peer.handled_messages))
            .unwrap_or_else(|| peer.unhandled_messages() as usize);

        let peer_map = Value::Map(vec![
            (Value::String("type".into()), Value::from(peer_type)),
            (
                Value::String("state".into()),
                Value::from(peer.state as u64),
            ),
            (Value::String("alive".into()), Value::Boolean(peer.alive)),
            (Value::String("name".into()), Value::Nil),
            (
                Value::String("last_heard".into()),
                Value::from(peer.last_heard as i64),
            ),
            (
                Value::String("next_sync_attempt".into()),
                Value::F64(peer.next_sync_attempt),
            ),
            (
                Value::String("last_sync_attempt".into()),
                Value::F64(peer.last_sync_attempt),
            ),
            (
                Value::String("sync_backoff".into()),
                Value::F64(peer.sync_backoff),
            ),
            (
                Value::String("peering_timebase".into()),
                Value::F64(peer.peering_timebase),
            ),
            (
                Value::String("ler".into()),
                Value::from(peer.link_establishment_rate as i64),
            ),
            (
                Value::String("str".into()),
                Value::from(peer.sync_transfer_rate as i64),
            ),
            (
                Value::String("transfer_limit".into()),
                option_f64(peer.propagation_transfer_limit),
            ),
            (
                Value::String("sync_limit".into()),
                option_f64(peer.propagation_sync_limit),
            ),
            (
                Value::String("target_stamp_cost".into()),
                option_u8(peer.stamp_cost),
            ),
            (
                Value::String("stamp_cost_flexibility".into()),
                option_u8(peer.stamp_cost_flexibility),
            ),
            (
                Value::String("peering_cost".into()),
                Value::from(peer.peering_cost as u64),
            ),
            (Value::String("peering_key".into()), peering_key_value),
            (
                Value::String("network_distance".into()),
                Value::from(255_u64),
            ),
            (Value::String("rx_bytes".into()), Value::from(peer.rx_bytes)),
            (Value::String("tx_bytes".into()), Value::from(peer.tx_bytes)),
            (
                Value::String("acceptance_rate".into()),
                Value::F64(acceptance_rate),
            ),
            (
                Value::String("messages".into()),
                Value::Map(vec![
                    (Value::String("offered".into()), Value::from(peer.offered)),
                    (Value::String("outgoing".into()), Value::from(peer.outgoing)),
                    (Value::String("incoming".into()), Value::from(peer.incoming)),
                    (
                        Value::String("unhandled".into()),
                        Value::from(unhandled as u64),
                    ),
                ]),
            ),
        ]);
        peer_entries.push((Value::Binary(hash.to_vec()), peer_map));
    }

    let static_peers = router
        .peers
        .keys()
        .filter(|hash| router.static_peers.contains(hash))
        .count();
    let discovered_peers = router.peers.len().saturating_sub(static_peers);
    let uptime = router
        .propagation_start_time
        .map(|started| now - started)
        .unwrap_or(0.0);

    let stats = Value::Map(vec![
        (
            Value::String("identity_hash".into()),
            Value::Binary(identity_hash.to_vec()),
        ),
        (
            Value::String("destination_hash".into()),
            Value::Binary(propagation_destination_hash.to_vec()),
        ),
        (Value::String("uptime".into()), Value::F64(uptime)),
        (
            Value::String("delivery_limit".into()),
            Value::F64(router.config.delivery_limit_kb),
        ),
        (
            Value::String("propagation_limit".into()),
            Value::from(router.config.propagation_limit_kb as u64),
        ),
        (
            Value::String("sync_limit".into()),
            Value::from(router.config.sync_limit_kb as u64),
        ),
        (
            Value::String("target_stamp_cost".into()),
            Value::from(router.config.propagation_stamp_cost as u64),
        ),
        (
            Value::String("stamp_cost_flexibility".into()),
            Value::from(router.config.propagation_stamp_flex as u64),
        ),
        (
            Value::String("peering_cost".into()),
            Value::from(router.config.ext.peering_cost as u64),
        ),
        (
            Value::String("max_peering_cost".into()),
            Value::from(router.config.ext.max_peering_cost as u64),
        ),
        (
            Value::String("autopeer_maxdepth".into()),
            Value::from(router.config.ext.autopeer_maxdepth as u64),
        ),
        (
            Value::String("from_static_only".into()),
            Value::Boolean(router.config.ext.from_static_only),
        ),
        (
            Value::String("messagestore".into()),
            Value::Map(vec![
                (
                    Value::String("count".into()),
                    Value::from(message_count as u64),
                ),
                (
                    Value::String("bytes".into()),
                    Value::from(message_size as u64),
                ),
                (
                    Value::String("limit".into()),
                    storage_limit
                        .map(|limit| Value::from(limit as u64))
                        .unwrap_or(Value::Nil),
                ),
            ]),
        ),
        (
            Value::String("clients".into()),
            Value::Map(vec![
                (
                    Value::String("client_propagation_messages_received".into()),
                    Value::from(router.client_propagation_messages_received),
                ),
                (
                    Value::String("client_propagation_messages_served".into()),
                    Value::from(router.client_propagation_messages_served),
                ),
            ]),
        ),
        (
            Value::String("unpeered_propagation_incoming".into()),
            Value::from(router.unpeered_propagation_incoming),
        ),
        (
            Value::String("unpeered_propagation_rx_bytes".into()),
            Value::from(router.unpeered_propagation_rx_bytes),
        ),
        (
            Value::String("static_peers".into()),
            Value::from(static_peers as u64),
        ),
        (
            Value::String("discovered_peers".into()),
            Value::from(discovered_peers as u64),
        ),
        (
            Value::String("total_peers".into()),
            Value::from(router.peers.len() as u64),
        ),
        (
            Value::String("max_peers".into()),
            Value::from(router.config.max_peers as u64),
        ),
        (Value::String("peers".into()), Value::Map(peer_entries)),
    ]);

    encode_value(&stats)
}

pub fn print_control_link_error(kind: ControlCommandKind, _error: &LinkClientError) -> ! {
    println!("{}", kind.timeout_message());
    std::process::exit(200);
}

pub fn exit_for_control_response(kind: ControlCommandKind, response: &ControlResponse) -> bool {
    match response {
        &ControlResponse::Error(PeerError::NoIdentity) => {
            println!("Remote received no identity");
            std::process::exit(203)
        }
        &ControlResponse::Error(PeerError::NoAccess) => {
            println!("Access denied");
            std::process::exit(204)
        }
        &ControlResponse::Error(PeerError::InvalidData) => {
            println!("Invalid data received by remote");
            std::process::exit(205)
        }
        &ControlResponse::Error(PeerError::NotFound) => {
            println!("The requested peer was not found");
            std::process::exit(206)
        }
        &ControlResponse::Error(PeerError::Timeout) => {
            println!("{}", kind.timeout_message());
            std::process::exit(200)
        }
        ControlResponse::Empty => {
            println!("Empty response received");
            std::process::exit(207)
        }
        ControlResponse::Error(_) | ControlResponse::Stats(_) | ControlResponse::Success => false,
    }
}

pub fn format_remote_status(
    stats: &Value,
    show_status: bool,
    show_peers: bool,
    now: f64,
) -> String {
    let mut out = String::new();

    let destination_hash = map_bytes(stats, "destination_hash").unwrap_or_default();
    let uptime = map_f64(stats, "uptime").unwrap_or(0.0);
    out.push_str(&format!(
        "\nLXMF Propagation Node running on {}, uptime is {}\n",
        pretty_hex(&destination_hash),
        pretty_time(uptime),
    ));

    let peers = map_value(stats, "peers");
    let peer_entries = peers
        .and_then(Value::as_map)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    let mut available_peers = 0_u64;
    let mut unreachable_peers = 0_u64;
    let mut peered_incoming = 0_u64;
    let mut peered_outgoing = 0_u64;
    let mut peered_rx_bytes = 0_u64;
    let mut peered_tx_bytes = 0_u64;

    for (_, peer) in peer_entries {
        let messages = map_value(peer, "messages");
        peered_incoming += messages.and_then(|m| map_u64(m, "incoming")).unwrap_or(0);
        peered_outgoing += messages.and_then(|m| map_u64(m, "outgoing")).unwrap_or(0);
        peered_rx_bytes += map_u64(peer, "rx_bytes").unwrap_or(0);
        peered_tx_bytes += map_u64(peer, "tx_bytes").unwrap_or(0);
        if map_bool(peer, "alive").unwrap_or(false) {
            available_peers += 1;
        } else {
            unreachable_peers += 1;
        }
    }

    let clients = map_value(stats, "clients");
    let client_received = clients
        .and_then(|c| map_u64(c, "client_propagation_messages_received"))
        .unwrap_or(0);
    let client_served = clients
        .and_then(|c| map_u64(c, "client_propagation_messages_served"))
        .unwrap_or(0);
    let unpeered_incoming = map_u64(stats, "unpeered_propagation_incoming").unwrap_or(0);
    let unpeered_rx_bytes = map_u64(stats, "unpeered_propagation_rx_bytes").unwrap_or(0);

    let total_incoming = peered_incoming + unpeered_incoming + client_received;
    let total_rx_bytes = peered_rx_bytes + unpeered_rx_bytes;
    let distribution_factor = if total_incoming != 0 {
        round2(peered_outgoing as f64 / total_incoming as f64)
    } else {
        0.0
    };

    if show_status {
        let messagestore = map_value(stats, "messagestore");
        let store_count = messagestore.and_then(|m| map_u64(m, "count")).unwrap_or(0);
        let store_bytes = messagestore.and_then(|m| map_u64(m, "bytes")).unwrap_or(0);
        let store_limit = messagestore.and_then(|m| map_u64(m, "limit")).unwrap_or(0);
        let store_util = if store_limit == 0 {
            0.0
        } else {
            round2((store_bytes as f64 / store_limit as f64) * 100.0)
        };
        let who = if map_bool(stats, "from_static_only").unwrap_or(false) {
            "static peers only"
        } else {
            "all nodes"
        };

        out.push_str(&format!(
            "Messagestore contains {store_count} messages, {} ({}% utilised of {})\n",
            pretty_size(store_bytes as f64, "B"),
            format_python_float(store_util),
            pretty_size(store_limit as f64, "B"),
        ));
        out.push_str(&format!(
            "Required propagation stamp cost is {}, flexibility is {}\n",
            map_u64(stats, "target_stamp_cost").unwrap_or(0),
            map_u64(stats, "stamp_cost_flexibility").unwrap_or(0),
        ));
        out.push_str(&format!(
            "Peering cost is {}, max remote peering cost is {}\n",
            map_u64(stats, "peering_cost").unwrap_or(0),
            map_u64(stats, "max_peering_cost").unwrap_or(0),
        ));
        out.push_str(&format!("Accepting propagated messages from {who}\n"));
        out.push_str(&format!(
            "{} message limit, {} sync limit\n\n",
            pretty_size(
                map_f64(stats, "propagation_limit").unwrap_or(0.0) * 1000.0,
                "B"
            ),
            pretty_size(map_f64(stats, "sync_limit").unwrap_or(0.0) * 1000.0, "B"),
        ));
        out.push_str(&format!(
            "Peers   : {} total (peer limit is {})\n",
            map_u64(stats, "total_peers").unwrap_or(peer_entries.len() as u64),
            map_display(stats, "max_peers"),
        ));
        out.push_str(&format!(
            "          {} discovered, {} static\n",
            map_u64(stats, "discovered_peers").unwrap_or(0),
            map_u64(stats, "static_peers").unwrap_or(0),
        ));
        out.push_str(&format!(
            "          {available_peers} available, {unreachable_peers} unreachable\n\n",
        ));
        out.push_str(&format!(
            "Traffic : {total_incoming} messages received in total ({})\n",
            pretty_size(total_rx_bytes as f64, "B"),
        ));
        out.push_str(&format!(
            "          {peered_incoming} messages received from peered nodes ({})\n",
            pretty_size(peered_rx_bytes as f64, "B"),
        ));
        out.push_str(&format!(
            "          {unpeered_incoming} messages received from unpeered nodes ({})\n",
            pretty_size(unpeered_rx_bytes as f64, "B"),
        ));
        out.push_str(&format!(
            "          {peered_outgoing} messages transferred to peered nodes ({})\n",
            pretty_size(peered_tx_bytes as f64, "B"),
        ));
        out.push_str(&format!(
            "          {client_received} propagation messages received directly from clients\n",
        ));
        out.push_str(&format!(
            "          {client_served} propagation messages served to clients\n",
        ));
        out.push_str(&format!(
            "          Distribution factor is {}\n\n",
            format_python_float(distribution_factor),
        ));
    }

    if show_peers {
        if !show_status {
            out.push('\n');
        }

        for (peer_id, peer) in peer_entries {
            let peer_hash = peer_id.as_slice().unwrap_or(&[]);
            let peer_type = match map_str(peer, "type").unwrap_or("unknown") {
                "static" => "Static peer     ",
                "discovered" => "Discovered peer ",
                _ => "Unknown peer    ",
            };
            let alive = if map_bool(peer, "alive").unwrap_or(false) {
                "Available"
            } else {
                "Unreachable"
            };
            let last_heard_age = (now - map_f64(peer, "last_heard").unwrap_or(0.0)).max(0.0);
            let hops = map_i64(peer, "network_distance").unwrap_or(255);
            let hops_text = if hops == 255 {
                "hops unknown".to_string()
            } else if hops == 1 {
                "1 hop away".to_string()
            } else {
                format!("{hops} hops away")
            };
            let messages = map_value(peer, "messages");
            let peering_key = match map_value(peer, "peering_key") {
                Some(value) if !value.is_nil() => {
                    format!("Generated, value is {}", value_to_display(value))
                }
                _ => "Not generated".to_string(),
            };
            let last_sync = match map_f64(peer, "last_sync_attempt").unwrap_or(0.0) {
                value if value != 0.0 => {
                    format!("last synced {} ago", pretty_time((now - value).max(0.0)))
                }
                _ => "never synced".to_string(),
            };
            let name =
                lxmf_core::presentation::sanitize_name(map_str(peer, "name").unwrap_or(""), 46);
            let display_name = if name.chars().count() > 45 {
                format!("{}...", name.chars().take(45).collect::<String>())
            } else {
                name
            };
            let acceptance_rate = round2(map_f64(peer, "acceptance_rate").unwrap_or(0.0) * 100.0);
            let unhandled = messages.and_then(|m| map_u64(m, "unhandled")).unwrap_or(0);
            let plural = if unhandled == 1 { "" } else { "s" };

            out.push_str(&format!("  {peer_type}{}\n", pretty_hex(peer_hash)));
            if !display_name.is_empty() {
                out.push_str(&format!("    Name       : {display_name}\n"));
            }
            out.push_str(&format!(
                "    Status     : {alive}, {hops_text}, last heard {} ago\n",
                pretty_time(last_heard_age),
            ));
            out.push_str(&format!(
                "    Costs      : Propagation {} (flex {}), peering {}\n",
                map_optional_display(peer, "target_stamp_cost"),
                map_optional_display(peer, "stamp_cost_flexibility"),
                map_optional_display(peer, "peering_cost"),
            ));
            out.push_str(&format!("    Sync key   : {peering_key}\n"));
            out.push_str(&format!(
                "    Speeds     : {} STR, {} LER\n",
                pretty_speed(map_f64(peer, "str").unwrap_or(0.0)),
                pretty_speed(map_f64(peer, "ler").unwrap_or(0.0)),
            ));
            out.push_str(&format!(
                "    Limits     : {} message limit, {} sync limit\n",
                optional_size_kb(peer, "transfer_limit", "Unknown"),
                optional_size_kb(peer, "sync_limit", "unknown"),
            ));
            out.push_str(&format!(
                "    Messages   : {} offered, {} outgoing, {} incoming, {}% acceptance rate\n",
                messages.and_then(|m| map_u64(m, "offered")).unwrap_or(0),
                messages.and_then(|m| map_u64(m, "outgoing")).unwrap_or(0),
                messages.and_then(|m| map_u64(m, "incoming")).unwrap_or(0),
                format_python_float(acceptance_rate),
            ));
            out.push_str(&format!(
                "    Traffic    : {} received, {} sent\n",
                pretty_size(map_f64(peer, "rx_bytes").unwrap_or(0.0), "B"),
                pretty_size(map_f64(peer, "tx_bytes").unwrap_or(0.0), "B"),
            ));
            out.push_str(&format!(
                "    Sync state : {unhandled} unhandled message{plural}, {last_sync}\n\n",
            ));
        }
    }

    out
}

fn map_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_map()?.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) {
            Some(v)
        } else {
            None
        }
    })
}

fn map_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    map_value(value, key)?.as_str()
}

fn map_bytes(value: &Value, key: &str) -> Option<Vec<u8>> {
    map_value(value, key)?.as_slice().map(|b| b.to_vec())
}

fn map_bool(value: &Value, key: &str) -> Option<bool> {
    map_value(value, key)?.as_bool()
}

fn map_u64(value: &Value, key: &str) -> Option<u64> {
    let value = map_value(value, key)?;
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|i| u64::try_from(i).ok()))
        .or_else(|| value.as_f64().map(|f| f as u64))
}

fn map_i64(value: &Value, key: &str) -> Option<i64> {
    let value = map_value(value, key)?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|u| i64::try_from(u).ok()))
        .or_else(|| value.as_f64().map(|f| f as i64))
}

fn map_f64(value: &Value, key: &str) -> Option<f64> {
    let value = map_value(value, key)?;
    value
        .as_f64()
        .or_else(|| value.as_u64().map(|u| u as f64))
        .or_else(|| value.as_i64().map(|i| i as f64))
}

fn map_display(value: &Value, key: &str) -> String {
    map_value(value, key)
        .map(value_to_display)
        .unwrap_or_else(|| "None".to_string())
}

fn map_optional_display(value: &Value, key: &str) -> String {
    match map_value(value, key) {
        Some(v) if !v.is_nil() => value_to_display(v),
        _ => "unknown".to_string(),
    }
}

fn value_to_display(value: &Value) -> String {
    if value.is_nil() {
        "None".to_string()
    } else if let Some(v) = value.as_str() {
        v.to_string()
    } else if let Some(v) = value.as_u64() {
        v.to_string()
    } else if let Some(v) = value.as_i64() {
        v.to_string()
    } else if let Some(v) = value.as_f64() {
        format_python_float(v)
    } else if let Some(v) = value.as_bool() {
        v.to_string()
    } else if let Some(v) = value.as_slice() {
        hex::encode(v)
    } else {
        format!("{value:?}")
    }
}

fn optional_size_kb(value: &Value, key: &str, none_text: &str) -> String {
    match map_f64(value, key) {
        Some(v) if v != 0.0 => pretty_size(v * 1000.0, "B"),
        _ => none_text.to_string(),
    }
}

fn pretty_hex(data: &[u8]) -> String {
    format!("<{}>", hex::encode(data))
}

fn pretty_speed(bits_per_second: f64) -> String {
    pretty_size(bits_per_second / 8.0, "b") + "ps"
}

fn pretty_size(mut num: f64, suffix: &str) -> String {
    let units = ["", "K", "M", "G", "T", "P", "E", "Z"];
    let mut last_unit = "Y";

    if suffix == "b" {
        num *= 8.0;
        last_unit = "Y";
    }

    for unit in units {
        if num.abs() < 1000.0 {
            if unit.is_empty() {
                return format!("{num:.0} {unit}{suffix}");
            }
            return format!("{num:.2} {unit}{suffix}");
        }
        num /= 1000.0;
    }

    format!("{num:.2}{last_unit}{suffix}")
}

fn pretty_time(mut seconds: f64) -> String {
    let negative = seconds < 0.0;
    if negative {
        seconds = seconds.abs();
    }

    let days = (seconds / 86_400.0).floor() as u64;
    seconds %= 86_400.0;
    let hours = (seconds / 3_600.0).floor() as u64;
    seconds %= 3_600.0;
    let minutes = (seconds / 60.0).floor() as u64;
    seconds %= 60.0;
    let seconds = round2(seconds);

    let mut components = Vec::new();
    if days > 0 {
        components.push(format!("{days}d"));
    }
    if hours > 0 {
        components.push(format!("{hours}h"));
    }
    if minutes > 0 {
        components.push(format!("{minutes}m"));
    }
    if seconds > 0.0 {
        components.push(format!("{}s", format_python_float(seconds)));
    }

    let rendered = match components.len() {
        0 => "0s".to_string(),
        1 => components[0].clone(),
        _ => {
            let last = components.pop().unwrap();
            format!("{} and {last}", components.join(", "))
        }
    };

    if negative {
        format!("-{rendered}")
    } else {
        rendered
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn format_python_float(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        let mut out = format!("{value:.2}");
        while out.ends_with('0') {
            out.pop();
        }
        if out.ends_with('.') {
            out.pop();
        }
        out
    }
}

fn option_u8(value: Option<u8>) -> Value {
    value.map(|v| Value::from(v as u64)).unwrap_or(Value::Nil)
}

fn option_f64(value: Option<f64>) -> Value {
    value.map(Value::F64).unwrap_or(Value::Nil)
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value).expect("msgpack value should encode");
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_value(data: &[u8]) -> Value {
        rmpv::decode::read_value(&mut &data[..]).unwrap()
    }

    #[test]
    fn decodes_python_peer_error_constants() {
        let err = decode_value(&[0xcc, 0xf0]);
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &err).unwrap();
        assert!(matches!(
            decode_control_response(&data),
            ControlResponse::Error(PeerError::NoIdentity)
        ));
    }

    #[test]
    fn status_formatter_matches_python_key_lines() {
        let value = rmpv::Value::Map(vec![
            (
                Value::String("destination_hash".into()),
                Value::Binary(vec![0x01; 16]),
            ),
            (Value::String("uptime".into()), Value::from(65)),
            (Value::String("propagation_limit".into()), Value::from(256)),
            (Value::String("sync_limit".into()), Value::from(10240)),
            (Value::String("target_stamp_cost".into()), Value::from(16)),
            (
                Value::String("stamp_cost_flexibility".into()),
                Value::from(3),
            ),
            (Value::String("peering_cost".into()), Value::from(18)),
            (Value::String("max_peering_cost".into()), Value::from(26)),
            (
                Value::String("from_static_only".into()),
                Value::Boolean(false),
            ),
            (
                Value::String("messagestore".into()),
                Value::Map(vec![
                    (Value::String("count".into()), Value::from(2)),
                    (Value::String("bytes".into()), Value::from(2048)),
                    (Value::String("limit".into()), Value::from(1_000_000)),
                ]),
            ),
            (
                Value::String("clients".into()),
                Value::Map(vec![
                    (
                        Value::String("client_propagation_messages_received".into()),
                        Value::from(3),
                    ),
                    (
                        Value::String("client_propagation_messages_served".into()),
                        Value::from(4),
                    ),
                ]),
            ),
            (
                Value::String("unpeered_propagation_incoming".into()),
                Value::from(5),
            ),
            (
                Value::String("unpeered_propagation_rx_bytes".into()),
                Value::from(6000),
            ),
            (Value::String("static_peers".into()), Value::from(0)),
            (Value::String("discovered_peers".into()), Value::from(0)),
            (Value::String("total_peers".into()), Value::from(0)),
            (Value::String("max_peers".into()), Value::from(20)),
            (Value::String("peers".into()), Value::Map(vec![])),
        ]);

        let out = format_remote_status(&value, true, true, 1_700_000_000.0);
        assert!(
            out.contains("LXMF Propagation Node running on <01010101010101010101010101010101>")
        );
        assert!(out.contains("Messagestore contains 2 messages"));
        assert!(out.contains("Required propagation stamp cost is 16, flexibility is 3"));
        assert!(out.contains("Peering cost is 18, max remote peering cost is 26"));
        assert!(out.contains("Accepting propagated messages from all nodes"));
        assert!(out.contains("256.00 KB message limit, 10.24 MB sync limit"));
        assert!(out.contains("Peers   : 0 total (peer limit is 20)"));
        assert!(out.contains("Traffic : 8 messages received in total"));
        assert!(out.contains("3 propagation messages received directly from clients"));
        assert!(out.contains("4 propagation messages served to clients"));
    }

    #[test]
    fn status_formatter_bounds_multibyte_untrusted_peer_names() {
        let hostile_name = format!("{}\u{202e}\u{1f680}", "界".repeat(50));
        let peer = Value::Map(vec![
            (
                Value::String("name".into()),
                Value::String(hostile_name.into()),
            ),
            (Value::String("alive".into()), Value::Boolean(true)),
        ]);
        let stats = Value::Map(vec![
            (
                Value::String("destination_hash".into()),
                Value::Binary(vec![0x01; 16]),
            ),
            (
                Value::String("peers".into()),
                Value::Map(vec![(Value::Binary(vec![0x02; 16]), peer)]),
            ),
        ]);

        let out = format_remote_status(&stats, false, true, 0.0);
        let expected = format!("Name       : {}...", "界".repeat(45));
        assert!(out.contains(&expected));
        assert!(!out.contains('\u{202e}'));
        assert!(!out.contains('\u{1f680}'));
    }

    #[test]
    fn stats_encoder_uses_python_compile_stats_shape() {
        use lxmf_core::peer::LxmPeer;
        use lxmf_core::router::{LxmRouter, RouterConfig};

        let mut config = RouterConfig {
            propagation_enabled: true,
            ..Default::default()
        };
        config.delivery_limit_kb = 0.38;
        config.ext.message_storage_limit = Some(500_000_000);
        let mut router = LxmRouter::new(config);
        router.propagation_start_time = Some(1_700_000_000.0);
        router.client_propagation_messages_received = 2;
        router.client_propagation_messages_served = 3;
        router.unpeered_propagation_incoming = 4;
        router.unpeered_propagation_rx_bytes = 2048;
        let peer_hash = [0xAA; 16];
        let mut peer = LxmPeer::new(peer_hash);
        peer.offered = 4;
        peer.outgoing = 2;
        peer.set_unhandled_count(1);
        router.peers.insert(peer_hash, peer);
        router.static_peers.push(peer_hash);

        let encoded =
            encode_router_control_stats(&router, [0x11; 16], [0x22; 16], None, 1_700_003_600.0);
        let stats = decode_value(&encoded);
        let keys = stats
            .as_map()
            .expect("stats map")
            .iter()
            .map(|(key, _)| key.as_str().expect("string key"))
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "identity_hash",
                "destination_hash",
                "uptime",
                "delivery_limit",
                "propagation_limit",
                "sync_limit",
                "target_stamp_cost",
                "stamp_cost_flexibility",
                "peering_cost",
                "max_peering_cost",
                "autopeer_maxdepth",
                "from_static_only",
                "messagestore",
                "clients",
                "unpeered_propagation_incoming",
                "unpeered_propagation_rx_bytes",
                "static_peers",
                "discovered_peers",
                "total_peers",
                "max_peers",
                "peers",
            ]
        );
        assert_eq!(map_bytes(&stats, "identity_hash").unwrap(), vec![0x11; 16]);
        assert_eq!(
            map_bytes(&stats, "destination_hash").unwrap(),
            vec![0x22; 16]
        );
        assert_eq!(map_u64(&stats, "static_peers"), Some(1));
        assert_eq!(map_u64(&stats, "discovered_peers"), Some(0));
        assert_eq!(map_u64(&stats, "total_peers"), Some(1));
        assert_eq!(map_f64(&stats, "delivery_limit"), Some(0.38));

        let peers = map_value(&stats, "peers").unwrap().as_map().unwrap();
        let peer_stats = &peers[0].1;
        assert_eq!(map_str(peer_stats, "type"), Some("static"));
        assert_eq!(
            map_value(peer_stats, "messages").and_then(|messages| map_u64(messages, "unhandled")),
            Some(1)
        );
        assert_eq!(map_f64(peer_stats, "acceptance_rate"), Some(0.5));
    }
}
