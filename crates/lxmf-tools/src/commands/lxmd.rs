//! LXMF Daemon (lxmd) -- propagation node and message handler.
//!
//! Python reference: LXMF/Utilities/lxmd.py.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::Parser;
use tokio::sync::mpsc;

use std::sync::{Arc, Mutex};

use lxmf_core::constants::{
    DELIVERY_RETRY_WAIT, DeliveryMethod, MAX_DELIVERY_ATTEMPTS, PATH_REQUEST_WAIT,
};
use lxmf_core::link_delivery::{
    BackchannelSendCommand, BackchannelSendError, BackchannelSendReceipt, DeliveryResult,
    is_retryable_link_delivery_failure,
};
use lxmf_core::message::LxMessage;
use lxmf_core::propagation_node::{PropagationNode, PropagationNodeConfig};
use lxmf_core::router::{
    DirectDeliveryPlan, DirectDeliveryPlanInput, DirectReusableLinkState, DirectRouteSnapshot,
    LxmRouter, OutboundAction, plan_direct_delivery,
};
use lxmf_tools::daemon::{DaemonConfig, create_router_with_transport, execute_on_inbound};
use lxmf_tools::lxmd_cli::{
    Args, example_config, load_hash_list, normalize_hash_hex, parse_destination_hash,
    parse_send_fields_json,
};
use lxmf_tools::lxmd_control::{
    CONTROL_APP_NAME, ControlCommandKind, ControlResponse, decode_control_response,
    encode_control_success, encode_nil_response, encode_peer_error, encode_router_control_stats,
    exit_for_control_response, format_remote_status, print_control_link_error, query_control,
    resolve_remote_identity_hash,
};
use lxmf_tools::lxmd_runtime::{
    LxmdPaths, delivery_announce_app_data, preflight_control_command,
    propagation_announce_app_data, resolve_config_dirs,
};
use rns_identity::announce::AnnounceData;
use rns_identity::destination::Destination;
use rns_identity::identity::Identity;
use rns_identity::ratchet::{
    RatchetRing, ReceivedRatchet, clean_received_ratchets_dir, purge_expired_ratchets_in_memory,
};
use rns_runtime::lifecycle::ShutdownSignal;
use rns_transport::messages::{
    AnnounceHandlerEvent, TransportMessage, TransportQuery, TransportQueryResponse,
};

const LXMF_APP_NAME: &str = "lxmf.delivery";

#[derive(Debug, Clone, Default)]
struct ControlSnapshot {
    allowed_control: Vec<[u8; 16]>,
    peer_hashes: HashSet<[u8; 16]>,
    stats_response: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
enum ControlCommand {
    Sync([u8; 16]),
    Unpeer([u8; 16]),
}

fn setup_logging(verbose: u8, quiet: u8, service: bool) {
    let level = match (verbose, quiet) {
        (v, _) if v >= 3 => tracing::Level::TRACE,
        (2, _) => tracing::Level::DEBUG,
        (1, _) => tracing::Level::INFO,
        (0, 0) => {
            if service {
                tracing::Level::WARN
            } else {
                tracing::Level::INFO
            }
        }
        (_, q) if q >= 2 => tracing::Level::ERROR,
        (_, 1) => tracing::Level::WARN,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();
}

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

async fn sleep_or_shutdown(shutdown: &ShutdownSignal, duration: Duration) -> bool {
    tokio::select! {
        _ = shutdown.wait() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

fn mark_delivery_attempt(message: &mut LxMessage) -> u32 {
    let now = now_f64();
    message.delivery_attempts += 1;
    message.last_delivery_attempt = now;
    message.next_delivery_attempt = now + DELIVERY_RETRY_WAIT as f64;
    message.delivery_attempts
}

fn queue_path_request(
    transport_tx: &mpsc::Sender<TransportMessage>,
    request_hash: [u8; 16],
    drop_existing: bool,
    reason: &str,
) {
    if drop_existing {
        let (response_tx, _response_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = transport_tx.try_send(TransportMessage::Rpc {
            query: TransportQuery::DropPath { dest: request_hash },
            response_tx,
        }) {
            tracing::warn!(
                dest = %hex::encode(request_hash),
                error = %e,
                reason,
                "failed to queue path drop before LXMF retry"
            );
        }
    }

    if let Err(e) = transport_tx.try_send(TransportMessage::RequestPath {
        destination_hash: request_hash,
    }) {
        tracing::warn!(
            dest = %hex::encode(request_hash),
            error = %e,
            reason,
            "failed to queue path request before LXMF retry"
        );
    }
}

fn queue_unknown_propagation_node_path_request(
    transport_tx: &mpsc::Sender<TransportMessage>,
    node: [u8; 16],
    last_propagation_check: &mut f64,
    now: f64,
) -> bool {
    *last_propagation_check = now;
    if let Err(e) = transport_tx.try_send(TransportMessage::RequestPath {
        destination_hash: node,
    }) {
        tracing::warn!(
            node = %hex::encode(node),
            error = %e,
            "failed to queue propagation node path request before download"
        );
        return false;
    }
    true
}

fn requeue_after_path_request(
    router: &mut LxmRouter,
    transport_tx: &mpsc::Sender<TransportMessage>,
    mut message: LxMessage,
    request_hash: [u8; 16],
    reason: &str,
    increment_attempt: bool,
) {
    let now = now_f64();
    if increment_attempt {
        message.delivery_attempts += 1;
    }
    message.last_delivery_attempt = now;
    message.next_delivery_attempt = now + PATH_REQUEST_WAIT as f64;
    queue_path_request(transport_tx, request_hash, false, reason);
    tracing::warn!(
        dest = %hex::encode(message.destination_hash),
        request_dest = %hex::encode(request_hash),
        attempts = message.delivery_attempts,
        reason,
        "re-queuing LXMF message after path request"
    );
    router.send(message);
}

fn link_failure_retryable(reason: &str) -> bool {
    is_retryable_link_delivery_failure(reason)
}

fn route_hops_for(route_hops: &HashMap<[u8; 16], u8>, dest_hash: [u8; 16]) -> u8 {
    route_hops.get(&dest_hash).copied().unwrap_or(1).max(1)
}

fn direct_route_snapshot(
    route_hops: &HashMap<[u8; 16], u8>,
    dest_hash: [u8; 16],
) -> Option<DirectRouteSnapshot> {
    route_hops
        .get(&dest_hash)
        .copied()
        .map(|hops| DirectRouteSnapshot::new(dest_hash, hops))
}

fn direct_reusable_link_state(
    link_delivery: Option<&lxmf_core::link_delivery::LinkDeliveryManager>,
    dest_hash: [u8; 16],
) -> DirectReusableLinkState {
    let Some(link_delivery) = link_delivery else {
        return DirectReusableLinkState::None;
    };

    if let Some(snapshot) = link_delivery.direct_link_snapshot(dest_hash) {
        return match snapshot.delivery_state {
            lxmf_core::link_delivery::DeliveryState::Idle => DirectReusableLinkState::Active,
            lxmf_core::link_delivery::DeliveryState::Failed => {
                DirectReusableLinkState::Closed { activated: false }
            }
            _ => DirectReusableLinkState::Pending,
        };
    }

    if let Some(snapshot) = link_delivery.backchannel_link_snapshot(dest_hash) {
        if snapshot.queued_deliveries > 0 || snapshot.in_flight_deliveries > 0 {
            DirectReusableLinkState::Pending
        } else {
            DirectReusableLinkState::Active
        }
    } else {
        DirectReusableLinkState::None
    }
}

fn backchannel_receipt_from_runtime(
    receipt: rns_runtime::link_manager::LinkPayloadSendReceipt,
) -> BackchannelSendReceipt {
    match receipt {
        rns_runtime::link_manager::LinkPayloadSendReceipt::Packet(receipt) => {
            BackchannelSendReceipt::Packet {
                link_id: receipt.link_id,
                packet_hash: receipt.packet_hash,
            }
        }
        rns_runtime::link_manager::LinkPayloadSendReceipt::Resource(receipt) => {
            BackchannelSendReceipt::Resource {
                link_id: receipt.link_id,
                resource_hash: receipt.resource_hash,
            }
        }
    }
}

fn backchannel_error_from_runtime(
    err: rns_runtime::link_manager::LinkSendError,
) -> BackchannelSendError {
    match err {
        rns_runtime::link_manager::LinkSendError::LinkNotFound => {
            BackchannelSendError::LinkNotFound
        }
        rns_runtime::link_manager::LinkSendError::LinkNotActive => {
            BackchannelSendError::LinkNotActive
        }
        rns_runtime::link_manager::LinkSendError::NoSessionKeys => {
            BackchannelSendError::NoSessionKeys
        }
        rns_runtime::link_manager::LinkSendError::TransportUnavailable => {
            BackchannelSendError::TransportUnavailable
        }
        rns_runtime::link_manager::LinkSendError::ResourceStartFailed => {
            BackchannelSendError::ResourceStartFailed
        }
    }
}

fn create_control_announce_packet(
    identity: &Identity,
    control_dest_hash: [u8; 16],
) -> Result<Vec<u8>, String> {
    let announce = AnnounceData::create(identity, CONTROL_APP_NAME, None, None)
        .map_err(|e| format!("Failed to create control announce: {e}"))?;
    let payload = announce.pack();

    let flags = rns_wire::flags::PacketFlags {
        header_type: rns_wire::flags::HeaderType::Header1,
        context_flag: false,
        transport_type: rns_wire::flags::TransportType::Broadcast,
        destination_type: rns_wire::flags::DestinationType::Single,
        packet_type: rns_wire::flags::PacketType::Announce,
    };
    let header = rns_wire::header::PacketHeader {
        flags,
        hops: 0,
        transport_id: None,
        destination_hash: control_dest_hash,
        context: rns_wire::context::PacketContext::None,
    };

    let mut raw = header.pack();
    raw.extend_from_slice(&payload);
    Ok(raw)
}

fn send_control_announce_try(
    tx: &mpsc::Sender<TransportMessage>,
    identity: &Identity,
    control_dest_hash: [u8; 16],
) {
    match create_control_announce_packet(identity, control_dest_hash) {
        Ok(raw) => {
            let _ = tx.try_send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: control_dest_hash,
                },
            ));
        }
        Err(e) => tracing::warn!("{e}"),
    }
}

fn create_propagation_announce_packet_for(
    identity: &Identity,
    propagation_dest_hash: [u8; 16],
    config: &DaemonConfig,
    ratchet_ref: Option<&[u8; 32]>,
) -> Result<Vec<u8>, String> {
    let mut pn_data = lxmf_core::handlers::PropagationNodeAnnounceData::new(
        config.propagation_enabled && !config.from_static_only,
        config.propagation_limit_kb as u64,
        config.sync_limit_kb as u64,
        config.propagation_stamp_cost,
        config.propagation_stamp_flex,
        config.peering_cost,
    );
    if let Some(ref name) = config.node_name {
        pn_data.set_name(name);
    }
    let app_data = propagation_announce_app_data(&pn_data);

    let announce = AnnounceData::create(
        identity,
        "lxmf.propagation",
        Some(app_data.as_slice()),
        ratchet_ref,
    )
    .map_err(|e| format!("Failed to create propagation announce: {e}"))?;

    let payload = announce.pack();

    let flags = rns_wire::flags::PacketFlags {
        header_type: rns_wire::flags::HeaderType::Header1,
        context_flag: ratchet_ref.is_some(),
        transport_type: rns_wire::flags::TransportType::Broadcast,
        destination_type: rns_wire::flags::DestinationType::Single,
        packet_type: rns_wire::flags::PacketType::Announce,
    };
    let header = rns_wire::header::PacketHeader {
        flags,
        hops: 0,
        transport_id: None,
        destination_hash: propagation_dest_hash,
        context: rns_wire::context::PacketContext::None,
    };

    let mut raw = header.pack();
    raw.extend_from_slice(&payload);
    Ok(raw)
}

fn send_propagation_announce_try(
    tx: &mpsc::Sender<TransportMessage>,
    identity: &Identity,
    propagation_dest_hash: [u8; 16],
    config: &DaemonConfig,
) {
    match create_propagation_announce_packet_for(identity, propagation_dest_hash, config, None) {
        Ok(raw) => {
            let _ = tx.try_send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: propagation_dest_hash,
                },
            ));
        }
        Err(e) => tracing::warn!("{e}"),
    }
}

/// Owns identity, router, and crypto state; drives the daemon main loop.
// Several fields are long-lived state handles that are intentionally retained
// even when the runner only touches them through setup or shutdown paths.
#[allow(dead_code)]
struct LxmdRunner {
    identity: Identity,
    identity_hash: String,
    lxmf_dest_hash: [u8; 16],
    propagation_dest_hash: [u8; 16],
    control_dest_hash: [u8; 16],
    router: LxmRouter,
    config: DaemonConfig,
    data_dir: PathBuf,
    messages_dir: PathBuf,
    ratchets_dir: PathBuf,
    ratchet_ring: RatchetRing,
    received_ratchets: HashMap<String, ReceivedRatchet>,
    known_identities: HashMap<String, [u8; 64]>,
    route_hops: HashMap<[u8; 16], u8>,
    link_delivery: Option<lxmf_core::link_delivery::LinkDeliveryManager>,
    link_command_tx: mpsc::Sender<rns_runtime::link_manager::LinkManagerCommand>,
    link_identified_rx: mpsc::Receiver<([u8; 16], [u8; 16])>,
    link_packet_proof_rx: mpsc::Receiver<rns_runtime::link_manager::LinkPacketProof>,
    link_resource_proof_rx: mpsc::Receiver<rns_runtime::link_manager::LinkResourceProof>,
    backchannel_command_rx: Option<mpsc::Receiver<BackchannelSendCommand>>,
    link_delivery_failures: Vec<String>,
    propagation_sync: Option<lxmf_core::propagation_sync::PropagationSyncTask>,
    propagation_client: Option<lxmf_core::propagation_client::PropagationClient>,
    propagation_node: Option<Arc<Mutex<PropagationNode>>>,
    transport_tx: mpsc::Sender<TransportMessage>,
    /// Plaintext application data decoded by the LinkManager.
    link_packet_rx: mpsc::Receiver<(Vec<u8>, [u8; 16])>,
    /// Completed resource transfers from the LinkManager.
    resource_rx: mpsc::Receiver<(Vec<u8>, [u8; 16])>,
    /// Plaintext propagation-wrapper packets decoded by the propagation LinkManager.
    prop_link_packet_rx: mpsc::Receiver<(Vec<u8>, [u8; 16])>,
    /// Completed propagation-wrapper resources from the propagation LinkManager.
    prop_resource_rx: mpsc::Receiver<(Vec<u8>, [u8; 16])>,
    /// Non-link inbound packets; still encrypted, need destination-level decrypt.
    inbound_raw_rx: mpsc::Receiver<Vec<u8>>,
    announce_rx: mpsc::Receiver<AnnounceHandlerEvent>,
    last_peer_announce: f64,
    last_node_announce: f64,
    last_propagation_check: f64,
    last_crypto_save: f64,
    last_cull: f64,
    last_ratchet_clean: f64,
    received_ratchets_dir: PathBuf,
    control_state: Arc<Mutex<ControlSnapshot>>,
    control_command_rx: mpsc::Receiver<ControlCommand>,
}

impl LxmdRunner {
    fn new(
        config: DaemonConfig,
        config_dir: &Path,
        transport_tx: mpsc::Sender<TransportMessage>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let paths = LxmdPaths::new(config_dir);
        std::fs::create_dir_all(&paths.config_dir)?;

        let identity_path = paths.preferred_identity_path().to_path_buf();
        let identity = if identity_path.exists() {
            tracing::info!("Loading identity from {}", identity_path.display());
            Identity::from_file(&identity_path)?
        } else {
            tracing::info!("No identity found, generating new one");
            let id = Identity::new();
            id.to_file(&paths.identity_path)?;
            id
        };

        let identity_hash = hex::encode(identity.hash);

        let lxmf_dest_hash =
            Destination::hash_from_name_and_identity(LXMF_APP_NAME, Some(&identity.hash));
        let propagation_dest_hash =
            Destination::hash_from_name_and_identity("lxmf.propagation", Some(&identity.hash));
        let control_dest_hash =
            Destination::hash_from_name_and_identity(CONTROL_APP_NAME, Some(&identity.hash));

        tracing::info!(
            "Identity: {} (LXMF: {})",
            &identity_hash[..16],
            &hex::encode(lxmf_dest_hash)[..16],
        );

        let ratchet_dir = paths.ratchets_dir.clone();
        std::fs::create_dir_all(&ratchet_dir)?;
        let ring_path = paths.ratchet_ring_path.clone();
        let mut ratchet_ring = if ring_path.exists() {
            RatchetRing::load(&ring_path)
                .map(|(ring, _sig)| ring)
                .unwrap_or_else(|e| {
                    tracing::warn!("Failed to load ratchet ring: {e}, creating new");
                    RatchetRing::new()
                })
        } else {
            RatchetRing::new()
        };
        if ratchet_ring.is_empty() {
            ratchet_ring.rotate();
            let sig = identity
                .sign(
                    ratchet_ring
                        .current_public_key()
                        .unwrap_or([0u8; 32])
                        .as_ref(),
                )
                .unwrap_or([0u8; 64]);
            let _ = ratchet_ring.save(&ring_path, &sig);
        }

        // Mirrors Python `Identity._clean_ratchets()`: sweep the directory at
        // startup so stale entries don't survive a restart.
        let received_dir = paths.received_ratchets_dir.clone();
        std::fs::create_dir_all(&received_dir)?;
        let removed = clean_received_ratchets_dir(&received_dir);
        if removed > 0 {
            tracing::info!(removed, "swept expired received-ratchet files at startup");
        }
        let mut received_ratchets = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&received_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_stem().and_then(|n| n.to_str())
                    && let Ok(rr) = ReceivedRatchet::load(&path)
                {
                    received_ratchets.insert(name.to_string(), rr);
                }
            }
        }

        // known_identities format: concat of [dest_hash:16][pubkey:64]
        let ki_path = paths.known_identities_path.clone();
        let mut known_identities: HashMap<String, [u8; 64]> = HashMap::new();
        if ki_path.exists()
            && let Ok(data) = std::fs::read(&ki_path)
        {
            let mut pos = 0;
            while pos + 80 <= data.len() {
                let mut dh = [0u8; 16];
                dh.copy_from_slice(&data[pos..pos + 16]);
                let mut pk = [0u8; 64];
                pk.copy_from_slice(&data[pos + 16..pos + 80]);
                known_identities.insert(hex::encode(dh), pk);
                pos += 80;
            }
        }

        tracing::info!(
            ratchet_keys = ratchet_ring.len(),
            received_ratchets = received_ratchets.len(),
            known_identities = known_identities.len(),
            "Crypto state loaded"
        );

        let router = create_router_with_transport(&config, transport_tx.clone());

        // LinkManager handles link handshakes (ECDH), keepalive, identification,
        // and resource transfers; it forwards plaintext application data here.
        let (delivery_tx, delivery_rx) = mpsc::channel(256);
        let (link_packet_tx, link_packet_rx) = mpsc::channel::<(Vec<u8>, [u8; 16])>(256);
        let (resource_tx, resource_rx) = mpsc::channel::<(Vec<u8>, [u8; 16])>(256);
        let (prop_link_packet_tx, prop_link_packet_rx) = mpsc::channel::<(Vec<u8>, [u8; 16])>(256);
        let (prop_resource_tx, prop_resource_rx) = mpsc::channel::<(Vec<u8>, [u8; 16])>(256);
        let (inbound_raw_tx, inbound_raw_rx) = mpsc::channel::<Vec<u8>>(256);
        let (link_command_tx, link_command_rx) =
            mpsc::channel::<rns_runtime::link_manager::LinkManagerCommand>(256);
        let (link_identified_tx, link_identified_rx) = mpsc::channel::<([u8; 16], [u8; 16])>(256);
        let (link_packet_proof_tx, link_packet_proof_rx) =
            mpsc::channel::<rns_runtime::link_manager::LinkPacketProof>(256);
        let (link_resource_proof_tx, link_resource_proof_rx) =
            mpsc::channel::<rns_runtime::link_manager::LinkResourceProof>(256);

        let signing_key = identity.get_signing_key();
        let mut link_mgr = rns_runtime::link_manager::LinkManager::with_destination(
            transport_tx.clone(),
            delivery_rx,
            &identity,
            LXMF_APP_NAME,
            signing_key,
        );
        link_mgr.set_link_packet_channel(link_packet_tx);
        link_mgr.set_resource_completed_channel(resource_tx);
        link_mgr.set_inbound_raw_channel(inbound_raw_tx);
        link_mgr.set_link_identified_channel(link_identified_tx);
        link_mgr.set_link_packet_proof_channel(link_packet_proof_tx);
        link_mgr.set_outbound_resource_proof_channel(link_resource_proof_tx);

        let _ = transport_tx.try_send(TransportMessage::RegisterDestination {
            hash: lxmf_dest_hash,
            app_name: LXMF_APP_NAME.to_string(),
            delivery_tx: Some(delivery_tx),
        });

        // Spawn the LinkManager as a background task
        tokio::spawn(async move {
            link_mgr.run_with_commands(link_command_rx).await;
        });

        let control_state = Arc::new(Mutex::new(ControlSnapshot {
            allowed_control: vec![identity.hash],
            peer_hashes: HashSet::new(),
            stats_response: None,
        }));
        let (control_command_tx, control_command_rx) = mpsc::channel::<ControlCommand>(256);

        let propagation_node: Option<Arc<Mutex<PropagationNode>>> = if config.propagation_enabled {
            let (prop_delivery_tx, prop_delivery_rx) = mpsc::channel(256);
            let _ = transport_tx.try_send(TransportMessage::RegisterDestination {
                hash: propagation_dest_hash,
                app_name: "lxmf.propagation".to_string(),
                delivery_tx: Some(prop_delivery_tx),
            });

            let pn_config = PropagationNodeConfig {
                max_storage: config
                    .message_storage_limit
                    .unwrap_or(config.propagation_limit_kb * 1024),
                max_message_size: config.propagation_limit_kb * 1024,
                max_message_age: lxmf_core::constants::MESSAGE_EXPIRY,
                min_stamp_cost: config
                    .propagation_stamp_cost
                    .saturating_sub(config.propagation_stamp_flex),
                ..Default::default()
            };
            let prop_storage_path = paths.propagation_store_dir.clone();
            let pn = match PropagationNode::with_storage(
                pn_config,
                propagation_dest_hash,
                prop_storage_path,
            ) {
                Ok(node) => Arc::new(Mutex::new(node)),
                Err(e) => {
                    tracing::warn!("Propagation disk storage failed, using in-memory: {e}");
                    Arc::new(Mutex::new(PropagationNode::new(
                        PropagationNodeConfig {
                            max_storage: config
                                .message_storage_limit
                                .unwrap_or(config.propagation_limit_kb * 1024),
                            max_message_size: config.propagation_limit_kb * 1024,
                            max_message_age: lxmf_core::constants::MESSAGE_EXPIRY,
                            min_stamp_cost: config
                                .propagation_stamp_cost
                                .saturating_sub(config.propagation_stamp_flex),
                            ..Default::default()
                        },
                        propagation_dest_hash,
                    )))
                }
            };

            // TODO(hardware-identity): route propagation link signing through the
            // backend-aware Identity path before supporting hardware-backed lxmd.
            let prop_signing_key = identity.get_signing_key().unwrap_or_else(|| {
                panic!("Identity must have signing key for propagation link management")
            });
            let mut prop_link_mgr = rns_runtime::link_manager::LinkManager::with_destination(
                transport_tx.clone(),
                prop_delivery_rx,
                &identity,
                "lxmf.propagation",
                Some(prop_signing_key),
            );
            prop_link_mgr.set_link_packet_channel(prop_link_packet_tx);
            prop_link_mgr.set_resource_completed_channel(prop_resource_tx);

            let pn_for_handler = pn.clone();
            let offer_path_hash = rns_crypto::sha::truncated_hash(
                lxmf_core::constants::OFFER_REQUEST_PATH.as_bytes(),
            );
            let get_path_hash =
                rns_crypto::sha::truncated_hash(lxmf_core::constants::MESSAGE_GET_PATH.as_bytes());
            let link_identities = prop_link_mgr.link_identities_handle();
            let local_identity_hash = identity.hash;
            prop_link_mgr.set_request_handler(move |link_id, path_hash, data| {
                let mut node = pn_for_handler.lock().ok()?;
                let remote_identity_hash = link_identities
                    .lock()
                    .ok()
                    .and_then(|ids| ids.get(&link_id).copied());
                let remote_identity_ref = remote_identity_hash.as_ref();
                let client_dest_hash = remote_identity_hash
                    .map(|identity_hash| {
                        Destination::hash_from_name_and_identity(
                            LXMF_APP_NAME,
                            Some(&identity_hash),
                        )
                    })
                    .unwrap_or([0; 16]);
                let handler =
                    lxmf_core::handlers::PropagationRequestHandler::new(local_identity_hash);
                if path_hash == offer_path_hash {
                    tracing::info!("propagation: handling offer request");
                    Some(handler.handle_offer_request(remote_identity_ref, &data, &mut node))
                } else if path_hash == get_path_hash {
                    tracing::info!("propagation: handling get request");
                    Some(handler.handle_message_get_request(
                        remote_identity_ref,
                        &client_dest_hash,
                        &data,
                        &mut node,
                    ))
                } else {
                    tracing::debug!(
                        path = hex::encode(path_hash),
                        "propagation: unknown request path"
                    );
                    None
                }
            });

            let prop_announce_tx = transport_tx.clone();
            let prop_announce_identity = identity
                .get_private_key()
                .and_then(|key| Identity::from_private_key(&*key).ok());
            let prop_announce_config = config.clone();
            prop_link_mgr.set_announce_handler(move || {
                if let Some(ref identity) = prop_announce_identity {
                    send_propagation_announce_try(
                        &prop_announce_tx,
                        identity,
                        propagation_dest_hash,
                        &prop_announce_config,
                    );
                }
            });

            tokio::spawn(async move {
                prop_link_mgr.run().await;
            });

            let (control_delivery_tx, control_delivery_rx) = mpsc::channel(256);
            let _ = transport_tx.try_send(TransportMessage::RegisterDestination {
                hash: control_dest_hash,
                app_name: CONTROL_APP_NAME.to_string(),
                delivery_tx: Some(control_delivery_tx),
            });

            // TODO(hardware-identity): route control link signing through the
            // backend-aware Identity path before supporting hardware-backed lxmd.
            let control_signing_key = identity.get_signing_key().unwrap_or_else(|| {
                panic!("Identity must have signing key for control link management")
            });
            let mut control_link_mgr = rns_runtime::link_manager::LinkManager::with_destination(
                transport_tx.clone(),
                control_delivery_rx,
                &identity,
                CONTROL_APP_NAME,
                Some(control_signing_key),
            );
            let control_link_identities = control_link_mgr.link_identities_handle();
            let stats_path_hash =
                rns_crypto::sha::truncated_hash(lxmf_core::constants::STATS_GET_PATH.as_bytes());
            let sync_path_hash =
                rns_crypto::sha::truncated_hash(lxmf_core::constants::SYNC_REQUEST_PATH.as_bytes());
            let unpeer_path_hash = rns_crypto::sha::truncated_hash(
                lxmf_core::constants::UNPEER_REQUEST_PATH.as_bytes(),
            );
            let control_state_for_handler = control_state.clone();
            let command_tx_for_handler = control_command_tx.clone();
            control_link_mgr.set_request_handler(move |link_id, path_hash, data| {
                let remote_identity_hash = control_link_identities
                    .lock()
                    .ok()
                    .and_then(|ids| ids.get(&link_id).copied());
                let snapshot = control_state_for_handler
                    .lock()
                    .map(|state| state.clone())
                    .unwrap_or_default();

                let Some(remote_hash) = remote_identity_hash else {
                    return Some(encode_peer_error(
                        lxmf_core::constants::PeerError::NoIdentity,
                    ));
                };
                if !snapshot.allowed_control.contains(&remote_hash) {
                    return Some(encode_peer_error(lxmf_core::constants::PeerError::NoAccess));
                }

                if path_hash == stats_path_hash {
                    tracing::info!("control: handling stats request");
                    Some(snapshot.stats_response.unwrap_or_else(encode_nil_response))
                } else if path_hash == sync_path_hash {
                    tracing::info!("control: handling peer sync request");
                    if data.len() != 16 {
                        return Some(encode_peer_error(
                            lxmf_core::constants::PeerError::InvalidData,
                        ));
                    }
                    let mut peer_hash = [0u8; 16];
                    peer_hash.copy_from_slice(&data);
                    if !snapshot.peer_hashes.contains(&peer_hash) {
                        return Some(encode_peer_error(lxmf_core::constants::PeerError::NotFound));
                    }
                    let _ = command_tx_for_handler.try_send(ControlCommand::Sync(peer_hash));
                    Some(encode_control_success())
                } else if path_hash == unpeer_path_hash {
                    tracing::info!("control: handling unpeer request");
                    if data.len() != 16 {
                        return Some(encode_peer_error(
                            lxmf_core::constants::PeerError::InvalidData,
                        ));
                    }
                    let mut peer_hash = [0u8; 16];
                    peer_hash.copy_from_slice(&data);
                    if !snapshot.peer_hashes.contains(&peer_hash) {
                        return Some(encode_peer_error(lxmf_core::constants::PeerError::NotFound));
                    }
                    let _ = command_tx_for_handler.try_send(ControlCommand::Unpeer(peer_hash));
                    Some(encode_control_success())
                } else {
                    tracing::debug!(
                        path = hex::encode(path_hash),
                        "control: unknown request path"
                    );
                    None
                }
            });

            let control_announce_tx = transport_tx.clone();
            let control_announce_identity = identity
                .get_private_key()
                .and_then(|key| Identity::from_private_key(&*key).ok());
            control_link_mgr.set_announce_handler(move || {
                if let Some(ref identity) = control_announce_identity {
                    send_control_announce_try(&control_announce_tx, identity, control_dest_hash);
                }
            });

            tokio::spawn(async move {
                control_link_mgr.run().await;
            });

            tracing::info!("propagation sync server ready for offer/get requests");
            Some(pn)
        } else {
            None
        };

        let (announce_tx, announce_rx) = mpsc::channel(256);
        let _ = transport_tx.try_send(TransportMessage::RegisterAnnounceHandler {
            aspect_filter: Some(LXMF_APP_NAME.to_string()),
            receive_path_responses: true,
            callback_tx: announce_tx.clone(),
        });
        let _ = transport_tx.try_send(TransportMessage::RegisterAnnounceHandler {
            aspect_filter: Some("lxmf.propagation".to_string()),
            receive_path_responses: true,
            callback_tx: announce_tx,
        });

        let messages_dir = paths.messages_dir.clone();
        std::fs::create_dir_all(&messages_dir)?;

        let now = now_f64();

        let mut runner = Self {
            identity,
            identity_hash,
            lxmf_dest_hash,
            propagation_dest_hash,
            control_dest_hash,
            router,
            config,
            data_dir: paths.router_state_dir,
            messages_dir,
            ratchets_dir: paths.ratchets_dir,
            ratchet_ring,
            received_ratchets,
            known_identities,
            route_hops: HashMap::new(),
            link_delivery: None,
            link_command_tx,
            link_identified_rx,
            link_packet_proof_rx,
            link_resource_proof_rx,
            backchannel_command_rx: None,
            link_delivery_failures: Vec::new(),
            propagation_sync: None,
            propagation_client: None,
            propagation_node: None,
            transport_tx: transport_tx.clone(),
            link_packet_rx,
            resource_rx,
            prop_link_packet_rx,
            prop_resource_rx,
            inbound_raw_rx,
            announce_rx,
            last_peer_announce: 0.0,
            last_node_announce: 0.0,
            last_propagation_check: 0.0,
            last_crypto_save: now,
            last_cull: now,
            last_ratchet_clean: now,
            received_ratchets_dir: received_dir,
            control_state,
            control_command_rx,
        };

        if runner.config.propagation_enabled {
            if let Some(ref pn) = propagation_node {
                let sync = lxmf_core::propagation_sync::PropagationSyncTask::with_shared_node(
                    transport_tx.clone(),
                    pn.clone(),
                );
                runner.propagation_sync = Some(sync);
            }
            runner.propagation_node = propagation_node;

            tracing::info!("propagation sync server initialized");
        }

        if runner.config.propagation_enabled || runner.config.outbound_propagation_node.is_some() {
            let mut client = lxmf_core::propagation_client::PropagationClient::new(
                transport_tx.clone(),
                Some(runner.identity.get_public_key()),
                runner.identity.get_signing_key(),
            );
            if let Some(ref node_hex) = runner.config.outbound_propagation_node {
                match hex::decode(node_hex) {
                    Ok(bytes) if bytes.len() == 16 => {
                        let mut node = [0u8; 16];
                        node.copy_from_slice(&bytes);
                        client.set_propagation_node(node);
                        runner.router.outbound_propagation_node = Some(node);
                        runner
                            .router
                            .peers
                            .entry(node)
                            .or_insert_with(|| lxmf_core::peer::LxmPeer::new(node));
                        if !runner.router.static_peers.contains(&node) {
                            runner.router.static_peers.push(node);
                        }
                        tracing::info!(
                            node = %hex::encode(node),
                            "outbound propagation node configured"
                        );
                    }
                    _ => {
                        tracing::warn!(
                            node = %node_hex,
                            "ignoring invalid outbound propagation node hash"
                        );
                    }
                }
            }
            runner.propagation_client = Some(client);

            tracing::info!("propagation client initialized");
        }

        Ok(runner)
    }

    fn apply_config(&mut self) {
        if self.config.propagation_enabled {
            self.router.set_propagation_enabled(true);
            if self.router.propagation_start_time.is_none() {
                self.router.propagation_start_time = Some(now_f64());
            }
            self.router.set_autopeer(self.config.autopeer);
            self.router.set_max_peers(self.config.max_peers);
            self.router
                .set_propagation_limit(self.config.propagation_limit_kb);
            self.router.set_stamp_requirements(
                self.config.propagation_stamp_cost,
                self.config.propagation_stamp_flex,
            );
        }

        self.router
            .set_message_storage_limit(self.config.message_storage_limit);
        self.router.set_authentication(self.config.auth_required);

        if let Some(cost) = self.config.stamp_cost {
            self.router.set_stamp_cost(self.lxmf_dest_hash, cost);
        }

        if self.config.enforce_ratchets {
            self.router.set_enforce_ratchets(true);
        }
        if self.config.enforce_stamps {
            self.router.set_enforce_stamps(true);
        }

        for configured in &self.config.control_allowed {
            match parse_destination_hash(configured) {
                Ok(hash) => self.router.allow_control(hash),
                Err(e) => {
                    tracing::warn!(hash = %configured, "ignoring invalid control_allowed hash: {e}")
                }
            }
        }
        for configured in &self.config.static_peers {
            match parse_destination_hash(configured) {
                Ok(hash) => {
                    if !self.router.static_peers.contains(&hash) {
                        self.router.static_peers.push(hash);
                    }
                    self.router
                        .peers
                        .entry(hash)
                        .or_insert_with(|| lxmf_core::peer::LxmPeer::new(hash));
                }
                Err(e) => {
                    tracing::warn!(hash = %configured, "ignoring invalid static peer hash: {e}")
                }
            }
        }
        for configured in &self.config.prioritise_destinations {
            match parse_destination_hash(configured) {
                Ok(hash) => self.router.prioritise(hash, 1),
                Err(e) => {
                    tracing::warn!(hash = %configured, "ignoring invalid prioritised destination hash: {e}")
                }
            }
        }
    }

    fn refresh_control_state(&mut self) {
        let mut allowed_control = vec![self.identity.hash];
        for hash in &self.router.allowed_control {
            if !allowed_control.contains(hash) {
                allowed_control.push(*hash);
            }
        }

        let peer_hashes = self.router.peers.keys().copied().collect::<HashSet<_>>();
        let stats_response = if self.config.propagation_enabled {
            let node_guard = self
                .propagation_node
                .as_ref()
                .and_then(|node| node.lock().ok());
            Some(encode_router_control_stats(
                &self.router,
                self.identity.hash,
                self.propagation_dest_hash,
                node_guard.as_deref(),
                now_f64(),
            ))
        } else {
            None
        };

        if let Ok(mut state) = self.control_state.lock() {
            *state = ControlSnapshot {
                allowed_control,
                peer_hashes,
                stats_response,
            };
        }
    }

    fn create_announce_packet(&mut self) -> Result<Vec<u8>, String> {
        if self.ratchet_ring.needs_rotation() {
            self.ratchet_ring.rotate();
            self.save_crypto_state();
        }

        let ratchet_pub = self.ratchet_ring.current_public_key();
        let ratchet_ref = ratchet_pub.as_ref();

        let app_data =
            delivery_announce_app_data(self.config.display_name.as_deref(), self.config.stamp_cost);

        let announce = AnnounceData::create(
            &self.identity,
            LXMF_APP_NAME,
            Some(app_data.as_slice()),
            ratchet_ref,
        )
        .map_err(|e| format!("Failed to create announce: {e}"))?;

        let payload = announce.pack();

        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: ratchet_ref.is_some(),
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: self.lxmf_dest_hash,
            context: rns_wire::context::PacketContext::None,
        };

        let mut raw = header.pack();
        raw.extend_from_slice(&payload);
        Ok(raw)
    }

    fn create_propagation_announce_packet(&mut self) -> Result<Vec<u8>, String> {
        if self.ratchet_ring.needs_rotation() {
            self.ratchet_ring.rotate();
            self.save_crypto_state();
        }

        let ratchet_pub = self.ratchet_ring.current_public_key();
        let ratchet_ref = ratchet_pub.as_ref();

        create_propagation_announce_packet_for(
            &self.identity,
            self.propagation_dest_hash,
            &self.config,
            ratchet_ref,
        )
    }

    async fn send_announce(&mut self) -> Result<(), String> {
        let raw = self.create_announce_packet()?;
        self.transport_tx
            .send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: self.lxmf_dest_hash,
                },
            ))
            .await
            .map_err(|e| format!("Failed to send announce: {e}"))
    }

    async fn send_propagation_announce(&mut self) -> Result<(), String> {
        let raw = self.create_propagation_announce_packet()?;
        self.transport_tx
            .send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: self.propagation_dest_hash,
                },
            ))
            .await
            .map_err(|e| format!("Failed to send propagation announce: {e}"))
    }

    async fn send_control_announce(&mut self) -> Result<(), String> {
        let raw = create_control_announce_packet(&self.identity, self.control_dest_hash)?;
        self.transport_tx
            .send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: self.control_dest_hash,
                },
            ))
            .await
            .map_err(|e| format!("Failed to send control announce: {e}"))
    }

    fn should_announce_control(&self) -> bool {
        if !self.config.propagation_enabled {
            return false;
        }
        let mut allowed = HashSet::from([self.identity.hash]);
        allowed.extend(self.router.allowed_control.iter().copied());
        allowed.len() > 1
    }

    fn drain_control_commands(&mut self) {
        while let Ok(command) = self.control_command_rx.try_recv() {
            match command {
                ControlCommand::Sync(peer_hash) => {
                    if !self.router.peers.contains_key(&peer_hash) {
                        continue;
                    }
                    if let Some(ref mut sync) = self.propagation_sync {
                        sync.request_sync_now(peer_hash);
                    }
                    if let Some(peer) = self.router.peers.get_mut(&peer_hash) {
                        peer.next_sync_attempt = 0.0;
                        peer.alive = true;
                    }
                    tracing::info!(peer = %hex::encode(peer_hash), "control: queued peer sync");
                }
                ControlCommand::Unpeer(peer_hash) => {
                    self.router.unpeer(&peer_hash);
                    if let Err(e) = self.router.save_state(&self.data_dir) {
                        tracing::warn!("Failed to save router state after control unpeer: {e}");
                    }
                    tracing::info!(peer = %hex::encode(peer_hash), "control: unpeered peer");
                }
            }
        }
    }

    fn drain_backchannel_events(&mut self) {
        let mut identified = Vec::new();
        while let Ok(item) = self.link_identified_rx.try_recv() {
            identified.push(item);
        }
        for (link_id, identity_hash) in identified {
            self.ensure_link_delivery();
            let dest_hash =
                Destination::hash_from_name_and_identity(LXMF_APP_NAME, Some(&identity_hash));
            if let Some(ref mut ld) = self.link_delivery {
                ld.register_backchannel(dest_hash, link_id);
            }
            tracing::info!(
                link_id = %hex::encode(link_id),
                identity = %hex::encode(identity_hash),
                dest = %hex::encode(dest_hash),
                "LXMF inbound Link identified; registered daemon backchannel"
            );
        }

        let mut packet_proofs = Vec::new();
        while let Ok(proof) = self.link_packet_proof_rx.try_recv() {
            packet_proofs.push(proof);
        }
        for proof in packet_proofs {
            if let Some(result) = self
                .link_delivery
                .as_mut()
                .and_then(|ld| ld.handle_backchannel_packet_proof(proof.link_id, proof.packet_hash))
            {
                self.handle_link_delivery_result(result);
            }
        }

        let mut resource_proofs = Vec::new();
        while let Ok(proof) = self.link_resource_proof_rx.try_recv() {
            resource_proofs.push(proof);
        }
        for proof in resource_proofs {
            if let Some(result) = self.link_delivery.as_mut().and_then(|ld| {
                ld.handle_backchannel_resource_proof(proof.link_id, proof.resource_hash)
            }) {
                self.handle_link_delivery_result(result);
            }
        }

        self.drain_core_backchannel_send_commands();
    }

    fn drain_core_backchannel_send_commands(&mut self) {
        let Some(rx) = self.backchannel_command_rx.as_mut() else {
            return;
        };
        let command_tx = self.link_command_tx.clone();

        while let Ok(command) = rx.try_recv() {
            let (result_tx, result_rx) = tokio::sync::oneshot::channel();
            let link_id = command.link_id;
            let link_command = rns_runtime::link_manager::LinkManagerCommand::SendLinkPayload {
                link_id,
                payload: command.payload,
                auto_compress: command.auto_compress,
                result_tx: Some(result_tx),
            };
            match command_tx.try_send(link_command) {
                Ok(()) => {
                    tokio::spawn(async move {
                        let result = match result_rx.await {
                            Ok(Ok(receipt)) => Ok(backchannel_receipt_from_runtime(receipt)),
                            Ok(Err(err)) => Err(backchannel_error_from_runtime(err)),
                            Err(_) => Err(BackchannelSendError::TransportUnavailable),
                        };
                        let _ = command.result_tx.send(result);
                    });
                }
                Err(err) => {
                    tracing::warn!(
                        link_id = %hex::encode(link_id),
                        error = %err,
                        "failed to queue LXMF daemon backchannel send command"
                    );
                    let _ = command
                        .result_tx
                        .send(Err(BackchannelSendError::TransportUnavailable));
                }
            }
        }
    }

    fn handle_link_delivery_result(&mut self, result: DeliveryResult) {
        match result {
            DeliveryResult::Complete { msg_hash, .. } => {
                if let Some(hash) = msg_hash {
                    let _ = self.router.mark_outbound_delivered(&hash);
                    tracing::info!(hash = %hex::encode(hash), "link delivery complete");
                }
            }
            DeliveryResult::Rejected {
                msg_hash,
                dest_hash,
                reason,
                ..
            } => {
                tracing::warn!(
                    dest = %hex::encode(dest_hash),
                    reason = %reason,
                    "link delivery rejected"
                );
                if let Some(hash) = msg_hash {
                    let _ = self.router.mark_outbound_rejected(&hash);
                }
                self.link_delivery_failures.push(reason);
            }
            DeliveryResult::Failed {
                msg_hash,
                dest_hash,
                message,
                reason,
                ..
            } => {
                tracing::warn!(
                    dest = %hex::encode(dest_hash),
                    reason = %reason,
                    attempts = message.delivery_attempts,
                    "link delivery failed"
                );
                let router_owned = msg_hash.is_some_and(|hash| {
                    self.router
                        .pending_outbound
                        .iter()
                        .any(|pending| pending.hash == Some(hash))
                });
                if link_failure_retryable(&reason)
                    && message.delivery_attempts <= MAX_DELIVERY_ATTEMPTS
                {
                    if let Some(hash) = msg_hash {
                        tracing::warn!(
                            hash = %hex::encode(hash),
                            "retrying message after link delivery failure"
                        );
                    }
                    if router_owned {
                        queue_path_request(&self.transport_tx, dest_hash, false, &reason);
                        if let Some(hash) = msg_hash {
                            let _ = self
                                .router
                                .defer_outbound_for_path_request(&hash, now_f64());
                        }
                    } else {
                        requeue_after_path_request(
                            &mut self.router,
                            &self.transport_tx,
                            message,
                            dest_hash,
                            &reason,
                            false,
                        );
                    }
                } else {
                    if let Some(hash) = msg_hash {
                        if router_owned {
                            let _ = self.router.mark_outbound_failed(&hash);
                        }
                        tracing::warn!(
                            hash = %hex::encode(hash),
                            "message delivery failed"
                        );
                    }
                    self.link_delivery_failures.push(reason);
                }
            }
        }
    }

    async fn refresh_route_hops_from_transport(&mut self) {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = self.transport_tx.try_send(TransportMessage::Rpc {
            query: TransportQuery::GetPathTable,
            response_tx,
        }) {
            tracing::debug!(error = %e, "failed to request transport path table for LXMF routing");
            return;
        }

        let Ok(Ok(TransportQueryResponse::PathTable(entries))) =
            tokio::time::timeout(Duration::from_millis(100), response_rx).await
        else {
            return;
        };

        let now = now_f64();
        for entry in entries {
            if entry.expires > now {
                self.route_hops.insert(entry.hash, entry.hops.max(1));
            }
        }
    }

    fn tick(&mut self) {
        let now = now_f64();

        self.drain_control_commands();
        self.drain_backchannel_events();

        self.router.process_deferred_stamps();
        let known_identities = self
            .known_identities
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        let route_hops = self.route_hops.clone();
        let direct_destinations = self
            .router
            .pending_outbound
            .iter()
            .filter(|message| message.method == DeliveryMethod::Direct)
            .map(|message| message.destination_hash)
            .collect::<HashSet<_>>();
        let reusable_links = direct_destinations
            .iter()
            .copied()
            .map(|dest| {
                (
                    dest,
                    direct_reusable_link_state(self.link_delivery.as_ref(), dest),
                )
            })
            .collect::<HashMap<_, _>>();
        let actions = self.router.process_outbound_with_direct(|message, _now| {
            let dest = message.destination_hash;
            DirectDeliveryPlanInput {
                identity_known: known_identities.contains(&hex::encode(dest)),
                route: direct_route_snapshot(&route_hops, dest),
                reusable_link: reusable_links
                    .get(&dest)
                    .copied()
                    .unwrap_or(DirectReusableLinkState::None),
            }
        });
        if !actions.is_empty() {
            self.execute_encrypted_actions(actions);
            self.drain_core_backchannel_send_commands();
        }

        if let Some(ref mut ld) = self.link_delivery {
            ld.drain_events(&self.known_identities);
            let results = ld.tick();
            for result in results {
                self.handle_link_delivery_result(result);
            }
        }

        if let Some(ref mut ps) = self.propagation_sync {
            ps.drain_events(&self.known_identities);
            ps.tick();
        }

        // Drive propagation client (download from node)
        let mut downloaded_messages = Vec::new();
        let propagation_node_ready = self
            .router
            .outbound_propagation_node
            .map(|node| self.known_identities.contains_key(&hex::encode(node)))
            .unwrap_or(false);
        if let Some(ref mut client) = self.propagation_client {
            client.drain_events(&self.known_identities);
            client.tick();

            downloaded_messages = client.take_received_messages();

            // Auto-download every 90s
            if now - self.last_propagation_check > 90.0
                && client.state == lxmf_core::propagation_client::PropagationClientState::Idle
            {
                if propagation_node_ready {
                    client.start_download();
                    self.last_propagation_check = now;
                    tracing::debug!("auto-triggered propagation download");
                } else if let Some(node) = self.router.outbound_propagation_node
                    && queue_unknown_propagation_node_path_request(
                        &self.transport_tx,
                        node,
                        &mut self.last_propagation_check,
                        now,
                    )
                {
                    tracing::debug!(
                        node = %hex::encode(node),
                        "propagation node identity unknown; requesting path before download"
                    );
                }
            }
        }
        // Borrow is released; process downloaded messages.
        for msg_data in downloaded_messages {
            self.handle_propagation_downloaded_data(&msg_data);
        }

        if let Some(interval) = self.config.announce_interval
            && now - self.last_peer_announce > interval as f64
        {
            let tx = self.transport_tx.clone();
            if let Ok(raw) = self.create_announce_packet() {
                let dest = self.lxmf_dest_hash;
                let _ = tx.try_send(TransportMessage::Outbound(
                    rns_transport::messages::OutboundRequest {
                        raw: Bytes::from(raw),
                        destination_hash: dest,
                    },
                ));
                self.last_peer_announce = now;
                tracing::debug!("periodic peer announce sent");
            }
        }

        if self.config.propagation_enabled
            && let Some(interval) = self.config.node_announce_interval
            && now - self.last_node_announce > interval as f64
            && let Ok(raw) = self.create_propagation_announce_packet()
        {
            let dest = self.propagation_dest_hash;
            let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw),
                    destination_hash: dest,
                },
            ));
            if self.should_announce_control()
                && let Ok(raw) =
                    create_control_announce_packet(&self.identity, self.control_dest_hash)
            {
                let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                    rns_transport::messages::OutboundRequest {
                        raw: Bytes::from(raw),
                        destination_hash: self.control_dest_hash,
                    },
                ));
            }
            self.last_node_announce = now;
            tracing::debug!("periodic propagation node announce sent");
        }

        if now - self.last_cull > 300.0 {
            self.router.cull_stamp_costs();
            self.router.cull_propagation();
            self.router.rotate_peers();
            self.last_cull = now;
        }

        if now - self.last_crypto_save > 300.0 {
            self.save_crypto_state();
            if let Err(e) = self.router.save_state(&self.data_dir) {
                tracing::warn!("Failed to save router state: {e}");
            }
            self.last_crypto_save = now;
        }

        // 15-minute interval matches Python's CLEAN_INTERVAL.
        if now - self.last_ratchet_clean > 900.0 {
            let mem_dropped = purge_expired_ratchets_in_memory(&mut self.received_ratchets);
            let disk_dropped = clean_received_ratchets_dir(&self.received_ratchets_dir);
            if mem_dropped > 0 || disk_dropped > 0 {
                tracing::debug!(
                    mem_dropped,
                    disk_dropped,
                    "ratchet cleanup pass: removed expired entries"
                );
            }
            self.last_ratchet_clean = now;
        }

        self.refresh_control_state();
    }

    fn drain_announce_events(&mut self) -> Vec<[u8; 16]> {
        let mut seen = Vec::new();
        let delivery_name_hash = rns_identity::name_hash::name_hash(LXMF_APP_NAME);
        let propagation_name_hash = rns_identity::name_hash::name_hash("lxmf.propagation");
        while let Ok(event) = self.announce_rx.try_recv() {
            seen.push(event.destination_hash);
            let dest_hex = hex::encode(event.destination_hash);
            let mut crypto_dirty = false;
            tracing::info!(
                dest = %dest_hex,
                hops = event.hops,
                "received announce"
            );
            self.route_hops
                .insert(event.destination_hash, event.hops.max(1));

            if event.name_hash == delivery_name_hash {
                if let Some(ref data) = event.app_data
                    && let Some((display_name, stamp_cost)) =
                        lxmf_core::handlers::parse_announce_app_data(data)
                {
                    if let Some(name) = display_name {
                        tracing::info!(dest = %dest_hex, name = %name, "announce display name");
                    }
                    if let Some(cost) = stamp_cost {
                        self.router.set_stamp_cost(event.destination_hash, cost);
                        tracing::debug!(
                            dest = %dest_hex,
                            stamp_cost = cost,
                            "learned delivery stamp cost from announce"
                        );
                    }
                }
                let triggered = self
                    .router
                    .trigger_outbound_for_delivery_announce(event.destination_hash);
                if triggered > 0 {
                    tracing::debug!(
                        dest = %dest_hex,
                        triggered,
                        "delivery announce made pending outbound messages eligible"
                    );
                }
            } else if event.name_hash == propagation_name_hash
                && let Some(ref data) = event.app_data
                && let Some(pn) = lxmf_core::handlers::parse_pn_announce_data(data)
            {
                self.router
                    .set_stamp_cost(event.destination_hash, pn.stamp_cost);
                tracing::debug!(
                    dest = %dest_hex,
                    stamp_cost = pn.stamp_cost,
                    "learned propagation-node stamp cost from announce"
                );
                let triggered = self
                    .router
                    .trigger_outbound_for_propagation_node_announce(event.destination_hash, data);
                if triggered > 0 {
                    tracing::debug!(
                        dest = %dest_hex,
                        triggered,
                        "propagation-node announce made pending propagated messages eligible"
                    );
                }
            }
            if let Some(pub_key) = event.public_key
                && self.known_identities.get(&dest_hex) != Some(&pub_key)
            {
                self.known_identities.insert(dest_hex.clone(), pub_key);
                crypto_dirty = true;
                tracing::debug!(dest = %dest_hex, "learned identity key from announce");
            }
            if let Some(ratchet_key) = event.ratchet {
                self.received_ratchets
                    .insert(dest_hex.clone(), ReceivedRatchet::new(ratchet_key));
                crypto_dirty = true;
                tracing::debug!(dest = %dest_hex, "learned ratchet from announce");
            }
            if crypto_dirty {
                self.save_crypto_state();
            }
        }
        seen
    }

    fn drain_link_packets(&mut self) {
        while let Ok((plaintext, link_id)) = self.link_packet_rx.try_recv() {
            tracing::info!(
                link_id = %hex::encode(link_id),
                len = plaintext.len(),
                "received decrypted packet via link"
            );
            self.handle_link_delivered_data(&plaintext);
        }

        while let Ok((data, link_id)) = self.resource_rx.try_recv() {
            tracing::info!(
                link_id = %hex::encode(link_id),
                len = data.len(),
                "resource transfer completed on link"
            );
            self.handle_link_delivered_data(&data);
        }

        while let Ok((data, link_id)) = self.prop_link_packet_rx.try_recv() {
            tracing::info!(
                link_id = %hex::encode(link_id),
                len = data.len(),
                "received propagation packet via link"
            );
            self.handle_propagation_transfer_data(&data);
        }

        while let Ok((data, link_id)) = self.prop_resource_rx.try_recv() {
            tracing::info!(
                link_id = %hex::encode(link_id),
                len = data.len(),
                "propagation resource transfer completed"
            );
            self.handle_propagation_transfer_data(&data);
        }
    }

    fn handle_link_delivered_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // LxMessage::unpack expects [dest_hash][lxm_data]; prepend if the
        // sender omitted it.
        let unpack_data = if data.len() >= 16 && data[..16] == self.lxmf_dest_hash {
            data.to_vec()
        } else {
            let mut full = self.lxmf_dest_hash.to_vec();
            full.extend_from_slice(data);
            full
        };

        match LxMessage::unpack(&unpack_data) {
            Ok(msg) => {
                tracing::info!(
                    from = %hex::encode(msg.source_hash),
                    title = %msg.title,
                    len = msg.content.len(),
                    "inbound LXMF message via link"
                );
                if self.should_reject_for_stamp(&msg) {
                    return;
                }
                self.handle_inbound_message(msg);
            }
            Err(e) => {
                tracing::debug!("link data not an LXMF message: {e}");
            }
        }
    }

    fn handle_propagation_transfer_data(&mut self, data: &[u8]) {
        let Some(ref pn) = self.propagation_node else {
            tracing::debug!("received propagation data but node storage is disabled");
            return;
        };

        let (_remote_timebase, entries) = match LxMessage::unpack_propagation_wrapper(data) {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!("failed to unpack propagation wrapper: {e}");
                return;
            }
        };

        let min_cost = self
            .config
            .propagation_stamp_cost
            .saturating_sub(self.config.propagation_stamp_flex);
        let mut accepted = 0usize;
        let mut rejected = 0usize;

        if let Ok(mut node) = pn.lock() {
            for entry in entries {
                match lxmf_core::stamper::validate_pn_stamp(&entry, min_cost) {
                    Some((_transient_id, lxmf_data, stamp_value, stamp_data)) => {
                        if node.accept_stamped_propagated_blob(
                            &lxmf_data,
                            &stamp_data,
                            stamp_value as u8,
                        ) {
                            accepted += 1;
                        }
                    }
                    None => rejected += 1,
                }
            }
        }

        tracing::info!(accepted, rejected, "processed inbound propagation transfer");
    }

    fn handle_propagation_downloaded_data(&mut self, data: &[u8]) {
        if data.len() < 16 {
            return;
        }

        let unpack_data = if data[..16] == self.lxmf_dest_hash {
            match self.decrypt_inbound(&data[16..]) {
                Some(plaintext) => {
                    let mut full = self.lxmf_dest_hash.to_vec();
                    full.extend_from_slice(&plaintext);
                    full
                }
                None => data.to_vec(),
            }
        } else {
            data.to_vec()
        };

        match LxMessage::unpack(&unpack_data) {
            Ok(mut msg) => {
                msg.method = lxmf_core::constants::DeliveryMethod::Propagated;
                tracing::info!(
                    from = %hex::encode(msg.source_hash),
                    title = %msg.title,
                    len = msg.content.len(),
                    "propagation: downloaded message"
                );
                self.handle_inbound_message(msg);
            }
            Err(e) => {
                tracing::warn!("failed to unpack downloaded propagation message: {e}");
            }
        }
    }

    fn handle_inbound_packet(&mut self, raw: &[u8]) {
        let (header, rest) = match rns_wire::header::PacketHeader::unpack(raw) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("failed to parse inbound packet header: {e}");
                return;
            }
        };

        let payload = &raw[rest..];
        if payload.is_empty() {
            return;
        }

        let plaintext = match self.decrypt_inbound(payload) {
            Some(pt) => pt,
            None => {
                tracing::warn!("failed to decrypt inbound packet");
                return;
            }
        };

        // Python strips the dest hash for opportunistic delivery; direct delivery
        // keeps it. Re-prepend if missing so LxMessage::unpack always sees the
        // [dest_hash][lxm_data] layout.
        let unpack_data = if plaintext.len() >= 16 && plaintext[..16] == self.lxmf_dest_hash {
            plaintext.clone()
        } else {
            let mut data = self.lxmf_dest_hash.to_vec();
            data.extend_from_slice(&plaintext);
            data
        };

        match LxMessage::unpack(&unpack_data) {
            Ok(msg) => {
                tracing::info!(
                    from = %hex::encode(msg.source_hash),
                    title = %msg.title,
                    len = msg.content.len(),
                    "inbound LXMF message received"
                );

                // Reject on stamp failure BEFORE sending the delivery proof.
                if self.should_reject_for_stamp(&msg) {
                    return;
                }

                if let Some(proof_raw) = self.create_delivery_proof(raw) {
                    let trunc =
                        rns_wire::hash::truncated_packet_hash(raw, header.flags.header_type);
                    let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                        rns_transport::messages::OutboundRequest {
                            raw: Bytes::from(proof_raw),
                            destination_hash: trunc,
                        },
                    ));
                }

                self.handle_inbound_message(msg);
            }
            Err(e) => {
                tracing::warn!("failed to unpack LXMF message: {e}");
            }
        }
    }

    /// Returns true if the message should be rejected.
    fn should_reject_for_stamp(&self, msg: &LxMessage) -> bool {
        if !self.config.enforce_stamps {
            return false;
        }
        let required_cost = match self.config.stamp_cost {
            Some(c) if c > 0 => c,
            _ => return false,
        };
        let stamp = match msg.stamp.as_deref() {
            Some(s) => s,
            None => {
                tracing::warn!(
                    from = %hex::encode(msg.source_hash),
                    required_cost,
                    "inbound message rejected: no stamp (enforce_stamps=true)"
                );
                return true;
            }
        };
        let message_id = match msg.message_id.or(msg.hash) {
            Some(id) => id,
            None => {
                tracing::warn!(
                    from = %hex::encode(msg.source_hash),
                    "inbound message rejected: no message_id for stamp validation"
                );
                return true;
            }
        };
        if !self.router.validate_stamp_with_tickets(
            &message_id,
            stamp,
            required_cost,
            &msg.source_hash,
        ) {
            tracing::warn!(
                from = %hex::encode(msg.source_hash),
                required_cost,
                "inbound message rejected: stamp PoW invalid or below required cost"
            );
            return true;
        }
        false
    }

    /// Write a received LXMF message to disk and invoke `on_inbound`.
    fn handle_inbound_message(&self, msg: LxMessage) {
        // Also deposit into the propagation store (if enabled) so peers can
        // download it via offer/get sync.
        if let Some(ref pn) = self.propagation_node
            && let Ok(mut node) = pn.lock()
            && node.accept_message(&msg)
        {
            tracing::info!(
                from = %hex::encode(msg.source_hash),
                "propagation: message accepted into store"
            );
        }

        let messages_dir = self.messages_dir.clone();
        std::fs::create_dir_all(&messages_dir).ok();

        let msg_hash = msg
            .hash
            .map(hex::encode)
            .unwrap_or_else(|| format!("{:.0}", now_f64()));
        let msg_path = messages_dir.join(format!("{msg_hash}.lxm"));

        // Pack synchronously (CPU-bound, no IO) and offload the disk write
        // to the blocking pool so a slow disk doesn't stall the lxmd runner
        // task between inbound messages.
        match msg.pack() {
            Ok(packed) => {
                let write_path = msg_path.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = std::fs::write(&write_path, &packed) {
                        tracing::error!("failed to write message to {}: {e}", write_path.display());
                    } else {
                        tracing::info!("message saved to {}", write_path.display());
                    }
                });
            }
            Err(e) => {
                tracing::error!("failed to pack message for storage: {e}");
                return;
            }
        }

        // Execute on_inbound command if configured
        if let Some(ref cmd) = self.config.on_inbound_command
            && let Err(e) = execute_on_inbound(cmd, &msg_path.to_string_lossy())
        {
            tracing::error!("on_inbound command failed: {e}");
        }

        // Update known identity from sender
        // (The source_hash to public_key mapping comes from announce processing,
        // not directly from the message. Log for diagnostics.)
        tracing::debug!(
            from = %hex::encode(msg.source_hash),
            "inbound message processed"
        );
    }

    fn execute_encrypted_actions(&mut self, actions: Vec<OutboundAction>) {
        for action in actions {
            let (mut message, dest_hash, is_opportunistic, direct_plan) = match action {
                OutboundAction::DeliverDirect { message, dest_hash } => {
                    (message, dest_hash, false, None)
                }
                OutboundAction::PlanDirect {
                    message,
                    dest_hash,
                    plan,
                } => (message, dest_hash, false, Some(plan)),
                OutboundAction::DeliverOpportunistic { message, dest_hash } => {
                    (message, dest_hash, true, None)
                }
                OutboundAction::DeliverPropagated { message, prop_hash } => {
                    let mut message = message;
                    let prop_hex = hex::encode(prop_hash);
                    if !self.known_identities.contains_key(&prop_hex) {
                        tracing::warn!(
                            prop = %prop_hex,
                            attempts = message.delivery_attempts,
                            "propagation node identity unknown, requesting path before link delivery"
                        );
                        requeue_after_path_request(
                            &mut self.router,
                            &self.transport_tx,
                            message,
                            prop_hash,
                            "propagation node identity unknown",
                            true,
                        );
                        continue;
                    }
                    tracing::info!(
                        dest = %hex::encode(message.destination_hash),
                        prop = %hex::encode(prop_hash),
                        "routing message via propagation node"
                    );
                    match self.pack_message_for_propagation(&mut message, prop_hash) {
                        Some(packed) => {
                            let attempts = mark_delivery_attempt(&mut message);
                            if attempts >= MAX_DELIVERY_ATTEMPTS {
                                tracing::warn!(
                                    prop = %prop_hex,
                                    attempts,
                                    max_attempts = MAX_DELIVERY_ATTEMPTS,
                                    "propagated delivery attempt budget reached; deferring terminal failure"
                                );
                                self.router.send(message);
                                continue;
                            }
                            let hops = route_hops_for(&self.route_hops, prop_hash);
                            self.ensure_link_delivery();
                            if let Some(ref mut ld) = self.link_delivery
                                && let Err(err) = ld
                                    .start_packed_delivery(message, prop_hash, hops, packed, false)
                            {
                                let reason = err.error.to_string();
                                tracing::warn!(
                                    error = %reason,
                                    prop = %hex::encode(prop_hash),
                                    "failed to start propagated link delivery"
                                );
                                requeue_after_path_request(
                                    &mut self.router,
                                    &self.transport_tx,
                                    *err.message,
                                    prop_hash,
                                    &reason,
                                    false,
                                );
                            }
                        }
                        None => {
                            tracing::warn!(
                                dest = %hex::encode(message.destination_hash),
                                "failed to prepare propagated LXMF message; re-queueing"
                            );
                            self.router.send(message);
                        }
                    }
                    continue;
                }
                OutboundAction::Failed(_) | OutboundAction::Expired(_) => continue,
            };

            if message.stamp.is_none()
                && let Some(cost) = self.router.get_stamp_cost(&message.destination_hash)
                && cost > 0
            {
                tracing::info!(
                    dest = %hex::encode(message.destination_hash),
                    cost = cost,
                    "generating stamp"
                );
                message.stamp_cost = Some(cost);
                message.get_stamp();
            }

            let dest_hex = hex::encode(dest_hash);
            if !is_opportunistic {
                let router_owned = direct_plan.is_some();
                let plan = direct_plan.unwrap_or_else(|| {
                    plan_direct_delivery(
                        &mut message,
                        DirectDeliveryPlanInput {
                            identity_known: self.known_identities.contains_key(&dest_hex),
                            route: direct_route_snapshot(&self.route_hops, dest_hash),
                            reusable_link: direct_reusable_link_state(
                                self.link_delivery.as_ref(),
                                dest_hash,
                            ),
                        },
                        now_f64(),
                    )
                });

                match plan {
                    DirectDeliveryPlan::RequestPath { drop_existing } => {
                        queue_path_request(
                            &self.transport_tx,
                            dest_hash,
                            drop_existing,
                            "direct delivery path request",
                        );
                        tracing::warn!(
                            dest = %dest_hex,
                            attempts = message.delivery_attempts,
                            drop_existing,
                            "direct delivery waiting for path"
                        );
                        if !router_owned {
                            self.router.send(message);
                        }
                    }
                    DirectDeliveryPlan::DeferTerminalFailure => {
                        tracing::warn!(
                            dest = %dest_hex,
                            attempts = message.delivery_attempts,
                            max_attempts = MAX_DELIVERY_ATTEMPTS,
                            "direct delivery attempt budget reached; deferring terminal failure"
                        );
                        if !router_owned {
                            self.router.send(message);
                        }
                    }
                    DirectDeliveryPlan::WaitForReusableLink => {
                        tracing::debug!(
                            dest = %dest_hex,
                            attempts = message.delivery_attempts,
                            "direct delivery waiting for reusable Link"
                        );
                        if !router_owned {
                            self.router.send(message);
                        }
                    }
                    DirectDeliveryPlan::UseReusableLink
                    | DirectDeliveryPlan::StartNewLink { .. } => {
                        let planned_hops = match plan {
                            DirectDeliveryPlan::StartNewLink { hops } => hops,
                            _ => route_hops_for(&self.route_hops, dest_hash),
                        };
                        tracing::info!(
                            dest = %dest_hex,
                            hops = planned_hops,
                            plan = ?plan,
                            "routing Direct LXMF message over link delivery"
                        );
                        self.ensure_link_delivery();
                        if let Some(ref mut ld) = self.link_delivery {
                            if matches!(plan, DirectDeliveryPlan::UseReusableLink)
                                && ld.direct_link_snapshot(dest_hash).is_none()
                                && ld.backchannel_link_snapshot(dest_hash).is_some()
                            {
                                match ld.start_backchannel_delivery(message, dest_hash) {
                                    Ok(_) => {}
                                    Err(err) => {
                                        let reason = err.error.to_string();
                                        let returned_message = *err.message;
                                        tracing::warn!(
                                            error = %reason,
                                            dest = %dest_hex,
                                            "failed to start daemon backchannel delivery"
                                        );
                                        if router_owned {
                                            queue_path_request(
                                                &self.transport_tx,
                                                dest_hash,
                                                false,
                                                &reason,
                                            );
                                            if let Some(hash) = returned_message.hash {
                                                let _ =
                                                    self.router.defer_outbound_for_path_request(
                                                        &hash,
                                                        now_f64(),
                                                    );
                                            }
                                        } else {
                                            requeue_after_path_request(
                                                &mut self.router,
                                                &self.transport_tx,
                                                returned_message,
                                                dest_hash,
                                                &reason,
                                                false,
                                            );
                                        }
                                    }
                                }
                                continue;
                            }

                            if let Err(err) =
                                ld.start_delivery_with_report(message, dest_hash, planned_hops)
                            {
                                let reason = err.error.to_string();
                                let returned_message = *err.message;
                                tracing::warn!(
                                    error = %reason,
                                    dest = %dest_hex,
                                    "failed to start direct link delivery"
                                );
                                if router_owned {
                                    queue_path_request(
                                        &self.transport_tx,
                                        dest_hash,
                                        false,
                                        &reason,
                                    );
                                    if let Some(hash) = returned_message.hash {
                                        let _ = self
                                            .router
                                            .defer_outbound_for_path_request(&hash, now_f64());
                                    }
                                } else {
                                    requeue_after_path_request(
                                        &mut self.router,
                                        &self.transport_tx,
                                        returned_message,
                                        dest_hash,
                                        &reason,
                                        false,
                                    );
                                }
                            }
                        }
                    }
                    DirectDeliveryPlan::Fail => {
                        tracing::warn!(
                            dest = %dest_hex,
                            attempts = message.delivery_attempts,
                            "direct delivery failed before link delivery"
                        );
                    }
                }
                continue;
            }

            let msg_hash = message.hash;
            let mut missing_identity = false;
            let payload = match message.pack_opportunistic_encrypted(|plaintext| {
                self.encrypt_for_destination(&dest_hex, plaintext)
                    .ok_or_else(|| {
                        missing_identity = true;
                        lxmf_core::message::MessageError::PackFailed(format!(
                            "no identity key for destination {dest_hex}"
                        ))
                    })
            }) {
                Ok(ct) => {
                    tracing::info!(
                        dest = %dest_hex,
                        encrypted_len = ct.len(),
                        "outbound LXMF: encrypted opportunistic payload"
                    );
                    ct
                }
                Err(err) if missing_identity => {
                    tracing::warn!(
                        dest = %dest_hex,
                        attempts = message.delivery_attempts,
                        error = %err,
                        "destination key unknown, re-queuing"
                    );
                    requeue_after_path_request(
                        &mut self.router,
                        &self.transport_tx,
                        message,
                        dest_hash,
                        "opportunistic destination identity unknown",
                        true,
                    );
                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        dest = %dest_hex,
                        error = %err,
                        "failed to pack opportunistic LXMF message"
                    );
                    continue;
                }
            };

            let flags = rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Data,
            };
            let header = rns_wire::header::PacketHeader {
                flags,
                hops: 0,
                transport_id: None,
                destination_hash: dest_hash,
                context: rns_wire::context::PacketContext::None,
            };
            let mut raw = header.pack();
            raw.extend_from_slice(&payload);

            // Escalate oversize packets to link delivery.
            if raw.len() > rns_wire::constants::MTU {
                tracing::info!(
                    dest = %dest_hex,
                    packet_len = raw.len(),
                    "packet exceeds MTU; routing to link delivery"
                );
                let attempts = mark_delivery_attempt(&mut message);
                if attempts >= MAX_DELIVERY_ATTEMPTS {
                    tracing::warn!(
                        dest = %dest_hex,
                        attempts,
                        max_attempts = MAX_DELIVERY_ATTEMPTS,
                        "oversized direct delivery attempt budget reached; deferring terminal failure"
                    );
                    self.router.send(message);
                    continue;
                }
                let hops = route_hops_for(&self.route_hops, dest_hash);
                self.ensure_link_delivery();
                if let Some(ref mut ld) = self.link_delivery
                    && let Err(err) = ld.start_delivery(message, dest_hash, hops)
                {
                    let reason = err.error.to_string();
                    tracing::warn!(
                        error = %reason,
                        dest = %dest_hex,
                        "failed to start oversized direct link delivery"
                    );
                    requeue_after_path_request(
                        &mut self.router,
                        &self.transport_tx,
                        *err.message,
                        dest_hash,
                        &reason,
                        false,
                    );
                }
                continue;
            }

            match self.transport_tx.try_send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: Bytes::from(raw.clone()),
                    destination_hash: dest_hash,
                },
            )) {
                Ok(()) => {
                    if let Some(hash) = msg_hash {
                        let (full, trunc) = rns_wire::hash::packet_hash_pair(
                            &raw,
                            rns_wire::flags::HeaderType::Header1,
                        );
                        let _ = self
                            .transport_tx
                            .try_send(TransportMessage::RegisterReceipt {
                                truncated_hash: trunc,
                                full_hash: full,
                                msg_id: hex::encode(hash),
                                timeout: Some(Duration::from_secs(15)),
                            });
                        tracing::info!(hash = %hex::encode(hash), "message sent");
                    }
                }
                Err(e) => {
                    tracing::error!(dest = %dest_hex, error = %e, "failed to send; message dropped");
                }
            }
        }
    }

    fn ensure_link_delivery(&mut self) {
        if self.link_delivery.is_none() {
            self.link_delivery = Some(lxmf_core::link_delivery::LinkDeliveryManager::new(
                self.transport_tx.clone(),
                Some(self.identity.get_public_key()),
                self.identity.get_signing_key(),
            ));
        }
        self.ensure_backchannel_sender();
    }

    fn ensure_backchannel_sender(&mut self) {
        if self.backchannel_command_rx.is_some() || self.link_delivery.is_none() {
            return;
        }

        let (tx, rx) = mpsc::channel(256);
        if let Some(ref mut ld) = self.link_delivery {
            ld.set_backchannel_sender(tx);
            self.backchannel_command_rx = Some(rx);
        }
    }

    fn encrypt_for_destination(&self, dest_hash_hex: &str, plaintext: &[u8]) -> Option<Vec<u8>> {
        let pub_key = self.known_identities.get(dest_hash_hex)?;
        let remote = Identity::from_public_key(pub_key).ok()?;
        let ratchet_pub = self
            .received_ratchets
            .get(dest_hash_hex)
            .filter(|rr| !rr.is_expired())
            .map(|rr| &rr.ratchet_pub);
        remote.encrypt(plaintext, ratchet_pub).ok()
    }

    fn pack_message_for_propagation(
        &self,
        message: &mut LxMessage,
        prop_hash: [u8; 16],
    ) -> Option<Vec<u8>> {
        let dest_hex = hex::encode(message.destination_hash);
        let target_cost = self.router.get_stamp_cost(&prop_hash).unwrap_or(0);
        let (packed, _tid, stamp_value) = message
            .pack_propagated_encrypted_with_stamp(
                |plaintext| {
                    self.encrypt_for_destination(&dest_hex, plaintext)
                        .ok_or_else(|| {
                            lxmf_core::message::MessageError::PackFailed(format!(
                                "no identity key for destination {dest_hex}"
                            ))
                        })
                },
                target_cost,
            )
            .ok()?;
        tracing::debug!(
            dest = %dest_hex,
            prop = %hex::encode(prop_hash),
            target_cost,
            stamp_value,
            packed_len = packed.len(),
            "prepared propagation wrapper"
        );
        Some(packed)
    }

    fn decrypt_inbound(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let prv_keys = self.ratchet_ring.private_keys();
        let refs: Vec<&[u8; 32]> = prv_keys.iter().collect();
        let ratchets = if refs.is_empty() {
            None
        } else {
            Some(refs.as_slice())
        };
        self.identity.decrypt(ciphertext, ratchets, false).ok()
    }

    fn create_delivery_proof(&self, raw_packet: &[u8]) -> Option<Vec<u8>> {
        let (header, _) = rns_wire::header::PacketHeader::unpack(raw_packet).ok()?;
        let full_hash = rns_wire::hash::packet_hash(raw_packet, header.flags.header_type);
        let trunc_hash =
            rns_wire::hash::truncated_packet_hash(raw_packet, header.flags.header_type);

        let signature = self.identity.sign(&full_hash)?;

        let proof_flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Proof,
        };
        let proof_header = rns_wire::header::PacketHeader {
            flags: proof_flags,
            hops: 0,
            transport_id: None,
            destination_hash: trunc_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut proof_raw = proof_header.pack();
        proof_raw.extend_from_slice(&signature);
        Some(proof_raw)
    }

    fn save_crypto_state(&self) {
        let ratchet_dir = self.ratchets_dir.clone();
        std::fs::create_dir_all(&ratchet_dir).ok();

        let ring_path = ratchet_dir.join("ring");
        let sig = self
            .identity
            .sign(
                self.ratchet_ring
                    .current_public_key()
                    .unwrap_or([0u8; 32])
                    .as_ref(),
            )
            .unwrap_or([0u8; 64]);
        if let Err(e) = self.ratchet_ring.save(&ring_path, &sig) {
            tracing::warn!("Failed to save ratchet ring: {e}");
        }

        let received_dir = ratchet_dir.join("received");
        std::fs::create_dir_all(&received_dir).ok();
        for (hash_hex, rr) in &self.received_ratchets {
            let path = received_dir.join(format!("{hash_hex}.ratchet"));
            if let Err(e) = rr.save(&path) {
                tracing::warn!("Failed to save received ratchet {hash_hex}: {e}");
            }
        }

        // Flat binary: [dest_hash:16][pub:64] per entry.
        let ki_path = ratchet_dir.join("known_identities");
        let mut data = Vec::with_capacity(self.known_identities.len() * 80);
        for (hash_hex, pk) in &self.known_identities {
            if let Ok(hash_bytes) = hex::decode(hash_hex)
                && hash_bytes.len() == 16
            {
                data.extend_from_slice(&hash_bytes);
                data.extend_from_slice(pk);
            }
        }
        if let Err(e) = rns_identity::persistence::atomic_write(&ki_path, &data) {
            tracing::warn!("Failed to save known identities: {e}");
        }
    }
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();

    if args.exampleconfig {
        print!("{}", example_config());
        return;
    }

    setup_logging(args.verbose, args.quiet, args.service);

    let (config_dir, rns_config_dir) =
        resolve_config_dirs(args.config.as_deref(), args.rnsconfig.as_deref());

    let is_control_command =
        args.status || args.peers || args.sync.is_some() || args.unpeer.is_some();
    let control_preflight = if is_control_command {
        let peer_hash = if args.status || args.peers {
            None
        } else {
            args.sync.as_deref().or(args.unpeer.as_deref())
        };
        match preflight_control_command(
            &config_dir,
            args.identity.as_deref(),
            peer_hash,
            args.remote.as_deref(),
        ) {
            Ok(preflight) => Some(preflight),
            Err(e) => {
                println!("{}", e.message);
                std::process::exit(e.exit_code);
            }
        }
    } else {
        None
    };

    let config_path = config_dir.join("config");
    let config = match rns_runtime::config::Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "Could not load config from {}: {}",
                config_path.display(),
                e
            );
            tracing::info!("Using default configuration");
            rns_runtime::config::Config::parse(rns_runtime::config::Config::default_config())
                .expect("default config must parse")
        }
    };

    let mut daemon_config = DaemonConfig::from_config(&config);
    if args.propagation_node {
        daemon_config.propagation_enabled = true;
    }
    if let Some(ref on_inbound) = args.on_inbound {
        daemon_config.on_inbound_command = Some(on_inbound.clone());
    }

    tracing::info!("LXMF Daemon starting");
    if let Some(ref name) = daemon_config.display_name {
        tracing::info!("Display name: {}", name);
    }

    if daemon_config.propagation_enabled {
        tracing::info!(
            "Propagation node enabled (stamp_cost={}, max_peers={}, autopeer={})",
            daemon_config.propagation_stamp_cost,
            daemon_config.max_peers,
            daemon_config.autopeer,
        );
    }

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            tracing::info!("Received shutdown signal");
            shutdown_clone.trigger();
        }
    });

    let rns_config_dir_str = rns_config_dir.to_string_lossy().to_string();
    let is_foreground = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let rns_handle = match rns_runtime::reticulum::init(
        Some(&rns_config_dir_str),
        None,
        shutdown.clone(),
        is_foreground,
    )
    .await
    {
        Ok(h) => {
            tracing::info!(
                "RNS initialized: mode={:?}, interfaces={}",
                h.instance_mode,
                h.interface_configs.len(),
            );
            h
        }
        Err(e) => {
            tracing::error!("Failed to initialize RNS: {e:?}");
            return;
        }
    };
    rns_handle
        .enable_on_network_discovery(Arc::new(
            lxmf_core::discovery_stamper::LxmfDiscoveryStamper::default(),
        ))
        .await;

    let transport_tx = rns_handle.transport_tx.clone();

    if let Some(preflight) = control_preflight {
        let identity = match Identity::from_file(&preflight.identity_path) {
            Ok(identity) => identity,
            Err(_) => {
                println!(
                    "Could not load the Primary Identity from {}",
                    preflight.identity_path.display()
                );
                std::process::exit(4);
            }
        };
        let target_identity_hash = match preflight.remote_hash {
            Some(remote_hash) => {
                match resolve_remote_identity_hash(transport_tx.clone(), remote_hash, 5.0).await {
                    Ok(identity_hash) => identity_hash,
                    Err(_) => {
                        println!("Resolving remote identity timed out, exiting now");
                        std::process::exit(200);
                    }
                }
            }
            None => identity.hash,
        };
        let timeout = args
            .timeout
            .unwrap_or(if args.status || args.peers { 5.0 } else { 10.0 })
            .max(0.0);

        if args.status || args.peers {
            let response_bytes = match query_control(
                transport_tx.clone(),
                identity,
                target_identity_hash,
                lxmf_core::constants::STATS_GET_PATH,
                Vec::new(),
                timeout,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => print_control_link_error(ControlCommandKind::Status, &error),
            };
            let response = decode_control_response(&response_bytes);
            exit_for_control_response(ControlCommandKind::Status, &response);
            match response {
                ControlResponse::Stats(stats) => {
                    print!(
                        "{}",
                        format_remote_status(&stats, args.status, args.peers, now_f64())
                    );
                }
                _ => {
                    println!("Empty response received");
                    std::process::exit(207);
                }
            }
            return;
        }

        if args.sync.is_some() {
            let peer_hash = preflight
                .peer_hash
                .expect("sync preflight should include peer hash");
            let response_bytes = match query_control(
                transport_tx.clone(),
                identity,
                target_identity_hash,
                lxmf_core::constants::SYNC_REQUEST_PATH,
                peer_hash.to_vec(),
                timeout,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => print_control_link_error(ControlCommandKind::Sync, &error),
            };
            let response = decode_control_response(&response_bytes);
            exit_for_control_response(ControlCommandKind::Sync, &response);
            println!("Sync requested for peer <{}>", hex::encode(peer_hash));
            return;
        }

        if args.unpeer.is_some() {
            let peer_hash = preflight
                .peer_hash
                .expect("unpeer preflight should include peer hash");
            let response_bytes = match query_control(
                transport_tx.clone(),
                identity,
                target_identity_hash,
                lxmf_core::constants::UNPEER_REQUEST_PATH,
                peer_hash.to_vec(),
                timeout,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => print_control_link_error(ControlCommandKind::Unpeer, &error),
            };
            let response = decode_control_response(&response_bytes);
            exit_for_control_response(ControlCommandKind::Unpeer, &response);
            println!("Broke peering with <{}>", hex::encode(peer_hash));
            return;
        }
    }

    let mut runner = match LxmdRunner::new(daemon_config.clone(), &config_dir, transport_tx) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to initialize LXMF daemon: {e}");
            return;
        }
    };

    runner.apply_config();

    if let Err(e) = runner.router.load_state(&runner.data_dir) {
        tracing::warn!("Failed to load persisted router state: {e}");
    } else {
        tracing::info!(
            "Loaded persisted router state from {}",
            runner.data_dir.display()
        );
    }

    let ignored = load_hash_list(&config_dir.join("ignored"));
    if !ignored.is_empty() {
        tracing::info!(
            "Loaded {} ignored destination(s) from ignored",
            ignored.len()
        );
        runner.router.ignored.extend(ignored);
    }
    let allowed = load_hash_list(&config_dir.join("allowed"));
    if !allowed.is_empty() {
        tracing::info!(
            "Loaded {} allowed destination(s) from allowed",
            allowed.len()
        );
        runner.router.allowed.extend(allowed);
    }

    runner.refresh_control_state();

    tracing::info!("LXMF router initialized");

    // Startup announce: wait until at least one interface is online, mirroring
    // Python's deferred_start_jobs() pattern.
    if daemon_config.announce_at_start {
        tracing::info!("Waiting for interfaces to come online before announcing...");
        let mut announced = false;
        for _ in 0..30 {
            if shutdown.is_triggered() {
                break;
            }
            let poll_started = Instant::now();
            let (otx, orx) = tokio::sync::oneshot::channel();
            tokio::select! {
                _ = shutdown.wait() => break,
                result = runner.transport_tx.send(TransportMessage::Rpc {
                    query: rns_transport::messages::TransportQuery::GetInterfaceStats,
                    response_tx: otx,
                }) => {
                    if result.is_err() {
                        break;
                    }
                }
            }

            let stats_result = tokio::select! {
                _ = shutdown.wait() => break,
                result = tokio::time::timeout(Duration::from_secs(1), orx) => result,
            };
            if let Ok(Ok(rns_transport::messages::TransportQueryResponse::InterfaceStats(stats))) =
                stats_result
            {
                let any_online = stats
                    .iter()
                    .any(|s| s.online && (s.rx_bytes > 0 || s.tx_bytes > 0));
                if any_online {
                    match runner.send_announce().await {
                        Ok(()) => {
                            tracing::info!("Startup announce sent (interface online)");
                            runner.last_peer_announce = now_f64();
                            announced = true;
                        }
                        Err(e) => tracing::warn!("Failed to send startup announce: {e}"),
                    }
                    break;
                }
            }
            let elapsed = poll_started.elapsed();
            if elapsed < Duration::from_secs(1)
                && sleep_or_shutdown(&shutdown, Duration::from_secs(1) - elapsed).await
            {
                break;
            }
        }
        if shutdown.is_triggered() {
            tracing::info!("Startup announce cancelled by shutdown");
        } else if !announced {
            tracing::warn!("No online interface detected after 30s, announcing anyway");
            let _ = runner.send_announce().await;
            runner.last_peer_announce = now_f64();
        }
    }

    if !shutdown.is_triggered()
        && daemon_config.node_announce_at_start
        && daemon_config.propagation_enabled
    {
        match runner.send_propagation_announce().await {
            Ok(()) => {
                tracing::info!("Startup propagation announce sent");
                if runner.should_announce_control() {
                    match runner.send_control_announce().await {
                        Ok(()) => tracing::info!("Startup control announce sent"),
                        Err(e) => tracing::warn!("Failed to send startup control announce: {e}"),
                    }
                }
                runner.last_node_announce = now_f64();
            }
            Err(e) => tracing::warn!("Failed to send startup propagation announce: {e}"),
        }
    }

    if let Some(ref cmd) = daemon_config.on_inbound_command {
        tracing::info!("On-inbound command: {}", cmd);
    }

    if !shutdown.is_triggered()
        && let Some(ref send_args) = args.send
    {
        let dest_hex = normalize_hash_hex(&send_args[0]);
        let content = match args.send_file.as_ref() {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(content) => content,
                Err(e) => {
                    tracing::error!(path = %path.display(), error = %e, "failed to read --send-file");
                    std::process::exit(1);
                }
            },
            None => match send_args.get(1) {
                Some(content) => content.clone(),
                None => {
                    tracing::error!("--send requires CONTENT unless --send-file is provided");
                    std::process::exit(1);
                }
            },
        };

        let dest_hash = match parse_destination_hash(&dest_hex) {
            Ok(hash) => hash,
            Err(e) => {
                tracing::error!("{e}");
                std::process::exit(1);
            }
        };

        tracing::info!(dest = %dest_hex, "sending message...");
        runner.link_delivery_failures.clear();

        // Wait up to 15s for a fresh announce so we learn the destination's key and
        // install a current path before queueing. A persisted key alone is not enough
        // behind transport hubs: link delivery can start before the path exists.
        let mut have_key = runner.known_identities.contains_key(&dest_hex);
        let mut saw_dest_announce = false;
        for _ in 0..30 {
            for announced in runner.drain_announce_events() {
                if announced == dest_hash {
                    saw_dest_announce = true;
                }
            }
            runner.refresh_route_hops_from_transport().await;
            runner.drain_link_packets();
            have_key = runner.known_identities.contains_key(&dest_hex);
            if have_key && saw_dest_announce {
                break;
            }
            if sleep_or_shutdown(&shutdown, Duration::from_millis(500)).await {
                tracing::info!("message send interrupted by shutdown");
                return;
            }
        }
        if !have_key {
            tracing::warn!(
                dest = %dest_hex,
                "no announce received for destination in 15s; sending anyway"
            );
        } else if !saw_dest_announce {
            tracing::warn!(
                dest = %dest_hex,
                "no fresh path announce received for destination in 15s; sending anyway"
            );
        }

        let mut msg = LxMessage::new(
            dest_hash,
            runner.lxmf_dest_hash,
            "",
            &content,
            args.send_method.delivery_method(),
        );
        if let Some(raw) = args.send_fields_json.as_deref() {
            match parse_send_fields_json(raw) {
                Ok(fields) => {
                    tracing::info!(count = fields.len(), "attaching custom fields to --send");
                    msg.fields = fields;
                }
                Err(e) => {
                    tracing::error!("--send-fields-json: {e}");
                    std::process::exit(1);
                }
            }
        }
        let Some(signing_key) = runner.identity.get_signing_key() else {
            tracing::error!("identity has no signing key");
            std::process::exit(1);
        };
        if let Err(e) = msg.sign(&signing_key) {
            tracing::error!(error = ?e, "failed to sign message");
            std::process::exit(1);
        }
        if let Err(e) = runner.router.try_send(msg) {
            tracing::error!(error = %e, "failed to queue message");
            eprintln!("Error: {e}");
            std::process::exit(1);
        }

        // Drain phase: tick until the message leaves the router queue.
        // 30 iterations absorbs one full DELIVERY_RETRY_WAIT (10s) backoff.
        let mut drained = false;
        for _ in 0..30 {
            runner.drain_announce_events();
            runner.refresh_route_hops_from_transport().await;
            runner.drain_link_packets();
            runner.tick();
            if sleep_or_shutdown(&shutdown, Duration::from_secs(1)).await {
                tracing::info!("message send interrupted by shutdown");
                return;
            }

            let stats = runner.router.stats();
            if stats.pending_outbound == 0 && stats.pending_deferred_stamps == 0 {
                drained = true;
                break;
            }
        }

        if !drained {
            tracing::warn!("message send timed out (router queue never drained)");
            eprintln!("Error: send timed out (destination may be unreachable)");
            std::process::exit(1);
        }

        // Link-delivery completion phase: when escalated to link delivery
        // (Opportunistic>MTU auto-downgrade, Direct, or Propagated), the
        // router queue empties immediately but the transfer continues on the
        // link. Wait up to 90s so the proof can come back.
        if runner
            .link_delivery
            .as_ref()
            .is_some_and(|ld| ld.pending_count() > 0)
        {
            tracing::info!("waiting for link delivery to complete...");
            let mut link_done = false;
            for _ in 0..args.send_timeout_secs {
                runner.drain_announce_events();
                runner.refresh_route_hops_from_transport().await;
                runner.drain_link_packets();
                runner.tick();
                if sleep_or_shutdown(&shutdown, Duration::from_secs(1)).await {
                    tracing::info!("message send interrupted by shutdown");
                    return;
                }

                if runner
                    .link_delivery
                    .as_ref()
                    .is_none_or(|ld| ld.pending_count() == 0)
                {
                    link_done = true;
                    break;
                }
            }
            if !link_done {
                tracing::warn!(
                    timeout_secs = args.send_timeout_secs,
                    "link delivery did not complete before timeout"
                );
                eprintln!("Error: link delivery did not complete in time");
                std::process::exit(1);
            }
        }
        if let Some(reason) = runner.link_delivery_failures.last() {
            tracing::warn!(reason = %reason, "message send failed during link delivery");
            eprintln!("Error: link delivery failed: {reason}");
            std::process::exit(1);
        }

        tracing::info!("message sent successfully");
        println!("Message sent to {}", dest_hex);
        std::process::exit(0);
    }

    if !shutdown.is_triggered() {
        tracing::info!("LXMF Daemon running. Press Ctrl+C to stop.");
    }

    // Event-driven for inbound, periodic for outbound and maintenance.
    let mut tick_timer = tokio::time::interval(Duration::from_secs(4));
    tick_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            _ = tick_timer.tick() => {
                runner.drain_announce_events();
                runner.refresh_route_hops_from_transport().await;
                runner.drain_link_packets();
                runner.tick();
            }
            Some(raw) = runner.inbound_raw_rx.recv() => {
                runner.handle_inbound_packet(&raw);
            }
            Some((plaintext, _link_id)) = runner.link_packet_rx.recv() => {
                runner.handle_link_delivered_data(&plaintext);
                runner.drain_link_packets();
            }
            Some((data, _link_id)) = runner.prop_link_packet_rx.recv() => {
                runner.handle_propagation_transfer_data(&data);
                runner.drain_link_packets();
            }
            Some((data, _link_id)) = runner.prop_resource_rx.recv() => {
                runner.handle_propagation_transfer_data(&data);
                runner.drain_link_packets();
            }
        }
    }

    tracing::info!("LXMF Daemon shutting down");
    runner.save_crypto_state();
    if let Err(e) = runner.router.save_state(&runner.data_dir) {
        tracing::warn!("Failed to save router state on shutdown: {e}");
    }
    tracing::info!("Crypto state saved");
    tracing::info!("LXMF Daemon stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use lxmf_core::constants::DeliveryMethod;

    #[test]
    fn path_request_requeue_sets_path_wait_deadline() {
        let mut router = LxmRouter::new(Default::default());
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        let dest = [0x22; 16];
        let source = [0x11; 16];
        let message = LxMessage::new(dest, source, "retry", "hello", DeliveryMethod::Direct);
        let before = now_f64();

        requeue_after_path_request(&mut router, &tx, message, dest, "test path wait", true);

        assert_eq!(router.pending_outbound.len(), 1);
        let queued = &router.pending_outbound[0];
        assert_eq!(queued.delivery_attempts, 1);
        assert!(queued.last_delivery_attempt >= before);
        assert!(
            queued.next_delivery_attempt >= before + PATH_REQUEST_WAIT as f64 - 1.0
                && queued.next_delivery_attempt <= now_f64() + PATH_REQUEST_WAIT as f64 + 1.0,
            "path-request retry should wait about {PATH_REQUEST_WAIT}s"
        );

        match rx.try_recv().expect("path request") {
            TransportMessage::RequestPath { destination_hash } => {
                assert_eq!(destination_hash, dest);
            }
            other => panic!("expected RequestPath, got {other:?}"),
        }
    }

    #[test]
    fn queue_path_request_can_drop_stale_path_before_requesting() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        let dest = [0x24; 16];

        queue_path_request(&tx, dest, true, "test rediscovery");

        match rx.try_recv().expect("drop path rpc") {
            TransportMessage::Rpc {
                query: TransportQuery::DropPath { dest: dropped },
                ..
            } => assert_eq!(dropped, dest),
            other => panic!("expected DropPath RPC, got {other:?}"),
        }
        match rx.try_recv().expect("path request") {
            TransportMessage::RequestPath { destination_hash } => {
                assert_eq!(destination_hash, dest);
            }
            other => panic!("expected RequestPath, got {other:?}"),
        }
    }

    #[test]
    fn unknown_propagation_node_path_request_updates_backoff_clock() {
        let (tx, mut rx) = mpsc::channel::<TransportMessage>(4);
        let node = [0x26; 16];
        let mut last = 0.0;
        let now = 1234.5;

        assert!(queue_unknown_propagation_node_path_request(
            &tx, node, &mut last, now
        ));
        assert_eq!(last, now);
        match rx.try_recv().expect("path request") {
            TransportMessage::RequestPath { destination_hash } => {
                assert_eq!(destination_hash, node);
            }
            other => panic!("expected RequestPath, got {other:?}"),
        }
    }

    #[test]
    fn unknown_propagation_node_path_request_updates_backoff_clock_on_full_channel() {
        let (tx, _rx) = mpsc::channel::<TransportMessage>(1);
        let node = [0x27; 16];
        let mut last = 99.0;

        tx.try_send(TransportMessage::RequestPath {
            destination_hash: [0x28; 16],
        })
        .expect("fill test channel");

        assert!(!queue_unknown_propagation_node_path_request(
            &tx, node, &mut last, 1234.5
        ));
        assert_eq!(last, 1234.5);
    }

    #[test]
    fn path_request_requeue_can_preserve_attempt_count_after_link_start_failure() {
        let mut router = LxmRouter::new(Default::default());
        let (tx, _rx) = mpsc::channel::<TransportMessage>(4);
        let dest = [0x44; 16];
        let source = [0x33; 16];
        let mut message = LxMessage::new(dest, source, "retry", "hello", DeliveryMethod::Direct);
        message.delivery_attempts = 3;

        requeue_after_path_request(&mut router, &tx, message, dest, "transport full", false);

        assert_eq!(router.pending_outbound.len(), 1);
        assert_eq!(router.pending_outbound[0].delivery_attempts, 3);
        assert!(router.pending_outbound[0].next_delivery_attempt > now_f64());
    }

    #[test]
    fn delivery_attempt_uses_delivery_retry_deadline() {
        let dest = [0x66; 16];
        let source = [0x55; 16];
        let mut message = LxMessage::new(dest, source, "direct", "hello", DeliveryMethod::Direct);
        let before = now_f64();

        let attempts = mark_delivery_attempt(&mut message);

        assert_eq!(attempts, 1);
        assert_eq!(message.delivery_attempts, 1);
        assert!(message.last_delivery_attempt >= before);
        assert!(
            message.next_delivery_attempt >= before + DELIVERY_RETRY_WAIT as f64 - 1.0
                && message.next_delivery_attempt <= now_f64() + DELIVERY_RETRY_WAIT as f64 + 1.0,
            "delivery retry should wait about {DELIVERY_RETRY_WAIT}s"
        );
    }

    #[test]
    fn link_failure_retry_policy_matches_pre_establishment_failures() {
        assert!(link_failure_retryable("link establishment timeout"));
        assert!(link_failure_retryable("link closed"));
        assert!(link_failure_retryable("transport full"));
        assert!(link_failure_retryable("transport closed"));
        assert!(link_failure_retryable("link is not active"));
        assert!(link_failure_retryable("link not found"));
        assert!(!link_failure_retryable("resource transfer failed"));
    }

    #[test]
    fn route_hops_for_uses_cached_announce_hops_with_one_hop_floor() {
        let dest = [0x77; 16];
        let mut hops = HashMap::new();

        assert_eq!(route_hops_for(&hops, dest), 1);

        hops.insert(dest, 4);
        assert_eq!(route_hops_for(&hops, dest), 4);

        hops.insert(dest, 0);
        assert_eq!(route_hops_for(&hops, dest), 1);
    }

    #[test]
    fn direct_route_snapshot_uses_cached_announce_hops() {
        let dest = [0x88; 16];
        let mut hops = HashMap::new();

        assert!(direct_route_snapshot(&hops, dest).is_none());

        hops.insert(dest, 5);
        let snapshot = direct_route_snapshot(&hops, dest).expect("route snapshot");
        assert_eq!(snapshot.destination_hash, dest);
        assert_eq!(snapshot.hops, 5);
    }

    #[test]
    fn direct_reusable_link_state_uses_registered_backchannel() {
        let (tx, _rx) = mpsc::channel(8);
        let mut manager = lxmf_core::link_delivery::LinkDeliveryManager::new(tx, None, None);
        let dest = [0x43; 16];
        let link_id = [0x44; 16];

        manager.register_backchannel(dest, link_id);

        assert_eq!(
            direct_reusable_link_state(Some(&manager), dest),
            DirectReusableLinkState::Active
        );
        assert_eq!(
            direct_reusable_link_state(Some(&manager), [0x45; 16]),
            DirectReusableLinkState::None
        );
    }
}
