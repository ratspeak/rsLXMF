//! LXMF daemon configuration and runner.
//!
//! Python reference: LXMF/Utilities/lxmd.py.

use lxmf_core::constants::*;
use lxmf_core::router::{LxmRouter, RouterConfig, RouterConfigExt};
use rns_runtime::config::{Config, ConfigSection};

/// Normalized view of Python `lxmd.apply_config()` behavior.
///
/// This intentionally mirrors Python's active_configuration keys and units.
/// It is kept separate from [`DaemonConfig`] while the daemon still has legacy
/// Rust fields and storage layout.
#[derive(Debug, Clone, PartialEq)]
pub struct PythonLxmdConfig {
    pub display_name: String,
    pub peer_announce_at_start: bool,
    pub peer_announce_interval: Option<i64>,
    pub delivery_transfer_max_accepted_size: f64,
    pub on_inbound: Option<String>,
    pub enable_propagation_node: bool,
    pub node_name: Option<String>,
    pub auth_required: bool,
    pub node_announce_at_start: bool,
    pub autopeer: bool,
    pub autopeer_maxdepth: Option<i64>,
    pub node_announce_interval: Option<i64>,
    pub message_storage_limit: f64,
    pub propagation_transfer_max_accepted_size: f64,
    pub propagation_sync_max_accepted_size: f64,
    pub propagation_stamp_cost_target: i64,
    pub propagation_stamp_cost_flexibility: i64,
    pub peering_cost: i64,
    pub remote_peering_cost_max: i64,
    pub prioritised_lxmf_destinations: Vec<String>,
    pub control_allowed_identities: Vec<String>,
    pub static_peers: Vec<String>,
    pub max_peers: Option<i64>,
    pub from_static_only: bool,
    pub target_loglevel: Option<i64>,
}

impl PythonLxmdConfig {
    pub fn from_config(config: &Config) -> Self {
        let lxmf = config.section("lxmf");
        let propagation = config.section("propagation");
        let logging = config.section("logging");

        let propagation_transfer_max_accepted_size = propagation
            .and_then(|sec| sec.get_float("propagation_message_max_accepted_size"))
            .map(|v| v.max(0.38))
            .unwrap_or(256.0);

        Self {
            display_name: lxmf
                .and_then(|sec| sec.get("display_name"))
                .unwrap_or("Anonymous Peer")
                .to_string(),
            peer_announce_at_start: get_bool_or(lxmf, "announce_at_start", false),
            peer_announce_interval: get_int(lxmf, "announce_interval").map(|v| v * 60),
            delivery_transfer_max_accepted_size: get_float_or_floor(
                lxmf,
                "delivery_transfer_max_accepted_size",
                1000.0,
                0.38,
            ),
            on_inbound: lxmf
                .and_then(|sec| sec.get("on_inbound"))
                .map(ToString::to_string),
            enable_propagation_node: get_bool_or(propagation, "enable_node", false),
            node_name: propagation
                .and_then(|sec| sec.get("node_name"))
                .map(ToString::to_string),
            auth_required: get_bool_or(propagation, "auth_required", false),
            node_announce_at_start: get_bool_or(propagation, "announce_at_start", false),
            autopeer: get_bool_or(propagation, "autopeer", true),
            autopeer_maxdepth: get_int(propagation, "autopeer_maxdepth"),
            node_announce_interval: get_int(propagation, "announce_interval").map(|v| v * 60),
            message_storage_limit: get_float_or_floor(
                propagation,
                "message_storage_limit",
                500.0,
                0.005,
            ),
            propagation_transfer_max_accepted_size,
            propagation_sync_max_accepted_size: get_float_or_floor(
                propagation,
                "propagation_sync_max_accepted_size",
                256.0 * 40.0,
                0.38,
            ),
            propagation_stamp_cost_target: get_int(propagation, "propagation_stamp_cost_target")
                .map(|v| v.max(PROPAGATION_COST_MIN as i64))
                .unwrap_or(PROPAGATION_COST as i64),
            propagation_stamp_cost_flexibility: get_int(
                propagation,
                "propagation_stamp_cost_flexibility",
            )
            .map(|v| v.max(0))
            .unwrap_or(PROPAGATION_COST_FLEX as i64),
            peering_cost: get_int(propagation, "peering_cost")
                .map(|v| v.max(0))
                .unwrap_or(PEERING_COST as i64),
            remote_peering_cost_max: get_int(propagation, "remote_peering_cost_max")
                .map(|v| v.max(0))
                .unwrap_or(MAX_PEERING_COST as i64),
            prioritised_lxmf_destinations: get_list(propagation, "prioritise_destinations"),
            control_allowed_identities: get_list(propagation, "control_allowed"),
            static_peers: get_list(propagation, "static_peers"),
            max_peers: get_int(propagation, "max_peers"),
            from_static_only: get_bool_or(propagation, "from_static_only", false),
            target_loglevel: get_int(logging, "loglevel"),
        }
    }
}

fn get_bool_or(section: Option<&ConfigSection>, key: &str, default: bool) -> bool {
    section.and_then(|sec| sec.get_bool(key)).unwrap_or(default)
}

fn get_int(section: Option<&ConfigSection>, key: &str) -> Option<i64> {
    section.and_then(|sec| sec.get_int(key))
}

fn get_float_or_floor(section: Option<&ConfigSection>, key: &str, default: f64, floor: f64) -> f64 {
    section
        .and_then(|sec| sec.get_float(key))
        .map(|value| value.max(floor))
        .unwrap_or(default)
}

fn get_list(section: Option<&ConfigSection>, key: &str) -> Vec<String> {
    section
        .and_then(|sec| sec.get_list(key))
        .unwrap_or_default()
}

/// Daemon configuration parsed from an INI config file.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub display_name: Option<String>,
    pub node_name: Option<String>,
    pub announce_at_start: bool,
    pub announce_interval: Option<u64>,
    pub stamp_cost: Option<u8>,
    pub propagation_enabled: bool,
    pub outbound_propagation_node: Option<String>,
    pub propagation_stamp_cost: u8,
    pub propagation_stamp_flex: u8,
    pub peering_cost: u8,
    pub max_peering_cost: u8,
    pub max_peers: usize,
    pub autopeer: bool,
    pub autopeer_maxdepth: usize,
    pub propagation_limit_kb: usize,
    pub sync_limit_kb: usize,
    pub on_inbound_command: Option<String>,
    pub node_announce_at_start: bool,
    pub node_announce_interval: Option<u64>,
    pub auth_required: bool,
    pub control_allowed: Vec<String>,
    pub static_peers: Vec<String>,
    pub prioritise_destinations: Vec<String>,
    pub enforce_stamps: bool,
    pub message_storage_limit: Option<usize>,
    pub from_static_only: bool,
    /// Max accepted inbound delivery transfer size in KB. Python reference:
    /// `delivery_transfer_max_accepted_size` in `lxmd.py`.
    pub delivery_transfer_max_accepted_size: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            display_name: Some("Anonymous Peer".to_string()),
            node_name: None,
            announce_at_start: false,
            announce_interval: None,
            stamp_cost: None,
            propagation_enabled: false,
            outbound_propagation_node: None,
            propagation_stamp_cost: PROPAGATION_COST,
            propagation_stamp_flex: PROPAGATION_COST_FLEX,
            peering_cost: PEERING_COST,
            max_peering_cost: MAX_PEERING_COST,
            max_peers: MAX_PEERS,
            autopeer: true,
            autopeer_maxdepth: AUTOPEER_MAXDEPTH,
            propagation_limit_kb: PROPAGATION_LIMIT,
            sync_limit_kb: SYNC_LIMIT,
            on_inbound_command: None,
            node_announce_at_start: false,
            node_announce_interval: None,
            auth_required: false,
            control_allowed: Vec::new(),
            static_peers: Vec::new(),
            prioritise_destinations: Vec::new(),
            enforce_stamps: false,
            message_storage_limit: Some(500_000_000),
            from_static_only: false,
            delivery_transfer_max_accepted_size: DELIVERY_LIMIT,
        }
    }
}

impl DaemonConfig {
    pub fn to_router_config(&self) -> RouterConfig {
        RouterConfig {
            propagation_enabled: self.propagation_enabled,
            autopeer: self.autopeer,
            max_peers: self.max_peers,
            propagation_limit_kb: self.propagation_limit_kb,
            delivery_limit_kb: self.delivery_transfer_max_accepted_size,
            sync_limit_kb: self.sync_limit_kb,
            propagation_stamp_cost: self.propagation_stamp_cost,
            propagation_stamp_flex: self.propagation_stamp_flex,
            stamp_cost: self.stamp_cost,
            ext: RouterConfigExt {
                autopeer_maxdepth: self.autopeer_maxdepth,
                peering_cost: self.peering_cost,
                max_peering_cost: self.max_peering_cost,
                auth_required: self.auth_required,
                message_storage_limit: self.message_storage_limit,
                name: self.node_name.clone(),
                from_static_only: self.from_static_only,
                ..Default::default()
            },
        }
    }

    /// Parse from `[lxmf]`, `[propagation]`, and `[control]` sections.
    pub fn from_config(config: &Config) -> Self {
        let py = PythonLxmdConfig::from_config(config);
        let mut dc = DaemonConfig {
            display_name: Some(py.display_name),
            node_name: py.node_name,
            announce_at_start: py.peer_announce_at_start,
            announce_interval: seconds_to_u64(py.peer_announce_interval),
            propagation_enabled: py.enable_propagation_node,
            propagation_stamp_cost: clamp_python_cost_to_u8(
                py.propagation_stamp_cost_target,
                PROPAGATION_COST_MIN as i64,
            ),
            propagation_stamp_flex: clamp_python_cost_to_u8(
                py.propagation_stamp_cost_flexibility,
                0,
            ),
            peering_cost: clamp_python_cost_to_u8(py.peering_cost, 0),
            max_peering_cost: clamp_python_cost_to_u8(py.remote_peering_cost_max, 0),
            max_peers: py
                .max_peers
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(MAX_PEERS),
            autopeer: py.autopeer,
            autopeer_maxdepth: py
                .autopeer_maxdepth
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(AUTOPEER_MAXDEPTH),
            propagation_limit_kb: kb_to_usize_ceil(py.propagation_transfer_max_accepted_size),
            sync_limit_kb: kb_to_usize_ceil(py.propagation_sync_max_accepted_size),
            on_inbound_command: py.on_inbound,
            node_announce_at_start: py.node_announce_at_start,
            node_announce_interval: seconds_to_u64(py.node_announce_interval),
            auth_required: py.auth_required,
            control_allowed: py.control_allowed_identities,
            static_peers: py.static_peers,
            prioritise_destinations: py.prioritised_lxmf_destinations,
            message_storage_limit: megabytes_to_bytes(py.message_storage_limit),
            from_static_only: py.from_static_only,
            delivery_transfer_max_accepted_size: kb_to_usize_ceil(
                py.delivery_transfer_max_accepted_size,
            ),
            ..DaemonConfig::default()
        };

        if let Some(sec) = config.section("lxmf")
            && let Some(cost) = sec.get_uint("stamp_cost")
        {
            dc.stamp_cost = Some(cost as u8);
        }

        if let Some(sec) = config.section("propagation") {
            if let Some(node) = sec.get("outbound_node") {
                let trimmed = node.trim();
                if !trimmed.is_empty() {
                    dc.outbound_propagation_node = Some(trimmed.to_string());
                }
            }
            if get_int(Some(sec), "propagation_stamp_cost_target").is_none()
                && let Some(cost) = sec.get_uint("propagation_stamp_cost")
            {
                dc.propagation_stamp_cost = cost as u8;
            }
            if get_float(Some(sec), "propagation_message_max_accepted_size").is_none()
                && get_float(Some(sec), "propagation_transfer_max_accepted_size").is_none()
                && let Some(limit) = sec.get_uint("propagation_limit")
            {
                dc.propagation_limit_kb = limit as usize;
            }
            dc.enforce_stamps = sec.get_bool_or("enforce_stamps", false);
        }

        if let Some(sec) = config.section("control") {
            if !dc.auth_required {
                dc.auth_required = sec.get_bool_or("auth_required", false);
            }
            if dc.control_allowed.is_empty()
                && let Some(allowed) = sec.get("allowed")
            {
                dc.control_allowed = allowed
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        dc
    }
}

fn clamp_python_cost_to_u8(value: i64, floor: i64) -> u8 {
    value.max(floor).min(u8::MAX as i64) as u8
}

fn get_float(section: Option<&ConfigSection>, key: &str) -> Option<f64> {
    section.and_then(|sec| sec.get_float(key))
}

fn seconds_to_u64(value: Option<i64>) -> Option<u64> {
    value.map(|seconds| seconds.max(0) as u64)
}

fn kb_to_usize_ceil(value: f64) -> usize {
    value.max(0.0).ceil().max(1.0) as usize
}

fn megabytes_to_bytes(value: f64) -> Option<usize> {
    let bytes = (value.max(0.0) * 1_000_000.0) as usize;
    (bytes > 0).then_some(bytes)
}

pub fn create_router(config: &DaemonConfig) -> LxmRouter {
    LxmRouter::new(config.to_router_config())
}

pub fn create_router_with_transport(
    config: &DaemonConfig,
    transport_tx: tokio::sync::mpsc::Sender<rns_transport::messages::TransportMessage>,
) -> LxmRouter {
    let mut router = LxmRouter::new(config.to_router_config());
    router.set_transport(transport_tx);
    router
}

/// Execute an on_inbound hook.
///
/// Runs `Command::new(prog).arg(...)` with `message_path` as a separate
/// argument rather than interpolating into a shell string, so untrusted path
/// contents cannot inject shell metacharacters.
pub fn execute_on_inbound(command: &str, message_path: &str) -> std::io::Result<()> {
    use std::process::Command;

    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    let mut cmd = Command::new(parts[0]);
    for arg in &parts[1..] {
        cmd.arg(arg);
    }
    cmd.arg(message_path);

    let status = cmd.status()?;
    if !status.success() {
        tracing::warn!("on_inbound command exited with status: {}", status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let dc = DaemonConfig::default();
        assert_eq!(dc.display_name.as_deref(), Some("Anonymous Peer"));
        assert!(!dc.announce_at_start);
        assert_eq!(dc.announce_interval, None);
        assert!(!dc.propagation_enabled);
        assert_eq!(dc.propagation_stamp_cost, 16);
        assert_eq!(dc.propagation_stamp_flex, 3);
        assert_eq!(dc.peering_cost, 18);
        assert_eq!(dc.max_peering_cost, 26);
        assert_eq!(dc.max_peers, 20);
        assert!(dc.autopeer);
        assert_eq!(dc.autopeer_maxdepth, AUTOPEER_MAXDEPTH);
        assert_eq!(dc.propagation_limit_kb, 256);
        assert_eq!(dc.sync_limit_kb, 10_240);
        assert!(!dc.node_announce_at_start);
        assert_eq!(dc.node_announce_interval, None);
        assert_eq!(dc.message_storage_limit, Some(500_000_000));
        assert_eq!(dc.delivery_transfer_max_accepted_size, 1000);
        assert!(!dc.from_static_only);
    }

    #[test]
    fn python_normalized_config_matches_omitted_defaults() {
        let config = rns_runtime::config::Config::parse("").unwrap();
        let py = PythonLxmdConfig::from_config(&config);

        assert_eq!(py.display_name, "Anonymous Peer");
        assert!(!py.peer_announce_at_start);
        assert_eq!(py.peer_announce_interval, None);
        assert_eq!(py.delivery_transfer_max_accepted_size, 1000.0);
        assert_eq!(py.on_inbound, None);
        assert!(!py.enable_propagation_node);
        assert_eq!(py.node_name, None);
        assert!(!py.auth_required);
        assert!(!py.node_announce_at_start);
        assert!(py.autopeer);
        assert_eq!(py.autopeer_maxdepth, None);
        assert_eq!(py.node_announce_interval, None);
        assert_eq!(py.message_storage_limit, 500.0);
        assert_eq!(py.propagation_transfer_max_accepted_size, 256.0);
        assert_eq!(py.propagation_sync_max_accepted_size, 10240.0);
        assert_eq!(py.propagation_stamp_cost_target, 16);
        assert_eq!(py.propagation_stamp_cost_flexibility, 3);
        assert_eq!(py.peering_cost, 18);
        assert_eq!(py.remote_peering_cost_max, 26);
        assert!(py.prioritised_lxmf_destinations.is_empty());
        assert!(py.control_allowed_identities.is_empty());
        assert!(py.static_peers.is_empty());
        assert_eq!(py.max_peers, None);
        assert!(!py.from_static_only);
        assert_eq!(py.target_loglevel, None);
    }

    #[test]
    fn python_normalized_config_matches_units_floors_and_lists() {
        let input = r#"
[propagation]
announce_interval = 2
message_storage_limit = 0.001
propagation_message_max_accepted_size = 0.1
propagation_sync_max_accepted_size = 0.1
propagation_stamp_cost_target = 1
propagation_stamp_cost_flexibility = -9
peering_cost = -1
remote_peering_cost_max = -2
static_peers = 00112233445566778899aabbccddeeff
prioritise_destinations = 0102030405060708090a0b0c0d0e0f10
control_allowed = 11111111111111111111111111111111
from_static_only = yes
max_peers = 7

[lxmf]
announce_interval = 3
delivery_transfer_max_accepted_size = 0.1

[logging]
loglevel = 6
"#;
        let config = rns_runtime::config::Config::parse(input).unwrap();
        let py = PythonLxmdConfig::from_config(&config);

        assert_eq!(py.peer_announce_interval, Some(180));
        assert_eq!(py.node_announce_interval, Some(120));
        assert_eq!(py.delivery_transfer_max_accepted_size, 0.38);
        assert_eq!(py.message_storage_limit, 0.005);
        assert_eq!(py.propagation_transfer_max_accepted_size, 0.38);
        assert_eq!(py.propagation_sync_max_accepted_size, 0.38);
        assert_eq!(py.propagation_stamp_cost_target, 13);
        assert_eq!(py.propagation_stamp_cost_flexibility, 0);
        assert_eq!(py.peering_cost, 0);
        assert_eq!(py.remote_peering_cost_max, 0);
        assert_eq!(py.static_peers, ["00112233445566778899aabbccddeeff"]);
        assert_eq!(
            py.prioritised_lxmf_destinations,
            ["0102030405060708090a0b0c0d0e0f10"]
        );
        assert_eq!(
            py.control_allowed_identities,
            ["11111111111111111111111111111111"]
        );
        assert_eq!(py.max_peers, Some(7));
        assert!(py.from_static_only);
        assert_eq!(py.target_loglevel, Some(6));
    }

    #[test]
    fn python_normalized_config_keeps_legacy_transfer_overwrite() {
        let input = r#"
[propagation]
propagation_transfer_max_accepted_size = 12
"#;
        let config = rns_runtime::config::Config::parse(input).unwrap();
        let py = PythonLxmdConfig::from_config(&config);

        assert_eq!(
            py.propagation_transfer_max_accepted_size, 256.0,
            "Python 0.9.6 ignores legacy propagation_transfer_max_accepted_size unless the newer key is set"
        );
    }

    #[test]
    fn daemon_config_matches_python_legacy_transfer_overwrite() {
        let input = r#"
[propagation]
propagation_transfer_max_accepted_size = 12
"#;
        let config = rns_runtime::config::Config::parse(input).unwrap();
        let dc = DaemonConfig::from_config(&config);

        assert_eq!(
            dc.propagation_limit_kb, 256,
            "DaemonConfig should match Python 0.9.6 handling of legacy propagation_transfer_max_accepted_size"
        );
    }

    #[test]
    fn test_to_router_config() {
        let dc = DaemonConfig::default();
        let rc = dc.to_router_config();
        assert!(!rc.propagation_enabled);
        assert_eq!(rc.max_peers, 20);
        assert_eq!(rc.delivery_limit_kb, 1000);
        assert_eq!(rc.propagation_limit_kb, 256);
        assert_eq!(rc.sync_limit_kb, 10_240);
        assert_eq!(rc.propagation_stamp_cost, 16);
        assert_eq!(rc.propagation_stamp_flex, 3);
        assert_eq!(rc.ext.autopeer_maxdepth, AUTOPEER_MAXDEPTH);
        assert_eq!(rc.ext.peering_cost, 18);
        assert_eq!(rc.ext.max_peering_cost, 26);
        assert!(!rc.ext.auth_required);
        assert_eq!(rc.ext.message_storage_limit, Some(500_000_000));
        assert_eq!(rc.ext.name, None);
        assert!(!rc.ext.from_static_only);
    }

    #[test]
    fn test_create_router() {
        let dc = DaemonConfig::default();
        let router = create_router(&dc);
        assert!(router.pending_outbound.is_empty());
    }

    #[test]
    fn test_create_router_with_transport() {
        let dc = DaemonConfig::default();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let router = create_router_with_transport(&dc, tx);
        assert!(router.has_transport());
        assert!(router.pending_outbound.is_empty());
    }

    #[test]
    fn test_parse_config() {
        let input = r#"
[lxmf]
display_name = TestNode
announce_at_start = yes
announce_interval = 3
delivery_transfer_max_accepted_size = 0.1
stamp_cost = 8

[propagation]
enable_node = yes
node_name = PropNode
outbound_node = aabbccddeeff00112233445566778899
announce_at_start = yes
announce_interval = 2
message_storage_limit = 0.001
propagation_message_max_accepted_size = 0.1
propagation_sync_max_accepted_size = 0.1
propagation_stamp_cost_target = 1
propagation_stamp_cost_flexibility = -9
peering_cost = -1
remote_peering_cost_max = -2
max_peers = 10
autopeer = no
autopeer_maxdepth = 2
static_peers = 00112233445566778899aabbccddeeff
prioritise_destinations = 0102030405060708090a0b0c0d0e0f10
control_allowed = 11111111111111111111111111111111
from_static_only = yes
"#;
        let config = rns_runtime::config::Config::parse(input).unwrap();
        let dc = DaemonConfig::from_config(&config);
        assert_eq!(dc.display_name.as_deref(), Some("TestNode"));
        assert!(dc.announce_at_start);
        assert_eq!(dc.announce_interval, Some(180));
        assert_eq!(dc.delivery_transfer_max_accepted_size, 1);
        assert_eq!(dc.stamp_cost, Some(8));
        assert!(dc.propagation_enabled);
        assert_eq!(dc.node_name.as_deref(), Some("PropNode"));
        assert_eq!(
            dc.outbound_propagation_node.as_deref(),
            Some("aabbccddeeff00112233445566778899")
        );
        assert!(dc.node_announce_at_start);
        assert_eq!(dc.node_announce_interval, Some(120));
        assert_eq!(dc.message_storage_limit, Some(5_000));
        assert_eq!(dc.propagation_limit_kb, 1);
        assert_eq!(dc.sync_limit_kb, 1);
        assert_eq!(dc.propagation_stamp_cost, 13);
        assert_eq!(dc.propagation_stamp_flex, 0);
        assert_eq!(dc.peering_cost, 0);
        assert_eq!(dc.max_peering_cost, 0);
        assert_eq!(dc.max_peers, 10);
        assert!(!dc.autopeer);
        assert_eq!(dc.autopeer_maxdepth, 2);
        assert_eq!(dc.static_peers, ["00112233445566778899aabbccddeeff"]);
        assert_eq!(
            dc.prioritise_destinations,
            ["0102030405060708090a0b0c0d0e0f10"]
        );
        assert_eq!(dc.control_allowed, ["11111111111111111111111111111111"]);
        assert!(dc.from_static_only);
    }

    #[test]
    fn test_parse_python_stamp_target_key_with_floor() {
        let input = r#"
[propagation]
propagation_stamp_cost_target = 1
"#;
        let config = rns_runtime::config::Config::parse(input).unwrap();
        let dc = DaemonConfig::from_config(&config);

        assert_eq!(dc.propagation_stamp_cost, PROPAGATION_COST_MIN);
        assert_eq!(
            dc.to_router_config().propagation_stamp_cost,
            PROPAGATION_COST_MIN
        );
    }

    #[test]
    fn test_legacy_stamp_cost_key_remains_fallback() {
        let input = r#"
[propagation]
propagation_stamp_cost = 19
"#;
        let config = rns_runtime::config::Config::parse(input).unwrap();
        let dc = DaemonConfig::from_config(&config);

        assert_eq!(dc.propagation_stamp_cost, 19);
        assert_eq!(dc.to_router_config().propagation_stamp_cost, 19);
    }

    /// Python lxmd exposes no enforce_ratchets option; the key must parse as a no-op.
    #[test]
    fn test_enforce_ratchets_key_ignored_matching_python_lxmd() {
        let input = r#"
[propagation]
enforce_ratchets = yes
enforce_stamps = yes
"#;
        let config = rns_runtime::config::Config::parse(input).unwrap();
        let dc = DaemonConfig::from_config(&config);

        assert!(dc.enforce_stamps);
    }
}
