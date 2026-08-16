//! LXMF daemon configuration and runner.
//!
//! Python reference: LXMF/Utilities/lxmd.py.

use lxmf_core::constants::*;
use lxmf_core::propagation_admission::{
    PN_DEFAULT_MAX_INBOUND_SYNCS, PN_MIN_MAX_INBOUND_SYNCS, PnInboundAdmissionConfig,
};
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
    pub peer_stamp_cost: i64,
    pub delivery_transfer_max_accepted_size: f64,
    pub on_inbound: Option<String>,
    pub enable_propagation_node: bool,
    pub node_name: Option<String>,
    pub auth_required: bool,
    pub node_announce_at_start: bool,
    pub autopeer: bool,
    pub autopeer_maxdepth: Option<i64>,
    pub sequential_pn_stamp_validation: bool,
    pub static_peers_bypass_sequential: bool,
    pub max_inbound_syncs: i64,
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
            peer_stamp_cost: get_int(lxmf, "stamp_cost")
                .map(|value| value.max(1))
                .unwrap_or(12),
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
            sequential_pn_stamp_validation: get_bool_or(
                propagation,
                "sequential_pn_stamp_validation",
                true,
            ),
            static_peers_bypass_sequential: get_bool_or(
                propagation,
                "static_peers_bypass_sequential",
                true,
            ),
            max_inbound_syncs: get_int(propagation, "max_inbound_syncs")
                .map(|value| value.max(PN_MIN_MAX_INBOUND_SYNCS as i64))
                .unwrap_or(PN_DEFAULT_MAX_INBOUND_SYNCS as i64),
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
    pub sequential_pn_stamp_validation: bool,
    pub static_peers_bypass_sequential: bool,
    pub max_inbound_syncs: usize,
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
    pub delivery_transfer_max_accepted_size: f64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            display_name: Some("Anonymous Peer".to_string()),
            node_name: None,
            announce_at_start: false,
            announce_interval: None,
            stamp_cost: Some(12),
            propagation_enabled: false,
            outbound_propagation_node: None,
            propagation_stamp_cost: PROPAGATION_COST,
            propagation_stamp_flex: PROPAGATION_COST_FLEX,
            peering_cost: PEERING_COST,
            max_peering_cost: MAX_PEERING_COST,
            max_peers: MAX_PEERS,
            autopeer: true,
            autopeer_maxdepth: AUTOPEER_MAXDEPTH,
            sequential_pn_stamp_validation: true,
            static_peers_bypass_sequential: true,
            max_inbound_syncs: PN_DEFAULT_MAX_INBOUND_SYNCS,
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
            // Python lxmd defaults direct-delivery Resource admission to
            // 1000 decimal KB when the setting is omitted.
            delivery_transfer_max_accepted_size: 1000.0,
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

    /// Build the long-lived inbound propagation admission policy.
    pub fn to_inbound_admission_config(&self) -> PnInboundAdmissionConfig {
        PnInboundAdmissionConfig {
            sequential_validation: self.sequential_pn_stamp_validation,
            static_sequential: !self.static_peers_bypass_sequential,
            max_inbound_syncs: self.max_inbound_syncs,
            from_static_only: self.from_static_only,
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
            stamp_cost: normalize_peer_stamp_cost(py.peer_stamp_cost),
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
            sequential_pn_stamp_validation: py.sequential_pn_stamp_validation,
            static_peers_bypass_sequential: py.static_peers_bypass_sequential,
            max_inbound_syncs: usize::try_from(py.max_inbound_syncs).unwrap_or(usize::MAX),
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
            delivery_transfer_max_accepted_size: py.delivery_transfer_max_accepted_size,
            ..DaemonConfig::default()
        };

        if let Some(sec) = config.section("propagation") {
            if let Some(node) = sec.get("outbound_node") {
                let trimmed = node.trim();
                if !trimmed.is_empty() {
                    dc.outbound_propagation_node = Some(trimmed.to_string());
                }
            }
            if get_int(Some(sec), "propagation_stamp_cost_target").is_none() {
                if let Some(cost) = sec.get_uint("propagation_stamp_cost") {
                    dc.propagation_stamp_cost = cost as u8;
                }
            }
            if get_float(Some(sec), "propagation_message_max_accepted_size").is_none()
                && get_float(Some(sec), "propagation_transfer_max_accepted_size").is_none()
            {
                if let Some(limit) = sec.get_uint("propagation_limit") {
                    dc.propagation_limit_kb = limit as usize;
                }
            }
            dc.enforce_stamps = sec.get_bool_or("enforce_stamps", false);
        }

        if let Some(sec) = config.section("control") {
            if !dc.auth_required {
                dc.auth_required = sec.get_bool_or("auth_required", false);
            }
            if dc.control_allowed.is_empty() {
                if let Some(allowed) = sec.get("allowed") {
                    dc.control_allowed = allowed
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }

        dc
    }
}

fn clamp_python_cost_to_u8(value: i64, floor: i64) -> u8 {
    value.max(floor).min(u8::MAX as i64) as u8
}

/// Apply Python lxmd's signed floor, then mirror `set_inbound_stamp_cost`:
/// delivery stamp costs are valid only in `1..=254`.
fn normalize_peer_stamp_cost(value: i64) -> Option<u8> {
    let cost = u8::try_from(value.max(1)).ok()?;
    (cost < u8::MAX).then_some(cost)
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

    let parts = split_command_line(command)?;
    if parts.is_empty() {
        return Ok(());
    }

    let mut cmd = Command::new(&parts[0]);
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

/// Parse the configured hook using the shell-like quoting supported by
/// Python's `shlex.split()`, without invoking a shell.
fn split_command_line(command: &str) -> std::io::Result<Vec<String>> {
    use std::io::{Error, ErrorKind};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote = Quote::None;
    let mut escaped = false;
    let mut started = false;

    for ch in command.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            started = true;
            continue;
        }

        match quote {
            Quote::Single => {
                if ch == '\'' {
                    quote = Quote::None;
                } else {
                    current.push(ch);
                }
                started = true;
            }
            Quote::Double => {
                if ch == '"' {
                    quote = Quote::None;
                } else if ch == '\\' {
                    escaped = true;
                } else {
                    current.push(ch);
                }
                started = true;
            }
            Quote::None => match ch {
                '\'' => {
                    quote = Quote::Single;
                    started = true;
                }
                '"' => {
                    quote = Quote::Double;
                    started = true;
                }
                '\\' => {
                    escaped = true;
                    started = true;
                }
                c if c.is_whitespace() => {
                    if started {
                        parts.push(std::mem::take(&mut current));
                        started = false;
                    }
                }
                _ => {
                    current.push(ch);
                    started = true;
                }
            },
        }
    }

    if escaped || quote != Quote::None {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "unterminated quote or escape in on_inbound command",
        ));
    }
    if started {
        parts.push(current);
    }
    Ok(parts)
}

/// Persist a received message before invoking the configured hook. Keeping
/// both operations in one blocking job prevents the hook from racing the
/// atomic file write and keeps process execution off the async daemon loop.
pub fn persist_inbound_and_execute(
    message_path: &std::path::Path,
    packed: &[u8],
    command: Option<&str>,
) -> std::io::Result<()> {
    lxmf_core::persist::write_file_atomic(message_path, packed)?;
    if let Some(command) = command {
        execute_on_inbound(command, &message_path.to_string_lossy())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_inbound_parser_matches_shell_like_quoting_without_a_shell() {
        assert_eq!(
            split_command_line("/tmp/a\\ b --label 'two words' \"\" --quoted=\"x y\"").unwrap(),
            ["/tmp/a b", "--label", "two words", "", "--quoted=x y"]
        );
        assert!(split_command_line("hook 'unterminated").is_err());
        assert!(split_command_line("hook trailing\\").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn inbound_hook_observes_fully_persisted_message() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let hook = dir.path().join("hook with spaces.sh");
        let message = dir.path().join("message.lxm");
        let observed = dir.path().join("observed");
        std::fs::write(
            &hook,
            "#!/bin/sh\nexpected=$1\nobserved=$2\nmessage=$3\ncmp \"$expected\" \"$message\" && printf ok > \"$observed\"\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&hook).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&hook, permissions).unwrap();
        let expected = dir.path().join("expected");
        std::fs::write(&expected, b"complete payload").unwrap();

        let command = format!(
            "'{}' '{}' '{}'",
            hook.display(),
            expected.display(),
            observed.display()
        );
        persist_inbound_and_execute(&message, b"complete payload", Some(&command)).unwrap();

        assert_eq!(std::fs::read(&message).unwrap(), b"complete payload");
        assert_eq!(std::fs::read(&observed).unwrap(), b"ok");
    }

    #[test]
    fn test_default_config() {
        let dc = DaemonConfig::default();
        assert_eq!(dc.display_name.as_deref(), Some("Anonymous Peer"));
        assert!(!dc.announce_at_start);
        assert_eq!(dc.announce_interval, None);
        assert_eq!(dc.stamp_cost, Some(12));
        assert!(!dc.propagation_enabled);
        assert_eq!(dc.propagation_stamp_cost, 16);
        assert_eq!(dc.propagation_stamp_flex, 3);
        assert_eq!(dc.peering_cost, 18);
        assert_eq!(dc.max_peering_cost, 26);
        assert_eq!(dc.max_peers, 20);
        assert!(dc.autopeer);
        assert_eq!(dc.autopeer_maxdepth, AUTOPEER_MAXDEPTH);
        assert!(dc.sequential_pn_stamp_validation);
        assert!(dc.static_peers_bypass_sequential);
        assert_eq!(dc.max_inbound_syncs, PN_DEFAULT_MAX_INBOUND_SYNCS);
        assert_eq!(
            dc.to_inbound_admission_config(),
            PnInboundAdmissionConfig::default()
        );
        assert_eq!(dc.propagation_limit_kb, 256);
        assert_eq!(dc.sync_limit_kb, 10_240);
        assert!(!dc.node_announce_at_start);
        assert_eq!(dc.node_announce_interval, None);
        assert_eq!(dc.message_storage_limit, Some(500_000_000));
        assert_eq!(dc.delivery_transfer_max_accepted_size, 1000.0);
        assert!(!dc.from_static_only);
    }

    #[test]
    fn python_normalized_config_matches_omitted_defaults() {
        let config = rns_runtime::config::Config::parse("").unwrap();
        let py = PythonLxmdConfig::from_config(&config);

        assert_eq!(py.display_name, "Anonymous Peer");
        assert!(!py.peer_announce_at_start);
        assert_eq!(py.peer_announce_interval, None);
        assert_eq!(py.peer_stamp_cost, 12);
        assert_eq!(py.delivery_transfer_max_accepted_size, 1000.0);
        assert_eq!(py.on_inbound, None);
        assert!(!py.enable_propagation_node);
        assert_eq!(py.node_name, None);
        assert!(!py.auth_required);
        assert!(!py.node_announce_at_start);
        assert!(py.autopeer);
        assert_eq!(py.autopeer_maxdepth, None);
        assert!(py.sequential_pn_stamp_validation);
        assert!(py.static_peers_bypass_sequential);
        assert_eq!(py.max_inbound_syncs, PN_DEFAULT_MAX_INBOUND_SYNCS as i64);
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
sequential_pn_stamp_validation = no
static_peers_bypass_sequential = no
max_inbound_syncs = 0

[lxmf]
announce_interval = 3
stamp_cost = -9
delivery_transfer_max_accepted_size = 0.1

[logging]
loglevel = 6
"#;
        let config = rns_runtime::config::Config::parse(input).unwrap();
        let py = PythonLxmdConfig::from_config(&config);

        assert_eq!(py.peer_announce_interval, Some(180));
        assert_eq!(py.node_announce_interval, Some(120));
        assert_eq!(py.peer_stamp_cost, 1);
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
        assert!(!py.sequential_pn_stamp_validation);
        assert!(!py.static_peers_bypass_sequential);
        assert_eq!(py.max_inbound_syncs, PN_MIN_MAX_INBOUND_SYNCS as i64);
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
        assert_eq!(rc.delivery_limit_kb, 1000.0);
        assert_eq!(RouterConfig::default().delivery_limit_kb, 1000.0);
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
sequential_pn_stamp_validation = no
static_peers_bypass_sequential = no
max_inbound_syncs = 5
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
        assert_eq!(dc.delivery_transfer_max_accepted_size, 0.38);
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
        assert!(!dc.sequential_pn_stamp_validation);
        assert!(!dc.static_peers_bypass_sequential);
        assert_eq!(dc.max_inbound_syncs, 5);
        assert_eq!(
            dc.to_inbound_admission_config(),
            PnInboundAdmissionConfig {
                sequential_validation: false,
                static_sequential: true,
                max_inbound_syncs: 5,
                from_static_only: true,
            }
        );
        assert_eq!(dc.static_peers, ["00112233445566778899aabbccddeeff"]);
        assert_eq!(
            dc.prioritise_destinations,
            ["0102030405060708090a0b0c0d0e0f10"]
        );
        assert_eq!(dc.control_allowed, ["11111111111111111111111111111111"]);
        assert!(dc.from_static_only);
    }

    #[test]
    fn delivery_stamp_cost_matches_python_floor_and_destination_range() {
        for (configured, normalized, expected) in [
            (-7, 1, Some(1)),
            (0, 1, Some(1)),
            (254, 254, Some(254)),
            (255, 255, None),
            (256, 256, None),
            (1000, 1000, None),
        ] {
            let input = format!("[lxmf]\nstamp_cost = {configured}\n");
            let config = rns_runtime::config::Config::parse(&input).unwrap();
            let py = PythonLxmdConfig::from_config(&config);
            let dc = DaemonConfig::from_config(&config);

            assert_eq!(py.peer_stamp_cost, normalized, "configured {configured}");
            assert_eq!(dc.stamp_cost, expected, "configured {configured}");
        }
    }

    #[test]
    fn fractional_delivery_limit_survives_daemon_and_router_config() {
        let config = rns_runtime::config::Config::parse(
            "[lxmf]\ndelivery_transfer_max_accepted_size = 0.38\n",
        )
        .unwrap();
        let dc = DaemonConfig::from_config(&config);

        assert_eq!(dc.delivery_transfer_max_accepted_size, 0.38);
        assert_eq!(dc.to_router_config().delivery_limit_kb, 0.38);
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
