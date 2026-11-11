//! LXMF daemon configuration and inbound-hook helpers.
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
/// Values retain Python's configuration units before conversion into
/// [`DaemonConfig`], including decimal KB/MB and announce intervals in seconds.
#[derive(Debug, Clone, PartialEq)]
pub struct PythonLxmdConfig {
    pub display_name: String,
    pub peer_announce_at_start: bool,
    pub peer_announce_interval: Option<i64>,
    pub peer_stamp_cost: f64,
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
    pub propagation_stamp_cost_target: f64,
    pub propagation_stamp_cost_flexibility: f64,
    pub peering_cost: f64,
    pub remote_peering_cost_max: f64,
    /// Seconds, floored at `PN_STAMP_THROTTLE` as Python does.
    pub propagation_stamp_throttle: f64,
    pub prioritised_lxmf_destinations: Vec<String>,
    pub control_allowed_identities: Vec<String>,
    pub static_peers: Vec<String>,
    pub max_peers: Option<i64>,
    pub from_static_only: bool,
    pub target_loglevel: Option<i64>,
}

/// A stamp-cost key lxmd cannot run with.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DaemonConfigError {
    /// Python `as_float` raises and lxmd exits.
    #[error("[{section}] {key} = {value:?} is not a number")]
    NotANumber {
        section: &'static str,
        key: &'static str,
        value: String,
    },
    /// Python `as_int` raises and lxmd exits.
    #[error("[{section}] {key} = {value:?} is not an integer")]
    NotAnInteger {
        section: &'static str,
        key: &'static str,
        value: String,
    },
    /// Python `as_bool` raises and lxmd exits.
    #[error("[{section}] {key} = {value:?} is not a boolean")]
    NotABoolean {
        section: &'static str,
        key: &'static str,
        value: String,
    },
    /// Python `bytes.fromhex` or the `LXMRouter` length check raises.
    #[error("[propagation] static_peers entry {0:?} is not a 16-byte hexadecimal destination hash")]
    InvalidStaticPeer(String),
    /// `LXMRouter` raises on a negative peer limit.
    #[error("[propagation] max_peers = {0} must not be negative")]
    NegativeMaxPeers(i64),
    /// Stamps at this cost cannot be generated (`STAMP_COST_CAP`).
    #[error("[{section}] {key} = {value} must be a finite cost below 100")]
    CostOutOfRange {
        section: &'static str,
        key: &'static str,
        value: f64,
    },
}

/// A cost key read as Python `as_float`; `None` when absent.
fn get_cost(
    section: Option<&ConfigSection>,
    section_name: &'static str,
    key: &'static str,
) -> Result<Option<f64>, DaemonConfigError> {
    let Some(raw) = section.and_then(|sec| sec.get(key)) else {
        return Ok(None);
    };
    section
        .and_then(|sec| sec.get_float(key))
        .map(Some)
        .ok_or_else(|| DaemonConfigError::NotANumber {
            section: section_name,
            key,
            value: raw.to_string(),
        })
}

/// Costs a stamp is generated at must be finite and below `STAMP_COST_CAP`.
fn generated_cost(
    value: f64,
    section: &'static str,
    key: &'static str,
) -> Result<f64, DaemonConfigError> {
    if value.is_finite() && value < lxmf_core::stamper::STAMP_COST_CAP {
        Ok(value)
    } else {
        Err(DaemonConfigError::CostOutOfRange {
            section,
            key,
            value,
        })
    }
}

fn floored_cost(
    section: Option<&ConfigSection>,
    section_name: &'static str,
    key: &'static str,
    floor: f64,
    default: f64,
) -> Result<f64, DaemonConfigError> {
    Ok(get_cost(section, section_name, key)?.map_or(default, |v| v.max(floor)))
}

impl PythonLxmdConfig {
    /// Python `lxmd.apply_config`. Stamp-cost keys use `as_float` with its
    /// floors and defaults; an unparsable cost, or one a stamp cannot be
    /// generated at, is an error.
    pub fn from_config(config: &Config) -> Result<Self, DaemonConfigError> {
        let lxmf = config.section("lxmf");
        let propagation = config.section("propagation");
        let logging = config.section("logging");

        // The legacy key is still parsed (and can raise) before the new one overwrites it.
        get_cost(
            propagation,
            "propagation",
            "propagation_transfer_max_accepted_size",
        )?;
        let propagation_transfer_max_accepted_size = get_float_or_floor(
            propagation,
            "propagation",
            "propagation_message_max_accepted_size",
            256.0,
            0.38,
        )?;

        let peer_stamp_cost = generated_cost(
            floored_cost(lxmf, "lxmf", "stamp_cost", 1.0, 12.0)?,
            "lxmf",
            "stamp_cost",
        )?;
        let propagation_stamp_cost_target = generated_cost(
            floored_cost(
                propagation,
                "propagation",
                "propagation_stamp_cost_target",
                PROPAGATION_COST_MIN,
                PROPAGATION_COST,
            )?,
            "propagation",
            "propagation_stamp_cost_target",
        )?;
        let peering_cost = generated_cost(
            floored_cost(
                propagation,
                "propagation",
                "peering_cost",
                0.0,
                PEERING_COST,
            )?,
            "propagation",
            "peering_cost",
        )?;
        let propagation_stamp_cost_flexibility = floored_cost(
            propagation,
            "propagation",
            "propagation_stamp_cost_flexibility",
            0.0,
            PROPAGATION_COST_FLEX,
        )?;
        let remote_peering_cost_max = floored_cost(
            propagation,
            "propagation",
            "remote_peering_cost_max",
            0.0,
            MAX_PEERING_COST,
        )?;

        let propagation_stamp_throttle =
            get_cost(propagation, "propagation", "propagation_stamp_throttle")?
                .map_or(PN_STAMP_THROTTLE as f64, |minutes| {
                    (minutes * 60.0).max(PN_STAMP_THROTTLE as f64)
                });
        let static_peers = get_list(propagation, "static_peers");
        for peer in &static_peers {
            parse_static_peer(peer)?;
        }
        let max_peers = get_int(propagation, "propagation", "max_peers")?;
        if let Some(value) = max_peers.filter(|value| *value < 0) {
            return Err(DaemonConfigError::NegativeMaxPeers(value));
        }

        Ok(Self {
            display_name: lxmf
                .and_then(|sec| sec.get("display_name"))
                .unwrap_or("Anonymous Peer")
                .to_string(),
            peer_announce_at_start: get_bool_or(lxmf, "lxmf", "announce_at_start", false)?,
            peer_announce_interval: get_int(lxmf, "lxmf", "announce_interval")?
                .map(|v| v.saturating_mul(60)),
            peer_stamp_cost,
            delivery_transfer_max_accepted_size: get_float_or_floor(
                lxmf,
                "lxmf",
                "delivery_transfer_max_accepted_size",
                1.0,
                0.38,
            )?,
            on_inbound: lxmf
                .and_then(|sec| sec.get("on_inbound"))
                .map(ToString::to_string),
            enable_propagation_node: get_bool_or(propagation, "propagation", "enable_node", false)?,
            node_name: propagation
                .and_then(|sec| sec.get("node_name"))
                .map(ToString::to_string),
            auth_required: get_bool_or(propagation, "propagation", "auth_required", false)?,
            node_announce_at_start: get_bool_or(
                propagation,
                "propagation",
                "announce_at_start",
                false,
            )?,
            autopeer: get_bool_or(propagation, "propagation", "autopeer", true)?,
            autopeer_maxdepth: get_int(propagation, "propagation", "autopeer_maxdepth")?,
            sequential_pn_stamp_validation: get_bool_or(
                propagation,
                "propagation",
                "sequential_pn_stamp_validation",
                true,
            )?,
            static_peers_bypass_sequential: get_bool_or(
                propagation,
                "propagation",
                "static_peers_bypass_sequential",
                true,
            )?,
            max_inbound_syncs: get_int(propagation, "propagation", "max_inbound_syncs")?
                .map(|value| value.max(PN_MIN_MAX_INBOUND_SYNCS as i64))
                .unwrap_or(PN_DEFAULT_MAX_INBOUND_SYNCS as i64),
            node_announce_interval: get_int(propagation, "propagation", "announce_interval")?
                .map(|v| v.saturating_mul(60)),
            message_storage_limit: get_float_or_floor(
                propagation,
                "propagation",
                "message_storage_limit",
                500.0,
                0.005,
            )?,
            propagation_transfer_max_accepted_size,
            propagation_sync_max_accepted_size: get_float_or_floor(
                propagation,
                "propagation",
                "propagation_sync_max_accepted_size",
                256.0 * 40.0,
                0.38,
            )?,
            propagation_stamp_cost_target,
            propagation_stamp_cost_flexibility,
            peering_cost,
            remote_peering_cost_max,
            propagation_stamp_throttle,
            prioritised_lxmf_destinations: get_list(propagation, "prioritise_destinations"),
            control_allowed_identities: get_list(propagation, "control_allowed"),
            static_peers,
            max_peers,
            from_static_only: get_bool_or(propagation, "propagation", "from_static_only", false)?,
            target_loglevel: get_int(logging, "logging", "loglevel")?,
        })
    }
}

/// A key that is present but not a scalar string fails every ConfigObj `as_*`.
fn raw_value(section: Option<&ConfigSection>, key: &str) -> Option<String> {
    let sec = section?;
    sec.has(key)
        .then(|| sec.get(key).map(ToString::to_string).unwrap_or_default())
}

/// ConfigObj `as_bool`; `None` when absent.
fn get_bool(
    section: Option<&ConfigSection>,
    section_name: &'static str,
    key: &'static str,
) -> Result<Option<bool>, DaemonConfigError> {
    let Some(raw) = raw_value(section, key) else {
        return Ok(None);
    };
    section
        .and_then(|sec| sec.get_bool(key))
        .map(Some)
        .ok_or(DaemonConfigError::NotABoolean {
            section: section_name,
            key,
            value: raw,
        })
}

fn get_bool_or(
    section: Option<&ConfigSection>,
    section_name: &'static str,
    key: &'static str,
    default: bool,
) -> Result<bool, DaemonConfigError> {
    Ok(get_bool(section, section_name, key)?.unwrap_or(default))
}

/// ConfigObj `as_int`, which is Python `int()`; `None` when absent.
fn get_int(
    section: Option<&ConfigSection>,
    section_name: &'static str,
    key: &'static str,
) -> Result<Option<i64>, DaemonConfigError> {
    let Some(raw) = raw_value(section, key) else {
        return Ok(None);
    };
    parse_python_int(&raw)
        .map(Some)
        .ok_or(DaemonConfigError::NotAnInteger {
            section: section_name,
            key,
            value: raw,
        })
}

/// Python `int(str)`: optional sign, decimal digits, single underscores between digits.
fn parse_python_int(raw: &str) -> Option<i64> {
    let s = raw.trim();
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    let bytes = digits.as_bytes();
    let well_formed = !bytes.is_empty()
        && bytes.iter().enumerate().all(|(i, &b)| {
            b.is_ascii_digit()
                || (b == b'_'
                    && i > 0
                    && bytes[i - 1].is_ascii_digit()
                    && bytes.get(i + 1).is_some_and(u8::is_ascii_digit))
        });
    if !well_formed {
        return None;
    }
    s.replace('_', "").parse().ok()
}

fn get_float_or_floor(
    section: Option<&ConfigSection>,
    section_name: &'static str,
    key: &'static str,
    default: f64,
    floor: f64,
) -> Result<f64, DaemonConfigError> {
    Ok(get_cost(section, section_name, key)?.map_or(default, |value| value.max(floor)))
}

fn get_list(section: Option<&ConfigSection>, key: &str) -> Vec<String> {
    section
        .and_then(|sec| sec.get_list(key))
        .unwrap_or_default()
}

/// Python `bytes.fromhex` followed by the `LXMRouter` static peer length check.
fn parse_static_peer(raw: &str) -> Result<[u8; 16], DaemonConfigError> {
    let invalid = || DaemonConfigError::InvalidStaticPeer(raw.to_string());
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(16);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let pair = bytes.get(i..i + 2).ok_or_else(invalid)?;
        if !pair.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid());
        }
        let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
        out.push(u8::from_str_radix(pair, 16).map_err(|_| invalid())?);
        i += 2;
    }
    out.try_into().map_err(|_| invalid())
}

/// Daemon configuration parsed from an INI config file.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub display_name: Option<String>,
    pub node_name: Option<String>,
    pub announce_at_start: bool,
    pub announce_interval: Option<u64>,
    pub stamp_cost: Option<f64>,
    pub propagation_enabled: bool,
    pub outbound_propagation_node: Option<String>,
    pub propagation_stamp_cost: f64,
    pub propagation_stamp_flex: f64,
    pub peering_cost: f64,
    pub max_peering_cost: f64,
    pub max_peers: usize,
    pub autopeer: bool,
    pub autopeer_maxdepth: usize,
    pub sequential_pn_stamp_validation: bool,
    pub static_peers_bypass_sequential: bool,
    pub max_inbound_syncs: usize,
    pub propagation_limit_kb: f64,
    pub sync_limit_kb: f64,
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
    /// Invalid-stamp peer throttle in seconds (`propagation_stamp_throttle`).
    pub pn_stamp_throttle: f64,
    /// Max accepted inbound delivery transfer size in decimal KB. Python reference:
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
            stamp_cost: Some(12.0),
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
            propagation_limit_kb: PROPAGATION_LIMIT as f64,
            sync_limit_kb: SYNC_LIMIT as f64,
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
            pn_stamp_throttle: PN_STAMP_THROTTLE as f64,
            // Current Python LXMF 1.1.0's standalone lxmd defaults
            // direct-delivery Resource admission to 1 decimal KB when the
            // setting is omitted. LXMRouter's library default is separate.
            delivery_transfer_max_accepted_size: 1.0,
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
                pn_stamp_throttle: self.pn_stamp_throttle,
                ..Default::default()
            },
        }
    }

    /// Python `max(0, propagation_stamp_cost - propagation_stamp_cost_flexibility)`.
    pub fn min_accepted_stamp_cost(&self) -> f64 {
        (self.propagation_stamp_cost - self.propagation_stamp_flex).max(0.0)
    }

    /// Build the long-lived inbound propagation admission policy.
    pub fn to_inbound_admission_config(&self) -> PnInboundAdmissionConfig {
        PnInboundAdmissionConfig {
            sequential_validation: self.sequential_pn_stamp_validation,
            static_sequential: !self.static_peers_bypass_sequential,
            max_inbound_syncs: self.max_inbound_syncs,
            from_static_only: self.from_static_only,
            invalid_stamp_throttle: std::time::Duration::try_from_secs_f64(self.pn_stamp_throttle)
                .unwrap_or(std::time::Duration::MAX),
        }
    }

    /// Parse from `[lxmf]`, `[propagation]`, and `[control]` sections.
    pub fn from_config(config: &Config) -> Result<Self, DaemonConfigError> {
        let py = PythonLxmdConfig::from_config(config)?;
        let mut dc = DaemonConfig {
            display_name: Some(py.display_name),
            node_name: py.node_name,
            announce_at_start: py.peer_announce_at_start,
            announce_interval: seconds_to_u64(py.peer_announce_interval),
            stamp_cost: Some(py.peer_stamp_cost),
            propagation_enabled: py.enable_propagation_node,
            propagation_stamp_cost: py.propagation_stamp_cost_target,
            propagation_stamp_flex: py.propagation_stamp_cost_flexibility,
            peering_cost: py.peering_cost,
            max_peering_cost: py.remote_peering_cost_max,
            max_peers: py
                .max_peers
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(MAX_PEERS),
            // Python compares hops against a negative depth and never autopeers.
            autopeer: py.autopeer && py.autopeer_maxdepth.is_none_or(|depth| depth >= 0),
            autopeer_maxdepth: py
                .autopeer_maxdepth
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(AUTOPEER_MAXDEPTH),
            sequential_pn_stamp_validation: py.sequential_pn_stamp_validation,
            static_peers_bypass_sequential: py.static_peers_bypass_sequential,
            max_inbound_syncs: usize::try_from(py.max_inbound_syncs).unwrap_or(usize::MAX),
            propagation_limit_kb: py.propagation_transfer_max_accepted_size,
            sync_limit_kb: py.propagation_sync_max_accepted_size,
            on_inbound_command: py.on_inbound,
            node_announce_at_start: py.node_announce_at_start,
            node_announce_interval: seconds_to_u64(py.node_announce_interval),
            auth_required: py.auth_required,
            control_allowed: py.control_allowed_identities,
            static_peers: py.static_peers,
            prioritise_destinations: py.prioritised_lxmf_destinations,
            message_storage_limit: megabytes_to_bytes(py.message_storage_limit),
            from_static_only: py.from_static_only,
            pn_stamp_throttle: py.propagation_stamp_throttle,
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
            if !sec.has("propagation_stamp_cost_target")
                && let Some(cost) = get_cost(Some(sec), "propagation", "propagation_stamp_cost")?
            {
                dc.propagation_stamp_cost = generated_cost(
                    cost.max(PROPAGATION_COST_MIN),
                    "propagation",
                    "propagation_stamp_cost",
                )?;
            }
            if get_float(Some(sec), "propagation_message_max_accepted_size").is_none()
                && get_float(Some(sec), "propagation_transfer_max_accepted_size").is_none()
                && let Some(limit) = sec.get_uint("propagation_limit")
            {
                dc.propagation_limit_kb = limit as f64;
            }
            dc.enforce_stamps = sec.get_bool_or("enforce_stamps", false);
        }

        // LXMRouter raises the per-sync limit to the per-transfer limit.
        dc.sync_limit_kb = dc.sync_limit_kb.max(dc.propagation_limit_kb);

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

        Ok(dc)
    }
}

fn get_float(section: Option<&ConfigSection>, key: &str) -> Option<f64> {
    section.and_then(|sec| sec.get_float(key))
}

fn seconds_to_u64(value: Option<i64>) -> Option<u64> {
    value.map(|seconds| seconds.max(0) as u64)
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

/// Execute an on_inbound hook as Python lxmd does: the command and the quoted
/// message path are split like `shlex.split(command + ' "' + path + '"')`, the
/// output is discarded and the exit status is ignored.
pub fn execute_on_inbound(command: &str, message_path: &str) -> std::io::Result<()> {
    execute_on_inbound_with_event(command, message_path, "")
}

/// Execute an inbound hook with `event_id` in the `LXMF_EVENT_ID` environment
/// variable when the identifier is nonempty. Durable propagation outbox events
/// may replay after a crash; the hook can use the identifier to deduplicate them.
/// Only a failure to run the command is an error.
pub fn execute_on_inbound_with_event(
    command: &str,
    message_path: &str,
    event_id: &str,
) -> std::io::Result<()> {
    use std::process::{Command, Stdio};

    // An empty command is falsy in Python and runs nothing.
    if command.is_empty() {
        return Ok(());
    }
    let parts = split_command_line(&format!("{command} \"{message_path}\""))?;
    let mut cmd = Command::new(&parts[0]);
    cmd.args(&parts[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !event_id.is_empty() {
        cmd.env("LXMF_EVENT_ID", event_id);
    }
    cmd.status()?;
    Ok(())
}

/// Split a command line as Python's POSIX `shlex.split()` does, without
/// invoking a shell.
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
    let mut escaped_in_double = false;

    for ch in command.chars() {
        // Inside double quotes a backslash escapes only `"` and `\`.
        if escaped_in_double {
            if ch != '"' && ch != '\\' {
                current.push('\\');
            }
            current.push(ch);
            escaped_in_double = false;
            continue;
        }
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
                    escaped_in_double = true;
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
                ' ' | '\t' | '\r' | '\n' => {
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

    if escaped || escaped_in_double || quote != Quote::None {
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

/// Persist a received message, then invoke the configured hook after the write
/// succeeds. This function blocks; async callers must run it on a blocking
/// worker. A hook error is returned after the message has already been saved.
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
        assert_eq!(dc.stamp_cost, Some(12.0));
        assert!(!dc.propagation_enabled);
        assert_eq!(dc.propagation_stamp_cost, 16.0);
        assert_eq!(dc.propagation_stamp_flex, 3.0);
        assert_eq!(dc.peering_cost, 18.0);
        assert_eq!(dc.max_peering_cost, 26.0);
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
        assert_eq!(dc.propagation_limit_kb, 256.0);
        assert_eq!(dc.sync_limit_kb, 10_240.0);
        assert!(!dc.node_announce_at_start);
        assert_eq!(dc.node_announce_interval, None);
        assert_eq!(dc.message_storage_limit, Some(500_000_000));
        assert_eq!(dc.delivery_transfer_max_accepted_size, 1.0);
        assert!(!dc.from_static_only);
    }

    #[test]
    fn python_normalized_config_matches_omitted_defaults() {
        let config = rns_runtime::config::Config::parse("").unwrap();
        let py = PythonLxmdConfig::from_config(&config).unwrap();

        assert_eq!(py.display_name, "Anonymous Peer");
        assert!(!py.peer_announce_at_start);
        assert_eq!(py.peer_announce_interval, None);
        assert_eq!(py.peer_stamp_cost, 12.0);
        assert_eq!(py.delivery_transfer_max_accepted_size, 1.0);
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
        assert_eq!(py.propagation_stamp_cost_target, 16.0);
        assert_eq!(py.propagation_stamp_cost_flexibility, 3.0);
        assert_eq!(py.peering_cost, 18.0);
        assert_eq!(py.remote_peering_cost_max, 26.0);
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
        let py = PythonLxmdConfig::from_config(&config).unwrap();

        assert_eq!(py.peer_announce_interval, Some(180));
        assert_eq!(py.node_announce_interval, Some(120));
        assert_eq!(py.peer_stamp_cost, 1.0);
        assert_eq!(py.delivery_transfer_max_accepted_size, 0.38);
        assert_eq!(py.message_storage_limit, 0.005);
        assert_eq!(py.propagation_transfer_max_accepted_size, 0.38);
        assert_eq!(py.propagation_sync_max_accepted_size, 0.38);
        assert_eq!(py.propagation_stamp_cost_target, 13.0);
        assert_eq!(py.propagation_stamp_cost_flexibility, 0.0);
        assert_eq!(py.peering_cost, 0.0);
        assert_eq!(py.remote_peering_cost_max, 0.0);
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
        let py = PythonLxmdConfig::from_config(&config).unwrap();

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
        let dc = DaemonConfig::from_config(&config).unwrap();

        assert_eq!(
            dc.propagation_limit_kb, 256.0,
            "DaemonConfig should match Python 0.9.6 handling of legacy propagation_transfer_max_accepted_size"
        );
    }

    #[test]
    fn test_to_router_config() {
        let dc = DaemonConfig::default();
        let rc = dc.to_router_config();
        assert!(!rc.propagation_enabled);
        assert_eq!(rc.max_peers, 20);
        assert_eq!(rc.delivery_limit_kb, 1.0);
        assert_eq!(RouterConfig::default().delivery_limit_kb, 1000.0);
        assert_eq!(rc.propagation_limit_kb, 256.0);
        assert_eq!(rc.sync_limit_kb, 10_240.0);
        assert_eq!(rc.propagation_stamp_cost, 16.0);
        assert_eq!(rc.propagation_stamp_flex, 3.0);
        assert_eq!(rc.ext.autopeer_maxdepth, AUTOPEER_MAXDEPTH);
        assert_eq!(rc.ext.peering_cost, 18.0);
        assert_eq!(rc.ext.max_peering_cost, 26.0);
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
        let dc = DaemonConfig::from_config(&config).unwrap();
        assert_eq!(dc.display_name.as_deref(), Some("TestNode"));
        assert!(dc.announce_at_start);
        assert_eq!(dc.announce_interval, Some(180));
        assert_eq!(dc.delivery_transfer_max_accepted_size, 0.38);
        assert_eq!(dc.stamp_cost, Some(8.0));
        assert!(dc.propagation_enabled);
        assert_eq!(dc.node_name.as_deref(), Some("PropNode"));
        assert_eq!(
            dc.outbound_propagation_node.as_deref(),
            Some("aabbccddeeff00112233445566778899")
        );
        assert!(dc.node_announce_at_start);
        assert_eq!(dc.node_announce_interval, Some(120));
        assert_eq!(dc.message_storage_limit, Some(5_000));
        assert_eq!(dc.propagation_limit_kb, 0.38);
        assert_eq!(dc.sync_limit_kb, 0.38);
        assert_eq!(dc.propagation_stamp_cost, 13.0);
        assert_eq!(dc.propagation_stamp_flex, 0.0);
        assert_eq!(dc.peering_cost, 0.0);
        assert_eq!(dc.max_peering_cost, 0.0);
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
                invalid_stamp_throttle: std::time::Duration::from_secs(300),
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
    fn delivery_stamp_cost_matches_python_floor_and_cap() {
        for (configured, expected) in [
            ("-7", 1.0),
            ("0", 1.0),
            ("0.5", 1.0),
            ("12.5", 12.5),
            ("99.5", 99.5),
        ] {
            let input = format!("[lxmf]\nstamp_cost = {configured}\n");
            let config = rns_runtime::config::Config::parse(&input).unwrap();
            let py = PythonLxmdConfig::from_config(&config).unwrap();
            let dc = DaemonConfig::from_config(&config).unwrap();

            assert_eq!(py.peer_stamp_cost, expected, "configured {configured}");
            assert_eq!(dc.stamp_cost, Some(expected), "configured {configured}");
        }
    }

    #[test]
    fn stamp_costs_of_100_or_more_are_refused_naming_the_key() {
        for (section, key) in [
            ("lxmf", "stamp_cost"),
            ("propagation", "propagation_stamp_cost_target"),
            ("propagation", "peering_cost"),
        ] {
            for value in ["100", "150", "254", "1000"] {
                let input = format!("[{section}]\n{key} = {value}\n");
                let config = rns_runtime::config::Config::parse(&input).unwrap();
                let error = DaemonConfig::from_config(&config).unwrap_err();
                assert!(error.to_string().contains(key), "{error}");
            }
        }
    }

    #[test]
    fn unparsable_stamp_cost_is_an_error() {
        for (section, key) in [
            ("lxmf", "stamp_cost"),
            ("propagation", "propagation_stamp_cost_target"),
            ("propagation", "propagation_stamp_cost_flexibility"),
            ("propagation", "peering_cost"),
            ("propagation", "remote_peering_cost_max"),
        ] {
            let input = format!("[{section}]\n{key} = abc\n");
            let config = rns_runtime::config::Config::parse(&input).unwrap();
            match DaemonConfig::from_config(&config).unwrap_err() {
                DaemonConfigError::NotANumber {
                    section: s,
                    key: k,
                    value,
                } => assert_eq!((s, k, value.as_str()), (section, key, "abc")),
                other => panic!("{other}"),
            }
        }
    }

    #[test]
    fn fractional_delivery_limit_survives_daemon_and_router_config() {
        let config = rns_runtime::config::Config::parse(
            "[lxmf]\ndelivery_transfer_max_accepted_size = 0.38\n",
        )
        .unwrap();
        let dc = DaemonConfig::from_config(&config).unwrap();

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
        let dc = DaemonConfig::from_config(&config).unwrap();

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
        let dc = DaemonConfig::from_config(&config).unwrap();

        assert_eq!(dc.propagation_stamp_cost, 19.0);
        assert_eq!(dc.to_router_config().propagation_stamp_cost, 19.0);
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
        let dc = DaemonConfig::from_config(&config).unwrap();

        assert!(dc.enforce_stamps);
    }
}
