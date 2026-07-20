//! Pure `lxmd` runtime helpers extracted from the binary.
//!
//! This module keeps daemon path handling and other pure helpers out of the
//! binary so CLI behavior can be tested directly.

use std::path::{Path, PathBuf};

use lxmf_core::router::RouterStats;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LxmdPaths {
    pub config_dir: PathBuf,
    pub identity_path: PathBuf,
    pub storage_dir: PathBuf,
    pub messages_dir: PathBuf,
    pub lxmf_storage_dir: PathBuf,
    pub router_state_dir: PathBuf,
    pub propagation_store_dir: PathBuf,
    pub ratchets_dir: PathBuf,
    pub ratchet_ring_path: PathBuf,
    pub ratchet_control_path: PathBuf,
    pub received_ratchets_dir: PathBuf,
    pub known_identities_path: PathBuf,
    pub legacy_lxmf_dir: PathBuf,
    pub legacy_identity_path: PathBuf,
    pub legacy_messages_dir: PathBuf,
    pub legacy_ratchets_dir: PathBuf,
    pub legacy_propagation_store_dir: PathBuf,
}

impl LxmdPaths {
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        let config_dir = config_dir.into();
        let identity_path = config_dir.join("identity");
        let storage_dir = config_dir.join("storage");
        let messages_dir = storage_dir.join("messages");
        let lxmf_storage_dir = storage_dir.join("lxmf");
        let router_state_dir = lxmf_storage_dir.clone();
        let propagation_store_dir = lxmf_storage_dir.join("messagestore");
        let ratchets_dir = lxmf_storage_dir.join("ratchets");
        let ratchet_ring_path = ratchets_dir.join("ring");
        let ratchet_control_path = ratchets_dir.join("ring.control");
        let received_ratchets_dir = ratchets_dir.join("received");
        let known_identities_path = ratchets_dir.join("known_identities");

        let legacy_lxmf_dir = config_dir.join(".lxmf");
        let legacy_identity_path = legacy_lxmf_dir.join("identity");
        let legacy_messages_dir = legacy_lxmf_dir.join("messages");
        let legacy_ratchets_dir = legacy_lxmf_dir.join("ratchets");
        let legacy_propagation_store_dir = legacy_lxmf_dir.join("propagation");

        Self {
            config_dir,
            identity_path,
            storage_dir,
            messages_dir,
            lxmf_storage_dir,
            router_state_dir,
            propagation_store_dir,
            ratchets_dir,
            ratchet_ring_path,
            ratchet_control_path,
            received_ratchets_dir,
            known_identities_path,
            legacy_lxmf_dir,
            legacy_identity_path,
            legacy_messages_dir,
            legacy_ratchets_dir,
            legacy_propagation_store_dir,
        }
    }

    pub fn preferred_identity_path(&self) -> &Path {
        if self.identity_path.exists() || !self.legacy_identity_path.exists() {
            &self.identity_path
        } else {
            &self.legacy_identity_path
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalStatusView {
    pub lxmf_dest_hash: [u8; 16],
    pub propagation_enabled: bool,
    pub peers: usize,
    pub propagation_entries: usize,
    pub propagation_size: usize,
    pub pending_outbound: usize,
    pub pending_deferred_stamps: usize,
    pub stamp_costs_cached: usize,
}

impl LocalStatusView {
    pub fn from_router_stats(
        lxmf_dest_hash: [u8; 16],
        propagation_enabled: bool,
        stats: &RouterStats,
    ) -> Self {
        Self {
            lxmf_dest_hash,
            propagation_enabled,
            peers: stats.peers,
            propagation_entries: stats.propagation_entries,
            propagation_size: stats.propagation_size,
            pending_outbound: stats.pending_outbound,
            pending_deferred_stamps: stats.pending_deferred_stamps,
            stamp_costs_cached: stats.stamp_costs_cached,
        }
    }
}

pub fn format_local_status(status: &LocalStatusView) -> String {
    format!(
        "LXMF destination: {}\n\
         Propagation node: {}\n\
         Peers: {}\n\
         Propagation messages: {}\n\
         Propagation storage bytes: {}\n\
         Pending outbound: {}\n\
         Pending deferred stamps: {}\n\
         Cached stamp costs: {}\n",
        hex::encode(status.lxmf_dest_hash),
        if status.propagation_enabled {
            "enabled"
        } else {
            "disabled"
        },
        status.peers,
        status.propagation_entries,
        status.propagation_size,
        status.pending_outbound,
        status.pending_deferred_stamps,
        status.stamp_costs_cached,
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalPeerView {
    pub hash: [u8; 16],
    pub state: u8,
    pub alive: bool,
    pub unhandled: u32,
    pub last_heard: f64,
}

pub fn format_local_peers(peers: &[LocalPeerView]) -> String {
    if peers.is_empty() {
        return "No peers\n".to_string();
    }

    let mut out = String::new();
    for peer in peers {
        out.push_str(&format!(
            "{} state={} alive={} unhandled={} last_heard={:.0}\n",
            hex::encode(peer.hash),
            peer.state,
            peer.alive,
            peer.unhandled,
            peer.last_heard,
        ));
    }
    out
}

pub fn delivery_announce_app_data(display_name: Option<&str>, stamp_cost: Option<u8>) -> Vec<u8> {
    lxmf_core::handlers::get_announce_app_data(display_name, stamp_cost)
}

pub fn propagation_announce_app_data(
    data: &lxmf_core::handlers::PropagationNodeAnnounceData,
) -> Vec<u8> {
    lxmf_core::handlers::get_propagation_node_app_data(data)
}

pub fn resolve_config_dirs(config: Option<&str>, rnsconfig: Option<&str>) -> (PathBuf, PathBuf) {
    let config_dir = match config {
        Some(dir) => PathBuf::from(dir),
        None => default_lxmd_config_dir(),
    };
    let rns_config_dir = match rnsconfig {
        Some(dir) => rns_runtime::platform::resolve_config_dir(Some(dir)),
        None => rns_runtime::platform::resolve_config_dir(None),
    };
    (config_dir, rns_config_dir)
}

fn default_lxmd_config_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        return std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("rsLXMF"))
            .unwrap_or_else(|| PathBuf::from(".rsLXMF"));
    }

    if cfg!(target_os = "android") {
        return PathBuf::from("/data/local/tmp/.rsLXMF");
    }

    let etc = PathBuf::from("/etc/rsLXMF");
    if etc.join("config").is_file() {
        return etc;
    }

    if let Ok(home) = std::env::var("HOME") {
        let xdg = PathBuf::from(&home).join(".config/rsLXMF");
        if xdg.join("config").is_file() {
            return xdg;
        }
        PathBuf::from(home).join(".rsLXMF")
    } else {
        PathBuf::from(".rsLXMF")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPreflight {
    pub peer_hash: Option<[u8; 16]>,
    pub remote_hash: Option<[u8; 16]>,
    pub identity_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPreflightError {
    pub exit_code: i32,
    pub message: String,
}

fn parse_python_control_hash(raw: &str, label: &str) -> Result<[u8; 16], ControlPreflightError> {
    let bytes = hex::decode(raw).map_err(|e| ControlPreflightError {
        exit_code: 203,
        message: format!("Invalid {label} destination hash: {e}"),
    })?;
    if bytes.len() != 16 {
        return Err(ControlPreflightError {
            exit_code: 203,
            message: format!(
                "Invalid {label} destination hash: Destination hash length must be 32 characters"
            ),
        });
    }

    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

pub fn preflight_control_command(
    config_dir: &Path,
    identity_path: Option<&Path>,
    peer_hash: Option<&str>,
    remote_hash: Option<&str>,
) -> Result<ControlPreflight, ControlPreflightError> {
    let peer_hash = match peer_hash {
        Some(raw) => Some(parse_python_control_hash(raw, "peer")?),
        None => None,
    };

    let identity_path = if let Some(path) = identity_path {
        path.to_path_buf()
    } else {
        if !config_dir.is_dir() {
            return Err(ControlPreflightError {
                exit_code: 201,
                message: "Specified configuration directory does not exist, exiting now"
                    .to_string(),
            });
        }
        config_dir.join("identity")
    };

    if !identity_path.is_file() {
        return Err(ControlPreflightError {
            exit_code: 202,
            message: "Identity file not found in specified configuration directory, exiting now"
                .to_string(),
        });
    }

    let remote_hash = match remote_hash {
        Some(raw) => Some(parse_python_control_hash(raw, "remote")?),
        None => None,
    };

    Ok(ControlPreflight {
        peer_hash,
        remote_hash,
        identity_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("lxmd-{name}-{}-{unique}", std::process::id()))
    }

    #[test]
    fn lxmd_paths_match_python_storage_layout() {
        let config = PathBuf::from("/tmp/lxmd-config");
        let paths = LxmdPaths::new(&config);

        assert_eq!(paths.config_dir, config);
        assert_eq!(
            paths.identity_path,
            PathBuf::from("/tmp/lxmd-config/identity")
        );
        assert_eq!(paths.storage_dir, PathBuf::from("/tmp/lxmd-config/storage"));
        assert_eq!(
            paths.messages_dir,
            PathBuf::from("/tmp/lxmd-config/storage/messages")
        );
        assert_eq!(
            paths.lxmf_storage_dir,
            PathBuf::from("/tmp/lxmd-config/storage/lxmf")
        );
        assert_eq!(
            paths.router_state_dir,
            PathBuf::from("/tmp/lxmd-config/storage/lxmf")
        );
        assert_eq!(
            paths.propagation_store_dir,
            PathBuf::from("/tmp/lxmd-config/storage/lxmf/messagestore")
        );
        assert_eq!(
            paths.ratchets_dir,
            PathBuf::from("/tmp/lxmd-config/storage/lxmf/ratchets")
        );
        assert_eq!(
            paths.ratchet_ring_path,
            PathBuf::from("/tmp/lxmd-config/storage/lxmf/ratchets/ring")
        );
        assert_eq!(
            paths.ratchet_control_path,
            PathBuf::from("/tmp/lxmd-config/storage/lxmf/ratchets/ring.control")
        );
        assert_eq!(
            paths.received_ratchets_dir,
            PathBuf::from("/tmp/lxmd-config/storage/lxmf/ratchets/received")
        );
        assert_eq!(
            paths.known_identities_path,
            PathBuf::from("/tmp/lxmd-config/storage/lxmf/ratchets/known_identities")
        );
    }

    #[test]
    fn lxmd_paths_expose_legacy_rust_layout() {
        let paths = LxmdPaths::new("/tmp/lxmd-config");

        assert_eq!(
            paths.legacy_lxmf_dir,
            PathBuf::from("/tmp/lxmd-config/.lxmf")
        );
        assert_eq!(
            paths.legacy_identity_path,
            PathBuf::from("/tmp/lxmd-config/.lxmf/identity")
        );
        assert_eq!(
            paths.legacy_messages_dir,
            PathBuf::from("/tmp/lxmd-config/.lxmf/messages")
        );
        assert_eq!(
            paths.legacy_ratchets_dir,
            PathBuf::from("/tmp/lxmd-config/.lxmf/ratchets")
        );
        assert_eq!(
            paths.legacy_propagation_store_dir,
            PathBuf::from("/tmp/lxmd-config/.lxmf/propagation")
        );
    }

    #[test]
    fn preferred_identity_path_uses_python_identity_first() {
        let temp = unique_temp_dir("identity-python-first");
        let paths = LxmdPaths::new(&temp);
        std::fs::create_dir_all(paths.legacy_lxmf_dir.clone()).unwrap();
        std::fs::write(&paths.identity_path, b"python").unwrap();
        std::fs::write(&paths.legacy_identity_path, b"legacy").unwrap();

        assert_eq!(paths.preferred_identity_path(), paths.identity_path);
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn preferred_identity_path_falls_back_to_legacy_identity() {
        let temp = unique_temp_dir("identity-legacy-fallback");
        let paths = LxmdPaths::new(&temp);
        std::fs::create_dir_all(paths.legacy_lxmf_dir.clone()).unwrap();
        std::fs::write(&paths.legacy_identity_path, b"legacy").unwrap();

        assert_eq!(paths.preferred_identity_path(), paths.legacy_identity_path);
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn preferred_identity_path_defaults_to_python_identity_for_fresh_config() {
        let temp = unique_temp_dir("identity-fresh");
        let paths = LxmdPaths::new(&temp);

        assert_eq!(paths.preferred_identity_path(), paths.identity_path);
    }

    #[test]
    fn local_status_format_matches_current_cli_output() {
        let status = LocalStatusView {
            lxmf_dest_hash: [0x11; 16],
            propagation_enabled: false,
            peers: 2,
            propagation_entries: 3,
            propagation_size: 4096,
            pending_outbound: 4,
            pending_deferred_stamps: 5,
            stamp_costs_cached: 6,
        };

        assert_eq!(
            format_local_status(&status),
            "LXMF destination: 11111111111111111111111111111111\n\
             Propagation node: disabled\n\
             Peers: 2\n\
             Propagation messages: 3\n\
             Propagation storage bytes: 4096\n\
             Pending outbound: 4\n\
             Pending deferred stamps: 5\n\
             Cached stamp costs: 6\n"
        );
    }

    #[test]
    fn local_peers_format_matches_current_cli_output() {
        assert_eq!(format_local_peers(&[]), "No peers\n");

        let peers = [LocalPeerView {
            hash: [0x22; 16],
            state: 1,
            alive: true,
            unhandled: 7,
            last_heard: 12.3,
        }];
        assert_eq!(
            format_local_peers(&peers),
            "22222222222222222222222222222222 state=1 alive=true unhandled=7 last_heard=12\n"
        );
    }

    #[test]
    fn delivery_announce_app_data_matches_python_msgpack() {
        // Python 1.0.1: msgpack([display_name, stamp_cost, [SF_COMPRESSION]])
        // — LXMRouter.py:999-1001.
        assert_eq!(
            hex::encode(delivery_announce_app_data(Some("Test"), Some(16))),
            "93c40454657374109100"
        );
        assert_eq!(
            hex::encode(delivery_announce_app_data(None, None)),
            "93c0c09100"
        );
    }

    #[test]
    fn propagation_announce_app_data_matches_python_msgpack() {
        let mut data =
            lxmf_core::handlers::PropagationNodeAnnounceData::new(true, 256, 10_240, 16, 3, 18);
        data.timebase = 1_700_000_000;
        data.set_name("Node");

        assert_eq!(
            hex::encode(propagation_announce_app_data(&data)),
            "97c2ce6553f100c3cd0100cd2800931003128101c4044e6f6465"
        );
    }

    #[test]
    fn explicit_rnsconfig_overrides_lxmd_config_dir() {
        let (config, rnsconfig) = resolve_config_dirs(Some("/tmp/lxmd-a"), Some("/tmp/rns-a"));
        assert_eq!(config, PathBuf::from("/tmp/lxmd-a"));
        assert_eq!(rnsconfig, PathBuf::from("/tmp/rns-a"));

        let (config, rnsconfig) = resolve_config_dirs(Some("/tmp/lxmd-b"), None);
        assert_eq!(config, PathBuf::from("/tmp/lxmd-b"));
        assert_ne!(rnsconfig, PathBuf::from("/tmp/lxmd-b"));
        assert!(
            rnsconfig.ends_with("rsReticulum")
                || rnsconfig.ends_with(".rsReticulum")
                || rnsconfig.ends_with("/data/local/tmp/.rsReticulum")
        );
    }

    #[test]
    fn omitted_config_uses_rslxmf_defaults() {
        let (config, rnsconfig) = resolve_config_dirs(None, None);
        assert!(
            config.ends_with("rsLXMF")
                || config.ends_with(".rsLXMF")
                || config.ends_with("/data/local/tmp/.rsLXMF")
        );
        assert!(
            rnsconfig.ends_with("rsReticulum")
                || rnsconfig.ends_with(".rsReticulum")
                || rnsconfig.ends_with("/data/local/tmp/.rsReticulum")
        );
        assert_ne!(config, rnsconfig);
    }

    #[test]
    fn control_preflight_matches_python_non_network_exit_order() {
        let missing_dir = std::env::temp_dir().join(format!(
            "lxmd-control-preflight-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&missing_dir);
        let invalid_peer =
            preflight_control_command(&missing_dir, None, Some("zz"), Some("also-invalid"))
                .unwrap_err();
        assert_eq!(invalid_peer.exit_code, 203);
        assert!(
            invalid_peer
                .message
                .contains("Invalid peer destination hash")
        );

        let missing_config =
            preflight_control_command(&missing_dir, None, None, Some("zz")).unwrap_err();
        assert_eq!(missing_config.exit_code, 201);
        assert!(
            missing_config
                .message
                .contains("Specified configuration directory does not exist")
        );

        let temp =
            std::env::temp_dir().join(format!("lxmd-control-preflight-{}", std::process::id()));
        std::fs::create_dir_all(&temp).unwrap();
        let missing_identity =
            preflight_control_command(&temp, None, None, Some("zz")).unwrap_err();
        assert_eq!(missing_identity.exit_code, 202);

        let identity = temp.join("identity");
        std::fs::write(&identity, b"identity").unwrap();
        let invalid_remote = preflight_control_command(&temp, None, None, Some("zz")).unwrap_err();
        assert_eq!(invalid_remote.exit_code, 203);
        assert!(
            invalid_remote
                .message
                .contains("Invalid remote destination hash")
        );

        let ok = preflight_control_command(
            &temp,
            None,
            Some("00112233445566778899aabbccddeeff"),
            Some("11111111111111111111111111111111"),
        )
        .unwrap();
        assert_eq!(
            ok.peer_hash.map(hex::encode),
            Some("00112233445566778899aabbccddeeff".to_string())
        );
        assert_eq!(
            ok.remote_hash.map(hex::encode),
            Some("11111111111111111111111111111111".to_string())
        );
        assert_eq!(ok.identity_path, identity);
        let _ = std::fs::remove_dir_all(temp);
    }
}
