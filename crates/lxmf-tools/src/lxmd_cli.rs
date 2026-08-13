//! `lxmd` CLI parsing and formatting helpers.
//!
//! Keeping these helpers outside the binary entrypoint lets tests exercise
//! parser, formatting, and small data-normalization surfaces without starting
//! the daemon runtime.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SendMethod {
    Opportunistic,
    Direct,
    Propagated,
}

impl SendMethod {
    pub fn delivery_method(self) -> lxmf_core::constants::DeliveryMethod {
        match self {
            SendMethod::Opportunistic => lxmf_core::constants::DeliveryMethod::Opportunistic,
            SendMethod::Direct => lxmf_core::constants::DeliveryMethod::Direct,
            SendMethod::Propagated => lxmf_core::constants::DeliveryMethod::Propagated,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "lxmd-rs",
    bin_name = "lxmd-rs",
    about = "LXMF Propagation Daemon",
    version
)]
pub struct Args {
    /// Path to configuration directory.
    #[arg(short, long)]
    pub config: Option<String>,

    /// Path to alternative Reticulum configuration directory.
    #[arg(long)]
    pub rnsconfig: Option<String>,

    /// Run an LXMF propagation node, overriding config.
    #[arg(short = 'p', long = "propagation-node")]
    pub propagation_node: bool,

    /// Executable to run when a message is received, overriding config.
    #[arg(short = 'i', long = "on-inbound", value_name = "PATH")]
    pub on_inbound: Option<String>,

    /// Increase verbosity (can be repeated).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Decrease verbosity (can be repeated).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub quiet: u8,

    /// Generate and print example configuration.
    #[arg(long)]
    pub exampleconfig: bool,

    /// Run as a system service (no interactive output).
    #[arg(short = 's', long)]
    pub service: bool,

    /// Display local node status and exit.
    #[arg(long)]
    pub status: bool,

    /// Display known propagation peers and exit.
    #[arg(long)]
    pub peers: bool,

    /// Request a sync with the specified peer and exit.
    #[arg(long, value_name = "PEER_HASH")]
    pub sync: Option<String>,

    /// Break peering with the specified peer and exit.
    #[arg(short = 'b', long = "break", value_name = "PEER_HASH")]
    pub unpeer: Option<String>,

    /// Timeout in seconds for query operations.
    #[arg(long)]
    pub timeout: Option<f64>,

    /// Remote propagation node destination hash for query operations.
    #[arg(short = 'r', long, value_name = "DEST_HASH")]
    pub remote: Option<String>,

    /// Identity path used for remote query operations.
    #[arg(long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Send a single message and exit: `--send <dest_hash> <content>`.
    #[arg(long, num_args = 1..=2, value_names = ["DEST_HASH", "CONTENT"])]
    pub send: Option<Vec<String>>,

    /// Read outgoing --send content from a UTF-8 file instead of argv.
    #[arg(long, value_name = "PATH")]
    pub send_file: Option<PathBuf>,

    /// Delivery method for --send.
    #[arg(long, value_enum, default_value_t = SendMethod::Opportunistic)]
    pub send_method: SendMethod,

    /// Link/resource completion timeout for --send.
    #[arg(long, default_value_t = 90)]
    pub send_timeout_secs: u64,

    /// Attach custom LXMF fields to the outgoing --send message. Accepts a
    /// JSON object mapping field-id -> base64(value). Example:
    ///   --send-fields-json '{"1":"aGVsbG8=","42":"AAECA/8="}'
    /// Only meaningful alongside --send.
    #[arg(long, value_name = "JSON")]
    pub send_fields_json: Option<String>,
}

pub fn parse_send_fields_json(raw: &str) -> Result<BTreeMap<u8, Vec<u8>>, String> {
    use base64::Engine;
    let parsed: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("--send-fields-json is not JSON: {e}"))?;
    let map = parsed
        .as_object()
        .ok_or_else(|| "--send-fields-json must be a JSON object".to_string())?;
    let mut out = BTreeMap::new();
    let b64 = base64::engine::general_purpose::STANDARD;
    for (key, value) in map {
        let fid: u8 = key
            .parse::<u16>()
            .ok()
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| format!("field id {key:?} is not a u8"))?;
        let s = value
            .as_str()
            .ok_or_else(|| format!("field {fid} value must be a base64 string"))?;
        let bytes = b64
            .decode(s)
            .map_err(|e| format!("field {fid} base64 decode failed: {e}"))?;
        out.insert(fid, bytes);
    }
    Ok(out)
}

pub fn normalize_hash_hex(raw: &str) -> String {
    raw.replace(":", "")
        .replace(" ", "")
        .replace("<", "")
        .replace(">", "")
}

pub fn parse_destination_hash(raw: &str) -> Result<[u8; 16], String> {
    let normalized = normalize_hash_hex(raw);
    if normalized.len() != 32 {
        return Err("destination hash must be 32 hex characters".to_string());
    }
    let bytes = hex::decode(&normalized).map_err(|e| format!("invalid destination hash: {e}"))?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

pub fn example_config() -> &'static str {
    r#"# This is an example LXM Daemon config file.
[propagation]

enable_node = no

# control_allowed = 7d7e542829b40f32364499b27438dba8, 437229f8e29598b2282b88bad5e44698

# node_name = Anonymous Propagation Node

announce_interval = 360

announce_at_start = yes

autopeer = yes

autopeer_maxdepth = 6

# Validate inbound propagation stamp batches sequentially by default.
# sequential_pn_stamp_validation = yes

# Let configured static peers bypass sequential validation and inbound limits.
# static_peers_bypass_sequential = yes

# Maximum concurrent inbound propagation sync transfers.
# max_inbound_syncs = 3

# message_storage_limit = 500

# propagation_message_max_accepted_size = 256

# propagation_sync_max_accepted_size = 10240

# propagation_stamp_cost_target = 16

# propagation_stamp_cost_flexibility = 3

# peering_cost = 18

# remote_peering_cost_max = 26

# max_peers = 20

# static_peers = e17f833c4ddf8890dd3a79a6fea8161d, 5a2d0029b6e5ec87020abaea0d746da4

# prioritise_destinations = 4a594a8cced4a8f6adf23a8ac67b4011

# from_static_only = True

auth_required = no


[lxmf]

display_name = Anonymous Peer

announce_at_start = no

# announce_interval = 360

# stamp_cost = 12

delivery_transfer_max_accepted_size = 1

# on_inbound = /path/to/handler


[logging]

loglevel = 4
"#
}

/// Parse a plaintext destination-hash list: one 16-byte hex value per line.
/// Missing files return empty. Like Python `lxmd.py`, this accepts only raw
/// 32-byte hex lines; comments and inline comments are ignored only because
/// their raw line length is not exactly 32 bytes.
///
/// Python reference: `lxmd.py` reads `ignored` / `allowed` from the config dir.
pub fn load_hash_list(path: &Path) -> Vec<[u8; 16]> {
    let contents = match std::fs::read(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    contents
        .split(|b| *b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| line.len() == 32)
        .filter_map(|line| {
            let hex_str = std::str::from_utf8(line).ok()?;
            let bytes = hex::decode(hex_str).ok()?;
            bytes.try_into().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_lxmd_utility_flags() {
        let args = Args::try_parse_from([
            "lxmd",
            "--config",
            "/tmp/lxmd",
            "--rnsconfig",
            "/tmp/rns",
            "-p",
            "-i",
            "/bin/true",
            "-s",
            "--status",
            "--peers",
            "--sync",
            "00112233445566778899aabbccddeeff",
            "-b",
            "ffeeddccbbaa99887766554433221100",
            "--timeout",
            "1.5",
            "-r",
            "01010101010101010101010101010101",
            "--identity",
            "/tmp/id",
        ])
        .unwrap();

        assert_eq!(args.config.as_deref(), Some("/tmp/lxmd"));
        assert_eq!(args.rnsconfig.as_deref(), Some("/tmp/rns"));
        assert!(args.propagation_node);
        assert_eq!(args.on_inbound.as_deref(), Some("/bin/true"));
        assert!(args.service);
        assert!(args.status);
        assert!(args.peers);
        assert!(args.sync.is_some());
        assert!(args.unpeer.is_some());
        assert_eq!(args.timeout, Some(1.5));
        assert!(args.remote.is_some());
        assert_eq!(args.identity.as_deref(), Some(Path::new("/tmp/id")));
    }

    #[test]
    fn parse_destination_hash_accepts_pretty_hex() {
        let hash =
            parse_destination_hash("<00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff>").unwrap();
        assert_eq!(hex::encode(hash), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn load_hash_list_matches_python_line_length_parser() {
        let path = std::env::temp_dir().join(format!(
            "lxmd-hash-list-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            b"00112233445566778899aabbccddeeff\n\
              # this full-line comment is ignored by length\n\
              11111111111111111111111111111111 # inline comments are not stripped\n\
              AABBCCDDEEFF00112233445566778899\n\
              short\n",
        )
        .unwrap();

        let hashes = load_hash_list(&path)
            .into_iter()
            .map(hex::encode)
            .collect::<Vec<_>>();
        assert_eq!(
            hashes,
            [
                "00112233445566778899aabbccddeeff",
                "aabbccddeeff00112233445566778899"
            ]
        );
        let _ = std::fs::remove_file(path);
    }
}
