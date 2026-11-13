//! Router state files in a caller-supplied directory.
//!
//! Files:
//! * `node_stats` — propagation-node counters
//! * `propagation_suppression_v1` — bounded download suppression records
//! * `propagation_node_policies_v1` — recorded propagation-node policies
//!
//! Stamp costs, tickets, and delivered and processed transient IDs live in
//! `state.db` ([`crate::state_store`]). `delivery_claims`, which earlier
//! releases appended to, is only read here so its records can be imported.
//!
//! Missing files yield empty/default state. Other I/O, malformed-data and
//! capacity errors propagate to the caller.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::types::PropagationTransientId;

pub const NODE_STATS_FILE: &str = "node_stats";
/// Delivered/processed claims that earlier releases appended before delivery callbacks ran.
const DELIVERY_CLAIMS_FILE: &str = "delivery_claims";

const CLAIM_DELIVERED: u8 = 0;
const CLAIM_PROCESSED: u8 = 1;
const CLAIM_RECORD_LEN: usize = 1 + 32 + 8;

/// Read appended claims as (delivered, processed). A torn trailing record is ignored.
#[allow(clippy::type_complexity)]
pub(crate) fn load_delivery_claims(
    dir: &Path,
) -> io::Result<(
    Vec<(PropagationTransientId, f64)>,
    Vec<(PropagationTransientId, f64)>,
)> {
    let mut records = Vec::new();
    for path in [claims_saving(dir), dir.join(DELIVERY_CLAIMS_FILE)] {
        match fs::read(path) {
            Ok(bytes) => {
                let whole = bytes.len() - bytes.len() % CLAIM_RECORD_LEN;
                records.extend_from_slice(&bytes[..whole]);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let (mut delivered, mut processed) = (Vec::new(), Vec::new());
    for record in records.chunks_exact(CLAIM_RECORD_LEN) {
        let id: PropagationTransientId = record[1..33].try_into().expect("32 bytes");
        let at = f64::from_le_bytes(record[33..].try_into().expect("8 bytes"));
        match record[0] {
            CLAIM_DELIVERED => delivered.push((id, at)),
            CLAIM_PROCESSED => processed.push((id, at)),
            _ => {}
        }
    }
    Ok((delivered, processed))
}

fn claims_saving(dir: &Path) -> std::path::PathBuf {
    dir.join(format!("{DELIVERY_CLAIMS_FILE}.saving"))
}

/// Remove every claim file once its records are committed to the LXMF state store.
pub(crate) fn clear_delivery_claims(dir: &Path) -> io::Result<()> {
    for path in [claims_saving(dir), dir.join(DELIVERY_CLAIMS_FILE)] {
        match fs::remove_file(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

/// Counters persisted by Python's `LXMRouter.save_node_stats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedNodeStats {
    pub client_propagation_messages_received: u64,
    pub client_propagation_messages_served: u64,
    pub unpeered_propagation_incoming: u64,
    pub unpeered_propagation_rx_bytes: u64,
}

/// Publish exact bytes through the strict platform durability boundary.
/// CommitUncertain remains an error: readback alone cannot authorize a receipt.
pub fn write_file_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    rns_identity::persistence::durable_write(path, data)
        .map(|_| ())
        .map_err(io::Error::other)
}

/// Suppression state cannot authorize a remote purge. Adapters nevertheless
/// persist it before allowing the next automatic wants selection.
pub fn save_suppression(
    dir: &Path,
    ledger: &crate::admission::SuppressionLedger,
) -> io::Result<()> {
    write_mpk(&dir.join("propagation_suppression_v1"), ledger)
}

pub fn load_suppression(dir: &Path) -> io::Result<crate::admission::SuppressionLedger> {
    // Preserve the existing one-field wrapper while rejecting duplicate keys,
    // mismatched embedded scope and quota violations before hydration.
    #[derive(serde::Deserialize)]
    struct Wire {
        #[serde(deserialize_with = "suppression_records")]
        records: Vec<crate::admission::SuppressionRecord>,
    }
    let wire: Option<Wire> =
        read_mpk_bounded(&dir.join("propagation_suppression_v1"), 65536 * 512 + 4096)?;
    crate::admission::SuppressionLedger::from_records(
        wire.map_or_else(Vec::new, |wire| wire.records),
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
fn suppression_records<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<crate::admission::SuppressionRecord>, D::Error> {
    struct Records;
    impl<'de> serde::de::Visitor<'de> for Records {
        type Value = Vec<crate::admission::SuppressionRecord>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bounded unique suppression map")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut seen = std::collections::HashSet::new();
            let mut records = Vec::new();
            while let Some((scope,record))=map.next_entry::<crate::admission::AdmissionScope,crate::admission::SuppressionRecord>()? {
                if scope!=record.scope || !seen.insert(scope) || records.len()>=crate::admission::SuppressionLedger::GLOBAL {
                    return Err(serde::de::Error::custom("invalid suppression scope or capacity"));
                }
                records.push(record);
            }
            Ok(records)
        }
    }
    deserializer.deserialize_map(Records)
}

pub fn save_node_policies(
    dir: &Path,
    policies: &HashMap<[u8; 16], crate::propagation_send::AdvertisedNodePolicy>,
) -> io::Result<()> {
    write_mpk(&dir.join("propagation_node_policies_v1"), policies)
}
pub fn load_node_policies(
    dir: &Path,
) -> io::Result<HashMap<[u8; 16], crate::propagation_send::AdvertisedNodePolicy>> {
    Ok(read_mpk(&dir.join("propagation_node_policies_v1"))?.unwrap_or_default())
}

fn write_mpk<T: serde::Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes =
        rmp_serde::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_file_atomic(path, &bytes)
}

fn read_mpk<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    read_mpk_bounded(path, 64 * 1024 * 1024)
}
fn read_mpk_bounded<T: serde::de::DeserializeOwned>(
    path: &Path,
    limit: usize,
) -> io::Result<Option<T>> {
    use std::io::Read;
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "router state exceeds bounded capacity",
        ));
    }
    // Allocation-free structural walk precedes serde's collection size hints.
    // It also rejects trailing roots, deep nesting and truncated huge lengths.
    let encoded = crate::message::EncodedFieldValue::new(bytes.into())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    rmp_serde::from_slice(encoded.encoded())
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn save_node_stats(dir: &Path, stats: &PersistedNodeStats) -> io::Result<()> {
    let bytes = rmp_serde::to_vec_named(stats)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::create_dir_all(dir)?;
    write_file_atomic(&dir.join(NODE_STATS_FILE), &bytes)
}

pub fn load_node_stats(dir: &Path) -> io::Result<PersistedNodeStats> {
    Ok(read_mpk(&dir.join(NODE_STATS_FILE))?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn missing_file_returns_default() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(
            load_node_stats(tmp.path()).unwrap(),
            PersistedNodeStats::default()
        );
        let (delivered, processed) = load_delivery_claims(tmp.path()).unwrap();
        assert!(delivered.is_empty() && processed.is_empty());
    }

    #[test]
    fn node_stats_roundtrip_uses_named_python_fields() {
        let tmp = TempDir::new().unwrap();
        let expected = PersistedNodeStats {
            client_propagation_messages_received: 11,
            client_propagation_messages_served: 12,
            unpeered_propagation_incoming: 13,
            unpeered_propagation_rx_bytes: 14,
        };

        save_node_stats(tmp.path(), &expected).unwrap();
        assert_eq!(load_node_stats(tmp.path()).unwrap(), expected);

        let encoded = fs::read(tmp.path().join(NODE_STATS_FILE)).unwrap();
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(encoded)).unwrap();
        let keys = value
            .as_map()
            .unwrap()
            .iter()
            .filter_map(|(key, _)| key.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert!(keys.contains("client_propagation_messages_received"));
        assert!(keys.contains("client_propagation_messages_served"));
        assert!(keys.contains("unpeered_propagation_incoming"));
        assert!(keys.contains("unpeered_propagation_rx_bytes"));
    }

    #[test]
    fn write_file_atomic_writes_and_replaces_without_leftover_tmp() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("message");

        write_file_atomic(&path, b"first").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");

        // Replaces existing content (os.replace semantics — LXMessage.py).
        write_file_atomic(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");

        // No .tmp.* residue in the directory after successful writes.
        let leftovers: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn write_file_atomic_cleans_tmp_on_error() {
        let tmp = TempDir::new().unwrap();
        // Destination is a directory: the final rename fails, and the tmp
        // file must be unlinked (LXMessage.py).
        let dir_path = tmp.path().join("collide");
        fs::create_dir(&dir_path).unwrap();

        assert!(write_file_atomic(&dir_path, b"data").is_err());
        let leftovers: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn serialization_failure_preserves_existing_file_without_temp_residue() {
        struct FailsToSerialize;

        impl serde::Serialize for FailsToSerialize {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("intentional failure"))
            }
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state");
        fs::write(&path, b"previous-good-state").unwrap();

        assert!(write_mpk(&path, &FailsToSerialize).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"previous-good-state");
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_atomic_writers_never_publish_torn_data_or_collide_on_temp_names() {
        use std::sync::{Arc, Barrier};

        let tmp = TempDir::new().unwrap();
        let path = Arc::new(tmp.path().join("shared"));
        let barrier = Arc::new(Barrier::new(8));
        let payloads = (0u8..8)
            .map(|value| vec![value; 16 * 1024])
            .collect::<Vec<_>>();
        let threads = payloads
            .iter()
            .cloned()
            .map(|payload| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    write_file_atomic(path.as_ref(), &payload).unwrap();
                })
            })
            .collect::<Vec<_>>();

        for thread in threads {
            thread.join().unwrap();
        }

        let published = fs::read(path.as_ref()).unwrap();
        assert!(payloads.contains(&published));
        let leftovers = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leftovers, 0);
    }
}
