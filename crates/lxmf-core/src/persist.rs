//! Persistent router state — matches Python `<storagepath>/lxmf/` layout.
//!
//! Files:
//! * `outbound_stamp_costs` — `HashMap<dest_hash, StampCostEntry>`
//! * `available_tickets` — versioned directional ticket state
//! * `local_deliveries` — `HashMap<transient_id, timestamp>`
//! * `locally_processed` — `HashMap<transient_id, timestamp>`
//!
//! All four files are MessagePack-encoded via `rmp-serde`. Missing files are
//! treated as "no prior state" and do not raise errors — a fresh daemon is a
//! valid state.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::router::StampCostEntry;
use crate::ticket::{Ticket, TicketStoreSnapshot};
use crate::types::PropagationTransientId;

pub const STAMP_COSTS_FILE: &str = "outbound_stamp_costs";
pub const TICKETS_FILE: &str = "available_tickets";
pub const LOCAL_DELIVERIES_FILE: &str = "local_deliveries";
pub const LOCALLY_PROCESSED_FILE: &str = "locally_processed";
pub const NODE_STATS_FILE: &str = "node_stats";

/// Counters persisted by Python's `LXMRouter.save_node_stats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedNodeStats {
    pub client_propagation_messages_received: u64,
    pub client_propagation_messages_served: u64,
    pub unpeered_propagation_incoming: u64,
    pub unpeered_propagation_rx_bytes: u64,
}

/// Atomically write `data` to `path`: unique tmp file + flush + fsync + rename.
///
/// Tmp name is `<path>.tmp.<pid>.<16 random hex>` so concurrent writers (or
/// other processes) never collide; the tmp file is unlinked on error. An fsync
/// failure is logged as a warning and is non-fatal, matching Python
/// `LXMessage.write_to_directory` — LXMessage.py:674-696 (1.0.1).
pub fn write_file_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let random: [u8; 8] = rand::random();
    let tmp_name = format!(
        "{}.tmp.{}.{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        std::process::id(),
        hex::encode(random)
    );
    let tmp = path.with_file_name(tmp_name);

    let result = (|| {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(data)?;
        file.flush()?;
        if let Err(e) = file.sync_all() {
            tracing::warn!(
                "Error while waiting for persist fsync for {}: {e}",
                tmp.display()
            );
        }
        drop(file);
        fs::rename(&tmp, path)
    })();

    if result.is_err() && tmp.exists() {
        if let Err(e) = fs::remove_file(&tmp) {
            tracing::error!(
                "Error while cleaning temporary file {} for {}: {e}",
                tmp.display(),
                path.display()
            );
        }
    }

    result
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
    match fs::read(path) {
        Ok(bytes) => {
            let value = rmp_serde::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn save_stamp_costs(dir: &Path, costs: &HashMap<[u8; 16], StampCostEntry>) -> io::Result<()> {
    write_mpk(&dir.join(STAMP_COSTS_FILE), costs)
}

pub fn load_stamp_costs(dir: &Path) -> io::Result<HashMap<[u8; 16], StampCostEntry>> {
    Ok(read_mpk(&dir.join(STAMP_COSTS_FILE))?.unwrap_or_default())
}

pub fn save_tickets(dir: &Path, tickets: &TicketStoreSnapshot) -> io::Result<()> {
    write_mpk(&dir.join(TICKETS_FILE), tickets)
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum PersistedTickets {
    Directional(TicketStoreSnapshot),
    Legacy(Vec<Ticket>),
}

pub fn load_tickets(dir: &Path) -> io::Result<(TicketStoreSnapshot, Option<Vec<Ticket>>)> {
    Ok(match read_mpk(&dir.join(TICKETS_FILE))? {
        Some(PersistedTickets::Directional(snapshot)) => (snapshot, None),
        Some(PersistedTickets::Legacy(tickets)) => (TicketStoreSnapshot::default(), Some(tickets)),
        None => (TicketStoreSnapshot::default(), None),
    })
}

pub fn save_local_deliveries(
    dir: &Path,
    ids: &HashMap<PropagationTransientId, f64>,
) -> io::Result<()> {
    write_mpk(&dir.join(LOCAL_DELIVERIES_FILE), ids)
}

pub fn load_local_deliveries(dir: &Path) -> io::Result<HashMap<PropagationTransientId, f64>> {
    Ok(read_mpk(&dir.join(LOCAL_DELIVERIES_FILE))?.unwrap_or_default())
}

pub fn save_locally_processed(
    dir: &Path,
    ids: &HashMap<PropagationTransientId, f64>,
) -> io::Result<()> {
    write_mpk(&dir.join(LOCALLY_PROCESSED_FILE), ids)
}

pub fn load_locally_processed(dir: &Path) -> io::Result<HashMap<PropagationTransientId, f64>> {
    Ok(read_mpk(&dir.join(LOCALLY_PROCESSED_FILE))?.unwrap_or_default())
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
    fn stamp_costs_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut costs = HashMap::new();
        costs.insert(
            [0xAA; 16],
            StampCostEntry {
                cost: 12,
                recorded_at: 1_700_000_000.0,
            },
        );
        save_stamp_costs(tmp.path(), &costs).unwrap();
        let loaded = load_stamp_costs(tmp.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[&[0xAA; 16]].cost, 12);
    }

    #[test]
    fn tickets_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let tickets = TicketStoreSnapshot {
            version: 1,
            outbound: vec![Ticket::new([0x01; 16], [0x02; 16], 9_999.0)],
            inbound: vec![Ticket::new([0x03; 16], [0x04; 16], 8_888.0)],
            last_deliveries: HashMap::from([([0x02; 16], 7_777.0)]),
        };
        save_tickets(tmp.path(), &tickets).unwrap();
        let (loaded, legacy) = load_tickets(tmp.path()).unwrap();
        assert!(legacy.is_none());
        assert_eq!(loaded, tickets);
    }

    #[test]
    fn legacy_flat_tickets_are_detected_for_migration() {
        let tmp = TempDir::new().unwrap();
        let tickets = vec![Ticket::new([0x01; 16], [0x02; 16], 9_999.0)];
        write_mpk(&tmp.path().join(TICKETS_FILE), &tickets).unwrap();
        let (snapshot, legacy) = load_tickets(tmp.path()).unwrap();
        assert_eq!(snapshot, TicketStoreSnapshot::default());
        assert_eq!(legacy.unwrap(), tickets);
    }

    #[test]
    fn local_deliveries_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut ids = HashMap::new();
        ids.insert([0x03; 32], 1_700_000_000.0);
        save_local_deliveries(tmp.path(), &ids).unwrap();
        let loaded = load_local_deliveries(tmp.path()).unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn missing_file_returns_default() {
        let tmp = TempDir::new().unwrap();
        assert!(load_stamp_costs(tmp.path()).unwrap().is_empty());
        let (tickets, legacy) = load_tickets(tmp.path()).unwrap();
        assert_eq!(tickets, TicketStoreSnapshot::default());
        assert!(legacy.is_none());
        assert!(load_local_deliveries(tmp.path()).unwrap().is_empty());
        assert!(load_locally_processed(tmp.path()).unwrap().is_empty());
        assert_eq!(
            load_node_stats(tmp.path()).unwrap(),
            PersistedNodeStats::default()
        );
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

        // Replaces existing content (os.replace semantics — LXMessage.py:687).
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
        // file must be unlinked (LXMessage.py:691-693).
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
