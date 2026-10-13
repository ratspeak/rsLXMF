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

pub fn save_stamp_costs(dir: &Path, costs: &HashMap<[u8; 16], StampCostEntry>) -> io::Result<()> {
    write_mpk(&dir.join(STAMP_COSTS_FILE), costs)
}

pub fn load_stamp_costs(dir: &Path) -> io::Result<HashMap<[u8; 16], StampCostEntry>> {
    Ok(read_mpk(&dir.join(STAMP_COSTS_FILE))?.unwrap_or_default())
}

/// Process-local revision of a captured ticket state. All production ticket
/// writes pass through the same path coordinator, so a delayed checkpoint can
/// never replace a ticket that a newer signing intent already committed.
#[derive(Debug, Clone)]
pub(crate) struct TicketPersistenceSnapshot {
    revision: u64,
    snapshot: std::sync::Arc<TicketStoreSnapshot>,
}
impl TicketPersistenceSnapshot {
    pub(crate) fn capture(snapshot: TicketStoreSnapshot) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        // Rust 1.99 renamed this operation; keep the identical Rust 1.89 API.
        #[allow(deprecated)]
        let revision = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("ticket checkpoint revision exhausted");
        Self {
            revision,
            snapshot: std::sync::Arc::new(snapshot),
        }
    }
    pub(crate) fn save(&self, dir: &Path, required: Option<&Ticket>) -> io::Result<()> {
        use std::sync::{Mutex, OnceLock};
        struct Latest {
            revision: u64,
            committed: bool,
        }
        static WRITERS: OnceLock<Mutex<HashMap<std::path::PathBuf, Latest>>> = OnceLock::new();
        fs::create_dir_all(dir)?;
        let path = fs::canonicalize(dir)?.join(TICKETS_FILE);
        let mut writers = WRITERS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .map_err(|_| io::Error::other("ticket persistence coordinator unavailable"))?;
        if !writers.contains_key(&path) && writers.len() >= 4096 {
            return Err(io::Error::other("ticket persistence path quota exhausted"));
        }
        let latest = writers.entry(path.clone()).or_insert(Latest {
            revision: self.revision,
            committed: false,
        });
        if self.revision < latest.revision {
            if !latest.committed {
                return Err(io::Error::other(
                    "newer ticket checkpoint is uncertain and must be retried",
                ));
            }
            if let Some(required) = required {
                let (stored, _) = load_tickets(dir)?;
                if !stored.inbound.contains(required) {
                    return Err(io::Error::other(
                        "newer ticket state no longer contains this signing intent",
                    ));
                }
            }
            return Ok(());
        }
        if required.is_some_and(|required| !self.snapshot.inbound.contains(required)) {
            return Err(io::Error::other(
                "ticket snapshot does not contain this signing intent",
            ));
        }
        latest.revision = self.revision;
        latest.committed = false;
        // Even an uncertain publication raises the revision floor. Older
        // snapshots fail closed until this or a newly captured current state
        // reestablishes the strict barrier. No failed payload is retained by
        // this bounded process-wide metadata coordinator.
        write_mpk(&path, &*self.snapshot)?;
        latest.committed = true;
        Ok(())
    }
}

pub fn save_tickets(dir: &Path, tickets: &TicketStoreSnapshot) -> io::Result<()> {
    TicketPersistenceSnapshot::capture(tickets.clone()).save(dir, None)
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
