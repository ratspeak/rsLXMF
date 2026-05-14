//! Persistent router state — matches Python `<storagepath>/lxmf/` layout.
//!
//! Files:
//! * `outbound_stamp_costs` — `HashMap<dest_hash, StampCostEntry>`
//! * `available_tickets` — `Vec<Ticket>`
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
use crate::ticket::Ticket;
use crate::types::PropagationTransientId;

pub const STAMP_COSTS_FILE: &str = "outbound_stamp_costs";
pub const TICKETS_FILE: &str = "available_tickets";
pub const LOCAL_DELIVERIES_FILE: &str = "local_deliveries";
pub const LOCALLY_PROCESSED_FILE: &str = "locally_processed";

fn write_mpk<T: serde::Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes =
        rmp_serde::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
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

pub fn save_tickets(dir: &Path, tickets: &[Ticket]) -> io::Result<()> {
    write_mpk(&dir.join(TICKETS_FILE), &tickets)
}

pub fn load_tickets(dir: &Path) -> io::Result<Vec<Ticket>> {
    Ok(read_mpk(&dir.join(TICKETS_FILE))?.unwrap_or_default())
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
        let tickets = vec![Ticket::new([0x01; 16], [0x02; 16], 9_999.0)];
        save_tickets(tmp.path(), &tickets).unwrap();
        let loaded = load_tickets(tmp.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].token, [0x01; 16]);
        assert_eq!(loaded[0].destination_hash, [0x02; 16]);
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
        assert!(load_tickets(tmp.path()).unwrap().is_empty());
        assert!(load_local_deliveries(tmp.path()).unwrap().is_empty());
        assert!(load_locally_processed(tmp.path()).unwrap().is_empty());
    }
}
