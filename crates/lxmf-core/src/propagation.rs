//! Store-and-forward message storage for LXMF propagation nodes.
//!
//! Mirrors propagation entry management in Python LXMRouter.py.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::PropagationTransientId;

/// A stored propagation entry awaiting collection by peers.
#[derive(Debug, Clone)]
pub struct PropagationEntry {
    pub transient_id: PropagationTransientId,
    pub message_hash: [u8; 32],
    pub destination_hash: [u8; 16],
    pub stored_at: f64,
    pub stamp_value: u8,
    pub size: usize,
    pub collected: bool,
}

impl PropagationEntry {
    pub fn new(
        transient_id: PropagationTransientId,
        message_hash: [u8; 32],
        destination_hash: [u8; 16],
        size: usize,
        stamp_value: u8,
    ) -> Self {
        Self {
            transient_id,
            message_hash,
            destination_hash,
            stored_at: now_f64(),
            stamp_value,
            size,
            collected: false,
        }
    }

    /// Format: `{hex_transient_id}_{timestamp}_{stamp_value}`.
    pub fn filename(&self) -> String {
        format!(
            "{}_{:.0}_{}",
            hex_encode(&self.transient_id),
            self.stored_at,
            self.stamp_value
        )
    }

    /// Accepts both the 3-component format and the legacy 2-component
    /// `{transient_id}_{timestamp}` form (stamp_value defaults to 0).
    pub fn parse_filename(filename: &str) -> Option<(PropagationTransientId, f64, u8)> {
        let parts: Vec<&str> = filename.split('_').collect();
        match parts.len() {
            3 => {
                let tid = hex_decode_32(parts[0])?;
                let ts: f64 = parts[1].parse().ok()?;
                let sv: u8 = parts[2].parse().ok()?;
                Some((tid, ts, sv))
            }
            2 => {
                let tid = hex_decode_32(parts[0])?;
                let ts: f64 = parts[1].parse().ok()?;
                Some((tid, ts, 0))
            }
            _ => None,
        }
    }
}

/// Owned by the router actor; no shared access.
#[derive(Debug, Default)]
pub struct PropagationStore {
    entries: HashMap<PropagationTransientId, PropagationEntry>,
    total_size: usize,
    locally_delivered_ids: HashSet<PropagationTransientId>,
    locally_processed_ids: HashSet<PropagationTransientId>,
    ignored_destinations: HashSet<[u8; 16]>,
    /// Prioritised destinations receive a 0.1x weight multiplier during culling.
    prioritised_destinations: HashSet<[u8; 16]>,
    peer_distribution_queue: VecDeque<(PropagationTransientId, Option<[u8; 16]>)>,
    /// `None` disables the byte-size cap.
    pub storage_limit: Option<usize>,
}

impl PropagationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `false` if the destination is in the ignored list.
    pub fn insert(&mut self, entry: PropagationEntry) -> bool {
        if self.ignored_destinations.contains(&entry.destination_hash) {
            return false;
        }
        self.total_size += entry.size;
        self.entries.insert(entry.transient_id, entry);
        true
    }

    pub fn get(&self, transient_id: &PropagationTransientId) -> Option<&PropagationEntry> {
        self.entries.get(transient_id)
    }

    pub fn contains(&self, transient_id: &PropagationTransientId) -> bool {
        self.entries.contains_key(transient_id)
    }

    pub fn remove(&mut self, transient_id: &PropagationTransientId) -> Option<PropagationEntry> {
        if let Some(entry) = self.entries.remove(transient_id) {
            self.total_size = self.total_size.saturating_sub(entry.size);
            Some(entry)
        } else {
            None
        }
    }

    pub fn transient_ids(&self) -> Vec<PropagationTransientId> {
        self.entries.keys().copied().collect()
    }

    pub fn entries(&self) -> impl Iterator<Item = &PropagationEntry> {
        self.entries.values()
    }

    pub fn entries_for_destination(&self, dest_hash: &[u8; 16]) -> Vec<&PropagationEntry> {
        self.entries
            .values()
            .filter(|e| &e.destination_hash == dest_hash)
            .collect()
    }

    pub fn cull_expired(&mut self, max_age_secs: u64) {
        let now = now_f64();
        let cutoff = now - max_age_secs as f64;
        let removed: Vec<PropagationTransientId> = self
            .entries
            .iter()
            .filter(|(_, e)| e.stored_at < cutoff)
            .map(|(k, _)| *k)
            .collect();
        for id in removed {
            self.remove(&id);
        }
    }

    /// Cull messages by weighted score until total size is within `limit_bytes`.
    ///
    /// Score = priority_weight * age_weight * size. Evicts highest-weight first
    /// (oldest + largest + non-prioritised). Matches Python
    /// `clean_message_store()` in LXMRouter.py.
    pub fn cull_by_weight(&mut self, limit_bytes: usize) {
        if self.total_size <= limit_bytes {
            return;
        }

        let bytes_needed = self.total_size - limit_bytes;
        let now = now_f64();

        let mut weighted: Vec<(PropagationTransientId, f64)> = self
            .entries
            .iter()
            .map(|(tid, entry)| {
                let weight = self.compute_weight(entry, now);
                (*tid, weight)
            })
            .collect();

        weighted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut bytes_cleaned = 0usize;
        let mut to_remove = Vec::new();

        for (tid, _weight) in &weighted {
            if bytes_cleaned >= bytes_needed {
                break;
            }
            if let Some(entry) = self.entries.get(tid) {
                bytes_cleaned += entry.size;
                to_remove.push(*tid);
            }
        }

        for tid in to_remove {
            self.remove(&tid);
        }
    }

    /// Matches Python `get_weight()`:
    ///   age_weight = max(1, (now - received) / 60 / 60 / 24 / 4)
    ///   priority_weight = 0.1 if prioritised, 1.0 otherwise
    ///   weight = priority_weight * age_weight * size
    pub fn compute_weight(&self, entry: &PropagationEntry, now: f64) -> f64 {
        let age_days = (now - entry.stored_at) / 86400.0 / 4.0;
        let age_weight = if age_days > 1.0 { age_days } else { 1.0 };

        let priority_weight = if self
            .prioritised_destinations
            .contains(&entry.destination_hash)
        {
            0.1
        } else {
            1.0
        };

        priority_weight * age_weight * entry.size as f64
    }

    pub fn get_stamp_value(&self, transient_id: &PropagationTransientId) -> Option<u8> {
        self.entries.get(transient_id).map(|e| e.stamp_value)
    }

    pub fn ignore_destination(&mut self, dest_hash: [u8; 16]) {
        self.ignored_destinations.insert(dest_hash);
    }

    pub fn unignore_destination(&mut self, dest_hash: &[u8; 16]) {
        self.ignored_destinations.remove(dest_hash);
    }

    pub fn is_destination_ignored(&self, dest_hash: &[u8; 16]) -> bool {
        self.ignored_destinations.contains(dest_hash)
    }

    pub fn prioritise_destination(&mut self, dest_hash: [u8; 16]) {
        self.prioritised_destinations.insert(dest_hash);
    }

    pub fn unprioritise_destination(&mut self, dest_hash: &[u8; 16]) {
        self.prioritised_destinations.remove(dest_hash);
    }

    pub fn mark_locally_delivered(&mut self, transient_id: PropagationTransientId) {
        self.locally_delivered_ids.insert(transient_id);
    }

    pub fn is_locally_delivered(&self, transient_id: &PropagationTransientId) -> bool {
        self.locally_delivered_ids.contains(transient_id)
    }

    pub fn mark_locally_processed(&mut self, transient_id: PropagationTransientId) {
        self.locally_processed_ids.insert(transient_id);
    }

    pub fn is_locally_processed(&self, transient_id: &PropagationTransientId) -> bool {
        self.locally_processed_ids.contains(transient_id)
    }

    pub fn locally_delivered_ids(&self) -> &HashSet<PropagationTransientId> {
        &self.locally_delivered_ids
    }

    pub fn locally_processed_ids(&self) -> &HashSet<PropagationTransientId> {
        &self.locally_processed_ids
    }

    pub fn replace_locally_delivered(&mut self, ids: HashSet<PropagationTransientId>) {
        self.locally_delivered_ids = ids;
    }

    pub fn replace_locally_processed(&mut self, ids: HashSet<PropagationTransientId>) {
        self.locally_processed_ids = ids;
    }

    /// Drop cache entries whose transient IDs no longer exist in `entries`
    /// (i.e. were culled). Python removes them once older than
    /// MESSAGE_EXPIRY * 6; the caller decides the cutoff here.
    pub fn clean_transient_caches(&mut self) {
        self.locally_delivered_ids
            .retain(|id| self.entries.contains_key(id));
        self.locally_processed_ids
            .retain(|id| self.entries.contains_key(id));
    }

    /// `from_peer` is the peer we received this message from, or `None` if it
    /// originated locally.
    pub fn enqueue_distribution(
        &mut self,
        transient_id: PropagationTransientId,
        from_peer: Option<[u8; 16]>,
    ) {
        self.peer_distribution_queue
            .push_back((transient_id, from_peer));
    }

    pub fn drain_distribution_queue(
        &mut self,
    ) -> Vec<(PropagationTransientId, Option<[u8; 16]>)> {
        self.peer_distribution_queue.drain(..).collect()
    }

    pub fn has_pending_distribution(&self) -> bool {
        !self.peer_distribution_queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_size(&self) -> usize {
        self.total_size
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PropagationTransientId, &PropagationEntry)> {
        self.entries.iter()
    }
}

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub use rns_crypto::hex_encode;

fn hex_decode_32(s: &str) -> Option<PropagationTransientId> {
    if s.len() != 64 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect();
    let bytes = bytes?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(byte: u8) -> PropagationTransientId {
        [byte; 32]
    }

    #[test]
    fn test_entry_filename() {
        let entry = PropagationEntry {
            transient_id: tid(0xAA),
            message_hash: [0xBB; 32],
            destination_hash: [0xCC; 16],
            stored_at: 1234567890.0,
            stamp_value: 8,
            size: 500,
            collected: false,
        };
        let fname = entry.filename();
        assert!(fname.starts_with(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        let parts: Vec<&str> = fname.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2], "8");
    }

    #[test]
    fn test_parse_filename_3_component() {
        let fname =
            "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd_1234567890_16";
        let (tid, ts, sv) = PropagationEntry::parse_filename(fname).unwrap();
        assert_eq!(tid[0], 0xaa);
        assert_eq!(ts, 1234567890.0);
        assert_eq!(sv, 16);
    }

    #[test]
    fn test_parse_filename_2_component_legacy() {
        let fname = format!("{}_1234567890", "aa".repeat(32));
        let (tid, ts, sv) = PropagationEntry::parse_filename(&fname).unwrap();
        assert_eq!(tid[0], 0xaa);
        assert_eq!(ts, 1234567890.0);
        assert_eq!(sv, 0);
    }

    #[test]
    fn test_propagation_store() {
        let mut store = PropagationStore::new();
        assert!(store.is_empty());

        let entry = PropagationEntry::new(tid(0xAA), [0xBB; 32], [0xCC; 16], 500, 8);
        store.insert(entry);

        assert_eq!(store.len(), 1);
        assert_eq!(store.total_size(), 500);
        assert!(store.contains(&tid(0xAA)));
        assert!(!store.contains(&tid(0x00)));
    }

    #[test]
    fn test_store_remove() {
        let mut store = PropagationStore::new();
        store.insert(PropagationEntry::new(
            tid(0xAA),
            [0xBB; 32],
            [0xCC; 16],
            500,
            8,
        ));
        store.insert(PropagationEntry::new(
            tid(0xDD),
            [0xEE; 32],
            [0xCC; 16],
            300,
            4,
        ));

        assert_eq!(store.total_size(), 800);

        store.remove(&tid(0xAA));
        assert_eq!(store.len(), 1);
        assert_eq!(store.total_size(), 300);
    }

    #[test]
    fn test_entries_for_destination() {
        let mut store = PropagationStore::new();
        let dest1 = [0xAA; 16];
        let dest2 = [0xBB; 16];

        store.insert(PropagationEntry::new(tid(0x01), [0; 32], dest1, 100, 0));
        store.insert(PropagationEntry::new(tid(0x02), [0; 32], dest1, 200, 0));
        store.insert(PropagationEntry::new(tid(0x03), [0; 32], dest2, 300, 0));

        assert_eq!(store.entries_for_destination(&dest1).len(), 2);
        assert_eq!(store.entries_for_destination(&dest2).len(), 1);
    }

    #[test]
    fn test_transient_ids() {
        let mut store = PropagationStore::new();
        store.insert(PropagationEntry::new(tid(0x01), [0; 32], [0; 16], 100, 0));
        store.insert(PropagationEntry::new(tid(0x02), [0; 32], [0; 16], 200, 0));

        let ids = store.transient_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_ignored_destinations() {
        let mut store = PropagationStore::new();
        let ignored_dest = [0xBB; 16];
        let allowed_dest = [0xCC; 16];

        store.ignore_destination(ignored_dest);

        let entry1 = PropagationEntry::new(tid(0x01), [0; 32], ignored_dest, 100, 0);
        assert!(!store.insert(entry1));
        assert_eq!(store.len(), 0);

        let entry2 = PropagationEntry::new(tid(0x02), [0; 32], allowed_dest, 200, 0);
        assert!(store.insert(entry2));
        assert_eq!(store.len(), 1);

        store.unignore_destination(&ignored_dest);
        let entry3 = PropagationEntry::new(tid(0x03), [0; 32], ignored_dest, 100, 0);
        assert!(store.insert(entry3));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_locally_delivered_ids() {
        let mut store = PropagationStore::new();
        let transient_id = tid(0xAA);

        assert!(!store.is_locally_delivered(&transient_id));
        store.mark_locally_delivered(transient_id);
        assert!(store.is_locally_delivered(&transient_id));
    }

    #[test]
    fn test_locally_processed_ids() {
        let mut store = PropagationStore::new();
        let transient_id = tid(0xBB);

        assert!(!store.is_locally_processed(&transient_id));
        store.mark_locally_processed(transient_id);
        assert!(store.is_locally_processed(&transient_id));
    }

    #[test]
    fn test_cull_by_weight() {
        let mut store = PropagationStore::new();

        let mut entry1 = PropagationEntry::new(tid(0x01), [0; 32], [0xAA; 16], 500, 0);
        entry1.stored_at = 1000.0;
        store.entries.insert(entry1.transient_id, entry1.clone());
        store.total_size += 500;

        let mut entry2 = PropagationEntry::new(tid(0x02), [0; 32], [0xBB; 16], 300, 0);
        entry2.stored_at = now_f64();
        store.entries.insert(entry2.transient_id, entry2.clone());
        store.total_size += 300;

        assert_eq!(store.total_size(), 800);

        store.cull_by_weight(400);
        assert!(store.total_size() <= 400);
        // Old entry evicted first (higher weight).
        assert!(!store.contains(&tid(0x01)));
    }

    #[test]
    fn test_peer_distribution_queue() {
        let mut store = PropagationStore::new();

        assert!(!store.has_pending_distribution());

        store.enqueue_distribution(tid(0xAA), Some([0xBB; 16]));
        store.enqueue_distribution(tid(0xCC), None);

        assert!(store.has_pending_distribution());

        let entries = store.drain_distribution_queue();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, tid(0xAA));
        assert_eq!(entries[0].1, Some([0xBB; 16]));
        assert_eq!(entries[1].0, tid(0xCC));
        assert!(entries[1].1.is_none());

        assert!(!store.has_pending_distribution());
    }

    #[test]
    fn test_compute_weight() {
        let mut store = PropagationStore::new();
        let now = now_f64();

        let entry = PropagationEntry {
            transient_id: tid(0x01),
            message_hash: [0; 32],
            destination_hash: [0xAA; 16],
            stored_at: now,
            stamp_value: 0,
            size: 1000,
            collected: false,
        };
        let w1 = store.compute_weight(&entry, now);

        store.prioritise_destination([0xAA; 16]);
        let w2 = store.compute_weight(&entry, now);
        assert!(w2 < w1, "prioritised entry should have lower weight");

        let old_entry = PropagationEntry {
            stored_at: now - 30.0 * 86400.0,
            ..entry.clone()
        };
        store.unprioritise_destination(&[0xAA; 16]);
        let w3 = store.compute_weight(&old_entry, now);
        assert!(w3 > w1, "old entry should have higher weight");
    }

    #[test]
    fn test_get_stamp_value() {
        let mut store = PropagationStore::new();
        store.insert(PropagationEntry::new(tid(0xAA), [0; 32], [0; 16], 100, 12));

        assert_eq!(store.get_stamp_value(&tid(0xAA)), Some(12));
        assert_eq!(store.get_stamp_value(&tid(0xBB)), None);
    }
}
