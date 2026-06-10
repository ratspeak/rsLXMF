//! LXMF peer propagation node used for store-and-forward sync.
//!
//! Python reference: LXMF/LXMPeer.py.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::*;
use crate::types::PropagationTransientId;

type StoredPeer = (
    Vec<u8>,
    f64,
    u32,
    u8,
    Option<u8>,
    Option<u8>,
    bool,
    bool,
    Vec<Vec<u8>>,
);

/// An LXMF peer propagation node.
#[derive(Debug)]
pub struct LxmPeer {
    pub destination_hash: [u8; 16],
    pub state: PeerState,
    pub sync_strategy: SyncStrategy,
    pub last_sync: f64,
    unhandled_count: u32,
    unhandled_count_cached: bool,
    pub unreachable_count: u32,
    pub autopeered: bool,
    pub stamp_cost: Option<u8>,
    pub stamp_cost_flexibility: Option<u8>,
    /// Peering cost used for outbound peering-key generation.
    pub peering_cost: u8,
    /// Generated peering key `(stamp, value)`. `None` until [`LxmPeer::generate_peering_key`] succeeds.
    pub peering_key: Option<([u8; 32], u32)>,
    /// Per-transfer propagation limit in KB.
    pub propagation_transfer_limit: Option<f64>,
    /// Per-sync propagation limit in KB.
    pub propagation_sync_limit: Option<f64>,
    pub currently_transferring_messages: Option<Vec<PropagationTransientId>>,
    pub link_alive: bool,
    pub created_at: f64,
    pub last_heard: f64,
    pub alive: bool,
    pub peering_timebase: f64,
    /// Link establishment rate in bits/sec.
    pub link_establishment_rate: f64,
    /// Sync transfer rate in bits/sec.
    pub sync_transfer_rate: f64,
    pub offered: u64,
    pub outgoing: u64,
    pub incoming: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_sync_attempt: f64,
    pub next_sync_attempt: f64,
    pub sync_backoff: f64,
    pub metadata: Option<Vec<u8>>,
    /// Static peers are operator-configured; autopeered peers come from announces.
    pub is_static: bool,
    /// Message hashes already handled by this peer, for sync filtering.
    pub handled_messages: std::collections::HashSet<PropagationTransientId>,
}

impl LxmPeer {
    pub fn new(destination_hash: [u8; 16]) -> Self {
        let now = now_f64();
        Self {
            destination_hash,
            state: PeerState::Idle,
            sync_strategy: SyncStrategy::default(),
            last_sync: 0.0,
            unhandled_count: 0,
            unhandled_count_cached: false,
            unreachable_count: 0,
            autopeered: false,
            stamp_cost: None,
            stamp_cost_flexibility: None,
            peering_cost: PEERING_COST,
            peering_key: None,
            propagation_transfer_limit: Some(PROPAGATION_LIMIT as f64),
            propagation_sync_limit: None,
            currently_transferring_messages: None,
            link_alive: false,
            created_at: now,
            last_heard: now,
            alive: true,
            peering_timebase: 0.0,
            link_establishment_rate: 0.0,
            sync_transfer_rate: 0.0,
            offered: 0,
            outgoing: 0,
            incoming: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            last_sync_attempt: 0.0,
            next_sync_attempt: 0.0,
            sync_backoff: 0.0,
            metadata: None,
            is_static: false,
            handled_messages: std::collections::HashSet::new(),
        }
    }

    /// Construct a peer from propagation-node announce data.
    ///
    /// Announce layout (see Python `LXMRouter.get_propagation_node_app_data`):
    /// `[legacy_flag, timebase, node_state, transfer_limit_kb, sync_limit_kb,
    /// [stamp_cost, stamp_flex, peering_cost], metadata]`.
    pub fn from_announce(
        destination_hash: [u8; 16],
        timebase: f64,
        transfer_limit: Option<f64>,
        sync_limit: Option<f64>,
        stamp_cost: Option<u8>,
        stamp_flexibility: Option<u8>,
        peering_cost: Option<u8>,
    ) -> Self {
        let mut peer = Self::new(destination_hash);
        peer.peering_timebase = timebase;
        peer.propagation_transfer_limit = transfer_limit;
        peer.propagation_sync_limit = sync_limit;
        peer.stamp_cost = stamp_cost;
        peer.stamp_cost_flexibility = stamp_flexibility;
        peer.peering_cost = peering_cost.unwrap_or(PEERING_COST);
        peer.autopeered = true;
        peer
    }

    /// Effective minimum stamp cost this peer will accept.
    pub fn minimum_accepted_stamp_cost(&self) -> u8 {
        match self.stamp_cost {
            Some(cost) => cost.saturating_sub(PROPAGATION_COST_FLEX),
            None => 0,
        }
    }

    pub fn stamp_costs_known(&self) -> bool {
        self.stamp_cost.is_some() && self.stamp_cost_flexibility.is_some()
    }

    pub fn add_unhandled_message(&mut self) {
        self.unhandled_count_cached = false;
        self.unhandled_count += 1;
    }

    pub fn unhandled_messages(&self) -> u32 {
        self.unhandled_count
    }

    pub fn set_unhandled_count(&mut self, count: u32) {
        self.unhandled_count = count;
        self.unhandled_count_cached = true;
    }

    pub fn heard(&mut self) {
        self.last_heard = now_f64();
        self.alive = true;
        self.unreachable_count = 0;
        self.sync_backoff = 0.0;
    }

    pub fn add_handled_message(&mut self, hash: &PropagationTransientId) {
        self.handled_messages.insert(*hash);
    }

    pub fn has_handled(&self, hash: &PropagationTransientId) -> bool {
        self.handled_messages.contains(hash)
    }

    /// Serialize peer state, including handled messages, for persistence.
    pub fn to_bytes_with_handled(&self) -> Vec<u8> {
        let handled: Vec<Vec<u8>> = self.handled_messages.iter().map(|h| h.to_vec()).collect();
        let data = (
            self.destination_hash.to_vec(),
            self.last_sync,
            self.unreachable_count,
            self.peering_cost,
            self.stamp_cost,
            self.stamp_cost_flexibility,
            self.autopeered,
            self.is_static,
            handled,
        );
        rmp_serde::to_vec(&data).unwrap_or_default()
    }

    /// Deserialize peer state, including handled messages, from [`to_bytes_with_handled`] output.
    ///
    /// [`to_bytes_with_handled`]: Self::to_bytes_with_handled
    pub fn from_bytes_with_handled(data: &[u8]) -> Option<Self> {
        let (
            dest_hash_vec,
            last_sync,
            unreachable_count,
            peering_cost,
            stamp_cost,
            stamp_cost_flexibility,
            autopeered,
            is_static,
            handled_vec,
        ): StoredPeer = rmp_serde::from_slice(data).ok()?;
        if dest_hash_vec.len() != 16 {
            return None;
        }
        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(&dest_hash_vec);
        let mut peer = Self::new(dest_hash);
        peer.last_sync = last_sync;
        peer.unreachable_count = unreachable_count;
        peer.peering_cost = peering_cost;
        peer.stamp_cost = stamp_cost;
        peer.stamp_cost_flexibility = stamp_cost_flexibility;
        peer.autopeered = autopeered;
        peer.is_static = is_static;
        peer.handled_messages = handled_vec
            .into_iter()
            .filter_map(|v| {
                if v.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    Some(arr)
                } else {
                    None
                }
            })
            .collect();
        Some(peer)
    }

    pub fn mark_unreachable(&mut self) {
        self.unreachable_count += 1;
        let now = now_f64();
        if now - self.last_heard > MAX_UNREACHABLE as f64 {
            self.alive = false;
        }
    }

    pub fn should_sync(&self) -> bool {
        if self.state != PeerState::Idle {
            return false;
        }

        let now = now_f64();
        now > self.next_sync_attempt
    }

    pub fn sync_backoff(&self) -> f64 {
        self.sync_backoff
    }

    /// Peers unseen for [`PEER_STALE_TIME`] are stale and should be rotated to the back of the queue.
    pub fn is_stale(&self) -> bool {
        let now = now_f64();
        now - self.last_heard > PEER_STALE_TIME as f64
    }

    /// Whether the peering key has been generated and meets [`Self::peering_cost`].
    pub fn peering_key_ready(&self) -> bool {
        if let Some((_, value)) = self.peering_key {
            value >= self.peering_cost as u32
        } else {
            false
        }
    }

    /// Peering-key value (leading zero bits), if generated.
    pub fn peering_key_value(&self) -> Option<u32> {
        self.peering_key.map(|(_, value)| value)
    }

    /// Generate a peering key for this peer.
    ///
    /// Key material is `peer_identity_hash || our_identity_hash` (16 + 16 bytes), run through the
    /// stamp PoW system with [`STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING`] expand rounds.
    ///
    /// Python reference: `LXMPeer.generate_peering_key` — LXMPeer.py:242-265.
    pub fn generate_peering_key(
        &mut self,
        peer_identity_hash: &[u8; 16],
        our_identity_hash: &[u8; 16],
    ) -> bool {
        if self.peering_key.is_some() {
            return true;
        }

        let mut key_material = Vec::with_capacity(32);
        key_material.extend_from_slice(peer_identity_hash);
        key_material.extend_from_slice(our_identity_hash);

        // Bounded search (stamper::stamp_iteration_cap): an announce-supplied
        // hostile peering_cost can no longer pin this thread forever.
        match crate::stamper::generate_stamp(
            &key_material,
            self.peering_cost,
            crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING,
        ) {
            Some((stamp, value)) => {
                self.peering_key = Some((stamp, value));
                true
            }
            None => false,
        }
    }

    /// Acceptance rate (`outgoing / offered`), used for peer rotation decisions. Returns 0.0 if
    /// the peer has not yet been offered any messages.
    pub fn acceptance_rate(&self) -> f64 {
        if self.offered == 0 {
            0.0
        } else {
            self.outgoing as f64 / self.offered as f64
        }
    }

    pub fn begin_sync(&mut self) {
        self.state = PeerState::LinkEstablishing;
        self.last_sync_attempt = now_f64();
        self.sync_backoff += SYNC_BACKOFF_STEP as f64;
        self.next_sync_attempt = now_f64() + self.sync_backoff;
    }

    /// Link-established callback.
    ///
    /// Records the establishment rate, transitions to [`PeerState::LinkReady`], resets
    /// `next_sync_attempt` so sync can proceed immediately, updates `last_heard`, and marks the
    /// peer alive.
    ///
    /// Python reference: LXMPeer.py:530-538.
    pub fn link_established(&mut self, _link_id: [u8; 16], establishment_rate: Option<f64>) {
        if let Some(rate) = establishment_rate {
            self.link_establishment_rate = rate;
        }
        self.state = PeerState::LinkReady;
        self.next_sync_attempt = 0.0;
        self.last_heard = now_f64();
        self.alive = true;
        self.link_alive = true;
    }

    /// Link-closed callback: clears the link and transitions to [`PeerState::Idle`].
    ///
    /// If the peer was mid-sync, the in-flight transfer list is cleared so backoff logic
    /// treats it as a sync failure.
    ///
    /// Python reference: LXMPeer.py:540-542.
    pub fn link_closed(&mut self) {
        let was_active = self.state != PeerState::Idle;
        self.link_alive = false;
        self.state = PeerState::Idle;

        if was_active {
            self.currently_transferring_messages = None;
        }
    }

    pub fn sync_complete(&mut self) {
        self.state = PeerState::Idle;
        self.last_sync = now_f64();
        self.currently_transferring_messages = None;
        self.sync_backoff = 0.0;
        self.next_sync_attempt = 0.0;
    }

    pub fn sync_failed(&mut self) {
        self.state = PeerState::Idle;
        self.mark_unreachable();
        self.currently_transferring_messages = None;
    }
}

/// Select the best peer to sync with from a set of candidates.
///
/// Mirrors Python `sync_peers()`: draw from the fastest [`FASTEST_N_RANDOM_POOL`] alive peers,
/// mix in unknown-speed peers, and fall back to unresponsive peers that have passed their sync
/// backoff.
pub fn select_sync_peer(peers: &[&LxmPeer]) -> Option<usize> {
    if peers.is_empty() {
        return None;
    }

    let mut alive_with_unhandled: Vec<(usize, &LxmPeer)> = peers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.alive && p.state == PeerState::Idle && p.unhandled_messages() > 0)
        .map(|(i, p)| (i, *p))
        .collect();

    if !alive_with_unhandled.is_empty() {
        alive_with_unhandled.sort_by(|a, b| {
            b.1.sync_transfer_rate
                .partial_cmp(&a.1.sync_transfer_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let pool_size = alive_with_unhandled.len().min(FASTEST_N_RANDOM_POOL);

        let unknown_speed: Vec<(usize, &LxmPeer)> = alive_with_unhandled
            .iter()
            .filter(|(_, p)| p.sync_transfer_rate == 0.0)
            .copied()
            .collect();

        let mut pool: Vec<usize> = alive_with_unhandled[..pool_size]
            .iter()
            .map(|(i, _)| *i)
            .collect();
        for (i, _) in unknown_speed.iter().take(pool_size) {
            if !pool.contains(i) {
                pool.push(*i);
            }
        }

        // Deterministic first-of-pool pick; callers that want randomization do it themselves.
        return pool.into_iter().next();
    }

    let unresponsive: Vec<(usize, &LxmPeer)> = peers
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            !p.alive && p.state == PeerState::Idle && p.unhandled_messages() > 0 && p.should_sync()
        })
        .map(|(i, p)| (i, *p))
        .collect();

    unresponsive.first().map(|(i, _)| *i)
}

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(byte: u8) -> PropagationTransientId {
        [byte; 32]
    }

    #[test]
    fn test_new_peer() {
        let peer = LxmPeer::new([0xAA; 16]);
        assert_eq!(peer.state, PeerState::Idle);
        assert_eq!(peer.sync_strategy, SyncStrategy::Persistent);
        assert!(peer.alive);
        assert_eq!(peer.unreachable_count, 0);
    }

    #[test]
    fn test_minimum_stamp_cost() {
        let mut peer = LxmPeer::new([0; 16]);
        assert_eq!(peer.minimum_accepted_stamp_cost(), 0);

        peer.stamp_cost = Some(16);
        assert_eq!(peer.minimum_accepted_stamp_cost(), 13);

        // cost < flex must saturate at 0.
        peer.stamp_cost = Some(2);
        assert_eq!(peer.minimum_accepted_stamp_cost(), 0);
    }

    /// T0-4: an absurd announce-supplied peering cost must fail the bounded
    /// key search instead of spinning forever; sane costs still succeed.
    #[test]
    fn test_generate_peering_key_capped() {
        let mut peer = LxmPeer::new([0xAA; 16]);
        peer.peering_cost = 255;
        assert!(!peer.generate_peering_key(&[0xBB; 16], &[0xCC; 16]));
        assert!(peer.peering_key.is_none());

        peer.peering_cost = 4;
        assert!(peer.generate_peering_key(&[0xBB; 16], &[0xCC; 16]));
        assert!(peer.peering_key.is_some());
    }

    #[test]
    fn test_mark_unreachable() {
        let mut peer = LxmPeer::new([0; 16]);
        peer.last_heard = 0.0;
        peer.mark_unreachable();
        assert!(!peer.alive);
    }

    #[test]
    fn test_heard_resets_unreachable() {
        let mut peer = LxmPeer::new([0; 16]);
        peer.unreachable_count = 2;

        peer.heard();
        assert_eq!(peer.unreachable_count, 0);
        assert!(peer.alive);
        assert_eq!(peer.sync_backoff, 0.0);
    }

    #[test]
    fn test_sync_lifecycle() {
        let mut peer = LxmPeer::new([0; 16]);
        assert!(peer.should_sync());

        peer.begin_sync();
        assert_eq!(peer.state, PeerState::LinkEstablishing);
        assert!(!peer.should_sync());

        peer.sync_complete();
        assert_eq!(peer.state, PeerState::Idle);
    }

    #[test]
    fn test_sync_failed() {
        let mut peer = LxmPeer::new([0; 16]);
        peer.begin_sync();
        peer.last_heard = 0.0;
        peer.sync_failed();
        assert_eq!(peer.state, PeerState::Idle);
        assert_eq!(peer.unreachable_count, 1);
    }

    #[test]
    fn test_currently_transferring() {
        let mut peer = LxmPeer::new([0; 16]);
        assert!(peer.currently_transferring_messages.is_none());

        peer.currently_transferring_messages = Some(vec![tid(0xAA), tid(0xBB)]);
        assert_eq!(
            peer.currently_transferring_messages.as_ref().unwrap().len(),
            2
        );

        peer.sync_complete();
        assert!(peer.currently_transferring_messages.is_none());
    }

    #[test]
    fn test_add_unhandled() {
        let mut peer = LxmPeer::new([0; 16]);
        assert_eq!(peer.unhandled_messages(), 0);

        peer.add_unhandled_message();
        peer.add_unhandled_message();
        assert_eq!(peer.unhandled_messages(), 2);
    }

    #[test]
    fn test_from_announce() {
        let peer = LxmPeer::from_announce(
            [0xAA; 16],
            1000.0,
            Some(256.0),
            Some(10240.0),
            Some(16),
            Some(3),
            Some(18),
        );
        assert_eq!(peer.peering_timebase, 1000.0);
        assert_eq!(peer.propagation_transfer_limit, Some(256.0));
        assert_eq!(peer.propagation_sync_limit, Some(10240.0));
        assert_eq!(peer.stamp_cost, Some(16));
        assert_eq!(peer.stamp_cost_flexibility, Some(3));
        assert_eq!(peer.peering_cost, 18);
        assert!(peer.autopeered);
    }

    #[test]
    fn test_acceptance_rate() {
        let mut peer = LxmPeer::new([0; 16]);
        assert_eq!(peer.acceptance_rate(), 0.0);

        peer.offered = 10;
        peer.outgoing = 5;
        assert!((peer.acceptance_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_stamp_costs_known() {
        let mut peer = LxmPeer::new([0; 16]);
        assert!(!peer.stamp_costs_known());

        peer.stamp_cost = Some(16);
        assert!(!peer.stamp_costs_known());

        peer.stamp_cost_flexibility = Some(3);
        assert!(peer.stamp_costs_known());
    }

    #[test]
    fn test_select_sync_peer_basic() {
        let mut peer1 = LxmPeer::new([0x01; 16]);
        peer1.add_unhandled_message();
        peer1.sync_transfer_rate = 100.0;

        let mut peer2 = LxmPeer::new([0x02; 16]);
        peer2.add_unhandled_message();
        peer2.sync_transfer_rate = 200.0;

        let peers: Vec<&LxmPeer> = vec![&peer1, &peer2];
        let selected = select_sync_peer(&peers);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap(), 1);
    }

    #[test]
    fn test_select_sync_peer_empty() {
        let peers: Vec<&LxmPeer> = vec![];
        assert!(select_sync_peer(&peers).is_none());
    }

    #[test]
    fn test_select_sync_peer_no_unhandled() {
        let peer = LxmPeer::new([0x01; 16]);
        let peers: Vec<&LxmPeer> = vec![&peer];
        assert!(select_sync_peer(&peers).is_none());
    }

    #[test]
    fn test_begin_sync_sets_backoff() {
        let mut peer = LxmPeer::new([0; 16]);
        assert_eq!(peer.sync_backoff, 0.0);

        peer.begin_sync();
        assert_eq!(peer.sync_backoff, SYNC_BACKOFF_STEP as f64);

        peer.state = PeerState::Idle;
        peer.begin_sync();
        assert_eq!(peer.sync_backoff, 2.0 * SYNC_BACKOFF_STEP as f64);
    }

    #[test]
    fn test_link_established() {
        let mut peer = LxmPeer::new([0xAA; 16]);
        peer.begin_sync();
        assert_eq!(peer.state, PeerState::LinkEstablishing);

        let link_id = [0xBB; 16];
        peer.link_established(link_id, Some(42.0));

        assert_eq!(peer.state, PeerState::LinkReady);
        assert!(peer.alive);
        assert!(peer.link_alive);
        assert_eq!(peer.link_establishment_rate, 42.0);
        assert_eq!(peer.next_sync_attempt, 0.0);
        assert!(peer.last_heard > 0.0);
    }

    #[test]
    fn test_link_established_no_rate() {
        let mut peer = LxmPeer::new([0xAA; 16]);
        peer.begin_sync();
        let original_rate = peer.link_establishment_rate;

        peer.link_established([0xBB; 16], None);

        assert_eq!(peer.state, PeerState::LinkReady);
        assert_eq!(peer.link_establishment_rate, original_rate);
    }

    #[test]
    fn test_link_closed_from_idle() {
        let mut peer = LxmPeer::new([0xAA; 16]);
        peer.link_alive = true;

        peer.link_closed();

        assert_eq!(peer.state, PeerState::Idle);
        assert!(!peer.link_alive);
    }

    #[test]
    fn test_link_closed_during_sync() {
        let mut peer = LxmPeer::new([0xAA; 16]);
        peer.begin_sync();
        peer.link_established([0xBB; 16], Some(10.0));
        peer.currently_transferring_messages = Some(vec![tid(0x01), tid(0x02)]);

        peer.link_closed();

        assert_eq!(peer.state, PeerState::Idle);
        assert!(!peer.link_alive);
        assert!(peer.currently_transferring_messages.is_none());
    }

    #[test]
    fn test_link_lifecycle_full_cycle() {
        let mut peer = LxmPeer::new([0xAA; 16]);

        peer.begin_sync();
        assert_eq!(peer.state, PeerState::LinkEstablishing);

        peer.link_established([0xBB; 16], Some(100.0));
        assert_eq!(peer.state, PeerState::LinkReady);
        assert!(peer.alive);

        peer.sync_complete();
        assert_eq!(peer.state, PeerState::Idle);

        peer.link_closed();
        assert_eq!(peer.state, PeerState::Idle);
        assert!(!peer.link_alive);
    }
}
