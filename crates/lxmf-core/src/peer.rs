//! LXMF peer propagation node used for store-and-forward sync.
//!
//! Python reference: LXMF/LXMPeer.py.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::constants::*;
use crate::types::PropagationTransientId;

type LegacyStoredPeer = (
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

const STORED_PEER_VERSION: u8 = 2;
const MAX_PEER_METADATA_ENTRIES: usize = 16;
const MAX_PEER_METADATA_VALUE_BYTES: usize = 1024;
const MAX_PEER_METADATA_BYTES: usize = 4096;

fn bounded_peer_metadata(metadata: Option<HashMap<u8, Vec<u8>>>) -> Option<HashMap<u8, Vec<u8>>> {
    let metadata = metadata?;
    let mut entries = metadata.into_iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| *key);

    let mut retained = HashMap::new();
    let mut retained_bytes = 0usize;
    for (key, value) in entries.into_iter().take(MAX_PEER_METADATA_ENTRIES) {
        if value.len() > MAX_PEER_METADATA_VALUE_BYTES {
            continue;
        }
        let entry_bytes = 1usize.saturating_add(value.len());
        if retained_bytes.saturating_add(entry_bytes) > MAX_PEER_METADATA_BYTES {
            continue;
        }
        retained_bytes += entry_bytes;
        retained.insert(key, value);
    }

    Some(retained)
}

/// Versioned peer persistence used by propagation sync.
///
/// The original Rust format was a nine-element tuple. Readers continue to
/// accept that tuple, while new writes retain the announce-derived policy
/// needed to prepare a correct outbound offer after restart.
#[derive(Debug, Serialize, Deserialize)]
struct StoredPeerV2 {
    version: u8,
    destination_hash: Vec<u8>,
    last_sync: f64,
    unreachable_count: u32,
    peering_cost: u8,
    stamp_cost: Option<u8>,
    stamp_cost_flexibility: Option<u8>,
    autopeered: bool,
    is_static: bool,
    handled_ids: Vec<Vec<u8>>,
    peering_timebase: f64,
    propagation_transfer_limit: Option<f64>,
    propagation_sync_limit: Option<f64>,
    peering_key: Option<(Vec<u8>, u32)>,
    metadata: Option<HashMap<u8, Vec<u8>>>,
    last_heard: f64,
    alive: bool,
}

/// Immutable inputs for one outbound propagation offer.
///
/// `LxmPeer` remains the authoritative mutable owner. The network task gets a
/// clone of this snapshot so offer selection cannot silently fall back to a
/// newly-created peer that lacks announce or handled-message state.
#[derive(Debug, Clone, PartialEq)]
pub struct OutboundOfferPolicy {
    pub peer_hash: [u8; 16],
    pub handled_messages: HashSet<PropagationTransientId>,
    pub stamp_cost: Option<u8>,
    pub stamp_cost_flexibility: Option<u8>,
    pub minimum_stamp_cost: u8,
    pub peering_cost: u8,
    pub propagation_transfer_limit: Option<f64>,
    pub propagation_sync_limit: Option<f64>,
    pub peering_key: Vec<u8>,
    pub peering_key_value: Option<u32>,
    pub peering_timebase: f64,
    pub autopeered: bool,
    pub is_static: bool,
    pub metadata: Option<HashMap<u8, Vec<u8>>>,
}

impl OutboundOfferPolicy {
    /// Compatibility policy for callers that only know a peer hash.
    ///
    /// This preserves the old unbounded selection behavior. Production
    /// callers should construct a snapshot from the authoritative `LxmPeer`.
    pub fn unrestricted(peer_hash: [u8; 16]) -> Self {
        Self {
            peer_hash,
            handled_messages: HashSet::new(),
            stamp_cost: None,
            stamp_cost_flexibility: None,
            minimum_stamp_cost: 0,
            peering_cost: PEERING_COST,
            propagation_transfer_limit: None,
            propagation_sync_limit: None,
            peering_key: Vec::new(),
            peering_key_value: None,
            peering_timebase: 0.0,
            autopeered: false,
            is_static: false,
            metadata: None,
        }
    }

    pub(crate) fn to_peer(&self) -> LxmPeer {
        let mut peer = LxmPeer::new(self.peer_hash);
        self.apply_to_peer(&mut peer);
        peer
    }

    pub(crate) fn apply_to_peer(&self, peer: &mut LxmPeer) {
        if self.peering_timebase >= peer.peering_timebase {
            peer.peering_timebase = self.peering_timebase;
            peer.stamp_cost = self.stamp_cost;
            peer.stamp_cost_flexibility = self.stamp_cost_flexibility;
            peer.peering_cost = self.peering_cost;
            peer.propagation_transfer_limit = self.propagation_transfer_limit;
            peer.propagation_sync_limit = self.propagation_sync_limit;
            peer.peering_key = self.peering_key_value.and_then(|value| {
                let stamp: [u8; 32] = self.peering_key.clone().try_into().ok()?;
                Some((stamp, value))
            });
            peer.autopeered = self.autopeered;
            peer.is_static = self.is_static;
            peer.metadata = self.metadata.clone();
        }
        peer.handled_messages
            .extend(self.handled_messages.iter().copied());
    }
}

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
    pub metadata: Option<HashMap<u8, Vec<u8>>>,
    /// Last local propagation-store revision conclusively processed by this
    /// peer. This is intentionally process-local because node revisions reset
    /// when the store is reconstructed at startup.
    pub last_offer_generation: u64,
    /// Static peers are operator-configured; autopeered peers come from announces.
    pub is_static: bool,
    /// Message hashes already handled by this peer, for sync filtering.
    pub handled_messages: HashSet<PropagationTransientId>,
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
            last_offer_generation: 0,
            is_static: false,
            handled_messages: HashSet::new(),
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
        Self::from_announce_with_metadata(
            destination_hash,
            timebase,
            transfer_limit,
            sync_limit,
            stamp_cost,
            stamp_flexibility,
            peering_cost,
            None,
        )
    }

    /// Construct a peer from announce data, retaining bounded metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn from_announce_with_metadata(
        destination_hash: [u8; 16],
        timebase: f64,
        transfer_limit: Option<f64>,
        sync_limit: Option<f64>,
        stamp_cost: Option<u8>,
        stamp_flexibility: Option<u8>,
        peering_cost: Option<u8>,
        metadata: Option<HashMap<u8, Vec<u8>>>,
    ) -> Self {
        let mut peer = Self::new(destination_hash);
        peer.peering_timebase = timebase;
        peer.propagation_transfer_limit = transfer_limit;
        peer.propagation_sync_limit = sync_limit.or(transfer_limit);
        peer.stamp_cost = stamp_cost;
        peer.stamp_cost_flexibility = stamp_flexibility;
        peer.peering_cost = peering_cost.unwrap_or(PEERING_COST);
        peer.metadata = bounded_peer_metadata(metadata);
        peer.autopeered = true;
        peer
    }

    /// Refresh announce-derived policy only when `timebase` is newer.
    ///
    /// Returns `true` when the peer was updated. Runtime counters, handled
    /// messages and static-peer status remain owned by the existing peer.
    #[allow(clippy::too_many_arguments)]
    pub fn refresh_from_announce(
        &mut self,
        timebase: f64,
        transfer_limit: Option<f64>,
        sync_limit: Option<f64>,
        stamp_cost: Option<u8>,
        stamp_flexibility: Option<u8>,
        peering_cost: Option<u8>,
    ) -> bool {
        let metadata = self.metadata.clone();
        self.refresh_from_announce_with_metadata(
            timebase,
            transfer_limit,
            sync_limit,
            stamp_cost,
            stamp_flexibility,
            peering_cost,
            metadata,
        )
    }

    /// Refresh announce-derived policy and bounded metadata only when newer.
    #[allow(clippy::too_many_arguments)]
    pub fn refresh_from_announce_with_metadata(
        &mut self,
        timebase: f64,
        transfer_limit: Option<f64>,
        sync_limit: Option<f64>,
        stamp_cost: Option<u8>,
        stamp_flexibility: Option<u8>,
        peering_cost: Option<u8>,
        metadata: Option<HashMap<u8, Vec<u8>>>,
    ) -> bool {
        if timebase <= self.peering_timebase {
            return false;
        }

        let offer_constraints_changed = self.propagation_transfer_limit != transfer_limit
            || self.propagation_sync_limit != sync_limit.or(transfer_limit)
            || self.stamp_cost != stamp_cost
            || self.stamp_cost_flexibility != stamp_flexibility
            || self.peering_cost != peering_cost.unwrap_or(PEERING_COST);
        self.peering_timebase = timebase;
        self.propagation_transfer_limit = transfer_limit;
        self.propagation_sync_limit = sync_limit.or(transfer_limit);
        self.stamp_cost = stamp_cost;
        self.stamp_cost_flexibility = stamp_flexibility;
        self.peering_cost = peering_cost.unwrap_or(PEERING_COST);
        self.metadata = bounded_peer_metadata(metadata);
        if offer_constraints_changed {
            self.last_offer_generation = 0;
        }

        // A key remains usable when it still meets the new target. Otherwise
        // the daemon must generate a replacement before taking a snapshot.
        if self
            .peering_key
            .is_some_and(|(_, value)| value < self.peering_cost as u32)
        {
            self.peering_key = None;
        }

        self.heard();
        self.next_sync_attempt = 0.0;
        true
    }

    /// Effective minimum stamp cost this peer will accept, using the peer's
    /// announced flexibility when known (Python `LXMPeer.sync`: cost - flex).
    pub fn minimum_accepted_stamp_cost(&self) -> u8 {
        match self.stamp_cost {
            Some(cost) => {
                cost.saturating_sub(self.stamp_cost_flexibility.unwrap_or(PROPAGATION_COST_FLEX))
            }
            None => 0,
        }
    }

    pub fn stamp_costs_known(&self) -> bool {
        self.stamp_cost.is_some() && self.stamp_cost_flexibility.is_some()
    }

    /// Snapshot the complete immutable policy for one outbound sync offer.
    pub fn outbound_offer_policy(&self) -> OutboundOfferPolicy {
        OutboundOfferPolicy::from(self)
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

    pub fn needs_offer_generation(&self, generation: u64) -> bool {
        generation > self.last_offer_generation
    }

    pub fn mark_offer_generation_processed(&mut self, generation: u64) {
        self.last_offer_generation = self.last_offer_generation.max(generation);
    }

    /// Serialize peer state, including handled messages, for persistence.
    pub fn to_bytes_with_handled(&self) -> Vec<u8> {
        let mut handled: Vec<Vec<u8>> = self.handled_messages.iter().map(|h| h.to_vec()).collect();
        handled.sort();
        let data = StoredPeerV2 {
            version: STORED_PEER_VERSION,
            destination_hash: self.destination_hash.to_vec(),
            last_sync: self.last_sync,
            unreachable_count: self.unreachable_count,
            peering_cost: self.peering_cost,
            stamp_cost: self.stamp_cost,
            stamp_cost_flexibility: self.stamp_cost_flexibility,
            autopeered: self.autopeered,
            is_static: self.is_static,
            handled_ids: handled,
            peering_timebase: self.peering_timebase,
            propagation_transfer_limit: self.propagation_transfer_limit,
            propagation_sync_limit: self.propagation_sync_limit,
            peering_key: self
                .peering_key
                .map(|(stamp, value)| (stamp.to_vec(), value)),
            metadata: self.metadata.clone(),
            last_heard: self.last_heard,
            alive: self.alive,
        };
        rmp_serde::to_vec_named(&data).unwrap_or_default()
    }

    /// Deserialize peer state, including handled messages, from [`to_bytes_with_handled`] output.
    ///
    /// [`to_bytes_with_handled`]: Self::to_bytes_with_handled
    pub fn from_bytes_with_handled(data: &[u8]) -> Option<Self> {
        if let Ok(stored) = rmp_serde::from_slice::<StoredPeerV2>(data) {
            return Self::from_stored_v2(stored);
        }

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
        ): LegacyStoredPeer = rmp_serde::from_slice(data).ok()?;
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

    fn from_stored_v2(stored: StoredPeerV2) -> Option<Self> {
        if stored.version != STORED_PEER_VERSION || stored.destination_hash.len() != 16 {
            return None;
        }

        let mut destination_hash = [0u8; 16];
        destination_hash.copy_from_slice(&stored.destination_hash);
        let mut peer = Self::new(destination_hash);
        peer.last_sync = stored.last_sync;
        peer.unreachable_count = stored.unreachable_count;
        peer.peering_cost = stored.peering_cost;
        peer.stamp_cost = stored.stamp_cost;
        peer.stamp_cost_flexibility = stored.stamp_cost_flexibility;
        peer.autopeered = stored.autopeered;
        peer.is_static = stored.is_static;
        peer.peering_timebase = stored.peering_timebase;
        peer.propagation_transfer_limit = stored.propagation_transfer_limit;
        peer.propagation_sync_limit = stored.propagation_sync_limit;
        peer.peering_key = stored.peering_key.and_then(|(stamp, value)| {
            let stamp: [u8; 32] = stamp.try_into().ok()?;
            Some((stamp, value))
        });
        peer.metadata = stored.metadata;
        peer.last_heard = stored.last_heard;
        peer.alive = stored.alive;
        peer.handled_messages = stored
            .handled_ids
            .into_iter()
            .filter_map(|value| value.try_into().ok())
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

impl From<&LxmPeer> for OutboundOfferPolicy {
    fn from(peer: &LxmPeer) -> Self {
        let peering_key = peer
            .peering_key
            .filter(|(_, value)| *value >= peer.peering_cost as u32)
            .map(|(stamp, _)| stamp.to_vec())
            .unwrap_or_default();
        Self {
            peer_hash: peer.destination_hash,
            handled_messages: peer.handled_messages.clone(),
            stamp_cost: peer.stamp_cost,
            stamp_cost_flexibility: peer.stamp_cost_flexibility,
            minimum_stamp_cost: peer.minimum_accepted_stamp_cost(),
            peering_cost: peer.peering_cost,
            propagation_transfer_limit: peer.propagation_transfer_limit,
            propagation_sync_limit: peer.propagation_sync_limit,
            peering_key,
            peering_key_value: peer.peering_key.map(|(_, value)| value),
            peering_timebase: peer.peering_timebase,
            autopeered: peer.autopeered,
            is_static: peer.is_static,
            metadata: peer.metadata.clone(),
        }
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

        // Announced flexibility overrides the default.
        peer.stamp_cost = Some(16);
        peer.stamp_cost_flexibility = Some(5);
        assert_eq!(peer.minimum_accepted_stamp_cost(), 11);
        peer.stamp_cost_flexibility = Some(0);
        assert_eq!(peer.minimum_accepted_stamp_cost(), 16);
    }

    #[test]
    fn outbound_offer_policy_captures_authoritative_peer_state() {
        let mut peer = LxmPeer::new([0xAA; 16]);
        peer.stamp_cost = Some(16);
        peer.stamp_cost_flexibility = Some(3);
        peer.propagation_transfer_limit = Some(1.5);
        peer.propagation_sync_limit = Some(4.5);
        peer.peering_cost = 18;
        peer.peering_key = Some(([0x77; 32], 18));
        peer.add_handled_message(&tid(0x11));

        let policy = peer.outbound_offer_policy();

        assert_eq!(policy.peer_hash, [0xAA; 16]);
        assert_eq!(policy.minimum_stamp_cost, 13);
        assert_eq!(policy.propagation_transfer_limit, Some(1.5));
        assert_eq!(policy.propagation_sync_limit, Some(4.5));
        assert_eq!(policy.peering_key, vec![0x77; 32]);
        assert!(policy.handled_messages.contains(&tid(0x11)));
    }

    #[test]
    fn stale_announce_cannot_overwrite_newer_peer_policy() {
        let mut peer = LxmPeer::from_announce(
            [0xAA; 16],
            200.0,
            Some(2.0),
            Some(8.0),
            Some(16),
            Some(3),
            Some(18),
        );

        assert!(!peer.refresh_from_announce(
            199.0,
            Some(1.0),
            Some(4.0),
            Some(8),
            Some(1),
            Some(4),
        ));
        assert_eq!(peer.peering_timebase, 200.0);
        assert_eq!(peer.propagation_transfer_limit, Some(2.0));
        assert_eq!(peer.stamp_cost, Some(16));

        peer.peering_key = Some(([0x55; 32], 18));
        assert!(peer.refresh_from_announce(201.0, Some(3.0), None, Some(20), Some(4), Some(19),));
        assert_eq!(peer.propagation_sync_limit, Some(3.0));
        assert_eq!(peer.stamp_cost, Some(20));
        assert!(peer.peering_key.is_none(), "under-cost key must be cleared");
    }

    #[test]
    fn peer_persistence_retains_offer_policy_and_reads_legacy_tuple() {
        let mut peer = LxmPeer::from_announce(
            [0xAA; 16],
            1234.0,
            Some(1.25),
            Some(9.5),
            Some(16),
            Some(3),
            Some(18),
        );
        peer.peering_key = Some(([0x66; 32], 19));
        peer.metadata = Some(HashMap::from([(0, vec![1, 2, 3])]));
        peer.add_handled_message(&tid(0x22));

        let restored = LxmPeer::from_bytes_with_handled(&peer.to_bytes_with_handled()).unwrap();
        assert_eq!(restored.peering_timebase, 1234.0);
        assert_eq!(restored.propagation_transfer_limit, Some(1.25));
        assert_eq!(restored.propagation_sync_limit, Some(9.5));
        assert_eq!(restored.peering_key, Some(([0x66; 32], 19)));
        assert_eq!(restored.metadata, Some(HashMap::from([(0, vec![1, 2, 3])])));
        assert!(restored.has_handled(&tid(0x22)));

        let legacy: LegacyStoredPeer = (
            vec![0xBB; 16],
            42.0,
            2,
            18,
            Some(12),
            Some(2),
            true,
            false,
            vec![tid(0x33).to_vec()],
        );
        let legacy_bytes = rmp_serde::to_vec(&legacy).unwrap();
        let restored_legacy = LxmPeer::from_bytes_with_handled(&legacy_bytes).unwrap();
        assert_eq!(restored_legacy.destination_hash, [0xBB; 16]);
        assert_eq!(restored_legacy.stamp_cost, Some(12));
        assert!(restored_legacy.has_handled(&tid(0x33)));
    }

    #[test]
    fn announce_metadata_is_typed_bounded_and_persisted() {
        let mut metadata = HashMap::new();
        metadata.insert(0, b"node name".to_vec());
        metadata.insert(1, vec![0xAA; MAX_PEER_METADATA_VALUE_BYTES + 1]);
        for key in 2..=30 {
            metadata.insert(key, vec![key; 8]);
        }

        let peer = LxmPeer::from_announce_with_metadata(
            [0xAA; 16],
            10.0,
            Some(1.0),
            Some(2.0),
            Some(12),
            Some(3),
            Some(18),
            Some(metadata),
        );
        let retained = peer.metadata.as_ref().unwrap();
        assert_eq!(retained.get(&0), Some(&b"node name".to_vec()));
        assert!(!retained.contains_key(&1));
        assert!(retained.len() <= MAX_PEER_METADATA_ENTRIES);

        let restored = LxmPeer::from_bytes_with_handled(&peer.to_bytes_with_handled()).unwrap();
        assert_eq!(restored.metadata, peer.metadata);

        let empty = LxmPeer::from_announce_with_metadata(
            [0xBB; 16],
            10.0,
            None,
            None,
            None,
            None,
            None,
            Some(HashMap::new()),
        );
        assert_eq!(empty.metadata, Some(HashMap::new()));
    }

    #[test]
    fn newer_policy_invalidates_processed_store_generation() {
        let mut peer =
            LxmPeer::from_announce([0xAA; 16], 10.0, None, None, Some(16), Some(3), None);
        peer.mark_offer_generation_processed(7);
        assert!(!peer.needs_offer_generation(7));

        assert!(peer.refresh_from_announce(11.0, None, None, Some(12), Some(3), None));
        assert!(peer.needs_offer_generation(7));

        peer.mark_offer_generation_processed(7);
        assert!(peer.refresh_from_announce(12.0, None, None, Some(12), Some(3), None));
        assert!(
            !peer.needs_offer_generation(7),
            "a newer announce with unchanged offer constraints must not rescan an unchanged store"
        );
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
