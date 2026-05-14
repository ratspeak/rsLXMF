//! Store-and-forward propagation node with optional disk persistence.
//!
//! Mirrors propagation node management in Python LXMRouter.py. Provides
//! message acceptance with size/duplicate checks, sync offer generation with
//! per-peer filtering, peer persistence (save/load with handled message sets),
//! and expired message culling with orphaned file cleanup.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::constants::*;
use crate::message::LxMessage;
use crate::peer::LxmPeer;
use crate::propagation::{PropagationEntry, PropagationStore, hex_encode};
use crate::sync::{OfferResponse, SyncGet, SyncOffer, SyncSession};
use crate::types::PropagationTransientId;

#[derive(Debug, Clone)]
pub struct PropagationNodeConfig {
    pub max_storage: usize,
    pub max_message_age: u64,
    /// Messages below this effective stamp value are rejected. Python derives
    /// this from `propagation_stamp_cost - propagation_stamp_cost_flexibility`.
    pub min_stamp_cost: u8,
    pub peering_cost: u8,
    pub max_message_size: usize,
}

impl Default for PropagationNodeConfig {
    fn default() -> Self {
        Self {
            max_storage: PROPAGATION_LIMIT * 1024 * 1024,
            max_message_age: MESSAGE_EXPIRY,
            // Disabled by default; set to PROPAGATION_COST for production.
            min_stamp_cost: 0,
            peering_cost: PEERING_COST,
            max_message_size: DELIVERY_LIMIT * 1024,
        }
    }
}

pub struct PropagationNode {
    config: PropagationNodeConfig,
    store: PropagationStore,
    sync_sessions: HashMap<[u8; 16], SyncSession>,
    pub dest_hash: [u8; 16],
    storage_path: Option<PathBuf>,
    /// Per-peer last offer time, for rate-limiting.
    last_offer_times: HashMap<[u8; 16], f64>,
}

impl PropagationNode {
    /// In-memory node (no disk persistence).
    pub fn new(config: PropagationNodeConfig, dest_hash: [u8; 16]) -> Self {
        Self {
            config,
            store: PropagationStore::new(),
            sync_sessions: HashMap::new(),
            dest_hash,
            storage_path: None,
            last_offer_times: HashMap::new(),
        }
    }

    pub fn min_stamp_cost(&self) -> u8 {
        self.config.min_stamp_cost
    }

    pub fn set_min_stamp_cost(&mut self, cost: u8) {
        self.config.min_stamp_cost = cost;
    }

    /// Disk-backed node. Loads existing messages from `storage_path` on startup.
    pub fn with_storage(
        config: PropagationNodeConfig,
        dest_hash: [u8; 16],
        storage_path: PathBuf,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(&storage_path)?;
        let mut node = Self {
            config,
            store: PropagationStore::new(),
            sync_sessions: HashMap::new(),
            dest_hash,
            storage_path: Some(storage_path),
            last_offer_times: HashMap::new(),
        };
        node.load_from_disk()?;
        Ok(node)
    }

    /// Returns `true` if the message was stored, `false` on duplicate, overflow,
    /// pack failure, oversized message, or insufficient stamp.
    #[tracing::instrument(
        level = "debug",
        name = "propagation.accept_message",
        skip_all,
        fields(
            transient_id = message.transient_id.as_ref().map(|tid| hex::encode(&tid[..8])),
            size = message.content.len(),
        ),
    )]
    pub fn accept_message(&mut self, message: &LxMessage) -> bool {
        let hash = match message.hash {
            Some(h) => h,
            None => return false,
        };

        let transient_id = message.transient_id.unwrap_or(hash);
        if self.store.contains(&transient_id) {
            return false;
        }
        if self.store.total_size() > self.config.max_storage {
            return false;
        }

        let packed = match message.pack() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let msg_size = packed.len();

        if msg_size > self.config.max_message_size {
            return false;
        }

        // Compute stamp value via HKDF workblock over full_hash(packed) using
        // PN expand rounds. Matches Python LXStamper.validate_pn_stamp().
        let sv = if let Some(ref stamp) = message.stamp {
            let transient_id_full = rns_crypto::sha::full_hash(&packed);
            let workblock = crate::stamper::stamp_workblock_raw(
                &transient_id_full,
                crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PN,
            );
            if let Ok(stamp) = <&[u8; 32]>::try_from(stamp.as_slice()) {
                crate::stamper::stamp_value_raw(&workblock, stamp) as u8
            } else {
                0
            }
        } else {
            0
        };

        if self.config.min_stamp_cost > 0 && sv < self.config.min_stamp_cost {
            return false;
        }

        let mut entry =
            PropagationEntry::new(transient_id, hash, message.destination_hash, msg_size, sv);
        entry.stored_at = message.timestamp;

        if let Some(ref dir) = self.storage_path {
            let path = dir.join(entry.filename());
            if let Err(e) = std::fs::write(&path, &packed) {
                // In-memory insert still proceeds on disk failure.
                tracing::warn!(error = %e, "failed to persist propagation message");
            }
        }

        self.store.insert(entry);
        true
    }

    /// Store an already propagation-packed LXMF blob (`dest_hash || encrypted_data`).
    ///
    /// This is the normal client -> propagation-node ingress path. Unlike
    /// [`Self::accept_message`], the node cannot decrypt or unpack this data;
    /// it indexes by the transient ID and serves the raw blob back to the
    /// destination client during `/get`.
    pub fn accept_propagated_blob(&mut self, lxmf_data: &[u8], stamp_value: u8) -> bool {
        if lxmf_data.len() < DESTINATION_LENGTH + 1 {
            return false;
        }
        if self.config.min_stamp_cost > 0 && stamp_value < self.config.min_stamp_cost {
            return false;
        }

        let transient_id = rns_crypto::sha::full_hash(lxmf_data);
        if self.store.contains(&transient_id) {
            return false;
        }
        if self.store.total_size() > self.config.max_storage {
            return false;
        }
        if lxmf_data.len() > self.config.max_message_size {
            return false;
        }

        let mut destination_hash = [0u8; 16];
        destination_hash.copy_from_slice(&lxmf_data[..DESTINATION_LENGTH]);

        let entry = PropagationEntry::new(
            transient_id,
            transient_id,
            destination_hash,
            lxmf_data.len(),
            stamp_value,
        );

        if let Some(ref dir) = self.storage_path {
            let path = dir.join(entry.filename());
            if let Err(e) = std::fs::write(&path, lxmf_data) {
                tracing::warn!(error = %e, "failed to persist propagated message");
            }
        }

        self.store.insert(entry)
    }

    fn load_from_disk(&mut self) -> std::io::Result<()> {
        let dir = match &self.storage_path {
            Some(d) => d,
            None => return Ok(()),
        };

        if !dir.exists() {
            return Ok(());
        }

        let mut loaded = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let filename = match path.file_name().and_then(|f| f.to_str()) {
                Some(f) => f.to_string(),
                None => continue,
            };

            if filename.ends_with(".peer") || filename.ends_with(".msgpack") {
                continue;
            }

            if let Some((tid, ts, sv)) = PropagationEntry::parse_filename(&filename) {
                let data = std::fs::read(&path)?;
                let size = data.len();

                if self.store.contains(&tid) {
                    continue;
                }

                let mut message_hash = [0u8; 32];
                message_hash.copy_from_slice(&rns_crypto::sha::full_hash(&data));

                // Opaque propagated blobs are stored as `dest_hash || encrypted_data`
                // and cannot be unpacked by the node. Recover the routing key from
                // the first 16 bytes before trying the legacy full-message path.
                let mut destination_hash = [0u8; 16];
                if data.len() >= DESTINATION_LENGTH {
                    destination_hash.copy_from_slice(&data[..DESTINATION_LENGTH]);
                }

                let mut pe = PropagationEntry::new(tid, message_hash, destination_hash, size, sv);
                pe.stored_at = ts;

                if let Ok(msg) = LxMessage::unpack(&data) {
                    pe.message_hash = msg.hash.unwrap_or([0u8; 32]);
                    pe.destination_hash = msg.destination_hash;
                }

                self.store.insert(pe);
                loaded += 1;
            }
        }

        if loaded > 0 {
            tracing::info!(loaded, "loaded propagation messages from disk");
        }

        Ok(())
    }

    /// Periodic maintenance: cull expired entries and clean up orphaned files.
    pub fn tick(&mut self) {
        let before = self.store.len();
        self.store.cull_expired(self.config.max_message_age);
        let after = self.store.len();

        if before > after
            && let Some(ref dir) = self.storage_path
        {
            self.cleanup_orphaned_files(dir);
        }
    }

    fn cleanup_orphaned_files(&self, dir: &std::path::Path) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let filename = match path.file_name().and_then(|f| f.to_str()) {
                    Some(f) => f.to_string(),
                    None => continue,
                };
                if filename.ends_with(".peer") || filename.ends_with(".msgpack") {
                    continue;
                }
                if let Some((tid, _, _)) = PropagationEntry::parse_filename(&filename)
                    && !self.store.contains(&tid)
                {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    /// When `peer_min_stamp_cost` is `Some`, include only messages whose stamp
    /// value meets the peer's threshold, so we don't send messages the peer
    /// would reject for insufficient PoW.
    pub fn create_offer(
        &self,
        _peer_hash: [u8; 16],
        peer_min_stamp_cost: Option<u8>,
    ) -> Vec<PropagationTransientId> {
        match peer_min_stamp_cost {
            Some(min_cost) if min_cost > 0 => self
                .store
                .entries()
                .filter(|e| e.stamp_value >= min_cost)
                .map(|e| e.transient_id)
                .collect(),
            _ => self.store.transient_ids(),
        }
    }

    /// Returns only messages the peer has not already received.
    pub fn create_offer_filtered(
        &self,
        handled: &HashSet<PropagationTransientId>,
    ) -> Vec<PropagationTransientId> {
        self.store
            .transient_ids()
            .into_iter()
            .filter(|id| !handled.contains(id))
            .collect()
    }

    pub fn message_count(&self) -> usize {
        self.store.len()
    }

    pub fn total_size(&self) -> usize {
        self.store.total_size()
    }

    pub fn contains(&self, transient_id: &PropagationTransientId) -> bool {
        self.store.contains(transient_id)
    }

    pub fn get_session(&self, peer_hash: &[u8; 16]) -> Option<&SyncSession> {
        self.sync_sessions.get(peer_hash)
    }

    pub fn get_session_mut(&mut self, peer_hash: &[u8; 16]) -> Option<&mut SyncSession> {
        self.sync_sessions.get_mut(peer_hash)
    }

    pub fn start_session(&mut self, peer_hash: [u8; 16]) -> &mut SyncSession {
        self.sync_sessions
            .entry(peer_hash)
            .or_insert_with(|| SyncSession::new(peer_hash))
    }

    pub fn remove_session(&mut self, peer_hash: &[u8; 16]) {
        self.sync_sessions.remove(peer_hash);
    }

    pub fn save_peer(&self, peer: &LxmPeer) -> std::io::Result<()> {
        if let Some(ref dir) = self.storage_path {
            let filename = format!("{}.peer", hex_encode(&peer.destination_hash));
            let path = dir.join(filename);
            let data = peer.to_bytes_with_handled();
            std::fs::write(path, data)?;
        }
        Ok(())
    }

    /// Inverse-offer pattern: the peer lists what it has; we return the IDs
    /// we hold that the peer does not. Python reference:
    /// LXMRouter.offer_request_received().
    pub fn offer_request(
        &mut self,
        _peer_hash: [u8; 16],
        offered_ids: &[PropagationTransientId],
    ) -> Vec<PropagationTransientId> {
        let peer_has: HashSet<PropagationTransientId> = offered_ids.iter().copied().collect();

        self.store
            .transient_ids()
            .into_iter()
            .filter(|id| !peer_has.contains(id))
            .collect()
    }

    /// Offer request with typed error responses. Python reference:
    /// LXMRouter.offer_request() (LXMRouter.py:2139-2189).
    ///
    /// The returned `OfferResponse` distinguishes
    /// NoIdentity/Throttled/NoAccess/InvalidKey errors from
    /// HaveAll/WantAll/WantSome outcomes.
    pub fn offer_request_checked(
        &mut self,
        _peer_hash: [u8; 16],
        identity_known: bool,
        is_throttled: bool,
        access_allowed: bool,
        peering_key_valid: bool,
        offered_ids: &[PropagationTransientId],
    ) -> OfferResponse {
        if !identity_known {
            return OfferResponse::ErrorNoIdentity;
        }
        if is_throttled {
            return OfferResponse::ErrorThrottled;
        }
        if !access_allowed {
            return OfferResponse::ErrorNoAccess;
        }
        if !peering_key_valid {
            return OfferResponse::ErrorInvalidKey;
        }

        let wanted: Vec<PropagationTransientId> = offered_ids
            .iter()
            .filter(|id| !self.store.contains(id))
            .copied()
            .collect();

        if wanted.is_empty() {
            OfferResponse::HaveAll
        } else if wanted.len() == offered_ids.len() {
            OfferResponse::WantAll
        } else {
            OfferResponse::WantSome(wanted.iter().map(|id| id.to_vec()).collect())
        }
    }

    /// Wire format matches Python: Boolean for WantAll/HaveAll, integer for
    /// error codes, array of binary IDs for WantSome.
    pub fn encode_offer_response(response: &OfferResponse) -> Vec<u8> {
        use rmpv::Value;

        let value = match response {
            OfferResponse::WantAll => Value::Boolean(true),
            OfferResponse::HaveAll => Value::Boolean(false),
            OfferResponse::WantSome(ids) => {
                Value::Array(ids.iter().map(|id| Value::Binary(id.clone())).collect())
            }
            OfferResponse::ErrorNoIdentity => Value::from(PeerError::NoIdentity as u64),
            OfferResponse::ErrorNoAccess => Value::from(PeerError::NoAccess as u64),
            OfferResponse::ErrorInvalidKey => Value::from(PeerError::InvalidKey as u64),
            OfferResponse::ErrorThrottled => Value::from(PeerError::Throttled as u64),
            OfferResponse::ErrorInvalidData => Value::from(PeerError::InvalidData as u64),
            OfferResponse::ErrorInvalidStamp => Value::from(PeerError::InvalidStamp as u64),
            OfferResponse::Unknown => Value::Nil,
        };

        crate::encode_value(&value)
    }

    /// Handle a Link REQUEST at the `/offer` path. Python reference:
    /// LXMRouter.offer_request() (LXMRouter.py:2139-2189).
    ///
    /// `request_data` is msgpack `[peering_key, [transient_id_1, ...]]`.
    /// Decodes, runs `offer_request_checked`, and returns an encoded
    /// `OfferResponse` ready for `link.create_response()`.
    pub fn handle_offer_request(
        &mut self,
        request_data: &[u8],
        peer_hash: [u8; 16],
        identity_known: bool,
        is_throttled: bool,
        access_allowed: bool,
        remote_identity_hash: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        if let Some(&last_time) = self.last_offer_times.get(&peer_hash)
            && now - last_time < PN_STAMP_THROTTLE as f64
        {
            return Self::encode_offer_response(&OfferResponse::ErrorThrottled);
        }

        let (peering_key, offered_ids) = match Self::decode_offer_request(request_data) {
            Some(parsed) => parsed,
            None => {
                return Self::encode_offer_response(&OfferResponse::ErrorInvalidData);
            }
        };

        // peering_id = self.dest_hash || remote_identity_hash. Empty key means
        // peering-cost enforcement is disabled.
        let peering_key_valid = if peering_key.is_empty() {
            true
        } else if peering_key.len() == 32 {
            if let Some(remote_hash) = remote_identity_hash {
                let mut key = [0u8; 32];
                key.copy_from_slice(&peering_key);
                let mut peering_id = Vec::with_capacity(32);
                peering_id.extend_from_slice(&self.dest_hash);
                peering_id.extend_from_slice(remote_hash);
                crate::stamper::validate_peering_key(&peering_id, &key, self.config.peering_cost)
            } else {
                false
            }
        } else {
            false
        };

        let response = self.offer_request_checked(
            peer_hash,
            identity_known,
            is_throttled,
            access_allowed,
            peering_key_valid,
            &offered_ids,
        );

        self.last_offer_times.insert(peer_hash, now);

        Self::encode_offer_response(&response)
    }

    /// Expected wire format: `[peering_key_bytes, [transient_id_1, ...]]`.
    fn decode_offer_request(data: &[u8]) -> Option<(Vec<u8>, Vec<PropagationTransientId>)> {
        let value: rmpv::Value = rmpv::decode::read_value(&mut &data[..]).ok()?;
        let arr = value.as_array()?;
        if arr.len() < 2 {
            return None;
        }

        let peering_key = arr[0].as_slice().unwrap_or(&[]).to_vec();

        let ids_array = arr[1].as_array()?;
        let mut offered_ids = Vec::with_capacity(ids_array.len());
        for id_val in ids_array {
            if let Some(id_bytes) = id_val.as_slice() {
                match id_bytes.len() {
                    32 => {
                        let mut tid = [0u8; 32];
                        tid.copy_from_slice(id_bytes);
                        offered_ids.push(tid);
                    }
                    _ => {}
                }
            }
        }

        Some((peering_key, offered_ids))
    }

    /// Handle a Link REQUEST at the `/get` path for client download. Python
    /// reference: LXMRouter.message_get_request() (LXMRouter.py:484-587).
    ///
    /// Wire format is msgpack `[wants, haves]` or `[wants, haves, delivery_limit]`:
    /// - Phase 1 (list): `[None, None]` -> available transient IDs for the client.
    /// - Phase 2 (get):  `[[wants...], [haves...]]` -> message payloads; haves
    ///   are purged in the same call.
    /// - Phase 3 (purge): `[None, [received_ids...]]` -> delete from store.
    pub fn handle_get_request(
        &mut self,
        request_data: &[u8],
        client_dest_hash: &[u8; 16],
    ) -> Vec<u8> {
        use rmpv::Value;

        let value: rmpv::Value = match rmpv::decode::read_value(&mut &request_data[..]) {
            Ok(v) => v,
            Err(_) => {
                let mut buf = Vec::new();
                rmpv::encode::write_value(&mut buf, &Value::Nil).ok();
                return buf;
            }
        };

        let arr = match value.as_array() {
            Some(a) if a.len() >= 2 => a,
            _ => {
                let mut buf = Vec::new();
                rmpv::encode::write_value(&mut buf, &Value::Nil).ok();
                return buf;
            }
        };

        let wants_is_nil = arr[0].is_nil();
        let haves_is_nil = arr[1].is_nil();

        fn parse_store_id(value: &rmpv::Value) -> Option<PropagationTransientId> {
            let id_bytes = value.as_slice()?;
            match id_bytes.len() {
                32 => {
                    let mut tid = [0u8; 32];
                    tid.copy_from_slice(id_bytes);
                    Some(tid)
                }
                _ => None,
            }
        }

        if wants_is_nil && haves_is_nil {
            // Phase 1: list available messages for this client.
            let available = self.store.entries_for_destination(client_dest_hash);
            let id_list: Vec<Value> = available
                .iter()
                .map(|e| Value::Binary(e.transient_id.to_vec()))
                .collect();
            let response = Value::Array(id_list);
            crate::encode_value(&response)
        } else if wants_is_nil && !haves_is_nil {
            // Phase 3: purge messages the client already received.
            if let Some(haves_arr) = arr[1].as_array() {
                for have_val in haves_arr {
                    if let Some(tid) = parse_store_id(have_val)
                        && let Some(entry) = self.store.remove(&tid)
                        && let Some(ref dir) = self.storage_path
                    {
                        let path = dir.join(entry.filename());
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
            crate::encode_value(&Value::Boolean(true))
        } else {
            // Phase 2: return requested message data.
            let mut messages: Vec<Value> = Vec::new();

            if let Some(wants_arr) = arr[0].as_array() {
                let delivery_limit = if arr.len() > 2 { arr[2].as_f64() } else { None };
                let limit_bytes = delivery_limit
                    .map(|kb| (kb * 1024.0) as usize)
                    .unwrap_or(usize::MAX);
                let mut total_sent = 0usize;

                for want_val in wants_arr {
                    if let Some(tid) = parse_store_id(want_val)
                        && let Some(ref dir) = self.storage_path
                        && let Some(entry) = self.store.get(&tid)
                    {
                        let path = dir.join(entry.filename());
                        if let Ok(data) = std::fs::read(&path) {
                            if total_sent + data.len() > limit_bytes {
                                break;
                            }
                            total_sent += data.len();
                            messages.push(Value::Binary(data));
                        }
                    }
                }
            }

            // Purge haves in the same call.
            if let Some(haves_arr) = arr[1].as_array() {
                for have_val in haves_arr {
                    if let Some(tid) = parse_store_id(have_val)
                        && let Some(entry) = self.store.remove(&tid)
                        && let Some(ref dir) = self.storage_path
                    {
                        let path = dir.join(entry.filename());
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }

            let response = Value::Array(messages);
            crate::encode_value(&response)
        }
    }

    /// Fetch raw packed message data for each requested transient ID. Python
    /// reference: LXMRouter.message_get_request_received(). Returns an empty
    /// vec when there is no disk storage configured.
    pub fn message_get_request(
        &self,
        requested_ids: &[PropagationTransientId],
    ) -> Vec<(PropagationTransientId, Vec<u8>)> {
        let dir = match &self.storage_path {
            Some(d) => d,
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        for tid in requested_ids {
            if let Some(entry) = self.store.get(tid) {
                let path = dir.join(entry.filename());
                if let Ok(data) = std::fs::read(&path) {
                    results.push((*tid, data));
                }
            }
        }
        results
    }

    /// Produce a `SyncOffer` listing message IDs the peer has not yet handled.
    /// The caller sends it over an established link. Python reference:
    /// LXMRouter.sync_request_received().
    pub fn prepare_sync_offer(&mut self, peer_hash: [u8; 16]) -> SyncOffer {
        // Compute IDs before borrowing sync_sessions mutably.
        let our_ids = if let Some(peer) = self.load_peer(&peer_hash) {
            self.create_offer_filtered(&peer.handled_messages)
        } else {
            self.create_offer(peer_hash, None)
        };

        let session = self
            .sync_sessions
            .entry(peer_hash)
            .or_insert_with(|| SyncSession::new(peer_hash));
        session.prepare_offer(our_ids, Vec::new())
    }

    /// Compare a peer's `SyncOffer` against our store and return a `SyncGet`
    /// listing IDs we want. Python reference: LXMRouter.offer_request_received().
    pub fn process_sync_offer(&mut self, peer_hash: [u8; 16], offer: &SyncOffer) -> SyncGet {
        // process_offer needs &self.store; compute the get before mutating sync_sessions.
        let mut tmp_session = SyncSession::new(peer_hash);
        let result = tmp_session.process_offer(offer, &self.store);
        self.sync_sessions.insert(peer_hash, tmp_session);
        result
    }

    /// Return the packed message data for each ID in `get`. The caller
    /// transfers each blob as a Resource over the link. Python reference:
    /// LXMRouter.message_get_request_received().
    pub fn process_sync_get(&mut self, peer_hash: [u8; 16], get: &SyncGet) -> Vec<Vec<u8>> {
        if let Some(session) = self.sync_sessions.get_mut(&peer_hash) {
            session.process_get(get);
        } else {
            let mut session = SyncSession::new(peer_hash);
            session.process_get(get);
            self.sync_sessions.insert(peer_hash, session);
        }

        let mut messages = Vec::new();
        for wanted_id_bytes in &get.wanted_ids {
            if wanted_id_bytes.len() != 32 {
                continue;
            }
            let mut tid = [0u8; 32];
            tid.copy_from_slice(wanted_id_bytes);

            if let Some(ref dir) = self.storage_path
                && let Some(entry) = self.store.get(&tid)
            {
                let path = dir.join(entry.filename());
                if let Ok(data) = std::fs::read(&path) {
                    messages.push(data);
                }
            }
        }

        messages
    }

    /// Record a successful transfer for a peer. Loads the peer, adds the
    /// transient ID to its handled set, saves it, and records the transfer in
    /// the sync session. Python reference:
    /// LXMRouter.propagation_resource_concluded() (LXMRouter.py:2271) --
    /// `peer.queue_handled_message(transient_id)`.
    pub fn mark_peer_handled(
        &mut self,
        peer_hash: &[u8; 16],
        transient_id: &PropagationTransientId,
    ) {
        if let Some(mut peer) = self.load_peer(peer_hash) {
            peer.add_handled_message(transient_id);
            let _ = self.save_peer(&peer);
        }

        if let Some(session) = self.sync_sessions.get_mut(peer_hash) {
            session.record_transfer();
        }
    }

    pub fn complete_sync(&mut self, peer_hash: &[u8; 16]) {
        if let Some(session) = self.sync_sessions.get_mut(peer_hash) {
            session.mark_complete();
        }
        self.remove_session(peer_hash);
    }

    fn load_peer(&self, peer_hash: &[u8; 16]) -> Option<LxmPeer> {
        let dir = self.storage_path.as_ref()?;
        let filename = format!("{}.peer", hex_encode(peer_hash));
        let path = dir.join(filename);
        let data = std::fs::read(&path).ok()?;
        LxmPeer::from_bytes_with_handled(&data)
    }

    pub fn load_peers(&self) -> Vec<LxmPeer> {
        let dir = match &self.storage_path {
            Some(d) => d,
            None => return Vec::new(),
        };

        let mut peers = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "peer").unwrap_or(false)
                    && let Ok(data) = std::fs::read(&path)
                    && let Some(peer) = LxmPeer::from_bytes_with_handled(&data)
                {
                    peers.push(peer);
                }
            }
        }
        peers
    }
}

impl std::fmt::Debug for PropagationNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PropagationNode")
            .field("dest_hash", &hex_encode(&self.dest_hash))
            .field("message_count", &self.store.len())
            .field("total_size", &self.store.total_size())
            .field("sessions", &self.sync_sessions.len())
            .field("storage_path", &self.storage_path)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DeliveryMethod;

    fn make_signed_message(dest: [u8; 16], src: [u8; 16], title: &str, content: &str) -> LxMessage {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(dest, src, title, content, DeliveryMethod::Propagated);
        msg.sign(&key).unwrap();
        msg
    }

    fn tid(byte: u8) -> PropagationTransientId {
        [byte; 32]
    }

    fn id(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn test_new_propagation_node() {
        let node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        assert_eq!(node.message_count(), 0);
        assert_eq!(node.total_size(), 0);
        assert_eq!(node.dest_hash, [0xAA; 16]);
    }

    #[test]
    fn test_accept_message() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "content");
        assert!(msg.hash.is_some());
        assert!(node.accept_message(&msg));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_reject_duplicate() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "duplicate");
        assert!(node.accept_message(&msg));
        assert!(!node.accept_message(&msg));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_reject_no_hash() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg = LxMessage::new(
            [0xBB; 16],
            [0xCC; 16],
            "Test",
            "no hash",
            DeliveryMethod::Propagated,
        );
        assert!(msg.hash.is_none());
        assert!(!node.accept_message(&msg));
    }

    #[test]
    fn test_reject_store_full() {
        let config = PropagationNodeConfig {
            max_storage: 1,
            ..Default::default()
        };
        let mut node = PropagationNode::new(config, [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg1");
        assert!(node.accept_message(&msg1));

        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg2");
        assert!(!node.accept_message(&msg2));
    }

    #[test]
    fn test_create_offer() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg1");
        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg2");
        node.accept_message(&msg1);
        node.accept_message(&msg2);

        let offer = node.create_offer([0xFF; 16], None);
        assert_eq!(offer.len(), 2);
    }

    #[test]
    fn test_create_offer_filtered() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg1");
        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg2");

        let tid1 = msg1.transient_id.unwrap();
        node.accept_message(&msg1);
        node.accept_message(&msg2);

        let all = node.create_offer([0xFF; 16], None);
        assert_eq!(all.len(), 2);

        let mut handled = HashSet::new();
        handled.insert(tid1);

        let filtered = node.create_offer_filtered(&handled);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_propagation_disk_persistence() {
        let dir = std::env::temp_dir().join("lxmf_test_prop_persist");
        let _ = std::fs::remove_dir_all(&dir);

        {
            let mut node = PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                [0xAA; 16],
                dir.clone(),
            )
            .unwrap();

            let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "persistent content");
            assert!(node.accept_message(&msg));
            assert_eq!(node.message_count(), 1);
        }

        // Fresh node reloads from disk.
        {
            let node = PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                [0xAA; 16],
                dir.clone(),
            )
            .unwrap();
            assert_eq!(node.message_count(), 1);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tick_culls_expired() {
        let config = PropagationNodeConfig {
            max_message_age: 1,
            ..Default::default()
        };
        let mut node = PropagationNode::new(config, [0xAA; 16]);

        let mut msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "will expire");
        msg.timestamp = 1000.0;
        node.accept_message(&msg);
        assert_eq!(node.message_count(), 1);

        node.tick();
        assert_eq!(node.message_count(), 0);
    }

    /// After a message is culled (expired), the same message resurfacing
    /// must be accepted again — the node's "seen" memory is the store
    /// itself, not a separate dedup log. Otherwise a node that culled a
    /// message and then received it again from another peer would
    /// silently drop it, breaking store-and-forward semantics.
    #[test]
    fn test_reaccept_after_cull() {
        let config = PropagationNodeConfig {
            max_message_age: 1,
            ..Default::default()
        };
        let mut node = PropagationNode::new(config, [0xAA; 16]);

        let mut msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "cull then redeliver");
        msg.timestamp = 1000.0;
        assert!(node.accept_message(&msg), "first accept");
        assert_eq!(node.message_count(), 1);

        node.tick();
        assert_eq!(node.message_count(), 0, "culled by tick");

        // Fresh timestamp so the re-delivery isn't itself expired.
        msg.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        assert!(
            node.accept_message(&msg),
            "same message re-accepted after cull"
        );
        assert_eq!(node.message_count(), 1);
    }

    /// A store that was full and rejecting new messages must recover
    /// capacity after culling — the reject-store-full path is transient,
    /// not terminal. Exercises: fill → reject → cull expired → accept.
    #[test]
    fn test_accept_after_store_full_and_cull() {
        let config = PropagationNodeConfig {
            max_storage: 1,
            max_message_age: 1,
            ..Default::default()
        };
        let mut node = PropagationNode::new(config, [0xAA; 16]);

        let mut msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "first");
        msg1.timestamp = 1000.0; // ancient so tick will cull it
        assert!(node.accept_message(&msg1));

        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "rejected-while-full");
        assert!(
            !node.accept_message(&msg2),
            "store full, second message must reject"
        );

        node.tick();
        assert_eq!(node.message_count(), 0, "expired msg culled");

        let msg3 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "accepted-after-cull");
        assert!(
            node.accept_message(&msg3),
            "store has space after cull, next message accepted"
        );
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_peer_persistence() {
        let dir = std::env::temp_dir().join("lxmf_test_peer_persist");
        let _ = std::fs::remove_dir_all(&dir);

        let node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut peer = LxmPeer::new([0xBB; 16]);
        peer.add_handled_message(&tid(0xCC));
        node.save_peer(&peer).unwrap();

        let loaded_peers = node.load_peers();
        assert_eq!(loaded_peers.len(), 1);
        assert!(loaded_peers[0].has_handled(&tid(0xCC)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_peer_persistence_multiple() {
        let dir = std::env::temp_dir().join("lxmf_test_peer_persist_multi");
        let _ = std::fs::remove_dir_all(&dir);

        let node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut peer1 = LxmPeer::new([0xBB; 16]);
        peer1.add_handled_message(&tid(0x11));
        node.save_peer(&peer1).unwrap();

        let mut peer2 = LxmPeer::new([0xDD; 16]);
        peer2.add_handled_message(&tid(0x22));
        peer2.add_handled_message(&tid(0x33));
        node.save_peer(&peer2).unwrap();

        let loaded = node.load_peers();
        assert_eq!(loaded.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_no_persistence_without_storage_path() {
        let node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let peer = LxmPeer::new([0xBB; 16]);
        node.save_peer(&peer).unwrap();

        let loaded = node.load_peers();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_disk_cleanup_on_cull() {
        let dir = std::env::temp_dir().join("lxmf_test_disk_cleanup");
        let _ = std::fs::remove_dir_all(&dir);

        let config = PropagationNodeConfig {
            max_message_age: 1,
            ..Default::default()
        };
        let mut node = PropagationNode::with_storage(config, [0xAA; 16], dir.clone()).unwrap();

        let mut msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "cleanup test");
        msg.timestamp = 1000.0;
        node.accept_message(&msg);

        let file_count = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .ok()
                    .and_then(|e| {
                        e.path()
                            .file_name()
                            .map(|f| !f.to_str().unwrap_or("").ends_with(".peer"))
                    })
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(file_count, 1);

        node.tick();
        assert_eq!(node.message_count(), 0);

        let remaining = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .ok()
                    .and_then(|e| {
                        e.path()
                            .file_name()
                            .map(|f| !f.to_str().unwrap_or("").ends_with(".peer"))
                    })
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(remaining, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sync_session_management() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let peer_hash = [0xBB; 16];

        assert!(node.get_session(&peer_hash).is_none());

        let session = node.start_session(peer_hash);
        assert_eq!(session.peer_hash, peer_hash);

        assert!(node.get_session(&peer_hash).is_some());

        node.remove_session(&peer_hash);
        assert!(node.get_session(&peer_hash).is_none());
    }

    #[test]
    fn test_offer_request_returns_missing() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg1");
        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg2");
        let msg3 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "msg3");

        let tid1 = msg1.transient_id.unwrap();
        let tid2 = msg2.transient_id.unwrap();
        let tid3 = msg3.transient_id.unwrap();

        node.accept_message(&msg1);
        node.accept_message(&msg2);
        node.accept_message(&msg3);

        let peer_has = [tid1, tid2];
        let missing = node.offer_request([0xDD; 16], &peer_has);

        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&tid3));
    }

    #[test]
    fn test_offer_request_peer_has_nothing() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "content");
        node.accept_message(&msg);

        let missing = node.offer_request([0xDD; 16], &[]);
        assert_eq!(missing.len(), 1);
    }

    #[test]
    fn test_offer_request_peer_has_everything() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "content");
        let tid = msg.transient_id.unwrap();
        node.accept_message(&msg);

        let missing = node.offer_request([0xDD; 16], &[tid]);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_message_get_request_with_storage() {
        let dir = std::env::temp_dir().join("lxmf_test_msg_get");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "get request content");
        let tid = msg.transient_id.unwrap();
        node.accept_message(&msg);

        let results = node.message_get_request(&[tid]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, tid);
        assert!(!results[0].1.is_empty());

        let unpacked = LxMessage::unpack(&results[0].1);
        assert!(unpacked.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_message_get_request_unknown_id() {
        let dir = std::env::temp_dir().join("lxmf_test_msg_get_unknown");
        let _ = std::fs::remove_dir_all(&dir);

        let node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let results = node.message_get_request(&[tid(0xFF)]);
        assert!(results.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_message_get_request_no_storage() {
        let node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let results = node.message_get_request(&[tid(0xFF)]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_prepare_sync_offer() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "sync1");
        let msg2 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "sync2");
        node.accept_message(&msg1);
        node.accept_message(&msg2);

        let peer_hash = [0xDD; 16];
        let offer = node.prepare_sync_offer(peer_hash);

        assert_eq!(offer.transient_ids.len(), 2);
        assert!(node.get_session(&peer_hash).is_some());
    }

    #[test]
    fn test_process_sync_offer_and_get() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let msg1 = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "has_this");
        let tid1 = msg1.transient_id.unwrap();
        node.accept_message(&msg1);

        let peer_hash = [0xDD; 16];
        let tid2 = tid(0xEE);
        let offer = crate::sync::SyncOffer {
            peering_key: Vec::new(),
            transient_ids: vec![tid1.to_vec(), tid2.to_vec()],
        };

        let get = node.process_sync_offer(peer_hash, &offer);
        assert_eq!(get.wanted_ids.len(), 1);
        assert_eq!(get.wanted_ids[0], tid2.to_vec());
    }

    #[test]
    fn test_sync_lifecycle_complete() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let peer_hash = [0xDD; 16];

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "lifecycle");
        node.accept_message(&msg);

        let _offer = node.prepare_sync_offer(peer_hash);
        assert!(node.get_session(&peer_hash).is_some());

        node.complete_sync(&peer_hash);
        assert!(node.get_session(&peer_hash).is_none());
    }

    #[test]
    fn test_process_sync_get_with_storage() {
        let dir = std::env::temp_dir().join("lxmf_test_sync_get");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "sync get content");
        let tid = msg.transient_id.unwrap();
        node.accept_message(&msg);

        let get = crate::sync::SyncGet {
            wanted_ids: vec![tid.to_vec()],
        };
        let peer_hash = [0xDD; 16];
        let messages = node.process_sync_get(peer_hash, &get);

        assert_eq!(messages.len(), 1);
        assert!(!messages[0].is_empty());

        let unpacked = LxMessage::unpack(&messages[0]);
        assert!(unpacked.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_offer_request_checked_no_identity() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let resp = node.offer_request_checked([0xDD; 16], false, false, true, true, &[]);
        assert_eq!(resp, OfferResponse::ErrorNoIdentity);
    }

    #[test]
    fn test_offer_request_checked_throttled() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let resp = node.offer_request_checked([0xDD; 16], true, true, true, true, &[]);
        assert_eq!(resp, OfferResponse::ErrorThrottled);
    }

    #[test]
    fn test_offer_request_checked_no_access() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let resp = node.offer_request_checked([0xDD; 16], true, false, false, true, &[]);
        assert_eq!(resp, OfferResponse::ErrorNoAccess);
    }

    #[test]
    fn test_offer_request_checked_invalid_key() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let resp = node.offer_request_checked([0xDD; 16], true, false, true, false, &[]);
        assert_eq!(resp, OfferResponse::ErrorInvalidKey);
    }

    #[test]
    fn test_offer_request_checked_have_all() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "content");
        let tid = msg.transient_id.unwrap();
        node.accept_message(&msg);

        let resp = node.offer_request_checked([0xDD; 16], true, false, true, true, &[tid]);
        assert_eq!(resp, OfferResponse::HaveAll);
    }

    #[test]
    fn test_offer_request_checked_want_all() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let resp = node.offer_request_checked(
            [0xDD; 16],
            true,
            false,
            true,
            true,
            &[tid(0x11), tid(0x22)],
        );
        assert_eq!(resp, OfferResponse::WantAll);
    }

    #[test]
    fn test_offer_request_checked_want_some() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "content");
        let stored_tid = msg.transient_id.unwrap();
        node.accept_message(&msg);

        let resp =
            node.offer_request_checked([0xDD; 16], true, false, true, true, &[stored_tid, tid(0x99)]);
        match resp {
            OfferResponse::WantSome(ids) => {
                assert_eq!(ids.len(), 1);
                assert_eq!(ids[0], id(0x99));
            }
            _ => panic!("expected WantSome"),
        }
    }

    #[test]
    fn test_encode_offer_response_roundtrip() {
        let encoded = PropagationNode::encode_offer_response(&OfferResponse::WantAll);
        let parsed = OfferResponse::from_msgpack(&encoded);
        assert_eq!(parsed, OfferResponse::WantAll);

        let encoded = PropagationNode::encode_offer_response(&OfferResponse::HaveAll);
        let parsed = OfferResponse::from_msgpack(&encoded);
        assert_eq!(parsed, OfferResponse::HaveAll);

        let encoded = PropagationNode::encode_offer_response(&OfferResponse::ErrorNoIdentity);
        let parsed = OfferResponse::from_msgpack(&encoded);
        assert_eq!(parsed, OfferResponse::ErrorNoIdentity);

        let encoded = PropagationNode::encode_offer_response(&OfferResponse::ErrorThrottled);
        let parsed = OfferResponse::from_msgpack(&encoded);
        assert_eq!(parsed, OfferResponse::ErrorThrottled);

        let ids = vec![id(0xAA), id(0xBB)];
        let encoded = PropagationNode::encode_offer_response(&OfferResponse::WantSome(ids.clone()));
        let parsed = OfferResponse::from_msgpack(&encoded);
        match parsed {
            OfferResponse::WantSome(parsed_ids) => {
                assert_eq!(parsed_ids, ids);
            }
            _ => panic!("expected WantSome"),
        }
    }

    #[test]
    fn test_handle_offer_request_valid() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        // Empty peering key disables peering-cost enforcement.
        use rmpv::Value;
        let offer = Value::Array(vec![
            Value::Binary(vec![]),
            Value::Array(vec![
                Value::Binary(id(0x11)),
                Value::Binary(id(0x22)),
            ]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &offer).unwrap();

        let response_bytes = node.handle_offer_request(&buf, [0xBB; 16], true, false, true, None);
        let response = OfferResponse::from_msgpack(&response_bytes);
        assert_eq!(response, OfferResponse::WantAll);
    }

    #[test]
    fn test_handle_offer_request_no_identity() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        use rmpv::Value;
        let offer = Value::Array(vec![Value::Binary(vec![]), Value::Array(vec![])]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &offer).unwrap();

        let response_bytes = node.handle_offer_request(&buf, [0xBB; 16], false, false, true, None);
        let response = OfferResponse::from_msgpack(&response_bytes);
        assert_eq!(response, OfferResponse::ErrorNoIdentity);
    }

    #[test]
    fn test_handle_offer_request_invalid_data() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let response_bytes =
            node.handle_offer_request(&[0xFF, 0xFF], [0xBB; 16], true, false, true, None);
        let response = OfferResponse::from_msgpack(&response_bytes);
        assert_eq!(response, OfferResponse::ErrorInvalidData);
    }

    #[test]
    fn test_decode_offer_request_valid() {
        use rmpv::Value;
        let offer = Value::Array(vec![
            Value::Binary(vec![0xAA; 32]),
            Value::Array(vec![
                Value::Binary(id(0x11)),
                Value::Binary(id(0x22)),
            ]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &offer).unwrap();

        let result = PropagationNode::decode_offer_request(&buf);
        assert!(result.is_some());
        let (key, ids) = result.unwrap();
        assert_eq!(key, vec![0xAA; 32]);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], tid(0x11));
        assert_eq!(ids[1], tid(0x22));
    }

    #[test]
    fn test_decode_offer_request_filters_bad_ids() {
        use rmpv::Value;
        let offer = Value::Array(vec![
            Value::Binary(vec![]),
            Value::Array(vec![
                Value::Binary(vec![0x11; 16]),
                Value::Binary(vec![0x22; 8]),
                Value::Binary(id(0x33)),
            ]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &offer).unwrap();

        let (_, ids) = PropagationNode::decode_offer_request(&buf).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], tid(0x33));
    }

    #[test]
    fn test_handle_get_request_list_phase() {
        let dir = std::env::temp_dir().join("lxmf_test_get_list");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "get list content");
        node.accept_message(&msg);

        use rmpv::Value;
        let request = Value::Array(vec![Value::Nil, Value::Nil]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &request).unwrap();

        let response_bytes = node.handle_get_request(&buf, &[0xBB; 16]);
        let response: rmpv::Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        let arr = response.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].as_slice().unwrap().len(), 32);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_handle_get_request_list_empty() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        use rmpv::Value;
        let request = Value::Array(vec![Value::Nil, Value::Nil]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &request).unwrap();

        let response_bytes = node.handle_get_request(&buf, &[0xBB; 16]);
        let response: rmpv::Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        let arr = response.as_array().unwrap();
        assert!(arr.is_empty());
    }

    #[test]
    fn test_accept_propagated_blob_and_get_with_full_hash_id() {
        let dir = std::env::temp_dir().join("lxmf_test_propagated_blob_get");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut lxmf_data = vec![0xBB; 16];
        lxmf_data.extend_from_slice(&[0xCC; 128]);
        assert!(node.accept_propagated_blob(&lxmf_data, 0));

        let full_id = rns_crypto::sha::full_hash(&lxmf_data);
        use rmpv::Value;
        let list_request = Value::Array(vec![Value::Nil, Value::Nil]);
        let mut list_buf = Vec::new();
        rmpv::encode::write_value(&mut list_buf, &list_request).unwrap();
        let list_response = node.handle_get_request(&list_buf, &[0xBB; 16]);
        let list_value: Value = rmpv::decode::read_value(&mut &list_response[..]).unwrap();
        assert_eq!(list_value.as_array().unwrap().len(), 1);

        let get_request = Value::Array(vec![
            Value::Array(vec![Value::Binary(full_id.to_vec())]),
            Value::Array(vec![]),
        ]);
        let mut get_buf = Vec::new();
        rmpv::encode::write_value(&mut get_buf, &get_request).unwrap();
        let get_response = node.handle_get_request(&get_buf, &[0xBB; 16]);
        let get_value: Value = rmpv::decode::read_value(&mut &get_response[..]).unwrap();
        let messages = get_value.as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].as_slice().unwrap(), lxmf_data.as_slice());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_propagated_blob_enforces_min_stamp_cost() {
        let config = PropagationNodeConfig {
            min_stamp_cost: 8,
            ..Default::default()
        };
        let mut node = PropagationNode::new(config, [0xAA; 16]);

        let mut lxmf_data = vec![0xBB; 16];
        lxmf_data.extend_from_slice(&[0xCC; 128]);

        assert!(!node.accept_propagated_blob(&lxmf_data, 7));
        assert_eq!(node.message_count(), 0);

        assert!(node.accept_propagated_blob(&lxmf_data, 8));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_opaque_propagated_blob_reload_preserves_destination() {
        let dir = std::env::temp_dir().join("lxmf_test_propagated_blob_reload");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let mut lxmf_data = vec![0xBB; 16];
        lxmf_data.extend_from_slice(&[0xCC; 128]);
        assert!(node.accept_propagated_blob(&lxmf_data, 0));
        drop(node);

        let mut reloaded = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        use rmpv::Value;
        let list_request = Value::Array(vec![Value::Nil, Value::Nil]);
        let mut list_buf = Vec::new();
        rmpv::encode::write_value(&mut list_buf, &list_request).unwrap();
        let response = reloaded.handle_get_request(&list_buf, &[0xBB; 16]);
        let value: Value = rmpv::decode::read_value(&mut &response[..]).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_handle_get_request_purge_phase() {
        let dir = std::env::temp_dir().join("lxmf_test_get_purge");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "purge content");
        let tid = msg.transient_id.unwrap();
        node.accept_message(&msg);
        assert_eq!(node.message_count(), 1);

        use rmpv::Value;
        let request = Value::Array(vec![
            Value::Nil,
            Value::Array(vec![Value::Binary(tid.to_vec())]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &request).unwrap();

        let _response_bytes = node.handle_get_request(&buf, &[0xBB; 16]);
        assert_eq!(node.message_count(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_handle_get_request_get_phase() {
        let dir = std::env::temp_dir().join("lxmf_test_get_data");
        let _ = std::fs::remove_dir_all(&dir);

        let mut node = PropagationNode::with_storage(
            PropagationNodeConfig::default(),
            [0xAA; 16],
            dir.clone(),
        )
        .unwrap();

        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "get data content");
        let tid = msg.transient_id.unwrap();
        node.accept_message(&msg);

        use rmpv::Value;
        let request = Value::Array(vec![
            Value::Array(vec![Value::Binary(tid.to_vec())]),
            Value::Array(vec![]),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &request).unwrap();

        let response_bytes = node.handle_get_request(&buf, &[0xBB; 16]);
        let response: rmpv::Value = rmpv::decode::read_value(&mut &response_bytes[..]).unwrap();
        let arr = response.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(!arr[0].as_slice().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_stamp_cost_validation_rejects_unstamped() {
        let config = PropagationNodeConfig {
            min_stamp_cost: 8,
            ..Default::default()
        };
        let mut node = PropagationNode::new(config, [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "unstamped");

        assert!(!node.accept_message(&msg));
        assert_eq!(node.message_count(), 0);
    }

    #[test]
    fn test_stamp_cost_zero_accepts_all() {
        let config = PropagationNodeConfig {
            min_stamp_cost: 0,
            ..Default::default()
        };
        let mut node = PropagationNode::new(config, [0xAA; 16]);
        let msg = make_signed_message([0xBB; 16], [0xCC; 16], "Test", "no_cost");

        assert!(node.accept_message(&msg));
        assert_eq!(node.message_count(), 1);
    }

    #[test]
    fn test_create_offer_with_stamp_filter() {
        let mut node = PropagationNode::new(PropagationNodeConfig::default(), [0xAA; 16]);

        let entry1 = crate::propagation::PropagationEntry {
            transient_id: tid(0x01),
            message_hash: [0x11; 32],
            destination_hash: [0xCC; 16],
            stored_at: 1000.0,
            stamp_value: 20,
            size: 100,
            collected: false,
        };
        let entry2 = crate::propagation::PropagationEntry {
            transient_id: tid(0x02),
            message_hash: [0x22; 32],
            destination_hash: [0xCC; 16],
            stored_at: 1000.0,
            stamp_value: 5,
            size: 100,
            collected: false,
        };
        node.store.insert(entry1);
        node.store.insert(entry2);

        let all = node.create_offer([0xFF; 16], None);
        assert_eq!(all.len(), 2);

        let filtered = node.create_offer([0xFF; 16], Some(10));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], tid(0x01));

        let all2 = node.create_offer([0xFF; 16], Some(0));
        assert_eq!(all2.len(), 2);
    }
}
