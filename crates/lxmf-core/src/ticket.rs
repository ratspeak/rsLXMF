//! LXMF ticket lifecycle and persistence state.
//!
//! A ticket issued to a peer is an *inbound* ticket: it validates that peer's
//! future stamps. A ticket learned from a peer is an *outbound* ticket: it is
//! used to stamp future messages to that peer. Keeping those directions
//! separate is required for Python LXMF compatibility.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::constants::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ticket {
    pub token: [u8; 16],
    pub destination_hash: [u8; 16],
    /// Expiry timestamp (Unix epoch seconds).
    pub expires: f64,
}

impl Ticket {
    pub fn new(token: [u8; 16], destination_hash: [u8; 16], expires: f64) -> Self {
        Self {
            token,
            destination_hash,
            expires,
        }
    }

    pub fn is_valid(&self, now: f64) -> bool {
        now < self.expires
    }

    pub fn should_renew(&self, now: f64) -> bool {
        self.is_valid(now) && (self.expires - now) <= TICKET_RENEW as f64
    }

    /// Encode Python's native MessagePack ticket field `[expires, token]`.
    pub fn encode_field(&self) -> Result<Vec<u8>, rmpv::encode::Error> {
        let value = rmpv::Value::Array(vec![
            rmpv::Value::F64(self.expires),
            rmpv::Value::Binary(self.token.to_vec()),
        ]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &value)?;
        Ok(encoded)
    }

    /// Decode a signed inbound Python-compatible ticket field.
    pub fn decode_field(destination_hash: [u8; 16], encoded: &[u8], now: f64) -> Option<Self> {
        let mut cursor = std::io::Cursor::new(encoded);
        let value = rmpv::decode::read_value(&mut cursor).ok()?;
        if cursor.position() != encoded.len() as u64 {
            return None;
        }
        let values = value.as_array()?;
        if values.len() != 2 {
            return None;
        }
        let expires = values[0].as_f64()?;
        let token = values[1].as_slice()?;
        if !expires.is_finite() || expires <= now || token.len() != TICKET_LENGTH {
            return None;
        }
        let mut token_array = [0u8; TICKET_LENGTH];
        token_array.copy_from_slice(token);
        Some(Self::new(token_array, destination_hash, expires))
    }
}

/// Versioned, serializable ticket state.
///
/// Version 1 replaces the former flat `Vec<Ticket>` representation. The flat
/// form could not distinguish tickets issued to peers from tickets learned
/// from peers and therefore could not implement Python's reply semantics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TicketStoreSnapshot {
    #[serde(default = "ticket_store_version")]
    pub version: u8,
    #[serde(default)]
    pub outbound: Vec<Ticket>,
    #[serde(default)]
    pub inbound: Vec<Ticket>,
    #[serde(default)]
    pub last_deliveries: HashMap<[u8; 16], f64>,
}

const fn ticket_store_version() -> u8 {
    1
}

impl Default for TicketStoreSnapshot {
    fn default() -> Self {
        Self {
            version: ticket_store_version(),
            outbound: Vec::new(),
            inbound: Vec::new(),
            last_deliveries: HashMap::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct TicketStore {
    /// One learned ticket per destination, matching Python's outbound map.
    outbound: HashMap<[u8; 16], Ticket>,
    /// Multiple locally issued tickets may overlap during renewal/grace.
    inbound: Vec<Ticket>,
    /// Last successful delivery of a message containing a ticket.
    last_deliveries: HashMap<[u8; 16], f64>,
}

impl TicketStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a ticket issued locally for `destination_hash`.
    pub fn add_inbound(&mut self, ticket: Ticket) {
        if self.inbound.iter().any(|existing| {
            existing.destination_hash == ticket.destination_hash && existing.token == ticket.token
        }) {
            return;
        }
        self.inbound.push(ticket);
    }

    /// Store or replace the ticket learned from `destination_hash`.
    pub fn remember_outbound(&mut self, ticket: Ticket) {
        self.outbound.insert(ticket.destination_hash, ticket);
    }

    /// Return the valid ticket learned from `destination_hash`.
    pub fn find_outbound(&self, destination_hash: &[u8; 16], now: f64) -> Option<&Ticket> {
        self.outbound
            .get(destination_hash)
            .filter(|ticket| ticket.is_valid(now))
    }

    /// Return every valid ticket issued locally for `destination_hash`.
    pub fn inbound_tokens(&self, destination_hash: &[u8; 16], now: f64) -> Vec<[u8; 16]> {
        self.inbound
            .iter()
            .filter(|ticket| &ticket.destination_hash == destination_hash && ticket.is_valid(now))
            .map(|ticket| ticket.token)
            .collect()
    }

    /// Generate or reuse a ticket for a peer, respecting Python's delivery
    /// interval and renewal window. `None` means a ticket was delivered too
    /// recently and should not be included in this message.
    pub fn issue_for(
        &mut self,
        destination_hash: [u8; 16],
        expiry_secs: u64,
        now: f64,
    ) -> Option<Ticket> {
        if !self.should_issue_for(&destination_hash, now) {
            return None;
        }

        if let Some(ticket) = self.inbound.iter().find(|ticket| {
            ticket.destination_hash == destination_hash
                && ticket.expires - now > TICKET_RENEW as f64
        }) {
            return Some(ticket.clone());
        }

        let token: [u8; TICKET_LENGTH] = rand::random();
        let ticket = Ticket::new(token, destination_hash, now + expiry_secs as f64);
        self.inbound.push(ticket.clone());
        Some(ticket)
    }

    pub fn should_issue_for(&self, destination_hash: &[u8; 16], now: f64) -> bool {
        !self
            .last_deliveries
            .get(destination_hash)
            .is_some_and(|last| now - *last < TICKET_INTERVAL as f64)
    }

    pub fn mark_ticket_delivered(&mut self, destination_hash: [u8; 16], delivered_at: f64) {
        self.last_deliveries.insert(destination_hash, delivered_at);
    }

    /// Drop expired outbound tickets and inbound tickets after their grace
    /// period. Delivery timestamps need only survive one interval.
    pub fn cull(&mut self, now: f64) {
        self.outbound.retain(|_, ticket| ticket.is_valid(now));
        self.inbound
            .retain(|ticket| now < ticket.expires + TICKET_GRACE as f64);
        self.last_deliveries
            .retain(|_, delivered| now - *delivered < TICKET_INTERVAL as f64);
    }

    pub fn count_valid(&self, now: f64) -> usize {
        self.outbound
            .values()
            .filter(|ticket| ticket.is_valid(now))
            .count()
            + self
                .inbound
                .iter()
                .filter(|ticket| ticket.is_valid(now))
                .count()
    }

    pub fn inbound(&self) -> &[Ticket] {
        &self.inbound
    }

    pub fn snapshot(&self) -> TicketStoreSnapshot {
        TicketStoreSnapshot {
            version: ticket_store_version(),
            outbound: self.outbound.values().cloned().collect(),
            inbound: self.inbound.clone(),
            last_deliveries: self.last_deliveries.clone(),
        }
    }

    pub fn replace_snapshot(&mut self, snapshot: TicketStoreSnapshot) {
        self.outbound = snapshot
            .outbound
            .into_iter()
            .map(|ticket| (ticket.destination_hash, ticket))
            .collect();
        self.inbound = snapshot.inbound;
        self.last_deliveries = snapshot.last_deliveries;
    }

    /// Migrate the legacy flat representation conservatively. Old Rust used
    /// every entry for both directions, so retaining entries in both stores
    /// preserves working stamps while all new state is direction-correct.
    pub fn replace_legacy(&mut self, tickets: Vec<Ticket>) {
        self.outbound = tickets
            .iter()
            .cloned()
            .map(|ticket| (ticket.destination_hash, ticket))
            .collect();
        self.inbound = tickets;
        self.last_deliveries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_state_is_separate() {
        let mut store = TicketStore::new();
        let dest = [0xBB; 16];
        store.add_inbound(Ticket::new([0x01; 16], dest, 2_000.0));
        assert_eq!(store.inbound_tokens(&dest, 1_000.0), vec![[0x01; 16]]);
        assert!(store.find_outbound(&dest, 1_000.0).is_none());

        store.remember_outbound(Ticket::new([0x02; 16], dest, 2_000.0));
        assert_eq!(
            store.find_outbound(&dest, 1_000.0).unwrap().token,
            [0x02; 16]
        );
        assert_eq!(store.inbound_tokens(&dest, 1_000.0), vec![[0x01; 16]]);
    }

    #[test]
    fn issuance_reuses_then_renews_and_throttles_after_delivery() {
        let mut store = TicketStore::new();
        let dest = [0xBB; 16];
        let first = store.issue_for(dest, TICKET_EXPIRY, 1_000.0).unwrap();
        let reused = store.issue_for(dest, TICKET_EXPIRY, 2_000.0).unwrap();
        assert_eq!(reused.token, first.token);

        store.mark_ticket_delivered(dest, 2_000.0);
        assert!(store.issue_for(dest, TICKET_EXPIRY, 2_001.0).is_none());
        let renewed = store
            .issue_for(dest, TICKET_EXPIRY, 2_000.0 + TICKET_INTERVAL as f64)
            .unwrap();
        assert_eq!(renewed.token, first.token);

        let near_expiry = first.expires - TICKET_RENEW as f64 + 1.0;
        let replacement = store.issue_for(dest, TICKET_EXPIRY, near_expiry).unwrap();
        assert_ne!(replacement.token, first.token);
    }

    #[test]
    fn snapshot_roundtrip_preserves_directions_and_delivery_gate() {
        let mut store = TicketStore::new();
        let dest = [0xCC; 16];
        store.add_inbound(Ticket::new([1; 16], dest, 9_999.0));
        store.remember_outbound(Ticket::new([2; 16], dest, 9_999.0));
        store.mark_ticket_delivered(dest, 100.0);

        let mut restored = TicketStore::new();
        restored.replace_snapshot(store.snapshot());
        assert_eq!(restored.inbound_tokens(&dest, 200.0), vec![[1; 16]]);
        assert_eq!(restored.find_outbound(&dest, 200.0).unwrap().token, [2; 16]);
        assert!(restored.issue_for(dest, TICKET_EXPIRY, 200.0).is_none());
    }

    #[test]
    fn ticket_field_is_native_python_shape_and_rejects_expired_values() {
        let ticket = Ticket::new([0x42; 16], [0x11; 16], 2_000.0);
        let encoded = ticket.encode_field().unwrap();
        let value = rmpv::decode::read_value(&mut encoded.as_slice()).unwrap();
        let values = value.as_array().unwrap();
        assert_eq!(values[0].as_f64(), Some(2_000.0));
        assert_eq!(values[1].as_slice(), Some(&[0x42; 16][..]));

        let decoded = Ticket::decode_field([0x11; 16], &encoded, 1_000.0).unwrap();
        assert_eq!(decoded, ticket);
        assert!(Ticket::decode_field([0x11; 16], &encoded, 2_000.0).is_none());
    }
}
