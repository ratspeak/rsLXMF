//! LXMF Ticket system: bypass PoW with pre-shared 16-byte tokens.
//!
//! Trusted peers may exchange tickets that bypass stamp requirements for a
//! fixed expiry window. Tickets are reusable until expiry and renewed once
//! within `TICKET_RENEW` of expiring.

use serde::{Deserialize, Serialize};

use crate::constants::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub token: [u8; 16],
    pub destination_hash: [u8; 16],
    /// Expiry timestamp (Unix epoch seconds).
    pub expires: f64,
    pub used: bool,
}

impl Ticket {
    pub fn new(token: [u8; 16], destination_hash: [u8; 16], expires: f64) -> Self {
        Self {
            token,
            destination_hash,
            expires,
            used: false,
        }
    }

    pub fn is_valid(&self, now: f64) -> bool {
        !self.used && now < self.expires
    }

    pub fn should_renew(&self, now: f64) -> bool {
        self.is_valid(now) && (self.expires - now) < TICKET_RENEW as f64
    }
}

#[derive(Debug, Default)]
pub struct TicketStore {
    tickets: Vec<Ticket>,
}

impl TicketStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, ticket: Ticket) {
        self.tickets.push(ticket);
    }

    pub fn find(&self, destination_hash: &[u8; 16], now: f64) -> Option<&Ticket> {
        self.tickets
            .iter()
            .find(|t| &t.destination_hash == destination_hash && t.is_valid(now))
    }

    /// Drop expired and used tickets (past TICKET_GRACE).
    pub fn cull(&mut self, now: f64) {
        self.tickets
            .retain(|t| !t.used && now < t.expires + TICKET_GRACE as f64);
    }

    pub fn count_valid(&self, now: f64) -> usize {
        self.tickets.iter().filter(|t| t.is_valid(now)).count()
    }

    /// Snapshot of all stored tickets (including expired / used).
    pub fn all(&self) -> &[Ticket] {
        &self.tickets
    }

    /// Replace the entire ticket set — used when restoring from persisted state.
    pub fn replace_all(&mut self, tickets: Vec<Ticket>) {
        self.tickets = tickets;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_validity() {
        let ticket = Ticket::new([0xAA; 16], [0xBB; 16], 1000.0);
        assert!(ticket.is_valid(999.0));
        assert!(!ticket.is_valid(1001.0));
    }

    #[test]
    fn test_ticket_used() {
        // `used` survives only for persisted-state compat; is_valid must
        // still reject such entries.
        let mut ticket = Ticket::new([0xAA; 16], [0xBB; 16], 1000.0);
        assert!(ticket.is_valid(500.0));
        ticket.used = true;
        assert!(!ticket.is_valid(500.0));
    }

    #[test]
    fn test_ticket_renew() {
        let expires = 2_000_000.0;
        let ticket = Ticket::new([0xAA; 16], [0xBB; 16], expires);
        // TICKET_RENEW is ~1 week; close to expiry should trigger, far should not.
        assert!(ticket.should_renew(expires - 1.0));
        assert!(!ticket.should_renew(0.0));
    }

    #[test]
    fn test_ticket_store() {
        let mut store = TicketStore::new();
        let dest = [0xBB; 16];

        store.add(Ticket::new([0x01; 16], dest, 1000.0));
        store.add(Ticket::new([0x02; 16], dest, 2000.0));
        store.add(Ticket::new([0x03; 16], [0xCC; 16], 1500.0));

        assert_eq!(store.count_valid(500.0), 3);
        assert_eq!(store.count_valid(1500.0), 1);

        let found = store.find(&dest, 500.0);
        assert!(found.is_some());
    }

    #[test]
    fn test_ticket_store_cull() {
        let mut store = TicketStore::new();
        store.add(Ticket::new([0x01; 16], [0xBB; 16], 100.0));
        store.add(Ticket::new([0x02; 16], [0xBB; 16], 99999.0));

        store.cull(100.0 + TICKET_GRACE as f64 + 1.0);
        assert_eq!(store.count_valid(99999.0 - 1.0), 1);
    }
}
