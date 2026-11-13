//! Router state in `<storage>/lxmf/state.db`, as LXMF 1.3.0 keeps it
//! (`LXMF/Storage.py`, class `LXMFStore`). Schema, pragmas, and version
//! handling follow that file; each [`StateStore`] method is one of its
//! operations. Timestamps are Unix seconds, and the store reads the system
//! clock where upstream calls `time.time()`.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::types::PropagationTransientId;

/// File name inside the router's `lxmf` storage directory.
pub const FILE_NAME: &str = "state.db";

/// Highest `user_version` this module writes and reads; `LXMFStore.CURRENT_VERSION`.
#[cfg(feature = "sqlite-store")]
const USER_VERSION: i64 = 1;

/// Rows per `IN (...)` query; `LXMFStore.IN_CHUNK`.
#[cfg(feature = "sqlite-store")]
const IN_CHUNK: usize = 512;

/// Pragma list and order of `LXMFStore.__init__`.
#[cfg(feature = "sqlite-store")]
const PRAGMAS: &str = "
PRAGMA auto_vacuum=INCREMENTAL;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA journal_size_limit=8388608;
PRAGMA busy_timeout=1500;";

#[cfg(feature = "sqlite-store")]
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS stamp_costs (
    destination_hash BLOB PRIMARY KEY,
    updated          REAL NOT NULL,
    used             REAL,
    cost             REAL);
CREATE TABLE IF NOT EXISTS delivered_transient_ids (
    transient_id BLOB PRIMARY KEY,
    received     REAL NOT NULL);
CREATE TABLE IF NOT EXISTS processed_transient_ids (
    transient_id BLOB PRIMARY KEY,
    received     REAL NOT NULL);
CREATE TABLE IF NOT EXISTS tickets_outbound (
    destination_hash BLOB PRIMARY KEY,
    expires          REAL NOT NULL,
    ticket           BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS tickets_inbound (
    ticket           BLOB PRIMARY KEY,
    destination_hash BLOB NOT NULL,
    expires          REAL NOT NULL);
CREATE TABLE IF NOT EXISTS ticket_deliveries (
    destination_hash BLOB PRIMARY KEY,
    timestamp        REAL NOT NULL);
CREATE INDEX IF NOT EXISTS idx_delivered_received ON delivered_transient_ids (received);
CREATE INDEX IF NOT EXISTS idx_processed_received ON processed_transient_ids (received);
CREATE INDEX IF NOT EXISTS idx_stampcost_updated ON stamp_costs (updated);
CREATE INDEX IF NOT EXISTS idx_tickets_in_dest ON tickets_inbound (destination_hash);";

/// Failure of a state-store call.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StateStoreError {
    /// The file's `user_version` is newer than this module supports.
    #[error("state store user_version {found} is newer than supported {supported}")]
    NewerVersion {
        /// Version found in the file.
        found: i64,
        /// Highest version this module supports.
        supported: i64,
    },
    /// The file could not be opened, configured, or given its schema.
    #[error("state store could not be opened: {0}")]
    Open(String),
    /// A statement failed on an open store.
    #[error("state store operation failed: {0}")]
    Operation(String),
    /// A stored value does not have the shape the schema promises.
    #[error("invalid value in {table}: {reason}")]
    InvalidRow {
        /// Table holding the value.
        table: &'static str,
        /// What is wrong with it.
        reason: String,
    },
}

/// One validated row of a legacy file, ready for [`Backend::apply_imported`].
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ImportRow {
    Delivered(PropagationTransientId, f64),
    Processed(PropagationTransientId, f64),
    /// Destination, last heard, cost.
    StampCost([u8; 16], f64, Option<f64>),
    /// Destination, expires, ticket.
    TicketOutbound([u8; 16], f64, [u8; 16]),
    /// Ticket, destination, expires.
    TicketInbound([u8; 16], [u8; 16], f64),
    /// Destination, timestamp.
    TicketDelivery([u8; 16], f64),
}

mod sealed {
    pub trait Sealed {}
}

/// The operations of upstream's `LXMFStore`, one method each, under its names.
/// Implemented only in this module, so operations can be added.
pub trait StateStore: Send + sealed::Sealed {
    /// Insert or update a destination's stamp cost (`update_stamp_cost`).
    fn update_stamp_cost(
        &mut self,
        destination: &[u8; 16],
        cost: Option<f64>,
    ) -> Result<(), StateStoreError>;

    /// Stored cost, `None` if absent or recorded without a cost. Sets the usage time.
    fn get_outbound_stamp_cost(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<f64>, StateStoreError>;

    /// Delete up to `max_entries` stamp costs last updated before `cutoff`.
    fn cull_stamp_costs(
        &mut self,
        cutoff: f64,
        max_entries: usize,
    ) -> Result<usize, StateStoreError>;

    /// Whether a transient ID is in the delivered table.
    fn has_delivered(&mut self, id: &PropagationTransientId) -> Result<bool, StateStoreError>;

    /// The subset of `ids` present in the delivered table.
    fn known_delivered(
        &mut self,
        ids: &[PropagationTransientId],
    ) -> Result<HashSet<PropagationTransientId>, StateStoreError>;

    /// Insert or refresh a delivered transient ID.
    fn mark_locally_delivered(
        &mut self,
        id: &PropagationTransientId,
        received: f64,
    ) -> Result<(), StateStoreError>;

    /// Insert or refresh a processed transient ID.
    fn unconditionally_mark_processed(
        &mut self,
        id: &PropagationTransientId,
        received: f64,
    ) -> Result<(), StateStoreError>;

    /// Insert a delivered ID unless present; `true` if it was inserted.
    fn conditionally_claim_delivered(
        &mut self,
        id: &PropagationTransientId,
        received: f64,
    ) -> Result<bool, StateStoreError>;

    /// Insert a processed ID unless present; `true` if it was inserted.
    fn conditionally_claim_processed(
        &mut self,
        id: &PropagationTransientId,
        received: f64,
    ) -> Result<bool, StateStoreError>;

    /// Delete up to `max_entries` processed IDs received before `cutoff`.
    fn cull_processed(&mut self, cutoff: f64, max_entries: usize)
    -> Result<usize, StateStoreError>;

    /// Delete up to `max_entries` delivered IDs received before `cutoff`.
    fn cull_delivered(&mut self, cutoff: f64, max_entries: usize)
    -> Result<usize, StateStoreError>;

    /// Store the outbound ticket for a destination, replacing any previous one.
    fn remember_ticket(
        &mut self,
        destination: &[u8; 16],
        expires: f64,
        ticket: &[u8; 16],
    ) -> Result<(), StateStoreError>;

    /// Unexpired outbound ticket for a destination.
    fn get_outbound_ticket(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<[u8; 16]>, StateStoreError>;

    /// Expiry of the unexpired outbound ticket for a destination.
    fn get_outbound_ticket_expiry(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<f64>, StateStoreError>;

    /// The unexpired inbound ticket expiring latest, provided it stays valid
    /// for at least `renew_before` more seconds; returned as `(expires, ticket)`.
    fn get_reusable_inbound_ticket(
        &mut self,
        destination: &[u8; 16],
        renew_before: f64,
    ) -> Result<Option<(f64, [u8; 16])>, StateStoreError>;

    /// Store a locally issued inbound ticket.
    fn store_inbound_ticket(
        &mut self,
        destination: &[u8; 16],
        ticket: &[u8; 16],
        expires: f64,
    ) -> Result<(), StateStoreError>;

    /// Unexpired inbound tickets for a destination; `None` when there are none.
    fn get_inbound_tickets(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<Vec<[u8; 16]>>, StateStoreError>;

    /// Time of the last ticket delivered to a destination.
    fn get_last_ticket_delivery(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<f64>, StateStoreError>;

    /// Record the time of the last ticket delivered to a destination.
    fn mark_last_ticket_delivery(
        &mut self,
        destination: &[u8; 16],
        timestamp: f64,
    ) -> Result<(), StateStoreError>;

    /// Delete up to `max_entries` outbound tickets expiring before `cutoff`.
    fn cull_tickets_outbound(
        &mut self,
        cutoff: f64,
        max_entries: usize,
    ) -> Result<usize, StateStoreError>;

    /// Delete up to `max_entries` inbound tickets expiring before `cutoff`.
    fn cull_tickets_inbound(
        &mut self,
        cutoff: f64,
        max_entries: usize,
    ) -> Result<usize, StateStoreError>;

    /// Return up to `max_pages` free pages to the file system; returns pages freed.
    fn incremental_vacuum(&mut self, max_pages: usize) -> Result<usize, StateStoreError>;
}

/// What the router needs beyond upstream's operations: the legacy import,
/// the processed IDs the propagation node shares, and writes that are on disk
/// when they return.
pub(crate) trait Backend: StateStore {
    /// Run `job` as one transaction that is flushed to disk before this
    /// returns. The claim a delivery follows and the ticket a signed message
    /// carries were fsynced by this crate's earlier files, and stay so:
    /// a claim lost to a power cut delivers a message twice, a lost ticket
    /// leaves the recipient's replies failing their stamp check.
    fn synced(&mut self, job: &mut dyn FnMut(&mut dyn StateStore)) -> Result<(), StateStoreError>;

    /// Insert imported rows in one transaction; rows already present are kept
    /// (`INSERT OR IGNORE` in `LXMFStore.import_legacy_*`).
    fn apply_imported(&mut self, rows: &[ImportRow]) -> Result<usize, StateStoreError>;

    /// Every processed transient ID with its timestamp.
    fn processed_ids(&mut self) -> Result<Vec<(PropagationTransientId, f64)>, StateStoreError>;
}

/// Unix time as f64 seconds.
fn clock() -> f64 {
    crate::now_f64()
}

#[cfg(feature = "sqlite-store")]
mod sqlite_impl {
    use super::*;
    use rusqlite::{Connection, OptionalExtension, params};

    fn op(error: rusqlite::Error) -> StateStoreError {
        StateStoreError::Operation(error.to_string())
    }

    fn fixed<const N: usize>(
        bytes: Vec<u8>,
        table: &'static str,
    ) -> Result<[u8; N], StateStoreError> {
        bytes
            .try_into()
            .map_err(|v: Vec<u8>| StateStoreError::InvalidRow {
                table,
                reason: format!("expected {N} bytes, found {}", v.len()),
            })
    }

    /// The `state.db` file on one connection.
    #[derive(Debug)]
    pub struct SqliteStateStore {
        conn: Connection,
    }

    impl SqliteStateStore {
        /// Open or create `path` with upstream's pragmas, schema, and
        /// `user_version`; a file with a newer version is refused.
        pub fn open(path: &Path) -> Result<Self, StateStoreError> {
            let open = |e: rusqlite::Error| StateStoreError::Open(e.to_string());
            let conn = Connection::open(path).map_err(open)?;
            // Read before any pragma, so a newer file is refused as it was found;
            // `LXMFStore.__init__` switches it to WAL first.
            let found: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(open)?;
            if found > USER_VERSION {
                return Err(StateStoreError::NewerVersion {
                    found,
                    supported: USER_VERSION,
                });
            }
            conn.execute_batch(PRAGMAS).map_err(open)?;
            let migrate = || -> rusqlite::Result<()> {
                conn.execute_batch("BEGIN")?;
                conn.execute_batch(SCHEMA)?;
                conn.execute_batch(&format!("PRAGMA user_version = {USER_VERSION}"))?;
                conn.execute_batch("COMMIT")
            };
            if let Err(error) = migrate() {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(StateStoreError::Open(error.to_string()));
            }
            Ok(Self { conn })
        }

        fn cull(
            &self,
            table: &'static str,
            column: &'static str,
            cutoff: f64,
            max_entries: usize,
        ) -> Result<usize, StateStoreError> {
            let sql = format!(
                "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {column} < ?1 LIMIT {max_entries})"
            );
            self.conn.execute(&sql, params![cutoff]).map_err(op)
        }

        fn claim(
            &self,
            table: &'static str,
            id: &PropagationTransientId,
            received: f64,
        ) -> Result<bool, StateStoreError> {
            let sql = format!(
                "INSERT INTO {table} (transient_id, received) VALUES (?1, ?2) ON CONFLICT(transient_id) DO NOTHING"
            );
            Ok(self
                .conn
                .execute(&sql, params![id.as_slice(), received])
                .map_err(op)?
                == 1)
        }

        fn upsert_received(
            &self,
            table: &'static str,
            id: &PropagationTransientId,
            received: f64,
        ) -> Result<(), StateStoreError> {
            let sql = format!(
                "INSERT INTO {table} (transient_id, received) VALUES (?1, ?2) ON CONFLICT(transient_id) DO UPDATE SET received=excluded.received"
            );
            self.conn
                .execute(&sql, params![id.as_slice(), received])
                .map(|_| ())
                .map_err(op)
        }
    }

    impl sealed::Sealed for SqliteStateStore {}

    impl StateStore for SqliteStateStore {
        fn update_stamp_cost(
            &mut self,
            destination: &[u8; 16],
            cost: Option<f64>,
        ) -> Result<(), StateStoreError> {
            self.conn
                .execute(
                    "INSERT INTO stamp_costs (destination_hash, updated, used, cost) VALUES (?1, ?2, NULL, ?3) ON CONFLICT(destination_hash) DO UPDATE SET updated=excluded.updated, cost=excluded.cost",
                    params![destination.as_slice(), clock(), cost],
                )
                .map(|_| ())
                .map_err(op)
        }

        fn get_outbound_stamp_cost(
            &mut self,
            destination: &[u8; 16],
        ) -> Result<Option<f64>, StateStoreError> {
            let cost: Option<Option<f64>> = self
                .conn
                .query_row(
                    "SELECT cost FROM stamp_costs WHERE destination_hash=?1",
                    params![destination.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(op)?;
            let Some(cost) = cost else {
                return Ok(None);
            };
            // Usage time is advisory; a failed update keeps the cost, as upstream does.
            let _ = self.conn.execute(
                "UPDATE stamp_costs SET used=?1 WHERE destination_hash=?2",
                params![clock(), destination.as_slice()],
            );
            Ok(cost)
        }

        fn cull_stamp_costs(
            &mut self,
            cutoff: f64,
            max_entries: usize,
        ) -> Result<usize, StateStoreError> {
            self.cull("stamp_costs", "updated", cutoff, max_entries)
        }

        fn has_delivered(&mut self, id: &PropagationTransientId) -> Result<bool, StateStoreError> {
            let row: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT transient_id FROM delivered_transient_ids WHERE transient_id=?1",
                    params![id.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(op)?;
            Ok(row.is_some())
        }

        fn known_delivered(
            &mut self,
            ids: &[PropagationTransientId],
        ) -> Result<HashSet<PropagationTransientId>, StateStoreError> {
            let mut known = HashSet::new();
            for chunk in ids.chunks(IN_CHUNK) {
                let marks = vec!["?"; chunk.len()].join(",");
                let sql = format!(
                    "SELECT transient_id FROM delivered_transient_ids WHERE transient_id IN ({marks})"
                );
                let mut stmt = self.conn.prepare(&sql).map_err(op)?;
                let params = rusqlite::params_from_iter(chunk.iter().map(|id| id.as_slice()));
                let rows = stmt
                    .query_map(params, |row| row.get::<_, Vec<u8>>(0))
                    .map_err(op)?;
                for row in rows {
                    known.insert(fixed(row.map_err(op)?, "delivered_transient_ids")?);
                }
            }
            Ok(known)
        }

        fn mark_locally_delivered(
            &mut self,
            id: &PropagationTransientId,
            received: f64,
        ) -> Result<(), StateStoreError> {
            self.upsert_received("delivered_transient_ids", id, received)
        }

        fn unconditionally_mark_processed(
            &mut self,
            id: &PropagationTransientId,
            received: f64,
        ) -> Result<(), StateStoreError> {
            self.upsert_received("processed_transient_ids", id, received)
        }

        fn conditionally_claim_delivered(
            &mut self,
            id: &PropagationTransientId,
            received: f64,
        ) -> Result<bool, StateStoreError> {
            self.claim("delivered_transient_ids", id, received)
        }

        fn conditionally_claim_processed(
            &mut self,
            id: &PropagationTransientId,
            received: f64,
        ) -> Result<bool, StateStoreError> {
            self.claim("processed_transient_ids", id, received)
        }

        fn cull_processed(
            &mut self,
            cutoff: f64,
            max_entries: usize,
        ) -> Result<usize, StateStoreError> {
            self.cull("processed_transient_ids", "received", cutoff, max_entries)
        }

        fn cull_delivered(
            &mut self,
            cutoff: f64,
            max_entries: usize,
        ) -> Result<usize, StateStoreError> {
            self.cull("delivered_transient_ids", "received", cutoff, max_entries)
        }

        fn remember_ticket(
            &mut self,
            destination: &[u8; 16],
            expires: f64,
            ticket: &[u8; 16],
        ) -> Result<(), StateStoreError> {
            self.conn
                .execute(
                    "INSERT INTO tickets_outbound (destination_hash, expires, ticket) VALUES (?1, ?2, ?3) ON CONFLICT(destination_hash) DO UPDATE SET expires=excluded.expires, ticket=excluded.ticket",
                    params![destination.as_slice(), expires, ticket.as_slice()],
                )
                .map(|_| ())
                .map_err(op)
        }

        fn get_outbound_ticket(
            &mut self,
            destination: &[u8; 16],
        ) -> Result<Option<[u8; 16]>, StateStoreError> {
            let row: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT ticket FROM tickets_outbound WHERE destination_hash=?1 AND expires > ?2",
                    params![destination.as_slice(), clock()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(op)?;
            row.map(|bytes| fixed(bytes, "tickets_outbound"))
                .transpose()
        }

        fn get_outbound_ticket_expiry(
            &mut self,
            destination: &[u8; 16],
        ) -> Result<Option<f64>, StateStoreError> {
            self.conn
                .query_row(
                    "SELECT expires FROM tickets_outbound WHERE destination_hash=?1 AND expires > ?2",
                    params![destination.as_slice(), clock()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(op)
        }

        fn get_reusable_inbound_ticket(
            &mut self,
            destination: &[u8; 16],
            renew_before: f64,
        ) -> Result<Option<(f64, [u8; 16])>, StateStoreError> {
            let row: Option<(f64, Vec<u8>)> = self
                .conn
                .query_row(
                    "SELECT expires, ticket FROM tickets_inbound WHERE destination_hash=?1 AND expires > ?2 ORDER BY expires DESC LIMIT 1",
                    params![destination.as_slice(), clock() + renew_before],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(op)?;
            row.map(|(expires, bytes)| Ok((expires, fixed(bytes, "tickets_inbound")?)))
                .transpose()
        }

        fn store_inbound_ticket(
            &mut self,
            destination: &[u8; 16],
            ticket: &[u8; 16],
            expires: f64,
        ) -> Result<(), StateStoreError> {
            self.conn
                .execute(
                    "INSERT INTO tickets_inbound (ticket, destination_hash, expires) VALUES (?1, ?2, ?3) ON CONFLICT(ticket) DO UPDATE SET destination_hash=excluded.destination_hash, expires=excluded.expires",
                    params![ticket.as_slice(), destination.as_slice(), expires],
                )
                .map(|_| ())
                .map_err(op)
        }

        fn get_inbound_tickets(
            &mut self,
            destination: &[u8; 16],
        ) -> Result<Option<Vec<[u8; 16]>>, StateStoreError> {
            let mut stmt = self
                .conn
                .prepare_cached(
                    "SELECT ticket FROM tickets_inbound WHERE destination_hash=?1 AND expires > ?2",
                )
                .map_err(op)?;
            let rows = stmt
                .query_map(params![destination.as_slice(), clock()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(op)?;
            let mut tickets = Vec::new();
            for row in rows {
                tickets.push(fixed(row.map_err(op)?, "tickets_inbound")?);
            }
            Ok((!tickets.is_empty()).then_some(tickets))
        }

        fn get_last_ticket_delivery(
            &mut self,
            destination: &[u8; 16],
        ) -> Result<Option<f64>, StateStoreError> {
            self.conn
                .query_row(
                    "SELECT timestamp FROM ticket_deliveries WHERE destination_hash=?1",
                    params![destination.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(op)
        }

        fn mark_last_ticket_delivery(
            &mut self,
            destination: &[u8; 16],
            timestamp: f64,
        ) -> Result<(), StateStoreError> {
            self.conn
                .execute(
                    "INSERT INTO ticket_deliveries (destination_hash, timestamp) VALUES (?1, ?2) ON CONFLICT(destination_hash) DO UPDATE SET timestamp=excluded.timestamp",
                    params![destination.as_slice(), timestamp],
                )
                .map(|_| ())
                .map_err(op)
        }

        fn cull_tickets_outbound(
            &mut self,
            cutoff: f64,
            max_entries: usize,
        ) -> Result<usize, StateStoreError> {
            self.cull("tickets_outbound", "expires", cutoff, max_entries)
        }

        fn cull_tickets_inbound(
            &mut self,
            cutoff: f64,
            max_entries: usize,
        ) -> Result<usize, StateStoreError> {
            self.cull("tickets_inbound", "expires", cutoff, max_entries)
        }

        fn incremental_vacuum(&mut self, max_pages: usize) -> Result<usize, StateStoreError> {
            let freelist = |conn: &Connection| -> Result<i64, StateStoreError> {
                conn.query_row("PRAGMA freelist_count", [], |row| row.get(0))
                    .map_err(op)
            };
            let mut freed: i64 = 0;
            while freed < max_pages as i64 {
                let before = freelist(&self.conn)?;
                let budget = max_pages as i64 - freed;
                self.conn
                    .execute_batch(&format!("PRAGMA incremental_vacuum({budget})"))
                    .map_err(op)?;
                let after = freelist(&self.conn)?;
                if after >= before {
                    break;
                }
                freed += before - after;
            }
            Ok(freed as usize)
        }
    }

    impl Backend for SqliteStateStore {
        fn synced(
            &mut self,
            job: &mut dyn FnMut(&mut dyn StateStore),
        ) -> Result<(), StateStoreError> {
            // Upstream commits every write at `synchronous=NORMAL`, which leaves
            // the WAL unflushed. `fullfsync` makes the flush reach the disk on
            // Apple systems and does nothing elsewhere. Both are restored after.
            let committed = self
                .conn
                .execute_batch("PRAGMA fullfsync=ON; PRAGMA synchronous=FULL; BEGIN")
                .map_err(op)
                .and_then(|()| {
                    job(self);
                    self.conn.execute_batch("COMMIT").map_err(op)
                });
            if committed.is_err() {
                let _ = self.conn.execute_batch("ROLLBACK");
            }
            if let Err(error) = self
                .conn
                .execute_batch("PRAGMA synchronous=NORMAL; PRAGMA fullfsync=OFF")
            {
                tracing::warn!(%error, "could not restore the LXMF state store's synchronous level");
            }
            committed
        }

        fn apply_imported(&mut self, rows: &[ImportRow]) -> Result<usize, StateStoreError> {
            let tx = self.conn.transaction().map_err(op)?;
            for row in rows {
                match row {
                    ImportRow::Delivered(id, at) => tx
                        .prepare_cached("INSERT OR IGNORE INTO delivered_transient_ids (transient_id, received) VALUES (?1, ?2)")
                        .and_then(|mut s| s.execute(params![id.as_slice(), at])),
                    ImportRow::Processed(id, at) => tx
                        .prepare_cached("INSERT OR IGNORE INTO processed_transient_ids (transient_id, received) VALUES (?1, ?2)")
                        .and_then(|mut s| s.execute(params![id.as_slice(), at])),
                    ImportRow::StampCost(dest, updated, cost) => tx
                        .prepare_cached("INSERT OR IGNORE INTO stamp_costs (destination_hash, updated, used, cost) VALUES (?1, ?2, NULL, ?3)")
                        .and_then(|mut s| s.execute(params![dest.as_slice(), updated, cost])),
                    ImportRow::TicketOutbound(dest, expires, ticket) => tx
                        .prepare_cached("INSERT OR IGNORE INTO tickets_outbound (destination_hash, expires, ticket) VALUES (?1, ?2, ?3)")
                        .and_then(|mut s| s.execute(params![dest.as_slice(), expires, ticket.as_slice()])),
                    ImportRow::TicketInbound(ticket, dest, expires) => tx
                        .prepare_cached("INSERT OR IGNORE INTO tickets_inbound (ticket, destination_hash, expires) VALUES (?1, ?2, ?3)")
                        .and_then(|mut s| s.execute(params![ticket.as_slice(), dest.as_slice(), expires])),
                    ImportRow::TicketDelivery(dest, at) => tx
                        .prepare_cached("INSERT OR IGNORE INTO ticket_deliveries (destination_hash, timestamp) VALUES (?1, ?2)")
                        .and_then(|mut s| s.execute(params![dest.as_slice(), at])),
                }
                .map_err(op)?;
            }
            tx.commit().map_err(op)?;
            Ok(rows.len())
        }

        fn processed_ids(&mut self) -> Result<Vec<(PropagationTransientId, f64)>, StateStoreError> {
            let mut stmt = self
                .conn
                .prepare("SELECT transient_id, received FROM processed_transient_ids")
                .map_err(op)?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, f64>(1)?)))
                .map_err(op)?;
            let mut out = Vec::new();
            for row in rows {
                let (id, at) = row.map_err(op)?;
                out.push((fixed(id, "processed_transient_ids")?, at));
            }
            Ok(out)
        }
    }

    impl Drop for SqliteStateStore {
        fn drop(&mut self) {
            // `LXMFStore.close`.
            let _ = self.conn.execute_batch("PRAGMA optimize");
        }
    }
}
#[cfg(feature = "sqlite-store")]
pub use sqlite_impl::SqliteStateStore;

/// The same operations in memory, for a router without a storage directory
/// and for a session whose `state.db` could not be opened.
#[derive(Debug, Default)]
pub(crate) struct MemoryStateStore {
    stamp_costs: HashMap<[u8; 16], (f64, Option<f64>)>,
    delivered: HashMap<PropagationTransientId, f64>,
    processed: HashMap<PropagationTransientId, f64>,
    tickets_outbound: HashMap<[u8; 16], (f64, [u8; 16])>,
    tickets_inbound: HashMap<[u8; 16], ([u8; 16], f64)>,
    last_deliveries: HashMap<[u8; 16], f64>,
}

impl MemoryStateStore {
    fn cull_map<K: Clone + Eq + std::hash::Hash, V>(
        map: &mut HashMap<K, V>,
        max_entries: usize,
        before: impl Fn(&V) -> bool,
    ) -> usize {
        let doomed: Vec<K> = map
            .iter()
            .filter(|(_, v)| before(v))
            .take(max_entries)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &doomed {
            map.remove(key);
        }
        doomed.len()
    }
}

impl sealed::Sealed for MemoryStateStore {}

impl StateStore for MemoryStateStore {
    fn update_stamp_cost(
        &mut self,
        destination: &[u8; 16],
        cost: Option<f64>,
    ) -> Result<(), StateStoreError> {
        self.stamp_costs.insert(*destination, (clock(), cost));
        Ok(())
    }

    fn get_outbound_stamp_cost(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<f64>, StateStoreError> {
        Ok(self
            .stamp_costs
            .get(destination)
            .and_then(|(_, cost)| *cost))
    }

    fn cull_stamp_costs(
        &mut self,
        cutoff: f64,
        max_entries: usize,
    ) -> Result<usize, StateStoreError> {
        Ok(Self::cull_map(
            &mut self.stamp_costs,
            max_entries,
            |(updated, _)| *updated < cutoff,
        ))
    }

    fn has_delivered(&mut self, id: &PropagationTransientId) -> Result<bool, StateStoreError> {
        Ok(self.delivered.contains_key(id))
    }

    fn known_delivered(
        &mut self,
        ids: &[PropagationTransientId],
    ) -> Result<HashSet<PropagationTransientId>, StateStoreError> {
        Ok(ids
            .iter()
            .filter(|id| self.delivered.contains_key(*id))
            .copied()
            .collect())
    }

    fn mark_locally_delivered(
        &mut self,
        id: &PropagationTransientId,
        received: f64,
    ) -> Result<(), StateStoreError> {
        self.delivered.insert(*id, received);
        Ok(())
    }

    fn unconditionally_mark_processed(
        &mut self,
        id: &PropagationTransientId,
        received: f64,
    ) -> Result<(), StateStoreError> {
        self.processed.insert(*id, received);
        Ok(())
    }

    fn conditionally_claim_delivered(
        &mut self,
        id: &PropagationTransientId,
        received: f64,
    ) -> Result<bool, StateStoreError> {
        Ok(match self.delivered.entry(*id) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(received);
                true
            }
        })
    }

    fn conditionally_claim_processed(
        &mut self,
        id: &PropagationTransientId,
        received: f64,
    ) -> Result<bool, StateStoreError> {
        Ok(match self.processed.entry(*id) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(received);
                true
            }
        })
    }

    fn cull_processed(
        &mut self,
        cutoff: f64,
        max_entries: usize,
    ) -> Result<usize, StateStoreError> {
        Ok(Self::cull_map(&mut self.processed, max_entries, |t| {
            *t < cutoff
        }))
    }

    fn cull_delivered(
        &mut self,
        cutoff: f64,
        max_entries: usize,
    ) -> Result<usize, StateStoreError> {
        Ok(Self::cull_map(&mut self.delivered, max_entries, |t| {
            *t < cutoff
        }))
    }

    fn remember_ticket(
        &mut self,
        destination: &[u8; 16],
        expires: f64,
        ticket: &[u8; 16],
    ) -> Result<(), StateStoreError> {
        self.tickets_outbound
            .insert(*destination, (expires, *ticket));
        Ok(())
    }

    fn get_outbound_ticket(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<[u8; 16]>, StateStoreError> {
        let now = clock();
        Ok(self
            .tickets_outbound
            .get(destination)
            .filter(|(expires, _)| *expires > now)
            .map(|(_, ticket)| *ticket))
    }

    fn get_outbound_ticket_expiry(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<f64>, StateStoreError> {
        let now = clock();
        Ok(self
            .tickets_outbound
            .get(destination)
            .filter(|(expires, _)| *expires > now)
            .map(|(expires, _)| *expires))
    }

    fn get_reusable_inbound_ticket(
        &mut self,
        destination: &[u8; 16],
        renew_before: f64,
    ) -> Result<Option<(f64, [u8; 16])>, StateStoreError> {
        let threshold = clock() + renew_before;
        Ok(self
            .tickets_inbound
            .iter()
            .filter(|(_, (dest, expires))| dest == destination && *expires > threshold)
            .max_by(|a, b| (a.1).1.total_cmp(&(b.1).1))
            .map(|(ticket, (_, expires))| (*expires, *ticket)))
    }

    fn store_inbound_ticket(
        &mut self,
        destination: &[u8; 16],
        ticket: &[u8; 16],
        expires: f64,
    ) -> Result<(), StateStoreError> {
        self.tickets_inbound
            .insert(*ticket, (*destination, expires));
        Ok(())
    }

    fn get_inbound_tickets(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<Vec<[u8; 16]>>, StateStoreError> {
        let now = clock();
        let tickets: Vec<[u8; 16]> = self
            .tickets_inbound
            .iter()
            .filter(|(_, (dest, expires))| dest == destination && *expires > now)
            .map(|(ticket, _)| *ticket)
            .collect();
        Ok((!tickets.is_empty()).then_some(tickets))
    }

    fn get_last_ticket_delivery(
        &mut self,
        destination: &[u8; 16],
    ) -> Result<Option<f64>, StateStoreError> {
        Ok(self.last_deliveries.get(destination).copied())
    }

    fn mark_last_ticket_delivery(
        &mut self,
        destination: &[u8; 16],
        timestamp: f64,
    ) -> Result<(), StateStoreError> {
        self.last_deliveries.insert(*destination, timestamp);
        Ok(())
    }

    fn cull_tickets_outbound(
        &mut self,
        cutoff: f64,
        max_entries: usize,
    ) -> Result<usize, StateStoreError> {
        Ok(Self::cull_map(
            &mut self.tickets_outbound,
            max_entries,
            |(e, _)| *e < cutoff,
        ))
    }

    fn cull_tickets_inbound(
        &mut self,
        cutoff: f64,
        max_entries: usize,
    ) -> Result<usize, StateStoreError> {
        Ok(Self::cull_map(
            &mut self.tickets_inbound,
            max_entries,
            |(_, e)| *e < cutoff,
        ))
    }

    fn incremental_vacuum(&mut self, _max_pages: usize) -> Result<usize, StateStoreError> {
        Ok(0)
    }
}

impl Backend for MemoryStateStore {
    fn synced(&mut self, job: &mut dyn FnMut(&mut dyn StateStore)) -> Result<(), StateStoreError> {
        job(self);
        Ok(())
    }

    fn apply_imported(&mut self, rows: &[ImportRow]) -> Result<usize, StateStoreError> {
        for row in rows {
            match *row {
                ImportRow::Delivered(id, at) => {
                    self.delivered.entry(id).or_insert(at);
                }
                ImportRow::Processed(id, at) => {
                    self.processed.entry(id).or_insert(at);
                }
                ImportRow::StampCost(dest, updated, cost) => {
                    self.stamp_costs.entry(dest).or_insert((updated, cost));
                }
                ImportRow::TicketOutbound(dest, expires, ticket) => {
                    self.tickets_outbound
                        .entry(dest)
                        .or_insert((expires, ticket));
                }
                ImportRow::TicketInbound(ticket, dest, expires) => {
                    self.tickets_inbound
                        .entry(ticket)
                        .or_insert((dest, expires));
                }
                ImportRow::TicketDelivery(dest, at) => {
                    self.last_deliveries.entry(dest).or_insert(at);
                }
            }
        }
        Ok(rows.len())
    }

    fn processed_ids(&mut self) -> Result<Vec<(PropagationTransientId, f64)>, StateStoreError> {
        Ok(self.processed.iter().map(|(id, at)| (*id, *at)).collect())
    }
}

/// Import of the msgpack caches that LXMF 1.3.0 replaced, by the rules of
/// `LXMFStore.import_legacy_*`. Files written by earlier rsLXMF releases are
/// recognised by their layout and imported to the same rows.
pub(crate) mod legacy {
    use super::*;
    use crate::ticket::{Ticket, TicketStoreSnapshot};

    /// The caches, in the order `LXMRouter.__import_legacy_storage` imports them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Source {
        LocalDeliveries,
        LocallyProcessed,
        OutboundStampCosts,
        AvailableTickets,
    }

    impl Source {
        pub(crate) const ALL: [Self; 4] = [
            Self::LocalDeliveries,
            Self::LocallyProcessed,
            Self::OutboundStampCosts,
            Self::AvailableTickets,
        ];

        pub(crate) fn file_name(self) -> &'static str {
            match self {
                Self::LocalDeliveries => "local_deliveries",
                Self::LocallyProcessed => "locally_processed",
                Self::OutboundStampCosts => "outbound_stamp_costs",
                Self::AvailableTickets => "available_tickets",
            }
        }
    }

    /// Why a source was not imported; it stays where it is and is tried again
    /// at the next start, as upstream does.
    #[derive(Debug)]
    pub(crate) enum ImportError {
        Unreadable(String),
        InvalidFormat,
        Store(StateStoreError),
    }

    impl std::fmt::Display for ImportError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Unreadable(error) => write!(f, "could not be read: {error}"),
                Self::InvalidFormat => f.write_str("has an invalid data format"),
                Self::Store(error) => write!(f, "{error}"),
            }
        }
    }

    /// A fixed-length key. Upstream writes `bin`; rsLXMF wrote `[u8; N]` as an
    /// array of integers.
    fn fixed_key<const N: usize>(value: &rmpv::Value) -> Option<[u8; N]> {
        match value {
            rmpv::Value::Binary(bytes) => bytes.as_slice().try_into().ok(),
            rmpv::Value::Array(items) => {
                let bytes: Option<Vec<u8>> = items
                    .iter()
                    .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                    .collect();
                bytes?.try_into().ok()
            }
            _ => None,
        }
    }

    /// Python's `type(v) in (int, float)`.
    fn number(value: &rmpv::Value) -> Option<f64> {
        match value {
            rmpv::Value::Integer(n) => n.as_f64(),
            rmpv::Value::F32(n) => Some(f64::from(*n)),
            rmpv::Value::F64(n) => Some(*n),
            _ => None,
        }
    }

    fn field<'a>(map: &'a [(rmpv::Value, rmpv::Value)], name: &str) -> Option<&'a rmpv::Value> {
        // A later duplicate key wins, as in a Python dict.
        map.iter()
            .rev()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    }

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum RustTickets {
        Directional(TicketStoreSnapshot),
        Flat(Vec<Ticket>),
    }

    /// rsLXMF's own `available_tickets`: the directional snapshot, or the older
    /// flat list whose entries served both directions.
    fn rust_ticket_rows(bytes: &[u8]) -> Option<Vec<ImportRow>> {
        let outbound =
            |t: &Ticket| ImportRow::TicketOutbound(t.destination_hash, t.expires, t.token);
        let inbound = |t: &Ticket| ImportRow::TicketInbound(t.token, t.destination_hash, t.expires);
        Some(match rmp_serde::from_slice(bytes).ok()? {
            RustTickets::Directional(snapshot) => snapshot
                .outbound
                .iter()
                .map(outbound)
                .chain(snapshot.inbound.iter().map(inbound))
                .chain(
                    snapshot
                        .last_deliveries
                        .iter()
                        .map(|(dest, at)| ImportRow::TicketDelivery(*dest, *at)),
                )
                .collect(),
            RustTickets::Flat(tickets) => tickets
                .iter()
                .map(outbound)
                .chain(tickets.iter().map(inbound))
                .collect(),
        })
    }

    /// Decode `path` into the rows upstream's `import_legacy_*` would insert.
    pub(crate) fn read_rows(source: Source, path: &Path) -> Result<Vec<ImportRow>, ImportError> {
        let bytes = std::fs::read(path).map_err(|e| ImportError::Unreadable(e.to_string()))?;
        // Upstream's unpacker ignores bytes after the first value.
        let root = rmpv::decode::read_value(&mut std::io::Cursor::new(&bytes))
            .map_err(|e| ImportError::Unreadable(e.to_string()))?;
        if source == Source::AvailableTickets && root.is_array() {
            return rust_ticket_rows(&bytes).ok_or(ImportError::InvalidFormat);
        }
        let Some(map) = root.as_map() else {
            return Err(ImportError::InvalidFormat);
        };
        let mut rows = Vec::new();
        match source {
            Source::LocalDeliveries | Source::LocallyProcessed => {
                for (key, value) in map {
                    let (Some(id), Some(at)) = (fixed_key::<32>(key), number(value)) else {
                        continue;
                    };
                    // Written this way so NaN is skipped, as `timestamp > 0` skips it.
                    if at > 0.0 {
                        rows.push(match source {
                            Source::LocalDeliveries => ImportRow::Delivered(id, at),
                            _ => ImportRow::Processed(id, at),
                        });
                    }
                }
            }
            Source::OutboundStampCosts => {
                for (key, value) in map {
                    let (Some(dest), Some(entry)) = (fixed_key::<16>(key), value.as_array()) else {
                        continue;
                    };
                    if entry.len() < 2 {
                        continue;
                    }
                    // Upstream writes `[time, cost]` under a `bin` key
                    // (`LXMRouter.update_stamp_cost_legacy`). rsLXMF wrote
                    // `StampCostEntry` as `[cost, recorded_at]` under an array key.
                    let (last_heard, cost) = match key {
                        rmpv::Value::Binary(_) => (&entry[0], &entry[1]),
                        _ => (&entry[1], &entry[0]),
                    };
                    let Some(last_heard) = number(last_heard) else {
                        continue;
                    };
                    let cost = match cost {
                        rmpv::Value::Nil => None,
                        other => match number(other) {
                            Some(cost) => Some(cost),
                            None => continue,
                        },
                    };
                    rows.push(ImportRow::StampCost(dest, last_heard, cost));
                }
            }
            Source::AvailableTickets => {
                if let Some(outbound) = field(map, "outbound").and_then(|v| v.as_map()) {
                    for (key, value) in outbound {
                        let (Some(dest), Some(entry)) = (fixed_key::<16>(key), value.as_array())
                        else {
                            continue;
                        };
                        if entry.len() < 2 {
                            continue;
                        }
                        if let (Some(expires), rmpv::Value::Binary(ticket)) =
                            (number(&entry[0]), &entry[1])
                            && let Ok(ticket) = ticket.as_slice().try_into()
                        {
                            rows.push(ImportRow::TicketOutbound(dest, expires, ticket));
                        }
                    }
                }
                if let Some(inbound) = field(map, "inbound").and_then(|v| v.as_map()) {
                    for (key, tickets) in inbound {
                        let (Some(dest), Some(tickets)) = (fixed_key::<16>(key), tickets.as_map())
                        else {
                            continue;
                        };
                        for (ticket, entry) in tickets {
                            let (Some(ticket), Some(entry)) =
                                (fixed_key::<16>(ticket), entry.as_array())
                            else {
                                continue;
                            };
                            if let Some(expires) = entry.first().and_then(number) {
                                rows.push(ImportRow::TicketInbound(ticket, dest, expires));
                            }
                        }
                    }
                }
                if let Some(deliveries) = field(map, "last_deliveries").and_then(|v| v.as_map()) {
                    for (key, value) in deliveries {
                        if let (Some(dest), Some(at)) = (fixed_key::<16>(key), number(value)) {
                            rows.push(ImportRow::TicketDelivery(dest, at));
                        }
                    }
                }
            }
        }
        Ok(rows)
    }

    /// Import one source in one transaction, then rename it to `<path>.imported`.
    /// The rename follows the commit, so an interrupted import runs again and
    /// inserts the same rows.
    pub(crate) fn import(
        store: &mut dyn Backend,
        source: Source,
        path: &Path,
    ) -> Result<usize, ImportError> {
        let rows = read_rows(source, path)?;
        let count = store.apply_imported(&rows).map_err(ImportError::Store)?;
        let mut imported = path.as_os_str().to_owned();
        imported.push(".imported");
        if let Err(error) = std::fs::rename(path, &imported) {
            tracing::warn!(%error, path = %path.display(), "could not mark legacy file as imported");
        }
        Ok(count)
    }
}

#[cfg(feature = "sqlite-store")]
type Job = Box<dyn FnOnce(&mut dyn Backend) + Send>;

/// The router's store. A file-backed store runs on its own thread, which owns
/// the connection: [`Self::write`] queues and returns, [`Self::call`] waits for
/// the result. Jobs run in the order they were handed over, so a read always
/// sees the writes queued before it.
pub(crate) struct StateStoreHandle {
    inner: Inner,
    /// `state.db` could not be opened; this session's state is not kept.
    fallback: bool,
}

enum Inner {
    Memory(Box<std::sync::Mutex<MemoryStateStore>>),
    #[cfg(feature = "sqlite-store")]
    File {
        jobs: Option<std::sync::mpsc::Sender<Job>>,
        worker: Option<std::thread::JoinHandle<()>>,
    },
}

impl std::fmt::Debug for StateStoreHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match (&self.inner, self.fallback) {
            (Inner::Memory(_), false) => "StateStoreHandle(memory)",
            (Inner::Memory(_), true) => "StateStoreHandle(memory, fallback)",
            #[cfg(feature = "sqlite-store")]
            (Inner::File { .. }, _) => "StateStoreHandle(file)",
        })
    }
}

impl StateStoreHandle {
    /// A store for a router without a storage directory.
    pub(crate) fn in_memory() -> Self {
        Self {
            inner: Inner::Memory(Default::default()),
            fallback: false,
        }
    }

    /// The in-memory store a router runs on when `state.db` cannot be opened.
    #[cfg(feature = "sqlite-store")]
    pub(crate) fn fallback() -> Self {
        Self {
            inner: Inner::Memory(Default::default()),
            fallback: true,
        }
    }

    /// Open `path` on a dedicated thread.
    #[cfg(feature = "sqlite-store")]
    pub(crate) fn open_file(path: &Path) -> Result<Self, StateStoreError> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (jobs, job_rx) = std::sync::mpsc::channel::<Job>();
        let path = path.to_path_buf();
        let worker = std::thread::Builder::new()
            .name("lxmf-state-store".into())
            .spawn(move || match SqliteStateStore::open(&path) {
                Ok(mut store) => {
                    let _ = ready_tx.send(Ok(()));
                    while let Ok(job) = job_rx.recv() {
                        job(&mut store);
                    }
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            })
            .map_err(|e| StateStoreError::Open(e.to_string()))?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                inner: Inner::File {
                    jobs: Some(jobs),
                    worker: Some(worker),
                },
                fallback: false,
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(StateStoreError::Open("store thread stopped".into())),
        }
    }

    /// Whether this is the in-memory store of a session whose file did not open.
    pub(crate) fn is_fallback(&self) -> bool {
        self.fallback
    }

    /// Whether writes reach `state.db`.
    pub(crate) fn is_file_backed(&self) -> bool {
        match &self.inner {
            Inner::Memory(_) => false,
            #[cfg(feature = "sqlite-store")]
            Inner::File { .. } => true,
        }
    }

    /// Run `job` and wait for its result; a file-backed store has committed
    /// the job's writes when this returns.
    pub(crate) fn call<T: Send + 'static>(
        &self,
        job: impl FnOnce(&mut dyn Backend) -> Result<T, StateStoreError> + Send + 'static,
    ) -> Result<T, StateStoreError> {
        match &self.inner {
            Inner::Memory(store) => job(&mut *store.lock().unwrap_or_else(|e| e.into_inner())),
            #[cfg(feature = "sqlite-store")]
            Inner::File { jobs, .. } => {
                let stopped = || StateStoreError::Operation("store thread stopped".into());
                let (tx, rx) = std::sync::mpsc::channel();
                jobs.as_ref()
                    .ok_or_else(stopped)?
                    .send(Box::new(move |store| {
                        let _ = tx.send(job(store));
                    }))
                    .map_err(|_| stopped())?;
                rx.recv().map_err(|_| stopped())?
            }
        }
    }

    /// [`Self::call`] with `job` run as one transaction that is flushed to
    /// disk before this returns ([`Backend::synced`]).
    pub(crate) fn call_synced<T: Send + 'static>(
        &self,
        mut job: impl FnMut(&mut dyn StateStore) -> Result<T, StateStoreError> + Send + 'static,
    ) -> Result<T, StateStoreError> {
        self.call(move |store| {
            let mut outcome = None;
            store.synced(&mut |store| outcome = Some(job(store)))?;
            outcome.expect("a synced transaction that began ran its job")
        })
    }

    /// Run a write nothing waits for. A file-backed store queues it; a failure
    /// is logged with `what`, as upstream logs it.
    pub(crate) fn write(
        &self,
        what: &'static str,
        job: impl FnOnce(&mut dyn Backend) -> Result<(), StateStoreError> + Send + 'static,
    ) {
        let logged = move |store: &mut dyn Backend| {
            if let Err(error) = job(store) {
                tracing::error!(%error, "could not {what} in the LXMF state store");
            }
        };
        match &self.inner {
            Inner::Memory(store) => logged(&mut *store.lock().unwrap_or_else(|e| e.into_inner())),
            #[cfg(feature = "sqlite-store")]
            Inner::File { jobs, .. } => {
                if jobs
                    .as_ref()
                    .is_none_or(|jobs| jobs.send(Box::new(logged)).is_err())
                {
                    tracing::error!("LXMF state store thread stopped; could not {what}");
                }
            }
        }
    }
}

#[cfg(feature = "sqlite-store")]
impl Drop for StateStoreHandle {
    fn drop(&mut self) {
        // Queued writes finish and the connection closes before the router is gone.
        if let Inner::File { jobs, worker } = &mut self.inner {
            drop(jobs.take());
            if let Some(worker) = worker.take() {
                let _ = worker.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::legacy::{Source, read_rows};
    use super::*;

    fn exercise(store: &mut dyn StateStore) {
        let id = [7u8; 32];
        assert!(store.conditionally_claim_delivered(&id, 1.0).unwrap());
        assert!(!store.conditionally_claim_delivered(&id, 2.0).unwrap());
        assert!(store.has_delivered(&id).unwrap());
        store.mark_locally_delivered(&id, 3.0).unwrap();
        assert!(store.conditionally_claim_processed(&id, 1.0).unwrap());
        assert_eq!(store.cull_delivered(10.0, 16).unwrap(), 1);
        assert!(!store.has_delivered(&id).unwrap());
        let dest = [9u8; 16];
        store.update_stamp_cost(&dest, Some(8.0)).unwrap();
        assert_eq!(store.get_outbound_stamp_cost(&dest).unwrap(), Some(8.0));
        store.update_stamp_cost(&dest, None).unwrap();
        assert_eq!(store.get_outbound_stamp_cost(&dest).unwrap(), None);
        let far = clock() + 1.0e6;
        store.remember_ticket(&dest, far, &[1; 16]).unwrap();
        assert_eq!(store.get_outbound_ticket(&dest).unwrap(), Some([1; 16]));
        store.store_inbound_ticket(&dest, &[2; 16], far).unwrap();
        assert_eq!(
            store.get_reusable_inbound_ticket(&dest, 60.0).unwrap(),
            Some((far, [2; 16]))
        );
        assert_eq!(
            store.get_inbound_tickets(&dest).unwrap(),
            Some(vec![[2; 16]])
        );
        assert_eq!(store.cull_tickets_inbound(clock(), 16).unwrap(), 0);
    }

    #[test]
    fn memory_store_follows_the_operation_contract() {
        exercise(&mut MemoryStateStore::default());
    }

    #[test]
    #[cfg(feature = "sqlite-store")]
    fn sqlite_store_follows_the_operation_contract() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = SqliteStateStore::open(&dir.path().join(FILE_NAME)).unwrap();
        exercise(&mut store);
    }

    #[test]
    #[cfg(feature = "sqlite-store")]
    fn a_newer_user_version_is_refused_and_the_file_keeps_its_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(FILE_NAME);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE later (x); PRAGMA user_version = 2")
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            SqliteStateStore::open(&path),
            Err(StateStoreError::NewerVersion {
                found: 2,
                supported: 1
            })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    fn rows_of(source: Source, bytes: Vec<u8>) -> Vec<ImportRow> {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(source.file_name());
        std::fs::write(&path, bytes).unwrap();
        read_rows(source, &path).unwrap()
    }

    // Every rsLXMF release up to 1.4.0 wrote `{[u8; 16]: [cost: u8, recorded_at]}`.
    #[test]
    fn stamp_costs_written_with_integer_costs_import() {
        #[derive(serde::Serialize)]
        struct Entry {
            cost: u8,
            recorded_at: f64,
        }
        let file = HashMap::from([(
            [0xAA; 16],
            Entry {
                cost: 12,
                recorded_at: 1_700_000_000.0,
            },
        )]);
        assert_eq!(
            rows_of(
                Source::OutboundStampCosts,
                rmp_serde::to_vec(&file).unwrap()
            ),
            vec![ImportRow::StampCost(
                [0xAA; 16],
                1_700_000_000.0,
                Some(12.0)
            )]
        );
    }

    // Later rsLXMF wrote `{[u8; 16]: [cost: Option<f64>, recorded_at]}`.
    #[test]
    fn stamp_costs_written_with_optional_fractional_costs_import() {
        #[derive(serde::Serialize)]
        struct Entry {
            cost: Option<f64>,
            recorded_at: f64,
        }
        let entry = |cost| Entry {
            cost,
            recorded_at: 1_700_000_000.0,
        };
        let file = HashMap::from([([0xAA; 16], entry(Some(8.5))), ([0xBB; 16], entry(None))]);
        let mut rows = rows_of(
            Source::OutboundStampCosts,
            rmp_serde::to_vec(&file).unwrap(),
        );
        rows.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        assert_eq!(
            rows,
            vec![
                ImportRow::StampCost([0xAA; 16], 1_700_000_000.0, Some(8.5)),
                ImportRow::StampCost([0xBB; 16], 1_700_000_000.0, None),
            ]
        );
    }

    #[test]
    fn transient_ids_written_by_rslxmf_import() {
        let file = HashMap::from([([0x11u8; 32], 1_700_000_000.0f64)]);
        assert_eq!(
            rows_of(Source::LocalDeliveries, rmp_serde::to_vec(&file).unwrap()),
            vec![ImportRow::Delivered([0x11; 32], 1_700_000_000.0)]
        );
        assert_eq!(
            rows_of(Source::LocallyProcessed, rmp_serde::to_vec(&file).unwrap()),
            vec![ImportRow::Processed([0x11; 32], 1_700_000_000.0)]
        );
    }

    #[test]
    fn tickets_written_by_rslxmf_import_in_both_of_its_layouts() {
        use crate::ticket::{Ticket, TicketStoreSnapshot};
        let learned = Ticket::new([0x01; 16], [0x02; 16], 9_999.0);
        let issued = Ticket::new([0x03; 16], [0x04; 16], 8_888.0);
        let directional = TicketStoreSnapshot {
            version: 1,
            outbound: vec![learned.clone()],
            inbound: vec![issued],
            last_deliveries: HashMap::from([([0x04; 16], 7_777.0)]),
        };
        assert_eq!(
            rows_of(
                Source::AvailableTickets,
                rmp_serde::to_vec(&directional).unwrap()
            ),
            vec![
                ImportRow::TicketOutbound([0x02; 16], 9_999.0, [0x01; 16]),
                ImportRow::TicketInbound([0x03; 16], [0x04; 16], 8_888.0),
                ImportRow::TicketDelivery([0x04; 16], 7_777.0),
            ]
        );
        // The flat list served both directions.
        assert_eq!(
            rows_of(
                Source::AvailableTickets,
                rmp_serde::to_vec(&vec![learned]).unwrap()
            ),
            vec![
                ImportRow::TicketOutbound([0x02; 16], 9_999.0, [0x01; 16]),
                ImportRow::TicketInbound([0x01; 16], [0x02; 16], 9_999.0),
            ]
        );
    }
}
