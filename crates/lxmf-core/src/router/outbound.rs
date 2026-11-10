//! Medium-aware outbound timing: Python `LXMRouter` path and retry model.
//!
//! The embedder supplies a [`MediumSnapshot`] of Reticulum's view (lowest
//! online bitrate, medium path timeout and per-destination routes); the router
//! derives retry waits, attempt limits and receipt timeouts from it.

use std::collections::HashMap;
use std::time::Duration;

use rand::Rng;

use crate::constants::{
    DELIVERY_RETRY_WAIT, MAX_DELIVERY_ATTEMPTS, PATH_REQUEST_WAIT, PROCESSING_INTERVAL,
};
use crate::message::LxMessage;

pub const PATH_REQUEST_DEBOUNCE: f64 = 60.0;
pub const SLOW_INTERFACE_BITRATE: u64 = 2000;
pub const AIRTIME_AWARE_MTU_TIME: f64 = 0.5;
const PER_HOP_TIMEOUT: f64 = rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT;

/// Reticulum's current route to a destination.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RouteInfo {
    pub hops: u8,
    /// `Reticulum.get_first_hop_timeout` for the destination, in seconds.
    pub first_hop_timeout: f64,
}

/// Reticulum inputs to outbound planning. A destination without an entry in
/// `routes` has no known path.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MediumSnapshot {
    /// `Reticulum.get_lowest_interface_bitrate`.
    pub lowest_interface_bitrate: Option<u64>,
    /// `Reticulum.get_medium_path_timeout`; 0 when no bitrate is known.
    pub medium_path_timeout: f64,
    pub routes: HashMap<[u8; 16], RouteInfo>,
}

impl MediumSnapshot {
    pub fn has_path(&self, destination: &[u8; 16]) -> bool {
        self.routes.contains_key(destination)
    }

    pub fn route(&self, destination: &[u8; 16]) -> Option<RouteInfo> {
        self.routes.get(destination).copied()
    }

    /// Python `LXMRouter.destination_round_trip`.
    pub fn destination_round_trip(&self, destination: &[u8; 16]) -> f64 {
        match self.routes.get(destination) {
            None => self.medium_path_timeout,
            Some(route) => {
                2.0 * (route.first_hop_timeout - PER_HOP_TIMEOUT).max(0.0) + PER_HOP_TIMEOUT
            }
        }
    }

    /// Python `LXMRouter.path_request_wait`.
    pub fn path_request_wait(&self) -> f64 {
        (PATH_REQUEST_WAIT as f64).max(self.medium_path_timeout)
    }

    /// Python `LXMRouter.slow_interface_online`.
    pub fn slow_interface_online(&self) -> bool {
        self.lowest_interface_bitrate
            .is_some_and(|bitrate| bitrate < SLOW_INTERFACE_BITRATE)
    }

    /// Window within which a repeated path request for one destination is skipped.
    pub fn path_request_debounce(&self) -> f64 {
        if self.slow_interface_online() {
            PATH_REQUEST_DEBOUNCE
        } else {
            self.path_request_wait()
        }
    }
}

/// Python `LXMRouter.attempt_limit`.
pub fn attempt_limit(message: &LxMessage) -> u32 {
    message
        .max_delivery_attempts
        .unwrap_or(MAX_DELIVERY_ATTEMPTS)
}

/// Python `LXMRouter.attempt_due`.
pub fn attempt_due(message: &LxMessage, has_path: bool, now: f64) -> bool {
    now > message.next_delivery_attempt || (message.awaiting_path && has_path)
}

/// Python `LXMRouter.schedule_attempt`, given the round trip it would use:
/// the medium path timeout for a path request, else the destination round trip.
pub fn schedule_attempt(message: &mut LxMessage, round_trip: f64, path_request: bool, now: f64) {
    let wait = if path_request {
        message.awaiting_path = true;
        (PATH_REQUEST_WAIT as f64).max(round_trip)
    } else {
        (DELIVERY_RETRY_WAIT as f64).max(round_trip)
    };
    message.next_delivery_attempt = now + wait;

    let limit = if round_trip > DELIVERY_RETRY_WAIT as f64 {
        // Python's round() rounds half to even.
        let scaled = (MAX_DELIVERY_ATTEMPTS as f64 * DELIVERY_RETRY_WAIT as f64 / round_trip)
            .round_ties_even() as u32;
        scaled.max(3)
    } else {
        MAX_DELIVERY_ATTEMPTS
    };
    message.max_delivery_attempts = Some(limit);

    let mtu_time = (round_trip - PER_HOP_TIMEOUT).max(0.0) / 2.0;
    if mtu_time > AIRTIME_AWARE_MTU_TIME {
        message.next_delivery_attempt += rand::thread_rng().gen_range(0.0..=mtu_time);
        let retry_wait = (DELIVERY_RETRY_WAIT as f64).max(round_trip) + mtu_time;
        let remaining = (i64::from(limit) - i64::from(message.delivery_attempts) + 1).max(1);
        message.receipt_timeout = Some(retry_wait * remaining as f64 + PROCESSING_INTERVAL as f64);
    } else {
        message.receipt_timeout = None;
    }
}

/// Timeout for an opportunistic delivery receipt: the RNS packet receipt
/// timeout (Packet.py:429-433), raised to the message's airtime-aware
/// `receipt_timeout` (LXMessage.py:482). Without a route Reticulum counts
/// `PATHFINDER_M` hops.
pub fn opportunistic_receipt_timeout(
    route: Option<RouteInfo>,
    receipt_timeout: Option<f64>,
) -> Duration {
    let (first_hop, hops) = route
        .map(|route| (route.first_hop_timeout, route.hops))
        .unwrap_or((PER_HOP_TIMEOUT, rns_transport::constants::PATHFINDER_M));
    let base = rns_wire::receipt::receipt_timeout_for_route(
        Duration::from_secs_f64(first_hop.max(0.0)),
        hops,
    );
    match receipt_timeout {
        Some(timeout) if timeout.is_finite() && timeout > base.as_secs_f64() => {
            Duration::from_secs_f64(timeout)
        }
        _ => base,
    }
}
