//! LXMF-backed stamper for Reticulum interface discovery.
//!
//! # Layering
//!
//! Python `RNS/Discovery.py:41` imports `LXMF.LXStamper` directly; the
//! discovery subsystem cannot work without LXMF installed. Rust keeps
//! Reticulum below LXMF, so `rns-transport` depends on a trait object and
//! the concrete implementation lives here.
//!
//! # Workblock: Python parity
//!
//! Python discovery uses `LXStamper.stamp_workblock(infohash, expand_rounds=20)`
//! (RNS/Discovery.py:220), where `stamp_workblock` is the
//! HKDF-expanded construction: one HKDF expand per round, each round
//! producing 256 bytes, total `expand_rounds * 256` bytes.
//! [`crate::stamper::stamp_workblock`] is the same construction.
//!
use rns_transport::discovery::DiscoveryStamper;

use crate::stamper::{stamp_valid, stamp_value, stamp_workblock};

/// Python `RNS.Discovery.InterfaceAnnouncer.WORKBLOCK_EXPAND_ROUNDS`,
/// the expand-round count discovery uses when building its workblock.
///
/// Much smaller than message stamps: discovery stamps are refreshed per
/// interface, so this path has to stay cheap enough for periodic announces.
pub const DISCOVERY_WORKBLOCK_EXPAND_ROUNDS: usize = 20;

/// Upper bound on the random-stamp search before we give up on a given
/// tick. If the cap is hit, the announcer skips this cycle and tries again
/// rather than pinning a blocking worker indefinitely.
///
/// Python has no equivalent cap (it blocks until success); we cap so
/// `spawn_blocking` threads cannot be stuck forever if the user
/// misconfigures `discover_interfaces_required_value` to something
/// unreasonable.
pub const DISCOVERY_MAX_ITERATIONS: u64 = 5_000_000;

/// PoW stamper for on-network discovery announces. Thin wrapper around
/// [`lxmf_core::stamper`](crate::stamper) that binds the exact Python
/// discovery construction (HKDF workblock with 20 expand rounds).
///
/// Clonable and `Send + Sync`; the default instance is fine for most
/// users.
#[derive(Debug, Clone, Default)]
pub struct LxmfDiscoveryStamper {
    /// Override the iteration cap; defaults to [`DISCOVERY_MAX_ITERATIONS`].
    /// Zero means "use the default".
    max_iterations: u64,
}

impl LxmfDiscoveryStamper {
    /// Build a stamper with a custom iteration cap. Most callers want
    /// [`LxmfDiscoveryStamper::default`].
    pub fn with_max_iterations(max_iterations: u64) -> Self {
        Self { max_iterations }
    }

    fn effective_max_iterations(&self) -> u64 {
        if self.max_iterations == 0 {
            DISCOVERY_MAX_ITERATIONS
        } else {
            self.max_iterations
        }
    }
}

impl DiscoveryStamper for LxmfDiscoveryStamper {
    fn generate(&self, infohash: &[u8; 32], target_value: u8) -> Option<Vec<u8>> {
        if target_value == 0 {
            return Some(vec![0u8; 32]);
        }

        let workblock = stamp_workblock(infohash, DISCOVERY_WORKBLOCK_EXPAND_ROUNDS);

        for _ in 0..self.effective_max_iterations() {
            let candidate = crate::stamper::rand_bytes();
            if stamp_valid(&candidate, target_value, &workblock) {
                return Some(candidate.to_vec());
            }
        }
        None
    }

    fn value(&self, infohash: &[u8; 32], stamp: &[u8]) -> u8 {
        if stamp.len() != 32 {
            return 0;
        }
        let mut stamp_arr = [0u8; 32];
        stamp_arr.copy_from_slice(stamp);
        let workblock = stamp_workblock(infohash, DISCOVERY_WORKBLOCK_EXPAND_ROUNDS);
        let v = stamp_value(&workblock, &stamp_arr);
        v.min(u8::MAX as u32) as u8
    }

    fn valid(&self, infohash: &[u8; 32], stamp: &[u8], required_value: u8) -> bool {
        if required_value == 0 {
            return true;
        }
        if stamp.len() != 32 {
            return false;
        }
        let mut stamp_arr = [0u8; 32];
        stamp_arr.copy_from_slice(stamp);
        let workblock = stamp_workblock(infohash, DISCOVERY_WORKBLOCK_EXPAND_ROUNDS);
        stamp_valid(&stamp_arr, required_value, &workblock)
    }
}

/// Validation helper: synchronous wrapper mirroring
/// [`crate::stamper::generate_stamp_limited`] but using the HKDF
/// workblock construction. Public so interop tests and downstream validation
/// can exercise discovery stamping without a transport runtime.
pub fn generate_discovery_stamp(
    infohash: &[u8; 32],
    target_value: u8,
    max_iterations: u64,
) -> Option<[u8; 32]> {
    if target_value == 0 {
        return Some([0u8; 32]);
    }
    let workblock = stamp_workblock(infohash, DISCOVERY_WORKBLOCK_EXPAND_ROUNDS);
    for _ in 0..max_iterations {
        let candidate = crate::stamper::rand_bytes();
        if stamp_valid(&candidate, target_value, &workblock) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::sha::sha256;

    fn mk_infohash(seed: &[u8]) -> [u8; 32] {
        sha256(seed)
    }

    #[test]
    fn cost_zero_generates_immediately_and_is_always_valid() {
        let stamper = LxmfDiscoveryStamper::default();
        let infohash = mk_infohash(b"cost-zero");
        let stamp = stamper.generate(&infohash, 0).unwrap();
        assert_eq!(stamp.len(), 32);
        assert!(stamper.valid(&infohash, &stamp, 0));
    }

    #[test]
    fn generate_stamp_passes_valid() {
        let stamper = LxmfDiscoveryStamper::with_max_iterations(200_000);
        let infohash = mk_infohash(b"generate-round-trip");
        let cost = 6;
        let stamp = stamper.generate(&infohash, cost);
        assert!(stamp.is_some(), "cost={cost} should be findable within cap");
        assert!(stamper.valid(&infohash, &stamp.unwrap(), cost));
    }

    #[test]
    fn value_reports_leading_zero_bits() {
        let stamper = LxmfDiscoveryStamper::with_max_iterations(200_000);
        let infohash = mk_infohash(b"value-check");
        let cost = 4;
        let stamp = stamper.generate(&infohash, cost).unwrap();
        let value = stamper.value(&infohash, &stamp);
        assert!(value >= cost, "value {value} must be >= cost {cost}");
    }

    #[test]
    fn invalid_stamp_is_rejected() {
        let stamper = LxmfDiscoveryStamper::default();
        let infohash = mk_infohash(b"invalid");
        let bogus = [0xFFu8; 32];
        assert!(!stamper.valid(&infohash, &bogus, 32));
    }

    #[test]
    fn non_32_byte_stamp_is_rejected() {
        let stamper = LxmfDiscoveryStamper::default();
        let infohash = mk_infohash(b"wrong-size");
        // Non-standard length; must not panic, must not validate.
        assert_eq!(stamper.value(&infohash, &[0u8; 16]), 0);
        assert!(!stamper.valid(&infohash, &[0u8; 16], 8));
    }

    #[test]
    fn generate_gives_up_when_cap_exhausted() {
        // Cost 64 is astronomically unreachable in a handful of iters.
        let stamper = LxmfDiscoveryStamper::with_max_iterations(10);
        let infohash = mk_infohash(b"unreachable");
        assert!(stamper.generate(&infohash, 64).is_none());
    }

    #[test]
    fn two_generated_stamps_both_validate_independently() {
        let stamper = LxmfDiscoveryStamper::with_max_iterations(200_000);
        let a = mk_infohash(b"a");
        let b = mk_infohash(b"b");
        let cost = 4;
        let sa = stamper.generate(&a, cost).unwrap();
        let sb = stamper.generate(&b, cost).unwrap();
        assert!(stamper.valid(&a, &sa, cost));
        assert!(stamper.valid(&b, &sb, cost));
        // Cross-validation MUST fail (different workblocks).
        assert!(
            !stamper.valid(&a, &sb, 16) || stamper.value(&a, &sb) < 16,
            "cross-infohash stamp must not clear a meaningful cost"
        );
    }

    #[test]
    fn workblock_constant_matches_python() {
        assert_eq!(DISCOVERY_WORKBLOCK_EXPAND_ROUNDS, 20);
    }

    #[test]
    fn generate_discovery_stamp_helper_works() {
        let infohash = mk_infohash(b"helper");
        let stamp = generate_discovery_stamp(&infohash, 4, 200_000);
        assert!(stamp.is_some());
        let stamper = LxmfDiscoveryStamper::default();
        assert!(stamper.valid(&infohash, &stamp.unwrap(), 4));
    }

    #[test]
    fn generate_discovery_stamp_cost_zero_is_instant() {
        let infohash = mk_infohash(b"helper-zero");
        let stamp = generate_discovery_stamp(&infohash, 0, 1);
        assert_eq!(stamp, Some([0u8; 32]));
    }
}
