//! Stamper for Reticulum interface discovery.
//!
//! Upstream's discovery stamper is `RNS.Stamps` (Discovery.py);
//! [`LxmfDiscoveryStamper`] delegates to
//! `rns_transport::discovery::RnsDiscoveryStamper` for callers that install it.
use rns_transport::discovery::DiscoveryStamper;

use rand::RngCore;

use crate::stamper::{stamp_valid, stamp_workblock};

fn random_stamp() -> [u8; 32] {
    let mut stamp = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut stamp);
    stamp
}

/// Python `RNS.Discovery.InterfaceAnnouncer.WORKBLOCK_EXPAND_ROUNDS`,
/// the expand-round count discovery uses when building its workblock.
///
/// Much smaller than message stamps: discovery stamps are refreshed per
/// interface, so this path has to stay cheap enough for periodic announces.
pub const DISCOVERY_WORKBLOCK_EXPAND_ROUNDS: usize = 20;

/// Attempt budget for [`generate_discovery_stamp`] callers. The
/// [`LxmfDiscoveryStamper`] trait implementation has no cap.
pub const DISCOVERY_MAX_ITERATIONS: u64 = 5_000_000;

/// Discovery stamper; delegates to
/// [`rns_transport::discovery::RnsDiscoveryStamper`], which has no attempt cap.
#[derive(Debug, Clone, Default)]
pub struct LxmfDiscoveryStamper {
    _private: (),
}

impl LxmfDiscoveryStamper {
    /// Discovery generation has no attempt cap upstream; the argument is ignored.
    #[deprecated(note = "discovery stamp generation has no attempt cap; use `default()`")]
    pub fn with_max_iterations(_max_iterations: u64) -> Self {
        Self::default()
    }
}

impl DiscoveryStamper for LxmfDiscoveryStamper {
    fn generate(
        &self,
        infohash: &[u8; 32],
        target_value: f64,
        ctl: &rns_identity::stamps::StampControl,
    ) -> Option<Vec<u8>> {
        rns_transport::discovery::RnsDiscoveryStamper.generate(infohash, target_value, ctl)
    }

    fn value(&self, infohash: &[u8; 32], stamp: &[u8]) -> f64 {
        rns_transport::discovery::RnsDiscoveryStamper.value(infohash, stamp)
    }

    fn valid(&self, infohash: &[u8; 32], stamp: &[u8], required_value: f64) -> bool {
        rns_transport::discovery::RnsDiscoveryStamper.valid(infohash, stamp, required_value)
    }

    fn validate(&self, infohash: &[u8; 32], stamp: &[u8], required_value: f64) -> Option<f64> {
        rns_transport::discovery::RnsDiscoveryStamper.validate(infohash, stamp, required_value)
    }
}

/// Synchronous discovery stamp search with 20 HKDF workblock rounds and an
/// explicit attempt limit. Uses the same construction as
/// [`crate::stamper::generate_stamp`], without a transport runtime.
/// For nonzero cost, a zero iteration limit returns `None`.
pub fn generate_discovery_stamp(
    infohash: &[u8; 32],
    target_value: u8,
    max_iterations: u64,
) -> Option<[u8; 32]> {
    if target_value == 0 {
        return Some(random_stamp());
    }
    let workblock = stamp_workblock(infohash, DISCOVERY_WORKBLOCK_EXPAND_ROUNDS);
    for _ in 0..max_iterations {
        let candidate = random_stamp();
        if stamp_valid(&candidate, f64::from(target_value), &workblock) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::sha::sha256;
    use rns_identity::stamps::StampControl;
    use std::sync::atomic::Ordering;

    fn mk_infohash(seed: &[u8]) -> [u8; 32] {
        sha256(seed)
    }

    #[test]
    fn cost_zero_returns_a_random_stamp_valid_at_zero() {
        let infohash = mk_infohash(b"cost-zero");
        let ctl = StampControl::default();
        let a = LxmfDiscoveryStamper::default()
            .generate(&infohash, 0.0, &ctl)
            .unwrap();
        let b = LxmfDiscoveryStamper::default()
            .generate(&infohash, 0.0, &ctl)
            .unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(LxmfDiscoveryStamper::default().valid(&infohash, &a, 0.0));
    }

    #[test]
    fn generated_stamp_value_meets_fractional_target() {
        let infohash = mk_infohash(b"value-check");
        let stamp = LxmfDiscoveryStamper::default()
            .generate(&infohash, 6.5, &StampControl::default())
            .unwrap();
        let value = LxmfDiscoveryStamper::default().value(&infohash, &stamp);
        assert!(value >= 6.5, "value {value}");
        assert!(LxmfDiscoveryStamper::default().valid(&infohash, &stamp, 6.5));
    }

    #[test]
    fn invalid_and_short_stamps_are_rejected() {
        let infohash = mk_infohash(b"invalid");
        assert!(!LxmfDiscoveryStamper::default().valid(&infohash, &[0xFF; 32], 32.0));
        assert!(LxmfDiscoveryStamper::default().value(&infohash, &[0u8; 16]) < 8.0);
        assert!(!LxmfDiscoveryStamper::default().valid(&infohash, &[0xFF; 16], 8.0));
    }

    #[test]
    fn cancelled_generation_returns_none() {
        let ctl = StampControl::default();
        ctl.cancel.store(true, Ordering::Relaxed);
        #[allow(deprecated)]
        let stamper = LxmfDiscoveryStamper::with_max_iterations(10);
        assert!(
            stamper
                .generate(&mk_infohash(b"unreachable"), 64.0, &ctl)
                .is_none()
        );
    }

    #[test]
    fn non_expanded_stamps_validate_with_their_own_value() {
        let infohash = mk_infohash(b"non-expanded");
        let (stamp, value) =
            rns_identity::stamps::generate_stamp(&infohash, 6.0, 0, 32, &StampControl::default())
                .unwrap()
                .unwrap();
        let stamper = LxmfDiscoveryStamper::default();
        assert_eq!(stamper.validate(&infohash, &stamp, 6.0), Some(value));
        assert!(stamper.valid(&infohash, &stamp, 6.0));
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
        assert!(LxmfDiscoveryStamper::default().valid(&infohash, &stamp.unwrap(), 4.0));
    }

    #[test]
    fn generate_discovery_stamp_cost_zero_is_instant() {
        let infohash = mk_infohash(b"helper-zero");
        let stamp = generate_discovery_stamp(&infohash, 0, 1);
        assert!(stamp.is_some());
    }
}
