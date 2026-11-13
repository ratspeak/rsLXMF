//! LXMF stamps: proof of work for messages, propagation and peering.
//!
//! Python reference: `LXMF/LXStamper.py`, which takes the workblock, value,
//! validity and generation from `RNS.Stamps`. Only the expand-round counts per
//! stamp kind are LXMF's own (`STAMP_WORKBLOCK_EXPAND_ROUNDS{,_PN,_PEERING}`
//! in constants.rs). Costs and values are fractional on the 1/256 grid.

use std::sync::atomic::Ordering;

/// The same type as `rns_identity::stamps::StampError`, not an LXMF-specific error.
pub use rns_identity::stamps::StampError;
pub use rns_identity::stamps::{
    STAMP_COST_CAP, STAMP_COST_CAP_FP, StampControl, cost_from_fp, cost_to_fp, quantize_cost,
    stamp_value, stamp_workblock,
};

use crate::constants::{
    LXMF_OVERHEAD, STAMP_SIZE, STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING,
    STAMP_WORKBLOCK_EXPAND_ROUNDS_PN,
};

/// Parsed propagation-node stamp parts: `(transient_id, lxm_data, value, stamp)`.
pub type PropagationStampParts = ([u8; 32], Vec<u8>, f64, [u8; 32]);

/// Python `stamp_valid`: the stamp hash meets the fixed-point target of
/// `cost`. A cost of 0 always passes; a non-finite cost never does.
pub fn stamp_valid(stamp: &[u8], cost: f64, workblock: &[u8]) -> bool {
    rns_identity::stamps::stamp_valid(stamp, cost, workblock).unwrap_or(false)
}

/// Whether a stamp of `value` passes [`stamp_valid`] at `cost`.
pub fn value_meets(value: f64, cost: f64) -> bool {
    quantize_cost(cost).is_ok_and(|cost| value >= cost)
}

/// Python `LXStamper.generate_stamp`: a 32-byte stamp and its real value.
/// Costs outside `0..=100` are refused as Python refuses them; a cost of 0
/// still returns a random stamp. `None` means cancelled or past the deadline.
pub fn generate_stamp(
    material: &[u8],
    cost: f64,
    expand_rounds: usize,
    ctl: &StampControl,
) -> Result<Option<([u8; 32], f64)>, StampError> {
    let generated =
        rns_identity::stamps::generate_stamp(material, cost, expand_rounds, STAMP_SIZE, ctl)?;
    Ok(generated.map(|(stamp, value)| {
        let stamp: [u8; 32] = stamp.try_into().expect("stamp size is 32");
        (stamp, value)
    }))
}

pub fn validate_stamp(
    message_id: &[u8; 32],
    stamp: &[u8],
    cost: f64,
    expand_rounds: usize,
) -> bool {
    let workblock = stamp_workblock(message_id, expand_rounds);
    stamp_valid(stamp, cost, &workblock)
}

/// Python reference: `LXStamper.validate_peering_key`.
pub fn validate_peering_key(peering_id: &[u8], peering_key: &[u8], target_cost: f64) -> bool {
    let workblock = stamp_workblock(peering_id, STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING);
    stamp_valid(peering_key, target_cost, &workblock)
}

/// Python reference: `LXStamper.validate_pn_stamp`.
///
/// `transient_data = lxm_data || stamp` where stamp is the last 32 bytes.
pub fn validate_pn_stamp(transient_data: &[u8], target_cost: f64) -> Option<PropagationStampParts> {
    if transient_data.len() <= LXMF_OVERHEAD + STAMP_SIZE {
        return None;
    }
    let split = transient_data.len() - STAMP_SIZE;
    let lxm_data = &transient_data[..split];
    let stamp: [u8; 32] = transient_data[split..].try_into().ok()?;
    let transient_id = rns_crypto::sha::full_hash(lxm_data);
    let workblock = stamp_workblock(&transient_id, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN);
    if !stamp_valid(&stamp, target_cost, &workblock) {
        return None;
    }
    let value = stamp_value(&workblock, &stamp);
    Some((transient_id, lxm_data.to_vec(), value, stamp))
}

/// Cooperative cancellation handle for a deferred PoW task.
/// Call `cancel()` to request cancellation; dropping this handle or the result
/// receiver does not stop the worker.
#[derive(Clone)]
pub struct DeferredStampHandle {
    ctl: StampControl,
}

impl DeferredStampHandle {
    pub fn cancel(&self) {
        self.ctl.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.ctl.cancel.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub enum DeferredStampResult {
    Success {
        stamp: [u8; 32],
        value: f64,
    },
    Cancelled,
    /// The cost cannot be generated, as Python's `generate_stamp` raises.
    Failed(StampError),
}

/// Spawn a deferred stamp-generation task on a blocking worker.
///
/// # Panics
/// Panics when called outside a Tokio runtime.
#[tracing::instrument(
    level = "debug",
    name = "stamper.compute",
    skip_all,
    fields(
        msg_id = %hex::encode(&message_id[..8]),
        cost,
        expand_rounds,
    ),
)]
pub fn spawn_deferred_stamp(
    message_id: [u8; 32],
    cost: f64,
    expand_rounds: usize,
) -> (
    DeferredStampHandle,
    tokio::sync::oneshot::Receiver<DeferredStampResult>,
) {
    let handle = tokio::runtime::Handle::current();
    spawn_deferred_stamp_on(&handle, message_id, cost, expand_rounds)
}

/// Spawn on an explicit runtime handle. The search runs until it succeeds or
/// the handle is cancelled; an invalid cost reports `Failed` at once.
pub fn spawn_deferred_stamp_on(
    runtime: &tokio::runtime::Handle,
    message_id: [u8; 32],
    cost: f64,
    expand_rounds: usize,
) -> (
    DeferredStampHandle,
    tokio::sync::oneshot::Receiver<DeferredStampResult>,
) {
    let ctl = StampControl::default();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let worker_ctl = ctl.clone();
    runtime.spawn_blocking(move || {
        let result = match generate_stamp(&message_id, cost, expand_rounds, &worker_ctl) {
            Ok(Some((stamp, value))) => DeferredStampResult::Success { stamp, value },
            Ok(None) => DeferredStampResult::Cancelled,
            Err(error) => DeferredStampResult::Failed(error),
        };
        let _ = tx.send(result);
    });
    (DeferredStampHandle { ctl }, rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{STAMP_WORKBLOCK_EXPAND_ROUNDS, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN};
    use rns_crypto::sha::sha256;

    fn found(material: &[u8], cost: f64, rounds: usize) -> ([u8; 32], f64) {
        generate_stamp(material, cost, rounds, &StampControl::default())
            .unwrap()
            .unwrap()
    }

    #[test]
    fn workblock_uses_lxmf_expand_rounds() {
        let id = sha256(b"size check");
        assert_eq!(
            stamp_workblock(&id, STAMP_WORKBLOCK_EXPAND_ROUNDS).len(),
            STAMP_WORKBLOCK_EXPAND_ROUNDS * 256
        );
        assert_eq!(stamp_workblock(&id, 0), id.to_vec());
    }

    #[test]
    fn zero_cost_generates_a_random_stamp_with_its_real_value() {
        let id = sha256(b"zero cost");
        let (stamp, value) = found(&id, 0.0, 20);
        assert_ne!(stamp, [0u8; 32]);
        assert_eq!(value, stamp_value(&stamp_workblock(&id, 20), &stamp));
        assert!(stamp_valid(&stamp, 0.0, &[]));
    }

    #[test]
    fn generation_refuses_costs_outside_the_cap() {
        let ctl = StampControl::default();
        for cost in [100.5, 150.0, 255.0, -1.0, f64::NAN] {
            assert!(generate_stamp(&[7; 32], cost, 1, &ctl).is_err(), "{cost}");
        }
    }

    #[test]
    fn fractional_cost_generates_and_validates() {
        let id = sha256(b"fractional");
        let (stamp, value) = found(&id, 4.5, 10);
        assert!(value >= 4.5);
        assert!(validate_stamp(&id, &stamp, 4.5, 10));
        assert!(!validate_stamp(&id, &stamp, value + 1.0 / 256.0, 10));
    }

    #[test]
    fn non_finite_target_never_validates() {
        assert!(!stamp_valid(&[0u8; 32], f64::NAN, b"x"));
    }

    #[test]
    fn peering_key_validates_at_its_value() {
        let peering_id = [0xAA; 32];
        let (key, value) = found(&peering_id, 3.25, STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING);
        assert!(validate_peering_key(&peering_id, &key, 3.25));
        assert!(validate_peering_key(&peering_id, &key, value));
        assert!(!validate_peering_key(
            &peering_id,
            &key,
            value + 1.0 / 256.0
        ));
        assert!(validate_peering_key(&peering_id, &[0xFF; 32], 0.0));
    }

    #[test]
    fn pn_stamp_too_short_is_rejected() {
        let short_data = vec![0u8; LXMF_OVERHEAD + 32];
        assert!(validate_pn_stamp(&short_data, 0.0).is_none());
    }

    #[test]
    fn pn_stamp_parts_carry_the_fractional_value() {
        let lxm_data = vec![0xAB; LXMF_OVERHEAD + 64];
        let tid = rns_crypto::sha::full_hash(&lxm_data);
        let (stamp, value) = found(&tid, 2.5, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN);
        let mut transient_data = lxm_data.clone();
        transient_data.extend_from_slice(&stamp);
        let (transient_id, extracted, got, extracted_stamp) =
            validate_pn_stamp(&transient_data, 2.5).unwrap();
        assert_eq!(transient_id, tid);
        assert_eq!(extracted, lxm_data);
        assert_eq!(extracted_stamp, stamp);
        assert_eq!(got, value);
        assert!(validate_pn_stamp(&transient_data, value + 1.0 / 256.0).is_none());
    }

    #[test]
    fn deferred_stamp_handle_cancel() {
        let handle = DeferredStampHandle {
            ctl: StampControl::default(),
        };
        assert!(!handle.is_cancelled());
        handle.cancel();
        assert!(handle.is_cancelled());
    }

    #[tokio::test]
    async fn deferred_stamp_cancelled_mid_computation() {
        let id = sha256(b"mid-pow cancel");
        let (handle, rx) = spawn_deferred_stamp(id, 32.0, 10);
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        handle.cancel();
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), rx)
            .await
            .expect("worker reports back after cancel")
            .expect("oneshot sender dropped");
        assert!(
            matches!(result, DeferredStampResult::Cancelled),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn deferred_stamp_refuses_cost_above_cap() {
        let (_handle, rx) = spawn_deferred_stamp([9; 32], 150.0, 1);
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, DeferredStampResult::Failed(_)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn deferred_stamp_zero_cost_completes_with_real_value() {
        let id = sha256(b"zero cost");
        let (_handle, rx) = spawn_deferred_stamp(id, 0.0, 10);
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap();
        let DeferredStampResult::Success { stamp, value } = result else {
            panic!("{result:?}");
        };
        assert_eq!(value, stamp_value(&stamp_workblock(&id, 10), &stamp));
    }
}
