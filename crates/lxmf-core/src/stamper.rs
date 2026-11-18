//! LXMF stamps: proof of work for messages, propagation and peering.
//!
//! Python reference: `LXMF/LXStamper.py`, which takes the workblock, value,
//! validity and generation from `RNS.Stamps`. Only the expand-round counts per
//! stamp kind are LXMF's own (`STAMP_WORKBLOCK_EXPAND_ROUNDS{,_PN,_PEERING}`
//! in constants.rs). Costs and values are fractional on the 1/256 grid.
//!
//! Validation accepts the non-expanded workblock (the material itself) as well
//! as the expanded one, as LXMF 1.3.1 does while senders move to it.
//! Generation stays expanded: LXMF 1.3.0 receivers accept only that form.

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

/// The stamp's value when it meets `cost` over the non-expanded workblock,
/// else over `expand_rounds`, from the workblock that passed (LXMF 1.3.1
/// `LXMessage.validate_stamp`, `LXStamper.validate_pn_stamp`). The value can
/// depend on `cost`: below about cost 4 an expanded stamp often passes the
/// non-expanded check too, and at cost 0 it always does.
pub fn validated_stamp_value(
    material: &[u8],
    stamp: &[u8],
    cost: f64,
    expand_rounds: usize,
) -> Option<f64> {
    if stamp_valid(stamp, cost, material) {
        return Some(stamp_value(material, stamp));
    }
    let workblock = stamp_workblock(material, expand_rounds);
    stamp_valid(stamp, cost, &workblock).then(|| stamp_value(&workblock, stamp))
}

/// Whether `stamp` meets `cost` in either workblock form; see [`validated_stamp_value`].
pub fn validate_stamp(
    message_id: &[u8; 32],
    stamp: &[u8],
    cost: f64,
    expand_rounds: usize,
) -> bool {
    validated_stamp_value(message_id, stamp, cost, expand_rounds).is_some()
}

/// Python reference: `LXStamper.validate_peering_key`.
pub fn validate_peering_key(peering_id: &[u8], peering_key: &[u8], target_cost: f64) -> bool {
    validated_stamp_value(
        peering_id,
        peering_key,
        target_cost,
        STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING,
    )
    .is_some()
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
    let value = validated_stamp_value(
        &transient_id,
        &stamp,
        target_cost,
        STAMP_WORKBLOCK_EXPAND_ROUNDS_PN,
    )?;
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

    // Upstream LXMF 1.3.1 / RNS 1.6.1 results: `LXMessage.validate_stamp`,
    // `LXStamper.validate_pn_stamp` and `validate_peering_key` over the same
    // inputs (gen_lxmf_ne.py in the K1 hand-back).
    fn bytes32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    #[test]
    fn message_stamps_validate_in_both_forms_as_upstream() {
        let id = bytes32("179201d9189af65b2fee7b97dc90a4e9232121e084050aff94d27f171dc71f55");
        let ne = bytes32("84276a6ab90c48763474eef01f7ce3e48b8ffad7f4b0eb1de8dd5761f9614ccd");
        let ex = bytes32("a824ef0289c7542b417588d5e93fd3e8e2a0f624c6dc27c1a02e3f864c45fba4");
        let rounds = STAMP_WORKBLOCK_EXPAND_ROUNDS;
        assert_eq!(
            validated_stamp_value(&id, &ne, 8.0, rounds),
            Some(11.84765625)
        );
        assert_eq!(validated_stamp_value(&id, &ex, 8.0, rounds), Some(8.09375));
        assert_eq!(
            validated_stamp_value(&id, &ex, 0.0, rounds),
            Some(0.37109375)
        );
        assert_eq!(validated_stamp_value(&id, &ne, 11.8515625, rounds), None);
        assert!(validate_stamp(&id, &ne, 8.0, rounds));
    }

    #[test]
    fn propagation_stamps_validate_in_both_forms_as_upstream() {
        let lxm_data: Vec<u8> = (0..150).collect();
        let entry = |stamp: &str| [lxm_data.clone(), bytes32(stamp).to_vec()].concat();
        let ne = entry("228341ee29d47d4d9defe50c2704b1feb4bc2ef066a740637916cc690aaa4fd1");
        let ex = entry("7e340b0726c99d8f60ae845912ecccc8aa7363db7a971a09132acd83c88ad771");
        let value = |entry: &[u8], cost| validate_pn_stamp(entry, cost).map(|parts| parts.2);
        assert_eq!(
            validate_pn_stamp(&ne, 8.0).unwrap().0,
            bytes32("f22b2e614e92d6453612b707385038300293d2cc292b148bc5335754b5ea30fd")
        );
        assert_eq!(value(&ne, 8.0), Some(8.0703125));
        assert_eq!(value(&ex, 8.0), Some(8.1953125));
        assert_eq!(value(&ex, 0.0), Some(2.19921875));
        assert_eq!(value(&ne, 8.07421875), None);
    }

    #[test]
    fn peering_keys_validate_in_both_forms_as_upstream() {
        let id: Vec<u8> = [[0x11; 16], [0x22; 16]].concat();
        let ne = bytes32("d63d05f5dbe354b33213745d275a343924b38da05098d2b7cbc521ca4ff103d1");
        let ex = bytes32("4269201b6742c33c84098644f37c3f159c66235bda2c26f108cc7c824936ac7f");
        assert!(validate_peering_key(&id, &ne, 8.0));
        assert!(validate_peering_key(&id, &ex, 8.0));
        assert!(!validate_peering_key(&id, &ne, 8.2578125));
    }

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
        // At cost 2.5 an expanded stamp often meets the non-expanded check too; keep one that doesn't.
        let (stamp, value) = loop {
            let (stamp, value) = found(&tid, 2.5, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN);
            if !stamp_valid(&stamp, 2.5, &tid) {
                break (stamp, value);
            }
        };
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
