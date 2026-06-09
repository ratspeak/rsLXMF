//! LXMF Stamp system: Proof-of-Work generation and validation.
//!
//! Python reference: LXMF/LXStamper.py.
//!
//! A single workblock construction is used for all stamp kinds (message,
//! propagation-node, peering), matching Python `LXStamper.stamp_workblock`:
//! per-round HKDF expansion concatenated into a `expand_rounds * 256` byte
//! workblock. Only the expand-round count differs per kind (see
//! `STAMP_WORKBLOCK_EXPAND_ROUNDS{,_PN,_PEERING}` in constants.rs).
//!
//! Validity check: `SHA-256(workblock || stamp)` must have >= `cost` leading
//! zero bits. Matches Python's `int.from_bytes(result) <= (1 << (256-cost))`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rand::RngCore;
use rns_crypto::hkdf::hkdf_sha256;
use rns_crypto::sha::sha256;
use sha2::{Digest, Sha256};

/// Parsed propagation-node stamp parts: `(transient_id, lxm_data, value, stamp)`.
pub type PropagationStampParts = ([u8; 32], Vec<u8>, u32, [u8; 32]);

/// Matches Python `LXStamper.stamp_workblock(material, expand_rounds)`:
///
/// For each round n in 0..expand_rounds:
///   salt = SHA256(material + msgpack.packb(n))
///   workblock += HKDF(length=256, derive_from=material, salt=salt, context=None)
///
/// Produces `expand_rounds * 256` bytes.
pub fn stamp_workblock(material: &[u8], expand_rounds: usize) -> Vec<u8> {
    let mut workblock = Vec::with_capacity(expand_rounds * 256);

    for n in 0..expand_rounds {
        let n_packed = pack_msgpack_uint(n);

        let mut salt_input = Vec::with_capacity(material.len() + n_packed.len());
        salt_input.extend_from_slice(material);
        salt_input.extend_from_slice(&n_packed);
        let salt = sha256(&salt_input);

        let chunk = hkdf_sha256(256, material, Some(&salt), None)
            .expect("HKDF expand failed for stamp workblock");
        workblock.extend_from_slice(&chunk);
    }

    workblock
}

fn pack_msgpack_uint(n: usize) -> Vec<u8> {
    let value = rmpv::Value::Integer(rmpv::Integer::from(n as u64));
    crate::encode_value(&value)
}

fn leading_zero_bits(data: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in data {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Leading zero bits of `SHA-256(workblock || stamp)`. Matches Python `stamp_value()`.
pub fn stamp_value(workblock: &[u8], stamp: &[u8; 32]) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(workblock);
    stamp_value_from_base(&hasher, stamp)
}

pub fn stamp_valid(stamp: &[u8; 32], cost: u8, workblock: &[u8]) -> bool {
    if cost == 0 {
        return true;
    }
    stamp_value(workblock, stamp) >= cost as u32
}

/// Single-threaded brute-force stamp search. Blocks until a valid stamp is found.
pub fn generate_stamp(material: &[u8], cost: u8, expand_rounds: usize) -> Option<([u8; 32], u32)> {
    if cost == 0 {
        return Some(([0u8; 32], 0));
    }

    let workblock = stamp_workblock(material, expand_rounds);
    let mut base_hasher = Sha256::new();
    base_hasher.update(&workblock);
    let mut rng = rand::thread_rng();

    loop {
        let stamp = rand_bytes_from(&mut rng);
        let value = stamp_value_from_base(&base_hasher, &stamp);
        if value >= cost as u32 {
            return Some((stamp, value));
        }
    }
}

/// Stamp search with a configurable iteration limit (for tests).
pub fn generate_stamp_limited(
    material: &[u8],
    cost: u8,
    expand_rounds: usize,
    max_iterations: u64,
) -> Option<[u8; 32]> {
    if cost == 0 {
        return Some([0u8; 32]);
    }

    let workblock = stamp_workblock(material, expand_rounds);
    let mut base_hasher = Sha256::new();
    base_hasher.update(&workblock);
    let mut rng = rand::thread_rng();

    for _ in 0..max_iterations {
        let stamp = rand_bytes_from(&mut rng);
        if stamp_value_from_base(&base_hasher, &stamp) >= cost as u32 {
            return Some(stamp);
        }
    }

    None
}

pub fn validate_stamp(
    message_id: &[u8; 32],
    stamp: &[u8; 32],
    cost: u8,
    expand_rounds: usize,
) -> bool {
    let workblock = stamp_workblock(message_id, expand_rounds);
    stamp_valid(stamp, cost, &workblock)
}

/// Python reference: LXStamper.py:48-51 (`validate_peering_key`).
///
/// `peering_id` = self_identity_hash || remote_identity_hash (32 bytes typical).
/// Uses `STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING` for workblock generation.
pub fn validate_peering_key(peering_id: &[u8], peering_key: &[u8; 32], target_cost: u8) -> bool {
    let workblock = stamp_workblock(
        peering_id,
        crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING,
    );
    stamp_valid(peering_key, target_cost, &workblock)
}

/// Python reference: LXStamper.py:53-65 (`validate_pn_stamp`).
///
/// `transient_data = lxm_data || stamp` where stamp is the last 32 bytes.
/// Uses `STAMP_WORKBLOCK_EXPAND_ROUNDS_PN` for workblock generation.
pub fn validate_pn_stamp(transient_data: &[u8], target_cost: u8) -> Option<PropagationStampParts> {
    let stamp_size = 32;
    let lxmf_overhead = crate::constants::LXMF_OVERHEAD;

    if transient_data.len() <= lxmf_overhead + stamp_size {
        return None;
    }

    let split = transient_data.len() - stamp_size;
    let lxm_data = &transient_data[..split];
    let stamp_bytes = &transient_data[split..];
    let mut stamp = [0u8; 32];
    stamp.copy_from_slice(stamp_bytes);

    let transient_id = rns_crypto::sha::full_hash(lxm_data);
    let workblock = stamp_workblock(
        &transient_id,
        crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PN,
    );

    let value = stamp_value(&workblock, &stamp);
    if value < target_cost as u32 {
        return None;
    }
    Some((transient_id, lxm_data.to_vec(), value, stamp))
}

/// Cancellation handle for a deferred PoW task.
#[derive(Clone)]
pub struct DeferredStampHandle {
    cancel: Arc<AtomicBool>,
}

impl DeferredStampHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub enum DeferredStampResult {
    Success { stamp: [u8; 32], value: u32 },
    Cancelled,
}

/// Spawn a deferred stamp-generation task on a blocking worker.
///
/// Returns a cancellation handle and a oneshot receiver for the result.
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
    cost: u8,
    expand_rounds: usize,
) -> (
    DeferredStampHandle,
    tokio::sync::oneshot::Receiver<DeferredStampResult>,
) {
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = tokio::sync::oneshot::channel();

    let cancel_flag = cancel.clone();
    tokio::task::spawn_blocking(move || {
        if cost == 0 {
            let _ = tx.send(DeferredStampResult::Success {
                stamp: [0u8; 32],
                value: 0,
            });
            return;
        }

        let workblock = stamp_workblock(&message_id, expand_rounds);
        let mut base_hasher = Sha256::new();
        base_hasher.update(&workblock);
        let mut rng = rand::thread_rng();

        loop {
            if cancel_flag.load(Ordering::Relaxed) {
                let _ = tx.send(DeferredStampResult::Cancelled);
                return;
            }

            // Check cancellation every 1000 iterations.
            for _ in 0..1000 {
                let stamp = rand_bytes_from(&mut rng);
                let value = stamp_value_from_base(&base_hasher, &stamp);
                if value >= cost as u32 {
                    let _ = tx.send(DeferredStampResult::Success { stamp, value });
                    return;
                }
            }
        }
    });

    (DeferredStampHandle { cancel }, rx)
}

pub(crate) fn rand_bytes() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    rand_bytes_from(&mut rng)
}

fn rand_bytes_from(rng: &mut impl RngCore) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn stamp_value_from_base(base_hasher: &Sha256, stamp: &[u8; 32]) -> u32 {
    let mut hasher = base_hasher.clone();
    hasher.update(stamp);
    let hash = hasher.finalize();
    leading_zero_bits(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{STAMP_WORKBLOCK_EXPAND_ROUNDS, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN};

    #[test]
    fn test_workblock_deterministic() {
        let id = sha256(b"test message id");
        let wb1 = stamp_workblock(&id, 10);
        let wb2 = stamp_workblock(&id, 10);
        assert_eq!(wb1, wb2);
        assert_eq!(wb1.len(), 10 * 256);
    }

    #[test]
    fn test_workblock_different_rounds() {
        let id = sha256(b"test");
        let wb1 = stamp_workblock(&id, 10);
        let wb2 = stamp_workblock(&id, 20);
        assert_ne!(wb1, wb2);
    }

    /// Workblock for the default message expand rounds matches the Python
    /// construction's size: 3000 rounds * 256 bytes.
    #[test]
    fn test_workblock_message_rounds_size() {
        let id = sha256(b"size check");
        let wb = stamp_workblock(&id, STAMP_WORKBLOCK_EXPAND_ROUNDS);
        assert_eq!(wb.len(), STAMP_WORKBLOCK_EXPAND_ROUNDS * 256);
    }

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(leading_zero_bits(&[0x0F]), 4);
        assert_eq!(leading_zero_bits(&[0x01]), 7);
        assert_eq!(leading_zero_bits(&[0x00, 0x01]), 15);
    }

    #[test]
    fn test_stamp_valid_cost_zero() {
        let stamp = [0u8; 32];
        let workblock = [0u8; 32];
        assert!(stamp_valid(&stamp, 0, &workblock));
    }

    #[test]
    fn test_generate_stamp_cost_zero() {
        let id = sha256(b"test");
        let (stamp, value) = generate_stamp(&id, 0, 20).unwrap();
        assert_eq!(stamp, [0u8; 32]);
        assert_eq!(value, 0);
    }

    #[test]
    fn test_generate_and_validate_stamp() {
        let id = sha256(b"test message for stamping");
        let cost = 4;

        let stamp = generate_stamp_limited(&id, cost, STAMP_WORKBLOCK_EXPAND_ROUNDS, 1_000_000);
        assert!(stamp.is_some(), "should find a stamp with cost={cost}");

        let stamp = stamp.unwrap();
        assert!(validate_stamp(
            &id,
            &stamp,
            cost,
            STAMP_WORKBLOCK_EXPAND_ROUNDS
        ));
    }

    #[test]
    fn test_validate_wrong_stamp() {
        let id = sha256(b"test");
        let wrong_stamp = [0xFFu8; 32];
        assert!(!validate_stamp(&id, &wrong_stamp, 32, 20));
    }

    #[test]
    fn test_generate_stamp_limited_fails() {
        let id = sha256(b"test");
        let result = generate_stamp_limited(&id, 128, 20, 10);
        assert!(result.is_none());
    }

    #[test]
    fn test_stamp_value_consistency() {
        let id = sha256(b"consistency test");
        let cost = 4;
        if let Some(stamp) = generate_stamp_limited(&id, cost, 20, 1_000_000) {
            let workblock = stamp_workblock(&id, 20);
            let value = stamp_value(&workblock, &stamp);
            assert!(value >= cost as u32);
            assert!(stamp_valid(&stamp, cost, &workblock));
        }
    }

    #[test]
    fn test_workblock_arbitrary_length_input() {
        let short_material = b"short";
        let wb = stamp_workblock(short_material, 5);
        assert_eq!(wb.len(), 5 * 256);

        let wb2 = stamp_workblock(short_material, 5);
        assert_eq!(wb, wb2);

        let wb3 = stamp_workblock(b"other", 5);
        assert_ne!(wb, wb3);
    }

    #[test]
    fn test_different_expand_round_constants() {
        let id = sha256(b"test expand rounds");
        let wb_pn = stamp_workblock(&id, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN);
        let wb_peering = stamp_workblock(
            &id,
            crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING,
        );
        // Workblocks are prefix-stable per construction; only length differs.
        assert_eq!(wb_pn[..wb_peering.len()], wb_peering[..]);
        assert_eq!(wb_pn.len(), STAMP_WORKBLOCK_EXPAND_ROUNDS_PN * 256);
        assert_eq!(
            wb_peering.len(),
            crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING * 256
        );
    }

    /// The first 256-byte chunk of the workblock is identical regardless of
    /// total round count — Python builds it incrementally the same way.
    #[test]
    fn test_workblock_prefix_stability() {
        let id = sha256(b"prefix stability");
        let wb_small = stamp_workblock(&id, 2);
        let wb_large = stamp_workblock(&id, 5);
        assert_eq!(wb_small[..], wb_large[..2 * 256]);
    }

    #[test]
    fn test_deferred_stamp_handle_cancel() {
        let handle = DeferredStampHandle {
            cancel: Arc::new(AtomicBool::new(false)),
        };
        assert!(!handle.is_cancelled());
        handle.cancel();
        assert!(handle.is_cancelled());
    }

    /// End-to-end: a stamp worker running a high-cost PoW must observe the
    /// cancellation flag and report `DeferredStampResult::Cancelled`
    /// without panicking. This exercises the worker checkpoint rather than
    /// only the handle state.
    #[tokio::test]
    async fn test_deferred_stamp_cancelled_mid_computation() {
        // Cost 32 is intentionally high enough that the worker is still
        // looping when cancellation is requested.
        let id = sha256(b"mid-pow cancel");
        let (handle, rx) = spawn_deferred_stamp(id, 32, 10);

        // Allow the worker to enter its inner loop.
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        handle.cancel();

        let result = tokio::time::timeout(std::time::Duration::from_secs(3), rx)
            .await
            .expect("worker should report back within 3s of cancel")
            .expect("oneshot sender dropped");

        assert!(
            matches!(result, DeferredStampResult::Cancelled),
            "worker must report Cancelled after handle.cancel(), got {result:?}"
        );
    }

    /// Cost=0 is the degenerate case: no work to do, oneshot fires
    /// immediately with a zero stamp + value. Cancelling after the fact
    /// must not race or produce a spurious Cancelled result.
    #[tokio::test]
    async fn test_deferred_stamp_zero_cost_completes_before_cancel() {
        let id = sha256(b"zero cost");
        let (handle, rx) = spawn_deferred_stamp(id, 0, 10);

        let result = tokio::time::timeout(std::time::Duration::from_secs(3), rx)
            .await
            .expect("cost=0 returns immediately")
            .expect("oneshot sender dropped");

        assert!(
            matches!(result, DeferredStampResult::Success { value: 0, .. }),
            "cost=0 returns Success with zero value, got {result:?}"
        );
        // The handle remains usable after completion; cancel is a no-op here.
        handle.cancel();
        assert!(handle.is_cancelled());
    }

    #[test]
    fn test_workblock_peering_id_length() {
        let mut peering_id = Vec::with_capacity(32);
        peering_id.extend_from_slice(&[0xAA; 16]);
        peering_id.extend_from_slice(&[0xBB; 16]);
        let wb = stamp_workblock(
            &peering_id,
            crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING,
        );
        assert_eq!(
            wb.len(),
            crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PEERING * 256
        );
    }

    #[test]
    fn test_validate_peering_key_cost_zero() {
        let peering_id = [0xAA; 32];
        let peering_key = [0xFF; 32];
        assert!(validate_peering_key(&peering_id, &peering_key, 0));
    }

    #[test]
    fn test_validate_peering_key_invalid() {
        let mut peering_id = Vec::with_capacity(32);
        peering_id.extend_from_slice(&[0xAA; 16]);
        peering_id.extend_from_slice(&[0xBB; 16]);
        let peering_key = [0xFF; 32];
        assert!(!validate_peering_key(&peering_id, &peering_key, 32));
    }

    #[test]
    fn test_validate_pn_stamp_too_short() {
        let short_data = vec![0u8; crate::constants::LXMF_OVERHEAD + 32];
        assert!(validate_pn_stamp(&short_data, 0).is_none());
    }

    #[test]
    fn test_validate_pn_stamp_extracts_parts() {
        let lxm_data = vec![0xAB; crate::constants::LXMF_OVERHEAD + 64];
        let stamp = [0u8; 32];

        let mut transient_data = lxm_data.clone();
        transient_data.extend_from_slice(&stamp);

        let result = validate_pn_stamp(&transient_data, 0);
        assert!(result.is_some());

        let (transient_id, extracted_lxm, value, extracted_stamp) = result.unwrap();
        assert_eq!(extracted_lxm, lxm_data);
        assert_eq!(extracted_stamp, stamp);
        assert_eq!(transient_id, rns_crypto::sha::full_hash(&lxm_data));
        let _ = value;
    }

    #[test]
    fn test_stamp_value_matches_direct_sha256_of_workblock_and_stamp() {
        let material = sha256(b"propagation transient id");
        let workblock = stamp_workblock(&material, STAMP_WORKBLOCK_EXPAND_ROUNDS_PN);
        let stamp = [0x5Au8; 32];

        let mut direct = Vec::with_capacity(workblock.len() + stamp.len());
        direct.extend_from_slice(&workblock);
        direct.extend_from_slice(&stamp);
        let direct_hash = sha256(&direct);

        assert_eq!(
            stamp_value(&workblock, &stamp),
            leading_zero_bits(&direct_hash)
        );
    }

    #[test]
    fn test_validate_pn_stamp_high_cost_fails() {
        let lxm_data = vec![0xCD; crate::constants::LXMF_OVERHEAD + 100];
        let stamp = [0xFF; 32];

        let mut transient_data = lxm_data.clone();
        transient_data.extend_from_slice(&stamp);

        let result = validate_pn_stamp(&transient_data, 32);
        assert!(result.is_none());
    }
}
