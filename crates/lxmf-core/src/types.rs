//! Shared LXMF identifier aliases.
//!
//! Reticulum addressable hashes are 16-byte truncated hashes. LXMF propagation
//! transient IDs are different: upstream Python uses the full SHA-256 hash of
//! the propagation blob (`RNS.Identity.full_hash(lxmf_data)`), so they are
//! 32-byte identifiers.

use crate::constants::DESTINATION_LENGTH;

/// Reticulum destination hash, as carried in LXMF wire messages.
pub type DestinationHash = [u8; DESTINATION_LENGTH];

/// Reticulum identity hash, used for peer and ticket identity binding.
pub type IdentityHash = [u8; DESTINATION_LENGTH];

/// Canonical LXMF message id / SHA-256 digest.
pub type MessageId = [u8; 32];

/// Canonical LXMF propagation transient id.
///
/// Python reference: `LXMessage.pack()` computes this as
/// `RNS.Identity.full_hash(lxmf_data)` before appending the propagation stamp.
pub type PropagationTransientId = [u8; 32];

pub const PROPAGATION_TRANSIENT_ID_LENGTH: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagation_transient_ids_are_full_hash_width() {
        assert_eq!(std::mem::size_of::<PropagationTransientId>(), 32);
        assert_eq!(PROPAGATION_TRANSIENT_ID_LENGTH, 32);
    }

    #[test]
    fn destination_and_identity_hashes_remain_reticulum_width() {
        assert_eq!(std::mem::size_of::<DestinationHash>(), 16);
        assert_eq!(std::mem::size_of::<IdentityHash>(), 16);
    }
}
