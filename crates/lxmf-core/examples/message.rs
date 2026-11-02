//! Construct, sign, freeze, and inspect a message through the canonical API.
//! The hashes below are placeholders: this local packing example does not
//! authenticate a sender or transmit a message. Real source hashes must bind
//! the signing identity to its lxmf.delivery destination.
use lxmf_core::message_api::{DeliveryMethod, LxMessage, LxMessageDraft, MessageState};
use rns_crypto::ed25519::Ed25519PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut draft = LxMessageDraft::new(
        [0x11; 16],
        [0x22; 16],
        "Hello",
        "LXMF from Rust",
        DeliveryMethod::Direct,
    )?;
    draft.set_field(0x105_u64, vec![1, 2, 3])?;
    let message = draft.sign(&Ed25519PrivateKey::generate())?.finalize(None)?;
    let unpacked = LxMessage::unpack(message.wire_bytes())?;
    assert_eq!(unpacked.title_text(), "Hello");
    assert_eq!(unpacked.state, MessageState::Generating);
    assert_eq!(unpacked.wire_bytes(), message.wire_bytes());
    Ok(())
}
