//! Construct, sign, pack, and inspect an LXMF message through the canonical API.

use lxmf_core::message_api::{DeliveryMethod, LxMessage, MessageState};
use rns_crypto::ed25519::Ed25519PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut message = LxMessage::new(
        [0x11; 16],
        [0x22; 16],
        "Hello",
        "LXMF from Rust",
        DeliveryMethod::Direct,
    );
    message.sign(&Ed25519PrivateKey::generate())?;

    let packed = message.pack()?;
    let unpacked = LxMessage::unpack(&packed)?;
    assert_eq!(unpacked.title, "Hello");
    assert_eq!(unpacked.state, MessageState::Generating);
    Ok(())
}
