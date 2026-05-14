//! Core implementation of the LXMF (Lightweight Extensible Message
//! Format) protocol: messages, routing, propagation, peering, and the
//! PoW stamp primitives.
//!
//! This crate implements the LXMF wire model and is the core LXMF building
//! block for `lxmf-tools` (the `lxmd-rs` daemon) and embedding applications.
//! Its Reticulum dependency is `rns-transport` from rsReticulum; LXMF sits one
//! layer above the Reticulum stack.
//!
//! # Module map
//!
//! | Module                | What it does                                       |
//! | --------------------- | -------------------------------------------------- |
//! | [`message`]           | Message object: fields, packing, stamp, encryption |
//! | [`router`]            | Actor-driven routing and delivery state machine    |
//! | [`peer`]              | Propagation-peer state and sync bookkeeping        |
//! | [`propagation`]       | On-disk store-and-forward message pool             |
//! | [`propagation_node`]  | Propagation-node role logic                        |
//! | [`propagation_client`]| Client side of propagation sync                    |
//! | [`propagation_sync`]  | Wire-level peer sync exchange                      |
//! | [`stamper`]           | Iterative and HKDF-expanded stamp workblocks       |
//! | [`discovery_stamper`] | [`DiscoveryStamper`] impl for on-network discovery |
//! | [`sync`]              | Shared peer-to-peer sync primitives                |
//! | [`link_delivery`]     | Reticulum-link-based delivery path                 |
//! | [`handlers`]          | Callback trait surface for delivery events         |
//! | [`ticket`]            | Small typed identifier for propagation workflows   |
//! | [`persist`]           | MessagePack-based on-disk state                    |
//! | [`constants`]         | Wire constants: STATE, METHOD, field IDs, etc.     |
//!
//! See also `crates/lxmf-tools/` for the `lxmd-rs` binary, and `rsReticulum`
//! (sibling repo) for the Reticulum protocol stack itself.
//!
//! [`DiscoveryStamper`]: rns_transport::discovery::DiscoveryStamper

pub mod constants;
pub mod discovery_stamper;
pub mod handlers;
pub mod link_delivery;
pub mod message;
pub mod peer;
pub mod persist;
pub mod propagation;
pub mod propagation_client;
pub mod propagation_node;
pub mod propagation_sync;
pub mod router;
pub mod stamper;
pub mod sync;
pub mod ticket;
pub mod types;

/// Encode an `rmpv::Value` into a byte buffer.
///
/// `Write` into a `Vec<u8>` is infallible, so the inner `expect` is unreachable.
pub(crate) fn encode_value(value: &rmpv::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, value).expect("internal: Vec<u8> write is infallible");
    buf
}
