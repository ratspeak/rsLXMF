//! External-consumer compile contract for canonical and retained LXMF paths.

pub mod canonical {
    use lxmf_core::message_api::{
        AudioField, DeliveryMethod, DeliveryRepresentation, DestinationHash, IdentityHash,
        LxMessage, MessageError, MessageId, MessageState, UnverifiedReason,
    };

    pub fn compile_surface() {
        let _ = std::mem::size_of::<AudioField<'static>>();
        let _ = std::mem::size_of::<DeliveryMethod>();
        let _ = std::mem::size_of::<DeliveryRepresentation>();
        let _ = std::mem::size_of::<DestinationHash>();
        let _ = std::mem::size_of::<IdentityHash>();
        let _ = std::mem::size_of::<LxMessage>();
        let _ = std::mem::size_of::<MessageError>();
        let _ = std::mem::size_of::<MessageId>();
        let _ = std::mem::size_of::<MessageState>();
        let _ = std::mem::size_of::<UnverifiedReason>();
    }
}

pub mod legacy {
    use lxmf_core::constants::{
        DeliveryMethod, DeliveryRepresentation, MessageState, UnverifiedReason,
    };
    use lxmf_core::message::{AudioField, LxMessage, MessageError};
    use lxmf_core::types::{DestinationHash, IdentityHash, MessageId};

    pub fn compile_surface() {
        let _ = std::mem::size_of::<AudioField<'static>>();
        let _ = std::mem::size_of::<DeliveryMethod>();
        let _ = std::mem::size_of::<DeliveryRepresentation>();
        let _ = std::mem::size_of::<DestinationHash>();
        let _ = std::mem::size_of::<IdentityHash>();
        let _ = std::mem::size_of::<LxMessage>();
        let _ = std::mem::size_of::<MessageError>();
        let _ = std::mem::size_of::<MessageId>();
        let _ = std::mem::size_of::<MessageState>();
        let _ = std::mem::size_of::<UnverifiedReason>();
    }
}
