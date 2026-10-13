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

/// Delivery coordination remains a module-qualified opt-in API.
pub mod delivery_ownership {
    use lxmf_core::link_delivery::LinkDeliveryManager;

    pub fn compile_surface(manager: &mut LinkDeliveryManager) {
        let _ = LinkDeliveryManager::set_link_endpoint_dispatch_handle;
        let _ = LinkDeliveryManager::set_cancellation_aware_backchannel_sender;
        let _ = LinkDeliveryManager::observe_backchannel_packet_wait;
        let _ = LinkDeliveryManager::observe_backchannel_resource_wait;
        let _ = LinkDeliveryManager::abandon_backchannel_packet;
        let _ = LinkDeliveryManager::message_timeout_window;
        manager.set_inbound_resource_completion_handler(|link_id, resource_id, data| {
            let _: ([u8; 16], [u8; 32], Vec<u8>) = (link_id, resource_id, data);
        });
    }
}

/// Reviewed immutable construction, full-width keys and source-bound verification.
pub mod immutable_messages {
    use lxmf_core::message_api::{
        DeliveryMethod, FieldId, LxMessage, LxMessageDraft, MessageError, RecipientStamp,
        VerifiedLxMessage,
    };
    pub fn with_external_signer<F, E>(signer: F) -> Result<LxMessage, MessageError>
    where
        F: FnOnce(&[u8]) -> Result<[u8; 64], E>,
        E: std::fmt::Display,
    {
        let mut draft =
            LxMessageDraft::new([1; 16], [2; 16], "title", "content", DeliveryMethod::Direct)?;
        draft.set_field(FieldId::from(u64::MAX), vec![1, 2])?;
        draft.set_msgpack_field(FieldId::from(i64::MIN), vec![0x91, 0x01])?;
        let signed = draft.sign_with(signer)?;
        let _id = signed.message_id();
        signed.finalize(Some(RecipientStamp::Ticket([0; 16])))
    }
    pub fn inspect<'a>(
        message: &'a LxMessage,
        public_key: &[u8; 64],
    ) -> Result<VerifiedLxMessage<'a>, MessageError> {
        let _same_owner = message.wire_owned();
        let _custom = message.fields().get(u64::MAX);
        message.verify(public_key)
    }
}
