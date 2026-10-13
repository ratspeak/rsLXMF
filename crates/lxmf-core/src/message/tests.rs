use super::*;
use rns_crypto::ed25519::Ed25519PrivateKey;
fn key() -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(&[7; 32])
}
fn draft() -> LxMessageDraft {
    LxMessageDraft::new([1; 16], [2; 16], "title", "content", DeliveryMethod::Direct).unwrap()
}
fn freeze(draft: LxMessageDraft) -> LxMessage {
    draft.sign(&key()).unwrap().finalize(None).unwrap()
}
fn payload(fields: &[u8], stamp: Option<&[u8]>) -> Vec<u8> {
    let mut p = vec![if stamp.is_some() { 0x95 } else { 0x94 }];
    rmp::encode::write_f64(&mut p, 1_700_000_000.).unwrap();
    p.extend_from_slice(&[0xc4, 1, b'T', 0xc4, 1, b'C']);
    p.extend_from_slice(fields);
    if let Some(s) = stamp {
        p.extend_from_slice(s);
    }
    p
}
fn wire(payload: &[u8]) -> Vec<u8> {
    let mut signed = vec![1; 16];
    signed.extend_from_slice(&[2; 16]);
    if let Some(body) = first_four_msgpack_array_body(payload) {
        signed.push(0x94);
        signed.extend_from_slice(body);
    } else {
        signed.extend_from_slice(payload);
    }
    let hash = sha256(&signed);
    signed.extend_from_slice(&hash);
    let mut out = vec![1; 16];
    out.extend_from_slice(&[2; 16]);
    out.extend_from_slice(&key().sign(&signed));
    out.extend_from_slice(payload);
    out
}
#[test]
fn signed_body_finalization_defaults_and_states() {
    let d = draft();
    assert!(d.timestamp() > 0.);
    assert_eq!(d.state, MessageState::Generating);
    assert!(d.auto_compress);
    assert!(!d.source_blackholed);
    let signed = d.sign(&key()).unwrap();
    let id = signed.message_id();
    let mut m = signed.finalize(None).unwrap();
    assert_eq!(m.state, MessageState::Outbound);
    assert_eq!(m.message_id(), id);
    let before = m.wire_owned();
    m.mark_sending();
    m.mark_sent();
    m.mark_delivered();
    assert_eq!(m.state, MessageState::Delivered);
    m.mark_failed();
    assert_eq!(m.state, MessageState::Failed);
    m.mark_rejected();
    assert_eq!(m.state, MessageState::Rejected);
    assert_eq!(m.wire_bytes(), before.as_ref());
}
#[test]
fn received_wire_identity_repeated_verification_and_ownership() {
    let mut p = payload(&[0x82, 0x0f, 0x01, 0x0c, 0x92, 0x00, 0xc4, 0x00], None);
    // A retained noncanonical f32 timestamp cannot be reencoded as f64.
    p.splice(1..10, [0xca, 0x3f, 0x80, 0x00, 0x00]);
    let wire = Bytes::from(wire(&p));
    let ptr = wire.as_ptr();
    let mut m = LxMessage::unpack_owned(wire.clone(), MessageDecodeLimits::default()).unwrap();
    assert_eq!(m.wire_bytes().as_ptr(), ptr);
    let id = m.message_id();
    assert!(m.verify_signature(&key().public_key()));
    assert!(m.verify_signature(&key().public_key()));
    assert_eq!(m.pack().unwrap(), wire);
    assert_eq!(m.pack_payload().unwrap(), p);
    assert_eq!(m.message_id(), id);
    m.method = DeliveryMethod::Propagated;
    m.progress = 0.8;
    assert_eq!(m.clone().wire_bytes().as_ptr(), ptr);
    assert_eq!(m.pack().unwrap(), wire);
    let restored = LxMessage::unpack_container(&m.pack_container().unwrap()).unwrap();
    assert_eq!(restored.wire_bytes(), wire);
    assert_eq!(restored.message_id(), id);
    assert!(restored.verify_signature(&key().public_key()));
}
#[test]
fn received_wire_identity_real_python_reordered_vector() {
    // Emitted by Python LXMF 1.0.1: renderer precedes the subsequently added reply ticket.
    let raw = include_bytes!("fixtures/python-reordered.bin");
    let public = include_bytes!("fixtures/python-reordered-public.bin");
    let key =
        rns_crypto::ed25519::Ed25519PublicKey::from_bytes(public.as_slice().try_into().unwrap())
            .unwrap();
    let m = LxMessage::unpack(raw).unwrap();
    assert!(m.verify_signature(&key));
    assert!(m.verify_signature(&key));
    assert_eq!(m.pack().unwrap(), raw);
    let restored = LxMessage::unpack_container(&m.pack_container().unwrap()).unwrap();
    assert_eq!(restored.wire_bytes(), raw);
    assert_eq!(restored.message_id(), m.message_id());
    assert!(restored.verify_signature(&key));
}
#[test]
fn received_wire_identity_source_binding() {
    let identity = rns_identity::identity::Identity::from_private_key(&[7; 64]).unwrap();
    let source = rns_identity::destination::Destination::hash_from_name_and_identity(
        "lxmf.delivery",
        Some(&identity.hash),
    );
    let d = LxMessageDraft::new([1; 16], source, "", "", DeliveryMethod::Direct).unwrap();
    let m = freeze(d);
    assert!(m.verify(&identity.get_public_key()).is_ok());
    assert!(m.verify(&identity.get_public_key()).is_ok());
    let mut altered = identity.get_public_key();
    altered[..32].fill(8);
    assert!(matches!(
        m.verify(&altered),
        Err(MessageError::SourceMismatch)
    ));
    let wrong_source = freeze(draft());
    assert!(wrong_source.verify_signature(&key().public_key()));
    assert!(matches!(
        wrong_source.verify(&identity.get_public_key()),
        Err(MessageError::SourceMismatch)
    ));
    assert!(!m.verify_signature(&Ed25519PrivateKey::from_bytes(&[9; 32]).public_key()));
}
#[test]
fn owned_verification_retains_exact_source_and_shared_wire_after_handoff() {
    let identity = rns_identity::identity::Identity::from_private_key(&[7; 64]).unwrap();
    let source = rns_identity::destination::Destination::hash_from_name_and_identity(
        "lxmf.delivery",
        Some(&identity.hash),
    );
    let message = freeze(
        LxMessageDraft::new([1; 16], source, "title", "content", DeliveryMethod::Direct).unwrap(),
    );
    let pointer = message.wire_bytes().as_ptr();
    let hash = message.message_id();
    let owned = message
        .verify(&identity.get_public_key())
        .unwrap()
        .to_owned();
    drop(message);
    let verified = owned.as_verified();
    assert_eq!(verified.message().wire_bytes().as_ptr(), pointer);
    assert_eq!(verified.message().message_id(), hash);
    assert_eq!(verified.source_public_key(), &identity.get_public_key());
    assert_eq!(verified.message().source_hash(), source);
}
#[test]
fn field_id_entire_domain_and_serde_roundtrip() {
    let values = [
        i64::MIN as i128,
        -1,
        0,
        255,
        256,
        i64::MAX as i128,
        i64::MAX as i128 + 1,
        u64::MAX as i128,
    ];
    let mut d = draft();
    for v in values {
        let id = FieldId::try_from(v).unwrap();
        let bytes = rmp_serde::to_vec(&id).unwrap();
        let decoded: FieldId = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, id);
        d.set_field(id, vec![42]).unwrap();
    }
    let m = freeze(d);
    for v in values {
        assert_eq!(
            m.get_field(FieldId::try_from(v).unwrap())
                .unwrap()
                .as_binary(),
            Some(&[42][..])
        );
    }
    assert!(FieldId::try_from(i64::MIN as i128 - 1).is_err());
    assert!(FieldId::try_from(u64::MAX as i128 + 1).is_err());
    assert!(FieldId::from(256u64).as_standard().is_none());
    assert_eq!(FieldId::from(1u64), FieldId::from(1i64));
}
#[test]
fn field_id_never_aliases_native_ids() {
    let mut d = draft();
    d.set_field(0x105u64, vec![1]).unwrap();
    d.set_field(0x10cu64, vec![2]).unwrap();
    d.set_field(-1i64, vec![3]).unwrap();
    let m = freeze(d);
    assert!(!m.fields().contains(5u8));
    assert!(!m.fields().contains(12u8));
    assert!(!m.fields().contains(255u8));
    assert_eq!(m.fields().len(), 3);
}
#[test]
fn field_id_duplicate_numeric_encodings_rejected() {
    for map in [
        vec![0x82, 1, 0xc0, 1, 0xc0],
        vec![0x82, 1, 0xc0, 0xd1, 0, 1, 0xc0],
        vec![0x82, 0xcf, 0, 0, 0, 0, 0, 0, 0, 1, 0xc0, 0xcc, 1, 0xc0],
    ] {
        assert!(matches!(
            LxMessage::unpack(&wire(&payload(&map, None))),
            Err(MessageError::DuplicateField)
        ));
        let mut dto = vec![0x94, 0xcb];
        dto.extend_from_slice(&0f64.to_be_bytes());
        dto.extend_from_slice(&[0xc4, 0, 0xc4, 0]);
        dto.extend_from_slice(&map);
        assert!(rmp_serde::from_slice::<MessagePayload>(&dto).is_err());
    }
}
#[test]
fn field_id_coherent_replacement_and_binary_is_not_structure() {
    let mut d = draft();
    d.set_msgpack_field(FIELD_AUDIO, vec![0x92, 0x10, 0xc4, 0])
        .unwrap();
    d.set_field(FIELD_AUDIO, vec![0x92, 0x10, 0xc4, 0]).unwrap();
    let m = freeze(d);
    let value = m.get_field(FIELD_AUDIO).unwrap();
    assert_eq!(value.as_binary(), Some(&[0x92, 0x10, 0xc4, 0][..]));
    assert!(m.audio_field().is_err());
    assert!(LxMessage::unpack(m.wire_bytes()).is_ok());
    let mut d = draft();
    d.set_field(FIELD_AUDIO, vec![0]).unwrap();
    d.set_audio_field(0x10, &[1, 2]).unwrap();
    assert_eq!(freeze(d).audio_field().unwrap().unwrap().bytes, &[1, 2]);
}
#[test]
fn field_id_opaque_nested_duplicate_map_is_preserved() {
    let raw = vec![0x82, 1, 0x01, 0xd1, 0, 1, 0x02];
    let mut d = draft();
    d.set_msgpack_field(300u64, raw.clone()).unwrap();
    let m = freeze(d);
    assert_eq!(m.get_field(300u64).unwrap().encoded(), raw);
    assert_eq!(
        LxMessage::unpack(m.wire_bytes()).unwrap().pack().unwrap(),
        m.wire_bytes()
    );
}
#[test]
fn field_id_profile_counts_inbound_and_outbound() {
    let mut d = draft();
    for i in 0..4096u64 {
        d.set_field(i, Bytes::new()).unwrap();
    }
    d.set_field(0u64, vec![1]).unwrap();
    assert!(matches!(
        d.set_field(4096u64, Bytes::new()),
        Err(MessageError::TooManyFields)
    ));
    let m = freeze(d);
    assert_eq!(m.fields().len(), 4096);
    let smaller = MessageDecodeLimits {
        max_top_level_fields: 4095,
        ..MessageDecodeLimits::default()
    };
    assert!(matches!(
        LxMessage::unpack_owned(m.wire_owned(), smaller),
        Err(MessageError::TooManyFields)
    ));
    let profile = MessageDecodeLimits {
        max_top_level_fields: 1,
        ..MessageDecodeLimits::default()
    };
    let mut d =
        LxMessageDraft::new_with_limits([1; 16], [2; 16], "", "", DeliveryMethod::Direct, profile)
            .unwrap();
    d.set_field(1u8, vec![]).unwrap();
    assert!(d.set_field(FIELD_TICKET, vec![]).is_err());
    d.set_field(1u8, vec![2]).unwrap();
    assert_eq!(freeze(d).fields().len(), 1);
    let map = [0xdf, 0xff, 0xff, 0xff, 0xff];
    assert!(LxMessage::unpack(&wire(&payload(&map, None))).is_err());
}
#[test]
fn signed_body_finalization_enforces_exact_stamp_limit() {
    let base = freeze(draft()).wire_bytes().len();
    let mut profile = MessageDecodeLimits {
        max_wire_bytes: base,
        max_top_level_fields: 4096,
    };
    let d = LxMessageDraft::new_with_limits(
        [1; 16],
        [2; 16],
        "title",
        "content",
        DeliveryMethod::Direct,
        profile,
    )
    .unwrap();
    assert!(matches!(
        d.sign(&key())
            .unwrap()
            .finalize(Some(RecipientStamp::Ticket([1; 16]))),
        Err(MessageError::TooLarge { .. })
    ));
    profile.max_wire_bytes = base + 18;
    let d = LxMessageDraft::new_with_limits(
        [1; 16],
        [2; 16],
        "title",
        "content",
        DeliveryMethod::Direct,
        profile,
    )
    .unwrap();
    assert_eq!(
        d.sign(&key())
            .unwrap()
            .finalize(Some(RecipientStamp::Ticket([1; 16])))
            .unwrap()
            .wire_bytes()
            .len(),
        base + 18
    );
}
#[test]
fn signed_body_finalization_stamp_preserves_id_and_signature() {
    let mut d = draft();
    d.set_timestamp(1700000000.).unwrap();
    let no_stamp = freeze(d.clone());
    for stamp in [
        RecipientStamp::Ticket([3; 16]),
        RecipientStamp::ProofOfWork([4; 32]),
    ] {
        let m = d
            .clone()
            .sign(&key())
            .unwrap()
            .finalize(Some(stamp))
            .unwrap();
        assert_eq!(m.message_id(), no_stamp.message_id());
        assert_eq!(m.signature(), no_stamp.signature());
        assert!(m.verify_signature(&key().public_key()));
        assert_eq!(m.recipient_stamp(), Some(&stamp));
        assert_eq!(
            LxMessage::unpack(m.wire_bytes()).unwrap().message_id(),
            no_stamp.message_id()
        );
    }
}
#[test]
fn recipient_stamp_array_range_and_malformed_dispositions() {
    for (element, valid) in [
        (vec![0], true),
        (vec![0xcc, 255], true),
        (vec![0xd1, 0, 255], true),
        (vec![0xff], false),
        (vec![0xcd, 1, 0], false),
        (vec![0xcf, 255, 255, 255, 255, 255, 255, 255, 255], false),
    ] {
        let mut stamp = vec![0xdc, 0, 16];
        for _ in 0..16 {
            stamp.extend_from_slice(&element);
        }
        let bytes = wire(&payload(&[0x80], Some(&stamp)));
        let m = LxMessage::unpack(&bytes).unwrap();
        assert_eq!(m.recipient_stamp().is_some(), valid);
        assert_eq!(m.wire_bytes(), bytes);
        assert!(m.verify_signature(&key().public_key()));
        if !valid {
            assert!(!m.validate_stamp_with_tickets(0, None));
        }
    }
    for stamp in [vec![0xc0], vec![0x91, 0], vec![0xc4, 1, 0], vec![0xa0]] {
        let m = LxMessage::unpack(&wire(&payload(&[0x80], Some(&stamp)))).unwrap();
        assert!(m.recipient_stamp().is_none());
    }
    for stamp in [vec![], vec![0xc4], {
        let mut s = vec![0xdc, 0, 16];
        s.extend_from_slice(&[0xc0; 16]);
        s
    }] {
        assert!(LxMessage::unpack(&wire(&payload(&[0x80], Some(&stamp)))).is_err());
    }
}
#[test]
fn recipient_ticket_stamp_and_missing_stamp_policy() {
    let mut d = draft();
    d.outbound_ticket = Some([3; 16]);
    let signed = d.sign(&key()).unwrap();
    let stamp = signed.generate_recipient_stamp().unwrap();
    let m = signed.finalize(stamp).unwrap();
    assert!(m.validate_stamp_with_tickets(255, Some(&[vec![3; 16]])));
    assert_eq!(
        m.validated_stamp_value(255, Some(&[vec![3; 16]])),
        Some(COST_TICKET)
    );
    assert!(!m.validate_stamp_with_tickets(1, Some(&[vec![4; 16]])));
    assert!(!freeze(draft()).validate_stamp_with_tickets(0, None));
    let signed = draft().sign(&key()).unwrap();
    assert_eq!(signed.generate_recipient_stamp().unwrap(), None);
}
#[test]
fn signed_body_finalization_matches_semantic_dto() {
    let mut d = draft();
    d.set_timestamp(1700000000.).unwrap();
    d.set_field(256u64, vec![1, 2]).unwrap();
    d.set_msgpack_field(-1i64, vec![0x92, 1, 0xc4, 0]).unwrap();
    let dto = MessagePayload {
        timestamp: d.timestamp(),
        title: "title".into(),
        content: "content".into(),
        fields: d.fields().clone(),
        stamp: None,
    };
    let encoded = rmp_serde::to_vec(&dto).unwrap();
    assert_eq!(d.pack_payload().unwrap(), encoded);
    let decoded: MessagePayload = rmp_serde::from_slice(&encoded).unwrap();
    assert_eq!(decoded.fields, dto.fields);
}
#[test]
fn native_attachments_borrow_exact_image_and_clone() {
    let data = vec![0xa5; 2 * 1024 * 1024];
    let mut d = draft();
    d.set_audio_field(AM_OPUS_OGG, &data).unwrap();
    d.set_image_field("webp", &[2, 3]).unwrap();
    d.set_file_attachment_field("test.bin", &[4, 5]).unwrap();
    let m = freeze(d);
    let audio = m.audio_field().unwrap().unwrap();
    assert_eq!(audio.bytes, data);
    let start = m.wire_bytes().as_ptr() as usize;
    assert!((start..start + m.wire_bytes().len()).contains(&(audio.bytes.as_ptr() as usize)));
    assert_eq!(m.clone().wire_bytes().as_ptr(), m.wire_bytes().as_ptr());
    assert_eq!(
        m.image_attachment().unwrap(),
        Some(("webp".into(), &[2, 3][..]))
    );
    assert_eq!(
        m.first_file_attachment().unwrap(),
        Some(("test.bin".into(), &[4, 5][..]))
    );
    assert_eq!(m.packed_len().unwrap(), m.pack().unwrap().len());
    assert!(m.verify_signature(&key().public_key()));
    assert_eq!(
        m.audio_field().unwrap().unwrap().bytes.as_ptr(),
        audio.bytes.as_ptr()
    );
}
#[test]
fn native_audio_shape_and_optional_failure() {
    for malformed in [
        vec![0xc0],
        vec![0x91, 0x10],
        vec![0x93, 0x10, 0xc4, 0, 0xc0],
        vec![0x92, 0xff, 0xc4, 0],
        vec![0x92, 0xcd, 1, 0, 0xc4, 0],
        vec![0x92, 0xc0, 0xc4, 0],
        vec![0x92, 0x10, 0xa0],
    ] {
        let mut d = draft();
        d.set_msgpack_field(FIELD_AUDIO, malformed).unwrap();
        let m = freeze(d);
        assert!(m.audio_field().is_err());
        assert_eq!(m.content_text(), "content");
        assert!(m.verify_signature(&key().public_key()));
    }
    let mut d = draft();
    assert!(
        d.set_msgpack_field(FIELD_AUDIO, vec![0x92, 0x10, 0xc4])
            .is_err()
    );
    assert!(
        d.set_msgpack_field(FIELD_AUDIO, vec![0x92, 0x10, 0xc4, 0, 0xc0])
            .is_err()
    );
    d.set_msgpack_field(FIELD_AUDIO, vec![0x92, 0xcd, 0, 255, 0xc4, 0])
        .unwrap();
    assert_eq!(freeze(d).audio_field().unwrap().unwrap().mode, 255);
}
#[test]
fn received_wire_identity_paper_and_opportunistic_use_exact_tail() {
    let mut m = freeze(draft());
    m.method = DeliveryMethod::Paper;
    let uri = m.to_paper_uri(|tail| Ok(tail.to_vec())).unwrap();
    assert!(uri.starts_with("lxm://"));
    let read = LxMessage::from_paper_uri(&uri, |tail| Ok(tail.to_vec())).unwrap();
    assert_eq!(read.wire_bytes(), m.wire_bytes());
    assert!(read.verify_signature(&key().public_key()));
    assert_eq!(
        m.pack_opportunistic_encrypted(|tail| Ok(tail.to_vec()))
            .unwrap(),
        m.wire_bytes()[16..]
    );
    assert!(LxMessage::decode_paper_uri("not-uri").is_err());
    assert!(LxMessage::decode_paper_uri("lxm://!!").is_err());
    m.method = DeliveryMethod::Direct;
    assert!(m.to_paper_uri(|b| Ok(b.to_vec())).is_err());
}
#[test]
fn received_wire_identity_file_and_method_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = freeze(draft());
    m.state = MessageState::Delivered;
    m.transport_encrypted = true;
    m.transport_encryption = Some("ECIES".into());
    for method in [
        DeliveryMethod::Direct,
        DeliveryMethod::Propagated,
        DeliveryMethod::Paper,
        DeliveryMethod::Opportunistic,
    ] {
        m.method = method;
        let path = m.write_to_directory(dir.path().to_str().unwrap()).unwrap();
        let read = LxMessage::read_from_file(&path).unwrap();
        assert_eq!(read.method, method);
        assert_eq!(read.state, MessageState::Delivered);
        assert_eq!(read.wire_bytes(), m.wire_bytes());
        assert_eq!(read.transport_encryption, m.transport_encryption);
        assert!(read.verify_signature(&key().public_key()));
    }
}
#[test]
fn message_callbacks_and_compression_metadata_do_not_mutate_wire() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut m = freeze(draft());
    let before = m.wire_owned();
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    m.register_delivery_callback(move |_| {
        c.fetch_add(1, Ordering::SeqCst);
    });
    let c = calls.clone();
    m.register_failed_callback(move |_| {
        c.fetch_add(10, Ordering::SeqCst);
    });
    m.mark_delivered();
    m.mark_failed();
    assert_eq!(calls.load(Ordering::SeqCst), 11);
    m.determine_compression_support(None);
    assert!(m.auto_compress);
    m.determine_compression_support(Some(&[0x93, 0xc0, 0xc0, 0x90]));
    assert!(!m.auto_compress);
    assert_eq!(m.wire_bytes(), before);
}
#[test]
fn propagation_wrapper_compatibility_and_bounds() {
    let entry = vec![1; LxMessage::MIN_PROPAGATION_ENTRY_SIZE];
    let entries = [entry.as_slice()];
    let encoded = rmp_serde::to_vec(&PropagationWrapperRef {
        timestamp: 1.,
        entries: &entries,
    })
    .unwrap();
    assert_eq!(
        LxMessage::unpack_propagation_wrapper(&encoded).unwrap().1,
        vec![entry]
    );
    assert!(LxMessage::unpack_propagation_wrapper_bounded(&encoded, encoded.len()).is_ok());
    assert!(LxMessage::unpack_propagation_wrapper_bounded(&encoded, encoded.len() - 1).is_err());
    assert_eq!(
        LxMessage::compute_propagation_transient_id(&encoded),
        full_hash(&encoded)
    );
}
#[test]
fn received_wire_identity_bounds_and_invalid_utf8_preserved() {
    for len in 0..97 {
        assert!(LxMessage::unpack(&vec![0; len]).is_err());
    }
    let mut p = payload(&[0x80], None);
    p[12] = 255;
    let raw = wire(&p);
    let m = LxMessage::unpack(&raw).unwrap();
    assert_eq!(m.title_bytes(), &[255]);
    assert_eq!(m.title_text(), "\u{fffd}");
    assert_eq!(m.wire_bytes(), raw);
    assert!(m.verify_signature(&key().public_key()));
    let limits = MessageDecodeLimits {
        max_wire_bytes: raw.len() - 1,
        ..MessageDecodeLimits::default()
    };
    assert!(LxMessage::unpack_owned(raw.into(), limits).is_err());
}

#[test]
fn nested_field_duplicate_schema_reader_rejects_ambiguous_keys() {
    for encoded in [
        vec![0x82, 0xa1, b'a', 1, 0xa1, b'a', 2],
        vec![0x82, 1, 0, 0xd1, 0, 1, 1],
        vec![0x81, 0xc3, 0],
    ] {
        let mut d = draft();
        d.set_msgpack_field(300u64, encoded).unwrap();
        let m = freeze(d);
        assert!(m.get_field(300u64).unwrap().unique_map().is_err());
        assert!(m.verify_signature(&key().public_key()));
    }
    let mut d = draft();
    d.set_msgpack_field(300u64, vec![0x82, 0xa1, b'a', 0xc4, 1, 7, 0x01, 0x02])
        .unwrap();
    let m = freeze(d);
    let map = m.get_field(300u64).unwrap().unique_map().unwrap();
    assert_eq!(map.len(), 2);
    assert_eq!(
        map.get(FieldMapKey::Text("a")).unwrap().as_binary(),
        Some(&[7][..])
    );
    assert_eq!(
        map.get(FieldMapKey::Integer(1u8.into())).unwrap().encoded(),
        &[2]
    );
}
#[test]
fn signed_body_finalization_ticket_barrier_blocks_signer() {
    let owner = Arc::new(());
    let mut d = draft();
    d.mark_ticket_pending(owner.clone());
    assert!(!d.release_ticket_barrier(&Arc::new(())));
    assert!(matches!(
        d.clone()
            .sign_with(|_| -> Result<[u8; 64], &str> { panic!("uncommitted signer called") }),
        Err(MessageError::TicketNotCommitted)
    ));
    assert!(d.release_ticket_barrier(&owner));
    assert!(!d.release_ticket_barrier(&owner));
    assert!(d.sign(&key()).is_ok());
}

#[test]
fn lossy_projection_uses_exact_capacity_and_preserves_utf8_replacement() {
    for bytes in [
        b"".as_slice(),
        b"valid \xf0\x9f\xa6\x80".as_slice(),
        b"\xff\xff\xff".as_slice(),
        b"a\xf0\x90\x80".as_slice(),
        b"a\xed\xa0\x80b\xc0\x80c".as_slice(),
    ] {
        let actual = bounded_lossy_text(bytes);
        assert_eq!(actual, String::from_utf8_lossy(bytes));
        match actual {
            Cow::Borrowed(text) => assert_eq!(text.as_ptr(), bytes.as_ptr()),
            Cow::Owned(text) => assert_eq!(text.capacity(), text.len()),
        }
    }
    let bytes = vec![0xff; 1024 * 1024];
    let repaired = bounded_lossy_text(&bytes).into_owned();
    assert_eq!(repaired.len(), bytes.len() * 3);
    assert_eq!(repaired.capacity(), repaired.len());
}

proptest::proptest! {
    #[test]
    fn bounded_lossy_projection_matches_standard(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)) {
        let actual = bounded_lossy_text(&bytes);
        proptest::prop_assert_eq!(&actual, &String::from_utf8_lossy(&bytes));
        if let Cow::Owned(text) = actual {
            proptest::prop_assert_eq!(text.capacity(), text.len());
            proptest::prop_assert!(text.len() <= 3 * bytes.len());
        }
    }
}

#[test]
fn borrowed_encoded_field_validates_shape_without_copy_or_implicit_conversion() {
    let encoded = b"\xa4text";
    let field = FieldValueRef::from_encoded(encoded).unwrap();
    assert_eq!(field.encoded().as_ptr(), encoded.as_ptr());
    assert_eq!(field.as_text(), Some("text"));
    assert!(field.as_binary().is_none());
    assert!(
        FieldValueRef::from_encoded(b"\xc4\x04text")
            .unwrap()
            .as_text()
            .is_none()
    );
    assert!(
        FieldValueRef::from_encoded(b"\xa1\xff")
            .unwrap()
            .as_text()
            .is_none()
    );
    for invalid in [b"".as_slice(), b"\xa5text", b"\xa4text\xc0", b"\x81\x01"] {
        assert!(FieldValueRef::from_encoded(invalid).is_err());
    }
    let duplicate = FieldValueRef::from_encoded(b"\x82\x01\x02\xcc\x01\x03").unwrap();
    assert!(matches!(
        duplicate.unique_map(),
        Err(MessageError::DuplicateField)
    ));
}

#[test]
fn owned_propagation_wrapper_shares_binary_and_preserves_legacy_byte_arrays() {
    let entry = vec![0xff; LxMessage::MIN_PROPAGATION_ENTRY_SIZE];
    let entries = [entry.as_slice()];
    let binary = Bytes::from(
        rmp_serde::to_vec(&PropagationWrapperRef {
            timestamp: 1.,
            entries: &entries,
        })
        .unwrap(),
    );
    let (_, decoded) =
        LxMessage::unpack_propagation_wrapper_owned(binary.clone(), binary.len()).unwrap();
    assert_eq!(decoded[0].as_ref(), entry);
    assert_eq!(
        decoded[0].as_ptr(),
        binary[binary.len() - entry.len()..].as_ptr()
    );
    drop(binary);
    assert_eq!(decoded[0].as_ref(), entry);
    let legacy = rmp_serde::to_vec(&(1.0, vec![entry.clone()])).unwrap();
    assert_eq!(
        LxMessage::unpack_propagation_wrapper_bounded(&legacy, legacy.len())
            .unwrap()
            .1,
        vec![entry]
    );
}

#[test]
fn bounded_propagation_wrapper_rejects_forged_counts_and_lengths_before_allocation() {
    let forged_count = [0x92, 0x01, 0xdd, 0xff, 0xff, 0xff, 0xff];
    assert!(
        LxMessage::unpack_propagation_wrapper_owned(
            Bytes::copy_from_slice(&forged_count),
            usize::MAX
        )
        .is_err()
    );
    for marker in [0xdd, 0xc6] {
        let mut forged_length = vec![0x92, 0x01, 0x91, marker, 0xff, 0xff, 0xff, 0xff];
        forged_length.resize(1024, 0);
        assert!(LxMessage::unpack_propagation_wrapper_bounded(&forged_length, 1024).is_err());
    }
    let mut trailing = rmp_serde::to_vec(&(1.0, Vec::<Vec<u8>>::new())).unwrap();
    trailing.push(0);
    assert!(LxMessage::unpack_propagation_wrapper_bounded(&trailing, trailing.len()).is_err());
}
