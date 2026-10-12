//! In-process encrypted peers: every emitted packet is checked at the real MTU.
use super::*;
use rmpv::Value;
use rns_wire::{context::PacketContext as Context, flags::PacketType};

struct Peer {
    client: PropagationClient,
    link: Link,
    rx: mpsc::Receiver<TransportMessage>,
    held: Vec<oneshot::Sender<LinkEndpointSendResult>>,
    hold_advertisement: bool,
    resource_requests: usize,
    hmus: usize,
    drop_part: bool,
    drop_hmu: bool,
    drop_request: bool,
    retries: usize,
}

impl Peer {
    fn new() -> Self {
        let key = Ed25519PrivateKey::generate();
        let (mut initiator, request) = Link::new_initiator([0xe8; 16], 1);
        let (mut responder, proof) = Link::new_responder(&request, &key, [0xe8; 16], 1).unwrap();
        let rtt = initiator
            .validate_proof(&proof, &key.public_key(), &key.public_key().to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt).unwrap();
        let (tx, rx) = mpsc::channel(256);
        let mut client = PropagationClient::new(tx, None, None);
        client.link_id = Some(initiator.link_id);
        client.link = Some(initiator);
        client.attached_interface = Some(7);
        client.set_propagation_node([0xe8; 16]);
        Self {
            client,
            link: responder,
            rx,
            held: Vec::new(),
            hold_advertisement: false,
            resource_requests: 0,
            hmus: 0,
            drop_part: false,
            drop_hmu: false,
            drop_request: false,
            retries: 0,
        }
    }

    fn inject(&mut self, context: Context, payload: &[u8]) {
        let raw = PropagationClient::link_packet_bytes(
            self.link.link_id,
            context,
            if context == Context::ResourcePrf {
                PacketType::Proof
            } else {
                PacketType::Data
            },
            payload,
        );
        assert!(
            raw.len() <= rns_wire::constants::MTU,
            "peer packet exceeds MTU"
        );
        self.client
            .event_tx
            .try_send(DestinationEvent::InboundPacket {
                raw: raw.into(),
                interface_id: 7,
                metrics: Default::default(),
            })
            .unwrap();
        self.client.drain_events(&HashMap::new());
    }

    fn packet(&mut self) -> (Context, Vec<u8>, Vec<u8>) {
        let TransportMessage::SendLinkEndpoint {
            request,
            result_tx,
            role,
            ..
        } = self.rx.try_recv().expect("client packet")
        else {
            panic!("request must use typed Link endpoint");
        };
        assert_eq!(role, LinkEndpointRole::Initiator);
        assert!(
            request.raw.len() <= rns_wire::constants::MTU,
            "client packet exceeds MTU: {}",
            request.raw.len()
        );
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        if self.hold_advertisement && header.context == Context::ResourceAdv {
            self.held.push(result_tx);
            self.hold_advertisement = false;
        } else {
            result_tx.send(LinkEndpointSendResult::Sent).unwrap();
        }
        self.client.poll_endpoint_control();
        (
            header.context,
            request.raw[offset..].to_vec(),
            request.raw.to_vec(),
        )
    }

    /// Receive the exact client's next request, optionally withholding its
    /// Resource proof to exercise response-before-proof ordering.
    fn request(&mut self, prove: bool) -> ([u8; 16], Value, Option<Vec<u8>>) {
        let (context, payload, raw) = self.packet();
        if context == Context::Request {
            let (_, _, _, data) = self.link.handle_request(&payload).unwrap();
            let id =
                rns_wire::hash::truncated_packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
            assert_eq!(self.client.request.as_ref().unwrap().id, id);
            return (
                id,
                PropagationClient::decode_response_value(&data).unwrap(),
                None,
            );
        }
        assert_eq!(context, Context::ResourceAdv);
        self.resource_requests += 1;
        let adv = ResourceAdvertisement::unpack(&self.link.decrypt(&payload).unwrap()).unwrap();
        assert!(adv.flags.encrypted && adv.flags.is_request && !adv.flags.is_response);
        assert_eq!(adv.total_segments, 1);
        let mut receiver = InboundTransfer::from_advertisement(
            adv.num_parts,
            adv.transfer_size,
            adv.data_size,
            adv.random_hash.as_slice().try_into().unwrap(),
            adv.resource_hash,
            adv.flags,
            adv.get_map_hashes(),
            Duration::from_millis(10),
        )
        .unwrap();
        if let TransferAction::SendRequest(request) = receiver.request_next() {
            if !self.drop_request {
                self.inject(Context::ResourceReq, &self.link.encrypt(&request).unwrap());
            }
            self.drop_request = false;
        }
        let mut packets = 0;
        while !receiver.resource.is_complete() {
            packets += 1;
            assert!(packets < 20_000, "bounded request peer loop");
            if self.rx.is_empty() {
                receiver.last_activity = Instant::now() - Duration::from_secs(1000);
                receiver.req_sent = Some(receiver.last_activity);
                let TransferAction::SendRequest(request) = receiver.check_timeout() else {
                    panic!("receiver should retry its missing window");
                };
                self.retries += 1;
                self.inject(Context::ResourceReq, &self.link.encrypt(&request).unwrap());
            }
            let (context, body, _) = self.packet();
            if context == Context::Resource && self.drop_part {
                self.drop_part = false;
                continue;
            }
            if context == Context::ResourceHmu && self.drop_hmu {
                self.drop_hmu = false;
                continue;
            }
            let action = match context {
                Context::Resource => receiver.receive_part(body),
                Context::ResourceHmu => {
                    self.hmus += 1;
                    let plaintext = self.link.decrypt(&body).unwrap();
                    assert_eq!(&plaintext[..32], &adv.resource_hash);
                    let fields =
                        PropagationClient::decode_response_value(&plaintext[32..]).unwrap();
                    let fields = fields.as_array().unwrap();
                    receiver.hashmap_update(
                        fields[0].as_u64().unwrap() as usize,
                        fields[1].as_slice().unwrap(),
                    )
                }
                other => panic!("unexpected client Resource context {other:?}"),
            };
            if let TransferAction::SendRequest(request) = action {
                self.inject(Context::ResourceReq, &self.link.encrypt(&request).unwrap());
            }
        }
        let decrypt = |data: &[u8]| self.link.decrypt(data).map_err(|_| ResourceError::Corrupt);
        let (plaintext, proof) = receiver.complete(Some(&decrypt)).unwrap();
        let (id, path, _, data) = Link::parse_request(&plaintext).unwrap();
        assert_eq!(
            path,
            rns_crypto::sha::truncated_hash(MESSAGE_GET_PATH.as_bytes())
        );
        assert_eq!(adv.request_id.as_deref(), Some(id.as_slice()));
        assert_eq!(self.client.request.as_ref().unwrap().id, id);
        if prove {
            self.inject(Context::ResourcePrf, &proof);
        }
        (
            id,
            PropagationClient::decode_response_value(&data).unwrap(),
            Some(proof),
        )
    }

    fn response(&mut self, id: [u8; 16], value: Value, resource: bool) {
        self.response_with_envelope(id, id, value, resource);
    }

    fn response_with_envelope(
        &mut self,
        id: [u8; 16],
        envelope_id: [u8; 16],
        value: Value,
        resource: bool,
    ) {
        if !resource {
            let payload = self
                .link
                .create_response(&envelope_id, &crate::encode_value(&value))
                .unwrap();
            self.inject(Context::Response, &payload);
            return;
        }
        let envelope = crate::encode_value(&Value::Array(vec![
            Value::Binary(envelope_id.to_vec()),
            value,
        ]));
        let keys = self.link.session_keys().unwrap();
        let encrypt = |data: &[u8]| rns_link::encryption::link_encrypt(&keys, data).unwrap();
        let resources = if envelope.len() <= MAX_EFFICIENT_SIZE {
            let mut transfer =
                OutboundTransfer::new_encrypted(envelope, false, Duration::from_millis(10), keys)
                    .unwrap();
            transfer.resource.flags.is_response = true;
            transfer.resource.request_id = Some(id.to_vec());
            vec![transfer]
        } else {
            rns_protocol::resource::MultiSegmentOutbound::with_options(
                envelope,
                false,
                None,
                Some(id.to_vec()),
                true,
                Some(&encrypt),
            )
            .unwrap()
            .segments
            .into_iter()
            .map(|segment| OutboundTransfer::from_prebuilt(segment, Duration::from_millis(10)))
            .collect()
        };
        for mut sender in resources {
            let TransferAction::SendAdvertisement(adv) = sender.tick() else {
                panic!()
            };
            self.inject(Context::ResourceAdv, &self.link.encrypt(&adv).unwrap());
            let mut packets = 0;
            loop {
                packets += 1;
                assert!(packets < 20_000, "bounded response peer loop");
                let (context, body, _) = self.packet();
                if context == Context::ResourcePrf {
                    assert!(sender.handle_proof(&body));
                    break;
                }
                assert_eq!(context, Context::ResourceReq);
                let request = self.link.decrypt(&body).unwrap();
                for action in sender.handle_request(&request) {
                    match action {
                        TransferAction::SendPart(_, data) => self.inject(Context::Resource, &data),
                        TransferAction::SendHmu(data) => {
                            self.inject(Context::ResourceHmu, &self.link.encrypt(&data).unwrap())
                        }
                        other => panic!("unexpected response action {other:?}"),
                    }
                }
            }
        }
    }
}

fn ids(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| rns_crypto::sha::full_hash(&(i as u64).to_be_bytes()).to_vec())
        .collect()
}
fn blobs(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut data = ids(5).concat();
            data[..8].copy_from_slice(&(i as u64).to_be_bytes());
            data
        })
        .collect()
}
fn binary_list(items: &[Vec<u8>]) -> Value {
    Value::Array(items.iter().cloned().map(Value::Binary).collect())
}
fn empty() -> Value {
    Value::Array(Vec::new())
}

#[test]
fn full_encoded_mdu_boundary_selects_packet_or_resource() {
    for delta in [-1isize, 0, 1] {
        let mut peer = Peer::new();
        let len = peer
            .client
            .link
            .as_ref()
            .unwrap()
            .mdu
            .wrapping_add_signed(delta);
        let body = crate::encode_value(&Value::Array(vec![Value::Binary(vec![0x42; len - 32])]));
        assert!(peer.client.send_get_path_request(&body, RequestKind::List));
        let resource = peer.client.request.as_ref().unwrap().outbound.is_some();
        assert_eq!(resource, delta > 0);
        let _ = peer.request(true);
    }
}

#[test]
fn fifty_haves_complete_through_encrypted_request_resource() {
    let mut peer = Peer::new();
    let haves = ids(50);
    peer.client.available_messages = haves.clone();
    peer.client.replace_local_message_ids(haves.clone());
    peer.client.send_get_request();
    let (id, data, _) = peer.request(true);
    assert_eq!(data, Value::Array(vec![Value::Nil, binary_list(&haves)]));
    assert_eq!(
        peer.client.state(),
        PropagationClientState::PurgeRequested,
        "proof is not purge success"
    );
    peer.response(id, empty(), false);
    assert_eq!(peer.client.state(), PropagationClientState::Complete);
    assert_eq!(peer.resource_requests, 1);
    assert!(peer.client.pending_haves.is_empty());
}

#[test]
fn fifty_downloaded_messages_survive_get_and_purge_resource_round_trip() {
    let mut peer = Peer::new();
    let messages = blobs(50);
    let wants: Vec<_> = messages
        .iter()
        .map(|data| rns_crypto::sha::full_hash(data).to_vec())
        .collect();
    peer.client.available_messages = wants.clone();
    peer.client.send_get_request();
    let (get_id, request, _) = peer.request(true);
    assert_eq!(request.as_array().unwrap()[0], binary_list(&wants));
    peer.response(get_id, binary_list(&messages), true);
    assert_eq!(peer.client.received_count(), 50);
    let (purge_id, request, _) = peer.request(true);
    assert_eq!(request, Value::Array(vec![Value::Nil, binary_list(&wants)]));
    peer.response(purge_id, empty(), true);
    assert_eq!(peer.client.state(), PropagationClientState::Complete);
    assert_eq!(peer.client.transfer_status().result, Some(50));
    assert_eq!(peer.client.take_received_messages(), messages);
    assert_eq!(peer.resource_requests, 2);
    assert_eq!(peer.client.unread_bytes, 0);
}

#[test]
fn early_response_retires_sender_and_ignores_late_proof_cancel_and_receipt() {
    let mut peer = Peer::new();
    peer.hold_advertisement = true;
    peer.client.available_messages = ids(50);
    peer.client.send_get_request();
    let (old_id, _, proof) = peer.request(false);
    let old_hash = peer
        .client
        .request
        .as_ref()
        .unwrap()
        .outbound
        .as_ref()
        .unwrap()
        .resource
        .resource_hash;
    peer.response(old_id, binary_list(&blobs(1)), false);
    let new_request = peer.client.request.as_ref().unwrap();
    assert_ne!(old_id, new_request.id);
    let generation = new_request.generation;
    let wait = new_request.waiting_since;
    assert!(new_request.outbound.is_none());
    peer.inject(Context::ResourcePrf, &proof.unwrap());
    peer.inject(Context::ResourceRcl, &peer.link.encrypt(&old_hash).unwrap());
    for receipt in peer.held.drain(..) {
        let _ = receipt.send(LinkEndpointSendResult::InvalidPacket);
    }
    peer.client.poll_endpoint_control();
    assert_eq!(peer.client.request.as_ref().unwrap().generation, generation);
    assert_eq!(peer.client.request.as_ref().unwrap().waiting_since, wait);
    assert_eq!(peer.client.state(), PropagationClientState::PurgeRequested);
    let (purge, _, _) = peer.request(true);
    peer.response(purge, empty(), false);
    assert_eq!(peer.client.state(), PropagationClientState::Complete);
}

#[test]
fn foreign_responses_and_cancels_cannot_advance_or_fail_request() {
    let mut peer = Peer::new();
    peer.client.available_messages = ids(50);
    peer.client.send_get_request();
    let id = peer.client.request.as_ref().unwrap().id;
    peer.response([0xaa; 16], empty(), false);
    peer.inject(
        Context::ResourceRcl,
        &peer.link.encrypt(&[0xbb; 32]).unwrap(),
    );
    peer.inject(Context::ResourcePrf, &[0xcc; 64]);
    let hash = peer
        .client
        .request
        .as_ref()
        .unwrap()
        .outbound
        .as_ref()
        .unwrap()
        .resource
        .resource_hash;
    peer.inject(Context::ResourceIcl, &peer.link.encrypt(&hash).unwrap());
    assert_eq!(peer.client.request.as_ref().unwrap().id, id);
    assert_eq!(peer.client.state(), PropagationClientState::GetRequested);
    peer.inject(Context::ResourceRcl, &peer.link.encrypt(&hash).unwrap());
    assert_eq!(peer.client.state(), PropagationClientState::Failed);
}

#[test]
fn purge_errors_never_complete_or_advance_chunk() {
    for value in [
        Value::Nil,
        Value::from(0xf0),
        Value::Array(vec![Value::Nil]),
        Value::Binary(vec![0x90]),
    ] {
        let mut peer = Peer::new();
        peer.client.received_ids = ids(12);
        peer.client.send_purge_request();
        let (id, _, _) = peer.request(true);
        peer.response(id, value, false);
        assert_eq!(peer.client.state(), PropagationClientState::Failed);
        assert_eq!(peer.client.received_ids.len(), 12);
    }
}

#[test]
fn capacity_failure_precedes_publication_purge_and_cursor_advance() {
    let mut peer = Peer::new();
    peer.client.unread_limit = 100;
    peer.client.received_messages.push(vec![1; 20]);
    peer.client.unread_bytes = 20;
    peer.client.available_messages = ids(2);
    peer.client.send_get_request();
    let (id, _, _) = peer.request(true);
    peer.response(id, binary_list(&[vec![2; 60], vec![3; 30]]), false);
    assert_eq!(peer.client.state(), PropagationClientState::Failed);
    assert_eq!(peer.client.pending_wants.len(), 2);
    assert!(peer.client.received_ids.is_empty());
    assert_eq!(peer.client.received_messages, vec![vec![1; 20]]);
    assert_eq!(peer.client.unread_bytes, 20);
    assert!(peer.rx.try_recv().is_err(), "overflow must not queue purge");
    assert!(!peer.client.start_download());
    peer.client.cancel_download();
    assert!(!peer.client.start_download());
    assert_eq!(peer.client.take_received_messages(), vec![vec![1; 20]]);
}

#[test]
fn request_resource_progress_is_not_a_fixed_120_second_operation() {
    let mut peer = Peer::new();
    peer.client.received_ids = ids(50);
    peer.client.send_purge_request();
    peer.client.started_at = Some(Instant::now() - Duration::from_secs(600));
    peer.client.tick();
    assert_eq!(peer.client.state(), PropagationClientState::PurgeRequested);
    let (id, _, _) = peer.request(true);
    let request = peer.client.request.as_mut().unwrap();
    request.waiting_since = Some(Instant::now() - request.timeout - Duration::from_secs(1));
    peer.client.tick();
    assert_eq!(peer.client.state(), PropagationClientState::Failed);
    assert!(peer.client.request.is_none());
    // No late response can resurrect a cleaned-up request.
    peer.response(id, empty(), false);
    assert_eq!(peer.client.state(), PropagationClientState::Failed);
}

#[test]
fn lost_advertisement_retries_same_resource_and_eventually_fails() {
    let mut peer = Peer::new();
    peer.client.received_ids = ids(50);
    peer.client.send_purge_request();
    let (_, payload, _) = peer.packet();
    let original = peer.link.decrypt(&payload).unwrap();
    let mut retries = 0;
    while peer.client.state() != PropagationClientState::Failed {
        peer.client
            .request
            .as_mut()
            .unwrap()
            .outbound
            .as_mut()
            .unwrap()
            .started_at = Instant::now() - Duration::from_secs(100_000);
        peer.client.drive_outbound_request();
        if peer.client.state() != PropagationClientState::Failed {
            let (context, payload, _) = peer.packet();
            assert_eq!(context, Context::ResourceAdv);
            assert_eq!(peer.link.decrypt(&payload).unwrap(), original);
            retries += 1;
            assert!(retries <= rns_protocol::resource::MAX_ADV_RETRIES);
        }
    }
    assert!(retries > 0);
}

#[test]
fn oversized_logical_sets_advance_after_empty_and_partial_chunks() {
    let mut peer = Peer::new();
    let selected = ids(30_845);
    peer.client.max_messages = Some(30_840);
    peer.client.available_messages = selected.clone();
    peer.client.available_messages.push(selected[0].clone());
    peer.client.send_get_request();
    let first = peer.client.request.as_ref().unwrap();
    let RequestKind::Get(first_count) = first.kind else {
        panic!()
    };
    assert!(first_count < 30_840);
    assert!(
        first
            .outbound
            .as_ref()
            .unwrap()
            .resource
            .advertisement_data_size
            <= MAX_EFFICIENT_SIZE
    );
    let id = first.id;
    // Correlated early empty response skips the complete requested chunk.
    peer.response(id, empty(), false);
    let RequestKind::Get(tail_count) = peer.client.request.as_ref().unwrap().kind else {
        panic!()
    };
    assert_eq!(first_count + tail_count, 30_840);
    let tail = peer.client.request.as_ref().unwrap().id;
    peer.response(tail, binary_list(&blobs(1)), false);
    assert!(peer.client.pending_wants.is_empty());
    assert_eq!(peer.client.received_ids.len(), 1);
    let purge = peer.client.request.as_ref().unwrap().id;
    peer.response(purge, empty(), false);
    assert_eq!(peer.client.state(), PropagationClientState::Complete);
    assert_eq!(peer.client.transfer_status().result, Some(1));
}

#[test]
fn known_haves_chunks_complete_and_retain_policy_skips_only_known_haves() {
    let mut peer = Peer::new();
    let selected = ids(30_840);
    peer.client.available_messages = selected.clone();
    peer.client.replace_local_message_ids(selected);
    peer.client.send_get_request();
    let RequestKind::Haves(first) = peer.client.request.as_ref().unwrap().kind else {
        panic!()
    };
    assert!(first < 30_840);
    let id = peer.client.request.as_ref().unwrap().id;
    peer.response(id, empty(), false);
    assert_eq!(peer.client.pending_haves.len(), 30_840 - first);
    let id = peer.client.request.as_ref().unwrap().id;
    peer.response(id, empty(), false);
    assert!(peer.client.pending_haves.is_empty());
    assert_eq!(peer.client.state(), PropagationClientState::Complete);

    let mut peer = Peer::new();
    peer.client.available_messages = ids(2);
    peer.client.replace_local_message_ids(ids(1));
    peer.client.set_retain_synced_on_node(true);
    peer.client.send_get_request();
    let (id, data, _) = peer.request(true);
    assert_eq!(data.as_array().unwrap()[0], binary_list(&ids(2)[1..]));
    assert_eq!(data.as_array().unwrap()[1], empty());
    peer.response(id, binary_list(&blobs(1)), false);
    assert!(matches!(
        peer.client.request.as_ref().unwrap().kind,
        RequestKind::Purge(1)
    ));
}

#[test]
fn hashmap_updates_and_split_responses_keep_exact_request_identity() {
    let mut peer = Peer::new();
    peer.client.received_ids = ids(1200);
    peer.client.send_purge_request();
    let (id, _, _) = peer.request(true);
    assert!(
        peer.hmus > 0,
        "incompressible IDs cross advertised hashmap boundary"
    );
    peer.response(id, empty(), false);
    assert_eq!(peer.client.state(), PropagationClientState::Complete);

    let mut peer = Peer::new();
    peer.client.available_messages = ids(1);
    peer.client.set_delivery_limit(2000.0);
    peer.client.send_get_request();
    let (id, _, _) = peer.request(true);
    let blob = vec![0x5a; MAX_EFFICIENT_SIZE + 100];
    peer.response(id, binary_list(std::slice::from_ref(&blob)), true);
    assert_eq!(peer.client.received_messages, vec![blob]);
    assert_eq!(peer.client.state(), PropagationClientState::PurgeRequested);
    assert!(peer.client.inbound_split_resources.is_empty());
}

#[test]
fn every_id_branch_switches_at_real_packet_boundary() {
    for count in [11, 12, 50] {
        for branch in 0..4 {
            let mut peer = Peer::new();
            let selected = ids(count);
            peer.client.set_delivery_limit(1000.0);
            match branch {
                0 => {
                    peer.client.available_messages = selected.clone();
                    peer.client.send_get_request();
                }
                1 | 2 => {
                    peer.client.available_messages = selected.clone();
                    peer.client.replace_local_message_ids(selected.clone());
                    if branch == 2 {
                        peer.client.available_messages.push(vec![0xee; 32]);
                    }
                    peer.client.send_get_request();
                }
                _ => {
                    peer.client.received_ids = selected.clone();
                    peer.client.send_purge_request();
                }
            }
            assert_eq!(
                peer.client.request.as_ref().unwrap().outbound.is_some(),
                count > 11
            );
            let (id, body, _) = peer.request(true);
            let fields = body.as_array().unwrap();
            assert_eq!(
                fields[if branch == 0 { 0 } else { 1 }],
                binary_list(&selected)
            );
            peer.response(id, empty(), false);
            if branch == 2 {
                let (id, body, _) = peer.request(true);
                assert_eq!(body.as_array().unwrap()[0], binary_list(&[vec![0xee; 32]]));
                peer.response(id, empty(), false);
            }
            assert_eq!(peer.client.state(), PropagationClientState::Complete);
        }
    }
}

#[test]
fn list_resource_response_starts_correlated_haves_resource() {
    let mut peer = Peer::new();
    let selected = ids(50);
    peer.client.replace_local_message_ids(selected.clone());
    peer.client.send_list_request();
    let (id, body, _) = peer.request(true);
    assert_eq!(body, Value::Array(vec![Value::Nil, Value::Nil]));
    peer.response(id, binary_list(&selected), true);
    let (id, body, _) = peer.request(true);
    assert_eq!(body, Value::Array(vec![Value::Nil, binary_list(&selected)]));
    peer.response(id, empty(), false);
    assert_eq!(peer.client.state(), PropagationClientState::Complete);
}

#[test]
fn request_resource_recovers_lost_req_part_and_hashmap_update() {
    let mut peer = Peer::new();
    peer.drop_request = true;
    peer.drop_part = true;
    peer.drop_hmu = true;
    peer.client.received_ids = ids(1200);
    peer.client.send_purge_request();
    let (id, body, _) = peer.request(true);
    assert_eq!(body.as_array().unwrap()[1].as_array().unwrap().len(), 1200);
    assert!(peer.retries >= 3);
    peer.response(id, empty(), false);
    assert_eq!(peer.client.state(), PropagationClientState::Complete);
}

#[test]
fn encoded_single_segment_ceiling_is_inclusive() {
    for extra in [0, 1] {
        let mut peer = Peer::new();
        // A bin32 adds five bytes, its array one byte, and the request
        // envelope adds 28 bytes for the float timestamp and path hash.
        let body = crate::encode_value(&Value::Array(vec![Value::Binary(vec![
            0x42;
            MAX_EFFICIENT_SIZE
                - 34
                + extra
        ])]));
        let admitted = peer.client.send_get_path_request(&body, RequestKind::List);
        assert_eq!(admitted, extra == 0);
        if admitted {
            let sender = peer
                .client
                .request
                .as_ref()
                .unwrap()
                .outbound
                .as_ref()
                .unwrap();
            assert_eq!(sender.resource.advertisement_data_size, MAX_EFFICIENT_SIZE);
        } else {
            assert!(peer.client.request.is_none());
            assert!(peer.rx.is_empty());
        }
    }
}

#[test]
fn mismatched_resource_envelope_fails_without_publishing_or_purging() {
    let mut peer = Peer::new();
    peer.client.available_messages = ids(1);
    peer.client.send_get_request();
    let (id, _, _) = peer.request(true);
    peer.response_with_envelope(id, [0xff; 16], binary_list(&blobs(1)), true);
    assert_eq!(peer.client.state(), PropagationClientState::Failed);
    assert_eq!(peer.client.received_count(), 0);
    assert!(peer.client.received_ids.is_empty());
    assert_eq!(peer.client.pending_wants.len(), 1);
}

#[test]
fn advertisement_requires_matching_request_id_and_response_direction() {
    let mut peer = Peer::new();
    peer.client.received_ids = ids(12);
    peer.client.send_purge_request();
    let (id, _, _) = peer.request(true);
    let mut sender = OutboundTransfer::new_encrypted(
        Link::pack_response(&id, &[0x90]).unwrap(),
        false,
        Duration::from_millis(10),
        peer.link.session_keys().unwrap(),
    )
    .unwrap();
    sender.resource.flags.is_response = true;
    sender.resource.request_id = Some(vec![0xfe; 16]);
    let TransferAction::SendAdvertisement(bytes) = sender.tick() else {
        panic!()
    };
    let mut adv = ResourceAdvertisement::unpack(&bytes).unwrap();
    peer.inject(
        Context::ResourceAdv,
        &peer.link.encrypt(&adv.pack()).unwrap(),
    );
    assert!(peer.client.inbound_resources.is_empty());
    assert_eq!(peer.client.state(), PropagationClientState::PurgeRequested);
    adv.request_id = Some(id.to_vec());
    adv.flags.is_response = false;
    peer.inject(
        Context::ResourceAdv,
        &peer.link.encrypt(&adv.pack()).unwrap(),
    );
    assert!(peer.client.inbound_resources.is_empty());
    adv.flags.is_response = true;
    adv.flags.is_request = true;
    peer.inject(
        Context::ResourceAdv,
        &peer.link.encrypt(&adv.pack()).unwrap(),
    );
    assert_eq!(peer.client.state(), PropagationClientState::Failed);
}

#[test]
fn malformed_batch_is_atomic_and_preserves_prior_results() {
    let mut peer = Peer::new();
    peer.client.received_messages.push(vec![0xab; 20]);
    peer.client.unread_bytes = 20;
    peer.client.available_messages = ids(2);
    peer.client.send_get_request();
    let (id, _, _) = peer.request(true);
    peer.response(
        id,
        Value::Array(vec![Value::Binary(vec![7; 10]), Value::Nil]),
        false,
    );
    assert_eq!(peer.client.state(), PropagationClientState::Failed);
    assert_eq!(peer.client.received_messages, vec![vec![0xab; 20]]);
    assert_eq!(peer.client.unread_bytes, 20);
    assert!(peer.client.received_ids.is_empty());
    assert_eq!(peer.client.pending_wants.len(), 2);
}

#[test]
fn accepted_results_survive_purge_failure_cancel_and_disconnect_until_drained() {
    for failure in 0..3 {
        let mut peer = Peer::new();
        let messages = blobs(50);
        peer.client.available_messages = ids(50);
        peer.client.send_get_request();
        let (id, _, _) = peer.request(true);
        peer.response(id, binary_list(&messages), true);
        assert_eq!(peer.client.received_count(), 50);
        match failure {
            0 => {
                let (id, _, _) = peer.request(true);
                peer.response(id, Value::from(0xf0), false);
                peer.client.tick();
            }
            1 => peer.client.cancel_download(),
            _ => {
                let teardown = peer.link.teardown(CloseReason::DestinationClosed).unwrap();
                peer.inject(Context::LinkClose, &teardown);
            }
        }
        assert!(!peer.client.start_download());
        assert_eq!(peer.client.take_received_messages(), messages);
        assert_eq!(peer.client.unread_bytes, 0);
        assert!(peer.client.start_download());
        assert!(peer.client.take_received_messages().is_empty());
    }
}

#[test]
fn transport_result_deadline_is_finite_and_retains_results() {
    let mut peer = Peer::new();
    peer.client.received_messages.push(vec![0x33; 10]);
    peer.client.unread_bytes = 10;
    peer.client.received_ids = ids(50);
    peer.client.send_purge_request();
    let pending = peer.client.pending_endpoint_sends.last_mut().unwrap();
    pending.queued_at = Instant::now() - Duration::from_secs(121);
    peer.client.tick();
    assert_eq!(peer.client.state(), PropagationClientState::Failed);
    assert!(peer.client.request.is_none());
    assert!(!peer.client.start_download());
    assert_eq!(peer.client.take_received_messages(), vec![vec![0x33; 10]]);
}

#[test]
fn packet_response_wait_begins_after_transport_admission() {
    let mut peer = Peer::new();
    peer.client.send_list_request();
    assert!(
        peer.client
            .request
            .as_ref()
            .unwrap()
            .waiting_since
            .is_none()
    );
    peer.client.started_at = Some(Instant::now() - Duration::from_secs(600));
    peer.client.tick();
    assert_eq!(peer.client.state(), PropagationClientState::ListRequested);
    let (id, _, _) = peer.request(true);
    assert!(
        peer.client
            .request
            .as_ref()
            .unwrap()
            .waiting_since
            .is_some()
    );
    peer.response(id, empty(), false);
    assert_eq!(peer.client.state(), PropagationClientState::Complete);
}

#[test]
fn slow_segment_gets_a_fresh_proof_admission_deadline() {
    let mut peer = Peer::new();
    peer.client.available_messages = ids(1);
    peer.client.send_get_request();
    let (id, _, _) = peer.request(true);
    let messages = blobs(1);
    let mut sender = OutboundTransfer::new_encrypted(
        Link::pack_response(&id, &crate::encode_value(&binary_list(&messages))).unwrap(),
        false,
        Duration::from_millis(10),
        peer.link.session_keys().unwrap(),
    )
    .unwrap();
    sender.resource.flags.is_response = true;
    sender.resource.request_id = Some(id.to_vec());
    let TransferAction::SendAdvertisement(adv) = sender.tick() else {
        panic!()
    };
    peer.inject(Context::ResourceAdv, &peer.link.encrypt(&adv).unwrap());
    let (context, request, _) = peer.packet();
    assert_eq!(context, Context::ResourceReq);
    peer.client.started_at = Some(Instant::now() - Duration::from_secs(600));
    peer.client
        .request
        .as_mut()
        .unwrap()
        .response
        .as_mut()
        .unwrap()
        .waiting_since = Instant::now() - Duration::from_secs(600);
    for action in sender.handle_request(&peer.link.decrypt(&request).unwrap()) {
        let TransferAction::SendPart(_, data) = action else {
            panic!()
        };
        peer.inject(Context::Resource, &data);
    }
    assert!(
        peer.client
            .request
            .as_ref()
            .unwrap()
            .response
            .as_ref()
            .unwrap()
            .waiting_since
            .elapsed()
            < Duration::from_secs(1)
    );
    peer.client.tick();
    assert_eq!(peer.client.state(), PropagationClientState::Receiving);
    let (context, proof, _) = peer.packet();
    assert_eq!(context, Context::ResourcePrf);
    assert!(sender.handle_proof(&proof));
    assert_eq!(peer.client.received_messages, messages);
}

#[test]
fn response_resource_before_request_proof_retires_only_its_sender() {
    let mut peer = Peer::new();
    peer.client.available_messages = ids(50);
    peer.client.send_get_request();
    let (id, _, proof) = peer.request(false);
    peer.response(id, binary_list(&blobs(50)), true);
    let successor = peer.client.request.as_ref().unwrap().id;
    let generation = peer.client.request.as_ref().unwrap().generation;
    peer.inject(Context::ResourcePrf, &proof.unwrap());
    assert_eq!(peer.client.request.as_ref().unwrap().generation, generation);
    assert_eq!(peer.client.request.as_ref().unwrap().id, successor);
    let (id, _, _) = peer.request(true);
    peer.response(id, empty(), false);
    assert_eq!(peer.client.state(), PropagationClientState::Complete);
    assert_eq!(peer.client.received_count(), 50);
}

#[test]
fn full_then_closed_transport_fails_request_without_losing_accepted_results() {
    let mut peer = Peer::new();
    while peer
        .client
        .transport_tx
        .try_send(TransportMessage::DeregisterDestination { hash: [0; 16] })
        .is_ok()
    {}
    peer.client.received_messages.push(vec![1; 12]);
    peer.client.unread_bytes = 12;
    peer.client.received_ids = ids(50);
    peer.client.send_purge_request();
    assert_eq!(peer.client.pending_transport.len(), 1);
    assert_eq!(peer.client.state(), PropagationClientState::PurgeRequested);
    peer.rx.close();
    peer.client.tick();
    assert_eq!(peer.client.state(), PropagationClientState::Failed);
    assert!(peer.client.request.is_none());
    assert_eq!(peer.client.take_received_messages(), vec![vec![1; 12]]);
}
