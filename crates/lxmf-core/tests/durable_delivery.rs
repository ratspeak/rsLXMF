//! Focused public-boundary regressions for durable propagation delivery.
use lxmf_core::admission::*;
use lxmf_core::admission_store::FileAdmissionStore;
use lxmf_core::constants::DeliveryMethod;
use lxmf_core::message::{LxMessage, LxMessageDraft, RecipientStamp};
use lxmf_core::propagation_send::*;
use rns_crypto::{ed25519::Ed25519PrivateKey, sha::full_hash};

// These tests deliberately exhaust the shared production admission budget.
// Exclude only other budget-exhaustion fixtures, without changing its limits.
static PROCESSING_BUDGET_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn message(stamp: Option<RecipientStamp>) -> LxMessage {
    let mut draft = LxMessageDraft::new(
        [1; 16],
        [2; 16],
        "title",
        "body",
        DeliveryMethod::Propagated,
    )
    .unwrap();
    draft.set_timestamp(100.).unwrap();
    draft
        .sign(&Ed25519PrivateKey::from_bytes(&[3; 32]))
        .unwrap()
        .finalize(stamp)
        .unwrap()
}
fn scope(n: u8) -> AdmissionScope {
    AdmissionScope {
        identity: [4; 16],
        node: [5; 16],
        transient_id: [n; 32],
    }
}
fn record(msg: &LxMessage, n: u8, time: u64, disposition: DurableDisposition) -> AdmissionRecord {
    AdmissionRecord {
        scope: scope(n),
        message_id: msg.message_id(),
        received_wire_hash: full_hash(msg.wire_bytes()),
        stored_message_wire_hash: None,
        disposition,
        committed_at: time,
    }
}
fn commit(
    store: &FileAdmissionStore,
    msg: &LxMessage,
    n: u8,
    time: u64,
    disposition: DurableDisposition,
) -> DurableAdmissionReceipt {
    DurableAdmissionReceipt::commit(store.prepare(
        record(msg, n, time, disposition),
        msg.wire_owned(),
        true,
    ))
    .unwrap()
}
#[test]
fn duplicate_stamp_images_keep_first_archive_and_one_hook_across_restart() {
    let temp = tempfile::tempdir().unwrap();
    let bodies = temp.path().join("messages");
    let store = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
    let first = message(None);
    let second = message(Some(RecipientStamp::ProofOfWork([7; 32])));
    assert_eq!(first.message_id(), second.message_id());
    assert_ne!(first.wire_bytes(), second.wire_bytes());
    commit(&store, &first, 1, 100, DurableDisposition::Committed);
    let duplicate = commit(&store, &second, 2, 101, DurableDisposition::Committed);
    assert_eq!(
        duplicate.record().disposition,
        DurableDisposition::Duplicate
    );
    assert_eq!(
        duplicate.record().received_wire_hash,
        full_hash(second.wire_bytes())
    );
    assert_eq!(
        duplicate.record().stored_message_wire_hash,
        Some(full_hash(first.wire_bytes()))
    );
    assert_eq!(
        std::fs::read(bodies.join(format!("{}.lxm", hex::encode(first.message_id())))).unwrap(),
        first.wire_bytes()
    );
    assert_eq!(store.pending_hooks().len(), 1);
    drop(store);
    let reopened = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
    assert_eq!(
        reopened.haves(scope(1).identity, scope(1).node, 102).len(),
        2
    );
    assert_eq!(reopened.pending_hooks().len(), 1);
    let event = reopened.pending_hooks()[0].0;
    reopened.complete_hook(event).unwrap();
    drop(reopened);
    assert!(
        FileAdmissionStore::open(temp.path(), &bodies)
            .unwrap()
            .pending_hooks()
            .is_empty()
    );
}
#[test]
fn published_body_intent_recovers_original_tid_after_missing_commit() {
    let temp = tempfile::tempdir().unwrap();
    let bodies = temp.path().join("messages");
    let store = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
    let msg = message(None);
    commit(&store, &msg, 9, 100, DurableDisposition::Committed);
    drop(store);
    let dir = temp.path().join("download-admission-v1");
    for file in std::fs::read_dir(&dir).unwrap() {
        let path = file.unwrap().path();
        if path.extension().is_some_and(|s| s == "commit") {
            std::fs::remove_file(path).unwrap();
        }
    }
    let recovered = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
    assert_eq!(
        recovered.haves(scope(9).identity, scope(9).node, 101),
        vec![scope(9).transient_id.to_vec()]
    );
    assert_eq!(recovered.pending_hooks().len(), 1);
}
#[test]
fn damaged_archive_never_becomes_purge_authority_on_restart() {
    let temp = tempfile::tempdir().unwrap();
    let bodies = temp.path().join("messages");
    let store = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
    let msg = message(None);
    commit(&store, &msg, 1, 100, DurableDisposition::Committed);
    drop(store);
    let archive = bodies.join(format!("{}.lxm", hex::encode(msg.message_id())));
    std::fs::write(&archive, b"preserved corrupt evidence").unwrap();
    let reopened = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
    assert!(
        reopened
            .haves(scope(1).identity, scope(1).node, 101)
            .is_empty()
    );
    assert!(reopened.pending_hooks().is_empty());
    assert_eq!(
        std::fs::read(archive).unwrap(),
        b"preserved corrupt evidence"
    );
}
#[test]
fn expired_policy_receipt_is_revalidated_and_user_deletion_outlives_tid_receipts() {
    let temp = tempfile::tempdir().unwrap();
    let bodies = temp.path().join("messages");
    let store = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
    let msg = message(None);
    commit(&store, &msg, 1, 100, DurableDisposition::PolicyDiscard);
    assert!(
        !bodies
            .join(format!("{}.lxm", hex::encode(msg.message_id())))
            .exists()
    );
    let now = 101 + POLICY_RECEIPT_LIFETIME;
    assert!(
        store
            .haves(scope(1).identity, scope(1).node, now)
            .is_empty()
    );
    assert_eq!(
        commit(&store, &msg, 1, now, DurableDisposition::Committed)
            .record()
            .disposition,
        DurableDisposition::Committed
    );
    store
        .mark_user_deleted(scope(1).identity, msg.message_id(), now + 1)
        .unwrap();
    assert!(store.pending_hooks().is_empty());
    assert_eq!(
        store.maintain(now + 2 + POLICY_RECEIPT_LIFETIME).unwrap(),
        1
    );
    drop(store);
    let reopened = FileAdmissionStore::open(temp.path(), &bodies).unwrap();
    assert_eq!(
        commit(
            &reopened,
            &msg,
            2,
            now + 3 + POLICY_RECEIPT_LIFETIME,
            DurableDisposition::Committed
        )
        .record()
        .disposition,
        DurableDisposition::UserDeleted
    );
    assert!(
        !bodies
            .join(format!("{}.lxm", hex::encode(msg.message_id())))
            .exists()
    );
}
#[test]
fn suppression_retries_transient_failures_and_revalidates_epoch_changes() {
    let mut ledger = SuppressionLedger::default();
    let epoch = AdmissionEpochs::default();
    ledger
        .record_failure(scope(1), SuppressionReason::DecryptionFailed, epoch, 100)
        .unwrap();
    assert!(ledger.get(&scope(1)).unwrap().active(101, epoch));
    let mut new = epoch;
    new.keys[0] = 1;
    assert!(!ledger.get(&scope(1)).unwrap().active(101, new));
    for _ in 0..20 {
        ledger
            .record_failure(scope(2), SuppressionReason::StorageBusy, epoch, 100)
            .unwrap();
    }
    let retry = ledger.get(&scope(2)).unwrap();
    assert!((3340..=4060).contains(&retry.next_retry));
    assert!(!retry.active(retry.next_retry, epoch));
    let wire = rmp_serde::to_vec(&ledger).unwrap();
    let restored: SuppressionLedger = rmp_serde::from_slice(&wire).unwrap();
    assert_eq!(restored.records().count(), 2);
}
#[test]
fn processing_admission_fails_promptly_without_partial_credit_deadlock() {
    let _exclusive = PROCESSING_BUDGET_TEST.lock().unwrap();
    assert!(matches!(
        ProcessingLease::try_acquire(usize::MAX),
        Err(SuppressionReason::TooLarge)
    ));
    let workers = (0..MAX_PROCESSORS)
        .map(|_| ProcessingLease::try_acquire(100).unwrap())
        .collect::<Vec<_>>();
    assert!(matches!(
        ProcessingLease::try_acquire(100),
        Err(SuppressionReason::WorkerUnavailable)
    ));
    drop(workers);
    assert!(ProcessingLease::try_acquire(100).is_ok());
}
#[test]
fn propagation_retry_keeps_ciphertext_and_tid_when_cost_rises() {
    let msg = message(None);
    let binding = EncryptionBinding::for_recipient(&[6; 64], None);
    let mut envelope = PropagationEnvelope::new(msg, binding, 0.0, |p| Ok(p.to_vec())).unwrap();
    let initial = envelope.ciphertext().clone();
    let tid = envelope.transient_id();
    let policy = AdvertisedNodePolicy {
        stamp_cost: 0.0,
        transfer_limit_kb: 256.,
        recorded_at: 100.,
    };
    let mut ready = propagation_readiness([8; 16], true, true, Some(policy), true, 101.).unwrap();
    envelope.pack_for(ready, 101.).unwrap();
    ready.policy.stamp_cost = 4.0;
    envelope.pack_for(ready, 102.).unwrap();
    assert_eq!(envelope.ciphertext(), &initial);
    assert_eq!(envelope.transient_id(), tid);
    assert!(envelope.stamp_value() >= 4.0);
    assert_eq!(
        propagation_readiness([8; 16], true, true, None, true, 101.).unwrap_err(),
        MissingPropagationInput::NodePolicy
    );
    assert!(propagation_readiness([8; 16], true, true, Some(policy), true, 101.).is_ok());
}
#[test]
#[cfg(feature = "sqlite-store")]
fn tickets_and_delivered_claims_are_in_the_state_store_before_they_are_acted_on() {
    use lxmf_core::state_store::{FILE_NAME, SqliteStateStore, StateStore};
    let temp = tempfile::tempdir().unwrap();
    let mut router = lxmf_core::router::LxmRouter::new(Default::default());
    router.load_state(temp.path()).unwrap();
    let stale = router.state_snapshot();
    let mut draft =
        LxMessageDraft::new([1; 16], [2; 16], "", "ticket", DeliveryMethod::Direct).unwrap();
    draft.include_ticket = true;
    router.prepare_outbound(&mut draft).unwrap();
    // A second connection reads the committed ticket while the router still runs.
    let issued = SqliteStateStore::open(&temp.path().join(FILE_NAME))
        .unwrap()
        .get_inbound_tickets(&[1; 16])
        .unwrap()
        .expect("ticket committed before prepare_outbound returned");
    let msg = draft
        .sign(&Ed25519PrivateKey::from_bytes(&[3; 32]))
        .unwrap()
        .finalize(None)
        .unwrap();
    assert!(
        msg.fields()
            .get(lxmf_core::constants::FIELD_TICKET)
            .is_some()
    );
    // The delivered claim is in the file before the delivery callback runs.
    let db = temp.path().join(FILE_NAME);
    let claimed_first = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = claimed_first.clone();
    router.register_delivery_callback(move |delivered| {
        let claimed = SqliteStateStore::open(&db)
            .unwrap()
            .has_delivered(&delivered.message_id())
            .unwrap();
        seen.store(claimed, std::sync::atomic::Ordering::Relaxed);
    });
    assert!(router.deliver_inbound(&msg, false));
    assert!(claimed_first.load(std::sync::atomic::Ordering::Relaxed));
    // An older checkpoint written afterwards cannot take the ticket away.
    stale.save_state(temp.path()).unwrap();
    drop(router);
    let mut restarted = lxmf_core::router::LxmRouter::new(Default::default());
    restarted.load_state(temp.path()).unwrap();
    assert_eq!(restarted.get_inbound_tickets(&[1; 16]), Some(issued));
}

#[test]
fn suppression_hydration_rejects_duplicate_scopes_and_node_quota() {
    let mut ledger = SuppressionLedger::default();
    let row = ledger
        .record_failure(
            scope(1),
            SuppressionReason::InvalidSignature,
            AdmissionEpochs::default(),
            100,
        )
        .unwrap()
        .clone();
    assert!(SuppressionLedger::from_records([row.clone(), row.clone()]).is_err());
    let mut keys = row.epochs;
    keys.keys[0] = 1;
    assert!(!row.active(101, keys));
    let mut policy = row.epochs;
    policy.policy[0] = 1;
    assert!(!row.active(101, policy));
    let rows = (0..=SuppressionLedger::PER_NODE).map(|index| {
        let mut value = row.clone();
        value.scope.transient_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
        value
    });
    assert!(matches!(
        SuppressionLedger::from_records(rows),
        Err(AdmissionError::DispositionLedgerFull)
    ));
    assert_eq!(
        SuppressionLedger::from_records([row])
            .unwrap()
            .records()
            .count(),
        1
    );
}

#[test]
fn adapter_processing_memory_shares_peak_budget_without_second_worker() {
    let _exclusive = PROCESSING_BUDGET_TEST.lock().unwrap();
    let worker = ProcessingLease::try_acquire(1).unwrap();
    assert!(matches!(
        ProcessingMemoryLease::try_acquire(MAX_PROCESSING_BYTES),
        Err(SuppressionReason::WorkerUnavailable)
    ));
    let extra = ProcessingMemoryLease::try_acquire(8 * 1024 * 1024).unwrap();
    drop(extra);
    drop(worker);
    let all = ProcessingMemoryLease::try_acquire(MAX_PROCESSING_BYTES).unwrap();
    assert!(matches!(
        ProcessingLease::try_acquire(1),
        Err(SuppressionReason::WorkerUnavailable)
    ));
    drop(all);
    assert!(ProcessingLease::try_acquire(1).is_ok());
}

fn answer_node_path(
    receiver: &mut tokio::sync::mpsc::Receiver<rns_transport::messages::TransportMessage>,
) {
    use rns_transport::messages::{TransportMessage, TransportQuery, TransportQueryResponse};
    while let Ok(message) = receiver.try_recv() {
        if let TransportMessage::Rpc {
            query: TransportQuery::HasPath { .. },
            response_tx,
        } = message
        {
            response_tx
                .send(TransportQueryResponse::BoolResult(true))
                .unwrap();
        }
    }
}

fn reject_link_request(
    receiver: &mut tokio::sync::mpsc::Receiver<rns_transport::messages::TransportMessage>,
) {
    use rns_transport::messages::TransportMessage;
    while let Ok(message) = receiver.try_recv() {
        if let TransportMessage::SendLinkRequest { result_tx, .. } = message {
            result_tx
                .send(Err(
                    rns_transport::link_messages::LinkRequestDispatchError::Capacity(
                        rns_transport::InterfaceCapacityError::LinkCapacityUnavailable {
                            interface_id: 7,
                            clear_mtu: 499,
                            required: 500,
                        },
                    ),
                ))
                .unwrap();
            return;
        }
    }
    panic!("exact Link request dispatch channel was not staged");
}
#[test]
fn link_capacity_failure_reaches_all_three_initiators_before_establishment_timeout() {
    use lxmf_core::link_delivery::{DeliveryResult, LinkDeliveryManager};
    use lxmf_core::propagation_client::{PropagationClient, PropagationClientState};
    use lxmf_core::propagation_sync::{PeerSyncTerminalState, PropagationSyncTask};
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let mut delivery = LinkDeliveryManager::new(tx.clone(), None, None);
    delivery.start_delivery(message(None), [3; 16], 1).unwrap();
    reject_link_request(&mut rx);
    assert!(delivery.tick().iter().any(
        |result| matches!(result,DeliveryResult::Failed {reason,..} if reason.contains("499"))
    ));
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let mut client = PropagationClient::new(tx, None, None);
    client.set_propagation_node([3; 16]);
    assert!(client.start_download());
    answer_node_path(&mut rx);
    client.tick();
    reject_link_request(&mut rx);
    client.tick();
    assert_eq!(
        client.transfer_status().state,
        PropagationClientState::Failed
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let mut sync = PropagationSyncTask::new(tx, [8; 16]);
    assert!(sync.request_sync_now([3; 16]));
    answer_node_path(&mut rx);
    sync.tick();
    reject_link_request(&mut rx);
    sync.tick();
    assert_eq!(
        sync.take_terminal_peer_result().unwrap().state,
        PeerSyncTerminalState::Failed
    );
}
#[test]
fn canceled_download_closes_exact_request_admission_reply() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let mut client = lxmf_core::propagation_client::PropagationClient::new(tx, None, None);
    client.set_propagation_node([3; 16]);
    assert!(client.start_download());
    answer_node_path(&mut rx);
    client.tick();
    client.cancel_download();
    let mut found = false;
    while let Ok(message) = rx.try_recv() {
        if let rns_transport::messages::TransportMessage::SendLinkRequest { result_tx, .. } =
            message
        {
            assert!(result_tx.is_closed());
            found = true;
        }
    }
    assert!(found);
}
