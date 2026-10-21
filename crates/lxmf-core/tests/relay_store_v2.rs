use bytes::Bytes;
use lxmf_core::propagation_node::{
    PropagationAdmission, PropagationAdmissionOutcome, PropagationNode, PropagationNodeConfig,
    ValidatedOpaquePropagationBlob, read_planned_messages,
};
use rmpv::Value;
fn payload(destination: [u8; 16]) -> Bytes {
    let recipient = rns_identity::identity::Identity::new();
    let mut bytes = destination.to_vec();
    bytes.extend_from_slice(&recipient.encrypt(b"private test payload", None).unwrap());
    bytes.extend_from_slice(&[0; 32]);
    bytes.into()
}
fn validated(bytes: Bytes) -> ValidatedOpaquePropagationBlob {
    ValidatedOpaquePropagationBlob::validate(bytes, 0).unwrap()
}
fn request(wants: Option<Vec<[u8; 32]>>, haves: Option<Vec<[u8; 32]>>) -> Vec<u8> {
    let ids = |value: Option<Vec<[u8; 32]>>| {
        value
            .map(|v| Value::Array(v.into_iter().map(|id| Value::Binary(id.to_vec())).collect()))
            .unwrap_or(Value::Nil)
    };
    encode(&Value::Array(vec![ids(wants), ids(haves)]))
}
fn reserve(
    node: &mut PropagationNode,
    bytes: Bytes,
) -> lxmf_core::propagation_node::PropagationStoreWritePlan {
    match node.plan_opaque_admission(validated(bytes)) {
        PropagationAdmission::Reserved(plan) => *plan,
        other => panic!("expected new admission: {other:?}"),
    }
}
#[tokio::test]
async fn duplicate_waits_for_exact_commit_and_rechecks_retained_files() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("store");
    let mut node =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], old.clone())
            .unwrap();
    let bytes = payload([2; 16]);
    let tid = validated(bytes.clone()).transient_id();
    let plan = reserve(&mut node, bytes.clone());
    let PropagationAdmission::Pending(waiter) =
        node.plan_opaque_admission(validated(bytes.clone()))
    else {
        panic!("duplicate must coalesce")
    };
    let task = tokio::spawn(waiter.wait());
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    assert!(node.commit_store_write(plan.persist().unwrap()));
    assert_eq!(task.await.unwrap(), PropagationAdmissionOutcome::Committed);
    let PropagationAdmission::CommittedDuplicate(check) =
        node.plan_opaque_admission(validated(bytes.clone()))
    else {
        panic!("committed duplicate")
    };
    check.verify().unwrap();
    let path = node.plan_message_reads(&[tid]).pop().unwrap().path;
    std::fs::write(&path, b"corruption").unwrap();
    let PropagationAdmission::CommittedDuplicate(check) =
        node.plan_opaque_admission(validated(bytes))
    else {
        panic!("duplicate requires file check")
    };
    assert!(check.verify().is_err());
    drop(node);
    assert!(PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], old).is_err());
}
#[test]
fn restart_skips_body_rereads_and_never_serves_a_damaged_body() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let mut node =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], store.clone())
            .unwrap();
    let bytes = payload([2; 16]);
    let tid = validated(bytes.clone()).transient_id();
    let plan = reserve(&mut node, bytes);
    assert!(node.commit_store_write(plan.persist().unwrap()));
    let path = node.plan_message_reads(&[tid]).pop().unwrap().path;
    drop(node);
    let mut damaged = std::fs::read(&path).unwrap();
    *damaged.last_mut().unwrap() ^= 0xff;
    std::fs::write(&path, &damaged).unwrap();
    let reopened =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], store).unwrap();
    assert_eq!(reopened.message_count(), 1);
    assert!(read_planned_messages(&reopened.plan_message_reads(&[tid])).is_empty());
}
#[tokio::test]
async fn cancelled_reservation_releases_waiters_without_authority_and_can_retry() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = PropagationNode::with_storage(
        PropagationNodeConfig::default(),
        [1; 16],
        dir.path().join("store"),
    )
    .unwrap();
    let bytes = payload([2; 16]);
    let plan = reserve(&mut node, bytes.clone());
    let PropagationAdmission::Pending(waiter) =
        node.plan_opaque_admission(validated(bytes.clone()))
    else {
        panic!("duplicate must coalesce")
    };
    drop(plan);
    assert_eq!(waiter.wait().await, PropagationAdmissionOutcome::Failed);
    let retry = reserve(&mut node, bytes);
    assert!(node.commit_store_write(retry.persist().unwrap()));
}
#[tokio::test]
async fn lost_persisted_callback_reuses_first_image_and_restart_has_one_admission() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join("store");
    let mut node =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], legacy.clone())
            .unwrap();
    let bytes = payload([2; 16]);
    let tid = validated(bytes.clone()).transient_id();
    let plan = reserve(&mut node, bytes.clone());
    let PropagationAdmission::Pending(waiter) =
        node.plan_opaque_admission(validated(bytes.clone()))
    else {
        panic!("duplicate must coalesce")
    };
    drop(plan.persist().unwrap());
    assert_eq!(waiter.wait().await, PropagationAdmissionOutcome::Failed);
    let objects = legacy.with_extension("v2").join("objects");
    let first_files: std::collections::BTreeSet<_> = std::fs::read_dir(&objects)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(first_files.len(), 3);
    let plan = reserve(&mut node, bytes.clone());
    assert!(node.commit_store_write(plan.persist().unwrap()));
    let retry_files: std::collections::BTreeSet<_> = std::fs::read_dir(&objects)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(retry_files, first_files);
    drop(node);
    let reopened =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], legacy).unwrap();
    assert_eq!(reopened.message_count(), 1);
    assert_eq!(
        std::fs::read(&reopened.plan_message_reads(&[tid])[0].path).unwrap(),
        bytes
    );
}
#[test]
fn purge_cannot_report_success_when_its_durable_intent_cannot_be_published() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join("store");
    let mut node =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], legacy.clone())
            .unwrap();
    let destination = [2; 16];
    let bytes = payload(destination);
    let tid = validated(bytes.clone()).transient_id();
    let plan = reserve(&mut node, bytes.clone());
    assert!(node.commit_store_write(plan.persist().unwrap()));
    let objects = legacy.with_extension("v2").join("objects");
    let unavailable = legacy.with_extension("v2").join("temporarily-unavailable");
    std::fs::rename(&objects, &unavailable).unwrap();
    assert_eq!(
        node.handle_get_request(&request(None, Some(vec![tid])), &destination)
            .into_response(),
        encode(&Value::Nil)
    );
    assert!(node.contains(&tid));
    std::fs::rename(&unavailable, &objects).unwrap();
    assert_eq!(
        node.handle_get_request(&request(None, Some(vec![tid])), &destination)
            .into_response(),
        encode(&Value::Array(vec![]))
    );
    drop(node);
    let reopened =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], legacy).unwrap();
    assert!(!reopened.contains(&tid));
}
#[test]
fn purge_is_durable_before_success_and_old_plan_cannot_delete_readmission() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("store");
    let destination = [2; 16];
    let mut node =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], old.clone())
            .unwrap();
    let bytes = payload(destination);
    let tid = validated(bytes.clone()).transient_id();
    let plan = reserve(&mut node, bytes.clone());
    assert!(node.commit_store_write(plan.persist().unwrap()));
    let old_path = node.plan_message_reads(&[tid]).pop().unwrap().path;
    let stale = node.handle_get_request(&request(None, Some(vec![tid])), &destination);
    let purge = node.handle_get_request(&request(None, Some(vec![tid])), &destination);
    assert_eq!(purge.into_response(), encode(&Value::Array(vec![])));
    assert!(!node.contains(&tid));
    assert!(!old_path.exists());
    let replacement = reserve(&mut node, bytes.clone());
    assert!(node.commit_store_write(replacement.persist().unwrap()));
    let new_path = node.plan_message_reads(&[tid]).pop().unwrap().path;
    assert_ne!(old_path, new_path);
    // The old plan fails or sees an already completed retirement; it cannot
    // gain authority over the distinct new admission path.
    let _ = stale.into_response();
    assert!(node.contains(&tid));
    assert_eq!(std::fs::read(&new_path).unwrap(), bytes);
    drop(node);
    let reopened =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], old).unwrap();
    assert!(reopened.contains(&tid));
}
#[test]
fn foreign_purge_has_no_effect_and_maintenance_publishes_retirement_off_lock() {
    let dir = tempfile::tempdir().unwrap();
    let config = PropagationNodeConfig {
        max_storage: 0,
        ..Default::default()
    };
    let mut node =
        PropagationNode::with_storage(config, [1; 16], dir.path().join("store")).unwrap();
    let bytes = payload([2; 16]);
    let tid = validated(bytes.clone()).transient_id();
    let plan = reserve(&mut node, bytes);
    assert!(node.commit_store_write(plan.persist().unwrap()));
    node.handle_get_request(&request(None, Some(vec![tid])), &[3; 16])
        .into_response();
    assert!(node.contains(&tid));
    let maintenance = node.plan_maintenance();
    assert!(!maintenance.is_empty());
    assert!(node.contains(&tid));
    maintenance.persist().unwrap();
    assert!(!node.contains(&tid));
    assert!(node.create_offer([4; 16], None).is_empty());
}
#[test]
fn legacy_trees_and_second_live_host_cannot_be_opened_implicitly() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("legacy");
    std::fs::create_dir(&old).unwrap();
    std::fs::write(old.join("private"), b"plaintext").unwrap();
    assert!(
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], old.clone())
            .is_err()
    );
    assert_eq!(std::fs::read(old.join("private")).unwrap(), b"plaintext");
    let fresh = dir.path().join("fresh");
    let node =
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], fresh.clone())
            .unwrap();
    assert!(
        PropagationNode::with_storage(PropagationNodeConfig::default(), [1; 16], fresh).is_err()
    );
    drop(node);
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).unwrap();
    out
}
