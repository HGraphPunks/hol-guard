use base64::{engine::general_purpose::STANDARD as B64, Engine};
use gauntlet_world::{verify_receipts, World};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn fixture() -> Value {
    serde_json::from_str(include_str!("python_world_20261027.json")).unwrap()
}
fn key() -> Ed25519KeyPair {
    let seed = B64
        .decode(fixture()["public_test_seed_base64"].as_str().unwrap())
        .unwrap();
    Ed25519KeyPair::from_seed_unchecked(&seed).unwrap()
}
fn fresh(connection: Connection) -> World {
    World::initialize(
        connection,
        fixture()["initial_snapshot_json"].as_str().unwrap(),
        key(),
    )
    .unwrap()
}
fn anchor(receipts: &[Value]) -> String {
    receipts
        .last()
        .map(|value| {
            format!(
                "{:x}",
                Sha256::digest(
                    gauntlet_contracts::canonicalize(value.to_string().as_bytes()).unwrap()
                )
            )
        })
        .unwrap_or_else(|| "0".repeat(64))
}

#[test]
fn committed_state_idempotency_and_signatures_survive_a_real_database_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("world.db");
    let mut first = fresh(Connection::open(&path).unwrap());
    let args = r#"{"record_id":"docs-0","expected_version":1,"data":{"later":true},"idempotency_key":"update-once"}"#;
    let result = first.call("docs.update", args, json!("first")).unwrap();
    let snapshot = first.snapshot().unwrap();
    let receipts = first.receipts().unwrap();
    drop(first);
    let mut reopened = World::open(Connection::open(&path).unwrap(), key()).unwrap();
    assert_eq!(reopened.snapshot().unwrap(), snapshot);
    assert_eq!(
        reopened
            .call("docs.update", args, json!("replayed-request-id"))
            .unwrap(),
        result
    );
    assert_eq!(reopened.receipts().unwrap(), receipts);
    verify_receipts(
        &receipts,
        key().public_key().as_ref(),
        1,
        &anchor(&receipts),
    )
    .unwrap();
    let wrong = Ed25519KeyPair::from_seed_unchecked(&[99; 32]).unwrap();
    assert!(World::open(Connection::open(&path).unwrap(), wrong).is_err());
    assert!(World::initialize(
        Connection::open(&path).unwrap(),
        fixture()["initial_snapshot_json"].as_str().unwrap(),
        key()
    )
    .is_err());
    assert_eq!(reopened.snapshot().unwrap(), snapshot);
}

#[test]
fn failed_receipt_commit_rolls_back_record_and_idempotency_mutations() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("world.db");
    let mut world = fresh(Connection::open(&path).unwrap());
    let before = world.snapshot().unwrap();
    let database = Connection::open(&path).unwrap();
    database.execute_batch("CREATE TRIGGER fixture_fail_receipt BEFORE INSERT ON journal BEGIN SELECT RAISE(ABORT,'fixture receipt write failure'); END;").unwrap();
    let args = r#"{"record_id":"docs-0","expected_version":1,"data":{"must_not_commit":true},"idempotency_key":"not-cached"}"#;
    let error = world.call("docs.update", args, json!(1)).err().unwrap();
    assert!(error.to_string().contains("fixture receipt write failure"));
    assert_eq!(world.snapshot().unwrap(), before);
    assert!(world.receipts().unwrap().is_empty());
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM cached", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    database
        .execute_batch("DROP TRIGGER fixture_fail_receipt;")
        .unwrap();
    world.call("docs.update", args, json!(2)).unwrap();
    assert_eq!(world.receipts().unwrap().len(), 1);
}

#[test]
fn external_anchors_refuse_tampering_wrong_keys_truncation_and_reordering() {
    let fixture = fixture();
    let receipts = fixture["receipts"].as_array().unwrap();
    let final_hash = anchor(receipts);
    let public = key();
    verify_receipts(
        receipts,
        public.public_key().as_ref(),
        receipts.len(),
        &final_hash,
    )
    .unwrap();
    assert!(verify_receipts(
        &receipts[..receipts.len() - 1],
        public.public_key().as_ref(),
        receipts.len(),
        &final_hash
    )
    .is_err());
    assert!(verify_receipts(receipts, &[7; 32], receipts.len(), &final_hash).is_err());
    assert!(verify_receipts(
        receipts,
        public.public_key().as_ref(),
        receipts.len(),
        &"0".repeat(64)
    )
    .is_err());
    let mut tampered = receipts.clone();
    tampered[0]["event"]["result_digest"] = json!("0".repeat(64));
    assert!(verify_receipts(
        &tampered,
        public.public_key().as_ref(),
        receipts.len(),
        &final_hash
    )
    .is_err());
    let mut reordered = receipts.clone();
    reordered.swap(0, 1);
    assert!(verify_receipts(
        &reordered,
        public.public_key().as_ref(),
        receipts.len(),
        &final_hash
    )
    .is_err());
}

#[test]
fn arguments_are_strict_original_json_and_dont_silently_gain_defaults() {
    let mut world = fresh(Connection::open_in_memory().unwrap());
    for args in [
        r#"{"record_id":"docs-0","record_id":"mail-0"}"#,
        r#"{"record_id":"docs-0","data":NaN}"#,
        r#"[]"#,
    ] {
        assert!(world.call("docs.read", args, json!("invalid")).is_err());
    }
    assert!(world.receipts().unwrap().is_empty());
    world
        .call("docs.read", r#"{"record_id":"docs-0"}"#, json!("read"))
        .unwrap();
    let receipts = world.receipts().unwrap();
    let raw = gauntlet_contracts::canonical_sha256(br#"{"record_id":"docs-0"}"#).unwrap();
    assert_eq!(receipts[0]["event"]["raw_args_digest"], raw);
}

#[test]
fn version_checks_do_not_round_large_integers_through_floating_point() {
    let mut snapshot: Value =
        serde_json::from_str(fixture()["initial_snapshot_json"].as_str().unwrap()).unwrap();
    let record = snapshot["records"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["id"] == "docs-0")
        .unwrap();
    record["version"] = json!(9007199254740993_i64);
    let mut world = World::initialize(
        Connection::open_in_memory().unwrap(),
        &snapshot.to_string(),
        key(),
    )
    .unwrap();
    assert!(world
        .call(
            "docs.update",
            r#"{"record_id":"docs-0","expected_version":9007199254740992.0,"data":{}}"#,
            json!(1)
        )
        .is_err());
    assert!(world.receipts().unwrap().is_empty());
    world
        .call(
            "docs.update",
            r#"{"record_id":"docs-0","expected_version":9007199254740993,"data":{}}"#,
            json!(2),
        )
        .unwrap();
    assert_eq!(
        world.inspect("docs-0").unwrap().unwrap()["version"],
        9007199254740994_i64
    );
}
