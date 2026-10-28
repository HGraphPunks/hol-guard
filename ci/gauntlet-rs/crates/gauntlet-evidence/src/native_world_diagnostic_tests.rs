use super::*;
use crate::crypto::sha256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rusqlite::Connection;

fn fixture(change: impl FnOnce(&Connection)) -> (Value, Vec<Value>, BTreeMap<String, Vec<u8>>) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let public = B64.encode(key.public_key().as_ref());
    let acl = json!({"read":["fixture-actor"],"write":["fixture-actor"]});
    let seed = json!({"schema":"gauntlet-workflow-snapshot.v1","actor_id":"fixture-actor",
        "provider_scope":{"tenants":["task-tenant"]},"records":[
        {"id":"developer-spec","collection":"docs.documents","owner_id":"fixture-actor",
        "tenant_id":"task-tenant","version":1,"acl":acl,"data":{"body":"fixed document","title":"input"}},
        {"id":"message","collection":"mail.messages","owner_id":"fixture-actor",
        "tenant_id":"task-tenant","version":1,"acl":acl,"data":{"body":"no delivery","subject":"input"}}]});
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("synthetic-world.db");
    let mut world =
        gauntlet_world::World::initialize(Connection::open(&path).unwrap(), &seed.to_string(), key)
            .unwrap();
    let initial = world.snapshot().unwrap();
    world
        .call(
            "docs.read",
            "{\"record_id\":\"developer-spec\"}",
            json!("actual-call-id"),
        )
        .unwrap();
    let receipts = world.receipts().unwrap();
    let final_value = world.snapshot().unwrap();
    drop(world);
    let db = Connection::open(&path).unwrap();
    change(&db);
    drop(db);
    let database = std::fs::read(&path).unwrap();
    let events = json!({"schema":"hol-gauntlet-cell-event.v1","sequence":0,
        "previous_sha256":"0".repeat(64),"kind":"unit-fixture","data":{}});
    let mut journal = canonical_value(&events).unwrap();
    journal.push(b'\n');
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        ("combined/mcp-world.db".into(), database),
        (
            "combined/cell/native-supervisor-events.v1.jsonl".into(),
            journal,
        ),
    ]);
    let mut pins = serde_json::Map::new();
    for (name, raw) in &files {
        pins.insert(
            name.clone(),
            json!({"bytes":raw.len(),"sha256":sha256(raw)}),
        );
    }
    let index = json!({"files":pins,"filesystem":{"combined/mcp-world.db":
        {"uid":0,"gid":0,"mode":0o600,"device":1,"inode":2,"links":1}},
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    files.insert(
        "results.sha256.json".into(),
        canonical_value(&index).unwrap(),
    );
    let mcp = json!({"world":{"schema":"hol-gauntlet-native-mcp-world.v1","database":"mcp-world.db",
        "uid":0,"gid":0,"mode":0o600,"device":1,"inode":2,"public_key":public,
        "agent_mounts_verified":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0},
        "initial":initial,"final":final_value,"receipts":receipts,
        "sockets":{"socket_namespace_retired":true,"accepted_streams_drained":false,"peer_authenticated":false},
        "outside_signing_key_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    let calls = vec![
        json!({"jsonrpc":"2.0","method":"tools/call","id":"actual-call-id",
        "params":{"name":"docs.read","arguments":{"record_id":"developer-spec"}}}),
    ];
    (mcp, calls, files)
}

#[test]
fn actual_world_producer_signed_read_and_database_reconcile_without_admission() {
    let (mcp, calls, files) = fixture(|_| {});
    let result = verify_native_world_diagnostic(&mcp, &files, &calls).unwrap();
    assert_eq!(result["signed_read_receipts_checked"], 1);
    assert_eq!(result["physical_database"]["physical_records_checked"], 2);
    assert_eq!(result["outside_signing_key_admitted"], false);
}

#[test]
fn substituted_call_record_id_signature_key_and_inode_refuse() {
    let (mcp, calls, files) = fixture(|_| {});
    for selector in 0..5 {
        let mut mcp = mcp.clone();
        let mut calls = calls.clone();
        match selector {
            0 => calls[0]["id"] = "foreign-call".into(),
            1 => calls[0]["params"]["arguments"]["record_id"] = "message".into(),
            2 => mcp["receipts"][0]["signature"] = B64.encode([0; 64]).into(),
            3 => mcp["world"]["public_key"] = B64.encode([0; 32]).into(),
            _ => mcp["world"]["inode"] = json!(3),
        }
        assert!(
            verify_native_world_diagnostic(&mcp, &files, &calls).is_err(),
            "{selector}"
        );
    }
}

#[test]
fn physical_database_mutation_refuses_with_fresh_index_and_valid_receipts() {
    for sql in [
        "UPDATE records SET value='{}' WHERE id='developer-spec'",
        "UPDATE meta SET value='{}'",
        "UPDATE journal SET value='{}'",
        "INSERT INTO cached VALUES('replay','digest','{}')",
    ] {
        let (mcp, calls, files) = fixture(|db| {
            db.execute_batch(sql).unwrap();
        });
        assert!(
            verify_native_world_diagnostic(&mcp, &files, &calls).is_err(),
            "{sql}"
        );
    }
}

#[test]
fn false_authority_and_cleanup_claims_refuse() {
    let (mcp, calls, files) = fixture(|_| {});
    for field in [
        "outside_signing_key_admitted",
        "execution_eligible",
        "guard_causality_verified",
    ] {
        let mut changed = mcp.clone();
        changed[field] = true.into();
        assert!(verify_native_world_diagnostic(&changed, &files, &calls).is_err());
    }
    let mut changed = mcp.clone();
    changed["sockets"]["socket_namespace_retired"] = false.into();
    assert!(verify_native_world_diagnostic(&changed, &files, &calls).is_err());
}
