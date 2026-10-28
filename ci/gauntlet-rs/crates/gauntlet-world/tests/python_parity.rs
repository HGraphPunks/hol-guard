use base64::{engine::general_purpose::STANDARD as B64, Engine};
use gauntlet_world::World;
use ring::signature::Ed25519KeyPair;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn digest(value: &Value) -> String {
    let bytes = gauntlet_contracts::canonicalize(value.to_string().as_bytes()).unwrap();
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn python_frozen_transactions_receipts_search_order_acl_and_idempotency() {
    let fixture: Value = serde_json::from_str(include_str!("python_world_20261027.json")).unwrap();
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(include_bytes!("../../../../gauntlet/benchmark/world.py"))
        ),
        fixture["source_sha256"]["ci/gauntlet/benchmark/world.py"]
    );
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(include_bytes!(
                "../../../../gauntlet/benchmark/json_data.py"
            ))
        ),
        fixture["source_sha256"]["ci/gauntlet/benchmark/json_data.py"]
    );
    let seed = B64
        .decode(fixture["public_test_seed_base64"].as_str().unwrap())
        .unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let mut world = World::initialize(
        Connection::open_in_memory().unwrap(),
        fixture["initial_snapshot_json"].as_str().unwrap(),
        key,
    )
    .unwrap();
    assert_eq!(world.public_key(), fixture["public_key"]);
    for case in fixture["cases"].as_array().unwrap() {
        let result = world.call(
            case["operation"].as_str().unwrap(),
            case["arguments_json"].as_str().unwrap(),
            case["request_id"].clone(),
        );
        if let Some(expected) = case.get("error") {
            let error = result
                .err()
                .unwrap_or_else(|| panic!("expected refusal: {case}"));
            assert_eq!(error.category(), expected["category"], "{case}");
            assert_eq!(error.to_string(), expected["message"], "{case}");
        } else {
            assert_eq!(
                result.unwrap_or_else(|e| panic!("{e}: {case}")),
                case["result"],
                "{case}"
            );
        }
        assert_eq!(
            digest(&world.snapshot().unwrap()),
            case["snapshot_digest"],
            "{case}"
        );
        let receipts = world.receipts().unwrap();
        assert_eq!(
            receipts.len() as u64,
            case["receipt_count"].as_u64().unwrap(),
            "{case}"
        );
        assert_eq!(
            digest(&Value::Array(receipts)),
            case["receipts_digest"],
            "{case}"
        );
    }
    assert_eq!(world.snapshot().unwrap(), fixture["final_snapshot"]);
    assert_eq!(Value::Array(world.receipts().unwrap()), fixture["receipts"]);
}
