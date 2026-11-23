use gauntlet_contracts::{FeatureExecutorSpec, FEATURE_CATALOG_SHA256, FEATURE_NODE_SHA256};
use serde_json::{json, Value};

fn body() -> Value {
    json!({"schema":"hol-gauntlet-feature-executor.v1","audit_id":"a".repeat(16),"source_sha":"b".repeat(40),
        "source_archive_sha256":"c".repeat(64),"candidate_archive_sha256":"d".repeat(64),
        "wheel_sha256":"e".repeat(64),"native_sha256":"f".repeat(64),"version":"3.58.0",
        "node_sha256":FEATURE_NODE_SHA256,"catalog_sha256":FEATURE_CATALOG_SHA256,"executor_sha256":"1".repeat(64)})
}

#[test]
fn declaration_roundtrips_but_never_accepts_test_command_or_profile_selectors() {
    let value = body();
    let spec = FeatureExecutorSpec::parse(value.to_string().as_bytes()).unwrap();
    assert_eq!(spec.to_json(), value);
    assert_eq!(
        FeatureExecutorSpec::parse(spec.canonical_bytes())
            .unwrap()
            .digest(),
        spec.digest()
    );
    for key in [
        "command",
        "tests",
        "groups",
        "profile",
        "model",
        "controller_root",
    ] {
        let mut changed = value.clone();
        changed[key] = json!("caller selector");
        assert!(
            FeatureExecutorSpec::parse(changed.to_string().as_bytes()).is_err(),
            "{key}"
        );
    }
}

#[test]
fn changed_catalog_node_identity_and_wrong_field_types_refuse() {
    let value = body();
    for (key, bad) in [
        ("schema", json!("hol-gauntlet-feature-executor.v2")),
        ("audit_id", json!("../other")),
        ("source_sha", json!("b".repeat(39))),
        ("node_sha256", json!("0".repeat(64))),
        ("catalog_sha256", json!("0".repeat(64))),
        ("version", json!("3.58.0 --selector")),
        ("executor_sha256", json!(true)),
    ] {
        let mut changed = value.clone();
        changed[key] = bad;
        assert!(
            FeatureExecutorSpec::parse(changed.to_string().as_bytes()).is_err(),
            "{key}"
        );
    }
    let duplicate = value
        .to_string()
        .replacen('{', "{\"audit_id\":\"other\",", 1);
    assert!(FeatureExecutorSpec::parse(duplicate.as_bytes()).is_err());
}
