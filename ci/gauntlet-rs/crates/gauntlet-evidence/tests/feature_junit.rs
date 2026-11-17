use gauntlet_evidence::{verify_feature_junit_v2, MAX_FEATURE_JUNIT_BYTES};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn python_frozen_reports_match_or_explicitly_refuse_under_the_v2_contract() {
    let raw = include_bytes!("fixtures/python_feature_junit_v1.json");
    assert_eq!(
        format!("{:x}", Sha256::digest(raw)),
        "bc9072deb392ae37b473a095f6e4416f69eaa01c55f2cb0f4ff9a3957f0b7938"
    );
    let oracle: Value = serde_json::from_slice(raw).unwrap();
    let rows = oracle["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 16);
    for row in rows {
        let result = verify_feature_junit_v2(row["xml"].as_str().unwrap().as_bytes());
        if row["rust_v2_refuses"] == true {
            assert!(result.is_err(), "{}", row["case"]);
        } else {
            let actual = result.unwrap();
            assert_eq!(actual.to_json(), row["python"]["counts"], "{}", row["case"]);
            assert_eq!(
                actual.status(row["exit_code"].as_i64().unwrap() as i32),
                row["python"]["status"]
            );
        }
    }
}

#[test]
fn byte_node_depth_encoding_and_entity_limits_are_enforced() {
    assert!(verify_feature_junit_v2(&vec![b' '; MAX_FEATURE_JUNIT_BYTES + 1]).is_err());
    assert!(verify_feature_junit_v2(b"\xff").is_err());
    let deep = format!(
        "<testsuite tests=\"0\"><properties>{}x{}</properties></testsuite>",
        "<property>".repeat(65),
        "</property>".repeat(65)
    );
    assert!(verify_feature_junit_v2(deep.as_bytes()).is_err());
    let many = format!(
        "<testsuite tests=\"200000\" failures=\"0\" errors=\"0\" skipped=\"0\">{}</testsuite>",
        "<testcase/>".repeat(200_000)
    );
    assert!(many.len() < MAX_FEATURE_JUNIT_BYTES);
    assert!(verify_feature_junit_v2(many.as_bytes()).is_err());
    let entity = br#"<!DOCTYPE testsuite [<!ENTITY x "not expanded">]><testsuite tests="1"><testcase><system-out>&x;</system-out></testcase></testsuite>"#;
    assert!(verify_feature_junit_v2(entity).is_err());
}

#[test]
fn optional_aggregate_counts_must_agree_and_a_nonzero_exit_never_passes() {
    let xml = br#"<testsuites tests="1" failures="0" errors="0" skipped="0"><testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="actual"/></testsuite></testsuites>"#;
    let counts = verify_feature_junit_v2(xml).unwrap();
    assert_eq!(counts.status(0), "passed");
    assert_eq!(counts.status(124), "failed");
    assert_eq!(counts.status(-9), "failed");
    let changed = std::str::from_utf8(xml)
        .unwrap()
        .replacen("tests=\"1\"", "tests=\"2\"", 1);
    assert!(verify_feature_junit_v2(changed.as_bytes()).is_err());
}
