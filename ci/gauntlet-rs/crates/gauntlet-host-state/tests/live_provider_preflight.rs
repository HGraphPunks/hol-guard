use gauntlet_host_state::evaluate_live_provider_preflight;
use serde_json::{json, Value};

#[test]
fn live_provider_admission_matches_exact_python_branch() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_live_provider_preflight_v1.json")).unwrap();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = baseline["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"] == "ci/gauntlet/control_plane/live_provider.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(
        fixture["branch_ast_sha256"],
        "d2c6f3e6297796727b4ba6aa3389965fc3dbe34093c6b95f441a72c65fdafbb9"
    );
    assert_eq!(
        fixture["schema"],
        "hol-gauntlet-python-live-provider-preflight-fixtures.v1"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 21);
    for case in cases {
        let actual = evaluate_live_provider_preflight(&case["input"]);
        if case["expected"]["accepted"] == true {
            assert_eq!(
                actual.unwrap(),
                json!({
                    "reservation":case["expected"]["reservation"],
                    "known_tokens_before":case["expected"]["known_tokens_before"],
                }),
                "{}",
                case["name"]
            );
        } else {
            assert_eq!(
                actual.unwrap_err().to_string(),
                case["expected"]["reason"],
                "{}",
                case["name"]
            );
        }
    }
}

#[test]
fn malformed_external_snapshot_cannot_admit_a_provider() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_live_provider_preflight_v1.json")).unwrap();
    let mut input = fixture["cases"][0]["input"].clone();
    input["quota"]["known_tokens"] = json!(true);
    assert!(evaluate_live_provider_preflight(&input).is_err());
    input["quota"]["known_tokens"] = json!(13_746_906);
    input["port_busy"] = json!("false");
    assert!(evaluate_live_provider_preflight(&input).is_err());
    input["port_busy"] = json!(false);
    input["requested_candidate_source_sha"] = json!("b".repeat(40));
    assert!(evaluate_live_provider_preflight(&input).is_err());
}
