use super::*;

fn vectors() -> Vec<Value> {
    let fixture: Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/native_stdio_hook_vectors.v1.json"
    ))
    .unwrap();
    fixture["vectors"].as_array().unwrap().clone()
}

#[test]
fn actual_outer_inputs_preserve_caller_context_and_distinguish_reauthorization() {
    let cases = vectors();
    for case in cases {
        let reauthorization = case["contained_reauthorization"].as_bool().unwrap();
        let supplied =
            payload_relation(&case["request"], &case["outer_input"], reauthorization).unwrap();
        assert_eq!(
            supplied,
            !reauthorization
                && case["outer_input"]
                    .get("guard_execution_environment")
                    .is_some()
        );
        if reauthorization {
            assert!(payload_relation(&case["request"], &case["outer_input"], false).is_err());
        }
    }
}

#[test]
fn changed_outer_command_context_and_receipt_only_flag_refuse() {
    let cases = vectors();
    let case = &cases[1];
    let mut changed = case["outer_input"].clone();
    changed["tool_input"]["command"] = json!("other command");
    assert!(payload_relation(&case["request"], &changed, false).is_err());
    let mut changed = case["outer_input"].clone();
    changed["guard_execution_environment"]["path"] = json!("/other/bin");
    assert!(payload_relation(&case["request"], &changed, false).is_err());
    let case = &cases[2];
    let mut changed = case["request"].clone();
    changed["raw_payload"]["guard_containment_receipt_only"] = json!(false);
    assert!(payload_relation(&changed, &case["outer_input"], true).is_err());
    assert!(payload_relation(&cases[0]["request"], &cases[0]["outer_input"], true).is_err());
}
