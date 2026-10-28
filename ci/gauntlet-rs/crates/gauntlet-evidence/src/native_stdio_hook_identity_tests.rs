use super::*;

fn vectors() -> Vec<Value> {
    let raw = include_bytes!("../tests/fixtures/native_stdio_hook_vectors.v1.json");
    assert_eq!(
        sha256(raw),
        "ba19d19e0300b52d66f79dff5f972d08a5fe7630bb969ada95b5b10ab14f59cc"
    );
    let fixture: Value = serde_json::from_slice(raw).unwrap();
    assert_eq!(
        fixture["product_source"],
        "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
    );
    assert_eq!(
        fixture["public_archive_sha256"],
        "24e4ab9b915d32c5d599553a1b38a460d8355e64109d5defb5a0bc07c35e9376"
    );
    fixture["vectors"].as_array().unwrap().clone()
}

#[test]
fn five_actual_copied_edges_match_independently_derived_request_intent_and_decision() {
    let cases = vectors();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let result = verify(&case["request"], &case["response"]).unwrap();
        assert_eq!(
            result["request_digest"],
            case["response"]["receipt"]["request_digest"]
        );
        assert_eq!(result["copied_request_and_receipt_identity_checked"], true);
        assert_eq!(result["policy_evaluation_recomputed"], false);
        assert_eq!(result["product_claims_authenticated"], false);
    }
}

#[test]
fn altered_nested_action_context_policy_event_and_transport_identity_refuse() {
    let case = &vectors()[1];
    for (pointer, value) in [
        (
            "/raw_payload/tool_input/command",
            json!("different command"),
        ),
        (
            "/source/execution_environment/environment_digest",
            json!("0".repeat(64)),
        ),
        ("/policy_snapshot/policy_digest", json!("0".repeat(64))),
        ("/policy_generation", json!(1)),
        ("/schema", json!("guard-hook-envelope.v3")),
        ("/raw_payload/hook_event_name", json!("PostToolUse")),
        ("/request_id", json!("different-request")),
    ] {
        let mut changed = case["request"].clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(verify(&changed, &case["response"]).is_err(), "{pointer}");
    }
}

#[test]
fn swapped_or_self_inconsistent_receipts_do_not_supply_correlation() {
    let cases = vectors();
    assert!(verify(&cases[0]["request"], &cases[1]["response"]).is_err());
    let case = &cases[1];
    for (pointer, value) in [
        ("/receipt/request_digest", json!("0".repeat(64))),
        ("/receipt/execution_intent_digest", json!("0".repeat(64))),
        ("/receipt/decision_id", json!("0".repeat(64))),
        ("/receipt/policy_generation", json!(0)),
        ("/result/decision", json!("allow")),
        ("/authority", json!("other")),
    ] {
        let mut changed = case["response"].clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(verify(&case["request"], &changed).is_err(), "{pointer}");
    }
}

#[test]
fn root_transport_metadata_is_excluded_while_nested_arguments_remain_bound() {
    let case = &vectors()[1];
    let mut changed = case["request"].clone();
    changed["raw_payload"]["tool_call_id"] = json!("another-attempt");
    changed["raw_payload"]["timestamp"] = json!("later");
    verify(&changed, &case["response"]).unwrap();
    changed["raw_payload"]["tool_input"]["timestamp"] = json!("actual argument");
    assert!(verify(&changed, &case["response"]).is_err());
}

#[test]
fn unsupported_identity_dialects_remain_unverified() {
    let case = &vectors()[1];
    for (key, value) in [
        ("recording_only", json!(true)),
        ("unknown_selector", json!(true)),
    ] {
        let mut changed = case["request"].clone();
        changed[key] = value;
        assert!(verify(&changed, &case["response"]).is_err());
    }
    let mut changed = case["request"].clone();
    changed["raw_payload"]["tool_input"]["numeric_argument"] = json!(1.5);
    assert!(verify(&changed, &case["response"]).is_err());
}

#[test]
fn native_typed_context_omits_empty_maps_and_inserts_declared_defaults() {
    let case = &vectors()[1];
    let mut changed = case["request"].clone();
    let context = changed["source"]["execution_environment"]
        .as_object_mut()
        .unwrap();
    for key in [
        "git_pager_disabled",
        "pager_disabled",
        "git_config_no_system",
    ] {
        assert_eq!(context.remove(key), Some(json!(false)));
    }
    assert_eq!(context.remove("xdg_config_home"), Some(Value::Null));
    assert_eq!(context.remove("library_search_paths"), Some(json!({})));
    verify(&changed, &case["response"]).unwrap();
    changed["source"]["execution_environment"]["library_search_paths"] =
        json!({"LD_LIBRARY_PATH":"/different"});
    assert!(verify(&changed, &case["response"]).is_err());
}
