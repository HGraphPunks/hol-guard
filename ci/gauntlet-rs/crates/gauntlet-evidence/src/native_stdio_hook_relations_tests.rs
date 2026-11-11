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

#[test]
fn owned_pipe_outer_gate_requires_the_exact_adapter_and_preserves_original_guard_argv() {
    let plane = json!({"schema":"hol-gauntlet-native-hook-plane.v4",
        "native_launch_adapter_sha256":crate::crypto::sha256(crate::native_diagnostic_artifacts::PIPE_LAUNCH.as_bytes())});
    let original = crate::native_diagnostic_artifacts::guard_argv(
        "/opt/hol-gauntlet/candidates/pinned/prefix",
        &["hook", "--json"],
    );
    let wire =
        crate::native_diagnostic_artifacts::transport_argv(&plane, original.clone()).unwrap();
    let mut gate = vec![
        "/public/gauntlet-product-cell".to_owned(),
        "exec-gate".to_owned(),
    ];
    gate.extend(wire);
    let row = json!({"data":{"identity":{"argv":gate}}});
    assert_eq!(&outer_command(&plane, &row).unwrap()[2..], original);
    for index in [0, 1, 5, 6, 7] {
        let mut changed = row.clone();
        changed["data"]["identity"]["argv"][index] = json!("substituted");
        assert!(outer_command(&plane, &changed).is_err(), "{index}");
    }
}

#[test]
fn pipe_stream_retains_exact_raw_frames_and_measured_exec_identity_for_the_join() {
    let image = crate::native_process_events::tests::image_value(42, 42, 7);
    let row = json!({"kind":"task-exec","data":{"id":3,"image":image}});
    let stream = pipe_stream(4, 9, &row, [b"request".to_vec(), b"response".to_vec()]).unwrap();
    assert_eq!(stream.stream, 4);
    assert_eq!(stream.identity["task_id"], 3);
    assert_eq!(stream.identity["process_exec_sequence"], 9);
    assert_eq!(stream.identity["tid"], 42);
    assert_eq!(stream.read, b"request");
    assert_eq!(stream.written, b"response");
    let mut wrong = row;
    wrong["kind"] = json!("task-created");
    assert!(pipe_stream(4, 9, &wrong, [vec![], vec![]]).is_err());
}

#[test]
fn resolved_readonly_reauthorization_requires_the_exact_measured_interpreter_transition() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let expected = json!({"hook_event_name":"PreToolUse",
        "tool_input":{"command":"python3 -m unittest discover -s tests -v"}});
    let native = json!({"task_id":3,"gate_sequence":7,
        "operation":"restricted-linux-launch","trace_sequence":2});
    let pin = "a".repeat(64);
    let row = json!({"kind":"task-exec","data":{"id":3,"image":{
        "executable":{"sha256":pin},"argv_base64":STANDARD.encode(
            b"/usr/bin/python3.12\0-m\0unittest\0discover\0-s\0tests\0-v\0")}}});
    let events = vec![Value::Null, Value::Null, Value::Null, row];
    let images = vec![native];
    let resolved = resolved_readonly_payload(&expected, &events, &images, 7, 1, &pin).unwrap();
    assert_eq!(
        resolved["tool_input"]["command"],
        "/usr/bin/python3.12 -m unittest discover -s tests -v"
    );
    for (pointer, value) in [
        ("/task_id", json!(4)),
        ("/gate_sequence", json!(8)),
        ("/trace_sequence", json!(0)),
        ("/trace_sequence", json!(3)),
        ("/operation", json!("resident-client-stream")),
    ] {
        let mut changed = images.clone();
        *changed[0].pointer_mut(pointer).unwrap() = value;
        assert!(resolved_readonly_payload(&expected, &events, &changed, 7, 1, &pin).is_err());
    }
    let mut changed = events.clone();
    changed[3]["data"]["image"]["argv_base64"] =
        json!(STANDARD.encode(b"/usr/bin/python3.12\0-m\0other\0"));
    assert!(resolved_readonly_payload(&expected, &changed, &images, 7, 1, &pin).is_err());
    assert!(resolved_readonly_payload(&expected, &events, &images, 7, 1, &"b".repeat(64)).is_err());
    let mut changed = expected;
    changed["tool_input"]["command"] = json!("python3 -c arbitrary");
    assert!(resolved_readonly_payload(&changed, &events, &images, 7, 1, &pin).is_err());
}
