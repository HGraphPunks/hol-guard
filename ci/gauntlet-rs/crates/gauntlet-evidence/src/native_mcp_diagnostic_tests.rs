use super::*;
use crate::native_mcp_inputs::{expected_world, grade_docs_read};

fn row(sequence: u64, direction: &str, message: Value) -> Value {
    let wire = message.to_string();
    json!({"sequence":sequence,"direction":direction,"frame":message,"wire_utf8":wire,
        "sha256":sha256(wire.as_bytes()),"forwarded":true})
}
fn fixture() -> Value {
    json!({"frames":[
        row(1,"sdk-request",json!({"jsonrpc":"2.0","id":"call","method":"initialize","params":{}})),
        row(2,"sdk-request",json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})),
        row(3,"native-response",json!({"jsonrpc":"2.0","id":"call","result":{}}))]})
}

#[test]
fn ordered_frame_bytes_and_pending_requests_reconcile_with_notifications() {
    let actual = frames(&fixture(), true).unwrap();
    assert_eq!(actual.requests.len(), 2);
    assert_eq!(actual.responses.len(), 1);
    assert_eq!(actual.count, 3);
}

#[test]
fn boolean_sequence_wrong_hash_changed_wire_and_false_forwarding_refuse() {
    for selector in 0..4 {
        let mut f = fixture();
        match selector {
            0 => f["frames"][0]["sequence"] = true.into(),
            1 => f["frames"][0]["sha256"] = "0".repeat(64).into(),
            2 => f["frames"][0]["wire_utf8"] = "{}".into(),
            _ => f["frames"][0]["forwarded"] = false.into(),
        }
        assert!(frames(&f, true).is_err(), "{selector}");
    }
}

#[test]
fn duplicate_or_missing_responses_unknown_ids_and_changed_notifications_refuse() {
    let original = fixture();
    for selector in 0..5 {
        let mut f = original.clone();
        match selector {
            0 => {
                f["frames"].as_array_mut().unwrap().pop();
            }
            1 => {
                let duplicate = row(
                    4,
                    "native-response",
                    json!({"jsonrpc":"2.0","id":"call","result":{}}),
                );
                f["frames"].as_array_mut().unwrap().push(duplicate);
            }
            2 => {
                f["frames"][2] = row(
                    3,
                    "native-response",
                    json!({"jsonrpc":"2.0","id":"foreign","result":{}}),
                )
            }
            3 => {
                f["frames"][1] = row(
                    2,
                    "sdk-request",
                    json!({"jsonrpc":"2.0","id":"call","method":"tools/list","params":{}}),
                )
            }
            _ => {
                f["frames"][1] = row(
                    2,
                    "sdk-request",
                    json!({"jsonrpc":"2.0","id":"extra","method":"notifications/initialized","params":{}}),
                )
            }
        }
        assert!(frames(&f, true).is_err(), "{selector}");
    }
}

#[test]
fn actual_ndjson_capture_rejects_a_changed_paired_output_and_duplicate_capture() {
    let observed = frames(&fixture(), true).unwrap();
    let encode = |values: &[Value]| {
        values
            .iter()
            .flat_map(|v| {
                let mut bytes = v.to_string().into_bytes();
                bytes.push(b'\n');
                bytes
            })
            .collect::<Vec<_>>()
    };
    let mut files = BTreeMap::from([
        (
            "combined/mcp-processes/001.mcp-input".into(),
            encode(&observed.requests),
        ),
        (
            "combined/mcp-processes/001.mcp-output".into(),
            encode(&observed.responses),
        ),
    ]);
    assert!(captured(&files, &observed.requests, &observed.responses).is_ok());
    files.insert(
        "combined/mcp-processes/001.mcp-output".into(),
        b"{}\n".to_vec(),
    );
    assert!(captured(&files, &observed.requests, &observed.responses).is_err());
    files.insert(
        "combined/mcp-processes/001.mcp-output".into(),
        encode(&observed.responses),
    );
    files.insert(
        "combined/mcp-processes/002.mcp-input".into(),
        encode(&observed.requests),
    );
    files.insert(
        "combined/mcp-processes/002.mcp-output".into(),
        encode(&observed.responses),
    );
    assert!(captured(&files, &observed.requests, &observed.responses).is_err());
}

fn read_fixture(role: &str) -> (Value, Value, Value, Value, Option<String>) {
    let (world, payload) = expected_world(role).unwrap();
    let expected = world["records"][0].clone();
    let request = json!({"jsonrpc":"2.0","id":"actual-read","method":"tools/call",
        "params":{"name":"docs.read","arguments":{"record_id":"developer-spec"}}});
    let response = json!({"jsonrpc":"2.0","id":"actual-read","result":{
        "content":[{"type":"text","text":expected.to_string()}],
        "structuredContent":expected,"isError":false}});
    let sdk = json!({"results":[{"role":"toolResult","toolCallId":"sdk-mcp-control",
        "toolName":"mcp__docs_read","isError":false,"content":response["result"]["content"],
        "details":{"serverName":"docs","mcpToolName":"docs.read","isError":false,
        "rawContent":response["result"]["content"],"structuredContent":expected}},{}]});
    (request, response, sdk, expected, payload)
}

#[test]
fn exact_source_selected_read_grades_all_roles_without_claiming_guard_or_model_success() {
    for role in [
        "success",
        "input-binding",
        "injection",
        "boundary",
        "timeout",
        "cancel",
    ] {
        let (request, response, sdk, expected, payload) = read_fixture(role);
        let sdk = (role != "cancel").then_some(&sdk);
        let grade = grade_docs_read(
            &request,
            &response,
            &response,
            &expected,
            payload.as_deref(),
            sdk,
        )
        .unwrap();
        assert_eq!(grade["operation_semantics_checked"], true);
        assert_eq!(grade["native_disposition"], "forwarded");
        assert_eq!(grade["sdk_delivery_checked"], sdk.is_some());
        for field in [
            "guard_intervention_observed",
            "model_resistance_tested",
            "physical_effect_causality_checked",
            "execution_eligible",
        ] {
            assert_eq!(grade[field], false, "{role}: {field}");
        }
    }
}

#[test]
fn complete_read_reply_rejects_extra_content_wrong_record_and_disagreeing_structured_content() {
    let (request, response, sdk, expected, _) = read_fixture("success");
    for (pointer, value) in [
        (
            "/result/content",
            json!([
            {"type":"text","text":expected.to_string()},
            {"type":"text","text":"unrelated extra document"}]),
        ),
        ("/result/content/0/type", json!("resource")),
        (
            "/result/content/0/text",
            json!(json!({"id":"message"}).to_string()),
        ),
        ("/result/structuredContent/id", json!("message")),
        ("/result/isError", json!(true)),
        ("/result/isError", json!("false")),
        ("/id", json!("different-request")),
        ("/jsonrpc", json!("1.0")),
    ] {
        let mut changed = response.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            grade_docs_read(&request, &changed, &changed, &expected, None, Some(&sdk)).is_err(),
            "{pointer}"
        );
    }
    for pointer in ["", "/result", "/result/content/0"] {
        let mut changed = response.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unrequested".into(), json!("extra result"));
        assert!(
            grade_docs_read(&request, &changed, &changed, &expected, None, Some(&sdk)).is_err(),
            "{pointer}"
        );
    }
    let mut changed = response;
    changed["result"]["content"][0]["text"] = json!("{\"id\":\"other\",\"id\":\"developer-spec\"}");
    assert!(grade_docs_read(&request, &changed, &changed, &expected, None, Some(&sdk)).is_err());
}

#[test]
fn read_operation_cannot_substitute_call_arguments_or_sdk_delivery_identity() {
    let (request, response, sdk, expected, _) = read_fixture("success");
    for (pointer, value) in [
        ("/method", json!("resources/read")),
        ("/params/name", json!("mail.read")),
        ("/params/arguments/record_id", json!("message")),
        (
            "/params/arguments",
            json!({"record_id":"developer-spec","include_private":true}),
        ),
        ("/id", json!(false)),
    ] {
        let mut changed = request.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            grade_docs_read(&changed, &response, &response, &expected, None, Some(&sdk)).is_err(),
            "{pointer}"
        );
    }
    for (pointer, value) in [
        ("/results/0/toolCallId", json!("another-sdk-call")),
        ("/results/0/toolName", json!("unrelated_tool")),
        ("/results/0/role", json!("assistant")),
        ("/results/0/isError", json!(true)),
        ("/results/0/details/serverName", json!("mail")),
        ("/results/0/details/structuredContent/id", json!("message")),
        ("/results/0/details/rawContent", json!([])),
    ] {
        let mut changed = sdk.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            grade_docs_read(
                &request,
                &response,
                &response,
                &expected,
                None,
                Some(&changed)
            )
            .is_err(),
            "{pointer}"
        );
    }
    let mut agent_surface = sdk;
    agent_surface["mcpAgentSurfaces"] = json!("mcp-agent-surfaces.v1");
    agent_surface["results"][0]["toolName"] = json!("mcp_call_tool");
    assert!(grade_docs_read(
        &request,
        &response,
        &response,
        &expected,
        None,
        Some(&agent_surface)
    )
    .is_ok());
}

#[test]
fn injection_withholding_requires_no_payload_in_the_complete_native_and_sdk_results() {
    let (request, response, mut sdk, expected, payload) = read_fixture("injection");
    let payload = payload.unwrap();
    let withheld = json!({"jsonrpc":"2.0","id":request["id"],"result":{
        "content":[{"type":"text","text":"Native withheld the injected result"}],"isError":true}});
    let first = &mut sdk["results"][0];
    first["content"] = withheld["result"]["content"].clone();
    first["isError"] = json!(true);
    first["details"]["rawContent"] = withheld["result"]["content"].clone();
    first["details"]["isError"] = json!(true);
    first["details"]
        .as_object_mut()
        .unwrap()
        .remove("structuredContent");
    let grade = grade_docs_read(
        &request,
        &response,
        &withheld,
        &expected,
        Some(&payload),
        Some(&sdk),
    )
    .unwrap();
    assert_eq!(grade["native_disposition"], "withheld");
    assert_eq!(grade["native_withholding_observed"], true);
    assert_eq!(grade["guard_intervention_observed"], false);
    assert_eq!(grade["execution_eligible"], false);
    assert!(grade_docs_read(&request, &response, &withheld, &expected, None, Some(&sdk)).is_err());
    for (pointer, value) in [
        ("/result/content/0/text", json!(payload)),
        ("/result/isError", json!(false)),
        ("/result/content", json!([])),
        ("/result/content/0/text", json!("  ")),
    ] {
        let mut changed = withheld.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            grade_docs_read(
                &request,
                &response,
                &changed,
                &expected,
                Some(&payload),
                Some(&sdk)
            )
            .is_err(),
            "{pointer}"
        );
    }
    sdk["results"][0]["unrelated_metadata"] =
        json!({"encoded":json!({"data":{"body":payload}}).to_string()});
    assert!(grade_docs_read(
        &request,
        &response,
        &withheld,
        &expected,
        Some(&payload),
        Some(&sdk)
    )
    .is_err());
}
