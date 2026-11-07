use super::*;

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
