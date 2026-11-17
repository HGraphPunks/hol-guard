use super::*;
use crate::native_live_http::{normalize_request, sse_response};

fn pins() -> NativeLiveModelPins {
    NativeLiveModelPins::parse(&json!({"schema":"hol-gauntlet-native-live-model-pins.v1","provider_job_id":"a".repeat(16),"budget_digest":"b".repeat(64),"model_id":MODEL,"max_turns":2,"token_limit":100_000})).unwrap()
}
fn request() -> Vec<u8> {
    canonicalize(json!({"model":MODEL,"stream":false,"messages":[{"role":"user","content":"source-selected workflow"}],"max_tokens":4096}).to_string().as_bytes()).unwrap()
}
fn response(request: &Value) -> Value {
    let raw=canonicalize(json!({"id":"chat-real","created":1,"model":MODEL,"choices":[{"index":0,"message":{"role":"assistant","content":"real completed answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":21,"completion_tokens":7,"total_tokens":28}}).to_string().as_bytes()).unwrap();
    let before = json!({"quota":{"requests":9}});
    let after = json!({"quota":{"requests":10}});
    let receipt = json!({"schema":"hol-gauntlet-rust-provider-usage.v1","source_sha":request["source_sha"],"provider_job_id":request["provider_job_id"],"cell_job_id":request["job_id"],"budget_digest":request["budget_digest"],"turn":request["turn"],"request_sha256":request["request_sha256"],"response_sha256":sha(&raw),"response_bytes":raw.len(),"model_id":MODEL,"reservation_id":"c".repeat(32),"prepared_input_sha256":"d".repeat(64),"prompt_tokens":21,"output_tokens":7,"complete":true,"quota_before_sha256":sha(&canonicalize(before["quota"].to_string().as_bytes()).unwrap()),"quota_after_sha256":sha(&canonicalize(after["quota"].to_string().as_bytes()).unwrap()),"quota_journal_before":"1".repeat(64),"quota_journal_after":"2".repeat(64),"quota_requests_before":9,"quota_requests_after":10,"qualification_eligible":false});
    json!({"schema":"hol-gauntlet-native-live-model-response.v1","source_sha":request["source_sha"],"provider_job_id":request["provider_job_id"],"job_id":request["job_id"],"budget_digest":request["budget_digest"],"turn":request["turn"],"request_sha256":request["request_sha256"],"response_sha256":sha(&raw),"body_b64":STANDARD.encode(&raw),"usage_receipt":receipt,"before":before,"after":after})
}
fn ledger() -> NativeLiveModelLedger {
    NativeLiveModelLedger::new(&"3".repeat(40), &"4".repeat(16), &pins()).unwrap()
}

#[test]
fn live_turn_consumption_delivery_and_usage_chain_are_one_use() {
    assert_eq!(REQUEST_FRAME_LIMIT, 2 * REQUEST_LIMIT);
    let raw = request();
    let sdk = sha(&raw);
    let mut ledger = ledger();
    let first = ledger.begin(&raw, &sdk).unwrap();
    assert!(ledger.begin(&raw, &sdk).is_err());
    let first_response = response(&first);
    assert!(ledger.finish(first_response.to_string().as_bytes()).is_ok());
    assert!(ledger.begin(&raw, &sdk).is_err());
    ledger.delivered().unwrap();
    assert!(ledger.delivered().is_err());
    let second = ledger.begin(&raw, &sdk).unwrap();
    assert_eq!(second["turn"], 2);
    let mut next = response(&second);
    next["before"] = first_response["after"].clone();
    next["after"] = json!({"quota":{"requests":11}});
    let next_before = sha(&canonicalize(next["before"]["quota"].to_string().as_bytes()).unwrap());
    let next_after = sha(&canonicalize(next["after"]["quota"].to_string().as_bytes()).unwrap());
    let receipt = &mut next["usage_receipt"];
    receipt["quota_before_sha256"] = json!(next_before);
    receipt["quota_after_sha256"] = json!(next_after);
    receipt["quota_journal_before"] = json!("2".repeat(64));
    receipt["quota_journal_after"] = json!("5".repeat(64));
    receipt["quota_requests_before"] = json!(10);
    receipt["quota_requests_after"] = json!(11);
    ledger.finish(next.to_string().as_bytes()).unwrap();
    ledger.delivered().unwrap();
    assert!(ledger.begin(&raw, &sdk).is_err());
    let observed = ledger.observation();
    assert_eq!(observed["turns_completed"], 2);
    assert_eq!(observed["tokens_counted"], 56);
    assert_eq!(observed["pending_turn"], Value::Null);
    assert_eq!(observed["retries"], 0);
    assert!(!observed.to_string().contains("source-selected workflow"));
}
#[test]
fn invalid_transport_receipts_remain_pending_and_block_retry() {
    for (pointer, value) in [
        ("/source_sha", json!("6".repeat(40))),
        ("/job_id", json!("6".repeat(16))),
        ("/budget_digest", json!("6".repeat(64))),
        ("/turn", json!(2)),
        ("/request_sha256", json!("6".repeat(64))),
        ("/response_sha256", json!("6".repeat(64))),
        ("/usage_receipt/complete", json!(false)),
        ("/usage_receipt/quota_requests_after", json!(11)),
        ("/usage_receipt/prompt_tokens", json!(0)),
        ("/usage_receipt/output_tokens", json!(8)),
        ("/usage_receipt/qualification_eligible", json!(true)),
    ] {
        let raw = request();
        let mut ledger = ledger();
        let request = ledger.begin(&raw, &sha(&raw)).unwrap();
        let mut changed = response(&request);
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            ledger.finish(changed.to_string().as_bytes()).is_err(),
            "{pointer}"
        );
        assert!(ledger.begin(&raw, &sha(&raw)).is_err(), "{pointer}");
        assert_eq!(ledger.observation()["pending_turn"], 1);
    }
}
#[test]
fn unknown_model_streaming_upstream_and_changed_budget_pins_refuse() {
    let base: Value = serde_json::from_slice(&request()).unwrap();
    for (name, value) in [
        ("model", json!("other")),
        ("stream", json!(true)),
        ("max_tokens", json!(4097)),
        ("n", json!(2)),
    ] {
        let mut changed = base.clone();
        changed[name] = value;
        assert!(ledger()
            .begin(changed.to_string().as_bytes(), &"a".repeat(64))
            .is_err());
    }
    let mut p = pins().to_json();
    p["token_limit"] = json!(100_001);
    assert!(NativeLiveModelPins::parse(&p).is_err());
    p = pins().to_json();
    p["max_turns"] = json!(65);
    assert!(NativeLiveModelPins::parse(&p).is_err());
}

#[test]
fn streaming_transport_normalization_preserves_actual_messages_and_pins_model_budget() {
    let input = json!({"model":MODEL,"messages":[{"role":"user","content":"source-selected prompt"}],"tools":[{"type":"function","function":{"name":"docs_read"}}],"stream":true,"stream_options":{"include_usage":true},"max_tokens":8192});
    let (raw, streamed) = normalize_request(input.to_string().as_bytes()).unwrap();
    let output: Value = serde_json::from_slice(&raw).unwrap();
    assert!(streamed);
    assert_eq!(output["messages"], input["messages"]);
    assert_eq!(output["tools"], input["tools"]);
    assert_eq!(output["max_tokens"], 4096);
    assert_eq!(output["stream"], false);
    assert!(output.get("stream_options").is_none());
    let mut actual = input.clone();
    actual.as_object_mut().unwrap().remove("max_tokens");
    actual["max_completion_tokens"] = json!(8192);
    actual["n"] = json!(1);
    actual["preserve_thinking"] = json!(true);
    actual["chat_template_kwargs"] = json!({"preserve_thinking":true});
    assert_eq!(
        normalize_request(actual.to_string().as_bytes()).unwrap(),
        (raw.clone(), true)
    );
    let sdk_raw = actual.to_string().into_bytes();
    let mut joined = ledger();
    let request = joined.begin(&raw, &sha(&sdk_raw)).unwrap();
    assert_eq!(request["request_sha256"], sha(&raw));
    assert_eq!(request["body_b64"], STANDARD.encode(&raw));
    joined
        .finish(&canonicalize(response(&request).to_string().as_bytes()).unwrap())
        .unwrap();
    assert_eq!(
        joined.observation()["turns"][0]["sdk_request_sha256"],
        sha(&sdk_raw)
    );
    let mut controls = actual.clone();
    controls["enable_thinking"] = json!(false);
    controls["chat_template_kwargs"] = json!({"enable_thinking":false,"preserve_thinking":true});
    controls["max_completion_tokens"] = json!(65536);
    assert_eq!(
        normalize_request(controls.to_string().as_bytes()).unwrap(),
        (raw, true)
    );
    let duplicate = sdk_raw
        .iter()
        .copied()
        .take(1)
        .chain(b"\"max_completion_tokens\":8192,".iter().copied())
        .chain(sdk_raw.iter().copied().skip(1))
        .collect::<Vec<_>>();
    assert!(normalize_request(&duplicate).is_err());
    for (key, value) in [
        ("n", json!(2)),
        ("n", Value::Null),
        ("enable_thinking", json!(true)),
        ("preserve_thinking", json!(false)),
        ("chat_template_kwargs", json!({"other":true})),
        ("chat_template_kwargs", json!({"preserve_thinking":false})),
        ("chat_template_kwargs", Value::Null),
        ("chat_template_kwargs", json!({})),
        ("stream_options", json!({"include_usage":true,"other":true})),
        ("unknown", json!(true)),
        ("max_tokens", json!(8192)),
    ] {
        let mut changed = actual.clone();
        changed[key] = value;
        assert!(
            normalize_request(changed.to_string().as_bytes()).is_err(),
            "{key}"
        );
    }
    for key in ["max_tokens", "max_completion_tokens"] {
        for value in [
            json!(0),
            json!(-1),
            json!(1.5),
            Value::Null,
            json!(true),
            json!("4096"),
            json!(65537),
        ] {
            let mut changed = input.clone();
            changed.as_object_mut().unwrap().remove("max_tokens");
            changed[key] = value;
            assert!(
                normalize_request(changed.to_string().as_bytes()).is_err(),
                "{key}"
            );
        }
    }
    let mut changed = input;
    changed["model"] = json!("other");
    assert!(normalize_request(changed.to_string().as_bytes()).is_err());
}
#[test]
fn real_response_stream_preserves_tool_arguments_usage_and_stop_reason() {
    let input = json!({"id":"chat-real","created":1,"model":MODEL,"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-a","type":"function","function":{"name":"docs_read","arguments":"{\"id\":\"ticket-a\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":21,"completion_tokens":7,"total_tokens":28}});
    let raw = sse_response(input.to_string().as_bytes()).unwrap();
    let text = std::str::from_utf8(&raw).unwrap();
    let chunks = text
        .split("\n\n")
        .filter_map(|line| line.strip_prefix("data: "))
        .filter(|s| *s != "[DONE]")
        .map(|s| serde_json::from_str::<Value>(s).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(chunks.len(), 2);
    assert_eq!(
        chunks[0]["choices"][0]["delta"]["tool_calls"][0]["function"],
        input["choices"][0]["message"]["tool_calls"][0]["function"]
    );
    assert_eq!(chunks[1]["choices"][0]["finish_reason"], "tool_calls");
    assert_eq!(chunks[1]["usage"], input["usage"]);
}
