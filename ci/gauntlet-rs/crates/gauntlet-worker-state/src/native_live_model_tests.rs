use super::*;

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
