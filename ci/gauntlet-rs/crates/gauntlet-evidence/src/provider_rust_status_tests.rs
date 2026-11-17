use super::*;

fn fixture() -> (Value, Value, Value, Value) {
    let mut pins = json!({"profile":"owned-mlx-rust-serial.v2", "source_sha":"a".repeat(40),
        "provider_job_id":"provider-test", "binding_sha256":"1".repeat(64), "adapter_sha256":"2".repeat(64),
        "server_sha256":"3".repeat(64), "producer_sha256":"4".repeat(64), "model_identity_digest":"5".repeat(64),
        "quota_config_digest":"6".repeat(64), "quota_allowance_digest":"7".repeat(64),
        "token_cap":200000, "maximum_requests":100});
    let quota = json!({"schema":"gauntlet-provider-quota-status.v1", "config_digest":pins["quota_config_digest"],
        "allowance_digest":pins["quota_allowance_digest"], "model_identity_digest":pins["model_identity_digest"],
        "charged_tokens":100,"known_tokens":100,"reserved_tokens":0,"requests":2,"maximum_requests":100,
        "pending_requests":0,"remaining_tokens":199900,"token_cap":200000,"halted":false,
        "journal_hash":"8".repeat(64),"qualification_eligible":false});
    let before = json!({"adapter":{
        "schema":"gauntlet-mlx-quota-adapter.v2", "source_sha":pins["source_sha"],
        "provider_job_id":pins["provider_job_id"], "producer_sha256":pins["producer_sha256"],
        "server_sha256":pins["server_sha256"], "adapter_sha256":pins["adapter_sha256"],
        "quota_config_digest":pins["quota_config_digest"], "quota_allowance_digest":pins["quota_allowance_digest"],
        "producer_mode":"serial-original-tokenization-and-generation",
        "counting":"full prompt including cached input plus every producer-emitted response token",
        "batching":false,"draft":false,"qualification_eligible":false},
        "binding_sha256":pins["binding_sha256"],"qualification":false,"quota":quota});
    let mut after = before.clone();
    after["quota"]["charged_tokens"] = json!(137);
    after["quota"]["known_tokens"] = json!(137);
    after["quota"]["remaining_tokens"] = json!(199863);
    after["quota"]["requests"] = json!(3);
    after["quota"]["journal_hash"] = json!("9".repeat(64));
    let extra = json!({"cell_job_id":"cell-test","budget_digest":"b".repeat(64),"turn":1,
        "request_sha256":"c".repeat(64),"response_sha256":"d".repeat(64),"response_bytes":400,
        "model_id":"test-model","reservation_id":"reservation-test","prepared_input_sha256":"e".repeat(64)});
    pins.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let mut usage = json!({"schema":"hol-gauntlet-rust-provider-usage.v1","source_sha":pins["source_sha"],
        "provider_job_id":pins["provider_job_id"],"prompt_tokens":30,"output_tokens":7,"complete":true,
        "quota_before_sha256":sha256(&canonical_value(&before["quota"]).unwrap()),
        "quota_after_sha256":sha256(&canonical_value(&after["quota"]).unwrap()),
        "quota_journal_before":before["quota"]["journal_hash"],"quota_journal_after":after["quota"]["journal_hash"],
        "quota_requests_before":2,"quota_requests_after":3,"qualification_eligible":false});
    usage
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    (pins, usage, before, after)
}

#[test]
fn exact_settled_request_uses_distinct_rust_source_and_quota_pins() {
    let (pins, usage, before, after) = fixture();
    let result = verify_rust_provider_usage(&usage, &pins, &before, &after).unwrap();
    assert_eq!(result["model_tokens"], 37);
    assert_eq!(result["qualification_eligible"], false);
}

#[test]
fn unknown_usage_identity_drift_and_budget_undercharge_are_refused() {
    let (pins, usage, before, after) = fixture();
    for (key, value) in [
        ("complete", json!(false)),
        ("prompt_tokens", json!(29)),
        ("request_sha256", json!("f".repeat(64))),
        ("quota_requests_after", json!(4)),
        ("prepared_input_sha256", json!("0".repeat(64))),
        ("qualification_eligible", json!(true)),
    ] {
        let mut changed = usage.clone();
        changed[key] = value;
        assert!(
            verify_rust_provider_usage(&changed, &pins, &before, &after).is_err(),
            "{key}"
        );
    }
    for key in ["reserved_tokens", "pending_requests"] {
        let mut changed = after.clone();
        changed["quota"][key] = json!(1);
        assert!(verify_rust_provider_usage(&usage, &pins, &before, &changed).is_err());
    }
}

#[test]
fn python_identity_extra_fields_and_replayed_quota_are_refused() {
    let (pins, usage, before, after) = fixture();
    let mut changed = before.clone();
    changed["adapter"]["schema"] = json!("gauntlet-mlx-quota-adapter.v1");
    assert!(verify_rust_provider_usage(&usage, &pins, &changed, &after).is_err());
    let mut changed = usage.clone();
    changed["producer_passed"] = json!(true);
    assert!(verify_rust_provider_usage(&changed, &pins, &before, &after).is_err());
    assert!(verify_rust_provider_usage(&usage, &pins, &before, &before).is_err());
}

fn retained_turns() -> (Value, Value, Value) {
    let (mut identity, mut usage, before, after) = fixture();
    let request = json!({"model":"test-model","stream":false,"max_tokens":64,
        "messages":[{"role":"user","content":"original source prompt"}]})
    .to_string();
    let response = json!({"model":"test-model","choices":[{"message":{"role":"assistant","content":"original response"}}],
        "usage":{"prompt_tokens":30,"completion_tokens":7}}).to_string();
    for (name, value) in [
        ("request_sha256", json!(sha256(request.as_bytes()))),
        ("response_sha256", json!(sha256(response.as_bytes()))),
        ("response_bytes", json!(response.len())),
    ] {
        identity[name] = value.clone();
        usage[name] = value;
    }
    let status = Value::Object(
        STATUS_PINS
            .iter()
            .map(|key| (key.to_string(), identity[*key].clone()))
            .collect(),
    );
    let mut first_pin = Value::Object(
        USAGE_PINS
            .iter()
            .map(|key| (key.to_string(), identity[*key].clone()))
            .collect(),
    );
    let first =
        json!({"request":request,"response":response,"usage":usage,"before":before,"after":after});
    first_pin["observation_sha256"] = json!(sha256(
        &canonical_value(
            &json!({"usage":first["usage"],"before":first["before"],"after":first["after"]})
        )
        .unwrap()
    ));
    let mut second = first.clone();
    second["before"] = after.clone();
    second["after"]["quota"]["charged_tokens"] = json!(174);
    second["after"]["quota"]["known_tokens"] = json!(174);
    second["after"]["quota"]["remaining_tokens"] = json!(199826);
    second["after"]["quota"]["requests"] = json!(4);
    second["after"]["quota"]["journal_hash"] = json!("f".repeat(64));
    second["usage"]["turn"] = json!(2);
    second["usage"]["reservation_id"] = json!("reservation-test-2");
    second["usage"]["quota_requests_before"] = json!(3);
    second["usage"]["quota_requests_after"] = json!(4);
    for (field, snapshot) in [("before", "before"), ("after", "after")] {
        second["usage"][format!("quota_{field}_sha256")] = json!(sha256(
            &canonical_value(&second[snapshot]["quota"]).unwrap()
        ));
        second["usage"][format!("quota_journal_{field}")] =
            second[snapshot]["quota"]["journal_hash"].clone();
    }
    let mut second_pin = Value::Object(
        USAGE_PINS
            .iter()
            .map(|key| (key.to_string(), second["usage"][*key].clone()))
            .collect(),
    );
    let report = json!({"job_id":"cell-test","model_requests":2,"guard_pins":{"source_sha":identity["source_sha"]}});
    second_pin["observation_sha256"] = json!(sha256(
        &canonical_value(
            &json!({"usage":second["usage"],"before":second["before"],"after":second["after"]})
        )
        .unwrap()
    ));
    (
        json!({"provider_turns":[first,second]}),
        report,
        json!({"status_pins":status,"turn_pins":[first_pin,second_pin]}),
    )
}

#[test]
fn provider_turns_exhaust_current_job_outside_observations_without_consuming_other_cells() {
    let (artifacts, report, mut pins) = retained_turns();
    let mut other = pins["turn_pins"][0].clone();
    other["cell_job_id"] = json!("other-cell");
    pins["turn_pins"].as_array_mut().unwrap().push(other);
    let actual =
        verify_rust_provider_turns(&artifacts, &report, &pins, "original source prompt").unwrap();
    assert_eq!(actual["completed_requests"], 2);
    assert_eq!(actual["model_tokens"], 74);
    assert_eq!(actual["qualification_eligible"], false);
    let mut omitted = artifacts.clone();
    omitted["provider_turns"].as_array_mut().unwrap().pop();
    let mut claimed = report.clone();
    claimed["model_requests"] = json!(1);
    assert!(
        verify_rust_provider_turns(&omitted, &claimed, &pins, "original source prompt").is_err()
    );
}

#[test]
fn missing_duplicate_and_noncontiguous_outside_turns_are_refused() {
    let (artifacts, report, pins) = retained_turns();
    for mutation in 0..3 {
        let mut changed = pins.clone();
        match mutation {
            0 => {
                changed["turn_pins"].as_array_mut().unwrap().pop();
            }
            1 => changed["turn_pins"][1] = changed["turn_pins"][0].clone(),
            2 => changed["turn_pins"][1]["turn"] = json!(3),
            _ => unreachable!(),
        }
        assert!(verify_rust_provider_turns(
            &artifacts,
            &report,
            &changed,
            "original source prompt"
        )
        .is_err());
    }
}

#[test]
fn quota_snapshot_history_is_bound_to_the_actual_outside_provider_observation() {
    let (artifacts, report, pins) = retained_turns();
    let mut rewritten = artifacts.clone();
    for turn in rewritten["provider_turns"].as_array_mut().unwrap() {
        for snapshot in ["before", "after"] {
            for field in ["charged_tokens", "known_tokens"] {
                turn[snapshot]["quota"][field] =
                    json!(turn[snapshot]["quota"][field].as_u64().unwrap() + 100);
            }
            turn[snapshot]["quota"]["remaining_tokens"] = json!(
                turn[snapshot]["quota"]["remaining_tokens"]
                    .as_u64()
                    .unwrap()
                    - 100
            );
            turn["usage"][format!("quota_{snapshot}_sha256")] =
                json!(sha256(&canonical_value(&turn[snapshot]["quota"]).unwrap()));
        }
    }
    assert!(
        verify_rust_provider_turns(&rewritten, &report, &pins, "original source prompt").is_err()
    );
    for mutation in 0..3 {
        let mut changed = pins.clone();
        match mutation {
            0 => {
                changed["turn_pins"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("observation_sha256");
            }
            1 => changed["turn_pins"][0]["observation_sha256"] = json!("0".repeat(64)),
            2 => changed["turn_pins"][0]["usage_complete"] = json!(true),
            _ => unreachable!(),
        }
        assert!(verify_rust_provider_turns(
            &artifacts,
            &report,
            &changed,
            "original source prompt"
        )
        .is_err());
    }
}

fn observation(turn: &Value) -> String {
    sha256(
        &canonical_value(
            &json!({"usage":turn["usage"],"before":turn["before"],"after":turn["after"]}),
        )
        .unwrap(),
    )
}

fn frame_text(frame: &Value) -> Value {
    json!(format!(
        "{}\n",
        String::from_utf8(canonical_value(frame).unwrap()).unwrap()
    ))
}

fn change_frame(turn: &mut Value, side: &str, change: impl FnOnce(&mut Value)) {
    let mut frame: Value = serde_json::from_str(turn[side].as_str().unwrap()).unwrap();
    change(&mut frame);
    turn[side] = frame_text(&frame);
}

fn framed_turns() -> (Value, Value, Value) {
    let (mut artifacts, mut report, mut pins) = retained_turns();
    report["job_id"] = json!("0123456789abcdef");
    pins["status_pins"]["provider_job_id"] = json!("fedcba9876543210");
    for (index, turn) in artifacts["provider_turns"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        turn["usage"]["cell_job_id"] = report["job_id"].clone();
        turn["usage"]["provider_job_id"] = pins["status_pins"]["provider_job_id"].clone();
        for snapshot in ["before", "after"] {
            turn[snapshot]["adapter"]["provider_job_id"] = turn["usage"]["provider_job_id"].clone();
        }
        pins["turn_pins"][index]["cell_job_id"] = report["job_id"].clone();
        pins["turn_pins"][index]["observation_sha256"] = json!(observation(turn));
        let usage = &turn["usage"];
        let request = json!({"schema":"hol-gauntlet-native-live-model-request.v1",
            "source_sha":usage["source_sha"],"provider_job_id":usage["provider_job_id"],
            "job_id":usage["cell_job_id"],"budget_digest":usage["budget_digest"],"turn":usage["turn"],
            "request_sha256":usage["request_sha256"],"body_b64":STANDARD.encode(turn["request"].as_str().unwrap())});
        let mut response = request.clone();
        response["schema"] = json!("hol-gauntlet-native-live-model-response.v1");
        response["body_b64"] = json!(STANDARD.encode(turn["response"].as_str().unwrap()));
        response["response_sha256"] = usage["response_sha256"].clone();
        response["usage_receipt"] = usage.clone();
        response["before"] = turn["before"].clone();
        response["after"] = turn["after"].clone();
        turn["request"] = frame_text(&request);
        turn["response"] = frame_text(&response);
    }
    (artifacts, report, pins)
}

#[test]
fn framed_provider_turns_join_decoded_body_pins_and_full_quota_history() {
    let (artifacts, report, pins) = framed_turns();
    let actual =
        verify_rust_provider_turns(&artifacts, &report, &pins, "original source prompt").unwrap();
    assert_eq!(actual["completed_requests"], 2);
    assert_eq!(actual["model_tokens"], 74);
    assert_eq!(actual["qualification_eligible"], false);
    let (legacy, _, _) = retained_turns();
    assert_eq!(
        provider_turn_bodies(&artifacts["provider_turns"][0]),
        provider_turn_bodies(&legacy["provider_turns"][0])
    );
    assert_ne!(
        json!(sha256(
            artifacts["provider_turns"][0]["response"]
                .as_str()
                .unwrap()
                .as_bytes()
        )),
        pins["turn_pins"][0]["response_sha256"]
    );
    for field in ["request_sha256", "response_sha256", "observation_sha256"] {
        let mut changed = pins.clone();
        changed["turn_pins"][0][field] = json!("0".repeat(64));
        assert!(
            verify_rust_provider_turns(&artifacts, &report, &changed, "original source prompt")
                .is_err(),
            "{field}"
        );
    }
    let mut old = pins.clone();
    old["turn_pins"][0]
        .as_object_mut()
        .unwrap()
        .remove("observation_sha256");
    assert!(
        verify_rust_provider_turns(&artifacts, &report, &old, "original source prompt").is_err()
    );
}

#[test]
fn malformed_mixed_or_foreign_frames_cannot_fall_back_to_legacy_bodies() {
    let (artifacts, _, _) = framed_turns();
    for side in ["request", "response"] {
        for (field, value) in [
            ("schema", json!("hol-gauntlet-native-live-model-request.v2")),
            ("source_sha", json!("0".repeat(40))),
            ("provider_job_id", json!("0".repeat(16))),
            ("job_id", json!("0".repeat(16))),
            ("budget_digest", json!("0".repeat(64))),
            ("turn", json!(3)),
            ("request_sha256", json!("0".repeat(64))),
            ("body_b64", json!("not base64")),
            ("body_b64", json!(STANDARD.encode(b"{}"))),
            ("extra", json!(true)),
        ] {
            let mut turn = artifacts["provider_turns"][0].clone();
            change_frame(&mut turn, side, |frame| frame[field] = value);
            assert!(provider_turn_bodies(&turn).is_none(), "{side}/{field}");
        }
        let mut mixed = artifacts["provider_turns"][0].clone();
        let (request, response) = provider_turn_bodies(&mixed).unwrap();
        mixed[side] = json!(if side == "request" { request } else { response }.to_string());
        assert!(provider_turn_bodies(&mixed).is_none());
    }
    for field in ["usage", "before", "after"] {
        let mut turn = artifacts["provider_turns"][0].clone();
        turn[field]["foreign"] = json!(true);
        assert!(provider_turn_bodies(&turn).is_none(), "outer/{field}");
    }
    let mut duplicate = artifacts["provider_turns"][0].clone();
    duplicate["request"] =
        json!(duplicate["request"]
            .as_str()
            .unwrap()
            .replacen('{', "{\"turn\":1,", 1));
    assert!(provider_turn_bodies(&duplicate).is_none());
    let mut noncanonical = artifacts["provider_turns"][0].clone();
    let (body, _) = provider_turn_bodies(&noncanonical).unwrap();
    let mut raw = canonical_value(&body).unwrap();
    raw.push(b'\n');
    noncanonical["usage"]["request_sha256"] = json!(sha256(&raw));
    let usage = noncanonical["usage"].clone();
    change_frame(&mut noncanonical, "request", |frame| {
        frame["body_b64"] = json!(STANDARD.encode(&raw));
        frame["request_sha256"] = json!(sha256(&raw));
    });
    change_frame(&mut noncanonical, "response", |frame| {
        frame["request_sha256"] = usage["request_sha256"].clone();
        frame["usage_receipt"] = usage;
    });
    assert!(provider_turn_bodies(&noncanonical).is_none());
}

#[test]
fn self_consistent_framed_substitution_still_requires_original_outside_pins() {
    let (mut artifacts, report, pins) = framed_turns();
    let turn = &mut artifacts["provider_turns"][0];
    let (_, mut body) = provider_turn_bodies(turn).unwrap();
    body["choices"][0]["message"]["content"] = json!("substituted response");
    let raw = canonical_value(&body).unwrap();
    turn["usage"]["response_sha256"] = json!(sha256(&raw));
    turn["usage"]["response_bytes"] = json!(raw.len());
    let usage = turn["usage"].clone();
    change_frame(turn, "response", |frame| {
        frame["body_b64"] = json!(STANDARD.encode(&raw));
        frame["response_sha256"] = usage["response_sha256"].clone();
        frame["usage_receipt"] = usage;
    });
    assert!(provider_turn_bodies(turn).is_some());
    assert!(
        verify_rust_provider_turns(&artifacts, &report, &pins, "original source prompt").is_err()
    );
}

#[test]
fn legacy_body_whitespace_keeps_its_original_raw_byte_identity() {
    let (mut artifacts, report, mut pins) = retained_turns();
    for (index, turn) in artifacts["provider_turns"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        for side in ["request", "response"] {
            let raw = format!(" {}\n", turn[side].as_str().unwrap());
            turn["usage"][format!("{side}_sha256")] = json!(sha256(raw.as_bytes()));
            pins["turn_pins"][index][format!("{side}_sha256")] =
                turn["usage"][format!("{side}_sha256")].clone();
            if side == "response" {
                turn["usage"]["response_bytes"] = json!(raw.len());
                pins["turn_pins"][index]["response_bytes"] = json!(raw.len());
            }
            turn[side] = json!(raw);
        }
        pins["turn_pins"][index]["observation_sha256"] = json!(observation(turn));
        assert!(provider_turn_bodies(turn).is_some());
    }
    assert_eq!(
        verify_rust_provider_turns(&artifacts, &report, &pins, "original source prompt").unwrap()
            ["model_tokens"],
        74
    );
}
