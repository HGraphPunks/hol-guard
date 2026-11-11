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
