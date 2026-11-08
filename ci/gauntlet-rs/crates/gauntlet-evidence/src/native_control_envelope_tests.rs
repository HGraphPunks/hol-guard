use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn fixture() -> (NativeControlReportPins, Value, Ed25519KeyPair) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
    let pins = NativeControlReportPins {
        prelaunch: PrelaunchPrepared {
            job_id: "1".repeat(16),
            source_sha: "2".repeat(40),
            deployment_digest: "3".repeat(64),
            worker_generation: "4".repeat(64),
            started_marker_sha256: "5".repeat(64),
            controller_key_pin_sha256: "6".repeat(64),
            controller_public_key_hex: key
                .public_key()
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        },
        preparation_sha256: "7".repeat(64),
        role: "timeout".into(),
    };
    let report = json!({"schema":"hol-gauntlet-native-deterministic-control.v1",
        "job_id":pins.prelaunch.job_id,"preparation_sha256":pins.preparation_sha256,"control_role":pins.role,
        "guard_pins":{"source_sha":pins.prelaunch.source_sha},"status":"failed","error":"fixture failure",
        "execution_eligible":false,"guard_causality_verified":false,"qualified_role_complete":false,
        "model_requests":0,"controller_identity":{"pid":19,"start_ticks":23},"measurement":{"captured_exit":null}});
    (pins, report, key)
}
fn signed(report: &Value, pins: &NativeControlReportPins, key: &Ed25519KeyPair) -> Vec<u8> {
    let record = native_control_signing_record(report, pins).unwrap();
    let signature = key.sign(&canonical_value(&record).unwrap());
    canonical_value(&json!({"record":record,"signature":STANDARD.encode(signature.as_ref())}))
        .unwrap()
}

#[test]
fn authenticated_failure_and_pass_claims_both_remain_ineligible() {
    let (pins, mut report, key) = fixture();
    for status in ["failed", "passed"] {
        report["status"] = json!(status);
        report["error"] = if status == "passed" {
            Value::Null
        } else {
            json!("fixture failure")
        };
        let raw = signed(&report, &pins, &key);
        let verified = verify_native_control_envelope(&raw, &pins).unwrap();
        assert_eq!(verified.report(), &report);
        let observation = verified.observation();
        assert_eq!(observation["reported_status"], status);
        assert_eq!(observation["signature_verified"], true);
        for field in [
            "execution_eligible",
            "guard_causality_verified",
            "qualified_role_complete",
            "independent_effects_scored",
        ] {
            assert_eq!(observation[field], false);
        }
    }
}

#[test]
fn another_valid_key_cannot_authenticate_the_same_job() {
    let (pins, report, _) = fixture();
    let other = Ed25519KeyPair::from_seed_unchecked(&[38; 32]).unwrap();
    assert!(verify_native_control_envelope(&signed(&report, &pins, &other), &pins).is_err());
}

#[test]
fn every_outside_context_pin_is_required_even_with_a_valid_signature() {
    let (pins, report, key) = fixture();
    let raw = signed(&report, &pins, &key);
    for field in 0..9 {
        let mut replaced = pins.clone();
        match field {
            0 => replaced.prelaunch.job_id = "8".repeat(16),
            1 => replaced.prelaunch.source_sha = "8".repeat(40),
            2 => replaced.prelaunch.deployment_digest = "8".repeat(64),
            3 => replaced.prelaunch.worker_generation = "8".repeat(64),
            4 => replaced.prelaunch.started_marker_sha256 = "8".repeat(64),
            5 => replaced.prelaunch.controller_key_pin_sha256 = "8".repeat(64),
            6 => replaced.prelaunch.controller_public_key_hex = "8".repeat(64),
            7 => replaced.preparation_sha256 = "8".repeat(64),
            8 => replaced.role = "cancel".into(),
            _ => unreachable!(),
        }
        assert!(
            verify_native_control_envelope(&raw, &replaced).is_err(),
            "context {field}"
        );
    }
}

#[test]
fn modified_effect_or_an_extra_signed_field_is_not_accepted() {
    let (pins, report, key) = fixture();
    let raw = signed(&report, &pins, &key);
    let mut changed: Value = serde_json::from_slice(&raw).unwrap();
    changed["record"]["controller_report"]["measurement"]["captured_exit"] = json!(124);
    assert!(verify_native_control_envelope(&canonical_value(&changed).unwrap(), &pins).is_err());
    changed["record"]["extra_context"] = json!(true);
    changed["signature"] = json!(STANDARD.encode(
        key.sign(&canonical_value(&changed["record"]).unwrap())
            .as_ref()
    ));
    assert!(verify_native_control_envelope(&canonical_value(&changed).unwrap(), &pins).is_err());
}

#[test]
fn duplicate_fields_oversize_and_claimed_qualification_are_refused() {
    let (pins, mut report, key) = fixture();
    let raw = signed(&report, &pins, &key);
    let duplicate = format!(
        "{{\"record\":null,{}",
        std::str::from_utf8(&raw[1..]).unwrap()
    );
    assert!(verify_native_control_envelope(duplicate.as_bytes(), &pins).is_err());
    assert!(
        verify_native_control_envelope(&vec![b' '; NATIVE_CONTROL_ENVELOPE_LIMIT + 1], &pins)
            .is_err()
    );
    for field in [
        "execution_eligible",
        "guard_causality_verified",
        "qualified_role_complete",
    ] {
        report[field] = json!(true);
        assert!(native_control_signing_record(&report, &pins).is_err());
        report[field] = json!(false);
    }
    report["control_role"] = json!("injection");
    assert!(native_control_signing_record(&report, &pins).is_err());
}

#[test]
fn readonly_hook_requires_explicit_v2_pins_and_cannot_be_a_six_role_report() {
    let (mut pins, mut report, key) = fixture();
    pins.role = "readonly-utility".into();
    report["schema"] = json!("hol-gauntlet-native-hook-transport.v2");
    report["pins"] = report
        .as_object_mut()
        .unwrap()
        .remove("guard_pins")
        .unwrap();
    report.as_object_mut().unwrap().remove("control_role");
    report["sdk_exercised"] = json!(false);
    report["artifact_admitted"] = json!(false);
    let raw = signed(&report, &pins, &key);
    let verified = verify_native_control_envelope(&raw, &pins).unwrap();
    assert_eq!(verified.report(), &report);
    assert_eq!(
        verified.observation()["schema"],
        "hol-gauntlet-authenticated-native-controller-record.v2"
    );
    assert_eq!(verified.observation()["independent_effects_scored"], false);
    let mut old = pins.clone();
    old.role = "success".into();
    assert!(verify_native_control_envelope(&raw, &old).is_err());
    for (pointer, value) in [
        ("/schema", json!("hol-gauntlet-native-hook-transport.v1")),
        ("/pins/source_sha", json!("8".repeat(40))),
        ("/job_id", json!("8".repeat(16))),
        ("/preparation_sha256", json!("8".repeat(64))),
        ("/sdk_exercised", json!(true)),
        ("/artifact_admitted", json!(true)),
        ("/execution_eligible", json!(true)),
        ("/guard_causality_verified", json!(true)),
        ("/qualified_role_complete", json!(true)),
    ] {
        let mut changed = report.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            native_control_signing_record(&changed, &pins).is_err(),
            "{pointer}"
        );
    }
    let mut changed: Value = serde_json::from_slice(&raw).unwrap();
    changed["record"]["schema"] = json!("hol-gauntlet-native-controller-record.v1");
    changed["signature"] = json!(STANDARD.encode(
        key.sign(&canonical_value(&changed["record"]).unwrap())
            .as_ref()
    ));
    assert!(verify_native_control_envelope(&canonical_value(&changed).unwrap(), &pins).is_err());
    report["control_role"] = json!("success");
    assert!(native_control_signing_record(&report, &pins).is_err());
}
