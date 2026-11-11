use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_evidence::{native_control_signing_record, verify_native_control_envelope};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::os::unix::fs::PermissionsExt;

fn bytes(value: &Value) -> Vec<u8> {
    canonicalize(value.to_string().as_bytes()).unwrap()
}
pub(crate) fn refresh(frame: &mut Value) {
    frame["terminal"]["report_sha256"] = json!(digest(&frame["report"]).unwrap());
    frame["terminal_sha256"] = json!(digest(&frame["terminal"]).unwrap());
}
fn fixture() -> (tempfile::TempDir, HostPrelaunchIdentity, String, Value) {
    fixture_for("timeout")
}
pub(crate) fn fixture_for(role: &str) -> (tempfile::TempDir, HostPrelaunchIdentity, String, Value) {
    fixture_with_pins(role, &"3".repeat(64), &"7".repeat(64))
}
pub(crate) fn fixture_with_pins(
    role: &str,
    deployment: &str,
    preparation: &str,
) -> (tempfile::TempDir, HostPrelaunchIdentity, String, Value) {
    let readonly = role == "readonly-utility";
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&path).unwrap();
    let expected = HostPrelaunchIdentity {
        job_id: "1".repeat(16),
        source_sha: "2".repeat(40),
        deployment_digest: deployment.into(),
        worker_generation: "4".repeat(64),
    };
    let key = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
    let public = key
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let started = json!({"schema":"hol-gauntlet-worker-started.v2","source_sha":expected.source_sha,
        "job_id":expected.job_id,"deployment_digest":expected.deployment_digest,"worker_generation":expected.worker_generation,"controller_public_key_hex":public});
    let started_sha = digest(&started).unwrap();
    let pin = json!({"schema":"hol-gauntlet-controller-key-pin.v1","source_sha":expected.source_sha,
        "job_id":expected.job_id,"deployment_digest":expected.deployment_digest,"worker_generation":expected.worker_generation,
        "started_marker_sha256":started_sha,"controller_public_key_hex":public});
    let pin_sha = digest(&pin).unwrap();
    let prepared = PrelaunchPrepared {
        job_id: expected.job_id.clone(),
        source_sha: expected.source_sha.clone(),
        deployment_digest: expected.deployment_digest.clone(),
        worker_generation: expected.worker_generation.clone(),
        started_marker_sha256: started_sha.clone(),
        controller_key_pin_sha256: pin_sha.clone(),
        controller_public_key_hex: public.clone(),
    };
    let preparation = preparation.to_owned();
    let (retained, ack) = journal
        .accept_prepared(&prepared.to_bytes().unwrap(), &expected)
        .unwrap();
    let mut diagnostic = json!({"schema":"hol-gauntlet-native-deterministic-control.v1","job_id":expected.job_id,"preparation_sha256":preparation,
        "control_role":"timeout","guard_pins":{"source_sha":expected.source_sha},"status":"passed","error":null,
        "controller_identity":{"pid":241,"start_ticks":32},"execution_eligible":false,"guard_causality_verified":false,"qualified_role_complete":false,"model_requests":0});
    if readonly {
        diagnostic["schema"] = json!("hol-gauntlet-native-hook-transport.v2");
        diagnostic["pins"] = diagnostic
            .as_object_mut()
            .unwrap()
            .remove("guard_pins")
            .unwrap();
        diagnostic.as_object_mut().unwrap().remove("control_role");
        diagnostic["sdk_exercised"] = json!(false);
        diagnostic["artifact_admitted"] = json!(false);
    }
    let pins = NativeControlReportPins {
        prelaunch: prepared.clone(),
        preparation_sha256: preparation.clone(),
        role: role.into(),
    };
    let record = native_control_signing_record(&diagnostic, &pins).unwrap();
    let envelope =
        json!({"signature":STANDARD.encode(key.sign(&bytes(&record)).as_ref()),"record":record});
    let envelope_raw = String::from_utf8(bytes(&envelope)).unwrap() + "\n";
    let verified = verify_native_control_envelope(envelope_raw.as_bytes(), &pins).unwrap();
    let mut report = json!({"schema":"hol-gauntlet-native-worker-report.v7","profile":"native-host-pinned-control-v1",
        "source_sha":expected.source_sha,"job_id":expected.job_id,"deployment_digest":expected.deployment_digest,"worker_generation":expected.worker_generation,
        "started_marker_sha256":started_sha,"preparation_sha256":preparation,"controller":{"pid":241,"start_ticks":32},
        "controller_report":diagnostic,"controller_envelope_utf8":envelope_raw,
        "controller_stdout_sha256":format!("{:x}",Sha256::digest(envelope_raw.as_bytes())),
        "controller_signature_verification":verified.observation(),"controller_signature_error":null,
        "prelaunch_custody":{"prepared":serde_json::from_slice::<Value>(&prepared.to_bytes().unwrap()).unwrap(),
            "host_ack_received_before_controller_spawn":true,"acknowledgement_sha256":format!("{:x}",Sha256::digest(&ack))},
        "exit_code":0,"status":"invalid-evidence","execution_eligible":false,"guard_causality_verified":false,"model_requests":0,
        "controller_cgroup_drained":true,"product_slice_absent":true,"image_lease_absent":true,"sdk_agent_absent":true,"sdk_profile_absent":true,"mcp_agent_absent":true,"mcp_profile_absent":true});
    if readonly {
        report["schema"] = json!("hol-gauntlet-native-worker-report.v8");
        report["profile"] = json!("native-host-pinned-readonly-hook-v1");
        for field in [
            "sdk_agent_absent",
            "sdk_profile_absent",
            "mcp_agent_absent",
            "mcp_profile_absent",
        ] {
            report.as_object_mut().unwrap().remove(field);
        }
    }
    let terminal = json!({"schema":"hol-gauntlet-worker-terminal.v2","source_sha":expected.source_sha,"job_id":expected.job_id,
        "deployment_digest":expected.deployment_digest,"worker_generation":expected.worker_generation,"started_marker_sha256":started_sha,
        "controller_public_key_hex":public,"controller_key_pin_sha256":pin_sha,"report_sha256":digest(&report).unwrap(),
        "pid":241,"process_start_ticks":32,"exit_code":0,"status":"invalid-evidence"});
    let frame = json!({"schema":if readonly {"hol-gauntlet-native-host-pinned-completion.v2"}else{"hol-gauntlet-native-host-pinned-completion.v1"},"started":started,"controller_key_pin":pin,
        "terminal_sha256":digest(&terminal).unwrap(),"terminal":terminal,"report":report,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    assert_eq!(journal.read(&expected.job_id).unwrap(), retained);
    (directory, expected, preparation, frame)
}

#[test]
fn restarted_host_binds_all_public_records_but_does_not_grant_a_verdict() {
    let (directory, expected, prep, frame) = fixture();
    let journal =
        HostControllerKeyPinJournal::open(&directory.path().canonicalize().unwrap()).unwrap();
    let result = journal
        .verify_native_completion(&bytes(&frame), &expected, &prep, "timeout")
        .unwrap();
    assert_eq!(result.diagnostic()["status"], "passed");
    assert_eq!(result.observation()["host_prelaunch_tuple_bound"], true);
    assert_eq!(result.observation()["execution_eligible"], false);
    assert_eq!(result.observation()["qualified_role_complete"], false);
}

#[test]
fn bounded_completion_requires_original_initialized_storage_and_cannot_upgrade_legacy() {
    let (directory, expected, prep, mut frame) = fixture();
    let journal =
        HostControllerKeyPinJournal::open(&directory.path().canonicalize().unwrap()).unwrap();
    let original = crate::native_operation::job_storage_fixture(
        &expected.source_sha,
        &expected.job_id,
        &expected.worker_generation,
        &"a".repeat(64),
        "native-v1",
    );
    assert!(journal
        .verify_native_bounded_completion(
            &bytes(&frame),
            &expected,
            &prep,
            "timeout",
            None,
            &original
        )
        .is_err());
    frame["report"]["retained_storage"] = original.clone();
    refresh(&mut frame);
    assert!(journal
        .verify_native_completion(&bytes(&frame), &expected, &prep, "timeout")
        .is_err());
    let bound = journal
        .verify_native_bounded_completion(
            &bytes(&frame),
            &expected,
            &prep,
            "timeout",
            None,
            &original,
        )
        .unwrap();
    assert_eq!(
        bound.observation()["bounded_storage"]["receipt_sha256"],
        original["receipt_sha256"]
    );
    assert_eq!(
        bound.observation()["bounded_storage"]["profile"],
        "native-v1"
    );
    assert_eq!(
        bound.observation()["bounded_storage"]["original_initialization_bound"],
        true
    );
    assert!(!bound.observation().to_string().contains("owner_nonce_hex"));
    assert!(!bound.observation().to_string().contains(
        original["receipt"]["namespace_owner"]["owner_nonce_hex"]
            .as_str()
            .unwrap()
    ));
    assert_eq!(bound.observation()["execution_eligible"], false);
    for field in ["boot_id", "mke2fs_sha256", "namespace_owner"] {
        let mut changed = frame.clone();
        changed["report"]["retained_storage"]["receipt"][field] = Value::Null;
        let storage = &mut changed["report"]["retained_storage"];
        storage["receipt_sha256"] = json!(digest(&storage["receipt"]).unwrap());
        refresh(&mut changed);
        assert!(
            journal
                .verify_native_bounded_completion(
                    &bytes(&changed),
                    &expected,
                    &prep,
                    "timeout",
                    None,
                    &original
                )
                .is_err(),
            "{field}"
        );
    }
    let mut other = original.clone();
    other["receipt"]["namespace_owner"]["process"]["pid"] = json!(103);
    other["receipt_sha256"] = json!(digest(&other["receipt"]).unwrap());
    assert!(journal
        .verify_native_bounded_completion(&bytes(&frame), &expected, &prep, "timeout", None, &other)
        .is_err());
}

#[test]
fn self_declared_key_and_other_job_context_cannot_replace_the_host_journal() {
    let (directory, expected, prep, frame) = fixture();
    let journal =
        HostControllerKeyPinJournal::open(&directory.path().canonicalize().unwrap()).unwrap();
    let mut other = expected.clone();
    other.worker_generation = "8".repeat(64);
    assert!(journal
        .verify_native_completion(&bytes(&frame), &other, &prep, "timeout")
        .is_err());
    assert!(journal
        .verify_native_completion(&bytes(&frame), &expected, &prep, "cancel")
        .is_err());
    assert!(journal
        .verify_native_completion(&bytes(&frame), &expected, &"8".repeat(64), "timeout")
        .is_err());
    let empty = tempfile::tempdir().unwrap();
    std::fs::set_permissions(empty.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let empty = HostControllerKeyPinJournal::open(&empty.path().canonicalize().unwrap()).unwrap();
    assert!(empty
        .verify_native_completion(&bytes(&frame), &expected, &prep, "timeout")
        .is_err());
}

#[test]
fn unsigned_metadata_rehash_cannot_change_signed_controller_identity_or_effects() {
    let (directory, expected, prep, frame) = fixture();
    let journal =
        HostControllerKeyPinJournal::open(&directory.path().canonicalize().unwrap()).unwrap();
    let mut changed = frame.clone();
    changed["report"]["controller"]["pid"] = json!(242);
    changed["terminal"]["pid"] = json!(242);
    refresh(&mut changed);
    assert!(journal
        .verify_native_completion(&bytes(&changed), &expected, &prep, "timeout")
        .is_err());
    let mut changed = frame.clone();
    changed["report"]["controller_report"]["effect"] = json!({"forged":true});
    refresh(&mut changed);
    assert!(journal
        .verify_native_completion(&bytes(&changed), &expected, &prep, "timeout")
        .is_err());
    let mut changed = frame;
    changed["report"]["prelaunch_custody"]["acknowledgement_sha256"] = json!("0".repeat(64));
    refresh(&mut changed);
    assert!(journal
        .verify_native_completion(&bytes(&changed), &expected, &prep, "timeout")
        .is_err());
}

#[test]
fn missing_terminal_duplicate_fields_and_qualification_claims_refuse() {
    let (directory, expected, prep, frame) = fixture();
    let journal =
        HostControllerKeyPinJournal::open(&directory.path().canonicalize().unwrap()).unwrap();
    let mut changed = frame.clone();
    changed.as_object_mut().unwrap().remove("terminal");
    assert!(journal
        .verify_native_completion(&bytes(&changed), &expected, &prep, "timeout")
        .is_err());
    let mut changed = frame.clone();
    changed["execution_eligible"] = json!(true);
    assert!(journal
        .verify_native_completion(&bytes(&changed), &expected, &prep, "timeout")
        .is_err());
    let raw = bytes(&frame);
    let duplicate = format!(
        "{{\"terminal\":null,{}",
        std::str::from_utf8(&raw[1..]).unwrap()
    );
    assert!(journal
        .verify_native_completion(duplicate.as_bytes(), &expected, &prep, "timeout")
        .is_err());
}

fn live_fixture() -> (
    tempfile::TempDir,
    HostPrelaunchIdentity,
    String,
    Value,
    Value,
) {
    let (directory, expected, preparation, mut frame) = fixture();
    let journal =
        HostControllerKeyPinJournal::open(&directory.path().canonicalize().unwrap()).unwrap();
    let retained = journal.read(&expected.job_id).unwrap();
    let p = &retained.pins;
    let pins = NativeControlReportPins {
        prelaunch: PrelaunchPrepared {
            job_id: p.job_id.clone(),
            source_sha: p.source_sha.clone(),
            deployment_digest: p.deployment_digest.clone(),
            worker_generation: p.worker_generation.clone(),
            started_marker_sha256: p.started_marker_sha256.clone(),
            controller_key_pin_sha256: p.controller_key_pin_sha256.clone(),
            controller_public_key_hex: p.controller_public_key_hex.clone(),
        },
        preparation_sha256: preparation.clone(),
        role: "feature-ai-protected".into(),
    };
    let key = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
    let world = Ed25519KeyPair::from_seed_unchecked(&[38; 32]).unwrap();
    let cleanup = Ed25519KeyPair::from_seed_unchecked(&[39; 32]).unwrap();
    let public = |key: &Ed25519KeyPair| {
        key.public_key()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let spec = gauntlet_evidence::feature_ai_support_spec().unwrap();
    let cell = &spec["cells"][1]["id"];
    let prepared = json!({"schema":"hol-gauntlet-native-live-prepared.v2","source_sha":expected.source_sha,
        "job_id":expected.job_id,"deployment_digest":expected.deployment_digest,"worker_generation":expected.worker_generation,
        "preparation_sha256":preparation,"role":pins.role,"cell_id":cell,"spec_sha256":digest(&spec).unwrap(),
        "normal_preparation_receipt_sha256":"a".repeat(64),"world_public_key_hex":public(&world),
        "world_initial_sha256":initial_world_hash(&spec).unwrap(),"cleanup_public_key_hex":public(&cleanup)});
    let mut diagnostic = frame["report"]["controller_report"].clone();
    diagnostic["schema"] = json!("hol-gauntlet-native-live-omp.v1");
    diagnostic["control_role"] = json!(pins.role);
    diagnostic["cell_id"] = cell.clone();
    diagnostic["spec_sha256"] = prepared["spec_sha256"].clone();
    diagnostic["artifact_sha256"] = json!({});
    diagnostic["model_requests"] = json!(2);
    let record = native_control_signing_record(&diagnostic, &pins).unwrap();
    let envelope =
        json!({"record":record,"signature":STANDARD.encode(key.sign(&bytes(&record)).as_ref())});
    let raw = String::from_utf8(bytes(&envelope)).unwrap() + "\n";
    let authenticated = verify_native_control_envelope(raw.as_bytes(), &pins).unwrap();
    let task = json!({"boot_id":"unit-boot","pid":241,"start_ticks":32,"pid_namespace":19,
        "cgroup":format!("/holgauntletrust{}.slice/controller",expected.job_id)});
    let cleanup_record = json!({"schema":"hol-gauntlet-feature-ai-cleanup.v1","source_sha":expected.source_sha,
        "job_id":expected.job_id,"preparation_sha256":preparation,"cell_id":cell,
        "owned_tasks":[task],"before_tasks":[task],"after_tasks":[],
        "owned_resources":[{"kind":"cgroup","name":"unit-owned-cgroup","identity":"1:2"}],"after_resources":[]});
    frame["schema"] = json!("hol-gauntlet-native-host-pinned-completion.v3");
    frame["model_requests"] = json!(2);
    let report = &mut frame["report"];
    report["schema"] = json!("hol-gauntlet-native-worker-report.v9");
    report["profile"] = json!("native-host-pinned-live-omp-v1");
    report["model_requests"] = json!(2);
    report["controller_report"] = diagnostic;
    report["controller_envelope_utf8"] = json!(raw);
    report["controller_stdout_sha256"] = json!(format!("{:x}", Sha256::digest(raw.as_bytes())));
    report["controller_signature_verification"] = authenticated.observation();
    report["live_prepared_sha256"] = json!(digest(&prepared).unwrap());
    report["model_channel_pending"] = json!(false);
    report["live_world"] = json!({"schema":"hol-gauntlet-native-live-world-final.v1",
        "prepared_sha256":digest(&prepared).unwrap(),"world_public_key_hex":prepared["world_public_key_hex"],
        "world_initial_sha256":prepared["world_initial_sha256"],"world_final_sha256":"b".repeat(64),
        "receipt_count":2,"final_hash":"c".repeat(64),"database":{}});
    report["live_cleanup"] = json!({"record":cleanup_record,"signature":STANDARD.encode(cleanup.sign(&bytes(&cleanup_record)).as_ref())});
    refresh(&mut frame);
    (directory, expected, preparation, frame, prepared)
}

#[test]
fn live_completion_requires_outside_prepared_keys_and_actual_counted_version() {
    let (directory, expected, preparation, frame, prepared) = live_fixture();
    let journal =
        HostControllerKeyPinJournal::open(&directory.path().canonicalize().unwrap()).unwrap();
    let pin = digest(&prepared).unwrap();
    let accepted = journal
        .verify_native_live_completion(
            &bytes(&frame),
            &expected,
            &preparation,
            "feature-ai-protected",
            &prepared,
            &pin,
        )
        .unwrap();
    assert_eq!(accepted.observation()["model_requests"], 2);
    assert_eq!(accepted.observation()["qualified_role_complete"], false);
    assert_eq!(accepted.observation()["execution_eligible"], false);
    let spec = gauntlet_evidence::feature_ai_support_spec().unwrap();
    let mut wrong_order = prepared.clone();
    wrong_order["world_initial_sha256"] = json!(digest(&spec["initial_snapshot"]).unwrap());
    assert_ne!(
        wrong_order["world_initial_sha256"],
        prepared["world_initial_sha256"]
    );
    let wrong_pin = digest(&wrong_order).unwrap();
    assert!(journal
        .verify_native_live_completion(
            &bytes(&frame),
            &expected,
            &preparation,
            "feature-ai-protected",
            &wrong_order,
            &wrong_pin
        )
        .is_err());
    assert!(journal
        .verify_native_completion(
            &bytes(&frame),
            &expected,
            &preparation,
            "feature-ai-protected"
        )
        .is_err());
    assert!(journal
        .verify_native_live_completion(
            &bytes(&frame),
            &expected,
            &preparation,
            "feature-ai-protected",
            &prepared,
            &"0".repeat(64)
        )
        .is_err());
    for field in [
        "world_public_key_hex",
        "cleanup_public_key_hex",
        "world_initial_sha256",
        "normal_preparation_receipt_sha256",
    ] {
        let mut changed = prepared.clone();
        changed[field] = json!("0".repeat(64));
        assert!(
            journal
                .verify_native_live_completion(
                    &bytes(&frame),
                    &expected,
                    &preparation,
                    "feature-ai-protected",
                    &changed,
                    &pin
                )
                .is_err(),
            "{field}"
        );
    }
    for (pointer, value) in [
        (
            "/schema",
            json!("hol-gauntlet-native-host-pinned-completion.v1"),
        ),
        ("/model_requests", json!(0)),
        ("/report/model_channel_pending", json!(true)),
        ("/report/live_prepared_sha256", json!("0".repeat(64))),
        (
            "/report/live_world/world_initial_sha256",
            json!("0".repeat(64)),
        ),
        (
            "/report/live_cleanup/record/after_tasks",
            json!([{"survived":true}]),
        ),
        (
            "/report/live_cleanup/signature",
            json!(STANDARD.encode([0; 64])),
        ),
    ] {
        let mut changed = frame.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        refresh(&mut changed);
        assert!(
            journal
                .verify_native_live_completion(
                    &bytes(&changed),
                    &expected,
                    &preparation,
                    "feature-ai-protected",
                    &prepared,
                    &pin
                )
                .is_err(),
            "{pointer}"
        );
    }
}
