use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_evidence::{native_control_signing_record, verify_native_control_envelope};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::os::unix::fs::PermissionsExt;

fn bytes(value: &Value) -> Vec<u8> {
    canonicalize(value.to_string().as_bytes()).unwrap()
}
fn refresh(frame: &mut Value) {
    frame["terminal"]["report_sha256"] = json!(digest(&frame["report"]).unwrap());
    frame["terminal_sha256"] = json!(digest(&frame["terminal"]).unwrap());
}
fn fixture() -> (tempfile::TempDir, HostPrelaunchIdentity, String, Value) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostControllerKeyPinJournal::open(&path).unwrap();
    let expected = HostPrelaunchIdentity {
        job_id: "1".repeat(16),
        source_sha: "2".repeat(40),
        deployment_digest: "3".repeat(64),
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
    let preparation = "7".repeat(64);
    let (retained, ack) = journal
        .accept_prepared(&prepared.to_bytes().unwrap(), &expected)
        .unwrap();
    let diagnostic = json!({"schema":"hol-gauntlet-native-deterministic-control.v1","job_id":expected.job_id,"preparation_sha256":preparation,
        "control_role":"timeout","guard_pins":{"source_sha":expected.source_sha},"status":"passed","error":null,
        "controller_identity":{"pid":241,"start_ticks":32},"execution_eligible":false,"guard_causality_verified":false,"qualified_role_complete":false,"model_requests":0});
    let pins = NativeControlReportPins {
        prelaunch: prepared.clone(),
        preparation_sha256: preparation.clone(),
        role: "timeout".into(),
    };
    let record = native_control_signing_record(&diagnostic, &pins).unwrap();
    let envelope =
        json!({"signature":STANDARD.encode(key.sign(&bytes(&record)).as_ref()),"record":record});
    let envelope_raw = String::from_utf8(bytes(&envelope)).unwrap() + "\n";
    let verified = verify_native_control_envelope(envelope_raw.as_bytes(), &pins).unwrap();
    let report = json!({"schema":"hol-gauntlet-native-worker-report.v7","profile":"native-host-pinned-control-v1",
        "source_sha":expected.source_sha,"job_id":expected.job_id,"deployment_digest":expected.deployment_digest,"worker_generation":expected.worker_generation,
        "started_marker_sha256":started_sha,"preparation_sha256":preparation,"controller":{"pid":241,"start_ticks":32},
        "controller_report":diagnostic,"controller_envelope_utf8":envelope_raw,
        "controller_stdout_sha256":format!("{:x}",Sha256::digest(envelope_raw.as_bytes())),
        "controller_signature_verification":verified.observation(),"controller_signature_error":null,
        "prelaunch_custody":{"prepared":serde_json::from_slice::<Value>(&prepared.to_bytes().unwrap()).unwrap(),
            "host_ack_received_before_controller_spawn":true,"acknowledgement_sha256":format!("{:x}",Sha256::digest(&ack))},
        "exit_code":0,"status":"invalid-evidence","execution_eligible":false,"guard_causality_verified":false,"model_requests":0,
        "controller_cgroup_drained":true,"product_slice_absent":true,"image_lease_absent":true,"sdk_agent_absent":true,"sdk_profile_absent":true,"mcp_agent_absent":true,"mcp_profile_absent":true});
    let terminal = json!({"schema":"hol-gauntlet-worker-terminal.v2","source_sha":expected.source_sha,"job_id":expected.job_id,
        "deployment_digest":expected.deployment_digest,"worker_generation":expected.worker_generation,"started_marker_sha256":started_sha,
        "controller_public_key_hex":public,"controller_key_pin_sha256":pin_sha,"report_sha256":digest(&report).unwrap(),
        "pid":241,"process_start_ticks":32,"exit_code":0,"status":"invalid-evidence"});
    let frame = json!({"schema":"hol-gauntlet-native-host-pinned-completion.v1","started":started,"controller_key_pin":pin,
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
