use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
fn pins(id: &str) -> FeatureRunPins {
    let spec = json!({"schema":"hol-gauntlet-feature-executor.v1","audit_id":id,
        "source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
        "candidate_archive_sha256":"c".repeat(64),"wheel_sha256":"d".repeat(64),
        "native_sha256":"e".repeat(64),"executor_sha256":"f".repeat(64),"version":"3.58.0",
        "catalog_sha256":gauntlet_contracts::FEATURE_CATALOG_SHA256,
        "node_sha256":gauntlet_contracts::FEATURE_NODE_SHA256});
    let mut p = json!({"executor_spec":spec,"build_job_id":"0123456789abcdee",
        "controller_root":"/opt/hol-gauntlet/controller-0123456789abcdee",
        "builder_image_id":format!("sha256:{}","a".repeat(64))});
    for k in [
        "build_result_sha256",
        "controller_tree_sha256",
        "uv_base_image_id",
        "rust_base_image_id",
        "policy_sha256",
        "podman_sha256",
        "slirp4netns_sha256",
        "apparmor_parser_sha256",
        "seccomp_sha256",
        "runner_binary_sha256",
    ] {
        p[k] = json!("b".repeat(64));
    }
    FeatureRunPins::from_value(p).unwrap()
}
#[test]
fn private_feature_intent_survives_restart_and_consumed_ids_preserve_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ops = crate::public_vm_operations(Some("owned-vm")).unwrap();
    let journal = FeatureIntentJournal::open(&path).unwrap();
    let intent = journal.record(pins("0123456789abcdef"), &ops).unwrap();
    assert_eq!(
        FeatureIntentJournal::open(&path)
            .unwrap()
            .read("0123456789abcdef")
            .unwrap(),
        intent
    );
    let original = std::fs::read(path.join("0123456789abcdef.feature-intent.json")).unwrap();
    assert!(journal.record(pins("0123456789abcdef"), &ops).is_err());
    journal.dispatch(&intent).unwrap();
    let restarted = FeatureIntentJournal::open(&path).unwrap();
    assert!(restarted.dispatch(&intent).is_err());
    assert_eq!(
        std::fs::read(path.join("0123456789abcdef.feature-intent.json")).unwrap(),
        original
    );
}
#[test]
fn transport_failure_leaves_consumed_dispatch_and_never_implicitly_retries() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let transport = path.join("limactl");
    std::fs::write(&transport, b"#!/bin/sh\ncat >/dev/null\nexit 2\n").unwrap();
    std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut ops = crate::public_vm_operations(Some("owned-vm")).unwrap();
    ops["limactl"] = json!(transport.to_str().unwrap());
    let journal = FeatureIntentJournal::open(&path).unwrap();
    let intent = journal.record(pins("0123456789abcdef"), &ops).unwrap();
    let mut args = vec![
        "run".into(),
        path.to_str().unwrap().into(),
        "0123456789abcdef".into(),
        "0".repeat(64),
    ];
    assert!(run_feature_audit_command(&args)
        .unwrap_err()
        .contains("digest differs"));
    let dispatch = path.join("0123456789abcdef.feature-dispatch.json");
    assert!(!dispatch.exists());
    args[3] = intent.digest().unwrap();
    assert!(run_feature_audit_command(&args)
        .unwrap_err()
        .contains("uncertain"));
    let original = std::fs::read(&dispatch).unwrap();
    assert!(run_feature_audit_command(&args)
        .unwrap_err()
        .contains("consumed"));
    assert_eq!(std::fs::read(dispatch).unwrap(), original);
}

#[test]
fn feature_record_command_keeps_nonce_private_and_preserves_consumed_intent() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pins_path = path.join("pins.json");
    std::fs::write(&pins_path, pins("0123456789abcdef").value().to_string()).unwrap();
    std::fs::set_permissions(&pins_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let args = vec![
        "record".into(),
        path.to_str().unwrap().into(),
        pins_path.to_str().unwrap().into(),
        "owned-vm".into(),
    ];
    let result = run_feature_audit_command(&args).unwrap();
    let journal = FeatureIntentJournal::open(&path).unwrap();
    let intent = journal.read("0123456789abcdef").unwrap();
    assert_eq!(
        result,
        json!({"schema":"hol-gauntlet-host-feature-record.v1",
            "audit_id":"0123456789abcdef","source_sha":"a".repeat(40),
            "intent_sha256":intent.digest().unwrap(),
            "execution_eligible":false,"qualification_eligible":false})
    );
    let private: Value = serde_json::from_slice(&intent.bytes().unwrap()).unwrap();
    assert!(!result
        .to_string()
        .contains(private["host_nonce_hex"].as_str().unwrap()));
    let original = std::fs::read(path.join("0123456789abcdef.feature-intent.json")).unwrap();
    assert!(run_feature_audit_command(&args).is_err());
    assert_eq!(
        std::fs::read(path.join("0123456789abcdef.feature-intent.json")).unwrap(),
        original
    );
    assert!(!path.join("0123456789abcdef.feature-dispatch.json").exists());
    for malformed in [vec![], vec!["unknown".into()], args[..3].to_vec(), {
        let mut extra = args.clone();
        extra.push("unexpected".into());
        extra
    }] {
        assert_eq!(
            run_feature_audit_command(&malformed).unwrap_err(),
            FEATURE_AUDIT_USAGE
        );
    }
}
#[test]
fn read_reconciles_only_a_completed_result_after_consumed_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let transport = path.join("limactl");
    std::fs::write(
        &transport,
        b"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\ncat \"$0.reply\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut ops = crate::public_vm_operations(Some("owned-vm")).unwrap();
    ops["limactl"] = json!(transport.to_str().unwrap());
    let journal = FeatureIntentJournal::open(&path).unwrap();
    let intent = journal.record(pins("0123456789abcdef"), &ops).unwrap();
    assert!(journal.read_retained(&intent).is_err());
    assert!(!path.join("limactl.args").exists());
    journal.dispatch(&intent).unwrap();
    let dispatch = path.join("0123456789abcdef.feature-dispatch.json");
    let original_dispatch = std::fs::read(&dispatch).unwrap();
    std::fs::write(&dispatch, b"{}").unwrap();
    assert!(journal.read_retained(&intent).is_err());
    assert!(!path.join("limactl.args").exists());
    std::fs::write(&dispatch, original_dispatch).unwrap();
    let result = json!({"schema":"hol-gauntlet-native-feature-result.v1",
        "audit_id":intent.pins().audit_id(),"source_sha":intent.pins().spec().text("source_sha"),
        "intent_sha256":intent.digest().unwrap(),"worker_generation":intent.pins().text("runner_binary_sha256"),
        "container_id":"a".repeat(64),"client_pid":123,"client_start_ticks":1,
        "exit_code":1,"execution_error":"synthetic-check","audit_status":"invalid-evidence",
        "feature_report_sha256":null,"feature_readback_sha256":null,
        "stdout_sha256":"b".repeat(64),"stderr_sha256":"c".repeat(64),
        "feature_artifacts_verified":false,"container_absent":true,
        "container_cgroup_absent":true,"client_cgroup_drained":true,
        "build_profile_removed":true,"status":"invalid-evidence","rust_root_supervised":true,
        "artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,
        "guard_causality_verified":false,"model_requests":0,"model_tokens":0});
    let reply = path.join("limactl.reply");
    let mut wrong = result.clone();
    wrong["intent_sha256"] = json!("d".repeat(64));
    let mut raw = canonicalize(wrong.to_string().as_bytes()).unwrap();
    raw.push(b'\n');
    std::fs::write(&reply, raw).unwrap();
    assert!(journal.read_retained(&intent).is_err());
    assert!(!path.join("0123456789abcdef.feature-result.json").exists());
    let expected = canonicalize(result.to_string().as_bytes()).unwrap();
    let mut raw = expected.clone();
    raw.push(b'\n');
    std::fs::write(&reply, raw).unwrap();
    assert_eq!(journal.read_retained(&intent).unwrap(), result);
    assert_eq!(
        std::fs::read(path.join("0123456789abcdef.feature-result.json")).unwrap(),
        expected
    );
    assert_eq!(journal.read_retained(&intent).unwrap(), result);
    let argv = std::fs::read_to_string(path.join("limactl.args")).unwrap();
    assert!(argv.contains("\n--read\n0123456789abcdef\n"));
    assert!(!argv.contains("--run"));
    assert!(journal.repair(&intent, &"d".repeat(64)).is_err());
    assert!(!path.join("0123456789abcdef.feature-repair.json").exists());
    assert_eq!(
        std::fs::read_to_string(path.join("limactl.args")).unwrap(),
        argv
    );
    std::fs::write(path.join("0123456789abcdef.feature-result.json"), b"{}").unwrap();
    assert!(journal.read_retained(&intent).is_err());
}
#[test]
fn linked_or_changed_host_state_blocks_before_any_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = FeatureIntentJournal::open(&path).unwrap();
    let outside = path.join("outside");
    std::fs::write(&outside, b"retained").unwrap();
    symlink(&outside, path.join("0123456789abcdef.feature-intent.json")).unwrap();
    assert!(journal.read("0123456789abcdef").is_err());
    let ops = crate::public_vm_operations(None).unwrap();
    assert!(journal.record(pins("0123456789abcdef"), &ops).is_err());
    assert_eq!(std::fs::read(outside).unwrap(), b"retained");
    let wrong = json!({"build_memory_gib":1});
    assert!(journal.record(pins("1123456789abcdef"), &wrong).is_err());
}

#[test]
fn repair_reconciles_aborted_audit_only_with_durable_outside_authorization() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let transport = path.join("limactl");
    std::fs::write(
        &transport,
        b"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\ncat \"$0.reply\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut ops = crate::public_vm_operations(Some("owned-vm")).unwrap();
    ops["limactl"] = json!(transport.to_str().unwrap());
    let journal = FeatureIntentJournal::open(&path).unwrap();
    let intent = journal.record(pins("0123456789abcdef"), &ops).unwrap();
    let generation = "d".repeat(64);
    assert!(journal.repair(&intent, &generation).is_err());
    assert!(!path.join("limactl.args").exists());
    journal.dispatch(&intent).unwrap();
    let dispatch = path.join("0123456789abcdef.feature-dispatch.json");
    let original = std::fs::read(&dispatch).unwrap();
    let receipt = json!({"schema":"hol-gauntlet-native-feature-repair.v1",
        "audit_id":intent.pins().audit_id(),"source_sha":intent.pins().spec().text("source_sha"),
        "intent_sha256":intent.digest().unwrap(),"worker_generation":intent.pins().text("runner_binary_sha256"),
        "repair_generation":generation,"running_sha256":"a".repeat(64),"container_id":"e".repeat(64),
        "status":"aborted","exit_code":null,"quiescent":true,"artifact_admitted":false,
        "execution_eligible":false,"qualification_eligible":false,"guard_causality_verified":false,
        "model_requests":0,"model_tokens":0});
    let mut raw = canonicalize(receipt.to_string().as_bytes()).unwrap();
    raw.push(b'\n');
    std::fs::write(path.join("limactl.reply"), &raw).unwrap();
    assert!(journal.read_retained(&intent).is_err()); // guest cannot authorize repair
    let result = path.join("0123456789abcdef.feature-result.json");
    assert!(!result.exists());
    assert!(journal.repair(&intent, "../worker").is_err());
    let authorization = path.join("0123456789abcdef.feature-repair.json");
    assert!(!authorization.exists());
    // A failed transport preserves its cleanup authorization and original dispatch.
    std::fs::write(path.join("limactl.reply"), b"transport failed\n").unwrap();
    assert!(journal.repair(&intent, &generation).is_err());
    let authorized = std::fs::read(&authorization).unwrap();
    assert!(!result.exists());
    std::fs::write(path.join("limactl.reply"), &raw).unwrap();
    let restarted = FeatureIntentJournal::open(&path).unwrap();
    assert_eq!(restarted.repair(&intent, &generation).unwrap(), receipt);
    assert_eq!(restarted.read_retained(&intent).unwrap(), receipt);
    assert_eq!(restarted.repair(&intent, &generation).unwrap(), receipt);
    let result_bytes = std::fs::read(&result).unwrap();
    assert_eq!(result_bytes, &raw[..raw.len() - 1]);
    let argv = std::fs::read_to_string(path.join("limactl.args")).unwrap();
    assert!(argv.contains(&format!("/rust-feature-worker-{generation}\n--repair\n")));
    assert!(!argv.contains("--run"));
    assert!(restarted.execute_once(&intent).is_err());
    assert!(restarted.repair(&intent, &"e".repeat(64)).is_err());
    assert_eq!(
        std::fs::read_to_string(path.join("limactl.args")).unwrap(),
        argv
    );
    // Partial or substituted cleanup authorization refuses before transport.
    std::fs::write(&authorization, b"{").unwrap();
    assert!(restarted.read_retained(&intent).is_err());
    assert!(restarted.repair(&intent, &generation).is_err());
    assert_eq!(
        std::fs::read_to_string(path.join("limactl.args")).unwrap(),
        argv
    );
    std::fs::write(&authorization, authorized).unwrap();
    let mut changed = receipt.clone();
    changed["quiescent"] = json!(false);
    let mut raw = canonicalize(changed.to_string().as_bytes()).unwrap();
    raw.push(b'\n');
    std::fs::write(path.join("limactl.reply"), raw).unwrap();
    assert!(restarted.read_retained(&intent).is_err());
    assert_eq!(std::fs::read(result).unwrap(), result_bytes);
    assert_eq!(std::fs::read(dispatch).unwrap(), original);
}
