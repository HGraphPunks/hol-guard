use gauntlet_contracts::{canonicalize, DependencyRunIntent, DependencyRunPins};
use gauntlet_host_state::{public_vm_operations, DependencyIntentJournal};
use serde_json::json;
use std::os::unix::fs::{symlink, PermissionsExt};

fn pins(job: &str) -> DependencyRunPins {
    DependencyRunPins::from_value(json!({
        "job_id":job,"source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
        "capsule_sha256":"c".repeat(64),"capsule_bytes":1551712,"pyproject_sha256":"d".repeat(64),
        "uv_lock_sha256":"e".repeat(64),"exporter_sha256":"f".repeat(64),"capture_worker_sha256":"1".repeat(64),
        "capture_receipt_sha256":"2".repeat(64),"controller_root":"/opt/hol-gauntlet/controller-0123456789abcdef",
        "controller_tree_sha256":"3".repeat(64),"uv_base_image_id":"4".repeat(64),"rust_base_image_id":"5".repeat(64),
        "builder_image_id":format!("sha256:{}", "6".repeat(64)),"policy_sha256":"7".repeat(64),"podman_sha256":"8".repeat(64),
        "slirp4netns_sha256":"9".repeat(64),"apparmor_parser_sha256":"a".repeat(64),"seccomp_sha256":"b".repeat(64),"runner_binary_sha256":"c".repeat(64)
    })).unwrap()
}

fn transport_fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    DependencyIntentJournal,
    DependencyRunIntent,
) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let transport = root.join("limactl");
    std::fs::write(
        &transport,
        b"#!/bin/sh\n/bin/cat >/dev/null\nprintf 'attempt\\n' >> \"$0.calls\"\nexit 7\n",
    )
    .unwrap();
    std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut operations = public_vm_operations(None).unwrap();
    operations["limactl"] = json!(transport);
    let journal = DependencyIntentJournal::open(&root).unwrap();
    let intent = journal
        .record(pins("0123456789abcdef"), &operations)
        .unwrap();
    (temp, root, journal, intent)
}

fn private_reply(intent: &DependencyRunIntent) -> serde_json::Value {
    json!({"schema":"hol-gauntlet-native-dependency-result.v1",
        "job_id":intent.pins.text("job_id"),"source_sha":intent.pins.text("source_sha"),
        "intent_sha256":intent.digest().unwrap(),"intent":serde_json::from_slice::<serde_json::Value>(&intent.bytes().unwrap()).unwrap(),
        "worker_generation":intent.pins.text("runner_binary_sha256"),"status":"invalid-evidence",
        "exit_code":0,"captured_dependencies_bytes":1234,"captured_dependencies_sha256":"d".repeat(64),
        "container_absent":true,"container_cgroup_absent":true,"client_cgroup_drained":true,
        "build_profile_removed":true,"artifact_admitted":false,"execution_eligible":false,
        "guard_causality_verified":false,"model_requests":0,"other_private_field":intent.nonce})
}

fn write_reply(root: &std::path::Path, private: &serde_json::Value) -> Vec<u8> {
    let raw = canonicalize(private.to_string().as_bytes()).unwrap();
    let script = format!(
        "#!/bin/sh\n/bin/cat >/dev/null\n/bin/cat <<'REPLY'\n{}\nREPLY\n",
        String::from_utf8(raw.clone()).unwrap()
    );
    std::fs::write(root.join("limactl"), script).unwrap();
    raw
}

#[test]
fn dependency_intent_survives_restart_and_replay_preserves_exact_target_pins() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let operations = public_vm_operations(Some("hol-gauntlet-rust-build-20261026-001")).unwrap();
    let journal = DependencyIntentJournal::open(&canonical).unwrap();
    let intent = journal
        .record(pins("0123456789abcdef"), &operations)
        .unwrap();
    let path = temp.path().join("0123456789abcdef.dependency-intent.json");
    let original = std::fs::read(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        DependencyIntentJournal::open(&canonical)
            .unwrap()
            .read("0123456789abcdef")
            .unwrap(),
        intent
    );
    assert!(journal
        .record(pins("0123456789abcdef"), &operations)
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let second = journal
        .record(pins("1123456789abcdef"), &operations)
        .unwrap();
    assert_ne!(intent.nonce, second.nonce);
    assert_eq!(intent.vm, "hol-gauntlet-rust-build-20261026-001");
    std::fs::write(&path, b"{}").unwrap();
    assert!(journal.read("0123456789abcdef").is_err());
    assert!(journal
        .record(pins("0123456789abcdef"), &operations)
        .is_err());
}

#[test]
fn dependency_journal_refuses_linked_records_and_a_replaced_directory() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = canonical.join("journal");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = DependencyIntentJournal::open(&directory).unwrap();
    let outside = temp.path().join("outside");
    std::fs::write(&outside, b"retained").unwrap();
    symlink(
        &outside,
        directory.join("0123456789abcdef.dependency-intent.json"),
    )
    .unwrap();
    assert!(journal.read("0123456789abcdef").is_err());
    let operations = public_vm_operations(None).unwrap();
    assert!(journal
        .record(pins("0123456789abcdef"), &operations)
        .is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"retained");
    std::fs::rename(&directory, temp.path().join("retained-journal")).unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(journal
        .record(pins("1123456789abcdef"), &operations)
        .is_err());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
}

#[test]
fn uncertain_dependency_transport_stays_consumed_after_journal_restart() {
    let (_temp, root, journal, intent) = transport_fixture();
    std::thread::scope(|scope| {
        let attempts: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| journal.execute_once(&intent)))
            .collect();
        for attempt in attempts {
            assert!(attempt.join().unwrap().is_err());
        }
    });
    let original = std::fs::read(root.join("0123456789abcdef.dependency-intent.json")).unwrap();
    drop(journal);
    let journal = DependencyIntentJournal::open(&root).unwrap();
    let reopened = journal.read("0123456789abcdef").unwrap();
    assert_eq!(reopened, intent);
    assert!(journal.execute_once(&reopened).is_err());
    assert_eq!(
        std::fs::read(root.join("limactl.calls")).unwrap(),
        b"attempt\n"
    );
    assert_eq!(
        std::fs::read(root.join("0123456789abcdef.dependency-intent.json")).unwrap(),
        original
    );
}

#[test]
fn legacy_or_partial_dependency_records_remain_readable_without_authorizing_a_retry() {
    for kind in [
        "legacy",
        "partial",
        "symlink",
        "hardlink",
        "wrong-authorization",
    ] {
        let (_temp, root, journal, intent) = transport_fixture();
        let authorized = root.join("0123456789abcdef.dependency-authorized.json");
        let dispatch = root.join("0123456789abcdef.dependency-dispatch.json");
        let retained = root.join("retained");
        std::fs::write(&retained, b"retained").unwrap();
        match kind {
            "legacy" => std::fs::remove_file(authorized).unwrap(),
            "partial" => std::fs::write(dispatch, b"").unwrap(),
            "symlink" => symlink(&retained, dispatch).unwrap(),
            "hardlink" => std::fs::hard_link(&retained, dispatch).unwrap(),
            _ => std::fs::write(authorized, b"{}").unwrap(),
        }
        assert_eq!(journal.read("0123456789abcdef").unwrap(), intent);
        assert!(journal.execute_once(&intent).is_err());
        assert!(!root.join("limactl.calls").exists());
        assert_eq!(std::fs::read(retained).unwrap(), b"retained");
    }
}

#[test]
fn dependency_public_result_retains_private_reply_and_omits_intent_and_untyped_fields() {
    let (_temp, root, journal, intent) = transport_fixture();
    let raw = write_reply(&root, &private_reply(&intent));
    let public = journal.execute_once(&intent).unwrap();
    assert_eq!(
        public["schema"],
        "hol-gauntlet-host-dependency-run-claim.v1"
    );
    assert_eq!(public["captured_dependencies_bytes"], 1234);
    assert_eq!(public["captured_dependencies_sha256"], "d".repeat(64));
    assert_eq!(public["qualification_eligible"], false);
    assert_eq!(public["retained_result_reconciled"], false);
    assert!(!public.to_string().contains(&intent.nonce));
    assert!(public.get("intent").is_none());
    assert!(public.get("other_private_field").is_none());
    let stored = root.join("0123456789abcdef.dependency-result.json");
    assert_eq!(std::fs::read(&stored).unwrap(), raw);
    assert_eq!(
        std::fs::metadata(stored).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn dependency_unknown_exit_stays_null_without_inventing_an_export() {
    let (_temp, root, journal, intent) = transport_fixture();
    let mut private = private_reply(&intent);
    for field in [
        "exit_code",
        "captured_dependencies_bytes",
        "captured_dependencies_sha256",
    ] {
        private[field] = serde_json::Value::Null;
    }
    private["execution_error"] = json!(intent.nonce);
    write_reply(&root, &private);
    let public = journal.execute_once(&intent).unwrap();
    assert_eq!(public["status"], "invalid-evidence");
    for field in [
        "exit_code",
        "captured_dependencies_bytes",
        "captured_dependencies_sha256",
    ] {
        assert_eq!(public[field], serde_json::Value::Null);
    }
    assert!(!public.to_string().contains(&intent.nonce));
    assert!(journal.execute_once(&intent).is_err());
}

#[test]
fn malformed_dependency_public_fields_refuse_and_keep_the_attempt_consumed() {
    for field in [
        "exit_code",
        "captured_dependencies_bytes",
        "captured_dependencies_sha256",
        "status",
        "guard_causality_verified",
        "intent",
        "missing-exit",
        "missing-export",
    ] {
        let (_temp, root, journal, intent) = transport_fixture();
        let mut private = private_reply(&intent);
        match field {
            "intent" => private["intent"]["vm"] = json!("different-vm"),
            "guard_causality_verified" => private[field] = json!(true),
            "missing-exit" => {
                private.as_object_mut().unwrap().remove("exit_code");
            }
            "missing-export" => {
                private
                    .as_object_mut()
                    .unwrap()
                    .remove("captured_dependencies_bytes");
            }
            _ => private[field] = json!(intent.nonce),
        }
        write_reply(&root, &private);
        assert!(journal.execute_once(&intent).is_err(), "{field}");
        write_reply(&root, &private_reply(&intent));
        assert!(journal.execute_once(&intent).is_err(), "replayed {field}");
    }
}

fn retained_reply(intent: &DependencyRunIntent) -> serde_json::Value {
    let report = private_reply(intent);
    let raw = canonicalize(report.to_string().as_bytes()).unwrap();
    let public = gauntlet_contracts::verify_dependency_run_result(intent, &raw).unwrap();
    json!({"schema":"hol-gauntlet-native-dependency-read.v1","reader_generation":"8".repeat(64),
        "intent_sha256":intent.digest().unwrap(),"report_sha256":public["private_result_sha256"],
        "terminal_sha256":"9".repeat(64),"report":report,
        "archive_proof":{"schema":"hol-gauntlet-native-dependency-archive-readback.v1","files":1,
            "directories":0,"decoded_bytes":1234,"entry_bytes_sha256":"a".repeat(64),
            "archive_sha256":"d".repeat(64),"dependency_imported":false,
            "artifact_admitted":false,"execution_eligible":false},
        "artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,
        "guard_causality_verified":false,"model_requests":0,"model_tokens":0})
}

#[test]
fn dependency_reconciliation_reads_legacy_intents_without_authorizing_dispatch() {
    let (_temp, root, journal, intent) = transport_fixture();
    std::fs::remove_file(root.join("0123456789abcdef.dependency-authorized.json")).unwrap();
    let original = intent.bytes().unwrap();
    let reply = retained_reply(&intent);
    let raw = canonicalize(reply.to_string().as_bytes()).unwrap();
    let script = format!(
        "#!/bin/sh\numask 077\n/bin/cat > \"$0.input\"\n/bin/cat <<'REPLY'\n{}\nREPLY\n",
        String::from_utf8(raw).unwrap()
    );
    std::fs::write(root.join("limactl"), script).unwrap();
    let reader = "8".repeat(64);
    for vm in ["different-vm", "../bad", "--flag"] {
        assert!(journal
            .reconcile_read_only("0123456789abcdef", &reader, Some(vm))
            .is_err());
        assert!(!root.join("limactl.input").exists());
    }
    let public = journal
        .reconcile_read_only("0123456789abcdef", &reader, None)
        .unwrap();
    assert_eq!(std::fs::read(root.join("limactl.input")).unwrap(), original);
    assert_eq!(
        public["schema"],
        "hol-gauntlet-host-dependency-reconciled.v1"
    );
    assert_eq!(public["retained_result_reconciled"], true);
    assert_eq!(public["execution_eligible"], false);
    assert!(!public.to_string().contains(&intent.nonce));
    assert!(public.get("report").is_none());
    let name = format!("0123456789abcdef.dependency-reconciled-{reader}.json");
    let retained = std::fs::read(root.join(&name)).unwrap();
    assert_eq!(
        DependencyIntentJournal::open(&root)
            .unwrap()
            .reconcile_read_only("0123456789abcdef", &reader, Some(&intent.vm))
            .unwrap(),
        public
    );
    assert_eq!(std::fs::read(root.join(&name)).unwrap(), retained);
    assert!(!root
        .join("0123456789abcdef.dependency-dispatch.json")
        .exists());
    assert!(journal.execute_once(&intent).is_err());
    assert_eq!(journal.read("0123456789abcdef").unwrap(), intent);
}

#[test]
fn dependency_read_codec_refuses_foreign_missing_or_authoritative_frames() {
    let (_temp, _root, _journal, intent) = transport_fixture();
    let original = retained_reply(&intent);
    for field in [
        "schema",
        "reader_generation",
        "intent_sha256",
        "report_sha256",
        "terminal_sha256",
        "report-intent",
        "archive-hash",
        "archive-extra",
        "archive-count",
        "archive-authority",
        "extra",
        "missing",
        "qualification_eligible",
        "model_tokens",
    ] {
        let mut bad = original.clone();
        match field {
            "report-intent" => bad["report"]["intent"]["vm"] = json!("foreign"),
            "archive-hash" => bad["archive_proof"]["archive_sha256"] = json!("f".repeat(64)),
            "archive-extra" => bad["archive_proof"]["nonce"] = json!(intent.nonce),
            "archive-count" => bad["archive_proof"]["files"] = json!(true),
            "archive-authority" => bad["archive_proof"]["execution_eligible"] = json!(true),
            "missing" => {
                bad.as_object_mut().unwrap().remove("report_sha256");
            }
            "qualification_eligible" => bad[field] = json!(true),
            "model_tokens" => bad[field] = json!(1),
            _ => bad[field] = json!("invalid"),
        }
        let raw = canonicalize(bad.to_string().as_bytes()).unwrap();
        assert!(
            gauntlet_contracts::verify_dependency_read_response(&intent, &"8".repeat(64), &raw)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn both_dependency_read_entrypoints_refuse_foreign_vm_before_transport() {
    let (_temp, root, journal, intent) = transport_fixture();
    let original = intent.bytes().unwrap();
    for (binary, prefix) in [
        (env!("CARGO_BIN_EXE_gauntlet-host"), vec!["dependencies"]),
        (env!("CARGO_BIN_EXE_gauntlet-host-run-dependencies"), vec![]),
    ] {
        let result = std::process::Command::new(binary)
            .args(prefix)
            .arg("read")
            .arg(&root)
            .args(["0123456789abcdef", &"8".repeat(64), "--vm", "foreign-vm"])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(!root.join("limactl.calls").exists());
        assert_eq!(journal.read("0123456789abcdef").unwrap(), intent);
        assert_eq!(
            std::fs::read(root.join("0123456789abcdef.dependency-intent.json")).unwrap(),
            original
        );
    }
}
