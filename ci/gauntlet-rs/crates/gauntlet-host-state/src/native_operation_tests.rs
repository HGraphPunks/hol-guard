use super::*;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

pub(super) fn intent(job: &str, path: &Path) -> Intent {
    let vm = "hol-native-fixture";
    match fs::create_dir(path.join(vm)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => panic!("{e}"),
    }
    Intent::parse(&bytes(&json!({"schema":"hol-gauntlet-host-native-intent.v1","job_id":job,
        "source_sha":"2".repeat(40),"deployment_digest":"3".repeat(64),"worker_generation":"4".repeat(64),
        "preparation_sha256":"7".repeat(64),"role":"timeout","vm":"hol-native-fixture","limactl":"/opt/homebrew/bin/limactl",
        "lima_sha256":"8".repeat(64),"interpreter_sha256":"9".repeat(64),"observer_sha256":"a".repeat(64),
        "transport_context":context::TransportContext::from_paths(path,path,vm).unwrap().value()})).unwrap()).unwrap()
}
pub(super) fn journal() -> (tempfile::TempDir, Journal) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = Journal::open(&path).unwrap();
    (temp, journal)
}
fn record_args(path: &Path) -> Vec<String> {
    let i = intent(&"1".repeat(16), path);
    vec![
        "record".into(),
        path.to_str().unwrap().into(),
        i.text("vm").into(),
        i.text("lima_sha256").into(),
        i.text("source_sha").into(),
        i.job().into(),
        i.text("deployment_digest").into(),
        i.text("worker_generation").into(),
        i.text("preparation_sha256").into(),
        i.text("role").into(),
        i.text("interpreter_sha256").into(),
        i.text("observer_sha256").into(),
        path.to_str().unwrap().into(),
        path.to_str().unwrap().into(),
    ]
}
fn install(journal: &Journal, intent: &Intent) {
    journal
        .write(intent.job(), "intent", &intent.raw().unwrap())
        .unwrap();
    journal
        .write(
            intent.job(),
            "dispatch",
            &Journal::dispatch_raw(intent).unwrap(),
        )
        .unwrap();
}

#[test]
fn record_has_only_public_identity_and_restart_preserves_original_vm_and_pins() {
    let (_temp, j) = journal();
    let args = record_args(&j.path);
    let value = run_native_operation_command(&args).unwrap();
    let expected = intent(&"1".repeat(16), &j.path);
    assert_eq!(
        value,
        json!({"schema":"hol-gauntlet-host-deterministic-record.v1","job_id":expected.job(),
        "source_sha":expected.text("source_sha"),"intent_sha256":expected.digest().unwrap(),"next_operation":"prepare",
        "execution_eligible":false,"qualification_eligible":false})
    );
    let before = j.read(expected.job(), "intent").unwrap();
    let mut changed = args.clone();
    changed[2] = "hol-other-fixture".into();
    assert!(run_native_operation_command(&changed).is_err());
    assert_eq!(j.read(expected.job(), "intent").unwrap(), before);
    let reopened = Journal::open(&j.path).unwrap();
    assert_eq!(
        reopened.intent(expected.job()).unwrap().text("vm"),
        "hol-native-fixture"
    );
    assert_eq!(
        fs::metadata(
            j.path
                .join(Journal::name(expected.job(), "intent").unwrap())
        )
        .unwrap()
        .permissions()
        .mode()
            & 0o777,
        0o600
    );
    assert!(!value.to_string().contains("controller_public_key_hex"));
}

#[test]
fn malformed_operations_refuse_before_opening_a_private_journal() {
    let (_temp, j) = journal();
    for args in [
        vec![
            "run".into(),
            j.path.to_str().unwrap().into(),
            "bad".into(),
            "a".repeat(64),
        ],
        vec![
            "read".into(),
            j.path.to_str().unwrap().into(),
            "1".repeat(16),
            "bad".into(),
        ],
        vec![
            "repair".into(),
            j.path.to_str().unwrap().into(),
            "1".repeat(16),
            "a".repeat(64),
            "bad".into(),
        ],
        vec![
            "report".into(),
            j.path.to_str().unwrap().into(),
            "1".repeat(16),
            "a".repeat(64),
            "relative".into(),
            "b".repeat(64),
        ],
        vec![
            "run".into(),
            j.path.to_str().unwrap().into(),
            "1".repeat(16),
            "a".repeat(64),
            "--vm".into(),
            "hol-other".into(),
        ],
    ] {
        assert!(run_native_operation_command(&args).is_err());
    }
    assert_eq!(fs::read_dir(&j.path).unwrap().count(), 0);
    let mut args = record_args(&j.path);
    args[9] = "model-inference".into();
    assert!(run_native_operation_command(&args).is_err());
    assert_eq!(fs::read_dir(&j.path).unwrap().count(), 1);
}

#[test]
fn owner_lock_refuses_concurrent_operations_and_replacement() {
    let (_temp, mut first) = journal();
    first.lock().unwrap();
    let mut second = Journal::open(&first.path).unwrap();
    assert!(second.lock().is_err());
    fs::rename(
        first.path.join("native-operation.lock"),
        first.path.join("saved.lock"),
    )
    .unwrap();
    fs::write(first.path.join("native-operation.lock"), b"").unwrap();
    fs::set_permissions(
        first.path.join("native-operation.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(first.stable().is_err());
    assert!(first
        .write(
            &"1".repeat(16),
            "intent",
            &intent(&"1".repeat(16), &first.path).raw().unwrap()
        )
        .is_err());
}

#[test]
fn unknown_and_partial_dispatches_block_every_new_native_run_after_restart() {
    for kind in ["unknown", "partial", "linked", "hardlinked"] {
        let (_temp, j) = journal();
        let i = intent(&"1".repeat(16), &j.path);
        j.write(i.job(), "intent", &i.raw().unwrap()).unwrap();
        let path = j.path.join(Journal::name(i.job(), "dispatch").unwrap());
        let saved = j.path.join("preserved");
        fs::write(&saved, b"preserve").unwrap();
        match kind {
            "unknown" => j
                .write(i.job(), "dispatch", &Journal::dispatch_raw(&i).unwrap())
                .unwrap(),
            "partial" => fs::write(&path, b"").unwrap(),
            "linked" => symlink(&saved, &path).unwrap(),
            _ => fs::hard_link(&saved, &path).unwrap(),
        }
        let fresh = intent(&"b".repeat(16), &j.path);
        j.write(fresh.job(), "intent", &fresh.raw().unwrap())
            .unwrap();
        let restarted = Journal::open(&j.path).unwrap();
        assert!(restarted.require_idle().is_err(), "{kind}");
        assert!(j
            .write(i.job(), "dispatch", &Journal::dispatch_raw(&i).unwrap())
            .is_err());
        assert_eq!(fs::read(saved).unwrap(), b"preserve");
    }
}

#[test]
fn concurrent_dispatch_creation_has_exactly_one_durable_winner() {
    let (_temp, j) = journal();
    let i = intent(&"1".repeat(16), &j.path);
    j.write(i.job(), "intent", &i.raw().unwrap()).unwrap();
    let attempts = std::thread::scope(|scope| {
        let jobs = (0..4)
            .map(|_| {
                scope.spawn(|| j.write(i.job(), "dispatch", &Journal::dispatch_raw(&i).unwrap()))
            })
            .collect::<Vec<_>>();
        jobs.into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(attempts.iter().filter(|v| v.is_ok()).count(), 1);
    let before = j.read(i.job(), "dispatch").unwrap();
    assert_eq!(before, Journal::dispatch_raw(&i).unwrap());
    assert!(Journal::open(&j.path).unwrap().require_idle().is_err());
    assert_eq!(j.read(i.job(), "dispatch").unwrap(), before);
}

#[test]
fn only_authenticated_complete_cleanup_resolves_a_consumed_dispatch() {
    let (temp, _, _, frame) = crate::native_control_readback::tests::fixture_for("timeout");
    let path = temp.path().canonicalize().unwrap();
    let j = Journal::open(&path).unwrap();
    let i = intent(&"1".repeat(16), &j.path);
    install(&j, &i);
    assert!(j.require_idle().is_err());
    let result = j.observe(&i, "run", &bytes(&frame).unwrap()).unwrap();
    assert_eq!(result["next_operation"], "report");
    assert_eq!(result["execution_eligible"], false);
    assert!(result.get("completion").is_none());
    assert!(result.get("host_pin").is_none());
    assert!(!result.to_string().contains("controller_public_key_hex"));
    assert!(j.require_idle().is_ok());
    let reopened = Journal::open(&path).unwrap();
    assert!(reopened.require_idle().is_ok());
    assert_eq!(
        reopened.read(i.job(), "completion").unwrap(),
        bytes(&frame).unwrap()
    );
    let mut changed = i.clone();
    changed.0["preparation_sha256"] = json!("a".repeat(64));
    assert!(reopened.verify(&changed, &bytes(&frame).unwrap()).is_err());
    assert!(j
        .write(i.job(), "dispatch", &Journal::dispatch_raw(&i).unwrap())
        .is_err());
}

#[test]
fn forged_or_unclean_completion_is_preserved_without_resolving_unknown_work() {
    for mutation in ["signature", "cleanup", "role"] {
        let (temp, _, _, mut frame) = crate::native_control_readback::tests::fixture_for("timeout");
        let j = Journal::open(&temp.path().canonicalize().unwrap()).unwrap();
        let i = intent(&"1".repeat(16), &j.path);
        install(&j, &i);
        match mutation {
            "signature" => frame["report"]["controller_stdout_sha256"] = json!("f".repeat(64)),
            "cleanup" => frame["report"]["product_slice_absent"] = json!(false),
            _ => frame["report"]["controller_report"]["control_role"] = json!("success"),
        }
        let raw = bytes(&frame).unwrap();
        assert!(j.observe(&i, "run", &raw).is_err());
        assert_eq!(j.read(i.job(), "return").unwrap(), raw);
        assert!(j.absent(i.job(), "completion").unwrap());
        assert!(Journal::open(&j.path).unwrap().require_idle().is_err());
    }
}

#[test]
fn native_storage_accepts_its_bound_without_expanding_historical_private_readers() {
    let (_temp, j) = journal();
    let raw = vec![b'x'; 1024 * 1024 + 1];
    let job = "1".repeat(16);
    j.write(&job, "completion", &raw).unwrap();
    assert_eq!(j.read(&job, "completion").unwrap(), raw);
    assert!(crate::private_jobs::read_regular_bytes(
        &j.root,
        &Journal::name(&job, "completion").unwrap(),
        j.owner
    )
    .is_err());
    assert!(write_private_once_bounded(&j.root, "oversize.json", b"x", LIMIT + 1).is_err());
    assert!(!j.path.join("oversize.json").exists());
}

#[test]
fn fixed_transport_joins_dispatch_keyed_execution_restart_readback_and_sanitized_result() {
    use super::transport::Lima;
    let (_signed, _, _, frame) = crate::native_control_readback::tests::fixture_for("timeout");
    let (_temp, j) = journal();
    let path = j.path.join("fixture-lima");
    let script=b"#!/bin/sh\nprintf x >> \"$0.calls\"\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ntest -s \"$0.dispatch\" || exit 4\nIFS= read -r request || exit 2\nprintf '%s\\n' \"$request\" > \"$0.request\"\ncase \"$*\" in\n*--read-native-host-pinned-v1*) cat \"$0.completion\";;\n*) cat \"$0.prepared\"; IFS= read -r ack || exit 3; test -n \"$ack\" || exit 3; cat \"$0.completion\";;\nesac\n";
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut i = intent(&"1".repeat(16), &j.path);
    i.0["lima_sha256"] = json!(sha(script));
    install(&j, &i);
    let mut prepared = bytes(&frame["report"]["prelaunch_custody"]["prepared"]).unwrap();
    prepared.push(b'\n');
    fs::write(path.with_extension("prepared"), prepared).unwrap();
    let mut completion = bytes(&frame).unwrap();
    completion.push(b'\n');
    fs::write(path.with_extension("completion"), &completion).unwrap();
    symlink(
        j.path.join(Journal::name(i.job(), "dispatch").unwrap()),
        path.with_extension("dispatch"),
    )
    .unwrap();
    let mut lima = Lima::open_path(path.clone(), &sha(script), &i.0["transport_context"]).unwrap();
    let output = transport::execute(&j, &i, &mut lima, true).unwrap();
    assert_eq!(output, completion);
    let value = j.observe(&i, "run", &output).unwrap();
    assert_eq!(value["next_operation"], "report");
    assert!(value.get("host_pin").is_none());
    assert!(value.get("completion").is_none());
    let expected_argv=format!("shell\nhol-native-fixture\n--\nsudo\n-n\n/opt/hol-gauntlet/rust-native-host-pinned-worker-{}\n--native-host-pinned-v1\n{}\n{}\n{}\n",i.text("worker_generation"),i.text("source_sha"),i.text("deployment_digest"),i.text("worker_generation"));
    assert_eq!(
        fs::read_to_string(path.with_extension("argv")).unwrap(),
        expected_argv
    );
    let reopened = Journal::open(&j.path).unwrap();
    assert!(reopened.require_idle().is_ok());
    let read = transport::execute(&reopened, &i, &mut lima, false).unwrap();
    assert_eq!(
        j.observe(&i, "read", &read).unwrap()["completion_sha256"],
        value["completion_sha256"]
    );
    assert!(transport::execute(&reopened, &i, &mut lima, true).is_err());
    let mut other = i.clone();
    other.0["vm"] = json!("hol-other-fixture");
    assert!(transport::execute(&reopened, &other, &mut lima, false).is_err());
    assert_eq!(fs::read(path.with_extension("calls")).unwrap(), b"xx");
}

#[test]
fn lima_descriptor_rejects_wrong_pin_replacement_links_and_writable_binary() {
    use super::transport::Lima;
    let (_temp, j) = journal();
    let path = j.path.join("lima");
    fs::write(&path, b"inert transport fixture").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let digest = sha(b"inert transport fixture");
    let i = intent(&"1".repeat(16), &j.path);
    let home = context::TransportContext::parse(&i.0["transport_context"]).unwrap();
    let context = home.value();
    assert!(Lima::open_path(path.clone(), &"a".repeat(64), context).is_err());
    let mut lima = Lima::open_path(path.clone(), &digest, context).unwrap();
    fs::rename(&path, path.with_extension("saved")).unwrap();
    fs::write(&path, b"inert transport fixture").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(lima.recheck().is_err());
    fs::hard_link(&path, path.with_extension("hard")).unwrap();
    assert!(Lima::open_path(path.clone(), &digest, context).is_err());
    let writable = path.with_extension("writable");
    fs::write(&writable, b"inert transport fixture").unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o720)).unwrap();
    assert!(Lima::open_path(writable, &digest, context).is_err());
    let link = path.with_extension("link");
    symlink(&path, &link).unwrap();
    assert!(Lima::open_path(link, &digest, context).is_err());
}

#[test]
fn keyed_repairs_resolve_only_the_original_unknown_job_without_inventing_an_exit() {
    for startup in [false, true] {
        let (temp, _, _, frame) = crate::native_control_readback::tests::fixture_for("timeout");
        let j = Journal::open(&temp.path().canonicalize().unwrap()).unwrap();
        let i = intent(&"1".repeat(16), &j.path);
        install(&j, &i);
        let authorization = transport::repair_intent(&i, &"e".repeat(64), startup).unwrap();
        j.write(i.job(), "repair-intent", &authorization).unwrap();
        j.write(i.job(), "repair-dispatch", &authorization).unwrap();
        let cleanup = if startup {
            json!({"untouched":{"workspace_empty":true,"only_preparation_and_workspace":true},"controller_marker_absent":true,
                "controller_logs_absent":true,"controller_cgroup_absent":true,"product_slice_absent":true,"product_stage_absent":true,
                "sdk_container_and_profile_absent":true,"mcp_container_and_profile_absent":true,"image_lease_absent":true,"public_key_retained":true})
        } else {
            json!({"quiescent":{"image_history":"recovered-pending-v1"},"image_unmounted":true,"active_pointer_absent":true,"active_pointer_sha256":"b".repeat(64),
                "controller_process_absent":true,"controller_cgroup_absent":true,"product_slice_absent":true,"sdk_agent_absent":true,"sdk_profile_absent":true,
                "mcp_agent_absent":true,"mcp_profile_absent":true,"image_lease_absent":true,"public_key_retained":true})
        };
        let mut receipt = json!({"schema":if startup {"hol-gauntlet-native-keyed-pre-controller-repair.v1"}else{"hol-gauntlet-native-keyed-worker-repair.v1"},
            "prelaunch":frame["report"]["prelaunch_custody"]["prepared"],"preparation_sha256":i.text("preparation_sha256"),"repair_generation":"e".repeat(64),
            "status":"aborted","controller_state":if startup {"never-released"}else{"released-exit-unavailable"},"exit_code":null,
            "model_requests":0,"execution_eligible":false,"guard_causality_verified":false,"cleanup":cleanup});
        if !startup {
            receipt["running_marker_sha256"] = json!("a".repeat(64));
            receipt["artifact_admitted"] = json!(false);
            receipt["qualification_eligible"] = json!(false);
        }
        let raw = bytes(&receipt).unwrap();
        let result = transport::verify_repair(&j, &i, &raw).unwrap();
        assert_eq!(result["status"], "aborted");
        assert_eq!(result["exit_code"], Value::Null);
        assert_eq!(result["retry_allowed"], false);
        assert_eq!(result["execution_eligible"], false);
        assert!(!result.to_string().contains("controller_public_key_hex"));
        assert!(j.require_idle().is_err());
        for (pointer, bad) in [
            ("/prelaunch/source_sha", json!("9".repeat(40))),
            (
                "/prelaunch/controller_public_key_hex",
                json!("9".repeat(64)),
            ),
            ("/preparation_sha256", json!("9".repeat(64))),
            ("/repair_generation", json!("9".repeat(64))),
            ("/status", json!("passed")),
            ("/exit_code", json!(0)),
            ("/cleanup/product_slice_absent", json!(false)),
            ("/execution_eligible", json!(true)),
        ] {
            let mut changed = receipt.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(
                transport::verify_repair(&j, &i, &bytes(&changed).unwrap()).is_err(),
                "{pointer}"
            );
        }
        j.write(i.job(), "repair", &raw).unwrap();
        assert!(Journal::open(&j.path).unwrap().require_idle().is_ok());
        assert!(j
            .write(i.job(), "dispatch", &Journal::dispatch_raw(&i).unwrap())
            .is_err());
        assert_eq!(j.read(i.job(), "repair").unwrap(), raw);
    }
}

#[test]
fn readonly_hook_completion_is_bound_to_explicit_host_role_and_version() {
    use crate::native_control_readback::tests::{fixture_for, refresh};
    let raw = |v: &Value| bytes(v).unwrap();
    let (directory, expected, prep, frame) = fixture_for("readonly-utility");
    let journal =
        HostControllerKeyPinJournal::open(&directory.path().canonicalize().unwrap()).unwrap();
    let result = journal
        .verify_native_completion(&raw(&frame), &expected, &prep, "readonly-utility")
        .unwrap();
    assert_eq!(
        result.observation()["schema"],
        "hol-gauntlet-host-native-control-readback.v2"
    );
    assert_eq!(result.diagnostic()["sdk_exercised"], false);
    assert_eq!(result.observation()["execution_eligible"], false);
    assert!(journal
        .verify_native_completion(&raw(&frame), &expected, &prep, "success")
        .is_err());
    for (pointer, value) in [
        (
            "/schema",
            json!("hol-gauntlet-native-host-pinned-completion.v1"),
        ),
        (
            "/report/schema",
            json!("hol-gauntlet-native-worker-report.v7"),
        ),
        ("/report/profile", json!("native-host-pinned-control-v1")),
        ("/report/controller_report/sdk_exercised", json!(true)),
        ("/report/controller/pid", json!(242)),
        (
            "/report/prelaunch_custody/acknowledgement_sha256",
            json!("0".repeat(64)),
        ),
        ("/report/product_slice_absent", json!(false)),
    ] {
        let mut changed = frame.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        refresh(&mut changed);
        assert!(
            journal
                .verify_native_completion(&raw(&changed), &expected, &prep, "readonly-utility")
                .is_err(),
            "{pointer}"
        );
    }
}
