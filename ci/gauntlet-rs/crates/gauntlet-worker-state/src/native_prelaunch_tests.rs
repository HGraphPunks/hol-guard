use super::*;
use crate::{NativeJobExecution, NativeSdkPins};
use gauntlet_cell_rootfs::{NativeControlRole, NativeGuardPins};
use std::os::unix::fs::PermissionsExt;
fn fixture() -> Option<(
    tempfile::TempDir,
    RunReservationJournal,
    NativeJobSpec,
    WorkerRequest,
)> {
    fixture_for(false)
}
fn fixture_for(
    readonly: bool,
) -> Option<(
    tempfile::TempDir,
    RunReservationJournal,
    NativeJobSpec,
    WorkerRequest,
)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let temp = tempfile::Builder::new()
        .prefix("gnative-ack-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = RunReservationJournal::open_root_owned(temp.path()).unwrap();
    let source = "a".repeat(40);
    let mut spec=NativeJobSpec {source_sha:source.clone(),job_id:"0123456789abcdef".into(),
        worker_generation:"c".repeat(64),preparation_sha256:"d".repeat(64),
        execution:NativeJobExecution::HostPinnedControl {
            guard:NativeGuardPins::parse(&json!({"schema":"hol-gauntlet-native-hook-product-pins.v1",
                "source_sha":source,"package_version":"3.57.0","native_sha256":"e".repeat(64),"bwrap_sha256":"f".repeat(64)})).unwrap(),
            sdk:NativeSdkPins{sdk_tree_sha256:"1".repeat(64),bun_sha256:"2".repeat(64),publication_sha256:"3".repeat(64)},
            role:NativeControlRole::Success}};
    if readonly {
        let NativeJobExecution::HostPinnedControl { guard, .. } = spec.execution else {
            unreachable!()
        };
        spec.execution = NativeJobExecution::HostPinnedReadonlyHook(guard);
    }
    let request = WorkerRequest::parse(
        json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
        "source_sha":source,"job_id":spec.job_id,"deployment_digest":"b".repeat(64)})
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    Some((temp, journal, spec, request))
}
fn no_controller(temp: &tempfile::TempDir) {
    let mut names = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            "0123456789abcdef.controller-key.json",
            "0123456789abcdef.started.json",
            "active.lock"
        ]
    );
}
#[test]
fn host_ack_is_checked_after_durable_key_pin_and_key_is_closed_on_failure() {
    for (readonly, fault) in [false, true].into_iter().flat_map(|readonly| {
        [
            "wrong-ack",
            "oversized",
            "lost-ack",
            "cancelled-after-ack",
            "deadline-after-ack",
        ]
        .into_iter()
        .map(move |fault| (readonly, fault))
    }) {
        let Some((temp, journal, spec, request)) = fixture_for(readonly) else {
            return;
        };
        let lease = journal.acquire_active_lease().unwrap();
        let deadline =
            BoottimeDeadline::start(if fault == "deadline-after-ack" { 1 } else { 60 }).unwrap();
        let cancelled = AtomicBool::new(false);
        let mut observed = None;
        let mut ack = |raw: &[u8], _: &BoottimeDeadline, _: &AtomicBool| {
            let prepared = PrelaunchPrepared::parse(raw).unwrap();
            let started = journal
                .started(
                    &spec.job_id,
                    &spec.source_sha,
                    &"b".repeat(64),
                    &spec.worker_generation,
                )
                .unwrap()
                .unwrap();
            let pin = crate::controller_key::read_pin(&journal, &started, true).unwrap();
            assert_eq!(pin.raw_sha256, prepared.controller_key_pin_sha256);
            assert_eq!(pin.public_key_hex, prepared.controller_public_key_hex);
            assert_eq!(prepared.started_marker_sha256, started.sha256);
            observed = Some(prepared.clone());
            match fault {
                "wrong-ack" => Ok(b"{}".to_vec()),
                "oversized" => Ok(vec![b'x'; 8193]),
                "lost-ack" => Err("simulated lost host acknowledgement".into()),
                "deadline-after-ack" => {
                    std::thread::sleep(std::time::Duration::from_millis(1100));
                    Ok(prepared
                        .acknowledgement(&prepared.host_record_sha256().unwrap())
                        .unwrap())
                }
                "cancelled-after-ack" => {
                    cancelled.store(true, Ordering::Release);
                    Ok(prepared
                        .acknowledgement(&prepared.host_record_sha256().unwrap())
                        .unwrap())
                }
                _ => unreachable!(),
            }
        };
        assert!(
            reserve_native(
                &journal,
                &lease,
                &request,
                &spec,
                &deadline,
                &cancelled,
                Some(&mut ack)
            )
            .is_err(),
            "{fault}"
        );
        assert!(observed.is_some());
        no_controller(&temp);
        assert!(journal
            .reserve_keyed_under_lease(
                &lease,
                &request,
                &spec.source_sha,
                &"b".repeat(64),
                &spec.worker_generation,
                &"f".repeat(64)
            )
            .is_err());
    }
}
#[test]
fn exact_ack_retains_only_the_sealed_key_and_cancellation_before_ack_consumes_nothing() {
    let Some((temp, journal, spec, request)) = fixture() else {
        return;
    };
    let lease = journal.acquire_active_lease().unwrap();
    let deadline = BoottimeDeadline::start(60).unwrap();
    let cancelled = AtomicBool::new(true);
    let mut ack = |raw: &[u8], _: &BoottimeDeadline, _: &AtomicBool| {
        let p = PrelaunchPrepared::parse(raw).unwrap();
        p.acknowledgement(&p.host_record_sha256().unwrap())
            .map_err(|e| e.to_string())
    };
    assert!(reserve_native(
        &journal,
        &lease,
        &request,
        &spec,
        &deadline,
        &cancelled,
        Some(&mut ack)
    )
    .is_err());
    assert!(journal
        .started(
            &spec.job_id,
            &spec.source_sha,
            &"b".repeat(64),
            &spec.worker_generation
        )
        .unwrap()
        .is_none());
    cancelled.store(false, Ordering::Release);
    let (started, custody) = reserve_native(
        &journal,
        &lease,
        &request,
        &spec,
        &deadline,
        &cancelled,
        Some(&mut ack),
    )
    .unwrap();
    let custody = custody.unwrap();
    custody.recheck(&journal, &lease, &started).unwrap();
    assert_eq!(
        custody.observation().unwrap()["host_ack_received_before_controller_spawn"],
        true
    );
    no_controller(&temp);
    use std::os::fd::AsRawFd;
    let fd = custody.descriptor().as_raw_fd();
    let held = custody.descriptor().metadata().unwrap();
    assert_eq!(held.len(), 32);
    assert!(std::process::Command::new("/usr/bin/cat")
        .arg(format!("/proc/self/fd/{fd}"))
        .output()
        .unwrap()
        .stdout
        .is_empty());
    drop(custody);
    // Other test threads may reuse the descriptor number; compare its inode.
    use std::os::unix::fs::MetadataExt;
    if let Ok(after) = std::fs::metadata(format!("/proc/self/fd/{fd}")) {
        assert_ne!((after.dev(), after.ino()), (held.dev(), held.ino()));
    }
}

#[test]
fn unsigned_readonly_failure_requires_actual_exit_and_original_host_ack() {
    let pre = PrelaunchPrepared {
        source_sha: "a".repeat(40),
        job_id: "b".repeat(16),
        deployment_digest: "c".repeat(64),
        worker_generation: "d".repeat(64),
        started_marker_sha256: "e".repeat(64),
        controller_key_pin_sha256: "f".repeat(64),
        controller_public_key_hex: "1".repeat(64),
    };
    let hash = |v: &Value| {
        crate::native_job_storage::linux::sha(
            &crate::native_job_storage::linux::canonical(v).unwrap(),
        )
    };
    let storage = json!({"receipt_sha256":"2".repeat(64)});
    let ack = pre
        .acknowledgement(&pre.host_record_sha256().unwrap())
        .unwrap();
    let mut frame = json!({"schema":"hol-gauntlet-native-host-pinned-completion.v2","terminal_sha256":"3".repeat(64),"model_requests":0,
        "terminal":{"exit_code":2,"status":"invalid-evidence"},"report":{
        "schema":"hol-gauntlet-native-worker-report.v8","profile":"native-host-pinned-readonly-hook-v1","preparation_sha256":"4".repeat(64),"retained_storage":storage,
        "exit_code":2,"status":"invalid-evidence","execution_error":null,"interruption":null,"controller_report":null,"controller_signature_verification":null,
        "controller_envelope_utf8":"","controller_stdout_sha256":crate::native_job_storage::linux::sha(b""),"controller_signature_error":"bounded native controller envelope required",
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0,"controller_cgroup_drained":true,"product_slice_absent":true,"image_lease_absent":true,
        "prelaunch_custody":{"prepared":serde_json::from_slice::<Value>(&pre.to_bytes().unwrap()).unwrap(),"host_ack_received_before_controller_spawn":true,"acknowledgement_sha256":crate::native_job_storage::linux::sha(&ack)}}});
    let report_sha = hash(&frame["report"]);
    frame["terminal"]["report_sha256"] = json!(report_sha);
    let p = ReadonlyFailurePins(
        json!({"preparation_sha256":"4".repeat(64),"terminal_sha256":"3".repeat(64),"report_sha256":report_sha}),
    );
    let check = |f: &Value, p: &ReadonlyFailurePins| {
        crate::native_completion::validate_readonly_failure(f, p, &pre, &storage)
    };
    check(&frame, &p).unwrap();
    for (pointer, bad) in [
        (
            "/report/schema",
            json!("hol-gauntlet-native-worker-report.v9"),
        ),
        ("/report/profile", json!("native-host-pinned-live-omp-v1")),
        ("/report/execution_error", json!("synthetic worker failure")),
        ("/report/interruption", json!("deadline")),
        ("/report/controller_report", json!({})),
        ("/report/controller_signature_error", Value::Null),
        (
            "/report/controller_envelope_utf8",
            json!("unsigned replacement"),
        ),
        (
            "/report/prelaunch_custody/acknowledgement_sha256",
            json!("0".repeat(64)),
        ),
        (
            "/report/prelaunch_custody/host_ack_received_before_controller_spawn",
            json!(false),
        ),
        (
            "/report/retained_storage",
            json!({"receipt_sha256":"0".repeat(64)}),
        ),
        ("/report/controller_cgroup_drained", json!(false)),
        ("/model_requests", json!(1)),
    ] {
        let mut changed = frame.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        let digest = hash(&changed["report"]);
        changed["terminal"]["report_sha256"] = json!(digest);
        let mut pins = ReadonlyFailurePins(p.0.clone());
        pins.0["report_sha256"] = json!(digest);
        assert!(check(&changed, &pins).is_err(), "{pointer}");
    }
    for bad in [json!(-1), json!(0), Value::Null, json!(256)] {
        let mut changed = frame.clone();
        changed["report"]["exit_code"] = bad.clone();
        changed["terminal"]["exit_code"] = bad;
        let digest = hash(&changed["report"]);
        changed["terminal"]["report_sha256"] = json!(digest);
        let mut pins = ReadonlyFailurePins(p.0.clone());
        pins.0["report_sha256"] = json!(digest);
        assert!(check(&changed, &pins).is_err());
    }
    let mut changed = ReadonlyFailurePins(p.0.clone());
    changed.0["terminal_sha256"] = json!("0".repeat(64));
    assert!(check(&frame, &changed).is_err());
}
