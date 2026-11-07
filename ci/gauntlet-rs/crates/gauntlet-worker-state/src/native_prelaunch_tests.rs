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
    let spec=NativeJobSpec {source_sha:source.clone(),job_id:"0123456789abcdef".into(),
        worker_generation:"c".repeat(64),preparation_sha256:"d".repeat(64),
        execution:NativeJobExecution::HostPinnedControl {
            guard:NativeGuardPins::parse(&json!({"schema":"hol-gauntlet-native-hook-product-pins.v1",
                "source_sha":source,"package_version":"3.57.0","native_sha256":"e".repeat(64),"bwrap_sha256":"f".repeat(64)})).unwrap(),
            sdk:NativeSdkPins{sdk_tree_sha256:"1".repeat(64),bun_sha256:"2".repeat(64),publication_sha256:"3".repeat(64)},
            role:NativeControlRole::Success}};
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
    for fault in [
        "wrong-ack",
        "oversized",
        "lost-ack",
        "cancelled-after-ack",
        "deadline-after-ack",
    ] {
        let Some((temp, journal, spec, request)) = fixture() else {
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
