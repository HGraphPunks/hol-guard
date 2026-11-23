//! Owned Linux fixtures for snapshots and the separate Root pipe data plane.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::AtomicBool;

const FRAME: &[u8] = b"\0\0\0\x09{\"x\":123}";

fn io_rows(stage: &Path) -> Vec<Value> {
    let raw = std::fs::read_to_string(stage.join("native-stdio-events.v1.jsonl")).unwrap();
    raw.split_inclusive('\n')
        .filter(|v| v.ends_with('\n'))
        .map(|v| serde_json::from_str(v).unwrap())
        .collect()
}

fn captured(rows: &[Value], direction: &str) -> Vec<u8> {
    let calls = rows
        .iter()
        .filter(|r| r["kind"] == "stdio-call" && r["data"]["direction"] == direction)
        .map(|r| r["data"]["call"].as_u64().unwrap())
        .collect::<Vec<_>>();
    rows.iter()
        .filter(|r| {
            r["kind"] == "stdio-bytes" && calls.contains(&r["data"]["call"].as_u64().unwrap())
        })
        .flat_map(|r| {
            STANDARD
                .decode(r["data"]["base64"].as_str().unwrap())
                .unwrap()
        })
        .collect()
}

pub(super) fn start(mode: &str, wrong: bool) -> (PathBuf, Fixture, NativeProcessEvents) {
    let stage = stage(&format!("native-{mode}"));
    let fixture = Fixture::start(mode);
    let native = if wrong {
        "c".repeat(64)
    } else {
        std::env::var("HOL_GAUNTLET_PROCESS_TRACE_FIXTURE_SHA256").unwrap()
    };
    let recorder = NativeProcessEvents::start_stdio_fixture(
        fixture.child.id(),
        fixture.cgroup(),
        &stage,
        &native,
    )
    .unwrap();
    (stage, fixture, recorder)
}

pub(super) fn save(stage: &Path, result: &Value) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(stage.join("stdio-test-result.json"))
        .unwrap();
    file.write_all(result.to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();
}

pub(super) fn gone(fixture: &Fixture) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while crate::kernel_process::alive(&fixture.pidfd).unwrap() {
        assert!(Instant::now() < deadline, "owned stdio fixture still alive");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn selected(stage: &Path, recorder: &NativeProcessEvents) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        recorder.check().unwrap();
        if io_rows(stage)
            .iter()
            .any(|row| row["kind"] == "stdio-selected")
        {
            return;
        }
        assert!(Instant::now() < deadline, "owned stdio exec not selected");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn scalar_and_vectored_snapshots_match_both_actual_parent_pipe_streams() {
    for mode in ["stdio-scalar", "stdio-vector"] {
        let (stage, mut fixture, mut recorder) = start(mode, false);
        fixture.release();
        // The driver's buffered stdin must consume only its gate byte. Wait
        // for the observed exec before sending any leaf payload.
        selected(&stage, &recorder);
        fixture
            .child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(FRAME)
            .unwrap();
        drop(fixture.child.stdin.take());
        let result = recorder.finish(Duration::from_secs(5)).unwrap();
        let mut output = Vec::new();
        fixture.reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, FRAME);
        let rows = io_rows(&stage);
        assert_eq!(captured(&rows, "read"), FRAME);
        assert_eq!(captured(&rows, "write"), output);
        assert_eq!(result["schema"], "hol-gauntlet-native-process-events.v3");
        assert_eq!(
            result["task_isolation_schema"],
            "hol-gauntlet-native-task-isolation.v1"
        );
        assert_eq!(result["native_stdio"]["counts"]["streams"], 1);
        assert_eq!(result["native_stdio"]["counts"]["bytes"], FRAME.len() * 2);
        assert_eq!(
            result["native_stdio"]["declaration"]["atomic_kernel_pipe_bytes_verified"],
            false
        );
        fixture.success(&records(&stage));
        save(&stage, &result);
    }
}

#[test]
fn nonblocking_short_write_credits_only_the_real_completed_prefix() {
    let (stage, mut fixture, mut recorder) = start("stdio-partial", false);
    fixture.release();
    // Do not drain until death: the fixture's nonblocking oversized write
    // must fill its small pipe and return a real short count.
    let result = recorder.finish(Duration::from_secs(5)).unwrap();
    let mut output = Vec::new();
    fixture.reader.read_to_end(&mut output).unwrap();
    assert!(!output.is_empty() && output.len() < 128 * 1024);
    assert!(output.iter().all(|v| *v == b'P'));
    let rows = io_rows(&stage);
    assert_eq!(captured(&rows, "write"), output);
    let calls = rows
        .iter()
        .filter(|r| r["kind"] == "stdio-call")
        .map(|r| {
            (
                r["data"]["call"].as_u64().unwrap(),
                r["data"]["requested"].as_u64().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert!(rows.iter().any(|r| r["kind"] == "stdio-transfer"
        && r["data"]["completed"]
            .as_u64()
            .is_some_and(|n| n > 0 && n < calls[&r["data"]["call"].as_u64().unwrap()])));
    fixture.success(&records(&stage));
    save(&stage, &result);
}

type RelayFixture = (
    [std::os::fd::OwnedFd; 4],
    [std::fs::File; 4],
    [(u64, u64); 4],
);

fn relay_fixture() -> RelayFixture {
    use std::os::fd::{FromRawFd, OwnedFd};
    fn pipe() -> [OwnedFd; 2] {
        let mut pair = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        pair.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
    }
    let [a_read, a_write] = pipe();
    let [b_read, b_write] = pipe();
    let [c_read, c_write] = pipe();
    let [d_read, d_write] = pipe();
    let ends = [a_read, b_write, c_read, d_write];
    let expected = ends.each_ref().map(|fd| {
        let s = rustix::fs::fstat(fd).unwrap();
        (s.st_dev, s.st_ino)
    });
    (
        ends,
        [a_write.into(), b_read.into(), c_write.into(), d_read.into()],
        expected,
    )
}

#[test]
#[ignore = "requires initial Linux Root for an owned Native pipe data-plane fixture"]
fn root_native_pipe_relay_preserves_actual_bytes_backpressure_and_eof() {
    use crate::NativePipeEvent;
    let (ends, peers, expected) = relay_fixture();
    let [mut source, mut native_input, mut native_output, mut destination] = peers;
    let input = (0..200_000).map(|v| (v % 251) as u8).collect::<Vec<_>>();
    let reply = input.iter().rev().copied().collect::<Vec<_>>();
    let expected_input = input.clone();
    let expected_reply = reply.clone();
    let native = std::thread::spawn(move || {
        let mut actual = Vec::new();
        native_input.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected_input);
        native_output.write_all(&reply).unwrap();
    });
    let client = std::thread::spawn(move || {
        source.write_all(&input).unwrap();
        drop(source);
        let mut actual = Vec::new();
        destination.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected_reply);
    });
    let mut reads = [Vec::new(), Vec::new()];
    let mut writes = [Vec::new(), Vec::new()];
    let mut ended = [false; 2];
    let counts = crate::relay_native_pipe_bytes(
        ends,
        expected,
        Instant::now() + Duration::from_secs(5),
        &AtomicBool::new(false),
        |event| {
            match event {
                NativePipeEvent::Read {
                    direction,
                    offset,
                    bytes,
                } => {
                    assert_eq!(offset, reads[direction].len());
                    reads[direction].extend_from_slice(bytes);
                }
                NativePipeEvent::BeforeWrite {
                    direction,
                    offset,
                    bytes,
                } => {
                    assert_eq!(offset, writes[direction].len());
                    assert_eq!(bytes, &reads[direction][offset..offset + bytes.len()]);
                }
                NativePipeEvent::Write {
                    direction,
                    offset,
                    bytes,
                } => {
                    assert_eq!(offset, writes[direction].len());
                    writes[direction].extend_from_slice(bytes);
                }
                NativePipeEvent::Eof { direction, bytes } => {
                    assert!(!ended[direction]);
                    assert_eq!(bytes, reads[direction].len());
                    assert_eq!(reads[direction], writes[direction]);
                    ended[direction] = true;
                }
            }
            Ok(())
        },
    )
    .unwrap();
    native.join().unwrap();
    client.join().unwrap();
    assert_eq!(reads, writes);
    assert_eq!(counts.read, [200_000; 2]);
    assert_eq!(counts.written, counts.read);
    assert_eq!(ended, [true; 2]);
}

#[test]
#[ignore = "requires initial Linux Root for owned pipe failure and closure checks"]
fn root_native_pipe_relay_refuses_before_forward_and_closes_all_owned_ends() {
    let (ends, peers, expected) = relay_fixture();
    let [mut source, mut input, output, mut destination] = peers;
    source.write_all(b"must not reach Native").unwrap();
    drop(source);
    let error = crate::relay_native_pipe_bytes(
        ends,
        expected,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
        |event| {
            if matches!(event, crate::NativePipeEvent::BeforeWrite { .. }) {
                return Err("outside peer changed".into());
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error, "outside peer changed");
    let mut received = Vec::new();
    input.read_to_end(&mut received).unwrap();
    destination.read_to_end(&mut received).unwrap();
    assert!(received.is_empty());
    drop(output);
    for cancelled in [false, true] {
        let (ends, _peers, expected) = relay_fixture();
        let error = crate::relay_native_pipe_bytes(
            ends,
            expected,
            Instant::now() + Duration::from_millis(20),
            &AtomicBool::new(cancelled),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.contains(if cancelled { "cancelled" } else { "deadline" }));
    }
    let (ends, _peers, mut expected) = relay_fixture();
    expected[0] = (0, 0);
    assert!(crate::relay_native_pipe_bytes(
        ends,
        expected,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
        |_| panic!("wrong endpoint dispatched")
    )
    .is_err());
}

fn refused(mode: &str, wrong: bool) {
    let (stage, mut fixture, mut recorder) = start(mode, wrong);
    fixture.release();
    let error = recorder.finish(Duration::from_secs(5)).unwrap_err();
    gone(&fixture);
    let rows = io_rows(&stage);
    assert!(!rows.iter().any(|r| r["kind"] == "stdio-bytes"));
    assert!(rows.iter().any(|r| r["kind"] == "stdio-failed"));
    save(
        &stage,
        &serde_json::json!({"expected_refusal":true,"error":error,
        "execution_eligible":false,"target_pipe_bytes_credited":0}),
    );
}

#[test]
fn replacing_stdout_with_a_nonpipe_refuses_before_buffer_copy() {
    refused("stdio-rebind", false);
}

#[test]
fn wrong_prelaunch_elf_digest_refuses_before_buffer_copy() {
    refused("stdio-scalar", true);
}

#[test]
fn excessive_requested_write_refuses_before_buffer_copy() {
    refused("stdio-oversize", false);
}

#[test]
fn killed_pending_read_is_interrupted_and_never_supplies_bytes_or_eof() {
    let (stage, mut fixture, mut recorder) = start("stdio-linger", false);
    fixture.release();
    let mut output = vec![0; FRAME.len()];
    fixture.reader.read_exact(&mut output).unwrap();
    assert_eq!(output, FRAME);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !io_rows(&stage)
        .iter()
        .any(|r| r["kind"] == "stdio-call" && r["data"]["direction"] == "read")
    {
        assert!(Instant::now() < deadline, "owned pending read not observed");
        std::thread::sleep(Duration::from_millis(1));
    }
    rustix::process::pidfd_send_signal(&fixture.pidfd, rustix::process::Signal::KILL).unwrap();
    let result = recorder.finish(Duration::from_secs(5)).unwrap();
    gone(&fixture);
    let rows = io_rows(&stage);
    assert!(captured(&rows, "read").is_empty());
    assert_eq!(captured(&rows, "write"), output);
    assert!(rows.iter().any(|r| r["kind"] == "stdio-ended"
        && r["data"]["interrupted_stdio_call"].as_u64().is_some()
        && r["data"]["pipe_eof_inferred"] == false));
    save(&stage, &result);
}

#[test]
#[ignore = "requires a fresh pinned preparation and actual unprivileged Native in the owned ARM VM"]
fn root_native_pipe_live_hook_preserves_normal_product_execution() {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::Arc;
    crate::require_outside_root().unwrap();
    let path = PathBuf::from(std::env::var("HOL_GAUNTLET_NATIVE_WIRE_PREPARATION").unwrap());
    let pin = std::env::var("HOL_GAUNTLET_NATIVE_WIRE_PREPARATION_SHA256").unwrap();
    let pins_path = PathBuf::from(std::env::var("HOL_GAUNTLET_NATIVE_WIRE_PRODUCT_PINS").unwrap());
    let pins_pin = std::env::var("HOL_GAUNTLET_NATIVE_WIRE_PRODUCT_PINS_SHA256").unwrap();
    let raw = crate::fs_input::pinned(&path, 49152, &pin).unwrap();
    let preparation = crate::CellPreparation::parse(&raw, &pin).unwrap();
    let launch = preparation.supervisor(&"0".repeat(64)).unwrap();
    assert_eq!(launch["schema"], "hol-gauntlet-cell-supervisor.v5");
    let pins_raw = crate::fs_input::pinned(&pins_path, 4096, &pins_pin).unwrap();
    let pins = crate::NativeGuardPins::parse(&serde_json::from_slice(&pins_raw).unwrap()).unwrap();
    let attempt =
        crate::run_native_hook_transport(&path, &pin, &pins, Arc::new(AtomicBool::new(false)));
    let value = match &attempt {
        Ok(report) => report.report.clone(),
        Err(error) => {
            serde_json::json!({"status":"failed","error":error,"execution_eligible":false})
        }
    };
    let output = path
        .parent()
        .unwrap()
        .join("native-wire-live-result.v1.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)
        .unwrap();
    file.write_all(value.to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();
    let report = attempt.unwrap();
    assert_eq!(report.error, None, "{}", report.report);
    assert_eq!(report.report["status"], "passed");
    assert_eq!(
        report.report["plane"]["schema"],
        "hol-gauntlet-native-hook-plane.v4"
    );
    assert_eq!(
        report.report["plane"]["native_pipe_bytes"]["available"],
        true
    );
    assert_eq!(report.report["cell_cleanup_complete"], true);
    if preparation.control_profile() == gauntlet_evidence::NativeContainmentRoute::PythonReadonlyV1
    {
        assert_eq!(
            report.report["schema"],
            "hol-gauntlet-native-hook-transport.v2"
        );
        assert_eq!(
            report.report["fixture"]["schema"],
            "hol-gauntlet-native-contained-fixture.v7"
        );
        assert_eq!(report.report["effect"]["write_probe_absent"], true);
        assert_eq!(
            report.report["measurements"]["unprotected_write_positive"]["retired"],
            true
        );
        assert_eq!(
            report.report["plane"]["containment_contract"]["required_execution_profile"],
            "python-eval-readonly-v1"
        );
    } else {
        assert_eq!(
            report.report["schema"],
            "hol-gauntlet-native-hook-transport.v1"
        );
    }
    assert_eq!(report.report["execution_eligible"], false);
    assert_eq!(report.report["model_requests"], 0);
}

#[test]
#[ignore = "requires the retained failed startup, drained resources and outside preparation pin in the owned VM"]
fn root_native_pipe_failed_start_recovers_only_its_quiescent_image() {
    use std::os::unix::fs::OpenOptionsExt;
    crate::require_outside_root().unwrap();
    let path = PathBuf::from(std::env::var("HOL_GAUNTLET_NATIVE_WIRE_PREPARATION").unwrap());
    let pin = std::env::var("HOL_GAUNTLET_NATIVE_WIRE_PREPARATION_SHA256").unwrap();
    let raw = crate::fs_input::pinned(&path, 49152, &pin).unwrap();
    let preparation = crate::CellPreparation::parse(&raw, &pin).unwrap();
    assert_eq!(
        crate::native_preparation_image_history(&preparation).unwrap(),
        crate::NativeImageHistory::Pending
    );
    assert!(crate::verify_closed_native_preparation(&preparation).is_err());
    let before = crate::fs_input::read(
        &preparation.stage.join("native-supervisor-events.v1.jsonl"),
        64 * 1024 * 1024,
    )
    .unwrap();
    let recovery = crate::recover_quiescent_preparation(&preparation).unwrap();
    assert_eq!(recovery["image_unmounted"], true);
    assert_eq!(recovery["active_pointer_absent"], true);
    assert_eq!(
        crate::verify_quiescent_preparation(&preparation).unwrap(),
        recovery["quiescent"]
    );
    let after = crate::fs_input::read(
        &preparation.stage.join("native-supervisor-events.v1.jsonl"),
        64 * 1024 * 1024,
    )
    .unwrap();
    assert_eq!(
        before, after,
        "recovery must preserve the failed startup history"
    );
    let output = path
        .parent()
        .unwrap()
        .join("native-wire-recovery-result.v1.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)
        .unwrap();
    let value = serde_json::json!({"recovery":recovery,"startup_history_unchanged":true,"workload_replayed":false,"execution_eligible":false});
    file.write_all(value.to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();
}
