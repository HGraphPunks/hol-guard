//! Live proof of the private read-only buffer path, using a pinned synthetic ELF.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeMap;
use std::io::Read;

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

fn start(mode: &str, wrong: bool) -> (PathBuf, Fixture, NativeProcessEvents) {
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

fn save(stage: &Path, result: &Value) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(stage.join("stdio-test-result.json"))
        .unwrap();
    file.write_all(result.to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();
}

fn gone(fixture: &Fixture) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while crate::kernel_process::alive(&fixture.pidfd).unwrap() {
        assert!(Instant::now() < deadline, "owned stdio fixture still alive");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn scalar_and_vectored_snapshots_match_both_actual_parent_pipe_streams() {
    for mode in ["stdio-scalar", "stdio-vector"] {
        let (stage, mut fixture, mut recorder) = start(mode, false);
        fixture.release();
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
        assert_eq!(result["schema"], "hol-gauntlet-native-process-events.v2");
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
