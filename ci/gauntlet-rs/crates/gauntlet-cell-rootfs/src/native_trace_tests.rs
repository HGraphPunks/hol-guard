//! These opt-in tests require Root in the owned VM and an outside-pinned ELF.
use crate::native_trace::NativeProcessEvents;
use crate::Result;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
    pidfd: OwnedFd,
}
impl Fixture {
    fn start(mode: &str) -> Self {
        crate::kernel_process::root_proc().unwrap();
        let path = std::env::var("HOL_GAUNTLET_PROCESS_TRACE_FIXTURE")
            .expect("outside-pinned fixture path");
        let digest = std::env::var("HOL_GAUNTLET_PROCESS_TRACE_FIXTURE_SHA256")
            .expect("outside-pinned fixture SHA256");
        let raw = crate::fs_input::pinned(Path::new(&path), 16 * 1024 * 1024, &digest).unwrap();
        assert_eq!(&raw[..4], b"\x7fELF");
        let mut command = Command::new(path);
        command
            .arg(mode)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        unsafe {
            command.pre_exec(|| {
                for capability in 0..64 {
                    if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0
                        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(10004, 10004, 10004) != 0
                    || libc::setresuid(10004, 10004, 10004) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                let zero = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let pidfd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "trace-fixture-ready\n");
        Self {
            child,
            reader,
            pidfd,
        }
    }
    fn cgroup(&self) -> String {
        let raw = std::fs::read_to_string(format!("/proc/{}/cgroup", self.child.id())).unwrap();
        raw.trim().strip_prefix("0::").unwrap().to_owned()
    }
    fn release(&mut self) {
        self.child.stdin.as_mut().unwrap().write_all(b"G").unwrap();
    }
    fn success(&mut self, rows: &[Value]) {
        assert!(
            rows.iter().any(|r| r["kind"] == "task-final-wait"
                && r["data"]["tid"] == self.child.id()
                && r["data"]["death_observed"] == true
                && r["data"]["status"] == serde_json::json!({"kind":"exit","code":0})),
            "the actual anchor's final wait must prove exit zero"
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    assert!(status.success(), "{status}");
                    return;
                }
                Ok(None) => {}
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                    // Tracer and real parent are threads of this same test
                    // process. Linux reports the final status only once.
                    assert!(!crate::kernel_process::alive(&self.pidfd).unwrap());
                    return;
                }
                Err(error) => panic!("fixture wait failed: {error}"),
            }
            assert!(Instant::now() < deadline, "owned fixture exit deadline");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if crate::kernel_process::alive(&self.pidfd).unwrap_or(false) {
            let _ = rustix::process::pidfd_send_signal(&self.pidfd, rustix::process::Signal::KILL);
        }
        let _ = self.child.wait();
    }
}

fn stage(label: &str) -> PathBuf {
    let root = PathBuf::from(
        std::env::var("HOL_GAUNTLET_PROCESS_TRACE_PROOF_ROOT").expect("owned proof root"),
    );
    crate::fs_input::directory(&root).unwrap();
    let path = root.join(format!("{label}-{}", crate::nonce().unwrap()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    path
}

fn records(stage: &Path) -> Vec<Value> {
    let raw = std::fs::read_to_string(stage.join("native-process-events.v1.jsonl")).unwrap();
    raw.split_inclusive('\n')
        .filter(|line| line.ends_with('\n'))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn run(mode: &str) -> (Value, Vec<Value>) {
    let stage = stage(mode);
    let mut fixture = Fixture::start(mode);
    let mut recorder =
        NativeProcessEvents::start_fixture(fixture.child.id(), fixture.cgroup(), &stage).unwrap();
    fixture.release();
    let report = recorder.finish(Duration::from_secs(8)).unwrap();
    let rows = records(&stage);
    fixture.success(&rows);
    assert_eq!(report["complete"], true);
    assert_eq!(report["execution_eligible"], false);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(stage.join("result.json"))
        .unwrap();
    file.write_all(report.to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();
    assert_eq!(
        report["created_tasks"].as_u64().unwrap(),
        report["final_waits"].as_u64().unwrap() + report["exec_retirements"].as_u64().unwrap()
    );
    (report, rows)
}

#[test]
fn fork_vfork_detach_exec_signal_and_short_lived_descendants_have_final_waits() {
    let (report, rows) = run("fork-tree");
    assert_eq!(report["created_tasks"], 5);
    assert_eq!(report["final_waits"], 5);
    assert_eq!(report["execs"], 1);
    assert!(rows
        .iter()
        .any(|r| r["kind"] == "kernel-creation" && r["data"]["creation"] == "vfork"));
    assert!(rows
        .iter()
        .any(|r| r["kind"] == "signal-delivery" && r["data"]["signal"] == libc::SIGTRAP));
    assert!(rows
        .iter()
        .any(|r| r["kind"] == "task-final-wait" && r["data"]["status"]["signal"] == libc::SIGTRAP));
    assert!(rows
        .iter()
        .filter(|r| r["kind"] == "task-exit-stop")
        .all(|r| r["data"]["death_observed"] == false));
}

#[test]
fn nonleader_exec_records_the_replaced_leader_without_inventing_its_final_wait() {
    let (report, rows) = run("thread-exec");
    assert_eq!(report["created_tasks"], 2);
    assert_eq!(report["final_waits"], 1);
    assert_eq!(report["exec_retirements"], 1);
    let exec = rows.iter().find(|r| r["kind"] == "task-exec").unwrap();
    assert_ne!(
        exec["data"]["old_tid"],
        exec["data"]["image"]["task"]["tid"]
    );
    assert_eq!(exec["data"]["retired"][0]["final_wait_observed"], false);
}

#[test]
fn seized_group_stop_and_sigcont_preserve_tracee_behavior() {
    let (report, rows) = run("group-stop");
    assert_eq!(report["final_waits"], 2);
    assert!(rows
        .iter()
        .any(|r| r["kind"] == "seized-stop" && r["data"]["signal"] == libc::SIGSTOP));
    assert!(rows
        .iter()
        .any(|r| r["kind"] == "signal-delivery" && r["data"]["signal"] == libc::SIGCONT));
}

#[test]
fn sixty_four_serial_children_are_recorded_even_when_each_exits_immediately() {
    let (report, _) = run("rapid-exit");
    assert_eq!(report["created_tasks"], 65);
    assert_eq!(report["final_waits"], 65);
}

#[test]
fn lost_recorder_kills_owned_descendants_and_refuses_completeness() {
    let stage = stage("lost-recorder");
    let mut fixture = Fixture::start("linger");
    let mut sentinel = Fixture::start("linger");
    let recorder =
        NativeProcessEvents::start_fixture(fixture.child.id(), fixture.cgroup(), &stage).unwrap();
    fixture.release();
    let mut line = String::new();
    fixture.reader.read_line(&mut line).unwrap();
    assert_eq!(line, "trace-fixture-descendant-created\n");
    let deadline = Instant::now() + Duration::from_secs(5);
    let child = loop {
        let rows = records(&stage);
        if let Some(row) = rows.iter().find(|r| r["kind"] == "task-created") {
            break row["data"]["task"]["tid"].as_u64().unwrap() as u32;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    };
    let fd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(child as i32).unwrap(),
        rustix::process::PidfdFlags::empty(),
    )
    .unwrap();
    drop(recorder);
    while crate::kernel_process::alive(&fd).unwrap() {
        assert!(
            Instant::now() < deadline,
            "EXITKILL did not terminate the owned descendant"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!fixture.child.wait().unwrap().success());
    assert!(sentinel.child.try_wait().unwrap().is_none());
    let rows = records(&stage);
    assert!(rows.iter().any(|r| r["kind"] == "trace-failed"));
    assert!(!rows.iter().any(|r| r["kind"] == "trace-complete"));
}

#[test]
fn wrong_cgroup_cannot_attach_or_change_an_unrelated_fixture() {
    let stage = stage("wrong-cgroup");
    let mut sentinel = Fixture::start("linger");
    let outcome: Result<_> = NativeProcessEvents::start_fixture(
        sentinel.child.id(),
        "/system.slice/not-an-owned-cell.service".into(),
        &stage,
    );
    assert!(outcome.is_err());
    assert!(sentinel.child.try_wait().unwrap().is_none());
    let status = std::fs::read_to_string(format!("/proc/{}/status", sentinel.child.id())).unwrap();
    assert!(status.lines().any(|line| line == "TracerPid:\t0"));
}
