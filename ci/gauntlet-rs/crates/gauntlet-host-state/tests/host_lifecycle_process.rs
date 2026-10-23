//! Real process boundaries: exclusive lease, crash recovery and durable stop.

use gauntlet_contracts::canonicalize;
use gauntlet_host_state::{HostLifecycleError as Error, HostLifecycleStore};
use rustix::fs::{flock, FlockOperation};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn parent() -> TempDir {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

fn command(parent: &Path, action: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gauntlet-host"));
    command.arg(action).arg("--state-parent").arg(parent);
    command
}

fn run(parent: &Path, action: &str) -> Output {
    command(parent, action).output().unwrap()
}

fn status(store: &HostLifecycleStore) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match store.status(now()) {
            Ok(value) => return value,
            Err(Error::Busy) if Instant::now() < deadline => sleep(Duration::from_millis(10)),
            result => panic!("status unavailable: {result:?}"),
        }
    }
}

struct OwnedChild(Option<Child>);
impl OwnedChild {
    fn start(parent: &Path) -> Self {
        Self(Some(
            command(parent, "agent")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }
    fn wait(&mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return self.0.take().unwrap().wait_with_output().unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "owned observer did not stop within its bound"
            );
            sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            if child.try_wait().ok().flatten().is_none() {
                child.kill().expect("stop only this test-owned observer");
                child.wait().expect("reap test-owned observer");
            }
        }
    }
}

fn online(store: &HostLifecycleStore, child: &mut OwnedChild) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if status(store)["observer"]["status"] == "online" {
            return;
        }
        assert!(
            child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "observer exited before readiness"
        );
        assert!(
            Instant::now() < deadline,
            "observer did not acquire its lease"
        );
        sleep(Duration::from_millis(10));
    }
}

#[test]
fn cli_lease_is_exclusive_across_processes_and_down_is_a_durable_request() {
    let parent = parent();
    let init = command(parent.path(), "init")
        .args(["--repository", "hashgraph-online/hol-guard"])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let store = HostLifecycleStore::open(parent.path()).unwrap();
    let mut child = OwnedChild::start(parent.path());
    online(&store, &mut child);
    let duplicate = command(parent.path(), "agent")
        .arg("--once")
        .output()
        .unwrap();
    assert_eq!(duplicate.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already owned"));
    let resume = run(parent.path(), "resume");
    assert!(
        resume.status.success(),
        "{}",
        String::from_utf8_lossy(&resume.stderr)
    );
    let resumed: Value = serde_json::from_slice(&resume.stdout).unwrap();
    assert_eq!(resumed["admissions_held"], false);
    assert_eq!(resumed["execution_eligible"], false);
    assert_eq!(resumed["observer"]["lease_held"], true);
    let down = run(parent.path(), "down");
    assert!(
        down.status.success(),
        "{}",
        String::from_utf8_lossy(&down.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&down.stdout).unwrap()["stop_requested"],
        true
    );
    let output = child.wait();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(status(&store)["observer"]["status"], "stopped");
    assert!(command(parent.path(), "agent")
        .arg("--once")
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(status(&store)["stop_requested"], false);
}

#[test]
fn killed_process_releases_kernel_lease_and_restart_blocks_synthetic_interrupted_work() {
    let parent = parent();
    let store =
        HostLifecycleStore::initialize(parent.path(), "hashgraph-online/hol-guard", 1000).unwrap();
    store
        .enqueue_release("1111111111111111", "v3.48.0", &"a".repeat(40), 1100)
        .unwrap();
    let mut child = OwnedChild::start(parent.path());
    online(&store, &mut child);
    child.0.as_mut().unwrap().kill().unwrap();
    let killed = child.wait();
    assert!(!killed.status.success());
    assert_eq!(status(&store)["observer"]["lease_held"], false);
    // Freeze a synthetic active record only after the owning child is reaped.
    let path = parent.path().join("rust-host-v1/state.json");
    let mut checkpoint: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    checkpoint["jobs"][0]["state"] = json!("running");
    fs::write(
        &path,
        canonicalize(checkpoint.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    let restart = command(parent.path(), "agent")
        .arg("--once")
        .output()
        .unwrap();
    assert!(
        restart.status.success(),
        "{}",
        String::from_utf8_lossy(&restart.stderr)
    );
    let recovered: Value = serde_json::from_slice(&restart.stdout).unwrap();
    assert_eq!(recovered["unknown_jobs"], 1);
    assert_eq!(recovered["jobs"][0]["state"], "unknown");
    assert_eq!(recovered["jobs"][0]["id"], "1111111111111111");
    assert_eq!(recovered["observer"]["status"], "stopped");
    assert_eq!(recovered["execution_eligible"], false);
    let resume = run(parent.path(), "resume");
    assert!(resume.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&resume.stdout).unwrap()["unknown_jobs"],
        1
    );
}

#[test]
fn malformed_cli_and_refused_release_do_not_mutate_checkpoint() {
    let parent = parent();
    let _store =
        HostLifecycleStore::initialize(parent.path(), "hashgraph-online/hol-guard", 1000).unwrap();
    let path = parent.path().join("rust-host-v1/state.json");
    let before = fs::read(&path).unwrap();
    for extra in [
        vec!["--once"],
        vec!["--repository", "wrong/repo"],
        vec!["--state-parent", "duplicate"],
    ] {
        let output = command(parent.path(), "resume")
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    let output = command(parent.path(), "enqueue-release")
        .args([
            "--job-id",
            "1111111111111111",
            "--tag",
            "v3.50.0",
            "--source-sha",
            &"a".repeat(40),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn transaction_contention_refuses_the_second_process_without_a_partial_update() {
    let parent = parent();
    let store =
        HostLifecycleStore::initialize(parent.path(), "hashgraph-online/hol-guard", 1000).unwrap();
    let path = parent.path().join("rust-host-v1/state.json");
    let before = fs::read(&path).unwrap();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(parent.path().join("rust-host-v1/transaction.lock"))
        .unwrap();
    flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    let output = run(parent.path(), "resume");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("already owned"));
    assert_eq!(fs::read(&path).unwrap(), before);
    drop(lock);
    assert!(run(parent.path(), "resume").status.success());
    assert_eq!(status(&store)["admissions_held"], false);
    assert_eq!(status(&store)["generation"], 1);
}
