//! Real host process, loopback socket, state ownership and probe cancellation.
use gauntlet_host_state::{wait_for_lifecycle, HostLifecycleStore};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn command(parent: &Path, action: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gauntlet-host"));
    command.arg(action).arg("--state-parent").arg(parent);
    command
}
fn executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
struct Fixture {
    temp: tempfile::TempDir,
    parent: PathBuf,
    config: String,
}
impl Fixture {
    fn new(slow: bool) -> Self {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let parent = temp.path().join("state");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let git = temp.path().join("git");
        let script = if slow {
            "#!/bin/sh\nbase=${0%/*}\nprintf started > \"$base/probe-started\"\n(sleep 1.5; printf escaped > \"$base/escaped\") &\nwait\n".to_owned()
        } else {
            format!("#!/bin/sh\nfor argument in \"$@\"; do\ncase \"$argument\" in\nrefs/tags/v3.48.0) printf '%s\\t%s\\n' '{}' \"$argument\";;\nrefs/tags/v3.49.0) printf '%s\\t%s\\n' '{}' \"$argument\";;\nesac\ndone\n","a".repeat(40),"b".repeat(40))
        };
        executable(&git, &script);
        let lima = temp.path().join("limactl");
        executable(
            &lima,
            r#"#!/bin/sh
[ "$#" = 4 ] && [ "$1" = shell ] && [ "$3" = -- ] || exit 8
case "$4" in /opt/hol-gauntlet/gauntlet-vm-telemetry-*) ;; *) exit 9 ;; esac
checked=$(/bin/date +%s)
printf '{"schema":"hol-gauntlet-vm-telemetry.v1","platform":"Linux","status":"running","checked_at":%s,"cpus":2,"load":0.1,"memory_total":17179869184,"memory_available":15000000000,"disk_total":51539607552,"disk_free":20000000000}\n' "$checked"
"#,
        );
        let store =
            HostLifecycleStore::initialize(&parent, "hashgraph-online/hol-guard", now()).unwrap();
        // Parallel process tests can briefly inherit a just-released flock
        // before exec closes its descriptor. This fixed immutable configuration
        // is idempotent; preserve every real failure and bound Busy alone.
        let config = wait_for_lifecycle(|| {
            store.configure_observer(
                &json!({"git":git,"limactl":lima,"telemetry_seconds":5}),
                &"c".repeat(64),
            )
        })
        .unwrap()
        .sha256;
        Self {
            temp,
            parent,
            config,
        }
    }
    fn up(&self) -> Command {
        let mut command = command(&self.parent, "up");
        command.args(["--config-sha256", &self.config, "--port", "0"]);
        command
    }
}
struct Owned {
    child: Option<Child>,
    stdout: PathBuf,
    stderr: PathBuf,
}
impl Owned {
    fn start(fixture: &Fixture) -> Self {
        let stdout = fixture.temp.path().join("stdout");
        let stderr = fixture.temp.path().join("stderr");
        let child = fixture
            .up()
            .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        Self {
            child: Some(child),
            stdout,
            stderr,
        }
    }
    fn startup(&mut self) -> Value {
        let until = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(line) = fs::read_to_string(&self.stdout).unwrap().lines().next() {
                return serde_json::from_str(line).unwrap();
            }
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "{}",
                fs::read_to_string(&self.stderr).unwrap()
            );
            assert!(Instant::now() < until, "no observer startup");
            sleep(Duration::from_millis(20));
        }
    }
    fn wait(&mut self) -> Vec<Value> {
        let until = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                assert!(
                    status.success(),
                    "{}",
                    fs::read_to_string(&self.stderr).unwrap()
                );
                self.child.take();
                return fs::read_to_string(&self.stdout)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
            }
            assert!(Instant::now() < until, "observer shutdown did not finish");
            sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            if child.try_wait().unwrap().is_none() {
                child.kill().unwrap();
                child.wait().unwrap();
            }
        }
    }
}
fn http(url: &str, path: &str) -> Value {
    let mut socket = TcpStream::connect(url.strip_prefix("http://").unwrap()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(socket, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 200 OK"));
    let offset = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    serde_json::from_slice(&bytes[offset..]).unwrap()
}
fn action(fixture: &Fixture, name: &str) -> Value {
    let output = command(&fixture.parent, name).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn combined_observer_serves_exact_release_queue_and_operator_lifecycle() {
    let fixture = Fixture::new(false);
    let mut owned = Owned::start(&fixture);
    let startup = owned.startup();
    let url = startup["url"].as_str().unwrap();
    let until = Instant::now() + Duration::from_secs(8);
    let snapshot = loop {
        let snapshot = http(url, "/api/status");
        if snapshot["jobs"]
            .as_array()
            .is_some_and(|rows| rows.len() == 2)
            && snapshot["vm"]["status"] == "running"
        {
            break snapshot;
        }
        assert!(
            Instant::now() < until,
            "no completed observations: {snapshot}"
        );
        sleep(Duration::from_millis(30));
    };
    assert_eq!(snapshot["collector_status"], "online");
    assert_eq!(snapshot["github"]["status"], "connected");
    assert_eq!(snapshot["jobs"][0]["state"], "queued");
    assert_eq!(snapshot["execution_eligible"], false);
    let health = http(url, "/healthz");
    assert_eq!(health["instance_id"], startup["instance_id"]);
    assert_eq!(health["collector"], "online");
    let status = command(&fixture.parent, "status")
        .args(["--config-sha256", &fixture.config])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&status.stdout).unwrap()["instance_id"],
        startup["instance_id"]
    );
    assert_eq!(action(&fixture, "resume")["admissions_held"], false);
    assert_eq!(action(&fixture, "hold")["admissions_held"], true);
    assert_eq!(action(&fixture, "down")["stop_requested"], true);
    let output = owned.wait();
    let stopped = output.last().unwrap();
    assert_eq!(
        stopped["observer"]["schema"],
        "hol-gauntlet-observer.stopped"
    );
    assert_eq!(stopped["jobs"].as_array().unwrap().len(), 2);
    assert!(TcpStream::connect(url.strip_prefix("http://").unwrap()).is_err());
    let store = HostLifecycleStore::open(&fixture.parent).unwrap();
    assert_eq!(
        store.status(now()).unwrap()["observer"]["lease_held"],
        false
    );
    assert_eq!(
        store
            .published_observer_snapshot(&fixture.config, now())
            .unwrap()["collector_status"],
        "stopped"
    );
}

#[test]
fn occupied_dashboard_port_does_not_acquire_lease_or_mutate_checkpoint() {
    let fixture = Fixture::new(false);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let path = fixture.parent.join("rust-host-v1/state.json");
    let before = fs::read(&path).unwrap();
    let output = command(&fixture.parent, "up")
        .args([
            "--config-sha256",
            &fixture.config,
            "--port",
            &listener.local_addr().unwrap().port().to_string(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(path).unwrap(), before);
    assert!(!fixture.parent.join("rust-host-v1/public").exists());
}

#[test]
fn termination_cancels_slow_source_probes_without_losing_heartbeat_or_descendants() {
    let fixture = Fixture::new(true);
    let mut owned = Owned::start(&fixture);
    let startup = owned.startup();
    let url = startup["url"].as_str().unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while !fixture.temp.path().join("probe-started").exists() {
        assert!(Instant::now() < until);
        sleep(Duration::from_millis(10));
    }
    assert_eq!(http(url, "/healthz")["collector"], "online");
    let before = Instant::now();
    let child = owned.child.as_mut().unwrap();
    assert!(child.try_wait().unwrap().is_none());
    let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    owned.wait();
    assert!(before.elapsed() < Duration::from_secs(3));
    sleep(Duration::from_millis(1700));
    assert!(!fixture.temp.path().join("escaped").exists());
    assert!(TcpStream::connect(url.strip_prefix("http://").unwrap()).is_err());
}

#[test]
fn doctor_collects_read_only_without_starting_an_observer_or_queuing_work() {
    let fixture = Fixture::new(false);
    let path = fixture.parent.join("rust-host-v1/state.json");
    let before = fs::read(&path).unwrap();
    let output = command(&fixture.parent, "doctor")
        .args(["--config-sha256", &fixture.config])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(snapshot["vm"]["status"], "running");
    assert_eq!(snapshot["github"]["status"], "connected");
    assert_eq!(snapshot["jobs"], json!([]));
    assert_eq!(snapshot["execution_eligible"], false);
    assert_eq!(fs::read(path).unwrap(), before);
    assert!(!fixture.parent.join("rust-host-v1/public").exists());
}

#[test]
fn restrictive_operator_umask_still_creates_only_the_declared_public_modes() {
    let fixture = Fixture::new(false);
    let mut command = fixture.up();
    command.arg("--once");
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = fixture.parent.join("rust-host-v1/public");
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o755
    );
    for file in ["dashboard-id.json", "snapshot.json"] {
        assert_eq!(
            fs::metadata(root.join(file)).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
    assert_eq!(
        fs::metadata(fixture.parent.join("rust-host-v1/observer-config.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
