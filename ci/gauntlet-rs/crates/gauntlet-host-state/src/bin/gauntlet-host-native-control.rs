//! Explicit zero-model host-pinned Native run/readback over the owned Lima VM.
use gauntlet_contracts::{canonicalize, is_git_sha, WorkerRequest};
use gauntlet_host_state::{HostControllerKeyPinJournal, HostKeyPinError, HostPrelaunchIdentity};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
struct Lima {
    path: PathBuf,
    file: File,
    expected: String,
    device: u64,
    inode: u64,
}
impl Lima {
    fn open(expected: &str) -> Result<Self, String> {
        let path = Path::new("/opt/homebrew/bin/limactl")
            .canonicalize()
            .map_err(|e| e.to_string())?;
        let file = File::open(&path).map_err(|e| e.to_string())?;
        let s = file.metadata().map_err(|e| e.to_string())?;
        if !s.is_file()
            || s.mode() & 0o022 != 0
            || !(1..=128 * 1024 * 1024).contains(&s.len())
            || ![0, unsafe { libc::geteuid() }].contains(&s.uid())
        {
            return Err("owned immutable Lima executable required".into());
        }
        let mut result = Self {
            path,
            file,
            expected: expected.into(),
            device: s.dev(),
            inode: s.ino(),
        };
        result.recheck()?;
        Ok(result)
    }
    fn recheck(&mut self) -> Result<(), String> {
        let visible = self.path.metadata().map_err(|e| e.to_string())?;
        let before = self.file.metadata().map_err(|e| e.to_string())?;
        if visible.dev() != self.device
            || visible.ino() != self.inode
            || before.dev() != self.device
            || before.ino() != self.inode
            || !before.is_file()
            || !(1..=128 * 1024 * 1024).contains(&before.len())
            || before.mode() & 0o022 != 0
            || ![0, unsafe { libc::geteuid() }].contains(&before.uid())
        {
            return Err("Lima executable custody changed".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut total = 0u64;
        loop {
            let count = self.file.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > before.len() {
                return Err("Lima executable grew while held".into());
            }
            hash.update(&buffer[..count]);
        }
        let after = self.file.metadata().map_err(|e| e.to_string())?;
        if format!("{:x}", hash.finalize()) != self.expected
            || total != before.len()
            || before.uid() != after.uid()
            || before.mode() != after.mode()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err("Lima executable differs from outside SHA-256 pin".into());
        }
        Ok(())
    }
}

fn run() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS owned Lima host required".into());
    }
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 11 {
        return Err("usage: gauntlet-host-native-control run|reconcile PRIVATE_0700_PIN_DIRECTORY VM_NAME LIMA_SHA256 SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_SHA256 PREPARATION_SHA256 ROLE".into());
    }
    let (action, vm, lima_pin, source, job, deployment, generation, preparation, role) = (
        args[1].as_str(),
        args[3].as_str(),
        args[4].as_str(),
        args[5].as_str(),
        args[6].as_str(),
        args[7].as_str(),
        args[8].as_str(),
        args[9].as_str(),
        args[10].as_str(),
    );
    if !matches!(action, "run" | "reconcile")
        || !vm.starts_with("hol-")
        || vm.len() > 96
        || !vm
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !hex(lima_pin, 64)
        || !is_git_sha(source)
        || !hex(job, 16)
        || !hex(deployment, 64)
        || !hex(generation, 64)
        || !hex(preparation, 64)
        || !matches!(
            role,
            "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
        )
    {
        return Err("closed native host operation and exact outside pins required".into());
    }
    let journal =
        HostControllerKeyPinJournal::open(Path::new(&args[2])).map_err(|e| e.to_string())?;
    let expected = HostPrelaunchIdentity {
        job_id: job.into(),
        source_sha: source.into(),
        deployment_digest: deployment.into(),
        worker_generation: generation.into(),
    };
    match (action, journal.read(job)) {
        ("run", Err(HostKeyPinError::Missing)) => (),
        ("reconcile", Ok(record))
            if record.pins.source_sha == source
                && record.pins.deployment_digest == deployment
                && record.pins.worker_generation == generation => {}
        ("run", Ok(_)) => {
            return Err("host job ID already pinned; reconcile without rerunning".into())
        }
        (_, Err(e)) => return Err(e.to_string()),
        _ => return Err("host readback identity differs from retained pin".into()),
    }
    let mut lima = Lima::open(lima_pin)?;
    let mut request = json!({"schema":"hol-gauntlet-worker-request.v1","action":action,"source_sha":source,"job_id":job});
    if action == "run" {
        request["deployment_digest"] = json!(deployment);
    }
    let request_raw = canonicalize(request.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let request = WorkerRequest::parse(&request_raw).map_err(|e| e.to_string())?;
    let worker = format!("/opt/hol-gauntlet/rust-native-host-pinned-worker-{generation}");
    let operation = if action == "run" {
        "--native-host-pinned-v1"
    } else {
        "--read-native-host-pinned-v1"
    };
    let child = Command::new(&lima.path)
        .args([
            "shell", vm, "--", "sudo", "-n", &worker, operation, source, deployment, generation,
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env(
            "HOME",
            std::env::var_os("HOME").ok_or("host home unavailable for Lima transport")?,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut accepted = if action == "run" {
        journal
            .send_run_request_and_accept_prepared_child(
                child,
                &request,
                &expected,
                Duration::from_secs(60),
            )
            .map_err(|e| {
                format!(
                    "native prelaunch refused: {}; host pin consumed or uncertain: {}",
                    e.reason, e.pin_recorded_or_uncertain
                )
            })?
    } else {
        journal
            .send_native_readback_request_and_bind_child(
                child,
                &request,
                &expected,
                Duration::from_secs(60),
            )
            .map_err(|e| e.reason.to_string())?
    };
    let output = accepted
        .wait_bounded_native_completion(Duration::from_secs(if action == "run" { 420 } else { 60 }))
        .map_err(|e| {
            format!("native completion unavailable; retain pinned job until reconciliation: {e}")
        })?;
    lima.recheck()?;
    let completion = output.strip_suffix(b"\n").unwrap_or(&output);
    let raw = canonicalize(completion).map_err(|e| e.to_string())?;
    let frame: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let result = journal.verify_native_completion(&raw, &expected, preparation, role);
    let message = json!({"schema":"hol-gauntlet-host-native-control-result.v1","operation":action,
        "vm":vm,"lima_sha256":lima_pin,"host_pin":accepted.record().to_json(),"completion":frame,
        "readback":result.as_ref().ok().map(|r|r.observation()),"readback_error":result.as_ref().err().map(|e|e.to_string()),
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    println!("{message}");
    result.map(|_| ()).map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native host control unavailable: {error}");
        std::process::exit(2);
    }
}
