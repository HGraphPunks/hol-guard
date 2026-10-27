//! Private one-use dependency intent, durably committed before VM execution.
use crate::fixed_process::run_fixed_intent;
use crate::private_jobs::{read_regular_bytes, state_root};
use gauntlet_contracts::{DependencyRunIntent, DependencyRunPins};
use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{fchmod, fstat, fsync, openat, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::Value;
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct DependencyIntentJournal {
    root: OwnedFd,
    path: PathBuf,
    owner: u32,
}

impl DependencyIntentJournal {
    pub fn open(path: &Path) -> Result<Self, String> {
        let owner = geteuid().as_raw();
        let root = state_root(path, owner).map_err(|e| e.to_string())?;
        Ok(Self {
            root,
            path: path.to_owned(),
            owner,
        })
    }

    fn stable(&self) -> Result<(), String> {
        let visible = state_root(&self.path, self.owner).map_err(|e| e.to_string())?;
        let a = fstat(&self.root).map_err(|e| e.to_string())?;
        let b = fstat(&visible).map_err(|e| e.to_string())?;
        if (a.st_dev, a.st_ino, a.st_uid, a.st_mode) != (b.st_dev, b.st_ino, b.st_uid, b.st_mode) {
            return Err("dependency intent directory replaced".into());
        }
        Ok(())
    }

    fn name(job: &str) -> Result<String, String> {
        if job.len() != 16
            || !job
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("exact dependency job required".into());
        }
        Ok(format!("{job}.dependency-intent.json"))
    }

    pub fn read(&self, job: &str) -> Result<DependencyRunIntent, String> {
        self.stable()?;
        let raw = read_regular_bytes(&self.root, &Self::name(job)?, self.owner)
            .map_err(|e| e.to_string())?;
        let intent = DependencyRunIntent::parse(&raw)?;
        if intent.pins.text("job_id") != job {
            return Err("dependency intent job differs".into());
        }
        self.stable()?;
        Ok(intent)
    }

    pub fn record(
        &self,
        pins: DependencyRunPins,
        operations: &Value,
    ) -> Result<DependencyRunIntent, String> {
        let operations = crate::load_operations_bytes(operations.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        if operations["release_build_backend"] != "local-vm"
            || operations["build_memory_gib"] != 12
            || operations["vm_memory_gib"].as_u64().is_none_or(|n| n < 16)
            || operations["vm_cpus"].as_u64().is_none_or(|n| n < 2)
        {
            return Err("fixed dependency VM capacity required".into());
        }
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "dependency nonce unavailable")?;
        let nonce = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let intent = DependencyRunIntent::new(
            pins,
            operations["limactl"].as_str().ok_or("transport missing")?,
            operations["vm"].as_str().ok_or("VM missing")?,
            &nonce,
        )?;
        self.stable()?;
        let name = Self::name(intent.pins.text("job_id"))?;
        let fd = openat(
            &self.root,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| "dependency intent already consumed or unavailable")?;
        fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
        let mut file = File::from(fd);
        file.write_all(&intent.bytes()?)
            .and_then(|_| file.sync_all())
            .map_err(|_| "dependency intent commit uncertain")?;
        fsync(&self.root).map_err(|_| "dependency intent directory commit uncertain")?;
        if self.read(intent.pins.text("job_id"))? != intent {
            return Err("dependency intent changed after write".into());
        }
        Ok(intent)
    }

    /// A transport error consumes this intent. Read retained guest state before
    /// considering any new job; this method never retries or admits an artifact.
    pub fn execute_once(&self, intent: &DependencyRunIntent) -> Result<Value, String> {
        if self.read(intent.pins.text("job_id"))? != *intent {
            return Err("dependency prelaunch intent changed".into());
        }
        let digest = intent.digest()?;
        let generation = intent.pins.text("runner_binary_sha256");
        let argv = vec![
            intent.limactl.clone(),
            "shell".into(),
            intent.vm.clone(),
            "--".into(),
            "sudo".into(),
            "-n".into(),
            format!("/opt/hol-gauntlet/rust-native-dependency-worker-{generation}"),
            "--prepare-native-dependencies".into(),
            digest.clone(),
            intent.bytes()?.len().to_string(),
            generation.into(),
        ];
        let raw = run_fixed_intent(
            &argv,
            &intent.bytes()?,
            Duration::from_secs(2400),
            16384,
            8192,
        )
        .map_err(|e| {
            format!("dependency VM execution uncertain; reconcile without retry: {e:?}")
        })?;
        let frame = raw
            .strip_suffix(b"\n")
            .ok_or("canonical dependency response required")?;
        if gauntlet_contracts::canonicalize(frame).map_err(|e| e.to_string())? != frame {
            return Err("dependency response is ambiguous".into());
        }
        let result: Value = serde_json::from_slice(frame).map_err(|e| e.to_string())?;
        if result["schema"] != "hol-gauntlet-native-dependency-result.v1"
            || result["intent_sha256"] != digest
            || result["job_id"] != intent.pins.text("job_id")
            || result["source_sha"] != intent.pins.text("source_sha")
            || result["worker_generation"] != generation
            || result["execution_eligible"] != false
            || result["artifact_admitted"] != false
            || result["model_requests"] != 0
            || result["container_absent"] != true
            || result["container_cgroup_absent"] != true
            || result["client_cgroup_drained"] != true
            || result["build_profile_removed"] != true
        {
            return Err("dependency response differs from prelaunch intent".into());
        }
        if self.read(intent.pins.text("job_id"))? != *intent {
            return Err("dependency intent changed during execution".into());
        }
        Ok(result)
    }
}

pub fn read_dependency_run_pins(path: &Path) -> Result<DependencyRunPins, String> {
    let parent = path
        .parent()
        .ok_or("private dependency pins parent required")?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("ordinary dependency pins filename required")?;
    let owner = geteuid().as_raw();
    let root = state_root(parent, owner).map_err(|e| e.to_string())?;
    let raw = read_regular_bytes(&root, name, owner).map_err(|e| e.to_string())?;
    DependencyRunPins::parse(&raw)
}
