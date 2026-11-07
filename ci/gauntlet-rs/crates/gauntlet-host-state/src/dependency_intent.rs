//! Private one-use dependency intent, durably committed before VM execution.
use crate::fixed_process::run_fixed_intent;
use crate::private_jobs::{read_regular_bytes, state_root, write_private_once};
use gauntlet_contracts::{DependencyRunIntent, DependencyRunPins};
use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{fchmod, fstat, fsync, openat, statat, AtFlags, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
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

    fn launch_authorization(intent: &DependencyRunIntent) -> Result<Vec<u8>, String> {
        gauntlet_contracts::canonicalize(
            json!({
            "schema":"hol-gauntlet-host-dependency-launch-authorization.v1",
            "job_id":intent.pins.text("job_id"),"intent_sha256":intent.digest()?,
            "retry_allowed":false,"execution_eligible":false})
            .to_string()
            .as_bytes(),
        )
        .map_err(|e| e.to_string())
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
        // Older intents remain readable; absence of this fresh reservation
        // must never be interpreted as an undispatched attempt after upgrade.
        write_private_once(
            &self.root,
            &format!("{}.dependency-authorized.json", intent.pins.text("job_id")),
            &Self::launch_authorization(&intent)?,
        )?;
        self.stable()?;
        if self.read(intent.pins.text("job_id"))? != intent {
            return Err("dependency intent changed after authorization".into());
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
        let authorization = Self::launch_authorization(intent)?;
        let name = format!("{}.dependency-authorized.json", intent.pins.text("job_id"));
        let authorized = || {
            if read_regular_bytes(&self.root, &name, self.owner)
                .ok()
                .as_deref()
                != Some(authorization.as_slice())
            {
                return Err("dependency launch authorization missing or changed; retained intent is read-only".to_owned());
            }
            Ok(())
        };
        authorized()?;
        write_private_once(
            &self.root,
            &format!("{}.dependency-dispatch.json", intent.pins.text("job_id")),
            &authorization,
        )?;
        self.stable()?;
        if self.read(intent.pins.text("job_id"))? != *intent {
            return Err("dependency intent changed before transport".into());
        }
        authorized()?;
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
        let public = gauntlet_contracts::verify_dependency_run_result(intent, frame)?;
        if self.read(intent.pins.text("job_id"))? != *intent {
            return Err("dependency intent changed during execution".into());
        }
        // The Root v1 reply embeds the private intent. Preserve it privately
        // and return only typed public fields through the operator CLI.
        write_private_once(
            &self.root,
            &format!("{}.dependency-result.json", intent.pins.text("job_id")),
            frame,
        )?;
        self.stable()?;
        Ok(public)
    }
    fn repair_pins(
        &self,
        intent: &DependencyRunIntent,
    ) -> Result<Option<(String, String)>, String> {
        let name = format!(
            "{}.dependency-repair-authorized.json",
            intent.pins.text("job_id")
        );
        match statat(&self.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.to_string()),
            Ok(_) => {}
        }
        let raw = read_regular_bytes(&self.root, &name, self.owner).map_err(|e| e.to_string())?;
        gauntlet_contracts::parse_dependency_repair_authorization(intent, &raw).map(Some)
    }

    fn repaired(
        &self,
        intent: &DependencyRunIntent,
        reader: &str,
        read: bool,
    ) -> Result<Value, String> {
        let (started, generation) = self
            .repair_pins(intent)?
            .ok_or("dependency cleanup has no outside authorization")?;
        gauntlet_contracts::dependency_repair_authorization(intent, &started, reader)?;
        let argv = vec![
            intent.limactl.clone(),
            "shell".into(),
            intent.vm.clone(),
            "--".into(),
            "sudo".into(),
            "-n".into(),
            format!("/opt/hol-gauntlet/rust-native-dependency-worker-{reader}"),
            if read {
                "--read-native-dependency-repair".into()
            } else {
                "--repair-owned-native-dependencies".into()
            },
            intent.pins.text("job_id").into(),
            intent.digest()?,
            started.clone(),
            intent.pins.text("runner_binary_sha256").into(),
            reader.into(),
        ];
        let raw =
            run_fixed_intent(&argv, &[], Duration::from_secs(120), 8193, 8192).map_err(|e| {
                format!("dependency recovery unavailable; workload cannot retry: {e:?}")
            })?;
        let frame = raw
            .strip_suffix(b"\n")
            .ok_or("canonical dependency recovery response required")?;
        let mut public = gauntlet_contracts::verify_dependency_repair_result(
            intent,
            &started,
            &generation,
            frame,
        )?;
        self.stable()?;
        if self.read(intent.pins.text("job_id"))? != *intent
            || self.repair_pins(intent)? != Some((started.clone(), generation.clone()))
        {
            return Err("dependency recovery authorization or intent changed".into());
        }
        if read {
            public["retained_result_reconciled"] = json!(true);
            public["reader_generation"] = json!(reader);
            if public.to_string().contains(&intent.nonce) {
                return Err("private dependency value appeared in readback".into());
            }
        } else {
            self.retain_view(
                &format!(
                    "{}.dependency-repair-result.json",
                    intent.pins.text("job_id")
                ),
                &public,
            )?;
        }
        if self.read(intent.pins.text("job_id"))? != *intent
            || self.repair_pins(intent)? != Some((started, generation))
        {
            return Err("dependency recovery pins changed after readback".into());
        }
        Ok(public)
    }

    fn retain_view(&self, name: &str, value: &Value) -> Result<(), String> {
        let encoded = gauntlet_contracts::canonicalize(value.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        match statat(&self.root, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => write_private_once(&self.root, name, &encoded)?,
            Err(e) => return Err(e.to_string()),
            Ok(_) => {
                if read_regular_bytes(&self.root, name, self.owner).map_err(|e| e.to_string())?
                    != encoded
                {
                    return Err("retained dependency reconciliation differs".into());
                }
            }
        }
        self.stable()
    }

    pub fn repair(
        &self,
        job: &str,
        started: &str,
        generation: &str,
        vm: Option<&str>,
    ) -> Result<Value, String> {
        let intent = self.read(job)?;
        if vm.is_some_and(|v| v != intent.vm) {
            return Err("dependency repair requires the original VM".into());
        }
        let encoded =
            gauntlet_contracts::dependency_repair_authorization(&intent, started, generation)?;
        match self.repair_pins(&intent)? {
            None => {
                let observed = self.reconcile_read_only(job, generation, vm)?;
                if observed["status"] != "unknown" || observed["started_marker_sha256"] != started {
                    return Err("dependency reservation differs or is already complete; cleanup not authorized".into());
                }
                write_private_once(
                    &self.root,
                    &format!("{job}.dependency-repair-authorized.json"),
                    &encoded,
                )?;
            }
            Some(pins) => {
                if pins != (started.into(), generation.into()) {
                    return Err("retained dependency repair authorization differs".into());
                }
            }
        }
        if self.repair_pins(&intent)? != Some((started.into(), generation.into())) {
            return Err("dependency repair authorization commit uncertain".into());
        }
        self.repaired(&intent, generation, false)
    }
    /// Reconcile the original VM and intent without authorizing a new launch.
    pub fn reconcile_read_only(
        &self,
        job: &str,
        generation: &str,
        vm: Option<&str>,
    ) -> Result<Value, String> {
        if generation.len() != 64 || !generation.bytes().all(|b| b"0123456789abcdef".contains(&b)) {
            return Err("exact dependency reader binary SHA-256 required".into());
        }
        let intent = self.read(job)?;
        if vm.is_some_and(|v| v != intent.vm) {
            return Err("dependency read requires the original VM".into());
        }
        let digest = intent.digest()?;
        let argv = vec![
            intent.limactl.clone(),
            "shell".into(),
            intent.vm.clone(),
            "--".into(),
            "sudo".into(),
            "-n".into(),
            format!("/opt/hol-gauntlet/rust-native-dependency-worker-{generation}"),
            "--read-native-dependencies".into(),
            digest,
            intent.bytes()?.len().to_string(),
            generation.into(),
        ];
        let response = run_fixed_intent(
            &argv,
            &intent.bytes()?,
            Duration::from_secs(120),
            32769,
            8192,
        );
        let raw = match response {
            Ok(raw) => raw,
            Err(_) if self.repair_pins(&intent)?.is_some() => {
                let public = self.repaired(&intent, generation, true)?;
                self.retain_view(
                    &format!("{job}.dependency-reconciled-{generation}.json"),
                    &public,
                )?;
                if self.read(job)? != intent
                    || self.repair_pins(&intent)?.is_none_or(|(started, repair)| {
                        public["started_marker_sha256"] != started
                            || public["repair_generation"] != repair
                    })
                {
                    return Err("dependency readback pins changed after retention".into());
                }
                return Ok(public);
            }
            Err(e) => {
                return Err(format!(
                    "dependency retained read unavailable; workload cannot retry: {e:?}"
                ))
            }
        };
        let frame = raw
            .strip_suffix(b"\n")
            .ok_or("one dependency read frame required")?;
        let schema: Value =
            serde_json::from_slice(frame).map_err(|_| "dependency read response JSON required")?;
        let public = match schema["schema"].as_str() {
            Some("hol-gauntlet-native-dependency-unknown.v1") => {
                gauntlet_contracts::verify_dependency_unknown_result(&intent, generation, frame)?
            }
            Some(
                "hol-gauntlet-native-dependency-repair.v2"
                | "hol-gauntlet-native-dependency-repair.v3",
            ) => {
                let (started, repair) = self
                    .repair_pins(&intent)?
                    .ok_or("retained dependency cleanup was not authorized")?;
                let mut public = gauntlet_contracts::verify_dependency_repair_result(
                    &intent, &started, &repair, frame,
                )?;
                public["reader_generation"] = json!(generation);
                public["retained_result_reconciled"] = json!(true);
                public
            }
            _ => gauntlet_contracts::verify_dependency_read_response(&intent, generation, frame)?,
        };
        if public.to_string().contains(&intent.nonce) {
            return Err("private dependency value appeared in readback".into());
        }
        if self.read(job)? != intent {
            return Err("dependency intent changed during reconciliation".into());
        }
        let name = if public["status"] == "unknown" {
            format!("{job}.dependency-unknown-{generation}.json")
        } else {
            format!("{job}.dependency-reconciled-{generation}.json")
        };
        self.retain_view(&name, &public)?;
        self.stable()?;
        if self.read(job)? != intent
            || (public["schema"] == "hol-gauntlet-host-dependency-repair.v1"
                && self.repair_pins(&intent)?.is_none_or(|(started, repair)| {
                    public["started_marker_sha256"] != started
                        || public["repair_generation"] != repair
                }))
        {
            return Err("dependency pins changed after reconciliation".into());
        }
        Ok(public)
    }
}

pub const DEPENDENCY_COMMAND_USAGE:&str="dependency commands:\nrun PRIVATE_INTENT_DIR PRIVATE_RUN_PINS_JSON [--vm VM_NAME]\nread PRIVATE_INTENT_DIR JOB_ID READER_BINARY_SHA256 [--vm VM_NAME]\nrepair PRIVATE_INTENT_DIR JOB_ID STARTED_MARKER_SHA256 REPAIR_BINARY_SHA256 [--vm VM_NAME]\nRead never authorizes cleanup or a new launch. Repair preserves the original unknown attempt and supplies no execution admission.";

pub fn run_dependency_command(args: &[String]) -> Result<Value, String> {
    match (args.first().map(String::as_str), args.len()) {
        (Some("repair"), 5) | (Some("repair"), 7) if args.len() == 5 || args[5] == "--vm" => {
            DependencyIntentJournal::open(Path::new(&args[1]))?.repair(
                &args[2],
                &args[3],
                &args[4],
                args.get(6).map(String::as_str),
            )
        }
        (Some("run"), 3) | (Some("run"), 5) if args.len() == 3 || args[3] == "--vm" => {
            let pins = read_dependency_run_pins(Path::new(&args[2]))?;
            let operations = crate::public_vm_operations(args.get(4).map(String::as_str))
                .map_err(|e| e.to_string())?;
            let journal = DependencyIntentJournal::open(Path::new(&args[1]))?;
            let intent = journal.record(pins, &operations)?;
            journal.execute_once(&intent)
        }
        (Some("read"), 4) | (Some("read"), 6) if args.len() == 4 || args[4] == "--vm" => {
            DependencyIntentJournal::open(Path::new(&args[1]))?.reconcile_read_only(
                &args[2],
                &args[3],
                args.get(5).map(String::as_str),
            )
        }
        _ => Err(DEPENDENCY_COMMAND_USAGE.into()),
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
