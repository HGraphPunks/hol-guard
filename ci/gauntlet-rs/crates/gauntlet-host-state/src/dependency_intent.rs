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

pub(crate) type DependencyTransport<'a> = dyn FnMut(
        &[String],
        &[u8],
        Duration,
        usize,
        usize,
    ) -> Result<Vec<u8>, crate::fixed_process::FixedProcessError>
    + 'a;

pub struct DependencyIntentJournal {
    pub(crate) root: OwnedFd,
    path: PathBuf,
    pub(crate) owner: u32,
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

    pub(crate) fn stable(&self) -> Result<(), String> {
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
    pub(crate) fn require_dispatch(&self, intent: &DependencyRunIntent) -> Result<(), String> {
        self.stable()?;
        let job = intent.pins.text("job_id");
        if self.read(job)? != *intent {
            return Err("original dependency intent changed".into());
        }
        for suffix in ["authorized", "dispatch"] {
            if read_regular_bytes(
                &self.root,
                &format!("{job}.dependency-{suffix}.json"),
                self.owner,
            )
            .map_err(|e| e.to_string())?
                != Self::launch_authorization(intent)?
            {
                return Err(
                    "original dependency launch/dispatch authorization missing or changed".into(),
                );
            }
        }
        Ok(())
    }
    pub(crate) fn retained_result(
        &self,
        intent: &DependencyRunIntent,
    ) -> Result<Option<Value>, String> {
        self.require_dispatch(intent)?;
        let name = format!("{}.dependency-result.json", intent.pins.text("job_id"));
        match statat(&self.root, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.to_string()),
            Ok(_) => {}
        }
        let raw = read_regular_bytes(&self.root, &name, self.owner).map_err(|e| e.to_string())?;
        let public = gauntlet_contracts::verify_dependency_run_result(intent, &raw)?;
        self.require_dispatch(intent)?;
        Ok(Some(public))
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
        self.execute_once_using(intent, &mut run_fixed_intent)
    }
    pub(crate) fn execute_once_using(
        &self,
        intent: &DependencyRunIntent,
        transport: &mut DependencyTransport<'_>,
    ) -> Result<Value, String> {
        if self.read(intent.pins.text("job_id"))? != *intent {
            return Err("dependency prelaunch intent changed".into());
        }
        if self.repair_pins(intent)?.is_some() {
            return Err("dependency recovery has consumed this intent; never launch it".into());
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
        let raw = transport(
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
    pub(crate) fn retain_view(&self, name: &str, value: &Value) -> Result<(), String> {
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

    /// Reconcile the original VM and intent without authorizing a new launch.
    pub fn reconcile_read_only(
        &self,
        job: &str,
        generation: &str,
        vm: Option<&str>,
    ) -> Result<Value, String> {
        self.reconcile_using(job, generation, vm, &mut run_fixed_intent)
    }
    pub(crate) fn reconcile_using(
        &self,
        job: &str,
        generation: &str,
        vm: Option<&str>,
        transport: &mut DependencyTransport<'_>,
    ) -> Result<Value, String> {
        if generation.len() != 64 || !generation.bytes().all(|b| b"0123456789abcdef".contains(&b)) {
            return Err("exact dependency reader binary SHA-256 required".into());
        }
        let intent = self.read(job)?;
        if vm.is_some_and(|v| v != intent.vm) {
            return Err("dependency read requires the original VM".into());
        }
        let digest = intent.digest()?;
        let authorization = self.repair_pins(&intent)?;
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
        let response = transport(
            &argv,
            &intent.bytes()?,
            Duration::from_secs(120),
            32769,
            8192,
        );
        let raw = match response {
            Ok(raw) => raw,
            Err(_) if self.repair_pins(&intent)?.is_some() => {
                let public = self.repaired(&intent, generation, true, transport)?;
                self.retain_view(
                    &format!("{job}.dependency-reconciled-{generation}.json"),
                    &public,
                )?;
                if self.read(job)? != intent || self.repair_pins(&intent)? != authorization {
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
            Some(
                "hol-gauntlet-native-dependency-unknown.v1"
                | "hol-gauntlet-native-dependency-unknown.v2"
                | "hol-gauntlet-native-dependency-unknown.v3",
            ) => gauntlet_contracts::verify_dependency_unknown_result(&intent, generation, frame)?,
            Some(
                "hol-gauntlet-native-dependency-repair.v2"
                | "hol-gauntlet-native-dependency-repair.v3"
                | "hol-gauntlet-native-dependency-repair.v4"
                | "hol-gauntlet-native-dependency-repair.v5",
            ) => {
                let auth = authorization
                    .as_ref()
                    .ok_or("retained dependency cleanup was not authorized")?;
                let mut public = gauntlet_contracts::verify_dependency_repair_result(
                    &intent,
                    &auth.started,
                    &auth.generation,
                    frame,
                )?;
                Self::check_repair_view(&public, auth)?;
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
        if self.read(job)? != intent || self.repair_pins(&intent)? != authorization {
            return Err("dependency pins changed after reconciliation".into());
        }
        Ok(public)
    }
}

pub const DEPENDENCY_COMMAND_USAGE:&str=concat!("dependency commands:\ninputs PRIVATE_SOURCE_STATE JOB_ID SOURCE_ARCHIVE_SHA256 REPOSITORY SOURCE_SHA EXPORTER_ELF EXPORTER_SHA256\ntransfer PRIVATE_SOURCE_STATE PRIVATE_TRANSFER_DIR VM LIMA_SHA256 JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 PAYLOAD_SHA256 WORKER_SHA256 SSH_HOME LIMA_HOME [STORAGE_RECEIPT_SHA256]\nrun PRIVATE_INTENT_DIR PRIVATE_RUN_PINS_JSON [--vm VM_NAME]\nread PRIVATE_INTENT_DIR JOB_ID READER_BINARY_SHA256 [--vm VM_NAME]\nrepair PRIVATE_INTENT_DIR JOB_ID EXPECTED_STARTED_MARKER_SHA256 REPAIR_BINARY_SHA256 [--vm VM_NAME]\n",
"prefix-stage|prefix-stage-read PRIVATE_INTENT_DIR PRIVATE_TRANSFER_DIR SOURCE_INTENT_SHA256 JOB_ID PYTHON_SHA256 STAGER_SHA256\n",
"run-bounded PRIVATE_INTENT_DIR PRIVATE_TRANSFER_DIR SOURCE_TRANSFER_INTENT_SHA256 PRIVATE_RUN_PINS_JSON\nread-bounded PRIVATE_INTENT_DIR PRIVATE_TRANSFER_DIR SOURCE_TRANSFER_INTENT_SHA256 JOB_ID READER_SHA256\nrepair-bounded PRIVATE_INTENT_DIR PRIVATE_TRANSFER_DIR SOURCE_TRANSFER_INTENT_SHA256 JOB_ID EXPECTED_STARTED_SHA256 REPAIR_SHA256\ntransfer-read uses the bounded transfer arguments and never retransmits capsule bytes.\nFor partial preparation, use the expected reservation hash from read. Incomplete completion retirement preserves original files and has unknown exit. Read never authorizes cleanup or a new launch. Bounded operations use the completed Source's original transport. Repair supplies no execution admission.");

pub fn run_dependency_command(args: &[String]) -> Result<Value, String> {
    if args.first().is_some_and(|s| {
        matches!(
            s.as_str(),
            "run-bounded"
                | "read-bounded"
                | "repair-bounded"
                | "prefix-stage"
                | "prefix-stage-read"
        )
    }) {
        return crate::native_operation::artifact::run_dependency_bounded_command(args);
    }
    match (args.first().map(String::as_str), args.len()) {
        (Some("inputs"), 8) => crate::prepare_local_dependency_inputs(
            Path::new(&args[1]),
            &args[2],
            &args[3],
            Path::new(&args[4]),
            &args[5],
            Path::new(&args[6]),
            &args[7],
        ),
        (Some("transfer"), 12 | 13) | (Some("transfer-read"), 13) => {
            crate::local_dependency_inputs::transfer(args)
        }
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
