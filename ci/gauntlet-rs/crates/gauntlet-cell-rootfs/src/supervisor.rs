//! Root owns the service, outside measurements, private bootstrap and cleanup.
use crate::inputs::Inputs;
use crate::supervisor_cleanup::absent;
use crate::supervisor_io::{helper, kernel_file, marker, nonblocking, release_initializer};
use crate::supervisor_journal::Journal;
use crate::{
    CellProcessExpectation, CpuProfile, HeldCellProcess, Result, RootfsSpec, SupervisorSpec,
};
use gauntlet_agent_bridge::{BootstrapKind, BridgeChannel, BridgeClient, OutboundBootstrap};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{Duration, Instant};

pub struct NativeCell {
    pub(crate) inputs: Inputs,
    pub(crate) spec: SupervisorSpec,
    pub(crate) profile: String,
    pub(crate) cgroup: PathBuf,
    pub(crate) cpu: Option<u32>,
    pub(crate) actor: Option<HeldCellProcess>,
    pub(crate) children: BTreeMap<String, HeldCellProcess>,
    pub(crate) output_counts: BTreeMap<String, u64>,
    pub(crate) client: Option<BridgeClient>,
    pub(crate) cancelled: Arc<AtomicBool>,
    pub(crate) journal: Journal,
    pub(crate) process: Option<Child>,
    pub(crate) errors: Option<OwnedFd>,
    pub(crate) loaded: bool,
    pub(crate) service_started: bool,
    pub(crate) service_observed: bool,
    pub(crate) closed: bool,
    pub(crate) image: Option<crate::image_lease::ImageLease>,
    pub(crate) image_interpreter: Option<crate::image_interpreter::HeldImageInterpreter>,
    declaration_sha256: String,
    actor_sha256: String,
}

fn selected_cpu(profile: CpuProfile) -> Result<Option<u32>> {
    if profile == CpuProfile::Quota {
        return Ok(None);
    }
    let raw = String::from_utf8(kernel_file(Path::new("/proc/self/status"), 65536)?)
        .map_err(|_| "own status UTF-8")?;
    let value = raw
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .ok_or("own CPU allocation unavailable")?;
    let first = value
        .trim()
        .split([',', '-'])
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|n| *n < 4096)
        .ok_or("bounded own CPU allocation required")?;
    Ok(Some(first))
}

impl NativeCell {
    pub fn runtime_prefix(&self) -> &Path {
        &self.inputs.runtime.prefix
    }
    pub fn workspace_path(&self) -> &str {
        &self.inputs.system.workspace
    }
    pub fn workspace_source(&self) -> &Path {
        &self.inputs.tasks[0].source
    }
    pub fn actor_observation(&self) -> Option<&Value> {
        self.actor.as_ref().map(HeldCellProcess::observation)
    }
    pub fn cleanup_complete(&self) -> bool {
        self.closed
    }
    pub(crate) fn capture_journal_binding(&self) -> Result<Value> {
        self.journal.binding()
    }
    pub fn supervisor_declaration_sha256(&self) -> &str {
        &self.declaration_sha256
    }
    pub fn image_lease_owned(&self) -> bool {
        self.image.is_some()
    }

    pub fn start(
        declaration: &Path,
        expected_sha256: &str,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        Self::start_with_image(declaration, expected_sha256, cancelled, None)
    }

    pub(crate) fn start_with_image(
        declaration: &Path,
        expected_sha256: &str,
        cancelled: Arc<AtomicBool>,
        image: Option<crate::image_lease::ImageLease>,
    ) -> Result<Self> {
        crate::kernel_process::root_proc()?;
        let raw = crate::fs_input::pinned(declaration, 8192, expected_sha256)?;
        let spec = SupervisorSpec::parse(&raw, expected_sha256)?;
        for (path, pin) in &spec.host_helpers {
            crate::fs_input::pinned(Path::new(path), 16 * 1024 * 1024, pin)?;
        }
        crate::fs_input::pinned(
            &spec.constructor,
            16 * 1024 * 1024,
            &spec.constructor_sha256,
        )?;
        let raw = crate::fs_input::pinned(&spec.rootfs_declaration, 8192, &spec.rootfs_sha256)?;
        let rootfs = RootfsSpec::parse(&raw, &spec.rootfs_sha256)?;
        if spec.rootfs_declaration.parent() != Some(rootfs.stage.as_path()) {
            return Err("rootfs declaration must belong to its exact owned stage".into());
        }
        let inputs = crate::inputs::load(rootfs)?;
        let image_interpreter = spec
            .image_interpreter_sha256
            .as_deref()
            .map(|pin| crate::image_interpreter::HeldImageInterpreter::open(&inputs.image, pin))
            .transpose()?;
        if !absent(&inputs.spec.stage.join("rootfs"))? {
            return Err("one-use product rootfs already exists".into());
        }
        let profile = format!("hol-product-cell-{}", crate::nonce()?);
        let cgroup = spec.cgroup_path(&profile)?;
        crate::fs_input::directory(cgroup.parent().ok_or("owned cgroup parent required")?)?;
        if !absent(&cgroup)? {
            return Err("fresh product cgroup already exists".into());
        }
        let manifest = crate::fs_input::pinned(
            &inputs.spec.stage.join("cell-artifact-manifest.json"),
            1024 * 1024,
            &inputs.spec.artifact_manifest_sha256,
        )?;
        let manifest = gauntlet_evidence::verify_native_private_cell_manifest(
            &manifest,
            &inputs.spec.artifact_manifest_sha256,
            &inputs.spec.initializer_sha256,
        )
        .map_err(|e| e.to_string())?;
        let actor_sha256 = manifest
            .native_actor_sha256()
            .ok_or("native actor pin required")?
            .to_owned();
        let cpu = selected_cpu(spec.cpu)?;
        let mut journal = Journal::create(&inputs.spec.stage)?;
        journal.append("prepared",json!({"supervisor_declaration_sha256":expected_sha256,
            "rootfs_declaration_sha256":spec.rootfs_sha256,"constructor_sha256":spec.constructor_sha256,
            "profile":profile,"cgroup":cgroup,"cpu":cpu,"execution_eligible":false}))?;
        if let Some(pin) = &image_interpreter {
            let mut value = pin.observation();
            value["outside_observer_declared_sha256"] = json!(spec.outside_observer_sha256);
            journal.append("image-interpreter-pinned", value)?;
        }
        let mut cell = Self {
            inputs,
            spec,
            profile,
            cgroup,
            cpu,
            actor: None,
            children: BTreeMap::new(),
            output_counts: BTreeMap::new(),
            client: None,
            cancelled,
            journal,
            process: None,
            errors: None,
            loaded: false,
            service_started: false,
            service_observed: false,
            closed: false,
            image,
            image_interpreter,
            declaration_sha256: expected_sha256.into(),
            actor_sha256,
        };
        if let Err(error) = cell.launch() {
            let _ = cell
                .journal
                .append("startup-failure", json!({"error":error}));
            return match cell.close() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!("{error}; cleanup uncertain: {cleanup}")),
            };
        }
        Ok(cell)
    }

    fn expectation(
        &self,
        filtered: bool,
        local_pid: u32,
        argv: Vec<String>,
    ) -> Result<CellProcessExpectation> {
        let relative = self
            .cgroup
            .strip_prefix("/sys/fs/cgroup")
            .map_err(|_| "fixed cgroup root required")?
            .to_str()
            .ok_or("UTF-8 product cgroup required")?
            .to_owned();
        let cgroup = format!("/{relative}");
        Ok(CellProcessExpectation {
            profile: self.profile.clone(),
            cgroup,
            local_pid,
            argv,
            executable_sha256: if filtered {
                self.actor_sha256.clone()
            } else {
                self.inputs.spec.initializer_sha256.clone()
            },
            filtered,
            cpu: self.cpu,
        })
    }

    pub(crate) fn find(&self, expected: CellProcessExpectation) -> Result<HeldCellProcess> {
        let raw = kernel_file(&self.cgroup.join("cgroup.procs"), 4096)?;
        let text = std::str::from_utf8(&raw).map_err(|_| "kernel cgroup PID UTF-8")?;
        let pids = text
            .split_ascii_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| "kernel cgroup PID syntax")?;
        if pids.len() > 128 {
            return Err("product task count exceeds kernel ceiling".into());
        }
        let mut result = None;
        for pid in pids {
            if let Ok(process) = HeldCellProcess::observe(pid, expected.clone()) {
                if result.is_some() {
                    return Err("multiple matching product processes".into());
                }
                result = Some(process);
            }
        }
        result.ok_or_else(|| "no unique outside-measured product process".into())
    }

    fn launch(&mut self) -> Result<()> {
        self.recheck_image_interpreter()?;
        let profile_path = self.inputs.spec.stage.join("native-cell.apparmor");
        let template = include_str!("../../../../gauntlet/benchmark/product_vm.apparmor");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&profile_path)
            .map_err(|e| e.to_string())?;
        use std::io::Write;
        file.write_all(
            template
                .replace("HOL_PRODUCT_VM_PROFILE", &self.profile)
                .as_bytes(),
        )
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
        // The parser may have changed kernel policy before an uncertain exit.
        // Always retain and attempt cleanup of this fresh, exclusively owned name.
        self.loaded = true;
        self.run_helper(
            "/usr/sbin/apparmor_parser",
            &["--add".into(), profile_path.to_string_lossy().into()],
            Duration::from_secs(10),
        )?;
        let mut argv = vec![
            "--quiet".into(),
            "--collect".into(),
            "--wait".into(),
            "--pipe".into(),
            format!("--unit={}.service", self.profile),
            "--property=MemoryMax=1G".into(),
            "--property=TasksMax=128".into(),
            "--property=CPUQuota=100%".into(),
            format!("--property=RuntimeMaxSec={}", self.spec.wall_seconds),
            "--property=TimeoutStopSec=2".into(),
            "--property=KillMode=control-group".into(),
        ];
        if let Some(slice) = &self.spec.job_slice {
            argv.push(format!("--slice={slice}"));
        }
        if let Some(cpu) = self.cpu {
            argv.extend([
                format!("--property=AllowedCPUs={cpu}"),
                format!("--property=CPUAffinity={cpu}"),
            ]);
        }
        argv.extend([
            "/usr/bin/aa-exec".into(),
            "-p".into(),
            self.profile.clone(),
            "--".into(),
            "/usr/bin/unshare".into(),
            "--mount".into(),
            "--pid".into(),
            "--net".into(),
            "--ipc".into(),
            "--uts".into(),
            "--cgroup".into(),
            "--fork".into(),
            "--kill-child=KILL".into(),
            self.spec.constructor.to_string_lossy().into(),
            self.spec.rootfs_declaration.to_string_lossy().into(),
            self.spec.rootfs_sha256.clone(),
        ]);
        crate::fs_input::pinned(
            &self.spec.constructor,
            16 * 1024 * 1024,
            &self.spec.constructor_sha256,
        )?;
        if let Some(image) = &mut self.image {
            image.before_cell_launch()?;
        }
        let mut child = Command::new("/usr/bin/systemd-run")
            .args(argv)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|e| e.to_string())?;
        self.service_started = true;
        let reader: OwnedFd = child
            .stdout
            .take()
            .ok_or("product stdout pipe missing")?
            .into();
        let writer: OwnedFd = child
            .stdin
            .take()
            .ok_or("product stdin pipe missing")?
            .into();
        self.errors = Some(
            child
                .stderr
                .take()
                .ok_or("product stderr pipe missing")?
                .into(),
        );
        self.process = Some(child);
        nonblocking(&reader)?;
        nonblocking(&writer)?;
        nonblocking(self.errors.as_ref().unwrap())?;
        marker(
            &reader,
            b"HOL_CELL_READY_V1\n",
            Instant::now() + Duration::from_secs(5),
            &self.cancelled,
        )?;
        let initial = self.find(self.expectation(
            false,
            1,
            vec![
                "/public/initializer".into(),
                "/public/gauntlet-product-cell".into(),
                "actor".into(),
            ],
        )?)?;
        self.service_observed = true;
        let mounts =
            initial.verify_task_mounts(&self.inputs.tasks, &self.inputs.runtime.mountpoint)?;
        self.journal.append("idmapped-task-mounts", mounts)?;
        self.journal
            .append("before-cell-gate", initial.observation().clone())?;
        release_initializer(
            &writer,
            Instant::now() + Duration::from_secs(5),
            &self.cancelled,
        )?;
        marker(
            &reader,
            b"HOL_CELL_FILTER_READY_V1\n",
            Instant::now() + Duration::from_secs(5),
            &self.cancelled,
        )?;
        let filtered = initial.after_filter_gate(self.expectation(
            true,
            1,
            vec!["/public/gauntlet-product-cell".into(), "actor".into()],
        )?)?;
        self.journal
            .append("filtered-cell", filtered.observation().clone())?;
        self.actor = Some(filtered);
        for (name, expected) in [
            ("memory.max", "1073741824"),
            ("pids.max", "128"),
            ("cpu.max", "100000 100000"),
        ] {
            let actual = String::from_utf8(kernel_file(&self.cgroup.join(name), 4096)?)
                .map_err(|_| "cgroup value UTF-8")?;
            if actual.trim() != expected {
                return Err("actual product cgroup resource ceiling differs".into());
            }
        }
        if let Some(cpu) = self.cpu {
            let actual = String::from_utf8(kernel_file(
                &self.cgroup.join("cpuset.cpus.effective"),
                4096,
            )?)
            .map_err(|_| "cpuset UTF-8")?;
            if actual.trim() != cpu.to_string() {
                return Err("actual product cpuset differs".into());
            }
        }
        self.journal.append("resource-ceilings",json!({"memory_max":1073741824,"pids_max":128,"cpu_max":"100000 100000","cpu":self.cpu}))?;
        let boot = String::from_utf8(kernel_file(
            Path::new("/proc/sys/kernel/random/boot_id"),
            128,
        )?)
        .map_err(|_| "boot identity UTF-8")?;
        let codec = OutboundBootstrap::generate(
            BootstrapKind::ProductCellSupervisor,
            boot.trim(),
            boot.trim(),
            None,
        )
        .and_then(|b| {
            b.deliver(
                &writer,
                Instant::now() + Duration::from_secs(5),
                &self.cancelled,
                10000,
                256 * 1024 * 1024,
            )
        })
        .map_err(|e| e.to_string())?;
        self.client = Some(BridgeClient::new(
            BridgeChannel::new(reader, writer, codec).map_err(|e| e.to_string())?,
        ));
        let hello = self.call("hello", &json!({}), Instant::now() + Duration::from_secs(5))?;
        if hello
            != json!({"schema":"product-cell-actor.v2","local_pid":1,"uid":10004,"gid":10004,
            "limits":{"active_children":64,"total_spawns":1024,"read_wait_ms":100}})
        {
            return Err("actual actor hello differs".into());
        }
        self.journal
            .append("actor-ready", json!({"schema":"product-cell-actor.v2"}))
    }

    pub(crate) fn call(
        &self,
        operation: &str,
        payload: &Value,
        deadline: Instant,
    ) -> Result<Value> {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5));
        self.client
            .as_ref()
            .ok_or("product client unavailable")?
            .call(operation, payload, left, &self.cancelled)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn run_helper(
        &self,
        program: &'static str,
        args: &[String],
        limit: Duration,
    ) -> Result<()> {
        let expected = self
            .spec
            .host_helpers
            .get(program)
            .ok_or("fixed pinned Root helper required")?;
        crate::fs_input::pinned(Path::new(program), 16 * 1024 * 1024, expected)?;
        helper(program, args, limit)?;
        crate::fs_input::pinned(Path::new(program), 16 * 1024 * 1024, expected)?;
        Ok(())
    }

    pub(crate) fn child_expectation(
        &self,
        local_pid: u32,
        argv: &[String],
    ) -> Result<CellProcessExpectation> {
        let mut expected = vec!["/public/gauntlet-product-cell".into(), "exec-gate".into()];
        expected.extend_from_slice(argv);
        self.expectation(true, local_pid, expected)
    }
}
