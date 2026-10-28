//! Root owns the service, outside measurements, private bootstrap and cleanup.
use crate::inputs::Inputs;
use crate::supervisor_cleanup::absent;
use crate::supervisor_io::{helper, kernel_file};
use crate::supervisor_journal::Journal;
use crate::{
    CellProcessExpectation, CpuProfile, HeldCellProcess, Result, RootfsSpec, SupervisorSpec,
};
use gauntlet_agent_bridge::BridgeClient;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::{Duration, Instant};

#[path = "supervisor_launch.rs"]
mod launch;

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
    pub(crate) process_events: Option<crate::NativeProcessEvents>,
    pub(crate) process_events_result: Option<Result<Value>>,
    pub(crate) process_events_journaled: bool,
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
            process_events: None,
            process_events_result: None,
            process_events_journaled: false,
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
            tracer_tid: self
                .process_events
                .as_ref()
                .map(crate::NativeProcessEvents::tracer_tid),
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

    pub(crate) fn call(
        &self,
        operation: &str,
        payload: &Value,
        deadline: Instant,
    ) -> Result<Value> {
        self.recorder_health()?;
        let left = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5));
        let response = self
            .client
            .as_ref()
            .ok_or("product client unavailable")?
            .call(operation, payload, left, &self.cancelled)
            .map_err(|e| e.to_string());
        match (response, self.recorder_health()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(recorder)) => Err(format!("{error}; process recorder: {recorder}")),
        }
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
