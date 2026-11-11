//! Fixed cgroup-v2 containment and kill-and-drain primitives. Probe entrypoints
//! cannot select candidate code; the SDK tap group is derived from one run ID.

use crate::{
    hex, interpreter_exec::spawn_contained_interpreter_probe,
    launch_plan::rust_controller_cgroup_path, process_reap::reap_probe_child_bounded,
    HeldInterpreter,
};
use rustix::fs::{open, Mode, OFlags};
use serde_json::{json, Value};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::fd::{OwnedFd, RawFd};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const NAME: &str = "hol-gauntlet-rust-probe-20261020";
const GROUP: &str = "/system.slice/hol-gauntlet-rust-probe-20261020";
const MEMORY_LIMIT: &str = "536870912\n";
const PID_LIMIT: &str = "16\n";
const CPU_LIMIT: &str = "100000 100000\n";
const CONTROLLER_MEMORY_LIMIT: &str = "4294967296\n";
const CONTROLLER_PID_LIMIT: &str = "256\n";
const CONTROLLER_CPU_LIMIT: &str = "100000 100000\n";
const TAP_MEMORY_LIMIT: &str = "268435456\n";
const TAP_PID_LIMIT: &str = "32\n";
const TAP_CPU_LIMIT: &str = "50000 100000\n";
const POLL: Duration = Duration::from_millis(20);
const WAIT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupProbeError {
    RootRequired,
    InvalidJobId,
    ExistingGroup,
    UnsafeGroup,
    ControlUnavailable,
    Spawn,
    GrandchildUnavailable,
    KillUnavailable,
    DrainUnknown,
    CleanupUnavailable,
    InterpreterChanged,
    ChildIdentityUnknown,
}

impl fmt::Display for CgroupProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux Root required for isolated cgroup probe",
            Self::InvalidJobId => "probe job ID must be exactly 16 lowercase hex characters",
            Self::ExistingGroup => "fixed probe cgroup already exists; inspect it before retry",
            Self::UnsafeGroup => "fixed probe cgroup identity is unsafe or changed",
            Self::ControlUnavailable => "fixed cgroup controls are unavailable",
            Self::Spawn => "fixed inert child could not start or be reaped",
            Self::GrandchildUnavailable => "fixed child and grandchild were not both observed",
            Self::KillUnavailable => "fixed cgroup subtree kill failed",
            Self::DrainUnknown => "fixed cgroup subtree did not prove drained",
            Self::CleanupUnavailable => "drained fixed cgroup could not be removed",
            Self::InterpreterChanged => "held interpreter changed during contained probe",
            Self::ChildIdentityUnknown => "contained child credentials were not safely observed",
        })
    }
}

impl std::error::Error for CgroupProbeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupProbeProof {
    pub observed_tasks: u64,
}

impl CgroupProbeProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-cgroup-containment-probe.v1",
            "cgroup":GROUP,
            "observed_tasks":self.observed_tasks,
            "child_and_grandchild_observed":true,
            "recursive_kill_written":true,
            "drained_observed":true,
            "cgroup_removed":true,
            "benchmark_executed":false,
            "execution_eligible":false,
        })
    }
}

pub(crate) use crate::owned_cgroup::{GroupLimits, OwnedProbeGroup};

const PROBE_LIMITS: GroupLimits = GroupLimits {
    memory: MEMORY_LIMIT,
    pids: PID_LIMIT,
    cpu: CPU_LIMIT,
};

const CONTROLLER_LIMITS: GroupLimits = GroupLimits {
    memory: CONTROLLER_MEMORY_LIMIT,
    pids: CONTROLLER_PID_LIMIT,
    cpu: CONTROLLER_CPU_LIMIT,
};

const TAP_LIMITS: GroupLimits = GroupLimits {
    memory: TAP_MEMORY_LIMIT,
    pids: TAP_PID_LIMIT,
    cpu: TAP_CPU_LIMIT,
};

/// A Root-owned, job-ID-derived controller cgroup with a fixed 4-GiB,
/// 256-PID, one-CPU profile. Dropping this handle never implies cleanup;
/// terminal code must kill, drain and remove it under the active lease.
pub struct OwnedJobCgroup {
    inner: OwnedProbeGroup,
}

/// Separate one-use Root-owned SDK tap cgroup. It is never an eligibility
/// result, and dropping the handle never implies descendant cleanup.
pub struct OwnedSdkTapCgroup {
    inner: OwnedProbeGroup,
}

impl OwnedSdkTapCgroup {
    pub fn create(run_id: &str) -> Result<Self, CgroupProbeError> {
        if !hex(run_id, 16) {
            return Err(CgroupProbeError::InvalidJobId);
        }
        let name = format!("hol-gauntlet-rust-tap-{run_id}");
        let path = format!("/system.slice/{name}");
        Ok(Self {
            inner: OwnedProbeGroup::create_named(name, path, TAP_LIMITS)?,
        })
    }

    pub fn path(&self) -> &str {
        self.inner.path()
    }

    pub fn attach_child(&self, command: &mut Command) -> Result<(), CgroupProbeError> {
        self.inner.attach_child(command)
    }

    /// Return the held cgroup directory only after matching its visible
    /// Root-owned identity. `clone3(CLONE_INTO_CGROUP)` consumes this FD
    /// synchronously, so a PID-namespace child starts inside the tap limit.
    pub(crate) fn clone_into_fd(&self) -> Result<RawFd, CgroupProbeError> {
        self.inner.clone_into_fd()
    }

    pub fn kill(&self) -> Result<(), CgroupProbeError> {
        self.inner.kill()
    }

    pub fn drain_and_remove(&mut self) -> Result<(), CgroupProbeError> {
        self.inner.drain_and_remove()
    }
}

impl OwnedJobCgroup {
    pub fn create(job_id: &str) -> Result<Self, CgroupProbeError> {
        Ok(Self {
            inner: OwnedProbeGroup::create_job_with_limits(job_id, CONTROLLER_LIMITS)?,
        })
    }

    pub fn path(&self) -> &str {
        self.inner.path()
    }

    pub fn writer(&self) -> Result<OwnedFd, CgroupProbeError> {
        self.inner.writer()
    }

    pub fn tasks(&self) -> Result<u64, CgroupProbeError> {
        self.inner.tasks()
    }

    pub fn kill(&self) -> Result<(), CgroupProbeError> {
        self.inner.kill()
    }

    pub fn drain_and_remove(&mut self) -> Result<(), CgroupProbeError> {
        self.inner.drain_and_remove()
    }
}

fn check_unprivileged_child(pid: u32) -> Result<(), CgroupProbeError> {
    let path = format!("/proc/{pid}/status");
    let fd = open(
        path.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CgroupProbeError::ChildIdentityUnknown)?;
    let mut bytes = Vec::new();
    File::from(fd)
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CgroupProbeError::ChildIdentityUnknown)?;
    if bytes.len() > 16 * 1024 {
        return Err(CgroupProbeError::ChildIdentityUnknown);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| CgroupProbeError::ChildIdentityUnknown)?;
    let uid = text
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or(CgroupProbeError::ChildIdentityUnknown)?;
    let no_new_privs = text
        .lines()
        .find(|line| line.starts_with("NoNewPrivs:"))
        .ok_or(CgroupProbeError::ChildIdentityUnknown)?;
    let zero_capabilities = ["CapPrm:", "CapEff:", "CapAmb:"].iter().all(|label| {
        text.lines()
            .find(|line| line.starts_with(label))
            .is_some_and(|line| {
                line.split_ascii_whitespace().collect::<Vec<_>>() == [*label, "0000000000000000"]
            })
    });
    if uid.split_ascii_whitespace().collect::<Vec<_>>()
        != ["Uid:", "65534", "65534", "65534", "65534"]
        || no_new_privs.split_ascii_whitespace().collect::<Vec<_>>() != ["NoNewPrivs:", "1"]
        || !zero_capabilities
    {
        return Err(CgroupProbeError::ChildIdentityUnknown);
    }
    Ok(())
}

impl OwnedProbeGroup {
    pub(crate) fn create() -> Result<Self, CgroupProbeError> {
        Self::create_named(NAME.to_owned(), GROUP.to_owned(), PROBE_LIMITS)
    }

    fn create_job(job_id: &str) -> Result<Self, CgroupProbeError> {
        Self::create_job_with_limits(job_id, PROBE_LIMITS)
    }

    fn create_job_with_limits(job_id: &str, limits: GroupLimits) -> Result<Self, CgroupProbeError> {
        let path =
            rust_controller_cgroup_path(job_id).map_err(|_| CgroupProbeError::InvalidJobId)?;
        let name = path
            .strip_prefix("/system.slice/")
            .ok_or(CgroupProbeError::InvalidJobId)?
            .to_owned();
        Self::create_named(name, path, limits)
    }
}

/// Create only the fixed probe group, run a fixed short-lived shell/sleep
/// child pair, kill the cgroup subtree, prove it drained and remove it. On
/// uncertain cleanup the cgroup is retained for inspection, never reported
/// as a successful terminal benchmark or silently reused.
pub fn run_fixed_cgroup_probe() -> Result<CgroupProbeProof, CgroupProbeError> {
    let observed_tasks = run_inert_group_probe(OwnedProbeGroup::create()?)?;
    Ok(CgroupProbeProof { observed_tasks })
}

/// Inert per-job cgroup exercise. The job ID is fixed in the probe, and the
/// same create/kill/drain code refuses any pre-existing or unsafe cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobCgroupProbeProof {
    pub observed_tasks: u64,
    pub cgroup: String,
}

impl JobCgroupProbeProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-rust-job-cgroup-probe.v1",
            "job_id":"0123456789abcdef",
            "cgroup":self.cgroup,
            "observed_tasks":self.observed_tasks,
            "child_and_grandchild_observed":true,
            "recursive_kill_written":true,
            "drained_observed":true,
            "cgroup_removed":true,
            "controller_executed":false,
            "execution_eligible":false,
        })
    }
}

pub fn run_fixed_job_cgroup_probe() -> Result<JobCgroupProbeProof, CgroupProbeError> {
    let group = OwnedProbeGroup::create_job("0123456789abcdef")?;
    let cgroup = group.path().to_owned();
    let observed_tasks = run_inert_group_probe(group)?;
    Ok(JobCgroupProbeProof {
        observed_tasks,
        cgroup,
    })
}

fn run_inert_group_probe(mut group: OwnedProbeGroup) -> Result<u64, CgroupProbeError> {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "/usr/bin/sleep 5 & wait"])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Err(error) = group.attach_child(&mut command) {
        if error != CgroupProbeError::UnsafeGroup {
            group.remove_empty()?;
        }
        return Err(error);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            drop(command);
            group.remove_empty()?;
            return Err(CgroupProbeError::Spawn);
        }
    };
    drop(command);
    let started = Instant::now();
    let observed_tasks = loop {
        match group.tasks() {
            Ok(tasks) if tasks >= 2 => break Ok(tasks),
            Ok(_) if started.elapsed() < WAIT => thread::sleep(POLL),
            Ok(_) => break Err(CgroupProbeError::GrandchildUnavailable),
            Err(error) => break Err(error),
        }
    };
    let killed = group.kill();
    let reaped = reap_probe_child_bounded(&mut child);
    let drained = group.drain_and_remove();
    let observed_tasks = observed_tasks?;
    killed?;
    reaped?;
    drained?;
    Ok(observed_tasks)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainedInterpreterProbeProof {
    pub observed_tasks: u64,
    pub interpreter_sha256: String,
}

impl ContainedInterpreterProbeProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-contained-interpreter-probe.v1",
            "cgroup":GROUP,
            "observed_tasks":self.observed_tasks,
            "interpreter_sha256":self.interpreter_sha256,
            "child_uid":65534,
            "child_uid_kernel_observed":true,
            "no_new_privileges_kernel_observed":true,
            "child_capabilities_zero_kernel_observed":true,
            "execveat_fd_bound":true,
            "python_site_disabled":true,
            "recursive_kill_written":true,
            "drained_observed":true,
            "cgroup_removed":true,
            "controller_executed":false,
            "benchmark_executed":false,
            "execution_eligible":false,
        })
    }
}

/// Join the held executable and fixed cgroup in one inert launch. The child
/// enters the group as Root, drops to nobody before exec, then the fixed
/// Python snippet forks once and sleeps. This proves process containment of
/// the descriptor-bound interpreter, not controller or benchmark eligibility.
pub fn run_fixed_contained_interpreter_probe(
    interpreter: &HeldInterpreter,
) -> Result<ContainedInterpreterProbeProof, CgroupProbeError> {
    interpreter
        .assert_unchanged()
        .map_err(|_| CgroupProbeError::InterpreterChanged)?;
    let mut group = OwnedProbeGroup::create()?;
    let writer = match group.writer() {
        Ok(writer) => writer,
        Err(error) => {
            group.remove_empty()?;
            return Err(error);
        }
    };
    let mut child = match spawn_contained_interpreter_probe(interpreter, writer) {
        Ok(child) => child,
        Err(_) => {
            group.drain_and_remove()?;
            return Err(CgroupProbeError::Spawn);
        }
    };
    let started = Instant::now();
    let observed_tasks = loop {
        match group.tasks() {
            Ok(tasks) if tasks >= 2 => break Ok(tasks),
            Ok(_) if started.elapsed() < WAIT => thread::sleep(POLL),
            Ok(_) => break Err(CgroupProbeError::GrandchildUnavailable),
            Err(error) => break Err(error),
        }
    };
    let child_identity = check_unprivileged_child(child.id());
    let killed = group.kill();
    let reaped = reap_probe_child_bounded(&mut child);
    let drained = group.drain_and_remove();
    let interpreter_unchanged = interpreter
        .assert_unchanged()
        .map_err(|_| CgroupProbeError::InterpreterChanged);
    let observed_tasks = observed_tasks?;
    child_identity?;
    killed?;
    reaped?;
    drained?;
    interpreter_unchanged?;
    Ok(ContainedInterpreterProbeProof {
        observed_tasks,
        interpreter_sha256: interpreter.declaration().sha256.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_group_refuses_a_cgroup_name_selector() {
        assert!(matches!(
            OwnedProbeGroup::create_job("../system.slice"),
            Err(CgroupProbeError::InvalidJobId)
        ));
        assert!(matches!(
            OwnedProbeGroup::create_job("0123456789ABCDEF"),
            Err(CgroupProbeError::InvalidJobId)
        ));
    }
}
