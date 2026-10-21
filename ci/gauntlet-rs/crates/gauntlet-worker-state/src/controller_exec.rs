//! Descriptor-bound Root controller launch primitive. It accepts only a
//! `PreparedLaunch` produced by the fixed prelaunch reader and the matching
//! job-owned cgroup. The caller still owns lease, deadline, report, product
//! slice and terminal reconciliation; spawning is not a benchmark verdict.

use crate::contained_probe::{CgroupProbeError, OwnedJobCgroup};
use crate::interpreter_exec::InterpreterExecError;
use crate::launch_plan::{rust_controller_cgroup_path, rust_job_slice_name};
use crate::linux_process::{observe_process, parse_proc_stat, ProcessObservationError};
use crate::prelaunch::{PrelaunchError, PreparedLaunch};
use crate::process_reap::reap_probe_child_bounded;
use crate::{
    open_canonical_directory, open_root_owned_public_directory, ActiveLease, HeldInterpreter,
    ReservationError, RunReservationJournal, StartedMarker,
};
use gauntlet_contracts::WorkerRequest;
use rustix::fs::{fstat, fsync, openat, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_ARGV: usize = 22;
const ENV_KEYS: [&str; 4] = ["HOL_GAUNTLET_RUST_JOB_SLICE", "HOME", "LANG", "PATH"];
const PROBE_JOB_ID: &str = "a1b2c3d4e5f60718";
const PROBE_CODE: &str = "import os,time;os.fork();time.sleep(5)";
const OUTPUT_DIRECTORY: &str = "/var/lib/hol-gauntlet/outputs";
const POLL: Duration = Duration::from_millis(20);
const WAIT: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub enum ControllerExecError {
    RootRequired,
    InvalidPlan,
    UnsafeLog,
    Prelaunch(PrelaunchError),
    Reservation(ReservationError),
    Interpreter(InterpreterExecError),
    Cgroup(CgroupProbeError),
    Process(ProcessObservationError),
    Spawn,
    ChildIdentityUnknown,
    CleanupUncertain,
}

impl fmt::Display for ControllerExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootRequired => f.write_str("Linux Root required for controller launch"),
            Self::InvalidPlan => {
                f.write_str("fixed controller launch plan differs from held inputs")
            }
            Self::UnsafeLog => f.write_str("Root-owned private controller log required"),
            Self::Prelaunch(error) => write!(f, "prelaunch custody changed: {error}"),
            Self::Reservation(error) => write!(f, "worker reservation: {error}"),
            Self::Interpreter(error) => write!(f, "interpreter execution: {error}"),
            Self::Cgroup(error) => write!(f, "controller cgroup: {error}"),
            Self::Process(error) => write!(f, "controller process identity: {error:?}"),
            Self::Spawn => f.write_str("descriptor-bound Root child could not start or be reaped"),
            Self::ChildIdentityUnknown => f.write_str("Root child credentials are unavailable"),
            Self::CleanupUncertain => f.write_str("Root child cleanup could not be proven"),
        }
    }
}

impl std::error::Error for ControllerExecError {}

fn cstring(value: &str) -> Result<CString, ControllerExecError> {
    CString::new(value).map_err(|_| ControllerExecError::InvalidPlan)
}

fn fixed_environment(
    environment: &BTreeMap<&'static str, String>,
) -> Result<Vec<CString>, ControllerExecError> {
    if environment.len() != ENV_KEYS.len()
        || environment.keys().copied().collect::<Vec<_>>() != ENV_KEYS
    {
        return Err(ControllerExecError::InvalidPlan);
    }
    environment
        .iter()
        .map(|(name, value)| cstring(&format!("{name}={value}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_environment_accepts_only_the_four_fixed_keys() {
        let mut environment = BTreeMap::from([
            (
                "HOL_GAUNTLET_RUST_JOB_SLICE",
                "holgauntletrust1234567890abcdef.slice".to_owned(),
            ),
            ("HOME", "/root".to_owned()),
            ("LANG", "C.UTF-8".to_owned()),
            ("PATH", "/usr/bin:/bin".to_owned()),
        ]);
        assert_eq!(fixed_environment(&environment).unwrap().len(), 4);
        environment.remove("HOME");
        assert!(matches!(
            fixed_environment(&environment),
            Err(ControllerExecError::InvalidPlan)
        ));
        environment.insert("HOME", "/root".to_owned());
        environment.insert("UNTRUSTED", "value".to_owned());
        assert!(matches!(
            fixed_environment(&environment),
            Err(ControllerExecError::InvalidPlan)
        ));
    }
}

/// Replace `/usr/bin/false` before it can execute. All strings, pointers,
/// descriptors and output handles are prepared in the parent. The child
/// performs only fixed syscalls before `execveat(AT_EMPTY_PATH)`.
#[allow(clippy::too_many_arguments)]
fn spawn_root_fd(
    interpreter: &HeldInterpreter,
    argv: &[String],
    environment: &BTreeMap<&'static str, String>,
    cwd: OwnedFd,
    cgroup_writer: OwnedFd,
    stdout: Stdio,
    stderr: Stdio,
) -> Result<Child, ControllerExecError> {
    if argv.is_empty() || argv.len() > MAX_ARGV || argv[0] != interpreter.declaration().python_path
    {
        return Err(ControllerExecError::InvalidPlan);
    }
    let args: Vec<CString> = argv
        .iter()
        .map(|value| cstring(value))
        .collect::<Result<_, _>>()?;
    let env = fixed_environment(environment)?;
    let argument_ptrs: Vec<usize> = args.iter().map(|value| value.as_ptr() as usize).collect();
    let environment_ptrs: Vec<usize> = env.iter().map(|value| value.as_ptr() as usize).collect();
    let executable = interpreter
        .checked_fd()
        .map_err(|_| ControllerExecError::Interpreter(InterpreterExecError::InvalidInterpreter))?;
    let executable_fd = executable.as_raw_fd();
    let mut command = Command::new("/usr/bin/false");
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    // SAFETY: no allocation or lock is taken after fork. The fixed cgroup
    // writer and already-opened cwd/executable descriptors remain alive until
    // the syscall replaces the child or `Command::spawn` returns an error.
    unsafe {
        command.pre_exec(move || {
            let _keep_args = &args;
            let _keep_env = &env;
            let mut pid = libc::getpid() as u32;
            let mut digits = [0u8; 10];
            let mut start = digits.len();
            loop {
                start -= 1;
                digits[start] = b'0' + (pid % 10) as u8;
                pid /= 10;
                if pid == 0 {
                    break;
                }
            }
            let bytes = &digits[start..];
            let written = libc::write(
                cgroup_writer.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
            );
            if written != bytes.len() as isize {
                return Err(if written < 0 {
                    io::Error::last_os_error()
                } else {
                    io::Error::from_raw_os_error(libc::EIO)
                });
            }
            if libc::fchdir(cwd.as_raw_fd()) != 0
                || libc::setsid() < 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            let mut argv_ptrs = [std::ptr::null(); MAX_ARGV + 1];
            for (slot, pointer) in argv_ptrs.iter_mut().zip(&argument_ptrs) {
                *slot = *pointer as *const libc::c_char;
            }
            let mut env_ptrs = [std::ptr::null(); ENV_KEYS.len() + 1];
            for (slot, pointer) in env_ptrs.iter_mut().zip(&environment_ptrs) {
                *slot = *pointer as *const libc::c_char;
            }
            libc::syscall(
                libc::SYS_execveat,
                executable_fd,
                c"".as_ptr(),
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            Err(io::Error::last_os_error())
        });
    }
    command.spawn().map_err(|_| ControllerExecError::Spawn)
}

/// Internal launch step for a future worker dispatcher. A verified one-time
/// marker and matching lease are mandatory; the caller must still retain the
/// lease, child and cgroup through deadline, report, product-slice cleanup and
/// terminal reconciliation. Until that owner exists, this is not exported.
#[allow(dead_code)]
pub(crate) fn spawn_prepared_controller(
    prepared: &PreparedLaunch,
    group: &OwnedJobCgroup,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    request: &WorkerRequest,
    worker_generation: &str,
) -> Result<(Child, StartedMarker), ControllerExecError> {
    if geteuid().as_raw() != 0 {
        return Err(ControllerExecError::RootRequired);
    }
    if !journal.root_owned {
        return Err(ControllerExecError::Reservation(
            ReservationError::UnsafeRoot,
        ));
    }
    lease
        .verify(&journal.root)
        .map_err(ControllerExecError::Reservation)?;
    let plan = prepared.launch_plan();
    if !prepared.matches_run_request(request)
        || rust_controller_cgroup_path(request.job_id())
            .ok()
            .as_deref()
            != Some(plan.controller_cgroup())
        || rust_job_slice_name(request.job_id()).ok().as_deref() != Some(plan.job_slice())
        || group.path() != plan.controller_cgroup()
        || plan.fixed().argv.len() != MAX_ARGV
        || plan.fixed().argv[0] != prepared.interpreter().declaration().python_path
    {
        return Err(ControllerExecError::InvalidPlan);
    }
    prepared
        .recheck_controller_and_interpreter()
        .map_err(ControllerExecError::Prelaunch)?;
    let deployment_digest = request
        .deployment_digest()
        .ok_or(ControllerExecError::InvalidPlan)?;
    let started = journal
        .reserve_under_lease(
            lease,
            request,
            request.source_sha(),
            deployment_digest,
            worker_generation,
        )
        .map_err(ControllerExecError::Reservation)?;
    let log = open_fixed_log(request.job_id(), &plan.fixed().log_path)?;
    let cwd = open_root_owned_public_directory(Path::new(&plan.fixed().cwd))
        .map_err(|_| ControllerExecError::InvalidPlan)?;
    let writer = group.writer().map_err(ControllerExecError::Cgroup)?;
    let mut child = spawn_root_fd(
        prepared.interpreter(),
        &plan.fixed().argv,
        &plan.environment(),
        cwd,
        writer,
        Stdio::from(
            log.try_clone()
                .map_err(|_| ControllerExecError::UnsafeLog)?,
        ),
        Stdio::from(
            log.try_clone()
                .map_err(|_| ControllerExecError::UnsafeLog)?,
        ),
    )?;
    let post_check = prepared
        .recheck_controller_and_interpreter()
        .map_err(ControllerExecError::Prelaunch)
        .and_then(|()| {
            lease
                .verify(&journal.root)
                .map_err(ControllerExecError::Reservation)
        })
        .and_then(|()| {
            let retained = journal
                .started(
                    request.job_id(),
                    request.source_sha(),
                    deployment_digest,
                    worker_generation,
                )
                .map_err(ControllerExecError::Reservation)?;
            if retained.as_ref() == Some(&started) {
                Ok(())
            } else {
                Err(ControllerExecError::Reservation(
                    ReservationError::InvalidMarker,
                ))
            }
        });
    if let Err(error) = post_check {
        let killed = group.kill();
        let reaped = reap_probe_child_bounded(&mut child);
        if killed.is_err() || reaped.is_err() {
            return Err(ControllerExecError::CleanupUncertain);
        }
        return Err(error);
    }
    Ok((child, started))
}

fn open_fixed_log(job_id: &str, declared_path: &str) -> Result<File, ControllerExecError> {
    if declared_path != format!("{OUTPUT_DIRECTORY}/{job_id}.log") {
        return Err(ControllerExecError::UnsafeLog);
    }
    let output = open_canonical_directory(Path::new(OUTPUT_DIRECTORY), true)
        .map_err(|_| ControllerExecError::UnsafeLog)?;
    let filename = format!("{job_id}.log");
    let descriptor = openat(
        &output,
        filename.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| ControllerExecError::UnsafeLog)?;
    let metadata = fstat(&descriptor).map_err(|_| ControllerExecError::UnsafeLog)?;
    if metadata.st_uid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o077 != 0
        || metadata.st_size != 0
    {
        return Err(ControllerExecError::UnsafeLog);
    }
    fsync(&descriptor).map_err(|_| ControllerExecError::UnsafeLog)?;
    fsync(&output).map_err(|_| ControllerExecError::UnsafeLog)?;
    Ok(File::from(descriptor))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootControllerProbeProof {
    pub cgroup: String,
    pub observed_tasks: u64,
    pub interpreter_sha256: String,
    pub pid: u32,
    pub start_ticks: u64,
}

impl RootControllerProbeProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-root-controller-exec-probe.v1",
            "job_id":PROBE_JOB_ID,
            "cgroup":self.cgroup,
            "observed_tasks":self.observed_tasks,
            "interpreter_sha256":self.interpreter_sha256,
            "pid":self.pid,
            "process_start_ticks":self.start_ticks,
            "root_uid_kernel_observed":true,
            "no_new_privileges_kernel_observed":true,
            "execveat_fd_bound":true,
            "resource_profile":{"memory_max":4294967296_u64,"pids_max":256,"cpu_max":"100000 100000"},
            "recursive_kill_written":true,
            "drained_observed":true,
            "cgroup_removed":true,
            "controller_executed":false,
            "benchmark_executed":false,
            "execution_eligible":false,
        })
    }
}

fn observe_root_probe_child(pid: u32, cgroup: &str) -> Result<u64, ControllerExecError> {
    let stat = std::fs::read(format!("/proc/{pid}/stat"))
        .map_err(|_| ControllerExecError::ChildIdentityUnknown)?;
    let ticks = parse_proc_stat(&stat, pid)
        .ok_or(ControllerExecError::ChildIdentityUnknown)?
        .start_ticks;
    observe_process(pid, ticks, cgroup).map_err(ControllerExecError::Process)?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| ControllerExecError::ChildIdentityUnknown)?;
    let uid = status.lines().find(|line| line.starts_with("Uid:"));
    let no_new_privs = status.lines().find(|line| line.starts_with("NoNewPrivs:"));
    if uid.map(|line| line.split_ascii_whitespace().collect::<Vec<_>>())
        != Some(vec!["Uid:", "0", "0", "0", "0"])
        || no_new_privs.map(|line| line.split_ascii_whitespace().collect::<Vec<_>>())
            != Some(vec!["NoNewPrivs:", "1"])
    {
        return Err(ControllerExecError::ChildIdentityUnknown);
    }
    observe_process(pid, ticks, cgroup).map_err(ControllerExecError::Process)?;
    Ok(ticks)
}

/// Fixed inert proof of the same Root `execveat` syscall path that a future
/// prepared controller will use. It does not import any controller code.
pub fn run_fixed_root_controller_exec_probe(
    interpreter: &HeldInterpreter,
) -> Result<RootControllerProbeProof, ControllerExecError> {
    if geteuid().as_raw() != 0 {
        return Err(ControllerExecError::RootRequired);
    }
    let mut group = OwnedJobCgroup::create(PROBE_JOB_ID).map_err(ControllerExecError::Cgroup)?;
    let cgroup = group.path().to_owned();
    let argv = vec![
        interpreter.declaration().python_path.clone(),
        "-I".to_owned(),
        "-S".to_owned(),
        "-B".to_owned(),
        "-c".to_owned(),
        PROBE_CODE.to_owned(),
    ];
    let environment = BTreeMap::from([
        ("PATH", "/usr/bin:/bin".to_owned()),
        ("LANG", "C.UTF-8".to_owned()),
        ("HOME", "/root".to_owned()),
        (
            "HOL_GAUNTLET_RUST_JOB_SLICE",
            format!("holgauntletrust{PROBE_JOB_ID}.slice"),
        ),
    ]);
    let cwd = match open_root_owned_public_directory(Path::new("/")) {
        Ok(cwd) => cwd,
        Err(_) => {
            group
                .drain_and_remove()
                .map_err(ControllerExecError::Cgroup)?;
            return Err(ControllerExecError::InvalidPlan);
        }
    };
    let writer = match group.writer() {
        Ok(writer) => writer,
        Err(error) => {
            group
                .drain_and_remove()
                .map_err(ControllerExecError::Cgroup)?;
            return Err(ControllerExecError::Cgroup(error));
        }
    };
    let mut child = match spawn_root_fd(
        interpreter,
        &argv,
        &environment,
        cwd,
        writer,
        Stdio::null(),
        Stdio::null(),
    ) {
        Ok(child) => child,
        Err(error) => {
            group
                .drain_and_remove()
                .map_err(ControllerExecError::Cgroup)?;
            return Err(error);
        }
    };
    let started = Instant::now();
    let observed_tasks = loop {
        match group.tasks() {
            Ok(tasks) if tasks >= 2 => break Ok(tasks),
            Ok(_) if started.elapsed() < WAIT => thread::sleep(POLL),
            Ok(_) => break Err(ControllerExecError::ChildIdentityUnknown),
            Err(error) => break Err(ControllerExecError::Cgroup(error)),
        }
    };
    let identity = observe_root_probe_child(child.id(), &cgroup);
    let killed = group.kill().map_err(ControllerExecError::Cgroup);
    let reaped = reap_probe_child_bounded(&mut child).map_err(ControllerExecError::Cgroup);
    let drained = group
        .drain_and_remove()
        .map_err(ControllerExecError::Cgroup);
    let interpreter_unchanged = interpreter
        .assert_unchanged()
        .map_err(|_| ControllerExecError::Interpreter(InterpreterExecError::InvalidInterpreter));
    let observed_tasks = observed_tasks?;
    let start_ticks = identity?;
    killed?;
    reaped?;
    drained?;
    interpreter_unchanged?;
    Ok(RootControllerProbeProof {
        cgroup,
        observed_tasks,
        interpreter_sha256: interpreter.declaration().sha256.clone(),
        pid: child.id(),
        start_ticks,
    })
}
