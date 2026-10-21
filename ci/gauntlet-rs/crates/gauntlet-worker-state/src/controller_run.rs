//! Internal owner of one prepared controller's lease, deadline, process and
//! cleanup. This path does not read a benchmark report or issue a verdict.

use crate::contained_probe::{CgroupProbeError, OwnedJobCgroup};
use crate::controller_exec::{spawn_prepared_controller, ControllerExecError};
use crate::deadline::{BoottimeDeadline, DeadlineError};
use crate::linux_process::{observe_process, parse_proc_stat, ProcessObservationError};
use crate::prelaunch::PreparedLaunch;
use crate::process_reap::reap_probe_child_bounded;
use crate::{
    stop_rust_job_slice, ActiveLease, ProcessIdentity, ReservationError, RunReservationJournal,
};
use gauntlet_contracts::WorkerRequest;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::thread;

#[derive(Debug)]
pub(crate) enum ControllerRunError {
    Lease(ReservationError),
    Cgroup(CgroupProbeError),
    Launch(ControllerExecError),
    Identity(ProcessObservationError),
    Deadline(DeadlineError),
    Wait,
    CleanupUncertain,
}

impl std::fmt::Display for ControllerRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lease(error) => write!(f, "worker lease or running marker: {error}"),
            Self::Cgroup(error) => write!(f, "controller cgroup: {error}"),
            Self::Launch(error) => write!(f, "controller launch: {error}"),
            Self::Identity(error) => write!(f, "controller process identity: {error:?}"),
            Self::Deadline(error) => write!(f, "controller deadline: {error}"),
            Self::Wait => f.write_str("controller child wait failed"),
            Self::CleanupUncertain => f.write_str("controller or product-cell cleanup uncertain"),
        }
    }
}

impl std::error::Error for ControllerRunError {}

enum WaitOutcome {
    Exited(ExitStatus),
    TimedOut,
}

/// This observation is deliberately insufficient for a terminal receipt.
/// A future dispatcher must authenticate report bytes and independently score
/// the six controls before writing even an invalid-evidence terminal record.
#[allow(dead_code)]
pub(crate) struct ControllerRunObservation {
    pub(crate) process: ProcessIdentity,
    pub(crate) started_marker_sha256: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
}

fn wait_for_child(
    child: &mut Child,
    deadline: &BoottimeDeadline,
    mut check_owner: impl FnMut() -> Result<(), ControllerRunError>,
) -> Result<WaitOutcome, ControllerRunError> {
    loop {
        check_owner()?;
        if let Some(status) = child.try_wait().map_err(|_| ControllerRunError::Wait)? {
            return Ok(WaitOutcome::Exited(status));
        }
        let poll = deadline.next_poll().map_err(ControllerRunError::Deadline)?;
        if poll.is_zero() {
            return Ok(WaitOutcome::TimedOut);
        }
        thread::sleep(poll);
    }
}

fn observe_child(
    child: &Child,
    expected_cgroup: &str,
) -> Result<ProcessIdentity, ControllerRunError> {
    let pid = child.id();
    let stat = fs::read(format!("/proc/{pid}/stat"))
        .map_err(|_| ControllerRunError::Identity(ProcessObservationError::Unavailable))?;
    let start_ticks = parse_proc_stat(&stat, pid)
        .ok_or(ControllerRunError::Identity(
            ProcessObservationError::Unavailable,
        ))?
        .start_ticks;
    observe_process(pid, start_ticks, expected_cgroup).map_err(ControllerRunError::Identity)?;
    Ok(ProcessIdentity { pid, start_ticks })
}

/// Cleanup is attempted on every post-create path. A failed step keeps the
/// reserved job unresolved; no retry or terminal success is inferred.
fn cleanup(
    group: &mut OwnedJobCgroup,
    child: Option<&mut Child>,
    job_id: &str,
    stop_product_slice: bool,
) -> Result<(), ControllerRunError> {
    let killed = group.kill();
    let reaped = child.map(reap_probe_child_bounded).transpose();
    let drained = group.drain_and_remove();
    // A pre-spawn refusal may refer to an older run with the same job ID.
    // Stop the product slice only if this invocation actually spawned a child.
    // Even on uncertain controller cleanup, attempt that exact slice stop;
    // its absence cannot turn an uncertain controller into success.
    let slice_ok = !stop_product_slice || stop_rust_job_slice(job_id).is_ok();
    if killed.is_err() || reaped.is_err() || drained.is_err() || !slice_ok {
        return Err(ControllerRunError::CleanupUncertain);
    }
    Ok(())
}

/// Own one actual fixed controller process until exit or CLOCK_BOOTTIME
/// expiry, then kill remaining descendants, reap and remove the controller
/// cgroup, and stop/observe the job's product-cell slice. No public caller is
/// wired to this until trusted pin delivery and report authentication exist.
#[allow(dead_code)]
pub(crate) fn run_prepared_controller_ineligible(
    prepared: &PreparedLaunch,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    request: &WorkerRequest,
    worker_generation: &str,
    active_seconds: u64,
) -> Result<ControllerRunObservation, ControllerRunError> {
    let deadline = BoottimeDeadline::start(active_seconds).map_err(ControllerRunError::Deadline)?;
    lease
        .verify(&journal.root)
        .map_err(ControllerRunError::Lease)?;
    let mut group = OwnedJobCgroup::create(request.job_id()).map_err(ControllerRunError::Cgroup)?;
    let launched =
        spawn_prepared_controller(prepared, &group, journal, lease, request, worker_generation);
    let (mut child, started) = match launched {
        Ok(value) => value,
        Err(error) => {
            let spawned = matches!(
                error,
                ControllerExecError::PostLaunch(_) | ControllerExecError::CleanupUncertain
            );
            cleanup(&mut group, None, request.job_id(), spawned)?;
            return Err(ControllerRunError::Launch(error));
        }
    };
    let observed = (|| {
        let process = observe_child(&child, group.path())?;
        journal
            .mark_running_under_lease(
                lease,
                request,
                request.source_sha(),
                request
                    .deployment_digest()
                    .ok_or(ControllerRunError::Lease(ReservationError::WrongRequest))?,
                worker_generation,
                &started.sha256,
                process,
                group.path(),
            )
            .map_err(ControllerRunError::Lease)?;
        let outcome = wait_for_child(&mut child, &deadline, || {
            lease
                .verify(&journal.root)
                .map_err(ControllerRunError::Lease)
        })?;
        let (exit_code, timed_out) = match outcome {
            WaitOutcome::Exited(status) => (
                status.code().or_else(|| status.signal().map(|s| 128 + s)),
                false,
            ),
            WaitOutcome::TimedOut => (None, true),
        };
        Ok(ControllerRunObservation {
            process,
            started_marker_sha256: started.sha256,
            exit_code,
            timed_out,
        })
    })();
    cleanup(&mut group, Some(&mut child), request.job_id(), true)?;
    lease
        .verify(&journal.root)
        .map_err(ControllerRunError::Lease)?;
    observed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn bounded_wait_distinguishes_exit_and_deadline_without_leaking_child() {
        let mut quick = Command::new("/usr/bin/true").spawn().unwrap();
        let deadline = BoottimeDeadline::start(5).unwrap();
        assert!(matches!(
            wait_for_child(&mut quick, &deadline, || Ok(())),
            Ok(WaitOutcome::Exited(status)) if status.success()
        ));

        let mut slow = Command::new("/usr/bin/sleep").arg("3").spawn().unwrap();
        let deadline = BoottimeDeadline::start(1).unwrap();
        let outcome = wait_for_child(&mut slow, &deadline, || Ok(()));
        slow.kill().unwrap();
        slow.wait().unwrap();
        assert!(matches!(outcome, Ok(WaitOutcome::TimedOut)));
    }

    #[test]
    fn owner_loss_aborts_wait_before_deadline() {
        let mut slow = Command::new("/usr/bin/sleep").arg("3").spawn().unwrap();
        let deadline = BoottimeDeadline::start(5).unwrap();
        let result = wait_for_child(&mut slow, &deadline, || Err(ControllerRunError::Wait));
        slow.kill().unwrap();
        slow.wait().unwrap();
        assert!(matches!(result, Err(ControllerRunError::Wait)));
    }
}
