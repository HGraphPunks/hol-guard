//! Own a caller-launched child across the host half of the prelaunch exchange.
//! The caller must separately attest the Lima executable, VM and guest worker.

use super::{
    pipe::write_frame, HostControllerKeyPinJournal, HostKeyPinError, HostKeyPinRecord,
    HostPrelaunchIdentity,
};
use gauntlet_contracts::{canonicalize, WorkerAction, WorkerRequest};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::process::{Child, ExitStatus};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostProcessFailure {
    pub reason: HostKeyPinError,
    /// Once a host record might exist, this job ID must remain unresolved.
    /// Killing `limactl` cannot prove that a guest worker stopped.
    pub pin_recorded_or_uncertain: bool,
}

/// Owns the host transport process until it exits or is killed. This object
/// does not authenticate the guest or grant execution/qualification eligibility.
pub struct HostPreparedProcess {
    child: ChildOwner,
    record: HostKeyPinRecord,
}

struct ChildOwner(Option<Child>);

impl HostPreparedProcess {
    pub fn record(&self) -> &HostKeyPinRecord {
        &self.record
    }

    pub fn process_id(&self) -> Option<u32> {
        self.child.0.as_ref().map(Child::id)
    }

    /// Wait only for the host transport process. A successful exit does not
    /// authenticate a terminal receipt or prove guest descendant cleanup.
    pub fn wait_bounded(&mut self, timeout: Duration) -> Result<ExitStatus, HostKeyPinError> {
        if timeout.is_zero() || timeout > Duration::from_secs(86_400) {
            drop(ChildOwner(self.child.0.take()));
            return Err(HostKeyPinError::TransportTimedOut);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(HostKeyPinError::TransportTimedOut)?;
        loop {
            let child = self
                .child
                .0
                .as_mut()
                .ok_or(HostKeyPinError::TransportFailed)?;
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.child.0.take();
                    return Ok(status);
                }
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    drop(ChildOwner(self.child.0.take()));
                    return Err(HostKeyPinError::TransportTimedOut);
                }
                Err(_) => {
                    drop(ChildOwner(self.child.0.take()));
                    return Err(HostKeyPinError::TransportFailed);
                }
            }
        }
    }

    /// Drain the guest's one final JSON line while waiting for its transport
    /// to exit. A large or absent result leaves the already-pinned job
    /// unresolved; the caller must still read back the VM terminal separately.
    pub fn wait_bounded_result(
        &mut self,
        timeout: Duration,
        limit: usize,
    ) -> Result<Vec<u8>, HostKeyPinError> {
        if limit == 0 || limit > 8192 {
            return Err(HostKeyPinError::FrameTooLarge);
        }
        self.wait_result(timeout, limit)
    }

    /// Read only the new native completion envelope's bounded public records.
    /// Historical result readers retain their original 8192-byte bound.
    pub fn wait_bounded_native_completion(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<u8>, HostKeyPinError> {
        self.wait_result(
            timeout,
            gauntlet_contracts::NATIVE_HOST_PINNED_COMPLETION_LIMIT + 1,
        )
    }

    fn wait_result(&mut self, timeout: Duration, limit: usize) -> Result<Vec<u8>, HostKeyPinError> {
        let stdout = self
            .child
            .0
            .as_mut()
            .and_then(|child| child.stdout.take())
            .ok_or(HostKeyPinError::TransportFailed)?;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = stdout;
            let mut kept = Vec::new();
            let mut buffer = [0_u8; 4096];
            let mut overflow = false;
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) if kept.len().saturating_add(count) > limit => overflow = true,
                    Ok(count) if !overflow => kept.extend_from_slice(&buffer[..count]),
                    Ok(_) => (),
                    Err(_) => {
                        let _ = sender.send(Err(HostKeyPinError::TransportFailed));
                        return;
                    }
                }
            }
            let _ = sender.send(if overflow {
                Err(HostKeyPinError::FrameTooLarge)
            } else {
                Ok(kept)
            });
        });
        let status = self.wait_bounded(timeout)?;
        let output = receiver
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| HostKeyPinError::TransportFailed)??;
        if !status.success() || output.is_empty() {
            return Err(HostKeyPinError::TransportFailed);
        }
        Ok(output)
    }
}

impl Drop for ChildOwner {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            // Reaping is detached so a stuck host transport cannot block the
            // observer. Remote work remains unknown until guest reconciliation.
            let _ = thread::Builder::new()
                .name("gauntlet-host-child-reap".to_owned())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}

impl HostControllerKeyPinJournal {
    /// Own the readback transport before writing its one bounded request.
    /// The existing durable pin is required; no acknowledgement is sent.
    pub fn send_native_readback_request_and_bind_child(
        &self,
        child: Child,
        request: &WorkerRequest,
        expected: &HostPrelaunchIdentity,
        timeout: Duration,
    ) -> Result<HostPreparedProcess, HostProcessFailure> {
        let mut accepted = self.bind_native_readback_child(child, expected)?;
        let result = (|| {
            if !expected.valid()
                || !matches!(
                    request.action(),
                    WorkerAction::Inspect | WorkerAction::Reconcile
                )
                || request.source_sha() != expected.source_sha
                || request.job_id() != expected.job_id
            {
                return Err(HostKeyPinError::WrongRequest);
            }
            if timeout.is_zero() || timeout > Duration::from_secs(60) {
                return Err(HostKeyPinError::TransportTimedOut);
            }
            let raw = canonicalize(request.to_json().to_string().as_bytes())
                .map_err(|_| HostKeyPinError::WrongRequest)?;
            let input = accepted
                .child
                .0
                .as_mut()
                .and_then(|child| child.stdin.take())
                .ok_or(HostKeyPinError::TransportFailed)?;
            write_frame(input.as_raw_fd(), &raw, Instant::now() + timeout)?;
            drop(input);
            Ok(())
        })();
        result.map_err(|reason| HostProcessFailure {
            reason,
            pin_recorded_or_uncertain: true,
        })?;
        Ok(accepted)
    }

    /// Bind a read-only native result transport to an already durable pin.
    /// This sends no acknowledgement and cannot authorize another execution.
    pub fn bind_native_readback_child(
        &self,
        child: Child,
        expected: &HostPrelaunchIdentity,
    ) -> Result<HostPreparedProcess, HostProcessFailure> {
        let owned = ChildOwner(Some(child));
        if !expected.valid() {
            return Err(HostProcessFailure {
                reason: HostKeyPinError::WrongPreparedIdentity,
                pin_recorded_or_uncertain: true,
            });
        }
        let record = self
            .read(&expected.job_id)
            .map_err(|reason| HostProcessFailure {
                reason,
                pin_recorded_or_uncertain: !matches!(reason, HostKeyPinError::Missing),
            })?;
        if record.pins.source_sha != expected.source_sha
            || record.pins.job_id != expected.job_id
            || record.pins.deployment_digest != expected.deployment_digest
            || record.pins.worker_generation != expected.worker_generation
        {
            return Err(HostProcessFailure {
                reason: HostKeyPinError::WrongPreparedIdentity,
                pin_recorded_or_uncertain: true,
            });
        }
        Ok(HostPreparedProcess {
            child: owned,
            record,
        })
    }

    /// Consume a caller-launched child with piped stdout (prepared frame) and
    /// stdin (ack). The caller must use fixed, externally pinned argv and null
    /// or independently drained stderr. No child is spawned by this method.
    /// A failure kills the host child; a persisted pin still consumes the job.
    pub fn accept_prepared_child(
        &self,
        child: Child,
        expected: &HostPrelaunchIdentity,
        timeout: Duration,
    ) -> Result<HostPreparedProcess, HostProcessFailure> {
        self.accept_child_inner(child, None, expected, timeout)
    }

    /// Send one exact run request before receiving the prepared frame. The
    /// entire request/prepared/ack sequence shares one 60-second deadline.
    /// This still does not authenticate the Lima child or authorize a run.
    pub fn send_run_request_and_accept_prepared_child(
        &self,
        child: Child,
        request: &WorkerRequest,
        expected: &HostPrelaunchIdentity,
        timeout: Duration,
    ) -> Result<HostPreparedProcess, HostProcessFailure> {
        self.accept_child_inner(child, Some(request), expected, timeout)
    }

    fn accept_child_inner(
        &self,
        child: Child,
        request: Option<&WorkerRequest>,
        expected: &HostPrelaunchIdentity,
        timeout: Duration,
    ) -> Result<HostPreparedProcess, HostProcessFailure> {
        let owned = ChildOwner(Some(child));
        let result = (|| {
            if !expected.valid() {
                return Err(HostKeyPinError::WrongPreparedIdentity);
            }
            if timeout.is_zero() || timeout > Duration::from_secs(60) {
                return Err(HostKeyPinError::TransportTimedOut);
            }
            if request.is_some_and(|request| {
                request.action() != WorkerAction::Run
                    || !request
                        .matches_deployment(&expected.source_sha, &expected.deployment_digest)
                    || request.job_id() != expected.job_id
            }) {
                return Err(HostKeyPinError::WrongRequest);
            }
            match self.read(&expected.job_id) {
                Err(HostKeyPinError::Missing) => (),
                Ok(_) => return Err(HostKeyPinError::AlreadyRecorded),
                Err(error) => return Err(error),
            }
            let process = owned.0.as_ref().ok_or(HostKeyPinError::TransportFailed)?;
            let reader = process
                .stdout
                .as_ref()
                .ok_or(HostKeyPinError::TransportFailed)?;
            let writer = process
                .stdin
                .as_ref()
                .ok_or(HostKeyPinError::TransportFailed)?;
            if let Some(request) = request {
                let raw = canonicalize(request.to_json().to_string().as_bytes())
                    .map_err(|_| HostKeyPinError::WrongRequest)?;
                let deadline = Instant::now() + timeout;
                write_frame(writer.as_raw_fd(), &raw, deadline)?;
                self.accept_prepared_pipe(
                    reader,
                    writer,
                    expected,
                    deadline.saturating_duration_since(Instant::now()),
                )
            } else {
                self.accept_prepared_pipe(reader, writer, expected, timeout)
            }
        })();
        match result {
            Ok(record) => Ok(HostPreparedProcess {
                child: owned,
                record,
            }),
            Err(reason) => {
                let pin_recorded_or_uncertain = expected.valid()
                    && !matches!(self.read(&expected.job_id), Err(HostKeyPinError::Missing));
                Err(HostProcessFailure {
                    reason,
                    pin_recorded_or_uncertain,
                })
            }
        }
    }
}
