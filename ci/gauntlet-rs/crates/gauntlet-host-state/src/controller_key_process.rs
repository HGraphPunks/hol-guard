//! Own a caller-launched child across the host half of the prelaunch exchange.
//! The caller must separately attest the Lima executable, VM and guest worker.

use super::{
    HostControllerKeyPinJournal, HostKeyPinError, HostKeyPinRecord, HostPrelaunchIdentity,
};
use std::process::{Child, ExitStatus};
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
        let owned = ChildOwner(Some(child));
        let result = (|| {
            if !expected.valid() {
                return Err(HostKeyPinError::WrongPreparedIdentity);
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
            self.accept_prepared_pipe(reader, writer, expected, timeout)
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
