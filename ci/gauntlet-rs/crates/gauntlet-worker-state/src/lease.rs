//! Nonblocking exclusive lease for one live Linux worker invocation.
//! The descriptor owns the lock until it is dropped.

use crate::{
    io, ReservationError, RunReservationJournal, StartedMarker, TerminalOutcome, TerminalReceipt,
};
use gauntlet_contracts::WorkerRequest;
use rustix::fs::{
    flock, fstat, fsync, openat, statat, AtFlags, FileType, FlockOperation, Mode, OFlags,
};
use rustix::io::Errno;
use std::os::fd::OwnedFd;

const LEASE_FILE: &str = "active.lock";

pub struct ActiveLease {
    descriptor: OwnedFd,
    root_dev: u64,
    root_ino: u64,
    lock_dev: u64,
    lock_ino: u64,
}

#[cfg(test)]
mod retained_report_tests {
    use super::*;
    use crate::terminal::create_durable;
    use std::cell::Cell;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn explicit_finalization_preserves_report_and_resumes_after_publication_interruption() {
        let source = "a".repeat(40);
        let deployment = "b".repeat(64);
        let generation = "c".repeat(64);
        let job = "0123456789abcdef";
        let request = WorkerRequest::parse(
            serde_json::json!({"schema":"hol-gauntlet-worker-request.v1",
            "action":"run","job_id":job,"source_sha":source,"deployment_digest":deployment})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let report = br#"{"complete":true}"#;
        for retained in [report.as_slice(), b"{", b"{}", b""] {
            let temp = tempfile::tempdir().unwrap();
            let journal =
                RunReservationJournal::open(&temp.path().canonicalize().unwrap()).unwrap();
            let started = journal
                .reserve(&request, &source, &deployment, &generation)
                .unwrap();
            let name = format!("{job}.report.json");
            create_durable(&journal.root, &name, retained).unwrap();
            let before = std::fs::metadata(temp.path().join(&name)).unwrap();
            let publications = Cell::new(0);
            let interrupted = |_: &[u8]| {
                publications.set(publications.get() + 1);
                Err(ReservationError::Io(
                    "injected publication interruption".into(),
                ))
            };
            let finish = |status, publish: &dyn Fn(&[u8]) -> Result<(), ReservationError>| {
                journal.finish_internal(
                    &request,
                    &source,
                    &deployment,
                    &generation,
                    &started.sha256,
                    report,
                    crate::ProcessIdentity {
                        pid: 321,
                        start_ticks: 456,
                    },
                    0,
                    status,
                    None,
                    Some(publish),
                )
            };
            for status in [TerminalOutcome::Passed, TerminalOutcome::Failed] {
                assert!(finish(status, &interrupted).is_err());
            }
            assert_eq!(publications.get(), 0);
            assert!(finish(TerminalOutcome::InvalidEvidence, &interrupted).is_err());
            assert_eq!(publications.get(), u32::from(retained == report));
            assert!(!temp.path().join(format!("{job}.terminal.json")).exists());
            let publish = |raw: &[u8]| {
                publications.set(publications.get() + 1);
                create_durable(&journal.root, &format!("{job}.terminal.json"), raw)
            };
            let result = finish(TerminalOutcome::InvalidEvidence, &publish);
            if retained == report {
                let terminal = result.unwrap();
                assert_eq!(terminal.status, TerminalOutcome::InvalidEvidence);
                assert_eq!(
                    journal
                        .terminal(job, &source, &deployment, &generation)
                        .unwrap(),
                    Some(terminal)
                );
                assert!(finish(TerminalOutcome::InvalidEvidence, &publish).is_err());
                assert_eq!(publications.get(), 2);
            } else {
                assert!(result.is_err());
                assert_eq!(publications.get(), 0);
            }
            let after = std::fs::metadata(temp.path().join(&name)).unwrap();
            assert_eq!(std::fs::read(temp.path().join(&name)).unwrap(), retained);
            assert_eq!(
                (
                    before.dev(),
                    before.ino(),
                    before.ctime(),
                    before.ctime_nsec(),
                    before.mtime(),
                    before.mtime_nsec()
                ),
                (
                    after.dev(),
                    after.ino(),
                    after.ctime(),
                    after.ctime_nsec(),
                    after.mtime(),
                    after.mtime_nsec()
                )
            );
        }
    }
}

fn acquire(root: &OwnedFd, require_root: bool) -> Result<ActiveLease, ReservationError> {
    let descriptor = openat(
        root,
        LEASE_FILE,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(io)?;
    let opened = fstat(&descriptor).map_err(io)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || opened.st_nlink != 1
        || opened.st_mode & 0o077 != 0
        || (require_root && opened.st_uid != 0)
    {
        return Err(ReservationError::UnsafeRoot);
    }
    match flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::AGAIN) => return Err(ReservationError::LeaseBusy),
        Err(error) => return Err(io(error)),
    }
    let visible = statat(root, LEASE_FILE, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if visible.st_dev != opened.st_dev || visible.st_ino != opened.st_ino {
        return Err(ReservationError::UnsafeRoot);
    }
    fsync(&descriptor).map_err(io)?;
    fsync(root).map_err(io)?;
    let root_stat = fstat(root).map_err(io)?;
    Ok(ActiveLease {
        descriptor,
        root_dev: root_stat.st_dev as u64,
        root_ino: root_stat.st_ino,
        lock_dev: opened.st_dev as u64,
        lock_ino: opened.st_ino,
    })
}

impl ActiveLease {
    pub(crate) fn verify(&self, root: &OwnedFd) -> Result<(), ReservationError> {
        let current_root = fstat(root).map_err(io)?;
        let descriptor = fstat(&self.descriptor).map_err(io)?;
        let visible = statat(root, LEASE_FILE, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        if current_root.st_dev as u64 != self.root_dev
            || current_root.st_ino != self.root_ino
            || descriptor.st_dev as u64 != self.lock_dev
            || descriptor.st_ino != self.lock_ino
            || visible.st_dev as u64 != self.lock_dev
            || visible.st_ino != self.lock_ino
        {
            return Err(ReservationError::UnsafeRoot);
        }
        Ok(())
    }
}

impl RunReservationJournal {
    /// Acquire the one active-worker lease without waiting. The caller must
    /// retain `ActiveLease` through process exit, cleanup and terminal receipt.
    pub fn acquire_active_lease(&self) -> Result<ActiveLease, ReservationError> {
        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        acquire(&self.root, true)
    }

    /// The live worker path requires its lease before consuming a job ID.
    pub fn reserve_under_lease(
        &self,
        lease: &ActiveLease,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<StartedMarker, ReservationError> {
        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        lease.verify(&self.root)?;
        self.reserve_internal(
            request,
            source_sha,
            deployment_digest,
            worker_generation,
            None,
        )
    }

    /// The Rust-owned deterministic path anchors its public signing key in
    /// the immutable started marker before any controller process exists.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(crate) fn reserve_keyed_under_lease(
        &self,
        lease: &ActiveLease,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        controller_public_key_hex: &str,
    ) -> Result<StartedMarker, ReservationError> {
        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        lease.verify(&self.root)?;
        self.reserve_internal(
            request,
            source_sha,
            deployment_digest,
            worker_generation,
            Some(controller_public_key_hex),
        )
    }

    /// The same lease must cover durable terminal writing and cleanup.
    #[allow(clippy::too_many_arguments)]
    pub fn finish_under_lease(
        &self,
        lease: &ActiveLease,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        expected_started_sha256: &str,
        report_raw: &[u8],
        process: crate::ProcessIdentity,
        exit_code: i32,
        status: TerminalOutcome,
        expected_controller_key_pin_sha256: Option<&str>,
    ) -> Result<TerminalReceipt, ReservationError> {
        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        lease.verify(&self.root)?;
        #[cfg(target_os = "linux")]
        {
            let running = self
                .running_marker(
                    request.job_id(),
                    source_sha,
                    deployment_digest,
                    worker_generation,
                )?
                .ok_or(ReservationError::InvalidMarker)?;
            if running.process != process
                || running.started_marker_sha256 != expected_started_sha256
            {
                return Err(ReservationError::InvalidMarker);
            }
            crate::require_rust_job_slice_absent(request.job_id())?;
        }
        self.finish_internal(
            request,
            source_sha,
            deployment_digest,
            worker_generation,
            expected_started_sha256,
            report_raw,
            process,
            exit_code,
            status,
            expected_controller_key_pin_sha256,
            None,
        )
    }
    /// Complete only an unchanged, unkeyed invalid-evidence report. The caller
    /// independently verifies its artifacts and process/resource absence.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_retained_report_under_lease(
        &self,
        lease: &ActiveLease,
        request: &WorkerRequest,
        started: &crate::StartedMarker,
        report: &[u8],
        process: crate::ProcessIdentity,
        exit: i32,
        publish: &dyn Fn(&[u8]) -> Result<(), ReservationError>,
    ) -> Result<TerminalReceipt, ReservationError> {
        if !self.root_owned || started.controller_public_key_hex.is_some() {
            return Err(ReservationError::UnsafeRoot);
        }
        lease.verify(&self.root)?;
        let running = self
            .running_marker(
                &started.job_id,
                &started.source_sha,
                &started.deployment_digest,
                &started.worker_generation,
            )?
            .ok_or(ReservationError::InvalidMarker)?;
        if running.process != process || running.started_marker_sha256 != started.sha256 {
            return Err(ReservationError::InvalidMarker);
        }
        crate::require_rust_job_slice_absent(&started.job_id)?;
        self.finish_internal(
            request,
            &started.source_sha,
            &started.deployment_digest,
            &started.worker_generation,
            &started.sha256,
            report,
            process,
            exit,
            TerminalOutcome::InvalidEvidence,
            None,
            Some(publish),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_canonical_directory, ProcessIdentity};
    use gauntlet_contracts::WorkerRequest;
    use serde_json::json;
    use std::fs;

    #[test]
    fn separate_open_descriptions_compete_for_one_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let first = RunReservationJournal::open(&root).unwrap();
        let second = RunReservationJournal::open(&root).unwrap();
        let held = acquire(&first.root, false).unwrap();
        assert!(matches!(
            acquire(&second.root, false),
            Err(ReservationError::LeaseBusy)
        ));
        assert!(matches!(
            first.acquire_active_lease(),
            Err(ReservationError::UnsafeRoot)
        ));
        drop(held);
        // Concurrent tests can fork while this descriptor is open. CLOEXEC
        // closes that inherited description at exec, rather than at our drop.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let recovered = loop {
            match acquire(&second.root, false) {
                Ok(lease) => break lease,
                Err(ReservationError::LeaseBusy) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("lease did not release after descriptor close: {error:?}"),
            }
        };
        recovered.verify(&second.root).unwrap();
    }

    #[test]
    fn replacing_the_visible_lock_file_invalidates_the_held_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let journal = RunReservationJournal::open(&root).unwrap();
        let held = acquire(&journal.root, false).unwrap();
        fs::rename(root.join(LEASE_FILE), root.join("old.lock")).unwrap();
        fs::write(root.join(LEASE_FILE), b"replacement").unwrap();
        assert!(matches!(
            held.verify(&journal.root),
            Err(ReservationError::UnsafeRoot)
        ));
    }

    #[test]
    fn live_journal_rejects_unleased_write_entrypoints() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let journal = RunReservationJournal {
            root: open_canonical_directory(&root, false).unwrap(),
            root_owned: true,
        };
        let source = "a".repeat(40);
        let deployment = "b".repeat(64);
        let generation = "c".repeat(64);
        let request = WorkerRequest::parse(
            &serde_json::to_vec(&json!({
                "schema":"hol-gauntlet-worker-request.v1",
                "action":"run",
                "source_sha":source,
                "job_id":"dddddddddddddddd",
                "deployment_digest":deployment,
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            journal.reserve(&request, &source, &deployment, &generation),
            Err(ReservationError::UnsafeRoot)
        );
        assert_eq!(
            journal.finish(
                &request,
                &source,
                &deployment,
                &generation,
                &"e".repeat(64),
                br#"{}"#,
                ProcessIdentity {
                    pid: 1,
                    start_ticks: 1,
                },
                0,
                TerminalOutcome::Passed,
            ),
            Err(ReservationError::UnsafeRoot)
        );
    }
}
