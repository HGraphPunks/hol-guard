//! Durable, data-only terminal custody for the future Linux worker.
//! The caller still owns process observation, report scoring and Root custody.

use crate::{hex, io, marker_name, read_bounded_regular, ReservationError, RunReservationJournal};
use gauntlet_contracts::{canonicalize, is_git_sha, WorkerAction, WorkerRequest};
use rustix::fs::{fsync, openat, statat, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;

const TERMINAL_SCHEMA: &str = "hol-gauntlet-worker-terminal.v1";
const MAX_TERMINAL_BYTES: u64 = 2048;
const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalOutcome {
    Passed,
    Failed,
    InvalidEvidence,
}

impl TerminalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::InvalidEvidence => "invalid-evidence",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "passed" => Some(Self::Passed),
            "failed" => Some(Self::Failed),
            "invalid-evidence" => Some(Self::InvalidEvidence),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalReceipt {
    pub source_sha: String,
    pub job_id: String,
    pub deployment_digest: String,
    pub worker_generation: String,
    pub started_marker_sha256: String,
    pub report_sha256: String,
    pub process: ProcessIdentity,
    pub exit_code: i32,
    pub status: TerminalOutcome,
    pub sha256: String,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn report_name(job_id: &str) -> String {
    format!("{job_id}.report.json")
}

fn terminal_name(job_id: &str) -> String {
    format!("{job_id}.terminal.json")
}

fn valid_process_outcome(
    process: ProcessIdentity,
    exit_code: i32,
    status: TerminalOutcome,
) -> bool {
    process.pid > 0
        && process.start_ticks > 0
        && (-128..=255).contains(&exit_code)
        && (status != TerminalOutcome::Passed || exit_code == 0)
}

fn create_durable(
    root: &std::os::fd::OwnedFd,
    name: &str,
    bytes: &[u8],
) -> Result<(), ReservationError> {
    let descriptor = openat(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| {
        if error == Errno::EXIST {
            ReservationError::AlreadyStarted
        } else {
            io(error)
        }
    })?;
    let mut file = File::from(descriptor);
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    fsync(root).map_err(io)?;
    Ok(())
}

impl RunReservationJournal {
    /// Inert test entrypoint. A Root-owned live journal must use
    /// `finish_under_lease` so no terminal can be written after losing its lease.
    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        &self,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        expected_started_sha256: &str,
        report_raw: &[u8],
        process: ProcessIdentity,
        exit_code: i32,
        status: TerminalOutcome,
    ) -> Result<TerminalReceipt, ReservationError> {
        if self.root_owned {
            return Err(ReservationError::UnsafeRoot);
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
        )
    }

    /// Write the exact bounded report bytes before a terminal marker. This is
    /// not a gate verdict: the caller must independently establish the kernel
    /// process identity and recompute the report outcome before using `Passed`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_internal(
        &self,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        expected_started_sha256: &str,
        report_raw: &[u8],
        process: ProcessIdentity,
        exit_code: i32,
        status: TerminalOutcome,
    ) -> Result<TerminalReceipt, ReservationError> {
        if request.action() != WorkerAction::Run
            || !request.matches_deployment(source_sha, deployment_digest)
        {
            return Err(ReservationError::WrongRequest);
        }
        if !is_git_sha(source_sha)
            || !hex(deployment_digest, 64)
            || !hex(worker_generation, 64)
            || !hex(expected_started_sha256, 64)
        {
            return Err(ReservationError::InvalidPins);
        }
        if !valid_process_outcome(process, exit_code, status)
            || report_raw.is_empty()
            || report_raw.len() as u64 > MAX_REPORT_BYTES
            || canonicalize(report_raw).map_err(|_| ReservationError::InvalidMarker)? != report_raw
        {
            return Err(ReservationError::InvalidMarker);
        }
        let started = self
            .started(
                request.job_id(),
                source_sha,
                deployment_digest,
                worker_generation,
            )?
            .ok_or(ReservationError::InvalidMarker)?;
        if started.sha256 != expected_started_sha256 {
            return Err(ReservationError::InvalidMarker);
        }
        let job_id = request.job_id();
        match statat(
            &self.root,
            terminal_name(job_id).as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => return Err(ReservationError::AlreadyStarted),
            Err(Errno::NOENT) => {}
            Err(error) => return Err(io(error)),
        }
        let report_sha256 = digest(report_raw);
        let value = json!({
            "schema": TERMINAL_SCHEMA,
            "source_sha": source_sha,
            "job_id": job_id,
            "deployment_digest": deployment_digest,
            "worker_generation": worker_generation,
            "started_marker_sha256": expected_started_sha256,
            "report_sha256": report_sha256,
            "pid": process.pid,
            "process_start_ticks": process.start_ticks,
            "exit_code": exit_code,
            "status": status.as_str(),
        });
        let bytes = canonicalize(value.to_string().as_bytes())
            .map_err(|_| ReservationError::InvalidMarker)?;
        if bytes.len() as u64 > MAX_TERMINAL_BYTES {
            return Err(ReservationError::InvalidMarker);
        }
        create_durable(&self.root, &report_name(job_id), report_raw)?;
        create_durable(&self.root, &terminal_name(job_id), &bytes)?;
        Ok(TerminalReceipt {
            source_sha: source_sha.to_owned(),
            job_id: job_id.to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            started_marker_sha256: expected_started_sha256.to_owned(),
            report_sha256,
            process,
            exit_code,
            status,
            sha256: digest(&bytes),
        })
    }

    /// Reconcile a retained report and terminal marker against independent
    /// pins. Missing terminal after a start is unresolved; report-only state
    /// is invalid and must never trigger a second run.
    pub fn terminal(
        &self,
        job_id: &str,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<Option<TerminalReceipt>, ReservationError> {
        marker_name(job_id)?;
        let started = self.started(job_id, source_sha, deployment_digest, worker_generation)?;
        let terminal =
            read_bounded_regular(&self.root, &terminal_name(job_id), MAX_TERMINAL_BYTES)?;
        let Some(bytes) = terminal else {
            if read_bounded_regular(&self.root, &report_name(job_id), MAX_REPORT_BYTES)?.is_some() {
                return Err(ReservationError::InvalidMarker);
            }
            return Ok(None);
        };
        let started = started.ok_or(ReservationError::InvalidMarker)?;
        if canonicalize(&bytes).map_err(|_| ReservationError::InvalidMarker)? != bytes {
            return Err(ReservationError::InvalidMarker);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| ReservationError::InvalidMarker)?;
        let fields = value.as_object().ok_or(ReservationError::InvalidMarker)?;
        let process = ProcessIdentity {
            pid: value["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or(ReservationError::InvalidMarker)?,
            start_ticks: value["process_start_ticks"]
                .as_u64()
                .ok_or(ReservationError::InvalidMarker)?,
        };
        let exit_code = value["exit_code"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok())
            .ok_or(ReservationError::InvalidMarker)?;
        let status = value["status"]
            .as_str()
            .and_then(TerminalOutcome::parse)
            .ok_or(ReservationError::InvalidMarker)?;
        let report_sha256 = value["report_sha256"]
            .as_str()
            .filter(|sha| hex(sha, 64))
            .ok_or(ReservationError::InvalidMarker)?;
        if fields.len() != 11
            || value["schema"] != TERMINAL_SCHEMA
            || value["source_sha"] != source_sha
            || value["job_id"] != job_id
            || value["deployment_digest"] != deployment_digest
            || value["worker_generation"] != worker_generation
            || value["started_marker_sha256"] != started.sha256
            || !valid_process_outcome(process, exit_code, status)
        {
            return Err(ReservationError::InvalidMarker);
        }
        #[cfg(target_os = "linux")]
        if self.root_owned {
            let running = self
                .running_marker(job_id, source_sha, deployment_digest, worker_generation)?
                .ok_or(ReservationError::InvalidMarker)?;
            if running.process != process || running.started_marker_sha256 != started.sha256 {
                return Err(ReservationError::InvalidMarker);
            }
        }
        let report = read_bounded_regular(&self.root, &report_name(job_id), MAX_REPORT_BYTES)?
            .ok_or(ReservationError::InvalidMarker)?;
        if report.is_empty()
            || canonicalize(&report).map_err(|_| ReservationError::InvalidMarker)? != report
            || digest(&report) != report_sha256
        {
            return Err(ReservationError::InvalidMarker);
        }
        Ok(Some(TerminalReceipt {
            source_sha: source_sha.to_owned(),
            job_id: job_id.to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            started_marker_sha256: started.sha256,
            report_sha256: report_sha256.to_owned(),
            process,
            exit_code,
            status,
            sha256: digest(&bytes),
        }))
    }
}
