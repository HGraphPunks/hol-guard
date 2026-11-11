//! Read back the exact public keyed records; never reopen or export a seed.
use crate::terminal::{digest, report_name, terminal_name, MAX_TERMINAL_BYTES};
use crate::{hex, read_bounded_regular, ReservationError, RunReservationJournal, TerminalOutcome};
use gauntlet_contracts::{canonicalize, WorkerAction, WorkerRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

pub use gauntlet_contracts::NATIVE_HOST_PINNED_COMPLETION_LIMIT;

fn value(
    journal: &RunReservationJournal,
    name: &str,
    limit: u64,
    expected: &str,
) -> Result<Value, String> {
    let raw = read_bounded_regular(&journal.root, name, limit)
        .map_err(|e| e.to_string())?
        .ok_or("complete native keyed record unavailable")?;
    if format!("{:x}", Sha256::digest(&raw)) != expected
        || canonicalize(&raw).map_err(|e| e.to_string())? != raw
    {
        return Err("native keyed record changed from its bound digest".into());
    }
    serde_json::from_slice(&raw).map_err(|e| e.to_string())
}

pub(crate) fn read_completion(
    journal: &RunReservationJournal,
    source: &str,
    job: &str,
    deployment: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    let started = journal
        .started(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("native keyed started marker unavailable")?;
    if started.controller_public_key_hex.is_none() {
        return Err("native host-pinned readback requires a keyed reservation".into());
    }
    let pin =
        crate::controller_key::read_pin(journal, &started, true).map_err(|e| e.to_string())?;
    let terminal = journal
        .terminal(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("native host-pinned job has no complete terminal; retain unknown state")?;
    if terminal.controller_public_key_hex.as_deref() != Some(&pin.public_key_hex)
        || terminal.controller_key_pin_sha256.as_deref() != Some(&pin.raw_sha256)
        || terminal.status != TerminalOutcome::InvalidEvidence
    {
        return Err("native keyed terminal binding or diagnostic status differs".into());
    }
    let report = value(
        journal,
        &format!("{job}.report.json"),
        16 * 1024 * 1024,
        &terminal.report_sha256,
    )?;
    let completion = match (report["schema"].as_str(), report["profile"].as_str()) {
        (Some("hol-gauntlet-native-worker-report.v7"), Some("native-host-pinned-control-v1")) => {
            "hol-gauntlet-native-host-pinned-completion.v1"
        }
        (
            Some("hol-gauntlet-native-worker-report.v8"),
            Some("native-host-pinned-readonly-hook-v1"),
        ) => "hol-gauntlet-native-host-pinned-completion.v2",
        (Some("hol-gauntlet-native-worker-report.v9"), Some("native-host-pinned-live-omp-v1")) => {
            "hol-gauntlet-native-host-pinned-completion.v3"
        }
        _ => return Err("native keyed report version/profile differs".into()),
    };
    if report["source_sha"] != source
        || report["job_id"] != job
        || report["worker_generation"] != generation
        || report["deployment_digest"] != deployment
        || report["started_marker_sha256"] != started.sha256
        || report["execution_eligible"] != false
        || report["guard_causality_verified"] != false
    {
        return Err("native host-pinned report identity differs".into());
    }
    let model_requests = if completion == "hol-gauntlet-native-host-pinned-completion.v3" {
        if report["model_requests"].as_u64().is_none_or(|n| n > 64)
            || report["model_channel_pending"] != false
        {
            return Err("live completion has unsettled model usage".into());
        }
        report["model_requests"].clone()
    } else {
        json!(0)
    };
    let frame = json!({"schema":completion,
        "started":value(journal,&format!("{job}.started.json"),1024,&started.sha256)?,
        "controller_key_pin":value(journal,&format!("{job}.controller-key.json"),1024,&pin.raw_sha256)?,
        "terminal":value(journal,&format!("{job}.terminal.json"),2048,&terminal.sha256)?,
        "terminal_sha256":terminal.sha256,"report":report,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":model_requests});
    let raw = canonicalize(frame.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if raw.len() > NATIVE_HOST_PINNED_COMPLETION_LIMIT {
        return Err("native keyed completion exceeds byte limit".into());
    }
    Ok(raw)
}

pub fn read_native_host_pinned_result(
    source: &str,
    deployment: &str,
    generation: &str,
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let request = WorkerRequest::parse(raw).map_err(|e| e.to_string())?;
    if request.source_sha() != source
        || !matches!(
            request.action(),
            WorkerAction::Inspect | WorkerAction::Reconcile
        )
    {
        return Err("outside-pinned native report or reconcile request required".into());
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(
        "/var/lib/hol-gauntlet-rust/worker-state",
    ))
    .map_err(|e| e.to_string())?;
    read_completion(&journal, source, request.job_id(), deployment, generation)
}

impl RunReservationJournal {
    /// Reopen an already completed Rust deterministic diagnostic for a host
    /// that retained the key before launch. This exports only the bounded
    /// invalid-evidence terminal and diagnostic summary, then independently
    /// reopens the fixed deterministic controller report to check its digest.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub fn read_deterministic_diagnostic_root_owned(
        &self,
        job_id: &str,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<Value, ReservationError> {
        use gauntlet_evidence::observe_deterministic_report_root_owned_ineligible;

        if !self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        let first = self
            .terminal(job_id, source_sha, deployment_digest, worker_generation)?
            .ok_or(ReservationError::InvalidMarker)?;
        if first.status != TerminalOutcome::InvalidEvidence
            || first.controller_key_pin_sha256.is_none()
        {
            return Err(ReservationError::InvalidMarker);
        }
        crate::require_rust_job_slice_absent(job_id)?;
        let terminal_raw =
            read_bounded_regular(&self.root, &terminal_name(job_id), MAX_TERMINAL_BYTES)?
                .ok_or(ReservationError::InvalidMarker)?;
        let report_raw = read_bounded_regular(&self.root, &report_name(job_id), 8192)?
            .ok_or(ReservationError::InvalidMarker)?;
        if digest(&terminal_raw) != first.sha256 || digest(&report_raw) != first.report_sha256 {
            return Err(ReservationError::InvalidMarker);
        }
        let terminal: Value =
            serde_json::from_slice(&terminal_raw).map_err(|_| ReservationError::InvalidMarker)?;
        let report: Value =
            serde_json::from_slice(&report_raw).map_err(|_| ReservationError::InvalidMarker)?;
        let config_digest = report["config_digest"]
            .as_str()
            .filter(|value| hex(value, 64))
            .ok_or(ReservationError::InvalidMarker)?;
        let expected_deterministic_sha = report["deterministic_report_sha256"]
            .as_str()
            .filter(|value| hex(value, 64))
            .ok_or(ReservationError::InvalidMarker)?;
        if report["schema"] != "hol-gauntlet-rust-deterministic-run-diagnostic.v1"
            || report["job_id"] != job_id
            || report["source_sha"] != source_sha
            || report["deployment_digest"] != deployment_digest
            || report["worker_generation"] != worker_generation
            || report["started_marker_sha256"] != first.started_marker_sha256
            || report["controller_key_pin_sha256"].as_str()
                != first.controller_key_pin_sha256.as_deref()
            || report["controller_public_key_hex"].as_str()
                != first.controller_public_key_hex.as_deref()
            || report["exit_code"] != first.exit_code
            || report["process"]["pid"] != first.process.pid
            || report["process"]["start_ticks"] != first.process.start_ticks
            || report["independent_control_verdict"] != false
            || report["execution_eligible"] != false
        {
            return Err(ReservationError::InvalidMarker);
        }
        let observed = observe_deterministic_report_root_owned_ineligible(
            job_id,
            source_sha,
            config_digest,
            first.exit_code,
        )
        .map_err(|_| ReservationError::InvalidMarker)?;
        if observed.raw_sha256 != expected_deterministic_sha
            || report["producer_status_claim"] != observed.producer_status
            || report["producer_cell_count"] != observed.cell_count
        {
            return Err(ReservationError::InvalidMarker);
        }
        if self.terminal(job_id, source_sha, deployment_digest, worker_generation)?
            != Some(first.clone())
        {
            return Err(ReservationError::InvalidMarker);
        }
        crate::require_rust_job_slice_absent(job_id)?;
        Ok(json!({
            "schema":"hol-gauntlet-rust-deterministic-readback.v1",
            "job_id":job_id,
            "source_sha":source_sha,
            "terminal":terminal,
            "diagnostic_report":report,
            "terminal_sha256":first.sha256,
            "diagnostic_report_sha256":first.report_sha256,
            "deterministic_report_sha256":observed.raw_sha256,
            "execution_eligible":false,
        }))
    }
}
