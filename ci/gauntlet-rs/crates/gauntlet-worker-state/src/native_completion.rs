//! Read back the exact public keyed records; never reopen or export a seed.
use crate::{read_bounded_regular, RunReservationJournal, TerminalOutcome};
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
    if report["schema"] != "hol-gauntlet-native-worker-report.v7"
        || report["source_sha"] != source
        || report["job_id"] != job
        || report["worker_generation"] != generation
        || report["deployment_digest"] != deployment
        || report["started_marker_sha256"] != started.sha256
        || report["execution_eligible"] != false
        || report["guard_causality_verified"] != false
    {
        return Err("native host-pinned report identity differs".into());
    }
    let frame = json!({"schema":"hol-gauntlet-native-host-pinned-completion.v1",
        "started":value(journal,&format!("{job}.started.json"),1024,&started.sha256)?,
        "controller_key_pin":value(journal,&format!("{job}.controller-key.json"),1024,&pin.raw_sha256)?,
        "terminal":value(journal,&format!("{job}.terminal.json"),2048,&terminal.sha256)?,
        "terminal_sha256":terminal.sha256,"report":report,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
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
