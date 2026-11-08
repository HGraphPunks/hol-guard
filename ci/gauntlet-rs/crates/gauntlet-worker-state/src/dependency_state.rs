//! Cross-job dependency uncertainty blocks further execution under the shared
//! worker lease. Completed records are checked against retained intent bytes.
use crate::{RunReservationJournal, TerminalOutcome};
use gauntlet_contracts::canonicalize;
use gauntlet_contracts::DependencyRunIntent;
use rustix::fs::{statat, AtFlags};
use serde_json::Value;
use std::path::Path;

pub(crate) const STATE: &str = "/var/lib/hol-gauntlet-rust/dependency-state";

pub(crate) use crate::dependency_run::require_idle;

pub(crate) fn client_group_absent(job: &str) -> Result<(), String> {
    let path = format!("/sys/fs/cgroup/system.slice/hol-gauntlet-rust-candidate-{job}");
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("dependency client cgroup absence uncertain".into()),
    }
}

/// Read only the original host-reserved dependency attempt. The private reply
/// travels over the bounded management pipe; the host projects public fields.
/// No admission scan opens unrelated worker records, and no workload starts.
pub fn read_native_dependencies(
    raw: &[u8],
    expected_intent: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let intent = DependencyRunIntent::parse(raw)?;
    if intent.digest()? != expected_intent {
        return Err("dependency reconciliation intent differs".into());
    }
    let p = &intent.pins;
    let job = p.text("job_id");
    let main =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let main_lease = main.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let features = RunReservationJournal::open_root_owned(Path::new(crate::feature_state::STATE))
        .map_err(|e| e.to_string())?;
    let feature_lease = features.acquire_active_lease().map_err(|e| e.to_string())?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let stable = || -> Result<(), String> {
        main_lease.verify(&main.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
        feature_lease
            .verify(&features.root)
            .map_err(|e| e.to_string())?;
        lease.verify(&journal.root).map_err(|e| e.to_string())
    };
    if crate::dependency_repair::intent_for_job(job, expected_intent)? != intent {
        return Err("dependency reconciliation differs from retained host intent".into());
    }
    let report_pending = present(&journal, &format!("{job}.report.json"))?
        && !present(&journal, &format!("{job}.terminal.json"))?;
    let terminal = if report_pending {
        retained_completion(&journal, &intent)?;
        None
    } else {
        journal
            .terminal(
                job,
                p.text("source_sha"),
                expected_intent,
                p.text("runner_binary_sha256"),
            )
            .map_err(|e| e.to_string())?
    };
    if terminal.is_some()
        && !matches!(
            statat(
                &journal.root,
                format!("{job}.dependency-repair.json"),
                AtFlags::SYMLINK_NOFOLLOW
            ),
            Err(rustix::io::Errno::NOENT)
        )
    {
        return Err("dependency has ambiguous terminal and repair records".into());
    }
    let Some(terminal) = terminal else {
        let result = if let Some(repair) = crate::dependency_repair::verified(&journal, &intent)? {
            repair
        } else {
            let started = journal
                .started(
                    job,
                    p.text("source_sha"),
                    expected_intent,
                    p.text("runner_binary_sha256"),
                )
                .map_err(|e| e.to_string())?
                .ok_or("dependency reservation missing; never retry it")?;
            if started.controller_public_key_hex.is_some() {
                return Err("keyed job is outside dependency observation".into());
            }
            let running = journal
                .running_marker(
                    job,
                    p.text("source_sha"),
                    expected_intent,
                    p.text("runner_binary_sha256"),
                )
                .map_err(|e| e.to_string())?;
            let slot = crate::builder_candidate_source::open_fixed_build_slot(job)
                .map_err(|e| e.to_string())?;
            let group = crate::feature_files::read(
                &slot,
                "candidate-client-cgroup.v1.json",
                (0, 0),
                0o600,
                2048,
            )?;
            canonicalize(serde_json::json!({"schema":"hol-gauntlet-native-dependency-unknown.v1","job_id":job,"source_sha":p.text("source_sha"),
                "intent_sha256":expected_intent,"worker_generation":p.text("runner_binary_sha256"),"reader_generation":generation,
                "started_marker_sha256":started.sha256,"running_marker_sha256":running.map(|r|r.sha256),
                "retained_client_cgroup_receipt_sha256":group.as_deref().map(|raw|format!("{:x}",Sha256::digest(raw))),
                "status":"unknown","exit_code":null,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,
                "guard_causality_verified":false,"model_requests":0,"model_tokens":0}).to_string().as_bytes()).map_err(|e|e.to_string())?
        };
        stable()?;
        return Ok(result);
    };
    completed_response(&journal, &intent, generation, &terminal, &stable)
}

struct ReportParts {
    raw: Vec<u8>,
    value: Value,
    public: Value,
    archive: Option<Value>,
}

fn present(journal: &RunReservationJournal, name: &str) -> Result<bool, String> {
    match statat(&journal.root, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

struct RetainedCompletion {
    parts: ReportParts,
    started: crate::StartedMarker,
    running: crate::RunningMarker,
    exit: i32,
}

fn retained_completion(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
) -> Result<RetainedCompletion, String> {
    let p = &intent.pins;
    let job = p.text("job_id");
    let digest = intent.digest()?;
    let started = journal
        .started(
            job,
            p.text("source_sha"),
            &digest,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?
        .ok_or("retained report reservation missing")?;
    if started.controller_public_key_hex.is_some()
        || present(journal, &format!("{job}.controller-key.json"))?
    {
        return Err("keyed report is outside dependency finalization".into());
    }
    let running = journal
        .running_marker(
            job,
            p.text("source_sha"),
            &digest,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?
        .ok_or("retained report process marker missing")?;
    if running.cgroup != format!("/system.slice/hol-gauntlet-rust-candidate-{job}") {
        return Err("retained report client group differs".into());
    }
    client_group_absent(job)?;
    match std::fs::read(format!("/proc/{}/stat", running.process.pid)) {
        Ok(raw) => {
            let observed = crate::linux_process::parse_proc_stat(&raw, running.process.pid)
                .ok_or("retained report client identity unavailable")?;
            if observed.start_ticks == running.process.start_ticks {
                return Err("retained report client still exists".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let parts = report_parts(journal, intent)?;
    let v = &parts.value;
    let exit = v["exit_code"]
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .ok_or("retained report exit unavailable")?;
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let crate::dependency_creator_recovery::OriginalCid::Retained(cid) =
        crate::dependency_creator_recovery::original(&slot, &digest)?
    else {
        return Err("retained report CID receipt missing".into());
    };
    if v["started_marker_sha256"] != started.sha256
        || v["container_id"] != cid
        || (exit == 0) != parts.archive.is_some()
    {
        return Err("retained report reservation, CID or export differs".into());
    }
    if v["execution_error"].is_null() {
        if v["client_pid"] != running.process.pid
            || v["client_start_ticks"] != running.process.start_ticks
            || ["stdout_sha256", "stderr_sha256"]
                .iter()
                .any(|k| !v[k].as_str().is_some_and(|s| crate::hex(s, 64)))
        {
            return Err("retained report process observation differs".into());
        }
    } else if !v["execution_error"].is_string()
        || exit != 2
        || [
            "client_pid",
            "client_start_ticks",
            "stdout_sha256",
            "stderr_sha256",
        ]
        .iter()
        .any(|k| !v[k].is_null())
    {
        return Err("retained report failed observation differs".into());
    }
    Ok(RetainedCompletion {
        parts,
        started,
        running,
        exit,
    })
}

/// Explicit recovery completes a full retained report without re-running it.
pub(crate) fn finalize_report(
    journal: &RunReservationJournal,
    lease: &crate::ActiveLease,
    intent: &DependencyRunIntent,
    generation: &str,
    read_only: bool,
    stable: &impl Fn() -> Result<(), String>,
) -> Result<Option<Vec<u8>>, String> {
    use sha2::{Digest, Sha256};
    let p = &intent.pins;
    let job = p.text("job_id");
    if !present(journal, &format!("{job}.report.json"))? {
        return Ok(None);
    }
    if present(journal, &format!("{job}.dependency-repair.json"))? {
        return Err("retained report conflicts with aborted dependency repair".into());
    }
    let retained = retained_completion(journal, intent)?;
    let digest = intent.digest()?;
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let context = |terminal: &[u8], finalizer: Option<&str>| {
        serde_json::json!({
        "schema":"hol-gauntlet-native-dependency-report-finalization.v1","job_id":job,"source_sha":p.text("source_sha"),
        "intent_sha256":digest,"worker_generation":p.text("runner_binary_sha256"),
        "finalizer_generation":finalizer,"started_marker_sha256":retained.started.sha256,
        "running_marker_sha256":retained.running.sha256,"report_sha256":retained.parts.public["private_result_sha256"],
        "terminal_sha256":format!("{:x}",Sha256::digest(terminal)),"status":"invalid-evidence","exit_code":retained.exit,
        "artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,"guard_causality_verified":false,
        "model_requests":0,"model_tokens":0})
    };
    if !present(journal, &format!("{job}.terminal.json"))? {
        if read_only {
            return Err("read never finalizes a retained report".into());
        }
        let request = gauntlet_contracts::WorkerRequest::parse(serde_json::json!({"schema":"hol-gauntlet-worker-request.v1",
            "action":"run","job_id":job,"source_sha":p.text("source_sha"),"deployment_digest":intent.digest()?}).to_string().as_bytes()).map_err(|e| e.to_string())?;
        stable()?;
        journal
            .finish_retained_report_under_lease(
                lease,
                &request,
                &retained.started,
                &retained.parts.raw,
                retained.running.process,
                retained.exit,
                &|terminal| {
                    stable().map_err(crate::ReservationError::Io)?;
                    crate::dependency_io::report_finalization(
                        &slot,
                        &context(terminal, Some(generation)),
                        true,
                    )
                    .map_err(crate::ReservationError::Io)?;
                    stable().map_err(crate::ReservationError::Io)?;
                    crate::dependency_creator_recovery::publish(
                        journal,
                        &slot,
                        &format!("{job}.terminal.json"),
                        terminal,
                    )
                    .map_err(crate::ReservationError::Io)
                },
            )
            .map_err(|e| e.to_string())?;
    }
    let terminal_raw = crate::dependency_io::read(
        &journal.root,
        &format!("{job}.terminal.json"),
        0,
        0o600,
        2048,
    )?;
    crate::dependency_io::report_finalization(
        &slot,
        &context(
            &terminal_raw,
            if read_only { None } else { Some(generation) },
        ),
        false,
    )?;
    let terminal = journal
        .terminal(
            job,
            p.text("source_sha"),
            &intent.digest()?,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?
        .ok_or("report finalization terminal missing")?;
    completed_response(journal, intent, generation, &terminal, stable).map(Some)
}

fn report_parts(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
) -> Result<ReportParts, String> {
    let p = &intent.pins;
    let job = p.text("job_id");
    let report = crate::dependency_io::read(
        &journal.root,
        &format!("{job}.report.json"),
        0,
        0o600,
        16384,
    )?;
    let public = gauntlet_contracts::verify_dependency_run_result(intent, &report)?;
    let value: Value = serde_json::from_slice(&report).map_err(|e| e.to_string())?;
    let cid = value["container_id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("dependency report container identity missing")?;
    crate::dependency_podman::verify_completed_absent(intent, cid)?;
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let archive = if let Some(hash) = public["captured_dependencies_sha256"].as_str() {
        let bytes =
            crate::dependency_io::read(&slot, "dependencies.zip", 0, 0o444, 256 * 1024 * 1024)?;
        if public["captured_dependencies_bytes"].as_u64() != Some(bytes.len() as u64) {
            return Err("dependency retained export length differs".into());
        }
        Some(
            crate::inspect_dependency_archive(
                &bytes,
                &crate::DependencyArchivePins {
                    job_id: job,
                    source_sha: p.text("source_sha"),
                    archive_sha256: hash,
                    pyproject_sha256: p.text("pyproject_sha256"),
                    uv_lock_sha256: p.text("uv_lock_sha256"),
                },
            )?
            .to_json(),
        )
    } else {
        match statat(&slot, "dependencies.zip", AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => None,
            _ => return Err("unreported dependency export needs separate inspection".into()),
        }
    };
    if crate::dependency_io::read(
        &journal.root,
        &format!("{job}.report.json"),
        0,
        0o600,
        16384,
    )? != report
    {
        return Err("dependency report changed while reconciling".into());
    }
    Ok(ReportParts {
        raw: report,
        value,
        public,
        archive,
    })
}

pub(crate) fn completed_response(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    generation: &str,
    terminal: &crate::TerminalReceipt,
    stable: &impl Fn() -> Result<(), String>,
) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    if terminal.status != TerminalOutcome::InvalidEvidence
        || terminal.controller_public_key_hex.is_some()
    {
        return Err("dependency terminal is outside this protocol".into());
    }
    let parts = report_parts(journal, intent)?;
    if parts.public["private_result_sha256"] != terminal.report_sha256
        || parts.public["exit_code"].as_i64() != Some(i64::from(terminal.exit_code))
    {
        return Err("dependency retained report differs from terminal".into());
    }
    stable()?;
    let response = serde_json::json!({"schema":"hol-gauntlet-native-dependency-read.v1",
        "reader_generation":generation,"intent_sha256":intent.digest()?,
        "report_sha256":format!("{:x}",Sha256::digest(&parts.raw)),"terminal_sha256":terminal.sha256,
        "report":parts.value,"archive_proof":parts.archive,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0,"model_tokens":0});
    let encoded = canonicalize(response.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if encoded.len() > 32768 {
        return Err("dependency reconciliation response exceeds bound".into());
    }
    stable()?;
    Ok(encoded)
}
