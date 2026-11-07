//! Cross-job dependency uncertainty blocks further execution under the shared
//! worker lease. Completed records are checked against retained intent bytes.
use crate::{
    open_root_owned_public_directory, read_bounded_regular, RunReservationJournal, TerminalOutcome,
};
use gauntlet_contracts::canonicalize;
use gauntlet_contracts::DependencyRunIntent;
use rustix::fs::{statat, AtFlags, Dir};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) const STATE: &str = "/var/lib/hol-gauntlet-rust/dependency-state";

pub(crate) fn require_idle() -> Result<(), String> {
    crate::feature_state::require_idle()?;
    let base = open_root_owned_public_directory(Path::new("/var/lib/hol-gauntlet-rust"))
        .map_err(|e| e.to_string())?;
    match statat(&base, "dependency-state", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    let mut jobs = BTreeSet::new();
    let mut starts = BTreeMap::new();
    let mut count = 0usize;
    for entry in Dir::read_from(&journal.root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "dependency state filename UTF-8")?;
        if matches!(name, "." | ".." | "active.lock") {
            continue;
        }
        count += 1;
        if count > 4096 {
            return Err("dependency state inventory bound exceeded".into());
        }
        let (job, suffix) = name
            .split_once('.')
            .filter(|(s, _)| crate::hex(s, 16))
            .ok_or("unrecognized dependency job")?;
        if !matches!(
            suffix,
            "started.json"
                | "running.json"
                | "report.json"
                | "terminal.json"
                | "dependency-repair.json"
        ) {
            return Err("unrecognized dependency sidecar".into());
        }
        jobs.insert(job.to_owned());
        if suffix == "started.json" {
            let raw = read_bounded_regular(&journal.root, name, 1024)
                .map_err(|e| e.to_string())?
                .ok_or("dependency start disappeared")?;
            if canonicalize(&raw).map_err(|e| e.to_string())? != raw {
                return Err("ambiguous dependency start".into());
            }
            let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            starts.insert(job.to_owned(), value);
        }
    }
    for job in jobs {
        let start = starts
            .get(&job)
            .ok_or("orphan dependency sidecar blocks execution")?;
        let digest = start["deployment_digest"]
            .as_str()
            .ok_or("dependency start lacks intent")?;
        let intent = crate::dependency_repair::intent_for_job(&job, digest)?;
        let p = &intent.pins;
        journal
            .started(
                &job,
                p.text("source_sha"),
                digest,
                p.text("runner_binary_sha256"),
            )
            .map_err(|e| e.to_string())?
            .ok_or("dependency start differs")?;
        let terminal = journal
            .terminal(
                &job,
                p.text("source_sha"),
                digest,
                p.text("runner_binary_sha256"),
            )
            .map_err(|e| e.to_string())?;
        let repair = crate::dependency_repair::verified(&journal, &intent)?;
        if terminal.is_some() == repair.is_some() {
            return Err("active, ambiguous or unknown dependency job blocks execution".into());
        }
        if let Some(terminal) = terminal {
            if terminal.status != TerminalOutcome::InvalidEvidence {
                return Err("dependency terminal claims execution authority".into());
            }
            let raw = read_bounded_regular(&journal.root, &format!("{job}.report.json"), 16384)
                .map_err(|e| e.to_string())?
                .ok_or("dependency report missing")?;
            let report: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            let reported = DependencyRunIntent::parse(
                &canonicalize(report["intent"].to_string().as_bytes())
                    .map_err(|e| e.to_string())?,
            )?;
            if reported != intent
                || report["schema"] != "hol-gauntlet-native-dependency-result.v1"
                || report["intent_sha256"] != digest
                || report["container_absent"] != true
                || report["container_cgroup_absent"] != true
                || report["client_cgroup_drained"] != true
                || report["build_profile_removed"] != true
                || report["artifact_admitted"] != false
                || report["execution_eligible"] != false
                || report["guard_causality_verified"] != false
                || report["model_requests"] != 0
            {
                return Err("dependency report differs from retained intent or cleanup".into());
            }
            crate::dependency_podman::verify_completed_absent(
                &intent,
                report["container_id"]
                    .as_str()
                    .ok_or("dependency CID missing")?,
            )?;
        }
    }
    Ok(())
}

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
    let terminal = journal
        .terminal(
            job,
            p.text("source_sha"),
            expected_intent,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?;
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
    if terminal.status != TerminalOutcome::InvalidEvidence
        || terminal.controller_public_key_hex.is_some()
    {
        return Err("dependency terminal is outside this protocol".into());
    }
    let report = crate::dependency_io::read(
        &journal.root,
        &format!("{job}.report.json"),
        0,
        0o600,
        16384,
    )?;
    let public = gauntlet_contracts::verify_dependency_run_result(&intent, &report)?;
    if public["private_result_sha256"] != terminal.report_sha256
        || public["exit_code"].as_i64() != Some(i64::from(terminal.exit_code))
    {
        return Err("dependency retained report differs from terminal".into());
    }
    let value: Value = serde_json::from_slice(&report).map_err(|e| e.to_string())?;
    let cid = value["container_id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("dependency report container identity missing")?;
    crate::dependency_podman::verify_completed_absent(&intent, cid)?;
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
    stable()?;
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
    let response = serde_json::json!({"schema":"hol-gauntlet-native-dependency-read.v1",
        "reader_generation":generation,"intent_sha256":expected_intent,
        "report_sha256":format!("{:x}",Sha256::digest(&report)),"terminal_sha256":terminal.sha256,
        "report":value,"archive_proof":archive,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0,"model_tokens":0});
    let encoded = canonicalize(response.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if encoded.len() > 32768 {
        return Err("dependency reconciliation response exceeds bound".into());
    }
    stable()?;
    Ok(encoded)
}
