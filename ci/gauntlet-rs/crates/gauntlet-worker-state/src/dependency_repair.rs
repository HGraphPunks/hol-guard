//! Quiescent dependency recovery retains an aborted attempt with unknown exit.
//! It never signals a historical PID, changes evidence or retries installation.
use crate::{read_bounded_regular, RunReservationJournal};
use gauntlet_contracts::{canonicalize, DependencyRunIntent};
use rustix::fs::{statat, AtFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::fd::OwnedFd;
use std::path::Path;

pub(crate) fn intent_for_job(job: &str, expected: &str) -> Result<DependencyRunIntent, String> {
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let raw = crate::dependency_io::read(&slot, "dependency-intent.v1.json", 0, 0o600, 8192)?;
    let intent = DependencyRunIntent::parse(&raw)?;
    if intent.pins.text("job_id") != job || intent.digest()? != expected {
        return Err("retained dependency intent differs".into());
    }
    crate::dependency_io::verify_inputs(&slot, &intent)?;
    Ok(intent)
}

fn container_identity(slot: &OwnedFd, digest: &str) -> Result<String, String> {
    let raw = crate::dependency_io::read(slot, "dependency-container.v1.json", 0, 0o600, 2048)?;
    if canonicalize(&raw).map_err(|e| e.to_string())? != raw {
        return Err("dependency CID receipt is ambiguous".into());
    }
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let cid = v["container_id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("dependency CID receipt missing")?;
    if v.as_object().is_none_or(|o| o.len() != 3)
        || v["schema"] != "hol-gauntlet-native-dependency-container.v1"
        || v["intent_sha256"] != digest
    {
        return Err("dependency CID receipt differs".into());
    }
    Ok(cid.into())
}

fn captured(slot: &OwnedFd) -> Result<Option<(u64, String)>, String> {
    match statat(slot, "dependencies.zip", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(e) => Err(e.to_string()),
        Ok(_) => {
            let raw =
                crate::dependency_io::read(slot, "dependencies.zip", 0, 0o444, 256 * 1024 * 1024)?;
            Ok(Some((
                raw.len() as u64,
                format!("{:x}", Sha256::digest(raw)),
            )))
        }
    }
}

fn body(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    repair: &str,
) -> Result<Value, String> {
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
        .ok_or("dependency reservation missing")?;
    if started.controller_public_key_hex.is_some() {
        return Err("keyed job is outside dependency recovery".into());
    }
    let running = journal
        .running_marker(
            job,
            p.text("source_sha"),
            &digest,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?;
    if let Some(marker) = &running {
        if marker.cgroup != format!("/system.slice/hol-gauntlet-rust-candidate-{job}") {
            return Err("dependency client cgroup differs".into());
        }
        match std::fs::symlink_metadata(format!("/proc/{}", marker.process.pid)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("dependency client PID still exists or is uncertain".into()),
        }
    }
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let cid = container_identity(&slot, &digest)?;
    crate::dependency_podman::verify_completed_absent(intent, &cid)?;
    let output = captured(&slot)?;
    Ok(
        json!({"schema":"hol-gauntlet-native-dependency-repair.v1","job_id":job,"source_sha":p.text("source_sha"),"intent_sha256":digest,
        "worker_generation":p.text("runner_binary_sha256"),"repair_generation":repair,"started_marker_sha256":started.sha256,
        "running_marker_sha256":running.map(|m|m.sha256),"container_id":cid,"captured_dependencies_bytes":output.as_ref().map(|(n,_)|n),
        "captured_dependencies_sha256":output.as_ref().map(|(_,s)|s),"status":"aborted","exit_code":null,"quiescent":true,
        "artifact_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

pub(crate) fn verified(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
) -> Result<Option<Vec<u8>>, String> {
    let name = format!("{}.dependency-repair.json", intent.pins.text("job_id"));
    let Some(raw) = read_bounded_regular(&journal.root, &name, 8192).map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    if canonicalize(&raw).map_err(|e| e.to_string())? != raw {
        return Err("canonical dependency repair receipt required".into());
    }
    let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let generation = value["repair_generation"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("dependency repair executable pin missing")?;
    if value != body(journal, intent, generation)? {
        return Err(
            "dependency repair differs from retained identity or claims execution credit".into(),
        );
    }
    Ok(Some(raw))
}

pub fn repair_native_dependencies(
    job: &str,
    digest: &str,
    expected_started: &str,
    original_generation: &str,
    repair_generation: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(repair_generation).map_err(|e| e.to_string())?;
    if !crate::hex(expected_started, 64) || !crate::hex(original_generation, 64) {
        return Err("outside dependency recovery pins required".into());
    }
    let main =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = main.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let journal = RunReservationJournal::open_root_owned(Path::new(crate::dependency_state::STATE))
        .map_err(|e| e.to_string())?;
    let job_lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let intent = intent_for_job(job, digest)?;
    if intent.pins.text("runner_binary_sha256") != original_generation {
        return Err("original dependency generation differs".into());
    }
    let started = journal
        .started(
            job,
            intent.pins.text("source_sha"),
            digest,
            original_generation,
        )
        .map_err(|e| e.to_string())?
        .ok_or("dependency job was not reserved")?;
    if started.sha256 != expected_started {
        return Err("outside dependency reservation differs".into());
    }
    for suffix in ["report.json", "terminal.json", "controller-key.json"] {
        match statat(
            &journal.root,
            format!("{job}.{suffix}"),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(
                "terminal, partial-report or keyed dependency job needs separate reconciliation"
                    .into(),
            ),
        }
    }
    if let Some(raw) = verified(&journal, &intent)? {
        return Ok(raw);
    }
    let raw = canonicalize(
        body(&journal, &intent, repair_generation)?
            .to_string()
            .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    lease.verify(&main.root).map_err(|e| e.to_string())?;
    job_lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    crate::terminal::create_durable(
        &journal.root,
        &format!("{job}.dependency-repair.json"),
        &raw,
    )
    .map_err(|e| e.to_string())?;
    let observed = verified(&journal, &intent)?.ok_or("dependency recovery commit unavailable")?;
    if observed != raw {
        return Err("dependency recovery changed after commit".into());
    }
    lease.verify(&main.root).map_err(|e| e.to_string())?;
    job_lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    Ok(raw)
}
