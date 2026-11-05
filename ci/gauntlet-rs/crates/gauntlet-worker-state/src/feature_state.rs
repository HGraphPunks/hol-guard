//! Feature uncertainty participates in every Rust native/dependency admission.
//! A complete diagnostic still needs matching Root artifacts and actual cleanup.
use crate::feature_files as files;
use crate::feature_journal::{self, FeatureRecord};
use crate::{open_root_owned_public_directory, RunReservationJournal};
use gauntlet_contracts::{canonicalize, verify_feature_run_result};
use rustix::fs::{statat, AtFlags};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::path::Path;

pub(crate) const STATE: &str = "/var/lib/hol-gauntlet-rust/feature-state";
pub(crate) const JOBS: &str = "/var/lib/hol-gauntlet-rust/feature-jobs";
pub(crate) fn journal() -> Result<RunReservationJournal, String> {
    RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())
}
pub(crate) fn slot(audit: &str) -> Result<Option<OwnedFd>, String> {
    if !crate::hex(audit, 16) {
        return Err("exact feature audit ID required".into());
    }
    let jobs = open_root_owned_public_directory(Path::new(JOBS)).map_err(|e| e.to_string())?;
    files::private_directory(&jobs, (0, 0))?;
    match statat(&jobs, audit, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(e) => Err(e.to_string()),
        Ok(_) => Ok(Some(files::open_directory(&jobs, audit, (0, 0))?)),
    }
}
pub(crate) fn client_absent(audit: &str) -> Result<(), String> {
    if !crate::hex(audit, 16) {
        return Err("exact feature client ID required".into());
    }
    match std::fs::symlink_metadata(format!(
        "/sys/fs/cgroup/system.slice/hol-gauntlet-rust-feature-{audit}"
    )) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("feature client cgroup exists or is uncertain".into()),
    }
}
pub(crate) fn verify_result(record: &FeatureRecord, result: &Value) -> Result<(), String> {
    let intent = &record.intent;
    verify_feature_run_result(intent, result)?;
    let running = record
        .running
        .as_ref()
        .ok_or("feature result lacks durable running identity")?;
    for key in ["container_id", "client_pid", "client_start_ticks"] {
        if result[key] != running[key] {
            return Err("feature result and running identity differ".into());
        }
    }
    let slot = slot(intent.pins().audit_id())?.ok_or("feature result slot missing")?;
    let container = crate::feature_container::FeatureContainer::restore(intent, Some(&slot))?;
    if container.id() != result["container_id"].as_str() {
        return Err("feature result CID differs from retained receipt".into());
    }
    crate::feature_container::completed_absent(intent, container.id())?;
    let stdout = files::required(&slot, "feature-run.stdout.log", (0, 0), 0o600, 128 * 1024)?;
    let stderr = files::required(&slot, "feature-run.stderr.log", (0, 0), 0o600, 128 * 1024)?;
    if result["stdout_sha256"] != crate::feature_capture::digest(&stdout)
        || result["stderr_sha256"] != crate::feature_capture::digest(&stderr)
    {
        return Err("feature result stream digests differ".into());
    }
    if result["feature_artifacts_verified"] == true {
        let readback = crate::feature_capture::verify_stored(&slot, intent)?;
        let raw = canonicalize(readback.to_string().as_bytes()).map_err(|e| e.to_string())?;
        if result["audit_status"] != readback["status"]
            || result["feature_report_sha256"] != readback["report_sha256"]
            || result["feature_readback_sha256"] != crate::feature_capture::digest(&raw)
        {
            return Err(
                "feature result and independently retained artifact readback differ".into(),
            );
        }
    }
    Ok(())
}
pub(crate) fn repair_body(record: &FeatureRecord, generation: &str) -> Result<Value, String> {
    if !crate::hex(generation, 64) {
        return Err("feature repair generation required".into());
    }
    let intent = &record.intent;
    let p = intent.pins();
    if let Some(running) = &record.running {
        let pid = running["client_pid"]
            .as_u64()
            .ok_or("feature PID missing")? as u32;
        let ticks = running["client_start_ticks"]
            .as_u64()
            .ok_or("feature start ticks missing")?;
        match std::fs::read(format!("/proc/{pid}/stat")) {
            Ok(raw) => {
                let current = crate::linux_process::parse_proc_stat(&raw, pid)
                    .ok_or("feature client process identity uncertain")?;
                if current.start_ticks == ticks {
                    return Err("original feature client still exists".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    let slot = slot(p.audit_id())?;
    let container = crate::feature_container::FeatureContainer::restore(intent, slot.as_ref())?;
    crate::feature_container::completed_absent(intent, container.id())?;
    let running_sha = record
        .running
        .as_ref()
        .map(|v| {
            canonicalize(v.to_string().as_bytes()).map(|raw| crate::feature_capture::digest(&raw))
        })
        .transpose()
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"schema":"hol-gauntlet-native-feature-repair.v1","audit_id":p.audit_id(),
        "source_sha":p.spec().text("source_sha"),"intent_sha256":intent.digest()?,
        "worker_generation":p.text("runner_binary_sha256"),"repair_generation":generation,
        "running_sha256":running_sha,"container_id":container.id(),"status":"aborted","exit_code":null,
        "quiescent":true,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,
        "guard_causality_verified":false,"model_requests":0,"model_tokens":0}),
    )
}
pub(crate) fn verify_repair(record: &FeatureRecord, value: &Value) -> Result<(), String> {
    let generation = value["repair_generation"]
        .as_str()
        .ok_or("feature repair generation missing")?;
    if *value != repair_body(record, generation)? {
        return Err("feature repair or present cleanup differs".into());
    }
    Ok(())
}
pub(crate) fn require_idle() -> Result<(), String> {
    let base = open_root_owned_public_directory(Path::new("/var/lib/hol-gauntlet-rust"))
        .map_err(|e| e.to_string())?;
    match statat(&base, "feature-state", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let journal = journal()?;
    for record in feature_journal::inventory(&journal.root, (0, 0))?.values() {
        match (&record.result, &record.repair) {
            (Some(result), None) => verify_result(record, result)?,
            (None, Some(repair)) => verify_repair(record, repair)?,
            _ => return Err("active, partial or unknown feature job blocks execution".into()),
        }
    }
    Ok(())
}
