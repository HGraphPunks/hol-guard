//! A consumed v4 reservation with no controller marker/log/key, untouched job
//! inputs and absent resources can be recorded aborted. It is never rerun.
use crate::{
    native_job_io::load, read_bounded_regular, NativeJobExecution, NativeJobSpec,
    RunReservationJournal,
};
use gauntlet_contracts::{canonicalize, WorkerRequest};
use rustix::fs::{fstat, statat, AtFlags, Dir, FileType};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const STATE: &str = "/var/lib/hol-gauntlet-rust/worker-state";
const SCHEMA: &str = "hol-gauntlet-native-pre-controller-repair.v1";
fn request(source: &str, job: &str, deployment: &str) -> Result<WorkerRequest, String> {
    WorkerRequest::parse(
        json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
        "source_sha":source,"job_id":job,"deployment_digest":deployment})
        .to_string()
        .as_bytes(),
    )
    .map_err(|e| e.to_string())
}
fn absent(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(format!(
            "pre-controller repair requires absent {}",
            path.display()
        )),
    }
}
fn entries(fd: &std::os::fd::OwnedFd) -> Result<std::collections::BTreeSet<String>, String> {
    let mut names = std::collections::BTreeSet::new();
    for entry in Dir::read_from(fd).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "startup directory UTF-8")?;
        if !matches!(name, "." | "..") {
            names.insert(name.into());
        }
        if names.len() > 2 {
            return Err("unexpected startup directory objects".into());
        }
    }
    Ok(names)
}
fn untouched_root(path: &Path, expected: &Value) -> Result<Value, String> {
    let root = crate::open_root_owned_public_directory(path).map_err(|e| e.to_string())?;
    let root_stat = fstat(&root).map_err(|e| e.to_string())?;
    if root_stat.st_uid != 0
        || root_stat.st_gid != 0
        || root_stat.st_mode & 0o7777 != 0o700
        || entries(&root)?
            != ["preparation.v1.json".into(), "workspace".into()]
                .into_iter()
                .collect()
    {
        return Err("startup job was touched or has unsafe custody".into());
    }
    let workspace = crate::open_root_owned_public_directory(&path.join("workspace"))
        .map_err(|e| e.to_string())?;
    let held = fstat(&workspace).map_err(|e| e.to_string())?;
    let visible =
        statat(&root, "workspace", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(held.st_mode) != FileType::Directory
        || held.st_uid != 0
        || held.st_gid != 0
        || held.st_mode & 0o7777 != 0o700
        || held.st_dev != visible.st_dev
        || held.st_ino != visible.st_ino
        || json!(held.st_dev) != expected["device"]
        || json!(held.st_ino) != expected["inode"]
        || expected["mode"] != 0o700
        || !entries(&workspace)?.is_empty()
    {
        return Err("startup workspace was touched or replaced".into());
    }
    Ok(
        json!({"job_device":root_stat.st_dev,"job_inode":root_stat.st_ino,
        "workspace_device":held.st_dev,"workspace_inode":held.st_ino,"workspace_empty":true,
        "only_preparation_and_workspace":true}),
    )
}
fn facts(_journal: &RunReservationJournal, spec: &NativeJobSpec) -> Result<Value, String> {
    if !matches!(spec.execution, NativeJobExecution::McpTransport(_)) {
        return Err("only the closed v4 MCP startup profile is supported".into());
    }
    for suffix in [
        "running.json",
        "terminal.json",
        "report.json",
        "controller-key.json",
        "native.stdout",
        "native.stderr",
        "native-repair.json",
    ] {
        absent(&PathBuf::from(STATE).join(format!("{}.{suffix}", spec.job_id)))?;
    }
    absent(
        &Path::new("/sys/fs/cgroup/system.slice")
            .join(format!("hol-gauntlet-rust-job-{}", spec.job_id)),
    )?;
    crate::require_rust_job_slice_absent(&spec.job_id).map_err(|e| e.to_string())?;
    crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
    let root =
        crate::open_root_owned_public_directory(&spec.job_root()).map_err(|e| e.to_string())?;
    let raw = read_bounded_regular(&root, "preparation.v1.json", 49152)
        .map_err(|e| e.to_string())?
        .ok_or("startup preparation absent")?;
    let preparation = spec.preparation(&raw)?;
    absent(&preparation.stage)?;
    let unchanged = untouched_root(&spec.job_root(), &preparation.task_mounts["workspace"])?;
    crate::native_mcp_quiescence::require_mcp_quiescence(spec, &preparation)?;
    gauntlet_cell_rootfs::require_image_lease_absent(
        &preparation.image_id,
        &preparation.podman_sha256,
    )?;
    Ok(
        json!({"untouched":unchanged,"controller_marker_absent":true,"controller_logs_absent":true,
        "controller_key_absent":true,"controller_cgroup_absent":true,"product_slice_absent":true,
        "product_stage_absent":true,"mcp_container_and_profile_absent":true,"image_lease_absent":true}),
    )
}
fn validate(
    value: &Value,
    source: &str,
    job: &str,
    deployment: &str,
    generation: &str,
    started: &str,
    preparation: &str,
) -> Result<(), String> {
    let fields = [
        "schema",
        "source_sha",
        "job_id",
        "deployment_digest",
        "worker_generation",
        "started_marker_sha256",
        "preparation_sha256",
        "repair_generation",
        "status",
        "controller_state",
        "exit_code",
        "model_requests",
        "execution_eligible",
        "guard_causality_verified",
        "cleanup",
    ];
    if value
        .as_object()
        .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|name| !o.contains_key(*name)))
        || value["schema"] != SCHEMA
        || value["source_sha"] != source
        || value["job_id"] != job
        || value["deployment_digest"] != deployment
        || value["worker_generation"] != generation
        || value["started_marker_sha256"] != started
        || value["preparation_sha256"] != preparation
        || value["repair_generation"]
            .as_str()
            .is_none_or(|s| !crate::hex(s, 64))
        || value["status"] != "aborted"
        || value["controller_state"] != "never-released"
        || !value["exit_code"].is_null()
        || value["model_requests"].as_u64() != Some(0)
        || value["execution_eligible"] != false
        || value["guard_causality_verified"] != false
    {
        return Err("startup repair differs from closed original bindings".into());
    }
    Ok(())
}
pub(crate) fn verified_receipt(
    journal: &RunReservationJournal,
    source: &str,
    job: &str,
    deployment: &str,
    generation: &str,
) -> Result<Option<Vec<u8>>, String> {
    let Some(raw) = read_bounded_regular(
        &journal.root,
        &format!("{job}.native-startup-repair.json"),
        8192,
    )
    .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let canonical = canonicalize(&raw).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| "startup repair JSON")?;
    let started = journal
        .started(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("startup reservation absent")?;
    if started.controller_public_key_hex.is_some() {
        return Err("keyed reservation cannot use pre-controller repair".into());
    }
    let (spec, _) = load(&request(source, job, deployment)?, generation)?;
    validate(
        &value,
        source,
        job,
        deployment,
        generation,
        &started.sha256,
        &spec.preparation_sha256,
    )?;
    if value["cleanup"] != facts(journal, &spec)? {
        return Err("startup repair custody/quiescence changed".into());
    }
    Ok(Some(raw))
}
pub fn repair_native_pre_controller(
    source: &str,
    job: &str,
    deployment: &str,
    generation: &str,
    expected_started: &str,
    repair_generation: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(repair_generation).map_err(|e| e.to_string())?;
    if !crate::hex(expected_started, 64) {
        return Err("outside original reservation digest required".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let started = journal
        .started(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("original startup reservation absent")?;
    if started.sha256 != expected_started || started.controller_public_key_hex.is_some() {
        return Err("original unkeyed startup reservation differs".into());
    }
    if let Some(raw) = verified_receipt(&journal, source, job, deployment, generation)? {
        return Ok(raw);
    }
    let (spec, _) = load(&request(source, job, deployment)?, generation)?;
    let cleanup = facts(&journal, &spec)?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    if facts(&journal, &spec)? != cleanup {
        return Err("startup custody changed before repair commit".into());
    }
    let receipt = json!({"schema":SCHEMA,"source_sha":source,"job_id":job,"deployment_digest":deployment,
        "worker_generation":generation,"started_marker_sha256":started.sha256,"preparation_sha256":spec.preparation_sha256,
        "repair_generation":repair_generation,"status":"aborted","controller_state":"never-released","exit_code":null,
        "model_requests":0,"execution_eligible":false,"guard_causality_verified":false,"cleanup":cleanup});
    let raw = canonicalize(receipt.to_string().as_bytes()).map_err(|e| e.to_string())?;
    crate::terminal::create_durable(
        &journal.root,
        &format!("{job}.native-startup-repair.json"),
        &raw,
    )
    .map_err(|e| e.to_string())?;
    verified_receipt(&journal, source, job, deployment, generation)?
        .ok_or("startup repair readback absent".into())
}

#[cfg(test)]
#[path = "native_startup_repair_tests.rs"]
mod tests;
