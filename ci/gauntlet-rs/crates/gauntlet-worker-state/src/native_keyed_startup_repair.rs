//! Recovery only for a v7 reservation interrupted before any controller state.
//! The public key and consumed job ID survive; no private key or exit is invented.
use crate::{native_job_io::load, read_bounded_regular, NativeJobSpec, RunReservationJournal};
use gauntlet_contracts::{canonicalize, PrelaunchPrepared, WorkerRequest};
use rustix::fs::{fstat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags};
use serde_json::{json, Value};
use std::{os::fd::OwnedFd, path::Path};

const STATE: &str = "/var/lib/hol-gauntlet-rust/worker-state";
const SUFFIX: &str = "native-keyed-startup-repair.json";
const SCHEMA: &str = "hol-gauntlet-native-keyed-pre-controller-repair.v1";

pub struct NativePrelaunchRepairPins<'a> {
    pub prelaunch: &'a PrelaunchPrepared,
    pub preparation_sha256: &'a str,
    pub repair_generation: &'a str,
}

fn request(pins: &PrelaunchPrepared) -> Result<WorkerRequest, String> {
    WorkerRequest::parse(json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
        "source_sha":pins.source_sha,"job_id":pins.job_id,"deployment_digest":pins.deployment_digest})
        .to_string().as_bytes()).map_err(|e|e.to_string())
}
fn absent(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(format!(
            "keyed startup repair requires absent {}",
            path.display()
        )),
    }
}
fn entries(fd: &OwnedFd) -> Result<std::collections::BTreeSet<String>, String> {
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
            return Err("unexpected keyed startup objects".into());
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
        || expected["source"] != path.join("workspace").to_string_lossy().as_ref()
        || expected["custody_root"] != path.to_string_lossy().as_ref()
    {
        return Err("keyed startup job custody or inventory differs".into());
    }
    // The original task workspace belongs to UID 10001. Only its Root parent is
    // traversed; a Root-only directory walker would reject this declared inode.
    let workspace = openat(
        &root,
        "workspace",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let held = fstat(&workspace).map_err(|e| e.to_string())?;
    let visible =
        statat(&root, "workspace", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(held.st_mode) != FileType::Directory
        || held.st_uid != 10001
        || held.st_gid != 10001
        || held.st_mode & 0o7777 != 0o700
        || held.st_dev != visible.st_dev
        || held.st_ino != visible.st_ino
        || json!(held.st_dev) != expected["device"]
        || json!(held.st_ino) != expected["inode"]
        || expected["mode"] != 0o700
        || !entries(&workspace)?.is_empty()
    {
        return Err("keyed startup workspace was touched or replaced".into());
    }
    Ok(
        json!({"job_device":root_stat.st_dev,"job_inode":root_stat.st_ino,
        "workspace_device":held.st_dev,"workspace_inode":held.st_ino,"workspace_uid":10001,
        "workspace_gid":10001,"workspace_empty":true,"only_preparation_and_workspace":true}),
    )
}
fn retained(
    journal: &RunReservationJournal,
    source: &str,
    job: &str,
    deployment: &str,
    generation: &str,
) -> Result<(PrelaunchPrepared, NativeJobSpec), String> {
    let started = journal
        .started(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("keyed startup reservation absent")?;
    let pin =
        crate::controller_key::read_pin(journal, &started, true).map_err(|e| e.to_string())?;
    let prepared = PrelaunchPrepared {
        job_id: job.into(),
        source_sha: source.into(),
        deployment_digest: deployment.into(),
        worker_generation: generation.into(),
        started_marker_sha256: started.sha256,
        controller_key_pin_sha256: pin.raw_sha256,
        controller_public_key_hex: pin.public_key_hex,
    };
    prepared.to_bytes().map_err(|e| e.to_string())?;
    let (spec, _) = load(&request(&prepared)?, generation)?;
    if !spec.requires_host_pin() {
        return Err("only the closed v7 host-pinned profile can use keyed startup repair".into());
    }
    Ok((prepared, spec))
}
fn facts(journal: &RunReservationJournal, spec: &NativeJobSpec) -> Result<Value, String> {
    for suffix in [
        "running.json",
        "terminal.json",
        "report.json",
        "native.stdout",
        "native.stderr",
        "native-repair.json",
        "native-startup-repair.json",
    ] {
        if read_bounded_regular(
            &journal.root,
            &format!("{}.{suffix}", spec.job_id),
            16 * 1024 * 1024,
        )
        .map_err(|e| e.to_string())?
        .is_some()
        {
            return Err(
                "controller state, logs or another recovery blocks keyed startup repair".into(),
            );
        }
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
        .ok_or("keyed startup preparation absent")?;
    let preparation = spec.preparation(&raw)?;
    absent(&preparation.stage)?;
    let unchanged = untouched_root(&spec.job_root(), &preparation.task_mounts["workspace"])?;
    crate::native_sdk_quiescence::require_sdk_quiescence(spec, &preparation)?;
    crate::native_mcp_quiescence::require_mcp_quiescence(spec, &preparation)?;
    gauntlet_cell_rootfs::require_image_lease_absent(
        &preparation.image_id,
        &preparation.podman_sha256,
    )?;
    Ok(
        json!({"untouched":unchanged,"controller_marker_absent":true,"controller_logs_absent":true,
        "controller_cgroup_absent":true,"product_slice_absent":true,"product_stage_absent":true,
        "sdk_container_and_profile_absent":true,"mcp_container_and_profile_absent":true,
        "image_lease_absent":true,"public_key_retained":true}),
    )
}
fn validate(value: &Value, prepared: &PrelaunchPrepared, preparation: &str) -> Result<(), String> {
    let fields = [
        "schema",
        "prelaunch",
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
    let prelaunch: Value = serde_json::from_slice(&prepared.to_bytes().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if value
        .as_object()
        .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
        || value["schema"] != SCHEMA
        || value["prelaunch"] != prelaunch
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
        return Err("keyed startup repair differs from original public pins".into());
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
    let Some(raw) = read_bounded_regular(&journal.root, &format!("{job}.{SUFFIX}"), 8192)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let canonical = canonicalize(&raw).map_err(|e| e.to_string())?;
    if canonical != raw {
        return Err("keyed startup receipt is not canonical".into());
    }
    let value: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
    let (prepared, spec) = retained(journal, source, job, deployment, generation)?;
    validate(&value, &prepared, &spec.preparation_sha256)?;
    if value["cleanup"] != facts(journal, &spec)? {
        return Err("keyed startup repair custody or quiescence changed".into());
    }
    Ok(Some(raw))
}
pub fn repair_native_host_pinned_pre_controller(
    pins: &NativePrelaunchRepairPins<'_>,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(pins.repair_generation).map_err(|e| e.to_string())?;
    pins.prelaunch.to_bytes().map_err(|e| e.to_string())?;
    if !crate::hex(pins.preparation_sha256, 64) {
        return Err("outside preparation pin required".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let p = pins.prelaunch;
    let (prepared, spec) = retained(
        &journal,
        &p.source_sha,
        &p.job_id,
        &p.deployment_digest,
        &p.worker_generation,
    )?;
    if prepared != *p || spec.preparation_sha256 != pins.preparation_sha256 {
        return Err("outside keyed reservation or preparation differs".into());
    }
    if let Some(raw) = verified_receipt(
        &journal,
        &p.source_sha,
        &p.job_id,
        &p.deployment_digest,
        &p.worker_generation,
    )? {
        return Ok(raw);
    }
    let cleanup = facts(&journal, &spec)?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    let (again, again_spec) = retained(
        &journal,
        &p.source_sha,
        &p.job_id,
        &p.deployment_digest,
        &p.worker_generation,
    )?;
    if again != prepared
        || again_spec.preparation_sha256 != spec.preparation_sha256
        || facts(&journal, &spec)? != cleanup
    {
        return Err("keyed startup custody changed before commit".into());
    }
    let prelaunch: Value = serde_json::from_slice(&p.to_bytes().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let receipt = json!({"schema":SCHEMA,"prelaunch":prelaunch,"preparation_sha256":pins.preparation_sha256,
        "repair_generation":pins.repair_generation,"status":"aborted","controller_state":"never-released",
        "exit_code":null,"model_requests":0,"execution_eligible":false,"guard_causality_verified":false,"cleanup":cleanup});
    let raw = canonicalize(receipt.to_string().as_bytes()).map_err(|e| e.to_string())?;
    crate::terminal::create_durable(&journal.root, &format!("{}.{}", p.job_id, SUFFIX), &raw)
        .map_err(|e| e.to_string())?;
    verified_receipt(
        &journal,
        &p.source_sha,
        &p.job_id,
        &p.deployment_digest,
        &p.worker_generation,
    )?
    .ok_or("keyed startup repair readback absent".into())
}

#[cfg(test)]
#[path = "native_keyed_startup_repair_tests.rs"]
mod tests;
