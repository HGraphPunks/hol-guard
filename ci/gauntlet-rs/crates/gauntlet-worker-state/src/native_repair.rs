//! Explicit recovery of a dead native apparatus job. The job remains consumed.
use crate::native_job_io::load;
use crate::native_repair_receipt::NativeRepairReceipt;
use crate::{read_bounded_regular, RunReservationJournal, RunningMarker};
use gauntlet_contracts::{canonicalize, WorkerRequest};
use rustix::fs::{statat, AtFlags};
use serde_json::{json, Value};
use std::path::Path;

const STATE: &str = "/var/lib/hol-gauntlet-rust/worker-state";

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
        _ => Err("live or uncertain controller resource blocks quiescent repair".into()),
    }
}

pub(crate) fn controller_absent(running: &RunningMarker) -> Result<(), String> {
    let expected = format!("/system.slice/hol-gauntlet-rust-job-{}", running.job_id);
    if running.cgroup != expected {
        return Err("native controller cgroup binding changed".into());
    }
    // A reused PID also refuses this conservative repair. Never signal a PID
    // obtained from a historical record.
    absent(&Path::new("/proc").join(running.process.pid.to_string()))?;
    absent(&Path::new("/sys/fs/cgroup").join(expected.trim_start_matches('/')))?;
    crate::require_rust_job_slice_absent(&running.job_id).map_err(|e| e.to_string())
}

pub(crate) fn verified_receipt(
    journal: &RunReservationJournal,
    source: &str,
    job: &str,
    deployment: &str,
    generation: &str,
) -> Result<Option<Vec<u8>>, String> {
    let Some(raw) = read_bounded_regular(&journal.root, &format!("{job}.native-repair.json"), 8192)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let started = journal
        .started(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("repair started marker missing")?;
    let running = journal
        .running_marker(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("repair running marker missing")?;
    let (spec, preparation) = load(&request(source, job, deployment)?, generation)?;
    if spec.requires_host_pin() {
        return verified_keyed_receipt(journal, &spec, &preparation, &running, &raw).map(Some);
    }
    if matches!(
        spec.execution,
        crate::NativeJobExecution::McpTransport(_)
            | crate::NativeJobExecution::SdkMcpTransport { .. }
            | crate::NativeJobExecution::DeterministicControl { .. }
            | crate::NativeJobExecution::HostPinnedControl { .. }
    ) {
        return Err(
            "Native MCP recovery requires its own reviewed repair profile; original job retained"
                .into(),
        );
    }
    let receipt = NativeRepairReceipt::parse(&raw)?;
    let sdk = matches!(
        spec.execution,
        crate::NativeJobExecution::SdkTransport { .. }
    );
    if sdk != (receipt.schema == "hol-gauntlet-native-worker-repair.v2") {
        return Err("native repair schema differs from the original SDK/non-SDK profile".into());
    }
    receipt.validate(
        source,
        job,
        deployment,
        generation,
        &started.sha256,
        &running.sha256,
        &spec.preparation_sha256,
    )?;
    controller_absent(&running)?;
    if sdk {
        crate::native_sdk_quiescence::require_sdk_quiescence(&spec, &preparation)?;
    }
    let current = if sdk {
        match receipt.cleanup["quiescent"]["image_history"].as_str() {
            Some("already-closed-v1") => {
                gauntlet_cell_rootfs::verify_closed_native_preparation(&preparation)?
            }
            Some("recovered-pending-v1") => {
                let mut facts = gauntlet_cell_rootfs::verify_quiescent_preparation(&preparation)?;
                facts["image_history"] = json!("recovered-pending-v1");
                facts
            }
            _ => return Err("SDK repair image history is unknown".into()),
        }
    } else {
        gauntlet_cell_rootfs::verify_quiescent_preparation(&preparation)?
    };
    if receipt.cleanup["quiescent"] != current {
        return Err("repaired job custody or quiescence changed".into());
    }
    Ok(Some(raw))
}

fn keyed_quiescence(
    spec: &crate::NativeJobSpec,
    preparation: &gauntlet_cell_rootfs::CellPreparation,
    running: &RunningMarker,
) -> Result<(), String> {
    controller_absent(running)?;
    crate::native_sdk_quiescence::require_sdk_quiescence(spec, preparation)?;
    crate::native_mcp_quiescence::require_mcp_quiescence(spec, preparation)?;
    crate::require_no_product_cell_units().map_err(|e| e.to_string())
}

fn keyed_exclusive(journal: &RunReservationJournal, job: &str) -> Result<(), String> {
    for suffix in [
        "terminal.json",
        "report.json",
        "native-startup-repair.json",
        "native-keyed-startup-repair.json",
    ] {
        match statat(
            &journal.root,
            format!("{job}.{suffix}"),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => {
                return Err(
                    "completed, partial or another repaired job blocks keyed running repair".into(),
                )
            }
        }
    }
    Ok(())
}

fn current_keyed_facts(
    spec: &crate::NativeJobSpec,
    preparation: &gauntlet_cell_rootfs::CellPreparation,
    history: &str,
) -> Result<Value, String> {
    let mut facts = match history {
        "already-closed-v1" => gauntlet_cell_rootfs::verify_closed_native_preparation(preparation)?,
        "recovered-pending-v1" => gauntlet_cell_rootfs::verify_quiescent_preparation(preparation)?,
        _ => return Err("keyed repair image history is unknown".into()),
    };
    facts["image_history"] = json!(history);
    gauntlet_cell_rootfs::require_image_lease_absent(
        &preparation.image_id,
        &preparation.podman_sha256,
    )?;
    if !spec.requires_host_pin() {
        return Err("keyed repair requires the original host-pinned Native profile".into());
    }
    Ok(facts)
}

fn verified_keyed_receipt(
    journal: &RunReservationJournal,
    spec: &crate::NativeJobSpec,
    preparation: &gauntlet_cell_rootfs::CellPreparation,
    running: &RunningMarker,
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    let (prelaunch, retained) = crate::native_keyed_startup_repair::retained(
        journal,
        &spec.source_sha,
        &spec.job_id,
        &running.deployment_digest,
        &spec.worker_generation,
    )?;
    if retained.preparation_sha256 != spec.preparation_sha256 {
        return Err("keyed repair preparation changed".into());
    }
    let value = if matches!(
        spec.execution,
        crate::NativeJobExecution::HostPinnedLive { .. }
    ) {
        let live = crate::native_live_prepare::retained(spec, &running.deployment_digest)?;
        crate::native_repair_receipt::verify_live_keyed(
            raw,
            &prelaunch,
            &spec.preparation_sha256,
            &running.sha256,
            &crate::native_live_model::sha(&live.raw),
        )?
    } else {
        crate::native_repair_receipt::verify_keyed(
            raw,
            &prelaunch,
            &spec.preparation_sha256,
            &running.sha256,
        )?
    };
    keyed_exclusive(journal, &spec.job_id)?;
    keyed_quiescence(spec, preparation, running)?;
    let facts = current_keyed_facts(
        spec,
        preparation,
        value["cleanup"]["quiescent"]["image_history"]
            .as_str()
            .ok_or("keyed repair image history missing")?,
    )?;
    if value["cleanup"]["quiescent"] != facts {
        return Err("keyed repaired job custody or quiescence changed".into());
    }
    Ok(raw.to_vec())
}

/// Reconcile a released host-pinned job only after all owned resources are
/// already quiescent. No process is adopted/signalled and no exit is inferred.
pub fn repair_native_host_pinned(
    pins: &crate::NativePrelaunchRepairPins<'_>,
) -> Result<Vec<u8>, String> {
    keyed_repair(pins, true, None)
}

/// Read an existing repair under the original public pins. A missing/partial
/// receipt remains unknown and this action never creates a replacement.
pub fn read_native_host_pinned_repair(
    pins: &crate::NativePrelaunchRepairPins<'_>,
) -> Result<Vec<u8>, String> {
    keyed_repair(pins, false, None)
}
pub fn repair_native_live_host_pinned(
    pins: &crate::NativePrelaunchRepairPins<'_>,
    live_prepared_sha256: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    if !crate::hex(live_prepared_sha256, 64) {
        return Err("outside live preparation receipt pin required for recovery".into());
    }
    keyed_repair(pins, publish, Some(live_prepared_sha256))
}

fn keyed_repair(
    pins: &crate::NativePrelaunchRepairPins<'_>,
    publish: bool,
    live_prepared_sha256: Option<&str>,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(pins.repair_generation).map_err(|e| e.to_string())?;
    pins.prelaunch.to_bytes().map_err(|e| e.to_string())?;
    if !crate::hex(pins.preparation_sha256, 64) {
        return Err("outside keyed preparation pin required".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let p = pins.prelaunch;
    let (original, spec) = crate::native_keyed_startup_repair::retained(
        &journal,
        &p.source_sha,
        &p.job_id,
        &p.deployment_digest,
        &p.worker_generation,
    )?;
    if original != *p || spec.preparation_sha256 != pins.preparation_sha256 {
        return Err("keyed repair differs from outside original reservation/preparation".into());
    }
    let live = matches!(
        spec.execution,
        crate::NativeJobExecution::HostPinnedLive { .. }
    );
    if live != live_prepared_sha256.is_some() {
        return Err(
            "live recovery requires its explicit outside preparation pin and selector".into(),
        );
    }
    if let Some(expected) = live_prepared_sha256 {
        let prepared = crate::native_live_prepare::retained(&spec, &p.deployment_digest)?;
        if crate::native_live_model::sha(&prepared.raw) != expected {
            return Err("live repair differs from original Host preparation receipt".into());
        }
    }
    let (_, preparation) = load(
        &request(&p.source_sha, &p.job_id, &p.deployment_digest)?,
        &p.worker_generation,
    )?;
    let running = journal
        .running_marker(
            &p.job_id,
            &p.source_sha,
            &p.deployment_digest,
            &p.worker_generation,
        )
        .map_err(|e| e.to_string())?
        .ok_or("keyed running repair requires a durable original process identity")?;
    let stable = || {
        lease.verify(&journal.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
        let (again, spec_again) = crate::native_keyed_startup_repair::retained(
            &journal,
            &p.source_sha,
            &p.job_id,
            &p.deployment_digest,
            &p.worker_generation,
        )?;
        if again != original
            || spec_again.preparation_sha256 != spec.preparation_sha256
            || journal
                .running_marker(
                    &p.job_id,
                    &p.source_sha,
                    &p.deployment_digest,
                    &p.worker_generation,
                )
                .map_err(|e| e.to_string())?
                != Some(running.clone())
        {
            return Err("keyed repair original custody changed".into());
        }
        keyed_exclusive(&journal, &p.job_id)?;
        keyed_quiescence(&spec, &preparation, &running)
    };
    stable()?;
    if let Some(raw) = read_bounded_regular(
        &journal.root,
        &format!("{}.native-repair.json", p.job_id),
        8192,
    )
    .map_err(|e| e.to_string())?
    {
        let raw = verified_keyed_receipt(&journal, &spec, &preparation, &running, &raw)?;
        stable()?;
        return Ok(raw);
    }
    if !publish {
        return Err("keyed repair is absent; original job remains unknown".into());
    }
    // The existing Rootfs recovery authenticates the retained declarations and
    // exact image pointer before any unmount; already closed images need none.
    let mut cleanup = match gauntlet_cell_rootfs::native_preparation_image_history(&preparation)? {
        gauntlet_cell_rootfs::NativeImageHistory::Closed => json!({
            "quiescent":gauntlet_cell_rootfs::verify_closed_native_preparation(&preparation)?,
            "image_unmounted":true,"active_pointer_absent":true,"active_pointer_sha256":null}),
        gauntlet_cell_rootfs::NativeImageHistory::Pending => {
            stable()?;
            let mut value = gauntlet_cell_rootfs::recover_quiescent_preparation(&preparation)?;
            value["quiescent"]["image_history"] = json!("recovered-pending-v1");
            value
        }
    };
    for key in [
        "controller_process_absent",
        "controller_cgroup_absent",
        "product_slice_absent",
        "sdk_agent_absent",
        "sdk_profile_absent",
        "mcp_agent_absent",
        "mcp_profile_absent",
        "image_lease_absent",
        "public_key_retained",
    ] {
        cleanup[key] = json!(true);
    }
    stable()?;
    crate::verify_running_binary(pins.repair_generation).map_err(|e| e.to_string())?;
    let prelaunch: Value = serde_json::from_slice(&p.to_bytes().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut value = json!({"schema":if live{crate::native_repair_receipt::LIVE_KEYED_SCHEMA}else{crate::native_repair_receipt::KEYED_SCHEMA},"prelaunch":prelaunch,
        "preparation_sha256":pins.preparation_sha256,"running_marker_sha256":running.sha256,
        "repair_generation":pins.repair_generation,"status":"aborted","controller_state":"released-exit-unavailable",
        "exit_code":null,"model_requests":0,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"cleanup":cleanup});
    if let Some(pin) = live_prepared_sha256 {
        value["live_prepared_sha256"] = json!(pin);
        value["model_requests"] = Value::Null;
    }
    let raw = canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string())?;
    verified_keyed_receipt(&journal, &spec, &preparation, &running, &raw)?;
    crate::terminal::create_durable(
        &journal.root,
        &format!("{}.native-repair.json", p.job_id),
        &raw,
    )
    .map_err(|e| e.to_string())?;
    stable()?;
    verified_receipt(
        &journal,
        &p.source_sha,
        &p.job_id,
        &p.deployment_digest,
        &p.worker_generation,
    )?
    .ok_or("keyed repair receipt unavailable after commit".into())
}

/// Arguments bind both the original job and the currently running repair
/// binary. No process, PID, cleanup command or terminal result is supplied.
pub fn repair_native_worker(
    source: &str,
    deployment: &str,
    generation: &str,
    job: &str,
    expected_started: &str,
    repair_generation: &str,
) -> Result<Vec<u8>, String> {
    crate::native_startup_repair::repair_released_worker(
        source,
        deployment,
        generation,
        job,
        expected_started,
        repair_generation,
    )
}
