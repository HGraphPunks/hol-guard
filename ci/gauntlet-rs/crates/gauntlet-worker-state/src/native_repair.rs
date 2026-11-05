//! Explicit recovery of a dead native apparatus job. The job remains consumed.
use crate::native_job_io::load;
use crate::native_repair_receipt::NativeRepairReceipt;
use crate::{read_bounded_regular, RunReservationJournal, RunningMarker};
use gauntlet_contracts::{canonicalize, WorkerRequest};
use serde_json::json;
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
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(repair_generation).map_err(|e| e.to_string())?;
    let run = request(source, job, deployment)?;
    if !crate::hex(expected_started, 64) {
        return Err("outside started-marker pin required for repair".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let started = journal
        .started(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("native job was never reserved")?;
    if started.sha256 != expected_started || started.controller_public_key_hex.is_some() {
        return Err("native repair differs from original unkeyed apparatus reservation".into());
    }
    for suffix in ["terminal.json", "report.json", "controller-key.json"] {
        if read_bounded_regular(&journal.root, &format!("{job}.{suffix}"), 16 * 1024 * 1024)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("terminal/keyed job is outside this native recovery profile".into());
        }
    }
    if let Some(raw) = verified_receipt(&journal, source, job, deployment, generation)? {
        return Ok(raw);
    }
    let running = journal
        .running_marker(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("native job lacks a retained running identity")?;
    controller_absent(&running)?;
    let (spec, preparation) = load(&run, generation)?;
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
    let sdk = matches!(
        spec.execution,
        crate::NativeJobExecution::SdkTransport { .. }
    );
    if sdk {
        crate::native_sdk_quiescence::require_sdk_quiescence(&spec, &preparation)?;
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    let mut cleanup = if sdk {
        match gauntlet_cell_rootfs::native_preparation_image_history(&preparation)? {
            gauntlet_cell_rootfs::NativeImageHistory::Closed => {
                let quiescent =
                    gauntlet_cell_rootfs::verify_closed_native_preparation(&preparation)?;
                json!({"quiescent":quiescent,"image_unmounted":true,"active_pointer_absent":true,"active_pointer_sha256":null})
            }
            gauntlet_cell_rootfs::NativeImageHistory::Pending => {
                let mut cleanup =
                    gauntlet_cell_rootfs::recover_quiescent_preparation(&preparation)?;
                cleanup["quiescent"]["image_history"] = json!("recovered-pending-v1");
                cleanup
            }
        }
    } else {
        gauntlet_cell_rootfs::recover_quiescent_preparation(&preparation)?
    };
    if sdk {
        crate::native_sdk_quiescence::require_sdk_quiescence(&spec, &preparation)?;
        cleanup["sdk_agent_absent"] = json!(true);
        cleanup["sdk_profile_absent"] = json!(true);
    }
    controller_absent(&running)?;
    if journal
        .running_marker(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        != Some(running.clone())
    {
        return Err("running marker changed during native repair".into());
    }
    crate::verify_running_binary(repair_generation).map_err(|e| e.to_string())?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    let receipt = NativeRepairReceipt {
        schema: if sdk {
            "hol-gauntlet-native-worker-repair.v2"
        } else {
            "hol-gauntlet-native-worker-repair.v1"
        }
        .into(),
        source_sha: source.into(),
        job_id: job.into(),
        deployment_digest: deployment.into(),
        worker_generation: generation.into(),
        started_marker_sha256: started.sha256,
        running_marker_sha256: running.sha256,
        preparation_sha256: spec.preparation_sha256,
        repair_generation: repair_generation.into(),
        status: "aborted".into(),
        model_requests: 0,
        execution_eligible: false,
        guard_causality_verified: false,
        exit_code: None,
        cleanup,
    };
    let raw = canonicalize(
        serde_json::to_string(&receipt)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    crate::terminal::create_durable(&journal.root, &format!("{job}.native-repair.json"), &raw)
        .map_err(|e| e.to_string())?;
    verified_receipt(&journal, source, job, deployment, generation)?
        .ok_or("native repair receipt unavailable after commit".into())
}
