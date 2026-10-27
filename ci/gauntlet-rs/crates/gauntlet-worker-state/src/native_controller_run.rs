//! Descriptor-bound Rust controller; all unprivileged children start after key consumption.
use crate::native_job_io::load;
use crate::native_job_spec::NativeJobExecution;
use crate::RunReservationJournal;
use gauntlet_contracts::{canonicalize, WorkerRequest};
use serde_json::json;
use std::io::Read;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const STATE: &str = "/var/lib/hol-gauntlet-rust/worker-state";

pub fn execute_native_controller(
    args: &[String],
) -> Result<gauntlet_cell_rootfs::NativeApparatusReport, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if args.len() != 6
        || !matches!(
            args[1].as_str(),
            "--native-controller" | "--native-keyed-controller"
        )
    {
        return Err("fixed native controller arguments required".into());
    }
    crate::verify_running_binary(&args[5]).map_err(|e| e.to_string())?;
    let mut gate = [0u8; 1];
    std::io::stdin()
        .read_exact(&mut gate)
        .map_err(|_| "native controller gate was not released")?;
    if gate != [1] {
        return Err("native controller gate differs".into());
    }
    let request = WorkerRequest::parse(
        json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
        "source_sha":args[2],"job_id":args[3],"deployment_digest":args[4]})
        .to_string()
        .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let (spec, _) = load(&request, &args[5])?;
    if spec.requires_host_pin() != (args[1] == "--native-keyed-controller") {
        return Err("native controller execution mode differs from declaration".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    let running = journal
        .running_marker(
            &spec.job_id,
            &spec.source_sha,
            &args[4],
            &spec.worker_generation,
        )
        .map_err(|e| e.to_string())?
        .ok_or("native controller lacks durable running identity")?;
    if running.process.pid != std::process::id() {
        return Err("native controller running marker belongs to another PID".into());
    }
    crate::observe_process(
        running.process.pid,
        running.process.start_ticks,
        &running.cgroup,
    )
    .map_err(|_| "native controller kernel identity changed")?;
    let signing = if spec.requires_host_pin() {
        let started = journal
            .started(
                &spec.job_id,
                &spec.source_sha,
                &args[4],
                &spec.worker_generation,
            )
            .map_err(|e| e.to_string())?
            .ok_or("native keyed started marker unavailable")?;
        let pin =
            crate::controller_key::read_pin(&journal, &started, true).map_err(|e| e.to_string())?;
        let pins = gauntlet_evidence::NativeControlReportPins {
            prelaunch: gauntlet_contracts::PrelaunchPrepared {
                job_id: spec.job_id.clone(),
                source_sha: spec.source_sha.clone(),
                deployment_digest: args[4].clone(),
                worker_generation: spec.worker_generation.clone(),
                started_marker_sha256: started.sha256,
                controller_key_pin_sha256: pin.raw_sha256,
                controller_public_key_hex: pin.public_key_hex,
            },
            preparation_sha256: spec.preparation_sha256.clone(),
            role: spec.case().into(),
        };
        let key = crate::native_controller_key::consume_inherited_native_controller_key(
            &pins.prelaunch.controller_public_key_hex,
        )?;
        Some((pins, key))
    } else {
        None
    };
    let cancellation = Arc::new(AtomicBool::new(
        crate::native_worker::cancellation_requested(),
    ));
    let finished = Arc::new(AtomicBool::new(false));
    let (signal, stop) = (cancellation.clone(), finished.clone());
    let watcher = std::thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            if crate::native_worker::cancellation_requested() {
                signal.store(true, Ordering::Release);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let result = match &spec.execution {
        NativeJobExecution::Apparatus(case) => gauntlet_cell_rootfs::run_native_apparatus(
            &spec.preparation_path(),
            &spec.preparation_sha256,
            *case,
            true,
            cancellation,
        ),
        NativeJobExecution::HookTransport(pins) => gauntlet_cell_rootfs::run_native_hook_transport(
            &spec.preparation_path(),
            &spec.preparation_sha256,
            pins,
            cancellation,
        ),
        NativeJobExecution::SdkTransport { guard, sdk } => {
            crate::native_sdk_control::run_native_sdk_transport(&spec, guard, sdk, cancellation)
        }
        NativeJobExecution::McpTransport(pins) => {
            crate::native_mcp_control::run_native_mcp_transport(&spec, pins, cancellation)
        }
        NativeJobExecution::SdkMcpTransport { guard, sdk } => {
            crate::native_sdk_mcp_control::run(&spec, guard, sdk, cancellation)
        }
        NativeJobExecution::DeterministicControl { guard, sdk, role }
        | NativeJobExecution::HostPinnedControl { guard, sdk, role } => {
            crate::native_sdk_mcp_control::run_role(&spec, guard, sdk, cancellation, *role)
        }
    };
    finished.store(true, Ordering::Release);
    watcher
        .join()
        .map_err(|_| "native controller signal watcher failed")?;
    let mut result = result?;
    if let Some((pins, key)) = signing {
        use base64::{engine::general_purpose::STANDARD, Engine};
        result.report["controller_identity"] =
            json!({"pid":running.process.pid,"start_ticks":running.process.start_ticks});
        let record = gauntlet_evidence::native_control_signing_record(&result.report, &pins)
            .map_err(|e| e.to_string())?;
        let signed = canonicalize(record.to_string().as_bytes()).map_err(|e| e.to_string())?;
        result.report =
            json!({"record":record,"signature":STANDARD.encode(key.sign(&signed).as_ref())});
    }
    Ok(result)
}
