//! Native apparatus dispatcher. It always retains an invalid-evidence terminal;
//! Guard control scoring and authenticated host admission are separate exits.
use crate::builder_image_context::{python_worker_lock, verify_python_lock};
use crate::native_controller_exec::NativeChild;
use crate::native_job_io::{load, own_identity, require_no_unknown_jobs};
use crate::native_job_spec::{NativeJobExecution, ACTIVE_SECONDS};
use crate::{BoottimeDeadline, OwnedJobCgroup, RunReservationJournal, TerminalOutcome};
use gauntlet_contracts::{canonicalize, WorkerAction, WorkerRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const STATE: &str = "/var/lib/hol-gauntlet-rust/worker-state";
static CANCELLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn cancellation_requested() -> bool {
    CANCELLED.load(Ordering::Acquire)
}

extern "C" fn cancel(_: libc::c_int) {
    CANCELLED.store(true, Ordering::Release);
}

pub fn install_native_worker_signals() -> Result<(), String> {
    // Only a lock-free atomic store runs in the signal handler.
    for signal in [libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::signal(signal, cancel as libc::sighandler_t) } == libc::SIG_ERR {
            return Err("native worker signal handler unavailable".into());
        }
    }
    Ok(())
}

pub fn execute_native_controller(
    args: &[String],
) -> Result<gauntlet_cell_rootfs::NativeApparatusReport, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if args.len() != 6 || args[1] != "--native-controller" {
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
    let cancellation = Arc::new(AtomicBool::new(CANCELLED.load(Ordering::Acquire)));
    let finished = Arc::new(AtomicBool::new(false));
    let (signal, stop) = (cancellation.clone(), finished.clone());
    let watcher = std::thread::spawn(move || {
        while !stop.load(Ordering::Acquire) {
            if CANCELLED.load(Ordering::Acquire) {
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
    };
    finished.store(true, Ordering::Release);
    watcher
        .join()
        .map_err(|_| "native controller signal watcher failed")?;
    result
}

pub fn dispatch_native_worker(
    source: &str,
    deployment: &str,
    generation: &str,
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let request = WorkerRequest::parse(raw).map_err(|e| e.to_string())?;
    if request.source_sha() != source {
        return Err("native request differs from outside source pin".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    if request.action() != WorkerAction::Run {
        return journal
            .project_read_only(&request, source, Some(deployment), generation)
            .map_err(|e| e.to_string());
    }
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = python_worker_lock().map_err(|e| e.to_string())?;
    require_no_unknown_jobs(&journal)?;
    crate::dependency_state::require_idle()?;
    if CANCELLED.load(Ordering::Acquire) {
        return Err("native worker cancelled before admission".into());
    }
    let (spec, preparation) = load(&request, generation)?;
    if request.deployment_digest() != Some(deployment) {
        return Err("native deployment differs from outside pin".into());
    }
    gauntlet_cell_rootfs::require_image_lease_absent(
        &preparation.image_id,
        &preparation.podman_sha256,
    )?;
    crate::require_rust_job_slice_absent(&spec.job_id).map_err(|e| e.to_string())?;
    let started = journal
        .reserve_under_lease(&lease, &request, source, deployment, generation)
        .map_err(|e| e.to_string())?;
    let deadline = BoottimeDeadline::start(ACTIVE_SECONDS).map_err(|e| e.to_string())?;
    let mut group = OwnedJobCgroup::create(&spec.job_id).map_err(|e| e.to_string())?;
    let mut native: Option<NativeChild> = None;
    let mut process = None;
    let mut slice_attempted = false;
    let systemctl = preparation
        .host_helper_sha256("/usr/bin/systemctl")
        .ok_or("native systemctl pin unavailable")?;
    let outcome = (|| -> Result<(i32, Option<String>), String> {
        lease.verify(&journal.root).map_err(|e| e.to_string())?;
        verify_python_lock(&python).map_err(|e| e.to_string())?;
        gauntlet_cell_rootfs::begin_owned_job_slice(&spec.job_id, systemctl, &mut slice_attempted)?;
        native = Some(NativeChild::spawn(
            &spec,
            deployment,
            &group,
            &journal.root,
        )?);
        let child = native.as_mut().ok_or("native child missing")?;
        let identity = own_identity(&child.child, &spec, deployment, group.path())?;
        process = Some(identity);
        journal
            .mark_running_under_lease(
                &lease,
                &request,
                source,
                deployment,
                generation,
                &started.sha256,
                identity,
                group.path(),
            )
            .map_err(|e| e.to_string())?;
        own_identity(&child.child, &spec, deployment, group.path())?;
        child.release()?;
        let mut interruption: Option<String> = None;
        let mut grace = None;
        loop {
            lease.verify(&journal.root).map_err(|e| e.to_string())?;
            verify_python_lock(&python).map_err(|e| e.to_string())?;
            child.check_logs()?;
            if let Some(status) = child.child.try_wait().map_err(|e| e.to_string())? {
                use std::os::unix::process::ExitStatusExt;
                return Ok((
                    status
                        .code()
                        .unwrap_or_else(|| -status.signal().unwrap_or(1)),
                    interruption,
                ));
            }
            let expired = deadline.remaining().map_err(|e| e.to_string())?.is_zero();
            if interruption.is_none() && (expired || CANCELLED.load(Ordering::Acquire)) {
                interruption = Some(
                    if expired {
                        "active deadline exceeded"
                    } else {
                        "worker cancelled"
                    }
                    .into(),
                );
                // The still-unreaped owned child pins this PID. Give its Rust
                // cleanup path a bounded chance before recursive cgroup kill.
                unsafe {
                    libc::kill(child.child.id() as i32, libc::SIGTERM);
                }
                grace = Some(BoottimeDeadline::start(25).map_err(|e| e.to_string())?);
            }
            if grace
                .is_some_and(|deadline| deadline.remaining().map_or(true, |left| left.is_zero()))
            {
                return Err(
                    interruption.unwrap_or_else(|| "native termination grace unavailable".into())
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    })();
    // Kill/drain the controller first so it cannot recreate product units.
    // Then stop only the fresh slice whose creation this invocation attempted.
    let helper_pin = gauntlet_cell_rootfs::verify_systemctl(systemctl);
    let cleanup = crate::controller_run::cleanup(
        &mut group,
        native.as_mut().map(|n| &mut n.child),
        &spec.job_id,
        slice_attempted && helper_pin.is_ok(),
    );
    cleanup.map_err(|e| e.to_string())?;
    helper_pin?;
    gauntlet_cell_rootfs::verify_systemctl(systemctl)?;
    gauntlet_cell_rootfs::require_image_lease_absent(
        &preparation.image_id,
        &preparation.podman_sha256,
    )?;
    let (_, post) = load(&request, generation)?;
    if post.runtime_tree_digest != preparation.runtime_tree_digest {
        return Err("native preparation changed after execution".into());
    }
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    verify_python_lock(&python).map_err(|e| e.to_string())?;
    let sdk_quiescent = matches!(spec.execution, NativeJobExecution::SdkTransport { .. });
    if sdk_quiescent {
        crate::native_sdk_quiescence::require_sdk_quiescence(&spec, &preparation)?;
    }
    let process =
        process.ok_or("native launch did not establish a running process; retain unknown job")?;
    let (stdout, stderr) = native.as_mut().ok_or("native child logs missing")?.logs()?;
    let parsed = canonicalize(&stdout)
        .ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
    let (exit_code, interruption, execution_error) = match outcome {
        Ok((code, reason)) => (code, reason, None),
        Err(error) => (-1, None, Some(error)),
    };
    let report_schema = match spec.execution {
        NativeJobExecution::Apparatus(_) => "hol-gauntlet-native-worker-report.v1",
        NativeJobExecution::HookTransport(_) => "hol-gauntlet-native-worker-report.v2",
        NativeJobExecution::SdkTransport { .. } => "hol-gauntlet-native-worker-report.v3",
    };
    let unavailable_reason = match spec.execution {
        NativeJobExecution::Apparatus(_) => "native apparatus profile has no independently scored Guard controls or host signing-key pin",
        NativeJobExecution::HookTransport(_) => "native hook transport has no authenticated SDK calls, independently scored Guard controls or host signing-key pin",
        NativeJobExecution::SdkTransport { .. } => "native SDK Bash transport has no MCP, independently scored Guard controls, six-role conformance or host signing-key pin",
    };
    let mut report = json!({"schema":report_schema,"profile":spec.profile(),
        "source_sha":source,"job_id":spec.job_id,"deployment_digest":deployment,"worker_generation":generation,
        "started_marker_sha256":started.sha256,"preparation_sha256":spec.preparation_sha256,"case":spec.case(),
        "controller":process_json(process),"controller_report":parsed,"controller_stdout_sha256":format!("{:x}",Sha256::digest(&stdout)),
        "controller_stderr_sha256":format!("{:x}",Sha256::digest(&stderr)),"exit_code":exit_code,"interruption":interruption,
        "execution_error":execution_error,"controller_cgroup_drained":true,"product_slice_absent":true,"image_lease_absent":true,
        "model_requests":0,"execution_eligible":false,"guard_causality_verified":false,"status":"invalid-evidence",
        "qualification_unavailable_reason":unavailable_reason});
    if sdk_quiescent {
        report["sdk_agent_absent"] = json!(true);
        report["sdk_profile_absent"] = json!(true);
    }
    let raw = canonicalize(report.to_string().as_bytes()).map_err(|e| e.to_string())?;
    journal
        .finish_under_lease(
            &lease,
            &request,
            source,
            deployment,
            generation,
            &started.sha256,
            &raw,
            process,
            exit_code,
            TerminalOutcome::InvalidEvidence,
            None,
        )
        .map_err(|e| e.to_string())?;
    journal
        .project_read_only(&request, source, Some(deployment), generation)
        .map_err(|e| e.to_string())
}

fn process_json(process: crate::ProcessIdentity) -> Value {
    json!({"pid":process.pid,"start_ticks":process.start_ticks})
}
