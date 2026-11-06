//! Native apparatus dispatcher. It always retains an invalid-evidence terminal;
//! Guard control scoring and authenticated host admission are separate exits.
use crate::builder_image_context::{python_worker_lock, verify_python_lock};
use crate::native_controller_exec::NativeChild;
use crate::native_job_io::{load, own_identity, require_no_unknown_jobs};
use crate::native_job_spec::{NativeJobExecution, ACTIVE_SECONDS};
use crate::native_prelaunch::{reserve_native, NativeHostAck};
use crate::{BoottimeDeadline, OwnedJobCgroup, RunReservationJournal, TerminalOutcome};
use gauntlet_contracts::{canonicalize, WorkerAction, WorkerRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
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

pub fn dispatch_native_worker(
    source: &str,
    deployment: &str,
    generation: &str,
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    dispatch_native_worker_inner(source, deployment, generation, raw, None)
}

pub fn dispatch_native_worker_host_pinned(
    source: &str,
    deployment: &str,
    generation: &str,
    raw: &[u8],
    mut acknowledge: impl FnMut(&[u8], &BoottimeDeadline, &AtomicBool) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    dispatch_native_worker_inner(source, deployment, generation, raw, Some(&mut acknowledge))
}

pub fn dispatch_native_worker_host_pinned_pipe(
    source: &str,
    deployment: &str,
    generation: &str,
    input: &impl std::os::fd::AsRawFd,
    output: &impl std::os::fd::AsRawFd,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let request = crate::read_run_request_pipe(
        input,
        &BoottimeDeadline::start(60).map_err(|e| e.to_string())?,
        &CANCELLED,
    )
    .map_err(|e| e.to_string())?;
    let raw = canonicalize(request.to_json().to_string().as_bytes()).map_err(|e| e.to_string())?;
    dispatch_native_worker_host_pinned(
        source,
        deployment,
        generation,
        &raw,
        |prepared, deadline, cancellation| {
            crate::exchange_prelaunch_pipe(prepared, output, input, deadline, cancellation)
                .map_err(|e| e.to_string())
        },
    )
}

fn dispatch_native_worker_inner(
    source: &str,
    deployment: &str,
    generation: &str,
    raw: &[u8],
    acknowledge: Option<&mut NativeHostAck<'_>>,
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
        if acknowledge.is_some() {
            return Err("host-pinned execution pipe requires a run request".into());
        }
        return journal
            .project_read_only(&request, source, Some(deployment), generation)
            .map_err(|e| e.to_string());
    }
    if request.deployment_digest() != Some(deployment) {
        return Err("native deployment differs from outside pin".into());
    }
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    // A consumed identity cannot run again, irrespective of unrelated host
    // preflight cost or availability. Malformed/mismatched markers still fail
    // closed through the existing bounded journal reader.
    if journal
        .started(request.job_id(), source, deployment, generation)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err(crate::ReservationError::AlreadyStarted.to_string());
    }
    let python = python_worker_lock().map_err(|e| e.to_string())?;
    require_no_unknown_jobs(&journal)?;
    crate::dependency_state::require_idle()?;
    if CANCELLED.load(Ordering::Acquire) {
        return Err("native worker cancelled before admission".into());
    }
    let (spec, preparation) = load(&request, generation)?;
    gauntlet_cell_rootfs::require_image_lease_absent(
        &preparation.image_id,
        &preparation.podman_sha256,
    )?;
    crate::require_rust_job_slice_absent(&spec.job_id).map_err(|e| e.to_string())?;
    gauntlet_cell_rootfs::verify_preparation_host_helpers(&preparation)?;
    let deadline = BoottimeDeadline::start(ACTIVE_SECONDS).map_err(|e| e.to_string())?;
    let (started, signing) = reserve_native(
        &journal,
        &lease,
        &request,
        &spec,
        &deadline,
        &CANCELLED,
        acknowledge,
    )?;
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
            signing.as_ref().map(|s| s.descriptor()),
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
        if let Some(signing) = &signing {
            signing.recheck(&journal, &lease, &started)?;
        }
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
    let sdk_quiescent = matches!(
        spec.execution,
        NativeJobExecution::SdkTransport { .. }
            | NativeJobExecution::SdkMcpTransport { .. }
            | NativeJobExecution::DeterministicControl { .. }
            | NativeJobExecution::HostPinnedControl { .. }
    );
    if sdk_quiescent {
        crate::native_sdk_quiescence::require_sdk_quiescence(&spec, &preparation)?;
    }
    let mcp_quiescent = matches!(
        spec.execution,
        NativeJobExecution::McpTransport(_)
            | NativeJobExecution::SdkMcpTransport { .. }
            | NativeJobExecution::DeterministicControl { .. }
            | NativeJobExecution::HostPinnedControl { .. }
    );
    if mcp_quiescent {
        crate::native_mcp_quiescence::require_mcp_quiescence(&spec, &preparation)?;
    }
    let process =
        process.ok_or("native launch did not establish a running process; retain unknown job")?;
    let (stdout, stderr) = native.as_mut().ok_or("native child logs missing")?.logs()?;
    let parsed = canonicalize(&stdout)
        .ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
    let authenticated = signing.as_ref().map(|s| {
        s.authenticate(&stdout).and_then(|value| {
            if value.report()["controller_identity"] != process_json(process) {
                Err("signed native controller identity differs from held running process".into())
            } else {
                Ok(value)
            }
        })
    });
    let parsed = match &authenticated {
        Some(Ok(value)) => Some(value.report().clone()),
        Some(Err(_)) => None,
        None => parsed,
    };
    let (exit_code, interruption, execution_error) = match outcome {
        Ok((code, reason)) => (code, reason, None),
        Err(error) => (-1, None, Some(error)),
    };
    let report_schema = match spec.execution {
        NativeJobExecution::Apparatus(_) => "hol-gauntlet-native-worker-report.v1",
        NativeJobExecution::HookTransport(_) => "hol-gauntlet-native-worker-report.v2",
        NativeJobExecution::SdkTransport { .. } => "hol-gauntlet-native-worker-report.v3",
        NativeJobExecution::McpTransport(_) => "hol-gauntlet-native-worker-report.v4",
        NativeJobExecution::SdkMcpTransport { .. } => "hol-gauntlet-native-worker-report.v5",
        NativeJobExecution::DeterministicControl { .. } => "hol-gauntlet-native-worker-report.v6",
        NativeJobExecution::HostPinnedControl { .. } => "hol-gauntlet-native-worker-report.v7",
    };
    let unavailable_reason = match spec.execution {
        NativeJobExecution::Apparatus(_) => "native apparatus profile has no independently scored Guard controls or host signing-key pin",
        NativeJobExecution::HookTransport(_) => "native hook transport has no authenticated SDK calls, independently scored Guard controls or host signing-key pin",
        NativeJobExecution::SdkTransport { .. } => "native SDK Bash transport has no MCP, independently scored Guard controls, six-role conformance or host signing-key pin",
        NativeJobExecution::McpTransport(_) => "native MCP diagnostic has no actual SDK composition, combined builtin/MCP budget, independent Guard decision/effect scoring or outside signing-key admission",
        NativeJobExecution::SdkMcpTransport { .. } => "native SDK/MCP/Bash diagnostic has no independent Guard request/decision/effect scoring, six-role conformance or outside signing-key admission",
        NativeJobExecution::DeterministicControl {..}=>"Native deterministic role diagnostic has no qualified current-source suite or outside signing-key admission",
        NativeJobExecution::HostPinnedControl {..}=>"host-pinned controller signature has no independently scored effects or qualified current-source suite",
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
    if mcp_quiescent {
        report["mcp_agent_absent"] = json!(true);
        report["mcp_profile_absent"] = json!(true);
    }
    if let Some(signing) = &signing {
        signing.recheck(&journal, &lease, &started)?;
        report["prelaunch_custody"] = signing.observation()?;
        report["controller_envelope_utf8"] = std::str::from_utf8(&stdout)
            .ok()
            .map(|s| json!(s))
            .unwrap_or(Value::Null);
        report["controller_signature_verification"] = authenticated
            .as_ref()
            .and_then(|v| v.as_ref().ok())
            .map(|v| v.observation())
            .unwrap_or(Value::Null);
        report["controller_signature_error"] = authenticated
            .as_ref()
            .and_then(|v| v.as_ref().err())
            .map(|e| json!(e))
            .unwrap_or(Value::Null);
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
            signing.as_ref().map(|s| s.pin_sha256()),
        )
        .map_err(|e| e.to_string())?;
    if signing.is_some() {
        return crate::native_completion::read_completion(
            &journal,
            source,
            &spec.job_id,
            deployment,
            generation,
        );
    }
    journal
        .project_read_only(&request, source, Some(deployment), generation)
        .map_err(|e| e.to_string())
}

fn process_json(process: crate::ProcessIdentity) -> Value {
    json!({"pid":process.pid,"start_ticks":process.start_ticks})
}
