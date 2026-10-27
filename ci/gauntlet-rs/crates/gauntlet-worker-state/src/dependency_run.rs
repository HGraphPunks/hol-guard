//! Native Root ownership of one fixed unprivileged dependency preparation.
//! Its terminal is always invalid-evidence and supplies no Guard authority.
use crate::builder_candidate_preflight::{verify_candidate_runtime, CandidateRuntimePins};
use crate::builder_candidate_process::{run_precreated_dependency_process, CandidateProcessError};
use crate::builder_context::inspect_fixed_builder_context;
use crate::builder_image::{fixed_builder_image_plan, inspect_fixed_builder_base_images};
use crate::builder_image_build::{free_bytes, inspect_result};
use crate::builder_image_context::{
    python_worker_lock, verify_existing_context, verify_python_lock, RUST_STATE,
};
use crate::builder_policy::{profile_absent, profile_is_loaded, read_policy, run_parser};
use crate::dependency_podman::DependencyContainer;
use crate::{RunReservationJournal, TerminalOutcome};
use gauntlet_contracts::{canonicalize, DependencyRunIntent, WorkerRequest};
use serde_json::{json, Value};
use std::path::Path;

pub fn receive_native_dependency_intent(
    fd: std::os::fd::RawFd,
    raw: &mut Vec<u8>,
    bytes: u64,
    digest: &str,
) -> Result<(), String> {
    if bytes == 0
        || bytes > gauntlet_contracts::DEPENDENCY_INTENT_LIMIT as u64
        || !crate::hex(digest, 64)
    {
        return Err("bounded dependency intent hash/bytes required".into());
    }
    let observed = crate::native_source_stream::copy_source(
        fd,
        raw,
        bytes,
        &crate::BoottimeDeadline::start(30).map_err(|e| e.to_string())?,
        crate::native_worker::cancellation_requested,
    )?;
    if observed != digest {
        return Err("dependency intent differs from outside hash".into());
    }
    Ok(())
}

fn preflight(intent: &DependencyRunIntent) -> Result<(), String> {
    let p = &intent.pins;
    let context = inspect_fixed_builder_context(
        Path::new(p.text("controller_root")),
        p.text("controller_tree_sha256"),
        p.text("job_id"),
    )
    .map_err(|e| e.to_string())?;
    if context.policy_sha256() != p.text("policy_sha256") {
        return Err("dependency policy differs from host intent".into());
    }
    let plan = fixed_builder_image_plan(
        &context,
        p.text("job_id"),
        p.text("uv_base_image_id"),
        p.text("rust_base_image_id"),
    )
    .map_err(|e| e.to_string())?;
    inspect_fixed_builder_base_images(&plan).map_err(|e| e.to_string())?;
    verify_existing_context(&plan).map_err(|e| e.to_string())?;
    if inspect_result(&plan).map_err(|e| e.to_string())? != p.text("builder_image_id") {
        return Err("dependency builder image differs".into());
    }
    read_policy(p.text("job_id"), p.text("policy_sha256")).map_err(|e| e.to_string())?;
    let runtime = CandidateRuntimePins::parse(
        p.text("podman_sha256"),
        p.text("slirp4netns_sha256"),
        p.text("apparmor_parser_sha256"),
        p.text("seccomp_sha256"),
    )
    .map_err(|e| e.to_string())?;
    verify_candidate_runtime(&runtime).map_err(|e| e.to_string())?;
    let slot = crate::builder_candidate_source::open_fixed_build_slot(p.text("job_id"))
        .map_err(|e| e.to_string())?;
    crate::dependency_io::verify_inputs(&slot, intent)
}

pub fn run_native_dependencies(
    raw: &[u8],
    expected_intent: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let intent = DependencyRunIntent::parse(raw)?;
    let digest = intent.digest()?;
    let p = &intent.pins;
    let job = p.text("job_id");
    if digest != expected_intent || generation != p.text("runner_binary_sha256") {
        return Err("dependency executable or host intent differs".into());
    }
    let main =
        RunReservationJournal::open_root_owned(Path::new(RUST_STATE)).map_err(|e| e.to_string())?;
    let lease = main.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = python_worker_lock().map_err(|e| e.to_string())?;
    crate::native_job_io::require_no_unknown_jobs(&main)?;
    crate::dependency_state::require_idle()?;
    preflight(&intent)?;
    let profile = format!("hol-gauntlet-build-{job}");
    if !profile_absent(&profile).map_err(|e| e.to_string())? {
        return Err("dependency profile already exists".into());
    }
    if !crate::builder_candidate_process::container_absent(job).map_err(|e| e.to_string())? {
        return Err("dependency container already exists".into());
    }
    crate::dependency_state::client_group_absent(job)?;
    if free_bytes().map_err(|e| e.to_string())? < 12 * 1024 * 1024 * 1024 {
        return Err("dependency job lacks fixed disk reserve".into());
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(crate::dependency_state::STATE))
        .map_err(|e| e.to_string())?;
    let job_lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let request = WorkerRequest::parse(
        json!({"schema":"hol-gauntlet-worker-request.v1","action":"run","job_id":job,
        "source_sha":p.text("source_sha"),"deployment_digest":digest})
        .to_string()
        .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let started = journal
        .reserve_under_lease(
            &job_lease,
            &request,
            p.text("source_sha"),
            &digest,
            generation,
        )
        .map_err(|e| e.to_string())?;
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    crate::builder_candidate_receipt::write_root_canonical_job_file(
        &slot,
        "dependency-intent.v1.json",
        &serde_json::from_slice::<Value>(raw).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    crate::builder_candidate_source::prepare_export(&slot).map_err(|e| e.to_string())?;
    let policy = format!("/var/lib/hol-gauntlet/builds/{job}/Builder.apparmor");
    if crate::native_worker::cancellation_requested() {
        return Err("dependency job cancelled after reservation; reconcile retained state".into());
    }
    let loaded = run_parser("--replace", &policy);
    if loaded.is_err() || profile_is_loaded(&profile) != Ok(true) {
        let _ = run_parser("--remove", &policy);
        return Err("dependency policy load failed; reconcile reserved job".into());
    }
    let still_owned = || {
        if crate::native_worker::cancellation_requested() {
            return Err(CandidateProcessError::TimedOut);
        }
        lease
            .verify(&main.root)
            .map_err(|_| CandidateProcessError::LeaseUnavailable)?;
        job_lease
            .verify(&journal.root)
            .map_err(|_| CandidateProcessError::LeaseUnavailable)?;
        verify_python_lock(&legacy).map_err(|_| CandidateProcessError::LeaseUnavailable)
    };
    let mut container = DependencyContainer::new(&intent);
    let execution = (|| {
        let plan = container.create()?;
        run_precreated_dependency_process(
            &plan,
            &slot,
            &still_owned,
            &|| {
                container
                    .drain()
                    .map_err(|_| CandidateProcessError::CleanupUncertain)
            },
            &|process, group| {
                journal
                    .mark_running_under_lease(
                        &job_lease,
                        &request,
                        p.text("source_sha"),
                        &digest,
                        generation,
                        &started.sha256,
                        process,
                        group,
                    )
                    .map(|_| ())
                    .map_err(|_| CandidateProcessError::ProcessMismatch)
            },
        )
        .map_err(|e| e.to_string())
    })();
    // Keep the enforced policy if exact-container teardown cannot be proved.
    container.drain()?;
    crate::dependency_state::client_group_absent(job)?;
    run_parser("--remove", &policy).map_err(|e| e.to_string())?;
    if !profile_absent(&profile).map_err(|e| e.to_string())? {
        return Err("dependency profile cleanup uncertain".into());
    }
    let cid = container
        .id()
        .ok_or("dependency create identity uncertain; reconcile reserved job")?;
    // Cancellation may have caused a known failed attempt. Recheck ownership
    // without turning that failure into another execution or an unknown pass.
    lease.verify(&main.root).map_err(|e| e.to_string())?;
    job_lease.verify(&journal.root).map_err(|e| e.to_string())?;
    verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    preflight(&intent)?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    if free_bytes().map_err(|e| e.to_string())? < 8 * 1024 * 1024 * 1024 {
        return Err("dependency completion disk reserve crossed".into());
    }
    let exit = execution.as_ref().map(|r| r.exit_code).unwrap_or(2);
    let output = if exit == 0 {
        Some(crate::dependency_io::capture_output(&slot)?)
    } else {
        None
    };
    let running = journal
        .running_marker(job, p.text("source_sha"), &digest, generation)
        .map_err(|e| e.to_string())?
        .ok_or("dependency client lacks retained running identity")?;
    let process = running.process;
    let report = json!({"schema":"hol-gauntlet-native-dependency-result.v1","job_id":job,"source_sha":p.text("source_sha"),
        "intent_sha256":digest,"intent":serde_json::from_slice::<Value>(raw).map_err(|e| e.to_string())?,"worker_generation":generation,
        "started_marker_sha256":started.sha256,"container_id":cid,"exit_code":exit,"execution_error":execution.as_ref().err(),
        "client_pid":execution.as_ref().ok().map(|r| r.client_pid),"client_start_ticks":execution.as_ref().ok().map(|r| r.client_start_ticks),
        "stdout_sha256":execution.as_ref().ok().map(|r| &r.stdout_sha256),"stderr_sha256":execution.as_ref().ok().map(|r| &r.stderr_sha256),
        "captured_dependencies_bytes":output.as_ref().map(|(n,_)| n),"captured_dependencies_sha256":output.as_ref().map(|(_,s)| s),
        "container_absent":true,"container_cgroup_absent":true,"client_cgroup_drained":true,"build_profile_removed":true,
        "status":"invalid-evidence","artifact_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    let bytes = canonicalize(report.to_string().as_bytes()).map_err(|e| e.to_string())?;
    journal
        .finish_under_lease(
            &job_lease,
            &request,
            p.text("source_sha"),
            &digest,
            generation,
            &started.sha256,
            &bytes,
            process,
            exit,
            TerminalOutcome::InvalidEvidence,
            None,
        )
        .map_err(|e| e.to_string())?;
    crate::dependency_state::require_idle()?;
    Ok(bytes)
}
