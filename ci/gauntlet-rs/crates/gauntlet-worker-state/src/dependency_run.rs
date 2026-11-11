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
use crate::builder_policy::{
    profile_absent, profile_is_loaded, read_policy, run_parser, run_parser_owned,
};
use crate::dependency_podman::DependencyContainer;
use crate::dependency_state::STATE;
use crate::{
    open_root_owned_public_directory, read_bounded_regular, RunReservationJournal, TerminalOutcome,
};
use gauntlet_contracts::{canonicalize, DependencyRunIntent, WorkerRequest};
use rustix::fs::{statat, AtFlags, Dir};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
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
    match statat(
        &journal.root,
        format!("{job}.dependency-repair.json"),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(rustix::io::Errno::NOENT) => {}
        _ => return Err("dependency job is consumed by recovery; never rerun it".into()),
    }
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
    let mut group = crate::dependency_io::prepare_creators(&slot, &intent, &started.sha256)?;
    let loaded = run_parser_owned("--replace", &policy, &group);
    if loaded.is_err() || profile_is_loaded(&profile) != Ok(true) {
        group.kill().map_err(|e| e.to_string())?;
        group.drain_and_remove().map_err(|e| e.to_string())?;
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
        let plan = match container.create(&group) {
            Ok(plan) => plan,
            Err(error) => {
                group.kill().map_err(|e| e.to_string())?;
                group.drain_and_remove().map_err(|e| e.to_string())?;
                return Err(error);
            }
        };
        run_precreated_dependency_process(
            &plan,
            &slot,
            &digest,
            group,
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

pub(crate) fn require_idle() -> Result<(), String> {
    let _namespace_scope = crate::native_job_storage::owner::scope()?;
    crate::feature_state::require_idle()?;
    let base = open_root_owned_public_directory(Path::new("/var/lib/hol-gauntlet-rust"))
        .map_err(|e| e.to_string())?;
    match statat(&base, "dependency-state", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    let mut jobs = BTreeSet::new();
    let mut starts = BTreeMap::new();
    let mut count = 0usize;
    for entry in Dir::read_from(&journal.root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "dependency state filename UTF-8")?;
        if matches!(name, "." | ".." | "active.lock") {
            continue;
        }
        count += 1;
        if count > 4096 {
            return Err("dependency state inventory bound exceeded".into());
        }
        let (job, suffix) = name
            .split_once('.')
            .filter(|(s, _)| crate::hex(s, 16))
            .ok_or("unrecognized dependency job")?;
        if !matches!(
            suffix,
            "started.json"
                | "running.json"
                | "report.json"
                | "terminal.json"
                | "dependency-repair.json"
        ) {
            return Err("unrecognized dependency sidecar".into());
        }
        jobs.insert(job.to_owned());
        if suffix == "started.json" {
            let raw = read_bounded_regular(&journal.root, name, 1024)
                .map_err(|e| e.to_string())?
                .ok_or("dependency start disappeared")?;
            starts.insert(job.to_owned(), raw);
        }
    }
    for job in jobs {
        if let Some(intent) = crate::dependency_preparation::intent_from_receipt(&journal, &job)? {
            crate::dependency_preparation::verified(&journal, &intent)?
                .ok_or("preparation retirement unavailable")?;
            continue;
        }
        let raw = starts
            .get(&job)
            .ok_or("orphan dependency sidecar blocks execution")?;
        if canonicalize(raw).map_err(|e| e.to_string())? != *raw {
            return Err("ambiguous dependency start".into());
        }
        let start: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        let digest = start["deployment_digest"]
            .as_str()
            .ok_or("dependency start lacks intent")?;
        let intent = crate::dependency_repair::intent_for_job(&job, digest)?;
        let p = &intent.pins;
        journal
            .started(
                &job,
                p.text("source_sha"),
                digest,
                p.text("runner_binary_sha256"),
            )
            .map_err(|e| e.to_string())?
            .ok_or("dependency start differs")?;
        if crate::dependency_completion::verified(&journal, &intent)?.is_some() {
            continue;
        }
        let terminal = journal
            .terminal(
                &job,
                p.text("source_sha"),
                digest,
                p.text("runner_binary_sha256"),
            )
            .map_err(|e| e.to_string())?;
        let repair = crate::dependency_repair::verified(&journal, &intent)?;
        if terminal.is_some() == repair.is_some() {
            return Err("active, ambiguous or unknown dependency job blocks execution".into());
        }
        if let Some(terminal) = terminal {
            if terminal.status != TerminalOutcome::InvalidEvidence {
                return Err("dependency terminal claims execution authority".into());
            }
            let raw = read_bounded_regular(&journal.root, &format!("{job}.report.json"), 16384)
                .map_err(|e| e.to_string())?
                .ok_or("dependency report missing")?;
            let report: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            let reported = DependencyRunIntent::parse(
                &canonicalize(report["intent"].to_string().as_bytes())
                    .map_err(|e| e.to_string())?,
            )?;
            if reported != intent
                || report["schema"] != "hol-gauntlet-native-dependency-result.v1"
                || report["intent_sha256"] != digest
                || report["container_absent"] != true
                || report["container_cgroup_absent"] != true
                || report["client_cgroup_drained"] != true
                || report["build_profile_removed"] != true
                || report["artifact_admitted"] != false
                || report["execution_eligible"] != false
                || report["guard_causality_verified"] != false
                || report["model_requests"] != 0
            {
                return Err("dependency report differs from retained intent or cleanup".into());
            }
            crate::dependency_podman::verify_completed_absent(
                &intent,
                report["container_id"]
                    .as_str()
                    .ok_or("dependency CID missing")?,
            )?;
        }
    }
    Ok(())
}
