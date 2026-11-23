//! One-use Root feature owner. Its complete reservation precedes all launch
//! mutations; only exact cleanup permits an ineligible diagnostic completion.
use crate::builder_candidate_process::{run_precreated_feature_process, CandidateProcessError};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::builder_policy::{profile_absent, profile_is_loaded, run_parser};
use crate::feature_files as files;
use crate::feature_journal;
use crate::{open_root_owned_public_directory, RunReservationJournal};
use gauntlet_contracts::{
    canonicalize, verify_feature_run_result, FeatureRunIntent, FEATURE_INTENT_LIMIT,
};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::os::fd::RawFd;
use std::path::Path;

pub fn receive_native_feature_intent(
    fd: RawFd,
    bytes: u64,
    expected: &str,
) -> Result<Vec<u8>, String> {
    if bytes == 0 || bytes > FEATURE_INTENT_LIMIT as u64 || !crate::hex(expected, 64) {
        return Err("bounded outside feature intent required".into());
    }
    let mut raw = Vec::new();
    let digest = crate::native_source_stream::copy_source(
        fd,
        &mut raw,
        bytes,
        &crate::BoottimeDeadline::start(30).map_err(|e| e.to_string())?,
        crate::native_worker::cancellation_requested,
    )?;
    if digest != expected {
        return Err("feature intent differs from outside byte hash".into());
    }
    FeatureRunIntent::parse(&raw)?;
    Ok(raw)
}
fn bounded_error(error: &str) -> String {
    let mut result = String::new();
    for c in error.chars() {
        if result.len() + c.len_utf8() > 1024 {
            break;
        }
        result.push(c);
    }
    result
}
pub fn run_native_features(
    raw: &[u8],
    expected: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let intent = FeatureRunIntent::parse(raw)?;
    let p = intent.pins();
    let id = p.audit_id();
    let digest = intent.digest()?;
    if digest != expected || p.text("runner_binary_sha256") != generation {
        return Err("feature executable or outside intent differs".into());
    }
    let main =
        RunReservationJournal::open_root_owned(Path::new(RUST_STATE)).map_err(|e| e.to_string())?;
    let lease = main.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = python_worker_lock().map_err(|e| e.to_string())?;
    crate::native_job_io::require_no_unknown_jobs(&main)?;
    crate::dependency_state::require_idle()?;
    let context = crate::feature_preflight::verify(&intent)?;
    let profile = format!("hol-gauntlet-build-{id}");
    if !profile_absent(&profile).map_err(|e| e.to_string())?
        || !crate::builder_candidate_process::container_absent(id).map_err(|e| e.to_string())?
        || crate::feature_state::slot(id)?.is_some()
    {
        return Err("feature audit resources or one-use slot already exist".into());
    }
    crate::feature_state::client_absent(id)?;
    if crate::builder_image_build::free_bytes().map_err(|e| e.to_string())?
        < 12 * 1024 * 1024 * 1024
    {
        return Err("feature audit lacks fixed disk reserve".into());
    }
    let journal = crate::feature_state::journal()?;
    let feature_lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let still_owned = || {
        if crate::native_worker::cancellation_requested() {
            return Err(CandidateProcessError::TimedOut);
        }
        lease
            .verify(&main.root)
            .map_err(|_| CandidateProcessError::LeaseUnavailable)?;
        feature_lease
            .verify(&journal.root)
            .map_err(|_| CandidateProcessError::LeaseUnavailable)?;
        verify_python_lock(&legacy).map_err(|_| CandidateProcessError::LeaseUnavailable)
    };
    still_owned().map_err(|e| e.to_string())?;
    // This complete, canonical intent is itself the atomic one-use reservation.
    // A failed/partial commit is retained and blocks all subsequent admission.
    feature_journal::write(
        &journal.root,
        id,
        "intent.json",
        &serde_json::from_slice::<Value>(raw).map_err(|e| e.to_string())?,
        (0, 0),
    )?;
    let jobs = open_root_owned_public_directory(Path::new(crate::feature_state::JOBS))
        .map_err(|e| e.to_string())?;
    let slot = files::directory(&jobs, id, (0, 0), true)?;
    files::write(
        &slot,
        "feature-spec.json",
        p.spec().canonical_bytes(),
        (0, 0),
        0o444,
    )?;
    files::write(
        &slot,
        "Builder.apparmor",
        context.policy_bytes(),
        (0, 0),
        0o600,
    )?;
    crate::builder_candidate_source::prepare_export(&slot).map_err(|e| e.to_string())?;
    let policy = format!(
        "{}/Builder.apparmor",
        crate::feature_container::job_root(id)
    );
    still_owned().map_err(|e| e.to_string())?;
    let loaded = run_parser("--replace", &policy);
    if loaded.is_err() || profile_is_loaded(&profile) != Ok(true) {
        let _ = run_parser("--remove", &policy);
        return Err("feature policy load failed; reconcile reserved audit".into());
    }
    let container = RefCell::new(crate::feature_container::FeatureContainer::new(&intent));
    let execution = (|| {
        still_owned().map_err(|e| e.to_string())?;
        let plan = container.borrow_mut().create(&slot)?;
        let cid = container
            .borrow()
            .id()
            .ok_or("feature CID not retained")?
            .to_owned();
        run_precreated_feature_process(&plan,&slot,&intent,&still_owned,
            &||container.borrow_mut().drain().map_err(|_|CandidateProcessError::CleanupUncertain),
            &|process,group| {
                let running=json!({"schema":"hol-gauntlet-native-feature-running.v1","audit_id":id,
                    "intent_sha256":digest,"worker_generation":generation,"container_id":cid,
                    "client_pid":process.pid,"client_start_ticks":process.start_ticks,"client_cgroup":group});
                feature_journal::validate_running(&intent,&running).map_err(|_|CandidateProcessError::ProcessMismatch)?;
                feature_journal::write(&journal.root,id,"running.json",&running,(0,0))
                    .map(|_|()).map_err(|_|CandidateProcessError::ProcessMismatch)
            }).map_err(|e|e.to_string())
    })();
    // Never remove confinement if the exact container or client drain is uncertain.
    container.borrow_mut().drain()?;
    crate::feature_state::client_absent(id)?;
    run_parser("--remove", &policy).map_err(|e| e.to_string())?;
    if !profile_absent(&profile).map_err(|e| e.to_string())? {
        return Err("feature profile cleanup uncertain".into());
    }
    let observed = execution.map_err(|e| {
        format!("feature execution interrupted; reconcile retained reservation: {e}")
    })?;
    let cid = container
        .borrow()
        .id()
        .ok_or("feature create identity uncertain")?
        .to_owned();
    crate::feature_container::completed_absent(&intent, Some(&cid))?;
    lease.verify(&main.root).map_err(|e| e.to_string())?;
    feature_lease
        .verify(&journal.root)
        .map_err(|e| e.to_string())?;
    verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    crate::feature_preflight::verify(&intent)?;
    if crate::builder_image_build::free_bytes().map_err(|e| e.to_string())? < 8 * 1024 * 1024 * 1024
    {
        return Err("feature completion disk reserve crossed".into());
    }
    let captured = crate::feature_capture::capture(&slot, &intent, &observed);
    let readback = captured.as_ref().ok();
    let checked = readback
        .map(|v| canonicalize(v.to_string().as_bytes()))
        .transpose()
        .map_err(|e| e.to_string())?;
    let result = json!({"schema":"hol-gauntlet-native-feature-result.v1","audit_id":id,
        "source_sha":p.spec().text("source_sha"),"intent_sha256":digest,"worker_generation":generation,
        "container_id":cid,"client_pid":observed.client_pid,"client_start_ticks":observed.client_start_ticks,
        "exit_code":observed.exit_code,"execution_error":captured.as_ref().err().map(|e|bounded_error(e)),
        "audit_status":readback.map(|v|v["status"].clone()).unwrap_or(json!("invalid-evidence")),
        "feature_report_sha256":readback.map(|v|v["report_sha256"].clone()),
        "feature_readback_sha256":checked.as_ref().map(|v|crate::feature_capture::digest(v)),
        "stdout_sha256":observed.stdout_sha256,"stderr_sha256":observed.stderr_sha256,
        "feature_artifacts_verified":readback.is_some(),"container_absent":true,"container_cgroup_absent":true,
        "client_cgroup_drained":true,"build_profile_removed":true,"status":"invalid-evidence",
        "rust_root_supervised":true,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0,"model_tokens":0});
    verify_feature_run_result(&intent, &result)?;
    let bytes = feature_journal::write(&journal.root, id, "result.json", &result, (0, 0))?;
    crate::feature_state::require_idle()?;
    Ok(bytes)
}
