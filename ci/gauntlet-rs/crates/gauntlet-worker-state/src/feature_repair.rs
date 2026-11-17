//! Restart opening and exact owned-resource recovery. Neither operation
//! retries a consumed audit or signals a historical/reused PID.
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::feature_journal::{self, FeatureRecord};
use crate::RunReservationJournal;
use gauntlet_contracts::canonicalize;
use std::path::Path;
use std::time::{Duration, Instant};

fn reclaim(
    record: &FeatureRecord,
    still_owned: &impl Fn() -> Result<(), String>,
) -> Result<(), String> {
    let intent = &record.intent;
    let p = intent.pins();
    for (path, pin) in [
        ("/usr/bin/podman", "podman_sha256"),
        ("/usr/sbin/apparmor_parser", "apparmor_parser_sha256"),
    ] {
        crate::builder_candidate_preflight::verify_file(path, p.text(pin), true, 64 * 1024 * 1024)
            .map_err(|e| e.to_string())?;
    }
    let slot = crate::feature_state::slot(p.audit_id())?;
    let mut group =
        crate::builder_cgroup::OwnedCandidateCgroup::reopen_feature(slot.as_ref(), intent)?;
    let mut container = crate::feature_container::FeatureContainer::restore(intent, slot.as_ref())?;
    if record
        .running
        .as_ref()
        .is_some_and(|v| v["container_id"].as_str() != container.id())
    {
        return Err("feature running and retained CID differ before recovery".into());
    }
    let profile = format!("hol-gauntlet-build-{}", p.audit_id());
    let policy = if crate::builder_policy::profile_absent(&profile).map_err(|e| e.to_string())? {
        None
    } else {
        let slot = slot
            .as_ref()
            .ok_or("active feature profile lacks private policy slot")?;
        let raw =
            crate::feature_files::required(slot, "Builder.apparmor", (0, 0), 0o600, 1024 * 1024)?;
        if crate::feature_capture::digest(&raw) != p.text("policy_sha256") {
            return Err("feature recovery policy differs from outside pin".into());
        }
        Some(format!(
            "{}/Builder.apparmor",
            crate::feature_container::job_root(p.audit_id())
        ))
    };
    still_owned()?;
    container.pin_repair_identity(slot.as_ref())?;
    if let Some(group) = &group {
        still_owned()?;
        group.kill().map_err(|e| e.to_string())?;
    }
    still_owned()?;
    container.drain()?;
    if let Some(group) = &mut group {
        still_owned()?;
        group.drain_and_remove().map_err(|e| e.to_string())?;
    }
    crate::feature_state::client_absent(p.audit_id())?;
    let start = Instant::now();
    while crate::feature_state::original_client_absent(record).is_err() {
        if start.elapsed() >= Duration::from_secs(3) {
            return Err("original feature client absence remains uncertain".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    // Keep confinement loaded until exact container and client cleanup succeeds.
    if let Some(policy) = policy {
        still_owned()?;
        crate::builder_policy::run_parser("--remove", &policy).map_err(|e| e.to_string())?;
    }
    crate::feature_container::completed_absent(intent, container.id())
}

fn record(audit: &str, expected: &str) -> Result<FeatureRecord, String> {
    if !crate::hex(audit, 16) || !crate::hex(expected, 64) {
        return Err("outside feature job and complete intent digest required".into());
    }
    let journal = crate::feature_state::journal()?;
    let r = feature_journal::inventory(&journal.root, (0, 0))?
        .remove(audit)
        .ok_or("feature reservation missing")?;
    if r.intent.digest() != Ok(expected.to_owned()) {
        return Err("outside feature intent differs".into());
    }
    Ok(r)
}
pub fn read_native_feature_result(
    audit: &str,
    expected: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let main =
        RunReservationJournal::open_root_owned(Path::new(RUST_STATE)).map_err(|e| e.to_string())?;
    let lease = main.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = python_worker_lock().map_err(|e| e.to_string())?;
    let r = record(audit, expected)?;
    let v = match (&r.result, &r.repair) {
        (Some(v), None) => {
            crate::feature_state::verify_result(&r, v)?;
            v
        }
        (None, Some(v)) => {
            crate::feature_state::verify_repair(&r, v)?;
            v
        }
        _ => {
            return Err(
                "feature audit is active, partial or unknown; reconcile without retry".into(),
            )
        }
    };
    let bytes = canonicalize(v.to_string().as_bytes()).map_err(|e| e.to_string())?;
    lease.verify(&main.root).map_err(|e| e.to_string())?;
    verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    Ok(bytes)
}
pub fn repair_native_features(
    audit: &str,
    expected: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let main =
        RunReservationJournal::open_root_owned(Path::new(RUST_STATE)).map_err(|e| e.to_string())?;
    let lease = main.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = python_worker_lock().map_err(|e| e.to_string())?;
    let journal = crate::feature_state::journal()?;
    let feature_lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let r = record(audit, expected)?;
    let still_owned = || {
        lease.verify(&main.root).map_err(|e| e.to_string())?;
        feature_lease
            .verify(&journal.root)
            .map_err(|e| e.to_string())?;
        verify_python_lock(&legacy).map_err(|e| e.to_string())?;
        crate::verify_running_binary(generation).map_err(|e| e.to_string())
    };
    if r.result.is_some() {
        return Err("completed feature result is immutable; use read".into());
    }
    if let Some(value) = &r.repair {
        crate::feature_state::verify_repair(&r, value)?;
        still_owned()?;
        return canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string());
    }
    still_owned()?;
    reclaim(&r, &still_owned)?;
    let body = crate::feature_state::repair_body(&r, generation)?;
    still_owned()?;
    let raw = feature_journal::write(&journal.root, audit, "repair.json", &body, (0, 0))?;
    let observed = record(audit, expected)?;
    let v = observed
        .repair
        .as_ref()
        .ok_or("feature repair commit missing")?;
    crate::feature_state::verify_repair(&observed, v)?;
    if canonicalize(v.to_string().as_bytes()).map_err(|e| e.to_string())? != raw {
        return Err("feature recovery changed after commit".into());
    }
    still_owned()?;
    Ok(raw)
}
