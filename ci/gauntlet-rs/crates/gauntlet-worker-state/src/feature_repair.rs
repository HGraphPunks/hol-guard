//! Read-only restart opening and quiescent aborted recovery. Neither operation
//! retries a consumed audit or signals a historical/reused PID.
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::feature_journal::{self, FeatureRecord};
use crate::RunReservationJournal;
use gauntlet_contracts::canonicalize;
use std::path::Path;

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
    if r.result.is_some() {
        return Err("completed feature result is immutable; use read".into());
    }
    if let Some(value) = &r.repair {
        crate::feature_state::verify_repair(&r, value)?;
        return canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string());
    }
    let body = crate::feature_state::repair_body(&r, generation)?;
    lease.verify(&main.root).map_err(|e| e.to_string())?;
    feature_lease
        .verify(&journal.root)
        .map_err(|e| e.to_string())?;
    verify_python_lock(&legacy).map_err(|e| e.to_string())?;
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
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    Ok(raw)
}
