//! Recheck the retained source, candidate and separate dependency custody.
//! The publication owner holds both worker leases while calling `verify`.
use crate::native_runtime_receipt::NativeRuntimePins;
use crate::RunReservationJournal;
use gauntlet_evidence::{
    inventory_tree, verify_installed_version_metadata, TreeInventory, TreeKind,
};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub(crate) fn prefix(pins: &NativeRuntimePins<'_>) -> PathBuf {
    Path::new("/var/lib/hol-gauntlet/builds")
        .join(pins.job_id)
        .join("inert-prefix")
}

pub(crate) fn read(pins: &NativeRuntimePins<'_>) -> Result<Value, String> {
    let job = crate::builder_candidate_source::open_fixed_build_slot(pins.job_id)
        .map_err(|e| e.to_string())?;
    let raw = crate::dependency_io::read(&job, "native-candidate-prefix.v1.json", 0, 0o600, 8192)?;
    crate::native_runtime_receipt::parse(&raw, pins)
}

pub(crate) fn verify(
    pins: &NativeRuntimePins<'_>,
    expected: &Value,
    journal: &RunReservationJournal,
) -> Result<TreeInventory, String> {
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    crate::native_job_io::require_no_unknown_jobs(journal)?;
    crate::dependency_state::require_idle()?;
    if read(pins)? != *expected {
        return Err("native clone receipt changed".into());
    }
    let text = |key: &str| expected[key].as_str().ok_or("native clone text missing");
    let slot = crate::builder_candidate_source::open_fixed_build_slot(pins.job_id)
        .map_err(|e| e.to_string())?;
    let bytes = crate::builder_candidate_source::verify_captured_source(
        &slot,
        text("source_archive_sha256")?,
    )
    .map_err(|e| e.to_string())?;
    let source = crate::dependency_io::read(&slot, "source-capture.v1.json", 0, 0o600, 8192)?;
    if gauntlet_contracts::canonicalize(&source).map_err(|e| e.to_string())? != source {
        return Err("native source receipt is not canonical".into());
    }
    let source: Value = serde_json::from_slice(&source).map_err(|e| e.to_string())?;
    if source.as_object().is_none_or(|v| v.len() != 9)
        || source["schema"] != "hol-gauntlet-native-source-capture.v1"
        || source["job_id"] != pins.job_id
        || source["source_sha"] != pins.source_sha
        || source["source_archive_sha256"] != text("source_archive_sha256")?
        || source["source_bytes"] != bytes
        || source["builder_executed"] != false
        || source["execution_eligible"] != false
        || source["model_requests"] != 0
        || !source["worker_generation"]
            .as_str()
            .is_some_and(|s| crate::hex(s, 64))
    {
        return Err("native runtime source receipt differs".into());
    }
    crate::candidate_capture::inactive(pins.job_id).map_err(|e| e.to_string())?;
    let archive = crate::dependency_io::read(&slot, "candidate.zip", 0, 0o444, 256 * 1024 * 1024)?;
    crate::candidate_capture::verify_captured(
        &slot,
        text("archive_sha256")?,
        archive.len() as u64,
        pins.source_sha,
        pins.version,
    )
    .map_err(|e| e.to_string())?;
    let (_, dependency_tree) = crate::dependency_prefix::verify_published_dependency_prefix(
        text("dependency_job_id")?,
        text("dependency_prefix_receipt_sha256")?,
        pins.source_sha,
    )?;
    if dependency_tree != text("baseline_tree_sha256")? {
        return Err("runtime dependency tree differs".into());
    }
    let path = prefix(pins);
    let tree = inventory_tree(&path, TreeKind::InstalledPrefix).map_err(|e| e.to_string())?;
    if tree.digest != pins.prefix_tree_sha256
        || expected["prefix_entries"] != tree.entries
        || expected["prefix_bytes"] != tree.bytes
    {
        return Err("native runtime prefix differs from outside receipt".into());
    }
    verify_installed_version_metadata(&path, pins.version, pins.source_sha, pins.native_sha256)
        .map_err(|e| e.to_string())?;
    if crate::native_worker::cancellation_requested() {
        return Err("runtime publication cancelled; retain consumed data".into());
    }
    Ok(tree)
}
