//! Current-source dependency/candidate composition. Historical prefix paths
//! and the shadow-v1 result remain available through their original entrypoint.
use crate::candidate_prefix_clone::{
    clone_prefix, CandidatePrefixClonePins, CandidatePrefixCloneProof,
};
use crate::RunReservationJournal;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct NativeCandidatePrefixPins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub source_archive_sha256: &'a str,
    pub archive_sha256: &'a str,
    pub version: &'a str,
    pub dependency_job_id: &'a str,
    pub dependency_prefix_receipt_sha256: &'a str,
    pub dependency_prefix_tree_sha256: &'a str,
    pub stage_tree_sha256: &'a str,
    pub generation: &'a str,
}

pub(crate) fn verify(
    pins: &NativeCandidatePrefixPins<'_>,
    baseline: &Path,
    journal: &RunReservationJournal,
) -> Result<(), String> {
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    crate::native_job_io::require_no_unknown_jobs(journal)?;
    crate::dependency_state::require_idle()?;
    let (path, digest) = crate::dependency_prefix::verify_published_dependency_prefix(
        pins.dependency_job_id,
        pins.dependency_prefix_receipt_sha256,
        pins.source_sha,
    )?;
    if path != baseline || digest != pins.dependency_prefix_tree_sha256 {
        return Err("native dependency baseline differs from outside tree pin".into());
    }
    if crate::native_worker::cancellation_requested() {
        return Err("native candidate prefix cancelled; preserve consumed data".into());
    }
    if crate::builder_image_build::free_bytes().map_err(|e| e.to_string())? < 8 * 1024 * 1024 * 1024
    {
        return Err("native prefix crossed disk reserve; preserve consumed data".into());
    }
    Ok(())
}

pub(crate) fn value(
    proof: &CandidatePrefixCloneProof,
    pins: &NativeCandidatePrefixPins<'_>,
) -> Value {
    let mut v = proof.to_json();
    v["schema"] = "hol-gauntlet-native-candidate-prefix.v1".into();
    v["source_archive_sha256"] = pins.source_archive_sha256.into();
    v["version"] = pins.version.into();
    v["dependency_job_id"] = pins.dependency_job_id.into();
    v["dependency_prefix_receipt_sha256"] = pins.dependency_prefix_receipt_sha256.into();
    v["clone_generation"] = pins.generation.into();
    v["console_scripts"] = crate::native_candidate_launchers::ENTRIES.len().into();
    v["guard_causality_verified"] = false.into();
    v["model_requests"] = 0.into();
    v
}

pub fn clone_native_candidate_prefix(
    pins: &NativeCandidatePrefixPins<'_>,
) -> Result<Value, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    if crate::builder_image_build::free_bytes().map_err(|e| e.to_string())?
        < 12 * 1024 * 1024 * 1024
    {
        return Err("native prefix staging lacks disk reserve".into());
    }
    if !crate::hex(pins.dependency_job_id, 16)
        || pins.dependency_job_id == pins.job_id
        || !crate::hex(pins.dependency_prefix_receipt_sha256, 64)
        || !crate::hex(pins.dependency_prefix_tree_sha256, 64)
    {
        return Err("separate source-bound dependency prefix pins required".into());
    }
    let baseline = Path::new("/var/lib/hol-gauntlet/builds")
        .join(pins.dependency_job_id)
        .join("dependency-prefix");
    let common = CandidatePrefixClonePins {
        job_id: pins.job_id,
        source_sha: pins.source_sha,
        source_archive_sha256: pins.source_archive_sha256,
        archive_sha256: pins.archive_sha256,
        version: pins.version,
        baseline_path: &baseline,
        baseline_tree_sha256: pins.dependency_prefix_tree_sha256,
        stage_tree_sha256: pins.stage_tree_sha256,
    };
    let proof = clone_prefix(&common, Some(pins)).map_err(|e| e.to_string())?;
    let mut result = value(&proof, pins);
    let raw = gauntlet_contracts::canonicalize(result.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    result["receipt_sha256"] = format!("{:x}", Sha256::digest(&raw)).into();
    Ok(result)
}
