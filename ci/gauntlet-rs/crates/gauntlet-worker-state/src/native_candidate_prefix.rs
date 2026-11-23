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
    let _namespace_scope = crate::native_job_storage::owner::scope()?;
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

fn completed(raw: &[u8], pins: &NativeCandidatePrefixPins<'_>) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let tree = v["prefix_tree_sha256"]
        .as_str()
        .ok_or("completed clone tree pin absent")?;
    let digest = format!("{:x}", Sha256::digest(raw));
    let v = crate::native_runtime_receipt::parse_clone(
        raw,
        pins.job_id,
        pins.source_sha,
        pins.version,
        &digest,
        tree,
    )?;
    if v["source_archive_sha256"] != pins.source_archive_sha256
        || v["archive_sha256"] != pins.archive_sha256
        || v["dependency_job_id"] != pins.dependency_job_id
        || v["dependency_prefix_receipt_sha256"] != pins.dependency_prefix_receipt_sha256
        || v["baseline_tree_sha256"] != pins.dependency_prefix_tree_sha256
        || v["stage_tree_sha256"] != pins.stage_tree_sha256
        || v["clone_generation"] != pins.generation
    {
        return Err("completed native clone differs from original outside pins".into());
    }
    Ok(v)
}

/// Read only the completed original clone, retaining all outside source,
/// archive, stage and dependency bindings. This never clones missing data.
pub fn read_native_candidate_prefix(pins: &NativeCandidatePrefixPins<'_>) -> Result<Value, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if !crate::hex(pins.job_id, 16)
        || !crate::hex(pins.source_sha, 40)
        || !crate::hex(pins.dependency_job_id, 16)
        || pins.dependency_job_id == pins.job_id
        || !gauntlet_evidence::valid_package_version(pins.version)
        || ![
            pins.source_archive_sha256,
            pins.archive_sha256,
            pins.dependency_prefix_receipt_sha256,
            pins.dependency_prefix_tree_sha256,
            pins.stage_tree_sha256,
            pins.generation,
        ]
        .iter()
        .all(|s| crate::hex(s, 64))
    {
        return Err("complete original native clone pins required".into());
    }
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    let _namespace_scope = crate::native_job_storage::owner::scope()?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let baseline = Path::new("/var/lib/hol-gauntlet/builds")
        .join(pins.dependency_job_id)
        .join("dependency-prefix");
    verify(pins, &baseline, &journal)?;
    let slot = crate::builder_candidate_source::open_fixed_build_slot(pins.job_id)
        .map_err(|e| e.to_string())?;
    let raw = crate::dependency_io::read(&slot, "native-candidate-prefix.v1.json", 0, 0o600, 8192)?;
    let mut value = completed(&raw, pins)?;
    let job = Path::new("/var/lib/hol-gauntlet/builds").join(pins.job_id);
    for _ in 0..2 {
        verify(pins, &baseline, &journal)?;
        let bytes = crate::builder_candidate_source::verify_captured_source(
            &slot,
            pins.source_archive_sha256,
        )
        .map_err(|e| e.to_string())?;
        crate::native_runtime_verify::source_receipt(
            &slot,
            pins.job_id,
            pins.source_sha,
            pins.source_archive_sha256,
            bytes,
        )?;
        crate::candidate_capture::inactive(pins.job_id).map_err(|e| e.to_string())?;
        let (_, wheel) = crate::candidate_capture::retained_wheel(
            &slot,
            pins.archive_sha256,
            pins.source_sha,
            pins.version,
        )
        .map_err(|e| e.to_string())?;
        let stage = gauntlet_evidence::inventory_tree(
            &job.join("inert-wheel"),
            gauntlet_evidence::TreeKind::InstalledPrefix,
        )
        .map_err(|e| e.to_string())?;
        let stage_root = crate::open_root_owned_public_directory(&job.join("inert-wheel"))
            .map_err(|e| e.to_string())?;
        crate::native_candidate_launchers::validate(&stage_root, pins.version)?;
        let prefix = gauntlet_evidence::inventory_tree(
            &job.join("inert-prefix"),
            gauntlet_evidence::TreeKind::InstalledPrefix,
        )
        .map_err(|e| e.to_string())?;
        if stage.digest != pins.stage_tree_sha256
            || value["wheel_files"] != wheel.entries
            || value["prefix_tree_sha256"] != prefix.digest
            || value["prefix_entries"] != prefix.entries
            || value["prefix_bytes"] != prefix.bytes
            || crate::dependency_io::read(&slot, "native-candidate-prefix.v1.json", 0, 0o600, 8192)?
                != raw
        {
            return Err("completed clone or original wheel/stage changed".into());
        }
        lease.verify(&journal.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    }
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    value["receipt_sha256"] = format!("{:x}", Sha256::digest(&raw)).into();
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn completed_clone_cannot_rebind_original_inputs_with_a_rehashed_receipt() {
        let source = "a".repeat(40);
        let hashes = (1..=7)
            .map(|n| format!("{n}").repeat(64))
            .collect::<Vec<_>>();
        let pins = NativeCandidatePrefixPins {
            job_id: "0123456789abcdef",
            source_sha: &source,
            source_archive_sha256: &hashes[0],
            archive_sha256: &hashes[1],
            version: "3.57.0",
            dependency_job_id: "0123456789abcdee",
            dependency_prefix_receipt_sha256: &hashes[2],
            dependency_prefix_tree_sha256: &hashes[3],
            stage_tree_sha256: &hashes[4],
            generation: &hashes[5],
        };
        let v = json!({"schema":"hol-gauntlet-native-candidate-prefix.v1","job_id":pins.job_id,"source_sha":source,"version":pins.version,
            "source_archive_sha256":hashes[0],"archive_sha256":hashes[1],"baseline_tree_sha256":hashes[3],"stage_tree_sha256":hashes[4],"prefix_tree_sha256":hashes[6],
            "clone_generation":hashes[5],"dependency_job_id":pins.dependency_job_id,"dependency_prefix_receipt_sha256":hashes[2],"prefix_entries":123,"prefix_bytes":456,"wheel_files":17,"console_scripts":6,"model_requests":0,
            "candidate_executed":false,"dependency_validation_completed":false,"conformance_completed":false,"artifact_admitted":false,"execution_eligible":false,"guard_causality_verified":false});
        let bytes = |v: &Value| gauntlet_contracts::canonicalize(v.to_string().as_bytes()).unwrap();
        assert_eq!(completed(&bytes(&v), &pins).unwrap(), v);
        for (key, bad) in [
            ("source_archive_sha256", json!("f".repeat(64))),
            ("archive_sha256", json!("f".repeat(64))),
            ("dependency_job_id", json!("1123456789abcdee")),
            ("dependency_prefix_receipt_sha256", json!("f".repeat(64))),
            ("baseline_tree_sha256", json!("f".repeat(64))),
            ("stage_tree_sha256", json!("f".repeat(64))),
            ("clone_generation", json!("f".repeat(64))),
            ("execution_eligible", json!(true)),
            ("model_requests", json!(1)),
            ("unknown", json!(true)),
        ] {
            let mut changed = v.clone();
            changed[key] = bad;
            assert!(completed(&bytes(&changed), &pins).is_err(), "{key}");
        }
        let mut noncanonical = bytes(&v);
        noncanonical.push(b' ');
        assert!(completed(&noncanonical, &pins).is_err());
    }
}
