//! Read-only Root preflight: an exact completed build, inert wheel/Native,
//! complete controller tree, local image and four outside runtime hashes.
use crate::builder_context::{inspect_fixed_builder_context, BuilderContextProof};
use crate::builder_image::{fixed_builder_image_plan, inspect_fixed_builder_base_images};
use crate::builder_image_context::verify_existing_context;
use crate::feature_files as files;
use gauntlet_contracts::FeatureRunIntent;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::Path;

pub(crate) fn verify(intent: &FeatureRunIntent) -> Result<BuilderContextProof, String> {
    let p = intent.pins();
    let spec = p.spec();
    let context = inspect_fixed_builder_context(
        Path::new(p.text("controller_root")),
        p.text("controller_tree_sha256"),
        p.audit_id(),
    )
    .map_err(|e| e.to_string())?;
    if context.policy_sha256() != p.text("policy_sha256") {
        return Err("feature policy differs from outside intent".into());
    }
    let build_context = inspect_fixed_builder_context(
        Path::new(p.text("controller_root")),
        p.text("controller_tree_sha256"),
        p.text("build_job_id"),
    )
    .map_err(|e| e.to_string())?;
    let plan = fixed_builder_image_plan(
        &build_context,
        p.text("build_job_id"),
        p.text("uv_base_image_id"),
        p.text("rust_base_image_id"),
    )
    .map_err(|e| e.to_string())?;
    inspect_fixed_builder_base_images(&plan).map_err(|e| e.to_string())?;
    verify_existing_context(&plan).map_err(|e| e.to_string())?;
    if crate::builder_image_build::inspect_result(&plan).map_err(|e| e.to_string())?
        != p.text("builder_image_id")
    {
        return Err("feature builder image differs".into());
    }
    let runtime = crate::builder_candidate_preflight::CandidateRuntimePins::parse(
        p.text("podman_sha256"),
        p.text("slirp4netns_sha256"),
        p.text("apparmor_parser_sha256"),
        p.text("seccomp_sha256"),
    )
    .map_err(|e| e.to_string())?;
    crate::builder_candidate_preflight::verify_candidate_runtime(&runtime)
        .map_err(|e| e.to_string())?;
    let slot = crate::builder_candidate_source::open_fixed_build_slot(p.text("build_job_id"))
        .map_err(|e| e.to_string())?;
    let source_bytes = crate::builder_candidate_source::verify_captured_source(
        &slot,
        spec.text("source_archive_sha256"),
    )
    .map_err(|e| e.to_string())?;
    let raw = files::required(&slot, "candidate-run.result.json", (0, 0), 0o600, 8192)?;
    if format!("{:x}", Sha256::digest(&raw)) != p.text("build_result_sha256") {
        return Err("feature build result differs from outside hash".into());
    }
    let result = crate::feature_journal::canonical(&raw)?;
    verify_build_result(intent, &result, source_bytes)?;
    let archive = files::required(&slot, "candidate.zip", (0, 0), 0o444, 256 * 1024 * 1024)?;
    if format!("{:x}", Sha256::digest(&archive)) != spec.text("candidate_archive_sha256")
        || result["unadmitted_export_bytes"] != archive.len() as u64
    {
        return Err("feature candidate archive differs".into());
    }
    let declaration = crate::inspect_candidate_archive(
        Cursor::new(&archive),
        spec.text("source_sha"),
        spec.text("version"),
    )
    .map_err(|e| e.to_string())?;
    if declaration.wheel_sha256 != spec.text("wheel_sha256")
        || declaration.native_sha256_claim != spec.text("native_sha256")
    {
        return Err("feature candidate declaration differs".into());
    }
    let mut zip = zip::ZipArchive::new(Cursor::new(&archive)).map_err(|e| e.to_string())?;
    let mut wheel = Vec::new();
    zip.by_name(&declaration.wheel)
        .map_err(|e| e.to_string())?
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut wheel)
        .map_err(|e| e.to_string())?;
    let proof = crate::inspect_candidate_wheel(&wheel, &declaration).map_err(|e| e.to_string())?;
    if proof.native_sha256 != spec.text("native_sha256") {
        return Err("feature actual Native ELF differs".into());
    }
    crate::feature_assets::verify("executor", spec.text("executor_sha256"))?;
    crate::feature_assets::verify("node", spec.text("node_sha256"))?;
    Ok(context)
}
fn verify_build_result(
    intent: &FeatureRunIntent,
    result: &Value,
    source_bytes: u64,
) -> Result<(), String> {
    let p = intent.pins();
    let spec = p.spec();
    if result["schema"] != "hol-gauntlet-candidate-build-result.v3"
        || result["job_id"] != p.text("build_job_id")
        || result["source_sha"] != spec.text("source_sha")
        || result["source_archive_sha256"] != spec.text("source_archive_sha256")
        || result["source_bytes"] != source_bytes
        || result["local_version"] != spec.text("version")
        || result["unadmitted_export_sha256"] != spec.text("candidate_archive_sha256")
        || result["image_id"] != p.text("builder_image_id")
        || result["status"] != "exited-zero"
        || result["exit_code"].as_i64() != Some(0)
        || result["container_absent"] != true
        || result["candidate_cgroup_drained"] != true
        || result["build_profile_removed"] != true
        || result["artifact_admitted"] != false
        || result["execution_eligible"] != false
    {
        return Err("feature requires the exact completed ineligible build".into());
    }
    for k in [
        "podman_sha256",
        "slirp4netns_sha256",
        "apparmor_parser_sha256",
        "seccomp_sha256",
    ] {
        if result["runtime_pins"][k] != p.text(k) {
            return Err("feature/build runtime pin differs".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn feature_audit_requires_a_successful_exact_build_without_artifact_admission() {
        let intent = crate::feature_journal::tests::fixture();
        let p = intent.pins();
        let spec = p.spec();
        let mut runtime = serde_json::json!({});
        for k in [
            "podman_sha256",
            "slirp4netns_sha256",
            "apparmor_parser_sha256",
            "seccomp_sha256",
        ] {
            runtime[k] = serde_json::json!(p.text(k));
        }
        let result = serde_json::json!({"schema":"hol-gauntlet-candidate-build-result.v3",
            "job_id":p.text("build_job_id"),"source_sha":spec.text("source_sha"),
            "source_archive_sha256":spec.text("source_archive_sha256"),"source_bytes":12345,
            "local_version":spec.text("version"),"unadmitted_export_sha256":spec.text("candidate_archive_sha256"),
            "image_id":p.text("builder_image_id"),"status":"exited-zero","exit_code":0,
            "container_absent":true,"candidate_cgroup_drained":true,"build_profile_removed":true,
            "artifact_admitted":false,"execution_eligible":false,"runtime_pins":runtime});
        verify_build_result(&intent, &result, 12345).unwrap();
        for (key, wrong) in [
            ("source_sha", serde_json::json!("f".repeat(40))),
            ("source_bytes", serde_json::json!(1)),
            ("status", serde_json::json!("running")),
            ("exit_code", serde_json::json!(1)),
            ("container_absent", serde_json::json!(false)),
            ("artifact_admitted", serde_json::json!(true)),
            ("execution_eligible", serde_json::json!(true)),
        ] {
            let mut v = result.clone();
            v[key] = wrong;
            assert!(verify_build_result(&intent, &v, 12345).is_err(), "{key}");
        }
    }
}
