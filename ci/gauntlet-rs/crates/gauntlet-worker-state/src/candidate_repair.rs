//! Exact owned-resource recovery for an interrupted host-bound candidate build.
//! Repair records an unknown exit and never starts or admits a workload.
use crate::builder_candidate_preflight::{verify_candidate_runtime, CandidateRuntimePins};
use crate::builder_candidate_receipt::write_root_canonical_job_file;
use crate::builder_candidate_source::open_fixed_build_slot;
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_host_anchor::{
    verify_running_binary, CandidateContainer, HostCandidateRunAnchor, HOST_ANCHOR_FILE,
};
use crate::{feature_files as files, hex, RunReservationJournal};
use gauntlet_contracts::{canonicalize, is_git_sha};
use rustix::fs::{statat, AtFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const REPAIR: &str = "candidate-run.repair.v1.json";

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("candidate anchor field missing: {key}"))
}
fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

struct Context {
    anchor: Value,
    runtime: CandidateRuntimePins,
    plan: crate::BuilderRunPlan,
}

fn context(raw: &[u8], job: &str, source: &str, expected: &str) -> Result<Context, String> {
    if !hex(job, 16) || !is_git_sha(source) || !hex(expected, 64) || digest(raw) != expected {
        return Err("outside candidate recovery identity differs".into());
    }
    let v = crate::feature_journal::canonical(raw)?;
    let p = &v["runtime_pins"];
    let runtime = CandidateRuntimePins::parse(
        text(p, "podman_sha256")?,
        text(p, "slirp4netns_sha256")?,
        text(p, "apparmor_parser_sha256")?,
        text(p, "seccomp_sha256")?,
    )
    .map_err(|e| e.to_string())?;
    let args = [
        text(&v, "policy_sha256")?,
        text(&v, "result_reader_binary_sha256")?,
        text(&v, "host_pin_sha256")?,
        text(&v, "host_nonce_hex")?,
        text(&v, "runner_binary_sha256")?,
    ];
    let anchor = match v.get("tag") {
        Some(tag) => HostCandidateRunAnchor::parse_with_tag(
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            tag.as_str().ok_or("candidate tag must be text")?,
        ),
        None => HostCandidateRunAnchor::parse(args[0], args[1], args[2], args[3], args[4]),
    }
    .ok_or("candidate recovery anchor is invalid")?;
    let expected_body = anchor.body(
        job,
        source,
        text(&v, "source_archive_sha256")?,
        text(&v, "version")?,
        text(&v, "controller_tree_sha256")?,
        text(&v, "image_id")?,
        &runtime,
    );
    if canonicalize(expected_body.to_string().as_bytes()).map_err(|e| e.to_string())? != raw
        || !hex(text(&v, "controller_tree_sha256")?, 64)
        || !gauntlet_evidence::valid_package_version(text(&v, "version")?)
    {
        return Err("candidate recovery anchor is not the reserved request".into());
    }
    let tag = v
        .get("tag")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("local-{source}"));
    let request = json!({"image_id":v["image_id"],"job_id":job,"source_sha":source,
        "source_archive_sha256":v["source_archive_sha256"],"tag":tag,"memory_gib":12,
        "local_version":if tag.starts_with("local-") {Some(text(&v,"version")?)} else {None},
        "retest_build_job_id":null});
    let plan = crate::fixed_builder_run_plan(&request).map_err(|e| e.to_string())?;
    Ok(Context {
        anchor: v,
        runtime,
        plan,
    })
}

pub fn repair_hostbound_candidate_ineligible(
    job: &str,
    source: &str,
    anchor_sha: &str,
    generation: &str,
) -> Result<Value, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    verify_running_binary(generation).map_err(|e| e.to_string())?;
    if !hex(job, 16) || !is_git_sha(source) || !hex(anchor_sha, 64) {
        return Err("exact outside candidate recovery pins required".into());
    }
    let main =
        RunReservationJournal::open_root_owned(Path::new(RUST_STATE)).map_err(|e| e.to_string())?;
    let lease = main.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = python_worker_lock().map_err(|e| e.to_string())?;
    let features = RunReservationJournal::open_root_owned(Path::new(crate::feature_state::STATE))
        .map_err(|e| e.to_string())?;
    let feature_lease = features.acquire_active_lease().map_err(|e| e.to_string())?;
    let dependencies =
        RunReservationJournal::open_root_owned(Path::new(crate::dependency_state::STATE))
            .map_err(|e| e.to_string())?;
    let dependency_lease = dependencies
        .acquire_active_lease()
        .map_err(|e| e.to_string())?;
    let still_owned = || -> Result<(), String> {
        lease.verify(&main.root).map_err(|e| e.to_string())?;
        verify_python_lock(&legacy).map_err(|e| e.to_string())?;
        feature_lease
            .verify(&features.root)
            .map_err(|e| e.to_string())?;
        dependency_lease
            .verify(&dependencies.root)
            .map_err(|e| e.to_string())
    };
    crate::dependency_state::require_idle()?;
    let slot = open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    match statat(
        &slot,
        "candidate-run.result.json",
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(rustix::io::Errno::NOENT) => {}
        _ => {
            return Err("candidate result exists or is uncertain; reconcile without repair".into())
        }
    }
    let raw = files::required(&slot, HOST_ANCHOR_FILE, (0, 0), 0o600, 8192)?;
    let ctx = context(&raw, job, source, anchor_sha)?;
    verify_candidate_runtime(&ctx.runtime).map_err(|e| e.to_string())?;
    let a = &ctx.anchor;
    let mut group =
        crate::builder_cgroup::OwnedCandidateCgroup::reopen_candidate(&slot, job, anchor_sha)?;
    let container = CandidateContainer::restore(
        &ctx.plan,
        text(a, "image_id")?,
        text(&a["runtime_pins"], "podman_sha256")?,
        anchor_sha,
        &slot,
    )?;
    let cgroup_receipt = files::read(
        &slot,
        "candidate-client-cgroup.v1.json",
        (0, 0),
        0o600,
        2048,
    )?;
    let body = json!({"schema":"hol-gauntlet-candidate-build-repair.v1","job_id":job,
        "source_sha":source,"host_anchor_sha256":anchor_sha,"host_pin_sha256":a["host_pin_sha256"],
        "runner_binary_sha256":a["runner_binary_sha256"],"repair_generation":generation,
        "container_id":container.id(),"client_cgroup_receipt_sha256":cgroup_receipt.as_deref().map(digest),
        "status":"aborted","exit_code":null,"quiescent":true,"artifact_admitted":false,
        "execution_eligible":false,"qualification_eligible":false,"guard_causality_verified":false,
        "model_requests":0,"model_tokens":0});
    let encoded = canonicalize(body.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let existing = files::read(&slot, REPAIR, (0, 0), 0o600, 8192)?;
    if existing.as_ref().is_some_and(|v| v != &encoded) {
        return Err("retained candidate repair differs from outside authorization".into());
    }
    if existing.is_some() {
        if group.is_some() {
            return Err("repaired candidate client group reappeared".into());
        }
        container.verify_absent()?;
        crate::candidate_capture::inactive(job).map_err(|e| e.to_string())?;
    } else {
        let profile = format!("hol-gauntlet-build-{job}");
        let policy =
            if crate::builder_policy::profile_absent(&profile).map_err(|e| e.to_string())? {
                None
            } else {
                crate::builder_policy::read_policy(job, text(a, "policy_sha256")?)
                    .map_err(|e| e.to_string())?;
                Some(format!(
                    "/var/lib/hol-gauntlet/builds/{job}/Builder.apparmor"
                ))
            };
        still_owned()?;
        if let Some(group) = &group {
            group.kill().map_err(|e| e.to_string())?;
        }
        still_owned()?;
        container.drain()?;
        if let Some(group) = &mut group {
            group.drain_and_remove().map_err(|e| e.to_string())?;
        }
        crate::candidate_capture::inactive_client_groups(job).map_err(|e| e.to_string())?;
        if let Some(policy) = policy {
            still_owned()?;
            crate::builder_policy::run_parser("--remove", &policy).map_err(|e| e.to_string())?;
        }
        crate::candidate_capture::inactive(job).map_err(|e| e.to_string())?;
    }
    still_owned()?;
    if files::required(&slot, HOST_ANCHOR_FILE, (0, 0), 0o600, 8192)? != raw {
        return Err("candidate recovery anchor changed".into());
    }
    let receipt = if existing.is_some() {
        digest(&encoded)
    } else {
        write_root_canonical_job_file(&slot, REPAIR, &body).map_err(|e| e.to_string())?
    };
    still_owned()?;
    let mut result = body;
    result["repair_receipt_sha256"] = json!(receipt);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let p = "b".repeat(64);
        let runtime = CandidateRuntimePins::parse(&p, &p, &p, &p).unwrap();
        let source = "a".repeat(40);
        let anchor =
            HostCandidateRunAnchor::parse_with_tag(&p, &p, &p, &p, &p, &format!("local-{source}"))
                .unwrap();
        canonicalize(
            anchor
                .body(
                    "0123456789abcdef",
                    &source,
                    &p,
                    "3.59.0",
                    &p,
                    &format!("sha256:{p}"),
                    &runtime,
                )
                .to_string()
                .as_bytes(),
        )
        .unwrap()
    }
    #[test]
    fn repair_requires_the_complete_closed_outside_anchor() {
        let raw = fixture();
        let source = "a".repeat(40);
        let pin = digest(&raw);
        assert!(context(&raw, "0123456789abcdef", &source, &pin).is_ok());
        assert!(context(&raw, "1123456789abcdef", &source, &pin).is_err());
        assert!(context(&raw, "0123456789abcdef", &"c".repeat(40), &pin).is_err());
        assert!(context(&raw, "0123456789abcdef", &source, &"c".repeat(64)).is_err());
        let v: Value = serde_json::from_slice(&raw).unwrap();
        for (field, value) in [
            ("schema", json!("other")),
            ("pre_candidate_run", json!(false)),
            ("execution_eligible", json!(true)),
            ("artifact_admitted", json!(true)),
            ("extra", json!(0)),
            ("tag", json!(format!("local-{}", "c".repeat(40)))),
        ] {
            let mut bad = v.clone();
            bad[field] = value;
            let bytes = canonicalize(bad.to_string().as_bytes()).unwrap();
            assert!(
                context(&bytes, "0123456789abcdef", &source, &digest(&bytes)).is_err(),
                "{field}"
            );
        }
    }
}
