//! Dependency recovery retains an aborted attempt with unknown exit. Live
//! cleanup uses the retained CID/kernel group; historical PIDs are never signalled.
use crate::{read_bounded_regular, RunReservationJournal};
use gauntlet_contracts::{canonicalize, DependencyRunIntent};
use rustix::fs::{statat, AtFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::fd::OwnedFd;
use std::path::Path;

pub(crate) fn intent_for_job(job: &str, expected: &str) -> Result<DependencyRunIntent, String> {
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let raw = crate::dependency_io::read(&slot, "dependency-intent.v1.json", 0, 0o600, 8192)?;
    let intent = DependencyRunIntent::parse(&raw)?;
    if intent.pins.text("job_id") != job || intent.digest()? != expected {
        return Err("retained dependency intent differs".into());
    }
    crate::dependency_io::verify_inputs(&slot, &intent)?;
    Ok(intent)
}

fn container_identity(slot: &OwnedFd, digest: &str) -> Result<String, String> {
    let raw = crate::dependency_io::read(slot, "dependency-container.v1.json", 0, 0o600, 2048)?;
    if canonicalize(&raw).map_err(|e| e.to_string())? != raw {
        return Err("dependency CID receipt is ambiguous".into());
    }
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let cid = v["container_id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("dependency CID receipt missing")?;
    if v.as_object().is_none_or(|o| o.len() != 3)
        || v["schema"] != "hol-gauntlet-native-dependency-container.v1"
        || v["intent_sha256"] != digest
    {
        return Err("dependency CID receipt differs".into());
    }
    Ok(cid.into())
}

fn captured(slot: &OwnedFd) -> Result<Option<(u64, String)>, String> {
    match statat(slot, "dependencies.zip", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(e) => Err(e.to_string()),
        Ok(_) => {
            let raw =
                crate::dependency_io::read(slot, "dependencies.zip", 0, 0o444, 256 * 1024 * 1024)?;
            Ok(Some((
                raw.len() as u64,
                format!("{:x}", Sha256::digest(raw)),
            )))
        }
    }
}

fn body(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    repair: &str,
    owned: bool,
) -> Result<Value, String> {
    let p = &intent.pins;
    let job = p.text("job_id");
    let digest = intent.digest()?;
    let started = journal
        .started(
            job,
            p.text("source_sha"),
            &digest,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?
        .ok_or("dependency reservation missing")?;
    if started.controller_public_key_hex.is_some() {
        return Err("keyed job is outside dependency recovery".into());
    }
    let running = journal
        .running_marker(
            job,
            p.text("source_sha"),
            &digest,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?;
    if let Some(marker) = &running {
        if marker.cgroup != format!("/system.slice/hol-gauntlet-rust-candidate-{job}") {
            return Err("dependency client cgroup differs".into());
        }
        match std::fs::symlink_metadata(format!("/proc/{}", marker.process.pid)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("dependency client PID still exists or is uncertain".into()),
        }
    }
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let cid = container_identity(&slot, &digest)?;
    crate::dependency_podman::verify_completed_absent(intent, &cid)?;
    let output = captured(&slot)?;
    let mut value = json!({"schema":"hol-gauntlet-native-dependency-repair.v1","job_id":job,"source_sha":p.text("source_sha"),"intent_sha256":digest,
        "worker_generation":p.text("runner_binary_sha256"),"repair_generation":repair,"started_marker_sha256":started.sha256,
        "running_marker_sha256":running.map(|m|m.sha256),"container_id":cid,"captured_dependencies_bytes":output.as_ref().map(|(n,_)|n),
        "captured_dependencies_sha256":output.as_ref().map(|(_,s)|s),"status":"aborted","exit_code":null,"quiescent":true,
        "artifact_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    if owned {
        let raw = crate::feature_files::required(
            &slot,
            "candidate-client-cgroup.v1.json",
            (0, 0),
            0o600,
            2048,
        )?;
        if crate::builder_cgroup::OwnedCandidateCgroup::reopen_candidate(&slot, job, &digest)?
            .is_some()
        {
            return Err("repaired dependency client group reappeared".into());
        }
        value["schema"] = json!("hol-gauntlet-native-dependency-repair.v2");
        value["client_cgroup_receipt_sha256"] = json!(format!("{:x}", Sha256::digest(&raw)));
        value["qualification_eligible"] = json!(false);
        value["model_tokens"] = json!(0);
    }
    Ok(value)
}

pub(crate) fn verified(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
) -> Result<Option<Vec<u8>>, String> {
    let name = format!("{}.dependency-repair.json", intent.pins.text("job_id"));
    let Some(raw) = read_bounded_regular(&journal.root, &name, 8192).map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    for suffix in ["report.json", "terminal.json", "controller-key.json"] {
        if !matches!(
            statat(
                &journal.root,
                format!("{}.{suffix}", intent.pins.text("job_id")),
                AtFlags::SYMLINK_NOFOLLOW
            ),
            Err(rustix::io::Errno::NOENT)
        ) {
            return Err("dependency repair conflicts with a report, terminal or key".into());
        }
    }
    if canonicalize(&raw).map_err(|e| e.to_string())? != raw {
        return Err("canonical dependency repair receipt required".into());
    }
    let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let generation = value["repair_generation"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("dependency repair executable pin missing")?;
    let owned = match value["schema"].as_str() {
        Some("hol-gauntlet-native-dependency-repair.v1") => false,
        Some("hol-gauntlet-native-dependency-repair.v2") => true,
        _ => return Err("unsupported dependency repair version".into()),
    };
    if value != body(journal, intent, generation, owned)? {
        return Err(
            "dependency repair differs from retained identity or claims execution credit".into(),
        );
    }
    Ok(Some(raw))
}

pub fn repair_native_dependencies(
    job: &str,
    digest: &str,
    expected_started: &str,
    original_generation: &str,
    repair_generation: &str,
) -> Result<Vec<u8>, String> {
    repair(
        job,
        digest,
        expected_started,
        original_generation,
        repair_generation,
        false,
        false,
    )
}

pub fn repair_owned_native_dependencies(
    job: &str,
    digest: &str,
    started: &str,
    original: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    repair(job, digest, started, original, generation, true, false)
}

pub fn read_repaired_native_dependencies(
    job: &str,
    digest: &str,
    started: &str,
    original: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    repair(job, digest, started, original, generation, true, true)
}

fn reclaim(
    intent: &DependencyRunIntent,
    still_owned: &impl Fn() -> Result<(), String>,
    phase: &mut &str,
) -> Result<(), String> {
    use crate::builder_candidate_preflight::{verify_candidate_runtime, CandidateRuntimePins};
    let p = &intent.pins;
    let job = p.text("job_id");
    let digest = intent.digest()?;
    let runtime = CandidateRuntimePins::parse(
        p.text("podman_sha256"),
        p.text("slirp4netns_sha256"),
        p.text("apparmor_parser_sha256"),
        p.text("seccomp_sha256"),
    )
    .map_err(|e| e.to_string())?;
    *phase = "runtime-pins";
    verify_candidate_runtime(&runtime).map_err(|e| e.to_string())?;
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    *phase = "retained-cgroup";
    // Missing historical kernel custody cannot authorize adopting an active group.
    crate::feature_files::required(
        &slot,
        "candidate-client-cgroup.v1.json",
        (0, 0),
        0o600,
        2048,
    )?;
    let mut group =
        crate::builder_cgroup::OwnedCandidateCgroup::reopen_candidate(&slot, job, &digest)?;
    *phase = "retained-container";
    let cid = container_identity(&slot, &digest)?;
    let container = crate::dependency_podman::DependencyContainer::restore(intent, &cid)?;
    *phase = "retained-policy";
    let profile = format!("hol-gauntlet-build-{job}");
    let policy = if crate::builder_policy::profile_absent(&profile).map_err(|e| e.to_string())? {
        None
    } else {
        crate::builder_policy::read_policy(job, p.text("policy_sha256"))
            .map_err(|e| e.to_string())?;
        Some(format!(
            "/var/lib/hol-gauntlet/builds/{job}/Builder.apparmor"
        ))
    };
    still_owned()?;
    *phase = "client-kill";
    if let Some(group) = &group {
        group.kill().map_err(|e| e.to_string())?;
    }
    still_owned()?;
    *phase = "container-drain";
    container.drain()?;
    *phase = "client-drain";
    if let Some(group) = &mut group {
        group.drain_and_remove().map_err(|e| e.to_string())?;
    }
    crate::dependency_state::client_group_absent(job)?;
    *phase = "policy-remove";
    if let Some(policy) = policy {
        still_owned()?;
        crate::builder_policy::run_parser("--remove", &policy).map_err(|e| e.to_string())?;
    }
    *phase = "resource-absence";
    crate::dependency_podman::verify_completed_absent(intent, &cid)
}

fn repair(
    job: &str,
    digest: &str,
    expected_started: &str,
    original_generation: &str,
    repair_generation: &str,
    owned: bool,
    read_only: bool,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(repair_generation).map_err(|e| e.to_string())?;
    if !crate::hex(expected_started, 64) || !crate::hex(original_generation, 64) {
        return Err("outside dependency recovery pins required".into());
    }
    let main =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = main.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let features = RunReservationJournal::open_root_owned(Path::new(crate::feature_state::STATE))
        .map_err(|e| e.to_string())?;
    let feature_lease = features.acquire_active_lease().map_err(|e| e.to_string())?;
    let journal = RunReservationJournal::open_root_owned(Path::new(crate::dependency_state::STATE))
        .map_err(|e| e.to_string())?;
    let job_lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let still_owned = || -> Result<(), String> {
        lease.verify(&main.root).map_err(|e| e.to_string())?;
        feature_lease
            .verify(&features.root)
            .map_err(|e| e.to_string())?;
        job_lease.verify(&journal.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())
    };
    let intent = intent_for_job(job, digest)?;
    if intent.pins.text("runner_binary_sha256") != original_generation {
        return Err("original dependency generation differs".into());
    }
    let started = journal
        .started(
            job,
            intent.pins.text("source_sha"),
            digest,
            original_generation,
        )
        .map_err(|e| e.to_string())?
        .ok_or("dependency job was not reserved")?;
    if started.sha256 != expected_started {
        return Err("outside dependency reservation differs".into());
    }
    for suffix in ["report.json", "terminal.json", "controller-key.json"] {
        match statat(
            &journal.root,
            format!("{job}.{suffix}"),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(
                "terminal, partial-report or keyed dependency job needs separate reconciliation"
                    .into(),
            ),
        }
    }
    if let Some(raw) = verified(&journal, &intent)? {
        still_owned()?;
        return Ok(raw);
    }
    if read_only {
        return Err("dependency has no retained repair; read never authorizes cleanup".into());
    }
    let mut phase = "recovery-preflight";
    let result: Result<Vec<u8>, String> = (|| {
        if owned {
            reclaim(&intent, &still_owned, &mut phase)?;
        }
        phase = "quiescent-body";
        let raw = canonicalize(
            body(&journal, &intent, repair_generation, owned)?
                .to_string()
                .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        still_owned()?;
        phase = "repair-commit";
        crate::terminal::create_durable(
            &journal.root,
            &format!("{job}.dependency-repair.json"),
            &raw,
        )
        .map_err(|e| e.to_string())?;
        phase = "repair-readback";
        let observed =
            verified(&journal, &intent)?.ok_or("dependency recovery commit unavailable")?;
        if observed != raw {
            return Err("dependency recovery changed after commit".into());
        }
        still_owned()?;
        Ok(raw)
    })();
    if owned {
        if let Err(error) = &result {
            still_owned()?;
            retain_failure(&intent, expected_started, repair_generation, phase, error)
                .map_err(|e| format!("{error}; private repair diagnostic unavailable: {e}"))?;
            still_owned()?;
        }
    }
    result
}

fn error_detail(error: &str) -> Value {
    let end = (0..=error.len().min(1024))
        .rev()
        .find(|n| error.is_char_boundary(*n))
        .unwrap_or(0);
    json!({"sha256":format!("{:x}",Sha256::digest(error.as_bytes())),
        "bytes":error.len(),"prefix":&error[..end],"truncated":end<error.len()})
}

fn retain_failure(
    intent: &DependencyRunIntent,
    started: &str,
    generation: &str,
    phase: &str,
    error: &str,
) -> Result<(), String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut random = [0u8; 8];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "repair diagnostic identity unavailable")?;
    let attempt: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let job = intent.pins.text("job_id");
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let value = json!({"schema":"hol-gauntlet-private-dependency-repair-failure.v1",
        "job_id":job,"source_sha":intent.pins.text("source_sha"),"intent_sha256":intent.digest()?,
        "worker_generation":intent.pins.text("runner_binary_sha256"),"repair_generation":generation,
        "started_marker_sha256":started,"attempt_id":attempt,"phase":phase,"error":error_detail(error),
        "status":"unknown","exit_code":null,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0,"model_tokens":0});
    let raw = canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if raw.len() > 8192 {
        return Err("private repair diagnostic exceeds bound".into());
    }
    // Private diagnostics never enter the public repair/read protocol.
    crate::feature_files::write(
        &slot,
        &format!("dependency-repair-error-{attempt}.json"),
        &raw,
        (0, 0),
        0o600,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_error_prefix_is_utf8_bounded_and_hashes_the_entire_error() {
        for error in [
            "😀".repeat(2048),
            "\u{0000}".repeat(8192),
            "a".repeat(1023) + "😀",
        ] {
            let v = error_detail(&error);
            assert!(v["prefix"].as_str().unwrap().len() <= 1024);
            assert!(error.starts_with(v["prefix"].as_str().unwrap()));
            assert_eq!(v["bytes"], error.len());
            assert_eq!(
                v["sha256"],
                format!("{:x}", Sha256::digest(error.as_bytes()))
            );
            assert_eq!(v["truncated"], true);
            assert!(canonicalize(v.to_string().as_bytes()).unwrap().len() < 8192);
        }
        let a = error_detail(&("a".repeat(1024) + "original"));
        let b = error_detail(&("a".repeat(1024) + "different"));
        assert_eq!(a["prefix"], b["prefix"]);
        assert_ne!(a["sha256"], b["sha256"]);
        assert_eq!(error_detail("short")["truncated"], false);
    }
}
