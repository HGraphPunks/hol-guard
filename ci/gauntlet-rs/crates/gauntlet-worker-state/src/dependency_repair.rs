//! Dependency recovery retains an aborted attempt with unknown exit. Live
//! cleanup uses the retained CID/kernel group; historical PIDs are never signalled.
use crate::dependency_io::{captured, error_detail};
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
    match crate::dependency_creator_recovery::original(slot, digest)? {
        crate::dependency_creator_recovery::OriginalCid::Retained(cid) => Ok(cid),
        _ => Err("retained dependency CID required".into()),
    }
}

fn body(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    repair: &str,
    owned: bool,
) -> Result<Value, String> {
    if owned {
        if let Some(value) = crate::dependency_creator_recovery::body(journal, intent, repair)? {
            return Ok(value);
        }
    }
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
        Some(
            "hol-gauntlet-native-dependency-repair.v2" | "hol-gauntlet-native-dependency-repair.v3",
        ) => true,
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
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    started: &str,
    generation: &str,
    still_owned: &impl Fn() -> Result<(), String>,
    phase: &mut &str,
) -> Result<(), String> {
    use crate::builder_candidate_preflight::{
        verify_candidate_runtime_files, CandidateRuntimePins,
    };
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
    verify_candidate_runtime_files(&runtime).map_err(|e| e.to_string())?;
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
    if matches!(
        crate::dependency_creator_recovery::original(&slot, &digest)?,
        crate::dependency_creator_recovery::OriginalCid::Incomplete(_)
    ) {
        return crate::dependency_creator_recovery::reclaim(
            journal,
            intent,
            started,
            generation,
            &mut group,
            still_owned,
            phase,
        );
    }
    *phase = "retained-container";
    let cid = container_identity(&slot, &digest)?;
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
    *phase = "client-drain";
    if let Some(group) = &mut group {
        group.drain_and_remove().map_err(|e| e.to_string())?;
    }
    crate::dependency_state::client_group_absent(job)?;
    *phase = "runtime-info";
    crate::builder_candidate_preflight::verify_candidate_runtime_info()
        .map_err(|e| e.to_string())?;
    still_owned()?;
    *phase = "container-drain";
    crate::dependency_podman::DependencyContainer::restore(intent, &cid)?.drain()?;
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
    if started.sha256 != expected_started || started.controller_public_key_hex.is_some() {
        return Err("outside dependency reservation differs".into());
    }
    if owned {
        if let Some(frame) = crate::dependency_state::finalize_report(
            &journal,
            &job_lease,
            &intent,
            repair_generation,
            read_only,
            &still_owned,
        )? {
            return Ok(frame);
        }
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
            reclaim(
                &journal,
                &intent,
                expected_started,
                repair_generation,
                &still_owned,
                &mut phase,
            )?;
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
        crate::dependency_creator_recovery::commit(&journal, &intent, &raw)?;
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

fn retain_failure(
    intent: &DependencyRunIntent,
    started: &str,
    generation: &str,
    phase: &str,
    error: &str,
) -> Result<(), String> {
    let job = intent.pins.text("job_id");
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let value = json!({"schema":"hol-gauntlet-private-dependency-repair-failure.v1",
        "job_id":job,"source_sha":intent.pins.text("source_sha"),"intent_sha256":intent.digest()?,
        "worker_generation":intent.pins.text("runner_binary_sha256"),"repair_generation":generation,
        "started_marker_sha256":started,"phase":phase,"error":error_detail(error),
        "status":"unknown","exit_code":null,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0,"model_tokens":0});
    write_failure(&slot, value).map(|_| ())
}

fn write_failure(slot: &OwnedFd, mut value: Value) -> Result<String, String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut random = [0u8; 8];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "repair diagnostic identity unavailable")?;
    let attempt: String = random.iter().map(|b| format!("{b:02x}")).collect();
    value["attempt_id"] = json!(attempt);
    let raw = canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if raw.len() > 8192 {
        return Err("private repair diagnostic exceeds bound".into());
    }
    // Private diagnostics never enter the public repair/read protocol.
    let name = format!("dependency-repair-error-{attempt}.json");
    crate::feature_files::write(slot, &name, &raw, (0, 0), 0o600)?;
    Ok(name)
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

    #[test]
    #[ignore = "requires outside Root; writes only an isolated temporary fixture"]
    fn private_failure_records_are_durable_exclusive_and_bounded() {
        use std::os::unix::fs::MetadataExt;
        gauntlet_cell_rootfs::require_outside_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let slot = rustix::fs::open(
            temp.path(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let value = json!({"status":"unknown","exit_code":null,"error":error_detail("private fixture error")});
        let first = write_failure(&slot, value.clone()).unwrap();
        let before = std::fs::read(temp.path().join(&first)).unwrap();
        let second = write_failure(&slot, value).unwrap();
        assert_ne!(first, second);
        assert_eq!(before, std::fs::read(temp.path().join(&first)).unwrap());
        for name in [first, second] {
            let m = std::fs::symlink_metadata(temp.path().join(&name)).unwrap();
            assert_eq!(
                (m.uid(), m.gid(), m.nlink(), m.mode() & 0o7777),
                (0, 0, 1, 0o600)
            );
            let raw = crate::feature_files::required(&slot, &name, (0, 0), 0o600, 8192).unwrap();
            assert_eq!(canonicalize(&raw).unwrap(), raw);
            let v: Value = serde_json::from_slice(&raw).unwrap();
            assert!(name.contains(v["attempt_id"].as_str().unwrap()));
            assert_eq!(v["status"], "unknown");
            assert!(v["exit_code"].is_null());
        }
        assert!(write_failure(&slot, json!({"oversized":"x".repeat(8192)})).is_err());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 2);
    }
}
