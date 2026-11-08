//! Retire quiescent preparation without replacing an original partial record.
use crate::{ActiveLease, RunReservationJournal};
use gauntlet_contracts::{canonicalize, DependencyPreparationState, DependencyRunIntent};
use rustix::fs::{statat, AtFlags, Stat};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::fd::OwnedFd;
use std::path::Path;

pub(crate) struct DependencyLeases {
    main: (RunReservationJournal, ActiveLease),
    legacy: crate::builder_image_context::PythonWorkerLease,
    features: (RunReservationJournal, ActiveLease),
    pub journal: RunReservationJournal,
    pub job: ActiveLease,
}
impl DependencyLeases {
    pub(crate) fn acquire() -> Result<Self, String> {
        let pair = |path: &str| -> Result<_, String> {
            let journal = RunReservationJournal::open_root_owned(Path::new(path))
                .map_err(|e| e.to_string())?;
            let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
            Ok((journal, lease))
        };
        let main = pair(crate::builder_image_context::RUST_STATE)?;
        let legacy =
            crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
        let features = pair(crate::feature_state::STATE)?;
        let (journal, job) = pair(crate::dependency_state::STATE)?;
        let result = Self {
            main,
            legacy,
            features,
            journal,
            job,
        };
        result.verify()?;
        Ok(result)
    }
    pub(crate) fn verify(&self) -> Result<(), String> {
        self.main
            .1
            .verify(&self.main.0.root)
            .map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&self.legacy)
            .map_err(|e| e.to_string())?;
        self.features
            .1
            .verify(&self.features.0.root)
            .map_err(|e| e.to_string())?;
        self.job
            .verify(&self.journal.root)
            .map_err(|e| e.to_string())
    }
}

pub(crate) fn intent_for_job(job: &str, expected: &str) -> Result<DependencyRunIntent, String> {
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let raw = crate::feature_files::read(&slot, "dependency-intent.v1.json", (0, 0), 0o600, 8192)?;
    let intent = match raw
        .as_deref()
        .and_then(|b| DependencyRunIntent::parse(b).ok())
    {
        Some(intent) => intent,
        None => {
            let journal =
                RunReservationJournal::open_root_owned(Path::new(crate::dependency_state::STATE))
                    .map_err(|e| e.to_string())?;
            let intent = crate::dependency_preparation::intent_from_receipt(&journal, job)?.ok_or(
                "original dependency intent is missing or partial; explicit retirement required",
            )?;
            crate::dependency_preparation::verified(&journal, &intent)?
                .ok_or("preparation retirement unavailable")?;
            intent
        }
    };
    if intent.pins.text("job_id") != job || intent.digest()? != expected {
        return Err("retained dependency intent differs".into());
    }
    crate::dependency_io::verify_inputs(&slot, &intent)?;
    Ok(intent)
}

fn metadata(s: &Stat) -> String {
    let raw = json!([
        s.st_dev,
        s.st_ino,
        s.st_mode,
        s.st_uid,
        s.st_gid,
        s.st_nlink,
        s.st_size,
        s.st_mtime,
        s.st_mtime_nsec,
        s.st_ctime,
        s.st_ctime_nsec
    ]);
    format!("{:x}", Sha256::digest(raw.to_string().as_bytes()))
}
fn retained(dir: &OwnedFd, name: &str, bound: usize) -> Result<Option<(Vec<u8>, String)>, String> {
    let before = match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(s) => s,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let raw = crate::feature_files::required(dir, name, (0, 0), 0o600, bound)?;
    let after = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    let hash = metadata(&before);
    if metadata(&after) != hash {
        return Err("preparation record changed while reading".into());
    }
    Ok(Some((raw, hash)))
}
fn present(dir: &OwnedFd, name: &str) -> Result<bool, String> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}
fn eligible(journal: &RunReservationJournal, slot: &OwnedFd, job: &str) -> Result<bool, String> {
    for suffix in [
        "running.json",
        "report.json",
        "terminal.json",
        "controller-key.json",
    ] {
        if present(&journal.root, &format!("{job}.{suffix}"))? {
            return Ok(false);
        }
    }
    for name in [
        "dependency-container.v1.json",
        "dependency-creators-ready.v1.json",
        "candidate-client-cgroup.v1.json",
        "dependencies.zip",
    ] {
        if present(slot, name)? {
            return Ok(false);
        }
    }
    Ok(true)
}
fn snapshot(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
) -> Result<DependencyPreparationState, String> {
    let job = intent.pins.text("job_id");
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    if !eligible(journal, &slot, job)? {
        return Err("dependency has progressed beyond preparation".into());
    }
    crate::dependency_io::verify_inputs(&slot, intent)?;
    let started = retained(&journal.root, &format!("{job}.started.json"), 1024)?;
    let stored = retained(
        &slot,
        "dependency-intent.v1.json",
        gauntlet_contracts::DEPENDENCY_INTENT_LIMIT,
    )?;
    DependencyPreparationState::inspect(
        intent,
        started.as_ref().map(|s| s.0.as_slice()),
        started.as_ref().map(|s| s.1.as_str()),
        stored.as_ref().map(|s| s.0.as_slice()),
        stored.as_ref().map(|s| s.1.as_str()),
    )
}
fn absent(intent: &DependencyRunIntent) -> Result<(), String> {
    use crate::builder_candidate_preflight::{
        verify_candidate_runtime_files, CandidateRuntimePins,
    };
    let p = &intent.pins;
    let job = p.text("job_id");
    // An unowned surviving group cannot authorize even a runtime query.
    crate::dependency_state::client_group_absent(job)?;
    let runtime = CandidateRuntimePins::parse(
        p.text("podman_sha256"),
        p.text("slirp4netns_sha256"),
        p.text("apparmor_parser_sha256"),
        p.text("seccomp_sha256"),
    )
    .map_err(|e| e.to_string())?;
    verify_candidate_runtime_files(&runtime).map_err(|e| e.to_string())?;
    if !crate::builder_candidate_process::container_absent(job).map_err(|e| e.to_string())?
        || !crate::builder_policy::profile_absent(&format!("hol-gauntlet-build-{job}"))
            .map_err(|e| e.to_string())?
    {
        return Err(
            "preparation container or profile exists; no kernel custody authorizes cleanup".into(),
        );
    }
    crate::dependency_state::client_group_absent(job)
}

pub(crate) fn observe(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    reader: &str,
) -> Result<Option<Vec<u8>>, String> {
    let slot = crate::builder_candidate_source::open_fixed_build_slot(intent.pins.text("job_id"))
        .map_err(|e| e.to_string())?;
    if !eligible(journal, &slot, intent.pins.text("job_id"))? {
        return Ok(None);
    }
    let state = snapshot(journal, intent)?;
    let raw = state.unknown(intent, reader)?;
    if snapshot(journal, intent)? != state {
        return Err("preparation observation changed".into());
    }
    Ok(Some(raw))
}

fn receipt(journal: &RunReservationJournal, job: &str) -> Result<Option<Vec<u8>>, String> {
    crate::feature_files::read(
        &journal.root,
        &format!("{job}.dependency-repair.json"),
        (0, 0),
        0o600,
        32768,
    )
}
pub(crate) fn intent_from_receipt(
    journal: &RunReservationJournal,
    job: &str,
) -> Result<Option<DependencyRunIntent>, String> {
    let Some(raw) = receipt(journal, job)? else {
        return Ok(None);
    };
    if canonicalize(&raw).map_err(|e| e.to_string())? != raw {
        return Err("canonical preparation receipt required".into());
    }
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if v["schema"] != "hol-gauntlet-native-dependency-repair.v4" {
        return Ok(None);
    }
    let intent = DependencyRunIntent::parse(
        &canonicalize(v["intent"].to_string().as_bytes()).map_err(|e| e.to_string())?,
    )?;
    if intent.pins.text("job_id") != job {
        return Err("preparation retirement job differs".into());
    }
    Ok(Some(intent))
}
pub(crate) fn verified(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
) -> Result<Option<Vec<u8>>, String> {
    let Some(raw) = receipt(journal, intent.pins.text("job_id"))? else {
        return Ok(None);
    };
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if v["schema"] != "hol-gauntlet-native-dependency-repair.v4" {
        return Ok(None);
    }
    let generation = v["repair_generation"]
        .as_str()
        .ok_or("preparation mutator generation missing")?;
    let state = snapshot(journal, intent)?;
    gauntlet_contracts::verify_dependency_repair_result(
        intent,
        &state.expected_started_sha256,
        generation,
        &raw,
    )?;
    if state.retired(intent, generation)? != raw {
        return Err("retained preparation state differs".into());
    }
    absent(intent)?;
    if snapshot(journal, intent)? != state
        || receipt(journal, intent.pins.text("job_id"))?.as_deref() != Some(raw.as_slice())
    {
        return Err("preparation retirement changed while reading".into());
    }
    Ok(Some(raw))
}

pub fn retire_native_dependency_preparation(
    raw: &[u8],
    digest: &str,
    started: &str,
    original: &str,
    generation: &str,
    preparation: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let intent = DependencyRunIntent::parse(raw)?;
    if intent.digest()? != digest || intent.pins.text("runner_binary_sha256") != original {
        return Err("preparation retirement differs from original outside intent".into());
    }
    // Only this exact original executable establishes the pre-creator ordering.
    // A newer reader can reopen the receipt; it cannot retire another writer's gap.
    if original != generation {
        return Err("preparation retirement requires the original pinned worker".into());
    }
    gauntlet_contracts::dependency_preparation_authorization(
        &intent,
        started,
        generation,
        preparation,
    )?;
    let held = DependencyLeases::acquire()?;
    let journal = &held.journal;
    let state = snapshot(journal, &intent)?;
    if state.expected_started_sha256 != started || state.sha256 != preparation {
        return Err("preparation snapshot differs from outside authorization".into());
    }
    if let Some(raw) = verified(journal, &intent)? {
        gauntlet_contracts::verify_dependency_repair_result(&intent, started, generation, &raw)?;
        held.verify()?;
        return Ok(raw);
    }
    if receipt(journal, intent.pins.text("job_id"))?.is_some() {
        return Err("foreign preparation recovery record exists".into());
    }
    absent(&intent)?;
    if snapshot(journal, &intent)? != state {
        return Err("preparation changed before retirement".into());
    }
    let result = state.retired(&intent, generation)?;
    let slot = crate::builder_candidate_source::open_fixed_build_slot(intent.pins.text("job_id"))
        .map_err(|e| e.to_string())?;
    held.verify()?;
    crate::dependency_creator_recovery::publish(
        journal,
        &slot,
        &format!("{}.dependency-repair.json", intent.pins.text("job_id")),
        &result,
    )?;
    if verified(journal, &intent)?.as_deref() != Some(result.as_slice()) {
        return Err("preparation retirement commit uncertain".into());
    }
    held.verify()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    #[ignore = "requires outside Root; uses only isolated temporary inert files"]
    fn preparation_metadata_preserves_prefixes_and_rejects_linked_or_progressed_state() {
        gauntlet_cell_rootfs::require_outside_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let journal = RunReservationJournal::open_root_owned(&root).unwrap();
        let slot_temp = tempfile::tempdir().unwrap();
        let slot = rustix::fs::open(
            slot_temp.path(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert!(retained(&slot, "original", 8192).unwrap().is_none());
        crate::feature_files::write(&slot, "original", b"{", (0, 0), 0o600).unwrap();
        let original = retained(&slot, "original", 8192).unwrap().unwrap();
        assert_eq!(original.0, b"{");
        assert_eq!(
            retained(&slot, "original", 8192).unwrap().unwrap(),
            original
        );
        assert!(retained(&slot, "original", 0).is_err());
        std::fs::rename(
            slot_temp.path().join("original"),
            slot_temp.path().join("kept"),
        )
        .unwrap();
        crate::feature_files::write(&slot, "original", b"{", (0, 0), 0o600).unwrap();
        assert_ne!(
            retained(&slot, "original", 8192).unwrap().unwrap().1,
            original.1
        );
        assert_eq!(std::fs::read(slot_temp.path().join("kept")).unwrap(), b"{");
        symlink("original", slot_temp.path().join("alias")).unwrap();
        assert!(retained(&slot, "alias", 8192).is_err());
        std::fs::hard_link(
            slot_temp.path().join("original"),
            slot_temp.path().join("hard"),
        )
        .unwrap();
        assert!(retained(&slot, "original", 8192).is_err());
        let job = "0123456789abcdef";
        assert!(eligible(&journal, &slot, job).unwrap());
        for suffix in [
            "running.json",
            "report.json",
            "terminal.json",
            "controller-key.json",
        ] {
            let name = format!("{job}.{suffix}");
            crate::feature_files::write(&journal.root, &name, b"", (0, 0), 0o600).unwrap();
            assert!(!eligible(&journal, &slot, job).unwrap());
            std::fs::remove_file(root.join(name)).unwrap();
        }
        for name in [
            "dependency-container.v1.json",
            "dependency-creators-ready.v1.json",
            "candidate-client-cgroup.v1.json",
            "dependencies.zip",
        ] {
            crate::feature_files::write(&slot, name, b"", (0, 0), 0o600).unwrap();
            assert!(!eligible(&journal, &slot, job).unwrap());
            std::fs::remove_file(slot_temp.path().join(name)).unwrap();
        }
        assert!(eligible(&journal, &slot, job).unwrap());
    }
}
