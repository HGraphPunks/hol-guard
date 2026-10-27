//! Cross-job dependency uncertainty blocks further execution under the shared
//! worker lease. Completed records are checked against retained intent bytes.
use crate::{
    open_root_owned_public_directory, read_bounded_regular, RunReservationJournal, TerminalOutcome,
};
use gauntlet_contracts::canonicalize;
use gauntlet_contracts::DependencyRunIntent;
use rustix::fs::{statat, AtFlags, Dir};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) const STATE: &str = "/var/lib/hol-gauntlet-rust/dependency-state";

pub(crate) fn require_idle() -> Result<(), String> {
    let base = open_root_owned_public_directory(Path::new("/var/lib/hol-gauntlet-rust"))
        .map_err(|e| e.to_string())?;
    match statat(&base, "dependency-state", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(STATE)).map_err(|e| e.to_string())?;
    let mut jobs = BTreeSet::new();
    let mut starts = BTreeMap::new();
    let mut count = 0usize;
    for entry in Dir::read_from(&journal.root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "dependency state filename UTF-8")?;
        if matches!(name, "." | ".." | "active.lock") {
            continue;
        }
        count += 1;
        if count > 4096 {
            return Err("dependency state inventory bound exceeded".into());
        }
        let (job, suffix) = name
            .split_once('.')
            .filter(|(s, _)| crate::hex(s, 16))
            .ok_or("unrecognized dependency job")?;
        if !matches!(
            suffix,
            "started.json"
                | "running.json"
                | "report.json"
                | "terminal.json"
                | "dependency-repair.json"
        ) {
            return Err("unrecognized dependency sidecar".into());
        }
        jobs.insert(job.to_owned());
        if suffix == "started.json" {
            let raw = read_bounded_regular(&journal.root, name, 1024)
                .map_err(|e| e.to_string())?
                .ok_or("dependency start disappeared")?;
            if canonicalize(&raw).map_err(|e| e.to_string())? != raw {
                return Err("ambiguous dependency start".into());
            }
            let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            starts.insert(job.to_owned(), value);
        }
    }
    for job in jobs {
        let start = starts
            .get(&job)
            .ok_or("orphan dependency sidecar blocks execution")?;
        let digest = start["deployment_digest"]
            .as_str()
            .ok_or("dependency start lacks intent")?;
        let intent = crate::dependency_repair::intent_for_job(&job, digest)?;
        let p = &intent.pins;
        journal
            .started(
                &job,
                p.text("source_sha"),
                digest,
                p.text("runner_binary_sha256"),
            )
            .map_err(|e| e.to_string())?
            .ok_or("dependency start differs")?;
        let terminal = journal
            .terminal(
                &job,
                p.text("source_sha"),
                digest,
                p.text("runner_binary_sha256"),
            )
            .map_err(|e| e.to_string())?;
        let repair = crate::dependency_repair::verified(&journal, &intent)?;
        if terminal.is_some() == repair.is_some() {
            return Err("active, ambiguous or unknown dependency job blocks execution".into());
        }
        if let Some(terminal) = terminal {
            if terminal.status != TerminalOutcome::InvalidEvidence {
                return Err("dependency terminal claims execution authority".into());
            }
            let raw = read_bounded_regular(&journal.root, &format!("{job}.report.json"), 16384)
                .map_err(|e| e.to_string())?
                .ok_or("dependency report missing")?;
            let report: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            let reported = DependencyRunIntent::parse(
                &canonicalize(report["intent"].to_string().as_bytes())
                    .map_err(|e| e.to_string())?,
            )?;
            if reported != intent
                || report["schema"] != "hol-gauntlet-native-dependency-result.v1"
                || report["intent_sha256"] != digest
                || report["container_absent"] != true
                || report["container_cgroup_absent"] != true
                || report["client_cgroup_drained"] != true
                || report["build_profile_removed"] != true
                || report["artifact_admitted"] != false
                || report["execution_eligible"] != false
                || report["guard_causality_verified"] != false
                || report["model_requests"] != 0
            {
                return Err("dependency report differs from retained intent or cleanup".into());
            }
            crate::dependency_podman::verify_completed_absent(
                &intent,
                report["container_id"]
                    .as_str()
                    .ok_or("dependency CID missing")?,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn client_group_absent(job: &str) -> Result<(), String> {
    let path = format!("/sys/fs/cgroup/system.slice/hol-gauntlet-rust-candidate-{job}");
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("dependency client cgroup absence uncertain".into()),
    }
}
