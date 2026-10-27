//! Cross-job dependency uncertainty blocks further execution under the shared
//! worker lease. Completed records are checked against retained intent bytes.
use crate::{open_root_owned_public_directory, read_bounded_regular, RunReservationJournal};
use gauntlet_contracts::DependencyRunIntent;
use rustix::fs::{statat, AtFlags, Dir};
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
    crate::native_job_io::require_no_unknown_jobs(&journal)?;
    for entry in Dir::read_from(&journal.root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "dependency state filename UTF-8")?;
        if !name.ends_with(".report.json") {
            continue;
        }
        let raw = read_bounded_regular(&journal.root, name, 16384)
            .map_err(|e| e.to_string())?
            .ok_or("dependency report disappeared")?;
        let report: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let intent_raw = gauntlet_contracts::canonicalize(report["intent"].to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        let intent = DependencyRunIntent::parse(&intent_raw)?;
        if name != format!("{}.report.json", intent.pins.text("job_id"))
            || report["schema"] != "hol-gauntlet-native-dependency-result.v1"
            || report["intent_sha256"] != intent.digest()?
            || report["container_absent"] != true
            || report["container_cgroup_absent"] != true
            || report["client_cgroup_drained"] != true
            || report["build_profile_removed"] != true
            || report["artifact_admitted"] != false
            || report["execution_eligible"] != false
        {
            return Err("prior dependency result lacks cleanup identity".into());
        }
        let cid = report["container_id"]
            .as_str()
            .ok_or("prior dependency container identity missing")?;
        crate::dependency_podman::verify_completed_absent(&intent, cid)?;
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
