//! Preserve incomplete Root report/terminal files; retire only absent resources.
use crate::dependency_preparation::{metadata, retained, DependencyLeases};
use crate::RunReservationJournal;
use gauntlet_contracts::{DependencyCompletionState, DependencyRunIntent};
use rustix::fs::{statat, AtFlags};
use serde_json::Value;
use std::os::fd::OwnedFd;

/// An acknowledged, retired source volume is not reopened for an idle scan.
/// Its original terminal still authenticates the retained intent and report.
pub(crate) fn retired_storage_completion(
    journal: &RunReservationJournal,
    job: &str,
    start_raw: &[u8],
    read: &Value,
) -> Result<(), String> {
    use gauntlet_contracts::canonicalize;
    use sha2::{Digest, Sha256};
    if canonicalize(start_raw).map_err(|e| e.to_string())? != start_raw {
        return Err("canonical retired dependency start required".into());
    }
    let start: Value = serde_json::from_slice(start_raw).map_err(|e| e.to_string())?;
    let text = |key: &str| {
        start[key]
            .as_str()
            .ok_or("retired dependency start pin absent")
    };
    let (source, digest, generation) = (
        text("source_sha")?,
        text("deployment_digest")?,
        text("worker_generation")?,
    );
    let terminal = journal
        .terminal(job, source, digest, generation)
        .map_err(|e| e.to_string())?
        .ok_or("retired dependency lacks original completed terminal")?;
    if terminal.status != crate::TerminalOutcome::InvalidEvidence
        || terminal.exit_code != 0
        || terminal.controller_public_key_hex.is_some()
        || !matches!(
            statat(
                &journal.root,
                format!("{job}.dependency-repair.json"),
                AtFlags::SYMLINK_NOFOLLOW
            ),
            Err(rustix::io::Errno::NOENT)
        )
    {
        return Err("retired dependency terminal is incomplete or conflicts with repair".into());
    }
    let raw = crate::dependency_io::read(
        &journal.root,
        &format!("{job}.report.json"),
        0,
        0o600,
        16384,
    )?;
    let report: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let intent = DependencyRunIntent::parse(
        &canonicalize(report["intent"].to_string().as_bytes()).map_err(|e| e.to_string())?,
    )?;
    let public = gauntlet_contracts::verify_dependency_run_result(&intent, &raw)?;
    let started = journal
        .started(job, source, digest, generation)
        .map_err(|e| e.to_string())?
        .ok_or("retired dependency original reservation absent")?;
    let running = journal
        .running_marker(job, source, digest, generation)
        .map_err(|e| e.to_string())?
        .ok_or("retired dependency original process marker absent")?;
    if intent.pins.text("job_id") != job
        || intent.pins.text("source_sha") != source
        || intent.pins.text("runner_binary_sha256") != generation
        || intent.digest()? != digest
        || terminal.report_sha256 != format!("{:x}", Sha256::digest(&raw))
        || read["source_capture"]["source_sha"] != source
        || read["result_sha256"] != terminal.report_sha256
        || read["host_binding_sha256"] != digest
        || read["archive_sha256"] != public["captured_dependencies_sha256"]
        || public["exit_code"] != 0
        || terminal.started_marker_sha256 != started.sha256
        || report["started_marker_sha256"] != started.sha256
        || running.process != terminal.process
        || running.cgroup != format!("/system.slice/hol-gauntlet-rust-candidate-{job}")
    {
        return Err(
            "retired dependency differs from acknowledged original terminal/archive/intent".into(),
        );
    }
    match std::fs::read(format!("/proc/{}/stat", running.process.pid)) {
        Ok(raw)
            if crate::linux_process::parse_proc_stat(&raw, running.process.pid)
                .is_some_and(|s| s.start_ticks != running.process.start_ticks) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("retired dependency original client remains or is unknown".into()),
    }
    crate::dependency_podman::verify_completed_absent(
        &intent,
        report["container_id"]
            .as_str()
            .ok_or("retired dependency CID absent")?,
    )
}

/// Bind retained-report finalization to the exact expected terminal bytes.
/// Partial attempts remain private and supply no authority.
pub(crate) fn report_finalization(
    slot: &OwnedFd,
    context: &serde_json::Value,
    create: bool,
) -> Result<(), String> {
    use gauntlet_contracts::canonicalize;
    use rustix::fs::Dir;
    const PREFIX: &str = "dependency-report-finalization-";
    let mut count = 0;
    let mut matched = false;
    for entry in Dir::read_from(slot).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_name().to_bytes().starts_with(PREFIX.as_bytes()) {
            continue;
        }
        count += 1;
        if count > 64 {
            return Err("report finalization attempt bound exceeded".into());
        }
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "finalization filename UTF-8")?;
        let id = name
            .strip_prefix(PREFIX)
            .and_then(|s| s.strip_suffix(".json"))
            .filter(|s| crate::hex(s, 16))
            .ok_or("report finalization name differs")?;
        let raw = crate::feature_files::required(slot, name, (0, 0), 0o600, 8192)?;
        let value: serde_json::Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) if e.is_eof() => continue,
            Err(_) => return Err("report finalization record is malformed".into()),
        };
        let generation = value["finalizer_generation"]
            .as_str()
            .filter(|s| crate::hex(s, 64))
            .ok_or("report finalizer generation missing")?;
        let mut expected = context.clone();
        expected["attempt_id"] = serde_json::json!(id);
        expected["finalizer_generation"] = serde_json::json!(generation);
        if canonicalize(expected.to_string().as_bytes()).map_err(|e| e.to_string())? != raw {
            return Err("report finalization binding differs".into());
        }
        matched |= context["finalizer_generation"].is_null()
            || context["finalizer_generation"] == generation;
    }
    if create {
        if count >= 64 {
            return Err("report finalization attempt bound exceeded".into());
        }
        let id = crate::dependency_creator_recovery::attempt()?;
        let mut value = context.clone();
        value["attempt_id"] = serde_json::json!(id);
        crate::builder_candidate_receipt::write_root_canonical_job_file(
            slot,
            &format!("{PREFIX}{id}.json"),
            &value,
        )
        .map_err(|e| e.to_string())?;
    } else if !matched {
        return Err("matching report finalization witness missing".into());
    }
    Ok(())
}

fn incomplete_object(raw: &[u8]) -> bool {
    (raw.is_empty() || raw.first() == Some(&b'{'))
        && serde_json::from_slice::<Value>(raw).is_err_and(|e| e.is_eof())
}
fn sync_record(dir: &std::os::fd::OwnedFd, name: &str, bound: usize) -> Result<(), String> {
    use rustix::fs::{fstat, fsync, openat, Mode, OFlags};
    let Some(before) = retained(dir, name, bound)? else {
        return Ok(());
    };
    let fd = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    if metadata(&fstat(&fd).map_err(|e| e.to_string())?) != before.1 {
        return Err("completion file changed before sync".into());
    }
    fsync(&fd).map_err(|e| e.to_string())?;
    if retained(dir, name, bound)?.as_ref() != Some(&before) {
        return Err("completion file changed during sync".into());
    }
    Ok(())
}
fn needs_retirement(
    report: &[u8],
    terminal: Option<&[u8]>,
    expected: Option<&[u8]>,
) -> Result<bool, String> {
    if incomplete_object(report) {
        if terminal.is_some() {
            return Err("partial dependency report conflicts with any terminal".into());
        }
        return Ok(true);
    }
    if serde_json::from_slice::<Value>(report).is_err() {
        return Err("malformed dependency report cannot be retired".into());
    }
    let Some(terminal) = terminal else {
        return Ok(false);
    };
    let expected = expected.ok_or("verified full report terminal recipe required")?;
    if terminal == expected {
        return Ok(false);
    }
    if !incomplete_object(terminal) || !expected.starts_with(terminal) {
        return Err("partial dependency terminal differs from verified full report".into());
    }
    Ok(true)
}
fn snapshot(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
) -> Result<Option<DependencyCompletionState>, String> {
    let p = &intent.pins;
    let job = p.text("job_id");
    let report = retained(&journal.root, &format!("{job}.report.json"), 16384)?;
    let terminal = retained(&journal.root, &format!("{job}.terminal.json"), 2048)?;
    let Some(report) = report else {
        if terminal.is_some() {
            return Err("orphan dependency terminal remains unknown".into());
        }
        return Ok(None);
    };
    // Complete historical terminals keep their existing validation path.
    if !incomplete_object(&report.0) && terminal.as_ref().is_none_or(|s| !incomplete_object(&s.0)) {
        return Ok(None);
    }
    let expected = if !incomplete_object(&report.0) && terminal.is_some() {
        Some(crate::dependency_state::expected_terminal(journal, intent)?)
    } else {
        None
    };
    if !needs_retirement(
        &report.0,
        terminal.as_ref().map(|s| s.0.as_slice()),
        expected.as_deref(),
    )? {
        return Ok(None);
    }
    match statat(
        &journal.root,
        format!("{job}.controller-key.json"),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(rustix::io::Errno::NOENT) => {}
        _ => return Err("keyed dependency completion is outside retirement".into()),
    }
    // Nothing is adopted or signalled. Absence precedes any runtime helper query.
    crate::dependency_state::client_group_absent(job)?;
    let runtime = crate::builder_candidate_preflight::CandidateRuntimePins::parse(
        p.text("podman_sha256"),
        p.text("slirp4netns_sha256"),
        p.text("apparmor_parser_sha256"),
        p.text("seccomp_sha256"),
    )
    .map_err(|e| e.to_string())?;
    crate::builder_candidate_preflight::verify_candidate_runtime_files(&runtime)
        .map_err(|e| e.to_string())?;
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    crate::dependency_io::verify_inputs(&slot, intent)?;
    let custody =
        crate::dependency_repair::body(journal, intent, p.text("runner_binary_sha256"), true)?;
    let state = DependencyCompletionState::inspect(
        intent,
        &custody,
        (&report.0, &report.1),
        terminal.as_ref().map(|s| (s.0.as_slice(), s.1.as_str())),
    )?;
    if retained(&journal.root, &format!("{job}.report.json"), 16384)?.as_ref() != Some(&report)
        || retained(&journal.root, &format!("{job}.terminal.json"), 2048)? != terminal
    {
        return Err("completion records changed while observing".into());
    }
    Ok(Some(state))
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
pub(crate) fn verified(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
) -> Result<Option<Vec<u8>>, String> {
    let Some(raw) = receipt(journal, intent.pins.text("job_id"))? else {
        return Ok(None);
    };
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if v["schema"] != "hol-gauntlet-native-dependency-repair.v5" {
        return Ok(None);
    }
    let generation = v["repair_generation"]
        .as_str()
        .ok_or("completion mutator pin missing")?;
    let state = snapshot(journal, intent)?.ok_or("retired completion state unavailable")?;
    if state.retired(intent, generation)? != raw {
        return Err("retired completion differs from original custody".into());
    }
    if receipt(journal, intent.pins.text("job_id"))?.as_deref() != Some(raw.as_slice()) {
        return Err("completion retirement changed while reading".into());
    }
    Ok(Some(raw))
}
pub(crate) fn observe(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    generation: &str,
) -> Result<Option<Vec<u8>>, String> {
    let Some(state) = snapshot(journal, intent)? else {
        return Ok(None);
    };
    let raw = state.unknown(intent, generation)?;
    if snapshot(journal, intent)? != Some(state) {
        return Err("completion observation changed".into());
    }
    Ok(Some(raw))
}
pub fn retire_native_dependency_completion(
    raw: &[u8],
    digest: &str,
    started: &str,
    original: &str,
    generation: &str,
    completion: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let intent = DependencyRunIntent::parse(raw)?;
    if intent.digest()? != digest || intent.pins.text("runner_binary_sha256") != original {
        return Err("completion retirement differs from original outside intent".into());
    }
    gauntlet_contracts::dependency_completion_authorization(
        &intent, started, generation, completion,
    )?;
    let held = DependencyLeases::acquire()?;
    let journal = &held.journal;
    if crate::dependency_repair::intent_for_job(intent.pins.text("job_id"), digest)? != intent {
        return Err("completion original intent differs".into());
    }
    let state = snapshot(journal, &intent)?.ok_or("incomplete completion record required")?;
    if state.sha256 != completion {
        return Err("completion snapshot differs from outside authorization".into());
    }
    if let Some(raw) = verified(journal, &intent)? {
        gauntlet_contracts::verify_dependency_repair_result(&intent, started, generation, &raw)?;
        held.verify()?;
        return Ok(raw);
    }
    if receipt(journal, intent.pins.text("job_id"))?.is_some() {
        return Err("foreign completion recovery record exists".into());
    }
    let result = state.retired(&intent, generation)?;
    let slot = crate::builder_candidate_source::open_fixed_build_slot(intent.pins.text("job_id"))
        .map_err(|e| e.to_string())?;
    held.verify()?;
    for (suffix, bound) in [("report.json", 16384), ("terminal.json", 2048)] {
        sync_record(
            &journal.root,
            &format!("{}.{suffix}", intent.pins.text("job_id")),
            bound,
        )?;
    }
    if snapshot(journal, &intent)? != Some(state) {
        return Err("completion changed before retirement".into());
    }
    crate::dependency_creator_recovery::publish(
        journal,
        &slot,
        &format!("{}.dependency-repair.json", intent.pins.text("job_id")),
        &result,
    )?;
    if verified(journal, &intent)?.as_deref() != Some(result.as_slice()) {
        return Err("completion retirement commit uncertain".into());
    }
    held.verify()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires outside Root; uses only isolated temporary inert files"]
    fn completion_sync_preserves_partial_bytes_inode_and_metadata() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        gauntlet_cell_rootfs::require_outside_root().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = rustix::fs::open(
            temp.path(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        sync_record(&dir, "absent", 16384).unwrap();
        for (name, raw) in [("empty", b"".as_slice()), ("partial", b"{".as_slice())] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(temp.path().join(name))
                .unwrap();
            file.write_all(raw).unwrap();
            drop(file);
            let before = retained(&dir, name, 16384).unwrap().unwrap();
            sync_record(&dir, name, 16384).unwrap();
            assert_eq!(retained(&dir, name, 16384).unwrap().unwrap(), before);
            assert_eq!(std::fs::read(temp.path().join(name)).unwrap(), raw);
        }
        std::os::unix::fs::symlink("partial", temp.path().join("alias")).unwrap();
        assert!(sync_record(&dir, "alias", 16384).is_err());
        std::fs::hard_link(temp.path().join("partial"), temp.path().join("linked")).unwrap();
        assert!(sync_record(&dir, "partial", 16384).is_err());
    }
    #[test]
    fn incomplete_completion_never_promotes_a_truncated_or_conflicting_outcome() {
        let report = br#"{"artifact_admitted":false,"exit_code":0,"schema":"fixture"}"#;
        let terminal = br#"{"exit_code":0,"report_sha256":"abcdef","status":"invalid-evidence"}"#;
        for end in 0..report.len() {
            assert!(needs_retirement(&report[..end], None, None).unwrap());
            assert!(needs_retirement(&report[..end], Some(b""), None).is_err());
        }
        assert!(!needs_retirement(report, None, None).unwrap());
        for end in 0..terminal.len() {
            assert!(needs_retirement(report, Some(&terminal[..end]), Some(terminal)).unwrap());
        }
        assert!(!needs_retirement(report, Some(terminal), Some(terminal)).unwrap());
        for bad in [
            b" ".as_slice(),
            b"[",
            b"n",
            b"{oops",
            b"garbage",
            b"{\"exit_code\":9",
        ] {
            assert!(needs_retirement(report, Some(bad), Some(terminal)).is_err());
        }
        for bad in [b" ".as_slice(), b"[", b"n", b"{oops", b"garbage"] {
            assert!(needs_retirement(bad, None, None).is_err());
        }
        assert!(needs_retirement(report, Some(b""), None).is_err());
    }
}
