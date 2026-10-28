//! Source/terminal-bound inert prefix publication. This never launches Python,
//! imports dependencies, installs a package or grants execution eligibility.
use crate::dependency_archive_read::{DependencyArchivePins, MAX_ARCHIVE};
use crate::dependency_prefix_write::{PARTIAL, PREFIX, RECEIPT};
use crate::{RunReservationJournal, TerminalOutcome};
use gauntlet_contracts::{canonicalize, DependencyRunIntent};
use gauntlet_evidence::{inventory_tree, TreeKind};
use rustix::fs::{fchmod, fstat, fsync, renameat_with, statat, AtFlags, Mode, RenameFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct DependencyPrefixPins<'a> {
    pub job_id: &'a str,
    pub intent_sha256: &'a str,
    pub result_sha256: &'a str,
    pub archive_sha256: &'a str,
    pub python_sha256: &'a str,
    pub stage_generation: &'a str,
}

fn python(expected: &str) -> Result<(), String> {
    crate::builder_candidate_preflight::verify_file(
        "/usr/bin/python3.12",
        expected,
        true,
        64 * 1024 * 1024,
    )
    .map_err(|e| e.to_string())
}

fn retained_result(
    intent: &DependencyRunIntent,
    result_hash: &str,
    archive_hash: &str,
) -> Result<(), String> {
    let p = &intent.pins;
    let job = p.text("job_id");
    let digest = intent.digest()?;
    let journal = RunReservationJournal::open_root_owned(Path::new(crate::dependency_state::STATE))
        .map_err(|e| e.to_string())?;
    let terminal = journal
        .terminal(
            job,
            p.text("source_sha"),
            &digest,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?
        .ok_or("dependency run has no terminal; repaired data cannot supply a prefix")?;
    if terminal.status != TerminalOutcome::InvalidEvidence
        || terminal.exit_code != 0
        || terminal.report_sha256 != result_hash
    {
        return Err("successful dependency producer result differs from outside pin".into());
    }
    let raw = crate::dependency_io::read(
        &journal.root,
        &format!("{job}.report.json"),
        0,
        0o600,
        16384,
    )?;
    if format!("{:x}", Sha256::digest(&raw)) != result_hash {
        return Err("dependency result file differs".into());
    }
    let report: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if report["schema"] != "hol-gauntlet-native-dependency-result.v1"
        || report["captured_dependencies_sha256"] != archive_hash
        || report["exit_code"] != 0
        || report["execution_error"] != Value::Null
        || report["artifact_admitted"] != false
        || report["execution_eligible"] != false
        || report["guard_causality_verified"] != false
        || report["model_requests"] != 0
    {
        return Err("dependency result cannot supply inert prefix data".into());
    }
    Ok(())
}

fn tree_path(job: &str, name: &str) -> PathBuf {
    Path::new("/var/lib/hol-gauntlet/builds")
        .join(job)
        .join(name)
}

pub fn stage_native_dependency_prefix(pins: &DependencyPrefixPins<'_>) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if !crate::hex(pins.job_id, 16)
        || ![
            pins.intent_sha256,
            pins.result_sha256,
            pins.archive_sha256,
            pins.python_sha256,
            pins.stage_generation,
        ]
        .iter()
        .all(|s| crate::hex(s, 64))
    {
        return Err("complete outside dependency prefix pins required".into());
    }
    crate::verify_running_binary(pins.stage_generation).map_err(|e| e.to_string())?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    crate::native_job_io::require_no_unknown_jobs(&journal)?;
    crate::dependency_state::require_idle()?;
    let intent = crate::dependency_repair::intent_for_job(pins.job_id, pins.intent_sha256)?;
    retained_result(&intent, pins.result_sha256, pins.archive_sha256)?;
    python(pins.python_sha256)?;
    if crate::builder_image_build::free_bytes().map_err(|e| e.to_string())?
        < 12 * 1024 * 1024 * 1024
    {
        return Err("inert prefix staging lacks disk reserve".into());
    }
    let slot = crate::builder_candidate_source::open_fixed_build_slot(pins.job_id)
        .map_err(|e| e.to_string())?;
    let raw = crate::dependency_io::read(&slot, "dependencies.zip", 0, 0o444, MAX_ARCHIVE as u64)?;
    let p = &intent.pins;
    let archive_pins = DependencyArchivePins {
        job_id: pins.job_id,
        source_sha: p.text("source_sha"),
        archive_sha256: pins.archive_sha256,
        pyproject_sha256: p.text("pyproject_sha256"),
        uv_lock_sha256: p.text("uv_lock_sha256"),
    };
    if crate::native_worker::cancellation_requested() {
        return Err("dependency prefix cancelled before reservation".into());
    }
    let (target, proof) =
        crate::dependency_prefix_write::write_private_prefix(&slot, &raw, &archive_pins)?;
    fchmod(&target, Mode::from_bits_truncate(0o755)).map_err(|e| e.to_string())?;
    fsync(&target).map_err(|e| e.to_string())?;
    let partial = inventory_tree(&tree_path(pins.job_id, PARTIAL), TreeKind::InstalledPrefix)
        .map_err(|e| e.to_string())?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    crate::dependency_io::verify_inputs(&slot, &intent)?;
    retained_result(&intent, pins.result_sha256, pins.archive_sha256)?;
    python(pins.python_sha256)?;
    if crate::dependency_io::read(&slot, "dependencies.zip", 0, 0o444, MAX_ARCHIVE as u64)? != raw {
        return Err("captured dependency ZIP changed during staging".into());
    }
    crate::verify_running_binary(pins.stage_generation).map_err(|e| e.to_string())?;
    if crate::native_worker::cancellation_requested() {
        return Err("dependency prefix cancelled; preserve partial".into());
    }
    if crate::builder_image_build::free_bytes().map_err(|e| e.to_string())? < 8 * 1024 * 1024 * 1024
    {
        return Err("dependency prefix publication crossed disk reserve; preserve partial".into());
    }
    renameat_with(&slot, PARTIAL, &slot, PREFIX, RenameFlags::NOREPLACE)
        .map_err(|_| "dependency prefix publication uncertain")?;
    fsync(&slot).map_err(|e| e.to_string())?;
    let held = fstat(&target).map_err(|e| e.to_string())?;
    let visible = statat(&slot, PREFIX, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    let final_tree = inventory_tree(&tree_path(pins.job_id, PREFIX), TreeKind::InstalledPrefix)
        .map_err(|e| e.to_string())?;
    if !crate::dependency_prefix_meta::same(&held, &visible)
        || final_tree.digest != partial.digest
        || final_tree.bytes != partial.bytes
        || final_tree.entries != partial.entries
    {
        return Err("published dependency prefix changed".into());
    }
    let value = json!({"schema":"hol-gauntlet-native-dependency-prefix.v1","job_id":pins.job_id,"source_sha":p.text("source_sha"),
        "source_archive_sha256":p.text("source_archive_sha256"),"intent_sha256":pins.intent_sha256,"result_sha256":pins.result_sha256,
        "dependency_archive_sha256":pins.archive_sha256,"pyproject_sha256":p.text("pyproject_sha256"),"uv_lock_sha256":p.text("uv_lock_sha256"),
        "run_generation":p.text("runner_binary_sha256"),"stage_generation":pins.stage_generation,"python_sha256":pins.python_sha256,"python_path":"/usr/bin/python3.12",
        "prefix_tree_sha256":final_tree.digest,"prefix_entries":final_tree.entries,"prefix_bytes":final_tree.bytes,
        "dependency_files":proof.files.len(),"dependency_entry_bytes_sha256":proof.entry_bytes_sha256,
        "artifact_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    let digest =
        crate::builder_candidate_receipt::write_root_canonical_job_file(&slot, RECEIPT, &value)
            .map_err(|e| e.to_string())?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    verify_published_dependency_prefix(pins.job_id, &digest, p.text("source_sha"))?;
    canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string())
}

/// Caller holds the shared worker leases. This verifies a separate published
/// data prefix against its outside receipt hash; it never adopts a partial.
pub(crate) fn verify_published_dependency_prefix(
    job: &str,
    receipt_sha256: &str,
    source_sha: &str,
) -> Result<(PathBuf, String), String> {
    if !crate::hex(job, 16) || !crate::hex(receipt_sha256, 64) || !crate::hex(source_sha, 40) {
        return Err("outside dependency prefix identity required".into());
    }
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let raw = crate::dependency_io::read(&slot, RECEIPT, 0, 0o600, 8192)?;
    if format!("{:x}", Sha256::digest(&raw)) != receipt_sha256
        || canonicalize(&raw).map_err(|e| e.to_string())? != raw
    {
        return Err("dependency prefix receipt differs from outside hash".into());
    }
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if v.as_object().is_none_or(|o| o.len() != 22)
        || v["schema"] != "hol-gauntlet-native-dependency-prefix.v1"
        || v["job_id"] != job
        || v["source_sha"] != source_sha
        || v["artifact_admitted"] != false
        || v["execution_eligible"] != false
        || v["guard_causality_verified"] != false
        || v["model_requests"] != 0
        || v["python_path"] != "/usr/bin/python3.12"
    {
        return Err("dependency prefix receipt claims authority or differs from identity".into());
    }
    let text = |key: &str| {
        v[key]
            .as_str()
            .filter(|s| crate::hex(s, 64))
            .ok_or("dependency prefix digest missing")
    };
    let intent = crate::dependency_repair::intent_for_job(job, text("intent_sha256")?)?;
    if intent.pins.text("source_sha") != source_sha
        || v["source_archive_sha256"] != intent.pins.text("source_archive_sha256")
        || v["pyproject_sha256"] != intent.pins.text("pyproject_sha256")
        || v["uv_lock_sha256"] != intent.pins.text("uv_lock_sha256")
        || v["run_generation"] != intent.pins.text("runner_binary_sha256")
        || !v["stage_generation"]
            .as_str()
            .is_some_and(|s| crate::hex(s, 64))
    {
        return Err("dependency prefix differs from retained input intent".into());
    }
    retained_result(
        &intent,
        text("result_sha256")?,
        text("dependency_archive_sha256")?,
    )?;
    python(text("python_sha256")?)?;
    let archive =
        crate::dependency_io::read(&slot, "dependencies.zip", 0, 0o444, MAX_ARCHIVE as u64)?;
    let proof = crate::inspect_dependency_archive(
        &archive,
        &DependencyArchivePins {
            job_id: job,
            source_sha,
            archive_sha256: text("dependency_archive_sha256")?,
            pyproject_sha256: intent.pins.text("pyproject_sha256"),
            uv_lock_sha256: intent.pins.text("uv_lock_sha256"),
        },
    )?;
    let path = tree_path(job, PREFIX);
    let tree = inventory_tree(&path, TreeKind::InstalledPrefix).map_err(|e| e.to_string())?;
    if v["prefix_tree_sha256"] != tree.digest
        || v["prefix_entries"] != tree.entries
        || v["prefix_bytes"] != tree.bytes
        || v["dependency_files"] != proof.files.len()
        || v["dependency_entry_bytes_sha256"] != proof.entry_bytes_sha256
    {
        return Err("dependency prefix tree or archive changed".into());
    }
    Ok((path, tree.digest))
}
