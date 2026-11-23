//! A failed build retains logs before authenticated retirement; it never gains an artifact.
use crate::candidate_host_anchor::{HostCandidateRunAnchor, HOST_ANCHOR_FILE};
use crate::candidate_repair::retain_failed_metadata as once;
use crate::candidate_result_read::{
    parse_failed_result, root_file_hash, HostBoundCandidateResultPins,
};
use crate::native_job_storage::artifact::{
    failed_export_body as expected_export, failure_wrapper as wrapper,
};
use crate::native_job_storage::linux::canonical;
use crate::native_job_storage::source::FAILED_BUILD_FIELDS as FIELDS;
use crate::native_job_storage::{
    lifecycle, linux, owner, source, JobStoragePins, JobStorageProfile,
};
use crate::native_public_archive::{encode_failed, PublicFiles};
use rustix::fs::{fstat, AtFlags};
use serde_json::{json, Value};
use std::{
    io,
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
};

const INTENT: &str = "failed-build-export-intent.json";
const EXPORT: &str = "failed-build-export.json";
const MANIFEST: &str = "failed-build-manifest.json";
const SOURCE: &str = "failed-build-source.json";
const ACK: &str = "failed-build-ack.json";
const LIMIT: usize = 32 * 1024 * 1024 + 65536;
struct Pins(Value);
impl Pins {
    fn new(args: &[String]) -> Result<Self, String> {
        let mut value = serde_json::Map::new();
        for (key, raw) in FIELDS.into_iter().zip(&args[2..11]) {
            let n = if key == "source_sha" {
                40
            } else if key == "job_id" {
                16
            } else {
                64
            };
            if !crate::hex(raw, n) {
                return Err("exact original failed-build public pins required".into());
            }
            value.insert(key.into(), json!(raw));
        }
        Ok(Self(Value::Object(value)))
    }
    fn text(&self, key: &str) -> &str {
        self.0[key].as_str().unwrap_or("")
    }
    fn body(&self, schema: &str) -> Value {
        let mut v = self.0.clone();
        v["schema"] = json!(schema);
        v
    }
    fn slot(&self) -> Result<OwnedFd, String> {
        let base = crate::open_root_owned_public_directory(Path::new(lifecycle::BASE))
            .map_err(|e| e.to_string())?;
        crate::feature_files::open_directory(&base, self.text("job_id"), (0, 0))
    }
}
fn read(root: &OwnedFd, name: &str) -> Result<Option<Value>, String> {
    crate::feature_files::read(root, name, (0, 0), 0o600, 49152)?
        .map(|raw| {
            let v: Value =
                serde_json::from_slice(&raw).map_err(|_| "failed-build retained JSON invalid")?;
            if canonical(&v)? != raw {
                return Err("canonical failed-build metadata required".into());
            }
            Ok(v)
        })
        .transpose()
}
fn required(root: &OwnedFd, name: &str) -> Result<Value, String> {
    read(root, name)?
        .ok_or_else(|| format!("original failed-build {name} absent; preserve uncertainty"))
}

struct Observed {
    root: OwnedFd,
    source: Value,
    result: Value,
    anchor: Vec<u8>,
}
fn observe(p: &Pins) -> Result<Observed, String> {
    owner::enter_pinned(
        p.text("source_sha"),
        p.text("job_id"),
        p.text("original_worker_generation"),
    )?;
    let root = crate::builder_candidate_source::open_fixed_build_slot(p.text("job_id"))
        .map_err(|e| e.to_string())?;
    let original = source::verify(p.text("job_id"), &root, Some(JobStorageProfile::Build))?
        .ok_or("original bounded Build Source absent")?;
    source::failed_source_matches(&p.0, &original)?;
    let (anchor_raw, anchor_sha) =
        root_file_hash(&root, HOST_ANCHOR_FILE, 8192, 0o600, false).map_err(|e| e.to_string())?;
    if anchor_sha != p.text("host_anchor_sha256") {
        return Err("failed-build original Host anchor differs".into());
    }
    if crate::feature_files::required(&root, HOST_ANCHOR_FILE, (0, 0), 0o600, 8192)? != anchor_raw {
        return Err("failed-build original Host anchor custody changed".into());
    }
    let c = crate::candidate_repair::context(
        &anchor_raw,
        p.text("job_id"),
        p.text("source_sha"),
        &anchor_sha,
    )?;
    let a = &c.anchor;
    if a["host_pin_sha256"] != p.0["host_pin_sha256"]
        || a["source_archive_sha256"] != p.0["source_archive_sha256"]
    {
        return Err("failed-build official Host pin differs from retained anchor".into());
    }
    crate::builder_candidate_preflight::verify_candidate_runtime(&c.runtime)
        .map_err(|e| e.to_string())?;
    let anchor = match a["tag"].as_str() {
        Some(tag) => HostCandidateRunAnchor::parse_with_tag(
            a["policy_sha256"].as_str().unwrap_or(""),
            a["result_reader_binary_sha256"].as_str().unwrap_or(""),
            p.text("host_pin_sha256"),
            a["host_nonce_hex"].as_str().unwrap_or(""),
            a["runner_binary_sha256"].as_str().unwrap_or(""),
            tag,
        ),
        None => HostCandidateRunAnchor::parse(
            a["policy_sha256"].as_str().unwrap_or(""),
            a["result_reader_binary_sha256"].as_str().unwrap_or(""),
            p.text("host_pin_sha256"),
            a["host_nonce_hex"].as_str().unwrap_or(""),
            a["runner_binary_sha256"].as_str().unwrap_or(""),
        ),
    }
    .ok_or("original failed-build anchor invalid")?;
    let bound = HostBoundCandidateResultPins {
        job_id: p.text("job_id").into(),
        source_sha: p.text("source_sha").into(),
        source_archive_sha256: p.text("source_archive_sha256").into(),
        result_sha256: p.text("result_sha256").into(),
        archive_sha256: String::new(),
        version: a["version"].as_str().unwrap_or("").into(),
        tag: a["tag"].as_str().map(str::to_owned),
        controller_tree_sha256: a["controller_tree_sha256"].as_str().unwrap_or("").into(),
        image_id: a["image_id"].as_str().unwrap_or("").into(),
        policy_sha256: a["policy_sha256"].as_str().unwrap_or("").into(),
        runtime: c.runtime.clone(),
        anchor,
    };
    let (raw, hash) = root_file_hash(&root, "candidate-run.result.json", 8192, 0o600, false)
        .map_err(|e| e.to_string())?;
    if hash != p.text("result_sha256") {
        return Err("failed-build result differs from outside SHA".into());
    }
    if crate::feature_files::required(&root, "candidate-run.result.json", (0, 0), 0o600, 8192)?
        != raw
    {
        return Err("failed-build original result custody changed".into());
    }
    let result = parse_failed_result(&raw, &bound).map_err(|e| e.to_string())?;
    if result["host_anchor_sha256"] != anchor_sha
        || result["source_bytes"]
            != crate::builder_candidate_source::verify_captured_source(
                &root,
                p.text("source_archive_sha256"),
            )
            .map_err(|e| e.to_string())?
    {
        return Err("failed-build source or original anchor changed".into());
    }
    if crate::builder_candidate_source::unadmitted_export_identity(&root)
        .map_err(|e| e.to_string())?
        .is_some()
        || !matches!(
            rustix::fs::statat(&root, "candidate.zip", AtFlags::SYMLINK_NOFOLLOW),
            Err(rustix::io::Errno::NOENT)
        )
    {
        return Err("failed build unexpectedly retains an artifact".into());
    }
    for (key, prefix) in [
        (
            "runner_binary_sha256",
            "rust-candidate-run-hostbound-shadow",
        ),
        (
            "result_reader_binary_sha256",
            "rust-candidate-result-hostbound-shadow",
        ),
    ] {
        let sha = a[key].as_str().unwrap_or("");
        crate::builder_candidate_preflight::verify_file(
            &format!("/opt/hol-gauntlet/{prefix}-{sha}"),
            sha,
            true,
            64 * 1024 * 1024,
        )
        .map_err(|e| e.to_string())?;
    }
    let container = crate::candidate_host_anchor::CandidateContainer::restore(
        &c.plan,
        a["image_id"].as_str().unwrap_or(""),
        a["runtime_pins"]["podman_sha256"].as_str().unwrap_or(""),
        &anchor_sha,
        &root,
    )?;
    container.verify_absent()?;
    crate::candidate_capture::inactive(p.text("job_id")).map_err(|e| e.to_string())?;
    crate::require_rust_job_slice_absent(p.text("job_id")).map_err(|e| e.to_string())?;
    crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
    crate::native_job_storage::temporary::require_all_absent(p.text("job_id"))?;
    let pid = result["client_pid"].as_u64().unwrap() as u32;
    match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(raw)
            if crate::linux_process::parse_proc_stat(&raw, pid)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed failed-build client stat",
                    )
                    .to_string()
                })?
                .start_ticks
                == result["client_start_ticks"].as_u64().unwrap() =>
        {
            return Err("original failed-build client still exists".into())
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("failed-build client absence unknown".into()),
    }
    Ok(Observed {
        root,
        source: original,
        result,
        anchor: anchor_raw,
    })
}
fn collect(p: &Pins) -> Result<(Vec<u8>, Value, Value), String> {
    let observed = observe(p)?;
    let mut captured = PublicFiles::default();
    for (name, key) in [
        ("candidate-run.stdout.log", "stdout_sha256"),
        ("candidate-run.stderr.log", "stderr_sha256"),
    ] {
        let (raw, hash) = root_file_hash(&observed.root, name, 16 * 1024 * 1024, 0o600, true)
            .map_err(|e| e.to_string())?;
        if observed.result[key] != hash
            || !captured.capture(&observed.root, name, name, (0, 0), 0o600)?
            || captured.files[name] != raw
        {
            return Err("failed-build retained log hash or custody differs".into());
        }
    }
    let mut binding = p.body("hol-gauntlet-failed-build-evidence.v1");
    for key in ["status", "exit_code", "client_pid", "client_start_ticks"] {
        binding[key] = observed.result[key].clone();
    }
    binding["original_runner_generation"] = observed.result["runner_binary_sha256"].clone();
    binding["original_result_reader_generation"] =
        observed.result["result_reader_binary_sha256"].clone();
    binding["qualification_eligible"] = json!(false);
    let archive = encode_failed(captured, binding)?;
    let mut tar = tar::Archive::new(archive.as_slice());
    let mut manifest = None;
    use std::io::Read;
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if entry.path().map_err(|e| e.to_string())?.as_ref() == Path::new("results.sha256.json") {
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw).map_err(|e| e.to_string())?;
            manifest = Some(serde_json::from_slice(&raw).map_err(|e| e.to_string())?);
        }
    }
    let after = observe(p)?;
    if after.source != observed.source
        || after.result != observed.result
        || after.anchor != observed.anchor
        || fstat(&after.root).map_err(|e| e.to_string())?.st_ino
            != fstat(&observed.root).map_err(|e| e.to_string())?.st_ino
    {
        return Err("original failed-build custody changed during capture".into());
    }
    Ok((
        archive,
        manifest.ok_or("failed-build manifest absent")?,
        observed.source,
    ))
}
fn retained_export(p: &Pins, slot: &OwnedFd) -> Result<Value, String> {
    if required(slot, INTENT)? != p.body("hol-gauntlet-failed-build-export-intent.v1") {
        return Err("original failed-build export intent changed".into());
    }
    let v = required(slot, EXPORT)?;
    let r = &v["receipt"];
    let m = required(slot, MANIFEST)?;
    source::failed_source_matches(&p.0, &required(slot, SOURCE)?)?;
    let mut expected = p.body("hol-gauntlet-failed-build-export.v1");
    for key in ["archive_sha256", "archive_bytes"] {
        expected[key] = r[key].clone();
    }
    expected["manifest_sha256"] = json!(linux::sha(&canonical(&m)?));
    expected["exit_code"] = m["exit_code"].clone();
    expected["execution_eligible"] = json!(false);
    expected["qualification_eligible"] = json!(false);
    if !crate::hex(r["archive_sha256"].as_str().unwrap_or(""), 64)
        || !r["archive_bytes"]
            .as_u64()
            .is_some_and(|n| (1..=LIMIT as u64).contains(&n))
        || v != wrapper("hol-gauntlet-failed-build-export-result.v1", expected)?
    {
        return Err("original failed-build export receipt changed".into());
    }
    Ok(v)
}
fn export(p: &Pins, slot: &OwnedFd, initial: Option<(u64, bool)>) -> Result<Vec<u8>, String> {
    if let Some((count, resume)) = initial {
        if read(slot, INTENT)?.is_some() && !resume {
            return Err("failed-build export consumed; use explicit read".into());
        }
        if !(1..=8192).contains(&count) {
            return Err("bounded private original Host anchor required".into());
        }
        let mut raw = Vec::new();
        let hash = crate::native_source_stream::copy_source(
            std::io::stdin().as_raw_fd(),
            &mut raw,
            count,
            &crate::BoottimeDeadline::start(30).map_err(|e| e.to_string())?,
            crate::native_worker::cancellation_requested,
        )?;
        let first = observe(p)?;
        if hash != p.text("host_anchor_sha256") || first.anchor != raw {
            return Err("private original Host anchor differs".into());
        }
        once(
            slot,
            INTENT,
            &p.body("hol-gauntlet-failed-build-export-intent.v1"),
        )?;
    } else {
        retained_export(p, slot)?;
    }
    let (raw, manifest, original) = collect(p)?;
    let again = collect(p)?;
    if (raw.as_slice(), &manifest, &original) != (again.0.as_slice(), &again.1, &again.2) {
        return Err("failed-build evidence changed between captures".into());
    }
    if initial.is_none() {
        if retained_export(p, slot)? != expected_export(&p.0, &raw, &manifest)?
            || required(slot, SOURCE)? != original
            || required(slot, MANIFEST)? != manifest
        {
            return Err("original failed-build evidence changed during read".into());
        }
        return Ok(raw);
    }
    once(slot, SOURCE, &original)?;
    once(slot, MANIFEST, &manifest)?;
    once(slot, EXPORT, &expected_export(&p.0, &raw, &manifest)?)?;
    retained_export(p, slot)?;
    Ok(raw)
}

fn acknowledgement(
    p: &Pins,
    slot: &OwnedFd,
    export_sha: &str,
    host: &str,
    publish: bool,
) -> Result<Value, String> {
    let e = retained_export(p, slot)?;
    if e["receipt_sha256"] != export_sha {
        return Err("failed-build export receipt differs from Host pin".into());
    }
    let expected = crate::native_job_storage::artifact::failed_ack_body(&e, host)?;
    if publish {
        let (raw, m, _) = collect(p)?;
        if expected_export(&p.0, &raw, &m)? != e {
            return Err("failure evidence changed before Host acknowledgement".into());
        }
        once(slot, ACK, &expected)?;
    }
    if required(slot, ACK)? != expected {
        return Err("actual Root failure acknowledgement absent or changed".into());
    }
    Ok(expected)
}
fn retire(
    p: &Pins,
    slot: &OwnedFd,
    export_sha: &str,
    host: &str,
    generation: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    let e = retained_export(p, slot)?;
    let ack = acknowledgement(p, slot, export_sha, host, false)?;
    let original = required(slot, SOURCE)?;
    let pins = JobStoragePins {
        source_sha: p.text("source_sha"),
        job_id: p.text("job_id"),
        worker_generation: p.text("original_worker_generation"),
        mke2fs_sha256: original["storage"]["receipt"]["mke2fs_sha256"]
            .as_str()
            .ok_or("original formatter absent")?,
    };
    let authority = json!({"schema":"hol-gauntlet-failed-build-storage-retirement-authority.v1","export_receipt_sha256":e["receipt_sha256"],"host_ack_sha256":ack["receipt_sha256"],"host_receipt_sha256":host,"result_sha256":p.0["result_sha256"],"host_pin_sha256":p.0["host_pin_sha256"],"host_anchor_sha256":p.0["host_anchor_sha256"],"manifest_sha256":e["receipt"]["manifest_sha256"]});
    crate::native_job_storage::retire::retire(
        &pins,
        JobStorageProfile::Build,
        authority,
        Some(p.text("storage_receipt_sha256")),
        e["receipt"]["archive_sha256"].as_str(),
        generation,
        publish,
        || {
            let (raw, m, s) = collect(p)?;
            if s != original || expected_export(&p.0, &raw, &m)? != e {
                return Err("original failed-build evidence changed before retirement".into());
            }
            Ok(())
        },
    )
}
pub(crate) fn dispatch(args: &[String]) -> Result<Option<Vec<u8>>, String> {
    let selector = args.get(1).map(String::as_str).unwrap_or("");
    let expected = match selector {
        "--export-failed-build-evidence-v1" | "--resume-failed-build-evidence-v1" => 12,
        "--read-failed-build-evidence-v1" | "--read-failed-build-export-v1" => 11,
        "--ack-failed-build-evidence-v1" | "--read-failed-build-ack-v1" => 13,
        "--retire-failed-build-storage-v1" | "--read-failed-build-retirement-v1" => 14,
        _ => return Ok(None),
    };
    if args.len() != expected {
        return Err("exact fixed failed-build selector arguments required".into());
    }
    gauntlet_cell_rootfs::require_outside_root()?;
    let p = Pins::new(args)?;
    let _scope = owner::scope()?;
    if expected == 14 {
        crate::verify_running_binary(&args[13]).map_err(|e| e.to_string())?;
        return retire(
            &p,
            &p.slot()?,
            &args[11],
            &args[12],
            &args[13],
            selector == "--retire-failed-build-storage-v1",
        )
        .map(Some);
    }
    crate::verify_running_binary(p.text("reader_generation")).map_err(|e| e.to_string())?;
    let journal = crate::RunReservationJournal::open_root_owned(Path::new(
        crate::builder_image_context::RUST_STATE,
    ))
    .map_err(|e| e.to_string())?;
    let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let slot = p.slot()?;
    let raw = match selector {
        "--export-failed-build-evidence-v1" | "--resume-failed-build-evidence-v1" => export(
            &p,
            &slot,
            Some((
                args[11]
                    .parse()
                    .map_err(|_| "exact private Host anchor byte count required")?,
                selector == "--resume-failed-build-evidence-v1",
            )),
        )?,
        "--read-failed-build-evidence-v1" => export(&p, &slot, None)?,
        "--read-failed-build-export-v1" => {
            if required(&slot, INTENT)? != p.body("hol-gauntlet-failed-build-export-intent.v1") {
                return Err("original failed export intent differs".into());
            }
            let e = if read(&slot, EXPORT)?.is_some() {
                Some(retained_export(&p, &slot)?)
            } else {
                None
            };
            canonical(
                &json!({"schema":"hol-gauntlet-failed-build-export-state.v1","intent_sha256":linux::sha(&canonical(&p.body("hol-gauntlet-failed-build-export-intent.v1"))?),"export_complete":e.is_some(),"export":e,"retry_allowed":false}),
            )?
        }
        _ => canonical(&acknowledgement(
            &p,
            &slot,
            &args[11],
            &args[12],
            selector == "--ack-failed-build-evidence-v1",
        )?)?,
    };
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    Ok(Some(raw))
}
