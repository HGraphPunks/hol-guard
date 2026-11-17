//! Retain an original unsigned pre-ready failure without inventing a signature.
use crate::candidate_repair::retain_failed_metadata as once;
use crate::native_job_storage::{linux, owner, JobStoragePins, JobStorageProfile};
use crate::native_prelaunch::{
    failure_export_body as export_body, failure_retained_export as retained_export,
    READONLY_FAILURE_ARCHIVE_LIMIT as LIMIT,
};
use crate::native_prelaunch::{
    failure_intent as intent, failure_prepared as prepared, failure_read as read,
    failure_required as required, failure_retained_prelaunch as retained_prelaunch,
    failure_wrap as wrap, ReadonlyFailurePins as Pins, READONLY_FAILURE_PREFIX as PREFIX,
};
use crate::native_public_archive::{encode_profile, PublicFiles};
use crate::RunReservationJournal;
use gauntlet_contracts::{PrelaunchPrepared, WorkerRequest};
use rustix::fs::fstat;
use serde_json::{json, Value};
use std::{
    io::Read,
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
};

const INTENT: &str = "readonly-failure-intent.json";
const PRELAUNCH: &str = "readonly-failure-prelaunch.json";
const MANIFEST: &str = "readonly-failure-manifest.json";
const INITIAL: &str = "readonly-failure-initialization.json";
const EXPORT: &str = "readonly-failure-export.json";
const ACK: &str = "readonly-failure-ack.json";
struct Observation {
    root: OwnedFd,
    initial: Value,
    frame: Value,
    quiescent: Value,
}
fn observe(
    p: &Pins,
    pre: &PrelaunchPrepared,
    journal: &RunReservationJournal,
) -> Result<Observation, String> {
    owner::enter_pinned(&pre.source_sha, &pre.job_id, &pre.worker_generation)?;
    let (original, spec) = crate::native_keyed_startup_repair::retained(
        journal,
        &pre.source_sha,
        &pre.job_id,
        &pre.deployment_digest,
        &pre.worker_generation,
    )?;
    if original != *pre
        || !matches!(
            spec.execution,
            crate::NativeJobExecution::HostPinnedReadonlyHook(_)
        )
        || spec.preparation_sha256 != p.text("preparation_sha256")
    {
        return Err("only the original host-pinned read-only failure is supported".into());
    }
    let request=WorkerRequest::parse(json!({"schema":"hol-gauntlet-worker-request.v1","action":"run","source_sha":pre.source_sha,"job_id":pre.job_id,"deployment_digest":pre.deployment_digest}).to_string().as_bytes()).map_err(|e|e.to_string())?;
    let (_, preparation) = crate::native_job_io::load(&request, &pre.worker_generation)?;
    let (initial_raw, initial) = crate::native_initialize::checked_job_initialization(
        &pre.source_sha,
        &pre.job_id,
        &pre.worker_generation,
        false,
    )?;
    if initial["schema"] != "hol-gauntlet-native-job-initialization.v2"
        || initial["storage"]["receipt_sha256"] != p.0["storage_receipt_sha256"]
        || linux::canonical(&initial)? != initial_raw
    {
        return Err("unsigned-failure original bounded initialization differs".into());
    }
    let frame_raw = crate::native_completion::read_completion(
        journal,
        &pre.source_sha,
        &pre.job_id,
        &pre.deployment_digest,
        &pre.worker_generation,
    )?;
    let frame: Value = serde_json::from_slice(&frame_raw).map_err(|e| e.to_string())?;
    crate::native_completion::validate_readonly_failure(&frame, p, pre, &initial["storage"])?;
    let running = journal
        .running_marker(
            &pre.job_id,
            &pre.source_sha,
            &pre.deployment_digest,
            &pre.worker_generation,
        )
        .map_err(|e| e.to_string())?
        .ok_or("unsigned failure running identity absent")?;
    if frame["report"]["controller"]
        != json!({"pid":running.process.pid,"start_ticks":running.process.start_ticks})
    {
        return Err("unsigned failure running process differs".into());
    }
    crate::native_repair::controller_absent(&running)?;
    crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
    crate::native_job_storage::temporary::require_all_absent(&pre.job_id)?;
    let quiescent = gauntlet_cell_rootfs::verify_failed_native_preparation(&preparation)?;
    let root =
        crate::open_root_owned_public_directory(&spec.job_root()).map_err(|e| e.to_string())?;
    Ok(Observation {
        root,
        initial,
        frame,
        quiescent,
    })
}
fn capture(
    files: &mut PublicFiles,
    root: &OwnedFd,
    path: &str,
    member: &str,
    mode: libc::mode_t,
) -> Result<(), String> {
    if !files.capture(root, path, member, (0, 0), mode)? {
        return Err(format!("original failure evidence {member} absent"));
    }
    Ok(())
}
fn collect(
    p: &Pins,
    pre: &PrelaunchPrepared,
    journal: &RunReservationJournal,
) -> Result<(Vec<u8>, Value, Value), String> {
    let o = observe(p, pre, journal)?;
    let mut files = PublicFiles::default();
    for suffix in ["started", "controller-key", "running", "terminal", "report"] {
        capture(
            &mut files,
            &journal.root,
            &format!("{}.{}.json", pre.job_id, suffix),
            &format!("worker/{suffix}.json"),
            0o600,
        )?;
    }
    for suffix in ["stdout", "stderr"] {
        let member = format!("native.{suffix}");
        capture(
            &mut files,
            &o.root,
            &format!("{}.native.{suffix}", pre.job_id),
            &member,
            0o600,
        )?;
        if files.files[&member].len() > 1024 * 1024
            || o.frame["report"][format!("controller_{suffix}_sha256")]
                != linux::sha(&files.files[&member])
        {
            return Err("original failure log hash or bound differs".into());
        }
    }
    if !files.files["native.stdout"].is_empty() {
        return Err("unsigned failure stdout is not empty".into());
    }
    capture(
        &mut files,
        &o.root,
        "preparation.v1.json",
        "preparation.json",
        0o600,
    )?;
    let initial = crate::open_root_owned_public_directory(Path::new(
        "/var/lib/hol-gauntlet-rust/native-initialization",
    ))
    .map_err(|e| e.to_string())?;
    capture(
        &mut files,
        &initial,
        &format!("{}.job.json", pre.job_id),
        "initialization.json",
        0o600,
    )?;
    let declarations = crate::open_root_owned_public_directory(Path::new(
        crate::native_job_spec::NATIVE_DEPLOYMENTS,
    ))
    .map_err(|e| e.to_string())?;
    capture(
        &mut files,
        &declarations,
        &format!("{}.json", pre.deployment_digest),
        "declaration.json",
        0o600,
    )?;
    for name in [
        "native-rootfs.v1.json",
        "native-supervisor.v1.json",
        "system.json",
        "runtime.json",
        "task-mounts.json",
        "cell-artifact-manifest.json",
        "native-wire.v1.json",
    ] {
        capture(
            &mut files,
            &o.root,
            &format!("cell/{name}"),
            &format!("cell/{name}"),
            0o444,
        )?;
    }
    for name in [
        "native-image-events.v1.jsonl",
        "native-supervisor-events.v1.jsonl",
    ] {
        capture(
            &mut files,
            &o.root,
            &format!("cell/{name}"),
            &format!("cell/{name}"),
            0o600,
        )?;
    }
    capture(
        &mut files,
        &o.root,
        "cell/native-cell.apparmor",
        "cell/native-cell.apparmor",
        0o400,
    )?;
    if files.files.len() != 20
        || files.files.values().map(Vec::len).sum::<usize>() > 32 * 1024 * 1024
    {
        return Err("closed unsigned failure evidence bound differs".into());
    }
    for (member, v) in [
        ("worker/started.json", &o.frame["started"]),
        ("worker/controller-key.json", &o.frame["controller_key_pin"]),
        ("worker/terminal.json", &o.frame["terminal"]),
        ("worker/report.json", &o.frame["report"]),
        ("initialization.json", &o.initial),
    ] {
        if files.files[member] != linux::canonical(v)? {
            return Err("original failure record capture differs".into());
        }
    }
    if linux::sha(&files.files["preparation.json"]) != p.text("preparation_sha256")
        || linux::sha(&files.files["declaration.json"]) != pre.deployment_digest
    {
        return Err("failure preparation/declaration capture differs".into());
    }
    let mut manifest = p.body("evidence");
    manifest["status"] = json!("controller-failed-before-report");
    manifest["exit_code"] = o.frame["terminal"]["exit_code"].clone();
    manifest["controller"] = o.frame["report"]["controller"].clone();
    manifest["prelaunch"] = serde_json::from_slice(&pre.to_bytes().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    manifest["host_pin_sha256"] = json!(pre.host_record_sha256().map_err(|e| e.to_string())?);
    manifest["quiescent"] = o.quiescent.clone();
    manifest["qualification_eligible"] = json!(false);
    let archive = encode_profile(
        files,
        manifest,
        &format!("{PREFIX}-evidence.v1"),
        Value::Null,
    )?;
    if archive.len() > LIMIT {
        return Err("unsigned failure USTAR bound".into());
    }
    let mut tar = tar::Archive::new(archive.as_slice());
    let mut index = None;
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if entry.path().map_err(|e| e.to_string())?.as_ref() == Path::new("results.sha256.json") {
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw).map_err(|e| e.to_string())?;
            index = Some(serde_json::from_slice(&raw).map_err(|e| e.to_string())?);
        }
    }
    let after = observe(p, pre, journal)?;
    if after.initial != o.initial
        || after.frame != o.frame
        || after.quiescent != o.quiescent
        || !crate::dependency_prefix_meta::same(
            &fstat(&o.root).map_err(|e| e.to_string())?,
            &fstat(&after.root).map_err(|e| e.to_string())?,
        )
    {
        return Err("original unsigned failure changed while captured".into());
    }
    Ok((
        archive,
        index.ok_or("unsigned failure manifest absent")?,
        o.initial,
    ))
}
fn export(
    p: &Pins,
    root: &OwnedFd,
    journal: &RunReservationJournal,
    initial: Option<(u64, bool)>,
) -> Result<Vec<u8>, String> {
    let pre = if let Some((count, resume)) = initial {
        if !resume && (read(root, INTENT)?.is_some() || read(root, PRELAUNCH)?.is_some()) {
            return Err("unsigned failure export consumed; use explicit read/resume".into());
        }
        if !(1..=1024).contains(&count) {
            return Err("bounded original prelaunch required".into());
        }
        let mut raw = Vec::new();
        crate::native_source_stream::copy_source(
            std::io::stdin().as_raw_fd(),
            &mut raw,
            count,
            &crate::BoottimeDeadline::start(30).map_err(|e| e.to_string())?,
            crate::native_worker::cancellation_requested,
        )?;
        let pre = prepared(&raw, p)?;
        observe(p, &pre, journal)?;
        once(
            root,
            PRELAUNCH,
            &serde_json::from_slice(&raw).map_err(|e| e.to_string())?,
        )?;
        once(root, INTENT, &intent(p, &pre)?)?;
        pre
    } else {
        retained_export(p, root)?;
        retained_prelaunch(root, p)?
    };
    let first = collect(p, &pre, journal)?;
    let second = collect(p, &pre, journal)?;
    if first != second {
        return Err("unsigned failure evidence changed between captures".into());
    }
    let expected = export_body(p, &first.0, &first.1)?;
    if initial.is_none() {
        if retained_export(p, root)? != expected
            || required(root, MANIFEST)? != first.1
            || required(root, INITIAL)? != first.2
        {
            return Err("original unsigned failure read changed".into());
        }
        return Ok(first.0);
    }
    once(root, INITIAL, &first.2)?;
    once(root, MANIFEST, &first.1)?;
    once(root, EXPORT, &expected)?;
    retained_export(p, root)?;
    Ok(first.0)
}
fn ack(
    p: &Pins,
    root: &OwnedFd,
    export_sha: &str,
    host: &str,
    publish: bool,
    journal: Option<&RunReservationJournal>,
) -> Result<Value, String> {
    let e = retained_export(p, root)?;
    if !crate::hex(host, 64) || e["receipt_sha256"] != export_sha {
        return Err("unsigned failure actual Host receipt/export pin required".into());
    }
    let mut body = e["receipt"].clone();
    body["schema"] = json!(format!("{PREFIX}-ack.v1"));
    body["export_receipt_sha256"] = json!(export_sha);
    body["host_receipt_sha256"] = json!(host);
    let expected = wrap("ack", body)?;
    if publish {
        let c = collect(
            p,
            &retained_prelaunch(root, p)?,
            journal.ok_or("failure ACK lease absent")?,
        )?;
        if export_body(p, &c.0, &c.1)? != e {
            return Err("unsigned failure changed before Host ACK".into());
        }
        once(root, ACK, &expected)?;
    }
    if required(root, ACK)? != expected {
        return Err("actual unsigned failure Root ACK absent or changed".into());
    }
    Ok(expected)
}
fn retire(
    p: &Pins,
    root: &OwnedFd,
    export_sha: &str,
    host: &str,
    generation: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    let e = retained_export(p, root)?;
    let a = ack(p, root, export_sha, host, false, None)?;
    let pre = retained_prelaunch(root, p)?;
    let initial = required(root, INITIAL)?;
    let pins = JobStoragePins {
        source_sha: &pre.source_sha,
        job_id: &pre.job_id,
        worker_generation: &pre.worker_generation,
        mke2fs_sha256: initial["storage"]["receipt"]["mke2fs_sha256"]
            .as_str()
            .ok_or("original failure formatter absent")?,
    };
    let authority = json!({"schema":format!("{PREFIX}-storage-retirement-authority.v1"),"export_receipt_sha256":e["receipt_sha256"],"host_ack_sha256":a["receipt_sha256"],"host_receipt_sha256":host,"terminal_sha256":p.0["terminal_sha256"],"report_sha256":p.0["report_sha256"],"prelaunch_sha256":linux::sha(&pre.to_bytes().map_err(|e|e.to_string())?),"manifest_sha256":e["receipt"]["manifest_sha256"]});
    crate::native_job_storage::retire::retire(
        &pins,
        JobStorageProfile::Native,
        authority,
        Some(p.text("storage_receipt_sha256")),
        e["receipt"]["archive_sha256"].as_str(),
        generation,
        publish,
        || {
            let journal = RunReservationJournal::open_root_owned(Path::new(
                crate::builder_image_context::RUST_STATE,
            ))
            .map_err(|e| e.to_string())?;
            let c = collect(p, &pre, &journal)?;
            if c.2 != initial || export_body(p, &c.0, &c.1)? != e {
                return Err("original unsigned failure changed before retirement".into());
            }
            Ok(())
        },
    )
}
pub(crate) fn dispatch(args: &[String]) -> Result<Option<Vec<u8>>, String> {
    let selector = args.get(1).map(String::as_str).unwrap_or("");
    let count = match selector {
        "--export-native-readonly-failure-v1" | "--resume-native-readonly-failure-v1" => 12,
        "--read-native-readonly-failure-v1" | "--read-native-readonly-failure-export-v1" => 11,
        "--ack-native-readonly-failure-v1" | "--read-native-readonly-failure-ack-v1" => 13,
        "--retire-native-readonly-failure-storage-v1"
        | "--read-native-readonly-failure-retirement-v1" => 14,
        _ => return Ok(None),
    };
    if args.len() != count {
        return Err("exact fixed unsigned-failure arguments required".into());
    }
    gauntlet_cell_rootfs::require_outside_root()?;
    let p = Pins::new(args)?;
    let _scope = owner::scope()?;
    if count == 14 {
        crate::verify_running_binary(&args[13]).map_err(|e| e.to_string())?;
        return retire(
            &p,
            &p.slot()?,
            &args[11],
            &args[12],
            &args[13],
            selector == "--retire-native-readonly-failure-storage-v1",
        )
        .map(Some);
    }
    crate::verify_running_binary(p.text("reader_generation")).map_err(|e| e.to_string())?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let slot = p.slot()?;
    let raw = match selector {
        "--export-native-readonly-failure-v1" | "--resume-native-readonly-failure-v1" => export(
            &p,
            &slot,
            &journal,
            Some((
                args[11]
                    .parse()
                    .map_err(|_| "original prelaunch byte count required")?,
                selector == "--resume-native-readonly-failure-v1",
            )),
        )?,
        "--read-native-readonly-failure-v1" => export(&p, &slot, &journal, None)?,
        "--read-native-readonly-failure-export-v1" => {
            let pre = retained_prelaunch(&slot, &p)?;
            let original = intent(&p, &pre)?;
            if required(&slot, INTENT)? != original {
                return Err("unsigned failure intent changed".into());
            }
            let e = if read(&slot, EXPORT)?.is_some() {
                Some(retained_export(&p, &slot)?)
            } else {
                None
            };
            linux::canonical(
                &json!({"schema":format!("{PREFIX}-export-state.v1"),"intent_sha256":linux::sha(&linux::canonical(&original)?),"export_complete":e.is_some(),"export":e,"retry_allowed":false}),
            )?
        }
        _ => linux::canonical(&ack(
            &p,
            &slot,
            &args[11],
            &args[12],
            selector == "--ack-native-readonly-failure-v1",
            Some(&journal),
        )?)?,
    };
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    Ok(Some(raw))
}
