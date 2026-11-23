//! Custody of one signed failed Live controller after exact original repair.
//! The absent outer terminal, controller exit and model usage remain unknown.
use crate::candidate_repair::retain_failed_metadata as once;
use crate::native_job_storage::{linux, owner, JobStoragePins, JobStorageProfile};
use crate::native_prelaunch::{
    failure_read as read, failure_required as required, live_failure_export as export_body,
    live_failure_wrap as wrap, LiveFailurePins as Pins, LIVE_FAILURE_PREFIX as PREFIX,
    READONLY_FAILURE_ARCHIVE_LIMIT as LIMIT,
};
use crate::native_public_archive::{encode_profile, PublicFiles};
use crate::RunReservationJournal;
use gauntlet_contracts::{PrelaunchPrepared, WorkerRequest};
use gauntlet_evidence::{verify_native_control_envelope, NativeControlReportPins};
use rustix::fs::fstat;
use serde_json::{json, Value};
use std::{
    io::Read,
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
};
#[path = "native_live_failure_custody.rs"]
mod custody;
pub(crate) use custody::{dispatch, retired_repair};
const INTENT: &str = "live-failure-intent.json";
const PRE: &str = "live-failure-prelaunch.json";
const MANIFEST: &str = "live-failure-manifest.json";
const OBS: &str = "live-failure-observation.json";
const INITIAL: &str = "live-failure-initialization.json";
const EXPORT: &str = "live-failure-export.json";
const ACK: &str = "live-failure-ack.json";
struct Observation {
    root: OwnedFd,
    initial: Value,
    value: Value,
}
fn observed(
    p: &Pins,
    pre: &PrelaunchPrepared,
    j: &RunReservationJournal,
) -> Result<Observation, String> {
    let (actual, spec) = crate::native_keyed_startup_repair::retained(
        j,
        &pre.source_sha,
        &pre.job_id,
        &pre.deployment_digest,
        &pre.worker_generation,
    )?;
    if actual != *pre
        || !matches!(
            spec.execution,
            crate::NativeJobExecution::HostPinnedLive { .. }
        )
        || spec.preparation_sha256 != p.text("preparation_sha256")
    {
        return Err("original signed Live failure profile differs".into());
    }
    let request=WorkerRequest::parse(json!({"schema":"hol-gauntlet-worker-request.v1","action":"run","source_sha":pre.source_sha,"job_id":pre.job_id,"deployment_digest":pre.deployment_digest}).to_string().as_bytes()).map_err(|e|e.to_string())?;
    let (_, prep) = crate::native_job_io::load(&request, &pre.worker_generation)?;
    let (_, initial) = crate::native_initialize::checked_job_initialization(
        &pre.source_sha,
        &pre.job_id,
        &pre.worker_generation,
        false,
    )?;
    let live = crate::native_live_prepare::retained(&spec, &pre.deployment_digest)?;
    if initial["schema"] != "hol-gauntlet-native-job-initialization.v2"
        || initial["storage"]["receipt_sha256"] != p.0["storage_receipt_sha256"]
        || linux::sha(&live.raw) != p.text("live_prepared_sha256")
    {
        return Err("original bounded Live preparation/storage differs".into());
    }
    for suffix in [
        "terminal.json",
        "report.json",
        "native-startup-repair.json",
        "native-keyed-startup-repair.json",
    ] {
        if crate::read_bounded_regular(
            &j.root,
            &format!("{}.{suffix}", pre.job_id),
            16 * 1024 * 1024,
        )
        .map_err(|e| e.to_string())?
        .is_some()
        {
            return Err("completed or partial Live terminal is outside failure custody".into());
        }
    }
    let repair = crate::native_repair::verified_receipt(
        j,
        &pre.source_sha,
        &pre.job_id,
        &pre.deployment_digest,
        &pre.worker_generation,
    )?
    .ok_or("original released Live repair required")?;
    let r: Value = serde_json::from_slice(&repair).map_err(|e| e.to_string())?;
    if linux::sha(&repair) != p.text("repair_sha256")
        || r["schema"] != "hol-gauntlet-native-live-keyed-worker-repair.v1"
        || !r["exit_code"].is_null()
        || !r["model_requests"].is_null()
        || r["live_prepared_sha256"] != p.0["live_prepared_sha256"]
    {
        return Err("original unknown-exit Live repair differs".into());
    }
    let running = j
        .running_marker(
            &pre.job_id,
            &pre.source_sha,
            &pre.deployment_digest,
            &pre.worker_generation,
        )
        .map_err(|e| e.to_string())?
        .ok_or("original Live running identity absent")?;
    let root =
        crate::open_root_owned_public_directory(&spec.job_root()).map_err(|e| e.to_string())?;
    let ci = required(&root, "live-sdk-created-repair-intent.v1.json")?;
    let cr = required(&root, "live-sdk-created-repair.v1.json")?;
    let pins = &ci["pins"];
    let expected = json!({"schema":"hol-gauntlet-native-live-sdk-created-repair.v1","intent_sha256":linux::sha(&linux::canonical(&ci)?),"pins_sha256":linux::sha(&linux::canonical(pins)?),"container_id_sha256":linux::sha(pins["container_id"].as_str().ok_or("original SDK CID pin absent")?.as_bytes()),"sdk_agent_absent":true,"sdk_profile_absent":true,"process_signalled":false,"image_adopted":false,"job_terminal_written":false,"model_requests":null,"exit_code":null,"execution_eligible":false,"qualification_eligible":false});
    if ci["schema"] != "hol-gauntlet-native-live-sdk-created-repair-intent.v1"
        || cr != expected
        || linux::sha(&linux::canonical(&cr)?) != p.text("created_repair_sha256")
        || ci["prelaunch"]
            != serde_json::from_slice::<Value>(&pre.to_bytes().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?
        || ci["running_marker_sha256"] != running.sha256
        || pins["source_sha"] != pre.source_sha
        || pins["job_id"] != pre.job_id
        || pins["deployment_digest"] != pre.deployment_digest
        || pins["worker_generation"] != pre.worker_generation
        || pins["preparation_sha256"] != p.0["preparation_sha256"]
        || pins["live_prepared_sha256"] != p.0["live_prepared_sha256"]
        || pins["storage_receipt_sha256"] != p.0["storage_receipt_sha256"]
        || pins["host_pin_sha256"] != pre.host_record_sha256().map_err(|e| e.to_string())?
    {
        return Err("original keyed never-started SDK repair differs".into());
    }
    let stdout = crate::feature_files::required(
        &root,
        &format!("{}.native.stdout", pre.job_id),
        (0, 0),
        0o600,
        32768,
    )?;
    let stderr = crate::feature_files::required(
        &root,
        &format!("{}.native.stderr", pre.job_id),
        (0, 0),
        0o600,
        1024 * 1024,
    )?;
    let envelope = verify_native_control_envelope(
        &stdout,
        &NativeControlReportPins {
            prelaunch: pre.clone(),
            preparation_sha256: p.text("preparation_sha256").into(),
            role: spec.case().into(),
        },
    )
    .map_err(|_| "original Live failure signature differs")?;
    let controller = json!({"pid":running.process.pid,"start_ticks":running.process.start_ticks});
    if envelope.report()["status"] != "failed"
        || envelope.report()["error"]
            .as_str()
            .is_none_or(str::is_empty)
        || envelope.report()["controller_identity"] != controller
        || (!p.text("signed_envelope_sha256").is_empty()
            && linux::sha(&stdout) != p.text("signed_envelope_sha256"))
    {
        return Err("only the exact signed failed Live controller is supported".into());
    }
    let mut hashes = json!({});
    for suffix in ["started", "controller-key", "running", "native-repair"] {
        let raw = crate::feature_files::required(
            &j.root,
            &format!("{}.{suffix}.json", pre.job_id),
            (0, 0),
            0o600,
            8192,
        )?;
        hashes[suffix] = json!(linux::sha(&raw));
    }
    let mut value = p.body("observation");
    value["signed_envelope_sha256"] = json!(linux::sha(&stdout));
    value["live_prepared"] = live.value.clone();
    for (k, v) in [
        (
            "prelaunch",
            serde_json::from_slice(&pre.to_bytes().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?,
        ),
        ("controller", controller),
        (
            "signed_envelope_utf8",
            json!(std::str::from_utf8(&stdout).map_err(|_| "Live envelope UTF-8")?),
        ),
        ("stderr_sha256", json!(linux::sha(&stderr))),
        ("records_sha256", hashes),
        ("quiescent", r["cleanup"].clone()),
        ("model_requests", Value::Null),
        ("exit_code", Value::Null),
        ("execution_eligible", json!(false)),
        ("qualification_eligible", json!(false)),
    ] {
        value[k] = v;
    }
    crate::native_sdk_quiescence::require_sdk_quiescence(&spec, &prep)?;
    crate::native_mcp_quiescence::require_mcp_quiescence(&spec, &prep)?;
    Ok(Observation {
        root,
        initial,
        value,
    })
}
fn capture(
    files: &mut PublicFiles,
    root: &OwnedFd,
    path: &str,
    member: &str,
    mode: libc::mode_t,
    required: bool,
) -> Result<(), String> {
    if !files.capture(root, path, member, (0, 0), mode)? && required {
        return Err("required signed Live failure member absent".into());
    }
    Ok(())
}
fn collect(
    p: &Pins,
    pre: &PrelaunchPrepared,
    j: &RunReservationJournal,
) -> Result<(Vec<u8>, Value, Value, Value), String> {
    let o = observed(p, pre, j)?;
    let mut files = PublicFiles::default();
    for suffix in ["started", "controller-key", "running", "native-repair"] {
        capture(
            &mut files,
            &j.root,
            &format!("{}.{suffix}.json", pre.job_id),
            &format!("worker/{suffix}.json"),
            0o600,
            true,
        )?;
    }
    for (path, member, mode) in [
        (
            format!("{}.native.stdout", pre.job_id),
            "native.stdout",
            0o600,
        ),
        (
            format!("{}.native.stderr", pre.job_id),
            "native.stderr",
            0o600,
        ),
        ("preparation.v1.json".into(), "preparation.json", 0o600),
        (
            "live-private/prepared.json".into(),
            "live/prepared.json",
            0o600,
        ),
        (
            "live-sdk-created-repair-intent.v1.json".into(),
            "sdk/created-intent.json",
            0o600,
        ),
        (
            "live-sdk-created-repair.v1.json".into(),
            "sdk/created-repair.json",
            0o600,
        ),
        ("sdk-processes/003.stdout".into(), "sdk/003.stdout", 0o600),
        ("sdk-processes/004.stdout".into(), "sdk/004.stdout", 0o600),
        ("sdk-agent.apparmor".into(), "sdk/policy.apparmor", 0o400),
    ] {
        capture(&mut files, &o.root, &path, member, mode, true)?;
    }
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
        true,
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
        true,
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
            true,
        )?;
    }
    for name in [
        "native-image-events.v1.jsonl",
        "native-supervisor-events.v1.jsonl",
        "native-process-events.v1.jsonl",
        "native-pipe-events.v1.jsonl",
    ] {
        capture(
            &mut files,
            &o.root,
            &format!("cell/{name}"),
            &format!("cell/{name}"),
            0o600,
            false,
        )?;
    }
    capture(
        &mut files,
        &o.root,
        "cell/native-cell.apparmor",
        "cell/native-cell.apparmor",
        0o400,
        true,
    )?;
    for name in ["evidence.v1.json", "context.v1.json"] {
        capture(
            &mut files,
            &o.root,
            &format!("live/{name}"),
            &format!("live/{name}"),
            0o600,
            false,
        )?;
    }
    for name in ["live-cleanup-before.v1.json", "live-cleanup.v1.json"] {
        capture(
            &mut files,
            &o.root,
            name,
            &format!("live/{name}"),
            0o600,
            false,
        )?;
    }
    if files.files.values().map(Vec::len).sum::<usize>() > 32 * 1024 * 1024 {
        return Err("signed Live failure archive bound".into());
    }
    let mut m = p.body("evidence");
    for (k, v) in [
        (
            "status",
            json!("signed-controller-failure-outer-exit-unavailable"),
        ),
        ("prelaunch", o.value["prelaunch"].clone()),
        ("controller", o.value["controller"].clone()),
        ("quiescent", o.value["quiescent"].clone()),
        (
            "observation_sha256",
            json!(linux::sha(&linux::canonical(&o.value)?)),
        ),
        ("exit_code", Value::Null),
        ("qualification_eligible", json!(false)),
    ] {
        m[k] = v;
    }
    let archive = encode_profile(files, m, &format!("{PREFIX}-evidence.v1"), Value::Null)?;
    if archive.len() > LIMIT {
        return Err("signed Live failure USTAR bound".into());
    }
    let mut tar = tar::Archive::new(archive.as_slice());
    let mut manifest = None;
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        if entry.path().map_err(|e| e.to_string())?.as_ref() == Path::new("results.sha256.json") {
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw).map_err(|e| e.to_string())?;
            manifest = Some(serde_json::from_slice(&raw).map_err(|e| e.to_string())?);
        }
    }
    let after = observed(p, pre, j)?;
    if after.initial != o.initial
        || after.value != o.value
        || !crate::dependency_prefix_meta::same(
            &fstat(&o.root).map_err(|e| e.to_string())?,
            &fstat(&after.root).map_err(|e| e.to_string())?,
        )
    {
        return Err("signed Live failure changed during capture".into());
    }
    Ok((
        archive,
        manifest.ok_or("Live failure index absent")?,
        o.initial,
        o.value,
    ))
}
