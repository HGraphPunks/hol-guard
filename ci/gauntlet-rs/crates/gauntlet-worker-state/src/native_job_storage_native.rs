//! Native container temporary files remain separately byte/inode bounded.
use super::{lifecycle, linux, JobStorageProfile};
use serde_json::Value;
use std::path::Path;
#[path = "native_job_storage_unstarted.rs"]
pub(crate) mod unstarted;
pub use unstarted::abort_initialized_native_job_storage;

pub(crate) fn verify(job: &str) -> Result<bool, String> {
    Ok(retained_storage(job)?.is_some())
}
pub(crate) fn retained_storage(job: &str) -> Result<Option<Value>, String> {
    if !lifecycle::present(job)? {
        return Ok(None);
    }
    let root = crate::open_root_owned_public_directory(Path::new(
        "/var/lib/hol-gauntlet-rust/native-initialization",
    ))
    .map_err(|e| e.to_string())?;
    let raw =
        crate::feature_files::required(&root, &format!("{job}.job.json"), (0, 0), 0o600, 24576)?;
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if v["schema"] != "hol-gauntlet-native-job-initialization.v2"
        || v["job_id"] != job
        || linux::canonical(&v)? != raw
    {
        return Err("original bounded Native initialization required".into());
    }
    let binding = lifecycle::verify_binding(
        &v["storage"],
        v["source_sha"].as_str().ok_or("Native source pin absent")?,
        job,
        v["worker_generation"]
            .as_str()
            .ok_or("Native generation absent")?,
        JobStorageProfile::Native,
    )?;
    Ok(Some(binding))
}
pub(crate) fn arguments(job: &str, scope: super::temporary::Scope) -> Result<Vec<String>, String> {
    if !verify(job)? {
        return Ok(Vec::new());
    }
    super::temporary::create(job, scope)
}
pub(crate) fn check(job: &str, value: &Value, running: bool) -> Result<(), String> {
    let bounded = verify(job)?;
    if !bounded {
        return Ok(());
    }
    let scope = if value["Config"]["Labels"]["hol.gauntlet.sdk.job"] == job {
        super::temporary::Scope::Sdk
    } else if value["Config"]["Labels"]["hol.gauntlet.mcp.job"] == job {
        super::temporary::Scope::Mcp
    } else {
        return Err("bounded Native temporary scope label absent".into());
    };
    super::temporary::verify(job, scope, Some(value))?;
    let count = super::check_tmpfs(value)?;
    if (count == 4) != bounded {
        return Err("Native tmpfs profile differs from original initialization".into());
    }
    if running && value["State"]["Running"] != true {
        return Err("bounded Native container is not running".into());
    }
    Ok(())
}

pub(crate) fn record_export(
    p: &crate::NativePublicExportPins<'_>,
    raw: &[u8],
    completion: &Value,
) -> Result<(), String> {
    let pin = p.prelaunch;
    if !verify(&pin.job_id)? {
        return Ok(());
    }
    let slot =
        crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(&pin.job_id))
            .map_err(|e| e.to_string())?;
    let storage = crate::feature_files::required(&slot, lifecycle::RECEIPT, (0, 0), 0o600, 16384)?;
    let prelaunch: Value = serde_json::from_slice(&pin.to_bytes().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let binding = serde_json::json!({"schema":"hol-gauntlet-native-storage-export.v1","prelaunch":prelaunch,
        "preparation_sha256":p.preparation_sha256,"role":p.role,"storage_receipt_sha256":linux::sha(&storage),
        "archive_sha256":linux::sha(raw),"archive_bytes":raw.len(),"terminal_sha256":completion["terminal_sha256"],"report_sha256":completion["terminal"]["report_sha256"]});
    let expected = linux::canonical(&binding)?;
    match crate::feature_files::read(&slot, "export.json", (0, 0), 0o600, 8192)? {
        Some(old) if old == expected => Ok(()),
        Some(_) => Err("original private export binding changed; retain storage".into()),
        None => crate::feature_files::write(&slot, "export.json", &expected, (0, 0), 0o600),
    }
}
pub fn retire_native_job_storage(
    p: &crate::NativePublicExportPins<'_>,
    storage_sha: &str,
    archive_sha: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    p.prelaunch.to_bytes().map_err(|e| e.to_string())?;
    let pin = p.prelaunch;
    let slot =
        crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(&pin.job_id))
            .map_err(|e| e.to_string())?;
    let raw = crate::feature_files::required(&slot, lifecycle::RECEIPT, (0, 0), 0o600, 16384)?;
    let storage: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if linux::sha(&raw) != storage_sha || linux::canonical(&storage)? != raw {
        return Err("original outside storage receipt SHA required for retirement".into());
    }
    let export_raw = crate::feature_files::required(&slot, "export.json", (0, 0), 0o600, 8192)?;
    let export: Value = serde_json::from_slice(&export_raw).map_err(|e| e.to_string())?;
    let prelaunch: Value = serde_json::from_slice(&pin.to_bytes().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if export.as_object().is_none_or(|o| o.len() != 9)
        || linux::canonical(&export)? != export_raw
        || export["schema"] != "hol-gauntlet-native-storage-export.v1"
        || export["prelaunch"] != prelaunch
        || export["preparation_sha256"] != p.preparation_sha256
        || export["role"] != p.role
        || export["storage_receipt_sha256"] != storage_sha
        || export["archive_sha256"] != archive_sha
    {
        return Err("retirement differs from original authenticated private archive export".into());
    }
    let pins = super::JobStoragePins {
        source_sha: &pin.source_sha,
        job_id: &pin.job_id,
        worker_generation: &pin.worker_generation,
        mke2fs_sha256: storage["mke2fs_sha256"]
            .as_str()
            .ok_or("original formatter pin absent")?,
    };
    super::retire::retire(
        &pins,
        JobStorageProfile::Native,
        export.clone(),
        Some(storage_sha),
        Some(archive_sha),
        p.exporter_generation,
        publish,
        || {
            let journal = crate::RunReservationJournal::open_root_owned(Path::new(
                crate::builder_image_context::RUST_STATE,
            ))
            .map_err(|e| e.to_string())?;
            let (original, spec) = crate::native_keyed_startup_repair::retained(
                &journal,
                &pin.source_sha,
                &pin.job_id,
                &pin.deployment_digest,
                &pin.worker_generation,
            )?;
            if original != *pin
                || spec.preparation_sha256 != p.preparation_sha256
                || spec.case() != p.role
            {
                return Err("original job pins differ before retirement".into());
            }
            let request=gauntlet_contracts::WorkerRequest::parse(serde_json::json!({"schema":"hol-gauntlet-worker-request.v1","action":"run","source_sha":pin.source_sha,"job_id":pin.job_id,"deployment_digest":pin.deployment_digest}).to_string().as_bytes()).map_err(|e|e.to_string())?;
            let (_, prep) = crate::native_job_io::load(&request, &pin.worker_generation)?;
            let running = journal
                .running_marker(
                    &pin.job_id,
                    &pin.source_sha,
                    &pin.deployment_digest,
                    &pin.worker_generation,
                )
                .map_err(|e| e.to_string())?
                .ok_or("original running marker absent before retirement")?;
            let completion = crate::native_completion::read_completion(
                &journal,
                &pin.source_sha,
                &pin.job_id,
                &pin.deployment_digest,
                &pin.worker_generation,
            )?;
            let completion: Value =
                serde_json::from_slice(&completion).map_err(|e| e.to_string())?;
            if completion["terminal_sha256"] != export["terminal_sha256"]
                || completion["terminal"]["report_sha256"] != export["report_sha256"]
            {
                return Err("original completed report changed before retirement".into());
            }
            gauntlet_evidence::verify_native_control_envelope(
                completion["report"]["controller_envelope_utf8"]
                    .as_str()
                    .ok_or("authenticated controller envelope absent")?
                    .as_bytes(),
                &gauntlet_evidence::NativeControlReportPins {
                    prelaunch: pin.clone(),
                    preparation_sha256: p.preparation_sha256.into(),
                    role: p.role.into(),
                },
            )
            .map_err(|e| e.to_string())?;
            crate::native_public_export::quiescent(&spec, &prep, &running)?;
            lifecycle::JobVolume::read(&pins, JobStorageProfile::Native)?;
            Ok(())
        },
    )
}
