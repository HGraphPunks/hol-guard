//! Global admission observes every new volume intent, including torn setup.
use super::{
    lifecycle::{self, JobVolume},
    linux, JobStorageProfile,
};
use serde_json::{json, Value};
use std::{os::fd::OwnedFd, path::Path};

pub(crate) fn require_complete() -> Result<(), String> {
    super::owner::require_admissible()?;
    let _namespace_scope = super::owner::scope()?;
    if !Path::new(lifecycle::BASE)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Ok(());
    }
    let root = crate::open_root_owned_public_directory(Path::new(lifecycle::BASE))
        .map_err(|e| e.to_string())?;
    crate::feature_files::private_directory(&root, (0, 0))?;
    for (count, row) in rustix::fs::Dir::read_from(&root)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if count > 4098 {
            return Err("storage intent inventory bound exceeded".into());
        }
        let row = row.map_err(|e| e.to_string())?;
        let name = row.file_name().to_str().map_err(|_| "storage job UTF8")?;
        if matches!(name, "." | "..") {
            continue;
        }
        if !crate::hex(name, 16) {
            return Err("unexpected entry in private storage namespace".into());
        }
        let slot = crate::feature_files::open_directory(&root, name, (0, 0))?;
        if let Some(raw) = crate::feature_files::read(&slot, "retired.json", (0, 0), 0o600, 8192)? {
            super::retire::verify_retired(&slot, name, &raw)?;
            continue;
        }
        if crate::feature_files::read(&slot, "retirement.json", (0, 0), 0o600, 24576)?.is_some() {
            return Err("unfinished storage retirement blocks all fresh volumes".into());
        }
        if crate::feature_files::read(&slot, "artifact-export-intent.json", (0, 0), 0o600, 8192)?
            .is_some()
            && crate::feature_files::read(&slot, "artifact-export.json", (0, 0), 0o600, 8192)?
                .is_none()
        {
            return Err("unfinished artifact export blocks fresh volume admission; explicit readback required".into());
        }
        let raw = crate::feature_files::required(&slot, "admitted.json", (0, 0), 0o600, 1024)
            .map_err(|_| {
                "unfinished storage allocation/source/initialization blocks all fresh volumes"
            })?;
        let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let storage =
            crate::feature_files::required(&slot, lifecycle::RECEIPT, (0, 0), 0o600, 16384)?;
        let v: Value = serde_json::from_slice(&storage).map_err(|e| e.to_string())?;
        let profile: JobStorageProfile = v["profile"]
            .as_str()
            .ok_or("storage profile absent")?
            .parse()?;
        let completion = match profile {
            JobStorageProfile::Native => {
                let receipts = crate::open_root_owned_public_directory(Path::new(
                    "/var/lib/hol-gauntlet-rust/native-initialization",
                ))
                .map_err(|e| e.to_string())?;
                crate::feature_files::required(
                    &receipts,
                    &format!("{name}.job.json"),
                    (0, 0),
                    0o600,
                    24576,
                )?
            }
            _ => {
                super::owner::enter(name)?;
                let job = crate::open_root_owned_public_directory(&profile.root(name)?)
                    .map_err(|e| e.to_string())?;
                crate::feature_files::required(
                    &job,
                    "source-capture.v2.json",
                    (0, 0),
                    0o600,
                    24576,
                )?
            }
        };
        if value != body(&storage, &completion) || linux::canonical(&value)? != raw {
            return Err("storage admission differs from original completed custody".into());
        }
        super::owner::enter(name)?;
        super::temporary::require_all_absent(name)?;
    }
    Ok(())
}
fn body(storage: &[u8], completion: &[u8]) -> Value {
    json!({"schema":"hol-gauntlet-job-storage-admitted.v1","storage_receipt_sha256":linux::sha(storage),"completion_sha256":linux::sha(completion)})
}
pub(crate) fn admit(volume: &JobVolume, completion: &[u8]) -> Result<(), String> {
    crate::feature_files::write(
        &volume.slot,
        "admitted.json",
        &linux::canonical(&body(&volume.raw, completion))?,
        (0, 0),
        0o600,
    )
}
pub(crate) fn verify_admitted(
    slot: &OwnedFd,
    storage: &[u8],
    completion: &[u8],
) -> Result<(), String> {
    if crate::feature_files::required(slot, "admitted.json", (0, 0), 0o600, 1024)?
        != linux::canonical(&body(storage, completion))?
    {
        return Err("original storage admission incomplete or changed".into());
    }
    Ok(())
}
pub(crate) fn closed_inventory(slot: &OwnedFd, allowed: &[&str]) -> Result<(), String> {
    for row in rustix::fs::Dir::read_from(slot).map_err(|e| e.to_string())? {
        let row = row.map_err(|e| e.to_string())?;
        let name = row
            .file_name()
            .to_str()
            .map_err(|_| "storage filename UTF8")?;
        if !matches!(name, "." | "..") && !allowed.contains(&name) {
            return Err("unexpected private storage entry blocks retirement".into());
        }
    }
    Ok(())
}
