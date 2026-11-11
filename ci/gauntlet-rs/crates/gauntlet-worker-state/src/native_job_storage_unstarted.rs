//! Admitted Native cleanup preserves fixed preparation bytes outside volume.
//! It creates no execution terminal and makes no model-usage claim.
use super::super::{admission, lifecycle, linux, JobStoragePins, JobStorageProfile};
use crate::RunReservationJournal;
use rustix::fs::{fstat, openat, statat, AtFlags, Mode, OFlags};
use serde_json::{json, Value};
use std::{fs::File, io::Read, os::fd::OwnedFd, path::Path};
const SNAPSHOT: &str = "unstarted-snapshot.json";
const PREPARATION: &str = "unstarted-preparation.raw";
fn read(slot: &OwnedFd, name: &str, bound: usize) -> Result<Option<Vec<u8>>, String> {
    crate::feature_files::read(slot, name, (0, 0), 0o600, bound)
}
fn retain(slot: &OwnedFd, name: &str, raw: &[u8]) -> Result<(), String> {
    match read(slot, name, 65536)? {
        Some(old) if old == raw => Ok(()),
        Some(_) => Err("original unstarted evidence changed".into()),
        None => crate::feature_files::write(slot, name, raw, (0, 0), 0o600),
    }
}
fn initialization(p: &JobStoragePins<'_>, init: &str, storage: &str) -> Result<Value, String> {
    let root = crate::open_root_owned_public_directory(Path::new(
        "/var/lib/hol-gauntlet-rust/native-initialization",
    ))
    .map_err(|e| e.to_string())?;
    let raw = crate::feature_files::required(
        &root,
        &format!("{}.job.json", p.job_id),
        (0, 0),
        0o600,
        24576,
    )?;
    let v: Value = serde_json::from_slice(&raw).map_err(|_| "original initialization JSON")?;
    if linux::sha(&raw) != init
        || linux::canonical(&v)? != raw
        || v["schema"] != "hol-gauntlet-native-job-initialization.v2"
        || v["source_sha"] != p.source_sha
        || v["job_id"] != p.job_id
        || v["worker_generation"] != p.worker_generation
        || v["storage"]["receipt_sha256"] != storage
        || v["storage"]["receipt"]["mke2fs_sha256"] != p.mke2fs_sha256
    {
        return Err("exact original initialized Source/job/storage/formatter required".into());
    }
    Ok(v)
}
fn resources(
    p: &JobStoragePins<'_>,
    podman: &str,
    journal: &RunReservationJournal,
) -> Result<(), String> {
    let epoch = crate::native_worker::interruption_epoch();
    crate::native_initialize::require_unstarted_job(journal, p.job_id)?;
    crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
    crate::dependency_state::client_group_absent(p.job_id)?;
    crate::builder_candidate_preflight::verify_file(
        "/usr/bin/podman",
        podman,
        true,
        64 * 1024 * 1024,
    )
    .map_err(|e| e.to_string())?;
    if !crate::builder_candidate_process::cleanup_container_absent(p.job_id, None)
        .map_err(|e| e.to_string())?
    {
        return Err("unstarted candidate container remains".into());
    }
    for role in ["sdk", "mcp"] {
        let out = crate::native_sdk_process::run_pinned_podman(
            podman,
            &[
                "ps".into(),
                "--all".into(),
                "--filter".into(),
                format!("label=hol.gauntlet.{role}.job={}", p.job_id),
                "--format=json".into(),
            ],
        )?;
        let v: Value =
            serde_json::from_slice(&out.stdout).map_err(|_| "unstarted agent inventory invalid")?;
        if !out.status.success() || v != json!([]) {
            return Err("unstarted SDK/MCP container metadata remains".into());
        }
    }
    let mut profiles = String::new();
    File::open("/sys/kernel/security/apparmor/profiles")
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_string(&mut profiles)
        .map_err(|e| e.to_string())?;
    if profiles.len() > 65536
        || profiles.lines().any(|line| {
            ["sdk", "mcp", "build"]
                .iter()
                .any(|role| line.starts_with(&format!("hol-gauntlet-{role}-{}", p.job_id)))
        })
    {
        return Err("unstarted scoped profile remains or inventory is incomplete".into());
    }
    epoch_unchanged(epoch)
}
fn snapshot(
    p: &JobStoragePins<'_>,
    slot: &OwnedFd,
    init: &str,
    storage: &str,
) -> Result<Value, String> {
    let (raw, v) =
        crate::native_initialize::job_initialization(p.source_sha, p.job_id, p.worker_generation)?;
    if linux::sha(&raw) != init || v["storage"]["receipt_sha256"] != storage {
        return Err("original initialized directory changed".into());
    }
    let root = crate::open_root_owned_public_directory(&JobStorageProfile::Native.root(p.job_id)?)
        .map_err(|e| e.to_string())?;
    admission::closed_inventory(&root, &["workspace", "preparation.v1.json"])?;
    let held = match openat(
        &root,
        "preparation.v1.json",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Some(fd),
        Err(rustix::io::Errno::NOENT) => None,
        Err(e) => return Err(e.to_string()),
    };
    let preparation = if let Some(held) = held {
        let s = fstat(&held).map_err(|e| e.to_string())?;
        let raw = read(&root, "preparation.v1.json", 49152)?.ok_or("preparation disappeared")?;
        retain(slot, PREPARATION, &raw)?;
        let after = fstat(&held).map_err(|e| e.to_string())?;
        let visible = statat(&root, "preparation.v1.json", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        if !crate::builder_candidate_source::same_file(&s, &after)
            || !crate::builder_candidate_source::same_file(&s, &visible)
        {
            return Err("preparation identity changed during preservation".into());
        }
        let meta = json!({"sha256":linux::sha(&raw),"bytes":raw.len(),"device":s.st_dev,"inode":s.st_ino,
            "uid":s.st_uid,"gid":s.st_gid,"mode":s.st_mode&0o7777,"links":s.st_nlink});
        if read(&root, "preparation.v1.json", 49152)?.as_deref() != Some(raw.as_slice()) {
            return Err("preparation changed during preservation".into());
        }
        meta
    } else {
        Value::Null
    };
    Ok(
        json!({"schema":"hol-gauntlet-native-unstarted-snapshot.v1","source_sha":p.source_sha,"job_id":p.job_id,
        "worker_generation":p.worker_generation,"initialization_sha256":init,"storage_receipt_sha256":storage,
        "workspace":v["workspace"],"preparation":preparation}),
    )
}
fn checked_snapshot(
    p: &JobStoragePins<'_>,
    slot: &OwnedFd,
    init: &str,
    storage: &str,
) -> Result<Value, String> {
    let raw = read(slot, SNAPSHOT, 8192)?.ok_or("original unstarted snapshot absent")?;
    let s: Value = serde_json::from_slice(&raw).map_err(|_| "unstarted snapshot JSON")?;
    let v = initialization(p, init, storage)?;
    let expected = json!({"schema":"hol-gauntlet-native-unstarted-snapshot.v1","source_sha":p.source_sha,"job_id":p.job_id,
        "worker_generation":p.worker_generation,"initialization_sha256":init,"storage_receipt_sha256":storage,
        "workspace":v["workspace"],"preparation":s["preparation"]});
    if raw != linux::canonical(&expected)? {
        return Err("unstarted snapshot identity changed".into());
    }
    if !s["preparation"].is_null() {
        let bytes = read(slot, PREPARATION, 49152)?.ok_or("preserved preparation bytes absent")?;
        if s["preparation"].as_object().is_none_or(|o| o.len() != 8)
            || s["preparation"]["sha256"] != linux::sha(&bytes)
            || s["preparation"]["bytes"] != bytes.len()
            || s["preparation"]["device"].as_u64().is_none()
            || s["preparation"]["inode"].as_u64().is_none_or(|n| n == 0)
            || s["preparation"]["uid"] != 0
            || s["preparation"]["gid"] != 0
            || s["preparation"]["mode"] != 0o600
            || s["preparation"]["links"] != 1
        {
            return Err("preserved preparation metadata or bytes changed".into());
        }
    } else if read(slot, PREPARATION, 49152)?.is_some() {
        return Err("orphan unstarted preparation copy".into());
    }
    Ok(s)
}
pub(crate) fn epoch_unchanged(epoch: usize) -> Result<(), String> {
    if crate::native_worker::interruption_epoch() != epoch {
        Err("new interruption leaves unstarted cleanup uncertain".into())
    } else {
        Ok(())
    }
}
fn authority_fields(
    a: &Value,
    profile: JobStorageProfile,
    storage: Option<&str>,
    archive: Option<&str>,
) -> Result<bool, String> {
    if a["schema"] != "hol-gauntlet-native-unstarted-storage-authority.v1" {
        return Ok(false);
    }
    if profile != JobStorageProfile::Native
        || archive.is_some()
        || storage != a["storage_receipt_sha256"].as_str()
        || a.as_object().is_none_or(|o| o.len() != 5)
        || [
            "initialization_sha256",
            "storage_receipt_sha256",
            "snapshot_sha256",
            "podman_sha256",
        ]
        .iter()
        .any(|k| !a[*k].as_str().is_some_and(|s| crate::hex(s, 64)))
    {
        return Err("closed exact unstarted initialization authority required".into());
    }
    Ok(true)
}
pub(crate) fn authority_mode(
    a: &Value,
    p: &JobStoragePins<'_>,
    profile: JobStorageProfile,
    storage: Option<&str>,
    archive: Option<&str>,
) -> Result<bool, String> {
    if !authority_fields(a, profile, storage, archive)? {
        return Ok(false);
    }
    let slot = crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(p.job_id))
        .map_err(|e| e.to_string())?;
    let s = checked_snapshot(
        p,
        &slot,
        a["initialization_sha256"].as_str().unwrap(),
        storage.unwrap(),
    )?;
    if linux::sha(&linux::canonical(&s)?) != a["snapshot_sha256"] {
        return Err("unstarted snapshot authority changed".into());
    }
    Ok(true)
}
fn phase_matches(mounted: bool, expected: &Value, current: Option<&Value>) -> Result<(), String> {
    if mounted && current != Some(expected) {
        return Err("original unstarted volume changed after snapshot".into());
    }
    Ok(())
}
pub(crate) fn recheck(
    p: &JobStoragePins<'_>,
    a: &Value,
    journal: &RunReservationJournal,
) -> Result<(), String> {
    resources(
        p,
        a["podman_sha256"]
            .as_str()
            .ok_or("unstarted Podman pin absent")?,
        journal,
    )
}
pub fn abort_initialized_native_job_storage(
    p: &JobStoragePins<'_>,
    init: &str,
    storage: &str,
    podman: &str,
    generation: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    let epoch = crate::native_worker::interruption_epoch();
    gauntlet_cell_rootfs::require_outside_root()?;
    linux::pins_valid(p)?;
    if [init, storage, podman, generation]
        .iter()
        .any(|s| !crate::hex(s, 64))
    {
        return Err("exact unstarted cleanup pins required".into());
    }
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let slot = crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(p.job_id))
        .map_err(|e| e.to_string())?;
    initialization(p, init, storage)?;
    if read(&slot, SNAPSHOT, 8192)?.is_none() {
        if !publish {
            return Err("unstarted cleanup has no original snapshot; read cannot create it".into());
        }
        let j = RunReservationJournal::open_root_owned(Path::new(
            crate::builder_image_context::RUST_STATE,
        ))
        .map_err(|e| e.to_string())?;
        let active = j.acquire_active_lease().map_err(|e| e.to_string())?;
        let legacy =
            crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
        resources(p, podman, &j)?;
        let s = snapshot(p, &slot, init, storage)?;
        retain(&slot, SNAPSHOT, &linux::canonical(&s)?)?;
        active.verify(&j.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    }
    let s = checked_snapshot(p, &slot, init, storage)?;
    let authority = json!({"schema":"hol-gauntlet-native-unstarted-storage-authority.v1","initialization_sha256":init,
        "storage_receipt_sha256":storage,"snapshot_sha256":linux::sha(&linux::canonical(&s)?),"podman_sha256":podman});
    let raw = super::super::retire::retire(
        p,
        JobStorageProfile::Native,
        authority.clone(),
        Some(storage),
        None,
        generation,
        publish,
        || {
            epoch_unchanged(epoch)?;
            let mounted =
                super::super::retire::mount_row(&JobStorageProfile::Native.root(p.job_id)?)?
                    .is_some();
            let current = if mounted {
                Some(snapshot(p, &slot, init, storage)?)
            } else {
                None
            };
            phase_matches(mounted, &s, current.as_ref())?;
            Ok(())
        },
    )?;
    epoch_unchanged(epoch)?;
    let receipt: Value = serde_json::from_slice(&raw).map_err(|_| "unstarted retirement JSON")?;
    linux::canonical(
        &json!({"schema":"hol-gauntlet-native-initialization-abort-result.v1","snapshot":s,"receipt":receipt,"receipt_sha256":linux::sha(&raw)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admitted_without_archive_requires_exact_native_unstarted_authority() {
        let a = json!({"schema":"hol-gauntlet-native-unstarted-storage-authority.v1","initialization_sha256":"a".repeat(64),
            "storage_receipt_sha256":"b".repeat(64),"snapshot_sha256":"c".repeat(64),"podman_sha256":"d".repeat(64)});
        assert!(
            authority_fields(&a, JobStorageProfile::Native, Some(&"b".repeat(64)), None).unwrap()
        );
        for profile in [JobStorageProfile::Build, JobStorageProfile::Dependency] {
            assert!(authority_fields(&a, profile, Some(&"b".repeat(64)), None).is_err());
        }
        for key in [
            "snapshot_sha256",
            "podman_sha256",
            "storage_receipt_sha256",
            "extra",
        ] {
            let mut bad = a.clone();
            bad[key] = json!("wrong");
            assert!(
                authority_fields(&bad, JobStorageProfile::Native, Some(&"b".repeat(64)), None)
                    .is_err(),
                "{key}"
            );
        }
        assert!(authority_fields(
            &a,
            JobStorageProfile::Native,
            Some(&"b".repeat(64)),
            Some(&"0".repeat(64))
        )
        .is_err());
        assert!(authority_fields(&a, JobStorageProfile::Native, None, None).is_err());
    }
    #[test]
    fn resumed_unmounted_cleanup_uses_retained_snapshot_without_recreating_workspace() {
        let s = json!({"workspace":{"inode":42},"preparation":{"sha256":"a".repeat(64)}});
        assert!(phase_matches(true, &s, Some(&s)).is_ok());
        assert!(phase_matches(true, &s, None).is_err());
        assert!(phase_matches(true, &s, Some(&json!({"workspace":{"inode":43}}))).is_err());
        assert!(phase_matches(false, &s, None).is_ok());
    }
}
