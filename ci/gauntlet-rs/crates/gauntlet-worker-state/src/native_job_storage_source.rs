//! Original one-use source custody is the authority for later bounded jobs.
use super::{lifecycle, JobStorageProfile};
use serde_json::Value;
use std::os::fd::OwnedFd;

pub(crate) fn receipt(slot: &OwnedFd) -> Result<Option<Value>, String> {
    let Some(raw) =
        crate::feature_files::read(slot, "source-capture.v2.json", (0, 0), 0o600, 24576)?
    else {
        return Ok(None);
    };
    if super::linux::canonical(&serde_json::from_slice::<Value>(&raw).map_err(|e| e.to_string())?)?
        != raw
    {
        return Err("canonical source-capture v2 required".into());
    }
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if v.as_object().is_none_or(|o| o.len() != 11)
        || v["schema"] != "hol-gauntlet-native-source-capture.v2"
        || !v["job_id"].as_str().is_some_and(|s| crate::hex(s, 16))
        || !v["source_sha"].as_str().is_some_and(|s| crate::hex(s, 40))
        || !v["worker_generation"]
            .as_str()
            .is_some_and(|s| crate::hex(s, 64))
        || !v["source_archive_sha256"]
            .as_str()
            .is_some_and(|s| crate::hex(s, 64))
        || !v["source_bytes"]
            .as_u64()
            .is_some_and(|n| (1..=256 * 1024 * 1024).contains(&n))
        || v["builder_executed"] != false
        || v["execution_eligible"] != false
        || v["model_requests"] != 0
    {
        return Err("exact original bounded source-capture receipt required".into());
    }
    Ok(Some(v))
}
pub(crate) fn verify(
    job: &str,
    slot: &OwnedFd,
    required: Option<JobStorageProfile>,
) -> Result<Option<Value>, String> {
    let Some(v) = receipt(slot)? else {
        lifecycle::require_absent(job)?;
        return Ok(None);
    };
    if v["job_id"] != job {
        return Err("bounded source job identity changed".into());
    }
    if crate::feature_files::read(slot, "source-capture.v1.json", (0, 0), 0o600, 8192)?.is_some() {
        return Err("mixed source custody versions refused".into());
    }
    let profile: JobStorageProfile = v["storage_profile"]
        .as_str()
        .ok_or("source storage profile absent")?
        .parse()?;
    if profile == JobStorageProfile::Native || required.is_some_and(|p| p != profile) {
        return Err("original source storage profile differs from operation".into());
    }
    lifecycle::verify_binding(
        &v["storage"],
        v["source_sha"].as_str().unwrap(),
        job,
        v["worker_generation"].as_str().unwrap(),
        profile,
    )?;
    let parent = crate::open_root_owned_public_directory(std::path::Path::new(lifecycle::BASE))
        .map_err(|e| e.to_string())?;
    let storage = crate::feature_files::open_directory(&parent, job, (0, 0))?;
    super::admission::verify_admitted(
        &storage,
        &super::linux::canonical(&v["storage"]["receipt"])?,
        &super::linux::canonical(&v)?,
    )?;
    Ok(Some(v))
}
pub(crate) fn require_profile(
    job: &str,
    slot: &OwnedFd,
    profile: JobStorageProfile,
) -> Result<bool, String> {
    Ok(verify(job, slot, Some(profile))?.is_some())
}
pub(crate) fn container_arguments(
    job: &str,
    slot: &OwnedFd,
    profile: JobStorageProfile,
) -> Result<Vec<String>, String> {
    if !require_profile(job, slot, profile)? {
        return Ok(Vec::new());
    }
    let scratch = crate::feature_files::directory(slot, "scratch", (0, 0), true)?;
    for name in ["work", "tmp"] {
        let directory = crate::feature_files::directory(&scratch, name, (0, 0), true)?;
        rustix::fs::fchown(
            &directory,
            Some(rustix::process::Uid::from_raw(65532)),
            Some(rustix::process::Gid::from_raw(65532)),
        )
        .and_then(|_| rustix::fs::fsync(&directory))
        .map_err(|e| e.to_string())?;
    }
    rustix::fs::fsync(&scratch).map_err(|e| e.to_string())?;
    let root = format!("/var/lib/hol-gauntlet/builds/{job}/scratch");
    Ok(vec![
        "--read-only".into(),
        "--read-only-tmpfs=false".into(),
        "--volume".into(),
        format!("{root}/work:/work:rw"),
        "--volume".into(),
        format!("{root}/tmp:/tmp:rw"),
        "--volume".into(),
        format!("{root}/tmp:/var/tmp:rw"),
        "--tmpfs".into(),
        "/dev/shm:rw,nosuid,nodev,noexec,size=67108864,nr_inodes=16384,mode=1777".into(),
    ])
}
pub(crate) fn verify_container(
    job: &str,
    v: &Value,
    profile: JobStorageProfile,
) -> Result<(), String> {
    if !lifecycle::present(job)? {
        return Ok(());
    }
    let slot =
        crate::open_root_owned_public_directory(&profile.root(job)?).map_err(|e| e.to_string())?;
    if !require_profile(job, &slot, profile)? {
        return Ok(());
    }
    if v["HostConfig"]["ReadonlyRootfs"] != true {
        return Err("bounded job container root must be readonly".into());
    }
    let mounts = v["Mounts"]
        .as_array()
        .ok_or("actual bounded container mounts absent")?;
    let root = format!("/var/lib/hol-gauntlet/builds/{job}/scratch");
    for (name, target) in [("work", "/work"), ("tmp", "/tmp"), ("tmp", "/var/tmp")] {
        let rows = mounts
            .iter()
            .filter(|m| m["Destination"] == target)
            .collect::<Vec<_>>();
        if rows.len() != 1
            || rows[0]["Source"] != format!("{root}/{name}")
            || rows[0]["Type"] != "bind"
            || rows[0]["RW"] != true
        {
            return Err("actual writable scratch must bind the original bounded volume".into());
        }
    }
    for m in mounts {
        if m["RW"] == true
            && m["Type"] == "bind"
            && !matches!(
                m["Destination"].as_str(),
                Some("/work" | "/tmp" | "/var/tmp" | "/output")
            )
        {
            return Err("unexpected writable container bind outside bounded job paths".into());
        }
    }
    let tmpfs = v["HostConfig"]["Tmpfs"]
        .as_object()
        .ok_or("explicit bounded shared-memory tmpfs absent")?;
    if tmpfs.len() != 1
        || !tmpfs
            .get("/dev/shm")
            .and_then(Value::as_str)
            .is_some_and(|s| {
                [
                    "size=67108864",
                    "nr_inodes=16384",
                    "nosuid",
                    "nodev",
                    "noexec",
                ]
                .iter()
                .all(|x| s.split(',').any(|a| a == *x))
            })
    {
        return Err("explicit tmpfs byte and inode ceilings differ".into());
    }
    Ok(())
}
pub(crate) fn record_read(
    job: &str,
    profile: JobStorageProfile,
    archive: &str,
    result: &str,
    binding: &str,
    readback: &Value,
) -> Result<(), String> {
    if !lifecycle::present(job)? {
        return Ok(());
    }
    let root =
        crate::open_root_owned_public_directory(&profile.root(job)?).map_err(|e| e.to_string())?;
    let source = verify(job, &root, Some(profile))?
        .ok_or("bounded artifact read lacks original source capture")?;
    if ![archive, result, binding].iter().all(|s| crate::hex(s, 64)) {
        return Err("outside artifact result/binding pins required".into());
    }
    let value = serde_json::json!({"schema":"hol-gauntlet-source-storage-artifact-read.v1","source_capture":source,
        "source_capture_sha256":super::linux::sha(&super::linux::canonical(&source)?),"profile":profile.as_str(),"job_id":job,
        "storage_receipt_sha256":source["storage"]["receipt_sha256"],"archive_sha256":archive,"result_sha256":result,"host_binding_sha256":binding,
        "readback_sha256":super::linux::sha(&super::linux::canonical(readback)?)});
    let slot =
        crate::open_root_owned_public_directory(&std::path::Path::new(lifecycle::BASE).join(job))
            .map_err(|e| e.to_string())?;
    if let Some(raw) =
        crate::feature_files::read(&slot, "artifact-read.json", (0, 0), 0o600, 24576)?
    {
        let old: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if super::linux::canonical(&old)? != raw
            || old.as_object().is_none_or(|o| o.len() != 10)
            || [
                "schema",
                "source_capture",
                "source_capture_sha256",
                "profile",
                "job_id",
                "storage_receipt_sha256",
                "archive_sha256",
                "result_sha256",
                "host_binding_sha256",
            ]
            .iter()
            .any(|k| old[*k] != value[*k])
        {
            return Err("original artifact readback binding changed".into());
        }
        return Ok(());
    }
    crate::feature_files::write(
        &slot,
        "artifact-read.json",
        &super::linux::canonical(&value)?,
        (0, 0),
        0o600,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn retire_source_job_storage(
    p: &super::JobStoragePins<'_>,
    profile: JobStorageProfile,
    storage_sha: &str,
    archive_sha: &str,
    result_sha: &str,
    host_binding: &str,
    generation: &str,
    host_receipt_sha: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if profile == JobStorageProfile::Native
        || ![storage_sha, archive_sha, result_sha, host_binding]
            .iter()
            .all(|s| crate::hex(s, 64))
    {
        return Err("exact original source artifact/Host storage pins required".into());
    }
    let slot = crate::open_root_owned_public_directory(
        &std::path::Path::new(lifecycle::BASE).join(p.job_id),
    )
    .map_err(|e| e.to_string())?;
    let raw = crate::feature_files::required(&slot, "artifact-read.json", (0, 0), 0o600, 24576)?;
    let authority: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if super::linux::canonical(&authority)? != raw
        || authority.as_object().is_none_or(|o| o.len() != 10)
        || authority["schema"] != "hol-gauntlet-source-storage-artifact-read.v1"
        || authority["job_id"] != p.job_id
        || authority["profile"] != profile.as_str()
        || authority["storage_receipt_sha256"] != storage_sha
        || authority["archive_sha256"] != archive_sha
        || authority["result_sha256"] != result_sha
        || authority["host_binding_sha256"] != host_binding
        || authority["source_capture"]["source_sha"] != p.source_sha
        || authority["source_capture"]["worker_generation"] != p.worker_generation
        || authority["source_capture_sha256"]
            != super::linux::sha(&super::linux::canonical(&authority["source_capture"])?)
    {
        return Err("retirement differs from original Host-bound artifact result/readback".into());
    }
    let authority = super::artifact::retirement_ack(&slot, &authority, host_receipt_sha)?;
    super::retire::retire(
        p,
        profile,
        authority,
        Some(storage_sha),
        Some(archive_sha),
        generation,
        publish,
        || {
            let root = crate::builder_candidate_source::open_fixed_build_slot(p.job_id)
                .map_err(|e| e.to_string())?;
            verify(p.job_id, &root, Some(profile))?;
            crate::candidate_capture::inactive(p.job_id).map_err(|e| e.to_string())?;
            crate::require_rust_job_slice_absent(p.job_id).map_err(|e| e.to_string())?;
            crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
            let (name, mode) = if profile == JobStorageProfile::Build {
                ("candidate.zip", 0o444)
            } else {
                ("dependencies.zip", 0o444)
            };
            let bytes = crate::dependency_io::read(&root, name, 0, mode, 256 * 1024 * 1024)?;
            if super::linux::sha(&bytes) != archive_sha {
                return Err(
                    "original captured artifact changed before acknowledged retirement".into(),
                );
            }
            lifecycle::JobVolume::read(p, profile)?;
            Ok(())
        },
    )
}
