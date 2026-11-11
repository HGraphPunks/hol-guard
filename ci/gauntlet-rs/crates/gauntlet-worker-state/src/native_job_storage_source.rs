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
    verify_mode(job, slot, required, false)
}
fn verify_mode(
    job: &str,
    slot: &OwnedFd,
    required: Option<JobStorageProfile>,
    cleanup: bool,
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
    let verify = if cleanup {
        lifecycle::verify_cleanup_binding
    } else {
        lifecycle::verify_binding
    };
    verify(
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
    let mut args = vec![
        "--read-only".into(),
        "--read-only-tmpfs=false".into(),
        "--volume".into(),
        format!("{root}/work:/work:rw"),
        "--volume".into(),
        format!("{root}/tmp:/tmp:rw"),
        "--volume".into(),
        format!("{root}/tmp:/var/tmp:rw"),
    ];
    args.extend(super::temporary::create(
        job,
        super::temporary::Scope::source(profile)?,
    )?);
    Ok(args)
}
pub(crate) fn verify_container(
    job: &str,
    v: &Value,
    profile: JobStorageProfile,
) -> Result<(), String> {
    verify_container_mode(job, v, profile, false)
}
pub(crate) fn verify_container_for_cleanup(
    job: &str,
    v: &Value,
    profile: JobStorageProfile,
) -> Result<(), String> {
    verify_container_mode(job, v, profile, true)
}
fn verify_container_mode(
    job: &str,
    v: &Value,
    profile: JobStorageProfile,
    cleanup: bool,
) -> Result<(), String> {
    if !lifecycle::present(job)? {
        return Ok(());
    }
    if cleanup {
        super::owner::cleanup_receipt(job)?;
    }
    let slot =
        crate::open_root_owned_public_directory(&profile.root(job)?).map_err(|e| e.to_string())?;
    if verify_mode(job, &slot, Some(profile), cleanup)?.is_none() {
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
    writable_mounts(job, mounts)?;
    let verify = if cleanup {
        super::temporary::verify_for_cleanup
    } else {
        super::temporary::verify
    };
    verify(job, super::temporary::Scope::source(profile)?, Some(v))
}
fn writable_mounts(job: &str, mounts: &[Value]) -> Result<(), String> {
    for m in mounts {
        let writable = m["RW"]
            .as_bool()
            .ok_or("actual writable mount state absent")?;
        if writable
            && (m["Type"] != "bind"
                || !matches!(
                    m["Destination"].as_str(),
                    Some("/work" | "/tmp" | "/var/tmp" | "/output" | "/dev/shm")
                ))
        {
            return Err("unexpected writable container mount outside bounded job paths".into());
        }
    }
    let output = mounts
        .iter()
        .filter(|m| m["Destination"] == "/output")
        .collect::<Vec<_>>();
    if output.len() != 1
        || output[0]["Type"] != "bind"
        || output[0]["RW"] != true
        || output[0]["Source"] != format!("/var/lib/hol-gauntlet/builds/{job}/export")
    {
        return Err("original bounded export bind required".into());
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_running(
    job: &str,
    profile: JobStorageProfile,
    podman: &str,
    cid: &str,
    image: &str,
    label: &str,
    binding: &str,
) -> Result<bool, String> {
    if !lifecycle::present(job)? {
        return Ok(true);
    }
    if !crate::hex(cid, 64) {
        return Err("original temporary container CID required".into());
    }
    let raw =
        crate::dependency_podman::run(podman, &["container".into(), "inspect".into(), cid.into()])?;
    let rows: Vec<Value> = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if rows.len() != 1
        || crate::dependency_podman::validated_container_identity(
            &rows[0], job, image, label, binding,
        )? != cid
    {
        return Err("temporary measurement container binding changed".into());
    }
    super::temporary::observe(job, super::temporary::Scope::source(profile)?, &rows[0])
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
    super::temporary::require_absent(job, super::temporary::Scope::source(profile)?)?;
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

pub(crate) fn validated_container_identity(
    v: &Value,
    job: &str,
    image: &str,
    label: &str,
    binding: &str,
) -> Result<String, String> {
    checked_identity(v, job, image, label, binding, false)
}
pub(crate) fn validated_container_identity_for_cleanup(
    v: &Value,
    job: &str,
    image: &str,
    label: &str,
    binding: &str,
) -> Result<String, String> {
    checked_identity(v, job, image, label, binding, true)
}
fn checked_identity(
    v: &Value,
    job: &str,
    image: &str,
    label: &str,
    binding: &str,
    cleanup: bool,
) -> Result<String, String> {
    if !crate::hex(job, 16)
        || !crate::hex(binding, 64)
        || !image
            .strip_prefix("sha256:")
            .is_some_and(|s| crate::hex(s, 64))
    {
        return Err("exact outside container identity pins required".into());
    }
    let cid = v["Id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("full owned container CID required")?;
    let image_matches = v["Image"].as_str().is_some_and(|s| {
        s.strip_prefix("sha256:").unwrap_or(s) == image.trim_start_matches("sha256:")
    });
    if v["Name"] != format!("hol-gauntlet-build-{job}")
        || !image_matches
        || v["Config"]["Labels"][label] != binding
        || v["Config"]["User"] != "65532:65532"
    {
        return Err("container identity differs from its outside binding".into());
    }
    let verify = if cleanup {
        verify_container_for_cleanup
    } else {
        verify_container
    };
    verify(
        job,
        v,
        if label == "hol-gauntlet.candidate-intent" {
            crate::JobStorageProfile::Build
        } else {
            crate::JobStorageProfile::Dependency
        },
    )?;
    Ok(cid.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_sources_refuse_anonymous_writable_volumes_and_foreign_exports() {
        let job = "0123456789abcdef";
        let output = serde_json::json!({"Destination":"/output","Type":"bind","RW":true,
            "Source":format!("/var/lib/hol-gauntlet/builds/{job}/export")});
        assert!(writable_mounts(job, std::slice::from_ref(&output)).is_ok());
        for extra in [
            serde_json::json!({"Destination":"/cache","Type":"volume","RW":true}),
            serde_json::json!({"Destination":"/work","Type":"tmpfs","RW":true}),
            serde_json::json!({"Destination":"/elsewhere","Type":"bind","RW":true}),
        ] {
            assert!(writable_mounts(job, &[output.clone(), extra]).is_err());
        }
        let mut foreign = output;
        foreign["Source"] =
            serde_json::json!("/var/lib/hol-gauntlet/builds/fedcba9876543210/export");
        assert!(writable_mounts(job, &[foreign]).is_err());
        assert!(writable_mounts(job, &[]).is_err());
    }
}
