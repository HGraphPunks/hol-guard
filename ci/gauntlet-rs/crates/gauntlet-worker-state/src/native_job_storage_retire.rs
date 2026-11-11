//! Explicit, resumable retirement of original fresh backing files only.
use super::{
    admission, lifecycle,
    linux::{self, LoopDevice},
    JobStoragePins, JobStorageProfile,
};
use crate::RunReservationJournal;
use rustix::fs::{fstat, fsync, openat, statat, unlinkat, AtFlags, Mode, OFlags};
use serde_json::{json, Value};
use std::{ffi::CString, fs::File, io::Read, os::fd::OwnedFd, path::Path};

fn read_value(slot: &OwnedFd, name: &str) -> Result<Option<Value>, String> {
    let Some(raw) = crate::feature_files::read(slot, name, (0, 0), 0o600, 24576)? else {
        return Ok(None);
    };
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if linux::canonical(&v)? != raw {
        return Err("canonical original retirement custody required".into());
    }
    Ok(Some(v))
}
pub(super) fn mount_row(target: &Path) -> Result<Option<Vec<String>>, String> {
    let mut raw = String::new();
    File::open("/proc/thread-self/mountinfo")
        .map_err(|e| e.to_string())?
        .take(2 * 1024 * 1024 + 1)
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 2 * 1024 * 1024 {
        return Err("mount inventory exceeds retirement bound".into());
    }
    let target = target.to_str().ok_or("fixed storage target UTF8")?;
    let rows = raw
        .lines()
        .map(|r| {
            r.split_ascii_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|r| r.get(4).map(String::as_str) == Some(target))
        .collect::<Vec<_>>();
    match rows.len() {
        0 => Ok(None),
        1 => Ok(rows.into_iter().next()),
        _ => Err("stacked job mounts block retirement".into()),
    }
}
pub(crate) fn verify_retired(slot: &OwnedFd, job: &str, raw: &[u8]) -> Result<(), String> {
    super::owner::verify_finished(job)?;
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let intent = crate::feature_files::required(slot, "retirement.json", (0, 0), 0o600, 24576)?;
    if v.as_object().is_none_or(|o| o.len() != 18)
        || linux::canonical(&v)? != raw
        || v["schema"] != "hol-gauntlet-job-storage-retired.v1"
        || v["job_id"] != job
        || v["retirement_intent_sha256"] != linux::sha(&intent)
        || [
            "volume_unmounted",
            "loop_detached",
            "backing_absent",
            "job_consumed",
        ]
        .iter()
        .any(|k| v[*k] != true)
        || [
            "retained_storage",
            "execution_eligible",
            "qualification_eligible",
        ]
        .iter()
        .any(|k| v[*k] != false)
    {
        return Err("exact original completed retirement required".into());
    }
    let profile: JobStorageProfile = v["profile"]
        .as_str()
        .ok_or("retired profile absent")?
        .parse()?;
    let target = profile.root(job)?;
    if mount_row(&target)?.is_some()
        || !matches!(
            statat(slot, "backing.ext4", AtFlags::SYMLINK_NOFOLLOW),
            Err(rustix::io::Errno::NOENT)
        )
    {
        return Err("retired volume mount/backing remains".into());
    }
    covered(&target, read_value(slot, "covered.json")?.as_ref())
}
fn covered(target: &Path, expected: Option<&Value>) -> Result<(), String> {
    if let Some(expected) = expected {
        let root = crate::open_root_owned_public_directory(target).map_err(|e| e.to_string())?;
        crate::feature_files::private_directory(&root, (0, 0))?;
        let s = fstat(&root).map_err(|e| e.to_string())?;
        if *expected != json!({"device":s.st_dev,"inode":s.st_ino,"uid":0,"gid":0,"mode":0o700}) {
            return Err("original covered directory changed during retirement".into());
        }
    }
    Ok(())
}
fn no_backing_loop(backing: &rustix::fs::Stat) -> Result<(), String> {
    for (count, entry) in std::fs::read_dir("/sys/block")
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if count > 8192 {
            return Err("kernel block inventory exceeds retirement bound".into());
        }
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("kernel block name UTF8")?;
        let Some(n) = name.strip_prefix("loop") else {
            continue;
        };
        let n = n
            .parse::<u32>()
            .ok()
            .filter(|n| *n < 4096)
            .ok_or("kernel loop number outside bound")?;
        if LoopDevice::retained(n)?.references(backing)? {
            return Err("original backing still has a loop association".into());
        }
    }
    Ok(())
}
fn backing(
    slot: &OwnedFd,
    profile: JobStorageProfile,
    original: Option<&Value>,
) -> Result<Option<File>, String> {
    let fd = match openat(
        slot,
        "backing.ext4",
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let s = fstat(&fd).map_err(|e| e.to_string())?;
    if s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o177777 != 0o100600
        || s.st_nlink != 1
        || s.st_size < 0
        || s.st_size as u64 > profile.bytes()
    {
        return Err("partial backing is not the original private ordinary file".into());
    }
    if let Some(original) = original {
        for (key, actual) in [
            ("device", json!(s.st_dev)),
            ("inode", json!(s.st_ino)),
            ("bytes", json!(s.st_size)),
        ] {
            if original[key] != actual {
                return Err("original retirement backing inode/capacity changed".into());
            }
        }
    }
    Ok(Some(File::from(fd)))
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn retire(
    p: &JobStoragePins<'_>,
    profile: JobStorageProfile,
    authority: Value,
    storage_sha: Option<&str>,
    archive_sha: Option<&str>,
    generation: &str,
    publish: bool,
    before: impl FnOnce() -> Result<(), String>,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    linux::pins_valid(p)?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let unstarted =
        super::native::unstarted::authority_mode(&authority, p, profile, storage_sha, archive_sha)?;
    let epoch = crate::native_worker::interruption_epoch();
    if storage_sha.is_some_and(|s| !crate::hex(s, 64))
        || archive_sha.is_some_and(|s| !crate::hex(s, 64))
        || (!unstarted && storage_sha.is_some() != archive_sha.is_some())
    {
        return Err("exact outside storage/archive pins required".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    if unstarted {
        super::native::unstarted::recheck(p, &authority, &journal)?;
    }
    let parent = crate::open_root_owned_public_directory(Path::new(lifecycle::BASE))
        .map_err(|e| e.to_string())?;
    let slot = crate::feature_files::open_directory(&parent, p.job_id, (0, 0))?;
    let intent = json!({"schema":"hol-gauntlet-job-storage-intent.v1","source_sha":p.source_sha,"job_id":p.job_id,"worker_generation":p.worker_generation,"mke2fs_sha256":p.mke2fs_sha256,"profile":profile.as_str(),"limits":profile.limits()});
    if read_value(&slot, "intent.json")? != Some(intent) {
        return Err("retirement differs from original one-use volume intent".into());
    }
    let context = json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":p.source_sha,"job_id":p.job_id,"worker_generation":p.worker_generation,"mke2fs_sha256":p.mke2fs_sha256,"profile":profile.as_str(),"retirer_generation":generation,"authority":authority,"storage_receipt_sha256":storage_sha,"archive_sha256":archive_sha});
    let expected = linux::canonical(&context)?;
    let target = profile.root(p.job_id)?;
    let original = read_value(&slot, lifecycle::RECEIPT)?;
    if let Some(pin) = storage_sha {
        if original
            .as_ref()
            .map(linux::canonical)
            .transpose()?
            .as_deref()
            .map(linux::sha)
            .as_deref()
            != Some(pin)
        {
            return Err("retirement storage receipt differs from outside pin".into());
        }
    }
    let result = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":p.source_sha,"job_id":p.job_id,"worker_generation":p.worker_generation,"profile":profile.as_str(),"retirer_generation":generation,
        "retirement_intent_sha256":linux::sha(&expected),"storage_receipt_sha256":storage_sha,"archive_sha256":archive_sha,"partial":storage_sha.is_none(),"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":if storage_sha.is_none(){json!(0)}else{Value::Null}});
    let result_raw = linux::canonical(&result)?;
    let covered_original = read_value(&slot, "covered.json")?;
    let allocation = read_value(&slot, "allocation.json")?;
    let loop_identity = original
        .as_ref()
        .map(|v| &v["loop"])
        .or_else(|| allocation.as_ref().map(|v| &v["loop"]));
    let device = loop_identity
        .map(|v| {
            v["number"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or("original retirement loop number absent")
                .and_then(|n| {
                    LoopDevice::retained(n).map_err(|_| "original retirement loop unavailable")
                })
        })
        .transpose()
        .map_err(str::to_owned)?;
    let verify_gone = || -> Result<(), String> {
        if mount_row(&target)?.is_some()
            || !matches!(
                statat(&slot, "backing.ext4", AtFlags::SYMLINK_NOFOLLOW),
                Err(rustix::io::Errno::NOENT)
            )
        {
            return Err("retired storage mount/backing remains or is uncertain".into());
        }
        covered(&target, covered_original.as_ref())?;
        if let Some(device) = &device {
            let old = original
                .as_ref()
                .map(|v| &v["backing"])
                .or_else(|| allocation.as_ref().map(|v| &v["backing"]))
                .ok_or("original loop backing identity absent")?;
            if device.references_identity(
                old["device"]
                    .as_u64()
                    .ok_or("original backing device absent")?,
                old["inode"]
                    .as_u64()
                    .ok_or("original backing inode absent")?,
            )? {
                return Err("retired original loop association remains".into());
            }
        }
        Ok(())
    };
    if let Some(raw) = crate::feature_files::read(&slot, "retired.json", (0, 0), 0o600, 8192)? {
        if raw != result_raw
            || crate::feature_files::required(&slot, "retirement.json", (0, 0), 0o600, 24576)?
                != expected
        {
            return Err("original storage retirement binding changed".into());
        }
        verify_gone()?;
        if publish {
            super::owner::finish(p.job_id)?;
        } else {
            super::owner::verify_finished(p.job_id)?;
        }
        return Ok(raw);
    }
    if storage_sha.is_some() || super::owner::cleanup_access(p.job_id).is_err() {
        super::owner::enter_pinned(p.source_sha, p.job_id, p.worker_generation)?;
    }
    if let Some(origin) = read_value(&slot, "origin.json")? {
        if origin != json!({"namespace":linux::namespace()?,"boot_id":linux::boot()?}) {
            return Err("original allocation namespace/boot changed".into());
        }
    } else {
        admission::closed_inventory(&slot, &["intent.json", "retirement.json", "retired.json"])?;
    }
    if !publish {
        return Err("storage retirement incomplete; read action cannot mutate".into());
    }
    match crate::feature_files::read(&slot, "retirement.json", (0, 0), 0o600, 24576)? {
        Some(raw) if raw == expected => {
            if unstarted {
                before()?;
            }
        }
        Some(_) => return Err("another retirement intent owns this volume".into()),
        None => {
            before()?;
            crate::feature_files::write(&slot, "retirement.json", &expected, (0, 0), 0o600)?;
        }
    }
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    let original_backing = original
        .as_ref()
        .map(|v| &v["backing"])
        .or_else(|| allocation.as_ref().map(|v| &v["backing"]));
    let backing = backing(&slot, profile, original_backing)?;
    if unstarted {
        super::native::unstarted::epoch_unchanged(epoch)?;
    }
    if let Some(row) = mount_row(&target)? {
        let device = device
            .as_ref()
            .ok_or("unrecorded mount blocks partial volume cleanup")?;
        let file = backing.as_ref().ok_or("mounted original backing absent")?;
        device.identity(file, profile.bytes())?;
        let d = fstat(&device.file).map_err(|e| e.to_string())?;
        let dev = format!("{}:{}", libc::major(d.st_rdev), libc::minor(d.st_rdev));
        let split = row
            .iter()
            .position(|s| s == "-")
            .ok_or("retirement mount separator absent")?;
        if row.get(2) != Some(&dev)
            || row.get(3).map(String::as_str) != Some("/")
            || row.get(split + 1).map(String::as_str) != Some("ext4")
        {
            return Err("another mount occupies the original storage target".into());
        }
        let a = allocation
            .as_ref()
            .ok_or("original mounted allocation metadata absent")?;
        if a["namespace"] != linux::namespace()? || a["boot_id"] != linux::boot()? {
            return Err("original storage namespace/boot changed".into());
        }
        linux::read_capacity(file, profile, &linux::uuid(p, profile)?)?;
        let target_c = CString::new(target.to_str().ok_or("storage target UTF8")?)
            .map_err(|_| "storage target NUL")?;
        if unsafe { libc::umount2(target_c.as_ptr(), 0) } != 0 {
            return Err("original storage normal unmount failed; retain retirement intent".into());
        }
    }
    if mount_row(&target)?.is_some() {
        return Err("original volume still mounted".into());
    }
    covered(&target, covered_original.as_ref())?;
    if let Some(device) = &device {
        if unstarted {
            super::native::unstarted::epoch_unchanged(epoch)?;
        }
        if !device.detached()? {
            device.identity(
                backing.as_ref().ok_or("original loop backing absent")?,
                profile.bytes(),
            )?;
            device.detach()?;
            if !device.detached()? {
                return Err("original loop detach remains pending".into());
            }
        }
    }
    if let Some(backing) = &backing {
        if unstarted {
            super::native::unstarted::epoch_unchanged(epoch)?;
        }
        let s = fstat(backing).map_err(|e| e.to_string())?;
        no_backing_loop(&s)?;
        let visible =
            statat(&slot, "backing.ext4", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        if !crate::builder_candidate_source::same_file(&s, &visible) {
            return Err("original backing changed before retirement unlink".into());
        }
        unlinkat(&slot, "backing.ext4", AtFlags::empty())
            .and_then(|_| fsync(&slot))
            .map_err(|e| e.to_string())?;
    }
    verify_gone()?;
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    if unstarted {
        super::native::unstarted::epoch_unchanged(epoch)?;
    }
    crate::feature_files::write(&slot, "retired.json", &result_raw, (0, 0), 0o600)?;
    super::owner::finish(p.job_id)?;
    Ok(result_raw)
}

pub fn abort_native_job_storage(
    p: &JobStoragePins<'_>,
    profile: JobStorageProfile,
    generation: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    if !Path::new(lifecycle::BASE)
        .join(p.job_id)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return super::owner::abort_only(p, profile, generation, publish);
    }
    let root = crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(p.job_id))
        .map_err(|e| e.to_string())?;
    if read_value(&root, "intent.json")?.is_none() && super::owner::present(p.job_id)? {
        return super::owner::abort_only(p, profile, generation, publish);
    }
    let authority =
        read_value(&root, "intent.json")?.ok_or("original partial storage intent absent")?;
    retire(
        p,
        profile,
        authority,
        None,
        None,
        generation,
        publish,
        || {
            if crate::feature_files::read(&root, "admitted.json", (0, 0), 0o600, 1024)?.is_some() {
                return Err("completed storage requires authenticated export retirement".into());
            }
            admission::closed_inventory(
                &root,
                &[
                    "intent.json",
                    "origin.json",
                    "covered.json",
                    "backing.ext4",
                    "mke2fs.conf",
                    "allocation.json",
                    "storage.json",
                ],
            )?;
            let journal = RunReservationJournal::open_root_owned(Path::new(
                crate::builder_image_context::RUST_STATE,
            ))
            .map_err(|e| e.to_string())?;
            crate::native_initialize::require_unstarted_job(&journal, p.job_id)?;
            crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
            crate::dependency_state::client_group_absent(p.job_id)?;
            if !crate::builder_candidate_process::container_absent(p.job_id)
                .map_err(|e| e.to_string())?
            {
                return Err("partial job has a candidate container".into());
            }
            let target = profile.root(p.job_id)?;
            if target.try_exists().map_err(|e| e.to_string())? {
                let job =
                    crate::open_root_owned_public_directory(&target).map_err(|e| e.to_string())?;
                if profile == JobStorageProfile::Native {
                    admission::closed_inventory(&job, &["lost+found", "workspace"])?;
                    match statat(&job, "workspace", AtFlags::SYMLINK_NOFOLLOW) {
                        Err(rustix::io::Errno::NOENT) => {}
                        Err(e) => return Err(e.to_string()),
                        Ok(s) => {
                            let owner = (s.st_uid, s.st_gid);
                            if !matches!(owner, (0, 0) | (10001, 10001)) {
                                return Err(
                                    "partial workspace owner differs from initialization phases"
                                        .into(),
                                );
                            }
                            admission::closed_inventory(
                                &crate::feature_files::open_directory(&job, "workspace", owner)?,
                                &[],
                            )?;
                        }
                    }
                } else {
                    admission::closed_inventory(
                        &job,
                        &[
                            "lost+found",
                            "source.receiving",
                            "source.tar.gz",
                            "source-capture.v2.json",
                        ],
                    )?;
                }
            }
            Ok(())
        },
    )
}
