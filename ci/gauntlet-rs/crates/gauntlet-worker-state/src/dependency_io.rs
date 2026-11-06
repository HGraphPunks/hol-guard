//! Descriptor-bound inert inputs and one-use output capture. No package byte
//! is imported or executed while Root reads or publishes these files.
use crate::builder_candidate_source::same_file;
use gauntlet_contracts::DependencyRunIntent;
use rustix::fs::{
    fchmod, fstat, fsync, openat, renameat_with, statat, AtFlags, FileType, Mode, OFlags,
    RenameFlags,
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

pub(crate) fn read(
    dir: &OwnedFd,
    name: &str,
    owner: u32,
    mode: u32,
    maximum: u64,
) -> Result<Vec<u8>, String> {
    let fd = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_gid != owner
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != mode
        || before.st_size <= 0
        || before.st_size as u64 > maximum
    {
        return Err("dependency file metadata differs".into());
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&before, &after)
        || !same_file(&before, &visible)
        || raw.len() as i64 != before.st_size
    {
        return Err("dependency file changed while reading".into());
    }
    Ok(raw)
}

pub(crate) fn verify_inputs(job: &OwnedFd, intent: &DependencyRunIntent) -> Result<(), String> {
    let p = &intent.pins;
    let pins = crate::native_dependency_inputs::NativeDependencyInputPins {
        job: p.text("job_id"),
        source: p.text("source_sha"),
        source_archive: p.text("source_archive_sha256"),
        payload_sha256: p.text("capsule_sha256"),
        payload_bytes: p.capsule_bytes(),
        project_sha256: p.text("pyproject_sha256"),
        lock_sha256: p.text("uv_lock_sha256"),
        exporter_sha256: p.text("exporter_sha256"),
        generation: p.text("capture_worker_sha256"),
    };
    let bytes = crate::builder_candidate_source::verify_captured_source(job, pins.source_archive)
        .map_err(|e| e.to_string())?;
    crate::native_dependency_capture::source_receipt(job, &pins, bytes)?;
    let raw = read(job, "dependency-inputs.zip", 0, 0o444, 32 * 1024 * 1024)?;
    crate::native_dependency_inputs::decode_inputs(&raw, &pins)?;
    let directory = openat(
        job,
        "dependency-inputs",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    crate::native_dependency_capture::verify_extracted_inputs(&directory, &pins)?;
    let receipt = read(&directory, "capture.v1.json", 0, 0o600, 8192)?;
    let expected = gauntlet_contracts::canonicalize(pins.receipt().to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    if receipt != expected
        || format!("{:x}", Sha256::digest(&receipt)) != p.text("capture_receipt_sha256")
    {
        return Err("dependency capture receipt differs from outside intent".into());
    }
    let held = fstat(&directory).map_err(|e| e.to_string())?;
    let visible =
        statat(job, "dependency-inputs", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&held, &visible) {
        return Err("dependency input directory replaced".into());
    }
    Ok(())
}

pub(crate) fn capture_output(job: &OwnedFd) -> Result<(u64, String), String> {
    let dir = openat(
        job,
        "export",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&dir).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::Directory
        || before.st_uid != 65532
        || before.st_gid != 65532
        || before.st_mode & 0o7777 != 0o700
    {
        return Err("private unprivileged dependency export required".into());
    }
    let raw = read(&dir, "dependencies.zip", 65532, 0o600, 256 * 1024 * 1024)?;
    let fd = openat(
        job,
        "dependencies.receiving",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "dependency output already consumed or unavailable")?;
    fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    let mut file = File::from(fd);
    file.write_all(&raw)
        .and_then(|_| file.sync_all())
        .map_err(|_| "dependency output copy commit uncertain")?;
    fchmod(&file, Mode::RUSR | Mode::RGRP | Mode::ROTH).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    let digest = format!("{:x}", Sha256::digest(&raw));
    if read(job, "dependencies.receiving", 0, 0o444, 256 * 1024 * 1024)? != raw
        || read(&dir, "dependencies.zip", 65532, 0o600, 256 * 1024 * 1024)? != raw
    {
        return Err("dependency output differs on independent readback".into());
    }
    let after = fstat(&dir).map_err(|e| e.to_string())?;
    let visible = statat(job, "export", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&before, &after) || !same_file(&before, &visible) {
        return Err("dependency export directory changed".into());
    }
    renameat_with(
        job,
        "dependencies.receiving",
        job,
        "dependencies.zip",
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| "dependency output publication uncertain")?;
    fsync(job).map_err(|_| "dependency output directory commit uncertain")?;
    if read(job, "dependencies.zip", 0, 0o444, 256 * 1024 * 1024)? != raw {
        return Err("published dependency output changed".into());
    }
    Ok((raw.len() as u64, digest))
}
