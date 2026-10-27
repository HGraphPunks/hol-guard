//! Lease-bound native capsule capture. No interpreter, installer or adapter runs.

use crate::builder_candidate_source::{open_fixed_build_slot, same_file, verify_captured_source};
use crate::native_dependency_inputs::{
    decode_inputs, NativeDependencyInputPins, INPUT_LIMITS, INPUT_NAMES,
};
use crate::{BoottimeDeadline, RunReservationJournal};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, openat, renameat_with, statat, AtFlags, FileType, Mode, OFlags,
    RenameFlags,
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

pub(crate) fn verify_extracted_inputs(
    directory: &OwnedFd,
    pins: &NativeDependencyInputPins<'_>,
) -> Result<(), String> {
    let stat = fstat(directory).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err("private Root dependency input directory required".into());
    }
    for index in 0..3 {
        let fd = openat(
            directory,
            INPUT_NAMES[index],
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "captured dependency member unavailable")?;
        let before = fstat(&fd).map_err(|e| e.to_string())?;
        let mode = if index == 2 { 0o555 } else { 0o444 };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != 0
            || before.st_gid != 0
            || before.st_nlink != 1
            || before.st_mode & 0o7777 != mode
            || before.st_size <= 0
            || before.st_size as u64 > INPUT_LIMITS[index]
        {
            return Err("captured dependency member metadata differs".into());
        }
        let mut file = File::from(fd);
        let mut raw = Vec::new();
        (&mut file)
            .take(INPUT_LIMITS[index] + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        let after = fstat(&file).map_err(|e| e.to_string())?;
        let visible = statat(directory, INPUT_NAMES[index], AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        if !same_file(&before, &after)
            || !same_file(&before, &visible)
            || raw.len() as i64 != before.st_size
            || format!("{:x}", Sha256::digest(&raw)) != pins.hashes()[index]
        {
            return Err("captured dependency member changed or differs from hash".into());
        }
    }
    Ok(())
}

pub(crate) fn source_receipt(
    slot: &OwnedFd,
    pins: &NativeDependencyInputPins<'_>,
    source_bytes: u64,
) -> Result<(), String> {
    let fd = openat(
        slot,
        "source-capture.v1.json",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "native source receipt missing")?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o600
        || !(1..=8192).contains(&before.st_size)
    {
        return Err("private native source receipt required".into());
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    (&mut file)
        .take(8193)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible = statat(slot, "source-capture.v1.json", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| e.to_string())?;
    if !same_file(&before, &after)
        || !same_file(&before, &visible)
        || raw.len() as i64 != before.st_size
        || gauntlet_contracts::canonicalize(&raw).map_err(|e| e.to_string())? != raw
    {
        return Err("native source receipt changed or is noncanonical".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if value.as_object().is_none_or(|v| v.len() != 9)
        || value["schema"] != "hol-gauntlet-native-source-capture.v1"
        || value["job_id"] != pins.job
        || value["source_sha"] != pins.source
        || value["source_archive_sha256"] != pins.source_archive
        || value["source_bytes"] != source_bytes
        || !value["worker_generation"]
            .as_str()
            .is_some_and(|s| crate::hex(s, 64))
        || value["builder_executed"] != false
        || value["execution_eligible"] != false
        || value["model_requests"] != 0
    {
        return Err("native source receipt differs from dependency pins".into());
    }
    Ok(())
}

pub fn capture_native_dependency_inputs(
    pins: &NativeDependencyInputPins<'_>,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    if !pins.valid() {
        return Err("complete native dependency input pins required".into());
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(
        "/var/lib/hol-gauntlet-rust/worker-state",
    ))
    .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let slot = open_fixed_build_slot(pins.job).map_err(|e| e.to_string())?;
    let source_bytes =
        verify_captured_source(&slot, pins.source_archive).map_err(|e| e.to_string())?;
    source_receipt(&slot, pins, source_bytes)?;
    if crate::native_worker::cancellation_requested() {
        return Err("dependency input capture cancelled before reservation".into());
    }
    for name in [
        "dependency-inputs",
        "dependency-inputs.partial",
        "dependency-inputs.zip",
    ] {
        match statat(&slot, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err("dependency input job already consumed".into()),
        }
    }
    let fd = openat(
        &slot,
        "dependency-inputs.receiving",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "dependency input job consumed or reservation unavailable")?;
    fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    fsync(&slot).map_err(|_| "dependency input reservation commit uncertain")?;
    let mut receiving = File::from(fd);
    let digest = crate::native_source_stream::copy_source(
        std::io::stdin().as_raw_fd(),
        &mut receiving,
        pins.payload_bytes,
        &BoottimeDeadline::start(180).map_err(|e| e.to_string())?,
        crate::native_worker::cancellation_requested,
    )?;
    receiving
        .sync_all()
        .map_err(|_| "dependency input payload commit uncertain")?;
    if digest != pins.payload_sha256 {
        return Err("dependency input payload differs from outside hash".into());
    }
    use std::io::{Seek, SeekFrom};
    receiving
        .seek(SeekFrom::Start(0))
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    (&mut receiving)
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let contents = decode_inputs(&raw, pins)?;
    let held = fstat(&receiving).map_err(|e| e.to_string())?;
    let visible = statat(
        &slot,
        "dependency-inputs.receiving",
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|e| e.to_string())?;
    if held.st_uid != 0
        || held.st_gid != 0
        || held.st_nlink != 1
        || held.st_mode & 0o7777 != 0o600
        || held.st_size as u64 != pins.payload_bytes
        || !same_file(&held, &visible)
    {
        return Err("dependency payload custody changed".into());
    }
    mkdirat(
        &slot,
        "dependency-inputs.partial",
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(|_| "dependency input partial exists")?;
    let target = openat(
        &slot,
        "dependency-inputs.partial",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    fchmod(&target, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
    for (index, content) in contents.iter().enumerate() {
        if crate::native_worker::cancellation_requested() {
            return Err("dependency input capture cancelled; preserve partial".into());
        }
        let mode = if index == 2 { 0o555 } else { 0o444 };
        let fd = openat(
            &target,
            INPUT_NAMES[index],
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(mode),
        )
        .map_err(|e| e.to_string())?;
        let mut file = File::from(fd);
        file.write_all(content).map_err(|e| e.to_string())?;
        fchmod(&file, Mode::from_bits_truncate(mode)).map_err(|e| e.to_string())?;
        file.sync_all()
            .map_err(|_| "dependency member commit uncertain")?;
    }
    let receipt = gauntlet_contracts::canonicalize(pins.receipt().to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    crate::terminal::create_durable(&target, "capture.v1.json", &receipt)
        .map_err(|e| e.to_string())?;
    fsync(&target).map_err(|_| "dependency input tree commit uncertain")?;
    verify_extracted_inputs(&target, pins)?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    source_receipt(
        &slot,
        pins,
        verify_captured_source(&slot, pins.source_archive).map_err(|e| e.to_string())?,
    )?;
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    if crate::native_worker::cancellation_requested() {
        return Err("dependency input capture cancelled before publication".into());
    }
    renameat_with(
        &slot,
        "dependency-inputs.partial",
        &slot,
        "dependency-inputs",
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| "dependency input publication uncertain")?;
    fchmod(&receiving, Mode::RUSR | Mode::RGRP | Mode::ROTH).map_err(|e| e.to_string())?;
    receiving
        .sync_all()
        .map_err(|_| "dependency archive mode commit uncertain")?;
    renameat_with(
        &slot,
        "dependency-inputs.receiving",
        &slot,
        "dependency-inputs.zip",
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| "dependency archive publication uncertain")?;
    fsync(&slot).map_err(|_| "dependency capture commit uncertain")?;
    verify_extracted_inputs(&target, pins)?;
    let held = fstat(&target).map_err(|e| e.to_string())?;
    let visible =
        statat(&slot, "dependency-inputs", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    let archive = fstat(&receiving).map_err(|e| e.to_string())?;
    let archive_visible = statat(&slot, "dependency-inputs.zip", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| e.to_string())?;
    if !same_file(&held, &visible)
        || !same_file(&archive, &archive_visible)
        || archive.st_mode & 0o7777 != 0o444
    {
        return Err("published dependency input custody differs".into());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    Ok(receipt)
}
