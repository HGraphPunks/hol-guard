//! Native stdin-to-build-slot custody, independent of the historical guest home.
use crate::{open_root_owned_public_directory, BoottimeDeadline, RunReservationJournal};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, openat, renameat_with, statat, AtFlags, FileType, Mode, OFlags,
    RenameFlags,
};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

const BUILDS: &str = "/var/lib/hol-gauntlet/builds";
fn private_directory(fd: &OwnedFd) -> Result<(), String> {
    let s = fstat(fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(s.st_mode) != FileType::Directory
        || s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o7777 != 0o700
    {
        return Err("private Root native build directory required".into());
    }
    Ok(())
}

pub fn capture_native_build_source(
    job: &str,
    source: &str,
    archive: &str,
    bytes: u64,
    generation: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    if !crate::hex(job, 16)
        || !gauntlet_contracts::is_git_sha(source)
        || !crate::hex(archive, 64)
        || !(1..=256 * 1024 * 1024).contains(&bytes)
    {
        return Err("exact native source/job/hash/byte pins required".into());
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(
        "/var/lib/hol-gauntlet-rust/worker-state",
    ))
    .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    if crate::native_worker::cancellation_requested() {
        return Err("native source cancelled before reservation".into());
    }
    let builds = open_root_owned_public_directory(Path::new(BUILDS)).map_err(|e| e.to_string())?;
    private_directory(&builds)?;
    mkdirat(&builds, job, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| {
        if e == rustix::io::Errno::EXIST {
            "native build job already consumed".into()
        } else {
            e.to_string()
        }
    })?;
    fsync(&builds).map_err(|_| "native source reservation commit uncertain")?;
    let slot = openat(
        &builds,
        job,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    fchmod(&slot, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
    private_directory(&slot)?;
    let fd = openat(
        &slot,
        "source.receiving",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| e.to_string())?;
    fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    let mut output = File::from(fd);
    let deadline = BoottimeDeadline::start(180).map_err(|e| e.to_string())?;
    let digest = crate::native_source_stream::copy_source(
        std::io::stdin().as_raw_fd(),
        &mut output,
        bytes,
        &deadline,
        crate::native_worker::cancellation_requested,
    )?;
    output
        .sync_all()
        .map_err(|_| "native source commit uncertain")?;
    if digest != archive {
        return Err("native source differs from outside digest; preserve partial slot".into());
    }
    let held = fstat(&output).map_err(|e| e.to_string())?;
    let visible =
        statat(&slot, "source.receiving", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(held.st_mode) != FileType::RegularFile
        || held.st_uid != 0
        || held.st_gid != 0
        || held.st_nlink != 1
        || held.st_mode & 0o7777 != 0o600
        || held.st_size as u64 != bytes
        || !crate::builder_candidate_source::same_file(&held, &visible)
    {
        return Err("native source custody changed before commit".into());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    fchmod(&output, Mode::RUSR | Mode::RGRP | Mode::ROTH).map_err(|e| e.to_string())?;
    output
        .sync_all()
        .map_err(|_| "native source mode commit uncertain")?;
    renameat_with(
        &slot,
        "source.receiving",
        &slot,
        "source.tar.gz",
        RenameFlags::NOREPLACE,
    )
    .map_err(|e| e.to_string())?;
    fsync(&slot).map_err(|_| "native source rename commit uncertain")?;
    // Use the actual candidate-build reader, rather than a matching fixture,
    // to enforce the downstream private-parent and immutable-file contract.
    let reopened =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    if crate::builder_candidate_source::verify_captured_source(&reopened, archive)
        .map_err(|e| e.to_string())?
        != bytes
    {
        return Err("native candidate source readback differs".into());
    }
    let report = serde_json::json!({"schema":"hol-gauntlet-native-source-capture.v1","job_id":job,"source_sha":source,
        "source_archive_sha256":archive,"source_bytes":bytes,"worker_generation":generation,"builder_executed":false,"execution_eligible":false,"model_requests":0});
    let raw = gauntlet_contracts::canonicalize(report.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    crate::terminal::create_durable(&slot, "source-capture.v1.json", &raw)
        .map_err(|e| e.to_string())?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    Ok(raw)
}
