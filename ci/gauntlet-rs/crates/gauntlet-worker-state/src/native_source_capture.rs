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
#[allow(clippy::too_many_arguments)]
pub fn read_native_build_source_v2(
    job: &str,
    source: &str,
    archive: &str,
    bytes: u64,
    generation: &str,
    profile: &str,
    formatter: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let profile: crate::JobStorageProfile = profile.parse()?;
    if profile == crate::JobStorageProfile::Native
        || !crate::hex(source, 40)
        || !crate::hex(job, 16)
        || !crate::hex(archive, 64)
        || !crate::hex(formatter, 64)
        || !(1..=256 * 1024 * 1024).contains(&bytes)
    {
        return Err("exact original bounded Source capture pins required".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let root =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let value = crate::native_job_storage::source::verify(job, &root, Some(profile))?
        .ok_or("original completed Source.v2 receipt absent")?;
    if value["source_sha"] != source
        || value["worker_generation"] != generation
        || value["source_archive_sha256"] != archive
        || value["source_bytes"] != bytes
        || value["storage"]["receipt"]["mke2fs_sha256"] != formatter
        || crate::builder_candidate_source::verify_captured_source(&root, archive)
            .map_err(|e| e.to_string())?
            != bytes
    {
        return Err("original Source capture bytes/volume differ from readback pins".into());
    }
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    gauntlet_contracts::canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string())
}
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
    capture(job, source, archive, bytes, generation, None)
}
pub fn capture_native_build_source_v2(
    job: &str,
    source: &str,
    archive: &str,
    bytes: u64,
    generation: &str,
    profile: &str,
    formatter: &str,
) -> Result<Vec<u8>, String> {
    let profile = profile.parse::<crate::native_job_storage::JobStorageProfile>()?;
    if profile == crate::native_job_storage::JobStorageProfile::Native {
        return Err("source capture requires build-v1 or dependency-v1 storage".into());
    }
    capture(
        job,
        source,
        archive,
        bytes,
        generation,
        Some((profile, formatter)),
    )
}
fn capture(
    job: &str,
    source: &str,
    archive: &str,
    bytes: u64,
    generation: &str,
    storage: Option<(crate::native_job_storage::JobStorageProfile, &str)>,
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
    let storage_pins = crate::native_job_storage::JobStoragePins {
        source_sha: source,
        job_id: job,
        worker_generation: generation,
        mke2fs_sha256: storage.map(|(_, pin)| pin).unwrap_or(""),
    };
    let volume = match storage {
        Some((profile, _)) => Some(crate::native_job_storage::lifecycle::JobVolume::create(
            &storage_pins,
            profile,
            &journal,
            &lease,
            &legacy,
        )?),
        None => {
            crate::native_job_storage::lifecycle::require_absent(job)?;
            None
        }
    };
    if crate::native_worker::cancellation_requested() {
        return Err("native source cancelled before reservation".into());
    }
    let builds = open_root_owned_public_directory(Path::new(BUILDS)).map_err(|e| e.to_string())?;
    private_directory(&builds)?;
    let slot = if let Some(volume) = &volume {
        rustix::io::dup(&volume.root).map_err(|e| e.to_string())?
    } else {
        mkdirat(&builds, job, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| {
            if e == rustix::io::Errno::EXIST {
                "native build job already consumed".into()
            } else {
                e.to_string()
            }
        })?;
        fsync(&builds).map_err(|_| "native source reservation commit uncertain")?;
        openat(
            &builds,
            job,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?
    };
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
    let mut report = serde_json::json!({"schema":"hol-gauntlet-native-source-capture.v1","job_id":job,"source_sha":source,
        "source_archive_sha256":archive,"source_bytes":bytes,"worker_generation":generation,"builder_executed":false,"execution_eligible":false,"model_requests":0});
    if let Some(volume) = &volume {
        volume.verify(&storage_pins)?;
        report["schema"] = serde_json::json!("hol-gauntlet-native-source-capture.v2");
        report["storage_profile"] = serde_json::json!(volume.profile.as_str());
        report["storage"] = volume.binding();
    }
    let raw = gauntlet_contracts::canonicalize(report.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    let name = if volume.is_some() {
        "source-capture.v2.json"
    } else {
        "source-capture.v1.json"
    };
    if let Some(volume) = &volume {
        crate::terminal::create_durable(&slot, name, &raw).map_err(|e| e.to_string())?;
        crate::native_job_storage::admission::admit(volume, &raw)?;
    }
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
    if volume.is_none() {
        crate::terminal::create_durable(&slot, name, &raw).map_err(|e| e.to_string())?;
    }
    if let Some(volume) = &volume {
        volume.verify(&storage_pins)?;
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    Ok(raw)
}
