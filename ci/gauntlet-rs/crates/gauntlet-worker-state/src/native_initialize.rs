//! Inert fixed-layout initialization; never runs a controller or adopts a job.
use crate::{open_root_owned_public_directory, read_bounded_regular, RunReservationJournal};
use rustix::fs::{
    fchmod, fchown, fstat, fsync, mkdirat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;

const BASE: &str = "/var/lib/hol-gauntlet-rust";

pub(crate) fn require_unstarted_job(
    journal: &RunReservationJournal,
    job: &str,
) -> Result<(), String> {
    let prefix = format!("{job}.");
    for (count, entry) in Dir::read_from(&journal.root)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        let entry = entry.map_err(|e| e.to_string())?;
        if count >= 4098 {
            return Err("native initialization state inventory bound exceeded".into());
        }
        if entry.file_name().to_bytes().starts_with(prefix.as_bytes()) {
            return Err("native job identity already consumed or uncertain".into());
        }
    }
    crate::require_rust_job_slice_absent(job).map_err(|e| e.to_string())
}

pub(crate) fn initialization_result(raw: &[u8], schema: &str) -> Result<Vec<u8>, String> {
    let receipt: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    gauntlet_contracts::canonicalize(
        json!({"schema":schema,"receipt":receipt,
        "receipt_sha256":format!("{:x}",Sha256::digest(raw))})
        .to_string()
        .as_bytes(),
    )
    .map_err(|e| e.to_string())
}

pub(crate) fn job_initialization(
    source: &str,
    job: &str,
    generation: &str,
) -> Result<(Vec<u8>, Value), String> {
    checked_job_initialization(source, job, generation, true)
}

/// Execution/readback can retain the initialized directory identity while
/// its legitimate workspace contains effects. Staging requires it untouched.
pub(crate) fn checked_job_initialization(
    source: &str,
    job: &str,
    generation: &str,
    untouched: bool,
) -> Result<(Vec<u8>, Value), String> {
    if !crate::hex(source, 40) || !crate::hex(job, 16) || !crate::hex(generation, 64) {
        return Err("outside source/job/worker pins required for native initialization".into());
    }
    crate::native_job_storage::owner::enter_pinned(source, job, generation)?;
    let jobs = open_root_owned_public_directory(&Path::new(BASE).join("native-jobs"))
        .map_err(|e| e.to_string())?;
    crate::feature_files::private_directory(&jobs, (0, 0))?;
    let root = crate::feature_files::open_directory(&jobs, job, (0, 0))?;
    let workspace = crate::feature_files::open_directory(&root, "workspace", (10001, 10001))?;
    if untouched {
        for (directory, allowed) in [
            (&root, vec!["workspace", "preparation.v1.json"]),
            (&workspace, Vec::new()),
        ] {
            for entry in Dir::read_from(directory).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry
                    .file_name()
                    .to_str()
                    .map_err(|_| "native initialization filename UTF-8")?;
                if !matches!(name, "." | "..") && !allowed.contains(&name) {
                    return Err("native initialized job/workspace was touched".into());
                }
            }
        }
    }
    let receipts = open_root_owned_public_directory(&Path::new(BASE).join("native-initialization"))
        .map_err(|e| e.to_string())?;
    crate::feature_files::private_directory(&receipts, (0, 0))?;
    let raw = crate::feature_files::required(
        &receipts,
        &format!("{job}.job.json"),
        (0, 0),
        0o600,
        24576,
    )?;
    let retained: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let storage = if retained["schema"] == "hol-gauntlet-native-job-initialization.v2" {
        Some(crate::native_job_storage::lifecycle::verify_binding(
            &retained["storage"],
            source,
            job,
            generation,
            crate::native_job_storage::JobStorageProfile::Native,
        )?)
    } else {
        crate::native_job_storage::lifecycle::require_absent(job)?;
        None
    };
    let receipt = job_receipt(source, job, generation, &root, &workspace, storage)?;
    let expected = gauntlet_contracts::canonicalize(receipt.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    if raw != expected {
        return Err("native initialization receipt or physical identity changed".into());
    }
    if let Some(storage) = receipt.get("storage") {
        let volumes =
            open_root_owned_public_directory(Path::new(crate::native_job_storage::lifecycle::BASE))
                .map_err(|e| e.to_string())?;
        let slot = crate::feature_files::open_directory(&volumes, job, (0, 0))?;
        crate::native_job_storage::admission::verify_admitted(
            &slot,
            &gauntlet_contracts::canonicalize(storage["receipt"].to_string().as_bytes())
                .map_err(|e| e.to_string())?,
            &raw,
        )?;
    }
    Ok((raw, receipt))
}

pub(crate) fn job_receipt(
    source: &str,
    job: &str,
    generation: &str,
    root: &OwnedFd,
    workspace: &OwnedFd,
    storage: Option<Value>,
) -> Result<Value, String> {
    let root_stat = fstat(root).map_err(|e| e.to_string())?;
    let task = fstat(workspace).map_err(|e| e.to_string())?;
    let path = Path::new(crate::native_job_spec::NATIVE_JOBS).join(job);
    let mut body = json!({"schema":"hol-gauntlet-native-job-initialization.v1","source_sha":source,"job_id":job,
        "worker_generation":generation,"job_directory":{"device":root_stat.st_dev,"inode":root_stat.st_ino,"uid":0,"gid":0,"mode":448},
        "workspace":{"source":path.join("workspace"),"destination":"/runtime/home/project","custody_root":path,
            "device":task.st_dev,"inode":task.st_ino,"uid":10001,"gid":10001,"mode":448},
        "job_dispatched":false,"candidate_executed":false,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0});
    if let Some(storage) = storage {
        body["schema"] = json!("hol-gauntlet-native-job-initialization.v2");
        body["storage"] = storage;
    }
    Ok(body)
}

pub fn initialize_native_job(source: &str, job: &str, generation: &str) -> Result<Vec<u8>, String> {
    native_job_initialization(source, job, generation, true)
}

pub fn read_native_job_initialization(
    source: &str,
    job: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    native_job_initialization(source, job, generation, false)
}

fn native_job_initialization(
    source: &str,
    job: &str,
    generation: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    if !crate::hex(source, 40) || !crate::hex(job, 16) {
        return Err("outside native source/job required".into());
    }
    if publish {
        // Global initialization releases its own leases before this job takes
        // them. The read action never creates layout, locks or receipts.
        initialize_native_worker(generation)?;
    }
    let journal = RunReservationJournal::open_root_owned(&Path::new(BASE).join("worker-state"))
        .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    require_unstarted_job(&journal, job)?;
    if publish {
        crate::native_job_io::require_no_unknown_jobs(&journal)?;
        crate::dependency_state::require_idle()?;
        if crate::native_worker::cancellation_requested() {
            return Err("native job initialization cancelled".into());
        }
        crate::native_job_storage::lifecycle::require_absent(job)?;
        let jobs = open_root_owned_public_directory(&Path::new(BASE).join("native-jobs"))
            .map_err(|e| e.to_string())?;
        crate::feature_files::private_directory(&jobs, (0, 0))?;
        let root = crate::feature_files::directory(&jobs, job, (0, 0), true)?;
        let workspace = crate::feature_files::directory(&root, "workspace", (0, 0), true)?;
        fchown(
            &workspace,
            Some(rustix::process::Uid::from_raw(10001)),
            Some(rustix::process::Gid::from_raw(10001)),
        )
        .and_then(|_| fsync(&workspace))
        .and_then(|_| fsync(&root))
        .map_err(|e| e.to_string())?;
        let body = job_receipt(source, job, generation, &root, &workspace, None)?;
        let raw = gauntlet_contracts::canonicalize(body.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        lease.verify(&journal.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
        let receipts =
            open_root_owned_public_directory(&Path::new(BASE).join("native-initialization"))
                .map_err(|e| e.to_string())?;
        crate::feature_files::private_directory(&receipts, (0, 0))?;
        crate::feature_files::write(&receipts, &format!("{job}.job.json"), &raw, (0, 0), 0o600)?;
    }
    let (raw, body) = job_initialization(source, job, generation)?;
    if body["schema"] != "hol-gauntlet-native-job-initialization.v1" {
        return Err("v1 initialization cannot adopt a bounded v2 job".into());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    initialization_result(&raw, "hol-gauntlet-native-job-initialization-result.v1")
}

fn directory(parent: &Path, name: &str, mode: u32, private: bool) -> Result<bool, String> {
    let parent = open_root_owned_public_directory(parent).map_err(|e| e.to_string())?;
    let created = match mkdirat(&parent, name, Mode::from_bits_truncate(mode)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(e) => return Err(e.to_string()),
    };
    let fd = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    if created {
        fchmod(&fd, Mode::from_bits_truncate(mode)).map_err(|e| e.to_string())?;
        fsync(&fd)
            .and_then(|_| fsync(&parent))
            .map_err(|e| e.to_string())?;
    }
    let held = fstat(&fd).map_err(|e| e.to_string())?;
    let visible = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(held.st_mode) != FileType::Directory
        || held.st_uid != 0
        || held.st_gid != 0
        || held.st_mode & 0o700 != 0o700
        || held.st_mode & 0o7022 != 0
        || (private && held.st_mode & 0o7777 != 0o700)
        || held.st_dev != visible.st_dev
        || held.st_ino != visible.st_ino
        || held.st_mode != visible.st_mode
        || held.st_uid != visible.st_uid
        || held.st_gid != visible.st_gid
    {
        return Err("native initialization directory is unsafe or replaced".into());
    }
    Ok(created)
}

fn private_file(root: &OwnedFd, name: &str) -> Result<(), String> {
    let fd = openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let held = fstat(&fd).map_err(|e| e.to_string())?;
    let visible = statat(root, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    for info in [&held, &visible] {
        if FileType::from_raw_mode(info.st_mode) != FileType::RegularFile
            || info.st_uid != 0
            || info.st_gid != 0
            || info.st_nlink != 1
            || info.st_mode & 0o7777 != 0o600
        {
            return Err("native initialization file is not private Root custody".into());
        }
    }
    if held.st_dev != visible.st_dev || held.st_ino != visible.st_ino {
        return Err("native initialization file replaced".into());
    }
    Ok(())
}

fn lock_file(parent: &Path, name: &str) -> Result<(), String> {
    let root = open_root_owned_public_directory(parent).map_err(|e| e.to_string())?;
    match openat(
        &root,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => {
            fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
            fsync(&fd)
                .and_then(|_| fsync(&root))
                .map_err(|e| e.to_string())?;
        }
        Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(e.to_string()),
    }
    private_file(&root, name)
}

pub fn initialize_native_worker(generation: &str) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    directory(Path::new("/opt"), "hol-gauntlet", 0o755, false)?;
    lock_file(Path::new("/opt/hol-gauntlet"), "worker.lock")?;
    directory(Path::new("/var/lib"), "hol-gauntlet-rust", 0o700, false)?;
    directory(Path::new(BASE), "worker-state", 0o700, true)?;
    lock_file(&Path::new(BASE).join("worker-state"), "active.lock")?;
    let journal = RunReservationJournal::open_root_owned(&Path::new(BASE).join("worker-state"))
        .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    // Once both owners are excluded, create only the fixed empty namespaces.
    // Existing directories are validated, never chmodded, replaced or adopted.
    for name in [
        "native-jobs",
        "cell-image-leases",
        "native-initialization",
        "dependency-state",
        "feature-state",
        "feature-jobs",
    ] {
        directory(Path::new(BASE), name, 0o700, true)?;
    }
    lock_file(&Path::new(BASE).join("dependency-state"), "active.lock")?;
    lock_file(&Path::new(BASE).join("feature-state"), "active.lock")?;
    directory(
        Path::new("/opt/hol-gauntlet"),
        "feature-assets",
        0o700,
        true,
    )?;
    directory(
        Path::new("/opt/hol-gauntlet"),
        "native-deployments",
        0o700,
        true,
    )?;
    directory(Path::new("/var/lib"), "hol-gauntlet", 0o755, false)?;
    directory(Path::new("/var/lib/hol-gauntlet"), "builds", 0o700, true)?;
    let body = serde_json::json!({"schema":"hol-gauntlet-native-initialization.v4","worker_generation":generation,
        "layout":"native-worker-layout-v4","job_dispatched":false,"execution_eligible":false,"model_requests":0});
    let raw =
        gauntlet_contracts::canonicalize(body.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let root = open_root_owned_public_directory(&Path::new(BASE).join("native-initialization"))
        .map_err(|e| e.to_string())?;
    let name = format!("{generation}.json");
    if let Some(existing) = read_bounded_regular(&root, &name, 2048).map_err(|e| e.to_string())? {
        private_file(&root, &name)?;
        if existing != raw {
            return Err("native initialization receipt differs; retain uncertainty".into());
        }
    } else {
        let fd = openat(
            &root,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| e.to_string())?;
        fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
        let mut file = File::from(fd);
        file.write_all(&raw)
            .and_then(|_| file.sync_all())
            .map_err(|_| "native initialization receipt commit uncertain")?;
        fsync(&root).map_err(|_| "native initialization directory commit uncertain")?;
        private_file(&root, &name)?;
        if read_bounded_regular(&root, &name, 2048).map_err(|e| e.to_string())? != Some(raw.clone())
        {
            return Err("native initialization receipt changed after write".into());
        }
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn existing_loose_directories_links_and_hardlinked_locks_are_never_repaired_in_place() {
        if rustix::process::geteuid().as_raw() != 0 {
            assert!(initialize_native_worker(&"0".repeat(64)).is_err());
            return;
        }
        let temp = tempfile::Builder::new()
            .prefix("native-init-custody-")
            .tempdir_in(BASE)
            .unwrap();
        assert!(directory(temp.path(), "private", 0o700, true).unwrap());
        assert!(!directory(temp.path(), "private", 0o700, true).unwrap());
        std::fs::set_permissions(
            temp.path().join("private"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(directory(temp.path(), "private", 0o700, true).is_err());
        assert_eq!(
            std::fs::metadata(temp.path().join("private"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        symlink(temp.path().join("private"), temp.path().join("alias")).unwrap();
        assert!(directory(temp.path(), "alias", 0o700, true).is_err());
        lock_file(temp.path(), "lease").unwrap();
        std::fs::hard_link(temp.path().join("lease"), temp.path().join("second-name")).unwrap();
        assert!(lock_file(temp.path(), "lease").is_err());
        let alias = temp.path().join("file-alias");
        symlink(temp.path().join("lease"), alias).unwrap();
        assert!(lock_file(temp.path(), "file-alias").is_err());
    }
}
