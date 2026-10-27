//! Inert fixed-layout initialization; never runs a controller or adopts a job.
use crate::{open_root_owned_public_directory, read_bounded_regular, RunReservationJournal};
use rustix::fs::{fchmod, fstat, fsync, mkdirat, openat, statat, AtFlags, FileType, Mode, OFlags};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;

const BASE: &str = "/var/lib/hol-gauntlet-rust";

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
    ] {
        directory(Path::new(BASE), name, 0o700, true)?;
    }
    lock_file(&Path::new(BASE).join("dependency-state"), "active.lock")?;
    directory(
        Path::new("/opt/hol-gauntlet"),
        "native-deployments",
        0o700,
        true,
    )?;
    directory(Path::new("/var/lib"), "hol-gauntlet", 0o755, false)?;
    directory(Path::new("/var/lib/hol-gauntlet"), "builds", 0o700, true)?;
    let body = serde_json::json!({"schema":"hol-gauntlet-native-initialization.v3","worker_generation":generation,
        "layout":"native-worker-layout-v3","job_dispatched":false,"execution_eligible":false,"model_requests":0});
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
