//! Necessary cleanup check for a Rust job's systemd product-cell slice.
//! Absence alone is not a full terminal proof: the controller must already be
//! stopped and reaped so it cannot create another product cell after this read.

use crate::{launch_plan::rust_job_slice_name, ReservationError};
use rustix::fs::{fstat, open, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::os::fd::OwnedFd;

#[cfg(target_os = "linux")]
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

fn safe_parent(stat: &Stat, expected_uid: u32) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == expected_uid
        && stat.st_mode & 0o022 == 0
}

fn same_directory(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
}

fn check_absent_at(
    parent: &OwnedFd,
    name: &str,
    expected_uid: u32,
) -> Result<(), ReservationError> {
    let before = fstat(parent).map_err(|_| ReservationError::CleanupUncertain)?;
    if !safe_parent(&before, expected_uid) {
        return Err(ReservationError::CleanupUncertain);
    }
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => {}
        _ => return Err(ReservationError::CleanupUncertain),
    }
    let after = fstat(parent).map_err(|_| ReservationError::CleanupUncertain)?;
    if !same_directory(&before, &after) {
        return Err(ReservationError::CleanupUncertain);
    }
    Ok(())
}

/// A terminal writer may call this only after the owned controller is stopped
/// and reaped. Any existing slice, including an empty one, blocks cleanup.
#[cfg(target_os = "linux")]
pub fn require_rust_job_slice_absent(job_id: &str) -> Result<(), ReservationError> {
    let name = rust_job_slice_name(job_id)?;
    if geteuid().as_raw() != 0 {
        return Err(ReservationError::RootRequired);
    }
    let parent = open(
        CGROUP_ROOT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ReservationError::CleanupUncertain)?;
    check_absent_at(&parent, &name, 0)?;
    let reopened = open(
        CGROUP_ROOT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ReservationError::CleanupUncertain)?;
    let held = fstat(&parent).map_err(|_| ReservationError::CleanupUncertain)?;
    let visible = fstat(&reopened).map_err(|_| ReservationError::CleanupUncertain)?;
    if !same_directory(&held, &visible) {
        return Err(ReservationError::CleanupUncertain);
    }
    check_absent_at(&reopened, &name, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn existing_or_replaced_slice_blocks_terminal_cleanup() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let descriptor = open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let name = rust_job_slice_name("0123456789abcdef").unwrap();
        let uid = geteuid().as_raw();
        assert_eq!(check_absent_at(&descriptor, &name, uid), Ok(()));
        fs::create_dir(root.path().join(&name)).unwrap();
        assert_eq!(
            check_absent_at(&descriptor, &name, uid),
            Err(ReservationError::CleanupUncertain)
        );
        fs::remove_dir(root.path().join(&name)).unwrap();
        symlink(root.path(), root.path().join(&name)).unwrap();
        assert_eq!(
            check_absent_at(&descriptor, &name, uid),
            Err(ReservationError::CleanupUncertain)
        );
    }

    #[test]
    fn unsafe_parent_and_invalid_job_id_refuse() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let descriptor = open(
            root.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            check_absent_at(
                &descriptor,
                "holgauntletrust0123456789abcdef.slice",
                geteuid().as_raw()
            ),
            Err(ReservationError::CleanupUncertain)
        );
        assert_eq!(
            rust_job_slice_name("../system"),
            Err(ReservationError::InvalidPins)
        );
    }
}
