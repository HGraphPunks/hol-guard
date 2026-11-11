//! Hold and recheck the host null-device inode across OCI runtime calls.
use rustix::fs::{fstat, openat, statat, AtFlags, Mode, OFlags, Stat};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::path::Path;

pub(crate) struct NativeSdkHostNull {
    directory: OwnedFd,
    device: OwnedFd,
    original: Stat,
}

fn value(s: &Stat) -> Value {
    json!({"device":s.st_dev,"inode":s.st_ino,"uid":s.st_uid,"gid":s.st_gid,
        "mode":s.st_mode & 0o7777,"links":s.st_nlink,
        "major":libc::major(s.st_rdev),"minor":libc::minor(s.st_rdev),
        "mtime_seconds":s.st_mtime,"mtime_nanoseconds":s.st_mtime_nsec,
        "ctime_seconds":s.st_ctime,"ctime_nanoseconds":s.st_ctime_nsec})
}
fn same_identity(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_mode == second.st_mode
        && first.st_uid == second.st_uid
        && first.st_gid == second.st_gid
        && first.st_nlink == second.st_nlink
        && first.st_rdev == second.st_rdev
}
fn checked(s: &Stat) -> Result<(), String> {
    if s.st_mode & 0o170000 != 0o020000
        || s.st_mode & 0o7777 != 0o666
        || s.st_uid != 0
        || s.st_gid != 0
        || s.st_nlink != 1
        || libc::major(s.st_rdev) != 1
        || libc::minor(s.st_rdev) != 3
    {
        return Err("SDK requires the unchanged Root host null-device inode".into());
    }
    Ok(())
}
impl NativeSdkHostNull {
    pub(crate) fn open() -> Result<Self, String> {
        let directory = crate::open_root_owned_public_directory(Path::new("/dev"))
            .map_err(|e| e.to_string())?;
        let device = openat(
            &directory,
            "null",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let original = fstat(&device).map_err(|e| e.to_string())?;
        checked(&original)?;
        let owned = Self {
            directory,
            device,
            original,
        };
        owned.recheck()?;
        Ok(owned)
    }
    pub(crate) fn before(&self) -> Value {
        value(&self.original)
    }
    pub(crate) fn recheck(&self) -> Result<Value, String> {
        let held = fstat(&self.device).map_err(|e| e.to_string())?;
        let visible = statat(&self.directory, "null", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        for s in [&held, &visible] {
            checked(s)?;
            if !same_identity(&self.original, s) {
                return Err("SDK runtime changed the held host null-device identity".into());
            }
        }
        Ok(value(&held))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Stat {
        // SAFETY: this integer-only stat fixture has no references or ownership.
        let mut s: Stat = unsafe { std::mem::zeroed() };
        s.st_dev = 5;
        s.st_ino = 5;
        s.st_mode = 0o020666;
        s.st_nlink = 1;
        s.st_rdev = libc::makedev(1, 3);
        s
    }
    #[test]
    fn device_timestamps_are_observations_rather_than_file_byte_custody() {
        let first = fixture();
        let mut second = fixture();
        second.st_ctime = 42;
        second.st_ctime_nsec = 17;
        second.st_mtime = 41;
        second.st_mtime_nsec = 16;
        checked(&first).unwrap();
        checked(&second).unwrap();
        assert!(same_identity(&first, &second));
        assert_ne!(value(&first), value(&second));
    }
    #[test]
    fn device_inode_owner_permissions_kind_and_number_remain_bound() {
        for field in [
            "device",
            "inode",
            "uid",
            "gid",
            "permissions",
            "kind",
            "links",
            "rdev",
        ] {
            let first = fixture();
            let mut changed = fixture();
            match field {
                "device" => changed.st_dev = 6,
                "inode" => changed.st_ino = 6,
                "uid" => changed.st_uid = 10001,
                "gid" => changed.st_gid = 10001,
                "permissions" => changed.st_mode = 0o020600,
                "kind" => changed.st_mode = 0o100666,
                "links" => changed.st_nlink = 2,
                "rdev" => changed.st_rdev = libc::makedev(1, 5),
                _ => unreachable!(),
            }
            assert!(!same_identity(&first, &changed), "{field}");
        }
    }
}
