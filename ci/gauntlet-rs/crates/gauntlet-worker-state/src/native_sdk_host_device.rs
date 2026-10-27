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
        "ctime_seconds":s.st_ctime,"ctime_nanoseconds":s.st_ctime_nsec})
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
            if s.st_rdev != self.original.st_rdev
                || !crate::dependency_prefix_meta::same(&self.original, s)
            {
                return Err("SDK runtime changed the held host null-device inode".into());
            }
        }
        Ok(value(&held))
    }
}
