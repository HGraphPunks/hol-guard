//! Root-controlled paths are walked with held, no-symlink descriptors.
use crate::{hash, spec::literal_path, Result};
use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(crate) fn root_metadata(info: &Stat, directory: bool) -> Result<()> {
    let wanted = if directory {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    if FileType::from_raw_mode(info.st_mode) != wanted
        || info.st_uid != 0
        || info.st_mode & 0o022 != 0
        || (!directory && info.st_nlink != 1)
    {
        return Err("immutable Root-owned no-link filesystem input required".into());
    }
    Ok(())
}

pub(crate) fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

pub(crate) fn directory(path: &Path) -> Result<OwnedFd> {
    let raw = path.to_str().ok_or("filesystem path is not UTF-8")?;
    literal_path(raw)?;
    if path.components().count() > 64 {
        return Err("Root directory depth bound".into());
    }
    let mut current = open("/", DIRECTORY, Mode::empty()).map_err(|e| e.to_string())?;
    root_metadata(&fstat(&current).map_err(|e| e.to_string())?, true)?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let next = openat(&current, name, DIRECTORY, Mode::empty()).map_err(|e| e.to_string())?;
        root_metadata(&fstat(&next).map_err(|e| e.to_string())?, true)?;
        current = next;
    }
    Ok(current)
}

pub(crate) fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    literal_path(path.to_str().ok_or("filesystem path is not UTF-8")?)?;
    let parent = directory(path.parent().ok_or("Root file needs a parent")?)?;
    let name = path.file_name().ok_or("Root file needs a basename")?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&descriptor).map_err(|e| e.to_string())?;
    root_metadata(&before, false)?;
    if before.st_size < 0 || before.st_size as u64 > maximum as u64 {
        return Err("Root file byte bound".into());
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if raw.len() != before.st_size as usize
        || raw.len() > maximum
        || !same(&before, &after)
        || !same(&before, &visible)
    {
        return Err("Root file changed while being read".into());
    }
    Ok(raw)
}

pub(crate) fn pinned(path: &Path, maximum: usize, expected: &str) -> Result<Vec<u8>> {
    let raw = read(path, maximum)?;
    if !crate::hex(expected, 64) || hash(&raw) != expected {
        return Err(format!(
            "Root input {} differs from outside digest",
            path.display()
        ));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readable_system_file_is_not_a_substitute_for_its_outside_pin() {
        assert!(pinned(Path::new("/usr/bin/true"), 1024 * 1024, &"0".repeat(64)).is_err());
        assert!(read(Path::new("/usr/../usr/bin/true"), 1024 * 1024).is_err());
        assert!(read(Path::new("/proc/self/status"), 1024 * 1024).is_err());
    }
    #[test]
    fn user_owned_and_symlinked_files_do_not_enter_root_custody() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("input");
        std::fs::write(&original, b"inert").unwrap();
        let link = temp.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&original, &link).unwrap();
        assert!(read(&link, 64).is_err());
        assert!(read(&original, 64).is_err());
    }
}
