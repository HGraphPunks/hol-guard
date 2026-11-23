//! Descriptor-bound audit files. Empty logs are valid; links, type changes,
//! unsafe modes, oversized files and replacement during a read are not.
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat,
};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

fn stable(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}
fn name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
        Err("ordinary feature filename required".into())
    } else {
        Ok(())
    }
}
pub(crate) fn private_directory(fd: &OwnedFd, owner: (u32, u32)) -> Result<(), String> {
    let s = fstat(fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(s.st_mode) != FileType::Directory
        || s.st_uid != owner.0
        || s.st_gid != owner.1
        || s.st_mode & 0o7777 != 0o700
    {
        return Err("private feature directory custody differs".into());
    }
    Ok(())
}
pub(crate) fn directory(
    parent: &OwnedFd,
    child: &str,
    owner: (u32, u32),
    exclusive: bool,
) -> Result<OwnedFd, String> {
    name(child)?;
    let created = match mkdirat(parent, child, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) if !exclusive => false,
        Err(e) => return Err(e.to_string()),
    };
    let fd = openat(
        parent,
        child,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    if created {
        fchmod(&fd, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
        fsync(&fd)
            .and_then(|_| fsync(parent))
            .map_err(|e| e.to_string())?;
    }
    private_directory(&fd, owner)?;
    let held = fstat(&fd).map_err(|e| e.to_string())?;
    let visible = statat(parent, child, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !stable(&held, &visible) {
        return Err("feature directory replaced".into());
    }
    Ok(fd)
}
pub(crate) fn open_directory(
    parent: &OwnedFd,
    child: &str,
    owner: (u32, u32),
) -> Result<OwnedFd, String> {
    name(child)?;
    let fd = openat(
        parent,
        child,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    private_directory(&fd, owner)?;
    let held = fstat(&fd).map_err(|e| e.to_string())?;
    let visible = statat(parent, child, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !stable(&held, &visible) {
        return Err("feature directory replaced".into());
    }
    Ok(fd)
}
pub(crate) fn read(
    dir: &OwnedFd,
    file: &str,
    owner: (u32, u32),
    mode: libc::mode_t,
    bound: usize,
) -> Result<Option<Vec<u8>>, String> {
    name(file)?;
    let fd = match openat(
        dir,
        file,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner.0
        || before.st_gid != owner.1
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != mode
        || before.st_size < 0
        || before.st_size as u64 > bound as u64
    {
        return Err("feature file custody or size differs".into());
    }
    let mut f = File::from(fd);
    let mut bytes = Vec::new();
    (&mut f)
        .take(bound as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = fstat(&f).map_err(|e| e.to_string())?;
    let visible = statat(dir, file, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if bytes.len() as i64 != before.st_size
        || !stable(&before, &after)
        || !stable(&before, &visible)
    {
        return Err("feature file changed while reading".into());
    }
    Ok(Some(bytes))
}
pub(crate) fn required(
    dir: &OwnedFd,
    file: &str,
    owner: (u32, u32),
    mode: libc::mode_t,
    bound: usize,
) -> Result<Vec<u8>, String> {
    read(dir, file, owner, mode, bound)?
        .ok_or_else(|| format!("required feature file missing: {file}"))
}
pub(crate) fn write(
    dir: &OwnedFd,
    file: &str,
    bytes: &[u8],
    owner: (u32, u32),
    mode: libc::mode_t,
) -> Result<(), String> {
    name(file)?;
    let fd = openat(
        dir,
        file,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "feature file already consumed or unavailable")?;
    fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    let mut output = File::from(fd);
    output
        .write_all(bytes)
        .and_then(|_| output.sync_all())
        .map_err(|e| e.to_string())?;
    fchmod(&output, Mode::from_bits_truncate(mode)).map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    fsync(dir).map_err(|e| e.to_string())?;
    if required(dir, file, owner, mode, bytes.len())? != bytes {
        return Err("feature file differs after durable commit".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    fn root(path: &std::path::Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }
    #[test]
    fn empty_logs_are_preserved_and_reserved_names_never_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let fd = root(temp.path());
        let m = std::fs::metadata(temp.path()).unwrap();
        let owner = (m.uid(), m.gid());
        write(&fd, "empty.log", b"", owner, 0o600).unwrap();
        assert_eq!(required(&fd, "empty.log", owner, 0o600, 0).unwrap(), b"");
        assert!(write(&fd, "empty.log", b"replacement", owner, 0o600).is_err());
        assert!(read(&fd, "../empty.log", owner, 0o600, 0).is_err());
        write(&fd, "intent.json", b"{", owner, 0o600).unwrap();
        assert!(write(&fd, "intent.json", b"{}", owner, 0o600).is_err());
    }
    #[test]
    fn file_and_directory_links_loose_modes_and_bounds_refuse() {
        let temp = tempfile::tempdir().unwrap();
        let fd = root(temp.path());
        let m = std::fs::metadata(temp.path()).unwrap();
        let owner = (m.uid(), m.gid());
        write(&fd, "record", b"abc", owner, 0o600).unwrap();
        assert!(read(&fd, "record", owner, 0o600, 2).is_err());
        symlink("record", temp.path().join("alias")).unwrap();
        assert!(read(&fd, "alias", owner, 0o600, 3).is_err());
        std::fs::hard_link(temp.path().join("record"), temp.path().join("hard")).unwrap();
        assert!(read(&fd, "record", owner, 0o600, 3).is_err());
        std::fs::create_dir(temp.path().join("dir")).unwrap();
        assert!(read(&fd, "dir", owner, 0o600, 3).is_err());
        directory(&fd, "private", owner, true).unwrap();
        open_directory(&fd, "private", owner).unwrap();
        std::fs::set_permissions(
            temp.path().join("private"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(directory(&fd, "private", owner, false).is_err());
        assert_eq!(
            std::fs::metadata(temp.path().join("private"))
                .unwrap()
                .mode()
                & 0o7777,
            0o755
        );
    }
}
