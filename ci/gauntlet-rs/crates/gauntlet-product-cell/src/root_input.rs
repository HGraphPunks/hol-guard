//! Bounded reads of fixed Root-authored apparatus inputs. No candidate path
//! is accepted by a CLI or a management request.
use crate::{CellError, Result};
use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

pub(crate) struct RootInput {
    pub(crate) file: File,
    pub(crate) bytes: Vec<u8>,
}
pub(crate) fn read_root_input(path: &Path, limit: usize) -> Result<Option<RootInput>> {
    let invalid = CellError("Root apparatus input is missing, unsafe, changed or oversized");
    if !path.is_absolute() {
        return Err(invalid);
    }
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(invalid);
    }
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| invalid)?;
    let mut parts = parts.peekable();
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return Err(invalid);
        };
        let parent = fstat(&directory).map_err(|_| invalid)?;
        if parent.st_uid != 0 || parent.st_mode & 0o022 != 0 {
            return Err(invalid);
        }
        if parts.peek().is_some() {
            directory = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| invalid)?;
            continue;
        }
        let fd = match openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(invalid),
        };
        let before = fstat(&fd).map_err(|_| invalid)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != 0
            || before.st_mode & 0o022 != 0
            || before.st_nlink != 1
            || before.st_size <= 0
            || before.st_size as u64 > limit as u64
        {
            return Err(invalid);
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid)?;
        let after = fstat(&file).map_err(|_| invalid)?;
        let visible = statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| invalid)?;
        let matches = |row: &rustix::fs::Stat| {
            before.st_dev == row.st_dev
                && before.st_ino == row.st_ino
                && before.st_uid == row.st_uid
                && before.st_gid == row.st_gid
                && before.st_mode == row.st_mode
                && before.st_nlink == row.st_nlink
                && before.st_size == row.st_size
                && before.st_mtime == row.st_mtime
                && before.st_mtime_nsec == row.st_mtime_nsec
                && before.st_ctime == row.st_ctime
                && before.st_ctime_nsec == row.st_ctime_nsec
        };
        if bytes.len() as i64 != before.st_size || !matches(&after) || !matches(&visible) {
            return Err(invalid);
        }
        return Ok(Some(RootInput { file, bytes }));
    }
    Err(invalid)
}
