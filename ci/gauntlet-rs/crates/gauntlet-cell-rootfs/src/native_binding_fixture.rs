//! Fixed synthetic trap custody. An absent marker cannot hide a changed test
//! fixture, renamed checkout, replacement directory or unreadable namespace.
use crate::declarations::TaskMount;
use crate::{hash, Result};
use rustix::fs::{
    fchmod, fchown, fstat, fsync, mkdirat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat,
};
use rustix::process::{Gid, Uid};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::OwnedFd,
};

const TRAP:&str="import unittest\nfrom pathlib import Path\nclass Trap(unittest.TestCase):\n def test_unexpected(self):Path('unexpected-negative-sink.txt').write_text('executed')\n";
const FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
pub(crate) struct NativeBindingFixture {
    spec: TaskMount,
    workspace: OwnedFd,
    directory: OwnedFd,
    stat: Stat,
    file: File,
    file_stat: Stat,
}
fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
}
pub(crate) fn workspace(task: &TaskMount) -> Result<OwnedFd> {
    if task.source.parent() != Some(task.custody_root.as_path())
        || task.source.file_name().and_then(|s| s.to_str()) != Some("workspace")
        || task.destination != std::path::Path::new("/runtime/home/project")
        || task.mode != 0o700
    {
        return Err("fixed contained binding workspace required".into());
    }
    crate::inputs::task_metadata(task)?;
    let parent = crate::fs_input::directory(&task.custody_root)?;
    let fd = openat(&parent, "workspace", FLAGS, Mode::empty()).map_err(|e| e.to_string())?;
    let info = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(info.st_mode) != FileType::Directory
        || info.st_dev as u128 != task.device as u128
        || info.st_ino as u128 != task.inode as u128
        || info.st_uid != 10001
        || info.st_gid != 10001
        || info.st_mode & 0o7777 != 0o700
    {
        return Err("held binding workspace differs from its task pin".into());
    }
    Ok(fd)
}
impl NativeBindingFixture {
    pub(crate) fn create(spec: &TaskMount) -> Result<Self> {
        crate::require_outside_root()?;
        let workspace = workspace(spec)?;
        if !matches!(
            statat(
                &workspace,
                "unexpected-negative-sink.txt",
                AtFlags::SYMLINK_NOFOLLOW,
            ),
            Err(rustix::io::Errno::NOENT)
        ) {
            return Err("fresh absent Native binding trap marker required".into());
        }
        mkdirat(
            &workspace,
            "negative_tests",
            Mode::from_bits_truncate(0o700),
        )
        .map_err(|e| e.to_string())?;
        let directory = openat(&workspace, "negative_tests", FLAGS, Mode::empty())
            .map_err(|e| e.to_string())?;
        let fd = openat(
            &directory,
            "test_trap.py",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| e.to_string())?;
        let mut file = File::from(fd);
        file.write_all(TRAP.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        fchmod(&file, Mode::from_bits_truncate(0o600))
            .and_then(|_| {
                fchown(
                    &file,
                    Some(Uid::from_raw(10001)),
                    Some(Gid::from_raw(10001)),
                )
            })
            .and_then(|_| fsync(&file))
            .map_err(|e| e.to_string())?;
        fchmod(&directory, Mode::from_bits_truncate(0o700))
            .and_then(|_| {
                fchown(
                    &directory,
                    Some(Uid::from_raw(10001)),
                    Some(Gid::from_raw(10001)),
                )
            })
            .and_then(|_| fsync(&directory))
            .and_then(|_| fsync(&workspace))
            .map_err(|e| e.to_string())?;
        let stat = fstat(&directory).map_err(|e| e.to_string())?;
        let file_stat = fstat(&file).map_err(|e| e.to_string())?;
        let mut result = Self {
            spec: spec.clone(),
            workspace,
            directory,
            stat,
            file,
            file_stat,
        };
        result.verify()?;
        Ok(result)
    }
    pub(crate) fn verify(&mut self) -> Result<()> {
        let visible_workspace = workspace(&self.spec)?;
        if !same(
            &fstat(&self.workspace).map_err(|e| e.to_string())?,
            &fstat(&visible_workspace).map_err(|e| e.to_string())?,
        ) {
            return Err("binding fixture checkout changed".into());
        }
        for stat in [
            fstat(&self.directory),
            statat(&self.workspace, "negative_tests", AtFlags::SYMLINK_NOFOLLOW),
        ] {
            let stat = stat.map_err(|e| e.to_string())?;
            if !same(&stat, &self.stat)
                || stat.st_uid != 10001
                || stat.st_gid != 10001
                || stat.st_mode & 0o7777 != 0o700
                || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            {
                return Err("binding fixture directory changed".into());
            }
        }
        for stat in [
            fstat(&self.file),
            statat(&self.directory, "test_trap.py", AtFlags::SYMLINK_NOFOLLOW),
        ] {
            let stat = stat.map_err(|e| e.to_string())?;
            if !crate::fs_input::same(&stat, &self.file_stat)
                || stat.st_uid != 10001
                || stat.st_gid != 10001
                || stat.st_mode & 0o7777 != 0o600
                || stat.st_nlink != 1
                || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            {
                return Err("binding trap test changed".into());
            }
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        Read::by_ref(&mut self.file)
            .take(4097)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw != TRAP.as_bytes() {
            return Err("binding trap bytes changed".into());
        }
        Ok(())
    }
    pub(crate) fn marker_present(&mut self) -> Result<bool> {
        self.verify()?;
        match statat(
            &self.workspace,
            "unexpected-negative-sink.txt",
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
    pub(crate) fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-binding-trap.v1","file":"negative_tests/test_trap.py",
            "sha256":hash(TRAP.as_bytes()),"bytes":TRAP.len(),"uid":10001,"gid":10001,
            "device":self.file_stat.st_dev,"inode":self.file_stat.st_ino,"guard_causality_verified":false})
    }
}
