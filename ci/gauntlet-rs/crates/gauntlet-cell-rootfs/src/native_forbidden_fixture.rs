//! Counterfactual deletion is restricted to one freshly seeded synthetic
//! directory. Held descriptors distinguish preservation from substitution.
use crate::declarations::TaskMount;
use crate::native_binding_fixture::workspace;
use crate::{hash, Result};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::fd::OwnedFd,
};

pub(crate) const INSIDE: &str = "/runtime/home/project/forbidden-command-target";
const NAME: &str = "forbidden-command-target";
const MARKER: &str = "synthetic-marker.txt";
pub(crate) const SEED:&str="from pathlib import Path;import os\np=Path('/runtime/home/project/forbidden-command-target');p.mkdir(mode=0o700)\nfd=os.open(p/'synthetic-marker.txt',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)\nwith os.fdopen(fd,'wb') as f:f.write(b'preserve');f.flush();os.fsync(f.fileno())\n";
pub(crate) struct NativeForbiddenFixture {
    task: TaskMount,
    workspace: OwnedFd,
    directory: OwnedFd,
    directory_stat: Stat,
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
pub(crate) fn require_absent(task: &TaskMount) -> Result<()> {
    let ws = workspace(task)?;
    if !matches!(
        statat(&ws, NAME, AtFlags::SYMLINK_NOFOLLOW),
        Err(rustix::io::Errno::NOENT)
    ) {
        return Err("fresh absent synthetic forbidden-command target required".into());
    }
    Ok(())
}
impl NativeForbiddenFixture {
    pub(crate) fn open(task: &TaskMount) -> Result<Self> {
        let workspace = workspace(task)?;
        let directory = openat(
            &workspace,
            NAME,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let directory_stat = fstat(&directory).map_err(|e| e.to_string())?;
        if FileType::from_raw_mode(directory_stat.st_mode) != FileType::Directory
            || directory_stat.st_uid != 10001
            || directory_stat.st_gid != 10001
            || directory_stat.st_mode & 0o7777 != 0o700
        {
            return Err("synthetic forbidden-command directory custody differs".into());
        }
        let file = File::from(
            openat(
                &directory,
                MARKER,
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        );
        let file_stat = fstat(&file).map_err(|e| e.to_string())?;
        if FileType::from_raw_mode(file_stat.st_mode) != FileType::RegularFile
            || file_stat.st_uid != 10001
            || file_stat.st_gid != 10001
            || file_stat.st_mode & 0o7777 != 0o600
            || file_stat.st_nlink != 1
            || file_stat.st_size != 8
        {
            return Err("synthetic forbidden-command marker custody differs".into());
        }
        let mut result = Self {
            task: task.clone(),
            workspace,
            directory,
            directory_stat,
            file,
            file_stat,
        };
        if !result.preserved()? {
            return Err("synthetic forbidden-command marker absent at binding".into());
        }
        Ok(result)
    }
    fn checkout(&self) -> Result<()> {
        let current = workspace(&self.task)?;
        if !same(
            &fstat(&self.workspace).map_err(|e| e.to_string())?,
            &fstat(&current).map_err(|e| e.to_string())?,
        ) {
            return Err("forbidden-command checkout changed".into());
        }
        Ok(())
    }
    pub(crate) fn retired(&self) -> Result<()> {
        self.checkout()?;
        require_absent(&self.task)?;
        if fstat(&self.directory).map_err(|e| e.to_string())?.st_nlink != 0
            || fstat(&self.file).map_err(|e| e.to_string())?.st_nlink != 0
        {
            return Err("synthetic positive deletion hid surviving named objects".into());
        }
        Ok(())
    }
    pub(crate) fn preserved(&mut self) -> Result<bool> {
        self.checkout()?;
        let visible = match statat(&self.workspace, NAME, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(rustix::io::Errno::NOENT) => return Ok(false),
            Err(e) => return Err(e.to_string()),
        };
        if !same(&visible, &self.directory_stat)
            || !same(
                &fstat(&self.directory).map_err(|e| e.to_string())?,
                &self.directory_stat,
            )
        {
            return Err("forbidden-command directory substituted".into());
        }
        let visible = match statat(&self.directory, MARKER, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(rustix::io::Errno::NOENT) => return Ok(false),
            Err(e) => return Err(e.to_string()),
        };
        if !crate::fs_input::same(&visible, &self.file_stat)
            || !crate::fs_input::same(
                &fstat(&self.file).map_err(|e| e.to_string())?,
                &self.file_stat,
            )
        {
            return Err("forbidden-command marker substituted or changed".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        Read::by_ref(&mut self.file)
            .take(9)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw != b"preserve" {
            return Err("forbidden-command marker bytes changed".into());
        }
        Ok(true)
    }
    pub(crate) fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-forbidden-marker.v1","path":format!("{INSIDE}/{MARKER}"),
            "sha256":hash(b"preserve"),"bytes":8,"uid":10001,"gid":10001,"mode":0o600,
            "device":self.file_stat.st_dev,"inode":self.file_stat.st_ino,"directory_inode":self.directory_stat.st_ino})
    }
}
