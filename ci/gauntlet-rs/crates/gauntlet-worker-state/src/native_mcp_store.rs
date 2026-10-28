//! A fresh Root-private SQLite world slot under one fixed native job. No model
//! argument can select a database path, signing identity or executable.
use gauntlet_mcp_service::{OperationError, Operations};
use gauntlet_world::World;
use ring::signature::Ed25519KeyPair;
use rusqlite::{Connection, OpenFlags};
use rustix::fs::{
    fchmod, fchown, fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags, Stat,
};
use rustix::process::{Gid, Uid};
use serde_json::{json, Value};
use std::{
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

const DATABASE: &str = "mcp-world.db";
pub struct NativeMcpWorld {
    path: PathBuf,
    directory: OwnedFd,
    directory_stat: Stat,
    file: OwnedFd,
    file_stat: Stat,
    world: World,
    poisoned: bool,
}
fn directory_same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
}
fn file_same(a: &Stat, b: &Stat) -> bool {
    directory_same(a, b) && a.st_nlink == b.st_nlink
}
fn private_directory(s: &Stat) -> bool {
    FileType::from_raw_mode(s.st_mode) == FileType::Directory
        && s.st_uid == 0
        && s.st_gid == 0
        && s.st_mode & 0o7777 == 0o700
}
fn private_file(s: &Stat) -> bool {
    FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
        && s.st_uid == 0
        && s.st_gid == 0
        && s.st_mode & 0o7777 == 0o600
        && s.st_nlink == 1
}
impl NativeMcpWorld {
    pub fn new(job_id: &str, snapshot: &str, key: Ed25519KeyPair) -> Result<Self, String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        if !crate::hex(job_id, 16) {
            return Err("fixed native MCP job required".into());
        }
        Self::create(
            &PathBuf::from(crate::native_job_spec::NATIVE_JOBS).join(job_id),
            snapshot,
            key,
        )
    }
    fn create(path: &Path, snapshot: &str, key: Ed25519KeyPair) -> Result<Self, String> {
        let directory = crate::open_root_owned_public_directory(path).map_err(|e| e.to_string())?;
        let directory_stat = fstat(&directory).map_err(|e| e.to_string())?;
        if !private_directory(&directory_stat) {
            return Err("private Root MCP job directory required".into());
        }
        let file = openat(
            &directory,
            DATABASE,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| e.to_string())?;
        fchown(&file, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
            .and_then(|_| fchmod(&file, Mode::from_bits_truncate(0o600)))
            .and_then(|_| fsync(&file))
            .and_then(|_| fsync(&directory))
            .map_err(|e| e.to_string())?;
        let file_stat = fstat(&file).map_err(|e| e.to_string())?;
        if !private_file(&file_stat) {
            return Err("private Root MCP database required".into());
        }
        let connection = Connection::open_with_flags(
            path.join(DATABASE),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| e.to_string())?;
        let world = World::initialize(connection, snapshot, key).map_err(|e| e.to_string())?;
        let owned = Self {
            path: path.to_owned(),
            directory,
            directory_stat,
            file,
            file_stat,
            world,
            poisoned: false,
        };
        owned.verify()?;
        Ok(owned)
    }
    /// Data timestamps and size change with real transactions; inode identity,
    /// private owner/mode/link count and close-on-exec remain invariant.
    pub fn verify(&self) -> Result<(), String> {
        if self.poisoned {
            return Err("MCP world custody previously failed".into());
        }
        let visible =
            crate::open_root_owned_public_directory(&self.path).map_err(|e| e.to_string())?;
        for s in [fstat(&visible), fstat(&self.directory)] {
            let s = s.map_err(|e| e.to_string())?;
            if !private_directory(&s) || !directory_same(&s, &self.directory_stat) {
                return Err("MCP world directory changed".into());
            }
        }
        for s in [
            fstat(&self.file),
            statat(&self.directory, DATABASE, AtFlags::SYMLINK_NOFOLLOW),
        ] {
            let s = s.map_err(|e| e.to_string())?;
            if !private_file(&s) || !file_same(&s, &self.file_stat) {
                return Err("MCP world database custody changed".into());
            }
        }
        // SQLite owns a second descriptor. Verify its actual Linux descriptor
        // flags before any child launch instead of assuming the VFS set them.
        let mut matching = 0;
        for entry in std::fs::read_dir("/proc/self/fd").map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            else {
                continue;
            };
            if fd < 0 {
                continue;
            }
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstat writes exactly one stat for the numeric self FD.
            if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
                continue;
            }
            // SAFETY: successful fstat initialized every field.
            let stat = unsafe { stat.assume_init() };
            if stat.st_dev == self.file_stat.st_dev && stat.st_ino == self.file_stat.st_ino {
                // SAFETY: F_GETFD only reads the descriptor's flags.
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
                    return Err("MCP database descriptor could leak across exec".into());
                }
                matching += 1;
            }
        }
        if matching < 2 {
            return Err("held and SQLite database descriptors were not observed".into());
        }
        Ok(())
    }
    fn check(&mut self) -> Result<(), String> {
        let result = self.verify();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn snapshot(&mut self) -> Result<Value, String> {
        self.check()?;
        let result = self.world.snapshot().map_err(|e| e.to_string());
        self.check()?;
        result
    }
    pub fn receipts(&mut self) -> Result<Vec<Value>, String> {
        self.check()?;
        let result = self.world.receipts().map_err(|e| e.to_string());
        self.check()?;
        result
    }
    pub fn observation(&mut self) -> Result<Value, String> {
        self.check()?;
        Ok(
            json!({"schema":"hol-gauntlet-native-mcp-world.v1","database":DATABASE,
            "device":self.file_stat.st_dev,"inode":self.file_stat.st_ino,"uid":0,"gid":0,"mode":0o600,
            "public_key":self.world.public_key(),"agent_mounts_verified":false,
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
        )
    }
}
impl Operations for NativeMcpWorld {
    fn call(
        &mut self,
        operation: &str,
        args: &Value,
        request_id: Value,
    ) -> Result<Value, OperationError> {
        let custody = |message: String| OperationError {
            category: "custody".into(),
            message,
        };
        self.check().map_err(custody)?;
        let result = Operations::call(&mut self.world, operation, args, request_id);
        self.check().map_err(custody)?;
        result
    }
}

#[cfg(test)]
#[path = "native_mcp_store_tests.rs"]
mod tests;
