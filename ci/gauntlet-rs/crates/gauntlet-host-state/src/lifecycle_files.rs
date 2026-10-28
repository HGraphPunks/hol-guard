//! Descriptor-bound storage for the new Rust-only host namespace.

use crate::private_jobs::{same_file, state_root};
use crate::HostLifecycleError as Error;
use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{
    flock, fstat, fsync, mkdirat, openat, renameat, statat, AtFlags, FileType, FlockOperation,
    Mode, OFlags, Stat,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

pub(crate) const NAMESPACE: &str = "rust-host-v1";
pub(crate) const MAX_BYTES: usize = 8 * 1024 * 1024;
const CHECKPOINT: &str = "state.json";

pub(crate) fn nonce() -> Result<String, Error> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Random)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn same_directory(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_mode == right.st_mode
}

pub(crate) struct LifecycleFiles {
    directory: OwnedFd,
    parent_identity: Stat,
    path: PathBuf,
    owner: u32,
}

pub(crate) struct LifecycleLock {
    descriptor: OwnedFd,
    before: Stat,
    name: &'static str,
}

impl LifecycleFiles {
    pub(crate) fn initialize(parent: &Path, bytes: &[u8]) -> Result<Self, Error> {
        let owner = geteuid().as_raw();
        let parent_fd = state_root(parent, owner).map_err(|_| Error::UnsafeDirectory)?;
        mkdirat(&parent_fd, NAMESPACE, Mode::from_bits_truncate(0o700)).map_err(|e| {
            if e == Errno::EXIST {
                Error::AlreadyInitialized
            } else {
                Error::Io
            }
        })?;
        let files = Self::open(parent)?;
        if !same_directory(
            &fstat(&parent_fd).map_err(|_| Error::Io)?,
            &files.parent_identity,
        ) {
            return Err(Error::Changed);
        }
        for name in ["transaction.lock", "observer.lock"] {
            let file = files.create(name)?;
            file.sync_all().map_err(|_| Error::Io)?;
        }
        let mut state = files.create(CHECKPOINT)?;
        state.write_all(bytes).map_err(|_| Error::Io)?;
        state.sync_all().map_err(|_| Error::Io)?;
        fsync(&files.directory).map_err(|_| Error::Io)?;
        fsync(&parent_fd).map_err(|_| Error::Io)?;
        files.stable()?;
        Ok(files)
    }

    pub(crate) fn open(parent: &Path) -> Result<Self, Error> {
        let owner = geteuid().as_raw();
        // Verify the caller-owned parent as well as the fixed child. No
        // Python file or lock name is opened or adopted by this writer.
        let parent_fd = state_root(parent, owner).map_err(|_| Error::UnsafeDirectory)?;
        let parent_identity = fstat(&parent_fd).map_err(|_| Error::Io)?;
        let path = parent.join(NAMESPACE);
        let directory = state_root(&path, owner).map_err(|_| Error::UnsafeDirectory)?;
        let files = Self {
            directory,
            parent_identity,
            path,
            owner,
        };
        files.stable()?;
        Ok(files)
    }

    pub(crate) fn stable(&self) -> Result<(), Error> {
        let parent = self.path.parent().ok_or(Error::UnsafeDirectory)?;
        let visible_parent = state_root(parent, self.owner).map_err(|_| Error::Changed)?;
        if !same_directory(
            &self.parent_identity,
            &fstat(&visible_parent).map_err(|_| Error::Io)?,
        ) {
            return Err(Error::Changed);
        }
        let visible = state_root(&self.path, self.owner).map_err(|_| Error::Changed)?;
        if !same_directory(
            &fstat(&self.directory).map_err(|_| Error::Io)?,
            &fstat(&visible).map_err(|_| Error::Io)?,
        ) {
            return Err(Error::Changed);
        }
        Ok(())
    }

    fn private_file(&self, stat: &Stat) -> bool {
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && stat.st_uid == self.owner
            && stat.st_mode & 0o777 == 0o600
            && stat.st_nlink == 1
            && stat.st_size >= 0
    }

    pub(crate) fn create(&self, name: &str) -> Result<File, Error> {
        self.stable()?;
        let fd = openat(
            &self.directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| Error::Io)?;
        if !self.private_file(&fstat(&fd).map_err(|_| Error::Io)?) {
            return Err(Error::UnsafeFile);
        }
        Ok(File::from(fd))
    }

    pub(crate) fn lock(&self, observer: bool, exclusive: bool) -> Result<LifecycleLock, Error> {
        self.stable()?;
        let name = if observer {
            "observer.lock"
        } else {
            "transaction.lock"
        };
        let descriptor = openat(
            &self.directory,
            name,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeFile)?;
        let before = fstat(&descriptor).map_err(|_| Error::Io)?;
        if !self.private_file(&before) || before.st_size != 0 {
            return Err(Error::UnsafeFile);
        }
        let lock = LifecycleLock {
            descriptor,
            before,
            name,
        };
        self.check_lock(&lock)?;
        let operation = if exclusive {
            FlockOperation::NonBlockingLockExclusive
        } else {
            FlockOperation::NonBlockingLockShared
        };
        flock(&lock.descriptor, operation).map_err(|e| {
            if e == Errno::AGAIN {
                Error::Busy
            } else {
                Error::Io
            }
        })?;
        self.check_lock(&lock)?;
        Ok(lock)
    }

    pub(crate) fn check_lock(&self, lock: &LifecycleLock) -> Result<(), Error> {
        self.stable()?;
        let held = fstat(&lock.descriptor).map_err(|_| Error::Changed)?;
        let visible = statat(&self.directory, lock.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Error::Changed)?;
        if !same_file(&lock.before, &held) || !same_file(&lock.before, &visible) {
            return Err(Error::Changed);
        }
        Ok(())
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>, Error> {
        self.read_named(CHECKPOINT, MAX_BYTES)
    }

    pub(crate) fn directory(&self) -> Result<&OwnedFd, Error> {
        self.stable()?;
        Ok(&self.directory)
    }

    pub(crate) fn owner(&self) -> u32 {
        self.owner
    }

    pub(crate) fn public_path(&self) -> PathBuf {
        self.path.join("public")
    }

    pub(crate) fn read_named(&self, name: &str, limit: usize) -> Result<Vec<u8>, Error> {
        self.stable()?;
        let fd = openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeFile)?;
        let before = fstat(&fd).map_err(|_| Error::Io)?;
        if !self.private_file(&before) || before.st_size == 0 {
            return Err(Error::UnsafeFile);
        }
        if before.st_size as u64 > limit as u64 {
            return Err(Error::TooLarge);
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Io)?;
        let held = fstat(&file).map_err(|_| Error::Changed)?;
        let visible =
            statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| Error::Changed)?;
        if bytes.len() as i64 != before.st_size
            || !same_file(&before, &held)
            || !same_file(&before, &visible)
        {
            return Err(Error::Changed);
        }
        self.stable()?;
        Ok(bytes)
    }

    pub(crate) fn replace(
        &self,
        lock: &LifecycleLock,
        before: &[u8],
        bytes: &[u8],
    ) -> Result<(), Error> {
        if lock.name != "transaction.lock" {
            return Err(Error::Changed);
        }
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        self.check_lock(lock)?;
        if self.read()? != before {
            return Err(Error::Changed);
        }
        let name = format!("checkpoint-{}.tmp", nonce()?);
        let mut file = self.create(&name)?;
        file.write_all(bytes).map_err(|_| Error::Io)?;
        file.sync_all().map_err(|_| Error::Io)?;
        self.check_lock(lock)?;
        if self.read()? != before {
            return Err(Error::Changed);
        }
        renameat(&self.directory, name.as_str(), &self.directory, CHECKPOINT)
            .map_err(|_| Error::Io)?;
        // A failure after rename cannot be treated as an uncommitted operation.
        fsync(&self.directory).map_err(|_| Error::CommitUncertain)?;
        self.check_lock(lock).map_err(|_| Error::CommitUncertain)?;
        if self.read().map_err(|_| Error::CommitUncertain)? != bytes {
            return Err(Error::CommitUncertain);
        }
        Ok(())
    }
}
