//! Atomic allowlisted public publication, isolated from Python's public files.

use crate::lifecycle_files::nonce;
use crate::private_jobs::same_file;
use crate::{HostLifecycleError as Error, HostObserverLease};
use gauntlet_contracts::canonicalize;
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, openat, renameat, statat, AtFlags, FileType, Mode, OFlags,
};
use rustix::io::Errno;
use serde_json::{json, Value};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::PathBuf;

pub(crate) struct ObserverPublic {
    directory: OwnedFd,
}

impl ObserverPublic {
    pub(crate) fn open(lease: &HostObserverLease<'_>) -> Result<Self, Error> {
        lease.verify_current()?;
        let parent = lease.store.files.directory()?;
        let created = match mkdirat(parent, "public", Mode::from_bits_truncate(0o700)) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(_) => return Err(Error::Io),
        };
        let directory = openat(
            parent,
            "public",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeDirectory)?;
        if created {
            let stat = fstat(&directory).map_err(|_| Error::Io)?;
            if stat.st_uid != lease.store.files.owner() || stat.st_mode & 0o777 != 0o700 {
                return Err(Error::UnsafeDirectory);
            }
            fchmod(&directory, Mode::from_bits_truncate(0o755)).map_err(|_| Error::Io)?;
            fsync(parent).map_err(|_| Error::Io)?;
        }
        let result = Self { directory };
        result.stable(lease)?;
        let expected = canonicalize(
            json!({"instance_id":lease.store.instance})
                .to_string()
                .as_bytes(),
        )
        .map_err(|_| Error::InvalidState)?;
        match result.read("dashboard-id.json", 4096, lease.store.files.owner())? {
            Some(bytes) if bytes == expected => {}
            Some(_) => return Err(Error::Changed),
            None => result.write(lease, "dashboard-id.json", &expected)?,
        }
        Ok(result)
    }

    fn stable(&self, lease: &HostObserverLease<'_>) -> Result<(), Error> {
        lease.verify_current()?;
        let stat = fstat(&self.directory).map_err(|_| Error::Io)?;
        let visible = statat(
            lease.store.files.directory()?,
            "public",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Error::Changed)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || stat.st_uid != lease.store.files.owner()
            || stat.st_mode & 0o777 != 0o755
            || stat.st_dev != visible.st_dev
            || stat.st_ino != visible.st_ino
            || stat.st_uid != visible.st_uid
            || stat.st_mode != visible.st_mode
        {
            return Err(Error::Changed);
        }
        Ok(())
    }

    fn read(&self, name: &str, limit: u64, owner: u32) -> Result<Option<Vec<u8>>, Error> {
        let fd = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(Error::UnsafeFile),
        };
        let before = fstat(&fd).map_err(|_| Error::Io)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != owner
            || before.st_nlink != 1
            || before.st_mode & 0o777 != 0o644
            || before.st_size < 0
        {
            return Err(Error::UnsafeFile);
        }
        if before.st_size as u64 > limit {
            return Err(Error::TooLarge);
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Io)?;
        let after = fstat(&file).map_err(|_| Error::Changed)?;
        let visible =
            statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| Error::Changed)?;
        if bytes.len() as i64 != before.st_size
            || !same_file(&before, &after)
            || !same_file(&before, &visible)
        {
            return Err(Error::Changed);
        }
        Ok(Some(bytes))
    }

    fn write(&self, lease: &HostObserverLease<'_>, name: &str, bytes: &[u8]) -> Result<(), Error> {
        self.stable(lease)?;
        let before = self.read(name, 4 * 1024 * 1024, lease.store.files.owner())?;
        let temp = format!("publication-{}.tmp", nonce()?);
        let fd = openat(
            &self.directory,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o644),
        )
        .map_err(|_| Error::Io)?;
        fchmod(&fd, Mode::from_bits_truncate(0o644)).map_err(|_| Error::Io)?;
        let mut file = File::from(fd);
        file.write_all(bytes).map_err(|_| Error::Io)?;
        file.sync_all().map_err(|_| Error::Io)?;
        self.stable(lease)?;
        if self.read(name, 4 * 1024 * 1024, lease.store.files.owner())? != before {
            return Err(Error::Changed);
        }
        renameat(&self.directory, temp.as_str(), &self.directory, name).map_err(|_| Error::Io)?;
        fsync(&self.directory).map_err(|_| Error::CommitUncertain)?;
        self.stable(lease).map_err(|_| Error::CommitUncertain)?;
        if self
            .read(name, 4 * 1024 * 1024, lease.store.files.owner())
            .map_err(|_| Error::CommitUncertain)?
            .as_deref()
            != Some(bytes)
        {
            return Err(Error::CommitUncertain);
        }
        Ok(())
    }

    pub(crate) fn publish(
        &self,
        lease: &HostObserverLease<'_>,
        value: &Value,
    ) -> Result<(), Error> {
        if value["schema"] != "hol-gauntlet-dashboard.v1"
            || value["instance_id"] != lease.store.instance
        {
            return Err(Error::InvalidState);
        }
        let bytes = canonicalize(value.to_string().as_bytes()).map_err(|_| Error::InvalidState)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(Error::TooLarge);
        }
        self.write(lease, "snapshot.json", &bytes)
    }
    pub(crate) fn path(&self, lease: &HostObserverLease<'_>) -> Result<PathBuf, Error> {
        self.stable(lease)?;
        Ok(lease.store.files.public_path())
    }
}
