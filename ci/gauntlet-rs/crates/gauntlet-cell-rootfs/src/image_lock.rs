//! A permanent lock plus one-use active pointer blocks unresolved image leases.
use crate::{fs_input, Result};
use rustix::fs::{fstat, openat, statat, AtFlags, FlockOperation, Mode, OFlags};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

pub(crate) struct ImageLock {
    directory: OwnedFd,
    lock: OwnedFd,
    lock_name: String,
    active: File,
    active_name: String,
    lock_stat: rustix::fs::Stat,
    active_stat: rustix::fs::Stat,
}

impl ImageLock {
    pub(crate) fn reopen_for_recovery(image: &str, stage: &Path) -> Result<(Self, String)> {
        let id = crate::image_protocol::image_id(image)?;
        let directory =
            fs_input::directory(Path::new("/var/lib/hol-gauntlet-rust/cell-image-leases"))?;
        let lock_name = format!("{id}.lock");
        let lock = openat(
            &directory,
            lock_name.as_str(),
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        Self::private(&fstat(&lock).map_err(|e| e.to_string())?)?;
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "image lease still held; recovery refused")?;
        let active_name = format!("{id}.active.json");
        let mut active = File::from(
            openat(
                &directory,
                active_name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        );
        let active_stat = fstat(&active).map_err(|e| e.to_string())?;
        Self::private(&active_stat)?;
        if !(1..=4096).contains(&active_stat.st_size) {
            return Err("active image pointer bound".into());
        }
        let mut raw = Vec::new();
        Read::by_ref(&mut active)
            .take(4097)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() as u64 != active_stat.st_size as u64 {
            return Err("active image pointer changed".into());
        }
        crate::recovery_protocol::active(&raw, image, stage)?;
        let lock_stat = fstat(&lock).map_err(|e| e.to_string())?;
        let held = Self {
            directory,
            lock,
            lock_name,
            active,
            active_name,
            lock_stat,
            active_stat,
        };
        held.verify()?;
        Ok((held, crate::hash(&raw)))
    }

    pub(crate) fn reserve(image: &str, stage: &Path) -> Result<Self> {
        let id = crate::image_protocol::image_id(image)?;
        let root = Path::new("/var/lib/hol-gauntlet-rust/cell-image-leases");
        fs_input::directory(root.parent().ok_or("image lock parent")?)?;
        match std::fs::symlink_metadata(root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(root)
                    .map_err(|e| e.to_string())?;
                File::open(root.parent().unwrap())
                    .and_then(|f| f.sync_all())
                    .map_err(|e| e.to_string())?;
            }
            Err(e) => return Err(e.to_string()),
            Ok(_) => {}
        }
        let directory = fs_input::directory(root)?;
        if fstat(&directory).map_err(|e| e.to_string())?.st_mode & 0o077 != 0 {
            return Err("private image lease directory required".into());
        }
        let lock_name = format!("{id}.lock");
        let lock = openat(
            &directory,
            lock_name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| e.to_string())?;
        Self::private(&fstat(&lock).map_err(|e| e.to_string())?)?;
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "image lease already held")?;
        let active_name = format!("{id}.active.json");
        let fd = openat(
            &directory,
            active_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| "unresolved prior image lease blocks acquisition")?;
        let mut active = File::from(fd);
        let data = serde_json::json!({"schema":"hol-gauntlet-cell-image-active.v1","image_id":image,"stage":stage,"nonce":crate::nonce()?});
        let mut raw = gauntlet_contracts::canonicalize(data.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        raw.push(b'\n');
        active
            .write_all(&raw)
            .and_then(|_| active.sync_all())
            .map_err(|_| "image lease reservation commit uncertain")?;
        File::from(rustix::io::dup(&directory).map_err(|e| e.to_string())?)
            .sync_all()
            .map_err(|_| "image lease directory commit uncertain")?;
        let lock_stat = fstat(&lock).map_err(|e| e.to_string())?;
        let active_stat = fstat(&active).map_err(|e| e.to_string())?;
        let held = Self {
            directory,
            lock,
            lock_name,
            active,
            active_name,
            lock_stat,
            active_stat,
        };
        held.verify()?;
        Ok(held)
    }

    fn private(info: &rustix::fs::Stat) -> Result<()> {
        fs_input::root_metadata(info, false)?;
        if info.st_gid != 0 || info.st_mode & 0o7777 != 0o600 {
            return Err("private Root image lease file required".into());
        }
        Ok(())
    }

    pub(crate) fn verify(&self) -> Result<()> {
        let visible_directory =
            fs_input::directory(Path::new("/var/lib/hol-gauntlet-rust/cell-image-leases"))?;
        let a = fstat(&self.directory).map_err(|e| e.to_string())?;
        let b = fstat(&visible_directory).map_err(|e| e.to_string())?;
        if a.st_dev != b.st_dev || a.st_ino != b.st_ino || a.st_uid != 0 || a.st_mode & 0o077 != 0 {
            return Err("image lease directory replaced or opened".into());
        }
        for (fd, name, original) in [
            (self.lock.as_fd(), self.lock_name.as_str(), &self.lock_stat),
            (
                self.active.as_fd(),
                self.active_name.as_str(),
                &self.active_stat,
            ),
        ] {
            let held = fstat(fd).map_err(|e| e.to_string())?;
            let visible = statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| e.to_string())?;
            Self::private(&held)?;
            Self::private(&visible)?;
            if !fs_input::same(&held, &visible) || !fs_input::same(original, &held) {
                return Err("image lease file was replaced".into());
            }
        }
        Ok(())
    }

    pub(crate) fn complete(&self) -> Result<()> {
        self.verify()?;
        rustix::fs::unlinkat(&self.directory, self.active_name.as_str(), AtFlags::empty())
            .map_err(|e| e.to_string())?;
        File::from(rustix::io::dup(&self.directory).map_err(|e| e.to_string())?)
            .sync_all()
            .map_err(|_| "image lease completion commit uncertain".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_pointer_blocks_a_second_owner_even_after_the_lock_is_released() {
        let stage = Path::new("/var/lib/hol-gauntlet-rust/image-lock-unit-no-cell");
        let image = format!("sha256:{}", crate::hash(crate::nonce().unwrap().as_bytes()));
        if rustix::process::geteuid().as_raw() != 0 {
            assert!(ImageLock::reserve(&image, stage).is_err());
            return;
        }
        let first = ImageLock::reserve(&image, stage).unwrap();
        assert!(ImageLock::reserve(&image, stage).is_err());
        // Model a dead owner releasing its kernel lock but leaving its durable
        // pointer. No image helper or cell runs in this test.
        rustix::fs::flock(&first.lock, FlockOperation::Unlock).unwrap();
        assert!(ImageLock::reserve(&image, stage).is_err());
        rustix::fs::flock(&first.lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        first.complete().unwrap();
        drop(first);
        let next = ImageLock::reserve(&image, stage).unwrap();
        next.complete().unwrap();
    }
}
