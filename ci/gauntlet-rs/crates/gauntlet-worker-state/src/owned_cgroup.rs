//! Shared Root cgroup custody, retained-identity reopening and bounded teardown.
//! Probe, controller, builder and feature owners use these same primitives.
use crate::contained_probe::CgroupProbeError;
use crate::{observe_cgroup_drain, CgroupDrainState};
use rustix::fs::{
    fstat, mkdirat, open, openat, statat, unlinkat, AtFlags, FileType, Mode, OFlags, Stat,
};
use rustix::io::{write, Errno};
use rustix::process::geteuid;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
const PARENT: &str = "/sys/fs/cgroup/system.slice";
const MAX_CONTROL_BYTES: usize = 4096;
const POLL: Duration = Duration::from_millis(20);
const WAIT: Duration = Duration::from_secs(3);

pub(crate) struct OwnedProbeGroup {
    parent: OwnedFd,
    directory: OwnedFd,
    original: Stat,
    name: String,
    path: String,
}

#[derive(Clone, Copy)]
pub(crate) struct GroupLimits {
    pub(crate) memory: &'static str,
    pub(crate) pids: &'static str,
    pub(crate) cpu: &'static str,
}

fn root_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0
        && stat.st_mode & 0o022 == 0
}

fn same_identity(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
}

fn read_control(directory: &OwnedFd, name: &str) -> Result<Vec<u8>, CgroupProbeError> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CgroupProbeError::ControlUnavailable)?;
    let mut bytes = Vec::new();
    File::from(fd)
        .take((MAX_CONTROL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CgroupProbeError::ControlUnavailable)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(CgroupProbeError::ControlUnavailable);
    }
    Ok(bytes)
}

fn write_control(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), CgroupProbeError> {
    let fd = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CgroupProbeError::ControlUnavailable)?;
    if write(&fd, bytes).map_err(|_| CgroupProbeError::ControlUnavailable)? != bytes.len() {
        return Err(CgroupProbeError::ControlUnavailable);
    }
    Ok(())
}

impl OwnedProbeGroup {
    pub(crate) fn identity(&self) -> Result<(u64, u64), CgroupProbeError> {
        self.check_identity()?;
        Ok((self.original.st_dev, self.original.st_ino))
    }

    /// Reopen only a previously retained kernel identity. This never creates,
    /// configures or adopts a replacement group through its historical name.
    pub(crate) fn reopen_named(
        name: String,
        path: String,
        identity: (u64, u64),
    ) -> Result<Self, CgroupProbeError> {
        if geteuid().as_raw() != 0 {
            return Err(CgroupProbeError::RootRequired);
        }
        if !name.starts_with("hol-gauntlet-rust-")
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || path != format!("/system.slice/{name}")
        {
            return Err(CgroupProbeError::InvalidJobId);
        }
        let parent = open(
            PARENT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| CgroupProbeError::ControlUnavailable)?;
        if !root_directory(&fstat(&parent).map_err(|_| CgroupProbeError::UnsafeGroup)?) {
            return Err(CgroupProbeError::UnsafeGroup);
        }
        let directory = openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| CgroupProbeError::UnsafeGroup)?;
        let original = fstat(&directory).map_err(|_| CgroupProbeError::UnsafeGroup)?;
        if (original.st_dev, original.st_ino) != identity {
            return Err(CgroupProbeError::UnsafeGroup);
        }
        let group = Self {
            parent,
            directory,
            original,
            name,
            path,
        };
        group.check_identity()?;
        Ok(group)
    }

    pub(crate) fn create_named(
        name: String,
        path: String,
        limits: GroupLimits,
    ) -> Result<Self, CgroupProbeError> {
        if geteuid().as_raw() != 0 {
            return Err(CgroupProbeError::RootRequired);
        }
        let parent = open(
            PARENT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| CgroupProbeError::ControlUnavailable)?;
        if !root_directory(&fstat(&parent).map_err(|_| CgroupProbeError::UnsafeGroup)?) {
            return Err(CgroupProbeError::UnsafeGroup);
        }
        mkdirat(&parent, name.as_str(), Mode::from_bits_truncate(0o755)).map_err(|error| {
            if error == Errno::EXIST {
                CgroupProbeError::ExistingGroup
            } else {
                CgroupProbeError::ControlUnavailable
            }
        })?;
        let directory = match openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(directory) => directory,
            Err(_) => {
                let _ = unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR);
                return Err(CgroupProbeError::UnsafeGroup);
            }
        };
        let original = match fstat(&directory) {
            Ok(original) => original,
            Err(_) => {
                let _ = unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR);
                return Err(CgroupProbeError::UnsafeGroup);
            }
        };
        let mut group = Self {
            parent,
            directory,
            original,
            name,
            path,
        };
        if !root_directory(&group.original) || group.check_identity().is_err() {
            // An identity mismatch is retained for inspection, never removed
            // through a name that could now refer to another cgroup.
            return Err(CgroupProbeError::UnsafeGroup);
        }
        if group.configure(limits).is_err() {
            group.remove_empty()?;
            return Err(CgroupProbeError::ControlUnavailable);
        }
        Ok(group)
    }

    fn check_identity(&self) -> Result<(), CgroupProbeError> {
        let held = fstat(&self.directory).map_err(|_| CgroupProbeError::UnsafeGroup)?;
        let visible = statat(&self.parent, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| CgroupProbeError::UnsafeGroup)?;
        if !root_directory(&held)
            || !same_identity(&self.original, &held)
            || !same_identity(&self.original, &visible)
        {
            return Err(CgroupProbeError::UnsafeGroup);
        }
        Ok(())
    }

    fn configure(&self, limits: GroupLimits) -> Result<(), CgroupProbeError> {
        self.check_identity()?;
        for (name, value) in [
            ("memory.max", limits.memory),
            ("pids.max", limits.pids),
            ("cpu.max", limits.cpu),
        ] {
            write_control(&self.directory, name, value.as_bytes())?;
            if read_control(&self.directory, name)? != value.as_bytes() {
                return Err(CgroupProbeError::ControlUnavailable);
            }
        }
        self.check_identity()
    }

    pub(crate) fn writer(&self) -> Result<OwnedFd, CgroupProbeError> {
        self.check_identity()?;
        openat(
            &self.directory,
            "cgroup.procs",
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| CgroupProbeError::ControlUnavailable)
    }

    pub(crate) fn attach_child(&self, command: &mut Command) -> Result<(), CgroupProbeError> {
        let writer = self.writer()?;
        // SAFETY: the callback uses only getpid, stack digits and one write
        // syscall after fork. It runs before the fixed shell is executed.
        unsafe {
            command.pre_exec(move || {
                let mut pid = libc::getpid() as u32;
                let mut digits = [0u8; 10];
                let mut start = digits.len();
                loop {
                    start -= 1;
                    digits[start] = b'0' + (pid % 10) as u8;
                    pid /= 10;
                    if pid == 0 {
                        break;
                    }
                }
                let bytes = &digits[start..];
                let written = libc::write(writer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len());
                if written == bytes.len() as isize {
                    Ok(())
                } else if written < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Err(io::Error::from_raw_os_error(libc::EIO))
                }
            });
        }
        Ok(())
    }

    pub(crate) fn tasks(&self) -> Result<u64, CgroupProbeError> {
        self.check_identity()?;
        let raw = read_control(&self.directory, "pids.current")?;
        let text = std::str::from_utf8(&raw).map_err(|_| CgroupProbeError::ControlUnavailable)?;
        let text = text
            .strip_suffix('\n')
            .ok_or(CgroupProbeError::ControlUnavailable)?;
        if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CgroupProbeError::ControlUnavailable);
        }
        text.parse()
            .map_err(|_| CgroupProbeError::ControlUnavailable)
    }

    pub(crate) fn kill(&self) -> Result<(), CgroupProbeError> {
        self.check_identity()?;
        write_control(&self.directory, "cgroup.kill", b"1")
            .map_err(|_| CgroupProbeError::KillUnavailable)
    }

    pub(crate) fn remove_empty(&mut self) -> Result<(), CgroupProbeError> {
        self.check_identity()?;
        if observe_cgroup_drain(&self.path) != Ok(CgroupDrainState::Drained) {
            return Err(CgroupProbeError::DrainUnknown);
        }
        unlinkat(&self.parent, self.name.as_str(), AtFlags::REMOVEDIR)
            .map_err(|_| CgroupProbeError::CleanupUnavailable)
    }

    pub(crate) fn drain_and_remove(&mut self) -> Result<(), CgroupProbeError> {
        let started = Instant::now();
        loop {
            match self.remove_empty() {
                Ok(()) => return Ok(()),
                Err(CgroupProbeError::DrainUnknown | CgroupProbeError::CleanupUnavailable)
                    if started.elapsed() < WAIT =>
                {
                    thread::sleep(POLL);
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn clone_into_fd(&self) -> Result<RawFd, CgroupProbeError> {
        self.check_identity()?;
        Ok(self.directory.as_raw_fd())
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }
}
