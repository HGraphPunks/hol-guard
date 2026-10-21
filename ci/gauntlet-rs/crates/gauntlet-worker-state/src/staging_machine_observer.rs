//! Kernel-only, read-only samples of Podman container scopes while a staging
//! control runs. These tuples can later be compared with a signed record's
//! container claim; scope presence alone cannot prove SDK or Guard behavior.

use crate::linux_process::{observe_process, parse_proc_stat};
use rustix::fs::{fstat, open, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

const MACHINE_SLICE: &str = "/sys/fs/cgroup/machine.slice";
const MAX_ENTRIES: usize = 512;
const MAX_SCOPES: usize = 32;
const MAX_PIDS_PER_SCOPE: usize = 256;
const MAX_CONTROL_BYTES: u64 = 4096;
const MAX_PROC_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ContainerProcessIdentity {
    pub(crate) container_id: String,
    pub(crate) pid: u32,
    pub(crate) start_ticks: u64,
    pub(crate) cgroup: String,
}

pub(crate) struct MachineSliceSampler {
    machine: OwnedFd,
    original: Stat,
}

fn same_root_directory(first: &Stat, second: &Stat) -> bool {
    FileType::from_raw_mode(first.st_mode) == FileType::Directory
        && first.st_uid == 0
        && first.st_mode & 0o022 == 0
        && first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
}

fn scope_id(name: &[u8]) -> Option<&[u8]> {
    let id = name.strip_prefix(b"libpod-")?.strip_suffix(b".scope")?;
    (id.len() == 64
        && id
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)))
    .then_some(id)
}

fn parse_pids(raw: &[u8]) -> Result<Vec<u32>, String> {
    if raw.len() as u64 > MAX_CONTROL_BYTES || !raw.is_empty() && !raw.ends_with(b"\n") {
        return Err("invalid container cgroup.procs framing".to_owned());
    }
    let text = std::str::from_utf8(raw).map_err(|_| "invalid container cgroup.procs UTF-8")?;
    let mut pids = BTreeSet::new();
    for line in text.lines() {
        if pids.len() == MAX_PIDS_PER_SCOPE
            || line.is_empty()
            || line.len() > 10
            || !line.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("invalid or unbounded container cgroup.procs".to_owned());
        }
        let pid = line
            .parse::<u32>()
            .map_err(|_| "container PID overflows u32")?;
        if pid == 0 || !pids.insert(pid) {
            return Err("invalid or duplicate container PID".to_owned());
        }
    }
    Ok(pids.into_iter().collect())
}

fn open_root_directory(parent: &OwnedFd, name: &str) -> Result<Option<OwnedFd>, String> {
    let directory = match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("unsafe container scope: {error}")),
    };
    let opened = fstat(&directory).map_err(|error| error.to_string())?;
    let visible = match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(visible) => visible,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("container scope changed: {error}")),
    };
    if !same_root_directory(&opened, &visible) {
        return Err("unsafe container scope identity".to_owned());
    }
    Ok(Some(directory))
}

fn read_pids(directory: &OwnedFd) -> Result<Option<Vec<u32>>, String> {
    let descriptor = match openat(
        directory,
        "cgroup.procs",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(format!("container cgroup.procs unavailable: {error}")),
    };
    let mut raw = Vec::new();
    File::from(descriptor)
        .take(MAX_CONTROL_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("container cgroup.procs read failed: {error}"))?;
    parse_pids(&raw).map(Some)
}

impl MachineSliceSampler {
    pub(crate) fn new() -> Result<Self, String> {
        let machine = open(
            MACHINE_SLICE,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("machine slice unavailable: {error}"))?;
        let original = fstat(&machine).map_err(|error| error.to_string())?;
        if !same_root_directory(&original, &original) {
            return Err("unsafe machine slice".to_owned());
        }
        Ok(Self { machine, original })
    }

    pub(crate) fn sample(&self) -> Result<Vec<ContainerProcessIdentity>, String> {
        let before = fstat(&self.machine).map_err(|error| error.to_string())?;
        if !same_root_directory(&self.original, &before) {
            return Err("machine slice changed before scan".to_owned());
        }
        let mut entries = Dir::read_from(&self.machine).map_err(|error| error.to_string())?;
        let mut entry_count = 0;
        let mut scope_count = 0;
        let mut result = Vec::new();
        for entry in &mut entries {
            let entry = entry.map_err(|error| error.to_string())?;
            entry_count += 1;
            if entry_count > MAX_ENTRIES {
                return Err("machine slice entry bound exceeded".to_owned());
            }
            let name = entry.file_name().to_bytes();
            let Some(id) = scope_id(name) else {
                continue;
            };
            scope_count += 1;
            if scope_count > MAX_SCOPES {
                return Err("Podman scope bound exceeded".to_owned());
            }
            let name = std::str::from_utf8(name).map_err(|_| "invalid Podman scope name")?;
            let Some(scope) = open_root_directory(&self.machine, name)? else {
                continue;
            };
            let Some(container) = open_root_directory(&scope, "container")? else {
                continue;
            };
            let Some(pids) = read_pids(&container)? else {
                continue;
            };
            let container_id = std::str::from_utf8(id)
                .map_err(|_| "invalid Podman container ID")?
                .to_owned();
            let expected_cgroup = format!("/machine.slice/{name}/container");
            for pid in pids {
                let path = format!("/proc/{pid}/stat");
                let Ok(raw) = std::fs::read(path) else {
                    continue;
                };
                if raw.len() > MAX_PROC_BYTES {
                    continue;
                }
                let Some(stat) = parse_proc_stat(&raw, pid) else {
                    continue;
                };
                if observe_process(pid, stat.start_ticks, &expected_cgroup).is_err() {
                    continue;
                }
                result.push(ContainerProcessIdentity {
                    container_id: container_id.clone(),
                    pid,
                    start_ticks: stat.start_ticks,
                    cgroup: expected_cgroup.clone(),
                });
            }
        }
        let after = fstat(&self.machine).map_err(|error| error.to_string())?;
        if !same_root_directory(&self.original, &after) {
            return Err("machine slice changed during scan".to_owned());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_podman_scope_and_pid_parser_refuse_ambiguous_names() {
        let id = "a".repeat(64);
        assert_eq!(
            scope_id(format!("libpod-{id}.scope").as_bytes()),
            Some(id.as_bytes())
        );
        assert!(scope_id(format!("libpod-{id}.scope/child").as_bytes()).is_none());
        assert!(scope_id(b"libpod-short.scope").is_none());
        assert_eq!(parse_pids(b"12\n7\n"), Ok(vec![7, 12]));
        for value in [b"1\n1\n".as_slice(), b"0\n", b"-1\n", b"1", b"4294967296\n"] {
            assert!(parse_pids(value).is_err());
        }
    }
}
