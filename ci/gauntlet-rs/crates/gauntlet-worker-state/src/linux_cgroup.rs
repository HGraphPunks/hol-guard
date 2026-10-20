//! Bounded cgroup-v2 resource sampling tied to a live pidfd observation.
//! Missing or malformed kernel counters are unavailable, never zero.

use crate::linux_process::{
    observe_process, valid_cgroup, ProcessObservation, ProcessObservationError,
};
use rustix::fs::{open, openat, Mode, OFlags};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

const MAX_COUNTER_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupResources {
    pub memory_bytes: u64,
    pub memory_limit_bytes: Option<u64>,
    pub peak_memory_bytes: u64,
    pub tasks: u64,
    pub task_limit: Option<u64>,
    pub oom_kills: u64,
    pub pid_limit_hits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResourceObservation {
    pub process: ProcessObservation,
    pub resources: CgroupResources,
}

fn read_counter(directory: &OwnedFd, name: &str) -> Result<Vec<u8>, ProcessObservationError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProcessObservationError::Unavailable)?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take((MAX_COUNTER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProcessObservationError::Unavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_COUNTER_BYTES {
        return Err(ProcessObservationError::Unavailable);
    }
    Ok(bytes)
}

fn parse_number(raw: &[u8], allow_max: bool) -> Option<Option<u64>> {
    let text = std::str::from_utf8(raw).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if allow_max && text == "max" {
        return Some(None);
    }
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(Some(text.parse().ok()?))
}

fn parse_event(raw: &[u8], target: &str) -> Option<u64> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut events = BTreeMap::new();
    for line in text.lines() {
        if events.len() >= 32 {
            return None;
        }
        let (name, count) = line.split_once(' ')?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return None;
        }
        let count = parse_number(count.as_bytes(), false)??;
        if events.insert(name, count).is_some() {
            return None;
        }
    }
    events.get(target).copied()
}

fn required_number(directory: &OwnedFd, name: &str) -> Result<u64, ProcessObservationError> {
    parse_number(&read_counter(directory, name)?, false)
        .flatten()
        .ok_or(ProcessObservationError::Unavailable)
}

fn limit(directory: &OwnedFd, name: &str) -> Result<Option<u64>, ProcessObservationError> {
    parse_number(&read_counter(directory, name)?, true).ok_or(ProcessObservationError::Unavailable)
}

fn event(directory: &OwnedFd, name: &str, target: &str) -> Result<u64, ProcessObservationError> {
    parse_event(&read_counter(directory, name)?, target).ok_or(ProcessObservationError::Unavailable)
}

fn read_resources(path: &str) -> Result<CgroupResources, ProcessObservationError> {
    if !valid_cgroup(path) {
        return Err(ProcessObservationError::InvalidExpectation);
    }
    let mut directory = open(
        "/sys/fs/cgroup",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProcessObservationError::Unavailable)?;
    for part in path[1..].split('/') {
        directory = openat(
            &directory,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ProcessObservationError::Unavailable)?;
    }
    Ok(CgroupResources {
        memory_bytes: required_number(&directory, "memory.current")?,
        memory_limit_bytes: limit(&directory, "memory.max")?,
        peak_memory_bytes: required_number(&directory, "memory.peak")?,
        tasks: required_number(&directory, "pids.current")?,
        task_limit: limit(&directory, "pids.max")?,
        oom_kills: event(&directory, "memory.events", "oom_kill")?,
        pid_limit_hits: event(&directory, "pids.events", "max")?,
    })
}

/// Sample kernel resource counters only while a process still has the
/// independently expected PID start tick and cgroup. The two process samples
/// bracket the cgroup reads; a missing counter makes the entire sample
/// unavailable. This reports a snapshot, not descendant cleanup or a verdict.
pub fn observe_process_resources(
    pid: u32,
    expected_start_ticks: u64,
    expected_cgroup: &str,
) -> Result<ProcessResourceObservation, ProcessObservationError> {
    observe_process(pid, expected_start_ticks, expected_cgroup)?;
    let resources = read_resources(expected_cgroup)?;
    let process = observe_process(pid, expected_start_ticks, expected_cgroup)?;
    Ok(ProcessResourceObservation { process, resources })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_limits_and_refuses_missing_or_forged_events() {
        assert_eq!(parse_number(b"max\n", true), Some(None));
        assert_eq!(parse_number(b"123\n", false), Some(Some(123)));
        assert_eq!(parse_number(b"-1\n", false), None);
        assert_eq!(parse_number(b"0\n1\n", false), None);
        assert_eq!(parse_event(b"low 0\noom_kill 2\n", "oom_kill"), Some(2));
        assert_eq!(parse_event(b"low 0\n", "oom_kill"), None);
        assert_eq!(parse_event(b"oom_kill 2\noom_kill 0\n", "oom_kill"), None);
    }

    #[test]
    fn samples_own_cgroup_without_promoting_missing_counters_to_zero() {
        let pid = std::process::id();
        let stat = std::fs::read(format!("/proc/{pid}/stat")).unwrap();
        let expected = crate::linux_process::parse_proc_stat(&stat, pid).unwrap();
        let cgroup = std::fs::read(format!("/proc/{pid}/cgroup")).unwrap();
        let path = std::str::from_utf8(&cgroup)
            .unwrap()
            .trim_end()
            .strip_prefix("0::")
            .unwrap();
        let sample = observe_process_resources(pid, expected.start_ticks, path).unwrap();
        assert_eq!(sample.process.cgroup, path);
        assert!(sample.resources.tasks > 0);
        assert!(sample.resources.peak_memory_bytes >= sample.resources.memory_bytes);
        assert_eq!(
            observe_process_resources(pid, expected.start_ticks, "/system.slice/absent.service"),
            Err(ProcessObservationError::IdentityMismatch)
        );
    }
}
