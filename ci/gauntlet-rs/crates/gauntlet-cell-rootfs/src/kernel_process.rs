//! Outside collection holds a pidfd and /proc descriptors across two samples.
//! It never accepts actor JSON as kernel identity or grants execution admission.
use crate::{hash, hex, Result};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fstat, fstatfs, open, openat, Mode, OFlags, PROC_SUPER_MAGIC};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

#[derive(Debug, Clone)]
pub struct CellProcessExpectation {
    pub profile: String,
    /// Exact kernel path /system.slice/hol-product-cell-<nonce>.service, or
    /// the equivalent beneath this run's fixed holgauntletrust<id>.slice.
    pub cgroup: String,
    pub local_pid: u32,
    pub argv: Vec<String>,
    pub executable_sha256: String,
    pub filtered: bool,
    pub cpu: Option<u32>,
    /// Established by this cell's outside recorder, never a product claim.
    pub tracer_tid: Option<u32>,
}

impl CellProcessExpectation {
    fn validate(&self) -> Result<()> {
        let suffix = self
            .profile
            .strip_prefix("hol-product-cell-")
            .filter(|s| hex(s, 32))
            .ok_or("fixed product service identity required")?;
        let parts: Vec<_> = self.cgroup.split('/').collect();
        if parts.len() != 3
            || !parts[0].is_empty()
            || parts[2] != format!("hol-product-cell-{suffix}.service")
            || !(parts[1] == "system.slice"
                || parts[1]
                    .strip_prefix("holgauntletrust")
                    .and_then(|s| s.strip_suffix(".slice"))
                    .is_some_and(|s| hex(s, 16)))
            || !hex(&self.executable_sha256, 64)
            || self.local_pid == 0
            || self
                .tracer_tid
                .is_some_and(|n| !self.filtered || n == 0 || n > i32::MAX as u32)
        {
            return Err(
                "exact product service cgroup, local PID and executable pin required".into(),
            );
        }
        gauntlet_product_cell::validate_product_argv(&self.argv).map_err(|e| e.to_string())?;
        let strings = self.argv.iter().map(String::as_str).collect::<Vec<_>>();
        if !self.filtered {
            if self.local_pid != 1
                || strings
                    != [
                        "/public/initializer",
                        "/public/gauntlet-product-cell",
                        "actor",
                    ]
            {
                return Err("only the fixed initializer may precede the filter gate".into());
            }
        } else if self.local_pid == 1 {
            if strings != ["/public/gauntlet-product-cell", "actor"] {
                return Err("fixed native PID1 actor required".into());
            }
        } else if strings.len() < 3
            || strings[..2] != ["/public/gauntlet-product-cell", "exec-gate"]
        {
            return Err("fixed native execution gate required".into());
        }
        Ok(())
    }
}

pub struct HeldCellProcess {
    pidfd: OwnedFd,
    proc: OwnedFd,
    pid: u32,
    start_ticks: u64,
    expectation: CellProcessExpectation,
    observation: Value,
}

fn same_identity(first: &Value, second: &Value) -> bool {
    // Routes are validated against the loopback-only policy on every sample.
    // Kernel reference/use counters may change as legitimate sockets open.
    let mut first = first.clone();
    let mut second = second.clone();
    if let Some(v) = first.as_object_mut() {
        v.remove("network");
    }
    if let Some(v) = second.as_object_mut() {
        v.remove("network");
    }
    first == second
}

pub(crate) fn read_at(directory: &OwnedFd, name: &str, maximum: usize) -> Result<Vec<u8>> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    File::from(fd)
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > maximum {
        return Err("kernel process file exceeds fixed bound".into());
    }
    Ok(raw)
}

pub(crate) fn alive(pidfd: &OwnedFd) -> Result<bool> {
    let mut fds = [PollFd::new(pidfd, PollFlags::IN)];
    Ok(poll(
        &mut fds,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(|e| e.to_string())?
        == 0)
}

pub(crate) fn root_proc() -> Result<OwnedFd> {
    // A Root identity inside an unprivileged user namespace is not an outside
    // VM collector. Require the kernel's complete initial UID and GID maps.
    if unsafe {
        libc::getuid() != 0 || libc::geteuid() != 0 || libc::getgid() != 0 || libc::getegid() != 0
    } {
        return Err("initial Root outside product collector required".into());
    }
    let proc = open(
        "/proc",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    if fstatfs(&proc).map_err(|e| e.to_string())?.f_type != PROC_SUPER_MAGIC {
        return Err("actual kernel procfs required".into());
    }
    // Follow the known kernel self link only beneath the held procfs root.
    let own = openat(
        &proc,
        "self",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    for name in ["uid_map", "gid_map"] {
        let raw = read_at(&own, name, 128)?;
        let fields = std::str::from_utf8(&raw)
            .map_err(|_| "invalid kernel ID map")?
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        if fields != ["0", "0", "4294967295"] {
            return Err("initial user namespace collector required".into());
        }
    }
    Ok(proc)
}

pub(crate) fn namespace_values(proc: &OwnedFd) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for name in ["pid", "mnt", "net", "ipc", "uts", "cgroup", "user"] {
        let relative = format!("ns/{name}");
        // These two links are generated by procfs under a held process; their
        // device/inode identities are compared, never supplied filesystem paths.
        let fd = openat(
            proc,
            &relative,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let own = open(
            format!("/proc/self/ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let info = fstat(&fd).map_err(|e| e.to_string())?;
        let host = fstat(&own).map_err(|e| e.to_string())?;
        let same = info.st_dev == host.st_dev && info.st_ino == host.st_ino;
        if same != (name == "user") {
            return Err("six private namespaces and original user namespace required".into());
        }
        result.insert(name.into(), format!("{}:{}", info.st_dev, info.st_ino));
    }
    Ok(result)
}

fn executable(proc: &OwnedFd, expected: &str) -> Result<()> {
    // Intentionally follow only the kernel exe link of the pidfd-held process.
    let fd = openat(proc, "exe", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    crate::fs_input::root_metadata(&before, false)?;
    if before.st_size <= 0 || before.st_size as u64 > 16 * 1024 * 1024 {
        return Err("bounded product executable required".into());
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    file.by_ref()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible = openat(proc, "exe", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| e.to_string())?;
    if !crate::fs_input::same(&before, &after)
        || !crate::fs_input::same(&before, &fstat(&visible).map_err(|e| e.to_string())?)
        || raw.len() as u64 != before.st_size as u64
        || hash(&raw) != expected
    {
        return Err("kernel executable differs from outside pin or changed while hashing".into());
    }
    Ok(())
}

impl HeldCellProcess {
    pub fn observe(pid: u32, expected: CellProcessExpectation) -> Result<Self> {
        let proc_root = root_proc()?;
        expected.validate()?;
        let raw = i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or("positive host product PID required")?;
        let pidfd = pidfd_open(raw, PidfdFlags::empty()).map_err(|e| e.to_string())?;
        let proc = openat(
            &proc_root,
            pid.to_string(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let start_ticks = crate::kernel_trace_owner::ticks(&proc, pid, expected.tracer_tid)?;
        let mut held = Self {
            pidfd,
            proc,
            pid,
            start_ticks,
            expectation: expected,
            observation: Value::Null,
        };
        let first = held.sample()?;
        let second = held.sample()?;
        if !same_identity(&first, &second) {
            return Err("kernel product identity changed across held samples".into());
        }
        held.observation = second;
        Ok(held)
    }

    fn sample(&self) -> Result<Value> {
        self.sample_with_pipes(&BTreeSet::new())
    }

    fn sample_with_pipes(&self, permitted: &BTreeSet<String>) -> Result<Value> {
        if !self.is_alive()?
            || crate::kernel_trace_owner::ticks(&self.proc, self.pid, self.expectation.tracer_tid)?
                != self.start_ticks
        {
            return Err("owned product process exited or PID was reused".into());
        }
        let e = &self.expectation;
        let cgroup = read_at(&self.proc, "cgroup", 4096)?;
        if cgroup != format!("0::{}\n", e.cgroup).as_bytes() {
            return Err("actual product cgroup differs from owned service".into());
        }
        let status = crate::kernel_status::status(
            &read_at(&self.proc, "status", 65536)?,
            self.pid,
            e.local_pid,
            e.filtered,
            e.cpu,
        )?;
        let argv = read_at(&self.proc, "cmdline", 65536)?;
        let wanted = e
            .argv
            .iter()
            .flat_map(|s| s.as_bytes().iter().copied().chain([0]))
            .collect::<Vec<_>>();
        if argv != wanted {
            return Err("actual product argv differs from measured gate".into());
        }
        let label = String::from_utf8(read_at(&self.proc, "attr/current", 4096)?)
            .map_err(|_| "LSM label UTF-8")?;
        if label.trim() != format!("{} (enforce)", e.profile) {
            return Err("exact enforcing product AppArmor profile required".into());
        }
        executable(&self.proc, &e.executable_sha256)?;
        let namespaces = namespace_values(&self.proc)?;
        let fds = crate::kernel_descriptors::read(&self.proc, permitted)?;
        let mounts = read_at(&self.proc, "mountinfo", 1024 * 1024)?;
        let network = gauntlet_product_cell::validate_private_topology(
            std::str::from_utf8(&read_at(&self.proc, "net/dev", 65536)?)
                .map_err(|_| "network device UTF-8")?,
            std::str::from_utf8(&read_at(&self.proc, "net/route", 65536)?)
                .map_err(|_| "network route UTF-8")?,
            std::str::from_utf8(&read_at(&self.proc, "net/ipv6_route", 65536)?)
                .map_err(|_| "IPv6 route UTF-8")?,
            std::str::from_utf8(&read_at(&self.proc, "net/if_inet6", 65536)?)
                .map_err(|_| "IPv6 address UTF-8")?,
        )
        .map_err(|e| e.to_string())?;
        if !self.is_alive()?
            || crate::kernel_trace_owner::ticks(&self.proc, self.pid, self.expectation.tracer_tid)?
                != self.start_ticks
        {
            return Err("product process changed during outside collection".into());
        }
        Ok(
            json!({"pid":self.pid,"start_ticks":self.start_ticks,"cgroup":e.cgroup,"status":status,
            "argv":e.argv,"executable_sha256":e.executable_sha256,"lsm_label":label.trim(),
            "namespaces":namespaces,"fds":fds,"mountinfo_sha256":hash(&mounts),"network":network}),
        )
    }

    pub fn is_alive(&self) -> Result<bool> {
        alive(&self.pidfd)
    }
    pub fn observation(&self) -> &Value {
        &self.observation
    }
    /// The initializer may exec only the expected actor while preserving the
    /// same kernel process and all namespaces. A new PID cannot replace it.
    pub fn after_filter_gate(&self, expected: CellProcessExpectation) -> Result<Self> {
        if self.expectation.filtered
            || !expected.filtered
            || self.expectation.local_pid != 1
            || expected.local_pid != 1
            || expected.profile != self.expectation.profile
            || expected.cgroup != self.expectation.cgroup
            || expected.cpu != self.expectation.cpu
            || !self.is_alive()?
        {
            return Err("exact initializer-to-filtered-actor transition required".into());
        }
        let next = Self::observe(self.pid, expected)?;
        if next.start_ticks != self.start_ticks
            || next.observation["namespaces"] != self.observation["namespaces"]
        {
            return Err("product process or namespaces changed at filter gate".into());
        }
        Ok(next)
    }
    pub fn recheck(&self) -> Result<()> {
        if !same_identity(&self.sample()?, &self.observation) {
            return Err("measured product identity changed before release".into());
        }
        Ok(())
    }
    pub(crate) fn adopt_trace_owner(&mut self, tid: u32) -> Result<()> {
        if !self.expectation.filtered
            || self.expectation.local_pid != 1
            || self.expectation.tracer_tid.is_some()
        {
            return Err("only the initially held filtered actor may adopt its recorder".into());
        }
        self.expectation.tracer_tid = Some(tid);
        self.recheck()
    }
    pub(crate) fn recheck_actor(&self, child_pipes: &BTreeSet<String>) -> Result<Value> {
        if self.expectation.local_pid != 1 || !self.expectation.filtered {
            return Err("only the measured filtered actor may hold child pipes".into());
        }
        let first = self.sample_with_pipes(child_pipes)?;
        let second = self.sample_with_pipes(child_pipes)?;
        if !same_identity(&first, &second) {
            return Err("actor identity changed across idle samples".into());
        }
        let mut identity = second.clone();
        identity["fds"]
            .as_object_mut()
            .ok_or("actor descriptors unavailable")?
            .retain(|name, _| matches!(name.as_str(), "0" | "1" | "2"));
        if !same_identity(&identity, &self.observation) {
            return Err("measured actor identity changed before spawn".into());
        }
        Ok(second)
    }
    pub fn verify_task_mounts(
        &self,
        tasks: &[crate::declarations::TaskMount],
        runtime: &std::path::Path,
    ) -> Result<Value> {
        self.recheck()?;
        let mounts = String::from_utf8(read_at(&self.proc, "mountinfo", 1024 * 1024)?)
            .map_err(|_| "product mountinfo UTF-8")?;
        let result = crate::kernel_mounts::verify(&self.proc, &mounts, tasks, runtime)?;
        self.recheck()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_units_arbitrary_argv_and_unfiltered_children_are_refused_before_sampling() {
        let good = CellProcessExpectation {
            profile: format!("hol-product-cell-{}", "a".repeat(32)),
            cgroup: format!("/system.slice/hol-product-cell-{}.service", "a".repeat(32)),
            local_pid: 1,
            argv: vec!["/public/gauntlet-product-cell".into(), "actor".into()],
            executable_sha256: "b".repeat(64),
            filtered: true,
            cpu: None,
            tracer_tid: None,
        };
        assert!(good.validate().is_ok());
        let mut bad = good.clone();
        bad.cgroup = "/system.slice/sshd.service".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.local_pid = 2;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.filtered = false;
        assert!(bad.validate().is_err());
        let mut bad = good;
        bad.argv = vec!["/bin/sh".into()];
        assert!(bad.validate().is_err());
    }
}
