//! Kernel-only process snapshot retained through a Native MCP session.
use super::*;
use crate::linux_process::observe_process;
pub(super) struct Snapshot {
    pub pin: SdkWirePeerPin,
    pub process: OwnedFd,
    pidfd: OwnedFd,
    pub namespaces: BTreeMap<String, (OwnedFd, String)>,
    pub status: BTreeMap<String, String>,
    pub label: String,
}
impl Snapshot {
    pub fn new(pin: &SdkWirePeerPin, label: &str) -> Result<Self, String> {
        observe_process(pin.pid, pin.start_ticks, &pin.cgroup).map_err(|_| "MCP tuple differs")?;
        let pid = Pid::from_raw(i32::try_from(pin.pid).map_err(|_| "MCP PID overflow")?)
            .ok_or("MCP PID invalid")?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(|e| e.to_string())?;
        let process = open(
            format!("/proc/{}", pin.pid),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let status = checked_status(&read_at(&process, "status", 16384)?, pin.pid)?;
        let current = String::from_utf8(read_at(&process, "attr/current", 4096)?)
            .map_err(|_| "MCP label UTF-8")?;
        let label = checked_label(label, current.trim())?;
        let mut namespaces = BTreeMap::new();
        for name in ["mnt", "pid", "net", "ipc", "uts", "cgroup", "user"] {
            let fd = openat(
                &process,
                format!("ns/{name}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let stat = fstat(&fd).map_err(|e| e.to_string())?;
            namespaces.insert(
                name.into(),
                (fd, format!("{}:{}", stat.st_dev, stat.st_ino)),
            );
        }
        let snapshot = Self {
            pin: pin.clone(),
            process,
            pidfd,
            namespaces,
            status,
            label,
        };
        snapshot.recheck()?;
        Ok(snapshot)
    }
    pub fn recheck(&self) -> Result<(), String> {
        alive(&self.pidfd)?;
        observe_process(self.pin.pid, self.pin.start_ticks, &self.pin.cgroup)
            .map_err(|_| "MCP PID/start/cgroup changed")?;
        if checked_status(&read_at(&self.process, "status", 16384)?, self.pin.pid)? != self.status
            || String::from_utf8(read_at(&self.process, "attr/current", 4096)?)
                .map_err(|_| "MCP label UTF-8")?
                .trim()
                != self.label
        {
            return Err("MCP IDs/capabilities/filter/label changed".into());
        }
        for (name, (held, expected)) in &self.namespaces {
            let visible = openat(
                &self.process,
                format!("ns/{name}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            for fd in [held, &visible] {
                let stat = fstat(fd).map_err(|e| e.to_string())?;
                if format!("{}:{}", stat.st_dev, stat.st_ino) != *expected {
                    return Err("MCP namespace changed".into());
                }
            }
        }
        alive(&self.pidfd)
    }
    pub fn namespace_values(&self) -> BTreeMap<String, String> {
        self.namespaces
            .iter()
            .map(|(name, (_, value))| (name.clone(), value.clone()))
            .collect()
    }
    pub fn value(&self) -> Value {
        json!({"pid":self.pin.pid,"start_ticks":self.pin.start_ticks,"cgroup":self.pin.cgroup,
            "status":self.status,"namespaces":self.namespace_values(),"lsm_label":self.label,"pidfd_held":true})
    }
}
