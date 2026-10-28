//! Ownership of the dedicated UID-65532 PID-1 feature container only. Never
//! enumerate or signal host/VM processes from an unverified namespace.
use gauntlet_contracts::FeatureExecutorSpec;
use rustix::process::{getegid, geteuid, getgid, getpid, getuid};
use std::time::{Duration, Instant};

pub(super) struct FeatureBox {
    profile: String,
}
impl FeatureBox {
    pub(super) fn preflight() -> Result<(), String> {
        if std::env::consts::ARCH != "aarch64"
            || getpid().as_raw_pid() != 1
            || [
                geteuid().as_raw(),
                getuid().as_raw(),
                getegid().as_raw(),
                getgid().as_raw(),
            ] != [65532; 4]
        {
            return Err("dedicated ARM feature PID-1 identity required".into());
        }
        Ok(())
    }
    pub(super) fn activate(spec: &FeatureExecutorSpec) -> Result<Self, String> {
        Self::preflight()?;
        let result = Self {
            profile: format!("hol-gauntlet-build-{}", spec.text("audit_id")),
        };
        result.floors()?;
        // Only the trusted controller keeps the Root-owned stdout channel.
        // Candidate test children get separate logs and cannot reopen this
        // PID's descriptors or memory through their matching unprivileged UID.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
        {
            return Err("feature controller dump protection unavailable".into());
        }
        Ok(result)
    }
    fn floors(&self) -> Result<(), String> {
        Self::preflight()?;
        let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
        };
        for key in ["CapAmb:", "CapBnd:", "CapEff:", "CapInh:", "CapPrm:"] {
            if field(key) != Some("0000000000000000") {
                return Err("feature capabilities differ".into());
            }
        }
        if field("NoNewPrivs:") != Some("1") || field("Seccomp:") != Some("2") {
            return Err("feature syscall/privilege floor differs".into());
        }
        let label =
            std::fs::read_to_string("/proc/self/attr/current").map_err(|e| e.to_string())?;
        if ![
            format!("{} (enforce)", self.profile),
            format!("crun//&{} (mixed)", self.profile),
            format!("{}//&crun (mixed)", self.profile),
        ]
        .contains(&label.trim().to_owned())
        {
            return Err("feature AppArmor attachment differs".into());
        }
        Ok(())
    }
    pub(super) fn verify(&self) -> Result<(), String> {
        self.floors()?;
        if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err("feature controller dump protection changed".into());
        }
        Ok(())
    }
    pub(super) fn drain_children(&self) -> Result<(), String> {
        self.verify()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut pids = Vec::new();
            for entry in std::fs::read_dir("/proc").map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if let Ok(pid) = name.parse::<i32>() {
                    if pid > 1 {
                        pids.push(pid);
                    }
                }
            }
            if pids.len() > 4096 {
                return Err("feature process inventory exceeds bound".into());
            }
            for pid in &pids {
                if unsafe { libc::kill(*pid, libc::SIGKILL) } != 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                {
                    return Err("owned feature descendant kill unavailable".into());
                }
            }
            loop {
                let mut status = 0;
                let result = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                if result > 0 {
                    continue;
                }
                if result < 0 {
                    let error = std::io::Error::last_os_error().raw_os_error();
                    if error == Some(libc::EINTR) {
                        continue;
                    }
                    if error != Some(libc::ECHILD) {
                        return Err("feature descendant reap unavailable".into());
                    }
                }
                break;
            }
            if pids.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("feature descendant cleanup uncertain".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
