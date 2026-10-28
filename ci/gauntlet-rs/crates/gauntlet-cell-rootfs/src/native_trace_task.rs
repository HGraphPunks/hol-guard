//! Kernel task references for the outside ptrace recorder. No target memory reads.
use crate::kernel_process::{read_at, root_proc};
use crate::{hash, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustix::fs::{fstat, openat, Mode, OFlags};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;

pub(super) struct Task {
    pub(super) tid: u32,
    pub(super) tgid: u32,
    pub(super) start: u64,
    proc: OwnedFd,
    // Thread IDs are held by the ptrace relationship. Leaders additionally
    // retain a pidfd; ordinary pidfd_open does not accept non-leader TIDs.
    _leader: Option<OwnedFd>,
}

fn status(proc: &OwnedFd) -> Result<BTreeMap<String, String>> {
    let raw = read_at(proc, "status", 65536)?;
    let text = std::str::from_utf8(&raw).map_err(|_| "kernel task status UTF-8")?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once(':').ok_or("kernel task status field")?;
        if fields
            .insert(key.to_owned(), value.trim().to_owned())
            .is_some()
        {
            return Err("duplicate kernel task status field".into());
        }
    }
    Ok(fields)
}

fn number(fields: &BTreeMap<String, String>, key: &str) -> Result<u32> {
    fields
        .get(key)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("kernel task {key} missing"))
}

impl Task {
    /// O_PATH retains only the pipe object; it adds no reader or writer and
    /// therefore cannot suppress the real transport's EOF or SIGPIPE.
    pub(super) fn stdio_pipe(&self, descriptor: u8) -> Result<OwnedFd> {
        if descriptor > 1 {
            return Err("only selected Native stdin/stdout descriptors permitted".into());
        }
        let name = format!("fd/{descriptor}");
        let fd = openat(
            &self.proc,
            &name,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let info = fstat(&fd).map_err(|e| e.to_string())?;
        let link =
            rustix::fs::readlinkat(&self.proc, &name, Vec::new()).map_err(|e| e.to_string())?;
        if rustix::fs::FileType::from_raw_mode(info.st_mode) != rustix::fs::FileType::Fifo
            || info.st_ino == 0
            || link.as_bytes() != format!("pipe:[{}]", info.st_ino).as_bytes()
        {
            return Err("anonymous Native transport pipe required".into());
        }
        Ok(fd)
    }

    pub(super) fn open(tid: u32, cgroup: &str) -> Result<Self> {
        let pid = i32::try_from(tid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or("positive kernel TID required")?;
        let root = root_proc()?;
        let proc = openat(
            &root,
            tid.to_string(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let fields = status(&proc)?;
        let tgid = number(&fields, "Tgid")?;
        if number(&fields, "Pid")? != tid || tgid == 0 {
            return Err("kernel task PID/Tgid differs".into());
        }
        let leader = if tid == tgid {
            Some(pidfd_open(pid, PidfdFlags::empty()).map_err(|e| e.to_string())?)
        } else {
            None
        };
        let start = crate::native_trace_identity::start_ticks(&read_at(&proc, "stat", 4096)?, tid)?;
        let held = Self {
            tid,
            tgid,
            start,
            proc,
            _leader: leader,
        };
        held.recheck(cgroup)?;
        Ok(held)
    }

    pub(super) fn recheck(&self, cgroup: &str) -> Result<()> {
        if crate::native_trace_identity::start_ticks(&read_at(&self.proc, "stat", 4096)?, self.tid)?
            != self.start
        {
            return Err("traced task generation changed".into());
        }
        let raw = read_at(&self.proc, "cgroup", 4096)?;
        let text = std::str::from_utf8(&raw).map_err(|_| "traced cgroup UTF-8")?;
        if text.trim() != format!("0::{cgroup}") {
            return Err("traced task escaped the owned product cgroup".into());
        }
        Ok(())
    }

    pub(super) fn anchor(&self, cgroup: &str) -> Result<Value> {
        self.recheck(cgroup)?;
        let fields = status(&self.proc)?;
        if number(&fields, "TracerPid")? != unsafe { libc::syscall(libc::SYS_gettid) } as u32 {
            return Err("kernel task is not owned by this recorder thread".into());
        }
        let selected = [
            "Uid",
            "Gid",
            "Groups",
            "CapAmb",
            "CapBnd",
            "CapEff",
            "CapInh",
            "CapPrm",
            "NoNewPrivs",
            "Seccomp",
            "Seccomp_filters",
            "NSpid",
            "TracerPid",
            "Threads",
            "Cpus_allowed_list",
        ];
        let values = selected
            .into_iter()
            .map(|key| {
                fields
                    .get(key)
                    .cloned()
                    .map(|v| (key.to_owned(), v))
                    .ok_or_else(|| format!("traced task status {key} missing"))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(
            json!({"tid":self.tid,"tgid":self.tgid,"start_ticks":self.start,"parent_pid":number(&fields,"PPid")?,"cgroup":cgroup,"status":values}),
        )
    }

    pub(super) fn initial_actor(&self, expected_start: u64, cgroup: &str) -> Result<()> {
        let fields = status(&self.proc)?;
        let ids = |name| {
            fields
                .get(name)
                .is_some_and(|s| s.split_ascii_whitespace().collect::<Vec<_>>() == ["10004"; 4])
        };
        if self.tid != self.tgid
            || self.start != expected_start
            || !ids("Uid")
            || !ids("Gid")
            || number(&fields, "TracerPid")? != 0
            || number(&fields, "Threads")? != 1
            || read_at(&self.proc, "cmdline", 65536)? != b"/public/gauntlet-product-cell\0actor\0"
        {
            return Err(
                "only the held, untraced, single-threaded product actor may start recording".into(),
            );
        }
        self.recheck(cgroup)
    }

    pub(super) fn exec_image(&self, cgroup: &str) -> Result<Value> {
        self.recheck(cgroup)?;
        // Follow only the kernel's executable link of this ptrace-stopped task.
        let fd = openat(
            &self.proc,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let image = crate::native_trace_image::measure(fd)?;
        let before = &image.metadata;
        let argv = read_at(&self.proc, "cmdline", 65536)?;
        if argv.is_empty() || !argv.ends_with(b"\0") {
            return Err("traced exec argv unavailable".into());
        }
        let label = read_at(&self.proc, "attr/current", 4096)?;
        // Descendant sandboxes may add a user namespace. Record every kernel
        // identity here; source-specific privilege/isolation grading is separate.
        let mut namespaces = BTreeMap::new();
        for name in ["pid", "mnt", "net", "ipc", "uts", "cgroup", "user"] {
            let fd = openat(
                &self.proc,
                format!("ns/{name}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let info = fstat(&fd).map_err(|e| e.to_string())?;
            namespaces.insert(name, format!("{}:{}", info.st_dev, info.st_ino));
        }
        self.recheck(cgroup)?;
        Ok(
            json!({"task":self.anchor(cgroup)?,"argv_base64":STANDARD.encode(&argv),"argv_sha256":hash(&argv),
            "executable":{"device":before.st_dev,"inode":before.st_ino,"uid":before.st_uid,"gid":before.st_gid,"mode":before.st_mode&0o7777,"links":before.st_nlink,"bytes":image.bytes,"sha256":image.sha256},
            "lsm_label":std::str::from_utf8(&label).map_err(|_|"traced label UTF-8")?.trim(),"namespaces":namespaces}),
        )
    }
}
