//! A detached fixture is identified from outside by pidfd, start time,
//! executable inode/bytes, exact argv, cgroup, ancestry and session identity.
use crate::kernel_process::{alive, read_at, root_proc};
use crate::native_lifecycle_spec::NativeLifecycleSpec;
use crate::{hash, NativeCell, Result};
use rustix::fs::{fstat, openat, readlinkat, FileType, Mode, OFlags};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::fd::OwnedFd,
};

const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
fn proc(root: &OwnedFd, pid: u32) -> Result<OwnedFd> {
    openat(root, pid.to_string(), DIR, Mode::empty()).map_err(|e| e.to_string())
}
fn stat(process: &OwnedFd, pid: u32) -> Result<Vec<String>> {
    let raw =
        String::from_utf8(read_at(process, "stat", 4096)?).map_err(|_| "detached stat UTF-8")?;
    if raw.split_whitespace().next() != Some(pid.to_string().as_str()) {
        return Err("detached stat PID differs".into());
    }
    let fields = raw
        .rsplit_once(") ")
        .ok_or("detached stat shape")?
        .1
        .split_whitespace()
        .map(String::from)
        .collect::<Vec<_>>();
    if fields.len() < 20 {
        return Err("detached stat fields unavailable".into());
    }
    Ok(fields)
}
fn number(fields: &[String], index: usize) -> Result<u64> {
    fields[index]
        .parse()
        .map_err(|_| "detached numeric stat field".into())
}
fn namespaces(process: &OwnedFd) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for name in ["pid", "mnt", "net", "ipc", "uts", "cgroup", "user"] {
        let fd = openat(
            process,
            format!("ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let s = fstat(&fd).map_err(|e| e.to_string())?;
        result.insert(name.into(), format!("{}:{}", s.st_dev, s.st_ino));
    }
    Ok(result)
}
fn ancestry(root: &OwnedFd, pid: u32, anchor: u32, anchor_start: u64) -> Result<Vec<Value>> {
    let mut current = pid;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for _ in 0..64 {
        if !seen.insert(current) {
            return Err("detached ancestry cycle".into());
        }
        let p = proc(root, current)?;
        let first = stat(&p, current)?;
        let parent =
            u32::try_from(number(&first, 1)?).map_err(|_| "bounded detached parent PID")?;
        let start = number(&first, 19)?;
        let second = stat(&p, current)?;
        if number(&second, 1)? != parent as u64 || number(&second, 19)? != start {
            return Err("detached ancestry changed during readback".into());
        }
        result.push(json!({"pid":current,"parent_pid":parent,"start_ticks":start}));
        if current == anchor {
            if start != anchor_start {
                return Err("detached Native CLI anchor PID reused".into());
            }
            return Ok(result);
        }
        if parent <= 1 {
            break;
        }
        current = parent;
    }
    Err("detached process is not an actual Native CLI descendant".into())
}
pub(crate) struct HeldLifecycleChild {
    pidfd: OwnedFd,
    process: OwnedFd,
    pub workspace: OwnedFd,
    pub observation: Value,
}
impl HeldLifecycleChild {
    pub fn find(
        cell: &NativeCell,
        handle: &str,
        spec: &NativeLifecycleSpec,
    ) -> Result<Option<Self>> {
        let root = root_proc()?;
        let gate = cell
            .children
            .get(handle)
            .ok_or("held Native CLI gate required for detached observation")?
            .observation();
        let anchor = gate["pid"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("Native CLI PID missing")?;
        let anchor_start = gate["start_ticks"]
            .as_u64()
            .ok_or("Native CLI start time missing")?;
        let raw = crate::supervisor_io::kernel_file(&cell.cgroup.join("cgroup.procs"), 65536)?;
        let text = std::str::from_utf8(&raw).map_err(|_| "owned cgroup PID list UTF-8")?;
        let pids = text
            .split_whitespace()
            .map(|p| {
                p.parse::<u32>()
                    .map_err(|_| "owned cgroup PID shape".to_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        if pids.len() > 256 {
            return Err("bounded detached process search required".into());
        }
        let expected = spec.argv().join("\0") + "\0";
        for pid in pids {
            let Ok(process) = proc(&root, pid) else {
                continue;
            };
            let Ok(command) = read_at(&process, "cmdline", 65536) else {
                continue;
            };
            if command != expected.as_bytes() {
                continue;
            }
            let pidfd = pidfd_open(
                Pid::from_raw(pid as i32).ok_or("positive detached host PID")?,
                PidfdFlags::empty(),
            )
            .map_err(|e| e.to_string())?;
            if !alive(&pidfd)? {
                continue;
            }
            let first = stat(&process, pid)?;
            if number(&first, 2)? != pid as u64 || number(&first, 3)? != pid as u64 {
                return Err("detached host session/group not established".into());
            }
            let status_raw = String::from_utf8(read_at(&process, "status", 65536)?)
                .map_err(|_| "detached status UTF-8")?;
            let status = status_raw
                .lines()
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.to_owned(), v.trim().to_owned()))
                .collect::<BTreeMap<_, _>>();
            let local = status
                .get("NSpid")
                .and_then(|v| v.split_whitespace().last())
                .and_then(|v| v.parse::<u64>().ok());
            let local = local.ok_or("detached namespace PID unavailable")?;
            for key in ["Uid", "Gid"] {
                if status.get(key).map(String::as_str) != Some("10004\t10004\t10004\t10004") {
                    return Err("detached host privilege identity differs".into());
                }
            }
            for (key, wanted) in [
                ("CapEff", "0000000000000000"),
                ("NoNewPrivs", "1"),
                ("Seccomp", "2"),
            ] {
                if status.get(key).map(String::as_str) != Some(wanted) {
                    return Err("detached kernel privilege/filter differs".into());
                }
            }
            let cgroup = read_at(&process, "cgroup", 4096)?;
            let relative = cell
                .cgroup
                .strip_prefix("/sys/fs/cgroup")
                .map_err(|_| "owned cgroup root")?
                .to_string_lossy();
            let wanted = format!("/{relative}");
            if cgroup != format!("0::{wanted}\n").as_bytes() {
                return Err("detached process escaped the owned product cgroup".into());
            }
            let label = String::from_utf8(read_at(&process, "attr/current", 4096)?)
                .map_err(|_| "detached LSM UTF-8")?;
            if label.trim() != format!("{} (enforce)", cell.profile) {
                return Err("detached product enforcing LSM label differs".into());
            }
            let executable = openat(
                &process,
                "exe",
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let image = openat(
                &cell.inputs.image,
                "usr/bin/python3.12",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let e = fstat(&executable).map_err(|e| e.to_string())?;
            let image = fstat(&image).map_err(|e| e.to_string())?;
            if FileType::from_raw_mode(e.st_mode) != FileType::RegularFile
                || e.st_dev != image.st_dev
                || e.st_ino != image.st_ino
                || e.st_uid != 0
                || e.st_gid != 0
                || e.st_mode & 0o022 != 0
                || !(1..=32 * 1024 * 1024).contains(&e.st_size)
            {
                return Err(
                    "detached executable is not the pinned product image interpreter".into(),
                );
            }
            let mut bytes = Vec::new();
            File::from(executable)
                .take(32 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            let ns = namespaces(&process)?;
            let own = namespaces(&proc(&root, std::process::id())?)?;
            for key in ["pid", "mnt", "net"] {
                if ns[key] == own[key] {
                    return Err("detached process shares controller namespace".into());
                }
            }
            let parents = ancestry(&root, pid, anchor, anchor_start)?;
            // The Linux product sandbox writes to an overlay. The task's lower
            // directory is deliberately not the child's live workspace view.
            // Follow only this held, kernel-identified process's procfs cwd link.
            let cwd = readlinkat(&process, "cwd", Vec::new()).map_err(|e| e.to_string())?;
            if cwd.as_bytes() != b"/runtime/home/project" {
                return Err("detached child cwd is not the fixed contained workspace".into());
            }
            let workspace = openat(
                &process,
                "cwd",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let directory = fstat(&workspace).map_err(|e| e.to_string())?;
            if FileType::from_raw_mode(directory.st_mode) != FileType::Directory {
                return Err("detached cwd is not a held directory".into());
            }
            let after = stat(&process, pid)?;
            let executable_after = openat(
                &process,
                "exe",
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            if !alive(&pidfd)?
                || number(&first, 19)? != number(&after, 19)?
                || read_at(&process, "cmdline", 65536)? != command
                || bytes.len() as i64 != e.st_size
                || !crate::fs_input::same(&e, &fstat(&executable_after).map_err(|e| e.to_string())?)
            {
                return Err("detached process changed during held observation".into());
            }
            let observation = json!({"pid":pid,"start_ticks":number(&first,19)?,"pidfd_held":true,"argv":spec.argv(),"argv_sha256":hash(&command),
                "status":status,"namespace_pid":local,"namespaces":ns,"lsm_label":label.trim(),"cgroup":wanted,"ancestry":parents,
                "workspace_view":{"source":"kernel-held-process-cwd.v1","path":"/runtime/home/project",
                    "device":directory.st_dev,"inode":directory.st_ino,"uid":directory.st_uid,"gid":directory.st_gid,"mode":directory.st_mode & 0o7777},
                "executable_device":e.st_dev,"executable_inode":e.st_ino,"executable_sha256":hash(&bytes)});
            return Ok(Some(Self {
                pidfd,
                process,
                workspace,
                observation,
            }));
        }
        Ok(None)
    }
    pub fn is_alive(&self) -> Result<bool> {
        let live = alive(&self.pidfd)?;
        if live {
            let pid = self.observation["pid"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or("held detached PID")?;
            if number(&stat(&self.process, pid)?, 19)?
                != self.observation["start_ticks"]
                    .as_u64()
                    .ok_or("held detached start")?
            {
                return Err("held detached PID identity changed".into());
            }
        }
        Ok(live)
    }
}
