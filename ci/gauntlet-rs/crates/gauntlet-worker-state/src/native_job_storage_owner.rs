//! Retained Root mount-namespace identity. V2 task descriptors are opened only
//! after joining the original live owner; owner loss never creates a successor.
use super::{linux, JobStoragePins, JobStorageProfile};
use crate::owned_cgroup::{GroupLimits, OwnedProbeGroup};
use rustix::fs::{fstat, open, openat, Mode, OFlags};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, OwnedFd},
    path::{Path, PathBuf},
};

#[path = "native_job_storage_owner_retire.rs"]
mod retirement;
#[path = "native_job_storage_owner_service.rs"]
mod service;
pub(crate) use retirement::{abort_only, finish, require_admissible, verify_finished};
pub use service::run_storage_namespace_owner;
pub(crate) const BASE: &str = "/var/lib/hol-gauntlet-rust/storage-owners";
pub(crate) const LIMITS: GroupLimits = GroupLimits {
    memory: "33554432\n",
    pids: "1\n",
    cpu: "10000 100000\n",
};
pub(crate) fn group_name(job: &str) -> String {
    format!("hol-gauntlet-rust-storage-owner-{job}")
}
pub(crate) fn group_path(job: &str) -> String {
    format!("/system.slice/{}", group_name(job))
}
pub(crate) fn path(job: &str) -> Result<PathBuf, String> {
    if !crate::hex(job, 16) {
        return Err("exact owner job ID required".into());
    }
    Ok(Path::new(BASE).join(job))
}
pub(crate) fn slot(job: &str) -> Result<OwnedFd, String> {
    crate::open_root_owned_public_directory(&path(job)?).map_err(|e| e.to_string())
}
pub(crate) fn present(job: &str) -> Result<bool, String> {
    path(job)?.try_exists().map_err(|e| e.to_string())
}
pub(crate) fn read(root: &OwnedFd, name: &str) -> Result<Value, String> {
    let raw = crate::feature_files::required(root, name, (0, 0), 0o600, 16384)?;
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if linux::canonical(&v)? != raw {
        return Err("canonical immutable owner metadata required".into());
    }
    Ok(v)
}
pub(crate) fn descriptor(fd: &impl std::os::fd::AsFd) -> Result<Value, String> {
    let s = fstat(fd).map_err(|e| e.to_string())?;
    Ok(json!({"device":s.st_dev,"inode":s.st_ino}))
}
pub(crate) fn current() -> Result<OwnedFd, String> {
    open(
        "/proc/thread-self/ns/mnt",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())
}
pub(crate) fn now() -> Result<u64, String> {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    if t.tv_sec < 0 || !(0..1_000_000_000).contains(&t.tv_nsec) {
        return Err("owner boottime unavailable".into());
    }
    (t.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(t.tv_nsec as u64))
        .ok_or("owner clock overflow".into())
}
pub(crate) fn hash_executable(file: &mut File, expected: &str) -> Result<(), String> {
    let before = fstat(&*file).map_err(|e| e.to_string())?;
    if !crate::hex(expected, 64)
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o177777 != 0o100500
        || !(1..=128 * 1024 * 1024).contains(&before.st_size)
    {
        return Err("original pinned Root owner executable required".into());
    }
    let mut hash = Sha256::new();
    let mut count = 0usize;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        count += n;
        if count > 128 * 1024 * 1024 {
            return Err("owner executable bound exceeded".into());
        }
        hash.update(&buffer[..n]);
    }
    if count as i64 != before.st_size
        || format!("{:x}", hash.finalize()) != expected
        || !crate::builder_candidate_source::same_file(
            &before,
            &fstat(&*file).map_err(|e| e.to_string())?,
        )
    {
        return Err("owner executable identity changed".into());
    }
    Ok(())
}
pub(crate) struct Anchor {
    pub value: Value,
    pub pidfd: OwnedFd,
    pub namespace: OwnedFd,
    pub original: OwnedFd,
    pub group: OwnedProbeGroup,
}
pub(crate) fn anchor(job: &str) -> Result<Anchor, String> {
    anchored(job, false)
}
pub(crate) fn anchored(job: &str, cleanup: bool) -> Result<Anchor, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    let root = slot(job)?;
    let v = read(&root, "owner.json")?;
    let intent = read(&root, "intent.json")?;
    let fields = [
        "schema",
        "source_sha",
        "job_id",
        "worker_generation",
        "owner_nonce_hex",
        "boot_id",
        "process",
        "executable_sha256",
        "cgroup",
        "namespace",
        "original_namespace",
        "started_boottime_ns",
        "deadline_boottime_ns",
        "state",
    ];
    if v.as_object()
        .is_none_or(|o| o.len() != 14 || fields.iter().any(|k| !o.contains_key(*k)))
        || v["schema"] != "hol-gauntlet-job-storage-namespace-owner.v1"
        || v["job_id"] != job
        || v["state"] != "retained"
        || v["boot_id"] != linux::boot()?
        || [
            "source_sha",
            "job_id",
            "worker_generation",
            "owner_nonce_hex",
            "executable_sha256",
            "original_namespace",
            "started_boottime_ns",
            "deadline_boottime_ns",
        ]
        .iter()
        .any(|k| v[*k] != intent[*k])
    {
        return Err("original Root namespace owner binding changed".into());
    }
    if crate::feature_files::read(&root, "retired.json", (0, 0), 0o600, 8192)?.is_some() {
        return Err("original namespace owner already retired".into());
    }
    let deadline = v["deadline_boottime_ns"]
        .as_u64()
        .ok_or("original owner deadline absent")?;
    if !cleanup && deadline <= now()? {
        return Err("original namespace owner expired; execution refused".into());
    }
    let pid = v["process"]["pid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 1)
        .ok_or("owner PID absent")?;
    let ticks = v["process"]["start_ticks"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("owner start ticks absent")?;
    let expected_group = group_path(job);
    crate::observe_process(pid, ticks, &expected_group)
        .map_err(|_| "original owner task/cgroup lost")?;
    let pidfd = pidfd_open(
        Pid::from_raw(pid as i32).ok_or("owner PID invalid")?,
        PidfdFlags::empty(),
    )
    .map_err(|e| e.to_string())?;
    let proc = open(
        format!("/proc/{pid}"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let namespace = openat(
        &proc,
        "ns/mnt",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let original = openat(
        &proc,
        "fd/3",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    if descriptor(&namespace)? != v["namespace"]
        || descriptor(&original)? != v["original_namespace"]
        || v["namespace"] == v["original_namespace"]
    {
        return Err("original owner namespace handles differ".into());
    }
    let mut executable = File::from(
        openat(
            &proc,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    hash_executable(
        &mut executable,
        v["executable_sha256"]
            .as_str()
            .ok_or("owner executable SHA absent")?,
    )?;
    let device = v["cgroup"]["device"]
        .as_u64()
        .ok_or("owner cgroup device absent")?;
    let inode = v["cgroup"]["inode"]
        .as_u64()
        .ok_or("owner cgroup inode absent")?;
    if v["cgroup"]["path"] != expected_group || v["cgroup"] != intent["cgroup"] {
        return Err("original owner cgroup binding differs".into());
    }
    let group =
        OwnedProbeGroup::reopen_named(group_name(job), expected_group.clone(), (device, inode))
            .map_err(|e| e.to_string())?;
    for (name, expected) in [
        ("memory.max", LIMITS.memory),
        ("pids.max", LIMITS.pids),
        ("cpu.max", LIMITS.cpu),
    ] {
        let root = crate::open_root_owned_public_directory(
            &Path::new("/sys/fs/cgroup").join(expected_group.trim_start_matches('/')),
        )
        .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        File::from(
            openat(
                &root,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        )
        .take(129)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
        if raw != expected.as_bytes() {
            return Err("original owner resource limits changed".into());
        }
    }
    if group.tasks().map_err(|e| e.to_string())? != 1 {
        return Err("owner cgroup contains unexpected tasks".into());
    }
    crate::observe_process(pid, ticks, &expected_group)
        .map_err(|_| "owner task changed while held")?;
    Ok(Anchor {
        value: v,
        pidfd,
        namespace,
        original,
        group,
    })
}
struct Frame {
    job: String,
    original: OwnedFd,
    pidfd: OwnedFd,
    deadline: u64,
    namespace: Value,
    owner: Value,
}
thread_local! {static ENTERED:RefCell<Vec<Frame>>=const{RefCell::new(Vec::new())};}
pub(crate) fn set_namespace(fd: &OwnedFd) -> Result<(), String> {
    if unsafe { libc::unshare(libc::CLONE_FS) } != 0
        || unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNS) } != 0
    {
        return Err("original private storage namespace entry failed".into());
    }
    Ok(())
}
pub(crate) fn enter(job: &str) -> Result<(), String> {
    if !present(job)? {
        return Ok(());
    }
    let selected = ENTERED.with(|s| {
        s.borrow()
            .last()
            .filter(|f| f.job == job)
            .map(|f| f.namespace.clone())
    });
    if let Some(expected) = selected {
        health()?;
        if descriptor(&current()?)? == expected {
            return Ok(());
        }
    }
    let held = anchor(job)?;
    let same = descriptor(&current()?)? == held.value["namespace"];
    let previous = if same {
        held.original.try_clone().map_err(|e| e.to_string())?
    } else {
        current()?
    };
    ENTERED.with(|s| {
        if s.borrow().len() >= 32 {
            Err("storage namespace nesting bound exceeded".to_owned())
        } else {
            Ok(())
        }
    })?;
    if !same {
        set_namespace(&held.namespace)?;
    }
    if descriptor(&current()?)? != held.value["namespace"] {
        return Err("storage namespace entry did not select original owner".into());
    }
    ENTERED.with(|s| {
        s.borrow_mut().push(Frame {
            job: job.into(),
            original: previous,
            pidfd: held.pidfd,
            deadline: held.value["deadline_boottime_ns"].as_u64().unwrap_or(0),
            namespace: held.value["namespace"].clone(),
            owner: held.value,
        })
    });
    Ok(())
}
pub(crate) fn receipt(job: &str) -> Result<Value, String> {
    enter(job)?;
    health()?;
    ENTERED.with(|s| {
        s.borrow()
            .last()
            .filter(|f| f.job == job)
            .map(|f| f.owner.clone())
            .ok_or_else(|| "original selected owner receipt absent".into())
    })
}
pub(crate) fn enter_pinned(source: &str, job: &str, generation: &str) -> Result<(), String> {
    if !present(job)? {
        return Ok(());
    }
    enter(job)?;
    let value = receipt(job)?;
    if value["source_sha"] != source || value["worker_generation"] != generation {
        return Err("outside job source/worker differs from original namespace owner".into());
    }
    Ok(())
}
pub(crate) fn cleanup_access(job: &str) -> Result<(), String> {
    if !present(job)? {
        return Ok(());
    }
    let value = read(&slot(job)?, "owner.json")?;
    if value["job_id"] != job
        || value["boot_id"] != linux::boot()?
        || descriptor(&current()?)? != value["namespace"]
    {
        return Err(
            "cleanup must retain the original job namespace, never adopt a successor".into(),
        );
    }
    Ok(())
}
pub(crate) struct Scope {
    original: OwnedFd,
    depth: usize,
}
pub(crate) fn scope() -> Result<Scope, String> {
    Ok(Scope {
        original: current()?,
        depth: ENTERED.with(|s| s.borrow().len()),
    })
}
impl Drop for Scope {
    fn drop(&mut self) {
        let unchanged = match (
            current().and_then(|fd| descriptor(&fd)),
            descriptor(&self.original),
        ) {
            (Ok(current), Ok(original)) => current == original,
            _ => false,
        };
        if !unchanged && set_namespace(&self.original).is_err() {
            eprintln!("storage namespace restore failed; retain unknown");
            std::process::exit(2);
        }
        ENTERED.with(|s| s.borrow_mut().truncate(self.depth));
    }
}
pub(crate) fn restore_original(job: &str, held: &Anchor) -> Result<(), String> {
    if held.value["job_id"] != job {
        return Err("owner restore belongs to another job".into());
    }
    restore_caller(job, Some(&held.original))
}
pub(crate) fn restore_caller(job: &str, fallback: Option<&OwnedFd>) -> Result<(), String> {
    let original = ENTERED.with(|s| {
        let frames = s.borrow();
        if frames.last().is_some_and(|f| f.job != job) {
            return Err("another owner is active during retirement".to_owned());
        }
        frames
            .first()
            .map(|f| f.original.try_clone().map_err(|e| e.to_string()))
            .transpose()
    })?;
    if let Some(original) = original {
        set_namespace(&original)?;
    } else if let Some(original) = fallback {
        set_namespace(original)?;
    }
    ENTERED.with(|s| s.borrow_mut().clear());
    Ok(())
}
pub(crate) fn credentials(
    stream: &std::os::unix::net::UnixStream,
) -> Result<(u32, u32, u32), String> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err("owner socket credentials unavailable".into());
    }
    let cred = unsafe { cred.assume_init() };
    if cred.pid <= 1 {
        return Err("owner socket peer PID invalid".into());
    }
    Ok((cred.pid as u32, cred.uid, cred.gid))
}
pub(crate) fn create(p: &JobStoragePins<'_>, profile: JobStorageProfile) -> Result<Value, String> {
    service::create(p, profile)
}
pub(crate) fn health() -> Result<(), String> {
    ENTERED.with(|s| {
        let frames = s.borrow();
        let Some(f) = frames.last() else {
            return Ok(());
        };
        let mut p = libc::pollfd {
            fd: f.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut p, 1, 0) } != 0 || f.deadline <= now()? {
            return Err(
                "original namespace owner lost/expired; halt runtime and retain unknown".into(),
            );
        }
        Ok(())
    })
}
