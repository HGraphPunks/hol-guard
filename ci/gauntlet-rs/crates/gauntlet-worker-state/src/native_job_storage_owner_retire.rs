//! Only original owner/resource shutdown. Admitted data is never discarded by
//! owner expiry/loss; the volume's authenticated retirement remains separate.
use super::*;
use std::{
    io::{BufRead, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
fn volume_slot(job: &str) -> PathBuf {
    Path::new(super::super::lifecycle::BASE).join(job)
}
fn has_mount(target: &Path) -> Result<bool, String> {
    let mut raw = String::new();
    File::open("/proc/thread-self/mountinfo")
        .map_err(|e| e.to_string())?
        .take(2 * 1024 * 1024 + 1)
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 2 * 1024 * 1024 {
        return Err("owner mount inventory bound exceeded".into());
    }
    Ok(raw
        .lines()
        .any(|r| r.split_ascii_whitespace().nth(4) == target.to_str()))
}
pub(crate) fn shutdown_authority(job: &str) -> Result<Value, String> {
    let root = slot(job)?;
    let intent = read(&root, "intent.json")?;
    let profile: JobStorageProfile = intent["profile"]
        .as_str()
        .ok_or("owner profile absent")?
        .parse()?;
    if has_mount(&profile.root(job)?)? {
        return Err("owner still retains job mount; shutdown refused".into());
    }
    if volume_slot(job).try_exists().map_err(|e| e.to_string())? {
        let volume = crate::open_root_owned_public_directory(&volume_slot(job))
            .map_err(|e| e.to_string())?;
        let retired = read(&volume, "retired.json")?;
        if retired["schema"] != "hol-gauntlet-job-storage-retired.v1"
            || retired["job_id"] != job
            || retired["source_sha"] != intent["source_sha"]
            || ["volume_unmounted", "loop_detached", "backing_absent"]
                .iter()
                .any(|k| retired[*k] != true)
            || !matches!(
                rustix::fs::statat(
                    &volume,
                    "backing.ext4",
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW
                ),
                Err(rustix::io::Errno::NOENT)
            )
        {
            return Err("original volume has not completed authenticated retirement".into());
        }
        Ok(retired)
    } else {
        let aborted = read(&root, "abort.json")?;
        let expected = json!({"schema":"hol-gauntlet-storage-owner-empty-abort.v1","job_id":job,"owner_intent_sha256":linux::sha(&linux::canonical(&intent)?),"volume_absent":true});
        if aborted != expected {
            return Err("original empty owner abort binding differs".into());
        }
        Ok(aborted)
    }
}
fn dead(value: &Value) -> Result<bool, String> {
    let Some(pid) = value["process"]["pid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
    else {
        return Err("original owner PID absent".into());
    };
    let raw = match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e.to_string()),
    };
    let state = crate::linux_process::parse_proc_stat(&raw, pid)
        .ok_or("owner process identity unavailable")?;
    Ok(
        value["process"]["start_ticks"].as_u64() != Some(state.start_ticks)
            || state.state == 'Z'
            || state.state == 'X',
    )
}
fn reap_dead_owner(value: &Value, held: Option<&OwnedFd>) -> Result<(), String> {
    use rustix::process::{waitid, WaitId, WaitIdOptions};
    use std::os::fd::AsFd;
    let pid = value["process"]["pid"]
        .as_u64()
        .and_then(|n| i32::try_from(n).ok())
        .filter(|n| *n > 1)
        .ok_or("original owner reap PID absent")?;
    let ticks = value["process"]["start_ticks"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("original owner reap start ticks absent")?;
    let fd = if let Some(held) = held {
        held.try_clone().map_err(|e| e.to_string())?
    } else {
        let fd = match pidfd_open(
            Pid::from_raw(pid).ok_or("owner PID invalid")?,
            PidfdFlags::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::SRCH) => return Ok(()),
            Err(e) => return Err(e.to_string()),
        };
        let raw = match std::fs::read(format!("/proc/{pid}/stat")) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.to_string()),
        };
        let observed = crate::linux_process::parse_proc_stat(&raw, pid as u32)
            .ok_or("original owner reap identity unavailable")?;
        if observed.start_ticks != ticks {
            return Ok(()); // A replacement PID is never waited on or signalled.
        }
        fd
    };
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll, 1, 0) } != 1
        || poll.revents & libc::POLLIN == 0
        || poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("original owner is not measured dead before reap".into());
    }
    match waitid(
        WaitId::PidFd(fd.as_fd()),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG,
    ) {
        Ok(Some(s)) if s.exited() || s.killed() || s.dumped() => Ok(()),
        Err(rustix::io::Errno::CHILD) => Ok(()), // A restarted operator is not the original parent.
        _ => Err("original owner pidfd reap remains uncertain".into()),
    }
}
fn retired_body(intent: &Value, owner: Option<&Value>, authority: &Value) -> Result<Value, String> {
    Ok(
        json!({"schema":"hol-gauntlet-storage-owner-retired.v1","source_sha":intent["source_sha"],"job_id":intent["job_id"],"worker_generation":intent["worker_generation"],
        "owner_intent_sha256":linux::sha(&linux::canonical(intent)?),"owner_receipt_sha256":owner.map(|v|linux::canonical(v).map(|b|linux::sha(&b))).transpose()?,
        "authority_sha256":linux::sha(&linux::canonical(authority)?),"owner_process_absent":true,"owner_cgroup_absent":true,"job_consumed":true,"execution_eligible":false}),
    )
}
pub(crate) fn verify_finished(job: &str) -> Result<(), String> {
    let root = slot(job)?;
    let intent = read(&root, "intent.json")?;
    let raw = crate::feature_files::read(&root, "owner.json", (0, 0), 0o600, 16384)?;
    let owner = raw
        .as_deref()
        .map(serde_json::from_slice::<Value>)
        .transpose()
        .map_err(|e| e.to_string())?;
    let authority = shutdown_authority(job)?;
    if read(&root, "retired.json")? != retired_body(&intent, owner.as_ref(), &authority)?
        || owner.as_ref().map(dead).transpose()?.is_some_and(|v| !v)
    {
        return Err("original storage owner has not completed teardown".into());
    }
    match std::fs::symlink_metadata(format!("/sys/fs/cgroup{}", group_path(job))) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("original storage owner cgroup remains or is uncertain".into()),
    }
}
pub(crate) fn finish(job: &str) -> Result<(), String> {
    let root = slot(job)?;
    let intent = read(&root, "intent.json")?;
    if intent["boot_id"] != linux::boot()? {
        return Err("owner teardown cannot cross original boot identity".into());
    }
    if crate::feature_files::read(&root, "retired.json", (0, 0), 0o600, 8192)?.is_some() {
        return verify_finished(job);
    }
    let raw = crate::feature_files::read(&root, "owner.json", (0, 0), 0o600, 16384)?;
    let owner = raw
        .as_deref()
        .map(serde_json::from_slice::<Value>)
        .transpose()
        .map_err(|e| e.to_string())?;
    let authority = shutdown_authority(job)?;
    let alive = owner.as_ref().map(dead).transpose()?.is_some_and(|v| !v);
    let held = if alive {
        Some(anchored(job, true)?)
    } else {
        None
    };
    if let Some(held) = &held {
        restore_original(job, held)?;
    } else {
        restore_caller(job, None)?;
        if descriptor(&current()?)? != intent["original_namespace"] {
            return Err("lost-owner cleanup cannot guess an outside namespace".into());
        }
    }
    if let Some(held) = &held {
        let request = json!({"schema":"hol-gauntlet-storage-owner-control.v1","action":"shutdown","source_sha":intent["source_sha"],"job_id":job,"worker_generation":intent["worker_generation"],"owner_nonce_hex":intent["owner_nonce_hex"],"retirement_sha256":linux::sha(&linux::canonical(&authority)?)});
        let sent = (|| -> Result<(), String> {
            let mut stream =
                UnixStream::connect(path(job)?.join("control.sock")).map_err(|e| e.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .map_err(|e| e.to_string())?;
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .map_err(|e| e.to_string())?;
            let peer = credentials(&stream)?;
            if peer.0 as u64
                != held.value["process"]["pid"]
                    .as_u64()
                    .ok_or("owner peer PID absent")?
                || peer.1 != 0
            {
                return Err("original owner control peer identity differs".into());
            }
            stream
                .write_all(&linux::canonical(&request)?)
                .and_then(|_| stream.write_all(b"\n"))
                .map_err(|e| e.to_string())?;
            let mut raw = Vec::new();
            std::io::BufReader::new(&mut stream)
                .take(8193)
                .read_until(b'\n', &mut raw)
                .map_err(|e| e.to_string())?;
            if raw.len() > 8192 || raw.pop() != Some(b'\n') {
                return Err("complete bounded owner shutdown reply required".into());
            }
            let response: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            if response
                != json!({"schema":"hol-gauntlet-storage-owner-stopped.v1","job_id":job,"owner_nonce_hex":intent["owner_nonce_hex"],"retirement_sha256":request["retirement_sha256"]})
            {
                return Err("original owner shutdown reply differs".into());
            }
            Ok(())
        })();
        if sent.is_err() {
            held.group.kill().map_err(|e| e.to_string())?;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut p = libc::pollfd {
                fd: held.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut p, 1, 0) } == 1 && p.revents & libc::POLLIN != 0 {
                break;
            }
            if Instant::now() >= deadline {
                held.group.kill().map_err(|e| e.to_string())?;
                return Err("owner death remains pending; retain cleanup state".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    if let Some(owner) = &owner {
        reap_dead_owner(owner, held.as_ref().map(|h| &h.pidfd))?;
    }
    let c = &intent["cgroup"];
    let group = OwnedProbeGroup::reopen_named(
        group_name(job),
        group_path(job),
        (
            c["device"]
                .as_u64()
                .ok_or("original owner group device absent")?,
            c["inode"]
                .as_u64()
                .ok_or("original owner group inode absent")?,
        ),
    );
    match group {
        Ok(mut group) => {
            if owner.is_none() {
                group.kill().map_err(|e| e.to_string())?;
            }
            group.drain_and_remove().map_err(|e| e.to_string())?;
        }
        Err(_) => {
            if std::fs::symlink_metadata(format!("/sys/fs/cgroup{}", group_path(job))).is_ok() {
                return Err("original owner cgroup cannot be adopted".into());
            }
        }
    }
    let owner = crate::feature_files::read(&root, "owner.json", (0, 0), 0o600, 16384)?
        .as_deref()
        .map(serde_json::from_slice::<Value>)
        .transpose()
        .map_err(|e| e.to_string())?;
    if let Some(owner) = &owner {
        if !dead(owner)? {
            return Err("original storage owner still runs".into());
        }
    }
    match rustix::fs::statat(&root, "control.sock", rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {}
        Err(e) => return Err(e.to_string()),
        Ok(s) => {
            if s.st_uid != 0
                || s.st_gid != 0
                || s.st_mode & 0o170000 != 0o140000
                || s.st_mode & 0o777 != 0o600
            {
                return Err("original owner socket custody changed".into());
            }
            rustix::fs::unlinkat(&root, "control.sock", rustix::fs::AtFlags::empty())
                .map_err(|e| e.to_string())?;
        }
    }
    crate::feature_files::write(
        &root,
        "retired.json",
        &linux::canonical(&retired_body(&intent, owner.as_ref(), &authority)?)?,
        (0, 0),
        0o600,
    )?;
    verify_finished(job)
}
pub(crate) fn abort_only(
    p: &JobStoragePins<'_>,
    profile: JobStorageProfile,
    generation: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    linux::pins_valid(p)?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let journal = crate::RunReservationJournal::open_root_owned(Path::new(
        crate::builder_image_context::RUST_STATE,
    ))
    .map_err(|e| e.to_string())?;
    let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let root = slot(p.job_id)?;
    let intent = read(&root, "intent.json")?;
    if intent["source_sha"] != p.source_sha
        || intent["job_id"] != p.job_id
        || intent["worker_generation"] != p.worker_generation
        || intent["mke2fs_sha256"] != p.mke2fs_sha256
        || intent["profile"] != profile.as_str()
    {
        return Err("empty owner abort differs from original allocation intent".into());
    }
    if publish {
        crate::native_initialize::require_unstarted_job(&journal, p.job_id)?;
        if let Some(raw) = crate::feature_files::read(&root, "owner.json", (0, 0), 0o600, 16384)? {
            let owner: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            if !dead(&owner)? {
                enter(p.job_id)?;
            }
        }
        if profile
            .root(p.job_id)?
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            return Err("empty owner abort has an unexpected task destination".into());
        }
        if volume_slot(p.job_id)
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            let parent =
                crate::open_root_owned_public_directory(Path::new(super::super::lifecycle::BASE))
                    .map_err(|e| e.to_string())?;
            let volume = crate::feature_files::open_directory(&parent, p.job_id, (0, 0))?;
            super::super::admission::closed_inventory(&volume, &[])?;
            let held = fstat(&volume).map_err(|e| e.to_string())?;
            let visible =
                rustix::fs::statat(&parent, p.job_id, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|e| e.to_string())?;
            if !crate::builder_candidate_source::same_file(&held, &visible) {
                return Err("empty allocation slot replaced".into());
            }
            rustix::fs::unlinkat(&parent, p.job_id, rustix::fs::AtFlags::REMOVEDIR)
                .and_then(|_| rustix::fs::fsync(&parent))
                .map_err(|e| e.to_string())?;
        }
        if crate::feature_files::read(&root, "abort.json", (0, 0), 0o600, 8192)?.is_none() {
            crate::feature_files::write(
                &root,
                "abort.json",
                &linux::canonical(
                    &json!({"schema":"hol-gauntlet-storage-owner-empty-abort.v1","job_id":p.job_id,"owner_intent_sha256":linux::sha(&linux::canonical(&intent)?),"volume_absent":true}),
                )?,
                (0, 0),
                0o600,
            )?;
        }
        finish(p.job_id)?;
    }
    if volume_slot(p.job_id)
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Err("empty owner cleanup remains incomplete".into());
    }
    verify_finished(p.job_id)?;
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    linux::canonical(&read(&root, "retired.json")?)
}

pub(crate) fn require_admissible() -> Result<(), String> {
    if !Path::new(BASE).try_exists().map_err(|e| e.to_string())? {
        return Ok(());
    }
    let root =
        crate::open_root_owned_public_directory(Path::new(BASE)).map_err(|e| e.to_string())?;
    for (count, row) in rustix::fs::Dir::read_from(&root)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if count > 4098 {
            return Err("namespace owner inventory bound exceeded".into());
        }
        let row = row.map_err(|e| e.to_string())?;
        let job = row
            .file_name()
            .to_str()
            .map_err(|_| "owner job filename UTF8")?;
        if matches!(job, "." | "..") {
            continue;
        }
        if !crate::hex(job, 16) {
            return Err("unexpected owner namespace entry".into());
        }
        let slot = slot(job)?;
        if crate::feature_files::read(&slot, "retired.json", (0, 0), 0o600, 8192)?.is_some() {
            verify_finished(job)?;
            continue;
        }
        anchor(job)?;
        let volume = Path::new(super::super::lifecycle::BASE).join(job);
        let volume = crate::open_root_owned_public_directory(&volume)
            .map_err(|_| "unfinished namespace owner has no completed volume")?;
        if crate::feature_files::read(&volume, "admitted.json", (0, 0), 0o600, 1024)?.is_none() {
            return Err("unfinished owner allocation blocks new jobs".into());
        }
    }
    Ok(())
}
