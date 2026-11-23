//! Fixed pinned owner bootstrap and bounded private-namespace service.
use super::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    ffi::CString,
    io::{BufRead, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn high(file: &File) -> Result<File, String> {
    let n = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) };
    if n < 0 {
        Err("owner descriptor retention failed".into())
    } else {
        Ok(unsafe { File::from_raw_fd(n) })
    }
}
fn executable(p: &JobStoragePins<'_>) -> Result<(File, String), String> {
    #[cfg(test)]
    let (path, sha) = {
        let sha = std::env::var("GAUNTLET_STORAGE_TEST_VM_WORKER_SHA")
            .map_err(|_| "outside frozen VM worker SHA required for namespace fixture")?;
        if !crate::hex(&sha, 64) {
            return Err("exact fixture VM worker SHA required".into());
        }
        (
            format!("/opt/hol-gauntlet/rust-native-host-pinned-worker-{sha}"),
            sha,
        )
    };
    #[cfg(not(test))]
    let (path, sha) = ("/proc/self/exe".to_owned(), p.worker_generation.to_owned());
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    hash_executable(&mut file, &sha)?;
    let _ = p;
    Ok((high(&file)?, sha))
}
pub(crate) fn create(p: &JobStoragePins<'_>, profile: JobStorageProfile) -> Result<Value, String> {
    linux::pins_valid(p)?;
    crate::verify_running_binary(p.worker_generation).map_err(|e| e.to_string())?;
    let original = File::from(current()?);
    let (program, exe) = executable(p)?;
    let base = crate::open_root_owned_public_directory(Path::new("/var/lib/hol-gauntlet-rust"))
        .map_err(|e| e.to_string())?;
    let owners = crate::feature_files::directory(&base, "storage-owners", (0, 0), false)?;
    let root = crate::feature_files::directory(&owners, p.job_id, (0, 0), true)?;
    let mut random = [0u8; 16];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "fresh owner instance identity unavailable")?;
    let nonce = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let started = now()?;
    let deadline = started
        .checked_add(86400 * 1_000_000_000)
        .ok_or("owner deadline overflow")?;
    let mut group =
        OwnedProbeGroup::create_named(group_name(p.job_id), group_path(p.job_id), LIMITS)
            .map_err(|e| e.to_string())?;
    let (device, inode) = group.identity().map_err(|e| e.to_string())?;
    let intent = json!({"schema":"hol-gauntlet-job-storage-owner-intent.v1","source_sha":p.source_sha,"job_id":p.job_id,"worker_generation":p.worker_generation,"mke2fs_sha256":p.mke2fs_sha256,"profile":profile.as_str(),
        "owner_nonce_hex":nonce,"executable_sha256":exe,"original_namespace":descriptor(&original)?,"cgroup":{"path":group_path(p.job_id),"device":device,"inode":inode},"boot_id":linux::boot()?,"started_boottime_ns":started,"deadline_boottime_ns":deadline});
    crate::feature_files::write(
        &root,
        "intent.json",
        &linux::canonical(&intent)?,
        (0, 0),
        0o600,
    )?;
    let original = high(&original)?;
    let arguments = [
        "gauntlet-vm-worker",
        "--own-job-storage-namespace-v1",
        p.source_sha,
        p.job_id,
        p.worker_generation,
        &exe,
        &nonce,
        profile.as_str(),
    ]
    .iter()
    .map(|s| CString::new(*s).map_err(|_| "fixed owner argv invalid"))
    .collect::<Result<Vec<_>, _>>()?;
    let pointers = arguments
        .iter()
        .map(|s| s.as_ptr() as usize)
        .chain([0])
        .collect::<Vec<_>>();
    let environment = [
        c"PATH=/usr/sbin:/usr/bin:/sbin:/bin".as_ptr() as usize,
        c"LANG=C".as_ptr() as usize,
        0,
    ];
    let mut command = Command::new("/usr/bin/false");
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    group
        .attach_child(&mut command)
        .map_err(|e| e.to_string())?;
    unsafe {
        command.pre_exec(move || {
            let _keep = (&program, &original, &arguments);
            libc::umask(0o077);
            if libc::setsid() < 0
                || libc::dup2(original.as_raw_fd(), 3) != 3
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            libc::syscall(
                libc::SYS_execveat,
                program.as_raw_fd(),
                c"".as_ptr(),
                pointers.as_ptr().cast::<*const libc::c_char>(),
                environment.as_ptr().cast::<*const libc::c_char>(),
                libc::AT_EMPTY_PATH,
            );
            Err(std::io::Error::last_os_error())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            group.drain_and_remove().map_err(|e| e.to_string())?;
            return Err(e.to_string());
        }
    };
    let raw_pid = child.id();
    let ready = (|| -> Result<Value, String> {
        let mut output = child.stdout.take().ok_or("owner readiness stream absent")?;
        let fd = output.as_raw_fd();
        let mut raw = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut poll, 1, 100) };
            if n < 0 {
                return Err("owner readiness poll failed".into());
            }
            if n > 0 {
                let mut b = [0u8; 1024];
                let count = output.read(&mut b).map_err(|e| e.to_string())?;
                if count == 0 {
                    return Err("owner readiness ended before immutable receipt".into());
                }
                raw.extend_from_slice(&b[..count]);
                if raw.len() > 16384 {
                    return Err("owner readiness bound exceeded".into());
                }
                if raw.last() == Some(&b'\n') {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("owner readiness deadline exceeded".into());
            }
        }
        raw.pop();
        let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let held = anchor(p.job_id)?;
        if held.value != v || v["process"]["pid"] != raw_pid {
            return Err("owner readiness differs from actual pinned task".into());
        }
        Ok(v)
    })();
    if ready.is_err() {
        group.kill().map_err(|e| e.to_string())?;
        crate::process_reap::reap_probe_child_bounded(&mut child).map_err(|e| e.to_string())?;
        group.drain_and_remove().map_err(|e| e.to_string())?;
        return ready;
    }
    let v = ready?;
    enter(p.job_id)?;
    Ok(v)
}
fn receive(stream: &mut UnixStream) -> Result<Value, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    std::io::BufReader::new(stream)
        .take(8193)
        .read_until(b'\n', &mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 8192 || raw.pop() != Some(b'\n') {
        return Err("bounded complete owner control frame required".into());
    }
    let v = serde_json::from_slice::<Value>(&raw).map_err(|e| e.to_string())?;
    if linux::canonical(&v)? != raw {
        return Err("canonical owner control frame required".into());
    }
    Ok(v)
}
pub fn run_storage_namespace_owner(args: &[String]) -> Result<(), String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if args.len() != 8
        || args[1] != "--own-job-storage-namespace-v1"
        || !crate::hex(&args[2], 40)
        || !crate::hex(&args[3], 16)
        || ![&args[4], &args[5]].iter().all(|s| crate::hex(s, 64))
        || !crate::hex(&args[6], 32)
    {
        return Err("fixed original storage owner argv required".into());
    }
    crate::verify_running_binary(&args[5]).map_err(|e| e.to_string())?;
    let profile: JobStorageProfile = args[7].parse()?;
    let root = slot(&args[3])?;
    let intent = read(&root, "intent.json")?;
    if intent["source_sha"] != args[2]
        || intent["job_id"] != args[3]
        || intent["worker_generation"] != args[4]
        || intent["executable_sha256"] != args[5]
        || intent["owner_nonce_hex"] != args[6]
        || intent["profile"] != profile.as_str()
        || intent["boot_id"] != linux::boot()?
    {
        return Err("owner tuple differs from original consumed intent".into());
    }
    let original = open(
        "/proc/self/fd/3",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    if descriptor(&original)? != intent["original_namespace"]
        || descriptor(&current()?)? != intent["original_namespace"]
    {
        return Err("owner original namespace descriptor differs".into());
    }
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err("fresh owner mount namespace creation failed".into());
    }
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err("new owner namespace propagation could not be isolated".into());
    }
    let pid = std::process::id();
    let stat = std::fs::read(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?;
    let ticks = crate::linux_process::parse_proc_stat(&stat, pid)
        .ok_or("owner actual start ticks absent")?
        .start_ticks;
    crate::observe_process(pid, ticks, &group_path(&args[3]))
        .map_err(|_| "owner is outside original retained cgroup")?;
    let value = json!({"schema":"hol-gauntlet-job-storage-namespace-owner.v1","source_sha":args[2],"job_id":args[3],"worker_generation":args[4],"owner_nonce_hex":args[6],"boot_id":intent["boot_id"],
        "process":{"pid":pid,"start_ticks":ticks},"executable_sha256":args[5],"cgroup":intent["cgroup"],"namespace":descriptor(&current()?)?,"original_namespace":intent["original_namespace"],"started_boottime_ns":intent["started_boottime_ns"],"deadline_boottime_ns":intent["deadline_boottime_ns"],"state":"retained"});
    let socket = path(&args[3])?.join("control.sock");
    let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    crate::feature_files::write(
        &root,
        "owner.json",
        &linux::canonical(&value)?,
        (0, 0),
        0o600,
    )?;
    std::io::stdout()
        .write_all(&linux::canonical(&value)?)
        .and_then(|_| std::io::stdout().write_all(b"\n"))
        .and_then(|_| std::io::stdout().flush())
        .map_err(|_| "owner readiness delivery uncertain")?;
    // The service never inherits or keeps its launching SSH output pipe.
    unsafe {
        libc::close(1);
    }
    let deadline = intent["deadline_boottime_ns"]
        .as_u64()
        .ok_or("owner deadline absent")?;
    while now()? < deadline && !crate::native_worker::cancellation_requested() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let peer = credentials(&stream)?;
                if peer.1 != 0 {
                    continue;
                }
                let request = match receive(&mut stream) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let retired = match retirement::shutdown_authority(&args[3]) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let expected = json!({"schema":"hol-gauntlet-storage-owner-control.v1","action":"shutdown","source_sha":args[2],"job_id":args[3],"worker_generation":args[4],"owner_nonce_hex":args[6],"retirement_sha256":linux::sha(&linux::canonical(&retired)?)});
                if request != expected {
                    continue;
                }
                let response = linux::canonical(
                    &json!({"schema":"hol-gauntlet-storage-owner-stopped.v1","job_id":args[3],"owner_nonce_hex":args[6],"retirement_sha256":request["retirement_sha256"]}),
                )?;
                stream
                    .write_all(&response)
                    .and_then(|_| stream.write_all(b"\n"))
                    .map_err(|_| "owner shutdown acknowledgement uncertain")?;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    crate::feature_files::write(
        &root,
        "lost.json",
        &linux::canonical(
            &json!({"schema":"hol-gauntlet-storage-owner-lost.v1","owner_receipt_sha256":linux::sha(&linux::canonical(&value)?),"backing_retained":true,"job_consumed":true}),
        )?,
        (0, 0),
        0o600,
    )?;
    Err("storage namespace owner expired/interrupted; retain unknown backing and job".into())
}
