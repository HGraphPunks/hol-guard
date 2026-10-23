//! PID1 bootstrap with the fixed syscall floor and authenticated private RPC.
use crate::actor::Actor;
use crate::root_input::read_root_input;
use crate::{install_product_filter, load_root_layout, CellError, NetworkProfile, Result};
use gauntlet_agent_bridge::{
    read_private_bootstrap, serve_one, Bootstrap, BootstrapKind, BridgeChannel, BridgeOperation,
    OperationResult,
};
use rustix::fs::{fstat, mkdir, open, openat, FileType, Mode, OFlags};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_signal: i32) {
    STOP.store(true, Ordering::Release);
}
extern "C" fn child_exited(_signal: i32) {}
fn signals() -> Result<()> {
    for (signal, handler) in [
        (libc::SIGTERM, stop as *const () as usize),
        (libc::SIGINT, stop as *const () as usize),
        (libc::SIGCHLD, child_exited as *const () as usize),
    ] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_flags = libc::SA_RESTART;
        action.sa_sigaction = handler;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
            || unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0
        {
            return Err(CellError("product actor signal setup failed"));
        }
    }
    Ok(())
}
fn network() -> Result<NetworkProfile> {
    let Some(input) = read_root_input(Path::new("/etc/hol-cell-network-profile"), 128)? else {
        return Ok(NetworkProfile::UnixOnly);
    };
    match std::str::from_utf8(&input.bytes)
        .map_err(|_| CellError("invalid network declaration"))?
        .trim()
    {
        "unix-only-v1" => Ok(NetworkProfile::UnixOnly),
        "private-loopback-v1" => Ok(NetworkProfile::PrivateLoopback),
        _ => Err(CellError("invalid network declaration")),
    }
}
fn state_directory(path: &str) -> Result<OwnedFd> {
    match mkdir(path, Mode::from_bits_truncate(0o700)) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(CellError("product private state directory unavailable")),
    }
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CellError("unsafe product state directory"))?;
    let stat = fstat(&fd).map_err(|_| CellError("unsafe product state directory"))?;
    if stat.st_uid != 10004 || stat.st_gid != 10004 || stat.st_mode & 0o777 != 0o700 {
        return Err(CellError("unsafe product state directory"));
    }
    Ok(fd)
}
fn initialize_state() -> Result<()> {
    state_directory("/product/home")?;
    let guard = state_directory("/product/guard")?;
    let contents=b"mode=\"enforce\"\nsync=false\ntelemetry=false\ndesktop_notifications=false\napproval_wait_timeout_seconds=1\n";
    let new = openat(
        &guard,
        "config.toml",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    );
    match new {
        Ok(fd) => {
            let mut file = File::from(fd);
            file.write_all(contents)
                .and_then(|_| file.sync_all())
                .map_err(|_| CellError("product initial configuration write failed"))?;
        }
        Err(rustix::io::Errno::EXIST) => {
            let fd = openat(
                &guard,
                "config.toml",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| CellError("unsafe product initial configuration"))?;
            let stat = fstat(&fd).map_err(|_| CellError("unsafe product initial configuration"))?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != 10004
                || stat.st_mode & 0o777 != 0o600
                || stat.st_nlink != 1
            {
                return Err(CellError("unsafe product initial configuration"));
            }
            let mut raw = Vec::new();
            File::from(fd)
                .take(contents.len() as u64 + 1)
                .read_to_end(&mut raw)
                .map_err(|_| CellError("product initial configuration unavailable"))?;
            if raw != contents {
                return Err(CellError("product initial configuration differs"));
            }
        }
        Err(_) => return Err(CellError("product initial configuration unavailable")),
    }
    Ok(())
}
fn boot_id() -> Result<String> {
    let mut raw = Vec::new();
    File::open("/proc/sys/kernel/random/boot_id")
        .map_err(|_| CellError("kernel boot identity unavailable"))?
        .take(128)
        .read_to_end(&mut raw)
        .map_err(|_| CellError("kernel boot identity unavailable"))?;
    String::from_utf8(raw)
        .map(|s| s.trim().to_owned())
        .map_err(|_| CellError("kernel boot identity invalid"))
}
pub fn run_actor() -> Result<()> {
    if unsafe { libc::getpid() } != 1
        || unsafe { libc::getuid() } != 10004
        || unsafe { libc::getgid() } != 10004
    {
        return Err(CellError("unprivileged PID1 product actor required"));
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(CellError("product actor dumpability lock failed"));
    }
    let layout = load_root_layout()?;
    let profile = read_root_input(
        Path::new("/public/product_vm_seccomp_oci_v1.json"),
        128 * 1024,
    )?
    .ok_or(CellError("pinned syscall profile missing"))?;
    install_product_filter(&profile.bytes, network()?)?;
    drop(profile);
    initialize_state()?;
    signals()?;
    std::io::stdout()
        .write_all(b"HOL_CELL_FILTER_READY_V1\n")
        .and_then(|_| std::io::stdout().flush())
        .map_err(|_| CellError("product ready pipe unavailable"))?;
    // Ownership of the dedicated standard pipes transfers into the bridge.
    // Product children receive fresh pipes, never either management pipe.
    let reader = unsafe { OwnedFd::from_raw_fd(0) };
    let writer = unsafe { OwnedFd::from_raw_fd(1) };
    let raw = read_private_bootstrap(&reader, Instant::now() + Duration::from_secs(5), &STOP)
        .map_err(|_| CellError("private actor bootstrap unavailable"))?;
    let codec = Bootstrap::parse(&raw, BootstrapKind::ProductCellActor, &boot_id()?, None)
        .and_then(|bootstrap| bootstrap.into_codec(10000, 256 * 1024 * 1024))
        .map_err(|_| CellError("private actor bootstrap mismatch"))?;
    let mut channel = BridgeChannel::new(reader, writer, codec)
        .map_err(|_| CellError("private actor channel unavailable"))?;
    let actor = Rc::new(RefCell::new(Actor::new(layout)));
    let names = [
        "hello",
        "spawn",
        "release",
        "write",
        "end_input",
        "read",
        "retire",
        "close",
    ];
    let mut handlers: Vec<_> = names
        .iter()
        .map(|&name| {
            let actor = Rc::clone(&actor);
            move |payload: &Value| -> OperationResult {
                actor
                    .borrow_mut()
                    .call(name, payload)
                    .map_err(|_| "ValueError")
            }
        })
        .collect();
    let mut registry: Vec<_> = names
        .iter()
        .zip(handlers.iter_mut())
        .map(|(&name, handler)| BridgeOperation { name, handler })
        .collect();
    let result = (|| {
        for _ in 0..10000 {
            if STOP.load(Ordering::Acquire) {
                break;
            }
            let operation = serve_one(
                &mut channel,
                &mut registry,
                Instant::now() + Duration::from_secs(4000),
                &STOP,
            );
            if STOP.load(Ordering::Acquire) {
                break;
            }
            let operation = operation
                .map_err(|_| CellError("private actor operation stream ended or failed"))?;
            actor.borrow_mut().reap()?;
            if operation == "close" {
                break;
            }
        }
        Ok(())
    })();
    let cleanup = actor.borrow_mut().call("close", &json!({}));
    result?;
    cleanup?;
    Ok(())
}
