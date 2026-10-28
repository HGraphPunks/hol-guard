//! Dedicated management pipes and fixed Root helper processes, all bounded.
use crate::Result;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) fn kernel_file(path: &std::path::Path, maximum: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > maximum {
        return Err("fixed kernel file byte bound".into());
    }
    Ok(raw)
}

pub(crate) fn nonblocking(fd: &OwnedFd) -> Result<()> {
    let flags = fcntl_getfl(fd).map_err(|e| e.to_string())?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|e| e.to_string())
}

fn ready(fd: &OwnedFd, events: PollFlags, deadline: Instant, cancelled: &AtomicBool) -> Result<()> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err("product management cancelled".into());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("product management deadline".into());
        }
        let wait = left.min(Duration::from_millis(25));
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: wait.as_nanos() as i64,
        };
        let mut descriptors = [PollFd::new(fd, events)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => {}
            Ok(_) => return Ok(()),
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub(crate) fn marker(
    fd: &OwnedFd,
    expected: &[u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut raw = vec![0; expected.len()];
    let mut offset = 0;
    while offset < raw.len() {
        ready(fd, PollFlags::IN, deadline, cancelled)?;
        match rustix::io::read(fd, &mut raw[offset..]) {
            Ok(0) => return Err("product management pipe exited before ready marker".into()),
            Ok(n) => offset += n,
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    if raw != expected {
        return Err("fixed product startup marker differs".into());
    }
    Ok(())
}

pub(crate) fn release_initializer(
    fd: &OwnedFd,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    loop {
        ready(fd, PollFlags::OUT, deadline, cancelled)?;
        match rustix::io::write(fd, &[1]) {
            Ok(1) => return Ok(()),
            Ok(_) => return Err("initializer gate write incomplete".into()),
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub(crate) fn helper(program: &'static str, args: &[String], limit: Duration) -> Result<()> {
    // Call sites supply only the fixed AppArmor parser or systemctl plus the
    // fresh owned profile/unit. Candidate input cannot choose a Root helper.
    if !matches!(program, "/usr/sbin/apparmor_parser" | "/usr/bin/systemctl") {
        return Err("fixed Root cell helper required".into());
    }
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| e.to_string())?;
    let errors: OwnedFd = child
        .stderr
        .take()
        .ok_or("helper error pipe missing")?
        .into();
    nonblocking(&errors)?;
    let deadline = Instant::now() + limit;
    let mut diagnostic = Vec::new();
    let result = loop {
        let mut chunk = [0u8; 4096];
        match rustix::io::read(&errors, &mut chunk) {
            Ok(n) => diagnostic.extend_from_slice(&chunk[..n]),
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
            Err(e) => break Err(e.to_string()),
        }
        if diagnostic.len() > 65536 {
            break Err("Root helper diagnostic byte bound".into());
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "fixed Root helper failed: {}",
                    String::from_utf8_lossy(&diagnostic)
                ))
            };
        }
        if Instant::now() >= deadline {
            break Err("fixed Root helper exceeded deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if result.is_err() && child.try_wait().map_err(|e| e.to_string())?.is_none() {
        // The unreaped child pins this newly created process group identity.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let reap = Instant::now() + Duration::from_secs(1);
        while child.try_wait().map_err(|e| e.to_string())?.is_none() {
            if Instant::now() >= reap {
                return Err("owned Root helper cleanup uncertain".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    result
}
