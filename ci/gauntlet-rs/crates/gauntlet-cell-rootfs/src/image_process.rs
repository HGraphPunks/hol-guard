//! Fixed Podman image operations with bounded streams and process lifetime.
use crate::Result;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) enum Operation {
    Inspect,
    Inventory,
    Mount,
    Unmount,
}

fn drain(fd: &OwnedFd, raw: &mut Vec<u8>, maximum: usize) -> Result<bool> {
    loop {
        let mut chunk = [0u8; 8192];
        match rustix::io::read(fd, &mut chunk) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > maximum {
                    return Err("image helper output exceeds fixed bound".into());
                }
            }
            Err(rustix::io::Errno::AGAIN) => return Ok(false),
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub(crate) fn run(pin: &str, operation: Operation, image: &str) -> Result<Vec<u8>> {
    crate::image_protocol::image_id(image)?;
    let program = std::path::Path::new("/usr/bin/podman");
    crate::fs_input::pinned(program, 128 * 1024 * 1024, pin)?;
    let args = match operation {
        Operation::Inspect => vec!["image", "inspect", image],
        Operation::Inventory => vec!["image", "mount", "--format", "json"],
        Operation::Mount => vec!["image", "mount", image],
        Operation::Unmount => vec!["image", "unmount", image],
    };
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| e.to_string())?;
    let output: OwnedFd = child
        .stdout
        .take()
        .ok_or("image stdout unavailable")?
        .into();
    let errors: OwnedFd = child
        .stderr
        .take()
        .ok_or("image stderr unavailable")?
        .into();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = (|| {
        crate::supervisor_io::nonblocking(&output)?;
        crate::supervisor_io::nonblocking(&errors)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let out_eof = drain(&output, &mut stdout, 1024 * 1024)?;
            let err_eof = drain(&errors, &mut stderr, 65536)?;
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                if out_eof && err_eof {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(format!(
                            "fixed image helper failed: {}",
                            String::from_utf8_lossy(&stderr)
                        ))
                    };
                }
            }
            if Instant::now() >= deadline {
                return Err("fixed image helper deadline exceeded".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() && child.try_wait().map_err(|e| e.to_string())?.is_none() {
        // The unreaped child pins this newly created group identity.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while child.try_wait().map_err(|e| e.to_string())?.is_none() {
            if Instant::now() >= deadline {
                return Err("image helper cleanup uncertain".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    result?;
    crate::fs_input::pinned(program, 128 * 1024 * 1024, pin)?;
    Ok(stdout)
}
