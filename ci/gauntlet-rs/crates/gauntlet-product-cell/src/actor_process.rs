//! Owned product children. Only this actor reaps them; a terminal PID is
//! never signalled again. Outside cgroup cleanup remains mandatory.
use crate::{validate_product_argv, CellError, CellLayout, Result, READY};
use ring::rand::{SecureRandom, SystemRandom};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const PROGRAM: &str = "/public/gauntlet-product-cell";
pub(crate) struct ProductProcess {
    pub(crate) child: Child,
    pub(crate) released: bool,
    pub(crate) input_bytes: usize,
    pub(crate) output_bytes: usize,
    pub(crate) stdout_eof: bool,
    pub(crate) stderr_eof: bool,
    pub(crate) returncode: Option<i32>,
}
pub(crate) fn handle() -> Result<String> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| CellError("product handle randomness unavailable"))?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
fn nonblocking(fd: &impl std::os::fd::AsFd) -> Result<()> {
    let flags = fcntl_getfl(fd).map_err(|_| CellError("product pipe flags unavailable"))?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK)
        .map_err(|_| CellError("product pipe flags unavailable"))
}
impl ProductProcess {
    pub(crate) fn spawn(argv: &[String], layout: CellLayout) -> Result<Self> {
        validate_product_argv(argv)?;
        let mut command = Command::new(PROGRAM);
        command
            .arg("exec-gate")
            .args(argv)
            .current_dir(layout.workspace)
            .env_clear()
            .env("PATH", layout.path)
            .env("HOME", "/product/home")
            .env("LANG", "C.UTF-8")
            .env("MALLOC_ARENA_MAX", "2")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Only the async-signal-safe setsid syscall runs in this callback.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let child = command
            .spawn()
            .map_err(|_| CellError("trusted product gate spawn failed"))?;
        Ok(Self {
            child,
            released: false,
            input_bytes: 0,
            output_bytes: 0,
            stdout_eof: false,
            stderr_eof: false,
            returncode: None,
        })
    }
    pub(crate) fn ready(&mut self) -> Result<()> {
        let invalid = CellError("trusted product gate did not reach measurement boundary");
        nonblocking(self.child.stdin.as_ref().ok_or(invalid)?)?;
        nonblocking(self.child.stdout.as_ref().ok_or(invalid)?)?;
        nonblocking(self.child.stderr.as_ref().ok_or(invalid)?)?;
        let stdout = self.child.stdout.as_mut().ok_or(invalid)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut marker = Vec::new();
        while marker.len() < READY.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(invalid);
            }
            let mut fds = [PollFd::new(&*stdout, PollFlags::IN)];
            let wait = Timespec {
                tv_sec: 0,
                tv_nsec: left.as_nanos().min(100_000_000) as i64,
            };
            match poll(&mut fds, Some(&wait)) {
                Ok(0) | Err(rustix::io::Errno::INTR) => continue,
                Ok(_) => {}
                Err(_) => return Err(invalid),
            }
            let mut bytes = [0_u8; 64];
            let remaining = READY.len() - marker.len();
            match stdout.read(&mut bytes[..remaining]) {
                Ok(0) => return Err(invalid),
                Ok(n) => marker.extend_from_slice(&bytes[..n]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(_) => return Err(invalid),
            }
        }
        if marker != READY {
            return Err(invalid);
        }
        Ok(())
    }
    pub(crate) fn release(&mut self) -> Result<()> {
        if self.released {
            return Err(CellError("product gate is single use"));
        }
        let pipe = self
            .child
            .stdin
            .as_mut()
            .ok_or(CellError("product gate pipe closed"))?;
        if pipe
            .write(&[1])
            .map_err(|_| CellError("product gate made no progress"))?
            != 1
        {
            return Err(CellError("product gate made no progress"));
        }
        self.released = true;
        Ok(())
    }
    pub(crate) fn read_output(&mut self, wait_ms: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        let invalid = CellError("product combined output byte budget or pipe failure");
        if wait_ms > 100 {
            return Err(invalid);
        }
        if wait_ms > 0 {
            let mut fds = Vec::new();
            if !self.stdout_eof {
                fds.push(PollFd::new(
                    self.child.stdout.as_ref().ok_or(invalid)?,
                    PollFlags::IN,
                ));
            }
            if !self.stderr_eof {
                fds.push(PollFd::new(
                    self.child.stderr.as_ref().ok_or(invalid)?,
                    PollFlags::IN,
                ));
            }
            if !fds.is_empty() {
                let wait = Timespec {
                    tv_sec: 0,
                    tv_nsec: wait_ms as i64 * 1_000_000,
                };
                if let Err(error) = poll(&mut fds, Some(&wait)) {
                    if error != rustix::io::Errno::INTR {
                        return Err(invalid);
                    }
                }
            }
        }
        let mut read = |stream: &mut dyn Read, eof: &mut bool| -> Result<Vec<u8>> {
            if *eof {
                return Ok(Vec::new());
            }
            let mut buffer = vec![0_u8; 32768];
            let count = match stream.read(&mut buffer) {
                Ok(n) => {
                    if n == 0 {
                        *eof = true;
                    }
                    n
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    0
                }
                Err(_) => return Err(invalid),
            };
            self.output_bytes = self.output_bytes.checked_add(count).ok_or(invalid)?;
            if self.output_bytes > 8 * 1024 * 1024 {
                return Err(invalid);
            }
            buffer.truncate(count);
            Ok(buffer)
        };
        Ok((
            read(
                self.child.stdout.as_mut().ok_or(invalid)?,
                &mut self.stdout_eof,
            )?,
            read(
                self.child.stderr.as_mut().ok_or(invalid)?,
                &mut self.stderr_eof,
            )?,
        ))
    }
}
pub(crate) fn exit_code(status: i32) -> Result<i32> {
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(-libc::WTERMSIG(status))
    } else {
        Err(CellError("unexpected product wait status"))
    }
}
