//! One-use measured execution boundary. No product executable runs before the
//! outside supervisor releases this already unprivileged process.

use crate::{load_root_layout, CellError, Result};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::io::{read, Errno};
use std::convert::Infallible;
use std::io::Write;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

pub const READY: &[u8] = b"HOL_PRODUCT_EXEC_READY_V1\n";

pub fn validate_product_argv(argv: &[String]) -> Result<()> {
    if !(1..=128).contains(&argv.len())
        || !argv[0].starts_with('/')
        || argv.iter().any(|arg| arg.contains('\0'))
        || argv
            .iter()
            .try_fold(0_usize, |total, arg| total.checked_add(arg.len()))
            .is_none_or(|size| size > 1024 * 1024)
    {
        return Err(CellError(
            "bounded absolute unprivileged product argv required",
        ));
    }
    Ok(())
}

fn release(fd: &impl AsFd, deadline: Instant) -> Result<()> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(CellError("product gate release deadline exceeded"));
        }
        let wait = Timespec {
            tv_sec: left.as_secs().min(1) as i64,
            tv_nsec: if left.as_secs() > 0 {
                0
            } else {
                i64::from(left.subsec_nanos())
            },
        };
        let mut fds = [PollFd::new(fd, PollFlags::IN)];
        match poll(&mut fds, Some(&wait)) {
            Ok(0) | Err(Errno::INTR) => continue,
            Ok(_) if fds[0].revents().intersects(PollFlags::IN | PollFlags::HUP) => {}
            _ => return Err(CellError("private product release pipe unavailable")),
        }
        let mut byte = [0_u8; 1];
        match read(fd, &mut byte) {
            Ok(1) if byte == [1] => return Ok(()),
            Err(Errno::INTR) | Err(Errno::AGAIN) => continue,
            _ => return Err(CellError("private product release was absent or invalid")),
        }
    }
}

pub fn run_exec_gate(argv: &[String]) -> Result<Infallible> {
    validate_product_argv(argv)?;
    if !cfg!(all(target_os = "linux", target_arch = "aarch64"))
        || rustix::process::getuid().as_raw() != 10004
        || rustix::process::geteuid().as_raw() != 10004
        || rustix::process::getgid().as_raw() != 10004
        || rustix::process::getegid().as_raw() != 10004
    {
        return Err(CellError(
            "native Linux ARM64 UID/GID 10004 product gate required",
        ));
    }
    let layout = load_root_layout()?;
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(CellError("product gate dumpability lock failed"));
    }
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(READY)
        .and_then(|_| stdout.flush())
        .map_err(|_| CellError("product gate readiness pipe unavailable"))?;
    drop(stdout);
    // Descriptor zero belongs to the private, measured actor-created pipe;
    // this program never opens a network/bootstrap credential channel.
    let input = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
    release(&input, Instant::now() + Duration::from_secs(30))?;
    let _error = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(layout.workspace)
        .env_clear()
        .env("PATH", layout.path)
        .env("HOME", "/product/home")
        .env("LANG", "C.UTF-8")
        .env("MALLOC_ARENA_MAX", "2")
        .exec();
    Err(CellError("released product exec failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    #[test]
    fn argv_boundaries_refuse_unbounded_relative_and_nul_commands() {
        assert!(validate_product_argv(&["/bin/echo".into(), "".into()]).is_ok());
        for argv in [
            vec![],
            vec!["echo".into()],
            vec!["/bin/echo\0bad".into()],
            vec!["/bin/echo".into(); 129],
            vec![format!("/{}", "x".repeat(1024 * 1024))],
        ] {
            assert!(validate_product_argv(&argv).is_err());
        }
    }
    #[test]
    fn release_requires_exact_byte_and_honors_eof_and_deadline() {
        for value in [None, Some(0), Some(1), Some(2)] {
            let (reader, mut writer) = UnixStream::pair().unwrap();
            if let Some(byte) = value {
                writer.write_all(&[byte]).unwrap();
            }
            drop(writer);
            assert_eq!(
                release(&reader, Instant::now() + Duration::from_secs(1)).is_ok(),
                value == Some(1)
            );
        }
        let (reader, _writer) = UnixStream::pair().unwrap();
        assert_eq!(
            release(&reader, Instant::now() + Duration::from_millis(20)),
            Err(CellError("product gate release deadline exceeded"))
        );
    }
}
