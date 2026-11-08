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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeSocketHelper {
    pub upstream_port: u16,
    pub parent_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocketStdio {
    pub listener: std::net::SocketAddr,
    pub objects: [(u64, u64); 2],
}

/// This helper consumes a listening socket and a liveness socket, not bytes
/// from a Native request pipe. No other command can select this handoff.
pub fn native_socket_helper(argv: &[Vec<u8>]) -> Result<Option<NativeSocketHelper>> {
    if argv.get(1).map(Vec::as_slice) != Some(b"daemon-edge") {
        return Ok(None);
    }
    let invalid = CellError("exact bounded Native socket helper arguments required");
    if argv.len() != 6 || argv[2] != b"--upstream-port" || argv[4] != b"--parent-pid" {
        return Err(invalid);
    }
    let decimal = |raw: &[u8]| -> Result<u32> {
        let text = std::str::from_utf8(raw).map_err(|_| invalid)?;
        let value: u32 = text.parse().map_err(|_| invalid)?;
        if value.to_string() != text {
            return Err(invalid);
        }
        Ok(value)
    };
    let port = decimal(&argv[3])?;
    let parent = decimal(&argv[5])?;
    if !(1..=u32::from(u16::MAX)).contains(&port) || !(2..=i32::MAX as u32).contains(&parent) {
        return Err(invalid);
    }
    Ok(Some(NativeSocketHelper {
        upstream_port: port as u16,
        parent_pid: parent,
    }))
}

/// Inspect duplicates briefly, without reading, writing, changing flags, or
/// retaining a socket reference that could postpone the real liveness EOF.
pub fn inspect_native_socket_stdio(
    input: &impl AsFd,
    output: &impl AsFd,
) -> Result<NativeSocketStdio> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (input, output);
        Err(CellError("Native socket inspection requires Linux"))
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let invalid =
            CellError("loopback listener and connected unnamed Native liveness socket required");
        let option = |fd: BorrowedFd<'_>, name| -> Result<libc::c_int> {
            let mut value: libc::c_int = 0;
            let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
            // SAFETY: the borrowed descriptor remains open; both output pointers
            // refer to correctly sized initialized local values.
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    name,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut size,
                )
            } != 0
                || size as usize != std::mem::size_of_val(&value)
            {
                return Err(invalid);
            }
            Ok(value)
        };
        if option(input.as_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
            || option(output.as_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
            || option(input.as_fd(), libc::SO_ACCEPTCONN)? != 1
            || option(output.as_fd(), libc::SO_ACCEPTCONN)? != 0
        {
            return Err(invalid);
        }
        let listener =
            std::net::TcpListener::from(input.as_fd().try_clone_to_owned().map_err(|_| invalid)?);
        let address = listener.local_addr().map_err(|_| invalid)?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(invalid);
        }
        let health = std::os::unix::net::UnixStream::from(
            output.as_fd().try_clone_to_owned().map_err(|_| invalid)?,
        );
        if !health.local_addr().map_err(|_| invalid)?.is_unnamed()
            || !health.peer_addr().map_err(|_| invalid)?.is_unnamed()
        {
            return Err(invalid);
        }
        let objects = [input.as_fd(), output.as_fd()].map(|fd| {
            let info = rustix::fs::fstat(fd).map_err(|_| invalid)?;
            if rustix::fs::FileType::from_raw_mode(info.st_mode) != rustix::fs::FileType::Socket
                || info.st_ino == 0
            {
                return Err(invalid);
            }
            Ok((info.st_dev, info.st_ino))
        });
        let [input, output] = objects;
        Ok(NativeSocketStdio {
            listener: address,
            objects: [input?, output?],
        })
    }
}

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

pub(crate) fn product_identity() -> Result<()> {
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
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(CellError("product gate dumpability lock failed"));
    }
    Ok(())
}

pub fn run_exec_gate(argv: &[String]) -> Result<Infallible> {
    validate_product_argv(argv)?;
    product_identity()?;
    let layout = load_root_layout()?;
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

/// A separate inherited control socket keeps Native stdin/stdout byte exact.
/// Environment and working directory are those selected by the Python caller.
pub fn run_native_gate(argv: &[std::ffi::OsString]) -> Result<Infallible> {
    crate::native_wire::validate_native_argv(argv)?;
    product_identity()?;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        use std::os::fd::FromRawFd;
        let config = crate::native_wire::load()?;
        if argv[0] != std::ffi::OsStr::new(&config.native_program) {
            return Err(CellError(
                "Native gate program differs from Root configuration",
            ));
        }
        // Descriptor 3 was duplicated from the connector's private socketpair
        // by its async-signal-safe pre_exec hook. It cannot reach Native exec.
        let mut control = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
        control
            .set_write_timeout(Some(Duration::from_secs(5)))
            .and_then(|_| control.write_all(b"G"))
            .map_err(|_| CellError("Native gate readiness unavailable"))?;
        release(&control, Instant::now() + Duration::from_secs(5))?;
        drop(control);
        let _error = Command::new(&argv[0]).args(&argv[1..]).exec();
        Err(CellError("released Native exec failed"))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    Err(CellError("Native gate requires Linux ARM64"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    #[cfg(target_os = "linux")]
    use std::{
        io::Read,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };
    #[test]
    fn only_exact_bounded_daemon_edge_arguments_select_socket_handoff() {
        let argv = |args: &[&str]| {
            args.iter()
                .map(|s| s.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        let valid = argv(&[
            "/native",
            "daemon-edge",
            "--upstream-port",
            "65535",
            "--parent-pid",
            "2147483647",
        ]);
        assert_eq!(
            native_socket_helper(&valid).unwrap(),
            Some(NativeSocketHelper {
                upstream_port: 65535,
                parent_pid: i32::MAX as u32
            })
        );
        assert_eq!(
            native_socket_helper(&argv(&["/native", "resident-client-stream"])).unwrap(),
            None
        );
        for (index, value) in [
            (2, "--parent-pid"),
            (3, "0"),
            (3, "65536"),
            (3, "01"),
            (3, "+1"),
            (3, "1\0"),
            (4, "--upstream-port"),
            (5, "1"),
            (5, "2147483648"),
            (5, "02"),
            (5, "-1"),
        ] {
            let mut changed = valid.clone();
            changed[index] = value.as_bytes().to_vec();
            assert!(native_socket_helper(&changed).is_err(), "{index}: {value}");
        }
        let mut extra = valid.clone();
        extra.push(b"--parent-pid".to_vec());
        assert!(native_socket_helper(&extra).is_err());
        assert!(native_socket_helper(&valid[..5]).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn socket_inspection_preserves_flags_objects_and_real_health_eof() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let (health, mut parent) = UnixStream::pair().unwrap();
        health.set_nonblocking(true).unwrap();
        parent
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let flags = |fd| unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let before = [flags(listener.as_raw_fd()), flags(health.as_raw_fd())];
        let inspected = inspect_native_socket_stdio(&listener, &health).unwrap();
        assert_eq!(inspected.listener, listener.local_addr().unwrap());
        assert_eq!(
            inspected.objects,
            [listener.as_fd(), health.as_fd()].map(|fd| {
                let s = rustix::fs::fstat(fd).unwrap();
                (s.st_dev, s.st_ino)
            })
        );
        assert_eq!(
            before,
            [flags(listener.as_raw_fd()), flags(health.as_raw_fd())]
        );
        drop(health);
        assert_eq!(parent.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn wildcard_listener_wrong_socket_roles_and_unconnected_health_refuse() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let wildcard = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (health, _parent) = UnixStream::pair().unwrap();
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(raw >= 0);
        let unconnected = unsafe { OwnedFd::from_raw_fd(raw) };
        assert!(inspect_native_socket_stdio(&wildcard, &health).is_err());
        assert!(inspect_native_socket_stdio(&udp, &health).is_err());
        assert!(inspect_native_socket_stdio(&health, &listener).is_err());
        assert!(inspect_native_socket_stdio(&listener, &listener).is_err());
        assert!(inspect_native_socket_stdio(&listener, &unconnected).is_err());
        assert!(inspect_native_socket_stdio(&tempfile::tempfile().unwrap(), &health).is_err());
    }
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
