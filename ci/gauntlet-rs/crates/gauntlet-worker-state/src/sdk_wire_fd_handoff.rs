//! One-use descriptor handoff from the unprivileged SDK tap child to Root.
//! Shared bounded framing owns ancillary cleanup; Root still inspects the
//! connected Native socket and its peer before retaining any trace.

#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

const MARKER: u8 = b'N';

#[cfg(target_os = "linux")]
pub(crate) fn send_native_socket(
    handoff: &UnixStream,
    native_socket: &UnixStream,
) -> Result<(), String> {
    gauntlet_agent_bridge::send_fd_frame(
        handoff,
        MARKER,
        &[native_socket.as_fd()],
        std::time::Instant::now() + std::time::Duration::from_secs(5),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
pub(crate) fn receive_native_socket(handoff: &UnixStream) -> Result<UnixStream, String> {
    let mut received = gauntlet_agent_bridge::receive_fd_frame(
        handoff,
        MARKER,
        1,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .map_err(|error| error.to_string())?;
    Ok(UnixStream::from(
        received.pop().ok_or("Native socket descriptor missing")?,
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn send_native_socket(_: &UnixStream, _: &UnixStream) -> Result<(), String> {
    Err("Native socket descriptor handoff requires Linux".to_owned())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn receive_native_socket(_: &UnixStream) -> Result<UnixStream, String> {
    Err("Native socket descriptor handoff requires Linux".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;

    #[cfg(target_os = "linux")]
    #[test]
    fn one_connected_socket_is_passed_without_reopening_a_path() {
        let (handoff_parent, handoff_child) = UnixStream::pair().unwrap();
        let (native, _peer) = UnixStream::pair().unwrap();
        send_native_socket(&handoff_child, &native).unwrap();
        let held = receive_native_socket(&handoff_parent).unwrap();
        let source = rustix::fs::fstat(&native).unwrap();
        let received = rustix::fs::fstat(&held).unwrap();
        assert_eq!(
            (source.st_dev, source.st_ino),
            (received.st_dev, received.st_ino)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_or_unexpected_descriptor_frame_refuses() {
        let (parent, mut child) = UnixStream::pair().unwrap();
        child.write_all(b"X").unwrap();
        assert!(receive_native_socket(&parent).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn two_passed_descriptors_refuse_instead_of_selecting_one() {
        let (parent, child) = UnixStream::pair().unwrap();
        let (first, _first_peer) = UnixStream::pair().unwrap();
        let (second, _second_peer) = UnixStream::pair().unwrap();
        gauntlet_agent_bridge::send_fd_frame(
            &child,
            MARKER,
            &[first.as_fd(), second.as_fd()],
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert!(receive_native_socket(&parent).is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    #[test]
    #[ignore = "requires Linux Root and UID 10001 for a real connected Native socket handoff"]
    fn root_can_forward_after_unprivileged_connector_exits_with_original_peer_credentials() {
        use crate::sdk_wire_tap::relay_bounded_sdk_mcp_pair_ineligible;
        use std::net::Shutdown;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        use std::os::unix::process::CommandExt;
        use std::process::Command;
        use std::sync::atomic::AtomicBool;
        use std::thread;
        use std::time::{Duration, Instant};

        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
        let path = directory.path().join("native.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (handoff_parent, handoff_child) = UnixStream::pair().unwrap();
        handoff_parent
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let child_fd = handoff_child.as_raw_fd();
        let script = r#"import array,socket,sys
handoff=socket.socket(fileno=int(sys.argv[1]))
native=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
native.connect(sys.argv[2])
handoff.sendmsg([b'N'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[native.fileno()]))])
"#;
        let mut command = Command::new("/usr/bin/python3");
        command
            .arg("-c")
            .arg(script)
            .arg(child_fd.to_string())
            .arg(&path)
            .uid(10001)
            .gid(10001);
        // SAFETY: the child only clears CLOEXEC on its one inherited
        // handoff socket before exec; Root retains the separate parent end.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(child_fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(child_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut connector = command.spawn().unwrap();
        drop(handoff_child);
        let began = Instant::now();
        let mut native_server = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(began.elapsed() < Duration::from_secs(5));
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("Native test accept failed: {error}"),
            }
        };
        let mut peer = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: the fixed struct and length are writable through
        // getsockopt, and the exact returned length is checked below.
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    native_server.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut peer as *mut libc::ucred).cast(),
                    &mut size,
                )
            },
            0
        );
        assert_eq!(size as usize, std::mem::size_of::<libc::ucred>());
        assert_eq!((peer.uid, peer.gid), (10001, 10001));
        assert_eq!(peer.pid as u32, connector.id());
        let native_client = receive_native_socket(&handoff_parent).unwrap();
        assert!(connector.wait().unwrap().success());
        native_client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        native_server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (mut sdk, relay_client) = UnixStream::pair().unwrap();
        sdk.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n";
        let response = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
        thread::scope(|scope| {
            let relay = scope.spawn(|| {
                relay_bounded_sdk_mcp_pair_ineligible(
                    relay_client,
                    native_client,
                    "docs",
                    &AtomicBool::new(false),
                )
                .unwrap()
            });
            let server = scope.spawn(|| {
                let mut observed = vec![0; request.len()];
                native_server.read_exact(&mut observed).unwrap();
                assert_eq!(&observed, request);
                native_server.write_all(response).unwrap();
                native_server.shutdown(Shutdown::Write).unwrap();
            });
            sdk.write_all(request).unwrap();
            sdk.shutdown(Shutdown::Write).unwrap();
            let mut observed = vec![0; response.len()];
            sdk.read_exact(&mut observed).unwrap();
            assert_eq!(&observed, response);
            server.join().unwrap();
            let proof = relay.join().unwrap();
            assert_eq!(proof.completed_tool_calls, 1);
            assert_eq!(proof.events.len(), 2);
        });
    }
}
