//! One-use descriptor handoff from the unprivileged SDK tap child to Root.
//! Root inspects the connected Native socket itself before retaining a trace.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::mem::{size_of, zeroed};

const MARKER: u8 = b'N';
#[cfg(target_os = "linux")]
const MAX_RECEIVED_FDS: usize = 4;

#[cfg(target_os = "linux")]
pub(crate) fn send_native_socket(
    handoff: &UnixStream,
    native_socket: &UnixStream,
) -> Result<(), String> {
    let mut marker = [MARKER];
    let mut payload = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    // SAFETY: CMSG_SPACE/CMSG_LEN are evaluated for exactly one RawFd. The
    // aligned control storage lives through sendmsg, and all pointers refer
    // to initialized local objects.
    let mut control = vec![
        0_usize;
        unsafe {
            (libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as usize)
                .div_ceil(size_of::<usize>())
        }
    ];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut payload;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() * size_of::<usize>();
    // SAFETY: message contains a valid iovec and a sufficiently large,
    // aligned control buffer. The resulting CMSG_DATA points inside it.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err("Native socket handoff control unavailable".to_owned());
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
        std::ptr::write_unaligned(
            libc::CMSG_DATA(header).cast::<libc::c_int>(),
            native_socket.as_raw_fd(),
        );
    }
    let written = unsafe { libc::sendmsg(handoff.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    if written != 1 {
        return Err(format!(
            "Native socket descriptor handoff failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn receive_native_socket(handoff: &UnixStream) -> Result<UnixStream, String> {
    let mut marker = [0_u8; 2];
    let mut payload = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let control_words =
        unsafe { libc::CMSG_SPACE((MAX_RECEIVED_FDS * size_of::<libc::c_int>()) as u32) as usize }
            .div_ceil(size_of::<usize>());
    let mut control = vec![0_usize; control_words];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut payload;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() * size_of::<usize>();
    // SAFETY: recvmsg writes only into the live iovec/control buffers. The
    // kernel marks any received descriptor CLOEXEC before returning it.
    let read = unsafe { libc::recvmsg(handoff.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if read < 0 {
        return Err(format!(
            "Native socket descriptor read failed: {}",
            io::Error::last_os_error()
        ));
    }
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    let mut received = Vec::<OwnedFd>::new();
    let mut headers = 0;
    let mut invalid_control = false;
    while !header.is_null() {
        headers += 1;
        let length = unsafe { (*header).cmsg_len as usize };
        let minimum = unsafe { libc::CMSG_LEN(0) as usize };
        if length < minimum || length > message.msg_controllen {
            invalid_control = true;
            break;
        }
        let bytes = length - minimum;
        if unsafe { (*header).cmsg_level != libc::SOL_SOCKET }
            || unsafe { (*header).cmsg_type != libc::SCM_RIGHTS }
            || bytes == 0
            || bytes % size_of::<libc::c_int>() != 0
        {
            invalid_control = true;
        } else {
            for index in 0..bytes / size_of::<libc::c_int>() {
                // SAFETY: the kernel supplied a bounded SCM_RIGHTS payload;
                // adopt every delivered FD so rejection closes extras too.
                let raw = unsafe {
                    std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                    )
                };
                if raw < 0 {
                    invalid_control = true;
                } else {
                    received.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if read != 1
        || marker[0] != MARKER
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || headers != 1
        || invalid_control
        || received.len() != 1
    {
        return Err("Native socket handoff frame changed or incomplete".to_owned());
    }
    let descriptor = received.pop().ok_or("Native socket descriptor missing")?;
    Ok(UnixStream::from(descriptor))
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
    use std::io::Write;

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
        let mut marker = [MARKER];
        let mut payload = libc::iovec {
            iov_base: marker.as_mut_ptr().cast(),
            iov_len: marker.len(),
        };
        let mut control = [0_usize; 4];
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut payload;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len() * size_of::<usize>();
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null());
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN((2 * size_of::<libc::c_int>()) as u32) as usize;
            let fds = libc::CMSG_DATA(header).cast::<libc::c_int>();
            std::ptr::write_unaligned(fds, first.as_raw_fd());
            std::ptr::write_unaligned(fds.add(1), second.as_raw_fd());
            assert_eq!(
                libc::sendmsg(child.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                1
            );
        }
        assert!(receive_native_socket(&parent).is_err());
    }
}
