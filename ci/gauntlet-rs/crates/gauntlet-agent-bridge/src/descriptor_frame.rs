//! Bounded Linux descriptor frames shared by the unprivileged connectors and
//! their Root owner. SCM_RIGHTS duplicates open descriptions: the caller must
//! authenticate the peer, inspect every received object, and arrange closure
//! of the sender's copies before claiming exclusive data-plane ownership.
use crate::{BridgeIoError, Result};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

const MAX_FDS: usize = 4;

/// Exact small control messages between descriptor-frame acknowledgements.
/// Per-call nonblocking I/O preserves flags and the same absolute deadline
/// across partial reads, cancellation and interrupted system calls.
pub fn receive_control_bytes(
    channel: &UnixStream,
    raw: &mut [u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    control(
        channel,
        raw.as_mut_ptr(),
        raw.len(),
        false,
        deadline,
        cancelled,
    )
}
pub fn send_control_bytes(
    channel: &UnixStream,
    raw: &[u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    control(
        channel,
        raw.as_ptr().cast_mut(),
        raw.len(),
        true,
        deadline,
        cancelled,
    )
}
fn control(
    channel: &UnixStream,
    raw: *mut u8,
    length: usize,
    send: bool,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    if !(1..=4096).contains(&length) {
        return Err(BridgeIoError::Invalid(
            "bounded descriptor control message required",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut offset = 0;
        while offset < length {
            crate::ready(
                channel.as_raw_fd(),
                if send { libc::POLLOUT } else { libc::POLLIN },
                deadline,
                cancelled,
            )?;
            // The wrappers borrow initialized slices throughout; send never
            // mutates input, and recv cannot exceed the remaining output.
            let count = unsafe {
                if send {
                    libc::send(
                        channel.as_raw_fd(),
                        raw.add(offset).cast(),
                        length - offset,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                } else {
                    libc::recv(
                        channel.as_raw_fd(),
                        raw.add(offset).cast(),
                        length - offset,
                        libc::MSG_DONTWAIT,
                    )
                }
            };
            if count == 0 {
                return Err(BridgeIoError::Eof);
            }
            if count < 0 {
                if matches!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(crate::operating_error());
            }
            offset += count as usize;
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (channel, raw, send, deadline, cancelled);
        Err(BridgeIoError::Invalid("descriptor control requires Linux"))
    }
}

fn shape(marker: u8, count: usize) -> Result<()> {
    if !marker.is_ascii_graphic() || !(1..=MAX_FDS).contains(&count) {
        return Err(BridgeIoError::Invalid(
            "one to four descriptors and a fixed marker required",
        ));
    }
    Ok(())
}

/// Send one marker and one exact, bounded SCM_RIGHTS array. No descriptor or
/// open-description flag is changed. The sender retains its original handles.
pub fn send_fd_frame(
    channel: &UnixStream,
    marker: u8,
    descriptors: &[BorrowedFd<'_>],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    shape(marker, descriptors.len())?;
    #[cfg(target_os = "linux")]
    {
        linux::send(channel, marker, descriptors, deadline, cancelled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (channel, deadline, cancelled);
        Err(BridgeIoError::Invalid("descriptor handoff requires Linux"))
    }
}

/// Receive exactly one frame. CLOEXEC is installed atomically by the kernel.
/// Every delivered descriptor is adopted before rejecting malformed framing,
/// excess rights or truncation; rejection closes all delivered handles.
pub fn receive_fd_frame(
    channel: &UnixStream,
    marker: u8,
    count: usize,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<OwnedFd>> {
    shape(marker, count)?;
    #[cfg(target_os = "linux")]
    {
        linux::receive(channel, marker, count, deadline, cancelled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (channel, deadline, cancelled);
        Err(BridgeIoError::Invalid("descriptor handoff requires Linux"))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::{operating_error, ready};
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::fd::{AsRawFd, FromRawFd};

    fn length<T, U: TryFrom<T>>(value: T) -> Result<U> {
        U::try_from(value).map_err(|_| BridgeIoError::Invalid("ancillary length overflow"))
    }

    fn again() -> bool {
        matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN | libc::EINTR)
        )
    }

    pub(super) fn send(
        channel: &UnixStream,
        marker: u8,
        descriptors: &[BorrowedFd<'_>],
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        // BorrowedFd is not an ancillary ABI. Allocate and populate the exact
        // array of C integers separately, with CMSG alignment from libc.
        let bytes = descriptors.len() * size_of::<libc::c_int>();
        let words = unsafe { libc::CMSG_SPACE(bytes as u32) as usize }.div_ceil(size_of::<usize>());
        let mut control = vec![0_usize; words];
        let mut marker = [marker];
        let mut payload = libc::iovec {
            iov_base: marker.as_mut_ptr().cast(),
            iov_len: 1,
        };
        // SAFETY: the initialized iovec and aligned control storage remain live
        // throughout sendmsg; CMSG_DATA contains only the borrowed raw handles.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut payload;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = length(control.len() * size_of::<usize>())?;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err(BridgeIoError::Invalid("descriptor control unavailable"));
        }
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = length(libc::CMSG_LEN(bytes as u32))?;
            for (index, fd) in descriptors.iter().enumerate() {
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                    fd.as_raw_fd(),
                );
            }
        }
        loop {
            ready(channel.as_raw_fd(), libc::POLLOUT, deadline, cancelled)?;
            let written = unsafe {
                libc::sendmsg(
                    channel.as_raw_fd(),
                    &message,
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                )
            };
            if written == 1 {
                return Ok(());
            }
            if written >= 0 || !again() {
                return Err(operating_error());
            }
        }
    }

    pub(super) fn receive(
        channel: &UnixStream,
        marker: u8,
        count: usize,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<OwnedFd>> {
        let words =
            unsafe { libc::CMSG_SPACE((MAX_FDS * size_of::<libc::c_int>()) as u32) as usize }
                .div_ceil(size_of::<usize>());
        let mut control = vec![0_usize; words];
        let mut payload_bytes = [0_u8; 2];
        let mut payload = libc::iovec {
            iov_base: payload_bytes.as_mut_ptr().cast(),
            iov_len: 2,
        };
        let (read, message) = loop {
            ready(channel.as_raw_fd(), libc::POLLIN, deadline, cancelled)?;
            // SAFETY: recvmsg writes only into the initialized local buffers.
            // Rebuild msghdr on every retry because its lengths are in/out.
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &mut payload;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = length(control.len() * size_of::<usize>())?;
            let read = unsafe {
                libc::recvmsg(
                    channel.as_raw_fd(),
                    &mut message,
                    libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
                )
            };
            if read >= 0 {
                break (read, message);
            }
            if !again() {
                return Err(operating_error());
            }
        };
        let capacity = control.len() * size_of::<usize>();
        let used = length::<_, usize>(message.msg_controllen)?;
        if used > capacity {
            return Err(BridgeIoError::Invalid(
                "kernel ancillary length exceeds storage",
            ));
        }
        let mut received = Vec::new();
        let mut invalid = false;
        let mut headers = 0;
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            headers += 1;
            let offset = (header as usize).checked_sub(control.as_ptr() as usize);
            let len = unsafe { (*header).cmsg_len as usize };
            let minimum = unsafe { libc::CMSG_LEN(0) as usize };
            if len < minimum
                || offset
                    .and_then(|v| v.checked_add(len))
                    .is_none_or(|end| end > used)
            {
                invalid = true;
                break;
            }
            let bytes = len - minimum;
            if unsafe {
                (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS
            } || bytes == 0
                || bytes % size_of::<libc::c_int>() != 0
            {
                invalid = true;
            } else {
                for index in 0..bytes / size_of::<libc::c_int>() {
                    // SAFETY: each validated SCM_RIGHTS slot lies in the kernel
                    // result. Adopt every FD, including extras, for error cleanup.
                    let raw = unsafe {
                        std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                        )
                    };
                    if raw < 0 {
                        invalid = true;
                    } else {
                        received.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
            }
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
        }
        if read != 1
            || payload_bytes[0] != marker
            || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
            || headers != 1
            || invalid
            || received.len() != count
        {
            return Err(BridgeIoError::Invalid(
                "descriptor handoff frame changed or incomplete",
            ));
        }
        Ok(received)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, AsRawFd};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[test]
    fn four_exact_descriptors_preserve_objects_and_are_cloexec() {
        let (parent, child) = UnixStream::pair().unwrap();
        let pairs: [_; 4] = std::array::from_fn(|_| UnixStream::pair().unwrap());
        let descriptors = pairs.iter().map(|v| v.0.as_fd()).collect::<Vec<_>>();
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        send_fd_frame(&child, b'P', &descriptors, deadline, &cancel).unwrap();
        let received = receive_fd_frame(&parent, b'P', 4, deadline, &cancel).unwrap();
        for (source, held) in pairs.iter().zip(&received) {
            let mut a: libc::stat = unsafe { std::mem::zeroed() };
            let mut b: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstat(source.0.as_raw_fd(), &mut a) }, 0);
            assert_eq!(unsafe { libc::fstat(held.as_raw_fd(), &mut b) }, 0);
            assert_eq!((a.st_dev, a.st_ino), (b.st_dev, b.st_ino));
            assert_ne!(
                unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
    }

    #[test]
    fn wrong_marker_count_deadline_and_cancel_refuse() {
        let (parent, child) = UnixStream::pair().unwrap();
        let (source, _) = UnixStream::pair().unwrap();
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        send_fd_frame(&child, b'N', &[source.as_fd()], deadline, &cancel).unwrap();
        assert!(receive_fd_frame(&parent, b'P', 1, deadline, &cancel).is_err());
        send_fd_frame(&child, b'N', &[source.as_fd()], deadline, &cancel).unwrap();
        assert!(receive_fd_frame(&parent, b'N', 4, deadline, &cancel).is_err());
        assert_eq!(
            receive_fd_frame(&parent, b'N', 1, Instant::now(), &cancel).unwrap_err(),
            BridgeIoError::Deadline
        );
        cancel.store(true, Ordering::Release);
        assert_eq!(
            receive_fd_frame(&parent, b'N', 1, deadline, &cancel).unwrap_err(),
            BridgeIoError::Cancelled
        );
        assert!(send_fd_frame(&child, b'N', &[], deadline, &cancel).is_err());
    }

    fn object_handles(fd: BorrowedFd<'_>) -> usize {
        let mut source: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut source) }, 0);
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let number = entry.file_name().to_str()?.parse::<i32>().ok()?;
                let mut current: libc::stat = unsafe { std::mem::zeroed() };
                (unsafe { libc::fstat(number, &mut current) } == 0
                    && (current.st_dev, current.st_ino) == (source.st_dev, source.st_ino))
                    .then_some(())
            })
            .count()
    }

    #[test]
    fn rejected_extra_and_kernel_truncated_rights_close_every_received_handle() {
        for count in [2, 6] {
            let (parent, child) = UnixStream::pair().unwrap();
            let sources = (0..count)
                .map(|_| UnixStream::pair().unwrap())
                .collect::<Vec<_>>();
            let descriptors = sources.iter().map(|v| v.0.as_fd()).collect::<Vec<_>>();
            let before = descriptors
                .iter()
                .map(|v| object_handles(*v))
                .collect::<Vec<_>>();
            let deadline = Instant::now() + Duration::from_secs(1);
            let cancel = AtomicBool::new(false);
            // Bypass the public sender's four-FD limit to exercise an actual
            // untrusted peer and MSG_CTRUNC from the kernel's receive path.
            linux::send(&child, b'P', &descriptors, deadline, &cancel).unwrap();
            assert!(receive_fd_frame(&parent, b'P', 1, deadline, &cancel).is_err());
            assert_eq!(
                descriptors
                    .iter()
                    .map(|v| object_handles(*v))
                    .collect::<Vec<_>>(),
                before
            );
        }
    }

    #[test]
    fn control_partial_reads_cannot_extend_deadlines_and_cancel_prevents_io() {
        let (reader, writer) = UnixStream::pair().unwrap();
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        send_control_bytes(&writer, &[7], deadline, &cancel).unwrap();
        let began = Instant::now();
        let mut metadata = [0; 4];
        assert!(matches!(
            receive_control_bytes(
                &reader,
                &mut metadata,
                began + Duration::from_millis(20),
                &cancel
            ),
            Err(BridgeIoError::Deadline)
        ));
        assert_eq!(metadata[0], 7);
        assert!(began.elapsed() < Duration::from_secs(1));
        cancel.store(true, std::sync::atomic::Ordering::Release);
        assert!(matches!(
            send_control_bytes(&writer, &[9], deadline, &cancel),
            Err(BridgeIoError::Cancelled)
        ));
        cancel.store(false, std::sync::atomic::Ordering::Release);
        send_control_bytes(&writer, &[8, 9, 10], deadline, &cancel).unwrap();
        let mut rest = [0; 3];
        receive_control_bytes(&reader, &mut rest, deadline, &cancel).unwrap();
        assert_eq!(rest, [8, 9, 10]);
        assert!(send_control_bytes(&writer, &[], deadline, &cancel).is_err());
        drop(writer);
        assert!(matches!(
            receive_control_bytes(&reader, &mut rest, deadline, &cancel),
            Err(BridgeIoError::Eof)
        ));
    }
}
