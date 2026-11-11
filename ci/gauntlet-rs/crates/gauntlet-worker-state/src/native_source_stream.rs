//! Deadline/cancellation-bounded byte copying. No candidate data is executed.
use crate::BoottimeDeadline;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::fd::RawFd;

pub(crate) fn copy_source(
    input: RawFd,
    output: &mut impl Write,
    expected_bytes: u64,
    deadline: &BoottimeDeadline,
    cancelled: impl Fn() -> bool,
) -> Result<String, String> {
    let mut count = 0u64;
    let mut digest = Sha256::new();
    loop {
        if cancelled() {
            return Err("native source upload cancelled; preserve partial slot".into());
        }
        let left = deadline.remaining().map_err(|e| e.to_string())?;
        if left.is_zero() {
            return Err("native source upload deadline; preserve partial slot".into());
        }
        let mut poll = libc::pollfd {
            fd: input,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized descriptor is borrowed for a finite poll.
        let ready = unsafe { libc::poll(&mut poll, 1, left.as_millis().clamp(1, 200) as i32) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err("native source pipe unavailable".into());
        }
        if ready == 0 {
            continue;
        }
        if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("native source pipe failed".into());
        }
        let mut raw = [0u8; 65536];
        // SAFETY: read borrows the input and writes within this live buffer.
        let n = unsafe { libc::read(input, raw.as_mut_ptr().cast(), raw.len()) };
        if n < 0 {
            if matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err("native source pipe read failed".into());
        }
        if n == 0 {
            if count != expected_bytes {
                return Err("native source upload truncated; preserve partial slot".into());
            }
            return Ok(format!("{:x}", digest.finalize()));
        }
        count = count
            .checked_add(n as u64)
            .filter(|n| *n <= expected_bytes)
            .ok_or("native source upload exceeds outside byte pin")?;
        output
            .write_all(&raw[..n as usize])
            .map_err(|_| "native source write uncertain")?;
        digest.update(&raw[..n as usize]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    #[test]
    fn binary_stream_matches_exact_bytes_and_refuses_truncation_or_extra_input() {
        for (bytes, expected, passes) in [
            (b"a\0\xff".as_slice(), 3, true),
            (b"ab", 3, false),
            (b"abcd", 3, false),
        ] {
            let (mut writer, reader) = UnixStream::pair().unwrap();
            writer.write_all(bytes).unwrap();
            drop(writer);
            let mut output = tempfile::tempfile().unwrap();
            let result = copy_source(
                reader.as_raw_fd(),
                &mut output,
                expected,
                &BoottimeDeadline::start(2).unwrap(),
                || false,
            );
            assert_eq!(result.is_ok(), passes);
            if passes {
                assert_eq!(result.unwrap(), format!("{:x}", Sha256::digest(bytes)));
            }
        }
    }
    #[test]
    fn cancellation_and_unanswered_pipe_are_bounded() {
        let (_writer, reader) = UnixStream::pair().unwrap();
        let mut output = tempfile::tempfile().unwrap();
        assert!(copy_source(
            reader.as_raw_fd(),
            &mut output,
            1,
            &BoottimeDeadline::start(2).unwrap(),
            || true
        )
        .unwrap_err()
        .contains("cancelled"));
        assert!(copy_source(
            reader.as_raw_fd(),
            &mut output,
            1,
            &BoottimeDeadline::start(1).unwrap(),
            || false
        )
        .unwrap_err()
        .contains("deadline"));
    }
}
