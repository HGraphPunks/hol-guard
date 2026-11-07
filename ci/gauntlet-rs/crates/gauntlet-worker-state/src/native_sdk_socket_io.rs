//! One bounded line per SDK connection. No JSON, peer or Native authority is
//! inferred by this byte transport; callers authenticate before dispatch.
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn ready(
    socket: &UnixStream,
    flags: PollFlags,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), String> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err("SDK transport cancelled".into());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("SDK transport deadline".into());
        }
        let mut fds = [PollFd::new(socket, flags)];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: left.min(Duration::from_millis(25)).as_nanos() as i64,
        };
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => {}
            Ok(_) => return Ok(()),
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub fn read_native_sdk_line(
    socket: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, String> {
    if !(1..=2 * 1024 * 1024).contains(&maximum) {
        return Err("SDK frame bound invalid".into());
    }
    socket.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut chunk = [0; 65536];
    loop {
        ready(socket, PollFlags::IN, deadline, cancel)?;
        let count = chunk.len().min(maximum + 1 - raw.len());
        match socket.read(&mut chunk[..count]) {
            Ok(0) => return Err("SDK frame ended before its one newline".into()),
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if let Some(index) = raw.iter().position(|b| *b == b'\n') {
                    if index != raw.len() - 1
                        || raw.iter().filter(|b| **b == b'\n').count() != 1
                        || index > maximum
                    {
                        return Err("SDK frame has trailing, multiple or excessive bytes".into());
                    }
                    raw.pop();
                    return Ok(raw);
                }
                if raw.len() > maximum {
                    return Err("SDK frame byte budget exhausted".into());
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub fn write_native_sdk_line(
    socket: &mut UnixStream,
    raw: &[u8],
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), String> {
    if raw.is_empty() || raw.len() > 2 * 1024 * 1024 || raw.contains(&b'\n') {
        return Err("one bounded SDK response line required".into());
    }
    socket.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut value = raw.to_vec();
    value.push(b'\n');
    let mut offset = 0;
    while offset < value.len() {
        ready(socket, PollFlags::OUT, deadline, cancel)?;
        match socket.write(&value[offset..]) {
            Ok(0) => return Err("SDK response made no progress".into()),
            Ok(n) => offset += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    #[test]
    fn exact_binary_payload_is_preserved_and_request_trailing_bytes_refuse() {
        for (value, expected) in [
            (b"abc\x00\xff\n".as_slice(), true),
            (b"{}\n{}\n".as_slice(), false),
            (b"no newline".as_slice(), false),
            (b"123456\n".as_slice(), false),
        ] {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            sender.write_all(value).unwrap();
            drop(sender);
            let result = read_native_sdk_line(
                &mut receiver,
                5,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            );
            assert_eq!(result.is_ok(), expected);
            if expected {
                assert_eq!(result.unwrap(), b"abc\x00\xff")
            }
        }
    }
    #[test]
    fn idle_cancellation_and_deadline_remain_unavailable() {
        let (_sender, mut receiver) = UnixStream::pair().unwrap();
        assert!(read_native_sdk_line(
            &mut receiver,
            128,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(true)
        )
        .is_err());
        assert!(read_native_sdk_line(
            &mut receiver,
            128,
            Instant::now() + Duration::from_millis(10),
            &AtomicBool::new(false)
        )
        .is_err());
    }
    #[test]
    fn response_write_is_complete_and_rejects_embedded_frames() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let data = vec![b'x'; 200000];
        let expected = data.clone();
        let reader = thread::spawn(move || {
            read_native_sdk_line(
                &mut receiver,
                300000,
                Instant::now() + Duration::from_secs(2),
                &AtomicBool::new(false),
            )
            .unwrap()
        });
        write_native_sdk_line(
            &mut sender,
            &data,
            Instant::now() + Duration::from_secs(2),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(reader.join().unwrap(), expected);
        assert!(write_native_sdk_line(
            &mut sender,
            b"{}\n{}",
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false)
        )
        .is_err());
    }
}
