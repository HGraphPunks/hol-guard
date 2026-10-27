//! Persistent bounded NDJSON over an already authenticated Unix connection.
//! Peer identity, socket-path custody and provider authority belong to callers.
use crate::{TransportError, MAX_FRAME_BYTES};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub struct McpStream {
    socket: UnixStream,
    pending: Vec<u8>,
    closed: bool,
}
impl McpStream {
    pub fn new(socket: UnixStream) -> Result<Self, TransportError> {
        socket.set_nonblocking(true).map_err(io)?;
        Ok(Self {
            socket,
            pending: Vec::new(),
            closed: false,
        })
    }
    pub fn socket(&self) -> &UnixStream {
        &self.socket
    }
    pub fn read_frame(
        &mut self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        let result = self.read_inner(deadline, cancel);
        if result.is_err() || matches!(&result, Ok(None)) {
            self.closed = true;
        }
        result
    }
    fn read_inner(
        &mut self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let mut chunk = [0u8; 65536];
        loop {
            active(deadline, cancel)?;
            if let Some(index) = self.pending.iter().position(|b| *b == b'\n') {
                if index > MAX_FRAME_BYTES {
                    return Err(TransportError::FrameBound);
                }
                let mut tail = self.pending.split_off(index + 1);
                std::mem::swap(&mut tail, &mut self.pending);
                tail.pop();
                return Ok(Some(tail));
            }
            if self.pending.len() > MAX_FRAME_BYTES {
                return Err(TransportError::FrameBound);
            }
            ready(&self.socket, PollFlags::IN, deadline, cancel)?;
            let count = chunk.len().min(MAX_FRAME_BYTES + 1 - self.pending.len());
            match self.socket.read(&mut chunk[..count]) {
                Ok(0) if self.pending.is_empty() => return Ok(None),
                Ok(0) => return Err(TransportError::Truncated),
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                Err(e) if transient(&e) => {}
                Err(e) => return Err(io(e)),
            }
        }
    }
    pub fn write_frame(
        &mut self,
        raw: &[u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        let result = self.write_inner(raw, deadline, cancel);
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    fn write_inner(
        &mut self,
        raw: &[u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<(), TransportError> {
        if raw.is_empty() || raw.len() > MAX_FRAME_BYTES {
            return Err(TransportError::FrameBound);
        }
        if raw.contains(&b'\n') {
            return Err(TransportError::Malformed);
        }
        let mut line = Vec::with_capacity(raw.len() + 1);
        line.extend_from_slice(raw);
        line.push(b'\n');
        let mut offset = 0;
        while offset < line.len() {
            ready(&self.socket, PollFlags::OUT, deadline, cancel)?;
            match self.socket.write(&line[offset..]) {
                Ok(0) => return Err(TransportError::Io("MCP response made no progress".into())),
                Ok(n) => offset += n,
                Err(e) if transient(&e) => {}
                Err(e) => return Err(io(e)),
            }
        }
        Ok(())
    }
}
fn io(error: std::io::Error) -> TransportError {
    TransportError::Io(error.to_string())
}
fn transient(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}
fn ready(
    socket: &UnixStream,
    flags: PollFlags,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), TransportError> {
    loop {
        active(deadline, cancel)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(TransportError::Deadline);
        }
        let mut fds = [PollFd::new(socket, flags)];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: left.min(Duration::from_millis(25)).as_nanos() as i64,
        };
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => {}
            Ok(_) => return Ok(()),
            Err(error) => return Err(TransportError::Io(error.to_string())),
        }
    }
}
fn active(deadline: Instant, cancel: &AtomicBool) -> Result<(), TransportError> {
    if cancel.load(Ordering::Acquire) {
        return Err(TransportError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(TransportError::Deadline);
    }
    Ok(())
}
