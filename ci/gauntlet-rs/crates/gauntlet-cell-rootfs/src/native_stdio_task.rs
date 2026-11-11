//! Private capability for selected syscall buffers of one held, stopped task.
//! Snapshot reads grant no wire authority. The separate owned-pipe relay below
//! forwards actual bytes without reading candidate memory.
use crate::native_stdio_syscall::{
    NativeMemoryRange, MAX_NATIVE_STDIO_IOVECS, MAX_NATIVE_STDIO_TRANSFER,
};
use crate::native_trace_task::Task;
use crate::Result;
use rustix::fs::{fstat, Stat};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;

pub(super) struct Pipes {
    tid: u32,
    start: u64,
    held: [OwnedFd; 2],
    identity: [(u64, u64); 2],
    argv: Value,
}

fn identity(info: &Stat) -> (u64, u64) {
    (info.st_dev, info.st_ino)
}

impl Pipes {
    pub(super) fn open(task: &Task, image: &Value) -> Result<Self> {
        let held = [task.stdio_pipe(0)?, task.stdio_pipe(1)?];
        let identity = [
            identity(&fstat(&held[0]).map_err(|e| e.to_string())?),
            identity(&fstat(&held[1]).map_err(|e| e.to_string())?),
        ];
        if identity[0] == identity[1] {
            return Err("distinct Native stdin/stdout pipes required".into());
        }
        Ok(Self {
            tid: task.tid,
            start: task.start,
            held,
            identity,
            argv: image["argv_sha256"].clone(),
        })
    }

    pub(super) fn observation(&self) -> Value {
        json!({"stdin":{"device":self.identity[0].0,"inode":self.identity[0].1},
            "stdout":{"device":self.identity[1].0,"inode":self.identity[1].1},
            "held_with":"O_PATH","pipe_readers_or_writers_added":false})
    }

    pub(super) fn recheck(
        &self,
        task: &Task,
        cgroup: &str,
        select: &impl Fn(&Value) -> Result<bool>,
    ) -> Result<()> {
        if task.tid != self.tid || task.tgid != self.tid || task.start != self.start {
            return Err("Native stdio task lifetime changed".into());
        }
        // Full executable bytes are re-hashed; metadata never substitutes for
        // a digest. exec_image also checks this dedicated tracer's ownership.
        let image = task.exec_image(cgroup)?;
        if image["argv_sha256"] != self.argv || !select(&image)? {
            return Err("Native stdio image or command changed".into());
        }
        for descriptor in 0..=1 {
            let current = task.stdio_pipe(descriptor)?;
            for fd in [&current, &self.held[descriptor as usize]] {
                if identity(&fstat(fd).map_err(|e| e.to_string())?)
                    != self.identity[descriptor as usize]
                {
                    return Err("Native stdio pipe identity changed".into());
                }
            }
        }
        task.recheck(cgroup)
    }

    /// The recorder supplies only ranges decoded from the selected fd0/fd1
    /// syscall or its bounded iovec table. No general process-memory API is
    /// exposed, and no target memory/register/syscall argument is changed.
    pub(super) fn copy(
        &self,
        task: &Task,
        cgroup: &str,
        ranges: &[NativeMemoryRange],
        count: usize,
        select: &impl Fn(&Value) -> Result<bool>,
    ) -> Result<Vec<u8>> {
        if count > MAX_NATIVE_STDIO_TRANSFER || ranges.len() > MAX_NATIVE_STDIO_IOVECS {
            return Err("Native pipe snapshot bound exceeded".into());
        }
        self.recheck(task, cgroup, select)?;
        let mut remaining = count;
        let mut remote = Vec::new();
        for range in ranges {
            if range.length > MAX_NATIVE_STDIO_TRANSFER
                || (range.length > 0 && range.address == 0)
                || range.address.checked_add(range.length as u64).is_none()
            {
                return Err("invalid selected Native pipe range".into());
            }
            let take = remaining.min(range.length);
            if take != 0 {
                remote.push(libc::iovec {
                    iov_base: range.address as usize as *mut libc::c_void,
                    iov_len: take,
                });
                remaining -= take;
            }
            if remaining == 0 {
                break;
            }
        }
        if remaining != 0 {
            return Err("selected Native pipe ranges are too short".into());
        }
        let mut raw = vec![0; count];
        if count != 0 {
            let local = libc::iovec {
                iov_base: raw.as_mut_ptr().cast(),
                iov_len: count,
            };
            // SAFETY: the local vector is live and exactly sized. Remote
            // ranges are read-only arguments to process_vm_readv, scoped above.
            let copied = unsafe {
                libc::process_vm_readv(
                    task.tid as i32,
                    &local,
                    1,
                    remote.as_ptr(),
                    remote.len() as libc::c_ulong,
                    0,
                )
            };
            self.recheck(task, cgroup, select)?;
            if copied != count as isize {
                return Err(format!(
                    "Native pipe snapshot incomplete: copied {copied}/{count}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(raw)
    }
}

/// A Root-observed read, successful write, or real read-side EOF. Observation
/// precedes forwarding; write events credit only the bytes the kernel accepted.
pub enum NativePipeEvent<'a> {
    Read {
        direction: usize,
        offset: usize,
        bytes: &'a [u8],
    },
    BeforeWrite {
        direction: usize,
        offset: usize,
        bytes: &'a [u8],
    },
    Write {
        direction: usize,
        offset: usize,
        bytes: &'a [u8],
    },
    Eof {
        direction: usize,
        bytes: usize,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct NativePipeCounts {
    pub read: [usize; 2],
    pub written: [usize; 2],
}

struct Flow {
    reader: Option<OwnedFd>,
    writer: Option<OwnedFd>,
    buffer: Vec<u8>,
    filled: usize,
    offset: usize,
    read: usize,
    written: usize,
}

impl Flow {
    fn new(reader: OwnedFd, writer: OwnedFd) -> Self {
        Self {
            reader: Some(reader),
            writer: Some(writer),
            buffer: vec![0; 65536],
            filled: 0,
            offset: 0,
            read: 0,
            written: 0,
        }
    }
}

/// Relay [SDK read, Native write, Native read, SDK write] after the caller has
/// authenticated the connector, matched all four kernel pipe identities to its
/// outside process observations, and obtained closure of the connector's copies.
/// Direction zero is SDK-to-Native; direction one is Native-to-SDK.
///
/// This consumes the four exclusive handles. It cannot infer peer identity,
/// request semantics, Native exit, or qualification from successful transport.
/// Errors close the handles; the job owner must retain the failure and clean up
/// its processes. EOF is forwarded only after every queued byte is written.
pub fn relay_native_pipe_bytes<F>(
    endpoints: [OwnedFd; 4],
    expected: [(u64, u64); 4],
    deadline: std::time::Instant,
    cancelled: &std::sync::atomic::AtomicBool,
    mut observe: F,
) -> Result<NativePipeCounts>
where
    F: FnMut(NativePipeEvent<'_>) -> Result<()>,
{
    use std::os::fd::AsRawFd;
    use std::sync::atomic::Ordering;

    // Reject Root in a candidate user namespace, and validate every endpoint
    // before changing any open-description flag or moving any payload bytes.
    let _proc = crate::kernel_process::root_proc()?;
    let mut distinct = std::collections::BTreeSet::new();
    for (index, fd) in endpoints.iter().enumerate() {
        let info = fstat(fd).map_err(|e| e.to_string())?;
        let object = identity(&info);
        let link = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
            .map_err(|e| e.to_string())?;
        let flags = rustix::fs::fcntl_getfl(fd).map_err(|e| e.to_string())?;
        if rustix::fs::FileType::from_raw_mode(info.st_mode) != rustix::fs::FileType::Fifo
            || object != expected[index]
            || !distinct.insert(object)
            || link.as_os_str() != std::ffi::OsStr::new(&format!("pipe:[{}]", info.st_ino))
            || flags & rustix::fs::OFlags::ACCMODE
                != if index % 2 == 0 {
                    rustix::fs::OFlags::RDONLY
                } else {
                    rustix::fs::OFlags::WRONLY
                }
        {
            return Err("four distinct, outside-bound anonymous pipe ends required".into());
        }
    }
    for fd in &endpoints {
        crate::supervisor_io::nonblocking(fd)?;
    }
    let [sdk_read, native_write, native_read, sdk_write] = endpoints;
    let mut flows = [
        Flow::new(sdk_read, native_write),
        Flow::new(native_read, sdk_write),
    ];
    const MAXIMUM: usize = 32 * 1024 * 1024;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err("Native pipe relay cancelled".into());
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("Native pipe relay deadline exceeded".into());
        }
        let mut pending = [libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        }; 4];
        for (direction, flow) in flows.iter_mut().enumerate() {
            if flow.offset == flow.filled {
                flow.offset = 0;
                flow.filled = 0;
                if flow.reader.is_none() {
                    flow.writer.take();
                }
                if let Some(fd) = &flow.reader {
                    pending[2 * direction] = libc::pollfd {
                        fd: fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                }
            } else if let Some(fd) = &flow.writer {
                pending[2 * direction + 1] = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
            }
        }
        if flows
            .iter()
            .all(|v| v.reader.is_none() && v.writer.is_none())
        {
            return Ok(NativePipeCounts {
                read: [flows[0].read, flows[1].read],
                written: [flows[0].written, flows[1].written],
            });
        }
        let timeout = remaining
            .min(std::time::Duration::from_millis(100))
            .as_millis()
            .max(1) as i32;
        // SAFETY: poll borrows exactly the four initialized entries; each live
        // descriptor is held by a flow throughout the poll and subsequent I/O.
        if unsafe { libc::poll(pending.as_mut_ptr(), pending.len() as libc::nfds_t, timeout) } < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut total = flows.iter().map(|v| v.read).sum::<usize>();
        for (direction, flow) in flows.iter_mut().enumerate() {
            let input = pending[2 * direction];
            let output = pending[2 * direction + 1];
            if (input.revents | output.revents) & libc::POLLNVAL != 0 {
                return Err("Native pipe descriptor became invalid".into());
            }
            if input.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                let maximum = (MAXIMUM - total).clamp(1, flow.buffer.len());
                match rustix::io::read(
                    flow.reader.as_ref().ok_or("Native source closed")?,
                    &mut flow.buffer[..maximum],
                ) {
                    Ok(0) => {
                        observe(NativePipeEvent::Eof {
                            direction,
                            bytes: flow.read,
                        })?;
                        flow.reader.take();
                    }
                    Ok(count) => {
                        total += count;
                        if total > MAXIMUM {
                            return Err("Native pipe byte budget exceeded".into());
                        }
                        observe(NativePipeEvent::Read {
                            direction,
                            offset: flow.read,
                            bytes: &flow.buffer[..count],
                        })?;
                        flow.read += count;
                        flow.filled = count;
                    }
                    Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => (),
                    Err(error) => return Err(error.to_string()),
                }
            }
            if output.revents & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0 {
                observe(NativePipeEvent::BeforeWrite {
                    direction,
                    offset: flow.written,
                    bytes: &flow.buffer[flow.offset..flow.filled],
                })?;
                match rustix::io::write(
                    flow.writer.as_ref().ok_or("Native destination closed")?,
                    &flow.buffer[flow.offset..flow.filled],
                ) {
                    Ok(0) => return Err("Native pipe write made no progress".into()),
                    Ok(count) => {
                        observe(NativePipeEvent::Write {
                            direction,
                            offset: flow.written,
                            bytes: &flow.buffer[flow.offset..flow.offset + count],
                        })?;
                        flow.offset += count;
                        flow.written += count;
                    }
                    Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => (),
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
    }
}
