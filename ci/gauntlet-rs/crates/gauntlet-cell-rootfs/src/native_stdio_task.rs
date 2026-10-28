//! Private capability for selected syscall buffers of one held, stopped task.
//! Reads are snapshots, not atomic kernel pipe interception or memory attestation.
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
