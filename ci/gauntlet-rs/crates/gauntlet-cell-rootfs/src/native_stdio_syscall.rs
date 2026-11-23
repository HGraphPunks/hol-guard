//! Bounded Linux AArch64 syscall metadata for the outside Native pipe observer.
//! These pure decoders grant no process or memory-read authority. The caller
//! must first bind the stopped task, Native image and selected pipe endpoints.
use crate::Result;

pub const MAX_NATIVE_STDIO_TRANSFER: usize = 8 * 1024 * 1024;
pub const MAX_NATIVE_STDIO_IOVECS: usize = 1024;
pub const NATIVE_SYSCALL_INFO_CAPACITY: usize = 88;
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeSyscallEntry {
    pub number: u64,
    pub arguments: [u64; 6],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSyscallStop {
    Entry(NativeSyscallEntry),
    Exit { result: i64, is_error: bool },
}

fn u64_at(raw: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        raw.get(offset..offset + 8)
            .and_then(|v| v.try_into().ok())
            .ok_or("truncated Native syscall information")?,
    ))
}

/// Decode only the bytes actually returned by PTRACE_GET_SYSCALL_INFO.
/// Current entry/exit payload sizes are 80/33 bytes; unknown fields refuse.
pub fn decode_native_syscall_info(raw: &[u8]) -> Result<NativeSyscallStop> {
    if raw.len() < 24
        || raw.len() > NATIVE_SYSCALL_INFO_CAPACITY
        || raw[1..4] != [0; 3]
        || u32::from_le_bytes(raw[4..8].try_into().unwrap()) != AUDIT_ARCH_AARCH64
    {
        return Err("closed Linux AArch64 syscall information required".into());
    }
    match raw[0] {
        1 if raw.len() == 80 => {
            let mut arguments = [0; 6];
            for (index, value) in arguments.iter_mut().enumerate() {
                *value = u64_at(raw, 32 + 8 * index)?;
            }
            Ok(NativeSyscallStop::Entry(NativeSyscallEntry {
                number: u64_at(raw, 24)?,
                arguments,
            }))
        }
        2 if raw.len() == 33 && raw[32] <= 1 => Ok(NativeSyscallStop::Exit {
            result: i64::from_le_bytes(raw[24..32].try_into().unwrap()),
            is_error: raw[32] == 1,
        }),
        _ => Err("unsupported, truncated or extended Native syscall stop".into()),
    }
}

/// Read syscall metadata only from a task stopped under this tracer thread.
/// The kernel enforces ptrace ownership; endpoint/image authority remains the
/// caller's separate obligation. No target memory or register is modified.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub fn stopped_native_syscall_info(tid: u32) -> Result<NativeSyscallStop> {
    let tid = i32::try_from(tid)
        .ok()
        .filter(|v| *v > 0)
        .ok_or("positive stopped Native task required")?;
    let mut raw = [0u8; NATIVE_SYSCALL_INFO_CAPACITY];
    // libc exposes this operation/structure only for GNU, while this worker
    // also targets musl. Use its fixed Linux ABI and decode returned bytes.
    #[cfg(target_env = "musl")]
    let request = 0x420e as libc::c_int;
    #[cfg(not(target_env = "musl"))]
    let request = 0x420e as libc::c_uint;
    // SAFETY: the kernel copies metadata into this live, bounded local buffer.
    // The size-valued addr argument is required by PTRACE_GET_SYSCALL_INFO.
    let count = unsafe {
        libc::ptrace(
            request,
            tid,
            NATIVE_SYSCALL_INFO_CAPACITY as *mut libc::c_void,
            raw.as_mut_ptr().cast::<libc::c_void>(),
        )
    };
    let count = usize::try_from(count)
        .ok()
        .filter(|v| *v <= raw.len())
        .ok_or_else(|| {
            format!(
                "Native syscall metadata unavailable or truncated: {}",
                std::io::Error::last_os_error()
            )
        })?;
    decode_native_syscall_info(&raw[..count])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeStdioDirection {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeMemoryRange {
    pub address: u64,
    pub length: usize,
}

fn range(address: u64, length: u64) -> Result<NativeMemoryRange> {
    let length = usize::try_from(length)
        .ok()
        .filter(|n| *n <= MAX_NATIVE_STDIO_TRANSFER)
        .ok_or("Native stdio transfer bound exceeded")?;
    if (length > 0 && address == 0) || address.checked_add(length as u64).is_none() {
        return Err("invalid Native stdio buffer range".into());
    }
    Ok(NativeMemoryRange { address, length })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeStdioBuffers {
    Scalar(NativeMemoryRange),
    Vector {
        table: NativeMemoryRange,
        count: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeStdioTransfer {
    pub direction: NativeStdioDirection,
    pub descriptor: u8,
    pub buffers: NativeStdioBuffers,
}

/// Select stdin reads and stdout writes only. Other descriptors, including
/// private state-file reads, never become candidate memory ranges here.
pub fn native_stdio_transfer(entry: NativeSyscallEntry) -> Result<Option<NativeStdioTransfer>> {
    let (direction, descriptor, vector) = match (entry.number, entry.arguments[0]) {
        (63, 0) => (NativeStdioDirection::Read, 0, false),
        (64, 1) => (NativeStdioDirection::Write, 1, false),
        (65, 0) => (NativeStdioDirection::Read, 0, true),
        (66, 1) => (NativeStdioDirection::Write, 1, true),
        _ => return Ok(None),
    };
    let address = entry.arguments[1];
    let count = entry.arguments[2];
    let buffers = if vector {
        let count = usize::try_from(count)
            .ok()
            .filter(|n| *n <= MAX_NATIVE_STDIO_IOVECS)
            .ok_or("Native stdio iovec count exceeded")?;
        NativeStdioBuffers::Vector {
            table: range(address, (count * 16) as u64)?,
            count,
        }
    } else {
        NativeStdioBuffers::Scalar(range(address, count)?)
    };
    Ok(Some(NativeStdioTransfer {
        direction,
        descriptor,
        buffers,
    }))
}

/// Decode a previously bounded 64-bit little-endian iovec table. This does
/// not read tracee memory. The aggregate data bound applies across vectors.
pub fn decode_native_iovecs(raw: &[u8], count: usize) -> Result<Vec<NativeMemoryRange>> {
    if count > MAX_NATIVE_STDIO_IOVECS || raw.len() != count * 16 {
        return Err("exact bounded Native iovec table required".into());
    }
    let mut total = 0usize;
    let mut output = Vec::with_capacity(count);
    for row in raw.chunks_exact(16) {
        let buffer = range(u64_at(row, 0)?, u64_at(row, 8)?)?;
        total = total
            .checked_add(buffer.length)
            .ok_or("Native iovec length overflow")?;
        if total > MAX_NATIVE_STDIO_TRANSFER {
            return Err("aggregate Native stdio transfer bound exceeded".into());
        }
        output.push(buffer);
    }
    Ok(output)
}

/// A failed syscall supplies no completed bytes. Short success transfers only
/// its returned prefix; neither a request length nor an error invents data.
pub fn completed_native_stdio_bytes(
    result: i64,
    is_error: bool,
    requested: usize,
) -> Result<Option<usize>> {
    if requested > MAX_NATIVE_STDIO_TRANSFER {
        return Err("Native stdio completion bound exceeded".into());
    }
    if is_error {
        if !(-4095..=-1).contains(&result) {
            return Err("invalid Linux Native stdio error result".into());
        }
        return Ok(None);
    }
    usize::try_from(result)
        .ok()
        .filter(|n| *n <= requested)
        .map(Some)
        .ok_or_else(|| "Native stdio completion exceeds submitted buffers".into())
}

#[derive(Debug, Default)]
pub struct NativeSyscallSequence {
    pending: Option<NativeSyscallEntry>,
    exec_boundary: bool,
    ended: bool,
}

impl NativeSyscallSequence {
    pub fn after_exec() -> Self {
        Self {
            pending: None,
            exec_boundary: true,
            ended: false,
        }
    }

    /// An exec stop can be followed by its successful syscall-exit stop.
    /// Only that first unpaired zero exit is allowed. Signals do not consume
    /// an entry or supply completed bytes; the owner keeps their real order.
    pub fn observe(
        &mut self,
        stop: NativeSyscallStop,
    ) -> Result<Option<(NativeSyscallEntry, i64, bool)>> {
        if self.ended {
            return Err("Native syscall sequence already ended".into());
        }
        match stop {
            NativeSyscallStop::Entry(entry) => {
                if self.pending.is_some() {
                    self.ended = true;
                    return Err("Native syscall entry lacks preceding exit".into());
                }
                self.exec_boundary = false;
                self.pending = Some(entry);
                Ok(None)
            }
            NativeSyscallStop::Exit { result, is_error } => {
                if let Some(entry) = self.pending.take() {
                    return Ok(Some((entry, result, is_error)));
                }
                if self.exec_boundary && result == 0 && !is_error {
                    self.exec_boundary = false;
                    return Ok(None);
                }
                self.ended = true;
                Err("Native syscall exit lacks observed entry".into())
            }
        }
    }

    /// Call only after the owner observes actual death or exec replacement.
    /// A pending call is returned as interrupted, never as completed I/O.
    pub fn finish(&mut self) -> Result<Option<NativeSyscallEntry>> {
        if self.ended {
            return Err("Native syscall sequence already ended".into());
        }
        self.ended = true;
        Ok(self.pending.take())
    }
}

#[cfg(test)]
#[path = "native_stdio_syscall_tests.rs"]
mod tests;
