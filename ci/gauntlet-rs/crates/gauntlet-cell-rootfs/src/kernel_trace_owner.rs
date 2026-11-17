//! Accept live trace stops only for the recorder TID established by the owner.
use crate::Result;

pub(crate) fn verify(raw: &[u8], expected: u32) -> Result<()> {
    if expected == 0 || expected > i32::MAX as u32 || raw.len() > 65536 {
        return Err("positive bounded recorder TID required".into());
    }
    let text = std::str::from_utf8(raw).map_err(|_| "kernel tracer status UTF-8")?;
    let fields = text
        .lines()
        .filter_map(|line| line.strip_prefix("TracerPid:"))
        .collect::<Vec<_>>();
    if fields.len() != 1 || fields[0].trim().parse::<u32>().ok() != Some(expected) {
        return Err("kernel tracer differs from the owned recorder thread".into());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) fn ticks(proc: &std::os::fd::OwnedFd, pid: u32, tracer: Option<u32>) -> Result<u64> {
    let raw = crate::kernel_process::read_at(proc, "stat", 4096)?;
    if let Some(owner) = tracer {
        verify(
            &crate::kernel_process::read_at(proc, "status", 65536)?,
            owner,
        )?;
        crate::native_trace_identity::start_ticks(&raw, pid)
    } else {
        crate::kernel_status::start_ticks(&raw, pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_foreign_zero_and_duplicate_tracers_cannot_authorize_stopped_identity() {
        assert!(verify(b"Name:\tactor\nTracerPid:\t42\n", 42).is_ok());
        for raw in [
            b"TracerPid:\t0\n".as_slice(),
            b"TracerPid:\t43\n",
            b"Name:\tactor\n",
            b"TracerPid:\t42\nTracerPid:\t42\n",
            b"TracerPid:\ttrue\n",
        ] {
            assert!(verify(raw, 42).is_err());
        }
        assert!(verify(b"TracerPid:\t0\n", 0).is_err());
    }
}
