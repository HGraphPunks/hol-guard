//! Fixed Linux observation operations. No memory/register/syscall mutation API.
use crate::native_trace_wait::{decode, Wait};
use crate::Result;
use std::ptr;

pub(super) fn thread_id() -> Result<u32> {
    u32::try_from(unsafe { libc::syscall(libc::SYS_gettid) })
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| "positive recorder kernel TID required".into())
}

#[cfg(target_env = "musl")]
type Request = libc::c_int;
#[cfg(not(target_env = "musl"))]
type Request = libc::c_uint;

fn call(request: Request, tid: u32, data: usize) -> Result<bool> {
    let tid = i32::try_from(tid)
        .ok()
        .filter(|n| *n > 0)
        .ok_or("positive trace TID required")?;
    let result = unsafe {
        libc::ptrace(
            request,
            tid,
            ptr::null_mut::<libc::c_void>(),
            data as *mut libc::c_void,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        // Losing a stop to SIGKILL is possible. Only a later final wait status
        // or the documented exec replacement can discharge this task.
        return Ok(false);
    }
    Err(format!("ptrace operation {request} on {tid}: {error}"))
}

pub(super) fn seize(tid: u32) -> Result<()> {
    seize_mode(tid, false)
}

pub(super) fn seize_stdio(tid: u32) -> Result<()> {
    seize_mode(tid, true)
}

fn seize_mode(tid: u32, stdio: bool) -> Result<()> {
    let mut options = libc::PTRACE_O_EXITKILL
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEEXIT
        | libc::PTRACE_O_TRACEVFORKDONE;
    if stdio {
        options |= libc::PTRACE_O_TRACESYSGOOD;
    }
    if !call(libc::PTRACE_SEIZE, tid, options as usize)? {
        return Err("owned actor disappeared before seize".into());
    }
    if !call(libc::PTRACE_INTERRUPT, tid, 0)? {
        return Err("owned actor disappeared before interrupt".into());
    }
    Ok(())
}

pub(super) fn resume(tid: u32, signal: u8) -> Result<bool> {
    if signal > 64 {
        return Err("invalid trace signal".into());
    }
    call(libc::PTRACE_CONT, tid, signal as usize)
}

pub(super) fn resume_syscall(tid: u32, signal: u8) -> Result<bool> {
    if signal > 64 {
        return Err("invalid trace signal".into());
    }
    call(libc::PTRACE_SYSCALL, tid, signal as usize)
}

pub(super) fn listen(tid: u32) -> Result<bool> {
    call(libc::PTRACE_LISTEN, tid, 0)
}

pub(super) fn message(tid: u32) -> Result<u64> {
    let mut value: libc::c_ulong = 0;
    let tid = i32::try_from(tid)
        .ok()
        .filter(|n| *n > 0)
        .ok_or("positive event TID required")?;
    if unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            tid,
            ptr::null_mut::<libc::c_void>(),
            &mut value,
        )
    } != 0
    {
        return Err(format!(
            "ptrace event message: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(value)
}

pub(super) enum WaitResult {
    Event(u32, Wait),
    Idle,
    Empty,
}

pub(super) fn wait() -> Result<WaitResult> {
    wait_mode(false)
}

pub(super) fn wait_stdio() -> Result<WaitResult> {
    wait_mode(true)
}

fn wait_mode(stdio: bool) -> Result<WaitResult> {
    let mut raw = 0;
    let pid = unsafe {
        libc::waitpid(
            -1,
            &mut raw,
            libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG,
        )
    };
    if pid > 0 {
        let event = if stdio {
            crate::native_trace_wait::decode_stdio(raw)?
        } else {
            decode(raw)?
        };
        return Ok(WaitResult::Event(pid as u32, event));
    }
    if pid == 0 {
        return Ok(WaitResult::Idle);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EINTR) {
        return Ok(WaitResult::Idle);
    }
    if error.raw_os_error() == Some(libc::ECHILD) {
        return Ok(WaitResult::Empty);
    }
    Err(format!("owned tracer wait: {error}"))
}
