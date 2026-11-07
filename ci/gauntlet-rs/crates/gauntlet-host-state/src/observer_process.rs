//! Cancellable, bounded read-only probes with exclusive child wait custody.
//! The child stays unreaped until its owned process group has been stopped.

use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use rustix::io::Errno;
use rustix::process::{
    kill_process, kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions,
};
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeError {
    Unavailable,
    Failed,
    TooLarge,
    TimedOut,
    Cancelled,
}

struct Owner {
    child: Child,
    pid: Pid,
    custody: bool,
}

#[cfg(target_os = "macos")]
fn group_has_no_other_members(pid: Pid) -> bool {
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_listpids(kind: u32, info: u32, buffer: *mut libc::c_void, bytes: i32) -> i32;
    }
    // PROC_PGRP_ONLY = 2 in the platform's sys/proc_info.h. Keep the exited
    // leader unreaped while querying; its PID/group identity cannot be reused.
    for _ in 0..2 {
        let mut pids = [0_i32; 256];
        unsafe {
            *libc::__error() = 0;
        }
        let bytes = unsafe {
            proc_listpids(
                2,
                pid.as_raw_nonzero().get() as u32,
                pids.as_mut_ptr().cast(),
                std::mem::size_of_val(&pids) as i32,
            )
        };
        if bytes < 0
            || bytes as usize >= std::mem::size_of_val(&pids)
            || bytes as usize % std::mem::size_of::<i32>() != 0
            || (bytes == 0 && std::io::Error::last_os_error().raw_os_error() != Some(0))
        {
            return false;
        }
        if pids[..bytes as usize / std::mem::size_of::<i32>()]
            .iter()
            .any(|member| *member != 0 && *member != pid.as_raw_nonzero().get())
        {
            return false;
        }
    }
    true
}

#[cfg(not(target_os = "macos"))]
fn group_has_no_other_members(_pid: Pid) -> bool {
    false
}

fn require_wait_custody() -> Result<(), ProbeError> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0
        || action.sa_sigaction == libc::SIG_IGN
        || action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err(ProbeError::Unavailable);
    }
    Ok(())
}

impl Owner {
    fn exited(&mut self) -> Result<bool, ProbeError> {
        if !self.custody {
            return Err(ProbeError::Unavailable);
        }
        match waitid(
            WaitId::Pid(self.pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(value) => Ok(value.is_some()),
            Err(Errno::INTR) => Ok(false),
            Err(Errno::CHILD) => {
                self.custody = false;
                Err(ProbeError::Unavailable)
            }
            Err(_) => Err(ProbeError::Unavailable),
        }
    }

    fn finish(&mut self) -> Result<ExitStatus, ProbeError> {
        // Check for a lost wait before signalling. The executable owns child
        // waits exclusively and retains normal SIGCHLD disposition throughout.
        let exited = self.exited()?;
        if let Err(error) = kill_process_group(self.pid, Signal::KILL) {
            // Darwin reports EPERM for a group containing only its zombie
            // leader. Accept this only after an independent kernel inventory;
            // an unobserved or surviving member still makes cleanup uncertain.
            if error != Errno::SRCH
                && !(error == Errno::PERM && exited && group_has_no_other_members(self.pid))
            {
                return Err(ProbeError::Unavailable);
            }
        }
        if !exited {
            if let Err(error) = kill_process(self.pid, Signal::KILL) {
                if error != Errno::SRCH {
                    return Err(ProbeError::Unavailable);
                }
            }
        }
        let status = self.child.wait().map_err(|_| ProbeError::Unavailable)?;
        self.custody = false;
        Ok(status)
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        if self.custody {
            let _ = self.finish();
        }
    }
}

fn read_available(
    reader: &mut impl Read,
    kept: &mut Vec<u8>,
    limit: usize,
) -> Result<bool, ProbeError> {
    let mut buffer = [0_u8; 4096];
    // Revisit cancellation/deadlines even when a child continuously writes.
    for _ in 0..16 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if kept.len().saturating_add(count) > limit {
                    return Err(ProbeError::TooLarge);
                }
                kept.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ProbeError::Unavailable),
        }
    }
    Ok(false)
}

pub(crate) fn run_probe(
    argv: &[String],
    timeout: Duration,
    output_limit: usize,
    environment: &[(&str, &str)],
    cancel: &AtomicBool,
) -> Result<Vec<u8>, ProbeError> {
    if cancel.load(Ordering::Acquire) {
        return Err(ProbeError::Cancelled);
    }
    let executable = argv
        .first()
        .filter(|value| Path::new(value).is_absolute())
        .ok_or(ProbeError::Unavailable)?;
    require_wait_custody()?;
    let child = Command::new(executable)
        .args(&argv[1..])
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| ProbeError::Unavailable)?;
    let pid = Pid::from_raw(child.id() as i32).ok_or(ProbeError::Unavailable)?;
    let mut owner = Owner {
        child,
        pid,
        custody: true,
    };
    let mut stdout = owner.child.stdout.take().ok_or(ProbeError::Unavailable)?;
    let mut stderr = owner.child.stderr.take().ok_or(ProbeError::Unavailable)?;
    for descriptor in [
        &stdout as &dyn std::os::fd::AsFd,
        &stderr as &dyn std::os::fd::AsFd,
    ] {
        let flags = fcntl_getfl(descriptor).map_err(|_| ProbeError::Unavailable)?;
        fcntl_setfl(descriptor, flags | OFlags::NONBLOCK).map_err(|_| ProbeError::Unavailable)?;
    }
    let started = Instant::now();
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let mut completed = None;
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(ProbeError::Cancelled);
        }
        if started.elapsed() >= timeout {
            return Err(ProbeError::TimedOut);
        }
        let stdout_done = read_available(&mut stdout, &mut output, output_limit)?;
        let stderr_done = read_available(&mut stderr, &mut diagnostics, 1500)?;
        if completed.is_none() && owner.exited()? {
            completed = Some(owner.finish()?);
        }
        if let Some(status) = completed {
            if stdout_done && stderr_done {
                return if status.success() {
                    Ok(output)
                } else {
                    Err(ProbeError::Failed)
                };
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn exit_output_failure_and_bounds_are_observed_without_raw_diagnostics() {
        let cancel = AtomicBool::new(false);
        let shell = |script: &str| vec!["/bin/sh".into(), "-c".into(), script.into()];
        assert_eq!(
            run_probe(
                &shell("printf observed"),
                Duration::from_secs(2),
                64,
                &[],
                &cancel
            ),
            Ok(b"observed".to_vec())
        );
        assert_eq!(
            run_probe(
                &shell("printf private-diagnostic >&2; exit 7"),
                Duration::from_secs(2),
                64,
                &[],
                &cancel
            ),
            Err(ProbeError::Failed)
        );
        assert_eq!(
            run_probe(
                &shell("while :; do printf overflowing; done"),
                Duration::from_secs(2),
                64,
                &[],
                &cancel
            ),
            Err(ProbeError::TooLarge)
        );
        assert_eq!(
            run_probe(
                &shell("while :; do :; done"),
                Duration::from_millis(100),
                64,
                &[],
                &cancel
            ),
            Err(ProbeError::TimedOut)
        );
        cancel.store(true, Ordering::Release);
        assert_eq!(
            run_probe(&shell("exit 0"), Duration::from_secs(2), 64, &[], &cancel),
            Err(ProbeError::Cancelled)
        );
    }

    #[test]
    fn cancellation_and_success_stop_owned_background_descendants_before_reaping() {
        for cancel_mid_run in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let marker = temp.path().join("escaped");
            let script =
                "(sleep 0.5; printf leaked > \"$1\") & if [ \"$2\" = wait ]; then wait; fi";
            let argv = vec![
                "/bin/sh".into(),
                "-c".into(),
                script.into(),
                "probe-test".into(),
                marker.to_string_lossy().into_owned(),
                if cancel_mid_run { "wait" } else { "exit" }.into(),
            ];
            let cancel = AtomicBool::new(false);
            std::thread::scope(|scope| {
                if cancel_mid_run {
                    scope.spawn(|| {
                        std::thread::sleep(Duration::from_millis(100));
                        cancel.store(true, Ordering::Release);
                    });
                }
                let result = run_probe(&argv, Duration::from_secs(2), 64, &[], &cancel);
                if cancel_mid_run {
                    assert_eq!(result, Err(ProbeError::Cancelled));
                } else {
                    assert_eq!(result, Ok(Vec::new()));
                }
            });
            std::thread::sleep(Duration::from_millis(650));
            assert!(
                !marker.exists(),
                "probe descendant outlived its owned process group"
            );
            assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        }
    }
}
