//! Bounded capture and direct-child reap for fixed helper probes. Production
//! job deadlines and descendant cleanup require separate worker evidence.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use crate::CgroupProbeError;
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use std::io;
use std::os::fd::OwnedFd;
use std::process::{Child, Output};
use std::thread;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(20);
const REAP_WAIT: Duration = Duration::from_secs(3);

pub(crate) fn probe_interrupted(
    cancelled: bool,
    initial_epoch: usize,
    current_epoch: usize,
    owned_cleanup: bool,
) -> bool {
    (!owned_cleanup && cancelled) || initial_epoch != current_epoch
}

fn reap_child_bounded(child: &mut Child) -> io::Result<()> {
    let mut started = Instant::now();
    let mut escalated = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if started.elapsed() < REAP_WAIT => thread::sleep(POLL),
            Ok(None) if !escalated => {
                let _ = child.kill();
                escalated = true;
                started = Instant::now();
            }
            Ok(None) => return Err(io::Error::other("owned helper reap deadline exceeded")),
            Err(_) => {
                let _ = child.kill();
                return Err(io::Error::other("owned helper reap uncertain"));
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) fn reap_probe_child_bounded(child: &mut Child) -> Result<(), CgroupProbeError> {
    reap_child_bounded(child).map_err(|_| CgroupProbeError::Spawn)
}

fn drain(fd: &OwnedFd, bytes: &mut Vec<u8>, limit: usize) -> io::Result<bool> {
    loop {
        let mut buffer = [0u8; 4096];
        match rustix::io::read(fd, &mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) if n <= limit.saturating_sub(bytes.len()) => {
                bytes.extend_from_slice(&buffer[..n]);
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "owned helper output bound exceeded",
                ));
            }
            Err(rustix::io::Errno::AGAIN) => return Ok(false),
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// The caller constructs the fixed helper argv and null stdin. Cancellation
/// invalidates every exit status, including Podman's signal-handler 0 and 1.
pub(crate) fn capture_probe_output_bounded(
    child: &mut Child,
    timeout: Duration,
    limits: (usize, usize),
    cancelled: &impl Fn() -> bool,
) -> io::Result<Output> {
    let started = Instant::now();
    let check = || {
        if cancelled() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "owned helper inspection interrupted",
            ))
        } else if started.elapsed() >= timeout {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned helper inspection deadline exceeded",
            ))
        } else {
            Ok(())
        }
    };
    let result = (|| {
        check()?;
        let out: OwnedFd = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("owned helper stdout missing"))?
            .into();
        let err: OwnedFd = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("owned helper stderr missing"))?
            .into();
        for fd in [&out, &err] {
            fcntl_setfl(fd, fcntl_getfl(fd)? | OFlags::NONBLOCK)?;
        }
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            check()?;
            let a = drain(&out, &mut stdout, limits.0)?;
            let b = drain(&err, &mut stderr, limits.1)?;
            let status = child.try_wait()?;
            check()?;
            if let Some(status) = status.filter(|_| a && b) {
                let output = Output {
                    status,
                    stdout,
                    stderr,
                };
                check()?;
                return Ok(output);
            }
            thread::sleep(POLL);
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        reap_child_bounded(child)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    const SLEEP: &str = if cfg!(target_os = "macos") {
        "/bin/sleep"
    } else {
        "/usr/bin/sleep"
    };

    #[test]
    fn long_lived_child_is_killed_and_reaped_after_fixed_wait() {
        let mut child = Command::new(SLEEP).arg("30").spawn().unwrap();
        let result = reap_child_bounded(&mut child);
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert!(result.is_ok());
    }

    fn command(script: &str) -> Child {
        use std::process::Stdio;
        Command::new("/bin/sh")
            .args(["-c", script])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[test]
    fn cancellation_rejects_owned_helper_exit_zero_and_one_before_and_after_status() {
        use std::cell::Cell;
        for script in ["exit 0", "exit 1"] {
            for cancel_at in 0..=3 {
                let mut child = command(script);
                let expected = child.wait().unwrap();
                let checks = Cell::new(0);
                let cancelled = || {
                    let n = checks.get();
                    checks.set(n + 1);
                    n >= cancel_at
                };
                let result = capture_probe_output_bounded(
                    &mut child,
                    Duration::from_secs(1),
                    (4096, 4096),
                    &cancelled,
                );
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
                assert_eq!(child.try_wait().unwrap(), Some(expected));
            }
        }
    }

    #[test]
    fn cancellation_kills_and_reaps_only_the_pending_owned_helper() {
        use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};
        let mut child = Command::new(SLEEP)
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = cancelled.clone();
        let thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            signal.store(true, Ordering::Release);
        });
        let result =
            capture_probe_output_bounded(&mut child, Duration::from_secs(1), (4096, 4096), &|| {
                cancelled.load(Ordering::Acquire)
            });
        thread.join().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(child.try_wait().unwrap().is_some_and(|s| !s.success()));
    }

    #[test]
    fn inspection_keeps_both_output_bounds_and_reaps_at_deadline() {
        for script in ["printf abc", "printf abc >&2"] {
            let mut child = command(script);
            let result =
                capture_probe_output_bounded(&mut child, Duration::from_secs(1), (2, 2), &|| false);
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(child.try_wait().unwrap().is_some());
        }
        let mut child = command("while :; do :; done");
        let result = capture_probe_output_bounded(
            &mut child,
            Duration::from_millis(20),
            (4096, 4096),
            &|| false,
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn uninterrupted_owned_helper_preserves_real_exit_and_bounded_streams() {
        for code in 0..=1 {
            let mut child = command(if code == 0 {
                "printf out; printf err >&2; exit 0"
            } else {
                "printf out; printf err >&2; exit 1"
            });
            let output =
                capture_probe_output_bounded(&mut child, Duration::from_secs(1), (3, 3), &|| false)
                    .unwrap();
            assert_eq!(output.status.code(), Some(code));
            assert_eq!(output.stdout, b"out");
            assert_eq!(output.stderr, b"err");
        }
    }

    #[test]
    fn prior_cancellation_allows_owned_cleanup_but_new_interruption_is_unknown() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for code in ["exit 0", "exit 1"] {
            let epoch = AtomicUsize::new(7);
            let mut child = command(code);
            let output = capture_probe_output_bounded(
                &mut child,
                Duration::from_secs(1),
                (4096, 4096),
                &|| probe_interrupted(true, 7, epoch.load(Ordering::Acquire), true),
            )
            .unwrap();
            assert!(matches!(output.status.code(), Some(0 | 1)));
            let mut child = command(code);
            epoch.store(8, Ordering::Release);
            let result = capture_probe_output_bounded(
                &mut child,
                Duration::from_secs(1),
                (4096, 4096),
                &|| probe_interrupted(true, 7, epoch.load(Ordering::Acquire), true),
            );
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            assert!(child.try_wait().unwrap().is_some());
        }
        assert!(probe_interrupted(true, 7, 7, false));
    }
}
