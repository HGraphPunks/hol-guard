//! Ineligible Root launcher for one SDK tap child. The caller still owns the
//! job lease, fixed cgroup, listener, controller mount and terminal pin.

use crate::linux_process::{observe_process, parse_proc_stat, valid_cgroup};
use crate::sdk_wire_peer::{
    authenticate_sdk_relay_peer_ineligible, bind_sdk_relay_to_ancestor_ineligible, SdkWirePeerPin,
};
use crate::sdk_wire_pipe::read_sdk_tap_frame_pipe_ineligible;
use crate::sdk_wire_tap::SdkWireObservation;
use crate::{hex, BoottimeDeadline, OwnedSdkTapCgroup};
use rustix::fs::{fstat, open, FileType, Mode, OFlags, Stat};
use rustix::process::{geteuid, pidfd_open, Pid, PidfdFlags};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAX_EXECUTABLE_BYTES: u64 = 32 * 1024 * 1024;
const READ_POLL: Duration = Duration::from_millis(250);
const TAP_UID: u32 = 10001;
const TAP_GID: u32 = 10001;
const ARG_COUNT: usize = 14;

pub struct HeldSdkTapExecutable {
    descriptor: OwnedFd,
    snapshot: Stat,
    sha256: String,
}

impl HeldSdkTapExecutable {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    fn recheck(&self) -> Result<(), String> {
        let current = fstat(&self.descriptor).map_err(|error| error.to_string())?;
        if !same_file(&current, &self.snapshot) {
            return Err("SDK tap executable inode or metadata changed".to_owned());
        }
        Ok(())
    }
}

fn same_file(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

/// Hold and hash the exact Root-owned child ELF before any SDK socket is
/// accepted. Only the final path component is protected from symlinks here;
/// deployment ancestry and the outside SHA remain the worker caller's pins.
pub fn open_pinned_sdk_tap_executable_ineligible(
    path: &Path,
    expected_sha256: &str,
) -> Result<HeldSdkTapExecutable, String> {
    if geteuid().as_raw() != 0 || !hex(expected_sha256, 64) || !path.is_absolute() {
        return Err("Root and outside SDK tap executable pin required".to_owned());
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("SDK tap executable unavailable: {error}"))?;
    let before = fstat(&descriptor).map_err(|error| error.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_mode & 0o7777 != 0o555
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > MAX_EXECUTABLE_BYTES
    {
        return Err("SDK tap executable lacks fixed Root-owned mode".to_owned());
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::new();
    file.by_ref()
        .take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| error.to_string())?;
    let after = fstat(&file).map_err(|error| error.to_string())?;
    let actual = format!("{:x}", Sha256::digest(&raw));
    if raw.len() as i64 != before.st_size
        || !same_file(&before, &after)
        || actual != expected_sha256
    {
        return Err("SDK tap executable bytes differ from outside pin".to_owned());
    }
    Ok(HeldSdkTapExecutable {
        descriptor: file.into(),
        snapshot: after,
        sha256: actual,
    })
}

struct DeadlineReader<'a> {
    stream: &'a UnixStream,
    deadline: &'a BoottimeDeadline,
    cancellation: &'a AtomicBool,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.cancellation.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "SDK tap cancelled",
                ));
            }
            match self.deadline.remaining() {
                Ok(remaining) if remaining > Duration::ZERO => {}
                _ => return Err(io::Error::new(io::ErrorKind::TimedOut, "SDK tap deadline")),
            }
            match self.stream.read(output) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                result => return result,
            }
        }
    }
}

fn process_start(pid: u32, expected_cgroup: &str) -> Result<u64, String> {
    if !valid_cgroup(expected_cgroup) {
        return Err("outside SDK tap child cgroup pin required".to_owned());
    }
    let raw = std::fs::read(format!("/proc/{pid}/stat")).map_err(|error| error.to_string())?;
    let parsed = parse_proc_stat(&raw, pid).ok_or("SDK tap child start tick unavailable")?;
    observe_process(pid, parsed.start_ticks, expected_cgroup)
        .map_err(|error| format!("SDK tap child kernel identity unavailable: {error:?}"))?;
    Ok(parsed.start_ticks)
}

fn kill_and_reap(child: &mut Child) -> Result<(), String> {
    let _ = child.kill();
    let began = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if began.elapsed() < Duration::from_secs(3) => {
                thread::sleep(Duration::from_millis(20))
            }
            Ok(None) => return Err("SDK tap child reap uncertain after SIGKILL".to_owned()),
            Err(error) => return Err(format!("SDK tap child reap uncertain: {error}")),
        }
    }
}

fn wait_success(
    child: &mut Child,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<(), String> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(format!("SDK tap child exited unsuccessfully: {status}"))
            }
            Ok(None) => {}
            Err(error) => return Err(format!("SDK tap child wait unavailable: {error}")),
        }
        if cancellation.load(Ordering::Acquire) {
            return Err("SDK tap child cancelled before exit".to_owned());
        }
        let remaining = deadline.remaining().map_err(|error| error.to_string())?;
        if remaining == Duration::ZERO {
            return Err("SDK tap child exceeded job deadline".to_owned());
        }
        thread::sleep(remaining.min(Duration::from_millis(20)));
    }
}

/// Run one already accepted SDK connection under a Root-held exact executable
/// and reparse the child report. The caller must retain the lease/listeners,
/// separately pin the job cgroup and terminal, and ensure descendants are gone.
#[allow(clippy::too_many_arguments)]
pub fn run_pinned_sdk_tap_child_ineligible(
    executable: &HeldSdkTapExecutable,
    sdk_connection: UnixStream,
    native_directory: OwnedFd,
    family: &str,
    sdk_relay: &SdkWirePeerPin,
    sdk_ancestor: &SdkWirePeerPin,
    native_frontdoor: &SdkWirePeerPin,
    child_cgroup: &str,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<(SdkWireObservation, SdkWirePeerPin), String> {
    run_pinned_sdk_tap_child_impl(
        executable,
        sdk_connection,
        native_directory,
        family,
        sdk_relay,
        sdk_ancestor,
        native_frontdoor,
        child_cgroup,
        None,
        deadline,
        cancellation,
    )
}

/// Attach the exact pinned child to a distinct one-use tap cgroup before
/// dropping UID/GID. The Root worker still owns cleanup under its lease.
#[allow(clippy::too_many_arguments)]
pub fn run_pinned_sdk_tap_child_in_group_ineligible(
    executable: &HeldSdkTapExecutable,
    sdk_connection: UnixStream,
    native_directory: OwnedFd,
    family: &str,
    sdk_relay: &SdkWirePeerPin,
    sdk_ancestor: &SdkWirePeerPin,
    native_frontdoor: &SdkWirePeerPin,
    group: &OwnedSdkTapCgroup,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<(SdkWireObservation, SdkWirePeerPin), String> {
    run_pinned_sdk_tap_child_impl(
        executable,
        sdk_connection,
        native_directory,
        family,
        sdk_relay,
        sdk_ancestor,
        native_frontdoor,
        group.path(),
        Some(group),
        deadline,
        cancellation,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_pinned_sdk_tap_child_impl(
    executable: &HeldSdkTapExecutable,
    sdk_connection: UnixStream,
    native_directory: OwnedFd,
    family: &str,
    sdk_relay: &SdkWirePeerPin,
    sdk_ancestor: &SdkWirePeerPin,
    native_frontdoor: &SdkWirePeerPin,
    child_cgroup: &str,
    group: Option<&OwnedSdkTapCgroup>,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
) -> Result<(SdkWireObservation, SdkWirePeerPin), String> {
    if geteuid().as_raw() != 0
        || !matches!(family, "docs" | "mail")
        || !valid_cgroup(child_cgroup)
        || cancellation.load(Ordering::Acquire)
        || deadline.remaining().map_err(|error| error.to_string())? == Duration::ZERO
    {
        return Err("Root SDK tap launch pins or deadline invalid".to_owned());
    }
    executable.recheck()?;
    let sdk_peer = authenticate_sdk_relay_peer_ineligible(&sdk_connection, sdk_relay)?;
    bind_sdk_relay_to_ancestor_ineligible(&sdk_connection, &sdk_peer, sdk_ancestor)?;
    let (report_parent, report_child) = UnixStream::pair().map_err(|error| error.to_string())?;
    report_parent
        .set_read_timeout(Some(READ_POLL))
        .map_err(|error| error.to_string())?;
    let passed = [
        sdk_connection.as_raw_fd(),
        native_directory.as_raw_fd(),
        report_child.as_raw_fd(),
    ];
    let arguments = [
        "gauntlet-sdk-tap-child".to_owned(),
        family.to_owned(),
        passed[0].to_string(),
        passed[1].to_string(),
        passed[2].to_string(),
        sdk_relay.pid.to_string(),
        sdk_relay.start_ticks.to_string(),
        sdk_relay.cgroup.clone(),
        sdk_ancestor.pid.to_string(),
        sdk_ancestor.start_ticks.to_string(),
        sdk_ancestor.cgroup.clone(),
        native_frontdoor.pid.to_string(),
        native_frontdoor.start_ticks.to_string(),
        native_frontdoor.cgroup.clone(),
    ];
    let arguments = arguments
        .iter()
        .map(|argument| {
            CString::new(argument.as_str()).map_err(|_| "invalid tap argument".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let argument_ptrs = arguments
        .iter()
        .map(|argument| argument.as_ptr() as usize)
        .collect::<Vec<_>>();
    let executable_fd = executable.descriptor.as_raw_fd();
    let mut command = Command::new("/usr/bin/false");
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(group) = group {
        if group.path() != child_cgroup {
            return Err("SDK tap cgroup differs from held one-use group".to_owned());
        }
        group
            .attach_child(&mut command)
            .map_err(|error| error.to_string())?;
    }
    // SAFETY: the child only executes fixed syscalls over prebuilt pointers
    // and held FDs. The exact hashed executable is invoked by descriptor;
    // no child path lookup or candidate-controlled environment is used.
    unsafe {
        command.pre_exec(move || {
            let _keep_arguments = &arguments;
            for fd in passed {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::setsid() < 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(TAP_GID, TAP_GID, TAP_GID) != 0
                || libc::setresuid(TAP_UID, TAP_UID, TAP_UID) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            let mut argv = [std::ptr::null(); ARG_COUNT + 1];
            for (slot, pointer) in argv.iter_mut().zip(&argument_ptrs) {
                *slot = *pointer as *const libc::c_char;
            }
            let env = [std::ptr::null::<libc::c_char>()];
            libc::syscall(
                libc::SYS_execveat,
                executable_fd,
                c"".as_ptr(),
                argv.as_ptr(),
                env.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            Err(io::Error::last_os_error())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("pinned SDK tap child spawn failed: {error}"))?;
    drop(report_child);
    let pid = child.id();
    let result = (|| {
        let child_start = process_start(pid, child_cgroup)?;
        let pidfd = pidfd_open(
            Pid::from_raw(i32::try_from(pid).map_err(|_| "invalid tap child PID")?)
                .ok_or("invalid tap child PID")?,
            PidfdFlags::empty(),
        )
        .map_err(|error| format!("SDK tap child pidfd unavailable: {error}"))?;
        sdk_peer.recheck(&sdk_connection)?;
        let report = read_sdk_tap_frame_pipe_ineligible(
            DeadlineReader {
                stream: &report_parent,
                deadline,
                cancellation,
            },
            family,
        )?;
        if cancellation.load(Ordering::Acquire) {
            return Err("SDK tap child cancelled".to_owned());
        }
        executable.recheck()?;
        wait_success(&mut child, deadline, cancellation)?;
        let _held_pidfd = pidfd;
        Ok((
            report,
            SdkWirePeerPin {
                pid,
                start_ticks: child_start,
                cgroup: child_cgroup.to_owned(),
            },
        ))
    })();
    if result.is_err() {
        kill_and_reap(&mut child)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_root_executable_pin() {
        assert!(open_pinned_sdk_tap_executable_ineligible(
            Path::new("/nonexistent-sdk-tap-child"),
            &"0".repeat(64)
        )
        .is_err());
    }
}
