//! Ineligible Root probe for a direct PID-1 SDK tap child. This does not
//! dispatch the MCP data plane; it proves the clone/cgroup/mount lifecycle
//! needed before the current child can stop relying on host-visible PIDs.

use crate::sdk_wire_spawn::{process_start, verify_tap_mounts};
use crate::OwnedSdkTapCgroup;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const TAP_UID: u32 = 10001;
const TAP_GID: u32 = 10001;
const PROC_MAGIC: libc::c_long = 0x9fa0;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

// linux/sched.h clone_args, version 0.8. All fields are u64 and the complete
// layout is passed to clone3; unused fields are initialized to zero.
#[repr(C)]
#[derive(Default)]
#[allow(dead_code)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Report one fixed error byte and leave without executing Rust cleanup in
/// the cloned child. The parent will reap it and drain the held cgroup.
unsafe fn child_fail(ready_fd: RawFd, code: u8) -> ! {
    // SAFETY: the one-byte stack value is valid until the immediate _exit.
    unsafe {
        libc::write(ready_fd, (&code as *const u8).cast(), 1);
        libc::_exit(2);
    }
}

/// The cloned child calls only fixed libc syscalls before notifying Root.
/// It has no candidate input, allocator call, runtime lock or path selection.
unsafe fn probe_child(ready_fd: RawFd, release_fd: RawFd) -> ! {
    // SAFETY: all mount strings are static NUL-terminated bytes, and the
    // process already has distinct PID/mount namespaces from clone3.
    unsafe {
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        ) != 0
        {
            child_fail(ready_fd, 10);
        }
        if libc::mount(
            c"tmpfs".as_ptr(),
            c"/tmp".as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            c"size=1048576,mode=0700,uid=10001,gid=10001"
                .as_ptr()
                .cast(),
        ) != 0
        {
            child_fail(ready_fd, 11);
        }
        for path in [c"/home", c"/opt"] {
            if libc::mount(
                c"tmpfs".as_ptr(),
                path.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"size=4096,mode=0000,uid=0,gid=0".as_ptr().cast(),
            ) != 0
            {
                child_fail(ready_fd, 12);
            }
        }
        if libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        ) != 0
        {
            child_fail(ready_fd, 13);
        }
        if libc::setsid() < 0
            || libc::setgroups(0, std::ptr::null()) != 0
            || libc::setresgid(TAP_GID, TAP_GID, TAP_GID) != 0
            || libc::setresuid(TAP_UID, TAP_UID, TAP_UID) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        {
            child_fail(ready_fd, 14);
        }
        libc::umask(0o077);
        if libc::getpid() != 1 {
            child_fail(ready_fd, 15);
        }
        let proc_other = libc::open(c"/proc/2/stat".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if proc_other >= 0 {
            libc::close(proc_other);
            child_fail(ready_fd, 16);
        }
        for path in [c"/home", c"/opt"] {
            let descriptor = libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            );
            if descriptor >= 0 {
                libc::close(descriptor);
                child_fail(ready_fd, 17);
            }
        }
        let temporary = libc::open(
            c"/tmp".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        );
        if temporary < 0 {
            child_fail(ready_fd, 18);
        }
        libc::close(temporary);
        let ready = [1_u8];
        if libc::write(ready_fd, ready.as_ptr().cast(), 1) != 1 {
            libc::_exit(2);
        }
        let mut release = [0_u8];
        if libc::read(release_fd, release.as_mut_ptr().cast(), 1) != 1 || release[0] != 1 {
            libc::_exit(2);
        }
        libc::_exit(0);
    }
}

fn verify_pid_namespace(pid: u32) -> Result<(), String> {
    let parent = fs::read_link("/proc/self/ns/pid").map_err(|error| error.to_string())?;
    let child = fs::read_link(format!("/proc/{pid}/ns/pid"))
        .map_err(|error| format!("tap PID namespace unavailable: {error}"))?;
    if parent == child {
        return Err("tap child shares Root PID namespace".to_owned());
    }
    let status =
        fs::read_to_string(format!("/proc/{pid}/status")).map_err(|error| error.to_string())?;
    if status.len() > 8192 {
        return Err("tap child proc status exceeds fixed bound".to_owned());
    }
    let nested = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .ok_or("tap child NSpid relation missing")?
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "tap child NSpid relation invalid")?;
    if nested.len() != 2 || nested[0] != pid || nested[1] != 1 {
        return Err("tap child is not PID 1 in its namespace".to_owned());
    }
    for field in ["Uid:", "Gid:"] {
        let expected = if field == "Uid:" { TAP_UID } else { TAP_GID };
        let values = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .ok_or("tap child credential field missing")?
            .split_ascii_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "tap child credentials invalid")?;
        if values != [expected; 4] {
            return Err("tap child credentials differ from fixed UID/GID".to_owned());
        }
    }
    if !status
        .lines()
        .filter_map(|line| line.strip_prefix("NoNewPrivs:"))
        .any(|value| value.trim() == "1")
        || !status
            .lines()
            .filter_map(|line| line.strip_prefix("Groups:"))
            .any(|value| value.trim().is_empty())
    {
        return Err("tap child privilege drop differs from fixed profile".to_owned());
    }
    fs::metadata(format!("/proc/{pid}/root/proc/1/stat"))
        .map_err(|error| format!("private proc PID 1 unavailable: {error}"))?;
    match fs::metadata(format!("/proc/{pid}/root/proc/2/stat")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("private proc exposes another PID".to_owned()),
    }
    let path = std::ffi::CString::new(format!("/proc/{pid}/root/proc"))
        .map_err(|error| error.to_string())?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let mut mount = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is NUL-terminated and outputs are initialized by success.
    if unsafe { libc::statfs(path.as_ptr(), filesystem.as_mut_ptr()) } != 0
        || unsafe { libc::statvfs(path.as_ptr(), mount.as_mut_ptr()) } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: both calls succeeded above.
    let filesystem = unsafe { filesystem.assume_init() };
    let mount = unsafe { mount.assume_init() };
    let flags = libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    if filesystem.f_type != PROC_MAGIC || mount.f_flag & flags != flags {
        return Err("private proc mount differs from fixed profile".to_owned());
    }
    Ok(())
}

fn probe_in_group(group: &OwnedSdkTapCgroup) -> Result<(u32, u64), String> {
    let (mut ready_parent, ready_child) = UnixStream::pair().map_err(|error| error.to_string())?;
    let (mut release_parent, release_child) =
        UnixStream::pair().map_err(|error| error.to_string())?;
    ready_parent
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let mut raw_pidfd: libc::c_int = -1;
    let mut args = CloneArgs {
        flags: libc::CLONE_NEWPID as u64
            | libc::CLONE_NEWNS as u64
            | libc::CLONE_PIDFD as u64
            | CLONE_INTO_CGROUP,
        pidfd: (&mut raw_pidfd as *mut libc::c_int) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: group.clone_into_fd().map_err(|error| error.to_string())? as u64,
        ..CloneArgs::default()
    };
    // SAFETY: clone_args has the kernel ABI layout; the child calls only
    // fixed syscalls then _exit. CLONE_INTO_CGROUP attaches it atomically to
    // the previously verified, fixed-limit tap group.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            (&mut args as *mut CloneArgs).cast::<libc::c_void>(),
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if result < 0 {
        return Err(format!(
            "tap PID namespace clone failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if result == 0 {
        // SAFETY: this is the direct cloned child, with no Rust unwinding.
        unsafe { probe_child(ready_child.as_raw_fd(), release_child.as_raw_fd()) }
    }
    let pid = u32::try_from(result).map_err(|_| "invalid cloned tap PID")?;
    if raw_pidfd < 0 {
        // The child has not been reaped, so its PID cannot yet be reused.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0) };
        return Err("clone3 returned no child pidfd".to_owned());
    }
    // SAFETY: CLONE_PIDFD returned one owned descriptor into raw_pidfd.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    drop(ready_child);
    drop(release_child);
    let observed = (|| {
        let mut ready = [0_u8];
        ready_parent
            .read_exact(&mut ready)
            .map_err(|error| format!("PID namespace child did not become ready: {error}"))?;
        if ready[0] != 1 {
            return Err(format!(
                "PID namespace child refused fixed profile at step {}",
                ready[0]
            ));
        }
        let start = process_start(pid, group.path())?;
        verify_tap_mounts(pid)?;
        verify_pid_namespace(pid)?;
        release_parent
            .write_all(&[1])
            .map_err(|error| error.to_string())?;
        let mut descriptors = [PollFd::new(&pidfd, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 3,
            tv_nsec: 0,
        };
        if poll(&mut descriptors, Some(&timeout)).map_err(|error| error.to_string())? != 1 {
            return Err("PID namespace child did not exit by deadline".to_owned());
        }
        Ok(start)
    })();
    if observed.is_err() {
        // The unreaped child still owns this PID; a failed probe must not
        // leave PID 1 alive inside the one-use tap cgroup.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: pid is the direct child returned by clone3, not a guessed PID.
    if unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) } != pid as libc::pid_t {
        return Err("PID namespace child could not be reaped".to_owned());
    }
    let start = observed?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err("PID namespace child exited outside fixed profile".to_owned());
    }
    Ok((pid, start))
}

/// Inert direct-clone probe. It never runs candidate bytes or a model, and
/// leaves the one-use tap cgroup absent only after a verified drain.
pub fn probe_owned_tap_pid_namespace_ineligible(run_id: &str) -> Result<Value, String> {
    if geteuid().as_raw() != 0 {
        return Err("Linux Root PID namespace probe required".to_owned());
    }
    let mut group = OwnedSdkTapCgroup::create(run_id).map_err(|error| error.to_string())?;
    let observed = probe_in_group(&group);
    if observed.is_err() {
        group.kill().map_err(|error| error.to_string())?;
    }
    group
        .drain_and_remove()
        .map_err(|error| format!("tap PID namespace cleanup uncertain: {error}"))?;
    let (host_pid, start_ticks) = observed?;
    Ok(json!({
        "schema":"hol-gauntlet-sdk-tap-pidns-probe.v1",
        "run_id":run_id,
        "host_pid":host_pid,
        "start_ticks":start_ticks,
        "tap_cgroup":format!("/system.slice/hol-gauntlet-rust-tap-{run_id}"),
        "cloned_direct_child_pid":1,
        "pidfd_held":true,
        "distinct_pid_and_mount_namespaces":true,
        "private_proc_only_pid_one":true,
        "private_path_masks_verified":true,
        "uid":TAP_UID,
        "gid":TAP_GID,
        "tap_cgroup_removed":true,
        "candidate_executed":false,
        "execution_eligible":false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_args_have_the_full_linux_u64_layout() {
        assert_eq!(std::mem::size_of::<CloneArgs>(), 11 * 8);
    }

    #[test]
    #[ignore = "requires the dedicated Root Linux ARM VM with cgroup-v2 clone3 support"]
    fn direct_pid_one_child_is_reaped_and_its_tap_group_removed() {
        let run_id = format!("{:016x}", ((std::process::id() as u64) << 32) | 0x5dba_2211);
        let proof = probe_owned_tap_pid_namespace_ineligible(&run_id).unwrap();
        println!("{proof}");
        assert_eq!(proof["cloned_direct_child_pid"], 1);
        assert_eq!(proof["tap_cgroup_removed"], true);
    }
}
