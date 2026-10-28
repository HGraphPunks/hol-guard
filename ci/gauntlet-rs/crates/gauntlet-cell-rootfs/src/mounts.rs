//! Fixed Linux operations in an already verified private mount/net namespace.
use crate::{fs_input, Result};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const RO: libc::c_ulong = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;

pub(crate) fn mount(
    source: Option<&Path>,
    target: &Path,
    kind: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let source = source
        .map(|p| CString::new(p.as_os_str().as_bytes()))
        .transpose()
        .map_err(|_| "invalid mount source")?;
    let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| "invalid mount target")?;
    let kind = kind
        .map(CString::new)
        .transpose()
        .map_err(|_| "invalid mount type")?;
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(|_| "invalid mount data")?;
    // SAFETY: all pointers refer to live NUL-terminated strings or are null;
    // flags/data are fixed by the constructor, never supplied by the candidate.
    let status = unsafe {
        libc::mount(
            source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            kind.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        )
    };
    if status != 0 {
        return Err(format!(
            "private mount failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(crate) fn fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}
pub(crate) fn bind(source: &Path, target: &Path) -> Result<()> {
    mount(Some(source), target, None, libc::MS_BIND, None)?;
    mount(
        None,
        target,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | RO,
        None,
    )
}

pub(crate) fn tmpfs(target: &Path, flags: libc::c_ulong, data: &str) -> Result<()> {
    mount(
        Some(Path::new("tmpfs")),
        target,
        Some("tmpfs"),
        flags,
        Some(data),
    )
}

pub(crate) fn verify_idmap_runtime(profile: &str) -> Result<()> {
    let (mount, library) = match profile {
        "ubuntu2404-product-v1" => (
            "d1f8e1f8e0b78f702f9d4ee0d996abd27f290ce0aa8a5490aa497d1c87b39092",
            "507b07264482e5e29171d9bf202abcac55ce85d0eb5d8b7100f07f1081578a63",
        ),
        "ubuntu2404-controller-v1" => (
            "a4e2960330ff237a185306d9d92df1fc69ee77d8abe9d3282f662f54e13f01f4",
            "cfa453687fb8eee3c6f8e06de6ab2c1f9dfc59b94d05477593fae99fe7fe1e6d",
        ),
        _ => return Err("fixed idmap runtime required".into()),
    };
    fs_input::pinned(Path::new("/usr/bin/mount"), 2 * 1024 * 1024, mount)?;
    fs_input::pinned(
        Path::new("/usr/lib/aarch64-linux-gnu/libmount.so.1.1.0"),
        2 * 1024 * 1024,
        library,
    )?;
    Ok(())
}

pub(crate) fn idmap(source: &Path, target: &Path) -> Result<()> {
    let mut child = Command::new("/usr/bin/mount")
        .args(["--no-mtab", "--bind", "-o", "X-mount.idmap=b:10001:10004:1"])
        .arg(source)
        .arg(target)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) if status.success() => return Ok(()),
            Some(_) => return Err("fixed private idmap helper failed".into()),
            None => {}
        }
        if started.elapsed() >= Duration::from_secs(5) {
            // SAFETY: the negative PID is the process group created above. It
            // cannot be reused while this unreaped child is still alive.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            return Err("fixed idmap helper exceeded deadline; constructor must exit".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn raise_loopback() -> Result<()> {
    gauntlet_product_cell::observe_private_loopback().map_err(|e| e.to_string())?;
    // SAFETY: socket arguments are fixed constants; ownership of a successful
    // descriptor is immediately transferred to OwnedFd.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: Linux ifreq is a C POD whose zero representation is valid.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[0] = b'l' as libc::c_char;
    request.ifr_name[1] = b'o' as libc::c_char;
    // SAFETY: the live ifreq has the exact SIOCGIFFLAGS/SIOCSIFFLAGS layout;
    // the only selected interface is this namespace's pre-existing loopback.
    unsafe {
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut request) < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS as _, &request) < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    gauntlet_product_cell::observe_private_loopback().map_err(|e| e.to_string())?;
    Ok(())
}
