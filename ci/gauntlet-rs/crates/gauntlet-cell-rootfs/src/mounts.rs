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

pub(crate) fn tmpfs(
    target: &Path,
    flags: libc::c_ulong,
    options: &str,
    bytes: u64,
    inodes: u64,
) -> Result<()> {
    if bytes == 0
        || inodes == 0
        || options
            .split(',')
            .any(|v| v.starts_with("size=") || v.starts_with("nr_inodes="))
    {
        return Err("explicit finite tmpfs byte and inode ceilings required".into());
    }
    let data = format!("{options},size={bytes},nr_inodes={inodes}");
    mount(
        Some(Path::new("tmpfs")),
        target,
        Some("tmpfs"),
        flags,
        Some(&data),
    )?;
    let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| "invalid tmpfs target")?;
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: statfs writes one complete structure into initialized storage;
    // the private namespace has no untrusted task while this mount is verified.
    if unsafe { libc::statfs(target.as_ptr(), info.as_mut_ptr()) } != 0 {
        return Err("mounted tmpfs capacity unavailable".into());
    }
    // SAFETY: the successful statfs call initialized the output structure.
    let info = unsafe { info.assume_init() };
    let capacity = i128::from(info.f_bsize).checked_mul(i128::from(info.f_blocks));
    if info.f_type != 0x0102_1994
        || capacity.is_none_or(|n| n <= 0 || n > i128::from(bytes))
        || info.f_files == 0
        || info.f_files > inodes
    {
        return Err("mounted tmpfs differs from finite byte/inode ceilings".into());
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct PrivateMount(PathBuf);
    impl Drop for PrivateMount {
        fn drop(&mut self) {
            let path = CString::new(self.0.as_os_str().as_bytes()).unwrap();
            // SAFETY: this test owns this exact mount in its private namespace.
            assert_eq!(unsafe { libc::umount2(path.as_ptr(), 0) }, 0);
        }
    }

    #[test]
    #[ignore = "requires Linux Root in the leased Gauntlet VM"]
    fn finite_tmpfs_enforces_bytes_and_inodes_independently() {
        // SAFETY: fixed namespace flags affect only this dedicated test thread.
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
        mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let bytes = root.path().join("bytes");
        let inodes = root.path().join("inodes");
        std::fs::create_dir(&bytes).unwrap();
        std::fs::create_dir(&inodes).unwrap();
        tmpfs(
            &bytes,
            libc::MS_NOSUID | libc::MS_NODEV,
            "mode=0700",
            65536,
            128,
        )
        .unwrap();
        let byte_mount = PrivateMount(bytes.clone());
        let mut file = std::fs::File::create(bytes.join("bounded")).unwrap();
        let block = [0u8; 4096];
        let mut written = 0;
        let byte_error = loop {
            assert!(written <= 65536);
            match file.write(&block) {
                Ok(0) => panic!("tmpfs write made no progress"),
                Ok(n) => written += n,
                Err(error) => break error,
            }
        };
        assert_eq!(byte_error.raw_os_error(), Some(libc::ENOSPC));
        assert_eq!(written, 65536);
        drop(file);
        tmpfs(
            &inodes,
            libc::MS_NOSUID | libc::MS_NODEV,
            "mode=0700",
            65536,
            16,
        )
        .unwrap();
        let inode_mount = PrivateMount(inodes.clone());
        let mut created = 0;
        let inode_error = loop {
            assert!(created < 16);
            match std::fs::File::create(inodes.join(format!("empty-{created}"))) {
                Ok(file) => {
                    assert_eq!(file.metadata().unwrap().len(), 0);
                    created += 1;
                }
                Err(error) => break error,
            }
        };
        assert_eq!(inode_error.raw_os_error(), Some(libc::ENOSPC));
        assert_eq!(created, 15);
        assert!(tmpfs(&bytes, 0, "mode=0700,size=1", 65536, 16).is_err());
        assert!(tmpfs(&bytes, 0, "mode=0700,nr_inodes=1", 65536, 16).is_err());
        drop(inode_mount);
        drop(byte_mount);
    }
}
