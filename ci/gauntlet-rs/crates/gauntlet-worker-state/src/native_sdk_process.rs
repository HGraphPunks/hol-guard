//! Bounded, retained Root helper clients. Only two pinned host executables
//! are permitted; container code remains unprivileged behind Podman's boundary.
use rustix::fs::{fstat, fsync, openat, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) const LIMIT: u64 = 1024 * 1024;

pub(crate) fn verify_helper(path: &str, pin: &str) -> Result<(), String> {
    if !matches!(path, "/usr/bin/podman" | "/usr/sbin/apparmor_parser") || !crate::hex(pin, 64) {
        return Err("fixed outside-pinned SDK helper required".into());
    }
    let parent = crate::open_root_owned_public_directory(Path::new(path).parent().unwrap())
        .map_err(|e| e.to_string())?;
    let fd = openat(
        &parent,
        Path::new(path).file_name().unwrap(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    // Match the existing image-operation reader: the pinned Podman binary is
    // 35,455,464 bytes on the owned VM. Parser inputs retain the 16 MiB bound.
    let maximum = if path == "/usr/bin/podman" {
        128 * 1024 * 1024
    } else {
        16 * 1024 * 1024
    };
    if before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o170000 != 0o100000
        || before.st_mode & 0o022 != 0
        || before.st_mode & 0o111 == 0
        || before.st_size <= 0
        || before.st_size > maximum
    {
        return Err("unsafe SDK Root helper".into());
    }
    let mut raw = Vec::new();
    let file = File::from(fd);
    (&file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if !crate::dependency_prefix_meta::same(&before, &fstat(&file).map_err(|e| e.to_string())?)
        || raw.len() as i64 != before.st_size
        || format!("{:x}", Sha256::digest(raw)) != pin
    {
        return Err("SDK helper changed or differs from outside pin".into());
    }
    Ok(())
}
pub(crate) struct RootCommands {
    directory: OwnedFd,
    counter: u32,
    podman: String,
    parser: String,
}
pub(crate) struct RootChild {
    child: Child,
    output: File,
    errors: File,
    output_pipe: Option<OwnedFd>,
    errors_pipe: Option<OwnedFd>,
    consumed: bool,
}
impl RootCommands {
    pub(crate) fn new(job: &Path, podman: &str, parser: &str) -> Result<Self, String> {
        Self::in_directory(job, "sdk-processes", podman, parser)
    }
    pub(crate) fn new_mcp(job: &Path, podman: &str, parser: &str) -> Result<Self, String> {
        Self::in_directory(job, "mcp-processes", podman, parser)
    }
    pub(crate) fn mcp_logs(&mut self) -> Result<[File; 3], String> {
        verify_helper("/usr/bin/podman", &self.podman)?;
        if self.counter >= 128 {
            return Err("MCP Root helper operation budget".into());
        }
        self.counter += 1;
        let mut files = Vec::new();
        for suffix in ["mcp-input", "mcp-output", "stderr"] {
            let fd = openat(
                &self.directory,
                format!("{:03}.{suffix}", self.counter),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|e| e.to_string())?;
            let info = fstat(&fd).map_err(|e| e.to_string())?;
            if info.st_uid != 0
                || info.st_gid != 0
                || info.st_nlink != 1
                || info.st_mode & 0o7777 != 0o600
            {
                return Err("private MCP helper log required".into());
            }
            files.push(File::from(fd));
        }
        fsync(&self.directory).map_err(|e| e.to_string())?;
        files
            .try_into()
            .map_err(|_| "three MCP logs required".into())
    }
    fn in_directory(job: &Path, name: &str, podman: &str, parser: &str) -> Result<Self, String> {
        verify_helper("/usr/bin/podman", podman)?;
        verify_helper("/usr/sbin/apparmor_parser", parser)?;
        let root = crate::open_root_owned_public_directory(job).map_err(|e| e.to_string())?;
        rustix::fs::mkdirat(&root, name, Mode::from_bits_truncate(0o700))
            .map_err(|e| e.to_string())?;
        let directory =
            crate::open_root_owned_public_directory(&job.join(name)).map_err(|e| e.to_string())?;
        Ok(Self {
            directory,
            counter: 0,
            podman: podman.into(),
            parser: parser.into(),
        })
    }
    pub(crate) fn spawn(&mut self, parser: bool, args: &[String]) -> Result<RootChild, String> {
        let (path, pin) = if parser {
            ("/usr/sbin/apparmor_parser", &self.parser)
        } else {
            ("/usr/bin/podman", &self.podman)
        };
        verify_helper(path, pin)?;
        if self.counter >= 128 {
            return Err("SDK Root helper operation budget".into());
        }
        self.counter += 1;
        let log = |suffix: &str| -> Result<File, String> {
            let fd = openat(
                &self.directory,
                format!("{:03}.{suffix}", self.counter),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|e| e.to_string())?;
            let info = fstat(&fd).map_err(|e| e.to_string())?;
            if info.st_uid != 0
                || info.st_gid != 0
                || info.st_nlink != 1
                || info.st_mode & 0o7777 != 0o600
            {
                return Err("private SDK helper output required".into());
            }
            Ok(File::from(fd))
        };
        let output = log("stdout")?;
        let errors = log("stderr")?;
        fsync(&self.directory).map_err(|e| e.to_string())?;
        RootChild::spawn(path, args, output, errors)
    }
    pub(crate) fn run(
        &mut self,
        parser: bool,
        args: &[String],
        seconds: u64,
        cancel: &AtomicBool,
    ) -> Result<Output, String> {
        let mut child = self.spawn(parser, args)?;
        let output = child.wait(seconds, cancel)?;
        verify_helper(
            if parser {
                "/usr/sbin/apparmor_parser"
            } else {
                "/usr/bin/podman"
            },
            if parser { &self.parser } else { &self.podman },
        )?;
        Ok(output)
    }
}
impl RootChild {
    fn spawn(path: &str, args: &[String], output: File, errors: File) -> Result<Self, String> {
        let mut command = Command::new(path);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("HOME", "/root")
            .env("TMPDIR", "/var/tmp")
            // crun 1.14 can chown an inherited non-TTY stdin during exec.
            // Keep host /dev/null out of that boundary. This helper accepts
            // no input; closing the private pipe supplies EOF explicitly.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: fixed async-signal-safe syscalls only; no candidate Root code.
        unsafe {
            command.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        drop(child.stdin.take());
        let output_pipe = child.stdout.take().ok_or("SDK stdout pipe absent")?.into();
        let errors_pipe = child.stderr.take().ok_or("SDK stderr pipe absent")?.into();
        let mut owner = RootChild {
            child,
            output,
            errors,
            output_pipe: Some(output_pipe),
            errors_pipe: Some(errors_pipe),
            consumed: false,
        };
        let configured = (|| -> Result<(), String> {
            for pipe in [
                owner.output_pipe.as_ref().unwrap(),
                owner.errors_pipe.as_ref().unwrap(),
            ] {
                let flags = rustix::fs::fcntl_getfl(pipe).map_err(|e| e.to_string())?;
                rustix::fs::fcntl_setfl(pipe, flags | OFlags::NONBLOCK)
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        })();
        if let Err(error) = configured {
            owner.stop()?;
            return Err(error);
        }
        Ok(owner)
    }
    fn wait(&mut self, seconds: u64, cancel: &AtomicBool) -> Result<Output, String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some(output) = self.poll()? {
                return Ok(output);
            }
            if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                self.stop()?;
                return Err("SDK Root helper cancelled or exceeded deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl RootChild {
    fn drain(pipe: &mut Option<OwnedFd>, file: &mut File) -> Result<(), String> {
        let Some(fd) = pipe.as_ref() else {
            return Ok(());
        };
        let mut raw = [0; 8192];
        loop {
            match rustix::io::read(fd, &mut raw) {
                Ok(0) => {
                    *pipe = None;
                    return Ok(());
                }
                Ok(n) => {
                    if file.metadata().map_err(|e| e.to_string())?.len() + n as u64 > LIMIT {
                        return Err(
                            "SDK helper output bound exceeded; retained prefix is incomplete"
                                .into(),
                        );
                    }
                    file.write_all(&raw[..n]).map_err(|e| e.to_string())?;
                }
                Err(rustix::io::Errno::AGAIN) => return Ok(()),
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
    }
    pub(crate) fn poll(&mut self) -> Result<Option<Output>, String> {
        if self.consumed {
            return Err("SDK helper result already consumed".into());
        }
        Self::drain(&mut self.output_pipe, &mut self.output)?;
        Self::drain(&mut self.errors_pipe, &mut self.errors)?;
        for file in [&self.output, &self.errors] {
            if file.metadata().map_err(|e| e.to_string())?.len() > LIMIT {
                return Err("SDK helper output bound".into());
            }
        }
        let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        if self.output_pipe.is_some() || self.errors_pipe.is_some() {
            return Ok(None);
        }
        let read = |file: &mut File| -> Result<Vec<u8>, String> {
            file.sync_all().map_err(|e| e.to_string())?;
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut raw = Vec::new();
            file.take(LIMIT + 1)
                .read_to_end(&mut raw)
                .map_err(|e| e.to_string())?;
            if raw.len() as u64 > LIMIT {
                return Err("SDK helper final output bound".into());
            }
            Ok(raw)
        };
        let stdout = read(&mut self.output)?;
        let stderr = read(&mut self.errors)?;
        self.consumed = true;
        Ok(Some(Output {
            status,
            stdout,
            stderr,
        }))
    }
    pub(crate) fn stop(&mut self) -> Result<(), String> {
        if self.consumed {
            return Ok(());
        }
        if self.child.try_wait().map_err(|e| e.to_string())?.is_none() {
            self.child.kill().map_err(|e| e.to_string())?;
        }
        let until = Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().map_err(|e| e.to_string())?.is_none() {
            if Instant::now() >= until {
                return Err("SDK Root helper cleanup uncertain".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}
impl Drop for RootChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Pinned helper calls with bounded output in anonymous non-executable memory
/// files. Post/repair readback can repeat without creating another disk slot.
pub(crate) fn run_pinned_podman(pin: &str, args: &[String]) -> Result<Output, String> {
    verify_helper("/usr/bin/podman", pin)?;
    let anonymous = || -> Result<File, String> {
        // SAFETY: the static name is NUL-terminated; a successful syscall
        // returns a newly owned FD. 0x8 is Linux MFD_NOEXEC_SEAL (kernel >=6.3).
        let raw = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"hol-gauntlet-sdk-read-only".as_ptr(),
                libc::MFD_CLOEXEC | 0x8,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: transfer sole ownership of the just-created descriptor.
        let file = unsafe { File::from_raw_fd(raw as i32) };
        rustix::fs::fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(|e| e.to_string())?;
        Ok(file)
    };
    let mut child = RootChild::spawn("/usr/bin/podman", args, anonymous()?, anonymous()?)?;
    let output = child.wait(20, &AtomicBool::new(false))?;
    verify_helper("/usr/bin/podman", pin)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    #[test]
    fn helper_capture_preserves_binary_bytes_and_never_writes_beyond_its_limit() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut pipe = Some(receiver.into());
        let mut file = tempfile::tempfile().unwrap();
        sender.write_all(b"binary\x00\xffbytes").unwrap();
        RootChild::drain(&mut pipe, &mut file).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut raw = Vec::new();
        file.read_to_end(&mut raw).unwrap();
        assert_eq!(raw, b"binary\x00\xffbytes");
        assert!(pipe.is_some());
        file.set_len(LIMIT - 2).unwrap();
        sender.write_all(b"excess bytes").unwrap();
        assert!(RootChild::drain(&mut pipe, &mut file).is_err());
        assert_eq!(file.metadata().unwrap().len(), LIMIT - 2);
        drop(sender);
    }
}
