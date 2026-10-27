//! Bounded, retained Root helper clients. Only two pinned host executables
//! are permitted; container code remains unprivileged behind Podman's boundary.
use rustix::fs::{fstat, fsync, openat, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::OwnedFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
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
    if before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o170000 != 0o100000
        || before.st_mode & 0o022 != 0
        || before.st_mode & 0o111 == 0
        || before.st_size <= 0
        || before.st_size > 16 * 1024 * 1024
    {
        return Err("unsafe SDK Root helper".into());
    }
    let mut raw = Vec::new();
    let file = File::from(fd);
    (&file)
        .take(16 * 1024 * 1024 + 1)
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
    consumed: bool,
}
impl RootCommands {
    pub(crate) fn new(job: &Path, podman: &str, parser: &str) -> Result<Self, String> {
        Self::in_directory(job, "sdk-processes", podman, parser)
    }
    pub(crate) fn for_post(job: &Path, podman: &str, parser: &str) -> Result<Self, String> {
        Self::in_directory(job, "sdk-final-processes", podman, parser)
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
        let mut command = Command::new(path);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("HOME", "/root")
            .env("TMPDIR", "/var/tmp")
            .stdin(Stdio::null())
            .stdout(output.try_clone().map_err(|e| e.to_string())?)
            .stderr(errors.try_clone().map_err(|e| e.to_string())?);
        // SAFETY: fixed async-signal-safe syscalls only; no candidate Root code.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: LIMIT,
                    rlim_max: LIMIT,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        let child = command.spawn().map_err(|e| e.to_string())?;
        Ok(RootChild {
            child,
            output,
            errors,
            consumed: false,
        })
    }
    pub(crate) fn run(
        &mut self,
        parser: bool,
        args: &[String],
        seconds: u64,
        cancel: &AtomicBool,
    ) -> Result<Output, String> {
        let mut child = self.spawn(parser, args)?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some(output) = child.poll()? {
                verify_helper(
                    if parser {
                        "/usr/sbin/apparmor_parser"
                    } else {
                        "/usr/bin/podman"
                    },
                    if parser { &self.parser } else { &self.podman },
                )?;
                return Ok(output);
            }
            if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                child.stop()?;
                return Err("SDK Root helper cancelled or exceeded deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl RootChild {
    pub(crate) fn poll(&mut self) -> Result<Option<Output>, String> {
        if self.consumed {
            return Err("SDK helper result already consumed".into());
        }
        for file in [&self.output, &self.errors] {
            if file.metadata().map_err(|e| e.to_string())?.len() > LIMIT {
                return Err("SDK helper output bound".into());
            }
        }
        let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
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
        if status.signal() == Some(libc::SIGXFSZ) {
            return Err("SDK helper exceeded retained output limit".into());
        }
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
