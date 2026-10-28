//! Only the already-hashed running worker can become a native controller.
use crate::{native_job_spec::NativeJobSpec, OwnedJobCgroup};
use rustix::fs::{fstat, openat, Mode, OFlags};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};

pub(crate) struct NativeChild {
    pub child: Child,
    gate: Option<ChildStdin>,
    output: File,
    errors: File,
}

fn log(root: &OwnedFd, name: &str) -> Result<File, String> {
    let fd = openat(
        root,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| e.to_string())?;
    let info = fstat(&fd).map_err(|e| e.to_string())?;
    if info.st_uid != 0 || info.st_gid != 0 || info.st_nlink != 1 || info.st_mode & 0o7777 != 0o600
    {
        return Err("private Root native controller log required".into());
    }
    Ok(File::from(fd))
}

impl NativeChild {
    pub(crate) fn spawn(
        spec: &NativeJobSpec,
        deployment: &str,
        group: &OwnedJobCgroup,
        state: &OwnedFd,
        signing_key: Option<&File>,
    ) -> Result<Self, String> {
        if spec.requires_host_pin() != signing_key.is_some() {
            return Err("native controller key handoff and declared profile differ".into());
        }
        crate::verify_running_binary(&spec.worker_generation).map_err(|e| e.to_string())?;
        // `/proc/self/exe` is a kernel reference to the still-running inode
        // just verified, not argv[0] or a caller-selected executable path.
        let executable = File::open("/proc/self/exe").map_err(|e| e.to_string())?;
        let executable = if signing_key.is_some()
            && executable.as_raw_fd() == crate::native_controller_key::NATIVE_CONTROLLER_KEY_FD
        {
            let fd = unsafe { libc::fcntl(executable.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            // SAFETY: fcntl returned a fresh owned descriptor for this same inode.
            unsafe { File::from_raw_fd(fd) }
        } else {
            executable
        };
        let executable_fd = executable.as_raw_fd();
        let key = signing_key
            .map(File::try_clone)
            .transpose()
            .map_err(|e| e.to_string())?;
        let key_fd = key.as_ref().map(AsRawFd::as_raw_fd);
        let writer = group.writer().map_err(|e| e.to_string())?;
        let output = log(state, &format!("{}.native.stdout", spec.job_id))?;
        let errors = log(state, &format!("{}.native.stderr", spec.job_id))?;
        let argv = [
            "gauntlet-vm-worker",
            if key.is_some() {
                "--native-keyed-controller"
            } else {
                "--native-controller"
            },
            spec.source_sha.as_str(),
            spec.job_id.as_str(),
            deployment,
            spec.worker_generation.as_str(),
        ]
        .into_iter()
        .map(CString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "native controller argument contains NUL")?;
        let environment = [
            c"PATH=/usr/sbin:/usr/bin:/sbin:/bin".as_ptr() as usize,
            c"LANG=C.UTF-8".as_ptr() as usize,
            0,
        ];
        let pointers = argv
            .iter()
            .map(|s| s.as_ptr() as usize)
            .chain([0])
            .collect::<Vec<_>>();
        let mut command = Command::new("/usr/bin/false");
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(output.try_clone().map_err(|e| e.to_string())?)
            .stderr(errors.try_clone().map_err(|e| e.to_string())?);
        // SAFETY: the child uses only prepared pointers, held FDs and fixed
        // syscalls before replacing itself. No candidate Root program runs.
        unsafe {
            command.pre_exec(move || {
                let _keep_program = &executable;
                let _keep_arguments = &argv;
                let _keep_key = &key;
                let mut pid = libc::getpid() as u32;
                let mut digits = [0u8; 10];
                let mut start = digits.len();
                loop {
                    start -= 1;
                    digits[start] = b'0' + (pid % 10) as u8;
                    pid /= 10;
                    if pid == 0 {
                        break;
                    }
                }
                let raw = &digits[start..];
                if libc::write(writer.as_raw_fd(), raw.as_ptr().cast(), raw.len())
                    != raw.len() as isize
                    || libc::chdir(c"/".as_ptr()) != 0
                    || libc::setsid() < 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                libc::umask(0o077);
                if let Some(fd) = key_fd {
                    let target = crate::native_controller_key::NATIVE_CONTROLLER_KEY_FD;
                    if libc::dup2(fd, target) != target || libc::fcntl(target, libc::F_SETFD, 0) < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                libc::syscall(
                    libc::SYS_execveat,
                    executable_fd,
                    c"".as_ptr(),
                    pointers.as_ptr().cast::<*const libc::c_char>(),
                    environment.as_ptr().cast::<*const libc::c_char>(),
                    libc::AT_EMPTY_PATH,
                );
                Err(std::io::Error::last_os_error())
            });
        }
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        let gate = child.stdin.take();
        Ok(Self {
            child,
            gate,
            output,
            errors,
        })
    }

    pub(crate) fn release(&mut self) -> Result<(), String> {
        self.gate
            .take()
            .ok_or("native controller gate already consumed")?
            .write_all(&[1])
            .map_err(|e| e.to_string())
    }

    pub(crate) fn check_logs(&self) -> Result<(), String> {
        if [&self.output, &self.errors]
            .iter()
            .any(|f| f.metadata().map_or(true, |m| m.len() > 1024 * 1024))
        {
            return Err("native controller log bound exceeded or unavailable".into());
        }
        Ok(())
    }

    pub(crate) fn logs(&mut self) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.check_logs()?;
        let read = |file: &mut File| -> Result<Vec<u8>, String> {
            file.sync_all().map_err(|e| e.to_string())?;
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut raw = Vec::new();
            file.take(1024 * 1024 + 1)
                .read_to_end(&mut raw)
                .map_err(|e| e.to_string())?;
            if raw.len() > 1024 * 1024 {
                return Err("native controller final log bound".into());
            }
            Ok(raw)
        };
        Ok((read(&mut self.output)?, read(&mut self.errors)?))
    }
}
