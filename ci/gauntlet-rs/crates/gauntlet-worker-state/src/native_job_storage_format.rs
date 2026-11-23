//! Fixed held-FD mke2fs execution. Ambient configuration never selects policy.
use super::*;
use crate::native_sdk_process::RootChild;
use std::{
    os::fd::FromRawFd, os::unix::process::CommandExt, process::Command, sync::atomic::AtomicBool,
};

fn high(file: &File) -> Result<File, String> {
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) };
    if fd < 0 {
        return Err("formatter descriptor custody failed".into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(crate) fn formatter(pin: &str) -> Result<File, String> {
    let parent = crate::open_root_owned_public_directory(Path::new("/usr/sbin"))
        .map_err(|e| e.to_string())?;
    let fd = openat(
        &parent,
        "mke2fs",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o170000 != 0o100000
        || before.st_mode & 0o7022 != 0
        || before.st_mode & 0o111 == 0
        || !(64..=16 * 1024 * 1024).contains(&before.st_size)
    {
        return Err("pinned ordinary Root mke2fs ELF required".into());
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as i64 != before.st_size
        || sha(&raw) != pin
        || !crate::dependency_prefix_meta::same(&before, &fstat(&file).map_err(|e| e.to_string())?)
    {
        return Err("mke2fs source pin or custody changed".into());
    }
    gauntlet_evidence::verify_native_actor_elf(&raw).map_err(|e| e.to_string())?;
    high(&file)
}
pub(crate) fn format(
    slot: &OwnedFd,
    backing: &File,
    program: &File,
    profile: JobStorageProfile,
    uuid: &str,
) -> Result<Value, String> {
    crate::feature_files::write(slot, "mke2fs.conf", CONFIG, (0, 0), 0o600)?;
    let config = File::from(
        openat(
            slot,
            "mke2fs.conf",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    let (program, backing, config) = (high(program)?, high(backing)?, high(&config)?);
    let arguments = vec![
        MKE2FS.into(),
        "-t".into(),
        "ext4".into(),
        "-F".into(),
        "-b".into(),
        "4096".into(),
        "-I".into(),
        "256".into(),
        "-g".into(),
        "32768".into(),
        "-N".into(),
        profile.format_inodes().to_string(),
        "-m".into(),
        "0".into(),
        "-e".into(),
        "remount-ro".into(),
        "-E".into(),
        "nodiscard,lazy_itable_init=0,lazy_journal_init=0".into(),
        "-U".into(),
        uuid_argument(uuid),
        "/proc/self/fd/3".into(),
        (profile.bytes() / 4096).to_string(),
    ];
    let argv = arguments
        .iter()
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "fixed formatter argv invalid")?;
    let pointers = argv
        .iter()
        .map(|v| v.as_ptr() as usize)
        .chain([0])
        .collect::<Vec<_>>();
    let environment = [
        c"PATH=/usr/sbin:/usr/bin:/sbin:/bin".as_ptr() as usize,
        c"LANG=C".as_ptr() as usize,
        c"MKE2FS_CONFIG=/proc/self/fd/4".as_ptr() as usize,
        0,
    ];
    let mut command = Command::new("/usr/bin/false");
    command.env_clear().current_dir("/");
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            let _keep = (&program, &backing, &config, &argv);
            libc::umask(0o077);
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent
                || libc::dup2(backing.as_raw_fd(), 3) != 3
                || libc::dup2(config.as_raw_fd(), 4) != 4
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
                || libc::fcntl(4, libc::F_SETFD, 0) < 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            libc::syscall(
                libc::SYS_execveat,
                program.as_raw_fd(),
                c"".as_ptr(),
                pointers.as_ptr().cast::<*const libc::c_char>(),
                environment.as_ptr().cast::<*const libc::c_char>(),
                libc::AT_EMPTY_PATH,
            );
            Err(std::io::Error::last_os_error())
        });
    }
    let log = || -> Result<File, String> {
        let raw = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"gauntlet-mke2fs-output".as_ptr(),
                libc::MFD_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err("bounded in-memory formatter capture unavailable".into());
        }
        let file = unsafe { File::from_raw_fd(raw as i32) };
        rustix::fs::fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(|e| e.to_string())?;
        Ok(file)
    };
    let mut child = RootChild::spawn_prepared(command, log()?, log()?)?;
    let output = child.wait(90, &AtomicBool::new(false))?;
    if !output.status.success() {
        return Err("fixed mke2fs did not complete; volume remains consumed".into());
    }
    Ok(
        json!({"exit_code":0,"stdout_sha256":sha(&output.stdout),"stderr_sha256":sha(&output.stderr),"configuration_sha256":sha(CONFIG)}),
    )
}
