//! Fresh Root-owned SDK gate/hook sockets. Only the agent group can connect;
//! it cannot replace either directory entry. Explicit cleanup retains doubt.
use rustix::fs::{
    fchmod, fchown, fstat, fsync, mkdirat, openat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags, Stat,
};
use rustix::process::{Gid, Uid};
use serde_json::{json, Value};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

fn identity(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
}
fn directory_identity(a: &Stat, b: &Stat) -> bool {
    // Other fixed job subdirectories may be created after the sockets.
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
}
struct Endpoint {
    role: &'static str,
    name: &'static str,
    directory: OwnedFd,
    directory_stat: Stat,
    socket: OwnedFd,
    socket_stat: Stat,
    listener: UnixListener,
    closed: bool,
}
impl Endpoint {
    fn new(job: &OwnedFd, role: &'static str, name: &'static str) -> Result<Self, String> {
        mkdirat(job, role, Mode::from_bits_truncate(0o700))
            .and_then(|_| fsync(job))
            .map_err(|e| e.to_string())?;
        let directory = openat(
            job,
            role,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let path = format!("/proc/self/fd/{}/{name}", directory.as_raw_fd());
        let listener = UnixListener::bind(&path).map_err(|e| e.to_string())?;
        // The directory remains Root-only until the listener and its exact
        // ownership/modes are ready. The agent never receives write access.
        std::os::unix::fs::chown(&path, Some(0), Some(10001)).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .map_err(|e| e.to_string())?;
        let socket = openat(
            &directory,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let socket_stat = fstat(&socket).map_err(|e| e.to_string())?;
        if FileType::from_raw_mode(socket_stat.st_mode) != FileType::Socket
            || socket_stat.st_uid != 0
            || socket_stat.st_gid != 10001
            || socket_stat.st_mode & 0o7777 != 0o660
            || socket_stat.st_nlink != 1
        {
            return Err("SDK socket custody differs".into());
        }
        fchown(
            &directory,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(10001)),
        )
        .and_then(|_| fchmod(&directory, Mode::from_bits_truncate(0o710)))
        .and_then(|_| fsync(&directory))
        .and_then(|_| fsync(job))
        .map_err(|e| e.to_string())?;
        let directory_stat = fstat(&directory).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let endpoint = Self {
            role,
            name,
            directory,
            directory_stat,
            socket,
            socket_stat,
            listener,
            closed: false,
        };
        endpoint.verify(job)?;
        Ok(endpoint)
    }
    fn verify(&self, job: &OwnedFd) -> Result<(), String> {
        if self.closed {
            return Err("SDK socket has retired".into());
        }
        let visible =
            statat(job, self.role, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        let held = fstat(&self.directory).map_err(|e| e.to_string())?;
        if !identity(&self.directory_stat, &visible) || !identity(&held, &visible) {
            return Err("SDK socket directory changed".into());
        }
        let visible = statat(&self.directory, self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        let held = fstat(&self.socket).map_err(|e| e.to_string())?;
        if !identity(&self.socket_stat, &visible) || !identity(&held, &visible) {
            return Err("SDK socket inode/mode/ownership changed".into());
        }
        Ok(())
    }
    fn accept(&self, job: &OwnedFd) -> Result<Option<UnixStream>, String> {
        self.verify(job)?;
        let stream = match self.listener.accept() {
            Ok((stream, _)) => Some(stream),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(e) => return Err(e.to_string()),
        };
        self.verify(job)?;
        Ok(stream)
    }
    fn close(&mut self, job: &OwnedFd) -> Result<(), String> {
        self.verify(job)?;
        unlinkat(&self.directory, self.name, AtFlags::empty())
            .and_then(|_| fsync(&self.directory))
            .map_err(|e| e.to_string())?;
        if fstat(&self.socket).map_err(|e| e.to_string())?.st_nlink != 0 {
            return Err("SDK socket inode survived scoped unlink".into());
        }
        self.closed = true;
        Ok(())
    }
    fn observation(&self) -> Value {
        json!({"role":self.role,"socket":self.name,"directory_device":self.directory_stat.st_dev,
            "directory_inode":self.directory_stat.st_ino,"socket_device":self.socket_stat.st_dev,
            "socket_inode":self.socket_stat.st_ino,"uid":0,"gid":10001,"directory_mode":0o710,
            "socket_mode":0o660,"retired":self.closed})
    }
}

pub struct NativeSdkSockets {
    job_path: PathBuf,
    job: OwnedFd,
    job_stat: Stat,
    gate: Endpoint,
    hooks: Endpoint,
}
impl NativeSdkSockets {
    pub fn new(job_id: &str) -> Result<Self, String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        if !crate::hex(job_id, 16) {
            return Err("fixed SDK job required".into());
        }
        let job_path = PathBuf::from(crate::native_job_spec::NATIVE_JOBS).join(job_id);
        if job_path.join("sdk-hooks/hook.sock").as_os_str().len() > 85 {
            return Err("SDK socket path exceeds fixed budget".into());
        }
        let job = crate::open_root_owned_public_directory(&job_path).map_err(|e| e.to_string())?;
        let job_stat = fstat(&job).map_err(|e| e.to_string())?;
        if job_stat.st_uid != 0 || job_stat.st_gid != 0 || job_stat.st_mode & 0o7777 != 0o700 {
            return Err("private Root SDK job directory required".into());
        }
        let gate = Endpoint::new(&job, "sdk-gate", "ready.sock")?;
        let hooks = Endpoint::new(&job, "sdk-hooks", "hook.sock")?;
        let sockets = Self {
            job_path,
            job,
            job_stat,
            gate,
            hooks,
        };
        sockets.verify_job()?;
        Ok(sockets)
    }
    fn verify_job(&self) -> Result<(), String> {
        let visible =
            crate::open_root_owned_public_directory(&self.job_path).map_err(|e| e.to_string())?;
        if !directory_identity(
            &self.job_stat,
            &fstat(&self.job).map_err(|e| e.to_string())?,
        ) || !directory_identity(&self.job_stat, &fstat(&visible).map_err(|e| e.to_string())?)
        {
            return Err("SDK job directory changed".into());
        }
        Ok(())
    }
    pub fn accept_gate(&self) -> Result<Option<UnixStream>, String> {
        self.verify_job()?;
        self.gate.accept(&self.job)
    }
    pub fn accept_hook(&self) -> Result<Option<UnixStream>, String> {
        self.verify_job()?;
        self.hooks.accept(&self.job)
    }
    pub fn gate_directory(&self) -> PathBuf {
        self.job_path.join("sdk-gate")
    }
    pub fn hook_directory(&self) -> PathBuf {
        self.job_path.join("sdk-hooks")
    }
    pub fn close(&mut self) -> Result<(), String> {
        self.verify_job()?;
        let gate = self.gate.close(&self.job);
        let hooks = self.hooks.close(&self.job);
        match (gate, hooks) {
            (Ok(()), Ok(())) => Ok(()),
            (a, b) => Err(format!(
                "SDK socket cleanup uncertain: gate={a:?}; hooks={b:?}"
            )),
        }
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-sockets.v1","gate":self.gate.observation(),
            "hooks":self.hooks.observation(),"cleanup_complete":self.gate.closed&&self.hooks.closed,
            "execution_eligible":false})
    }
}
