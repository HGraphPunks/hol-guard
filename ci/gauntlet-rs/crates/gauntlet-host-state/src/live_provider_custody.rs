//! Separate private provider journals and descriptor-held numerical assets.
use super::{bytes, sha};
use crate::private_jobs::{
    read_regular_bytes_bounded, same_file, state_root, write_private_once_bounded,
};
use rustix::fs::{flock, fstat, openat, statat, AtFlags, FileType, FlockOperation, Mode, OFlags};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(super) const RECORD_LIMIT: u64 = gauntlet_contracts::NATIVE_HOST_PINNED_COMPLETION_LIMIT as u64;
pub(super) struct Journal {
    pub path: PathBuf,
    root: OwnedFd,
    owner: u32,
    lease: Option<OwnedFd>,
    socket: Option<(OwnedFd, PathBuf, Value)>,
}
impl Journal {
    pub fn open(path: &Path) -> Result<Self, String> {
        let owner = rustix::process::geteuid().as_raw();
        Ok(Self {
            path: path.into(),
            root: state_root(path, owner).map_err(|e| e.to_string())?,
            owner,
            lease: None,
            socket: None,
        })
    }
    pub fn stable(&self) -> Result<(), String> {
        let visible = state_root(&self.path, self.owner).map_err(|e| e.to_string())?;
        let a = fstat(&self.root).map_err(|_| "provider journal unavailable")?;
        let b = fstat(&visible).map_err(|_| "provider journal unavailable")?;
        if (a.st_dev, a.st_ino, a.st_uid, a.st_mode) != (b.st_dev, b.st_ino, b.st_uid, b.st_mode) {
            return Err("provider journal replaced".into());
        }
        if let Some(lock) = &self.lease {
            let a = fstat(lock).map_err(|_| "provider owner lock unavailable")?;
            let b = statat(&self.root, "provider-owner.lock", AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| "provider owner lock replaced")?;
            if !same_file(&a, &b) {
                return Err("provider owner lock replaced".into());
            }
        }
        if let Some((held, path, context)) = &self.socket {
            let visible =
                state_root(path, self.owner).map_err(|_| "private socket directory unavailable")?;
            let a = fstat(held).map_err(|_| "private socket directory unavailable")?;
            let b = fstat(&visible).map_err(|_| "private socket directory unavailable")?;
            if (a.st_dev, a.st_ino, a.st_uid, a.st_mode)
                != (b.st_dev, b.st_ino, b.st_uid, b.st_mode)
                || socket_context(path)? != *context
            {
                return Err("retained private socket directory replaced".into());
            }
        }
        Ok(())
    }
    pub fn lock(&mut self) -> Result<(), String> {
        self.stable()?;
        let fd = openat(
            &self.root,
            "provider-owner.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| "provider owner lock unavailable")?;
        let s = fstat(&fd).map_err(|_| "provider owner lock unavailable")?;
        if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
            || s.st_uid != self.owner
            || s.st_nlink != 1
            || s.st_mode & 0o7777 != 0o600
            || s.st_size != 0
        {
            return Err("provider owner lock unsafe".into());
        }
        flock(&fd, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "provider already owned")?;
        self.lease = Some(fd);
        self.stable()
    }
    pub fn exists(&self, name: &str) -> Result<bool, String> {
        self.stable()?;
        match statat(&self.root, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(_) => Err("provider record existence uncertain".into()),
        }
    }
    pub fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        self.stable()?;
        let raw = read_regular_bytes_bounded(&self.root, name, self.owner, RECORD_LIMIT)
            .map_err(|e| e.to_string())?;
        self.stable()?;
        Ok(raw)
    }
    pub fn json(&self, name: &str) -> Result<Value, String> {
        let raw = self.read(name)?;
        let value: Value = serde_json::from_slice(&raw).map_err(|_| "provider record invalid")?;
        if bytes(&value)? != raw {
            return Err("canonical provider record required".into());
        }
        Ok(value)
    }
    pub fn write(&self, name: &str, raw: &[u8]) -> Result<(), String> {
        self.stable()?;
        write_private_once_bounded(&self.root, name, raw, RECORD_LIMIT)?;
        self.stable()
    }
    pub fn put(&self, name: &str, value: &Value) -> Result<(), String> {
        self.write(name, &bytes(value)?)
    }
    pub fn stop_requested(&self, digest: &str) -> Result<bool, String> {
        if !self.exists("provider-stop.json")? {
            return Ok(false);
        }
        if self.json("provider-stop.json")?
            != json!({"schema":"hol-gauntlet-rust-provider-stop.v1","binding_sha256":digest})
        {
            return Err("provider stop request differs".into());
        }
        Ok(true)
    }
    pub fn configure_socket(&mut self, path: &Path, context: &Value) -> Result<(), String> {
        if socket_context(path)? != *context {
            return Err("outside-pinned socket directory changed".into());
        }
        self.socket = Some((
            state_root(path, self.owner).map_err(|_| "private socket directory unsafe")?,
            path.into(),
            context.clone(),
        ));
        self.stable()
    }
    pub fn socket_path(&self) -> Result<PathBuf, String> {
        self.stable()?;
        Ok(self
            .socket
            .as_ref()
            .ok_or("outside-pinned private socket directory required")?
            .1
            .join("provider.sock"))
    }
    pub fn socket_facts(&self) -> Result<Value, String> {
        self.stable()?;
        let s = statat(
            &self
                .socket
                .as_ref()
                .ok_or("private socket directory absent")?
                .0,
            "provider.sock",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| "private provider socket unavailable")?;
        if FileType::from_raw_mode(s.st_mode) != FileType::Socket
            || s.st_uid != self.owner
            || s.st_nlink != 1
            || s.st_mode & 0o7777 != 0o600
        {
            return Err("private provider socket custody unsafe".into());
        }
        Ok(
            json!({"device":s.st_dev,"inode":s.st_ino,"uid":s.st_uid,"gid":s.st_gid,"mode":s.st_mode&0o7777}),
        )
    }
    pub fn pin_socket(&self, digest: &str) -> Result<(), String> {
        std::fs::set_permissions(self.socket_path()?, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "private provider socket mode unavailable")?;
        self.put("provider-socket.json",&json!({"schema":"hol-gauntlet-rust-provider-socket.v1","binding_sha256":digest,"socket":self.socket_facts()?}))
    }
    pub fn verify_socket(&self, digest: &str) -> Result<(), String> {
        if self.json("provider-socket.json")?
            != json!({"schema":"hol-gauntlet-rust-provider-socket.v1","binding_sha256":digest,"socket":self.socket_facts()?})
        {
            return Err("private provider socket replaced".into());
        }
        Ok(())
    }
    pub fn remove_socket(&self, digest: &str) -> Result<(), String> {
        self.verify_socket(digest)?;
        let root = &self
            .socket
            .as_ref()
            .ok_or("private socket directory absent")?
            .0;
        rustix::fs::unlinkat(root, "provider.sock", AtFlags::empty())
            .map_err(|_| "private provider socket cleanup uncertain")?;
        rustix::fs::fsync(root).map_err(|_| "private provider socket cleanup not durable")?;
        Ok(())
    }
    pub fn numerical_state(&self) -> Result<PathBuf, String> {
        self.stable()?;
        rustix::fs::mkdirat(
            &self.root,
            "provider-numerical-state",
            Mode::RUSR | Mode::WUSR | Mode::XUSR,
        )
        .map_err(|_| "numerical state already consumed or unavailable")?;
        rustix::fs::fsync(&self.root).map_err(|_| "numerical state creation not durable")?;
        let path = self.path.join("provider-numerical-state");
        state_root(&path, self.owner).map_err(|_| "numerical state custody unsafe")?;
        self.stable()?;
        Ok(path)
    }
    pub fn identity(&self) -> Result<Value, String> {
        self.stable()?;
        crate::native_operation::context::snapshot(&self.path)
    }
    pub fn clear_provider_active(&self, expected: &Value) -> Result<(), String> {
        if self.json("rust-provider-active.json")? != *expected {
            return Err("global provider identity changed before cleanup".into());
        }
        rustix::fs::unlinkat(&self.root, "rust-provider-active.json", AtFlags::empty())
            .map_err(|_| "global provider cleanup uncertain")?;
        rustix::fs::fsync(&self.root).map_err(|_| "global provider cleanup not durable")?;
        self.stable()
    }
}

pub(super) fn socket_context(path: &Path) -> Result<Value, String> {
    if path.join("provider.sock").as_os_str().len() > 100 {
        return Err("short private socket directory required (socket path <=100 bytes)".into());
    }
    state_root(path, rustix::process::geteuid().as_raw())
        .map_err(|_| "private socket directory unsafe")?;
    crate::native_operation::context::snapshot(path)
}

pub(super) fn private_input(path: &Path, expected: &str) -> Result<Vec<u8>, String> {
    let parent = path
        .parent()
        .ok_or("private provider input parent absent")?;
    let journal = Journal::open(parent)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("private provider input name invalid")?;
    let raw = journal.read(name)?;
    if sha(&raw) != expected {
        return Err("provider input differs from outside SHA256".into());
    }
    Ok(raw)
}
