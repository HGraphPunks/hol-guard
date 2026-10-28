//! Fixed Root-owned MCP listeners. Connection authentication belongs to the
//! controller; owning a pathname or connecting as an agent is not authority.
use gauntlet_mcp_service::Family;
use rustix::fs::{
    fchmod, fchown, fstat, fsync, mkdirat, openat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags, Stat,
};
use rustix::process::{Gid, Uid};
use serde_json::{json, Value};
use std::{
    os::fd::{AsRawFd, OwnedFd},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

const FAMILIES: [Family; 7] = [
    Family::Mail,
    Family::Crm,
    Family::Calendar,
    Family::Docs,
    Family::Tables,
    Family::Chat,
    Family::Tickets,
];

fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
}
fn directory_same(a: &Stat, b: &Stat) -> bool {
    // Sibling job owners may add directories, changing the job's link count.
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
}
fn cloexec(fd: &impl AsRawFd) -> Result<(), String> {
    // SAFETY: F_GETFD reads only flags of the caller-owned descriptor.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err("MCP socket descriptor could leak across exec".into());
    }
    Ok(())
}
struct Leaf {
    name: String,
    listener: Option<UnixListener>,
    inode: Option<OwnedFd>,
    stat: Option<Stat>,
    retired: bool,
}
impl Leaf {
    fn new(name: String) -> Self {
        Self {
            name,
            listener: None,
            inode: None,
            stat: None,
            retired: false,
        }
    }
    fn initialize(&mut self, directory: &OwnedFd, gid: u32) -> Result<(), String> {
        let path = format!("/proc/self/fd/{}/{}", directory.as_raw_fd(), self.name);
        self.listener = Some(UnixListener::bind(&path).map_err(|e| e.to_string())?);
        self.inode = Some(
            openat(
                directory,
                &self.name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        );
        // The directory is still private. Publish only after all leaves have
        // their exact owner/mode, and retain partial ownership on every error.
        std::os::unix::fs::chown(&path, Some(0), Some(gid)).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .map_err(|e| e.to_string())?;
        let s = fstat(self.inode.as_ref().unwrap()).map_err(|e| e.to_string())?;
        if FileType::from_raw_mode(s.st_mode) != FileType::Socket
            || s.st_uid != 0
            || s.st_gid != gid
            || s.st_mode & 0o7777 != 0o660
            || s.st_nlink != 1
        {
            return Err("private MCP socket custody differs".into());
        }
        self.stat = Some(s);
        self.listener
            .as_ref()
            .unwrap()
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        self.verify(directory)
    }
    fn verify(&self, directory: &OwnedFd) -> Result<(), String> {
        let expected = self
            .stat
            .as_ref()
            .ok_or("MCP socket initialization incomplete")?;
        let inode = self.inode.as_ref().ok_or("MCP held socket absent")?;
        cloexec(inode)?;
        let held = fstat(inode).map_err(|e| e.to_string())?;
        if self.retired {
            let mut retired = *expected;
            retired.st_nlink = 0;
            if !same(&held, &retired)
                || !matches!(
                    statat(directory, &self.name, AtFlags::SYMLINK_NOFOLLOW),
                    Err(rustix::io::Errno::NOENT)
                )
            {
                return Err("retired MCP socket namespace changed".into());
            }
        } else {
            let visible = statat(directory, &self.name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| e.to_string())?;
            if !same(expected, &held) || !same(expected, &visible) {
                return Err("MCP socket inode/owner/mode/link changed".into());
            }
            cloexec(self.listener.as_ref().ok_or("MCP listener absent")?)?;
        }
        Ok(())
    }
    fn close(&mut self, directory: &OwnedFd) -> Result<(), String> {
        self.verify(directory)?;
        if !self.retired {
            unlinkat(directory, &self.name, AtFlags::empty())
                .and_then(|_| fsync(directory))
                .map_err(|e| e.to_string())?;
            self.retired = true;
            self.listener = None;
        }
        self.verify(directory)
    }
    fn value(&self) -> Value {
        json!({"name":self.name,"device":self.stat.as_ref().map(|s|s.st_dev),
            "inode":self.stat.as_ref().map(|s|s.st_ino),"retired":self.retired,
            "inode_held":self.inode.is_some(),"listening":self.listener.is_some()})
    }
}
struct Directory {
    name: &'static str,
    gid: u32,
    fd: Option<OwnedFd>,
    stat: Option<Stat>,
    leaves: Vec<Leaf>,
}
impl Directory {
    fn new(name: &'static str, gid: u32, names: Vec<String>) -> Self {
        Self {
            name,
            gid,
            fd: None,
            stat: None,
            leaves: names.into_iter().map(Leaf::new).collect(),
        }
    }
    fn initialize(&mut self, job: &OwnedFd) -> Result<(), String> {
        mkdirat(job, self.name, Mode::from_bits_truncate(0o700))
            .and_then(|_| fsync(job))
            .map_err(|e| e.to_string())?;
        let directory = openat(
            job,
            self.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        self.stat = Some(fstat(&directory).map_err(|e| e.to_string())?);
        self.fd = Some(directory);
        let directory = self.fd.as_ref().unwrap();
        for leaf in &mut self.leaves {
            leaf.initialize(directory, self.gid)?;
        }
        fchown(
            directory,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(self.gid)),
        )
        .and_then(|_| fchmod(directory, Mode::from_bits_truncate(0o710)))
        .and_then(|_| fsync(directory))
        .and_then(|_| fsync(job))
        .map_err(|e| e.to_string())?;
        self.stat = Some(fstat(directory).map_err(|e| e.to_string())?);
        self.verify(job)
    }
    fn verify(&self, job: &OwnedFd) -> Result<(), String> {
        let expected = self.stat.as_ref().ok_or("MCP directory not initialized")?;
        let directory = self.fd.as_ref().ok_or("MCP directory not held")?;
        cloexec(directory)?;
        let visible =
            statat(job, self.name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        let held = fstat(directory).map_err(|e| e.to_string())?;
        if !same(expected, &visible) || !same(expected, &held) {
            return Err("MCP listener directory custody changed".into());
        }
        let visible_names = std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|e| e.to_string())?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .map_err(|e| e.to_string())?;
        let expected_names = self
            .leaves
            .iter()
            .filter(|leaf| !leaf.retired)
            .map(|leaf| std::ffi::OsString::from(&leaf.name))
            .collect();
        if visible_names != expected_names {
            return Err("MCP listener directory has missing or undeclared objects".into());
        }
        Ok(())
    }
    fn value(&self) -> Value {
        json!({"name":self.name,"uid":0,"gid":self.gid,"mode":self.stat.as_ref().map(|s|s.st_mode & 0o7777),
            "device":self.stat.as_ref().map(|s|s.st_dev),"inode":self.stat.as_ref().map(|s|s.st_ino),
            "sockets":self.leaves.iter().map(Leaf::value).collect::<Vec<_>>()})
    }
}

pub struct NativeMcpSockets {
    path: PathBuf,
    job: OwnedFd,
    job_stat: Stat,
    directories: Vec<Directory>,
    attempted: bool,
    initialized: bool,
    uncertain: bool,
    poisoned: bool,
}
impl NativeMcpSockets {
    /// Establish the owner before creating any filesystem objects. Callers keep
    /// this owner even when initialize fails; Drop never discards job evidence.
    pub fn prepare(job_id: &str) -> Result<Self, String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        if !crate::hex(job_id, 16) {
            return Err("fixed native MCP job required".into());
        }
        Self::at(&PathBuf::from(crate::native_job_spec::NATIVE_JOBS).join(job_id))
    }
    fn at(path: &Path) -> Result<Self, String> {
        let job = crate::open_root_owned_public_directory(path).map_err(|e| e.to_string())?;
        let job_stat = fstat(&job).map_err(|e| e.to_string())?;
        if job_stat.st_uid != 0 || job_stat.st_gid != 0 || job_stat.st_mode & 0o7777 != 0o700 {
            return Err("private Root MCP job directory required".into());
        }
        // Short fixed names leave room for every family within sockaddr_un.
        let names = || {
            FAMILIES
                .iter()
                .map(|f| format!("{}.sock", f.name()))
                .collect()
        };
        let directories = vec![
            Directory::new("mcp-u", 10005, names()),
            Directory::new("sdk-r", 10001, names()),
            Directory::new("mcp-g", 10005, vec!["ready.sock".into()]),
        ];
        for d in &directories {
            for l in &d.leaves {
                if path.join(d.name).join(&l.name).as_os_str().len() > 85 {
                    return Err("MCP socket path exceeds fixed budget".into());
                }
            }
        }
        Ok(Self {
            path: path.into(),
            job,
            job_stat,
            directories,
            attempted: false,
            initialized: false,
            uncertain: false,
            poisoned: false,
        })
    }
    fn verify_job(&self) -> Result<(), String> {
        let visible =
            crate::open_root_owned_public_directory(&self.path).map_err(|e| e.to_string())?;
        cloexec(&self.job)?;
        if !directory_same(
            &self.job_stat,
            &fstat(&self.job).map_err(|e| e.to_string())?,
        ) || !directory_same(&self.job_stat, &fstat(&visible).map_err(|e| e.to_string())?)
        {
            return Err("MCP job directory custody changed".into());
        }
        Ok(())
    }
    pub fn initialize(&mut self) -> Result<(), String> {
        if self.attempted {
            return Err("MCP listener initialization is one use".into());
        }
        self.verify_job()?;
        self.attempted = true;
        self.uncertain = true;
        for d in &mut self.directories {
            d.initialize(&self.job)?;
        }
        self.initialized = true;
        self.uncertain = false;
        self.verify()
    }
    fn verify_inner(&self) -> Result<(), String> {
        if !self.initialized || self.poisoned || self.uncertain {
            return Err("MCP listener initialization/custody uncertain".into());
        }
        self.verify_job()?;
        for d in &self.directories {
            d.verify(&self.job)?;
            for l in &d.leaves {
                l.verify(d.fd.as_ref().unwrap())?;
            }
        }
        Ok(())
    }
    pub fn verify(&mut self) -> Result<(), String> {
        let result = self.verify_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn verify_for_job(&mut self, job_id: &str) -> Result<(), String> {
        if !crate::hex(job_id, 16)
            || self.path != PathBuf::from(crate::native_job_spec::NATIVE_JOBS).join(job_id)
        {
            self.poisoned = true;
            return Err("MCP listener belongs to a different native job".into());
        }
        self.verify()
    }
    fn accept(&mut self, directory: usize, name: &str) -> Result<Option<UnixStream>, String> {
        self.verify()?;
        let leaf = self.directories[directory]
            .leaves
            .iter()
            .find(|l| l.name == name)
            .ok_or("fixed MCP endpoint required")?;
        let listener = leaf.listener.as_ref().ok_or("MCP listener retired")?;
        let result = match listener.accept() {
            Ok((stream, _)) => {
                cloexec(&stream)?;
                Ok(Some(stream))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.to_string()),
        };
        self.verify()?;
        result
    }
    pub fn accept_upstream(&mut self, family: Family) -> Result<Option<UnixStream>, String> {
        self.accept(0, &format!("{}.sock", family.name()))
    }
    pub fn accept_resource(&mut self, family: Family) -> Result<Option<UnixStream>, String> {
        self.accept(1, &format!("{}.sock", family.name()))
    }
    pub fn accept_gate(&mut self) -> Result<Option<UnixStream>, String> {
        self.accept(2, "ready.sock")
    }
    pub fn upstream_directory(&self) -> PathBuf {
        self.path.join("mcp-u")
    }
    pub fn resource_directory(&self) -> PathBuf {
        self.path.join("sdk-r")
    }
    pub fn gate_directory(&self) -> PathBuf {
        self.path.join("mcp-g")
    }
    pub fn close(&mut self) -> Result<(), String> {
        self.verify_job()?;
        let mut errors = Vec::new();
        for d in &mut self.directories {
            if d.fd.is_none() {
                continue;
            }
            if let Err(e) = d.verify(&self.job) {
                errors.push(e);
                continue;
            }
            for l in &mut d.leaves {
                if l.listener.is_none() && l.inode.is_none() {
                    continue;
                }
                if let Err(e) = l.close(d.fd.as_ref().unwrap()) {
                    errors.push(e);
                }
            }
        }
        if self.uncertain || !errors.is_empty() {
            self.uncertain = true;
            return Err(format!("MCP socket cleanup uncertain: {errors:?}"));
        }
        Ok(())
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-mcp-sockets.v1",
            "directories":self.directories.iter().map(Directory::value).collect::<Vec<_>>(),
            "initialized":self.initialized,"poisoned":self.poisoned,"cleanup_uncertain":self.uncertain,
            "socket_namespace_retired":self.attempted && !self.uncertain && self.directories.iter().all(|d|d.leaves.iter().all(|l|l.retired)),
            "accepted_streams_drained":false,"peer_authenticated":false,
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":0})
    }
}

#[cfg(test)]
#[path = "native_mcp_sockets_tests.rs"]
mod tests;
