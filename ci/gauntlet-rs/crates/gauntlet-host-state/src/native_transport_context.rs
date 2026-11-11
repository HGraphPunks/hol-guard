//! Bind Lima's state namespace and SSH home through directory metadata only.
//! No SSH configuration, VM configuration or credential bytes are opened.
use super::{hex, Intent};
use rustix::fs::{fstat, open, openat, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    process::Stdio,
};
use std::{
    path::{Component, Path, PathBuf},
    process::Command,
};

#[derive(Clone)]
pub(crate) struct TransportContext(Value);
impl TransportContext {
    pub(crate) fn from_paths(ssh_home: &Path, lima_home: &Path, vm: &str) -> Result<Self, String> {
        if !vm.starts_with("hol-")
            || vm.len() > 96
            || !vm
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("closed Lima instance name required".into());
        }
        Ok(Self(json!({"schema":"hol-gauntlet-host-lima-context.v1",
            "vm":vm,"ssh_home":snapshot(ssh_home)?,"lima_home":snapshot(lima_home)?,"instance":snapshot(&lima_home.join(vm))?})))
    }
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let ssh = value["ssh_home"]["path"]
            .as_str()
            .ok_or("retained SSH home absent")?;
        let lima = value["lima_home"]["path"]
            .as_str()
            .ok_or("retained Lima home absent")?;
        let vm = value["vm"]
            .as_str()
            .ok_or("retained Lima instance absent")?;
        let current = Self::from_paths(Path::new(ssh), Path::new(lima), vm)?;
        if &current.0 != value {
            return Err("retained Lima/SSH home ancestry changed".into());
        }
        Ok(current)
    }
    pub(crate) fn value(&self) -> &Value {
        &self.0
    }
    pub(super) fn configure(&self, command: &mut Command) -> Result<(), String> {
        Self::parse(&self.0)?;
        command
            .env(
                "HOME",
                self.0["ssh_home"]["path"]
                    .as_str()
                    .ok_or("SSH home absent")?,
            )
            .env(
                "LIMA_HOME",
                self.0["lima_home"]["path"]
                    .as_str()
                    .ok_or("Lima home absent")?,
            );
        Ok(())
    }
}

fn snapshot(path: &Path) -> Result<Value, String> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err("absolute canonical transport home required".into());
    }
    let mut normalized = PathBuf::from("/");
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                normalized.push(name);
                components.push(name);
            }
            _ => return Err("canonical transport home ancestry required".into()),
        }
    }
    if normalized != path || components.is_empty() || components.len() > 64 {
        return Err("bounded ordinary transport home ancestry required".into());
    }
    let mut fd = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "transport root unavailable")?;
    let owner = rustix::process::geteuid().as_raw();
    let mut ancestry = Vec::new();
    for (index, name) in components.iter().enumerate() {
        fd = openat(
            &fd,
            *name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "transport home ancestry unavailable or linked")?;
        let s = fstat(&fd).map_err(|_| "transport home metadata unavailable")?;
        let final_component = index + 1 == components.len();
        let sticky_root_ancestor = !final_component && s.st_uid == 0 && s.st_mode & 0o1000 != 0;
        if ![0, owner].contains(&s.st_uid)
            || s.st_mode & 0o6000 != 0
            || (s.st_mode & 0o022 != 0 && !sticky_root_ancestor)
            || (final_component && (s.st_uid != owner || s.st_mode & 0o1000 != 0))
        {
            return Err("transport home ancestry custody unsafe".into());
        }
        ancestry.push(json!({"device":s.st_dev,"inode":s.st_ino,"uid":s.st_uid,"gid":s.st_gid,"mode":s.st_mode&0o7777}));
    }
    Ok(json!({"path":path,"ancestry":ancestry}))
}

pub(super) struct Lima {
    path: PathBuf,
    file: File,
    expected: String,
    device: u64,
    inode: u64,
    context: TransportContext,
}
impl Lima {
    pub(super) fn open(intent: &Intent) -> Result<Self, String> {
        Self::open_pinned(
            intent.text("limactl"),
            intent.text("lima_sha256"),
            &intent.0["transport_context"],
        )
    }
    pub(super) fn open_pinned(path: &str, expected: &str, context: &Value) -> Result<Self, String> {
        if !cfg!(target_os = "macos") {
            return Err("macOS owned Lima host required".into());
        }
        let path = std::fs::canonicalize(path).map_err(|_| "pinned Lima transport unavailable")?;
        Self::open_path(path, expected, context)
    }
    pub(super) fn open_path(
        path: PathBuf,
        expected: &str,
        context: &Value,
    ) -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| "pinned Lima transport unavailable")?;
        let s = file.metadata().map_err(|_| "Lima descriptor unavailable")?;
        if !s.is_file()
            || s.nlink() != 1
            || s.mode() & 0o022 != 0
            || s.mode() & 0o111 == 0
            || !(1..=128 * 1024 * 1024).contains(&s.len())
            || ![0, rustix::process::geteuid().as_raw()].contains(&s.uid())
            || !hex(expected, 64)
        {
            return Err("owned immutable Lima executable required".into());
        }
        let mut result = Self {
            path,
            file,
            expected: expected.into(),
            device: s.dev(),
            inode: s.ino(),
            context: TransportContext::parse(context)?,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(super) fn recheck(&mut self) -> Result<(), String> {
        TransportContext::parse(self.context.value())?;
        let visible = std::fs::symlink_metadata(&self.path).map_err(|_| "Lima path unavailable")?;
        let before = self
            .file
            .metadata()
            .map_err(|_| "Lima descriptor unavailable")?;
        if !visible.is_file()
            || (visible.dev(), visible.ino()) != (self.device, self.inode)
            || (before.dev(), before.ino()) != (self.device, self.inode)
            || !before.is_file()
            || before.nlink() != 1
            || !(1..=128 * 1024 * 1024).contains(&before.len())
            || before.mode() & 0o022 != 0
            || before.mode() & 0o111 == 0
            || ![0, rustix::process::geteuid().as_raw()].contains(&before.uid())
        {
            return Err("Lima executable custody changed".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "Lima descriptor seek failed")?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut total = 0u64;
        loop {
            let count = self
                .file
                .read(&mut buffer)
                .map_err(|_| "Lima descriptor read failed")?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > before.len() {
                return Err("Lima executable grew while held".into());
            }
            hash.update(&buffer[..count]);
        }
        let after = self
            .file
            .metadata()
            .map_err(|_| "Lima descriptor unavailable")?;
        let snapshot = |s: &std::fs::Metadata| {
            (
                s.dev(),
                s.ino(),
                s.mode(),
                s.uid(),
                s.gid(),
                s.nlink(),
                s.len(),
                s.mtime(),
                s.mtime_nsec(),
                s.ctime(),
                s.ctime_nsec(),
            )
        };
        if format!("{:x}", hash.finalize()) != self.expected
            || total != before.len()
            || snapshot(&before) != snapshot(&after)
            || snapshot(&after)
                != snapshot(
                    &std::fs::symlink_metadata(&self.path).map_err(|_| "Lima path changed")?,
                )
        {
            return Err("Lima executable differs from outside SHA-256 pin".into());
        }
        Ok(())
    }
    pub(super) fn command(&mut self, vm: &str) -> Result<Command, String> {
        self.recheck()?;
        if self.context.value()["vm"] != vm {
            return Err("Lima target differs from retained instance".into());
        }
        let mut command = Command::new(&self.path);
        command
            .args(["shell", vm, "--", "sudo", "-n"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        self.context.configure(&mut command)?;
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn explicit_homes_override_ambient_redirects_and_refuse_replacement_or_links() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for name in ["ssh", "lima"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        let ssh = root.join("ssh");
        let lima = root.join("lima");
        let vm = "hol-context-fixture";
        std::fs::create_dir(lima.join(vm)).unwrap();
        let context = TransportContext::from_paths(&ssh, &lima, vm).unwrap();
        let mut command = Command::new("/usr/bin/true");
        command
            .env("HOME", "/tmp/untrusted-other-home")
            .env("LIMA_HOME", "/tmp/untrusted-other-lima");
        context.configure(&mut command).unwrap();
        let env = command
            .get_envs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            env.get(std::ffi::OsStr::new("HOME")).unwrap().unwrap(),
            ssh.as_os_str()
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("LIMA_HOME")).unwrap().unwrap(),
            lima.as_os_str()
        );
        std::fs::rename(&lima, root.join("saved-lima")).unwrap();
        std::fs::create_dir(&lima).unwrap();
        assert!(TransportContext::parse(context.value()).is_err());
        assert!(context.configure(&mut command).is_err());
        let link = root.join("linked");
        std::os::unix::fs::symlink(&ssh, &link).unwrap();
        assert!(TransportContext::from_paths(&link, &lima, vm).is_err());
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(TransportContext::from_paths(&ssh, &lima, vm).is_err());
    }

    #[test]
    fn same_name_vm_recreation_cannot_replace_the_recorded_instance() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let vm = "hol-instance-fixture";
        std::fs::create_dir(root.join(vm)).unwrap();
        let context = TransportContext::from_paths(&root, &root, vm).unwrap();
        std::fs::rename(root.join(vm), root.join("retained-old-instance")).unwrap();
        std::fs::create_dir(root.join(vm)).unwrap();
        assert!(TransportContext::parse(context.value()).is_err());
    }
}
