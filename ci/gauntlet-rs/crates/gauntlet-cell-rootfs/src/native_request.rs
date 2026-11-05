//! One-use data handoff to the unprivileged Native sink. Cleanup never follows
//! a replacement path or accepts a renamed surviving request directory.
use crate::{fs_input, hash, Result};
use rustix::fs::{
    fchmod, fchown, fstat, fsync, mkdirat, openat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags, Stat,
};
use rustix::process::{Gid, Uid};
use serde_json::{json, Value};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const MAXIMUM: usize = 1024 * 1024;

pub(crate) struct NativeRequest {
    parent: Option<OwnedFd>,
    home: OwnedFd,
    directory: OwnedFd,
    file: File,
    file_stat: Stat,
    owner: (u32, u32),
    name: String,
    sha256: String,
}

fn private(info: &Stat, directory: bool, owner: (u32, u32)) -> Result<()> {
    let expected = if directory {
        FileType::Directory
    } else {
        FileType::RegularFile
    };
    if FileType::from_raw_mode(info.st_mode) != expected
        || info.st_uid != owner.0
        || info.st_gid != owner.1
        || info.st_mode & 0o7777 != if directory { 0o700 } else { 0o600 }
        || (!directory && info.st_nlink != 1)
    {
        return Err("private native request custody differs".into());
    }
    Ok(())
}

fn inode(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

impl NativeRequest {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(crate) fn for_cell(cell: &crate::NativeCell, raw: &[u8]) -> Result<Self> {
        crate::require_outside_root()?;
        let stage = fs_input::directory(&cell.inputs.spec.stage)?;
        let state = openat(&stage, "state", DIRECTORY, Mode::empty()).map_err(|e| e.to_string())?;
        private(
            &fstat(&state).map_err(|e| e.to_string())?,
            true,
            (10004, 10004),
        )?;
        let home = openat(&state, "home", DIRECTORY, Mode::empty()).map_err(|e| e.to_string())?;
        Self::create(home, Some(state), raw, &crate::nonce()?, (10004, 10004))
    }

    fn create(
        home: OwnedFd,
        parent: Option<OwnedFd>,
        raw: &[u8],
        nonce: &str,
        owner: (u32, u32),
    ) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAXIMUM || !crate::hex(nonce, 32) {
            return Err("bounded native request and fresh fixed name required".into());
        }
        private(&fstat(&home).map_err(|e| e.to_string())?, true, owner)?;
        let name = format!("hol-guard-contained-test-{nonce}");
        // Every failure after mkdir consumes this slot; partials are retained.
        mkdirat(&home, name.as_str(), Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|e| e.to_string())?;
        let directory =
            openat(&home, name.as_str(), DIRECTORY, Mode::empty()).map_err(|e| e.to_string())?;
        let fd = openat(
            &directory,
            "request.json",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| e.to_string())?;
        let mut file = File::from(fd);
        file.write_all(raw).map_err(|e| e.to_string())?;
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
        fchown(
            &file,
            Some(Uid::from_raw(owner.0)),
            Some(Gid::from_raw(owner.1)),
        )
        .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fchmod(&directory, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
        fchown(
            &directory,
            Some(Uid::from_raw(owner.0)),
            Some(Gid::from_raw(owner.1)),
        )
        .map_err(|e| e.to_string())?;
        fsync(&directory)
            .and_then(|_| fsync(&home))
            .map_err(|e| e.to_string())?;
        let file_stat = fstat(&file).map_err(|e| e.to_string())?;
        let mut result = Self {
            parent,
            home,
            directory,
            file,
            file_stat,
            owner,
            name,
            sha256: hash(raw),
        };
        result.verify_before_execution()?;
        Ok(result)
    }

    fn verify_home(&self) -> Result<()> {
        let home = fstat(&self.home).map_err(|e| e.to_string())?;
        private(&home, true, self.owner)?;
        if let Some(parent) = &self.parent {
            private(&fstat(parent).map_err(|e| e.to_string())?, true, self.owner)?;
            let visible =
                statat(parent, "home", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
            private(&visible, true, self.owner)?;
            if !inode(&home, &visible) {
                return Err("native request home was replaced".into());
            }
        }
        Ok(())
    }

    pub(crate) fn verify_before_execution(&mut self) -> Result<()> {
        self.verify_home()?;
        let directory = fstat(&self.directory).map_err(|e| e.to_string())?;
        let visible = statat(&self.home, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        private(&directory, true, self.owner)?;
        private(&visible, true, self.owner)?;
        if !inode(&directory, &visible) {
            return Err("native request directory was replaced".into());
        }
        self.verify_file()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        Read::by_ref(&mut self.file)
            .take(MAXIMUM as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() != self.file_stat.st_size as usize || hash(&raw) != self.sha256 {
            return Err("native request data changed before execution".into());
        }
        self.verify_file()
    }

    fn verify_file(&self) -> Result<()> {
        let held = fstat(&self.file).map_err(|e| e.to_string())?;
        let visible = statat(&self.directory, "request.json", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        private(&held, false, self.owner)?;
        private(&visible, false, self.owner)?;
        if !fs_input::same(&held, &self.file_stat) || !fs_input::same(&held, &visible) {
            return Err("native request file was replaced or changed".into());
        }
        Ok(())
    }

    pub(crate) fn path(&self) -> String {
        format!("/product/home/{}/request.json", self.name)
    }
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
    pub(crate) fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-contained-request.v1","path":self.path(),
            "sha256":self.sha256,"bytes":self.file_stat.st_size,"device":self.file_stat.st_dev,
            "inode":self.file_stat.st_ino,"uid":self.owner.0,"gid":self.owner.1})
    }

    /// Explicit cleanup propagates uncertainty. Drop only closes descriptors.
    pub(crate) fn cleanup(self) -> Result<()> {
        self.verify_home()?;
        match statat(&self.home, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {
                if fstat(&self.directory).map_err(|e| e.to_string())?.st_nlink != 0
                    || fstat(&self.file).map_err(|e| e.to_string())?.st_nlink != 0
                {
                    return Err("missing native request name hides a surviving inode".into());
                }
            }
            Ok(visible) => {
                let held = fstat(&self.directory).map_err(|e| e.to_string())?;
                private(&visible, true, self.owner)?;
                if !inode(&held, &visible) {
                    return Err("native request cleanup refuses a replaced directory".into());
                }
                match statat(&self.directory, "request.json", AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(_) => {
                        self.verify_file()?;
                        unlinkat(&self.directory, "request.json", AtFlags::empty())
                            .map_err(|e| e.to_string())?;
                    }
                    Err(rustix::io::Errno::NOENT)
                        if fstat(&self.file).map_err(|e| e.to_string())?.st_nlink == 0 => {}
                    Err(e) => return Err(format!("native request cleanup is uncertain: {e}")),
                }
                if fstat(&self.file).map_err(|e| e.to_string())?.st_nlink != 0 {
                    return Err("native request file survived scoped cleanup".into());
                }
                unlinkat(&self.home, self.name.as_str(), AtFlags::REMOVEDIR)
                    .map_err(|e| e.to_string())?;
                if fstat(&self.directory).map_err(|e| e.to_string())?.st_nlink != 0 {
                    return Err("native request directory survived scoped cleanup".into());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
        fsync(&self.home).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::open;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn owned_home() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = open(home.path(), DIRECTORY, Mode::empty()).unwrap();
        // macOS inherits the parent's group even when its caller has another
        // primary GID. Give the synthetic home its declared test ownership.
        fchown(&directory, None, Some(rustix::process::getgid())).unwrap();
        home
    }
    fn request(root: &std::path::Path, nonce: &str, raw: &[u8]) -> Result<NativeRequest> {
        let home = open(root, DIRECTORY, Mode::empty()).unwrap();
        NativeRequest::create(
            home,
            None,
            raw,
            nonce,
            (
                rustix::process::getuid().as_raw(),
                rustix::process::getgid().as_raw(),
            ),
        )
    }
    #[test]
    fn data_readback_replay_refusal_and_both_retirement_paths_are_descriptor_bound() {
        let home = owned_home();
        let nonce = "a".repeat(32);
        let mut value = request(home.path(), &nonce, b"inert snapshot").unwrap();
        assert_eq!(value.sha256(), hash(b"inert snapshot"));
        value.verify_before_execution().unwrap();
        assert!(request(home.path(), &nonce, b"replacement").is_err());
        let path = home.path().join(&value.name).join("request.json");
        assert_eq!(std::fs::read(&path).unwrap(), b"inert snapshot");
        assert_eq!(value.observation()["bytes"], 14);
        let cleanup = value.cleanup();
        if cfg!(target_os = "linux") {
            cleanup.unwrap();
        } else {
            // This profile requires Linux's zero-link retirement witness.
            // APFS keeps a nonzero directory link count after unlink, so the
            // Linux-only proof must remain unavailable on the Mac host.
            assert!(cleanup.is_err());
        }
        let value = request(home.path(), &"b".repeat(32), b"native retires this").unwrap();
        let directory = home.path().join(&value.name);
        std::fs::remove_file(directory.join("request.json")).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        let cleanup = value.cleanup();
        if cfg!(target_os = "linux") {
            cleanup.unwrap();
        } else {
            assert!(cleanup.is_err());
        }
        assert!(request(home.path(), &"c".repeat(32), b"").is_err());
        assert!(request(home.path(), &"c".repeat(32), &vec![0; MAXIMUM + 1]).is_err());
    }
    #[test]
    fn replacements_renames_links_and_changed_bytes_retain_uncertainty() {
        for kind in ["rename", "symlink", "hardlink", "bytes"] {
            let home = owned_home();
            let mut value = request(home.path(), &"d".repeat(32), b"original").unwrap();
            let directory_name = value.name.clone();
            let dir = home.path().join(&value.name);
            let file = dir.join("request.json");
            match kind {
                "rename" => {
                    std::fs::rename(&dir, home.path().join("retained")).unwrap();
                }
                "symlink" => {
                    std::fs::rename(&dir, home.path().join("retained")).unwrap();
                    symlink(home.path().join("retained"), &dir).unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&file, home.path().join("extra")).unwrap();
                }
                _ => {
                    std::fs::write(&file, b"changed").unwrap();
                }
            }
            assert!(value.verify_before_execution().is_err(), "{kind}");
            assert!(value.cleanup().is_err(), "{kind}");
            assert!(home
                .path()
                .join(if matches!(kind, "rename" | "symlink") {
                    "retained"
                } else {
                    &directory_name
                })
                .exists());
        }
    }
}
