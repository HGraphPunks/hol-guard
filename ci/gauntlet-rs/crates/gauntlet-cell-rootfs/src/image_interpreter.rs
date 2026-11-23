//! Hold and hash the fixed image interpreter before any product gate starts.
use crate::{fs_input, hash, hex, Result};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::fd::OwnedFd,
};

const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const LIMIT: i64 = 16 * 1024 * 1024;
fn private(s: &Stat, kind: FileType, owner: (u32, u32)) -> Result<()> {
    if FileType::from_raw_mode(s.st_mode) != kind
        || s.st_uid != owner.0
        || s.st_gid != owner.1
        || s.st_mode & 0o022 != 0
    {
        return Err("image interpreter custody differs".into());
    }
    Ok(())
}
pub(crate) struct HeldImageInterpreter {
    directories: Vec<(OwnedFd, Stat)>,
    file: File,
    metadata: Stat,
    expected: String,
}
impl HeldImageInterpreter {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(crate) fn open(image: &OwnedFd, expected: &str) -> Result<Self> {
        crate::require_outside_root()?;
        Self::open_owned(image, expected, (0, 0))
    }
    fn open_owned(image: &OwnedFd, expected: &str, owner: (u32, u32)) -> Result<Self> {
        if !hex(expected, 64) {
            return Err("outside image interpreter SHA256 required".into());
        }
        let root = openat(image, ".", DIR, Mode::empty()).map_err(|e| e.to_string())?;
        let s = fstat(&root).map_err(|e| e.to_string())?;
        private(&s, FileType::Directory, owner)?;
        let mut directories = vec![(root, s)];
        for name in ["usr", "bin"] {
            let fd = openat(&directories.last().unwrap().0, name, DIR, Mode::empty())
                .map_err(|e| e.to_string())?;
            let s = fstat(&fd).map_err(|e| e.to_string())?;
            private(&s, FileType::Directory, owner)?;
            directories.push((fd, s));
        }
        let fd = openat(
            &directories[2].0,
            "python3.12",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let s = fstat(&fd).map_err(|e| e.to_string())?;
        private(&s, FileType::RegularFile, owner)?;
        if s.st_nlink != 1 || !(64..=LIMIT).contains(&s.st_size) || s.st_mode & 0o7777 != 0o755 {
            return Err("single-link bounded image interpreter required".into());
        }
        let mut held = Self {
            directories,
            file: File::from(fd),
            metadata: s,
            expected: expected.into(),
        };
        held.recheck()?;
        Ok(held)
    }
    fn directories_stable(&self) -> Result<()> {
        for (index, (fd, before)) in self.directories.iter().enumerate() {
            let current = fstat(fd).map_err(|e| e.to_string())?;
            if !fs_input::same(before, &current) {
                return Err("held image interpreter ancestry changed".into());
            }
            if index > 0 {
                let name = if index == 1 { "usr" } else { "bin" };
                let named = statat(
                    &self.directories[index - 1].0,
                    name,
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|e| e.to_string())?;
                if !fs_input::same(before, &named) {
                    return Err("named image interpreter ancestry changed".into());
                }
            }
        }
        Ok(())
    }
    pub(crate) fn recheck(&mut self) -> Result<()> {
        self.directories_stable()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        Read::by_ref(&mut self.file)
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        let after = fstat(&self.file).map_err(|e| e.to_string())?;
        let visible = statat(
            &self.directories[2].0,
            "python3.12",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|e| e.to_string())?;
        if !fs_input::same(&self.metadata, &after)
            || !fs_input::same(&after, &visible)
            || raw.len() as i64 != self.metadata.st_size
            || raw.len() < 64
            || raw[..6] != [127, b'E', b'L', b'F', 2, 1]
            || raw[18..20] != [183, 0]
            || hash(&raw) != self.expected
        {
            return Err("image interpreter generation, architecture or digest changed".into());
        }
        self.directories_stable()
    }
    pub(crate) fn observation(&self) -> Value {
        let s = &self.metadata;
        json!({"schema":"hol-gauntlet-image-interpreter-pin.v1","path":"/usr/bin/python3.12",
            "sha256":self.expected,"bytes":s.st_size,"device":s.st_dev,"inode":s.st_ino,
            "uid":s.st_uid,"gid":s.st_gid,"mode":s.st_mode&0o7777,"links":s.st_nlink,
            "verified_before_product_launch":true,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0})
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
impl crate::NativeCell {
    pub(crate) fn recheck_image_interpreter(&mut self) -> Result<()> {
        if let Some(pin) = &mut self.image_interpreter {
            pin.recheck()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fn fixture() -> (tempfile::TempDir, OwnedFd, Vec<u8>, (u32, u32)) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        let mut bytes = vec![0; 128];
        bytes[..6].copy_from_slice(&[127, b'E', b'L', b'F', 2, 1]);
        bytes[18] = 183;
        let file = root.path().join("usr/bin/python3.12");
        std::fs::write(&file, &bytes).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        let fd = rustix::fs::open(root.path(), DIR, Mode::empty()).unwrap();
        let m = std::fs::metadata(root.path()).unwrap();
        let owner = (m.uid(), m.gid());
        (root, fd, bytes, owner)
    }
    #[test]
    fn fixed_image_bytes_and_metadata_are_held_before_release() {
        let (_root, fd, raw, owner) = fixture();
        let mut held = HeldImageInterpreter::open_owned(&fd, &hash(&raw), owner).unwrap();
        for (directory, _) in &held.directories {
            assert!(rustix::io::fcntl_getfd(directory)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC));
        }
        assert!(rustix::io::fcntl_getfd(&held.file)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        held.recheck().unwrap();
        let value = held.observation();
        assert_eq!(value["sha256"], hash(&raw));
        assert_eq!(value["path"], "/usr/bin/python3.12");
        assert_eq!(value["verified_before_product_launch"], true);
        assert_eq!(value["execution_eligible"], false);
        assert!(HeldImageInterpreter::open_owned(&fd, &"0".repeat(64), owner).is_err());
    }
    #[test]
    fn changed_bytes_same_bytes_replacement_links_and_ancestor_swaps_refuse() {
        for kind in ["bytes", "replace", "link", "directory"] {
            let (root, fd, raw, owner) = fixture();
            let mut held = HeldImageInterpreter::open_owned(&fd, &hash(&raw), owner).unwrap();
            let file = root.path().join("usr/bin/python3.12");
            match kind {
                "bytes" => std::fs::write(&file, b"changed").unwrap(),
                "replace" => {
                    std::fs::rename(&file, root.path().join("retained")).unwrap();
                    std::fs::write(&file, &raw).unwrap();
                    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                "link" => std::fs::hard_link(&file, root.path().join("extra")).unwrap(),
                _ => {
                    std::fs::rename(
                        root.path().join("usr/bin"),
                        root.path().join("usr/retained"),
                    )
                    .unwrap();
                    std::fs::create_dir(root.path().join("usr/bin")).unwrap();
                }
            }
            assert!(held.recheck().is_err(), "{kind}");
        }
    }
    #[test]
    fn symlink_wrong_architecture_writable_or_nonexecutable_image_cannot_enter_custody() {
        let (root, fd, mut raw, owner) = fixture();
        let file = root.path().join("usr/bin/python3.12");
        for mode in [0o644, 0o777] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(HeldImageInterpreter::open_owned(&fd, &hash(&raw), owner).is_err());
        }
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        raw[18] = 62;
        std::fs::write(&file, &raw).unwrap();
        assert!(HeldImageInterpreter::open_owned(&fd, &hash(&raw), owner).is_err());
        std::fs::rename(&file, root.path().join("kept")).unwrap();
        std::os::unix::fs::symlink(root.path().join("kept"), &file).unwrap();
        assert!(HeldImageInterpreter::open_owned(&fd, &hash(&raw), owner).is_err());
    }
}
