//! Fixed Root-authored declaration shared by the actor and its child gate.

use crate::{CellError, Result};
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const INVALID: CellError = CellError("invalid or unsafe Root product-cell layout");
const LIMIT: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellLayout {
    pub workspace: &'static str,
    pub path: &'static str,
}
impl Default for CellLayout {
    fn default() -> Self {
        Self {
            workspace: "/task",
            path: "/usr/bin:/bin",
        }
    }
}

pub fn parse_layout(raw: &[u8]) -> Result<CellLayout> {
    if raw.len() > LIMIT {
        return Err(INVALID);
    }
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    if value.as_object().is_none_or(|map| map.len() != 3)
        || value["schema"] != "product-cell-layout.v1"
    {
        return Err(INVALID);
    }
    let workspace = match value["workspace"].as_str() {
        Some("/task") => "/task",
        Some("/runtime/home/project") => "/runtime/home/project",
        _ => return Err(INVALID),
    };
    let path = match value["path"].as_str() {
        Some("/usr/bin:/bin") => "/usr/bin:/bin",
        Some("/usr/local/bin:/usr/bin:/bin") => "/usr/local/bin:/usr/bin:/bin",
        _ => return Err(INVALID),
    };
    Ok(CellLayout { workspace, path })
}

fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

fn from_etc(path: &Path) -> Result<CellLayout> {
    let etc = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| INVALID)?;
    let parent = fstat(&etc).map_err(|_| INVALID)?;
    if parent.st_uid != 0 || parent.st_mode & 0o022 != 0 {
        return Err(INVALID);
    }
    let name = "hol-cell-layout.json";
    let fd = match openat(
        &etc,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(CellLayout::default()),
        Err(_) => return Err(INVALID),
    };
    let first = fstat(&fd).map_err(|_| INVALID)?;
    if FileType::from_raw_mode(first.st_mode) != FileType::RegularFile
        || first.st_uid != 0
        || first.st_mode & 0o022 != 0
        || first.st_nlink != 1
        || !(1..=LIMIT as i64).contains(&first.st_size)
    {
        return Err(INVALID);
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    (&mut file)
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| INVALID)?;
    let held = fstat(&file).map_err(|_| INVALID)?;
    let visible = statat(&etc, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| INVALID)?;
    let visible_etc = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| INVALID)?;
    let after = fstat(&visible_etc).map_err(|_| INVALID)?;
    if raw.len() as i64 != first.st_size
        || !same(&first, &held)
        || !same(&first, &visible)
        || parent.st_dev != after.st_dev
        || parent.st_ino != after.st_ino
        || parent.st_uid != after.st_uid
        || parent.st_mode != after.st_mode
    {
        return Err(INVALID);
    }
    parse_layout(&raw)
}

pub fn load_root_layout() -> Result<CellLayout> {
    from_etc(Path::new("/etc"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn declaration_allows_only_the_two_fixed_workspaces_and_paths() {
        for workspace in ["/task", "/runtime/home/project"] {
            for path in ["/usr/bin:/bin", "/usr/local/bin:/usr/bin:/bin"] {
                let value = serde_json::json!({"schema":"product-cell-layout.v1","workspace":workspace,"path":path});
                let layout = parse_layout(value.to_string().as_bytes()).unwrap();
                assert_eq!(layout.workspace, workspace);
                assert_eq!(layout.path, path);
            }
        }
        for raw in [b"{}".as_slice(),br#"{"schema":"product-cell-layout.v1","workspace":"/task","path":"/tmp:/bin"}"#,
            br#"{"schema":"product-cell-layout.v1","workspace":"/task","workspace":"/runtime/home/project","path":"/usr/bin:/bin"}"#,
            br#"{"schema":"product-cell-layout.v1","workspace":"/task","path":"/usr/bin:/bin","extra":1}"#] {assert!(parse_layout(raw).is_err());}
        assert!(parse_layout(&vec![b' '; LIMIT + 1]).is_err());
    }

    #[test]
    fn directory_symlink_is_never_an_etc_declaration_root() {
        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("etc");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        assert!(from_etc(&link).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Root-owned filesystem fixtures; run in the isolated ARM test container"]
    fn root_owned_declarations_refuse_loose_modes_symlinks_and_hardlinks() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(from_etc(temp.path()).unwrap(), CellLayout::default());
        let file = temp.path().join("hol-cell-layout.json");
        std::fs::write(
            &file,
            br#"{"schema":"product-cell-layout.v1","workspace":"/task","path":"/usr/bin:/bin"}"#,
        )
        .unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(from_etc(temp.path()).unwrap(), CellLayout::default());
        std::fs::hard_link(&file, temp.path().join("extra")).unwrap();
        assert!(from_etc(temp.path()).is_err());
        std::fs::remove_file(temp.path().join("extra")).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(from_etc(temp.path()).is_err());
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("absent", &file).unwrap();
        assert!(from_etc(temp.path()).is_err());
    }
}
