//! Inert Python-compatible SDK and installed-prefix inventories.
//!
//! This reader is exploratory. Directory enumeration uses host path APIs;
//! execution admission needs descriptor-relative enumeration on Linux.

use crate::crypto::sha256;
use crate::public_files::PublicRootReader;
use crate::{canonical_value, EvidenceError, Result};
use gauntlet_contracts::canonical_relative_asset_path;
use rustix::process::getuid;
use serde_json::{json, Map, Value};
use std::fs::{self, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 100_000;
const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeKind {
    Sdk,
    InstalledPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeInventory {
    pub digest: String,
    pub entries: usize,
    pub bytes: u64,
}

fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn inspect_one(
    root: &Path,
    relative: &str,
    kind: TreeKind,
    reader: &PublicRootReader,
) -> Result<(Value, u64, bool)> {
    if !canonical_relative_asset_path(relative) {
        return Err(EvidenceError::Invalid("noncanonical tree entry"));
    }
    let path = root.join(relative);
    let before =
        fs::symlink_metadata(&path).map_err(|error| EvidenceError::Io(error.to_string()))?;
    let file_kind = before.file_type();
    let mode = before.mode() & 0o7777;
    match kind {
        TreeKind::Sdk => {
            let user = getuid().as_raw();
            if ![0, 501, user].contains(&before.uid())
                || before.uid() == 10001
                || (!file_kind.is_symlink()
                    && (mode & 0o002 != 0 || (before.gid() == 10001 && mode & 0o020 != 0)))
            {
                return Err(EvidenceError::Invalid(
                    "unsafe public SDK ownership or mode",
                ));
            }
        }
        TreeKind::InstalledPrefix => {
            if before.uid() != 0 || (!file_kind.is_symlink() && mode & 0o022 != 0) {
                return Err(EvidenceError::Invalid(
                    "unsafe installed prefix ownership or mode",
                ));
            }
        }
    }
    let mut row = match kind {
        TreeKind::Sdk => json!({"path":relative,"uid":before.uid(),"gid":before.gid(),"mode":mode}),
        TreeKind::InstalledPrefix => json!({"uid":before.uid(),"mode":mode}),
    };
    let mut bytes = 0;
    if file_kind.is_symlink() {
        let target = fs::read_link(&path).map_err(|error| EvidenceError::Io(error.to_string()))?;
        let resolved = path
            .canonicalize()
            .map_err(|_| EvidenceError::Invalid("unresolved tree symlink"))?;
        let allowed = resolved.starts_with(root)
            || (kind == TreeKind::InstalledPrefix
                && [
                    Path::new("/usr/bin/python3"),
                    Path::new("/usr/bin/python3.12"),
                ]
                .contains(&resolved.as_path()));
        if !allowed {
            return Err(EvidenceError::Invalid("tree symlink escapes its root"));
        }
        let target = target
            .to_str()
            .ok_or(EvidenceError::Invalid("non-UTF8 symlink target"))?;
        row[if kind == TreeKind::Sdk {
            "symlink"
        } else {
            "link"
        }] = json!(target);
    } else if file_kind.is_file() {
        bytes = before.len();
        if bytes > MAX_BYTES {
            return Err(EvidenceError::Invalid("tree file exceeds byte budget"));
        }
        row["sha256"] = json!(reader.file_digest(relative)?);
        if kind == TreeKind::Sdk {
            row["size"] = json!(bytes);
        }
    } else if !file_kind.is_dir() {
        return Err(EvidenceError::Invalid("tree contains a nonregular object"));
    }
    let after =
        fs::symlink_metadata(&path).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !unchanged(&before, &after) {
        return Err(EvidenceError::Invalid(
            "tree entry changed during inventory",
        ));
    }
    Ok((row, bytes, file_kind.is_dir()))
}

/// Return a Python-shaped SHA-256 inventory without importing or executing any tree file.
/// A successful result does not establish executor-safe custody.
pub fn inventory_tree(root: &Path, kind: TreeKind) -> Result<TreeInventory> {
    let reader = PublicRootReader::open(root)?;
    let metadata =
        fs::symlink_metadata(root).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || root.canonicalize().ok().as_deref() != Some(root)
    {
        return Err(EvidenceError::Invalid(
            "tree root must be canonical ordinary directory",
        ));
    }
    if kind == TreeKind::InstalledPrefix && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0) {
        return Err(EvidenceError::Invalid(
            "installed prefix root is not root-owned",
        ));
    }
    let mut queue = vec![String::new()];
    let mut rows = Map::new();
    let mut total = 0_u64;
    while let Some(directory) = queue.pop() {
        let parent: PathBuf = if directory.is_empty() {
            root.to_path_buf()
        } else {
            root.join(&directory)
        };
        let mut names = Vec::new();
        for item in fs::read_dir(&parent).map_err(|error| EvidenceError::Io(error.to_string()))? {
            let item = item.map_err(|error| EvidenceError::Io(error.to_string()))?;
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| EvidenceError::Invalid("non-UTF8 tree entry"))?;
            names.push(name);
        }
        names.sort();
        for name in names {
            let relative = if directory.is_empty() {
                name
            } else {
                format!("{directory}/{name}")
            };
            let (row, bytes, is_directory) = inspect_one(root, &relative, kind, &reader)?;
            total = total
                .checked_add(bytes)
                .filter(|n| *n <= MAX_BYTES)
                .ok_or(EvidenceError::Invalid("tree exceeds two GiB"))?;
            if rows.insert(relative.clone(), row).is_some() || rows.len() > MAX_ENTRIES {
                return Err(EvidenceError::Invalid(
                    "tree inventory exceeds entry budget",
                ));
            }
            if is_directory {
                queue.push(relative);
            }
        }
    }
    let after = fs::symlink_metadata(root).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !unchanged(&metadata, &after) {
        return Err(EvidenceError::Invalid("tree root changed during inventory"));
    }
    let entries = rows.len();
    let shape = match kind {
        TreeKind::Sdk => Value::Array(rows.into_values().collect()),
        TreeKind::InstalledPrefix => {
            rows.insert(
                ".".to_owned(),
                json!({"mode":metadata.mode() & 0o7777,"uid":metadata.uid()}),
            );
            Value::Object(rows)
        }
    };
    let digest = sha256(&canonical_value(&shape)?);
    Ok(TreeInventory {
        digest,
        entries,
        bytes: total,
    })
}
