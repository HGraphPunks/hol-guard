//! Caller-pinned public feature readback. This authenticates bytes and counts,
//! never an execution owner, source review or qualification authority.
use crate::crypto::{is_sha256, sha256};
use crate::io::open_absolute_directory;
use crate::{verify_feature_report_v2, EvidenceError, Result};
use gauntlet_contracts::{FeatureExecutorSpec, FEATURE_SPEC_LIMIT};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

const INVALID: EvidenceError = EvidenceError::Invalid("feature public file or outside pin differs");

fn stable(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

fn artifact(dir: &OwnedFd, name: &str, bound: usize) -> Result<Option<Vec<u8>>> {
    if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
        return Err(INVALID);
    }
    let fd = match openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(INVALID),
    };
    let before = fstat(&fd).map_err(|_| INVALID)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_nlink != 1
        || before.st_mode & 0o6000 != 0
        || before.st_size < 0
        || before.st_size as u64 > bound as u64
    {
        return Err(INVALID);
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    (&mut file)
        .take(bound as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| INVALID)?;
    let after = fstat(&file).map_err(|_| INVALID)?;
    let visible = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| INVALID)?;
    if raw.len() as i64 != before.st_size || !stable(&before, &after) || !stable(&before, &visible)
    {
        return Err(INVALID);
    }
    Ok(Some(raw))
}

fn pinned(path: &Path, pin: &str, bound: usize) -> Result<Vec<u8>> {
    if !is_sha256(pin) {
        return Err(INVALID);
    }
    let parent = open_absolute_directory(path.parent().ok_or(INVALID)?)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(INVALID)?;
    let raw = artifact(&parent, name, bound)?.ok_or(INVALID)?;
    if sha256(&raw) != pin {
        return Err(INVALID);
    }
    Ok(raw)
}

/// Open bounded single-link files through no-symlink ancestry. The outside
/// caller chooses both byte pins; successful readback supplies no Root trust.
pub fn verify_feature_report_files_v2(
    spec: &Path,
    spec_sha256: &str,
    report: &Path,
    report_sha256: &str,
    artifacts: &Path,
) -> Result<Value> {
    let raw = pinned(spec, spec_sha256, FEATURE_SPEC_LIMIT)?;
    let spec = FeatureExecutorSpec::parse(&raw).map_err(|_| INVALID)?;
    if raw != spec.canonical_bytes() {
        return Err(INVALID);
    }
    let report = pinned(report, report_sha256, 128 * 1024)?;
    let root = open_absolute_directory(artifacts)?;
    verify_feature_report_v2(&spec, &report, |name, bound| artifact(&root, name, bound))
}
