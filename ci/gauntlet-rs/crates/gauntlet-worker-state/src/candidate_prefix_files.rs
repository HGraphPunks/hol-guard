//! Descriptor-relative inert prefix copying; shared by historical and native baselines.
use super::CandidatePrefixCloneError;
use crate::builder_candidate_source::same_file;
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, openat, readlinkat, statat, symlinkat, AtFlags, Dir, FileType,
    Mode, OFlags, Stat,
};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

pub(super) const SITE: &str = "lib/python3.12/site-packages/";
const NATIVE: &str = "codex_plugin_scanner/_native/hol-guard-runtime";
const MAX_ENTRIES: usize = 100_000;
const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_DEPTH: usize = 128;

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
}

fn entries(directory: &OwnedFd) -> Result<Vec<String>, CandidatePrefixCloneError> {
    let iterator =
        Dir::read_from(directory).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let mut names = Vec::new();
    for item in iterator {
        let item = item.map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        let name = item
            .file_name()
            .to_str()
            .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        if name == "." || name == ".." {
            continue;
        }
        if !safe_name(name) || names.len() >= MAX_ENTRIES {
            return Err(CandidatePrefixCloneError::CloneUncertain);
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

fn safe_source(stat: &Stat, kind: FileType) -> bool {
    stat.st_uid == 0
        && (kind == FileType::Symlink || stat.st_mode & 0o022 == 0)
        && stat.st_mode & 0o7000 == 0
        && matches!(
            kind,
            FileType::Directory | FileType::RegularFile | FileType::Symlink
        )
}

pub(super) fn private_directory(directory: &OwnedFd) -> Result<(), CandidatePrefixCloneError> {
    let stat = fstat(directory).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    Ok(())
}

fn regular_copy(
    source: &OwnedFd,
    target: &OwnedFd,
    name: &str,
    mode: u32,
    total: &mut u64,
) -> Result<(), CandidatePrefixCloneError> {
    let before = statat(source, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || !safe_source(&before, FileType::RegularFile)
        || before.st_size < 0
        || before.st_size as u64 > MAX_BYTES
    {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    let input = openat(
        source,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let opened = fstat(&input).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    if !same_file(&before, &opened) {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    let output = openat(
        target,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let mut input = File::from(input);
    let mut output = File::from(output);
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .filter(|size| *size <= MAX_BYTES)
            .ok_or(CandidatePrefixCloneError::CloneUncertain)?;
        output
            .write_all(&buffer[..n])
            .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        digest.update(&buffer[..n]);
    }
    *total = total
        .checked_add(count)
        .filter(|size| *size <= MAX_BYTES)
        .ok_or(CandidatePrefixCloneError::CloneUncertain)?;
    let after = fstat(&input).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let visible = statat(source, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    if count != before.st_size as u64
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
    {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    fchmod(&output, Mode::from_bits_truncate(mode))
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    output
        .sync_all()
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    fsync(target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let readback = openat(
        target,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    let proof = fstat(&readback).map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    if FileType::from_raw_mode(proof.st_mode) != FileType::RegularFile
        || proof.st_uid != 0
        || proof.st_nlink != 1
        || proof.st_mode & 0o777 != mode
        || proof.st_size != count as i64
    {
        return Err(CandidatePrefixCloneError::ReadbackMismatch);
    }
    let mut readback = File::from(readback);
    let mut observed = Sha256::new();
    let mut read_bytes = 0_u64;
    loop {
        let n = readback
            .read(&mut buffer)
            .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
        if n == 0 {
            break;
        }
        read_bytes += n as u64;
        observed.update(&buffer[..n]);
    }
    let later = fstat(&readback).map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    let visible = statat(target, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    if read_bytes != count
        || format!("{:x}", observed.finalize()) != format!("{:x}", digest.finalize())
        || !same_file(&proof, &later)
        || !same_file(&proof, &visible)
    {
        return Err(CandidatePrefixCloneError::ReadbackMismatch);
    }
    Ok(())
}

fn old_product(relative: &str) -> bool {
    let Some(after_site) = relative.strip_prefix(SITE) else {
        return false;
    };
    let head = after_site.split('/').next().unwrap_or("");
    head == "codex_plugin_scanner"
        || head
            .strip_prefix("hol_guard-")
            .and_then(|part| part.strip_suffix(".dist-info"))
            .is_some_and(|version| {
                !version.is_empty()
                    && version
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
            })
}

pub(crate) fn clone_baseline(
    source: &OwnedFd,
    target: &OwnedFd,
    prefix: &str,
    depth: usize,
    entries_seen: &mut usize,
    copied_bytes: &mut u64,
    skip_old_product: bool,
) -> Result<(), CandidatePrefixCloneError> {
    if depth > MAX_DEPTH {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    for name in entries(source)? {
        *entries_seen += 1;
        if *entries_seen > MAX_ENTRIES {
            return Err(CandidatePrefixCloneError::CloneUncertain);
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if skip_old_product && old_product(&relative) {
            continue;
        }
        let before = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        let kind = FileType::from_raw_mode(before.st_mode);
        if !safe_source(&before, kind) {
            return Err(CandidatePrefixCloneError::CloneUncertain);
        }
        match kind {
            FileType::Directory => {
                let child_source = openat(
                    source,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                if !same_file(
                    &before,
                    &fstat(&child_source).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?,
                ) {
                    return Err(CandidatePrefixCloneError::CloneUncertain);
                }
                mkdirat(target, name.as_str(), Mode::from_bits_truncate(0o700))
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let child_target = openat(
                    target,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                clone_baseline(
                    &child_source,
                    &child_target,
                    &relative,
                    depth + 1,
                    entries_seen,
                    copied_bytes,
                    skip_old_product,
                )?;
                fchmod(
                    &child_target,
                    Mode::from_bits_truncate(before.st_mode & 0o777),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fsync(&child_target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fsync(target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let held =
                    fstat(&child_source).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let visible = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                if !same_file(&before, &held) || !same_file(&before, &visible) {
                    return Err(CandidatePrefixCloneError::CloneUncertain);
                }
            }
            FileType::RegularFile => {
                regular_copy(source, target, &name, before.st_mode & 0o777, copied_bytes)?
            }
            FileType::Symlink => {
                let link = readlinkat(source, name.as_str(), Vec::new())
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let link = link
                    .to_str()
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                symlinkat(link, target, name.as_str())
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fsync(target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let after = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let target_link = readlinkat(target, name.as_str(), Vec::new())
                    .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
                if !same_file(&before, &after) || target_link.to_str() != Ok(link) {
                    return Err(CandidatePrefixCloneError::ReadbackMismatch);
                }
            }
            _ => return Err(CandidatePrefixCloneError::CloneUncertain),
        }
    }
    Ok(())
}

fn target_parent(
    root: &OwnedFd,
    relative: &str,
) -> Result<(OwnedFd, String), CandidatePrefixCloneError> {
    let full = format!("{SITE}{relative}");
    let mut directory = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let mut parts = full.split('/').peekable();
    while let Some(part) = parts.next() {
        if !safe_name(part) {
            return Err(CandidatePrefixCloneError::StageMismatch);
        }
        if parts.peek().is_none() {
            return Ok((directory, part.to_owned()));
        }
        match mkdirat(&directory, part, Mode::from_bits_truncate(0o700)) {
            Ok(()) => {
                let created = openat(
                    &directory,
                    part,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fchmod(&created, Mode::from_bits_truncate(0o755))
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fsync(&directory).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                directory = created;
            }
            Err(Errno::EXIST) => {
                let existing = openat(
                    &directory,
                    part,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let stat =
                    fstat(&existing).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
                    return Err(CandidatePrefixCloneError::CloneUncertain);
                }
                directory = existing;
            }
            Err(_) => return Err(CandidatePrefixCloneError::CloneUncertain),
        }
    }
    Err(CandidatePrefixCloneError::StageMismatch)
}

pub(super) fn overlay_wheel(
    source: &OwnedFd,
    target: &OwnedFd,
    prefix: &str,
    depth: usize,
    files: &mut usize,
    copied_bytes: &mut u64,
) -> Result<(), CandidatePrefixCloneError> {
    if depth > MAX_DEPTH {
        return Err(CandidatePrefixCloneError::StageMismatch);
    }
    for name in entries(source)? {
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let before = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
        let kind = FileType::from_raw_mode(before.st_mode);
        if !safe_source(&before, kind) {
            return Err(CandidatePrefixCloneError::StageMismatch);
        }
        match kind {
            FileType::Directory => {
                let child = openat(
                    source,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
                if !same_file(
                    &before,
                    &fstat(&child).map_err(|_| CandidatePrefixCloneError::StageMismatch)?,
                ) {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
                overlay_wheel(&child, target, &relative, depth + 1, files, copied_bytes)?;
                let held = fstat(&child).map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
                let visible = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
                if !same_file(&before, &held) || !same_file(&before, &visible) {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
            }
            FileType::RegularFile => {
                if !(relative.starts_with("codex_plugin_scanner/")
                    || relative.starts_with("hol_guard-") && relative.contains(".dist-info/"))
                {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
                *files += 1;
                if *files > MAX_ENTRIES {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
                let (destination, basename) = target_parent(target, &relative)?;
                if basename != name {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
                regular_copy(
                    source,
                    &destination,
                    name.as_str(),
                    if relative == NATIVE { 0o755 } else { 0o644 },
                    copied_bytes,
                )?;
            }
            _ => return Err(CandidatePrefixCloneError::StageMismatch),
        }
    }
    Ok(())
}
