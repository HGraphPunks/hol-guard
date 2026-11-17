//! One-use, inert materialization of a captured wheel into a private Root tree.
//! This writes data files only; it never imports or executes candidate bytes.
//! The resulting tree is not an installed prefix or an admitted deployment.

use crate::builder_candidate_source::{open_fixed_build_slot, same_file, verify_captured_source};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_archive::CandidateArchiveDeclaration;
use crate::candidate_capture::{inactive, verify_captured};
use crate::candidate_wheel::{inspect_candidate_wheel, CandidateWheelProof};
use crate::RunReservationJournal;
use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::{inventory_tree, valid_package_version, TreeKind};
use rustix::fs::{fchmod, fstat, fsync, mkdirat, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use zip::ZipArchive;

const ARCHIVE: &str = "candidate.zip";
const STAGE: &str = "inert-wheel";
const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const MAX_ENTRY: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateWheelStageError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    SourceMismatch,
    BuildActive,
    ArchiveInvalid,
    WheelInvalid,
    ExistingStage,
    StageUncertain,
    ReadbackMismatch,
}

impl fmt::Display for CandidateWheelStageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for inert wheel staging",
            Self::InvalidPins => "exact captured wheel identity and digest pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::SourceMismatch => "captured source differs from outside digest",
            Self::BuildActive => "candidate build or cleanup remains active or uncertain",
            Self::ArchiveInvalid => "captured candidate archive differs from outside pins",
            Self::WheelInvalid => "nested candidate wheel bytes or identity are invalid",
            Self::ExistingStage => "one-use inert wheel stage already exists",
            Self::StageUncertain => "private inert wheel stage could not be written durably",
            Self::ReadbackMismatch => "staged wheel bytes or metadata differ on readback",
        })
    }
}

impl std::error::Error for CandidateWheelStageError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateWheelStageProof {
    job_id: String,
    source_sha: String,
    archive_sha256: String,
    declaration: CandidateArchiveDeclaration,
    wheel: CandidateWheelProof,
    tree_digest: String,
    tree_entries: usize,
    tree_bytes: u64,
}

impl CandidateWheelStageProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-wheel-stage-shadow.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "archive_sha256":self.archive_sha256,
            "version":self.declaration.version,
            "wheel_sha256":self.declaration.wheel_sha256,
            "wheel_entries":self.wheel.entries,
            "wheel_uncompressed_bytes":self.wheel.uncompressed_bytes,
            "native_sha256":self.wheel.native_sha256,
            "stage_tree_digest":self.tree_digest,
            "stage_tree_entries":self.tree_entries,
            "stage_tree_bytes":self.tree_bytes,
            "readback_verified":true,
            "candidate_executed":false,
            "installed_prefix_created":false,
            "artifact_admitted":false,
            "execution_eligible":false,
        })
    }
}

pub(crate) fn completed_readback(
    job: &str,
    source: &str,
    archive: &str,
    declaration: CandidateArchiveDeclaration,
    wheel: CandidateWheelProof,
    tree: gauntlet_evidence::TreeInventory,
) -> Value {
    CandidateWheelStageProof {
        job_id: job.into(),
        source_sha: source.into(),
        archive_sha256: archive.into(),
        declaration,
        wheel,
        tree_digest: tree.digest,
        tree_entries: tree.entries,
        tree_bytes: tree.bytes,
    }
    .to_json()
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn private_directory(directory: &OwnedFd) -> Result<(), CandidateWheelStageError> {
    let stat = fstat(directory).map_err(|_| CandidateWheelStageError::StageUncertain)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(CandidateWheelStageError::StageUncertain);
    }
    Ok(())
}

fn directory_for_entry(
    stage: &OwnedFd,
    name: &str,
) -> Result<(OwnedFd, String), CandidateWheelStageError> {
    let mut directory = openat(
        stage,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateWheelStageError::StageUncertain)?;
    let mut parts = name.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return Ok((directory, part.to_owned()));
        }
        match mkdirat(&directory, part, Mode::from_bits_truncate(0o700)) {
            Ok(()) => fsync(&directory).map_err(|_| CandidateWheelStageError::StageUncertain)?,
            Err(Errno::EXIST) => (),
            Err(_) => return Err(CandidateWheelStageError::StageUncertain),
        }
        let child = openat(
            &directory,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| CandidateWheelStageError::StageUncertain)?;
        private_directory(&child)?;
        directory = child;
    }
    Err(CandidateWheelStageError::WheelInvalid)
}

fn write_entry(
    stage: &OwnedFd,
    name: &str,
    entry: &mut zip::read::ZipFile<'_>,
) -> Result<(), CandidateWheelStageError> {
    let (directory, basename) = directory_for_entry(stage, name)?;
    let descriptor = openat(
        &directory,
        basename.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| CandidateWheelStageError::StageUncertain)?;
    let mut output = File::from(descriptor);
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let n = entry
            .read(&mut buffer)
            .map_err(|_| CandidateWheelStageError::WheelInvalid)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .filter(|size| *size <= MAX_ENTRY)
            .ok_or(CandidateWheelStageError::WheelInvalid)?;
        output
            .write_all(&buffer[..n])
            .map_err(|_| CandidateWheelStageError::StageUncertain)?;
        digest.update(&buffer[..n]);
    }
    if count != entry.size() {
        return Err(CandidateWheelStageError::WheelInvalid);
    }
    fchmod(&output, Mode::from_bits_truncate(0o444))
        .map_err(|_| CandidateWheelStageError::StageUncertain)?;
    output
        .sync_all()
        .map_err(|_| CandidateWheelStageError::StageUncertain)?;
    fsync(&directory).map_err(|_| CandidateWheelStageError::StageUncertain)?;
    let expected = format!("{:x}", digest.finalize());
    let readback = openat(
        &directory,
        basename.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateWheelStageError::ReadbackMismatch)?;
    let before = fstat(&readback).map_err(|_| CandidateWheelStageError::ReadbackMismatch)?;
    let visible = statat(&directory, basename.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateWheelStageError::ReadbackMismatch)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != 0o444
        || before.st_size != count as i64
        || !same_file(&before, &visible)
    {
        return Err(CandidateWheelStageError::ReadbackMismatch);
    }
    let mut input = File::from(readback);
    let mut observed = Sha256::new();
    let mut actual = 0_u64;
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|_| CandidateWheelStageError::ReadbackMismatch)?;
        if n == 0 {
            break;
        }
        actual += n as u64;
        observed.update(&buffer[..n]);
    }
    let after = fstat(&input).map_err(|_| CandidateWheelStageError::ReadbackMismatch)?;
    let visible = statat(&directory, basename.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateWheelStageError::ReadbackMismatch)?;
    if actual != count
        || format!("{:x}", observed.finalize()) != expected
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
    {
        return Err(CandidateWheelStageError::ReadbackMismatch);
    }
    Ok(())
}

fn materialize_wheel(
    job: &OwnedFd,
    raw: &[u8],
    declaration: &CandidateArchiveDeclaration,
) -> Result<(CandidateWheelProof, usize), CandidateWheelStageError> {
    let proof = inspect_candidate_wheel(raw, declaration)
        .map_err(|_| CandidateWheelStageError::WheelInvalid)?;
    match mkdirat(job, STAGE, Mode::from_bits_truncate(0o700)) {
        Ok(()) => (),
        Err(Errno::EXIST) => return Err(CandidateWheelStageError::ExistingStage),
        Err(_) => return Err(CandidateWheelStageError::StageUncertain),
    }
    fsync(job).map_err(|_| CandidateWheelStageError::StageUncertain)?;
    let stage = openat(
        job,
        STAGE,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateWheelStageError::StageUncertain)?;
    private_directory(&stage)?;
    let mut archive =
        ZipArchive::new(Cursor::new(raw)).map_err(|_| CandidateWheelStageError::WheelInvalid)?;
    let mut directories = BTreeSet::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| CandidateWheelStageError::WheelInvalid)?;
        let name = entry.name().to_owned();
        for (offset, _) in name.match_indices('/') {
            directories.insert(name[..offset].to_owned());
        }
        write_entry(&stage, &name, &mut entry)?;
    }
    fsync(&stage).map_err(|_| CandidateWheelStageError::StageUncertain)?;
    fsync(job).map_err(|_| CandidateWheelStageError::StageUncertain)?;
    Ok((proof, directories.len()))
}

/// Materialize only the already captured Root archive's verified wheel files.
/// One-use partial output is retained on any failure and must never be retried
/// under the same job ID. No candidate code runs and no deployment is created.
pub fn materialize_captured_candidate_wheel_ineligible(
    job_id: &str,
    source_sha: &str,
    source_archive_sha256: &str,
    archive_sha256: &str,
    version: &str,
) -> Result<CandidateWheelStageProof, CandidateWheelStageError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateWheelStageError::RootRequired);
    }
    if !lower_hex(job_id, 16)
        || !is_git_sha(source_sha)
        || !lower_hex(source_archive_sha256, 64)
        || !lower_hex(archive_sha256, 64)
        || !valid_package_version(version)
    {
        return Err(CandidateWheelStageError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateWheelStageError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateWheelStageError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidateWheelStageError::LeaseUnavailable)?;
    let job =
        open_fixed_build_slot(job_id).map_err(|_| CandidateWheelStageError::SourceMismatch)?;
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidateWheelStageError::SourceMismatch)?;
    inactive(job_id).map_err(|_| CandidateWheelStageError::BuildActive)?;
    let descriptor = openat(
        &job,
        ARCHIVE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateWheelStageError::ArchiveInvalid)?;
    let before = fstat(&descriptor).map_err(|_| CandidateWheelStageError::ArchiveInvalid)?;
    if before.st_size <= 0 || before.st_size as u64 > MAX_ARCHIVE {
        return Err(CandidateWheelStageError::ArchiveInvalid);
    }
    let declaration = verify_captured(
        &job,
        archive_sha256,
        before.st_size as u64,
        source_sha,
        version,
    )
    .map_err(|_| CandidateWheelStageError::ArchiveInvalid)?;
    let mut outer = ZipArchive::new(File::from(descriptor))
        .map_err(|_| CandidateWheelStageError::ArchiveInvalid)?;
    let mut wheel_raw = Vec::with_capacity(declaration.wheel_bytes as usize);
    outer
        .by_name(&declaration.wheel)
        .map_err(|_| CandidateWheelStageError::ArchiveInvalid)?
        .take(MAX_ARCHIVE + 1)
        .read_to_end(&mut wheel_raw)
        .map_err(|_| CandidateWheelStageError::ArchiveInvalid)?;
    if wheel_raw.len() as u64 != declaration.wheel_bytes || wheel_raw.len() as u64 > MAX_ARCHIVE {
        return Err(CandidateWheelStageError::ArchiveInvalid);
    }
    let nested = inspect_candidate_wheel(&wheel_raw, &declaration)
        .map_err(|_| CandidateWheelStageError::WheelInvalid)?;
    let held = fstat(outer.into_inner()).map_err(|_| CandidateWheelStageError::ArchiveInvalid)?;
    let visible = statat(&job, ARCHIVE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateWheelStageError::ArchiveInvalid)?;
    if !same_file(&before, &held) || !same_file(&before, &visible) {
        return Err(CandidateWheelStageError::ArchiveInvalid);
    }
    // Recheck the held archive before the one-use directory is created.
    if verify_captured(
        &job,
        archive_sha256,
        before.st_size as u64,
        source_sha,
        version,
    )
    .map_err(|_| CandidateWheelStageError::ArchiveInvalid)?
        != declaration
    {
        return Err(CandidateWheelStageError::ArchiveInvalid);
    }
    let (written, directories) = materialize_wheel(&job, &wheel_raw, &declaration)?;
    if written != nested {
        return Err(CandidateWheelStageError::ReadbackMismatch);
    }
    let stage_path = Path::new("/var/lib/hol-gauntlet/builds")
        .join(job_id)
        .join(STAGE);
    let inventory = inventory_tree(&stage_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidateWheelStageError::ReadbackMismatch)?;
    if inventory.entries != nested.entries + directories
        || inventory.bytes != nested.uncompressed_bytes
    {
        return Err(CandidateWheelStageError::ReadbackMismatch);
    }
    if verify_captured(
        &job,
        archive_sha256,
        before.st_size as u64,
        source_sha,
        version,
    )
    .map_err(|_| CandidateWheelStageError::ArchiveInvalid)?
        != declaration
    {
        return Err(CandidateWheelStageError::ArchiveInvalid);
    }
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidateWheelStageError::SourceMismatch)?;
    inactive(job_id).map_err(|_| CandidateWheelStageError::BuildActive)?;
    lease
        .verify(&journal.root)
        .map_err(|_| CandidateWheelStageError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| CandidateWheelStageError::LeaseUnavailable)?;
    Ok(CandidateWheelStageProof {
        job_id: job_id.to_owned(),
        source_sha: source_sha.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        declaration,
        wheel: nested,
        tree_digest: inventory.digest,
        tree_entries: inventory.entries,
        tree_bytes: inventory.bytes,
    })
}

#[cfg(test)]
#[path = "candidate_wheel_stage_tests.rs"]
mod tests;
