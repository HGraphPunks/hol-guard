//! Inert, one-use clone of a reviewed dependency prefix with candidate wheel
//! files overlaid as data. No interpreter, installer, hook or candidate import
//! runs here. This is not a conformance or deployment admission path.

use crate::builder_candidate_source::{open_fixed_build_slot, verify_captured_source};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_capture::{inactive, verify_captured};
use crate::RunReservationJournal;
use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::{inventory_tree, valid_package_version, TreeKind};
use rustix::fs::{fchmod, fstat, fsync, mkdirat, open, openat, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fmt;
use std::path::{Component, Path};

const STAGE: &str = "inert-wheel";
const TARGET: &str = "inert-prefix";
#[path = "candidate_prefix_files.rs"]
mod files;
pub(crate) use files::clone_baseline;
use files::{overlay_wheel, private_directory};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePrefixCloneError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    SourceMismatch,
    BuildActive,
    ArchiveInvalid,
    BaselineMismatch,
    StageMismatch,
    ConsoleScriptsInvalid,
    ExistingClone,
    CloneUncertain,
    ReadbackMismatch,
}

impl fmt::Display for CandidatePrefixCloneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for inert prefix clone",
            Self::InvalidPins => "exact baseline, source, archive and wheel-tree pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::SourceMismatch => "captured source differs from outside digest",
            Self::BuildActive => "candidate build or cleanup remains active or uncertain",
            Self::ArchiveInvalid => "captured candidate archive differs from outside pins",
            Self::BaselineMismatch => "reviewed baseline prefix differs from outside tree pin",
            Self::StageMismatch => "one-use inert wheel stage differs from outside tree pin",
            Self::ConsoleScriptsInvalid => "wheel console declaration or launcher custody differs",
            Self::ExistingClone => "one-use inert prefix clone already exists",
            Self::CloneUncertain => "private prefix clone could not be written durably",
            Self::ReadbackMismatch => "cloned prefix bytes or tree metadata differ on readback",
        })
    }
}

impl std::error::Error for CandidatePrefixCloneError {}

#[derive(Debug, Clone, Copy)]
pub struct CandidatePrefixClonePins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub source_archive_sha256: &'a str,
    pub archive_sha256: &'a str,
    pub version: &'a str,
    pub baseline_path: &'a Path,
    pub baseline_tree_sha256: &'a str,
    pub stage_tree_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePrefixCloneProof {
    job_id: String,
    source_sha: String,
    archive_sha256: String,
    baseline_tree_sha256: String,
    stage_tree_sha256: String,
    prefix_tree_sha256: String,
    prefix_entries: usize,
    prefix_bytes: u64,
    wheel_files: usize,
}

impl CandidatePrefixCloneProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-prefix-clone-shadow.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "archive_sha256":self.archive_sha256,
            "baseline_tree_sha256":self.baseline_tree_sha256,
            "stage_tree_sha256":self.stage_tree_sha256,
            "prefix_tree_sha256":self.prefix_tree_sha256,
            "prefix_entries":self.prefix_entries,
            "prefix_bytes":self.prefix_bytes,
            "wheel_files":self.wheel_files,
            "candidate_executed":false,
            "dependency_validation_completed":false,
            "conformance_completed":false,
            "artifact_admitted":false,
            "execution_eligible":false,
        })
    }
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_baseline(path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix("/opt/hol-gauntlet/candidates") else {
        return false;
    };
    let mut components = relative.components();
    matches!(
        (components.next(), components.next(), components.next()),
        (Some(Component::Normal(source)), Some(Component::Normal(prefix)), None)
            if source.to_str().is_some_and(is_git_sha) && prefix == "prefix"
    )
}

/// Clone a separately pinned baseline and overlay a one-use inert wheel tree.
/// A partial clone is retained on failure. No installer or candidate process
/// runs, and the result cannot be used as a deployment.
pub fn clone_captured_candidate_prefix_ineligible(
    pins: &CandidatePrefixClonePins<'_>,
) -> Result<CandidatePrefixCloneProof, CandidatePrefixCloneError> {
    clone_prefix(pins, None)
}

pub(crate) fn clone_prefix(
    pins: &CandidatePrefixClonePins<'_>,
    native: Option<&crate::native_candidate_prefix::NativeCandidatePrefixPins<'_>>,
) -> Result<CandidatePrefixCloneProof, CandidatePrefixCloneError> {
    let CandidatePrefixClonePins {
        job_id,
        source_sha,
        source_archive_sha256,
        archive_sha256,
        version,
        baseline_path,
        baseline_tree_sha256,
        stage_tree_sha256,
    } = *pins;
    if geteuid().as_raw() != 0 {
        return Err(CandidatePrefixCloneError::RootRequired);
    }
    if !lower_hex(job_id, 16)
        || !is_git_sha(source_sha)
        || !lower_hex(source_archive_sha256, 64)
        || !lower_hex(archive_sha256, 64)
        || !valid_package_version(version)
        || native.is_none() && !valid_baseline(baseline_path)
        || !lower_hex(baseline_tree_sha256, 64)
        || !lower_hex(stage_tree_sha256, 64)
    {
        return Err(CandidatePrefixCloneError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    if let Some(native) = native {
        crate::native_candidate_prefix::verify(native, baseline_path, &journal)
            .map_err(|_| CandidatePrefixCloneError::BaselineMismatch)?;
    }
    let job =
        open_fixed_build_slot(job_id).map_err(|_| CandidatePrefixCloneError::SourceMismatch)?;
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidatePrefixCloneError::SourceMismatch)?;
    inactive(job_id).map_err(|_| CandidatePrefixCloneError::BuildActive)?;
    let archive = openat(
        &job,
        "candidate.zip",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::ArchiveInvalid)?;
    let archive_stat = fstat(&archive).map_err(|_| CandidatePrefixCloneError::ArchiveInvalid)?;
    if archive_stat.st_size <= 0 {
        return Err(CandidatePrefixCloneError::ArchiveInvalid);
    }
    verify_captured(
        &job,
        archive_sha256,
        archive_stat.st_size as u64,
        source_sha,
        version,
    )
    .map_err(|_| CandidatePrefixCloneError::ArchiveInvalid)?;
    let stage_path = Path::new("/var/lib/hol-gauntlet/builds")
        .join(job_id)
        .join(STAGE);
    let baseline = inventory_tree(baseline_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidatePrefixCloneError::BaselineMismatch)?;
    let stage = inventory_tree(&stage_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
    if baseline.digest != baseline_tree_sha256 {
        return Err(CandidatePrefixCloneError::BaselineMismatch);
    }
    if stage.digest != stage_tree_sha256 {
        return Err(CandidatePrefixCloneError::StageMismatch);
    }
    let baseline_fd = open(
        baseline_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::BaselineMismatch)?;
    let stage_fd = openat(
        &job,
        STAGE,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
    private_directory(&stage_fd).map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
    if native.is_some() {
        crate::native_candidate_launchers::validate(&stage_fd, version)
            .map_err(|_| CandidatePrefixCloneError::ConsoleScriptsInvalid)?;
    }
    match mkdirat(&job, TARGET, Mode::from_bits_truncate(0o700)) {
        Ok(()) => (),
        Err(Errno::EXIST) => return Err(CandidatePrefixCloneError::ExistingClone),
        Err(_) => return Err(CandidatePrefixCloneError::CloneUncertain),
    }
    fsync(&job).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let target = openat(
        &job,
        TARGET,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    private_directory(&target)?;
    let mut seen = 0_usize;
    let mut bytes = 0_u64;
    clone_baseline(&baseline_fd, &target, "", 0, &mut seen, &mut bytes, true)?;
    let mut wheel_files = 0_usize;
    overlay_wheel(&stage_fd, &target, "", 0, &mut wheel_files, &mut bytes)?;
    if native.is_some() {
        bytes += crate::native_candidate_launchers::write(&stage_fd, &target, version)
            .map_err(|_| CandidatePrefixCloneError::ConsoleScriptsInvalid)?;
    }
    if wheel_files == 0 {
        return Err(CandidatePrefixCloneError::StageMismatch);
    }
    fchmod(&target, Mode::from_bits_truncate(0o755))
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    fsync(&target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    fsync(&job).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let target_path = Path::new("/var/lib/hol-gauntlet/builds")
        .join(job_id)
        .join(TARGET);
    let cloned = inventory_tree(&target_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    if cloned.bytes != bytes {
        return Err(CandidatePrefixCloneError::ReadbackMismatch);
    }
    if inventory_tree(baseline_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidatePrefixCloneError::BaselineMismatch)?
        .digest
        != baseline_tree_sha256
        || inventory_tree(&stage_path, TreeKind::InstalledPrefix)
            .map_err(|_| CandidatePrefixCloneError::StageMismatch)?
            .digest
            != stage_tree_sha256
    {
        return Err(CandidatePrefixCloneError::ReadbackMismatch);
    }
    verify_captured(
        &job,
        archive_sha256,
        archive_stat.st_size as u64,
        source_sha,
        version,
    )
    .map_err(|_| CandidatePrefixCloneError::ArchiveInvalid)?;
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidatePrefixCloneError::SourceMismatch)?;
    inactive(job_id).map_err(|_| CandidatePrefixCloneError::BuildActive)?;
    lease
        .verify(&journal.root)
        .map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    let proof = CandidatePrefixCloneProof {
        job_id: job_id.to_owned(),
        source_sha: source_sha.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        baseline_tree_sha256: baseline_tree_sha256.to_owned(),
        stage_tree_sha256: stage_tree_sha256.to_owned(),
        prefix_tree_sha256: cloned.digest,
        prefix_entries: cloned.entries,
        prefix_bytes: cloned.bytes,
        wheel_files,
    };
    if let Some(native) = native {
        crate::native_candidate_prefix::verify(native, baseline_path, &journal)
            .map_err(|_| CandidatePrefixCloneError::BaselineMismatch)?;
        crate::builder_candidate_receipt::write_root_canonical_job_file(
            &job,
            "native-candidate-prefix.v1.json",
            &crate::native_candidate_prefix::value(&proof, native),
        )
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        lease
            .verify(&journal.root)
            .map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
        verify_python_lock(&python_lock)
            .map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    }
    Ok(proof)
}

#[cfg(test)]
#[path = "candidate_prefix_clone_tests.rs"]
mod tests;
