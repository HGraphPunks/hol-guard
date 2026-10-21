//! Read-only source/asset/capability preflight before fresh conformance.
//! It never creates a control directory or admits execution.

use crate::builder_candidate_source::same_file;
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::{open_root_owned_public_directory, RunReservationJournal};
use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::{
    inventory_tree, load_runner_config_from_paths, valid_package_version, verify_controller_tree,
    verify_runner_assets_inert, TreeKind,
};
use rustix::fs::{fstat, openat2, statat, AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fmt;
use std::path::Path;

const ASSET_ROOT: &str = "/opt";
const SHADOW_ROOT: &str = "/opt/hol-gauntlet/rust-shadow-candidates";
const COMPLETION: &str =
    "lib/python3.12/site-packages/codex_plugin_scanner/guard/runtime/contained_completion.py";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateConformanceReadinessError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    ControllerMismatch,
    ConfigMismatch,
    AssetMismatch,
    CapabilityUncertain,
}

impl fmt::Display for CandidateConformanceReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for conformance readiness",
            Self::InvalidPins => "exact source, config, controller and prefix pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::ControllerMismatch => "controller tree differs from outside source pin",
            Self::ConfigMismatch => "one-use source-matched config differs from outside pin",
            Self::AssetMismatch => "inert candidate assets differ from config and outside pins",
            Self::CapabilityUncertain => {
                "installed completion capability cannot be resolved safely"
            }
        })
    }
}

impl std::error::Error for CandidateConformanceReadinessError {}

#[derive(Debug, Clone, Copy)]
pub struct CandidateConformanceReadinessPins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub version: &'a str,
    pub config_digest: &'a str,
    pub private_manifest_sha256: &'a str,
    pub prefix_tree_sha256: &'a str,
    pub controller_path: &'a str,
    pub controller_tree_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConformanceReadinessProof {
    job_id: String,
    source_sha: String,
    version: String,
    config_digest: String,
    private_manifest_sha256: String,
    prefix_tree_sha256: String,
    controller_tree_sha256: String,
    controller_entries: usize,
    asset_roles: usize,
    completion_present: bool,
}

impl CandidateConformanceReadinessProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-conformance-readiness.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "version":self.version,
            "config_digest":self.config_digest,
            "private_manifest_sha256":self.private_manifest_sha256,
            "prefix_tree_sha256":self.prefix_tree_sha256,
            "controller_tree_sha256":self.controller_tree_sha256,
            "controller_entries":self.controller_entries,
            "asset_roles":self.asset_roles,
            "contained_completion_present":self.completion_present,
            "missing_capabilities":if self.completion_present { vec![] } else { vec!["contained-output-completion.v1"] },
            "conformance_started":false,
            "model_requests":0,
            "outside_source_reviewed":false,
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

fn controller_path_valid(raw: &str) -> bool {
    raw.strip_prefix("/opt/hol-gauntlet/controller-")
        .is_some_and(|generation| lower_hex(generation, 16))
}

fn completion_present(prefix: &Path) -> Result<bool, CandidateConformanceReadinessError> {
    let root = open_root_owned_public_directory(prefix)
        .map_err(|_| CandidateConformanceReadinessError::CapabilityUncertain)?;
    let descriptor = match openat2(
        &root,
        COMPLETION,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(false),
        Err(_) => return Err(CandidateConformanceReadinessError::CapabilityUncertain),
    };
    let before =
        fstat(&descriptor).map_err(|_| CandidateConformanceReadinessError::CapabilityUncertain)?;
    let visible = statat(&root, COMPLETION, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateConformanceReadinessError::CapabilityUncertain)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size > 2 * 1024 * 1024
        || !same_file(&before, &visible)
    {
        return Err(CandidateConformanceReadinessError::CapabilityUncertain);
    }
    Ok(true)
}

/// Repeat complete inert reads under both worker locks. Presence of the
/// completion module is only a diagnostic gate; actual controls and independent
/// source review are still required before a deployment can exist.
pub fn inspect_candidate_conformance_readiness_ineligible(
    pins: &CandidateConformanceReadinessPins<'_>,
) -> Result<CandidateConformanceReadinessProof, CandidateConformanceReadinessError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateConformanceReadinessError::RootRequired);
    }
    if !lower_hex(pins.job_id, 16)
        || !is_git_sha(pins.source_sha)
        || !valid_package_version(pins.version)
        || !lower_hex(pins.config_digest, 64)
        || !lower_hex(pins.private_manifest_sha256, 64)
        || !lower_hex(pins.prefix_tree_sha256, 64)
        || !lower_hex(pins.controller_tree_sha256, 64)
        || !controller_path_valid(pins.controller_path)
    {
        return Err(CandidateConformanceReadinessError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateConformanceReadinessError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateConformanceReadinessError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidateConformanceReadinessError::LeaseUnavailable)?;
    let controller =
        verify_controller_tree(Path::new(pins.controller_path), pins.controller_tree_sha256)
            .map_err(|_| CandidateConformanceReadinessError::ControllerMismatch)?;
    let base = format!("hol-gauntlet/rust-shadow-candidates/{}", pins.job_id);
    let config_name = format!("provisional-{}.json", &pins.private_manifest_sha256[..16]);
    let config_path = Path::new(SHADOW_ROOT).join(pins.job_id).join(config_name);
    let loaded =
        load_runner_config_from_paths(&config_path, pins.config_digest, Path::new(ASSET_ROOT))
            .map_err(|_| CandidateConformanceReadinessError::ConfigMismatch)?;
    let config = loaded.verified.config.value();
    let expected_id = format!(
        "rust-shadow-{}-{}-{}",
        pins.source_sha,
        pins.job_id,
        &pins.private_manifest_sha256[..16]
    );
    if loaded.verified.version != 7
        || config["id"] != expected_id
        || config["runtime"]["guard_source_sha"] != pins.source_sha
        || config["runtime"]["guard_package_version"] != pins.version
        || config["assets"]["guard_prefix"]["path"] != format!("{base}/prefix")
        || config["assets"]["guard_prefix"]["sha256"] != pins.prefix_tree_sha256
        || config["assets"]["private_cell"]["path"] != format!("{base}/cell-artifacts")
        || config["assets"]["private_cell"]["sha256"] != pins.private_manifest_sha256
    {
        return Err(CandidateConformanceReadinessError::ConfigMismatch);
    }
    let assets = verify_runner_assets_inert(&loaded, Path::new(ASSET_ROOT))
        .map_err(|_| CandidateConformanceReadinessError::AssetMismatch)?;
    let prefix = Path::new(SHADOW_ROOT).join(pins.job_id).join("prefix");
    let completion = completion_present(&prefix)?;
    if inventory_tree(&prefix, TreeKind::InstalledPrefix)
        .map_err(|_| CandidateConformanceReadinessError::AssetMismatch)?
        .digest
        != pins.prefix_tree_sha256
        || verify_controller_tree(Path::new(pins.controller_path), pins.controller_tree_sha256)
            .map_err(|_| CandidateConformanceReadinessError::ControllerMismatch)?
            .entries()
            != controller.entries()
    {
        return Err(CandidateConformanceReadinessError::AssetMismatch);
    }
    lease
        .verify(&journal.root)
        .map_err(|_| CandidateConformanceReadinessError::LeaseUnavailable)?;
    verify_python_lock(&python_lock)
        .map_err(|_| CandidateConformanceReadinessError::LeaseUnavailable)?;
    Ok(CandidateConformanceReadinessProof {
        job_id: pins.job_id.to_owned(),
        source_sha: pins.source_sha.to_owned(),
        version: pins.version.to_owned(),
        config_digest: pins.config_digest.to_owned(),
        private_manifest_sha256: pins.private_manifest_sha256.to_owned(),
        prefix_tree_sha256: pins.prefix_tree_sha256.to_owned(),
        controller_tree_sha256: pins.controller_tree_sha256.to_owned(),
        controller_entries: controller.entries(),
        asset_roles: assets.observed.len(),
        completion_present: completion,
    })
}
