//! Read-only diagnostic for a Root-owned installed staging template.

use crate::builder_candidate_source::same_file;
use crate::candidate_config_projection::{
    project_candidate_config_ineligible, CandidateConfigProjectionPins,
};
use crate::open_root_owned_public_directory;
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const NAME: &str = "staging-template.json";
const MAX_TEMPLATE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateConfigLiveError {
    RootRequired,
    InvalidTemplatePath,
    InvalidTemplatePin,
    UnsafeTemplate,
    ProjectionRefused,
}

impl fmt::Display for CandidateConfigLiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for installed template check",
            Self::InvalidTemplatePath => "fixed controller staging-template path required",
            Self::InvalidTemplatePin => "outside raw template SHA-256 required",
            Self::UnsafeTemplate => "stable Root-owned staging template required",
            Self::ProjectionRefused => "candidate config projection refused",
        })
    }
}

impl std::error::Error for CandidateConfigLiveError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConfigLiveProof {
    template_path: String,
    template_raw_sha256: String,
    template_canonical_sha256: String,
    config_digest: String,
    config_bytes: usize,
    file_bytes: usize,
}

impl CandidateConfigLiveProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-config-shadow.v1",
            "template_path":self.template_path,
            "template_raw_sha256":self.template_raw_sha256,
            "template_canonical_sha256":self.template_canonical_sha256,
            "config_digest":self.config_digest,
            "config_bytes":self.config_bytes,
            "file_bytes":self.file_bytes,
            "candidate_config_written":false,
            "assets_verified":false,
            "conformance_completed":false,
            "deployment_created":false,
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

fn fixed_template_directory(path: &str) -> Result<&Path, CandidateConfigLiveError> {
    let generation = path
        .strip_prefix("/opt/hol-gauntlet/controller-")
        .and_then(|rest| rest.strip_suffix("/staging-template.json"))
        .ok_or(CandidateConfigLiveError::InvalidTemplatePath)?;
    if !lower_hex(generation, 16) {
        return Err(CandidateConfigLiveError::InvalidTemplatePath);
    }
    Path::new(path)
        .parent()
        .ok_or(CandidateConfigLiveError::InvalidTemplatePath)
}

/// Hash a trusted installed template through stable descriptors, then project
/// only inert JSON. Outside native, prefix and wheel pins are not authenticated
/// here, so this result cannot authorize a candidate run.
pub fn project_installed_candidate_config_ineligible(
    template_path: &str,
    template_raw_sha256: &str,
    template_canonical_sha256: &str,
    pins: &CandidateConfigProjectionPins<'_>,
) -> Result<CandidateConfigLiveProof, CandidateConfigLiveError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateConfigLiveError::RootRequired);
    }
    let parent = fixed_template_directory(template_path)?;
    if !lower_hex(template_raw_sha256, 64) {
        return Err(CandidateConfigLiveError::InvalidTemplatePin);
    }
    let directory = open_root_owned_public_directory(parent)
        .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let directory_before =
        fstat(&directory).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let descriptor = openat(
        &directory,
        NAME,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let before = fstat(&descriptor).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > MAX_TEMPLATE
    {
        return Err(CandidateConfigLiveError::UnsafeTemplate);
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take(MAX_TEMPLATE + 1)
        .read_to_end(&mut raw)
        .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let after = fstat(&file).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible = openat(
        &directory,
        NAME,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible = fstat(&visible).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    if raw.len() as i64 != before.st_size
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
        || format!("{:x}", Sha256::digest(&raw)) != template_raw_sha256
    {
        return Err(CandidateConfigLiveError::UnsafeTemplate);
    }
    let projection = project_candidate_config_ineligible(&raw, template_canonical_sha256, pins)
        .map_err(|_| CandidateConfigLiveError::ProjectionRefused)?;
    let directory_after =
        fstat(&directory).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible_directory = open_root_owned_public_directory(parent)
        .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible_directory =
        fstat(&visible_directory).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let file_after = fstat(&file).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible_file = openat(
        &directory,
        NAME,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible_file =
        fstat(&visible_file).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    if !same_file(&directory_before, &directory_after)
        || !same_file(&directory_before, &visible_directory)
        || !same_file(&before, &file_after)
        || !same_file(&before, &visible_file)
    {
        return Err(CandidateConfigLiveError::UnsafeTemplate);
    }
    Ok(CandidateConfigLiveProof {
        template_path: template_path.to_owned(),
        template_raw_sha256: template_raw_sha256.to_owned(),
        template_canonical_sha256: template_canonical_sha256.to_owned(),
        config_digest: projection.digest,
        config_bytes: projection.canonical_bytes.len(),
        file_bytes: projection.file_bytes.len(),
    })
}
