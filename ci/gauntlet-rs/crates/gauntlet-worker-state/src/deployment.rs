//! Read-only, outside-pinned deployment declaration for the fixed VM tree.
//! This is not worker admission: controller file bytes, interpreter identity,
//! asset custody and conformance still need independent verification.

use crate::{hex, io, open_root_owned_public_directory, ReservationError};
use gauntlet_contracts::{canonical_sha256, canonicalize, is_git_sha};
use rustix::fs::{fstat, openat, FileType, Mode, OFlags, Stat};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

const CANDIDATES: &str = "/opt/hol-gauntlet/candidates";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentDeclaration {
    pub source_sha: String,
    pub deployment_digest: String,
    pub config_digest: String,
    pub controller_path: String,
    pub python_path: String,
}

fn unchanged(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn read_root_file(parent: &OwnedFd, name: &str, limit: u64) -> Result<Vec<u8>, ReservationError> {
    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let before = fstat(&descriptor).map_err(io)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_nlink != 1
        || before.st_size < 0
        || before.st_size as u64 > limit
    {
        return Err(ReservationError::InvalidDeployment);
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(io)?;
    let after = fstat(&file).map_err(io)?;
    if raw.len() as u64 != before.st_size as u64 || !unchanged(&before, &after) {
        return Err(ReservationError::InvalidDeployment);
    }
    Ok(raw)
}

fn json_value(raw: &[u8]) -> Result<Value, ReservationError> {
    let canonical = canonicalize(raw).map_err(|_| ReservationError::InvalidDeployment)?;
    serde_json::from_slice(&canonical).map_err(|_| ReservationError::InvalidDeployment)
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, ReservationError> {
    value[name]
        .as_str()
        .ok_or(ReservationError::InvalidDeployment)
}

fn controller_generation(value: &str) -> bool {
    value
        .strip_prefix("/opt/hol-gauntlet/controller-")
        .is_some_and(|generation| hex(generation, 16))
}

fn controller_python(value: &str) -> bool {
    value
        .strip_prefix("/opt/hol-benchmark-controller-")
        .and_then(|rest| rest.strip_suffix("/.venv/bin/python"))
        .is_some_and(|generation| {
            generation.len() == 8 && generation.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn parse_manifest(
    raw: &[u8],
    source_sha: &str,
    expected_digest: &str,
) -> Result<DeploymentDeclaration, ReservationError> {
    if format!("{:x}", Sha256::digest(raw)) != expected_digest {
        return Err(ReservationError::InvalidDeployment);
    }
    let value = json_value(raw)?;
    let fields = value
        .as_object()
        .ok_or(ReservationError::InvalidDeployment)?;
    if fields.len() != 7
        || field(&value, "schema")? != "hol-gauntlet-deployment.v1"
        || field(&value, "source_sha")? != source_sha
        || field(&value, "asset_root")? != "/opt"
        || !hex(field(&value, "config_digest")?, 64)
    {
        return Err(ReservationError::InvalidDeployment);
    }
    for name in [
        "schema",
        "source_sha",
        "config",
        "config_digest",
        "asset_root",
        "controller",
        "python",
    ] {
        if !fields.contains_key(name) {
            return Err(ReservationError::InvalidDeployment);
        }
    }
    let expected_config = format!("{CANDIDATES}/{source_sha}/config.json");
    let controller = field(&value, "controller")?;
    let python = field(&value, "python")?;
    if field(&value, "config")? != expected_config
        || !controller_generation(controller)
        || !controller_python(python)
    {
        return Err(ReservationError::InvalidDeployment);
    }
    Ok(DeploymentDeclaration {
        source_sha: source_sha.to_owned(),
        deployment_digest: expected_digest.to_owned(),
        config_digest: field(&value, "config_digest")?.to_owned(),
        controller_path: controller.to_owned(),
        python_path: python.to_owned(),
    })
}

/// Read the fixed `/opt/hol-gauntlet/candidates/<source>` declaration through
/// Root-owned no-symlink paths and compare its raw byte digest and canonical
/// config digest to outside pins. No candidate or controller code is executed.
pub fn read_fixed_deployment(
    source_sha: &str,
    expected_deployment_digest: &str,
) -> Result<DeploymentDeclaration, ReservationError> {
    if !is_git_sha(source_sha) || !hex(expected_deployment_digest, 64) {
        return Err(ReservationError::InvalidPins);
    }
    let directory = format!("{CANDIDATES}/{source_sha}");
    let root = open_root_owned_public_directory(Path::new(&directory))?;
    let manifest_raw = read_root_file(&root, "deployment.json", MAX_MANIFEST_BYTES)?;
    let manifest = parse_manifest(&manifest_raw, source_sha, expected_deployment_digest)?;
    let config_raw = read_root_file(&root, "config.json", MAX_CONFIG_BYTES)?;
    let config_digest =
        canonical_sha256(&config_raw).map_err(|_| ReservationError::InvalidDeployment)?;
    if config_digest != manifest.config_digest {
        return Err(ReservationError::InvalidDeployment);
    }
    let config = json_value(&config_raw)?;
    if config["runtime"]["guard_source_sha"] != source_sha {
        return Err(ReservationError::InvalidDeployment);
    }
    open_root_owned_public_directory(Path::new(&manifest.controller_path))?;
    let python_parent = Path::new(&manifest.python_path)
        .parent()
        .ok_or(ReservationError::InvalidDeployment)?;
    open_root_owned_public_directory(python_parent)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn declaration_requires_raw_outside_pin_and_fixed_fields() {
        let source = "a".repeat(40);
        let value = json!({
            "schema":"hol-gauntlet-deployment.v1", "source_sha":source,
            "config":format!("{CANDIDATES}/{source}/config.json"),
            "config_digest":"b".repeat(64), "asset_root":"/opt",
            "controller":"/opt/hol-gauntlet/controller-0123456789abcdef",
            "python":"/opt/hol-benchmark-controller-20261013/.venv/bin/python",
        });
        let raw = serde_json::to_vec(&value).unwrap();
        let pin = format!("{:x}", Sha256::digest(&raw));
        assert!(parse_manifest(&raw, &source, &pin).is_ok());
        assert_eq!(
            parse_manifest(&raw, &source, &"0".repeat(64)),
            Err(ReservationError::InvalidDeployment)
        );
        let mut wrong = value.clone();
        wrong["controller"] = json!("/tmp/attacker");
        let bytes = serde_json::to_vec(&wrong).unwrap();
        let wrong_pin = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            parse_manifest(&bytes, &source, &wrong_pin),
            Err(ReservationError::InvalidDeployment)
        );
    }
}
