//! Reconcile six distinct one-use staging roots against one host-pinned
//! manifest and Root-owned guest terminals. This cannot qualify a candidate.

use crate::crypto::{is_sha256, sha256};
use crate::io::open_absolute_directory;
use crate::public_files::PublicRootReader;
use crate::python_worker_files::{private_directory, read_private_file};
use crate::{
    observe_staging_physical_files_root_owned_ineligible, EvidenceError, Result,
    StagingEvidencePins,
};
use gauntlet_contracts::{canonicalize, is_git_sha};
use rustix::fs::{open, statat, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

const ROLES: [&str; 6] = [
    "success",
    "input-binding",
    "injection",
    "boundary",
    "timeout",
    "cancel",
];
const INVALID: EvidenceError = EvidenceError::Invalid("invalid host-pinned staging suite");
const STAGING: &str = "/var/lib/hol-gauntlet-rust/staging-state";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingSuiteShadow {
    pub manifest_sha256: String,
    pub signed_records: usize,
    pub physical_files: usize,
    pub absent_effects: usize,
    pub cleanup_journals: usize,
}

impl StagingSuiteShadow {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-staging-suite-shadow.v1",
            "manifest_sha256":self.manifest_sha256,
            "signed_records":self.signed_records,
            "physical_files":self.physical_files,
            "absent_effects":self.absent_effects,
            "cleanup_journals":self.cleanup_journals,
            "host_prelaunch_key_pins_matched":true,
            "outside_cgroups_absent":true,
            "independent_kernel_sdk_effects_verified":false,
            "conformance_package_created":false,
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

fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or(INVALID)
}

fn checked_manifest(raw: &[u8], outside_sha256: &str, build_job_id: &str) -> Result<Value> {
    if raw.is_empty()
        || raw.len() > 8192
        || !lower_hex(build_job_id, 16)
        || !is_sha256(outside_sha256)
        || sha256(raw) != outside_sha256
        || canonicalize(raw).ok().as_deref() != Some(raw)
    {
        return Err(INVALID);
    }
    let manifest: Value = serde_json::from_slice(raw).map_err(|_| INVALID)?;
    if !exact_keys(
        &manifest,
        &[
            "schema",
            "build_job_id",
            "source_sha",
            "version",
            "config_digest",
            "private_manifest_sha256",
            "prefix_tree_sha256",
            "worker_generation_sha256",
            "roles",
            "execution_eligible",
        ],
    ) || manifest["schema"] != "hol-gauntlet-staging-suite-pins.v1"
        || manifest["build_job_id"] != build_job_id
        || manifest["execution_eligible"] != false
        || !is_git_sha(string(&manifest, "source_sha")?)
        || !crate::valid_package_version(string(&manifest, "version")?)
        || [
            "config_digest",
            "private_manifest_sha256",
            "prefix_tree_sha256",
            "worker_generation_sha256",
        ]
        .iter()
        .any(|key| !is_sha256(string(&manifest, key).unwrap_or("")))
        || !exact_keys(&manifest["roles"], &ROLES)
    {
        return Err(INVALID);
    }
    let mut runs = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for role in ROLES {
        let row = &manifest["roles"][role];
        if !exact_keys(
            row,
            &[
                "run_id",
                "record_sha256",
                "controller_public_key_hex",
                "host_record_sha256",
                "controller_key_pin_sha256",
                "started_marker_sha256",
            ],
        ) || !lower_hex(string(row, "run_id")?, 16)
            || !runs.insert(string(row, "run_id")?.to_owned())
            || [
                "record_sha256",
                "controller_public_key_hex",
                "host_record_sha256",
                "controller_key_pin_sha256",
                "started_marker_sha256",
            ]
            .iter()
            .any(|key| !is_sha256(string(row, key).unwrap_or("")))
            || !keys.insert(string(row, "controller_public_key_hex")?.to_owned())
        {
            return Err(INVALID);
        }
    }
    Ok(manifest)
}

fn terminal_and_cleanup(
    journal: &std::os::fd::OwnedFd,
    role: &str,
    common: &Value,
    row: &Value,
) -> Result<()> {
    let run = string(row, "run_id")?;
    let report_name = format!("{run}.report.json");
    let terminal_name = format!("{run}.terminal.json");
    let report_raw = read_private_file(journal, &report_name, 0, 16 * 1024)?.ok_or(INVALID)?;
    let terminal_raw = read_private_file(journal, &terminal_name, 0, 16 * 1024)?.ok_or(INVALID)?;
    let report_canonical = canonicalize(&report_raw).map_err(|_| INVALID)?;
    let terminal_canonical = canonicalize(&terminal_raw).map_err(|_| INVALID)?;
    let report: Value = serde_json::from_slice(&report_canonical).map_err(|_| INVALID)?;
    let terminal: Value = serde_json::from_slice(&terminal_canonical).map_err(|_| INVALID)?;
    if report["schema"] != "hol-gauntlet-staging-control-run-report.v1"
        || report["source_sha"] != common["source_sha"]
        || report["build_job_id"] != common["build_job_id"]
        || report["run_id"] != run
        || report["role"] != role
        || report["provisional_config_digest"] != common["config_digest"]
        || report["controller_public_key_hex"] != row["controller_public_key_hex"]
        || report["exit_code"] != 0
        || report["timed_out"] != false
        || report["controller_and_product_slice_cleanup_verified"] != true
        || report["post_run_controller_custody"] != true
        || report["record_scored"] != false
        || report["execution_eligible"] != false
        || terminal["schema"] != "hol-gauntlet-worker-terminal.v2"
        || terminal["status"] != "invalid-evidence"
        || terminal["source_sha"] != common["source_sha"]
        || terminal["job_id"] != run
        || terminal["deployment_digest"] != common["config_digest"]
        || terminal["worker_generation"] != common["worker_generation_sha256"]
        || terminal["controller_public_key_hex"] != row["controller_public_key_hex"]
        || terminal["controller_key_pin_sha256"] != row["controller_key_pin_sha256"]
        || terminal["started_marker_sha256"] != row["started_marker_sha256"]
        || terminal["report_sha256"] != sha256(&report_raw)
        || terminal["exit_code"] != 0
    {
        return Err(INVALID);
    }
    let cgroup = open(
        "/sys/fs/cgroup/system.slice",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| EvidenceError::Io(error.to_string()))?;
    for name in [
        format!("hol-gauntlet-rust-job-{run}"),
        format!("holgauntletrust{run}.slice"),
    ] {
        match statat(&cgroup, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => {}
            _ => return Err(INVALID),
        }
    }
    Ok(())
}

/// Require a Root-owned copy of the exact host manifest, then open all six
/// distinct records, inspect retained files and reconcile guest journals.
/// Independent live kernel/SDK attribution still needs a separate observer.
pub fn observe_staging_suite_root_owned_ineligible(
    build_job_id: &str,
    outside_manifest_sha256: &str,
) -> Result<StagingSuiteShadow> {
    if geteuid().as_raw() != 0
        || !lower_hex(build_job_id, 16)
        || !is_sha256(outside_manifest_sha256)
    {
        return Err(INVALID);
    }
    let relative = format!(
        "hol-gauntlet/rust-shadow-candidates/{build_job_id}/suite-pins-{}.json",
        &outside_manifest_sha256[..16]
    );
    let root = PublicRootReader::open(Path::new("/opt"))?;
    let metadata = root.file_inventory(&relative, false)?;
    if metadata.sha256 != outside_manifest_sha256
        || metadata.size == 0
        || metadata.size > 8192
        || metadata.uid != 0
        || metadata.mode != 0o444
    {
        return Err(INVALID);
    }
    let raw = root.read_file(&relative, 8192)?;
    let manifest = checked_manifest(&raw, outside_manifest_sha256, build_job_id)?;
    let journal = open_absolute_directory(Path::new(STAGING))?;
    private_directory(&journal, 0)?;
    let mut physical_files = 0;
    let mut absent_effects = 0;
    for role in ROLES {
        let row = &manifest["roles"][role];
        let pins = StagingEvidencePins {
            build_job_id,
            run_id: string(row, "run_id")?,
            role,
            source_sha: string(&manifest, "source_sha")?,
            version: string(&manifest, "version")?,
            config_digest: string(&manifest, "config_digest")?,
            private_manifest_sha256: string(&manifest, "private_manifest_sha256")?,
            prefix_tree_sha256: string(&manifest, "prefix_tree_sha256")?,
            record_sha256: string(row, "record_sha256")?,
            controller_public_key_hex: string(row, "controller_public_key_hex")?,
        };
        let opened = observe_staging_physical_files_root_owned_ineligible(&pins)?;
        physical_files += opened.observed_files;
        absent_effects += opened.absent_effects;
        terminal_and_cleanup(&journal, role, &manifest, row)?;
    }
    if root.read_file(&relative, 8192)? != raw {
        return Err(INVALID);
    }
    Ok(StagingSuiteShadow {
        manifest_sha256: outside_manifest_sha256.to_owned(),
        signed_records: 6,
        physical_files,
        absent_effects,
        cleanup_journals: 6,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_pin_parser_requires_six_distinct_runs_and_keys() {
        let mut roles = serde_json::Map::new();
        for (index, role) in ROLES.iter().enumerate() {
            roles.insert(
                (*role).to_owned(),
                json!({
                    "run_id":format!("{index:016x}"),
                    "record_sha256":"1".repeat(64),
                    "controller_public_key_hex":format!("{:064x}",index+1),
                    "host_record_sha256":"2".repeat(64),
                    "controller_key_pin_sha256":"3".repeat(64),
                    "started_marker_sha256":"4".repeat(64),
                }),
            );
        }
        let mut value = json!({
            "schema":"hol-gauntlet-staging-suite-pins.v1",
            "build_job_id":"0123456789abcdef",
            "source_sha":"a".repeat(40),
            "version":"3.49.0",
            "config_digest":"b".repeat(64),
            "private_manifest_sha256":"c".repeat(64),
            "prefix_tree_sha256":"d".repeat(64),
            "worker_generation_sha256":"e".repeat(64),
            "roles":roles,
            "execution_eligible":false,
        });
        let raw = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(&raw, &sha256(&raw), "0123456789abcdef").is_ok());
        value["roles"]["cancel"]["run_id"] = value["roles"]["success"]["run_id"].clone();
        let duplicate = canonicalize(value.to_string().as_bytes()).unwrap();
        assert!(checked_manifest(&duplicate, &sha256(&duplicate), "0123456789abcdef").is_err());
    }
}
