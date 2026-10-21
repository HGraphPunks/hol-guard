//! Post-run, descriptor-relative checks of retained physical control files.
//! These checks corroborate filesystem effects, not process, kernel or SDK
//! provenance. The suite remains ineligible until live outside observations
//! and full conformance are independently reconciled.

use crate::crypto::{is_sha256, sha256};
use crate::python_worker_files::{open_private_directory, unchanged};
use crate::staging_control_record::{open_home, read_one};
use crate::{
    observe_staging_control_root_owned_ineligible, EvidenceError, Result, StagingEvidencePins,
};
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, openat2, statat, AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

const INVALID: EvidenceError = EvidenceError::Invalid("invalid staging physical file effect");
const MAX_FILE_BYTES: u64 = 32 * 1024;
const OUTPUT: &[u8] = b"private plane effect";
const PROVIDER: &[u8] = b"idmapped provider effect";
const CANARY: &[u8] = b"synthetic-boundary-canary";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingPhysicalFilesShadow {
    pub role: String,
    pub record_sha256: String,
    pub observed_files: usize,
    pub absent_effects: usize,
}

impl StagingPhysicalFilesShadow {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-staging-physical-files-shadow.v2",
            "role":self.role,
            "record_sha256":self.record_sha256,
            "observed_files":self.observed_files,
            "absent_effects":self.absent_effects,
            "physical_files_checked":true,
            "sdk_stdout_result_bound":true,
            "independent_kernel_sdk_effects_verified":false,
            "execution_eligible":false,
        })
    }
}

fn io(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError::Io(error.to_string())
}

fn read_file_once(root: &OwnedFd, path: &str, owner: u32) -> Result<Option<Vec<u8>>> {
    let fd = match openat2(
        root,
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let before = fstat(&fd).map_err(io)?;
    let visible = statat(root, path, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o600
        || before.st_size < 0
        || before.st_size as u64 > MAX_FILE_BYTES
        || !unchanged(&before, &visible)
    {
        return Err(INVALID);
    }
    let mut file = File::from(fd);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(io)?;
    let after = fstat(&file).map_err(io)?;
    let visible = statat(root, path, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if raw.len() as u64 != before.st_size as u64
        || !unchanged(&before, &after)
        || !unchanged(&before, &visible)
    {
        return Err(INVALID);
    }
    Ok(Some(raw))
}

fn read_stable(root: &OwnedFd, path: &str, owner: u32) -> Result<Option<Vec<u8>>> {
    let first = read_file_once(root, path, owner)?;
    if first != read_file_once(root, path, owner)? {
        return Err(INVALID);
    }
    Ok(first)
}

fn expect_bytes(root: &OwnedFd, path: &str, owner: u32, expected: &[u8]) -> Result<()> {
    if read_stable(root, path, owner)?.as_deref() != Some(expected) {
        return Err(INVALID);
    }
    Ok(())
}

fn expect_absent(root: &OwnedFd, path: &str, owner: u32) -> Result<()> {
    if read_stable(root, path, owner)?.is_some() {
        return Err(INVALID);
    }
    Ok(())
}

fn expect_json_equal(root: &OwnedFd, path: &str, owner: u32, expected: &Value) -> Result<()> {
    let raw = read_stable(root, path, owner)?.ok_or(INVALID)?;
    let observed: Value = serde_json::from_slice(&raw).map_err(|_| INVALID)?;
    if observed != *expected || observed.is_null() {
        return Err(INVALID);
    }
    Ok(())
}

fn audit_file_effects(
    root: &OwnedFd,
    role: &str,
    record: &Value,
    product_uid: u32,
    controller_uid: u32,
) -> Result<(usize, usize)> {
    let mut files = 0;
    let mut absent = 0;
    let stdout = read_stable(root, "sdk.stdout", controller_uid)?.ok_or(INVALID)?;
    let expected_stdout = record["sdk_stdout_sha256"].as_str().ok_or(INVALID)?;
    if !is_sha256(expected_stdout) || sha256(&stdout) != expected_stdout {
        return Err(INVALID);
    }
    let canonical_stdout = canonicalize(&stdout).map_err(|_| INVALID)?;
    let sdk_result: Value = serde_json::from_slice(&canonical_stdout).map_err(|_| INVALID)?;
    if !sdk_result.is_object() || sdk_result != record["sdk_result"] {
        return Err(INVALID);
    }
    files += 1;
    for path in [
        "tasks/remote/private-provider-control.txt",
        "tasks/home/private-provider-control.txt",
    ] {
        expect_bytes(root, path, product_uid, PROVIDER)?;
        files += 1;
    }
    if matches!(role, "success" | "input-binding" | "injection" | "boundary") {
        expect_bytes(
            root,
            "tasks/checkout/native-contained.txt",
            product_uid,
            OUTPUT,
        )?;
        files += 1;
    } else if matches!(role, "timeout" | "cancel") {
        expect_absent(root, "tasks/checkout/native-contained.txt", product_uid)?;
        absent += 1;
    } else {
        return Err(INVALID);
    }
    if matches!(role, "success" | "input-binding" | "injection") {
        expect_json_equal(
            root,
            "tasks/checkout/node-runtime-control.json",
            product_uid,
            &record["node_runtime_closure_control"],
        )?;
        files += 1;
    }
    if matches!(role, "input-binding" | "injection") {
        expect_bytes(
            root,
            "tasks/checkout/forbidden-command-target/synthetic-marker.txt",
            product_uid,
            b"preserve",
        )?;
        files += 1;
    }
    if role == "input-binding" {
        expect_absent(
            root,
            "tasks/checkout/unexpected-negative-sink.txt",
            product_uid,
        )?;
        absent += 1;
    }
    if role == "boundary" {
        for (path, owner) in [
            ("controller-canary.txt", controller_uid),
            ("agent/agent-canary.txt", product_uid),
            (
                "product/builtin-product/state/guard/native-boundary-canary.txt",
                10004,
            ),
        ] {
            expect_bytes(root, path, owner, CANARY)?;
            files += 1;
        }
        expect_json_equal(
            root,
            "tasks/checkout/boundary-negatives.json",
            product_uid,
            &record["native_contained_boundary_negatives"],
        )?;
        files += 1;
    }
    if matches!(role, "timeout" | "cancel") {
        expect_absent(root, "tasks/checkout/late-detached-effect.txt", product_uid)?;
        absent += 1;
    }
    if role == "cancel" {
        let ready =
            read_stable(root, "tasks/checkout/detached-ready.json", product_uid)?.ok_or(INVALID)?;
        let value: Value = serde_json::from_slice(&ready).map_err(|_| INVALID)?;
        if value["token"] != "native-lifecycle-detached-059"
            || value["pid"].as_u64().is_none_or(|pid| pid == 0)
        {
            return Err(INVALID);
        }
        files += 1;
    }
    Ok((files, absent))
}

/// Open the already signed diagnostic first, then corroborate exact retained
/// filesystem effects. This post-run audit cannot authenticate past kernel
/// process samples, SDK execution or a Guard policy decision.
pub fn observe_staging_physical_files_root_owned_ineligible(
    pins: &StagingEvidencePins<'_>,
) -> Result<StagingPhysicalFilesShadow> {
    if geteuid().as_raw() != 0 {
        return Err(EvidenceError::Invalid("Linux Root physical audit required"));
    }
    let opening = observe_staging_control_root_owned_ineligible(pins)?;
    let raw = read_one(pins.run_id, pins.role)?;
    if sha256(&raw) != pins.record_sha256 {
        return Err(INVALID);
    }
    let record: Value = serde_json::from_slice(&raw).map_err(|_| INVALID)?;
    let home = open_home()?;
    let name = format!("hx-{}", pins.run_id);
    let (state, _) = open_private_directory(&home, &name, 0)?.ok_or(INVALID)?;
    let (role, _) = open_private_directory(&state, pins.role, 0)?.ok_or(INVALID)?;
    let (observed_files, absent_effects) = audit_file_effects(&role, pins.role, &record, 10001, 0)?;
    if raw != read_one(pins.run_id, pins.role)? {
        return Err(INVALID);
    }
    Ok(StagingPhysicalFilesShadow {
        role: pins.role.to_owned(),
        record_sha256: opening.record_sha256,
        observed_files,
        absent_effects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::open;
    use rustix::process::getuid;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn file(path: &std::path::Path, raw: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, raw).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn physical_files_require_exact_effects_and_refuse_symlinks() {
        let tree = tempfile::tempdir().unwrap();
        let root = tree.path();
        let uid = getuid().as_raw();
        let stdout = br#"{"modelExercised":false,"results":[]}"#;
        file(&root.join("sdk.stdout"), stdout);
        for path in ["remote", "home"] {
            file(
                &root.join(format!("tasks/{path}/private-provider-control.txt")),
                PROVIDER,
            );
        }
        file(&root.join("tasks/checkout/native-contained.txt"), OUTPUT);
        file(
            &root.join("tasks/checkout/node-runtime-control.json"),
            br#"{"node_version":"v22.22.2"}"#,
        );
        let record = json!({
            "sdk_stdout_sha256":sha256(stdout),
            "sdk_result":{"modelExercised":false,"results":[]},
            "node_runtime_closure_control":{"node_version":"v22.22.2"},
        });
        let descriptor = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            audit_file_effects(&descriptor, "success", &record, uid, uid).unwrap(),
            (5, 0)
        );
        let mut false_result = record.clone();
        false_result["sdk_result"]["modelExercised"] = json!(true);
        assert!(audit_file_effects(&descriptor, "success", &false_result, uid, uid).is_err());
        fs::remove_file(root.join("tasks/checkout/native-contained.txt")).unwrap();
        symlink(
            "node-runtime-control.json",
            root.join("tasks/checkout/native-contained.txt"),
        )
        .unwrap();
        assert!(audit_file_effects(&descriptor, "success", &record, uid, uid).is_err());
    }
}
