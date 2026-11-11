//! Fixed Host-to-guest preparation custody. This module stages inert data;
//! the existing worker owns later one-use execution and independent cleanup.
use crate::native_job_spec::{parse_host_pinned_preparation_bundle, NativePreparationBundle};
use crate::{NativeJobExecution, RunReservationJournal};
use gauntlet_contracts::canonicalize;
use gauntlet_evidence::{inventory_tree, verify_installed_version_metadata, TreeKind};
use rustix::fs::{statat, AtFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::fd::RawFd;
use std::path::Path;

pub struct NativeJobPreparationPins<'a> {
    pub source_sha: &'a str,
    pub job_id: &'a str,
    pub deployment_digest: &'a str,
    pub worker_generation: &'a str,
    pub preparation_sha256: &'a str,
    pub bundle_sha256: &'a str,
    pub bundle_bytes: u64,
}

fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn preparation_receipt(
    pins: &NativeJobPreparationPins<'_>,
    bundle: &NativePreparationBundle,
    init_raw: &[u8],
) -> Result<Vec<u8>, String> {
    let sdk = match &bundle.spec.execution {
        NativeJobExecution::HostPinnedControl { sdk, .. }
        | NativeJobExecution::HostPinnedLive { sdk, .. } => Some(sdk.publication_sha256.as_str()),
        _ => None,
    };
    let mut body = json!({"schema":"hol-gauntlet-native-host-pinned-preparation.v1","source_sha":pins.source_sha,"job_id":pins.job_id,
        "deployment_digest":pins.deployment_digest,"worker_generation":pins.worker_generation,"preparation_sha256":pins.preparation_sha256,
        "bundle_sha256":pins.bundle_sha256,"initialization_sha256":sha(init_raw),"control_role":bundle.spec.case(),
        "runtime_tree_sha256":bundle.preparation.runtime_tree_digest,"sdk_publication_sha256":sdk,
        "job_dispatched":false,"candidate_executed":false,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0});
    let init: Value = serde_json::from_slice(init_raw).map_err(|e| e.to_string())?;
    if init["schema"] == "hol-gauntlet-native-job-initialization.v2" {
        body["schema"] = json!("hol-gauntlet-native-host-pinned-preparation.v2");
        body["storage_receipt_sha256"] = init["storage"]["receipt_sha256"].clone();
    } else if matches!(
        bundle.spec.execution,
        NativeJobExecution::HostPinnedLive { .. }
    ) {
        return Err("live jobs require original bounded initialization v2".into());
    }
    canonicalize(body.to_string().as_bytes()).map_err(|e| e.to_string())
}

/// New initialized jobs must have the exact completed preparation receipt.
/// Historical jobs without this namespace retain their existing loader path.
pub(crate) fn verify_staged_job(
    spec: &crate::NativeJobSpec,
    deployment: &str,
    declaration: &[u8],
    preparation: &[u8],
) -> Result<(), String> {
    let path = Path::new("/var/lib/hol-gauntlet-rust/native-initialization");
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let root = crate::open_root_owned_public_directory(path).map_err(|e| e.to_string())?;
    crate::feature_files::private_directory(&root, (0, 0))?;
    let initialized = crate::feature_files::read(
        &root,
        &format!("{}.job.json", spec.job_id),
        (0, 0),
        0o600,
        24576,
    )?;
    let receipt = crate::feature_files::read(
        &root,
        &format!("{}.preparation.json", spec.job_id),
        (0, 0),
        0o600,
        8192,
    )?;
    let Some(initialized) = initialized else {
        crate::native_job_storage::lifecycle::require_absent(&spec.job_id)?;
        return if receipt.is_none() {
            Ok(())
        } else {
            Err("orphan native preparation receipt blocks dispatch".into())
        };
    };
    let receipt = receipt
        .ok_or("initialized native job lacks completed preparation; retain unknown input")?;
    let (original, _) = crate::native_initialize::checked_job_initialization(
        &spec.source_sha,
        &spec.job_id,
        &spec.worker_generation,
        false,
    )?;
    if original != initialized {
        return Err("native job initialization changed before load".into());
    }
    let raw = canonicalize(
        json!({"schema":"hol-gauntlet-native-host-pinned-preparation-input.v1",
        "declaration":serde_json::from_slice::<Value>(declaration).map_err(|e|e.to_string())?,
        "preparation":serde_json::from_slice::<Value>(preparation).map_err(|e|e.to_string())?})
        .to_string()
        .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let bundle_pin = sha(&raw);
    let pins = NativeJobPreparationPins {
        source_sha: &spec.source_sha,
        job_id: &spec.job_id,
        deployment_digest: deployment,
        worker_generation: &spec.worker_generation,
        preparation_sha256: &spec.preparation_sha256,
        bundle_sha256: &bundle_pin,
        bundle_bytes: raw.len() as u64,
    };
    let bundle = parse_host_pinned_preparation_bundle(
        &raw,
        pins.source_sha,
        pins.job_id,
        pins.deployment_digest,
        pins.worker_generation,
        pins.preparation_sha256,
        pins.bundle_sha256,
    )?;
    if declaration != bundle.declaration_raw
        || preparation != bundle.preparation_raw
        || receipt != preparation_receipt(&pins, &bundle, &initialized)?
    {
        return Err(
            "initialized native declaration/preparation differs from completed receipt".into(),
        );
    }
    Ok(())
}

fn file(path: &Path, mode: u32, bound: u64) -> Result<Vec<u8>, String> {
    let parent =
        crate::open_root_owned_public_directory(path.parent().ok_or("native input parent absent")?)
            .map_err(|e| e.to_string())?;
    crate::dependency_io::read(
        &parent,
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or("native input filename absent")?,
        0,
        mode,
        bound,
    )
}

fn code_asset(path: &Path, mode: libc::mode_t, bound: usize) -> Result<Vec<u8>, String> {
    let parent =
        crate::open_root_owned_public_directory(path.parent().ok_or("code asset parent absent")?)
            .map_err(|e| e.to_string())?;
    crate::feature_files::required(
        &parent,
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or("code asset filename absent")?,
        (0, 0),
        mode,
        bound,
    )
}

fn verify_runtime(bundle: &NativePreparationBundle, generation: &str) -> Result<(), String> {
    let _namespace_scope = crate::native_job_storage::owner::scope()?;
    let guard = match &bundle.spec.execution {
        NativeJobExecution::HostPinnedControl { guard, .. }
        | NativeJobExecution::HostPinnedLive { guard, .. }
        | NativeJobExecution::HostPinnedReadonlyHook(guard) => guard,
        _ => return Err("host-pinned preparation requires its explicit Native profile".into()),
    };
    let prefix = &bundle.preparation.runtime_prefix;
    let raw = file(
        &prefix
            .parent()
            .ok_or("published runtime parent absent")?
            .join("native-runtime.v1.json"),
        0o600,
        8192,
    )?;
    if canonicalize(&raw).map_err(|e| e.to_string())? != raw {
        return Err("published runtime receipt must be canonical".into());
    }
    let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let text = |key: &str| value[key].as_str().ok_or("published runtime field missing");
    if value.as_object().is_none_or(|o| o.len() != 21)
        || value["schema"] != "hol-gauntlet-native-runtime-publication.v1"
        || value["source_sha"] != bundle.spec.source_sha
        || value["version"] != guard.package_version
        || value["prefix"] != prefix.to_string_lossy().as_ref()
        || value["prefix_tree_sha256"] != bundle.preparation.runtime_tree_digest
        || value["native_sha256"] != guard.native_sha256
        || ![
            "candidate_executed",
            "conformance_completed",
            "artifact_admitted",
            "execution_eligible",
            "guard_causality_verified",
        ]
        .iter()
        .all(|k| value[*k] == false)
        || value["model_requests"].as_u64() != Some(0)
        || !crate::hex(text("publisher_generation")?, 64)
    {
        return Err("runtime publication differs from preparation/product source pins".into());
    }
    let pins = crate::NativeRuntimePins {
        job_id: text("job_id")?,
        source_sha: &bundle.spec.source_sha,
        version: &guard.package_version,
        clone_receipt_sha256: text("clone_receipt_sha256")?,
        prefix_tree_sha256: &bundle.preparation.runtime_tree_digest,
        native_sha256: &guard.native_sha256,
        python_full_version: value["dependency_requirements"]["python_full_version"]
            .as_str()
            .ok_or("published runtime Python version absent")?,
        generation,
    };
    let slot = crate::builder_candidate_source::open_fixed_build_slot(pins.job_id)
        .map_err(|e| e.to_string())?;
    if crate::dependency_io::read(&slot, "native-runtime-publication.v1.json", 0, 0o600, 8192)?
        != raw
    {
        return Err("published runtime differs from original build publication".into());
    }
    let clone = crate::native_runtime_verify::read(&pins)?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let original = crate::native_runtime_verify::verify(&pins, &clone, &journal)?;
    let current = inventory_tree(prefix, TreeKind::InstalledPrefix).map_err(|e| e.to_string())?;
    if original != current
        || value["prefix_entries"] != current.entries
        || value["prefix_bytes"] != current.bytes
    {
        return Err("published and original inert runtime trees differ".into());
    }
    verify_installed_version_metadata(
        prefix,
        &guard.package_version,
        &guard.source_sha,
        &guard.native_sha256,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn verify_inputs(bundle: &NativePreparationBundle, generation: &str) -> Result<(), String> {
    verify_runtime(bundle, generation)?;
    let p = &bundle.preparation;
    let raw = file(&p.artifacts.join("manifest.json"), 0o444, 1024 * 1024)?;
    let manifest = gauntlet_evidence::verify_native_private_cell_manifest(
        &raw,
        &p.artifact_manifest_sha256,
        &p.initializer_sha256,
    )
    .map_err(|e| e.to_string())?;
    let mut total = 0usize;
    for (name, pin) in manifest.files {
        let mode = if matches!(
            name.as_str(),
            "public/initializer" | "public/gauntlet-product-cell"
        ) {
            0o555
        } else {
            0o444
        };
        let path = p.artifacts.join(&name);
        let bytes = if name.starts_with("code/") {
            code_asset(&path, mode, 2 * 1024 * 1024)
        } else {
            file(&path, mode, 2 * 1024 * 1024)
        }
        .map_err(|error| format!("native preparation artifact {name}: {error}"))?;
        total = total
            .checked_add(bytes.len())
            .filter(|n| *n <= 16 * 1024 * 1024)
            .ok_or("native preparation artifact byte bound")?;
        if sha(&bytes) != pin {
            return Err("native preparation artifact differs from outside manifest".into());
        }
        if name == "public/gauntlet-product-cell" {
            gauntlet_evidence::verify_native_actor_elf(&bytes).map_err(|e| e.to_string())?;
        }
    }
    gauntlet_cell_rootfs::verify_preparation_host_helpers(p)?;
    gauntlet_cell_rootfs::require_image_lease_absent(&p.image_id, &p.podman_sha256)?;
    if let NativeJobExecution::HostPinnedControl { sdk, .. }
    | NativeJobExecution::HostPinnedLive { sdk, .. } = &bundle.spec.execution
    {
        crate::VerifiedNativeSdkAssets::load(sdk)?.verify_after_cleanup()?;
    }
    Ok(())
}

pub fn stage_native_host_pinned_preparation(
    pins: &NativeJobPreparationPins<'_>,
    input: RawFd,
    publish: bool,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(pins.worker_generation).map_err(|e| e.to_string())?;
    if !(1..=65536).contains(&pins.bundle_bytes) || !crate::hex(pins.bundle_sha256, 64) {
        return Err("bounded outside preparation input required".into());
    }
    let mut raw = Vec::new();
    let digest = crate::native_source_stream::copy_source(
        input,
        &mut raw,
        pins.bundle_bytes,
        &crate::BoottimeDeadline::start(30).map_err(|e| e.to_string())?,
        crate::native_worker::cancellation_requested,
    )?;
    if digest != pins.bundle_sha256 {
        return Err("native preparation bundle differs from outside byte pin".into());
    }
    let bundle = parse_host_pinned_preparation_bundle(
        &raw,
        pins.source_sha,
        pins.job_id,
        pins.deployment_digest,
        pins.worker_generation,
        pins.preparation_sha256,
        pins.bundle_sha256,
    )?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let (init_raw, initialized) = crate::native_initialize::job_initialization(
        pins.source_sha,
        pins.job_id,
        pins.worker_generation,
    )?;
    let stable = || -> Result<(), String> {
        lease.verify(&journal.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
        crate::native_initialize::require_unstarted_job(&journal, pins.job_id)?;
        let (current, _) = crate::native_initialize::job_initialization(
            pins.source_sha,
            pins.job_id,
            pins.worker_generation,
        )?;
        if current != init_raw {
            return Err("native job initialization changed during staging".into());
        }
        if crate::native_worker::cancellation_requested() {
            return Err("native preparation cancelled; retain partial input".into());
        }
        Ok(())
    };
    stable()?;
    crate::native_job_io::require_no_unknown_jobs(&journal)?;
    crate::dependency_state::require_idle()?;
    let workspace = &bundle.preparation.task_mounts["workspace"];
    for key in [
        "source",
        "destination",
        "custody_root",
        "device",
        "inode",
        "mode",
    ] {
        if workspace[key] != initialized["workspace"][key] {
            return Err("preparation workspace differs from immutable initialization".into());
        }
    }
    verify_inputs(&bundle, pins.worker_generation)?;
    let root = crate::open_root_owned_public_directory(&bundle.spec.job_root())
        .map_err(|e| e.to_string())?;
    let declarations = crate::open_root_owned_public_directory(Path::new(
        crate::native_job_spec::NATIVE_DEPLOYMENTS,
    ))
    .map_err(|e| e.to_string())?;
    crate::feature_files::private_directory(&declarations, (0, 0))?;
    let receipts = crate::open_root_owned_public_directory(Path::new(
        "/var/lib/hol-gauntlet-rust/native-initialization",
    ))
    .map_err(|e| e.to_string())?;
    crate::feature_files::private_directory(&receipts, (0, 0))?;
    let declaration_name = format!("{}.json", pins.deployment_digest);
    let receipt_name = format!("{}.preparation.json", pins.job_id);
    let expected = preparation_receipt(pins, &bundle, &init_raw)?;
    if publish {
        for (fd, name) in [
            (&root, "preparation.v1.json"),
            (&declarations, declaration_name.as_str()),
            (&receipts, receipt_name.as_str()),
        ] {
            if !matches!(
                statat(fd, name, AtFlags::SYMLINK_NOFOLLOW),
                Err(rustix::io::Errno::NOENT)
            ) {
                return Err("native preparation destination already consumed or uncertain".into());
            }
        }
        stable()?;
        crate::feature_files::write(
            &root,
            "preparation.v1.json",
            &bundle.preparation_raw,
            (0, 0),
            0o600,
        )?;
        stable()?;
        crate::feature_files::write(
            &declarations,
            &declaration_name,
            &bundle.declaration_raw,
            (0, 0),
            0o600,
        )?;
        stable()?;
        crate::feature_files::write(&receipts, &receipt_name, &expected, (0, 0), 0o600)?;
    }
    if crate::feature_files::required(&root, "preparation.v1.json", (0, 0), 0o600, 49152)?
        != bundle.preparation_raw
        || crate::feature_files::required(&declarations, &declaration_name, (0, 0), 0o600, 8192)?
            != bundle.declaration_raw
        || crate::feature_files::required(&receipts, &receipt_name, (0, 0), 0o600, 8192)?
            != expected
    {
        return Err("native preparation/declaration/receipt readback differs".into());
    }
    stable()?;
    verify_inputs(&bundle, pins.worker_generation)?;
    crate::verify_running_binary(pins.worker_generation).map_err(|e| e.to_string())?;
    crate::native_initialize::initialization_result(
        &expected,
        if initialized["schema"] == "hol-gauntlet-native-job-initialization.v2" {
            "hol-gauntlet-native-host-pinned-preparation-result.v2"
        } else {
            "hol-gauntlet-native-host-pinned-preparation-result.v1"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires outside Root; public code assets retain Root ownership and exact modes"]
    fn empty_public_code_is_valid_while_private_empty_receipts_refuse() {
        gauntlet_cell_rootfs::require_outside_root().unwrap();
        let temp = tempfile::tempdir_in("/var/lib/hol-gauntlet-rust").unwrap();
        let root = crate::open_root_owned_public_directory(temp.path()).unwrap();
        crate::feature_files::write(&root, "__init__.py", b"", (0, 0), 0o444).unwrap();
        let code = code_asset(&temp.path().join("__init__.py"), 0o444, 2 * 1024 * 1024).unwrap();
        assert!(code.is_empty());
        assert_eq!(
            sha(&code),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(code_asset(&temp.path().join("__init__.py"), 0o555, 2 * 1024 * 1024).is_err());
        crate::feature_files::write(&root, "empty.json", b"", (0, 0), 0o600).unwrap();
        crate::feature_files::write(&root, "present.json", b"{}", (0, 0), 0o600).unwrap();
        assert!(file(&temp.path().join("empty.json"), 0o600, 8192).is_err());
        assert_eq!(
            file(&temp.path().join("present.json"), 0o600, 8192).unwrap(),
            b"{}"
        );
    }
}
