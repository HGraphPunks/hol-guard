//! Read-only recovery of completed bounded build artifacts.
use super::*;
use crate::builder_candidate_preflight::CandidateRuntimePins;
use crate::candidate_host_anchor::{HostCandidateRunAnchor, HOST_ANCHOR_FILE};
use crate::candidate_result_read::{parse_result, root_file_hash, HostBoundCandidateResultPins};
use crate::native_job_storage::{linux, source, JobStorageProfile};
use std::collections::BTreeSet;

pub struct NativeCandidateArtifactReadPins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub source_archive_sha256: &'a str,
    pub archive_sha256: &'a str,
    pub version: &'a str,
    pub original_producer_sha256: &'a str,
    pub host_pin_sha256: &'a str,
    pub result_sha256: &'a str,
    pub storage_receipt_sha256: &'a str,
    pub reader_generation: &'a str,
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("original artifact {key} pin absent"))
}
fn canonical_value(raw: &[u8]) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if linux::canonical(&v)? != raw {
        return Err("canonical original artifact custody required".into());
    }
    Ok(v)
}
fn producer(p: &NativeCandidateArtifactReadPins<'_>, operation: &str) -> Result<(), String> {
    let parent = crate::open_root_owned_public_directory(Path::new("/opt/hol-gauntlet"))
        .map_err(|e| e.to_string())?;
    let name = format!(
        "rust-candidate-{operation}-shadow-{}",
        p.original_producer_sha256
    );
    let mut file = File::from(
        openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    crate::native_job_storage::owner::hash_executable(&mut file, p.original_producer_sha256)
}
fn bounded_source(p: &NativeCandidateArtifactReadPins<'_>, job: &OwnedFd) -> Result<Value, String> {
    let original = source::verify(p.job_id, job, Some(JobStorageProfile::Build))?
        .ok_or("completed artifact reads require original bounded Source.v2")?;
    if original["source_sha"] != p.source_sha
        || original["source_archive_sha256"] != p.source_archive_sha256
        || original["storage"]["receipt_sha256"] != p.storage_receipt_sha256
    {
        return Err("artifact read differs from original bounded Source/storage".into());
    }
    Ok(original)
}
fn context(p: &NativeCandidateArtifactReadPins<'_>, job: &OwnedFd) -> Result<Value, String> {
    let original = bounded_source(p, job)?;
    let volume = crate::open_root_owned_public_directory(
        &Path::new("/var/lib/hol-gauntlet-rust/job-volumes").join(p.job_id),
    )
    .map_err(|e| e.to_string())?;
    let stamp_raw =
        crate::feature_files::required(&volume, "artifact-read.json", (0, 0), 0o600, 24576)?;
    let stamp = canonical_value(&stamp_raw)?;
    if stamp.as_object().is_none_or(|v| v.len() != 10)
        || stamp["schema"] != "hol-gauntlet-source-storage-artifact-read.v1"
        || stamp["source_capture"] != original
        || stamp["source_capture_sha256"] != linux::sha(&linux::canonical(&original)?)
        || stamp["profile"] != "build-v1"
        || stamp["job_id"] != p.job_id
        || stamp["storage_receipt_sha256"] != p.storage_receipt_sha256
        || stamp["archive_sha256"] != p.archive_sha256
        || stamp["result_sha256"] != p.result_sha256
        || stamp["host_binding_sha256"] != p.host_pin_sha256
        || !stamp["readback_sha256"]
            .as_str()
            .is_some_and(|s| crate::hex(s, 64))
    {
        return Err("original authenticated Host-bound result read is required".into());
    }
    let anchor_raw = crate::dependency_io::read(job, HOST_ANCHOR_FILE, 0, 0o600, 8192)?;
    let a = canonical_value(&anchor_raw)?;
    let runtime = CandidateRuntimePins::parse(
        text(&a["runtime_pins"], "podman_sha256")?,
        text(&a["runtime_pins"], "slirp4netns_sha256")?,
        text(&a["runtime_pins"], "apparmor_parser_sha256")?,
        text(&a["runtime_pins"], "seccomp_sha256")?,
    )
    .map_err(|e| e.to_string())?;
    let arguments = [
        text(&a, "policy_sha256")?,
        text(&a, "result_reader_binary_sha256")?,
        text(&a, "host_pin_sha256")?,
        text(&a, "host_nonce_hex")?,
        text(&a, "runner_binary_sha256")?,
    ];
    let anchor = if let Some(tag) = a.get("tag").and_then(Value::as_str) {
        HostCandidateRunAnchor::parse_with_tag(
            arguments[0],
            arguments[1],
            arguments[2],
            arguments[3],
            arguments[4],
            tag,
        )
    } else {
        HostCandidateRunAnchor::parse(
            arguments[0],
            arguments[1],
            arguments[2],
            arguments[3],
            arguments[4],
        )
    }
    .ok_or("original Host anchor pins invalid")?;
    let bound = HostBoundCandidateResultPins {
        job_id: p.job_id.into(),
        source_sha: p.source_sha.into(),
        source_archive_sha256: p.source_archive_sha256.into(),
        result_sha256: p.result_sha256.into(),
        archive_sha256: p.archive_sha256.into(),
        version: p.version.into(),
        tag: anchor.tag.clone(),
        controller_tree_sha256: text(&a, "controller_tree_sha256")?.into(),
        image_id: text(&a, "image_id")?.into(),
        policy_sha256: arguments[0].into(),
        runtime,
        anchor,
    };
    if !bound.valid()
        || bound.anchor.host_pin_sha256 != p.host_pin_sha256
        || linux::canonical(&bound.anchor.body(
            p.job_id,
            p.source_sha,
            p.source_archive_sha256,
            p.version,
            &bound.controller_tree_sha256,
            &bound.image_id,
            &bound.runtime,
        ))? != anchor_raw
    {
        return Err("original complete Host anchor differs".into());
    }
    let result_raw = crate::dependency_io::read(job, "candidate-run.result.json", 0, 0o600, 8192)?;
    if linux::sha(&result_raw) != p.result_sha256 {
        return Err("outside completed result hash differs".into());
    }
    let result = parse_result(
        &result_raw,
        p.job_id,
        p.source_sha,
        p.source_archive_sha256,
        p.archive_sha256,
        p.version,
        Some(&bound),
    )
    .map_err(|e| e.to_string())?;
    if result["host_anchor_sha256"] != linux::sha(&anchor_raw) {
        return Err("original result/Host anchor digest differs".into());
    }
    crate::builder_candidate_preflight::verify_candidate_runtime_files(&bound.runtime)
        .map_err(|e| e.to_string())?;
    let bytes = verify_captured_source(job, p.source_archive_sha256).map_err(|e| e.to_string())?;
    let export = crate::builder_candidate_source::unadmitted_export_identity(job)
        .map_err(|e| e.to_string())?
        .ok_or("original completed build export absent")?;
    if result["source_bytes"] != bytes
        || result["unadmitted_export_bytes"] != export.0
        || export.1 != p.archive_sha256
    {
        return Err("original source/export bytes differ from result".into());
    }
    for (name, key) in [
        ("candidate-run.stdout.log", "stdout_sha256"),
        ("candidate-run.stderr.log", "stderr_sha256"),
    ] {
        if result[key]
            != root_file_hash(job, name, 16 * 1024 * 1024, 0o600, true)
                .map_err(|e| e.to_string())?
                .1
        {
            return Err("original completed build log differs".into());
        }
    }
    inactive(p.job_id).map_err(|e| e.to_string())?;
    crate::require_rust_job_slice_absent(p.job_id).map_err(|e| e.to_string())?;
    crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
    Ok(
        json!({"source":original,"read_stamp_sha256":linux::sha(&stamp_raw),"anchor_sha256":linux::sha(&anchor_raw),"result_sha256":linux::sha(&result_raw),"archive_bytes":export.0}),
    )
}

pub(crate) fn retained_wheel(
    job: &OwnedFd,
    archive: &str,
    source: &str,
    version: &str,
) -> Result<(CandidateArchiveDeclaration, CandidateWheelProof), CandidateCaptureError> {
    let (declaration, proof, _) = retained_wheel_bytes(job, archive, source, version)?;
    Ok((declaration, proof))
}

fn existing_parent(stage: &OwnedFd, name: &str) -> Result<(OwnedFd, String), String> {
    let mut parent = stage.try_clone().map_err(|e| e.to_string())?;
    let parts = name.split('/').collect::<Vec<_>>();
    if parts.len() < 2
        || parts
            .iter()
            .any(|s| s.is_empty() || matches!(*s, "." | "..") || s.contains('\\'))
    {
        return Err("ordinary inert wheel path required".into());
    }
    for part in &parts[..parts.len() - 1] {
        let fd = openat(
            &parent,
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        crate::candidate_wheel_stage::private_directory(&fd).map_err(|e| e.to_string())?;
        let visible =
            statat(&parent, *part, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        if !same_file(&fstat(&fd).map_err(|e| e.to_string())?, &visible) {
            return Err("inert wheel directory replaced".into());
        }
        parent = fd;
    }
    Ok((parent, parts.last().unwrap().to_string()))
}

pub(crate) fn verify_stage(
    job: &OwnedFd,
    path: &Path,
    raw: &[u8],
    declaration: &CandidateArchiveDeclaration,
) -> Result<gauntlet_evidence::TreeInventory, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    let proof = inspect_candidate_wheel(raw, declaration).map_err(|e| e.to_string())?;
    let stage = openat(
        job,
        "inert-wheel",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    crate::candidate_wheel_stage::private_directory(&stage).map_err(|e| e.to_string())?;
    let before = fstat(&stage).map_err(|e| e.to_string())?;
    let mut zip = ZipArchive::new(std::io::Cursor::new(raw)).map_err(|e| e.to_string())?;
    let mut directories = BTreeSet::new();
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(|e| e.to_string())?;
        let name = entry.name().to_owned();
        for (offset, _) in name.match_indices('/') {
            directories.insert(name[..offset].to_owned());
        }
        let (parent, base) = existing_parent(&stage, &name)?;
        let actual =
            crate::feature_files::required(&parent, &base, (0, 0), 0o444, 128 * 1024 * 1024)?;
        let mut expected = Vec::new();
        Read::by_ref(&mut entry)
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut expected)
            .map_err(|e| e.to_string())?;
        if expected.len() as u64 != entry.size()
            || expected.len() > 128 * 1024 * 1024
            || actual != expected
        {
            return Err(format!("retained inert wheel entry differs: {name}"));
        }
    }
    let inventory = gauntlet_evidence::inventory_tree(
        &path.join("inert-wheel"),
        gauntlet_evidence::TreeKind::InstalledPrefix,
    )
    .map_err(|e| e.to_string())?;
    let visible =
        statat(job, "inert-wheel", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&before, &fstat(&stage).map_err(|e| e.to_string())?)
        || !same_file(&before, &visible)
        || inventory.entries != proof.entries + directories.len()
        || inventory.bytes != proof.uncompressed_bytes
    {
        return Err("inert stage incomplete, replaced or contains extra entries".into());
    }
    Ok(inventory)
}

fn read(p: &NativeCandidateArtifactReadPins<'_>, operation: &str) -> Result<Value, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if !crate::hex(p.job_id, 16)
        || !crate::hex(p.source_sha, 40)
        || !valid_package_version(p.version)
        || ![
            p.source_archive_sha256,
            p.archive_sha256,
            p.original_producer_sha256,
            p.host_pin_sha256,
            p.result_sha256,
            p.storage_receipt_sha256,
            p.reader_generation,
        ]
        .iter()
        .all(|s| crate::hex(s, 64))
    {
        return Err("complete original bounded artifact read pins required".into());
    }
    crate::verify_running_binary(p.reader_generation).map_err(|e| e.to_string())?;
    let _namespace_scope = crate::native_job_storage::owner::scope()?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(RUST_STATE)).map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = python_worker_lock().map_err(|e| e.to_string())?;
    let job =
        open_fixed_build_slot(p.job_id).map_err(|e| format!("artifact job {}: {e}", p.job_id))?;
    let selected =
        bounded_source(p, &job).map_err(|e| format!("artifact job {}: {e}", p.job_id))?;
    crate::native_job_io::require_no_unknown_jobs(&journal)?;
    crate::dependency_state::require_idle()?;
    producer(p, operation)?;
    let original = context(p, &job)?;
    if original["source"] != selected {
        return Err(format!(
            "artifact job {}: original Source custody changed",
            p.job_id
        ));
    }
    let proof = if operation == "capture" {
        let bytes = original["archive_bytes"]
            .as_u64()
            .ok_or("original archive byte count absent")?;
        let declaration = verify_captured(&job, p.archive_sha256, bytes, p.source_sha, p.version)
            .map_err(|e| e.to_string())?;
        CandidateCaptureProof {
            job_id: p.job_id.into(),
            source_sha: p.source_sha.into(),
            source_archive_sha256: p.source_archive_sha256.into(),
            archive_sha256: p.archive_sha256.into(),
            archive_bytes: bytes,
            declaration,
        }
        .to_json()
    } else {
        let (declaration, wheel, raw) =
            retained_wheel_bytes(&job, p.archive_sha256, p.source_sha, p.version)
                .map_err(|e| e.to_string())?;
        let inventory = verify_stage(
            &job,
            &Path::new("/var/lib/hol-gauntlet/builds").join(p.job_id),
            &raw,
            &declaration,
        )?;
        crate::candidate_wheel_stage::completed_readback(
            p.job_id,
            p.source_sha,
            p.archive_sha256,
            declaration,
            wheel,
            inventory,
        )
    };
    if context(p, &job)? != original {
        return Err("original bounded artifact custody changed during read".into());
    }
    producer(p, operation)?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    verify_python_lock(&python).map_err(|e| e.to_string())?;
    crate::verify_running_binary(p.reader_generation).map_err(|e| e.to_string())?;
    Ok(
        json!({"schema":"hol-gauntlet-native-candidate-artifact-completed-read.v1","operation":operation,"job_id":p.job_id,"source_sha":p.source_sha,"source_archive_sha256":p.source_archive_sha256,"archive_sha256":p.archive_sha256,"version":p.version,"original_producer_sha256":p.original_producer_sha256,"host_pin_sha256":p.host_pin_sha256,"result_sha256":p.result_sha256,"storage_receipt_sha256":p.storage_receipt_sha256,"reader_generation":p.reader_generation,"proof":proof}),
    )
}
pub fn read_native_candidate_capture(
    p: &NativeCandidateArtifactReadPins<'_>,
) -> Result<Value, String> {
    read(p, "capture")
}
pub fn read_native_candidate_wheel_stage(
    p: &NativeCandidateArtifactReadPins<'_>,
) -> Result<Value, String> {
    read(p, "wheel-stage")
}

/// Caller holds both worker leases. Verify every retained wheel entry as data
/// without materializing files, executing package code or granting admission.
fn retained_wheel_bytes(
    job: &OwnedFd,
    archive_sha256: &str,
    source_sha: &str,
    version: &str,
) -> Result<(CandidateArchiveDeclaration, CandidateWheelProof, Vec<u8>), CandidateCaptureError> {
    let descriptor = openat(
        job,
        ARCHIVE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    let before = fstat(&descriptor).map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    if before.st_size <= 0 || before.st_size as u64 > MAX_ARCHIVE {
        return Err(CandidateCaptureError::CaptureUncertain);
    }
    let declaration = verify_captured(
        job,
        archive_sha256,
        before.st_size as u64,
        source_sha,
        version,
    )?;
    let mut outer = ZipArchive::new(File::from(descriptor))
        .map_err(|_| CandidateCaptureError::ArchiveInvalid)?;
    let mut wheel = Vec::with_capacity(declaration.wheel_bytes as usize);
    outer
        .by_name(&declaration.wheel)
        .map_err(|_| CandidateCaptureError::ArchiveInvalid)?
        .take(MAX_ARCHIVE + 1)
        .read_to_end(&mut wheel)
        .map_err(|_| CandidateCaptureError::ArchiveInvalid)?;
    if wheel.len() as u64 != declaration.wheel_bytes || wheel.len() as u64 > MAX_ARCHIVE {
        return Err(CandidateCaptureError::ArchiveInvalid);
    }
    let nested = inspect_candidate_wheel(&wheel, &declaration)
        .map_err(|_| CandidateCaptureError::WheelInvalid)?;
    let held_file = outer.into_inner();
    let held = fstat(&held_file).map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    let visible = statat(job, ARCHIVE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    if !same_file(&before, &held) || !same_file(&before, &visible) {
        return Err(CandidateCaptureError::CaptureUncertain);
    }
    let after = verify_captured(
        job,
        archive_sha256,
        before.st_size as u64,
        source_sha,
        version,
    )?;
    if after != declaration {
        return Err(CandidateCaptureError::CaptureUncertain);
    }
    Ok((declaration, nested, wheel))
}
