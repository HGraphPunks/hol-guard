//! One-use publication of verified inert runtime data under its immutable
//! source path. It never writes a deployment/admission or runs package code.
use crate::native_runtime_receipt::NativeRuntimePins;
use crate::{CandidateDependencyLivePins, RunReservationJournal};
use gauntlet_evidence::{inventory_tree, TreeInventory, TreeKind};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, open, openat, renameat_with, statat, AtFlags, Mode, OFlags,
    RenameFlags,
};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::path::Path;

fn directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd, String> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let stat = fstat(&fd).map_err(|e| e.to_string())?;
    if stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o022 != 0
        || stat.st_mode & 0o7000 != 0
    {
        return Err("Root runtime directory custody required".into());
    }
    Ok(fd)
}

fn absent(parent: &OwnedFd, name: &str) -> Result<(), String> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err("runtime publication slot already consumed; preserve and reconcile".into()),
    }
}

fn publication(
    pins: &NativeRuntimePins<'_>,
    clone: &Value,
    tree: &TreeInventory,
    requirements: Value,
) -> Result<Value, String> {
    let text = |key: &str| {
        clone[key]
            .as_str()
            .ok_or("native runtime clone field missing")
    };
    Ok(
        json!({"schema":"hol-gauntlet-native-runtime-publication.v1","job_id":pins.job_id,"source_sha":pins.source_sha,"version":pins.version,
        "clone_receipt_sha256":pins.clone_receipt_sha256,"source_archive_sha256":text("source_archive_sha256")?,"archive_sha256":text("archive_sha256")?,"dependency_prefix_receipt_sha256":text("dependency_prefix_receipt_sha256")?,
        "prefix":Path::new("/opt/hol-gauntlet/candidates").join(pins.source_sha).join("prefix"),"prefix_tree_sha256":tree.digest,"prefix_entries":tree.entries,"prefix_bytes":tree.bytes,"native_sha256":pins.native_sha256,"publisher_generation":pins.generation,
        "dependency_requirements":requirements,"candidate_executed":false,"conformance_completed":false,"artifact_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

pub fn publish_native_runtime(pins: &NativeRuntimePins<'_>) -> Result<Value, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    let clone = crate::native_runtime_verify::read(pins)?;
    let text = |key: &str| {
        clone[key]
            .as_str()
            .ok_or("native runtime clone field missing")
    };
    // This typed proof is computed under the worker leases. Publication takes
    // them again and rechecks the exact same complete tree before any write.
    let requirements =
        crate::verify_cloned_candidate_dependencies_ineligible(&CandidateDependencyLivePins {
            job_id: pins.job_id,
            source_sha: pins.source_sha,
            source_archive_sha256: text("source_archive_sha256")?,
            archive_sha256: text("archive_sha256")?,
            version: pins.version,
            native_sha256: pins.native_sha256,
            prefix_tree_sha256: pins.prefix_tree_sha256,
            python_full_version: pins.python_full_version,
        })
        .map_err(|e| e.to_string())?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let original = crate::native_runtime_verify::verify(pins, &clone, &journal)?;
    if crate::builder_image_build::free_bytes().map_err(|e| e.to_string())?
        < 12 * 1024 * 1024 * 1024
    {
        return Err("runtime publication lacks disk reserve".into());
    }
    let base = crate::open_root_owned_public_directory(Path::new("/opt/hol-gauntlet"))
        .map_err(|e| e.to_string())?;
    let created = match mkdirat(&base, "candidates", Mode::from_bits_truncate(0o700)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(e) => return Err(e.to_string()),
    };
    let candidates = directory(&base, "candidates")?;
    if created {
        fchmod(&candidates, Mode::from_bits_truncate(0o755))
            .and_then(|_| fsync(&candidates))
            .and_then(|_| fsync(&base))
            .map_err(|e| e.to_string())?;
    }
    if fstat(&candidates).map_err(|e| e.to_string())?.st_mode & 0o7777 != 0o755 {
        return Err("public source directory must retain exact 0755 custody".into());
    }
    let partial = format!("{}.native-{}", pins.source_sha, pins.job_id);
    absent(&candidates, pins.source_sha)?;
    absent(&candidates, &partial)?;
    mkdirat(
        &candidates,
        partial.as_str(),
        Mode::from_bits_truncate(0o700),
    )
    .map_err(|e| e.to_string())?;
    fsync(&candidates).map_err(|e| e.to_string())?;
    let target = directory(&candidates, &partial)?;
    fchmod(&target, Mode::from_bits_truncate(0o700)).map_err(|e| e.to_string())?;
    mkdirat(&target, "prefix", Mode::from_bits_truncate(0o700)).map_err(|e| e.to_string())?;
    let prefix = directory(&target, "prefix")?;
    let source = open(
        crate::native_runtime_verify::prefix(pins),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let mut entries = 0;
    let mut bytes = 0;
    crate::candidate_prefix_clone::clone_baseline(
        &source,
        &prefix,
        "",
        0,
        &mut entries,
        &mut bytes,
        false,
    )
    .map_err(|e| e.to_string())?;
    fchmod(&prefix, Mode::from_bits_truncate(0o755))
        .and_then(|_| fsync(&prefix))
        .and_then(|_| fsync(&target))
        .map_err(|e| e.to_string())?;
    let parent = Path::new("/opt/hol-gauntlet/candidates");
    let staged = parent.join(&partial).join("prefix");
    let copied = inventory_tree(&staged, TreeKind::InstalledPrefix).map_err(|e| e.to_string())?;
    let after = crate::native_runtime_verify::verify(pins, &clone, &journal)?;
    if copied.digest != original.digest
        || copied.entries != original.entries
        || copied.bytes != original.bytes
        || copied.bytes != bytes
        || after != original
    {
        return Err("native runtime data changed during publication".into());
    }
    if crate::builder_image_build::free_bytes().map_err(|e| e.to_string())? < 8 * 1024 * 1024 * 1024
    {
        return Err("runtime publication crossed disk reserve; preserve partial".into());
    }
    let result = publication(pins, &clone, &copied, requirements.to_json())?;
    let digest = crate::builder_candidate_receipt::write_root_canonical_job_file(
        &target,
        "native-runtime.v1.json",
        &result,
    )
    .map_err(|e| e.to_string())?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    fchmod(&target, Mode::from_bits_truncate(0o755))
        .and_then(|_| fsync(&target))
        .map_err(|e| e.to_string())?;
    renameat_with(
        &candidates,
        partial.as_str(),
        &candidates,
        pins.source_sha,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| "runtime publication uncertain; retain both paths")?;
    fsync(&candidates).map_err(|e| e.to_string())?;
    let visible = directory(&candidates, pins.source_sha)?;
    if !crate::dependency_prefix_meta::same(
        &fstat(&target).map_err(|e| e.to_string())?,
        &fstat(&visible).map_err(|e| e.to_string())?,
    ) {
        return Err("published runtime directory changed".into());
    }
    let published = inventory_tree(
        &parent.join(pins.source_sha).join("prefix"),
        TreeKind::InstalledPrefix,
    )
    .map_err(|e| e.to_string())?;
    if published != copied {
        return Err("published runtime prefix differs".into());
    }
    let slot = crate::builder_candidate_source::open_fixed_build_slot(pins.job_id)
        .map_err(|e| e.to_string())?;
    if crate::builder_candidate_receipt::write_root_canonical_job_file(
        &slot,
        "native-runtime-publication.v1.json",
        &result,
    )
    .map_err(|e| e.to_string())?
        != digest
    {
        return Err("runtime publication receipts differ".into());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    let mut result = result;
    result["receipt_sha256"] = digest.into();
    Ok(result)
}

/// Reconcile a completed immutable publication only. Both original receipts
/// and all source/dependency/prefix trees must still be retained and exact.
pub fn read_native_runtime_publication(pins: &NativeRuntimePins<'_>) -> Result<Value, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    let _namespace_scope = crate::native_job_storage::owner::scope()?;
    let clone = crate::native_runtime_verify::read(pins)?;
    let text = |key: &str| {
        clone[key]
            .as_str()
            .ok_or("native runtime clone field missing")
    };
    let requirements =
        crate::verify_cloned_candidate_dependencies_ineligible(&CandidateDependencyLivePins {
            job_id: pins.job_id,
            source_sha: pins.source_sha,
            source_archive_sha256: text("source_archive_sha256")?,
            archive_sha256: text("archive_sha256")?,
            version: pins.version,
            native_sha256: pins.native_sha256,
            prefix_tree_sha256: pins.prefix_tree_sha256,
            python_full_version: pins.python_full_version,
        })
        .map_err(|e| e.to_string())?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let original = crate::native_runtime_verify::verify(pins, &clone, &journal)?;
    let base = crate::open_root_owned_public_directory(Path::new("/opt/hol-gauntlet"))
        .map_err(|e| e.to_string())?;
    let candidates = directory(&base, "candidates")?;
    if fstat(&candidates).map_err(|e| e.to_string())?.st_mode & 0o7777 != 0o755 {
        return Err("runtime source directory custody differs".into());
    }
    absent(
        &candidates,
        &format!("{}.native-{}", pins.source_sha, pins.job_id),
    )?;
    let target = directory(&candidates, pins.source_sha)?;
    if fstat(&target).map_err(|e| e.to_string())?.st_mode & 0o7777 != 0o755 {
        return Err("runtime publication incomplete or private".into());
    }
    let slot = crate::builder_candidate_source::open_fixed_build_slot(pins.job_id)
        .map_err(|e| e.to_string())?;
    let mut result = publication(pins, &clone, &original, requirements.to_json())?;
    let raw = gauntlet_contracts::canonicalize(result.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    for _ in 0..2 {
        if crate::dependency_io::read(&slot, "native-runtime-publication.v1.json", 0, 0o600, 8192)?
            != raw
            || crate::dependency_io::read(&target, "native-runtime.v1.json", 0, 0o600, 8192)? != raw
        {
            return Err("completed runtime publication differs from original pins/receipts".into());
        }
        let published = inventory_tree(
            &Path::new("/opt/hol-gauntlet/candidates")
                .join(pins.source_sha)
                .join("prefix"),
            TreeKind::InstalledPrefix,
        )
        .map_err(|e| e.to_string())?;
        if published != original
            || crate::native_runtime_verify::verify(pins, &clone, &journal)? != original
        {
            return Err("original published runtime or retained source chain changed".into());
        }
        lease.verify(&journal.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    }
    crate::verify_running_binary(pins.generation).map_err(|e| e.to_string())?;
    result["receipt_sha256"] = crate::native_job_storage::linux::sha(&raw).into();
    Ok(result)
}
