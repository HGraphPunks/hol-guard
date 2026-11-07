//! One-use inert SDK/Bun publication. The private bootstrap input is already
//! normalized to Root custody; Rust verifies and copies it without imports.
use crate::{NativeSdkAssetPins, RunReservationJournal};
use gauntlet_evidence::{inventory_tree, TreeKind};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, open, openat, renameat_with, statat, AtFlags, Dir, FileType,
    Mode, OFlags, RenameFlags,
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
    let s = fstat(&fd).map_err(|e| e.to_string())?;
    if s.st_uid != 0 || s.st_gid != 0 || s.st_mode & 0o7022 != 0 {
        return Err("SDK directory lacks ordinary Root custody".into());
    }
    Ok(fd)
}
fn absent(parent: &OwnedFd, name: &str) -> Result<(), String> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err("SDK publication slot already consumed; retain and reconcile".into()),
    }
}
fn names(fd: &OwnedFd) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for row in Dir::read_from(fd).map_err(|e| e.to_string())? {
        let row = row.map_err(|e| e.to_string())?;
        let n = row
            .file_name()
            .to_str()
            .map_err(|_| "SDK source name UTF-8")?;
        if n == "." || n == ".." {
            continue;
        }
        names.push(n.to_owned());
        if names.len() > 8 {
            return Err("closed SDK source root required".into());
        }
    }
    names.sort();
    Ok(names)
}
pub(crate) fn verify_bun(path: &Path, pins: &NativeSdkAssetPins) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let s = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != 0
        || s.st_gid != 0
        || s.st_nlink != 1
        || s.st_mode & 0o7777 != 0o555
        || s.st_size as u64 != pins.bun_bytes
        || s.st_size < 64
    {
        return Err("SDK Bun ordinary bounded Root executable required".into());
    }
    let mut f = std::fs::File::from(fd);
    let mut head = [0; 64];
    f.read_exact(&mut head).map_err(|e| e.to_string())?;
    if head[..7] != *b"\x7fELF\x02\x01\x01"
        || head[18..20] != [0xb7, 0]
        || ![2, 3].contains(&u16::from_le_bytes([head[16], head[17]]))
    {
        return Err("SDK Bun must be the pinned Linux ARM64 ELF".into());
    }
    let mut h = Sha256::new();
    h.update(head);
    let mut total = 64_u64;
    let mut bytes = [0; 65536];
    loop {
        let n = f.read(&mut bytes).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > pins.bun_bytes {
            return Err("SDK Bun grew while hashing".into());
        }
        h.update(&bytes[..n]);
    }
    let visible = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    if total != pins.bun_bytes
        || format!("{:x}", h.finalize()) != pins.bun_sha256
        || !crate::dependency_prefix_meta::same(&s, &fstat(&f).map_err(|e| e.to_string())?)
        || !crate::dependency_prefix_meta::same(&s, &fstat(&visible).map_err(|e| e.to_string())?)
    {
        return Err("SDK Bun differs from outside bytes or custody".into());
    }
    Ok(())
}
pub(crate) fn sdk_version(root: &Path) -> Result<(), String> {
    use std::io::Read;
    let fd = open(
        root.join("node_modules/@oh-my-pi/pi-coding-agent/package.json"),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_mode & 0o7022 != 0
        || before.st_nlink != 1
        || !(1..=65536).contains(&before.st_size)
    {
        return Err("SDK package metadata custody differs".into());
    }
    let mut f = std::fs::File::from(fd);
    let mut raw = Vec::new();
    Read::by_ref(&mut f)
        .take(65537)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as i64 != before.st_size
        || !crate::dependency_prefix_meta::same(&before, &fstat(&f).map_err(|e| e.to_string())?)
    {
        return Err("SDK package metadata changed".into());
    }
    let canonical =
        gauntlet_contracts::canonicalize(&raw).map_err(|_| "SDK package metadata is ambiguous")?;
    let v: Value = serde_json::from_slice(&canonical).map_err(|_| "SDK package metadata JSON")?;
    if v["version"] != "18.4.12" || v["name"] != "@oh-my-pi/pi-coding-agent" {
        return Err("SDK package identity differs from fixed adapter".into());
    }
    Ok(())
}

pub fn publish_native_sdk_assets(
    job_id: &str,
    declaration: &str,
    generation: &str,
) -> Result<Value, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if !crate::hex(job_id, 16) || !crate::hex(declaration, 64) {
        return Err("fixed SDK job/declaration pins required".into());
    }
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    crate::native_job_io::require_no_unknown_jobs(&journal)?;
    let job_path = Path::new(crate::native_job_spec::NATIVE_JOBS).join(job_id);
    let job = crate::open_root_owned_public_directory(&job_path).map_err(|e| e.to_string())?;
    let js = fstat(&job).map_err(|e| e.to_string())?;
    if js.st_uid != 0 || js.st_gid != 0 || js.st_mode & 0o7777 != 0o700 {
        return Err("private Root SDK input job required".into());
    }
    let raw = crate::read_bounded_regular(&job, "sdk-source.v1.json", 8192)
        .map_err(|e| e.to_string())?
        .ok_or("SDK source declaration missing")?;
    let pins = NativeSdkAssetPins::parse(&raw, declaration)?;
    let source = directory(&job, "sdk-source")?;
    if names(&source)? != ["bun", "node_modules"] {
        return Err("only the fixed SDK/Bun inputs may be published".into());
    }
    let source_path = job_path.join("sdk-source");
    let original = inventory_tree(&source_path.join("node_modules"), TreeKind::Sdk)
        .map_err(|e| e.to_string())?;
    if original.digest != pins.sdk_tree_sha256
        || original.entries as u64 != pins.sdk_entries
        || original.bytes != pins.sdk_bytes
    {
        return Err("SDK source tree differs from outside normalized pin".into());
    }
    verify_bun(&source_path.join("bun"), &pins)?;
    sdk_version(&source_path)?;
    if crate::builder_image_build::free_bytes().map_err(|e| e.to_string())?
        < 12 * 1024 * 1024 * 1024
    {
        return Err("SDK publication lacks disk reserve".into());
    }
    let base = crate::open_root_owned_public_directory(Path::new("/opt/hol-gauntlet"))
        .map_err(|e| e.to_string())?;
    let created = match mkdirat(&base, "sdk-assets", Mode::from_bits_truncate(0o700)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(e) => return Err(e.to_string()),
    };
    let parent = directory(&base, "sdk-assets")?;
    if created {
        fchmod(&parent, Mode::from_bits_truncate(0o755))
            .and_then(|_| fsync(&parent))
            .and_then(|_| fsync(&base))
            .map_err(|e| e.to_string())?
    }
    if fstat(&parent).map_err(|e| e.to_string())?.st_mode & 0o7777 != 0o755 {
        return Err("SDK publication parent must be Root 0755".into());
    }
    let slot = format!("{}-{}", pins.sdk_tree_sha256, pins.bun_sha256);
    let partial = format!(".{slot}-{job_id}");
    absent(&parent, &slot)?;
    absent(&parent, &partial)?;
    absent(&job, "sdk-publication.v1.json")?;
    mkdirat(&parent, partial.as_str(), Mode::from_bits_truncate(0o700))
        .and_then(|_| fsync(&parent))
        .map_err(|e| e.to_string())?;
    let target = directory(&parent, &partial)?;
    fchmod(&target, Mode::from_bits_truncate(0o700)).map_err(|e| e.to_string())?;
    let mut entries = 0;
    let mut bytes = 0;
    crate::candidate_prefix_clone::clone_baseline(
        &source,
        &target,
        "",
        0,
        &mut entries,
        &mut bytes,
        false,
    )
    .map_err(|e| e.to_string())?;
    let partial_path = Path::new("/opt/hol-gauntlet/sdk-assets").join(&partial);
    let copied = inventory_tree(&partial_path.join("node_modules"), TreeKind::Sdk)
        .map_err(|e| e.to_string())?;
    let after = inventory_tree(&source_path.join("node_modules"), TreeKind::Sdk)
        .map_err(|e| e.to_string())?;
    if copied != original
        || after != original
        || entries as u64 != pins.sdk_entries + 2
        || bytes != pins.sdk_bytes + pins.bun_bytes
    {
        return Err("SDK inert copy/readback or source metadata changed; retain partial".into());
    }
    verify_bun(&partial_path.join("bun"), &pins)?;
    sdk_version(&partial_path)?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    let receipt = json!({"schema":"hol-gauntlet-native-sdk-publication.v1","job_id":job_id,
        "source_declaration_sha256":declaration,"publisher_generation":generation,"inputs":pins.to_json(),
        "directory":pins.directory(),"sdk_entries":copied.entries,"sdk_bytes":copied.bytes,
        "root_custody_normalization":"uid/gid=0; remove group/other write on ordinary objects; retain symlink mode",
        "sdk_version":"18.4.12","sdk_imported":false,"bun_executed":false,
        "artifact_admitted":false,"execution_eligible":false,"model_requests":0});
    let receipt_sha = crate::builder_candidate_receipt::write_root_canonical_job_file(
        &target,
        "sdk-publication.v1.json",
        &receipt,
    )
    .map_err(|e| e.to_string())?;
    fchmod(&target, Mode::from_bits_truncate(0o755))
        .and_then(|_| fsync(&target))
        .map_err(|e| e.to_string())?;
    renameat_with(
        &parent,
        partial.as_str(),
        &parent,
        slot.as_str(),
        RenameFlags::NOREPLACE,
    )
    .and_then(|_| fsync(&parent))
    .map_err(|_| "SDK publication rename uncertain; retain and reconcile")?;
    let job_sha = crate::builder_candidate_receipt::write_root_canonical_job_file(
        &job,
        "sdk-publication.v1.json",
        &receipt,
    )
    .map_err(|e| e.to_string())?;
    if job_sha != receipt_sha {
        return Err("SDK dual publication receipts differ".into());
    }
    let published = inventory_tree(&pins.directory().join("node_modules"), TreeKind::Sdk)
        .map_err(|e| e.to_string())?;
    if published != original {
        return Err("published SDK readback changed".into());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    Ok(
        json!({"schema":"hol-gauntlet-native-sdk-publication-result.v1","receipt_sha256":receipt_sha,
        "directory":pins.directory(),"sdk_tree_sha256":pins.sdk_tree_sha256,"bun_sha256":pins.bun_sha256,
        "sdk_imported":false,"bun_executed":false,"artifact_admitted":false,"execution_eligible":false,"model_requests":0}),
    )
}
