//! Data-only publication of the two fixed feature executables. Neither input
//! is executed by Root. A partial content-addressed slot is never overwritten.
use crate::feature_files as files;
use crate::{open_root_owned_public_directory, BoottimeDeadline, RunReservationJournal};
use gauntlet_contracts::FEATURE_NODE_SHA256;
use rustix::fs::{fchmod, fsync, openat, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

const BASE: &str = "/opt/hol-gauntlet/feature-assets";
fn asset(kind: &str, digest: &str) -> Result<(&'static str, usize), String> {
    if !crate::hex(digest, 64) {
        return Err("exact feature asset hash required".into());
    }
    match kind {
        "executor" => Ok(("gauntlet-feature-executor", 32 * 1024 * 1024)),
        "node" if digest == FEATURE_NODE_SHA256 => Ok(("node", 160 * 1024 * 1024)),
        _ => Err("fixed feature executor or pinned Node required".into()),
    }
}
pub(crate) fn path(kind: &str, digest: &str) -> Result<String, String> {
    let (file, _) = asset(kind, digest)?;
    Ok(format!("{BASE}/{kind}-{digest}/{file}"))
}
pub(crate) fn verify(kind: &str, digest: &str) -> Result<(), String> {
    let (file, bound) = asset(kind, digest)?;
    let dir = open_root_owned_public_directory(Path::new(&format!("{BASE}/{kind}-{digest}")))
        .map_err(|e| e.to_string())?;
    files::private_directory(&dir, (0, 0))?;
    let raw = files::required(&dir, file, (0, 0), 0o555, bound)?;
    if raw.len() < 64
        || &raw[..6] != b"\x7fELF\x02\x01"
        || u16::from_le_bytes([raw[18], raw[19]]) != 183
        || !matches!(u16::from_le_bytes([raw[16], raw[17]]), 2 | 3)
        || format!("{:x}", Sha256::digest(&raw)) != digest
    {
        return Err("fixed ARM feature asset bytes differ".into());
    }
    Ok(())
}
pub fn capture_native_feature_asset(
    kind: &str,
    digest: &str,
    bytes: u64,
    generation: &str,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let (file, bound) = asset(kind, digest)?;
    if bytes < 64 || bytes > bound as u64 {
        return Err("bounded ARM feature asset required".into());
    }
    let main =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = main.acquire_active_lease().map_err(|e| e.to_string())?;
    let legacy = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    crate::native_job_io::require_no_unknown_jobs(&main)?;
    crate::dependency_state::require_idle()?;
    let base = open_root_owned_public_directory(Path::new(BASE)).map_err(|e| e.to_string())?;
    files::private_directory(&base, (0, 0))?;
    let slot = files::directory(&base, &format!("{kind}-{digest}"), (0, 0), true)?;
    let fd = openat(
        &slot,
        "asset.receiving",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| e.to_string())?;
    fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    let mut output = File::from(fd);
    let observed = crate::native_source_stream::copy_source(
        std::io::stdin().as_raw_fd(),
        &mut output,
        bytes,
        &BoottimeDeadline::start(180).map_err(|e| e.to_string())?,
        crate::native_worker::cancellation_requested,
    )?;
    output.sync_all().map_err(|e| e.to_string())?;
    if observed != digest {
        return Err("feature asset hash differs; retained slot consumed".into());
    }
    fchmod(&output, Mode::from_bits_truncate(0o555)).map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    rustix::fs::renameat_with(
        &slot,
        "asset.receiving",
        &slot,
        file,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|e| e.to_string())?;
    fsync(&slot).map_err(|e| e.to_string())?;
    verify(kind, digest)?;
    lease.verify(&main.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&legacy).map_err(|e| e.to_string())?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    let v = serde_json::json!({"schema":"hol-gauntlet-native-feature-asset.v1","kind":kind,
        "sha256":digest,"bytes":bytes,"worker_generation":generation,"executed":false,
        "artifact_admitted":false,"execution_eligible":false,"model_requests":0});
    let raw =
        gauntlet_contracts::canonicalize(v.to_string().as_bytes()).map_err(|e| e.to_string())?;
    files::write(&slot, "capture.v1.json", &raw, (0, 0), 0o600)?;
    Ok(raw)
}
