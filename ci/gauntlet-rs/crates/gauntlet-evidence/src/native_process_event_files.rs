//! Public readback uses exact caller pins and grants no Root/observer admission.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{parse, require};
use crate::native_process_kernel::hex;
use crate::public_files::PublicRootReader;
use crate::{verify_native_process_events, EvidenceError, Result};
use serde_json::Value;
use std::path::Path;

pub(crate) fn read(path: &Path, pin: &str, limit: usize) -> Result<Vec<u8>> {
    require(hex(pin, 64))?;
    let parent = path.parent().ok_or(EvidenceError::Invalid(
        "public process event parent missing",
    ))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(EvidenceError::Invalid(
            "public process event filename missing",
        ))?;
    let raw = PublicRootReader::open(parent)?.read_file(name, limit)?;
    require(sha256(&raw) == pin)?;
    Ok(raw)
}

pub fn verify_native_process_event_files(
    journal: &Path,
    journal_sha256: &str,
    checkpoint: &Path,
    checkpoint_sha256: &str,
) -> Result<Value> {
    let raw = read(journal, journal_sha256, 64 * 1024 * 1024)?;
    let checkpoint = parse(&read(checkpoint, checkpoint_sha256, 8192)?)?;
    verify_native_process_events(&raw, &checkpoint)
}
