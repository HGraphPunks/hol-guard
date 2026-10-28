//! Public caller-pinned diagnostic snapshots; never admits Root custody.
use crate::native_diagnostic_artifacts::parse;
use crate::native_process_event_files::read;
use crate::{verify_native_stdio_events, Result};
use serde_json::Value;
use std::path::Path;

pub fn verify_native_stdio_files(
    journal: &Path,
    journal_sha256: &str,
    process: &Path,
    process_sha256: &str,
    checkpoint: &Path,
    checkpoint_sha256: &str,
) -> Result<Value> {
    let raw = read(journal, journal_sha256, 64 * 1024 * 1024)?;
    let process = read(process, process_sha256, 64 * 1024 * 1024)?;
    let checkpoint = parse(&read(checkpoint, checkpoint_sha256, 8192)?)?;
    verify_native_stdio_events(&raw, &process, &checkpoint)
}
