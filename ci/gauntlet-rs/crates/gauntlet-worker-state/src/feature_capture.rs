//! Root captures only quiescent bounded report/XML/log data, recomputes all
//! counts, then retains immutable copies. No candidate module is imported.
use crate::builder_candidate_process::CandidateProcessObservation;
use crate::feature_files as files;
use gauntlet_contracts::{canonicalize, FeatureRunIntent};
use gauntlet_evidence::{verify_feature_report_v2, EvidenceError};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;

pub(crate) fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
pub(crate) fn capture(
    slot: &OwnedFd,
    intent: &FeatureRunIntent,
    observed: &CandidateProcessObservation,
) -> Result<Value, String> {
    let raw = files::required(slot, "feature-run.stdout.log", (0, 0), 0o600, 128 * 1024)?;
    let err = files::required(slot, "feature-run.stderr.log", (0, 0), 0o600, 128 * 1024)?;
    if digest(&raw) != observed.stdout_sha256
        || digest(&err) != observed.stderr_sha256
        || canonicalize(&raw).map_err(|e| e.to_string())? != raw
        || !err.is_empty()
    {
        return Err("feature owner output differs from observed streams".into());
    }
    let export = files::open_directory(slot, "export", (65532, 65532))?;
    if files::required(
        &export,
        "contracts.v2.json",
        (65532, 65532),
        0o600,
        128 * 1024,
    )? != raw
    {
        return Err("feature protected stdout and export report differ".into());
    }
    let mut artifacts = BTreeMap::new();
    let readback = verify_feature_report_v2(intent.pins().spec(), &raw, |name, bound| {
        let bytes = files::read(&export, name, (65532, 65532), 0o600, bound)
            .map_err(|_| EvidenceError::Invalid("feature exported file custody differs"))?;
        if let Some(bytes) = &bytes {
            artifacts.insert(name.to_owned(), bytes.clone());
        }
        Ok(bytes)
    })
    .map_err(|e| e.to_string())?;
    let expected = if readback["status"] == "passed" { 0 } else { 1 };
    if observed.exit_code != expected {
        return Err("feature exit contradicts independently recomputed status".into());
    }
    let retained = files::directory(slot, "artifacts", (0, 0), true)?;
    for (name, bytes) in artifacts {
        files::write(&retained, &name, &bytes, (0, 0), 0o444)?;
    }
    files::write(slot, "contracts.v2.json", &raw, (0, 0), 0o444)?;
    let checked = canonicalize(readback.to_string().as_bytes()).map_err(|e| e.to_string())?;
    files::write(slot, "readback.v2.json", &checked, (0, 0), 0o444)?;
    let result = verify_stored(slot, intent)?;
    if result != readback {
        return Err("retained feature readback differs".into());
    }
    Ok(readback)
}
pub(crate) fn verify_stored(slot: &OwnedFd, intent: &FeatureRunIntent) -> Result<Value, String> {
    let spec = intent.pins().spec();
    if files::required(slot, "feature-spec.json", (0, 0), 0o444, 16 * 1024)?
        != spec.canonical_bytes()
    {
        return Err("retained feature spec differs".into());
    }
    let raw = files::required(slot, "contracts.v2.json", (0, 0), 0o444, 128 * 1024)?;
    let artifacts = files::open_directory(slot, "artifacts", (0, 0))?;
    let readback = verify_feature_report_v2(spec, &raw, |name, bound| {
        files::read(&artifacts, name, (0, 0), 0o444, bound)
            .map_err(|_| EvidenceError::Invalid("retained feature artifact custody differs"))
    })
    .map_err(|e| e.to_string())?;
    let checked = canonicalize(readback.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if files::required(slot, "readback.v2.json", (0, 0), 0o444, 16 * 1024)? != checked {
        return Err("retained feature verification differs".into());
    }
    Ok(readback)
}
