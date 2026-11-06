//! A controller signature binds a diagnostic to prelaunch pins. It supplies
//! neither independent effect scoring nor benchmark admission.
use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::{canonical_value, verify_controller_envelope, EvidenceError, Result};
use gauntlet_contracts::PrelaunchPrepared;
use serde_json::{json, Value};

pub const NATIVE_CONTROL_ENVELOPE_LIMIT: usize = 1024 * 1024;
const INVALID: EvidenceError =
    EvidenceError::Invalid("native controller report differs from prelaunch pins");
const SCHEMA: &str = "hol-gauntlet-native-controller-record.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeControlReportPins {
    /// Must come from the host's durable journal, before controller execution.
    pub prelaunch: PrelaunchPrepared,
    pub preparation_sha256: String,
    pub role: String,
}

fn role(value: &str) -> bool {
    matches!(
        value,
        "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
    )
}

/// Construct the closed record signed by the Root Rust controller. This is
/// data validation, not evidence that the supplied prelaunch pins are trusted.
pub fn native_control_signing_record(
    report: &Value,
    pins: &NativeControlReportPins,
) -> Result<Value> {
    let prepared = pins.prelaunch.to_bytes().map_err(|_| INVALID)?;
    if !is_sha256(&pins.preparation_sha256)
        || !role(&pins.role)
        || report["schema"] != "hol-gauntlet-native-deterministic-control.v1"
        || report["job_id"] != pins.prelaunch.job_id
        || report["preparation_sha256"] != pins.preparation_sha256
        || report["control_role"] != pins.role
        || report["guard_pins"]["source_sha"] != pins.prelaunch.source_sha
        || report["execution_eligible"] != false
        || report["guard_causality_verified"] != false
        || report["qualified_role_complete"] != false
        || report["model_requests"].as_u64() != Some(0)
        || report.get("error").is_none()
        || report["controller_identity"]["pid"]
            .as_u64()
            .is_none_or(|p| p == 0 || p > u32::MAX as u64)
        || report["controller_identity"]["start_ticks"]
            .as_u64()
            .is_none_or(|n| n == 0)
        || !matches!(report["status"].as_str(), Some("passed" | "failed"))
        || (report["status"] == "passed" && !report["error"].is_null())
        || (report["status"] == "failed" && report["error"].as_str().is_none_or(str::is_empty))
    {
        return Err(INVALID);
    }
    let record = json!({"schema":SCHEMA,
        "prelaunch":serde_json::from_slice::<Value>(&prepared).map_err(|_|INVALID)?,
        "preparation_sha256":pins.preparation_sha256,"control_role":pins.role,"controller_report":report});
    // Leave room for the envelope keys and base64 Ed25519 signature.
    if canonical_value(&record)?.len() > NATIVE_CONTROL_ENVELOPE_LIMIT - 256 {
        return Err(EvidenceError::Invalid(
            "native controller signing record exceeds byte limit",
        ));
    }
    Ok(record)
}

#[derive(Debug, Clone)]
pub struct AuthenticatedNativeControlReport {
    report: Value,
    record_sha256: String,
    envelope_sha256: String,
}
impl AuthenticatedNativeControlReport {
    pub fn report(&self) -> &Value {
        &self.report
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-authenticated-native-controller-record.v1",
            "record_sha256":self.record_sha256,"envelope_sha256":self.envelope_sha256,
            "signature_verified":true,"reported_status":self.report["status"],
            "independent_effects_scored":false,"qualified_role_complete":false,
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":0})
    }
}

/// Authenticate under the exact caller-supplied prelaunch key and complete
/// job/preparation/role tuple. A replaceable record cannot choose its own key.
/// The caller remains responsible for obtaining the pins from outside the VM.
pub fn verify_native_control_envelope(
    raw: &[u8],
    pins: &NativeControlReportPins,
) -> Result<AuthenticatedNativeControlReport> {
    if raw.is_empty() || raw.len() > NATIVE_CONTROL_ENVELOPE_LIMIT {
        return Err(EvidenceError::Invalid(
            "bounded native controller envelope required",
        ));
    }
    pins.prelaunch.to_bytes().map_err(|_| INVALID)?;
    let public = decode_hex(&pins.prelaunch.controller_public_key_hex, 32)?;
    let record = verify_controller_envelope(raw, &public)?;
    let report = record.get("controller_report").ok_or(INVALID)?;
    if record != native_control_signing_record(report, pins)? {
        return Err(INVALID);
    }
    Ok(AuthenticatedNativeControlReport {
        report: report.clone(),
        record_sha256: sha256(&canonical_value(&record)?),
        envelope_sha256: sha256(raw),
    })
}

#[cfg(test)]
#[path = "native_control_envelope_tests.rs"]
mod tests;
