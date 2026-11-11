//! A controller signature binds a diagnostic to prelaunch pins. It supplies
//! neither independent effect scoring nor benchmark admission.
use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::native_diagnostic_artifacts::{digest, parse, require};
use crate::payload::exact_keys;
use crate::{canonical_value, verify_controller_envelope, EvidenceError, Result};
use gauntlet_contracts::PrelaunchPrepared;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) fn legacy_artifacts(
    report: &Value,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Option<Value>> {
    use crate::legacy_native_denied::{ARTIFACT_NAMES, CELL};
    let Some(raw) = files.get("combined/live/evidence.v1.json") else {
        return Ok(None);
    };
    require(raw.len() <= 32 * 1024 * 1024)?;
    let value = parse(raw)?;
    require(
        exact_keys(&value, &["schema", "cell_id", "artifacts"])
            && value["schema"] == "hol-gauntlet-native-legacy-denied-cell.v1"
            && value["cell_id"] == CELL
            && exact_keys(&value["artifacts"], ARTIFACT_NAMES)
            && value["artifacts"]["cleanup"].is_null(),
    )?;
    for name in ARTIFACT_NAMES {
        require(report["artifact_sha256"][*name] == digest(&value["artifacts"][*name])?)?;
    }
    Ok(Some(value["artifacts"].clone()))
}

pub const NATIVE_CONTROL_ENVELOPE_LIMIT: usize = 1024 * 1024;
const INVALID: EvidenceError =
    EvidenceError::Invalid("native controller report differs from prelaunch pins");

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
    let readonly = pins.role == "readonly-utility";
    let legacy = pins.role == crate::legacy_native_denied::ROLE;
    let live = matches!(
        pins.role.as_str(),
        "feature-ai-unprotected" | "feature-ai-protected"
    );
    let profile_matches = if legacy {
        crate::legacy_native_denied::signing_profile(report)?
            && report["guard_pins"]["source_sha"] == pins.prelaunch.source_sha
    } else if live {
        let spec = crate::feature_ai_support::feature_ai_support_spec()?;
        let index = usize::from(pins.role == "feature-ai-protected");
        report["schema"] == "hol-gauntlet-native-live-omp.v1"
            && report["control_role"] == pins.role
            && report["guard_pins"]["source_sha"] == pins.prelaunch.source_sha
            && report["cell_id"] == spec["cells"][index]["id"]
            && report["spec_sha256"] == sha256(&canonical_value(&spec)?)
            && report["artifact_sha256"].as_object().is_some_and(|rows| {
                rows.keys().all(|name| {
                    crate::feature_ai_support::pair::ARTIFACT_NAMES.contains(&name.as_str())
                }) && rows.values().all(|v| v.as_str().is_some_and(is_sha256))
            })
            && report["model_requests"]
                .as_u64()
                .is_some_and(|n| n <= 10_000 && (report["status"] != "passed" || n > 0))
    } else if readonly {
        report["schema"] == "hol-gauntlet-native-hook-transport.v2"
            && report["pins"]["source_sha"] == pins.prelaunch.source_sha
            && report["sdk_exercised"] == false
            && report["artifact_admitted"] == false
            && report.get("control_role").is_none()
    } else {
        role(&pins.role)
            && report["schema"] == "hol-gauntlet-native-deterministic-control.v1"
            && report["control_role"] == pins.role
            && report["guard_pins"]["source_sha"] == pins.prelaunch.source_sha
    };
    if !is_sha256(&pins.preparation_sha256)
        || !profile_matches
        || report["job_id"] != pins.prelaunch.job_id
        || report["preparation_sha256"] != pins.preparation_sha256
        || report["execution_eligible"] != false
        || report["guard_causality_verified"] != false
        || report["qualified_role_complete"] != false
        || (!(live || legacy) && report["model_requests"].as_u64() != Some(0))
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
    let record = json!({"schema":if legacy {"hol-gauntlet-native-controller-record.v4"}else if live {"hol-gauntlet-native-controller-record.v3"}else if readonly {"hol-gauntlet-native-controller-record.v2"}else{"hol-gauntlet-native-controller-record.v1"},
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
    worker_generation: String,
    deployment_digest: String,
}
impl AuthenticatedNativeControlReport {
    pub(crate) fn worker_generation(&self) -> &str {
        &self.worker_generation
    }
    pub(crate) fn deployment_digest(&self) -> &str {
        &self.deployment_digest
    }
    pub fn report(&self) -> &Value {
        &self.report
    }
    pub fn observation(&self) -> Value {
        json!({"schema":if self.report["schema"]==crate::legacy_native_denied::REPORT {"hol-gauntlet-authenticated-native-controller-record.v4"}else if self.report["schema"]=="hol-gauntlet-native-live-omp.v1" {"hol-gauntlet-authenticated-native-controller-record.v3"}else if self.report["schema"]=="hol-gauntlet-native-hook-transport.v2" {"hol-gauntlet-authenticated-native-controller-record.v2"}else{"hol-gauntlet-authenticated-native-controller-record.v1"},
            "record_sha256":self.record_sha256,"envelope_sha256":self.envelope_sha256,
            "signature_verified":true,"reported_status":self.report["status"],
            "independent_effects_scored":false,"qualified_role_complete":false,
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":self.report["model_requests"]})
    }

    /// Independently evaluate the retained role's source-selected artifact
    /// contracts. The caller must first authenticate archive custody under an
    /// outside byte pin. Invalid role artifacts produce a durable, sanitized
    /// judgment; substituted preparation or malformed outside pins refuse.
    pub fn judge(
        &self,
        preparation: &Value,
        files: &BTreeMap<String, Vec<u8>>,
        interpreter_sha256: &str,
        observer_sha256: &str,
    ) -> Result<Value> {
        if !is_sha256(interpreter_sha256) || !is_sha256(observer_sha256) {
            return Err(EvidenceError::Invalid(
                "independent Native judge pins required",
            ));
        }
        let preparation_raw =
            files
                .get("combined/preparation.v1.json")
                .ok_or(EvidenceError::Invalid(
                    "independent Native preparation missing",
                ))?;
        if self.report["preparation_sha256"] != sha256(preparation_raw)
            || crate::native_diagnostic_artifacts::parse(preparation_raw)? != *preparation
        {
            return Err(INVALID);
        }
        if self.report["schema"] == crate::legacy_native_denied::REPORT {
            return crate::legacy_native_denied::judge_from_files(self, preparation, files, None);
        }
        if self.report["schema"] == "hol-gauntlet-native-live-omp.v1" {
            return crate::feature_ai_support::pair::judge_from_files(
                self, files, None, None, None,
            );
        }
        let readonly = self.report["schema"] == "hol-gauntlet-native-hook-transport.v2";
        let role = if readonly {
            "readonly-utility"
        } else {
            self.report["control_role"].as_str().ok_or(INVALID)?
        };
        let relations = if self.report["status"] != "passed" {
            None
        } else {
            let result = if readonly {
                crate::verify_native_readonly_diagnostic(
                    &self.report,
                    preparation,
                    files,
                    interpreter_sha256,
                    observer_sha256,
                )
            } else {
                crate::verify_native_control_diagnostic(
                    &self.report,
                    preparation,
                    files,
                    interpreter_sha256,
                    observer_sha256,
                )
            };
            result.ok()
        };
        Ok(self.judgment(role, relations.as_ref()))
    }

    fn judgment(&self, role: &str, relations: Option<&Value>) -> Value {
        let checked = relations.is_some();
        let failure_code = if checked {
            Value::Null
        } else if self.report["status"] == "passed" {
            json!("required-role-artifacts-invalid-or-incomplete")
        } else {
            json!("controller-did-not-complete-role")
        };
        let mcp_grade = relations.and_then(|value| {
            value.pointer("/hooks/process_relations/mcp_artifact_relations/operation_grade")
        });
        let images = relations.and_then(|value| {
            value
                .get("runtime_image_relations")
                .or_else(|| value.pointer("/native_clients/process_event_images"))
        });
        let image_isolation_complete =
            images.is_some_and(|value| value["all_native_runtime_descendants_graded"] == true);
        // These are missing independent observations, not producer-selectable
        // flags. Neither a signature nor a matching final file supplies them.
        let mut missing = vec![
            "reviewed-source-and-build-admission",
            "outside-observer-execution-and-key-admission",
            "resident-operation-semantics",
            "request-decision-effect-attribution",
            "outside-descendant-death-and-cleanup",
        ];
        if !checked {
            missing.insert(0, "complete-role-artifact-observations");
        }
        if !image_isolation_complete {
            missing.push("native-descendant-image-isolation");
        }
        json!({"schema":"hol-gauntlet-native-independent-judgment.v1",
            "control_role":role,"producer_status":self.report["status"],
            "controller_record_sha256":self.record_sha256,"controller_envelope_sha256":self.envelope_sha256,
            "evidence_validity":"incomplete","independent_grade":"invalid-evidence",
            "expected_outcome_scope":"source-selected control artifact contracts",
            "expected_outcome":if checked {"met"}else{"unknown"},
            "observed_role_outcome":if checked {"met"}else{"unknown"},
            "failure_code":failure_code,"missing_observations":missing,
            "evidence_checks":{"controller_signature_verified":true,"signed_preparation_bytes_matched":true,
                "required_role_artifact_relations_checked":checked,
                "native_descendant_image_isolation_complete":image_isolation_complete,
                "native_exec_images_isolation_verified":images.map(|v| &v["native_exec_images_isolation_verified"]),
                "native_inherited_tasks_isolation_verified":images.map(|v| &v["native_inherited_tasks_isolation_verified"]),
                "mcp_operation_semantics_checked":mcp_grade.is_some_and(|v|v["operation_semantics_checked"]==true),
                "sdk_read_delivery_checked":mcp_grade.is_some_and(|v|v["sdk_delivery_checked"]==true)},
            "mcp_operation_grade":mcp_grade,"qualified_role_complete":false,
            "source_matched_conformance_verified":false,"execution_eligible":false,
            "guard_causality_verified":false,"model_resistance_tested":false,"model_requests":0})
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
        worker_generation: pins.prelaunch.worker_generation.clone(),
        deployment_digest: pins.prelaunch.deployment_digest.clone(),
        report: report.clone(),
        record_sha256: sha256(&canonical_value(&record)?),
        envelope_sha256: sha256(raw),
    })
}

#[cfg(test)]
#[path = "native_control_envelope_tests.rs"]
mod tests;
