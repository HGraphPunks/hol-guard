//! Check copied resident-operation reply bindings against their request bodies.
//! This does not evaluate the operation, authenticate pipe bytes or attest the
//! product's decision. Two older reply dialects expose no request digest.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{require, text};
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};

fn schemas(operation: &str) -> Option<(&'static str, &'static str)> {
    Some(match operation {
        "command_capability" => (
            "guard-command-capability-request.v1",
            "guard-command-capability-result.v1",
        ),
        "contained_wrapper_plan" => (
            "guard-contained-wrapper-plan-request.v1",
            "guard-contained-wrapper-plan-result.v1",
        ),
        "daemon_lifecycle_decide" => (
            "guard-daemon-lifecycle-decision-request.v1",
            "guard-daemon-lifecycle-decision-result.v1",
        ),
        "daemon_route" => (
            "guard-daemon-route-request.v1",
            "guard-daemon-route-result.v1",
        ),
        "directory_trust" => (
            "guard-directory-trust-request.v1",
            "guard-directory-trust-result.v1",
        ),
        "extension_control" => (
            "guard-extension-control-request.v1",
            "guard-extension-control-result.v1",
        ),
        "extension_control_authority" => (
            "guard-extension-control-authority-request.v1",
            "guard-extension-control-authority-result.v1",
        ),
        "git_execution_safety" => (
            "guard-git-execution-safety-request.v1",
            "guard-git-execution-safety-result.v1",
        ),
        "guard_store" => ("guard-store-request.v1", "guard-store-result.v1"),
        "hook_decide" => (
            "guard-hook-decision-request.v1",
            "guard-hook-decision-result.v1",
        ),
        "hook_evidence_writer" => (
            "guard-hook-evidence-writer-request.v1",
            "guard-hook-evidence-writer-result.v1",
        ),
        "hook_render" => (
            "guard-hook-render-request.v1",
            "guard-hook-render-result.v1",
        ),
        "local_cli_hook" => (
            "guard-local-cli-hook-request.v1",
            "guard-local-cli-hook-result.v1",
        ),
        "request_context_build" => (
            "guard-request-context-request.v1",
            "guard-request-context-result.v1",
        ),
        "shim_admin" => ("guard-shim-admin-request.v2", "guard-shim-admin-result.v2"),
        _ => return None,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReplyBinding {
    Digest,
    SnapshotEcho,
    Structural,
}

/// Command capability's digest intentionally excludes its signing key. The
/// snapshot ACK echoes an unverified product claim, not a request digest.
pub(super) fn verify(request: &Value, response: &Value) -> Result<ReplyBinding> {
    let row = request
        .as_object()
        .ok_or(EvidenceError::Invalid("resident operation object required"))?;
    require(
        row.len() == 3
            && row.contains_key("operation")
            && row.contains_key("request")
            && row.contains_key("deadline_budget_ms")
            && request["deadline_budget_ms"]
                .as_u64()
                .is_some_and(|n| n > 0),
    )?;
    let operation = text(request, "operation")?;
    let body = request["request"]
        .as_object()
        .ok_or(EvidenceError::Invalid("resident operation body required"))?;
    match operation {
        "hook_direct_evidence_drain" => {
            require(
                body.len() == 1
                    && body.get("guard_home").is_some_and(Value::is_string)
                    && response["schema"] == "guard-hook-direct-evidence.v1"
                    && response["records"].is_array()
                    && response["counters"].is_object()
                    && response["remaining"].as_u64().is_some(),
            )?;
            return Ok(ReplyBinding::Structural);
        }
        "policy_snapshot_push" => {
            let snapshot = &body["snapshot"];
            require(
                body.len() >= 2
                    && body.len() <= 3
                    && body
                        .keys()
                        .all(|key| matches!(key.as_str(), "schema" | "snapshot" | "direct_lane"))
                    && body["schema"] == "guard-policy-snapshot-push.v1"
                    && snapshot.is_object()
                    && response.as_object().is_some_and(|row| {
                        row.len() == 5
                            && [
                                "status",
                                "generation",
                                "policy_digest",
                                "idempotent",
                                "resident_generation",
                            ]
                            .iter()
                            .all(|key| row.contains_key(*key))
                    })
                    && response["status"] == "accepted"
                    && snapshot["generation"].as_u64().is_some_and(|n| n > 0)
                    && response["generation"] == snapshot["generation"]
                    && response["resident_generation"]
                        .as_u64()
                        .is_some_and(|n| n > 0)
                    && response["policy_digest"] == snapshot["policy_digest"]
                    && response["policy_digest"].as_str().is_some_and(|digest| {
                        digest.len() == 64
                            && digest
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    && response["idempotent"].is_boolean(),
            )?;
            return Ok(ReplyBinding::SnapshotEcho);
        }
        _ => {}
    }
    let (request_schema, response_schema) =
        schemas(operation).ok_or(EvidenceError::Invalid("unsupported resident operation"))?;
    let id = body
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 256)
        .ok_or(EvidenceError::Invalid("resident request ID required"))?;
    require(
        body.get("schema") == Some(&json!(request_schema))
            && response["schema"] == response_schema
            && response["request_id"] == id
            && matches!(response["status"].as_str(), Some("ok" | "error"))
            && response["code"]
                .as_str()
                .is_some_and(|code| !code.is_empty()),
    )?;
    let mut material = request["request"].clone();
    if operation == "command_capability" {
        require(material.get("integrity_key_b64").is_some())?;
        material["integrity_key_b64"] = Value::Null;
    }
    let expected = format!("sha256:{}", sha256(&canonical_value(&material)?));
    require(response["request_sha256"] == expected)?;
    Ok(ReplyBinding::Digest)
}

#[cfg(test)]
#[path = "native_stdio_operation_identity_tests.rs"]
mod tests;
