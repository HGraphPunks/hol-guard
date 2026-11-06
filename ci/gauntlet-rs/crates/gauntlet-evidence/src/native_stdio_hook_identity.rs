//! Independently recompute the copied OMP edge identities used by this profile.
//! These are product claim correlations, without observer or policy admission.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{require, text};
use crate::{EvidenceError, Result};
use serde_json::{json, Value};

fn fields(value: &Value, required: &[&str], optional: &[&str]) -> Result<()> {
    require(value.as_object().is_some_and(|row| {
        required.iter().all(|key| row.contains_key(*key))
            && row
                .keys()
                .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
    }))
}

// The product identity dialect serializes sorted JSON objects and integer
// numbers directly. This diagnostic subset refuses floats/oversized integers
// rather than silently substituting the Python canonical-number dialect.
fn native_digest(value: &Value) -> Result<String> {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(rows) => pending.extend(rows),
            Value::Object(row) => pending.extend(row.values()),
            Value::Number(number) => require(number.is_i64() || number.is_u64())?,
            _ => {}
        }
    }
    // serde_json's locked default map is sorted; preserve_order is not enabled.
    Ok(sha256(&serde_json::to_vec(value).map_err(|_| {
        EvidenceError::Invalid("Native identity encoding failed")
    })?))
}

fn normalized_source(source: &Value) -> Result<Value> {
    let mut normalized = source.clone();
    if let Some(context) = source.get("execution_environment") {
        fields(
            context,
            &["path", "environment_names", "environment_digest"],
            &[
                "home",
                "git_pager_disabled",
                "pager_disabled",
                "xdg_config_home",
                "git_config_no_system",
                "library_search_paths",
            ],
        )?;
        require(
            context["path"].is_string()
                && context["environment_digest"].is_string()
                && context["environment_names"]
                    .as_array()
                    .is_some_and(|rows| rows.iter().all(Value::is_string)),
        )?;
        let mut context = context.as_object().unwrap().clone();
        for key in ["home", "xdg_config_home"] {
            let value = context.entry(key).or_insert(Value::Null);
            require(value.is_null() || value.is_string())?;
        }
        for key in [
            "git_pager_disabled",
            "pager_disabled",
            "git_config_no_system",
        ] {
            require(context.entry(key).or_insert(json!(false)).is_boolean())?;
        }
        if let Some(paths) = context.get("library_search_paths") {
            require(
                paths
                    .as_object()
                    .is_some_and(|row| row.values().all(Value::is_string)),
            )?;
            // The Native contract skips an empty map when serializing the
            // typed execution context into either request identity.
            if paths.as_object().unwrap().is_empty() {
                context.remove("library_search_paths");
            }
        }
        normalized["execution_environment"] = Value::Object(context);
    }
    Ok(normalized)
}

fn identities(request: &Value) -> Result<(String, String)> {
    let event = text(request, "event")?;
    require(
        request["schema"] == "guard-hook-envelope.v2"
            && request["harness"] == "omp"
            && matches!(event, "UserPromptSubmit" | "PreToolUse" | "PostToolUse")
            && request["raw_payload"]["hook_event_name"] == event,
    )?;
    fields(
        request,
        &[
            "schema",
            "request_id",
            "harness",
            "event",
            "raw_payload",
            "deadline_budget_ms",
            "policy_generation",
            "policy_snapshot",
            "source",
        ],
        &[
            "recording_only",
            "local_cli_rules",
            "observe_local_cli",
            "structured_output_config",
        ],
    )?;
    require(request.get("recording_only").is_none_or(|v| v == false))?;
    require(
        request
            .get("observe_local_cli")
            .is_none_or(Value::is_boolean),
    )?;
    let source = &request["source"];
    fields(
        source,
        &[
            "cwd",
            "home_dir",
            "guard_home",
            "source_ref_external_allowed",
        ],
        &["execution_environment"],
    )?;
    require(
        source["cwd"] == "/runtime/home/project"
            && source["home_dir"] == "/runtime/home"
            && source["guard_home"] == "/product/guard"
            && source["source_ref_external_allowed"] == true
            && source
                .get("execution_environment")
                .is_none_or(Value::is_object),
    )?;
    let generation = request["policy_generation"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(EvidenceError::Invalid("Native hook generation required"))?;
    let snapshot = &request["policy_snapshot"];
    require(snapshot.is_object() && snapshot["generation"].as_u64() == Some(generation))?;
    require(
        request["deadline_budget_ms"].is_null() || request["deadline_budget_ms"].as_u64().is_some(),
    )?;
    let source = normalized_source(source)?;
    let mut payload = request["raw_payload"]
        .as_object()
        .ok_or(EvidenceError::Invalid(
            "Native hook payload object required",
        ))?
        .clone();
    for key in [
        "event",
        "eventName",
        "hook_event_name",
        "hookEventName",
        "hook_name",
        "hookName",
    ] {
        require(payload.get(key).is_none_or(|v| v == event))?;
        payload.remove(key);
    }
    for key in [
        "timestamp",
        "timestamp_ms",
        "timestampMs",
        "created_at",
        "createdAt",
        "received_at",
        "receivedAt",
    ] {
        payload.remove(key);
    }
    if event == "PreToolUse"
        && payload
            .get("session_id")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    {
        payload.remove("tool_call_id");
    }
    let policy = json!({"generation":generation,"policy_digest":snapshot["policy_digest"],
        "rule_digest":snapshot["rule_digest"],"runtime_identity":snapshot["runtime_identity"],
        "scope_digest":snapshot["scope_contract"]["scope_digest"]});
    let identity = json!({"schema":"guard-native-request-identity.v3","version":3,
        "event":event,"harness":"omp","payload":payload,"policy":policy,"source":source});
    let mut narrow_source = json!({"cwd":source["cwd"],"home_dir":source["home_dir"]});
    if let Some(context) = source.get("execution_environment") {
        narrow_source["execution_environment"] = context.clone();
    }
    let intent = json!({"schema":"guard-native-execution-intent.v2","version":2,
        "event":event,"harness":"omp","payload":payload,"source":narrow_source});
    Ok((native_digest(&identity)?, native_digest(&intent)?))
}

pub(crate) fn verify(request: &Value, response: &Value) -> Result<Value> {
    let (request_digest, intent) = identities(request)?;
    let request_id = match request.get("request_id") {
        Some(Value::Null) => format!("sha256:{request_digest}"),
        Some(Value::String(id))
            if !id.is_empty()
                && id.len() <= 256
                && id.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
                }) =>
        {
            id.clone()
        }
        _ => return Err(EvidenceError::Invalid("Native hook request ID unsupported")),
    };
    fields(
        response,
        &[
            "schema",
            "authority",
            "request_id",
            "harness",
            "event_name",
            "payload_kind",
            "result",
            "harness_response",
            "receipt",
        ],
        &["containment_route", "local_cli_rule"],
    )?;
    let receipt = &response["receipt"];
    let result = &response["result"];
    require(
        response["schema"] == "guard-hook-edge-result.v2"
            && response["authority"] == "rust"
            && response["request_id"] == request_id
            && response["harness"] == "omp"
            && response["event_name"] == request["event"]
            && response["payload_kind"] == "inline"
            && response["harness_response"].is_object()
            && result.is_object()
            && receipt["schema"] == "guard-native-hook-decision-receipt.v1"
            && receipt["version"].as_u64() == Some(1)
            && receipt["authority"] == "rust"
            && receipt["request_id"] == request_id
            && receipt["request_digest"] == request_digest
            && receipt["execution_intent_digest"] == intent
            && receipt["event_name"] == request["event"]
            && receipt["harness"] == "omp"
            && receipt["payload_kind"] == "inline"
            && receipt["policy_generation"] == request["policy_generation"]
            && receipt["policy_digest"] == request["policy_snapshot"]["policy_digest"]
            && receipt["runtime_identity"] == request["policy_snapshot"]["runtime_identity"]
            && receipt["workspace_bound"] == true
            && receipt["source_ref_external_allowed"] == true
            && receipt["deadline_budget_ms"] == request["deadline_budget_ms"]
            && receipt["observe_mode"] == false,
    )?;
    for key in [
        "decision",
        "policy_action",
        "observed_policy_action",
        "reason_code",
        "reviewed_output_sha256",
    ] {
        require(receipt[key] == result[key])?;
    }
    require(
        receipt["model_output_action"]
            == if request["event"] == "PostToolUse" {
                result["model_output_action"].clone()
            } else {
                json!("not_applicable")
            },
    )?;
    let mut decision = json!({"schema":"guard-native-hook-decision-identity.v1","version":1});
    for key in [
        "request_id",
        "request_digest",
        "harness",
        "event_name",
        "payload_kind",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "decision",
        "model_output_action",
        "policy_action",
        "observed_policy_action",
        "reason_code",
        "workspace_bound",
        "source_ref_external_allowed",
        "reviewed_output_sha256",
        "observe_mode",
        "deadline_budget_ms",
    ] {
        decision[key] = receipt
            .get(key)
            .ok_or(EvidenceError::Invalid(
                "Native decision identity field missing",
            ))?
            .clone();
    }
    for key in [
        "command_extensions",
        "business_review_binding",
        "prompt_risk_classes",
    ] {
        if let Some(value) = receipt.get(key) {
            decision[key] = value.clone();
        }
    }
    require(receipt["decision_id"] == native_digest(&decision)?)?;
    Ok(
        json!({"request_digest":request_digest,"execution_intent_digest":intent,
        "decision_id":receipt["decision_id"],"copied_request_and_receipt_identity_checked":true,
        "policy_evaluation_recomputed":false,"review_anchor_verified":false,
        "product_claims_authenticated":false,"atomic_kernel_pipe_bytes_verified":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_stdio_hook_identity_tests.rs"]
mod tests;
