//! Actual normal Native hook captures and contained-result/SDK joins.
//! Missing historical stdin receipts remain unverified; no role is admitted.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{
    argv, digest, guard_argv, handoff, request_argv, require, text, Artifacts,
};
use crate::native_process_kernel::list;
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn expected_pre(control: &Value) -> Result<Value> {
    let request = &control["requests"][0]["request"];
    require(
        request["tool_name"] == "bash"
            && request["tool_call_id"] == "sdk-contained-control"
            && request["hook_event_name"] == "PreToolUse"
            && request["tool_input"]
                == json!({"command":"python3 -m unittest discover -s tests -v"})
            && request["execution_environment"].is_object(),
    )?;
    Ok(
        json!({"hook_event_name":"PreToolUse","config_path":"/product/home/omp.json",
        "session_id":control["plane"]["controller_session_id"],"tool_call_id":"sdk-contained-control",
        "tool_name":"bash","tool_input":request["tool_input"],"guard_execution_environment":request["execution_environment"],
        "guard_contained_output_profile":"controller-contained-output.v1"}),
    )
}
pub(crate) fn completed_output(control: &Value) -> Result<Option<Value>> {
    let executions = list(&control["plane"]["executions"], 1)?;
    if control["control_role"] == "cancel" {
        require(executions.is_empty() && control["measurements"].get("sdk").is_none())?;
        return Ok(None);
    }
    require(executions.len() == 1)?;
    let result = &executions[0];
    let code = if control["control_role"] == "timeout" {
        124
    } else {
        0
    };
    require(
        result["exit_code"].as_i64() == Some(code)
            && result["product_claims_authenticated"] == false
            && result["containment_conformance_established"] == false
            && control["requests"][1]["response"]["result"] == *result,
    )?;
    let mut output = crate::captured_contained_output(result)?;
    output["pre_payload_digest"] = result["payload_digest"].clone();
    require(control["requests"][2]["response"]["contained_output"] == output)?;
    let delivered = &control["measurements"]["sdk"]["result"]["results"][1];
    require(
        delivered["toolCallId"] == "sdk-contained-control"
            && delivered["toolName"] == "bash"
            && delivered["content"] == output["tool_response"]
            && delivered["isError"] == output["is_error"],
    )?;
    Ok(Some(output))
}
pub(crate) fn hook_payloads(control: &Value, output: Option<&Value>) -> Result<Vec<Value>> {
    let plane = &control["plane"];
    let session = text(plane, "controller_session_id")?;
    require(!session.is_empty() && session.len() <= 256)?;
    let prompt = crate::native_process_public::PROMPT;
    let first = json!({"hook_event_name":"UserPromptSubmit","config_path":"/product/home/omp.json","session_id":session,"prompt":prompt});
    let pre = expected_pre(control)?;
    let mut result = vec![first, pre.clone()];
    if let Some(output) = output {
        let mut post = pre;
        post["hook_event_name"] = json!("PostToolUse");
        post["tool_response"] = output["tool_response"].clone();
        post["is_error"] = output["is_error"].clone();
        result.push(post);
    }
    if matches!(
        control["control_role"].as_str(),
        Some("input-binding" | "injection")
    ) {
        let extra = json!({"config_path":"/product/home/omp.json","hook_event_name":"PreToolUse","tool_name":"bash",
            "session_id":session,"tool_call_id":"forbidden-command-probe",
            "tool_input":{"command":"rm -rf /runtime/home/project/forbidden-command-target"}});
        require(
            control["measurements"]["forbidden_command_control"]["native_pre_payload"] == extra,
        )?;
        result.push(extra);
    }
    Ok(result)
}

/// Compose authenticated public process/provider relations with actual hook and
/// contained output bytes. Full Native process/effect/lifecycle custody is open.
pub fn verify_native_hook_diagnostic(
    control: &Value,
    preparation: &Value,
    files: &BTreeMap<String, Vec<u8>>,
    interpreter_sha256: &str,
    observer_sha256: &str,
) -> Result<Value> {
    let process = crate::verify_native_process_diagnostic(
        control,
        preparation,
        files,
        interpreter_sha256,
        observer_sha256,
    )?;
    let artifacts = Artifacts::new(files)?;
    let prefix = text(preparation, "runtime_prefix")?;
    let plane = &control["plane"];
    let plane_schema = match preparation["launch"]["schema"].as_str() {
        Some("hol-gauntlet-cell-supervisor.v3") => "hol-gauntlet-native-hook-plane.v2",
        Some("hol-gauntlet-cell-supervisor.v4") => "hol-gauntlet-native-hook-plane.v3",
        _ => "hol-gauntlet-native-hook-plane.v1",
    };
    require(
        plane["schema"] == plane_schema
            && plane["pins"] == control["guard_pins"]
            && plane["cleanup_complete"] == true
            && plane["product_claims_authenticated"] == false
            && plane["guard_causality_verified"] == false
            && plane["execution_eligible"] == false
            && plane["model_requests"].as_u64() == Some(0),
    )?;
    let journal_bound = crate::native_capture_input::journal_binding(plane, &artifacts)?;
    let output = completed_output(control)?;
    let expected = hook_payloads(control, output.as_ref())?;
    let hooks = list(&plane["hooks"], 4)?;
    require(hooks.len() == expected.len())?;
    let command = guard_argv(
        prefix,
        &[
            "hook",
            "--json",
            "--harness",
            "omp",
            "--guard-home",
            "/product/guard",
            "--home",
            "/runtime/home",
            "--workspace",
            "/runtime/home/project",
        ],
    );
    let mut after = None;
    let mut inputs = Vec::new();
    let mut captures = Vec::new();
    for (index, (row, payload)) in hooks.iter().zip(expected.iter()).enumerate() {
        require(
            row["payload"] == *payload
                && row["payload_digest"] == digest(payload)?
                && row["hook_event_name"] == payload["hook_event_name"]
                && row.get("normalization_error").is_some_and(Value::is_null)
                && row["product_claims_authenticated"] == false,
        )?;
        let code = row["returncode"]
            .as_i64()
            .filter(|n| (-255..=255).contains(n))
            .ok_or(EvidenceError::Invalid("typed Native hook exit required"))?;
        let captured = artifacts.capture(
            &command,
            code,
            text(row, "stdout_sha256")?,
            text(row, "stderr_sha256")?,
            after,
        )?;
        require(captured.stderr.is_empty())?;
        let event = text(payload, "hook_event_name")?;
        let response = crate::normalize_native_hook_response(captured.stdout, code, Some(event))?;
        require(row["response"] == response)?;
        match (index, output.as_ref()) {
            (0, _) => require(
                response["decision"] == "allow"
                    && plane["prompt"]["response"] == response
                    && plane["prompt"]["digest"]
                        == digest(&json!(crate::native_process_public::PROMPT))?,
            )?,
            (1, _) => require(
                response["decision"] == "deny"
                    && response["policy_action"] == "sandbox-required"
                    && response["required_execution_profile"] == "workspace-contained-v1"
                    && response["reason_code"] == "native_workspace_containment_required"
                    && control["requests"][0]["response"]["product_response"] == response,
            )?,
            (2, Some(out)) => {
                require(
                    response["decision"] == "allow"
                        && response["reviewed_output_sha256"] == out["output_sha256"]
                        && response["model_output_action"] == "allow_original"
                        && control["requests"][2]["response"]["product_response"] == response,
                )?;
            }
            _ => require(response["decision"] == "deny" || response["decision"] == "block")?,
        }
        let mut raw = canonical_value(payload)?;
        raw.push(b'\n');
        inputs.push(crate::verify_native_capture_input(
            &artifacts.events,
            captured.sequence,
            &command,
            &raw,
        )?);
        captures.push(captured.sequence);
        after = Some(captured.sequence);
    }
    let pre = &expected[1];
    let raw = canonical_value(
        &json!({"schema":"guard-contained-test-request.v1","workspace":"/runtime/home/project","payload":pre}),
    )?;
    let rows = list(&plane["observations"], 10_000)?;
    let handoffs = rows
        .iter()
        .filter(|r| r["kind"] == "native-contained-request-handoff")
        .collect::<Vec<_>>();
    require(handoffs.len() == 1)?;
    let handoff_row = handoffs[0];
    let request = &handoff_row["request"];
    handoff(request, &raw)?;
    require(
        handoff_row["cleanup_complete"] == true
            && handoff_row.get("cleanup_error").is_some_and(Value::is_null),
    )?;
    let mut command = request_argv(prefix, text(request, "path")?, &sha256(&raw));
    if control["control_role"] != "timeout" {
        *command.last_mut().unwrap() = "30".into();
    }
    let mut sink_input = None;
    if let Some(output) = &output {
        let result = &plane["executions"][0];
        require(
            result["payload_digest"] == digest(pre)?
                && result["request_sha256"] == sha256(&raw)
                && argv(&result["native_command"])? == command
                && handoff_row.get("capture_error").is_some_and(Value::is_null),
        )?;
        let captured = artifacts.capture(
            &command,
            result["exit_code"].as_i64().unwrap(),
            text(result, "stdout_sha256")?,
            text(result, "stderr_sha256")?,
            Some(captures[1]),
        )?;
        require(
            captured.sequence < captures[2]
                && captured.stdout == text(result, "stdout")?.as_bytes()
                && captured.stderr == text(result, "stderr")?.as_bytes()
                && output["pre_payload_digest"] == digest(pre)?,
        )?;
        sink_input = Some(crate::verify_native_capture_input(
            &artifacts.events,
            captured.sequence,
            &command,
            b"",
        )?);
    } else {
        require(hooks.len() == 2 && plane["executions"] == json!([]))?;
    }
    if journal_bound {
        require(
            inputs.iter().all(|v| v["input_delivery_checked"] == true)
                && sink_input
                    .as_ref()
                    .is_none_or(|v| v["input_delivery_checked"] == true),
        )?;
    }
    let checked = inputs
        .iter()
        .filter(|v| v["input_delivery_checked"] == true)
        .count();
    Ok(
        json!({"schema":"hol-gauntlet-native-hook-artifact-relations.v1","actual_hook_captures_checked":hooks.len(),
        "hook_input_deliveries_checked":checked,"hook_input_relations":inputs,"contained_result_checked":output.is_some(),
        "journal_report_binding_checked":journal_bound,
        "contained_sink_input":sink_input,"cancelled_sink_lifecycle_graded":false,
        "native_process_custody_checked":false,"physical_effect_causality_checked":false,
        "process_relations":process,"qualified_role_complete":false,"outside_signing_key_admitted":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_input_uses_root_session_exact_sdk_input_and_complete_environment() {
        let value = json!({"plane":{"controller_session_id":"root-session"},"requests":[{"request":{
            "session_id":"sdk-session","hook_event_name":"PreToolUse","tool_call_id":"sdk-contained-control","tool_name":"bash",
            "tool_input":{"command":"python3 -m unittest discover -s tests -v"},"execution_environment":{"path":"/usr/bin:/bin","guard":"actual"}}}]});
        let expected = expected_pre(&value).unwrap();
        assert_eq!(expected["session_id"], "root-session");
        assert_eq!(
            expected["guard_execution_environment"],
            value["requests"][0]["request"]["execution_environment"]
        );
        let mut wrong = value;
        wrong["requests"][0]["request"]["tool_input"]["command"] = json!("rm -rf target");
        assert!(expected_pre(&wrong).is_err());
    }
    #[test]
    fn cancellation_payloads_preserve_missing_post_and_forbidden_probe_is_role_selected() {
        let mut value = json!({"control_role":"cancel","plane":{"controller_session_id":"root"},"requests":[{"request":{
            "hook_event_name":"PreToolUse","tool_call_id":"sdk-contained-control","tool_name":"bash",
            "tool_input":{"command":"python3 -m unittest discover -s tests -v"},"execution_environment":{}}}]});
        assert_eq!(hook_payloads(&value, None).unwrap().len(), 2);
        value["control_role"] = json!("injection");
        assert!(hook_payloads(&value, None).is_err());
    }
}
