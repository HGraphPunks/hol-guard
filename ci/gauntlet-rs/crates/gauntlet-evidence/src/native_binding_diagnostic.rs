//! Recompute nine malformed Native controls and the separate forbidden control.
//! The host must authenticate the report and pin the public archive first.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{
    argv, digest, handoff, ineligible, request_argv, require, text, Artifacts,
};
use crate::{canonical_value, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const CASES: [&str; 9] = [
    "wrong-sha",
    "foreign-workspace",
    "foreign-cwd",
    "wrong-event",
    "wrong-tool",
    "nonstring-command",
    "duplicate-field",
    "wrong-schema",
    "missing-payload",
];
const TRAP: &[u8] = b"import unittest\nfrom pathlib import Path\nclass Trap(unittest.TestCase):\n def test_unexpected(self):Path('unexpected-negative-sink.txt').write_text('executed')\n";

fn expected_request(case: &str, session: &str) -> Result<Vec<u8>> {
    let mut value = json!({"schema":"guard-contained-test-request.v1","workspace":"/runtime/home/project",
        "payload":{"session_id":session,"config_path":"/product/home/omp.json","tool_name":"bash",
        "tool_call_id":"snapshot-negative","hook_event_name":"PreToolUse",
        "tool_input":{"command":"python3 -m unittest discover -s negative_tests -v"}}});
    match case {
        "foreign-workspace" => value["workspace"] = json!("/product/home"),
        "foreign-cwd" => value["payload"]["cwd"] = json!("/tmp"),
        "wrong-event" => value["payload"]["hook_event_name"] = json!("PostToolUse"),
        "wrong-tool" => value["payload"]["tool_name"] = json!("read"),
        "nonstring-command" => value["payload"]["tool_input"]["command"] = json!(42),
        "wrong-schema" => value["schema"] = json!("guard-contained-test-request.v0"),
        "missing-payload" => {
            value.as_object_mut().unwrap().remove("payload");
        }
        _ => {}
    }
    let mut raw = canonical_value(&value)?;
    if case == "duplicate-field" {
        let mut duplicate = b"{\"workspace\":\"/runtime/home/project\",".to_vec();
        duplicate.extend_from_slice(&raw[1..]);
        raw = duplicate;
    }
    Ok(raw)
}
pub(crate) fn authorization(stderr: &str) -> bool {
    stderr.split_once(':').is_some_and(|(code, reason)| {
        matches!(
            code,
            "contained_run_authorization_failed" | "contained_test_authorization_failed"
        ) && !reason.trim().is_empty()
    })
}
fn bindings(control: &Value, prefix: &str, artifacts: &Artifacts<'_>) -> Result<usize> {
    let controls = &control["measurements"]["request_binding_controls"];
    ineligible(controls)?;
    require(
        controls["schema"] == "hol-gauntlet-native-request-binding-controls.v1"
            && controls["root_control_probe_not_sdk_operation"] == true,
    )?;
    let rows = controls["rows"]
        .as_array()
        .ok_or(crate::EvidenceError::Invalid("Native binding rows missing"))?;
    require(rows.len() == CASES.len())?;
    let mut names = BTreeSet::new();
    let mut after = None;
    let session = text(&control["plane"], "controller_session_id")?;
    require(session == format!("gauntlet-native-sdk-mcp-{}", text(control, "job_id")?))?;
    let observations = control["plane"]["observations"]
        .as_array()
        .ok_or(crate::EvidenceError::Invalid("Native observations missing"))?;
    let observed: Vec<&Value> = observations
        .iter()
        .filter(|v| v["kind"] == "native-request-binding-control")
        .map(|v| &v["observation"])
        .collect();
    require(observed == rows.iter().collect::<Vec<_>>())?;
    for row in rows {
        let case = text(row, "case")?;
        require(CASES.contains(&case) && names.insert(case))?;
        let raw = text(row, "request_wire_utf8")?.as_bytes();
        require(
            raw == expected_request(case, session)? && row["actual_request_sha256"] == sha256(raw),
        )?;
        handoff(&row["handoff"], raw)?;
        let declared = text(row, "declared_request_sha256")?;
        require(
            declared
                == if case == "wrong-sha" {
                    "0".repeat(64)
                } else {
                    sha256(raw)
                },
        )?;
        let command = argv(&row["native_command"])?;
        require(command == request_argv(prefix, text(&row["handoff"], "path")?, declared))?;
        let stderr = text(row, "stderr")?;
        require(
            row["exit_code"].as_i64() == Some(126)
                && authorization(stderr)
                && row["stdout_sha256"] == sha256(b"")
                && row["stderr_sha256"] == sha256(stderr.as_bytes())
                && row["trap_effect_present"] == false
                && row["cleanup_complete"] == true,
        )?;
        for field in ["capture_error", "cleanup_error", "trap_readback_error"] {
            require(row.get(field).is_some_and(Value::is_null))?;
        }
        let capture = artifacts.capture(
            &command,
            126,
            &sha256(b""),
            &sha256(stderr.as_bytes()),
            after,
        )?;
        require(capture.stdout.is_empty() && capture.stderr == stderr.as_bytes())?;
        after = Some(capture.sequence);
    }
    let name = "combined/workspace/negative_tests/test_trap.py";
    require(artifacts.raw(name)? == TRAP)?;
    let fixture = &controls["fixture"];
    require(
        fixture["sha256"] == sha256(TRAP) && fixture["bytes"].as_u64() == Some(TRAP.len() as u64),
    )?;
    let physical = artifacts.json("combined/physical-control-readback.json")?;
    require(
        physical["unexpected_negative_sink_absent"] == true
            && physical["binding_fixture_sha256"] == sha256(TRAP),
    )?;
    let meta = artifacts.metadata(name)?;
    require(
        meta["uid"].as_u64() == Some(10001)
            && meta["gid"].as_u64() == Some(10001)
            && meta["mode"].as_u64() == Some(0o600)
            && meta["links"].as_u64() == Some(1),
    )?;
    for field in ["device", "inode", "uid", "gid"] {
        require(fixture.get(field).is_some() && fixture[field] == meta[field])?;
    }
    Ok(rows.len())
}

/// Supplied-byte relations only. Use the host's authenticated completion and
/// outside archive digest wrapper for retained evidence. No role is qualified.
pub fn verify_native_binding_diagnostic(
    control: &Value,
    preparation: &Value,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Value> {
    ineligible(control)?;
    require(
        control["schema"] == "hol-gauntlet-native-deterministic-control.v1"
            && control["control_role"] == "input-binding"
            && control["qualified_role_complete"] == false
            && preparation["schema"] == "hol-gauntlet-cell-preparation.v1"
            && control["preparation_sha256"] == digest(preparation)?,
    )?;
    let prefix = text(preparation, "runtime_prefix")?;
    let artifacts = Artifacts::new(files)?;
    let count = bindings(control, prefix, &artifacts)?;
    crate::native_forbidden_diagnostic::verify(control, prefix, &artifacts)?;
    Ok(
        json!({"schema":"hol-gauntlet-native-binding-diagnostic-relations.v1","job_id":control["job_id"],
        "native_request_refusals":count,"capture_bytes_and_chain_checked":true,
        "trap_unchanged_and_absent_effect":true,"forbidden_authorization_control_verified":true,
        "positive_target_retired_and_reseeded":true,"protected_marker_unchanged":true,
        "independent_process_custody_checked":false,"qualified_role_complete":false,
        "outside_signing_key_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_binding_diagnostic_tests.rs"]
mod tests;
