//! Exact historical input-binding cases, with a fixed synthetic trap request.
use crate::{hash, Result};
use serde_json::json;

pub(crate) const NAMES: [&str; 9] = [
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
pub(crate) fn request(case: &str, session: &str) -> Result<(Vec<u8>, String)> {
    if !NAMES.contains(&case) || session.is_empty() || session.len() > 256 {
        return Err("fixed Native request-binding case required".into());
    }
    let mut value = json!({"schema":"guard-contained-test-request.v1","workspace":"/runtime/home/project",
        "payload":{"hook_event_name":"PreToolUse","config_path":"/product/home/omp.json","tool_name":"bash",
            "tool_call_id":"snapshot-negative","session_id":session,
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
    let mut raw = gauntlet_contracts::canonicalize(value.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    if case == "duplicate-field" {
        let mut duplicate = br#"{"workspace":"/runtime/home/project","#.to_vec();
        duplicate.extend_from_slice(&raw[1..]);
        raw = duplicate;
    }
    let declared = if case == "wrong-sha" {
        "0".repeat(64)
    } else {
        hash(&raw)
    };
    Ok((raw, declared))
}
pub(crate) fn rejected(stderr: &[u8]) -> bool {
    std::str::from_utf8(stderr)
        .ok()
        .and_then(|s| s.split_once(':'))
        .is_some_and(|(code, _)| {
            matches!(
                code,
                "contained_test_authorization_failed" | "contained_run_authorization_failed"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_json_and_wrong_digest_controls_cannot_be_normalized_into_valid_inputs() {
        let (raw, declared) = request("duplicate-field", "outside-session").unwrap();
        assert!(gauntlet_contracts::canonicalize(&raw).is_err());
        assert_eq!(declared, hash(&raw));
        let (raw, declared) = request("wrong-sha", "outside-session").unwrap();
        assert_ne!(declared, hash(&raw));
        assert!(gauntlet_contracts::canonicalize(&raw).is_ok());
    }
    #[test]
    fn unrelated_planner_and_transport_failures_cannot_count_as_native_request_refusal() {
        for text in [
            "contained_test_authorization_failed: expected refusal",
            "contained_run_authorization_failed: expected refusal",
        ] {
            assert!(rejected(text.as_bytes()));
        }
        for text in [
            "contained_test_authorization_failed",
            " contained_test_authorization_failed: x",
            "planner_failure: refused",
            "pytest_restricted_invalid_workspace: missing project marker",
            "pytest_restricted_invalid_command: refused",
            "runtime unavailable",
        ] {
            assert!(!rejected(text.as_bytes()));
        }
    }
}
