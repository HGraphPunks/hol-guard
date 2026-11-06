//! The unified Native/daemon route reviews completed output once. The retired
//! CLI artifact pipeline must not be restored to reclassify the original call.
use guard_contracts::{NativeHookRequestV1, NATIVE_PROTOCOL_VERSION};
use guard_hook_core::{review_post_tool, sha256_text};
use serde_json::{json, Value};

fn request(command: &str, output: &str, hint: bool) -> NativeHookRequestV1 {
    let mut payload = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "bash",
        "tool_input": {"command": command},
        "tool_response": [{"type": "text", "text": output}],
        "is_error": false,
    });
    if hint {
        payload["guard_contained_output_profile"] = json!("controller-contained-output.v1");
    }
    NativeHookRequestV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        request_id: Some("contained-post-regression".into()),
        harness: "omp".into(),
        event_name: "PostToolUse".into(),
        payload,
        cwd: Some("/runtime/home/project".into()),
        home_dir: "/runtime/home".into(),
        guard_home: "/product/guard".into(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

#[test]
fn completed_shell_output_is_reviewed_without_reopening_execution() {
    for command in [
        "rm -rf /runtime/home/project/generated",
        "/usr/bin/node --test tests/control.cjs",
    ] {
        for hint in [false, true] {
            let response = review_post_tool(&request(command, "private plane effect", hint));
            assert_eq!(response.decision, "allow", "{command}");
            assert_eq!(response.reason_code, "output_scan_allow");
            assert_eq!(
                response.reviewed_output_sha256,
                Some(sha256_text("private plane effect"))
            );
        }
    }
}

#[test]
fn completion_hint_never_exempts_sensitive_output_from_review() {
    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    for hint in [false, true] {
        let response = review_post_tool(&request("node --test tests/control.cjs", &token, hint));
        assert_eq!(response.decision, "deny");
        assert_eq!(response.reason_code, "output_secret_match");
    }
}

#[test]
fn completed_output_path_cannot_answer_pre_tool_admission() {
    let mut pre = request("node --test tests/control.cjs", "ordinary output", true);
    pre.event_name = "PreToolUse".into();
    pre.payload["hook_event_name"] = Value::String(pre.event_name.clone());
    let response = review_post_tool(&pre);
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "not_post_tool");
}
