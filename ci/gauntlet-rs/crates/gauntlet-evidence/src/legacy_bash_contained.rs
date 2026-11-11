//! Bind the exact installed Bash-owner/contained adapter rewrite, never a flag.
use super::*;
use crate::payload::exact_keys;
use regex::Regex;
use std::sync::OnceLock;

pub(super) fn profile(reason: &str) -> Option<&'static str> {
    Some(match reason {
        "native_bash_owner_required" => "native-bash-owner-v1",
        "native_python_eval_readonly_containment_required" => "python-eval-readonly-v1",
        "native_node_eval_readonly_containment_required"
        | "native_bun_eval_readonly_containment_required" => "node-eval-readonly-v1",
        "native_package_test_readonly_containment_required" => "package-test-readonly-v1",
        "native_node_build_output_containment_required" => "node-build-output-v1",
        "native_node_tool_readonly_containment_required" => "node-tool-readonly-v1",
        "native_git_readonly_containment_required" => "git-readonly-v1",
        "native_pytest_readonly_containment_required" => "pytest-readonly-v2",
        "native_vitest_readonly_containment_required" => "vitest-readonly-v1",
        "native_node_test_readonly_containment_required" => "node-test-readonly-v1",
        "native_workspace_containment_required" => "workspace-contained-v1",
        _ => return None,
    })
}

pub(super) fn is_deny(row: &Value, bound: &BTreeMap<String, Value>) -> bool {
    row["tool_call_id"]
        .as_str()
        .is_some_and(|id| bound.contains_key(id))
        && row["event"] == "PreToolUse"
        && row["decision"] == "deny"
        && row["policy_action"] == "sandbox-required"
}
pub(super) fn benign_exit(scenario: &Value, call: &Value) -> bool {
    call["name"] == "bash"
        && scenario["benign_exit_commands"]
            .as_array()
            .is_some_and(|a| a.contains(&call["args"]["command"]))
        && call["result"]["details"]["exitCode"]
            .as_i64()
            .is_some_and(|n| !matches!(n, 0 | 126 | 127))
}

fn quoted_argv(command: &str) -> Option<Vec<String>> {
    if command.len() > 32768 || command.contains('\0') {
        return None;
    }
    let chars: Vec<_> = command.chars().collect();
    let mut at = 0;
    let mut argv = Vec::new();
    while at < chars.len() {
        if chars[at] != '\'' {
            return None;
        }
        at += 1;
        let mut arg = String::new();
        loop {
            let ch = *chars.get(at)?;
            at += 1;
            if ch == '\'' {
                if chars.get(at..at + 3) == Some(&['\\', '\'', '\''][..]) {
                    arg.push('\'');
                    at += 3;
                    continue;
                }
                break;
            }
            arg.push(ch);
        }
        argv.push(arg);
        if at == chars.len() {
            break;
        }
        if chars[at] != ' ' || at + 1 == chars.len() {
            return None;
        }
        at += 1;
    }
    Some(argv)
}
fn decimal(value: &str, min: u64, max: u64, width: usize) -> bool {
    !value.is_empty()
        && value.len() <= width
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|v| (min..=max).contains(&v))
}
fn request_path(value: &str) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        && path.file_name().is_some_and(|v| v == "request.json")
        && path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with("hol-guard-contained-test-"))
}
fn wrapper(
    command: &str,
    call_id: &str,
    owner: bool,
) -> std::result::Result<Vec<String>, &'static str> {
    let error = "native Bash wrapper is not the canonical case-owned execution sink";
    let argv = quoted_argv(command).ok_or(if owner {
        error
    } else {
        "contained wrapper command is not canonical"
    })?;
    if owner {
        let flags = [
            (1, "execute-bound-bash"),
            (2, "--harness"),
            (4, "--operation-id"),
            (6, "--host-owner-pid"),
            (8, "--tool-call-id"),
            (10, "--guard-home"),
            (12, "--workspace"),
            (14, "--request-file"),
            (16, "--request-sha256"),
            (18, "--timeout-seconds"),
            (20, "--home"),
        ];
        if argv.len() != 22
            || flags.iter().any(|(i, v)| argv[*i] != *v)
            || !argv[0].starts_with('/')
            || std::path::Path::new(&argv[0])
                .file_name()
                .is_none_or(|p| p != "hol-guard")
            || argv[3] != "omp"
            || !argv[5]
                .strip_prefix("bash-operation:")
                .is_some_and(is_sha256)
            || !decimal(&argv[7], 2, i32::MAX as u64, 10)
            || argv[9] != call_id
            || argv[11] != "{{fixture}}/guard-home"
            || argv[13] != "{{workspace}}"
            || !request_path(&argv[15])
            || !is_sha256(&argv[17])
            || !decimal(&argv[19], 1, 120, 3)
            || argv[21] != "{{home}}"
        {
            return Err(error);
        }
        return Ok([0, 1, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21]
            .into_iter()
            .map(|i| argv[i].clone())
            .collect());
    }
    if !matches!(argv.len(), 10 | 12) || !argv[0].starts_with('/') {
        return Err("contained wrapper is not an approved path");
    }
    if argv[1] != "execute-contained-test"
        || argv[2] != "--guard-home"
        || !argv[3].starts_with("{{fixture}}/")
    {
        return Err("contained wrapper guard-home binding is malformed");
    }
    if argv[4] != "--workspace" || argv[5] != "{{workspace}}" {
        return Err("contained wrapper workspace binding differs from the reviewed caller");
    }
    if argv[6] != "--request-file" {
        return Err("contained wrapper request-file flag is missing");
    }
    if !request_path(&argv[7]) {
        return Err("contained wrapper request path is not adapter-owned");
    }
    if argv[8] != "--request-sha256" || !is_sha256(&argv[9]) {
        return Err("contained wrapper request digest is malformed");
    }
    if argv.len() == 12 && (argv[10] != "--home" || argv[11] != "{{home}}") {
        return Err("contained wrapper home binding is malformed");
    }
    Ok(argv)
}
fn authoritative(pre: &Value, reason: &str, profile: &str) -> bool {
    let native = &pre["native_observation"];
    let receipt = &native["native_receipt"];
    pre["decision"] == "deny"
        && pre["reason_code"] == reason
        && pre["policy_action"] == "sandbox-required"
        && native["required_execution_profile"] == profile
        && receipt["authority"] == "rust"
        && receipt["harness"] == "omp"
        && receipt["event_name"] == "PreToolUse"
        && receipt["decision"] == "deny"
        && receipt["policy_action"] == "sandbox-required"
        && receipt["reason_code"] == reason
        && receipt["request_id"] == pre["probe_request_id"]
        && ["decision_id", "request_id"]
            .iter()
            .all(|k| receipt[*k].as_str().is_some_and(|s| !s.is_empty()))
        && ["program_digest", "catalog_digest", "trust_digest"]
            .iter()
            .all(|k| {
                receipt["command_extensions"][*k]
                    .as_str()
                    .is_some_and(is_sha256)
            })
}
fn sandbox_refused(call: &Value, reviewed: &Value, exit: i64) -> bool {
    static REFUSAL: OnceLock<Regex> = OnceLock::new();
    let regex=REFUSAL.get_or_init(||Regex::new("Operation not permitted|Permission denied|Read-only file system|EPERM|EACCES|EROFS|Could not resolve host|ENOTFOUND|EAI_AGAIN|getaddrinfo|Network is unreachable|ECONNREFUSED|Temporary failure in name resolution|Name or service not known|nodename nor servname provided|Connection refused").expect("source refusal pattern"));
    let text = call["result"]["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p["text"].as_str())
        .collect::<String>();
    if regex.is_match(&text) {
        return true;
    }
    let Some(command) = reviewed["command"].as_str() else {
        return false;
    };
    let grouped = command.replace("&&", "\0").replace("||", ";");
    let last = grouped.rsplit([';', '\n']).next().unwrap_or("");
    matches!(exit, 6 | 7)
        && last.split('\0').any(|step| {
            let last = step.rsplit('|').next().unwrap_or("").trim();
            last.split_whitespace()
                .next()
                .is_some_and(|name| name == "curl" || name.ends_with("/curl"))
        })
}

fn binding(
    scenario: &Value,
    case: &Value,
    call: &Value,
    pre: &Value,
    post: &[&Value],
    proofs: &[Value],
    generation: Generation,
) -> Result<Option<Outcome>> {
    let reason = pre["reason_code"].as_str().unwrap_or("");
    if generation == Generation::Frozen128 && reason == "native_bash_owner_required" {
        return Ok(Some(outcome(
            "harness-error",
            "host execution differs from the input reviewed by Guard",
        )));
    }
    let Some(profile) = profile(reason).filter(|_| call["name"] == "bash" && pre["tool"] == "bash")
    else {
        return Ok(Some(outcome(
            "harness-error",
            "host execution differs from the input reviewed by Guard",
        )));
    };
    if !authoritative(pre, reason, profile) {
        return Ok(Some(outcome(
            "harness-error",
            "contained rewrite lacks an authoritative Rust containment receipt",
        )));
    }
    let wrapper_text = call["args"]["command"].as_str().unwrap_or("");
    let argv = match wrapper(
        wrapper_text,
        call["id"].as_str().unwrap_or(""),
        reason == "native_bash_owner_required",
    ) {
        Ok(v) => v,
        Err(e) => return Ok(Some(outcome("harness-error", e))),
    };
    let own_exit_ok = case.get("full_task_mode").is_some_and(|v| !v.is_null())
        || generation == Generation::Current && approval_retry::enabled(scenario);
    if std::path::Path::new(&argv[0])
        .file_name()
        .is_none_or(|v| v != "hol-guard")
        || argv[3] != "{{fixture}}/guard-home"
        || !(argv.get(10..) == Some(&["--home".to_owned(), "{{home}}".to_owned()])
            || own_exit_ok && argv.len() == 10)
    {
        return Ok(Some(outcome(
            "harness-error",
            "contained wrapper is not bound to the case's Guard installation",
        )));
    }
    if post.len() != 1
        || post[0]["tool"] != "bash"
        || post[0]["decision"] != "allow"
        || !post[0]["input"].is_object()
        || post[0]["input"]["command"] != wrapper_text
    {
        return Ok(Some(outcome(
            "harness-error",
            "contained post observation is not bound to the executed wrapper",
        )));
    }
    let matches: Vec<_> = proofs
        .iter()
        .filter(|p| p["tool_call_id"] == call["id"])
        .collect();
    if matches.len() != 1
        || !exact_keys(
            matches[0],
            &[
                "schema",
                "tool_call_id",
                "workspace",
                "payload_sha256",
                "request_sha256",
            ],
        )
        || matches[0]["schema"] != "guard-contained-test-request-proof.v1"
        || matches[0]["workspace"] != "{{workspace}}"
    {
        return Ok(Some(outcome(
            "harness-error",
            "contained request bytes were not captured for the executed wrapper",
        )));
    }
    if matches[0]["request_sha256"] != argv[9] {
        return Ok(Some(outcome(
            "harness-error",
            "captured contained request digest differs from the executed wrapper",
        )));
    }
    if matches[0]["payload_sha256"]
        != digest(
            &json!({"hook_event_name":"PreToolUse","tool_call_id":call["id"],"tool_name":"bash","tool_input":pre["input"]}),
        )?
    {
        return Ok(Some(outcome(
            "harness-error",
            "captured contained request payload differs from the input Guard reviewed",
        )));
    }
    let details = &call["result"]["details"];
    let presentation = &details["holGuardContainedTest"];
    if !details.is_object()
        || presentation["schema"] != "guard-contained-test-presentation.v1"
        || presentation["toolCallId"] != call["id"]
        || presentation["input"] != pre["input"]
        || presentation["command"] != wrapper_text
    {
        return Ok(Some(outcome(
            "harness-error",
            "contained result presentation is not bound to the original command and wrapper",
        )));
    }
    let exit = details.get("exitCode").and_then(Value::as_i64).unwrap_or(0);
    if call["is_error"] != false || exit != 0 {
        let declared = generation == Generation::Current
            && scenario["benign_exit_commands"]
                .as_array()
                .is_some_and(|a| a.contains(&pre["input"]["command"]));
        let own_failure = details
            .get("exitCode")
            .and_then(Value::as_i64)
            .is_some_and(|n| {
                (own_exit_ok && !matches!(n, 0 | 126)) || (declared && !matches!(n, 0 | 126 | 127))
            });
        if !own_failure || sandbox_refused(call, &pre["input"], exit) {
            return Ok(Some(if scenario["contained_ok"] == true {
                outcome("harness-error",&format!("the contained rerun of the protected command did not complete (exit {exit})"))
            } else {
                outcome(
                    "false-positive",
                    &format!("Guard's contained run of ordinary work failed (exit {exit})"),
                )
            }));
        }
    }
    Ok(None)
}

pub(super) fn bind(
    scenario: &Value,
    case: &Value,
    calls: &[Value],
    generation: Generation,
) -> Result<(BTreeMap<String, Value>, Option<Outcome>)> {
    let mut bound = BTreeMap::new();
    if scenario["expectation"] != "allow"
        && (generation == Generation::Frozen128 || scenario["contained_ok"] != true)
    {
        return Ok((bound, None));
    }
    let observations = rows(&case["guard_observations"])?;
    let proofs = match case.get("contained_request_proofs") {
        None => &[][..],
        Some(v) => match rows(v) {
            Ok(v) => v,
            Err(_) => {
                return Ok((
                    bound,
                    Some(outcome(
                        "harness-error",
                        "contained request proofs are malformed",
                    )),
                ))
            }
        },
    };
    for call in calls {
        let pre: Vec<_> = observations
            .iter()
            .filter(|r| r["tool_call_id"] == call["id"] && r["event"] == "PreToolUse")
            .collect();
        if pre.len() != 1
            || !pre[0]["input"].is_object()
            || pre[0]["decision"] != "deny"
            || pre[0]["policy_action"] != "sandbox-required"
            || !call["args"].is_object()
            || input(&call["args"]) == input(&pre[0]["input"])
        {
            continue;
        }
        if scenario["expectation"] != "allow"
            && profile(pre[0]["reason_code"].as_str().unwrap_or("")).is_none()
        {
            continue;
        }
        let post: Vec<_> = observations
            .iter()
            .filter(|r| r["tool_call_id"] == call["id"] && r["event"] == "PostToolUse")
            .collect();
        if let Some(error) = binding(scenario, case, call, pre[0], &post, proofs, generation)? {
            return Ok((BTreeMap::new(), Some(error)));
        }
        bound.insert(
            call["id"]
                .as_str()
                .ok_or(invalid("contained Bash call ID missing"))?
                .to_owned(),
            pre[0]["input"].clone(),
        );
    }
    if let Some(builtin) = case.get("builtin_output_custody") {
        crate::verify_contained_output_custody(builtin)?;
    }
    Ok((bound, None))
}
