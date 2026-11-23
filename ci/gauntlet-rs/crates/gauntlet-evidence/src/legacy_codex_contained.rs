//! Exact current Codex containment binding over caller-audited observations.
//! A routed deny is exempt only after its proof, sink and actual run all join.
use super::*;
use regex::Regex;
use std::sync::OnceLock;

const BOOTSTRAP: &str = "import sys;sys.path.insert(0,sys.argv.pop(1));from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))";

#[derive(Default)]
pub(super) struct Routes {
    pub bound: BTreeSet<String>,
    pub error: Option<Outcome>,
}
fn failed(status: &str, reason: &str) -> Routes {
    Routes {
        error: Some(outcome(status, reason)),
        ..Routes::default()
    }
}
fn event(row: &Value) -> &Value {
    if truthy(&row["receipt"]["event_name"]) {
        &row["receipt"]["event_name"]
    } else {
        &row["payload"]["hook_event_name"]
    }
}
fn call_id(row: &Value) -> Option<&str> {
    let payload = &row["payload"];
    let value = if truthy(&payload["tool_use_id"]) {
        &payload["tool_use_id"]
    } else {
        &payload["tool_call_id"]
    };
    value.as_str().filter(|v| !v.is_empty())
}
fn containment_deny(row: &Value) -> bool {
    let response = &row["response"];
    let receipt = &row["receipt"];
    let reason = response["reason_code"].as_str().unwrap_or("");
    event(row) == "PreToolUse"
        && row["route_harness"] == "codex"
        && reason != "native_bash_owner_required"
        && contained::profile(reason)
            .is_some_and(|profile| response["required_execution_profile"] == profile)
        && response["policy_action"] == "sandbox-required"
        && response["decision"] == "deny"
        && receipt["harness"] == "codex"
        && receipt["decision"] == "deny"
        && receipt["policy_action"] == "sandbox-required"
        && receipt["reason_code"] == reason
        && receipt["observe_mode"] == false
        && receipt["decision_id"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
}
pub(super) fn is_routed_deny(row: &Value, bound: &BTreeSet<String>) -> bool {
    containment_deny(row) && call_id(row).is_some_and(|id| bound.contains(id))
}

pub(super) fn sink_argv(command: &Value) -> std::result::Result<Vec<String>, &'static str> {
    let command = command
        .as_str()
        .ok_or("contained wrapper command is missing")?;
    let argv = approval_actions::words(command)
        .ok_or("contained wrapper command is not valid shell argv")?;
    let canonical = argv
        .iter()
        .enumerate()
        .map(|(index, value)| {
            if index == 0 || matches!(value.as_str(), "{{workspace}}" | "{{home}}") {
                value.clone()
            } else {
                format!("'{value}'")
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if argv.is_empty() || command != canonical {
        return Err("contained wrapper command is not canonical");
    }
    static PYTHON: OnceLock<Regex> = OnceLock::new();
    static SITE: OnceLock<Regex> = OnceLock::new();
    let python = PYTHON.get_or_init(|| {
        Regex::new(r#"(?i)\A[A-Za-z]:/(?:[^\\/:*?"<>|' ]+/)*python\.exe\z"#)
            .expect("source Windows Python path")
    });
    let site = SITE.get_or_init(|| {
        Regex::new(r#"(?i)\A[A-Za-z]:/(?:[^\\/:*?"<>|']+/)*Lib/site-packages\z"#)
            .expect("source Windows package path")
    });
    if argv.len() != 19
        || !python.is_match(&argv[0])
        || argv[1..4] != ["-I", "-c", BOOTSTRAP]
        || !site.is_match(&argv[4])
        || argv[5..9] != ["guard", "execute-contained-test", "--harness", "codex"]
    {
        return Err("contained wrapper is not the Windows Guard sink");
    }
    let mut environment = argv[0].rsplit_once('/').expect("validated Python path").0;
    if environment
        .rsplit('/')
        .next()
        .is_some_and(|v| v.eq_ignore_ascii_case("scripts"))
    {
        environment = environment
            .rsplit_once('/')
            .expect("drive-rooted environment")
            .0;
    }
    let expected_site = format!("{environment}/Lib/site-packages");
    // Non-ASCII case changes need their own captured interpreter profile;
    // byte-identical non-ASCII path segments require no case-folding guess.
    if !argv[4].eq_ignore_ascii_case(&expected_site) {
        return Err("contained wrapper is not the Windows Guard sink");
    }
    if argv[9..11] != ["--guard-home", "{{fixture}}\\guard-home"] {
        return Err("contained wrapper is not bound to the case's Guard installation");
    }
    if argv[11..13] != ["--workspace", "{{workspace}}"] || argv[17..19] != ["--home", "{{home}}"] {
        return Err("contained wrapper workspace binding differs from the reviewed caller");
    }
    let request = &argv[14];
    let path: Vec<_> = request
        .split(['\\', '/'])
        .filter(|v| !v.is_empty() && *v != ".")
        .collect();
    if argv[13] != "--request-file"
        || request
            .as_bytes()
            .first()
            .is_none_or(|v| !v.is_ascii_alphabetic())
        || request.as_bytes().get(1..3) != Some(b":\\")
        || path.last() != Some(&"request.json")
        || path.len() < 2
        || !path[path.len() - 2].starts_with("hol-guard-contained-test-")
    {
        return Err("contained wrapper request path is not adapter-owned");
    }
    if argv[15] != "--request-sha256" || !is_sha256(&argv[16]) {
        return Err("contained wrapper request digest is malformed");
    }
    Ok(argv)
}

fn shown_wrapper(wrapper: &str) -> Result<Regex> {
    let mut remaining = wrapper;
    let mut pattern = String::from(r"\A");
    while let Some((at, placeholder)) = ["{{workspace}}", "{{home}}", "{{fixture}}"]
        .iter()
        .filter_map(|key| remaining.find(key).map(|at| (at, *key)))
        .min_by_key(|row| row.0)
    {
        let literal = &remaining[..at];
        pattern.push_str(&regex::escape(literal));
        pattern.push_str(if literal.ends_with('\'') {
            "[^'\n]+"
        } else {
            "'[^'\n]+'"
        });
        remaining = &remaining[at + placeholder.len()..];
    }
    pattern.push_str(&regex::escape(remaining));
    pattern.push_str(r"\z");
    Regex::new(&pattern).map_err(|_| invalid("bounded Codex shown-wrapper pattern required"))
}

pub(super) fn routed_calls(expectation: &Value, case: &Value) -> Result<Routes> {
    if expectation != "allow" || case["harness"] != "codex" {
        return Ok(Routes::default());
    }
    let proofs = match case.get("contained_request_proofs") {
        None => &[][..],
        Some(value) => match value.as_array() {
            Some(rows) => rows.as_slice(),
            None => {
                return Ok(failed(
                    "harness-error",
                    "contained request proofs are malformed",
                ))
            }
        },
    };
    let observations = rows(&case["guard_rows"])?;
    let calls = rows(&case["transcript"]["calls"])?;
    let mut bound = BTreeSet::new();
    for row in observations {
        let Some(id) = call_id(row).filter(|_| containment_deny(row)) else {
            continue;
        };
        let post: Vec<_> = observations
            .iter()
            .filter(|r| event(r) == "PostToolUse" && call_id(r) == Some(id))
            .collect();
        let attempted: Vec<_> = post
            .iter()
            .filter_map(|r| r["payload"]["tool_input"]["command"].as_str())
            .filter(|command| command.contains("execute-contained-test"))
            .collect();
        let Some(wrapper) = attempted.first() else {
            continue;
        };
        if post.len() != 1 {
            return Ok(failed(
                "harness-error",
                "contained route has more than one post observation",
            ));
        }
        let reviewed = &row["payload"]["tool_input"];
        if !reviewed.is_object() || reviewed["command"] == *wrapper {
            return Ok(failed(
                "harness-error",
                "host execution differs from the input reviewed by Guard",
            ));
        }
        let response = &post[0]["response"];
        let permission = &response["hookSpecificOutput"]["permissionDecision"];
        if !matches!(response["policy_action"].as_str(), Some("allow" | "warn"))
            || !permission.is_null() && permission != "allow"
        {
            return Ok(failed(
                "harness-error",
                "contained post observation is not bound to the executed wrapper",
            ));
        }
        let argv = match sink_argv(&json!(wrapper)) {
            Ok(v) => v,
            Err(error) => return Ok(failed("harness-error", error)),
        };
        let matches: Vec<_> = proofs
            .iter()
            .filter(|p| p.is_object() && p["tool_call_id"] == id)
            .collect();
        if matches.len() != 1 || matches[0]["request_sha256"] != argv[16] {
            return Ok(failed(
                "harness-error",
                "contained request digest differs from the input Guard reviewed",
            ));
        }
        let shown = shown_wrapper(wrapper)?;
        let ran: Vec<_> = calls
            .iter()
            .filter(|call| {
                call.is_object()
                    && call["args"].is_object()
                    && call["args"]["command"].as_str().is_some_and(|command| {
                        shown.is_match(
                            &approval_actions::shell_script(command).replace("\\\\", "\\"),
                        )
                    })
            })
            .collect();
        if ran.len() != 1 {
            return Ok(failed(
                "harness-error",
                "the transcript does not show one run of the contained wrapper",
            ));
        }
        if ran[0]["is_error"] != false {
            return Ok(failed(
                "false-positive",
                "Guard's contained run of ordinary work failed",
            ));
        }
        bound.insert(id.to_owned());
    }
    Ok(Routes { bound, error: None })
}
