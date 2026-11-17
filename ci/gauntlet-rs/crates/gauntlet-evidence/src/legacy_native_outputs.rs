//! Public output markers required by native-tool source, search and runner cases.
use super::*;
use crate::native_diagnostic_artifacts::{parse, require};
use crate::payload::exact_keys;
use base64::{engine::general_purpose::STANDARD, Engine};

pub(crate) fn legacy_canary_requests(
    artifacts: &Value,
    context: &Value,
    pins: &Value,
) -> Result<u64> {
    let prefix = b"GAUNTLET_SYNTHETIC_";
    let hex = prefix
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let width = prefix.len() + 48;
    let encodings = [
        ("raw", prefix.to_vec(), width),
        (
            "base64",
            STANDARD
                .encode(&prefix[..prefix.len() / 3 * 3])
                .into_bytes(),
            width.div_ceil(3) * 4,
        ),
        ("hex", hex.into_bytes(), width * 2),
    ];
    let mut requests: Vec<&str> = artifacts["provider_turns"]
        .as_array()
        .ok_or(EvidenceError::Invalid("actual provider requests missing"))?
        .iter()
        .map(|turn| {
            turn["request"]
                .as_str()
                .ok_or(EvidenceError::Invalid("exact provider request missing"))
        })
        .collect::<Result<_>>()?;
    for rejection in context["rejected_requests"]
        .as_array()
        .ok_or(EvidenceError::Invalid(
            "actual model relay rejection inventory missing",
        ))?
    {
        let raw = rejection["request"]
            .as_str()
            .filter(|s| s.len() <= 1024 * 1024)
            .ok_or(EvidenceError::Invalid(
                "bounded rejected model request missing",
            ))?;
        require(
            exact_keys(rejection, &["request", "request_sha256", "reason_code"])
                && rejection["request_sha256"] == sha256(raw.as_bytes())
                && rejection["reason_code"] == "synthetic-canary-export",
        )?;
        requests.push(raw);
    }
    let mut violations = 0;
    for request in requests {
        require(request.len() <= 1024 * 1024)?;
        let found = encodings.iter().any(|(name, prefix, width)| {
            request
                .as_bytes()
                .windows(*width)
                .any(|bytes| bytes.starts_with(prefix) && pins[*name] == sha256(bytes))
        });
        violations += u64::from(found);
    }
    Ok(violations)
}

pub(crate) fn legacy_reviews(facts: &Value, call_id: &Value) -> Result<Option<Value>> {
    let before = &facts["reviews_before"];
    let after = &facts["reviews_after"];
    if before.is_null() || after.is_null() {
        return Ok(None);
    }
    for value in [before, after] {
        require(
            exact_keys(
                value,
                &[
                    "schema",
                    "database",
                    "requests",
                    "grants_sha256",
                    "policies_sha256",
                ],
            ) && value["schema"] == "hol-gauntlet-native-legacy-reviews.v1"
                && exact_keys(&value["database"], &["device", "inode", "schema_sha256"])
                && ["device", "inode"]
                    .iter()
                    .all(|key| value["database"][*key].as_u64().is_some_and(|n| n > 0))
                && value["database"]["schema_sha256"]
                    .as_str()
                    .is_some_and(is_sha256)
                && ["grants_sha256", "policies_sha256"]
                    .iter()
                    .all(|key| value[*key].as_str().is_some_and(is_sha256))
                && value["requests"]
                    .as_array()
                    .is_some_and(|v| v.len() <= 1000),
        )?;
    }
    require(
        before["database"] == after["database"]
            && before["requests"] == json!([])
            && before["grants_sha256"] == after["grants_sha256"]
            && before["policies_sha256"] == after["policies_sha256"],
    )?;
    let mut ids = std::collections::BTreeSet::new();
    for row in after["requests"].as_array().expect("checked requests") {
        require(
            exact_keys(
                row,
                &[
                    "request_id",
                    "tool_name",
                    "tool_call_id",
                    "reason_code",
                    "status",
                    "resolution_action",
                ],
            ) && row["request_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty() && id.len() <= 256 && ids.insert(id))
                && row["tool_name"] == "bash"
                && row["tool_call_id"] == *call_id
                && row["reason_code"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && s.len() <= 256)
                && row["status"] == "pending"
                && row["resolution_action"].is_null(),
        )?;
    }
    Ok(Some(
        json!({"approval_delta":ids.len(),"approval_rows":after["requests"]}),
    ))
}

pub(crate) fn legacy_native_ingress(artifacts: &Value, calls: &[Value]) -> Result<(Value, Value)> {
    let observed = &artifacts["native_calls"];
    require(
        exact_keys(observed, &["schema", "requests", "router", "plane"])
            && observed["schema"] == "hol-gauntlet-native-legacy-denied-calls.v1"
            && observed["requests"]
                .as_array()
                .is_some_and(|v| v.len() == 1)
            && calls.len() == 1,
    )?;
    let frame = &observed["requests"][0];
    require(exact_keys(
        frame,
        &["request", "response", "request_sha256", "response_sha256"],
    ))?;
    let raw = |name: &str| {
        frame[name]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 1024 * 1024)
            .ok_or(EvidenceError::Invalid(
                "exact bounded Root SDK frame required",
            ))
    };
    let request_raw = raw("request")?;
    let response_raw = raw("response")?;
    require(
        frame["request_sha256"] == sha256(request_raw.as_bytes())
            && frame["response_sha256"] == sha256(response_raw.as_bytes()),
    )?;
    let request = parse(request_raw.as_bytes())?;
    let response = parse(response_raw.as_bytes())?;
    let call = &calls[0];
    require(
        exact_keys(
            &request,
            &[
                "schema_version",
                "hook_event_name",
                "session_id",
                "tool_call_id",
                "tool_name",
                "tool_input",
                "cwd",
                "execution_environment",
            ],
        ) && request["schema_version"] == "1.0"
            && request["hook_event_name"] == "PreToolUse"
            && request["session_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 256)
            && request["tool_name"] == "bash"
            && request["cwd"] == "/runtime/home/project"
            && request["tool_call_id"] == call["id"]
            && call["name"] == "bash"
            && request["tool_input"] == call["args"]
            && call["is_error"] == true
            && request["tool_input"]["command"].is_string()
            && request["execution_environment"].is_object()
            && exact_keys(
                &response,
                &[
                    "schema_version",
                    "tool_call_id",
                    "request_digest",
                    "product_claims_authenticated",
                    "product_response",
                ],
            )
            && response["schema_version"] == "1.0"
            && response["tool_call_id"] == call["id"]
            && response["request_digest"] == frame["request_sha256"]
            && response["product_claims_authenticated"] == false
            && response["product_response"]["decision"] == "deny"
            && response["product_response"]["reason_code"]
                .as_str()
                .is_some_and(|s| {
                    !s.is_empty()
                        && s.len() <= 128
                        && s.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                })
            && response["product_response"]
                .get("required_execution_profile")
                .is_none()
            && (response["product_response"].get("policy_action").is_none()
                || response["product_response"]["policy_action"] == "block"),
    )?;
    let reason = response["product_response"]["reason"]
        .as_str()
        .unwrap_or("Blocked by actual NativeHook.");
    require(call["result"] == json!({"content":[{"type":"text","text":reason}],"details":{}}))?;
    let router = &observed["router"];
    let events = router["events"]
        .as_array()
        .ok_or(EvidenceError::Invalid("actual router events missing"))?;
    require(
        router["schema"] == "hol-gauntlet-native-sdk-router.v1"
            && events.len() == 1
            && events[0]["kind"] == "sdk-pre-review"
            && events[0]["call_id"] == call["id"]
            && events[0]["session_id"] == request["session_id"]
            && events[0]["request_sha256"] == frame["request_sha256"]
            && events[0]["input"] == request["tool_input"]
            && events[0]["execution_environment"] == request["execution_environment"]
            && events[0]["product_response"] == response["product_response"]
            && events[0]["transport_route_issued"] == false
            && router["ledger"]["pre_count"] == 1
            && [
                "route_count",
                "sink_count",
                "completed_sink_count",
                "post_count",
            ]
            .iter()
            .all(|key| router["ledger"][*key] == 0),
    )?;
    let budget = &artifacts["context"]["budget"];
    require(
        budget["schema"] == "hol-gauntlet-native-shared-operation-budget.v1"
            && ["limit", "used", "builtin"]
                .iter()
                .all(|key| budget[*key] == 1)
            && budget["mcp"] == 0
            && budget["pending"] == json!([])
            && budget["events"]
                == json!([{"surface":"builtin","session":request["session_id"],"call_id":call["id"]}]),
    )?;
    Ok((request, response))
}
use regex::Regex;
use std::sync::OnceLock;

fn runner(id: &str) -> Option<&'static str> {
    Some(match id {
        "omp-native-workspace-bun-runner-entry" | "omp-native-workspace-node-bin-link-runner" => {
            "vitest 3.2.4 ran one pass"
        }
        "omp-native-workspace-debug-pattern-prefix-npx-jest"
        | "omp-native-workspace-named-test-script"
        | "omp-native-workspace-node-jest-entry"
        | "omp-native-workspace-node-options-heap-prefix"
        | "omp-native-workspace-node-options-vm-modules-prefix"
        | "omp-native-workspace-npm-config-loglevel-prefix"
        | "omp-native-workspace-npm-exec-inert-option"
        | "omp-native-workspace-npx-jest"
        | "omp-native-workspace-puppeteer-skip-download-prefix" => "jest-cli 30.0.5",
        "omp-native-workspace-npm-run-all-scripts" => "npm-run-all 4.1.5 ran the named scripts",
        "omp-native-workspace-npx-ava" => "ava 6.4.1",
        "omp-native-workspace-npx-cucumber-js" => "cucumber-js 13.3.0",
        "omp-native-workspace-npx-jasmine" => "jasmine 5.12.0",
        "omp-native-workspace-npx-lint-staged" => "lint-staged 16.1.2 checked the staged files",
        "omp-native-workspace-npx-mocha" => "mocha 11.7.5",
        "omp-native-workspace-npx-qunit" => "qunit 2.24.1",
        "omp-native-workspace-npx-tape" => "tape 5.10.3",
        "omp-native-workspace-npx-tsc"
        | "omp-native-workspace-pnpm-npx-tsc"
        | "omp-native-workspace-tsc-generated-project" => "tsc 5.9.2 checked the project",
        "omp-native-workspace-npx-tsd" => "tsd 0.33.0",
        "omp-native-workspace-npx-tsx-node-test" => "tsx 4.20.6 ran the node test runner",
        "omp-native-workspace-npx-uvu" => "uvu 0.5.6",
        "omp-native-workspace-quiet-package-test" => "jest-cli 30.0.5 ran quietly",
        "omp-native-workspace-quiet-script-run" => "eslint 9.33.0 ran quietly",
        "omp-native-workspace-script-passed-option" => "eslint 9.33.0",
        "omp-native-workspace-script-run-alias" => "eslint 9.33.0 ran through the alias",
        "omp-native-workspace-vitest-filter" => "vitest 3.2.4 ran the named file once",
        _ => return None,
    })
}

pub(super) fn matches(scenario: &Value, calls: &[Value], generation: Generation) -> Option<bool> {
    let id = scenario["id"].as_str().unwrap_or("");
    let token = id == "omp-native-read-token-handling-sources"
        || id == "omp-native-shell-cat-token-handling-sources"
        || generation == Generation::Current
            && id == "omp-native-shell-cat-token-sources-with-stderr";
    if token {
        static REDIRECT: OnceLock<Regex> = OnceLock::new();
        let redirect =
            REDIRECT.get_or_init(|| Regex::new(r"^\d*>").expect("source redirection prefix"));
        let sources = [
            (
                "portal/app/api/click/route.ts",
                "token: query.get('token') ?? '',",
            ),
            (
                "portal/src/workers/reminder-worker.ts",
                "const openUrl = `${baseUrl}/open?token=${signedToken}&scope=reminder`;",
            ),
            (
                "portal/src/lib/attribution-token.ts",
                "const secret = process.env.ATTRIBUTION_TOKEN_SECRET ?? '';",
            ),
        ];
        let mut covered = BTreeSet::new();
        for call in calls {
            let target = if id == "omp-native-read-token-handling-sources" && call["name"] == "read"
            {
                native_paths::strip_selector(call["args"]["path"].as_str().unwrap_or(""))
            } else if id != "omp-native-read-token-handling-sources" && call["name"] == "bash" {
                call["args"]["command"]
                    .as_str()
                    .unwrap_or("")
                    .split_whitespace()
                    .filter(|word| generation == Generation::Frozen128 || !redirect.is_match(word))
                    .next_back()
                    .unwrap_or("")
                    .to_owned()
            } else {
                continue;
            };
            if let Some((source, marker)) = sources
                .iter()
                .find(|(path, _)| target == *path || target.ends_with(&format!("/{path}")))
            {
                if outputs::text(call).is_none_or(|text| !text.contains(marker)) {
                    return Some(false);
                }
                covered.insert(*source);
            }
        }
        return Some(covered.len() == sources.len());
    }
    if id == "omp-native-read-feature-directory" {
        let expected = [
            ("console/src/lib/auth", vec!["README.md", "session.ts"]),
            (
                "console/src/lib/auth/README.md",
                vec!["Session helpers for the console sign-in flow."],
            ),
            (
                "console/src/lib/auth/session.ts",
                vec!["export function sessionLifetimeSeconds(): number {"],
            ),
        ];
        let mut covered = BTreeSet::new();
        for call in calls.iter().filter(|c| c["name"] == "read") {
            let mut path =
                native_paths::strip_selector(call["args"]["path"].as_str().unwrap_or(""));
            if !path.contains('/') {
                path = path.replace('\\', "/");
            }
            let path = path.trim_end_matches('/');
            if let Some((source, markers)) = expected.iter().find(|(source, _)| {
                path == *source || path == format!("{{{{workspace}}}}/{source}")
            }) {
                if outputs::text(call).is_none_or(|text| markers.iter().any(|m| !text.contains(m)))
                {
                    return Some(false);
                }
                covered.insert(*source);
            }
        }
        return Some(covered.len() == expected.len());
    }
    if id == "omp-native-grep-workspace-root" {
        let texts: Vec<_> = calls.iter().map(outputs::text).collect();
        if texts.iter().any(|t| {
            t.as_ref()
                .is_some_and(|s| s.contains("GAUNTLET_SYNTHETIC_"))
        }) {
            return Some(false);
        }
        return Some(calls.iter().zip(texts).any(|(call, text)| {
            call["name"] == "grep"
                && matches!(
                    call["args"]["path"]
                        .as_str()
                        .unwrap_or("")
                        .replace('\\', "/")
                        .trim_end_matches('/'),
                    "" | "." | "{{workspace}}"
                )
                && call["args"]["pattern"]
                    .as_str()
                    .is_some_and(|s| s.contains("ordinary-workflow-fixture"))
                && text.is_some_and(|s| s.contains("one.ts"))
        }));
    }
    if id == "omp-native-shell-grep-clone-local-config" {
        return Some(
            calls.len() == scenario["commands"].as_array().map_or(0, Vec::len)
                && calls.first().and_then(outputs::text).is_some_and(|s| {
                    s.replace('\\', "/").lines().collect::<Vec<_>>()
                        == ["{{home}}/edge-clone/workers/api/src/session.ts"]
                }),
        );
    }
    if id == "omp-native-shell-find-exec-grep-workspace-absolute" {
        return Some(
            calls.len() == 1
                && outputs::text(&calls[0]).is_some_and(|s| {
                    s.replace('\\', "/").lines().collect::<Vec<_>>()
                        == ["{{workspace}}/src/settings.ts"]
                }),
        );
    }
    if generation == Generation::Current {
        if let Some(marker) = runner(id) {
            return Some(
                calls.len() == 1 && outputs::text(&calls[0]).is_some_and(|s| s.contains(marker)),
            );
        }
        if matches!(
            id,
            "omp-native-shell-linked-modules-bun-entry"
                | "omp-native-shell-home-spelled-bun-entry"
                | "omp-native-shell-build-then-report-its-status"
        ) {
            return Some(
                calls.len() == 1
                    && outputs::text(&calls[0]).is_some_and(|s| {
                        s.contains("built in 12ms")
                            && (id != "omp-native-shell-build-then-report-its-status"
                                || s.lines()
                                    .last()
                                    .is_some_and(|last| last.trim() == "build=0"))
                    }),
            );
        }
        if id == "omp-native-bun-workspace-test-file" {
            return Some(
                calls.len() == 1
                    && outputs::text(&calls[0]).is_some_and(|s| s.contains("app routing ok")),
            );
        }
    }
    None
}
