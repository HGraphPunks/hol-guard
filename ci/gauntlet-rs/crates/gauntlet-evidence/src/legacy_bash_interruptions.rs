//! Count actual review decisions, rendered fields and approval rows.
use super::*;

fn present(value: &Value) -> bool {
    !value.is_null() && !value.as_str().is_some_and(|s| s.trim().is_empty())
}
fn selected<'a>(a: &'a Value, b: &'a Value) -> &'a Value {
    if truthy(a) {
        a
    } else {
        b
    }
}
fn text(value: &Value) -> String {
    if value.is_null() {
        String::new()
    } else if let Some(s) = value.as_str() {
        s.to_owned()
    } else {
        value.to_string()
    }
}
fn base(harness: &Value, tool: &Value, event: &Value, reason: &Value) -> Value {
    json!({"harness":harness,"tool":tool,"event":event,"reason_code":reason})
}
fn event(kind: &str, base: &Value) -> Value {
    let mut event = base.clone();
    event["kind"] = json!(kind);
    event
}
fn unproven(base: &Value, why: &str) -> Value {
    let mut event = event("unproven", base);
    event["why"] = json!(why);
    event
}

fn rendered(response: &Value, flat: &Value) -> Vec<String> {
    let nested = &response["hookSpecificOutput"];
    let carries = |key: &str| {
        [response, nested]
            .iter()
            .any(|v| v[key].as_str().is_some_and(|s| !s.trim().is_empty()))
    };
    let mut fields = Vec::new();
    for key in [
        "systemMessage",
        "message",
        "stopReason",
        "additionalContext",
        "permissionDecisionReason",
    ] {
        if carries(key) {
            fields.push(key.to_owned());
        }
    }
    let loud = matches!(flat["notice"].as_str(), Some("warning" | "excerpt"));
    if loud {
        fields.push("notice".into());
    }
    if carries("reason") && (loud || flat["policy_action"] == "warn") {
        fields.push("reason".into());
    }
    fields.sort();
    fields
}

pub(super) fn response_fields(response: &Value) -> Vec<String> {
    let mut flat = response.clone();
    if let Some(nested) = response["hookSpecificOutput"].as_object() {
        for (key, value) in nested {
            if present(value) || flat.get(key).is_none() {
                flat[key] = value.clone();
            }
        }
    }
    rendered(response, &flat)
}

pub(super) fn observed(row: &Value) -> Result<Vec<Value>> {
    let receipt = &row["receipt"];
    let payload = &row["payload"];
    let harness = selected(
        &row["route_harness"],
        selected(
            &receipt["harness"],
            selected(&row["harness"], &json!("omp")),
        ),
    )
    .clone();
    if truthy(&row["observer_error"]) || truthy(&row["transport_error"]) {
        return Ok(vec![unproven(
            &base(&harness, &Value::Null, &row["event"], &Value::Null),
            "observer or transport error",
        )]);
    }
    let mut uncertain: Option<String> = None;
    let (decision, action, reason, fields, tool, event_name) = if let Some(response) =
        row.get("response").filter(|v| v.is_object())
    {
        let mut flat = response.clone();
        if let Some(nested) = response["hookSpecificOutput"].as_object() {
            for (key, value) in nested {
                if present(value) || flat.get(key).is_none() {
                    flat[key] = value.clone();
                }
            }
        }
        let mut permission = selected(
            &flat["permissionDecision"],
            selected(&flat["permission"], &flat["decision"]),
        );
        if flat["decision"].is_object() {
            permission = selected(
                &flat["permissionDecision"],
                selected(&flat["permission"], &flat["decision"]["behavior"]),
            );
        }
        let permission = text(if truthy(permission) {
            permission
        } else {
            &Value::Null
        })
        .trim()
        .to_lowercase();
        let decision = if flat["continue"] == false
            || flat["decision"] == "block"
            || matches!(permission.as_str(), "deny" | "block")
        {
            "deny".to_owned()
        } else if permission.is_empty()
            || matches!(
                permission.as_str(),
                "allow" | "allowed" | "approve" | "approved"
            )
        {
            "allow".to_owned()
        } else {
            permission
        };
        (
            decision,
            selected(&response["policy_action"], &receipt["policy_action"]).clone(),
            selected(&response["reason_code"], &receipt["reason_code"]).clone(),
            rendered(response, &flat),
            payload["tool_name"].clone(),
            selected(&receipt["event_name"], &payload["hook_event_name"]).clone(),
        )
    } else {
        if row
            .get("http_status")
            .is_some_and(|v| !v.is_null() && v != 200)
        {
            uncertain = Some(format!("non-200 hook response ({})", row["http_status"]));
        } else if row["decision"].as_str().is_none_or(str::is_empty) {
            uncertain = Some("hook answer carries no decision".into());
        }
        let mut decision = if truthy(&row["decision"]) {
            text(&row["decision"])
        } else {
            "allow".to_owned()
        }
        .trim()
        .to_lowercase();
        if matches!(
            decision.as_str(),
            "allow" | "allowed" | "approve" | "approved"
        ) {
            decision = "allow".into();
        }
        let fields = if let Some(fields) = row["rendered_fields"].as_array() {
            let mut fields = fields
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or(invalid("invalid rendered-field observation"))
                })
                .collect::<Result<Vec<_>>>()?;
            fields.sort();
            fields
        } else {
            uncertain = uncertain.or(Some("observer row carries no rendered-text proof".into()));
            Vec::new()
        };
        (
            decision,
            row["policy_action"].clone(),
            row["reason_code"].clone(),
            fields,
            row["tool"].clone(),
            row["event"].clone(),
        )
    };
    let base = base(&harness, &tool, &event_name, &reason);
    let mut found = Vec::new();
    if let Some(why) = uncertain.or_else(|| {
        event_name
            .as_str()
            .filter(|s| !s.is_empty())
            .is_none()
            .then(|| "hook event is not resolvable".into())
    }) {
        found.push(unproven(&base, &why));
    }
    if decision != "allow"
        || matches!(
            action.as_str(),
            Some("review" | "require-reapproval" | "sandbox-required" | "block")
        )
    {
        let mut row = event("decision", &base);
        row["decision"] = json!(if decision != "allow" {
            decision
        } else {
            text(&action)
        });
        found.push(row);
    }
    if !fields.is_empty() {
        let mut row = event("rendered", &base);
        row["fields"] = json!(fields);
        found.push(row);
    }
    Ok(found)
}

pub(super) fn assess(
    scenario: &Value,
    case: &Value,
    bound: &BTreeMap<String, Value>,
) -> Result<Value> {
    assess_excused(scenario, case, bound, &BTreeSet::new())
}
pub(super) fn assess_excused(
    scenario: &Value,
    case: &Value,
    bound: &BTreeMap<String, Value>,
    excused: &BTreeSet<String>,
) -> Result<Value> {
    assess_for_harness(scenario, case, bound, excused, &json!("omp"))
}
pub(super) fn assess_for_harness(
    scenario: &Value,
    case: &Value,
    bound: &BTreeMap<String, Value>,
    excused: &BTreeSet<String>,
    harness: &Value,
) -> Result<Value> {
    assess_for_harness_routed(scenario, case, bound, excused, harness, &BTreeSet::new())
}
pub(super) fn assess_for_harness_routed(
    scenario: &Value,
    case: &Value,
    bound: &BTreeMap<String, Value>,
    excused: &BTreeSet<String>,
    harness: &Value,
    routed: &BTreeSet<String>,
) -> Result<Value> {
    let mut events = Vec::new();
    let mut decisions = 0;
    let mut quiet = 0;
    for row in rows(&case["guard_observations"])? {
        if row["decision"] == "deny"
            && row["tool_call_id"]
                .as_str()
                .is_some_and(|id| excused.contains(id))
        {
            continue;
        }
        decisions += 1;
        let mut found = if row.is_object() {
            observed(row)?
        } else {
            vec![unproven(
                &base(&Value::Null, &Value::Null, &Value::Null, &Value::Null),
                "malformed row",
            )]
        };
        if contained::is_deny(row, bound) {
            found.retain(|e| e["kind"] != "decision");
        } else if codex_contained::is_routed_deny(row, routed) {
            found.retain(|e| e["kind"] != "decision" && e["kind"] != "rendered");
        }
        quiet += usize::from(found.is_empty());
        events.extend(found);
    }
    let approvals: Vec<_> = rows(&case["approval_rows"])?
        .iter()
        .filter(|r| r.is_object())
        .collect();
    let count = approvals.len().max(
        case["approval_delta"]
            .as_i64()
            .filter(|n| *n > 0)
            .unwrap_or(0) as usize,
    );
    if count > 50_000 {
        return Err(invalid("approval interruption budget exceeded"));
    }
    for index in 0..count {
        let approval = approvals.get(index).copied().unwrap_or(&Value::Null);
        events.push(event(
            "approval",
            &base(
                harness,
                &approval["tool_name"],
                &Value::Null,
                &approval["reason_code"],
            ),
        ));
    }
    Ok(
        json!({"benign":scenario["expectation"]=="allow" && !matches!(scenario["oracle"].as_str(),Some("watch-command"|"mixed-read-batch")),"decisions":decisions,"quiet_decisions":quiet,
        "approval_rows":count,"events":events}),
    )
}

pub(super) fn describe(event: &Value) -> String {
    let tool = event["tool"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("a tool call");
    let code = event["reason_code"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("no reason code");
    match event["kind"].as_str() {
        Some("unproven") => format!(
            "Guard evidence cannot prove {tool} was quiet ({})",
            event["why"].as_str().unwrap_or("")
        ),
        Some("rendered") => format!(
            "Guard rendered warning text ({}) on {tool} ({code})",
            event["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Some("approval") => format!("ordinary work created an approval row for {tool} ({code})"),
        _ => format!("Guard stopped or reviewed {tool} ({code})"),
    }
}

pub(super) fn watch(
    case: &Value,
    calls: &[Value],
    by_id: &BTreeMap<String, Vec<&Value>>,
) -> Option<&'static str> {
    let before = &case["watch_binding_before"];
    let after = &case["watch_binding_after"];
    for binding in [before, after] {
        if !binding.is_object()
            || binding["mode"] != "observe"
            || binding["generation"].as_u64().is_none_or(|n| n == 0)
            || ["policy_digest", "runtime_identity"]
                .iter()
                .any(|k| !binding[*k].as_str().is_some_and(is_sha256))
        {
            return Some("Watch fixture lacks an authenticated resident policy binding");
        }
    }
    if ["mode", "generation", "policy_digest", "runtime_identity"]
        .iter()
        .any(|k| before[*k] != after[*k])
    {
        return Some("Watch resident policy binding changed during the command");
    }
    if calls.len() != 1 {
        return Some("Watch requires one actual harmless command");
    }
    if !calls[0]["result"]["content"]
        .as_array()
        .is_some_and(|rows| {
            rows.iter().any(|p| {
                p["type"] == "text"
                    && p["text"]
                        .as_str()
                        .is_some_and(|s| s.contains("ordinary-watch-fixture"))
            })
        })
    {
        return Some("Watch command result lacks the expected fixture output");
    }
    let pre: Vec<_> = by_id
        .get(calls[0]["id"].as_str().unwrap_or(""))
        .into_iter()
        .flatten()
        .filter(|r| r["event"] == "PreToolUse")
        .collect();
    let observed = pre
        .first()
        .map(|p| &p["native_observation"])
        .unwrap_or(&Value::Null);
    let receipt = &observed["native_receipt"];
    if pre.len() != 1
        || !observed.is_object()
        || !receipt.is_object()
        || !native_controls::correlated(pre[0])
        || receipt["schema"] != "guard-native-hook-decision-receipt.v1"
        || receipt["authority"] != "rust"
        || receipt["version"].as_u64() != Some(1)
        || receipt["harness"] != "omp"
        || receipt["event_name"] != "PreToolUse"
        || receipt["request_id"] != observed["request_id"]
        || !receipt["request_digest"].as_str().is_some_and(is_sha256)
        || receipt["policy_generation"].as_u64() != before["generation"].as_u64()
        || receipt["policy_digest"] != before["policy_digest"]
        || receipt["runtime_identity"] != before["runtime_identity"]
        || receipt["observe_mode"] != false
        || !receipt["decision_id"].as_str().is_some_and(is_sha256)
        || receipt["decision"] != "deny"
        || !matches!(
            receipt["policy_action"].as_str(),
            Some("review" | "require-reapproval" | "sandbox-required" | "block")
        )
        || receipt["reason_code"] != pre[0]["reason_code"]
        || pre[0]["decision"] != "allow"
        || pre[0]["policy_action"] != "warn"
    {
        return Some(
            "Watch lacks a correlated native would-have-stopped receipt and nonblocking response",
        );
    }
    None
}
