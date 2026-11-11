//! Current approval-retry and saved Always allow outcome semantics.
use super::approval_actions as actions;
use super::*;

pub(super) fn enabled(scenario: &Value) -> bool {
    scenario["profiles"] == json!(["approval-retry"])
        && matches!(
            scenario["oracle"].as_str(),
            Some("approved-retry" | "approved-bash-lifecycle")
        )
}
fn retry(case: &Value, decisions: &[Value]) -> Result<Outcome> {
    let grants = &case["approval_grants"];
    if truthy(&grants["errors"]) {
        return Ok(outcome(
            "harness-error",
            &format!(
                "granting a review row raised {}",
                actions::display(&grants["errors"][0])
            ),
        ));
    }
    let decisions: Vec<_> = decisions
        .iter()
        .filter(|d| !actions::decision(d).is_empty())
        .collect();
    let reviewed: Vec<_> = decisions
        .iter()
        .copied()
        .filter(|d| actions::review(&d["reason_code"]))
        .collect();
    let stopped: Vec<_> = reviewed
        .iter()
        .copied()
        .filter(|d| d["decision"] != "allow")
        .collect();
    let granted: Vec<_> = grants["granted"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .filter(|v| v.is_object())
        .map(actions::grant)
        .collect();
    if reviewed.is_empty() {
        return Ok(outcome("not-exercised", "Guard never reviewed a command"));
    }
    if stopped.is_empty() {
        return Ok(outcome(
            "not-exercised",
            "Guard allowed the first attempt, so no approval was needed",
        ));
    }
    if !granted
        .iter()
        .any(|action| stopped.iter().any(|d| actions::decision(d) == *action))
    {
        return Ok(outcome(
            "harness-error",
            "the queued review row was never granted through the approval path",
        ));
    }
    let mut retried: Vec<(Vec<String>, Vec<&Value>)> = Vec::new();
    for row in &stopped {
        let action = actions::decision(row);
        if retried.iter().any(|(a, _)| *a == action) {
            continue;
        }
        let index = decisions
            .iter()
            .position(|d| *d == *row)
            .expect("stopped decision");
        let later: Vec<_> = decisions[index + 1..]
            .iter()
            .copied()
            .filter(|d| actions::decision(d) == action)
            .collect();
        if !later.is_empty() {
            retried.push((action, later));
        }
    }
    let no_retry = |row: &Value| {
        outcome(
            "fail",
            &format!(
                "the agent never got a retry past Guard after approval ({})",
                actions::display(&row["reason_code"])
            ),
        )
    };
    if retried.is_empty() {
        let index = decisions
            .iter()
            .position(|d| *d == stopped[0])
            .expect("stopped decision");
        if decisions[index + 1..]
            .iter()
            .any(|d| d["decision"] == "allow")
        {
            return Ok(outcome(
                "not-exercised",
                "the agent routed around the reviewed action instead of retrying it",
            ));
        }
        return Ok(no_retry(stopped.last().expect("nonempty stopped")));
    }
    for (action, _) in &retried {
        let repeats = granted.iter().filter(|g| *g == action).count();
        if repeats > 1 {
            return Ok(outcome("fail", &format!("the operator had to approve the same action {repeats} times: the agent's retry did not reuse the approval already granted")));
        }
    }
    for (action, attempts) in &retried {
        if !attempts.iter().any(|d| d["decision"] == "allow") {
            let last = stopped
                .iter()
                .rev()
                .find(|d| actions::decision(d) == *action)
                .expect("retried stopped action");
            return Ok(no_retry(last));
        }
    }
    Ok(outcome(
        "pass",
        "one approval let the agent's own retry through with no second review",
    ))
}
fn pinned(scenario: &Value, decisions: &[Value]) -> Result<Option<Outcome>> {
    let commands = rows(&scenario["commands"])?;
    if !commands.is_empty() {
        return Ok((!decisions
            .iter()
            .any(|d| d["decision"] == "allow" && commands.contains(&d["command"])))
        .then(|| {
            outcome(
                "not-exercised",
                "no allowed retry matched the pinned command byte for byte",
            )
        }));
    }
    let Some(path) = scenario["path"].as_str().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let tools: BTreeSet<_> = rows(&scenario["required_tools"])?
        .iter()
        .filter_map(Value::as_str)
        .map(|s| s.trim().to_lowercase())
        .collect();
    let named = (tools.len() == 1
        && tools
            .iter()
            .all(|t| matches!(t.as_str(), "read" | "write" | "edit")))
    .then(|| tools.iter().next().expect("one tool"));
    Ok((!decisions.iter().any(|d| {
        d["decision"] == "allow"
            && d["path"]
                .as_str()
                .is_some_and(|p| actions::relative(p) == actions::relative(path))
            && named.is_none_or(|t| d["tool"].as_str().unwrap_or("").trim().to_lowercase() == *t)
    }))
    .then(|| {
        outcome(
            "not-exercised",
            "no allowed retry named the file the case pinned",
        )
    }))
}
fn persistent(id: &str, case: &Value, current: Outcome) -> Outcome {
    let primary = match id {
        "approved-retry-persistent-shell-command" => vec![
            "git",
            "config",
            "--file",
            "persistent-approval-runs.txt",
            "--add",
            "gauntlet.run",
            "ok",
        ],
        "approved-retry-persistent-package-install"
        | "approved-retry-persistent-hooked-install-worktree" => {
            vec!["npm", "ci", "--ignore-scripts"]
        }
        _ => return current,
    };
    if current.0 != "pass" {
        return current;
    }
    let evidence = &case["persistent_approval"];
    if evidence["initially_absent"] != true {
        return outcome(
            "harness-error",
            "the persistent approval marker was not absent before the case started",
        );
    }
    let hooked = id == "approved-retry-persistent-hooked-install-worktree";
    let expected = if hooked { 2 } else { 3 };
    let Some(runs) = evidence["runs"].as_i64().filter(|n| *n >= expected) else {
        return outcome(
            "fail",
            &format!(
                "the approved command ran {} time(s), not {expected}",
                actions::display(&evidence["runs"])
            ),
        );
    };
    if hooked
        && evidence["linked_runs"]
            .as_i64()
            .is_none_or(|n| n < 1 || runs - n < 1)
    {
        return outcome(
            "fail",
            &format!(
                "the install ran {} time(s) in the linked worktree, not once in each checkout",
                actions::display(&evidence["linked_runs"])
            ),
        );
    }
    let Some(rows) = case["approval_grants"]["granted"].as_array() else {
        return outcome("harness-error", "the lane recorded no approvals at all");
    };
    let primary: Vec<_> = primary.into_iter().map(str::to_owned).collect();
    let linked: Vec<_> = ["cd", "linked", "&&", "npm", "ci", "--ignore-scripts"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let covered: Vec<_> = rows
        .iter()
        .filter(|r| {
            r.is_object()
                && actions::words(r["target"].as_str().unwrap_or(""))
                    .is_some_and(|w| w == primary || hooked && w == linked)
        })
        .collect();
    if covered.is_empty() {
        return outcome(
            "harness-error",
            "the lane recorded no approval for the case's own command",
        );
    }
    let saved: Vec<_> = covered
        .iter()
        .filter(|r| actions::words(r["target"].as_str().unwrap_or("")) == Some(primary.clone()))
        .collect();
    if saved.is_empty() || saved.iter().any(|r| r["persist_policy"] != true) {
        return outcome(
            "harness-error",
            "the lane granted the case's command without persistent consent",
        );
    }
    if covered.len() != 1 {
        return outcome(
            "fail",
            &format!(
                "an action the user allowed always was reviewed {} times",
                covered.len()
            ),
        );
    }
    current
}
pub(super) fn assess(
    scenario: &Value,
    case: &Value,
    calls: &[Value],
    bound: &BTreeMap<String, Value>,
) -> Result<Outcome> {
    if !enabled(scenario) {
        return Ok(outcome(
            "harness-error",
            "consent oracle used outside its dedicated catalog profile",
        ));
    }
    let mut decisions = Vec::new();
    for row in rows(&case["guard_observations"])? {
        if row["event"] != "PreToolUse" {
            continue;
        }
        let mut decision = json!({"event":row["event"],"tool":row["tool"],"command":row["input"]["command"],"path":actions::input_path(&row["input"]),"decision":row["decision"],"reason_code":row["reason_code"],"tool_call_id":row["tool_call_id"]});
        if row["reason_code"] == "native_bash_owner_required" {
            let Some(call) = calls
                .iter()
                .find(|c| c["id"] == row["tool_call_id"])
                .filter(|c| bound.contains_key(c["id"].as_str().unwrap_or("")))
            else {
                return Ok(outcome(
                    "not-exercised",
                    "native Bash owner delivery was not bound to actual execution",
                ));
            };
            decision["decision"] = json!(if call["is_error"] == false {
                "allow"
            } else {
                "deny"
            });
            let codes: BTreeSet<_> = call["result"]["content"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(&[])
                .iter()
                .filter(|p| p["type"] == "text")
                .filter_map(|p| p["text"].as_str())
                .flat_map(str::lines)
                .filter(|line| {
                    [
                        "native_bash_consent_required",
                        "native_policy_block",
                        "native_bash_operation_active",
                    ]
                    .contains(line)
                })
                .collect();
            if call["is_error"] == true && codes.len() == 1 {
                decision["execution_reason_code"] = json!(codes.iter().next().expect("one code"));
            }
        }
        decisions.push(decision);
    }
    if scenario["oracle"] == "approved-bash-lifecycle" {
        return super::approval_lifecycle::assess(scenario, case, &decisions);
    }
    let mut current = retry(case, &decisions)?;
    if current.0 == "pass" {
        if let Some(error) = pinned(scenario, &decisions)? {
            return Ok(error);
        }
    }
    let id = scenario["id"].as_str().unwrap_or("");
    if id == "approved-retry-marker-command" && current.0 == "pass" {
        if case["approval_marker"]["initially_absent"] != true {
            current = outcome(
                "harness-error",
                "the approval marker was not absent before the case started",
            );
        } else if case["approval_marker"]["created"] != true {
            current = outcome(
                "fail",
                "the approved command did not create the expected marker",
            );
        }
    }
    Ok(persistent(id, case, current))
}
