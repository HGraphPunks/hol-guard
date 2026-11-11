//! Normal OMP wire normalization. Product responses remain product evidence;
//! an allowed prompt or a contained-route request is no benchmark verdict.
use crate::{EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};

const JSON: EvidenceError = EvidenceError::Invalid("invalid bounded NativeHook JSON");
const PROMPT: EvidenceError =
    EvidenceError::Invalid("normal OMP prompt protocol-2 response malformed");
const DECISION: EvidenceError =
    EvidenceError::Invalid("actual installed OMP hook returned an invalid decision/protocol");
const MEDIATION: EvidenceError =
    EvidenceError::Invalid("normal OMP structured mediation response malformed");

/// A normal Native denial may request its own contained sink. This is a route
/// contract, never an approval, policy decision or qualification assertion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NativeContainmentRoute {
    #[default]
    WorkspaceV1,
    PythonReadonlyV1,
}
impl NativeContainmentRoute {
    pub fn profile(self) -> &'static str {
        match self {
            Self::WorkspaceV1 => "workspace-contained-v1",
            Self::PythonReadonlyV1 => "python-eval-readonly-v1",
        }
    }
    pub fn reason(self) -> &'static str {
        match self {
            Self::WorkspaceV1 => "native_workspace_containment_required",
            Self::PythonReadonlyV1 => "native_python_eval_readonly_containment_required",
        }
    }
    pub fn from_response(value: &Value) -> Option<Self> {
        if value["decision"] != "deny"
            || value["policy_action"] != "sandbox-required"
            || !matches!(value.get("observe_mode"), None | Some(Value::Bool(false)))
        {
            return None;
        }
        [Self::WorkspaceV1, Self::PythonReadonlyV1]
            .into_iter()
            .find(|route| {
                value["reason_code"] == route.reason()
                    && value["required_execution_profile"] == route.profile()
            })
    }
}

/// Match the frozen Python response reader, including a nonzero valid denial.
/// The transport must separately bound its input, event and kernel exit status.
/// The original bytes must remain retained alongside the normalized value.
pub fn normalize_native_hook_response(
    raw: &[u8],
    returncode: i64,
    event: Option<&str>,
) -> Result<Value> {
    let bytes = canonicalize(raw).map_err(|_| JSON)?;
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| JSON)?;
    if value.is_object() && value.get("decision").is_none() && event == Some("UserPromptSubmit") {
        let object = value.as_object().ok_or(PROMPT)?;
        if returncode != 0
            || object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "policy_action" | "reason_code" | "hookSpecificOutput" | "risk_signals"
                )
            })
            || !matches!(value["policy_action"].as_str(), Some("allow" | "warn"))
            || value["reason_code"].as_str().is_none_or(str::is_empty)
            || value["hookSpecificOutput"] != json!({"hookEventName":"UserPromptSubmit"})
            || object.get("risk_signals").is_some_and(|v| {
                v.as_array()
                    .is_none_or(|items| items.iter().any(|item| !item.is_string()))
            })
        {
            return Err(PROMPT);
        }
        value["decision"] = json!("allow");
        return Ok(value);
    }
    let object = value.as_object().ok_or(DECISION)?;
    if !matches!(value["decision"].as_str(), Some("allow" | "deny" | "block"))
        || object
            .get("reason")
            .is_some_and(|v| !v.is_null() && !v.is_string())
        || (value["decision"] == "allow" && returncode != 0)
    {
        return Err(DECISION);
    }
    if let Some(mediation) = object.get("structured_content_mediation") {
        verify_mediation(mediation)?;
    }
    Ok(value)
}

fn verify_mediation(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or(MEDIATION)?;
    let forward = value["action"] == "forward";
    let reason = value["reason_code"].as_str().unwrap_or("");
    let valid_id = |v: &Value| {
        v.as_str().is_some_and(|s| {
            (1..=256).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
        })
    };
    if value["schema"] != "guard-structured-content-mediation.v1"
        || !matches!(value["action"].as_str(), Some("forward" | "withhold"))
        || !reason.strip_prefix("structured_").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
        || object
            .get("native_decision_id")
            .is_some_and(|v| !valid_id(v))
        || (forward
            && (!valid_id(&value["native_decision_id"])
                || !value["content_sha256"].as_str().is_some_and(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })))
        || object.keys().any(|key| {
            !(matches!(
                key.as_str(),
                "schema" | "action" | "reason_code" | "native_decision_id"
            ) || (forward && key == "content_sha256"))
        })
    {
        return Err(MEDIATION);
    }
    Ok(())
}

#[cfg(test)]
mod route_tests {
    use super::*;
    #[test]
    fn only_exact_terminal_reason_profile_pairs_supply_a_native_route() {
        for route in [
            NativeContainmentRoute::WorkspaceV1,
            NativeContainmentRoute::PythonReadonlyV1,
        ] {
            let value = json!({"decision":"deny","policy_action":"sandbox-required",
                "reason_code":route.reason(),"required_execution_profile":route.profile()});
            assert_eq!(NativeContainmentRoute::from_response(&value), Some(route));
            for (key, bad) in [
                ("decision", json!("allow")),
                ("decision", json!("review")),
                ("policy_action", json!("require-reapproval")),
                ("policy_action", json!("block")),
                ("reason_code", json!("other")),
                ("reason_code", json!(null)),
                ("required_execution_profile", json!("other")),
                ("observe_mode", json!(true)),
                ("observe_mode", json!("false")),
            ] {
                let mut changed = value.clone();
                changed[key] = bad;
                assert_eq!(
                    NativeContainmentRoute::from_response(&changed),
                    None,
                    "{key}"
                );
            }
        }
    }
}
