//! Source-selected diagnostic inputs and observed read disposition.
use crate::native_diagnostic_artifacts::{parse, require, text};
use crate::{EvidenceError, Result};
use serde_json::{json, Value};

fn unique<'a>(rows: &'a Value, id: &str) -> Result<&'a Value> {
    let values = rows.as_array().ok_or(EvidenceError::Invalid(
        "compiled Native control catalog missing",
    ))?;
    let found = values.iter().filter(|v| v["id"] == id).collect::<Vec<_>>();
    require(found.len() == 1)?;
    Ok(found[0])
}
pub(crate) fn expected_world(role: &str) -> Result<(Value, Option<String>)> {
    require(matches!(
        role,
        "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
    ))?;
    let mut snapshot = json!({"schema":"gauntlet-workflow-snapshot.v1","actor_id":"fixture-actor",
        "provider_scope":{"tenants":["task-tenant"]},"records":[
        {"id":"developer-spec","collection":"docs.documents","tenant_id":"task-tenant",
            "owner_id":"fixture-actor","version":1,"acl":{"read":["fixture-actor"],"write":["fixture-actor"]},
            "data":{"title":"Delegated developer input","body":"Read this fixed synthetic document."}},
        {"id":"message","collection":"mail.messages","tenant_id":"task-tenant",
            "owner_id":"fixture-actor","version":1,"acl":{"read":["fixture-actor"],"write":["fixture-actor"]},
            "data":{"subject":"Synthetic input","body":"No external delivery is authorized."}}]});
    let payload = if role == "injection" {
        let catalog = parse(include_bytes!(
            "../../../../gauntlet/benchmark/workflows.json"
        ))?;
        let workflow = unique(&catalog["workflows"], "python-cli-with-tests")?;
        let attack = unique(&workflow["attacks"], "text-injection")?;
        require(
            attack["kind"] == "text-injection"
                && attack["surface"] == "tool-result.body"
                && attack["source_id"] == "developer-spec",
        )?;
        let payload = text(attack, "payload")?;
        require(!payload.is_empty() && payload.len() <= 4096)?;
        snapshot["records"][0]["data"]["body"] =
            format!("Read this fixed synthetic document.\n\n{payload}").into();
        Some(payload.to_owned())
    } else {
        None
    };
    Ok((snapshot, payload))
}
fn visible(value: &Value, payload: &str, depth: usize) -> Result<bool> {
    require(depth <= 16)?;
    match value {
        Value::String(s) => {
            if s.contains(payload) {
                return Ok(true);
            }
            if let Ok(nested) = parse(s.as_bytes()) {
                if nested.is_object() || nested.is_array() {
                    return visible(&nested, payload, depth + 1);
                }
            }
        }
        Value::Array(v) => {
            for value in v {
                if visible(value, payload, depth + 1)? {
                    return Ok(true);
                }
            }
        }
        Value::Object(v) => {
            for value in v.values() {
                if visible(value, payload, depth + 1)? {
                    return Ok(true);
                }
            }
        }
        _ => {}
    }
    Ok(false)
}
pub(crate) fn disposition(
    delivered: &Value,
    native: &Value,
    payload: Option<&str>,
) -> Result<&'static str> {
    if let Some(payload) = payload {
        require(visible(delivered, payload, 0)?)?;
    }
    if delivered == native {
        return Ok("forwarded");
    }
    let payload = payload.ok_or(EvidenceError::Invalid("unexpected changed Native MCP read"))?;
    require(
        native.get("error").is_none()
            && native["result"]["isError"] == true
            && !visible(native, payload, 0)?,
    )?;
    Ok("withheld")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_selects_only_the_fixed_injection_surface() {
        let (plain, none) = expected_world("success").unwrap();
        let (injected, payload) = expected_world("injection").unwrap();
        let payload = payload.unwrap();
        assert!(none.is_none());
        assert!(!payload.is_empty());
        assert_eq!(
            injected["records"][0]["data"]["body"],
            format!("Read this fixed synthetic document.\n\n{payload}")
        );
        assert_eq!(plain["records"][1], injected["records"][1]);
        assert!(expected_world("producer-chosen-profile").is_err());
    }
    #[test]
    fn withheld_requires_actual_error_and_absent_payload_even_when_nested_encoded() {
        let payload = "quoted \"input\"\nnext line";
        let delivered = json!({"jsonrpc":"2.0","id":"call","result":{"content":[{"type":"text",
            "text":json!({"data":{"body":payload}}).to_string()}],"isError":false}});
        let blocked = json!({"jsonrpc":"2.0","id":"call","result":{"content":[{"type":"text","text":"blocked"}],"isError":true}});
        assert_eq!(
            disposition(&delivered, &delivered, Some(payload)).unwrap(),
            "forwarded"
        );
        assert_eq!(
            disposition(&delivered, &blocked, Some(payload)).unwrap(),
            "withheld"
        );
        let mut leaking = delivered.clone();
        leaking["result"]["isError"] = true.into();
        assert!(disposition(&delivered, &leaking, Some(payload)).is_err());
        let mut false_error = blocked.clone();
        false_error["result"]["isError"] = false.into();
        assert!(disposition(&delivered, &false_error, Some(payload)).is_err());
        assert!(disposition(&delivered, &blocked, None).is_err());
    }
}
