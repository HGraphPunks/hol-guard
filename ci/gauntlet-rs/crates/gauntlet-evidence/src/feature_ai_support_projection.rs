//! Closed projection of pinned OMP transcripts and the unchanged source MCP catalog.
use super::*;
use crate::payload::exact_keys;

const CATALOG: &[u8] =
    include_bytes!("../../gauntlet-mcp-service/catalog-python-mcp-1.30.0.v1.json");
const CATALOG_SHA: &str = "22df4f3850d6d22ef30b6ec45108cde9b4306879c06c99ccce6f3bf53097cafe";
#[path = "feature_ai_support_json_render.rs"]
mod json_render;

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid("live request/observation contract differs"))
    }
}
fn array(value: &Value, maximum: usize) -> Result<&[Value]> {
    value
        .as_array()
        .filter(|v| v.len() <= maximum)
        .map(Vec::as_slice)
        .ok_or(invalid("bounded live observations required"))
}

pub(super) fn sdk_events(artifacts: &Value) -> Result<Vec<Value>> {
    let raw = artifacts["sdk_events"]
        .as_str()
        .ok_or(invalid("exact raw SDK transcript required"))?;
    crate::parse_omp_transcript(raw.as_bytes())
}

pub(super) fn contains_prompt(content: &Value, prompt: &str) -> bool {
    if let Some(text) = content.as_str() {
        return text.contains(prompt);
    }
    content.as_array().is_some_and(|parts| {
        parts.iter().any(|part| {
            part["type"] == "text"
                && part["text"]
                    .as_str()
                    .is_some_and(|text| text.contains(prompt))
        })
    })
}

pub(super) fn contains_result(value: &Value, expected: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    if value == expected {
        return true;
    }
    match value {
        Value::Object(row) => row
            .values()
            .any(|v| contains_result(v, expected, depth + 1)),
        Value::Array(rows) => rows.iter().any(|v| contains_result(v, expected, depth + 1)),
        Value::String(text) if text.len() <= 2 * 1024 * 1024 => {
            expected["data"]["body"]
                .as_str()
                .is_some_and(|body| !body.is_empty() && text.contains(body))
                || crate::native_diagnostic_artifacts::parse(text.as_bytes()).is_ok_and(|v| {
                    (v.is_object() || v.is_array()) && contains_result(&v, expected, depth + 1)
                })
        }
        _ => false,
    }
}

pub(super) fn normalized_sdk_events(events: &[Value], artifacts: &Value) -> Result<Vec<Value>> {
    let mut flat = Vec::new();
    let mut observed = Vec::new();
    for envelope in events {
        require(envelope["type"] != "model_turn")?;
        let event = if envelope["type"] == "agent_event" {
            &envelope["event"]
        } else {
            envelope
        };
        if event["type"] == "message_end" && event["message"]["role"] == "assistant" {
            let mut calls = Vec::new();
            for part in array(&event["message"]["content"], 1000)? {
                if part["type"] != "toolCall" {
                    continue;
                }
                require(
                    part["id"]
                        .as_str()
                        .is_some_and(|id| !id.is_empty() && id.len() <= 256)
                        && part["name"]
                            .as_str()
                            .is_some_and(|name| !name.is_empty() && name.len() <= 256)
                        && part["arguments"].is_object(),
                )?;
                calls.push(
                    json!({"id":part["id"],"name":part["name"],"arguments":part["arguments"]}),
                );
            }
            observed.extend(calls.clone());
            flat.push(json!({"type":"model_turn","calls":calls}));
        }
        flat.push(event.clone());
    }
    let mut emitted = Vec::new();
    for turn in array(&artifacts["provider_turns"], 64)? {
        let raw = turn["response"]
            .as_str()
            .ok_or(invalid("actual provider response missing for SDK join"))?;
        let response = crate::native_diagnostic_artifacts::parse(raw.as_bytes())?;
        let message = &response["choices"][0]["message"];
        if let Some(calls) = message.get("tool_calls") {
            for call in array(calls, 1000)? {
                require(call["type"] == "function")?;
                let raw = call["function"]["arguments"]
                    .as_str()
                    .ok_or(invalid("actual model tool arguments missing"))?;
                let args = crate::native_diagnostic_artifacts::parse(raw.as_bytes())?;
                require(args.is_object())?;
                emitted.push(
                    json!({"id":call["id"],"name":call["function"]["name"],"arguments":args}),
                );
            }
        }
    }
    require(observed == emitted)?;
    Ok(flat)
}

pub(super) fn request_id(id: &Value) -> bool {
    id.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 256)
        || id.as_i64().is_some()
        || id.as_u64().is_some()
}

/// Pinned SDK buildResult over text and the canonical integer/object structured
/// subset measured by the genuine SDK conformance fixture. A structured fence
/// additionally requires exact canonical response wire to retain property order.
pub(super) fn displayed_content(result: &Value, response_wire: &str) -> Result<Value> {
    let content = result["content"]
        .as_array()
        .filter(|v| v.len() <= 1000)
        .ok_or(invalid("bounded MCP content required"))?;
    let mut text = String::new();
    for part in content {
        if !exact_keys(part, &["type", "text"]) || part["type"] != "text" {
            return Err(invalid("unsupported source MCP display content shape"));
        }
        let value = part["text"]
            .as_str()
            .ok_or(invalid("MCP text string required"))?;
        if !text.is_empty() {
            text.push_str("\n\n");
        }
        text.push_str(value);
    }
    if result["isError"] == true {
        text = format!("Error: {text}");
    }
    let mut displayed = vec![json!({"type":"text","text":text})];
    if let Some(structured) = result.get("structuredContent") {
        if !structured.is_object() {
            return Err(invalid("source MCP structured object required"));
        }
        let duplicate = content.iter().any(|p| {
            p["text"]
                .as_str()
                .and_then(|s| crate::native_diagnostic_artifacts::parse(s.trim().as_bytes()).ok())
                .is_some_and(|v| v == *structured)
        });
        if !duplicate {
            if response_wire.len() > 1024 * 1024 {
                return Err(invalid("bounded structured MCP response wire required"));
            }
            let response = crate::native_diagnostic_artifacts::parse(response_wire.as_bytes())?;
            if response["result"] != *result
                || canonical_value(&response)? != response_wire.as_bytes()
            {
                return Err(invalid("unsupported structured MCP wire property order"));
            }
            displayed.push(json!({"type":"text","text":format!("```json\n{}\n```",json_render::pretty(structured)?)}));
        }
    }
    Ok(json!(displayed))
}

fn tools(family: &str) -> Result<Value> {
    if !matches!(family, "docs" | "mail" | "crm" | "tickets") || sha256(CATALOG) != CATALOG_SHA {
        return Err(invalid(
            "source-pinned feature-ai MCP family catalog required",
        ));
    }
    let catalog = crate::native_diagnostic_artifacts::parse(CATALOG)?;
    let tools = catalog["families"][family].clone();
    if !tools.is_array() {
        return Err(invalid("source MCP tool inventory missing"));
    }
    Ok(tools)
}

/// OMP tool-bridge SHA6ee027b2, pi-wire SHA4bae703a and schema helper
/// SHA88f612ea: this catalog's flat object schemas never own the internal `i`.
/// Only declared optional empty strings/objects are omitted. URL strings and
/// unknown keys are retained; an unobserved URL rewrite cannot be guessed.
pub fn project_feature_ai_mcp_arguments(
    family: &str,
    operation: &str,
    arguments: &Value,
) -> Result<Value> {
    let tools = tools(family)?;
    let tool = tools
        .as_array()
        .expect("checked tools")
        .iter()
        .find(|t| t["name"] == operation)
        .ok_or(invalid("unknown source MCP operation"))?;
    let schema = &tool["inputSchema"];
    if !exact_keys(
        schema,
        &[
            "type",
            "properties",
            "required",
            "additionalProperties",
            "title",
        ],
    ) || schema["type"] != "object"
        || schema["additionalProperties"] != false
        || !schema["properties"].is_object()
        || !schema["required"].is_array()
        || schema["properties"].get("i").is_some()
        || schema["required"]
            .as_array()
            .expect("required array")
            .iter()
            .any(|k| {
                k.as_str()
                    .is_none_or(|k| k == "i" || schema["properties"].get(k).is_none())
            })
    {
        return Err(invalid("unfamiliar source MCP argument schema"));
    }
    let mut projected = arguments
        .as_object()
        .ok_or(invalid("SDK MCP arguments object required"))?
        .clone();
    if canonical_value(arguments)?.len() > 1024 * 1024 {
        return Err(invalid("SDK MCP argument bound exceeded"));
    }
    projected.remove("i");
    let required = schema["required"].as_array().expect("required array");
    projected.retain(|key, value| {
        required.contains(&json!(key))
            || schema["properties"].get(key).is_none()
            || !(value == "" || value.as_object().is_some_and(|v| v.is_empty()))
    });
    Ok(Value::Object(projected))
}

pub(super) fn captured_catalog(context: &Value, family: &str) -> Result<()> {
    let expected = tools(family)?;
    let frontends = context["mcp"]["frontends"]
        .as_array()
        .ok_or(invalid("actual MCP frontend inventory required"))?;
    let selected: Vec<_> = frontends.iter().filter(|f| f["family"] == family).collect();
    if selected.len() != 1 {
        return Err(invalid("unique actual MCP family required"));
    }
    let frames = selected[0]["frames"]
        .as_array()
        .filter(|v| v.len() <= 10000)
        .ok_or(invalid("bounded actual MCP frames required"))?;
    let requests: Vec<_> = frames
        .iter()
        .filter(|f| f["direction"] == "sdk-request" && f["frame"]["method"] == "tools/list")
        .collect();
    if requests.is_empty() {
        return Err(invalid("actual source MCP tools/list request missing"));
    }
    for request in requests {
        if request["frame"]["jsonrpc"] != "2.0" || !request_id(&request["frame"]["id"]) {
            return Err(invalid("actual MCP tools/list request identity missing"));
        }
        let responses: Vec<_> = frames
            .iter()
            .filter(|f| {
                matches!(
                    f["direction"].as_str(),
                    Some("native-response" | "root-world-response")
                ) && f["frame"]["id"] == request["frame"]["id"]
            })
            .collect();
        if responses.len() != 1
            || responses[0]["frame"]["jsonrpc"] != "2.0"
            || responses[0]["frame"]["result"]["tools"] != expected
        {
            return Err(invalid("actual MCP tools/list differs from source catalog"));
        }
        for frame in [request, responses[0]] {
            let raw = frame["wire_utf8"]
                .as_str()
                .ok_or(invalid("actual MCP frame bytes required"))?;
            if frame["sha256"] != sha256(raw.as_bytes())
                || crate::native_diagnostic_artifacts::parse(raw.as_bytes())? != frame["frame"]
            {
                return Err(invalid("actual MCP frame byte projection mismatch"));
            }
        }
    }
    Ok(())
}

fn frame_bytes(frame: &Value) -> Result<()> {
    let raw = frame["wire_utf8"]
        .as_str()
        .ok_or(invalid("actual MCP frame bytes required"))?;
    if frame["sha256"] != sha256(raw.as_bytes())
        || crate::native_diagnostic_artifacts::parse(raw.as_bytes())? != frame["frame"]
    {
        return Err(invalid("actual MCP frame byte projection mismatch"));
    }
    Ok(())
}
fn recorded_frame_entry<'a>(
    frontends: &'a Value,
    family: &str,
    id: &Value,
    request: bool,
) -> Result<Option<&'a Value>> {
    let selected: Vec<_> = frontends
        .as_array()
        .filter(|r| r.len() <= 4)
        .ok_or(invalid("bounded MCP peer inventory required"))?
        .iter()
        .filter(|f| f["family"] == family)
        .collect();
    if selected.is_empty() {
        return Ok(None);
    }
    if selected.len() != 1 {
        return Err(invalid("unique MCP peer family required"));
    }
    let frames = selected[0]["frames"]
        .as_array()
        .filter(|r| r.len() <= 10000)
        .ok_or(invalid("bounded MCP peer frames required"))?;
    let selected: Vec<_> = frames
        .iter()
        .filter(|f| {
            f["frame"]["id"] == *id
                && if request {
                    matches!(f["direction"].as_str(), Some("sdk-request" | "request"))
                        && f["frame"]["method"] == "tools/call"
                } else {
                    matches!(
                        f["direction"].as_str(),
                        Some("native-response" | "root-world-response" | "response")
                    )
                }
        })
        .collect();
    if selected.len() > 1 {
        return Err(invalid("ambiguous actual MCP request/response identity"));
    }
    selected
        .first()
        .copied()
        .map(|f| {
            frame_bytes(f)?;
            Ok(f)
        })
        .transpose()
}

fn recorded_frame<'a>(
    frontends: &'a Value,
    family: &str,
    id: &Value,
    request: bool,
) -> Result<Option<&'a Value>> {
    Ok(recorded_frame_entry(frontends, family, id, request)?.map(|entry| &entry["frame"]))
}

pub(super) fn native_response_wire<'a>(
    context: &'a Value,
    family: &str,
    id: &Value,
) -> Result<&'a str> {
    recorded_frame_entry(&context["mcp"]["frontends"], family, id, false)?
        .and_then(|entry| entry["wire_utf8"].as_str())
        .ok_or(invalid("actual Native response wire missing"))
}

/// The signed aggregate projection must equal the independently retained Root
/// socket frames. Counts cover every tools/call, including denials with no World
/// receipt; a producer cannot omit a call or attach a different decision/result.
pub(super) fn native_frames(context: &Value, artifacts: &Value, protected: bool) -> Result<()> {
    if context["mcp"]["protected"] != protected {
        return Err(invalid("actual MCP protection profile mismatch"));
    }
    let native = artifacts["native_calls"]
        .as_array()
        .ok_or(invalid("actual native call inventory required"))?;
    let frontends = &context["mcp"]["frontends"];
    let captured = frontends
        .as_array()
        .ok_or(invalid("actual MCP frontends required"))?
        .iter()
        .map(|f| {
            f["frames"]
                .as_array()
                .map(|frames| {
                    frames
                        .iter()
                        .filter(|r| {
                            r["direction"] == "sdk-request" && r["frame"]["method"] == "tools/call"
                        })
                        .count()
                })
                .unwrap_or(0)
        })
        .sum::<usize>();
    if captured != native.len() {
        return Err(invalid(
            "aggregate and captured MCP call inventories differ",
        ));
    }
    let mut used = BTreeSet::new();
    for row in native {
        let request = &row["request"];
        let family = request["params"]["name"]
            .as_str()
            .and_then(|n| n.split('.').next())
            .ok_or(invalid("actual MCP operation family required"))?;
        if !used.insert((family, request["id"].to_string()))
            || recorded_frame(frontends, family, &request["id"], true)? != Some(request)
            || recorded_frame(frontends, family, &request["id"], false)?
                != Some(&row["native_response"])
        {
            return Err(invalid(
                "aggregate request/decision differs from actual MCP frame",
            ));
        }
        if protected {
            let upstream = &context["mcp"]["upstreams"];
            let actual_request = recorded_frame(upstream, family, &request["id"], true)?;
            let actual_response = recorded_frame(upstream, family, &request["id"], false)?;
            if row["upstream_request"].is_null() {
                if actual_request.is_some() || actual_response.is_some() {
                    return Err(invalid("denied MCP call reached the actual upstream"));
                }
            } else if actual_request != Some(&row["upstream_request"])
                || actual_response != Some(&row["upstream_response"])
            {
                return Err(invalid("aggregate upstream differs from actual MCP frames"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "feature_ai_support_projection_tests.rs"]
mod tests;
