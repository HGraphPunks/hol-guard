//! Retain actual live observations separately from the bounded signed report.
//! Request/result projection never assigns a Guard verdict or a business score.
use crate::{NativeJobSpec, NativeLiveJob};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(crate) struct LiveArtifacts {
    pub hashes: Value,
    pub context_sha256: String,
}

fn raw_event(value: &Value) -> &Value {
    if value["type"] == "agent_event" {
        &value["event"]
    } else {
        value
    }
}
fn native_calls(mcp: &Value, budget: &Value, sdk: &[Value]) -> Value {
    let metadata = sdk.iter().find(|r| r["type"] == "episode_start");
    let mut calls = Vec::new();
    let mut used = BTreeSet::new();
    let Some(events) = budget["events"].as_array() else {
        return json!([]);
    };
    for event in events {
        if event["surface"] != "mcp" || event["method"] != "tools/call" {
            continue;
        }
        let family = &event["family"];
        let id = &event["request_id"];
        let frontend = mcp["frontends"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["family"] == *family));
        let request = frontend
            .and_then(|f| f["frames"].as_array())
            .and_then(|rows| {
                rows.iter()
                    .find(|r| r["direction"] == "sdk-request" && r["frame"]["id"] == *id)
            })
            .map(|r| r["frame"].clone())
            .unwrap_or(Value::Null);
        if request.is_null() {
            continue;
        }
        let response = frontend
            .and_then(|f| f["frames"].as_array())
            .and_then(|rows| {
                rows.iter().find(|r| {
                    matches!(
                        r["direction"].as_str(),
                        Some("native-response" | "root-world-response")
                    ) && r["frame"]["id"] == *id
                })
            })
            .map(|r| r["frame"].clone())
            .unwrap_or(Value::Null);
        let upstream = mcp["upstreams"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["family"] == *family));
        let upstream_request = upstream
            .and_then(|f| f["frames"].as_array())
            .and_then(|rows| {
                rows.iter()
                    .find(|r| r["direction"] == "request" && r["frame"]["id"] == *id)
            })
            .map(|r| r["frame"].clone());
        let upstream_response = upstream
            .and_then(|f| f["frames"].as_array())
            .and_then(|rows| {
                rows.iter()
                    .find(|r| r["direction"] == "response" && r["frame"]["id"] == *id)
            })
            .map(|r| r["frame"].clone());
        let baseline = mcp["protected"] == false;
        let display = metadata
            .and_then(|m| m["resourceTools"].as_array())
            .and_then(|tools| {
                tools
                    .iter()
                    .find(|t| t["server"] == *family && t["rawTool"] == request["params"]["name"])
            })
            .and_then(|t| t["name"].as_str());
        let tool_call_id = sdk
            .iter()
            .map(raw_event)
            .find(|e| {
                e["type"] == "tool_execution_start"
                    && display.is_some_and(|name| e["toolName"] == name)
                    && family
                        .as_str()
                        .zip(request["params"]["name"].as_str())
                        .is_some_and(|(family, operation)| {
                            gauntlet_evidence::project_feature_ai_mcp_arguments(
                                family, operation, &e["args"],
                            )
                            .is_ok_and(|args| args == request["params"]["arguments"])
                        })
                    && e["toolCallId"]
                        .as_str()
                        .is_some_and(|id| !used.contains(id))
            })
            .and_then(|e| e["toolCallId"].as_str());
        if let Some(id) = tool_call_id {
            used.insert(id.to_owned());
        }
        calls.push(json!({"sequence":calls.len()+1,"tool_call_id":tool_call_id,"request":request,
            "upstream_request":if baseline{Some(request.clone())}else{upstream_request},
            "upstream_response":if baseline{Some(response.clone())}else{upstream_response},"native_response":response}));
    }
    json!(calls)
}
pub(crate) fn retain(
    job: &NativeJobSpec,
    live: &NativeLiveJob,
    sdk_raw: &[u8],
    mcp: &Value,
    provider: &Value,
    budget: &Value,
) -> Result<LiveArtifacts, String> {
    let sdk_text = std::str::from_utf8(sdk_raw).ok();
    let parsed = sdk_text.and_then(|_| gauntlet_evidence::parse_omp_transcript(sdk_raw).ok());
    let artifacts = json!({"initial_snapshot":mcp["initial"],"final_snapshot":mcp["final"],"world_receipts":mcp["receipts"],
        "world_calls":mcp["world_calls"],"sdk_events":sdk_text,"provider_turns":provider["provider_turns"],
        "native_calls":parsed.as_ref().map(|rows|native_calls(mcp,budget,rows)).unwrap_or_else(||json!([])),"cleanup":null});
    let mut hashes = serde_json::Map::new();
    for (name, value) in artifacts.as_object().unwrap() {
        let raw = gauntlet_contracts::canonicalize(value.to_string().as_bytes())
            .map_err(|_| "live artifact canonicalization failed")?;
        hashes.insert(name.clone(), json!(crate::native_live_model::sha(&raw)));
    }
    let envelope = json!({"schema":"hol-gauntlet-feature-ai-support-cell.v1","cell_id":live.cell_id,"artifacts":artifacts});
    let raw = gauntlet_contracts::canonicalize(envelope.to_string().as_bytes())
        .map_err(|_| "live artifact envelope encoding failed")?;
    if raw.len() > 32 * 1024 * 1024 {
        return Err("live artifact aggregate exceeds archive member budget".into());
    }
    let root =
        crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
    let directory = crate::feature_files::directory(&root, "live", (0, 0), true)?;
    crate::feature_files::write(&directory, "evidence.v1.json", &raw, (0, 0), 0o600)?;
    let context = json!({"schema":"hol-gauntlet-native-live-context.v1","source_sha":job.source_sha,"job_id":job.job_id,"worker_generation":job.worker_generation,
        "preparation_sha256":job.preparation_sha256,"cell_id":live.cell_id,"spec_sha256":live.spec_sha256,"mcp":mcp});
    let context = gauntlet_contracts::canonicalize(context.to_string().as_bytes())
        .map_err(|_| "live context canonicalization failed")?;
    if context.len() > 32 * 1024 * 1024 {
        return Err("live context artifact bound exceeded".into());
    }
    crate::feature_files::write(&directory, "context.v1.json", &context, (0, 0), 0o600)?;
    Ok(LiveArtifacts {
        hashes: Value::Object(hashes),
        context_sha256: crate::native_live_model::sha(&context),
    })
}
