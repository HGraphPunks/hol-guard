//! Join the SDK-visible read, Root ingress permit and physical provider result.
//! This is a diagnostic join; it does not infer a Guard verdict from RPC status.
use crate::native_sdk_router::NativeSdkRouter;
use serde_json::Value;

pub(crate) fn verify(
    sdk: &Value,
    router: &NativeSdkRouter,
    mcp: &Value,
    budget: &Value,
) -> Result<(), String> {
    router.verify_completed()?;
    let captured = router
        .events
        .iter()
        .find(|v| v["kind"] == "sdk-contained-completed")
        .ok_or("SDK Bash capture missing from composed run")?;
    let frontends = mcp["frontends"]
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or("two actual SDK MCP routes required")?;
    let upstreams = mcp["upstreams"]
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or("two Native MCP upstream routes required")?;
    if frontends.iter().any(|s| s["status"] != "passed")
        || upstreams.iter().any(|s| s["status"] != "closed")
        || budget["used"] != 2
        || budget["builtin"] != 1
        || budget["mcp"] != 1
        || budget["pending"].as_array().is_none_or(|a| !a.is_empty())
    {
        return Err("composed SDK route/shared budget lifecycle incomplete".into());
    }
    let docs = frontends
        .iter()
        .find(|s| s["family"] == "docs")
        .ok_or("SDK docs route absent")?;
    let frames = docs["frames"].as_array().ok_or("SDK docs frames absent")?;
    let requests = frames
        .iter()
        .filter(|f| f["direction"] == "sdk-request" && f["frame"]["method"] == "tools/call")
        .collect::<Vec<_>>();
    if requests.len() != 1
        || requests[0]["forwarded"] != true
        || requests[0]["frame"]["params"]["name"] != "docs.read"
        || requests[0]["frame"]["params"]["arguments"]
            != serde_json::json!({"record_id":"developer-spec"})
    {
        return Err("actual SDK delegated read differs from fixed control".into());
    }
    let id = &requests[0]["frame"]["id"];
    let responses = frames
        .iter()
        .filter(|f| f["direction"] == "native-response" && &f["frame"]["id"] == id)
        .collect::<Vec<_>>();
    if responses.len() != 1 || responses[0]["forwarded"] != true {
        return Err("unique forwarded Native read response required".into());
    }
    let read = &responses[0]["frame"];
    let text = read["result"]["content"][0]["text"]
        .as_str()
        .ok_or("Native read content absent")?;
    let record: Value = serde_json::from_str(text).map_err(|_| "Native read content JSON")?;
    let initial = mcp["initial"]["records"]
        .as_array()
        .ok_or("initial Root world missing")?;
    let expected = initial
        .iter()
        .find(|r| r["id"] == "developer-spec")
        .ok_or("physical delegated record missing")?;
    if &record != expected
        || mcp["initial"]["records"] != mcp["final"]["records"]
        || mcp["receipts"].as_array().is_none_or(|r| r.len() != 1)
    {
        return Err("SDK MCP response does not match unchanged physical provider state".into());
    }
    let events = budget["events"]
        .as_array()
        .ok_or("shared operation events absent")?;
    let ingress = events
        .iter()
        .find(|e| e["surface"] == "mcp")
        .ok_or("SDK ingress permit absent")?;
    if ingress["backend_reached"] != true || ingress["response_completed"] != true {
        return Err("one-use SDK operation did not complete through the provider".into());
    }
    crate::native_sdk_result::verify_mcp(sdk, &captured["output"], read)
}
