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
    verify_profile(sdk, router, mcp, budget, None, false).map(|_| ())
}
pub(crate) fn verify_injection(
    sdk: &Value,
    router: &NativeSdkRouter,
    mcp: &Value,
    budget: &Value,
) -> Result<Value, String> {
    let payload = crate::native_mcp_control::injection_payload()?;
    verify_profile(sdk, router, mcp, budget, Some(&payload), false)
}
pub(crate) fn verify_timeout(
    sdk: &Value,
    router: &NativeSdkRouter,
    mcp: &Value,
    budget: &Value,
) -> Result<(), String> {
    let lifecycle = router
        .lifecycle()
        .ok_or("actual timeout observation absent")?;
    if lifecycle["status"] != "passed"
        || lifecycle["role"] != "timeout"
        || lifecycle["capture_exit_code"] != 124
    {
        return Err("actual timeout control did not complete".into());
    }
    verify_profile(sdk, router, mcp, budget, None, true).map(|_| ())
}
pub(crate) fn verify_cancelled(
    router: &NativeSdkRouter,
    mcp: &Value,
    budget: &Value,
    requests: &[Value],
) -> Result<(), String> {
    router.verify_cancelled()?;
    if requests.len() != 2
        || requests[0]["peer_rechecked_before_response"] != true
        || requests[1]["request"]["operation"] != "execute-contained"
        || requests[1]["request"]["token"] != requests[0]["response"]["execution_token"]
        || requests[1].get("response").is_some()
        || !requests[1]["dispatch_error"].is_string()
        || budget["used"] != 2
        || budget["builtin"] != 1
        || budget["mcp"] != 1
        || budget["pending"].as_array().is_none_or(|r| !r.is_empty())
    {
        return Err(
            "controlled cancellation lost actual SDK Pre/sink or operation accounting".into(),
        );
    }
    let front = mcp["frontends"]
        .as_array()
        .filter(|r| r.len() == 2)
        .ok_or("cancelled SDK MCP frontends missing")?;
    let up = mcp["upstreams"]
        .as_array()
        .filter(|r| r.len() == 2)
        .ok_or("cancelled Native MCP upstreams missing")?;
    if front.iter().any(|r| r["status"] != "passed")
        || up.iter().any(|r| r["status"] != "closed")
        || mcp["initial"]["records"] != mcp["final"]["records"]
        || mcp["receipts"].as_array().is_none_or(|r| r.len() != 1)
    {
        return Err("cancelled SDK did not drain its completed delegated read".into());
    }
    let docs = front
        .iter()
        .find(|r| r["family"] == "docs")
        .ok_or("cancelled docs route absent")?;
    let frames = docs["frames"]
        .as_array()
        .ok_or("cancelled docs frames absent")?;
    let calls = frames
        .iter()
        .filter(|r| r["direction"] == "sdk-request" && r["frame"]["method"] == "tools/call")
        .collect::<Vec<_>>();
    if calls.len() != 1
        || calls[0]["forwarded"] != true
        || calls[0]["frame"]["params"]
            != serde_json::json!({"name":"docs.read","arguments":{"record_id":"developer-spec"}})
    {
        return Err("cancelled SDK delegated request differs".into());
    }
    let replies = frames
        .iter()
        .filter(|r| {
            r["direction"] == "native-response" && r["frame"]["id"] == calls[0]["frame"]["id"]
        })
        .collect::<Vec<_>>();
    if replies.len() != 1 || replies[0]["forwarded"] != true {
        return Err("cancelled SDK delegated response was not delivered".into());
    }
    let record: Value = serde_json::from_str(
        replies[0]["frame"]["result"]["content"][0]["text"]
            .as_str()
            .ok_or("cancelled read content absent")?,
    )
    .map_err(|_| "cancelled read content JSON")?;
    if !mcp["initial"]["records"].as_array().is_some_and(|r| {
        r.iter()
            .any(|v| v == &record && v["id"] == "developer-spec")
    }) {
        return Err("cancelled SDK read differs from physical provider record".into());
    }
    Ok(())
}
fn verify_profile(
    sdk: &Value,
    router: &NativeSdkRouter,
    mcp: &Value,
    budget: &Value,
    injection: Option<&str>,
    timeout: bool,
) -> Result<Value, String> {
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
    let initial = mcp["initial"]["records"]
        .as_array()
        .ok_or("initial Root world missing")?;
    let expected = initial
        .iter()
        .find(|r| r["id"] == "developer-spec")
        .ok_or("physical delegated record missing")?;
    if mcp["initial"]["records"] != mcp["final"]["records"]
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
    let parse_record = |frame: &Value| -> Result<Value, String> {
        serde_json::from_str(
            frame["result"]["content"][0]["text"]
                .as_str()
                .ok_or("Native read content absent")?,
        )
        .map_err(|_| "Native read content JSON".into())
    };
    if let Some(payload) = injection {
        let upstream = upstreams
            .iter()
            .find(|s| s["family"] == "docs")
            .ok_or("Root docs upstream missing")?;
        let delivered = upstream["frames"]
            .as_array()
            .ok_or("Root docs frames missing")?
            .iter()
            .filter(|r| r["direction"] == "response" && &r["frame"]["id"] == id)
            .collect::<Vec<_>>();
        if delivered.len() != 1
            || delivered[0]["written"] != true
            || &parse_record(&delivered[0]["frame"])? != expected
            || !delivered[0]["frame"].to_string().contains(payload)
        {
            return Err("actual injected provider exposure to Native is unproven".into());
        }
        crate::native_sdk_result::verify_mcp_injection(sdk, &captured["output"], read)?;
        let response = &sdk["result"]["results"][0];
        let withheld = response["isError"]
            .as_bool()
            .ok_or("typed SDK injection disposition required")?;
        if response.to_string().contains(payload) == withheld
            || read.to_string().contains(payload) == withheld
            || (!withheld && &parse_record(read)? != expected)
        {
            return Err(
                "Native/SDK injection disposition differs from actual visible payload".into(),
            );
        }
        Ok(
            serde_json::json!({"schema":"hol-gauntlet-native-injection-control.v1","attack_payload":payload,
            "upstream_delivered_events":[{"kind":"delivered","message":delivered[0]["frame"],"wire_sha256":delivered[0]["sha256"]}],
            "sdk_response":response,"native_response":read,"mcp_result_disposition":if withheld{"withheld"}else{"forwarded"},
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
        )
    } else {
        if &parse_record(read)? != expected {
            return Err("Native read differs from physical provider record".into());
        }
        if timeout {
            crate::native_sdk_result::verify_mcp_timeout(sdk, &captured["output"], read)?;
        } else {
            crate::native_sdk_result::verify_mcp(sdk, &captured["output"], read)?;
        }
        Ok(Value::Null)
    }
}
