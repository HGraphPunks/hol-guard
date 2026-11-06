//! Recompute per-session RPC, Native captures, read disposition and provider DB.
//! Live process custody and Guard attribution are separate acceptance checks.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{digest, ineligible, parse, require, text, Artifacts};
use crate::{verify_native_world_diagnostic, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct Frames {
    pub(crate) requests: Vec<Value>,
    pub(crate) responses: Vec<Value>,
    pub(crate) count: usize,
}

pub(crate) fn frames(session: &Value, frontend: bool) -> Result<Frames> {
    let rows = session["frames"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 10_000)
        .ok_or(EvidenceError::Invalid("bounded Native MCP frames required"))?;
    let mut pending = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut requests = Vec::new();
    let mut responses = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let wire = text(row, "wire_utf8")?;
        require(
            !wire.is_empty()
                && wire.len() <= 1024 * 1024
                && !wire.contains(['\n', '\r', '\0'])
                && row["sequence"].as_u64() == Some(index as u64 + 1)
                && row["sha256"] == sha256(wire.as_bytes()),
        )?;
        let frame = parse(wire.as_bytes())?;
        require(row["frame"] == frame && frame["jsonrpc"] == "2.0")?;
        let direction = text(row, "direction")?;
        let request = direction == if frontend { "sdk-request" } else { "request" };
        let response = direction
            == if frontend {
                "native-response"
            } else {
                "response"
            };
        require(request || response)?;
        if frontend {
            require(row["forwarded"] == true)?;
        } else if response {
            require(row["written"] == true)?;
        }
        let id = frame.get("id");
        if request {
            let method = text(&frame, "method")?;
            require(
                frame["params"].is_object()
                    && frame.get("result").is_none()
                    && frame.get("error").is_none()
                    && matches!(
                        method,
                        "initialize"
                            | "notifications/initialized"
                            | "tools/list"
                            | "resources/list"
                            | "resources/templates/list"
                            | "prompts/list"
                            | "tools/call"
                    ),
            )?;
            if method == "notifications/initialized" {
                require(id.is_none())?;
            } else {
                let id = id.ok_or(EvidenceError::Invalid("MCP request ID missing"))?;
                require(
                    id.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 256)
                        && used.insert(digest(id)?)
                        && pending.insert(digest(id)?),
                )?;
            }
            requests.push(frame);
        } else {
            let id = id.ok_or(EvidenceError::Invalid("MCP response ID missing"))?;
            require(
                frame.get("method").is_none()
                    && frame.get("result").is_some() != frame.get("error").is_some()
                    && pending.remove(&digest(id)?),
            )?;
            responses.push(frame);
        }
    }
    require(pending.is_empty())?;
    Ok(Frames {
        requests,
        responses,
        count: rows.len(),
    })
}

fn lines(raw: &[u8]) -> Result<Vec<Value>> {
    require(!raw.is_empty() && raw.ends_with(b"\n"))?;
    let rows = raw[..raw.len() - 1]
        .split(|b| *b == b'\n')
        .collect::<Vec<_>>();
    require(rows.len() <= 10_000)?;
    rows.into_iter()
        .map(|row| {
            require(!row.is_empty() && row.len() <= 1024 * 1024)?;
            parse(row)
        })
        .collect()
}

fn captured(
    files: &BTreeMap<String, Vec<u8>>,
    requests: &[Value],
    responses: &[Value],
) -> Result<String> {
    let mut matching = Vec::new();
    for (name, raw) in files {
        if name.starts_with("combined/mcp-processes/")
            && name.ends_with(".mcp-input")
            && lines(raw)? == requests
        {
            let base = name.strip_suffix(".mcp-input").unwrap();
            let output = files
                .get(&format!("{base}.mcp-output"))
                .ok_or(EvidenceError::Invalid("Native captured MCP output missing"))?;
            require(lines(output)? == responses)?;
            matching.push(base.to_owned());
        }
    }
    require(matching.len() == 1)?;
    Ok(matching.remove(0))
}

fn sessions<'a>(value: &'a Value, name: &str) -> Result<BTreeMap<String, &'a Value>> {
    let rows = value[name]
        .as_array()
        .filter(|r| r.len() == 2)
        .ok_or(EvidenceError::Invalid("two Native MCP families required"))?;
    let mut result = BTreeMap::new();
    for row in rows {
        let family = text(row, "family")?;
        require(
            matches!(family, "docs" | "mail") && result.insert(family.to_owned(), row).is_none(),
        )?;
    }
    Ok(result)
}

pub fn verify_native_mcp_diagnostic(
    control: &Value,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Value> {
    ineligible(control)?;
    require(
        control["schema"] == "hol-gauntlet-native-deterministic-control.v1"
            && control["qualified_role_complete"] == false,
    )?;
    let mcp = &control["mcp"];
    ineligible(mcp)?;
    let (expected_world, payload) =
        crate::native_mcp_inputs::expected_world(text(control, "control_role")?)?;
    require(mcp["initial"] == expected_world && mcp["final"] == expected_world)?;
    let artifacts = Artifacts::new(files)?;
    if let Some(sdk) = control["measurements"].get("sdk") {
        let result = &sdk["result"];
        require(
            sdk["exit_code"] == 0
                && sdk["stderr"] == ""
                && result["schema"] == "private-cell-sdk-conformance-result.v1"
                && result["version"] == "18.4.12"
                && result["uid"] == 10001
                && result["syntheticStreamCalls"] == 3
                && result["mcpExercised"] == true
                && result["modelExercised"] == false
                && result["providerRequests"] == 0
                && result["qualificationEligible"] == false
                && result["results"].as_array().is_some_and(|r| r.len() == 2)
                && result["modelContextProjection"]["originalCommandVisible"] == true
                && result["modelContextProjection"]["executionTransportRetained"] == true,
        )?;
        let (stdout, stderr) = artifacts.unique_process_capture(
            "combined/sdk-processes/",
            text(sdk, "stdout_sha256")?,
            text(sdk, "stderr_sha256")?,
        )?;
        require(parse(stdout)? == *result && stderr.is_empty())?;
    } else {
        require(control["control_role"] == "cancel")?;
    }
    let frontends = sessions(mcp, "frontends")?;
    let upstreams = sessions(mcp, "upstreams")?;
    let mut calls = Vec::new();
    let mut captures = BTreeSet::new();
    let mut frame_count = 0;
    let mut disposition = "forwarded";
    for family in ["docs", "mail"] {
        let front = frontends[family];
        let upstream = upstreams[family];
        require(
            front["status"] == "passed"
                && front.get("error").is_some_and(Value::is_null)
                && upstream["status"] == "closed"
                && upstream
                    .get("shutdown_observation")
                    .is_some_and(Value::is_null)
                && upstream["sdk_builtin_budget_composed"] == true,
        )?;
        let observed = frames(front, true)?;
        let original = frames(upstream, false)?;
        require(
            observed.requests == original.requests
                && observed.responses.len() == original.responses.len()
                && captures.insert(captured(files, &observed.requests, &observed.responses)?),
        )?;
        frame_count += observed.count;
        for (delivered, native) in original.responses.iter().zip(&observed.responses) {
            require(delivered["id"] == native["id"])?;
            let request = observed
                .requests
                .iter()
                .find(|r| r.get("id") == native.get("id"))
                .ok_or(EvidenceError::Invalid(
                    "Native response lacks matching request",
                ))?;
            if request["method"] == "tools/call" {
                require(family == "docs" && calls.is_empty())?;
                calls.push(request.clone());
                let physical = parse(text(&delivered["result"]["content"][0], "text")?.as_bytes())?;
                require(
                    mcp["initial"]["records"]
                        .as_array()
                        .is_some_and(|r| r.contains(&physical)),
                )?;
                disposition =
                    crate::native_mcp_inputs::disposition(delivered, native, payload.as_deref())?;
                let withheld = disposition == "withheld";
                if let Some(sdk) = control["measurements"].get("sdk") {
                    let result = &sdk["result"]["results"][0];
                    require(
                        result["content"] == native["result"]["content"]
                            && result["isError"] == json!(withheld),
                    )?;
                } else {
                    require(control["control_role"] == "cancel")?;
                }
                let events = control["operation_budget"]["events"].as_array().ok_or(
                    EvidenceError::Invalid("Native shared operation events missing"),
                )?;
                let events = events
                    .iter()
                    .filter(|e| e["surface"] == "mcp")
                    .collect::<Vec<_>>();
                require(
                    events.len() == 1
                        && events[0]["backend_reached"] == true
                        && events[0]["response_completed"] == true
                        && events[0]["family"] == family
                        && events[0]["request_id"] == request["id"]
                        && events[0]["frame_sha256"] == digest(request)?
                        && events[0]["response_sha256"] == digest(native)?,
                )?;
            } else {
                require(delivered == native)?;
            }
        }
    }
    let budget = &control["operation_budget"];
    require(
        calls.len() == 1
            && budget["used"] == 2
            && budget["builtin"] == 1
            && budget["mcp"] == 1
            && budget["pending"] == json!([]),
    )?;
    let world = verify_native_world_diagnostic(mcp, files, &calls)?;
    let expected = [
        (
            "service_relay.py",
            include_bytes!("../../../../gauntlet/benchmark/service_relay.py").as_slice(),
        ),
        (
            "native_mcp_proxy_v1.py",
            include_bytes!("../../../adapters/native_mcp_proxy_v1.py.txt").as_slice(),
        ),
        (
            "native_mcp_identity_v1.py",
            include_bytes!("../../../adapters/native_mcp_identity_v1.py.txt").as_slice(),
        ),
        ("mcp.json", b"{}\n".as_slice()),
    ];
    for (name, bytes) in expected {
        require(artifacts.raw(&format!("combined/mcp-public/{name}"))? == bytes)?;
    }
    let prefix = artifacts.json("combined/mcp-public/prefix.json")?;
    let source = text(&control["guard_pins"], "source_sha")?;
    require(
        gauntlet_contracts::is_git_sha(source)
            && prefix == json!({"prefix":format!("/opt/hol-gauntlet/candidates/{source}/prefix")}),
    )?;
    Ok(
        json!({"schema":"hol-gauntlet-native-mcp-diagnostic-relations.v1",
        "families_checked":2,"captured_frames_checked":frame_count,"provider_world":world,
        "source_selected_inputs_checked":true,
        "actual_native_read_disposition":disposition,"independent_process_custody_checked":false,
        "qualified_role_complete":false,"outside_signing_key_admitted":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_mcp_diagnostic_tests.rs"]
mod tests;
