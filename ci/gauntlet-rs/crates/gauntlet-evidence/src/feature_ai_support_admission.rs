//! Scoped MCP-only admission binds actual SDK custody to outside Host requests.
//! Historical measurements and generic MCP errors never grant release credit.
use super::*;
use crate::payload::exact_keys;

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(invalid("MCP-only SDK admission differs"))
    }
}
fn array(value: &Value, maximum: usize) -> Result<&[Value]> {
    value
        .as_array()
        .filter(|v| v.len() <= maximum)
        .map(Vec::as_slice)
        .ok_or(invalid("bounded MCP-only admission observations required"))
}
fn names(value: &Value) -> Result<BTreeSet<&str>> {
    let rows = array(value, 256)?;
    let result: BTreeSet<_> = rows
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty() && s.len() <= 256)
                .ok_or(invalid("actual tool name missing"))
        })
        .collect::<Result<_>>()?;
    require(result.len() == rows.len())?;
    Ok(result)
}
fn source_tools() -> Result<BTreeMap<String, Value>> {
    let mut result = BTreeMap::new();
    for family in ["crm", "docs", "mail", "tickets"] {
        for tool in array(&super::projection::tools(family)?, 256)? {
            let operation = tool["name"]
                .as_str()
                .ok_or(invalid("source MCP operation missing"))?;
            require(operation.starts_with(&format!("{family}.")))?;
            let name = format!("mcp__{}", operation.replace('.', "_"));
            require(
                result
                    .insert(
                        name,
                        json!({"family":family,"operation":operation,
                "parameters":tool["inputSchema"],"description":tool["description"]}),
                    )
                    .is_none(),
            )?;
        }
    }
    Ok(result)
}

/// Observed from the genuine locked SDK serializer with fetch intercepted
/// before transport. This intentionally supports one reviewed wire profile.
fn observed_wire(source: &BTreeMap<String, Value>) -> Result<Value> {
    const RAW: &[u8] = include_bytes!("../tests/fixtures/omp_mcp_wire_observed_v1.json");
    require(sha256(RAW) == "da521f87183b20172ed331aa08fb2f8677e02072ec0ddd935a9043371e408fbe")?;
    let reference = crate::native_diagnostic_artifacts::parse(RAW)?;
    let observed = &reference["observation"];
    require(
        reference["schema"] == "hol-gauntlet-omp18412-mcp-wire-observed.v1"
            && reference["capture_sha256"]
                == "5995068375fb49a927201e1948ec7d0e3b05fae30b79734d0e1cf65a72fb9ca1"
            && reference["input_fixture_sha256"]
                == "d3ad3aee1136ad0783f712ba87e1563e4205a1db120773bfbfa7c4871a600170"
            && observed["schema"] == "hol-gauntlet-omp18412-mcp-wire-capture.v1"
            && observed["catalog_sha256"]
                == "22df4f3850d6d22ef30b6ec45108cde9b4306879c06c99ccce6f3bf53097cafe"
            && observed["sdk_version"] == "18.4.12"
            && observed["bun_version"] == "1.3.14"
            && observed["provider"] == "benchmark-local"
            && observed["base_url"] == "http://127.0.0.1:8001/v1"
            && observed["intercepted_requests"] == 1
            && [
                "network_requests",
                "model_requests",
                "model_completions",
                "tool_calls_during_request",
            ]
            .iter()
            .all(|key| observed[*key] == 0)
            && observed["qualification_eligible"] == false,
    )?;
    let mut seen = BTreeSet::new();
    for row in array(&observed["tools"], 256)? {
        let name = row["function"]["name"]
            .as_str()
            .ok_or(invalid("observed SDK tool absent"))?;
        let declared = source
            .get(name)
            .ok_or(invalid("observed SDK tool differs from source"))?;
        require(seen.insert(name) && row["function"]["description"] == declared["description"])?;
    }
    require(seen == source.keys().map(String::as_str).collect())?;
    Ok(observed.clone())
}

pub(super) fn inventory(artifacts: &Value, context: &Value) -> Result<Value> {
    let events = super::projection::sdk_events(artifacts)?;
    let starts: Vec<_> = events
        .iter()
        .filter(|e| e["type"] == "episode_start")
        .collect();
    require(starts.len() == 1)?;
    let start = starts[0];
    require(
        start["schema"] == "hol-gauntlet-developer-episode-start.v2"
            && start["episodeSchema"] == "developer-omp-episode.v3"
            && start["builtinToolProfile"] == "mcp-only.v1"
            && start["harness"] == "omp"
            && start["version"] == "18.4.12"
            && start["agentUid"] == 10001
            && start["qualification"] == false
            && start["guardExtensionAttached"] == context["mcp"]["protected"]
            && start["mountedXdevTools"] == json!([]),
    )?;
    let source = source_tools()?;
    let observed = observed_wire(&source)?;
    require(start["model"] == observed["model_id"])?;
    let reviewed: BTreeMap<_, _> = array(&observed["tools"], 256)?
        .iter()
        .map(|row| (row["function"]["name"].as_str().unwrap(), row))
        .collect();
    let expected: BTreeSet<_> = source.keys().map(String::as_str).collect();
    require(
        names(&start["activeTools"])? == expected && names(&start["enabledTools"])? == expected,
    )?;
    let mut mappings = BTreeSet::new();
    for row in array(&start["resourceTools"], 256)? {
        require(exact_keys(row, &["name", "server", "rawTool"]))?;
        let name = row["name"]
            .as_str()
            .ok_or(invalid("actual MCP tool mapping missing"))?;
        let tool = source
            .get(name)
            .ok_or(invalid("undeclared actual SDK tool"))?;
        require(
            mappings.insert(name)
                && row["server"] == tool["family"]
                && row["rawTool"] == tool["operation"],
        )?;
        super::projection::captured_catalog(context, tool["family"].as_str().unwrap())?;
    }
    require(mappings == expected)?;
    let turns = array(&artifacts["provider_turns"], 64)?;
    require(!turns.is_empty())?;
    let mut first = None;
    for turn in turns {
        let (request, _) = crate::provider_rust_status::provider_turn_bodies(turn)
            .ok_or(invalid("outside-bound provider request bodies invalid"))?;
        require(request["model"] == start["model"])?;
        let mut seen = BTreeSet::new();
        let declarations = array(&request["tools"], 256)?;
        for row in declarations {
            let function = &row["function"];
            let name = function["name"]
                .as_str()
                .ok_or(invalid("provider tool identity missing"))?;
            let tool = reviewed
                .get(name)
                .ok_or(invalid("undeclared provider tool surface"))?;
            require(seen.insert(name) && row == *tool)?;
        }
        require(seen == expected)?;
        let digest = hash(&request["tools"])?;
        if let Some(previous) = &first {
            require(previous == &digest)?;
        } else {
            first = Some(digest);
        }
    }
    Ok(json!({"profile":"mcp-only.v1","actual_tools":source.len(),
        "provider_tool_schema_sha256":first,"outside_bound_requests_checked":turns.len(),
        "builtin_tools":0,"mounted_tools":0}))
}

fn helper(binding: &Value, name: &str, digest: &str, mode: u32) -> Result<()> {
    let rows: Vec<_> = array(&binding["public_helpers"]["files"], 32)?
        .iter()
        .filter(|r| r["name"] == name)
        .collect();
    require(
        rows.len() == 1
            && rows[0]["sha256"] == digest
            && rows[0]["uid"] == 0
            && rows[0]["gid"] == 0
            && rows[0]["mode"] == mode
            && rows[0]["bytes"].as_u64().is_some_and(|n| n > 0)
            && ["device", "inode"]
                .iter()
                .all(|k| rows[0][*k].as_u64().is_some_and(|n| n > 0)),
    )
}
fn episode(report: &Value, protected: bool, artifacts: &Value) -> Result<Value> {
    let spec = feature_ai_support_spec()?;
    let model = &array(&artifacts["provider_turns"], 64)?
        .first()
        .ok_or(invalid("live provider turn absent"))?["usage"]["model_id"];
    let endpoints = ["crm", "docs", "mail", "tickets"].into_iter().map(|family| (family.to_owned(), json!({
        "command":"/usr/bin/python3","args":["/runtime/public/service_relay.py","--socket",format!("/runtime/resources/{family}.sock")],
        "env":{},"type":"stdio","envPolicy":"literal","cwd":"/runtime/home/project","timeout":30000,
        "requestIdFormat":"string","instructions":false}))).collect::<serde_json::Map<_,_>>();
    let mut value = json!({"schema":"developer-omp-episode.v3","builtinToolProfile":"mcp-only.v1",
        "sdkRoot":"/sdk/node_modules/@oh-my-pi/pi-coding-agent","workspace":"/runtime/home/project",
        "agentDir":"/runtime/agent","modelId":model,"prompt":spec["task_prompt"],"deadlineSeconds":900,
        "maxToolCalls":128,"maxModelTokens":100_000,"sdkGate":"/runtime/sdk-gate/ready.sock",
        "resourceEndpoints":endpoints,"startupProfile":"bun-1.3.14-sealed-v1"});
    if protected {
        value["guardExtension"] = json!("/runtime/public/builtin_guard_bridge.ts");
    }
    require(report["spec_sha256"] == hash(&spec)?)?;
    Ok(value)
}
fn negatives(binding: &Value, identity: &Value) -> Result<()> {
    let mut pids = BTreeSet::new();
    for (name, schema, refused) in [
        (
            "same_uid_negative",
            "sdk-same-uid-peer-control.v1",
            "rejected",
        ),
        (
            "mcp_same_uid_negative",
            "sdk-mcp-same-uid-peer-control.v1",
            "rejected_before_native_forward",
        ),
    ] {
        let row = &binding[name];
        let peer = &row["outside"]["kernel_peer"];
        require(
            row["refused_before_sdk_import"] == true
                && row["unprivileged_result"]["schema"] == schema
                && row["unprivileged_result"]["uid"] == 10001
                && row["unprivileged_result"]["denied"] == true
                && row["outside"][refused] == true
                && peer["schema"] == "hol-gauntlet-sdk-wire-peer.v1"
                && peer["uid"] == 10001
                && peer["gid"] == 10001
                && peer["cgroup"] == identity["cgroup"]
                && peer["pid"] == row["outside"]["pid"]
                && peer["pid"] != identity["pid"]
                && peer["start_ticks"].as_u64().is_some_and(|n| n > 0)
                && peer["pid"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && pids.insert(n)),
        )?;
    }
    Ok(())
}

pub(super) fn sdk(artifacts: &Value, context: &Value, report: &Value) -> Result<Value> {
    require(context["schema"] == "hol-gauntlet-native-live-context.v2")?;
    let binding = &context["binding"];
    let peer = &binding["peer"];
    let identity = &peer["identity"];
    let agent = &context["agent"];
    let terminal = &context["sdk_terminal"];
    require(
        report["pre_import_binding_sha256"] == hash(binding)?
            && binding["schema"] == "hol-gauntlet-native-sdk-pre-import-binding.v4"
            && peer["schema"] == "hol-gauntlet-native-sdk-executable-peer.v2"
            && peer["startup"]["schema"] == "hol-gauntlet-native-sdk-startup.v2"
            && binding["public_helpers"]["schema"] == "hol-gauntlet-native-sdk-public-helpers.v3"
            && peer["executable_sha256"] == report["sdk_pins"]["bun_sha256"]
            && identity["pid"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= u32::MAX as u64)
            && identity["start_ticks"].as_u64().is_some_and(|n| n > 0)
            && exact_keys(
                terminal,
                &[
                    "returncode",
                    "signal",
                    "timed_out",
                    "pid",
                    "start_ticks",
                    "status_source",
                    "cleanup_complete",
                    "cleanup_error",
                    "stderr_sha256",
                ],
            )
            && terminal["returncode"] == 0
            && terminal["signal"].is_null()
            && terminal["timed_out"] == false
            && terminal["status_source"] == "owned-podman-exec-kernel-exit.v1"
            && terminal["pid"] == identity["pid"]
            && terminal["start_ticks"] == identity["start_ticks"]
            && terminal["cleanup_complete"] == true
            && terminal["cleanup_error"].is_null()
            && terminal["stderr_sha256"].as_str().is_some_and(is_sha256)
            && agent["schema"] == "hol-gauntlet-native-sdk-agent-owner.v1"
            && agent["job_id"] == report["job_id"]
            && agent["cleanup_complete"] == true
            && agent["container_id"] == peer["agent"]["container_id"]
            && agent["inspection"]["Id"] == agent["container_id"]
            && agent["inspection"]["Image"]
                == report["sdk_pins"]["agent_image_id"]
                    .as_str()
                    .and_then(|s| s.strip_prefix("sha256:"))
                    .unwrap_or("")
            && agent["inspection"]["HostConfig"]["NetworkMode"] == "none"
            && agent["inspection"]["HostConfig"]["Privileged"] == false
            && agent["inspection"]["HostConfig"]["ReadonlyRootfs"] == true,
    )?;
    for key in ["cgroup", "lsm_label", "namespaces"] {
        require(identity.get(key).is_some() && identity[key] == peer["agent"]["identity"][key])?;
    }
    crate::legacy_bash_case::legacy_sdk_status(&identity["status"])?;
    crate::native_process_public::sdk_assets(binding, &report["sdk_pins"])?;
    crate::native_launch_provenance::sdk_startup(
        peer,
        &report["sdk_pins"],
        &binding["public_helpers"],
    )?;
    for (name, raw) in [
        (
            "developer_omp_episode.ts",
            include_bytes!("../../../../gauntlet/benchmark/developer_omp_episode.ts").as_slice(),
        ),
        (
            "builtin_guard_bridge.ts",
            include_bytes!("../../../../gauntlet/benchmark/builtin_guard_bridge.ts").as_slice(),
        ),
        (
            "service_relay.py",
            include_bytes!("../../../../gauntlet/benchmark/service_relay.py").as_slice(),
        ),
    ] {
        helper(binding, name, &sha256(raw), 0o444)?;
    }
    helper(
        binding,
        "episode.json",
        &hash(&episode(
            report,
            report["control_role"] == "feature-ai-protected",
            artifacts,
        )?)?,
        0o444,
    )?;
    helper(
        binding,
        "gauntlet-vm-worker",
        context["worker_generation"]
            .as_str()
            .filter(|s| is_sha256(s))
            .ok_or(invalid("outside live worker generation absent"))?,
        0o555,
    )?;
    negatives(binding, identity)?;
    let inventory = inventory(artifacts, context)?;
    let budget = &context["budget"];
    let calls = array(&artifacts["native_calls"], 128)?;
    let events = array(&budget["events"], 128)?;
    require(
        budget["schema"] == "hol-gauntlet-native-shared-operation-budget.v1"
            && budget["limit"] == 128
            && budget["used"] == events.len()
            && budget["mcp"] == events.len()
            && budget["builtin"] == 0
            && budget["pending"] == json!([])
            && events.len() == calls.len(),
    )?;
    for (event, call) in events.iter().zip(calls) {
        let request = &call["request"];
        let operation = request["params"]["name"].as_str().unwrap_or("");
        require(
            event["surface"] == "mcp"
                && event["family"] == operation.split('.').next().unwrap_or("")
                && event["method"] == "tools/call"
                && event["request_id"] == request["id"]
                && event["frame_sha256"] == hash(request)?
                && event["response_completed"] == true
                && event["response_sha256"] == hash(&call["native_response"])?
                && event["backend_reached"] == !call["upstream_request"].is_null(),
        )?;
    }
    Ok(
        json!({"schema":"hol-gauntlet-mcp-only-sdk-admission.v1","inventory":inventory,
        "actual_sdk_startup_and_terminal_bound":true,"observed_operations":calls.len()}),
    )
}

#[cfg(test)]
pub(super) fn framed_turn_fixture(request: &Value, response: &Value) -> Value {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let request_raw = canonical_value(request).unwrap();
    let response_raw = canonical_value(response).unwrap();
    let (source, provider, cell, budget) = (
        "a".repeat(40),
        "b".repeat(16),
        "c".repeat(16),
        "d".repeat(64),
    );
    let before = json!({"quota":"before"});
    let after = json!({"quota":"after"});
    let usage = json!({"schema":"hol-gauntlet-rust-provider-usage.v1","source_sha":source,
        "provider_job_id":provider,"cell_job_id":cell,"budget_digest":budget,"turn":1,
        "request_sha256":sha256(&request_raw),"response_sha256":sha256(&response_raw),
        "response_bytes":response_raw.len(),"model_id":request["model"],"reservation_id":"e".repeat(32),
        "prepared_input_sha256":"f".repeat(64),"prompt_tokens":3,"output_tokens":2,"complete":true,
        "quota_before_sha256":"1".repeat(64),"quota_after_sha256":"2".repeat(64),
        "quota_journal_before":"3".repeat(64),"quota_journal_after":"4".repeat(64),
        "quota_requests_before":0,"quota_requests_after":1,"qualification_eligible":false});
    let frame = |value: Value| {
        format!(
            "{}\n",
            String::from_utf8(canonical_value(&value).unwrap()).unwrap()
        )
    };
    json!({"request":frame(json!({"schema":"hol-gauntlet-native-live-model-request.v1",
        "source_sha":source,"provider_job_id":provider,"job_id":cell,"budget_digest":budget,
        "turn":1,"request_sha256":usage["request_sha256"],"body_b64":STANDARD.encode(&request_raw)})),
        "response":frame(json!({"schema":"hol-gauntlet-native-live-model-response.v1",
        "source_sha":source,"provider_job_id":provider,"job_id":cell,"budget_digest":budget,
        "turn":1,"request_sha256":usage["request_sha256"],"response_sha256":usage["response_sha256"],
        "body_b64":STANDARD.encode(&response_raw),"usage_receipt":usage,"before":before,"after":after})),
        "usage":usage,"before":before,"after":after})
}

#[cfg(test)]
#[test]
fn framed_provider_responses_bind_sdk_tool_calls_and_refuse_tampering() {
    let args = json!({"record_id":"ticket-a"});
    let call = json!({"type":"toolCall","id":"call-1","name":"mcp__docs_read","arguments":args});
    let events = vec![json!({"type":"agent_event","event":{"type":"message_end",
        "message":{"role":"assistant","content":[call]}}})];
    let request = json!({"model":"fixture-model"});
    let mut response = json!({"choices":[{"message":{"tool_calls":[{"id":"call-1",
        "type":"function","function":{"name":"mcp__docs_read","arguments":args.to_string()}}]}}]});
    let turn = framed_turn_fixture(&request, &response);
    let artifacts = json!({"provider_turns":[turn]});
    let projected = super::projection::normalized_sdk_events(&events, &artifacts).unwrap();
    assert_eq!(
        projected[0]["calls"][0],
        json!({"id":"call-1","name":"mcp__docs_read","arguments":args})
    );
    let mut changed = artifacts.clone();
    changed["provider_turns"][0]["usage"]["response_sha256"] = json!("0".repeat(64));
    assert!(super::projection::normalized_sdk_events(&events, &changed).is_err());
    response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] =
        json!(json!({"record_id":"other"}).to_string());
    changed["provider_turns"][0] = framed_turn_fixture(&request, &response);
    assert!(super::projection::normalized_sdk_events(&events, &changed).is_err());
}
