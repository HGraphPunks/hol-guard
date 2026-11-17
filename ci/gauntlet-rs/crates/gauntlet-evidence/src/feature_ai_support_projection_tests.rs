use super::*;

fn display(result: &Value) -> Result<Value> {
    let wire = String::from_utf8(canonical_value(&json!({"result":result}))?).unwrap();
    displayed_content(result, &wire)
}

#[test]
fn optional_projection_is_source_declared_and_preserves_real_values() {
    assert_eq!(project_feature_ai_mcp_arguments("docs","docs.search",&json!({"i":"search","intent":"retained","collection":"docs.documents","query":"","cursor":{},"fields":[],"tenant_id":null,"limit":0,"unknown":""})).unwrap(),
        json!({"intent":"retained","collection":"docs.documents","fields":[],"tenant_id":null,"limit":0,"unknown":""}));
    assert_eq!(project_feature_ai_mcp_arguments("mail","mail.create",&json!({"i":{},"collection":"mail.drafts","record_id":"","data":{},"idempotency_key":"","tenant_id":false})).unwrap(),
        json!({"collection":"mail.drafts","record_id":"","data":{},"tenant_id":false}));
    assert_eq!(
        project_feature_ai_mcp_arguments(
            "docs",
            "docs.read",
            &json!({"record_id":"local://unchanged","fields":{}})
        )
        .unwrap(),
        json!({"record_id":"local://unchanged"})
    );
    assert!(project_feature_ai_mcp_arguments("docs", "tickets.read", &json!({})).is_err());
    assert!(project_feature_ai_mcp_arguments("unknown", "unknown.read", &json!({})).is_err());
}

#[test]
fn sdk_display_retains_raw_error_and_original_structured_payload() {
    let raw = json!({"content":[{"type":"text","text":"blocked"},{"type":"text","text":"details"}],"isError":true});
    assert_eq!(
        display(&raw).unwrap(),
        json!([{"type":"text","text":"Error: blocked\n\ndetails"}])
    );
    assert_eq!(raw["content"][0]["text"], "blocked");
    let structured = json!({"content":[{"type":"text","text":" {\"record\":{\"id\":\"ticket-a\"}} "}],"structuredContent":{"record":{"id":"ticket-a"}},"isError":false});
    assert_eq!(display(&structured).unwrap(), structured["content"]);
    let mut substituted = structured;
    substituted["structuredContent"]["record"]["id"] = json!("other");
    assert_eq!(display(&substituted).unwrap().as_array().unwrap().len(), 2);
    assert!(
        display(&json!({"content":[{"type":"image","data":"opaque"}],"isError":false})).is_err()
    );
}

#[test]
fn json_rpc_identity_keeps_integer_and_string_distinct_and_refuses_ambiguity() {
    for value in [json!("1"), json!(1), json!(-1), json!(0)] {
        assert!(request_id(&value));
    }
    for value in [
        json!(null),
        json!(true),
        json!(1.0),
        json!(1.5),
        json!(""),
        json!({}),
    ] {
        assert!(!request_id(&value));
    }
    assert_ne!(json!("1"), json!(1));
}

#[test]
fn captured_catalog_requires_actual_exact_bytes_and_source_tools() {
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
    let response = json!({"jsonrpc":"2.0","id":1,"result":{"tools":tools("docs").unwrap()}});
    let frame = |direction: &str, value: &Value| {
        let raw = String::from_utf8(canonical_value(value).unwrap()).unwrap();
        json!({"direction":direction,"wire_utf8":raw,"sha256":sha256(raw.as_bytes()),"frame":value})
    };
    let mut context = json!({"mcp":{"frontends":[{"family":"docs","frames":[frame("sdk-request",&request),frame("native-response",&response)]}]}});
    captured_catalog(&context, "docs").unwrap();
    context["mcp"]["frontends"][0]["frames"][1]["sha256"] = json!("0".repeat(64));
    assert!(captured_catalog(&context, "docs").is_err());
    context["mcp"]["frontends"][0]["frames"][1] = frame(
        "native-response",
        &json!({"jsonrpc":"2.0","id":1,"result":{"tools":[]}}),
    );
    assert!(captured_catalog(&context, "docs").is_err());
}

#[test]
fn genuine_locked_sdk_outputs_and_outbound_arguments_match_closed_projection() {
    let raw = include_bytes!("../tests/fixtures/omp_mcp_bridge_observed_v1.json");
    assert_eq!(
        sha256(raw),
        "e86c661ece57ab54c068f44dc7be82c0d4d462b7b2568d55435e3c9b00454a98"
    );
    let reference: Value = serde_json::from_slice(raw).unwrap();
    assert_eq!(
        reference["capture_sha256"],
        "4185bce32f05614e3984b1d4310ce2f245a8c98a47fa9b84768dac14d92a0b25"
    );
    assert_eq!(
        sha256(include_bytes!(
            "../tests/fixtures/omp_mcp_bridge_conformance.v1.ts"
        )),
        reference["input_fixture_sha256"]
    );
    let observation = &reference["observation"];
    assert_eq!(observation["catalog_sha256"], CATALOG_SHA);
    assert_eq!(observation["model_requests"], 0);
    assert_eq!(observation["qualification_eligible"], false);
    let args = json!({"collection":"docs.documents","i":"internal intent","intent":"retained data","query":"","cursor":{},"fields":[],"tenant_id":null});
    let projected = project_feature_ai_mcp_arguments("docs", "docs.search", &args).unwrap();
    let rows = observation["observations"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        assert_eq!(row["wire"].as_array().unwrap().len(), 1);
        assert_eq!(row["wire"][0]["method"], "tools/call");
        assert_eq!(
            row["wire"][0]["params"],
            json!({"name":"docs.search","arguments":projected})
        );
        assert_eq!(
            display(&row["result"]).unwrap(),
            row["output"]["content"],
            "{}",
            row["name"]
        );
        assert_eq!(
            row["output"]["details"]["rawContent"],
            row["result"]["content"]
        );
        assert_eq!(
            row["output"]["details"].get("structuredContent"),
            row["result"].get("structuredContent")
        );
        assert_eq!(
            row["output"]["details"]["isError"],
            row["result"]["isError"]
        );
    }
}

#[test]
fn structured_rendering_refuses_unknown_wire_order_numbers_and_content() {
    let result = json!({"content":[{"type":"text","text":"summary"}],"isError":false,"structuredContent":{"z":1,"a":2}});
    assert!(displayed_content(&result,r#"{"result":{"structuredContent":{"z":1,"a":2},"isError":false,"content":[{"type":"text","text":"summary"}]}}"#).is_err());
    assert!(displayed_content(&result, r#"{"result":{}}"#).is_err());
    for structured in [
        json!({"number":1.5}),
        json!({"number":9_007_199_254_740_992_u64}),
        json!([1, 2]),
    ] {
        let mut altered = result.clone();
        altered["structuredContent"] = structured;
        assert!(display(&altered).is_err());
    }
    for part in [
        json!({"type":"image","data":"opaque"}),
        json!({"type":"resource","resource":{"uri":"local://unobserved","text":"text"}}),
    ] {
        let mut altered = result.clone();
        altered["content"] = json!([part]);
        assert!(display(&altered).is_err());
    }
}

fn wire_reference() -> Value {
    let raw = include_bytes!("../tests/fixtures/omp_mcp_wire_observed_v1.json");
    assert_eq!(
        sha256(raw),
        "da521f87183b20172ed331aa08fb2f8677e02072ec0ddd935a9043371e408fbe"
    );
    serde_json::from_slice(raw).unwrap()
}

fn admission_inventory() -> (Value, Value) {
    let mut mapping = Vec::new();
    let mut fronts = Vec::new();
    for family in ["crm", "docs", "mail", "tickets"] {
        let definitions = tools(family).unwrap();
        for tool in definitions.as_array().unwrap() {
            let name = format!("mcp__{}", tool["name"].as_str().unwrap().replace('.', "_"));
            mapping.push(json!({"name":name,"server":family,"rawTool":tool["name"]}));
        }
        let request = json!({"jsonrpc":"2.0","id":format!("catalog-{family}"),"method":"tools/list","params":{}});
        let response = json!({"jsonrpc":"2.0","id":request["id"],"result":{"tools":definitions}});
        let frames = [("sdk-request",request),("native-response",response)].into_iter().map(|(direction,frame)| {
            let raw = String::from_utf8(canonical_value(&frame).unwrap()).unwrap();
            json!({"direction":direction,"frame":frame,"wire_utf8":raw,"sha256":sha256(raw.as_bytes())})
        }).collect::<Vec<_>>();
        fronts.push(json!({"family":family,"frames":frames}));
    }
    let names = mapping
        .iter()
        .map(|m| m["name"].clone())
        .collect::<Vec<_>>();
    let reference = wire_reference();
    let observed = &reference["observation"];
    assert_eq!(observed["resourceTools"], json!(mapping));
    let declarations = &observed["tools"];
    let model = &observed["model_id"];
    let start = json!({"type":"episode_start","schema":"hol-gauntlet-developer-episode-start.v2",
        "episodeSchema":"developer-omp-episode.v3","builtinToolProfile":"mcp-only.v1","harness":"omp",
        "version":"18.4.12","agentUid":10001,"qualification":false,"guardExtensionAttached":true,
        "activeTools":names,"enabledTools":names,"mountedXdevTools":[],"resourceTools":mapping,"model":model});
    (
        json!({"sdk_events":format!("{start}\n"),"provider_turns":[{"request":json!({"model":model,"tools":declarations}).to_string(),"response":"{}"}]}),
        json!({"mcp":{"protected":true,"frontends":fronts}}),
    )
}

#[test]
fn mcp_only_inventory_joins_actual_getters_to_all_outside_model_declarations() {
    let (artifacts, context) = admission_inventory();
    let observed = super::super::admission::inventory(&artifacts, &context).unwrap();
    assert_eq!(observed["builtin_tools"], 0);
    assert_eq!(observed["mounted_tools"], 0);
    assert_eq!(observed["outside_bound_requests_checked"], 1);
    for variant in [
        "builtin", "enabled", "mounted", "mapping", "schema", "intent", "hidden", "new-turn",
    ] {
        let mut changed = artifacts.clone();
        let mut start: Value =
            serde_json::from_str(changed["sdk_events"].as_str().unwrap().trim()).unwrap();
        let mut request: Value =
            serde_json::from_str(changed["provider_turns"][0]["request"].as_str().unwrap())
                .unwrap();
        match variant {
            "builtin" => start["activeTools"]
                .as_array_mut()
                .unwrap()
                .push(json!("bash")),
            "enabled" => {
                start["enabledTools"].as_array_mut().unwrap().pop();
            }
            "mounted" => start["mountedXdevTools"] = json!(["xd://hidden/bash"]),
            "mapping" => start["resourceTools"][0]["rawTool"] = json!("unobserved.tool"),
            "schema" => {
                request["tools"][0]["function"]["parameters"]["additionalProperties"] = json!(true)
            }
            "intent" => {
                request["tools"][0]["function"]["parameters"]["properties"]["i"]["type"] =
                    json!("object")
            }
            "hidden" => request["tools"]
                .as_array_mut()
                .unwrap()
                .push(json!({"type":"function","function":{
                "name":"bash","description":"undeclared tool","parameters":{"type":"object"}}})),
            "new-turn" => {
                let mut next = request.clone();
                next["tools"].as_array_mut().unwrap().pop();
                changed["provider_turns"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"request":next.to_string(),"response":"{}"}));
            }
            _ => unreachable!(),
        }
        changed["sdk_events"] = json!(format!("{start}\n"));
        changed["provider_turns"][0]["request"] = json!(request.to_string());
        assert!(
            super::super::admission::inventory(&changed, &context).is_err(),
            "{variant}"
        );
    }
    let mut request: Value =
        serde_json::from_str(artifacts["provider_turns"][0]["request"].as_str().unwrap()).unwrap();
    let mut framed = artifacts.clone();
    framed["provider_turns"][0] =
        super::super::admission::framed_turn_fixture(&request, &json!({}));
    assert_eq!(
        super::super::admission::inventory(&framed, &context).unwrap(),
        observed
    );
    let mut changed = framed.clone();
    changed["provider_turns"][0]["before"]["quota"] = json!("substituted");
    assert!(super::super::admission::inventory(&changed, &context).is_err());
    request["tools"][0]["function"]["parameters"]["additionalProperties"] = json!(true);
    framed["provider_turns"][0] =
        super::super::admission::framed_turn_fixture(&request, &json!({}));
    assert!(super::super::admission::inventory(&framed, &context).is_err());
}

#[test]
fn unavailable_native_decision_and_policy_label_are_only_error_observations() {
    let reference = wire_reference();
    assert_eq!(
        reference["capture_sha256"],
        "5995068375fb49a927201e1948ec7d0e3b05fae30b79734d0e1cf65a72fb9ca1"
    );
    assert_eq!(
        reference["source_sha256"]["mcp_errors"],
        "f8b24cad63b67037b92e379bf4d4f43e0c0d95de154dae9ba0676c5c3d120e1c"
    );
    let observed = &reference["observation"];
    assert_eq!(observed["model_requests"], 0);
    assert_eq!(observed["network_requests"], 0);
    assert_eq!(observed["error_fixture_calls"], 3);
    assert_eq!(observed["error_observations"].as_array().unwrap().len(), 3);
    for row in observed["error_observations"].as_array().unwrap() {
        let response = &row["response"];
        let content = displayed_rpc_error(
            response,
            row["response_wire"].as_str().unwrap(),
            "docs",
            "docs.read",
        )
        .unwrap();
        assert_eq!(content, row["output"]["content"], "{}", row["name"]);
        assert_eq!(row["output"]["isError"], true);
        assert_eq!(
            row["output"]["details"],
            json!({"serverName":"docs","mcpToolName":"docs.read","isError":true})
        );
        // All three actual SDK outputs carry the same action label, including
        // unavailable Native decisions. This observation grants no block credit.
        assert_eq!(response["error"]["data"]["guardPolicyAction"], "block");
        let mut changed = response.clone();
        changed["error"]["data"]["approvalRequests"] = json!([{"id":"pending"}]);
        let raw = String::from_utf8(canonical_value(&changed).unwrap()).unwrap();
        assert!(displayed_rpc_error(&changed, &raw, "docs", "docs.read").is_err());
    }
    let redacted = json!({"error":{"code":-32001,"message":"Authorization: Bearer sensitive"}});
    let raw = String::from_utf8(canonical_value(&redacted).unwrap()).unwrap();
    assert!(displayed_rpc_error(&redacted, &raw, "docs", "docs.read").is_err());
}

fn sealed_admission() -> (Value, Value, Value) {
    let (mut artifacts, mut context) = admission_inventory();
    let model = wire_reference()["observation"]["model_id"].clone();
    artifacts["provider_turns"][0]["usage"] = json!({"model_id":model});
    artifacts["native_calls"] = json!([]);
    let bun = "37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086";
    let generation = "1".repeat(64);
    let pins = json!({"schema":"hol-gauntlet-native-sdk-pins.v1","bun_sha256":bun,
        "sdk_tree_sha256":"2".repeat(64),"publication_sha256":"3".repeat(64),"agent_image_id":format!("sha256:{}","4".repeat(64))});
    let environment = json!({"HOME":"/runtime/home","PATH":"/usr/bin:/bin","TMPDIR":"/tmp","XDG_CONFIG_HOME":"/runtime/public",
        "BUN_RUNTIME_TRANSPILER_CACHE_PATH":"0","DO_NOT_TRACK":"1","NO_COLOR":"1"});
    let argv = json!([
        "/runtime/bun",
        "--no-env-file",
        "--no-install",
        "--config=/runtime/public/bunfig.toml",
        "--cwd=/runtime/public",
        "/runtime/public/developer_omp_episode.ts",
        "/runtime/public/episode.json"
    ]);
    let mut report = json!({"job_id":"fixture-job","control_role":"feature-ai-protected",
        "spec_sha256":hash(&feature_ai_support_spec().unwrap()).unwrap(),"sdk_pins":pins});
    let endpoints = ["crm", "docs", "mail", "tickets"].into_iter().map(|family| (family.to_owned(), json!({
        "command":"/usr/bin/python3","args":["/runtime/public/service_relay.py","--socket",format!("/runtime/resources/{family}.sock")],
        "env":{},"type":"stdio","envPolicy":"literal","cwd":"/runtime/home/project","timeout":30000,
        "requestIdFormat":"string","instructions":false}))).collect::<serde_json::Map<_,_>>();
    let episode = json!({"schema":"developer-omp-episode.v3","builtinToolProfile":"mcp-only.v1",
        "sdkRoot":"/sdk/node_modules/@oh-my-pi/pi-coding-agent","workspace":"/runtime/home/project",
        "agentDir":"/runtime/agent","modelId":model,"prompt":feature_ai_support_spec().unwrap()["task_prompt"],
        "deadlineSeconds":900,"maxToolCalls":128,"maxModelTokens":100_000,"sdkGate":"/runtime/sdk-gate/ready.sock",
        "resourceEndpoints":endpoints,"startupProfile":"bun-1.3.14-sealed-v1","guardExtension":"/runtime/public/builtin_guard_bridge.ts"});
    let file = |name: &str, raw: &[u8], inode, mode| {
        json!({"name":name,"sha256":sha256(raw),"bytes":raw.len(),
        "device":1,"inode":inode,"uid":0,"gid":0,"mode":mode})
    };
    let files = vec![
        file(
            "bunfig.toml",
            b"preload = [\"/runtime/public/startup-noop.mjs\"]\n",
            3,
            0o444,
        ),
        file("startup-noop.mjs", b"export {};\n", 4, 0o444),
        file(
            "developer_omp_episode.ts",
            include_bytes!("../../../../gauntlet/benchmark/developer_omp_episode.ts"),
            5,
            0o444,
        ),
        file(
            "builtin_guard_bridge.ts",
            include_bytes!("../../../../gauntlet/benchmark/builtin_guard_bridge.ts"),
            6,
            0o444,
        ),
        file(
            "service_relay.py",
            include_bytes!("../../../../gauntlet/benchmark/service_relay.py"),
            7,
            0o444,
        ),
        file(
            "episode.json",
            &canonical_value(&episode).unwrap(),
            8,
            0o444,
        ),
        json!({"name":"gauntlet-vm-worker","sha256":generation,"bytes":1024,"device":1,"inode":9,"uid":0,"gid":0,"mode":0o555}),
    ];
    let mut config = files[0].clone();
    let mut preload = files[1].clone();
    config["mount_flags"] = json!(1);
    preload["mount_flags"] = json!(1);
    let mut status = json!({"Uid":"10001 10001 10001 10001","Gid":"10001 10001 10001 10001","Groups":"10001",
        "NoNewPrivs":"1","Seccomp":"2","Seccomp_filters":"1"});
    for key in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
        status[key] = json!("0000000000000000");
    }
    let identity = json!({"pid":100,"start_ticks":23,"cgroup":"/fixture/sdk","lsm_label":"crun (enforce)",
        "namespaces":{"pid":123,"mnt":124},"status":status});
    let negative = |pid: u32, schema: &str, rejected: &str| {
        json!({"refused_before_sdk_import":true,
        "unprivileged_result":{"schema":schema,"uid":10001,"denied":true},
        "outside":{"pid":pid,rejected:true,"kernel_peer":{"schema":"hol-gauntlet-sdk-wire-peer.v1",
            "pid":pid,"start_ticks":24,"uid":10001,"gid":10001,"cgroup":"/fixture/sdk"}}})
    };
    let binding = json!({"schema":"hol-gauntlet-native-sdk-pre-import-binding.v4",
        "peer":{"schema":"hol-gauntlet-native-sdk-executable-peer.v2","identity":identity,"executable_sha256":bun,
            "argv_sha256":sha256(argv.as_array().unwrap().iter().map(|v|v.as_str().unwrap()).collect::<Vec<_>>().join("\0").as_bytes()),
            "agent":{"container_id":"fixture-container","identity":identity},
            "startup":{"schema":"hol-gauntlet-native-sdk-startup.v2","profile":"bun-1.3.14-sealed-v1","bun_sha256":bun,
                "argv":argv,"cwd":{"device":1,"inode":2,"uid":0,"gid":0,"mode":0o755,"mount_flags":1},
                "public_directory":{"device":1,"inode":2,"uid":0,"gid":0,"mode":0o755},"environment":environment,
                "environment_sha256":hash(&environment).unwrap(),"config":config,"preload":preload}},
        "public_helpers":{"schema":"hol-gauntlet-native-sdk-public-helpers.v3","files":files},
        "assets":{"schema":"hol-gauntlet-verified-native-sdk-assets.v1","pins":pins,"sdk_version":"18.4.12",
            "actual_tree_and_bun_verified":true,"sdk_imported":false,"execution_eligible":false,"sdk_entries":10,"sdk_bytes":1024,
            "directory":format!("/opt/hol-gauntlet/sdk-assets/{}-{bun}","2".repeat(64))},
        "same_uid_negative":negative(101,"sdk-same-uid-peer-control.v1","rejected"),
        "mcp_same_uid_negative":negative(102,"sdk-mcp-same-uid-peer-control.v1","rejected_before_native_forward")});
    context["schema"] = json!("hol-gauntlet-native-live-context.v2");
    context["worker_generation"] = json!(generation);
    context["binding"] = binding;
    context["agent"] = json!({"schema":"hol-gauntlet-native-sdk-agent-owner.v1","job_id":"fixture-job","cleanup_complete":true,
        "container_id":"fixture-container","inspection":{"Id":"fixture-container","Image":"4".repeat(64),
            "HostConfig":{"NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true}}});
    context["sdk_terminal"] = json!({"returncode":0,"signal":null,"timed_out":false,"pid":100,"start_ticks":23,
        "status_source":"owned-podman-exec-kernel-exit.v1","cleanup_complete":true,"cleanup_error":null,"stderr_sha256":sha256(b"")});
    context["budget"] = json!({"schema":"hol-gauntlet-native-shared-operation-budget.v1","limit":128,
        "used":0,"mcp":0,"builtin":0,"pending":[],"events":[]});
    report["pre_import_binding_sha256"] = json!(hash(&context["binding"]).unwrap());
    (artifacts, context, report)
}

#[test]
fn sealed_mcp_only_admission_requires_actual_terminal_custody_and_isolation() {
    let (artifacts, context, report) = sealed_admission();
    let admitted = super::super::admission::sdk(&artifacts, &context, &report).unwrap();
    assert_eq!(admitted["actual_sdk_startup_and_terminal_bound"], true);
    for (path, value) in [
        ("/schema", json!("hol-gauntlet-native-live-context.v1")),
        ("/sdk_terminal/returncode", Value::Null),
        ("/sdk_terminal/status_source", Value::Null),
        ("/sdk_terminal/timed_out", json!(true)),
        ("/sdk_terminal/start_ticks", json!(24)),
        ("/sdk_terminal/cleanup_complete", json!(false)),
        ("/agent/cleanup_complete", json!(false)),
        ("/agent/inspection/HostConfig/NetworkMode", json!("host")),
        (
            "/binding/peer/identity/status/CapEff",
            json!("0000000000000001"),
        ),
        (
            "/binding/peer/startup/config/sha256",
            json!(sha256(b"preload = []\n")),
        ),
        (
            "/binding/public_helpers/files/2/sha256",
            json!("0".repeat(64)),
        ),
        (
            "/binding/mcp_same_uid_negative/outside/rejected_before_native_forward",
            json!(false),
        ),
        ("/budget/builtin", json!(1)),
    ] {
        let mut changed = context.clone();
        *changed.pointer_mut(path).unwrap() = value;
        let mut bound = report.clone();
        bound["pre_import_binding_sha256"] = json!(hash(&changed["binding"]).unwrap());
        assert!(
            super::super::admission::sdk(&artifacts, &changed, &bound).is_err(),
            "{path}"
        );
    }
    let mut changed = report.clone();
    changed["pre_import_binding_sha256"] = json!("0".repeat(64));
    assert!(super::super::admission::sdk(&artifacts, &context, &changed).is_err());
}
