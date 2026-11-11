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
