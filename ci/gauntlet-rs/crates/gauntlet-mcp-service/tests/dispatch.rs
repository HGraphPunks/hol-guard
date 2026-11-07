use base64::{engine::general_purpose::STANDARD as B64, Engine};
use gauntlet_mcp_service::{
    Family, OperationError, Operations, Session, TransportError, CATALOG_SHA256, MAX_FRAME_BYTES,
    MAX_SESSION_MESSAGES,
};
use gauntlet_world::World;
use ring::signature::Ed25519KeyPair;
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct Spy {
    calls: Vec<(String, Value, Value)>,
    result: Option<Value>,
    remaining: Option<usize>,
}
impl Operations for Spy {
    fn call(&mut self, operation: &str, args: &Value, id: Value) -> Result<Value, OperationError> {
        if self.remaining == Some(0) {
            return Err(OperationError {
                category: "budget".into(),
                message: "operation budget exhausted".into(),
            });
        }
        if let Some(n) = &mut self.remaining {
            *n -= 1;
        }
        self.calls.push((operation.into(), args.clone(), id));
        Ok(self.result.clone().unwrap_or_else(|| json!({"ok":true})))
    }
}
fn request(
    session: &mut Session,
    backend: &mut impl Operations,
    id: Value,
    method: &str,
    params: Value,
) -> Value {
    session
        .process(
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
                .to_string()
                .as_bytes(),
            backend,
        )
        .unwrap()
        .unwrap()
}
fn ready(family: Family, backend: &mut impl Operations) -> Session {
    let mut session = Session::new(family).unwrap();
    let result = request(
        &mut session,
        backend,
        json!(0),
        "initialize",
        json!({"protocolVersion":"2025-11-25","clientInfo":{"name":"interop","version":"1"},"capabilities":{}}),
    );
    assert_eq!(result["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        result["result"]["serverInfo"]["version"],
        "gauntlet-rust-mcp.v1"
    );
    assert!(session
        .process(
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            backend
        )
        .unwrap()
        .is_none());
    session
}
fn world() -> World {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../gauntlet-world/tests/python_world_20261027.json"
    ))
    .unwrap();
    let seed = B64
        .decode(fixture["public_test_seed_base64"].as_str().unwrap())
        .unwrap();
    World::initialize(
        Connection::open_in_memory().unwrap(),
        fixture["initial_snapshot_json"].as_str().unwrap(),
        Ed25519KeyPair::from_seed_unchecked(&seed).unwrap(),
    )
    .unwrap()
}

#[test]
fn all_41_tool_schemas_match_the_actual_pinned_python_catalog() {
    let raw = include_bytes!("../catalog-python-mcp-1.30.0.v1.json");
    assert_eq!(format!("{:x}", Sha256::digest(raw)), CATALOG_SHA256);
    let expected: Value = serde_json::from_slice(raw).unwrap();
    let mut count = 0;
    for name in [
        "mail", "crm", "calendar", "docs", "tables", "chat", "tickets",
    ] {
        let mut spy = Spy::default();
        let mut session = ready(Family::parse(name).unwrap(), &mut spy);
        let result = request(&mut session, &mut spy, json!(1), "tools/list", json!({}));
        assert_eq!(result["result"]["tools"], expected["families"][name]);
        count += result["result"]["tools"].as_array().unwrap().len();
        assert!(spy.calls.is_empty());
    }
    assert_eq!(count, 41);
}

#[test]
fn invalid_tools_parameters_and_nonliteral_integers_never_reach_the_provider() {
    let mut spy = Spy::default();
    let mut session = ready(Family::Docs, &mut spy);
    for params in [
        json!({"name":"mail.send","arguments":{"record_id":"mail-0","expected_version":1}}),
        json!({"name":"docs.read","arguments":{"record_id":"docs-0","extra":true}}),
        json!({"name":"docs.read","arguments":{"record_id":1}}),
        json!({"name":"docs.update","arguments":{"record_id":"docs-0","data":{},"expected_version":1.0}}),
        json!({"name":"docs.update","arguments":{"record_id":"docs-0","data":{},"expected_version":true}}),
        json!({"name":"docs.search","arguments":{"collection":"docs.documents","limit":1.0}}),
        json!({"name":"docs.search","arguments":{"collection":"mail.drafts"}}),
        json!({"name":"docs.set_permissions","arguments":{"record_id":"docs-0","expected_version":1,"permissions":[{"principal_id":"x","role":"owner","extra":true}]}}),
    ] {
        let result = request(&mut session, &mut spy, json!(1), "tools/call", params);
        assert_eq!(result["result"]["isError"], true, "{result}");
        assert!(spy.calls.is_empty());
    }
    let result = request(
        &mut session,
        &mut spy,
        json!(1),
        "tools/call",
        json!({"name":"docs.read","arguments":{"record_id":"docs-0"}}),
    );
    assert_eq!(result["result"]["isError"], false);
    assert_eq!(
        spy.calls,
        vec![("docs.read".into(), json!({"record_id":"docs-0"}), json!(1))]
    );
}

#[test]
fn real_world_results_receipts_and_omitted_defaults_survive_mcp_dispatch() {
    let mut world = world();
    let mut session = ready(Family::Docs, &mut world);
    let expected = world.inspect("docs-0").unwrap().unwrap();
    let result = request(
        &mut session,
        &mut world,
        json!("call-1"),
        "tools/call",
        json!({"name":"docs.read","arguments":{"record_id":"docs-0"}}),
    );
    assert_eq!(result["result"]["structuredContent"], expected);
    assert_eq!(result["result"]["isError"], false);
    let text = result["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(serde_json::from_str::<Value>(text).unwrap(), expected);
    let receipts = world.receipts().unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["event"]["request_id"], "call-1");
    assert_eq!(
        receipts[0]["event"]["raw_args_digest"],
        gauntlet_contracts::canonical_sha256(br#"{"record_id":"docs-0"}"#).unwrap()
    );
    let invalid = request(
        &mut session,
        &mut world,
        json!(2),
        "tools/call",
        json!({"name":"docs.update","arguments":{"record_id":"docs-0","expected_version":2,"data":{"must_not_commit":true}}}),
    );
    assert_eq!(invalid["result"]["isError"], true);
    assert_eq!(world.inspect("docs-0").unwrap().unwrap(), expected);
    assert_eq!(world.receipts().unwrap(), receipts);
}

#[test]
fn resources_use_the_same_acl_checked_world_and_preserve_the_requested_uri() {
    let mut world = world();
    let mut session = ready(Family::Docs, &mut world);
    let result = request(
        &mut session,
        &mut world,
        json!(1),
        "resources/read",
        json!({"uri":"fixture://docs/docs-0"}),
    );
    assert_eq!(
        result["result"]["contents"][0]["uri"],
        "fixture://docs/docs-0"
    );
    let text = result["result"]["contents"][0]["text"].as_str().unwrap();
    assert_eq!(serde_json::from_str::<Value>(text).unwrap()["id"], "docs-0");
    for uri in [
        "fixture://mail/mail-0",
        "file:///etc/passwd",
        "fixture://docs/",
        "fixture://docs/%64ocs-0",
        "fixture://docs/%ff",
    ] {
        let result = request(
            &mut session,
            &mut world,
            json!(2),
            "resources/read",
            json!({"uri":uri}),
        );
        assert!(result.get("error").is_some());
    }
    assert_eq!(world.receipts().unwrap().len(), 1);
}

#[test]
fn negotiation_requires_initialization_and_keeps_all_supported_versions() {
    for version in [
        "2024-11-05",
        "2025-03-26",
        "2025-06-18",
        "2025-11-25",
        "unknown",
    ] {
        let mut spy = Spy::default();
        let mut session = Session::new(Family::Mail).unwrap();
        assert_eq!(
            request(&mut session, &mut spy, json!(1), "tools/list", json!({}))["error"]["code"],
            -32600
        );
        let result = request(
            &mut session,
            &mut spy,
            json!(2),
            "initialize",
            json!({"protocolVersion":version,"clientInfo":{"name":"client","version":"1"},"capabilities":{}}),
        );
        assert_eq!(
            result["result"]["protocolVersion"],
            if version == "unknown" {
                "2025-11-25"
            } else {
                version
            }
        );
        assert_eq!(
            request(&mut session, &mut spy, json!(3), "tools/list", json!({}))["error"]["code"],
            -32600
        );
        assert!(session
            .process(
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                &mut spy
            )
            .unwrap()
            .is_none());
        assert!(
            request(&mut session, &mut spy, json!(4), "tools/list", json!({}))
                .get("result")
                .is_some()
        );
        assert_eq!(
            request(&mut session, &mut spy, json!(5), "initialize", json!({}))["error"]["code"],
            -32600
        );
        assert!(spy.calls.is_empty());
    }
}

#[test]
fn ambiguous_oversized_and_exhausted_sessions_close_before_provider_execution() {
    for raw in [
        br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":1.0,"method":"ping"}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}"#,
    ] {
        let mut spy = Spy::default();
        let mut session = Session::new(Family::Docs).unwrap();
        assert_eq!(
            session.process(raw, &mut spy),
            Err(TransportError::Malformed)
        );
        assert_eq!(
            session.process(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#, &mut spy),
            Err(TransportError::Closed)
        );
        assert!(spy.calls.is_empty());
    }
    let mut spy = Spy::default();
    let mut session = Session::new(Family::Docs).unwrap();
    assert_eq!(
        session.process(&vec![b' '; MAX_FRAME_BYTES + 1], &mut spy),
        Err(TransportError::FrameBound)
    );
    let mut session = Session::new(Family::Docs).unwrap();
    for _ in 0..MAX_SESSION_MESSAGES {
        assert!(session
            .process(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#, &mut spy)
            .unwrap()
            .is_some());
    }
    assert_eq!(
        session.process(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#, &mut spy),
        Err(TransportError::SessionBound)
    );
    assert!(spy.calls.is_empty());
}

#[test]
fn separate_sessions_share_the_callers_operation_budget_and_never_create_one() {
    let mut backend = Spy {
        remaining: Some(2),
        ..Default::default()
    };
    let mut docs = ready(Family::Docs, &mut backend);
    let mut mail = ready(Family::Mail, &mut backend);
    assert_eq!(
        request(
            &mut docs,
            &mut backend,
            json!(1),
            "tools/call",
            json!({"name":"docs.read","arguments":{"record_id":"docs-0"}})
        )["result"]["isError"],
        false
    );
    assert_eq!(
        request(
            &mut mail,
            &mut backend,
            json!(1),
            "tools/call",
            json!({"name":"mail.read","arguments":{"record_id":"mail-0"}})
        )["result"]["isError"],
        false
    );
    assert_eq!(
        request(
            &mut docs,
            &mut backend,
            json!(2),
            "tools/call",
            json!({"name":"docs.read","arguments":{"record_id":"docs-0"}})
        )["result"]["isError"],
        true
    );
    assert_eq!(backend.calls.len(), 2);
}

#[test]
fn oversized_provider_response_closes_the_session_without_a_second_call() {
    let mut spy = Spy {
        result: Some(json!({"body":"x".repeat(MAX_FRAME_BYTES)})),
        ..Default::default()
    };
    let mut session = ready(Family::Docs, &mut spy);
    let raw=br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"docs.read","arguments":{"record_id":"docs-0"}}}"#;
    assert_eq!(
        session.process(raw, &mut spy),
        Err(TransportError::ResponseBound)
    );
    assert_eq!(session.process(raw, &mut spy), Err(TransportError::Closed));
    assert_eq!(spy.calls.len(), 1);
}

#[test]
fn full_integer_request_ids_survive_into_signed_provider_receipts() {
    let mut world = world();
    let mut session = ready(Family::Docs, &mut world);
    let id: Value = serde_json::from_str("92233720368547758081234567890").unwrap();
    let result = request(
        &mut session,
        &mut world,
        id.clone(),
        "tools/call",
        json!({"name":"docs.read","arguments":{"record_id":"docs-0"}}),
    );
    assert_eq!(result["id"], id);
    assert_eq!(result["result"]["isError"], false);
    assert_eq!(world.receipts().unwrap()[0]["event"]["request_id"], id);
}
