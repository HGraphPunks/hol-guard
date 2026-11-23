use super::*;

#[test]
fn raw_sdk_capture_hashes_original_order_and_retains_missing_cancel_response() {
    let wire = "{\"b\":2,\"a\":1}";
    let mut row = json!({"schema":"hol-gauntlet-native-sdk-request-capture.v2",
        "request":{"a":1,"b":2},"request_wire_utf8":wire,"request_sha256":sha256(wire.as_bytes()),
        "peer_rechecked_before_response":false});
    assert!(request_bytes(&row, true).unwrap());
    assert!(request_bytes(&row, false).is_err());
    row["request_sha256"] = json!(digest(&row["request"]).unwrap());
    assert!(request_bytes(&row, true).is_err());
    row["request_sha256"] = json!(sha256(wire.as_bytes()));
    row["peer_rechecked_before_response"] = json!(true);
    row["response"] = json!({"ok":true});
    row["response_wire_utf8"] = json!("{\"ok\":true}");
    row["response_sha256"] = json!(digest(&row["response"]).unwrap());
    assert!(request_bytes(&row, false).unwrap());
    assert!(request_bytes(&row, true).is_err());
    row["response_wire_utf8"] = json!("{\"ok\":false}");
    assert!(request_bytes(&row, false).is_err());
}

#[test]
fn historical_missing_raw_sdk_bytes_never_receive_capture_credit() {
    let row = json!({"request":{"a":1},"request_sha256":"a".repeat(64),
        "response":{"ok":true},"response_sha256":digest(&json!({"ok":true})).unwrap(),
        "peer_rechecked_before_response":true});
    assert!(!request_bytes(&row, false).unwrap());
    let mut changed = row.clone();
    changed["schema"] = json!("hol-gauntlet-native-sdk-request-capture.v2");
    assert!(request_bytes(&changed, false).is_err());
    let mut changed = row;
    changed["request_sha256"] = json!(true);
    assert!(request_bytes(&changed, false).is_err());
}
#[test]
fn ancestry_requires_same_agent_start_time_direct_parent_and_distinct_pid() {
    let sdk = json!({"pid":42,"start_ticks":500,"cgroup":"job","lsm_label":"label","namespaces":{"mnt":"4:1"}});
    let peer = json!({"identity":{"pid":43,"start_ticks":510,"cgroup":"job","lsm_label":"label","namespaces":{"mnt":"4:1"}},
        "ancestry":{"schema":"hol-gauntlet-sdk-wire-ancestry.v1","ancestor_pid":42,"ancestor_start_ticks":500,
            "relay_pid":43,"cgroup":"job","hops":1,"execution_eligible":false,"ancestor_executable_verified":false}});
    let outside = json!({"parent_pid":42,"start_ticks":510});
    assert!(ancestry(&peer, &sdk, &[&outside]).is_ok());
    for (pointer, value) in [
        ("/ancestry/ancestor_start_ticks", json!(499)),
        ("/ancestry/hops", json!(true)),
        ("/identity/namespaces/mnt", json!("4:2")),
        ("/identity/pid", json!(42)),
    ] {
        let mut changed = peer.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(ancestry(&changed, &sdk, &[&outside]).is_err());
    }
    assert!(ancestry(&peer, &sdk, &[&json!({"parent_pid":41,"start_ticks":510})]).is_err());
    assert!(ancestry(&peer, &sdk, &[&json!({"parent_pid":42,"start_ticks":499})]).is_err());
}
#[test]
fn native_proxy_server_ids_match_the_independent_product_encoding() {
    for (family, identifier) in [
        ("docs", "mcp_server:omp:project:docs:ab3a6f8e60021e87e4c2"),
        ("mail", "mcp_server:omp:project:mail:0fc8525e4f702fd82399"),
    ] {
        let argv = native_argv("/prefix", family);
        assert_eq!(argv[11], identifier);
        assert_eq!(
            argv.last().unwrap(),
            &format!("--arg=/upstream/{family}.sock")
        );
    }
}
#[test]
fn sdk_marker_and_raw_kernel_argv_have_distinct_versioned_digests() {
    let raw = b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json\0";
    assert_eq!(
        sha256(raw),
        "bfae09e6b877e4504265e126e72ba64e2bdca83ffb7bc65cbda3f0dcbf8dcbed"
    );
    assert_eq!(
        sha256(&raw[..raw.len() - 1]),
        "2384aaacd0c241cb3d946dbe24b7b39db98d64023a89c327514dd11484ee3618"
    );
}
