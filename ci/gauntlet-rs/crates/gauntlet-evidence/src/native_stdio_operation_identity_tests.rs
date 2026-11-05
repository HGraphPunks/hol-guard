use super::*;

fn pair(operation: &str, request_schema: &str, response_schema: &str) -> (Value, Value) {
    let request = json!({"operation":operation,"deadline_budget_ms":10000,
        "request":{"schema":request_schema,"request_id":"one","query":"status"}});
    let digest = format!(
        "sha256:{}",
        sha256(&canonical_value(&request["request"]).unwrap())
    );
    let response = json!({"schema":response_schema,"request_id":"one",
        "request_sha256":digest,"status":"ok","code":"ok","payload":{}});
    (request, response)
}

#[test]
fn resident_reply_digest_binds_request_and_refuses_substitution() {
    let (request, response) = pair(
        "daemon_route",
        "guard-daemon-route-request.v1",
        "guard-daemon-route-result.v1",
    );
    assert_eq!(verify(&request, &response).unwrap(), ReplyBinding::Digest);
    let mut changed = request.clone();
    changed["request"]["query"] = json!("other");
    assert!(verify(&changed, &response).is_err());
    let mut changed = response.clone();
    changed["request_id"] = json!("other");
    assert!(verify(&request, &changed).is_err());
    let mut changed = response.clone();
    changed["request_sha256"] = json!("sha256:0000");
    assert!(verify(&request, &changed).is_err());
    let mut changed = request.clone();
    changed["operation"] = json!("unknown_operation");
    assert!(verify(&changed, &response).is_err());
}

#[test]
fn command_capability_digest_excludes_only_the_signing_key() {
    let (mut request, mut response) = pair(
        "command_capability",
        "guard-command-capability-request.v1",
        "guard-command-capability-result.v1",
    );
    request["request"]["integrity_key_b64"] = json!("synthetic-key-a");
    let mut material = request["request"].clone();
    material["integrity_key_b64"] = Value::Null;
    response["request_sha256"] = json!(format!(
        "sha256:{}",
        sha256(&canonical_value(&material).unwrap())
    ));
    assert_eq!(verify(&request, &response).unwrap(), ReplyBinding::Digest);
    request["request"]["integrity_key_b64"] = json!("synthetic-key-b");
    assert_eq!(verify(&request, &response).unwrap(), ReplyBinding::Digest);
    request["request"]["query"] = json!("other");
    assert!(verify(&request, &response).is_err());
}

#[test]
fn dialects_without_reply_digest_cannot_claim_identity_verification() {
    let drain = json!({"operation":"hook_direct_evidence_drain","deadline_budget_ms":2000,
        "request":{"guard_home":"/product/guard"}});
    let answer = json!({"schema":"guard-hook-direct-evidence.v1","records":[],
        "counters":{},"remaining":0,"through":null,"epoch":"synthetic-1"});
    assert_eq!(verify(&drain, &answer).unwrap(), ReplyBinding::Structural);
    let mut changed = answer.clone();
    changed["schema"] = json!("other");
    assert!(verify(&drain, &changed).is_err());
    let mut paged = drain.clone();
    paged["request"]["max_records"] = json!(1);
    paged["request"]["ack_through"] = json!(7);
    paged["request"]["ack_epoch"] = json!("synthetic-1");
    let mut page = answer.clone();
    page["records"] = json!([{"seq":8}]);
    page["through"] = json!(8);
    assert_eq!(verify(&paged, &page).unwrap(), ReplyBinding::Structural);
    page["records"] = json!([{"seq":8},{"seq":9}]);
    assert!(verify(&paged, &page).is_err());
}

#[test]
fn accepted_policy_ack_echoes_the_requested_snapshot_without_claiming_admission() {
    let request = json!({"operation":"policy_snapshot_push","deadline_budget_ms":9000,
        "request":{"schema":"guard-policy-snapshot-push.v1",
        "snapshot":{"generation":4,"policy_digest":"a".repeat(64)}}});
    let answer = json!({"status":"accepted","generation":4,
        "policy_digest":"a".repeat(64),"idempotent":false,"resident_generation":7});
    assert_eq!(
        verify(&request, &answer).unwrap(),
        ReplyBinding::SnapshotEcho
    );
    let mut changed = answer.clone();
    changed["generation"] = json!(3);
    assert!(verify(&request, &changed).is_err());
    let mut changed = answer.clone();
    changed["policy_digest"] = json!("b".repeat(64));
    assert!(verify(&request, &changed).is_err());
    let mut changed = answer.clone();
    changed["status"] = json!("accepted-without-policy");
    assert!(verify(&request, &changed).is_err());
}
