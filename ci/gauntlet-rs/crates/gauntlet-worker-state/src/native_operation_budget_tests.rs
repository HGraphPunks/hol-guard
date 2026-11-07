use super::*;
fn request(id: Value) -> Vec<u8> {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"docs.read","arguments":{"record_id":"doc"}}}).to_string().into_bytes()
}
fn response(id: Value) -> Vec<u8> {
    json!({"jsonrpc":"2.0","id":id,"result":{}})
        .to_string()
        .into_bytes()
}
#[test]
fn shared_limit_cannot_be_multiplied_by_switching_builtin_or_mcp_families() {
    let mut budget = NativeOperationBudget::new(4).unwrap();
    budget.reserve_builtin("sdk", "one").unwrap();
    for family in [Family::Docs, Family::Mail] {
        let raw = request(json!(3));
        let sequence = budget.reserve_mcp(family, &raw).unwrap().unwrap();
        budget.admit_upstream(family, &raw).unwrap();
        budget
            .complete_mcp(family, sequence, &response(json!(3)))
            .unwrap();
    }
    budget.reserve_builtin("sdk", "two").unwrap();
    assert!(budget.reserve_builtin("sdk", "three").is_err());
    assert!(budget
        .reserve_mcp(Family::Docs, &request(json!(4)))
        .is_err());
    assert_eq!(budget.observation()["used"], 4);
    assert_eq!(budget.observation()["builtin"], 2);
    assert_eq!(budget.observation()["mcp"], 2);
    budget.verify_completed().unwrap();
}
#[test]
fn provider_handoff_refuses_missing_permits_changed_arguments_cross_routes_and_replays() {
    let mut budget = NativeOperationBudget::new(4).unwrap();
    let raw = request(json!("sdk-id"));
    assert!(budget.admit_upstream(Family::Docs, &raw).is_err());
    let sequence = budget.reserve_mcp(Family::Docs, &raw).unwrap().unwrap();
    let mut changed: Value = serde_json::from_slice(&raw).unwrap();
    changed["params"]["arguments"]["record_id"] = json!("other");
    assert!(budget
        .admit_upstream(Family::Docs, changed.to_string().as_bytes())
        .is_err());
    assert!(budget.admit_upstream(Family::Mail, &raw).is_err());
    budget.admit_upstream(Family::Docs, &raw).unwrap();
    assert!(budget.admit_upstream(Family::Docs, &raw).is_err());
    assert!(budget
        .complete_mcp(Family::Docs, sequence, &response(json!("wrong")))
        .is_err());
    assert!(budget.verify_completed().is_err());
    budget
        .complete_mcp(Family::Docs, sequence, &response(json!("sdk-id")))
        .unwrap();
    budget.verify_completed().unwrap();
    let next = budget.reserve_mcp(Family::Docs, &raw).unwrap().unwrap();
    assert_ne!(
        next, sequence,
        "JSON-RPC IDs may be reused after a completed response, with a fresh budget debit"
    );
}
#[test]
fn refused_guard_calls_still_spend_ingress_budget_without_claiming_provider_execution() {
    let mut budget = NativeOperationBudget::new(1).unwrap();
    let raw = request(json!(1));
    let sequence = budget.reserve_mcp(Family::Docs, &raw).unwrap().unwrap();
    budget
        .complete_mcp(
            Family::Docs,
            sequence,
            &json!({"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"refused"}})
                .to_string()
                .into_bytes(),
        )
        .unwrap();
    assert_eq!(budget.observation()["events"][0]["backend_reached"], false);
    assert!(budget.reserve_builtin("sdk", "call").is_err());
    budget.verify_completed().unwrap();
}
