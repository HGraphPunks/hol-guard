use super::*;

#[test]
fn signed_journal_binding_refuses_appended_events_rehashed_tail_and_inode_substitution() {
    let (events, _) = fixture();
    let raw = b"pinned journal bytes\n";
    let metadata = json!({"device":1,"inode":2,"uid":0,"gid":0,"mode":0o600,"links":1});
    let pin = json!({"schema":"hol-gauntlet-cell-journal-binding.v1","available":true,"events":events.len(),
        "bytes":raw.len(),"tail_sha256":digest(events.last().unwrap()).unwrap(),"device":1,"inode":2,"uid":0,"gid":0,"mode":0o600,"links":1});
    assert!(check_journal_binding(&pin, raw, &events, &metadata).is_ok());
    let mut wrong = events.clone();
    wrong.push(events[0].clone());
    assert!(check_journal_binding(&pin, raw, &wrong, &metadata).is_err());
    let mut wrong = events;
    wrong.last_mut().unwrap()["data"]["argv_sha256"] = json!("0".repeat(64));
    assert!(check_journal_binding(&pin, raw, &wrong, &metadata).is_err());
    let mut wrong = metadata;
    wrong["inode"] = json!(3);
    assert!(check_journal_binding(&pin, raw, &fixture().0, &wrong).is_err());
    let mut wrong = pin;
    wrong["available"] = json!(false);
    assert!(check_journal_binding(&wrong, raw, &fixture().0, &json!({})).is_err());
}
const HANDLE: &str = "12345678-1234-1234-1234-1234567890ab";
fn fixture() -> (Vec<Value>, Vec<String>) {
    let command = vec!["/usr/bin/cat".to_owned()];
    let pin = sha256(b"/usr/bin/cat");
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let rows = [
        (
            "gated-product-process",
            json!({"handle":HANDLE,"identity":{"argv":["/public/gauntlet-product-cell","exec-gate","/usr/bin/cat"]}}),
        ),
        (
            "capture-input-bound",
            json!({"schema":"hol-gauntlet-capture-input-binding.v1","handle":HANDLE,"argv_sha256":pin,"expected_sha256":digest,"expected_bytes":3}),
        ),
        ("product-release", json!({"handle":HANDLE})),
        (
            "capture-input-terminal",
            json!({"schema":"hol-gauntlet-capture-input-terminal.v1","handle":HANDLE,"argv_sha256":pin,
            "expected_sha256":digest,"expected_bytes":3,"delivered_sha256":digest,"delivered_bytes":3,"stdin_close_acknowledged":true,
            "input_complete":true,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
        ),
        (
            "capture-terminal",
            json!({"argv_sha256":pin,"returncode":0}),
        ),
    ];
    let events=rows.into_iter().enumerate().map(|(i,(kind,data))|json!({"schema":"hol-gauntlet-cell-event.v1","sequence":i,"kind":kind,"data":data})).collect();
    (events, command)
}
#[test]
fn complete_receipt_binds_exact_gate_arguments_and_original_input() {
    let (events, command) = fixture();
    let result = verify_native_capture_input(&events, 4, &command, b"abc").unwrap();
    assert_eq!(result["input_delivery_checked"], true);
    assert_eq!(result["execution_eligible"], false);
    assert!(verify_native_capture_input(&events, 4, &command, b"abd").is_err());
    assert!(verify_native_capture_input(&events, 4, &["/usr/bin/other".into()], b"abc").is_err());
    let mut wrong = events;
    wrong[0]["data"]["identity"]["argv"][2] = json!("/usr/bin/other");
    assert!(verify_native_capture_input(&wrong, 4, &command, b"abc").is_err());
}
#[test]
fn missing_historical_receipts_and_partial_delivery_never_receive_full_credit() {
    let (mut events, command) = fixture();
    let old = vec![
        json!({"schema":"hol-gauntlet-cell-event.v1","sequence":0,"kind":"capture-terminal","data":{"argv_sha256":sha256(b"/usr/bin/cat")}}),
    ];
    let result = verify_native_capture_input(&old, 0, &command, b"abc").unwrap();
    assert_eq!(result["historical_input_receipt_missing"], true);
    assert_eq!(result["input_delivery_checked"], false);
    let row = &mut events[3]["data"];
    row["delivered_bytes"] = json!(1);
    row["delivered_sha256"] =
        json!("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
    row["stdin_close_acknowledged"] = json!(false);
    row["input_complete"] = json!(false);
    assert_eq!(
        verify_native_capture_input(&events, 4, &command, b"abc").unwrap()
            ["input_delivery_checked"],
        false
    );
    events[3]["data"]["input_complete"] = json!(true);
    assert!(verify_native_capture_input(&events, 4, &command, b"abc").is_err());
}
#[test]
fn reordered_boolean_changed_byte_and_wrong_handle_claims_refuse() {
    let (events, command) = fixture();
    for (index, pointer, value) in [
        (3, "/data/delivered_bytes", json!(true)),
        (3, "/data/stdin_close_acknowledged", json!(1)),
        (3, "/data/delivered_sha256", json!("0".repeat(64))),
        (1, "/data/handle", json!("foreign")),
        (1, "/sequence", json!(true)),
        (3, "/data/expected_bytes", json!(false)),
    ] {
        let mut wrong = events.clone();
        *wrong[index].pointer_mut(pointer).unwrap() = value;
        assert!(
            verify_native_capture_input(&wrong, 4, &command, b"abc").is_err(),
            "{index}:{pointer}"
        );
    }
    let mut wrong = events;
    wrong.swap(1, 2);
    for (i, row) in wrong.iter_mut().enumerate() {
        row["sequence"] = json!(i);
    }
    assert!(verify_native_capture_input(&wrong, 4, &command, b"abc").is_err());
}
#[test]
fn duplicate_binding_and_new_journal_with_missing_receipt_refuse() {
    let (mut events, command) = fixture();
    let mut other = events[1].clone();
    other["sequence"] = json!(events.len());
    events.push(other);
    assert!(verify_native_capture_input(&events, 4, &command, b"abc").is_err());
    let (mut events, command) = fixture();
    events[3]["kind"] = json!("unrelated");
    assert!(verify_native_capture_input(&events, 4, &command, b"abc").is_err());
}
