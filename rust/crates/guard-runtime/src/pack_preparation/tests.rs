use super::*;
fn request() -> Value {
    let engine = guard_command::source_cli::compiler_info()["implementation_digest"].clone();
    json!({"profile":"remote","engine":engine,"now":1500,"selected":[],"retained":[],"validate_only":true,
        "release_data":json!({"engine":engine,"issued_at":1000,"expires_at":2000}).to_string()})
}
#[test]
fn preflight_has_no_filesystem_capability_and_preserves_errors() {
    let mut input = request();
    assert_eq!(evaluate(&input).unwrap(), json!({"validated":true}));
    input["now"] = json!(2000);
    assert!(evaluate(&input)
        .unwrap_err()
        .contains("fresh authenticated"));
    input["now"] = json!(1500);
    input["engine"] = json!("0".repeat(64));
    assert!(evaluate(&input)
        .unwrap_err()
        .contains("different native engine"));
}
#[test]
fn selection_ids_are_strict_and_bounded() {
    for id in [
        "command.",
        "command.Foo",
        "command.a..b",
        "command.a/-b",
        "command.a-",
    ] {
        let mut input = request();
        input["selected"] = json!([id]);
        assert!(evaluate(&input).unwrap_err().contains("selection invalid"));
    }
    let mut input = request();
    input["selected"] = json!((0..=MAX_SELECTED)
        .map(|i| format!("command.pack-{i}"))
        .collect::<Vec<_>>());
    assert!(evaluate(&input).unwrap_err().contains("admission budget"));
}

#[test]
fn target_metadata_selection_and_legacy_are_native_and_io_free() {
    let mut input = json!({"operation":"target-metadata", "controls":[
        {"kind":"extension", "id":"command.present", "extension_present":true},
        {"kind":"permission", "id":"command.owner.permission.run", "permission_present":true},
        {"kind":"extension", "id":"invalid/target"}
    ]});
    assert_eq!(evaluate(&input).unwrap(), json!({"catalog_refs":[]}));
    input["controls"][1]["permission_present"] = json!(false);
    assert_eq!(evaluate(&input).unwrap(), json!({"authority":"installed"}));
    input["installed"] = Value::Null;
    input["committed"] = json!(false);
    assert_eq!(evaluate(&input).unwrap(), json!({"catalog_refs":[]}));
    input["committed"] = json!(true);
    input["directory"] = json!("unused");
    assert_eq!(evaluate(&input).unwrap(), json!({"authority":"remote"}));
}
