use super::*;

fn reference() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/python_legacy_full_task_cases_v1.json"
    ))
    .unwrap()
}
#[test]
fn full_task_wrapper_and_all_stop_rows_match_exact_current_python_functions() {
    let reference = reference();
    for row in reference["vectors"].as_array().unwrap() {
        let observed =
            assess_audited_legacy_full_task_case(row["id"].as_str().unwrap(), &row["case"])
                .unwrap();
        assert_eq!(
            observed["source_assessment"], row["source_assessment"],
            "{}",
            row["name"]
        );
        assert_eq!(
            observed["would_have_stopped"], row["would_have_stopped"],
            "{}",
            row["name"]
        );
        assert_eq!(observed["qualification_eligible"], false);
        if row["name"]
            .as_str()
            .unwrap()
            .contains("missing-inference-still-separate")
            || row["name"]
                .as_str()
                .unwrap()
                .contains("empty-physical-map-still-separate")
        {
            assert_eq!(observed["source_assessment"]["outcome"], "pass");
            assert_eq!(observed["evidence_validity"], "incomplete");
            assert_eq!(observed["expected_outcome"], "unknown");
        }
    }
}
#[test]
fn full_task_source_and_catalog_kind_are_pinned_without_trusting_pass_flags() {
    let reference = reference();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../gauntlet");
    for (name, expected) in reference["source_sha256"].as_object().unwrap() {
        assert!(!name.contains('/') && name.ends_with(".py"));
        let observed = sha256(&std::fs::read(source.join(name)).unwrap());
        if name == "evidence.py" {
            let compatibility: Value = serde_json::from_str(include_str!(
                "../tests/fixtures/python_legacy_upstream_62fe_v1.json"
            ))
            .unwrap();
            let relation = &compatibility["source_compatibility"][name];
            assert_eq!(*expected, relation["historical"]);
            assert_eq!(observed, relation["current"]);
        } else {
            assert_eq!(observed, expected.as_str().unwrap(), "{name}");
        }
    }
    let mut case = reference["vectors"][0]["case"].clone();
    case["passed"] = json!(true);
    case["would_have_stopped"] = json!([]);
    case["filesystem"]["protected:synthetic-credential"] = json!(false);
    case["cleanup_ok"] = json!(false);
    let observed = assess_audited_legacy_full_task_case("todo-app-to-github", &case).unwrap();
    assert_eq!(observed["expected_outcome"], "false-negative");
    assert!(assess_audited_legacy_full_task_case("secret-copy", &case).is_err());
}
