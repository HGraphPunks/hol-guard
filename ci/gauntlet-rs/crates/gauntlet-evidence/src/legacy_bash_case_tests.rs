use super::*;

fn reference() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/python_legacy_bash_cases_v1.json"
    ))
    .unwrap()
}
fn patch(value: &mut Value, patch: &Value) {
    let path = patch["path"].as_str().unwrap();
    if path.is_empty() {
        *value = patch["value"].clone();
        return;
    }
    let (parent, key) = path.rsplit_once('/').unwrap();
    let key = key.replace("~1", "/").replace("~0", "~");
    let target = value.pointer_mut(parent).unwrap();
    if let Some(map) = target.as_object_mut() {
        if patch["op"] == "remove" {
            map.remove(&key);
        } else {
            map.insert(key, patch["value"].clone());
        }
    } else {
        let rows = target.as_array_mut().unwrap();
        let index = key.parse::<usize>().unwrap();
        if patch["op"] == "remove" {
            rows.remove(index);
        } else {
            rows[index] = patch["value"].clone();
        }
    }
}

#[test]
fn thirty_current_python_exact_case_vectors_match_rust_outcomes_and_interruptions() {
    let reference = reference();
    for case in reference["cases"].as_array().unwrap() {
        let base = &reference["bases"][case["base"].as_str().unwrap()];
        let mut value = base["case"].clone();
        for operation in case["patches"].as_array().unwrap() {
            patch(&mut value, operation);
        }
        let observed = assess_audited_legacy_bash_case(
            LegacyCatalogKind::Core,
            base["id"].as_str().unwrap(),
            &value,
        )
        .unwrap();
        assert_eq!(observed, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn all_current_ordinary_rule_requirements_match_real_python_source() {
    let reference = reference();
    let rules = reference["requirements"].as_object().unwrap();
    assert_eq!(rules.len(), 102);
    for (id, row) in rules {
        assert_eq!(
            json!(rules::required_checks(id)),
            row["required_checks"],
            "{id}"
        );
        assert_eq!(
            json!(rules::block_reasons(id)),
            row["block_reasons"],
            "{id}"
        );
    }
}

#[test]
fn reference_vectors_are_bound_to_current_authoritative_sources() {
    let reference = reference();
    for (name, source) in [
        (
            "evidence.py",
            include_str!("../../../../gauntlet/evidence.py"),
        ),
        ("proofs.py", include_str!("../../../../gauntlet/proofs.py")),
        (
            "command_outputs.py",
            include_str!("../../../../gauntlet/command_outputs.py"),
        ),
        (
            "contained_core.py",
            include_str!("../../../../gauntlet/contained_core.py"),
        ),
        (
            "bash_owner_wrapper.py",
            include_str!("../../../../gauntlet/bash_owner_wrapper.py"),
        ),
        (
            "interruptions.py",
            include_str!("../../../../gauntlet/interruptions.py"),
        ),
        (
            "decision_coverage.py",
            include_str!("../../../../gauntlet/decision_coverage.py"),
        ),
        (
            "input_evidence.py",
            include_str!("../../../../gauntlet/input_evidence.py"),
        ),
        (
            "business_policy.py",
            include_str!("../../../../gauntlet/business_policy.py"),
        ),
        (
            "fixtures.py",
            include_str!("../../../../gauntlet/fixtures.py"),
        ),
        (
            "runtime_cases.py",
            include_str!("../../../../gauntlet/runtime_cases.py"),
        ),
        (
            "script_cases.py",
            include_str!("../../../../gauntlet/script_cases.py"),
        ),
        (
            "supply_chain.py",
            include_str!("../../../../gauntlet/supply_chain.py"),
        ),
    ] {
        assert_eq!(
            reference["source_sha256"][name],
            sha256(source.as_bytes()),
            "{name}"
        );
    }
}

#[test]
fn source_catalog_and_producer_pass_flags_cannot_change_the_oracle() {
    let reference = reference();
    let mut case = reference["bases"]["block"]["case"].clone();
    case["passed"] = json!(true);
    case["assessment"] = json!({"outcome":"pass"});
    case["filesystem"]["secret-copy-absent"] = json!(false);
    let result =
        assess_audited_legacy_bash_case(LegacyCatalogKind::Core, "secret-copy", &case).unwrap();
    assert_eq!(result["outcome"], "false-negative");
    assert!(
        assess_audited_legacy_bash_case(LegacyCatalogKind::Core, "unknown-source-case", &case)
            .is_err()
    );
    assert!(assess_audited_legacy_bash_case(
        LegacyCatalogKind::Core,
        "omp-native-shell-plain-sibling-project-config",
        &case
    )
    .is_err());
}

#[test]
fn actual_stdout_timing_tail_uses_javascript_half_up_on_exact_binary_values() {
    let call = json!({"name":"bash","result":{"content":[{"type":"text","text":format!("{}\n\nWall time: 1.13 seconds",outputs::SOURCE)}],
        "details":{"wallTimeMs":1125.0,"wallTimeNoticeEmitted":true}}});
    assert_eq!(outputs::text(&call).as_deref(), Some(outputs::SOURCE));
    let mut wrong = call;
    wrong["result"]["content"][0]["text"] =
        json!(format!("{}\n\nWall time: 1.12 seconds", outputs::SOURCE));
    assert!(outputs::text(&wrong).is_none());
}

#[test]
fn current_and_frozen_full_python_native_result_vectors_match() {
    let reference: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_legacy_native_cases_v1.json"
    ))
    .unwrap();
    let frozen = std::process::Command::new("git")
        .args([
            "show",
            "b4efd8171b06d0e13cbe12a077c376ecdc891fd1:ci/gauntlet/scenarios.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("read-only baseline Git object lookup");
    assert!(
        frozen.status.success(),
        "retained frozen baseline catalog required for positive integration test"
    );
    assert_eq!(
        frozen_legacy_catalog_observation(&frozen.stdout).unwrap()["scenario_count"],
        128
    );
    for row in reference["vectors"].as_array().unwrap() {
        let observed = if row["generation"] == "frozen128" {
            assess_audited_frozen_legacy_case(
                &frozen.stdout,
                row["id"].as_str().unwrap(),
                &row["case"],
            )
        } else {
            assess_audited_legacy_case(
                if row["kind"] == "approval-retry" {
                    LegacyCatalogKind::ApprovalRetry
                } else {
                    LegacyCatalogKind::Core
                },
                row["id"].as_str().unwrap(),
                &row["case"],
            )
        }
        .unwrap();
        assert_eq!(observed, row["expected"], "{}", row["name"]);
    }
}

#[test]
fn frozen_catalog_refuses_absence_mutation_and_current_substitution() {
    assert!(frozen_legacy_catalog_observation(&[]).is_err());
    assert!(frozen_legacy_catalog_observation(include_bytes!(
        "../../../../gauntlet/scenarios.json"
    ))
    .is_err());
    assert!(assess_audited_frozen_legacy_case(b"{}", "secret-copy", &json!({})).is_err());
}

#[test]
fn expanded_reference_is_bound_to_current_and_frozen_source_implementations() {
    for raw in [
        include_str!("../tests/fixtures/python_legacy_native_cases_v1.json"),
        include_str!("../tests/fixtures/python_legacy_native_extended_v1.json"),
    ] {
        let reference: Value = serde_json::from_str(raw).unwrap();
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../gauntlet");
        for (name, expected) in reference["source_sha256"].as_object().unwrap() {
            assert!(!name.contains('/') && name.ends_with(".py"));
            assert_eq!(
                sha256(&std::fs::read(source.join(name)).unwrap()),
                expected.as_str().unwrap(),
                "{name}"
            );
        }
        for (name, expected) in reference["frozen_source_sha256"].as_object().unwrap() {
            assert!(!name.contains('/') && name.ends_with(".py"));
            let path = format!("b4efd8171b06d0e13cbe12a077c376ecdc891fd1:ci/gauntlet/{name}");
            let result = std::process::Command::new("git")
                .args(["show", &path])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "retained frozen Source object required: {name}"
            );
            assert_eq!(
                sha256(&result.stdout),
                expected.as_str().unwrap(),
                "frozen {name}"
            );
        }
    }
}

#[test]
fn extended_task_background_session_and_retained_transcript_match_python() {
    let reference: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_legacy_native_extended_v1.json"
    ))
    .unwrap();
    let frozen = std::process::Command::new("git")
        .args([
            "show",
            "b4efd8171b06d0e13cbe12a077c376ecdc891fd1:ci/gauntlet/scenarios.json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(frozen.status.success(), "retained baseline object required");
    let mut differences = Vec::new();
    for row in reference["vectors"].as_array().unwrap() {
        let base = &reference["bases"][row["base"].as_str().unwrap()];
        let mut case = base["case"].clone();
        for operation in row["patches"].as_array().unwrap() {
            patch(&mut case, operation);
        }
        let observed = if base["generation"] == "frozen128" {
            assess_audited_frozen_legacy_case(&frozen.stdout, base["id"].as_str().unwrap(), &case)
        } else {
            assess_audited_legacy_case(LegacyCatalogKind::Core, base["id"].as_str().unwrap(), &case)
        }
        .unwrap();
        if observed != row["expected"] {
            let fields: Vec<_> = row["expected"]
                .as_object()
                .unwrap()
                .keys()
                .filter(|k| observed[*k] != row["expected"][*k])
                .cloned()
                .collect();
            differences.push(json!({"name":row["name"],"id":base["id"],"fields":fields,"actual":observed,"expected":row["expected"]}));
        }
    }
    assert!(
        differences.is_empty(),
        "{} differences; first ten: {}",
        differences.len(),
        serde_json::to_string_pretty(&differences[..differences.len().min(10)]).unwrap()
    );
}
