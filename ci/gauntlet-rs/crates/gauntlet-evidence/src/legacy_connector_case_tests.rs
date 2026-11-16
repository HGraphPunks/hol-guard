use super::*;

fn reference() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/python_legacy_connector_cases_v1.json"
    ))
    .unwrap()
}
#[test]
fn connector_wrapper_matches_full_actual_python_harness_results() {
    let reference = reference();
    let mut differences = Vec::new();
    for row in reference["vectors"].as_array().unwrap() {
        let observed =
            assess_audited_legacy_connector_case(row["id"].as_str().unwrap(), &row["case"])
                .unwrap();
        if observed["source_assessment"] != row["source_assessment"] {
            differences.push(json!({"name":row["name"],"actual":observed["source_assessment"],"expected":row["source_assessment"]}));
        }
        assert_eq!(observed["qualification_eligible"], false);
        if row["name"]
            .as_str()
            .unwrap()
            .ends_with("missing-inference-separate")
        {
            assert_eq!(observed["model_observation"], "unknown");
            assert_eq!(observed["evidence_validity"], "incomplete");
            assert_eq!(observed["expected_outcome"], "unknown");
        }
    }
    assert!(
        differences.is_empty(),
        "{}",
        serde_json::to_string_pretty(&differences).unwrap()
    );
}
#[test]
fn connector_source_kind_and_unavailable_identity_are_not_producer_pass_flags() {
    let reference = reference();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    for (path, expected) in reference["source_sha256"].as_object().unwrap() {
        assert!(!path.split('/').any(|s| s == ".."));
        assert!(
            path.starts_with("ci/gauntlet/")
                || path == "src/codex_plugin_scanner/guard/blocked_request_mode.py"
        );
        super::super::tests::assert_source_pin(
            path,
            &std::fs::read(root.join(path)).unwrap(),
            expected,
        );
    }
    let row = reference["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["source_assessment"]["outcome"] == "pass")
        .unwrap();
    let mut case = row["case"].clone();
    case["passed"] = json!(true);
    case["assessment"] = json!({"outcome":"pass"});
    case["inference"]["live_rounds"] = json!([]);
    let observed =
        assess_audited_legacy_connector_case(row["id"].as_str().unwrap(), &case).unwrap();
    assert_eq!(observed["expected_outcome"], "unknown");
    case.as_object_mut().unwrap().remove("credentials_seeded");
    case["inference"] = row["case"]["inference"].clone();
    assert_eq!(
        assess_audited_legacy_connector_case(row["id"].as_str().unwrap(), &case).unwrap()
            ["evidence_validity"],
        "incomplete"
    );
    assert!(assess_audited_legacy_connector_case("secret-copy", &case).is_err());
}

#[test]
fn windows_tokens_shell_envelopes_and_full_cases_match_original_python() {
    let reference: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_legacy_connector_windows_v1.json"
    ))
    .unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../gauntlet");
    for (name, expected) in reference["source_sha256"].as_object().unwrap() {
        assert!(!name.contains('/') && name.ends_with(".py"));
        super::super::tests::assert_source_pin(
            name,
            &std::fs::read(source.join(name)).unwrap(),
            expected,
        );
    }
    for row in reference["tokens"].as_array().unwrap() {
        assert_eq!(
            json!(tokens(row["command"].as_str().unwrap()).unwrap()),
            row["expected"],
            "{}",
            row["command"]
        );
    }
    for row in reference["scripts"].as_array().unwrap() {
        let observed = approval_actions::shell_script(row["command"].as_str().unwrap());
        assert_eq!(observed, row["expected"].as_str().unwrap());
        assert_eq!(observed, row["call_expected"].as_str().unwrap());
    }
    for row in reference["cases"].as_array().unwrap() {
        assert_eq!(
            assess_audited_legacy_connector_case(row["id"].as_str().unwrap(), &row["case"])
                .unwrap()["source_assessment"],
            row["source_assessment"],
            "{}",
            row["name"]
        );
    }
}

#[test]
fn codex_routes_match_exact_python_proof_sink_run_and_interruption_results() {
    let reference: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_legacy_codex_contained_v1.json"
    ))
    .unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    for (name, expected) in reference["source_sha256"].as_object().unwrap() {
        assert!(!name.split('/').any(|part| part == ".."));
        assert!(name.starts_with("ci/gauntlet/") || name.starts_with("tests/test_guard_gauntlet_"));
        super::super::tests::assert_source_pin(
            name,
            &std::fs::read(source.join(name)).unwrap(),
            expected,
        );
    }
    for row in reference["sink_vectors"].as_array().unwrap() {
        let observed = codex_contained::sink_argv(&row["command"]);
        let (argv, error) = match observed {
            Ok(argv) => (json!(argv), Value::Null),
            Err(error) => (Value::Null, json!(error)),
        };
        assert_eq!(argv, row["argv"], "{}", row["command"]);
        assert_eq!(error, row["error"], "{}", row["command"]);
    }
    for row in reference["case_vectors"].as_array().unwrap() {
        let routed = codex_contained::routed_calls(&json!("allow"), &row["case"]).unwrap();
        assert_eq!(
            json!({"bound":routed.bound,"error":routed.error}),
            row["routed"],
            "{}",
            row["name"]
        );
        let observed =
            assess_audited_legacy_connector_case(row["id"].as_str().unwrap(), &row["case"])
                .unwrap();
        assert_eq!(
            observed["source_assessment"], row["source_assessment"],
            "{}",
            row["name"]
        );
        assert_eq!(observed["qualification_eligible"], false);
        if matches!(
            row["name"].as_str(),
            Some(
                "unknown-run-status"
                    | "numeric-run-status"
                    | "null-run-status"
                    | "unknown-model"
                    | "producer-pass-cannot-replace-proof"
            )
        ) {
            assert_eq!(
                observed["evidence_validity"], "incomplete",
                "{}",
                row["name"]
            );
            assert_eq!(observed["expected_outcome"], "unknown");
        }
    }
    let positive = &reference["case_vectors"][0]["case"];
    assert!(codex_contained::routed_calls(&json!("block"), positive)
        .unwrap()
        .bound
        .is_empty());
    let mut foreign = positive.clone();
    foreign["harness"] = json!("claude-code");
    assert!(codex_contained::routed_calls(&json!("allow"), &foreign)
        .unwrap()
        .bound
        .is_empty());
}

#[test]
fn retained_v1_lineage_keeps_goldens_and_current_generation_separate() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let output = std::process::Command::new("python3")
        .args(["-I", "-B"])
        .arg(root.join("ci/gauntlet-rs/proofs/verify_host_event_fixture_compatibility.py"))
        .arg("retained-legacy-v1")
        .output()
        .expect("isolated stdlib-only historical Source verification");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let proof: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(proof["historical_fixtures"], 9);
    assert_eq!(proof["source_files"], 17);
    assert_eq!(proof["unchanged_definition_asts"], 113);
    assert_eq!(proof["changed_definition_asts"], 22);
    assert_eq!(proof["full_current_assessment_parity"], false);
    assert_eq!(proof["current_legacy_generation_supported"], false);
    let retained = fixed_legacy_catalog(LegacyCatalogKind::Core).unwrap();
    assert_eq!(retained.scenarios().len(), 310);
    assert_eq!(
        fixed_legacy_catalog(LegacyCatalogKind::ApprovalRetry)
            .unwrap()
            .scenarios()
            .len(),
        16
    );
    let current: Value =
        serde_json::from_slice(include_bytes!("../../../../gauntlet/scenarios.json")).unwrap();
    assert_eq!(current["scenarios"].as_array().unwrap().len(), 378);
    let new_case = current["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            !retained
                .scenarios()
                .iter()
                .any(|old| old["id"] == row["id"])
        })
        .expect("current-only cases remain unsupported");
    assert!(matches!(
        assess_audited_legacy_case(
            LegacyCatalogKind::Core,
            new_case["id"].as_str().unwrap(),
            &json!({})
        ),
        Err(EvidenceError::Invalid("unknown fixed legacy scenario"))
    ));
    let current = include_bytes!("../../../../gauntlet/evidence.py");
    assert!(
        std::panic::catch_unwind(|| super::super::tests::assert_source_pin(
            "evidence.py",
            current,
            &json!("0".repeat(64))
        ))
        .is_err()
    );
    let mut changed = current.to_vec();
    changed.push(b'\n');
    assert!(
        std::panic::catch_unwind(|| super::super::tests::assert_source_pin(
            "evidence.py",
            &changed,
            &json!("67c2477bca5264350eb679e4397afee485a6af84743ae212935888a6a252dfa1")
        ))
        .is_err()
    );
}
