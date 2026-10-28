use gauntlet_contracts::{
    fixed_feature_catalog, FeatureExecutorSpec, FEATURE_CATALOG_SHA256, FEATURE_NODE_SHA256,
};
use gauntlet_evidence::verify_feature_report_v2;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn fixture() -> (FeatureExecutorSpec, Value, BTreeMap<String, Vec<u8>>) {
    let spec=FeatureExecutorSpec::parse(json!({"schema":"hol-gauntlet-feature-executor.v1","audit_id":"a".repeat(16),
        "source_sha":"b".repeat(40),"source_archive_sha256":"c".repeat(64),"candidate_archive_sha256":"d".repeat(64),
        "wheel_sha256":"e".repeat(64),"native_sha256":"f".repeat(64),"version":"3.58.0",
        "node_sha256":FEATURE_NODE_SHA256,"catalog_sha256":FEATURE_CATALOG_SHA256,"executor_sha256":"1".repeat(64)}).to_string().as_bytes()).unwrap();
    let xml=br#"<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="synthetic"/></testsuite>"#.to_vec();
    let mut files = BTreeMap::new();
    let mut rows = Vec::new();
    for group in fixed_feature_catalog().unwrap() {
        files.insert(format!("{}.xml", group.id()), xml.clone());
        files.insert(format!("{}.log", group.id()), Vec::new());
        let mut row = group.to_json();
        for (key, value) in [
            ("attempted", json!(true)),
            ("status", json!("passed")),
            (
                "counts",
                json!({"tests":1,"failures":0,"errors":0,"skipped":0}),
            ),
            ("exit_code", json!(0)),
            ("elapsed_millis", json!(1)),
            ("junit_sha256", json!(sha(&xml))),
            ("log_sha256", json!(sha(b""))),
            ("reason", Value::Null),
        ] {
            row[key] = value;
        }
        rows.push(row);
    }
    let report = json!({"schema":"hol-gauntlet-feature-contracts.v2","audit_id":spec.text("audit_id"),"source_sha":spec.text("source_sha"),
        "version":"3.58.0","wheel_sha256":spec.text("wheel_sha256"),"native_sha256":spec.text("native_sha256"),
        "node_version":"v22.22.2","catalog_sha256":FEATURE_CATALOG_SHA256,"feature_executor_sha256":spec.text("executor_sha256"),
        "source_compiler_sha256":"2".repeat(64),"evidence_kind":"mixed-source-installed-contract","status":"passed",
        "groups":rows,"model_requests":0,"model_tokens":0,"qualification_eligible":false});
    (spec, report, files)
}
fn verify(spec: &FeatureExecutorSpec, report: &Value, files: &BTreeMap<String, Vec<u8>>) -> bool {
    verify_feature_report_v2(spec, report.to_string().as_bytes(), |name, _| {
        Ok(files.get(name).cloned())
    })
    .is_ok()
}

#[test]
fn all_fixed_groups_are_recomputed_without_granting_execution_or_qualification() {
    let (spec, report, files) = fixture();
    let result = verify_feature_report_v2(&spec, report.to_string().as_bytes(), |name, _| {
        Ok(files.get(name).cloned())
    })
    .unwrap();
    assert_eq!(result["fixed_groups_checked"], 28);
    assert_eq!(result["status"], "passed");
    assert_eq!(result["counts_independently_recomputed"], true);
    assert_eq!(result["execution_provenance_authenticated"], false);
    assert_eq!(result["qualification_eligible"], false);
}

#[test]
fn rehashed_failure_missing_group_wrong_context_and_model_claims_refuse() {
    let (spec, report, mut files) = fixture();
    let failed=br#"<testsuite tests="1" failures="1" errors="0" skipped="0"><testcase name="synthetic"><failure>observed</failure></testcase></testsuite>"#.to_vec();
    files.insert("native_runtime.xml".into(), failed.clone());
    let mut forged = report.clone();
    forged["groups"][0]["junit_sha256"] = json!(sha(&failed));
    assert!(!verify(&spec, &forged, &files));
    let (spec, report, files) = fixture();
    let mut missing = report.clone();
    missing["groups"].as_array_mut().unwrap().pop();
    assert!(!verify(&spec, &missing, &files));
    for (pointer, value) in [
        (
            "/groups/0/evidence_kind",
            json!("installed-product-contract"),
        ),
        ("/groups/0/exit_code", json!(-9)),
        ("/groups/0/counts/tests", json!(99)),
        ("/model_requests", json!(1)),
        ("/qualification_eligible", json!(true)),
        ("/feature_executor_sha256", json!("0".repeat(64))),
    ] {
        let mut changed = report.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(!verify(&spec, &changed, &files), "{pointer}");
    }
}

#[test]
fn missing_xml_and_unattempted_groups_remain_invalid_evidence() {
    let (spec, mut report, mut files) = fixture();
    files.remove("native_runtime.xml");
    report["groups"][0]["counts"] = Value::Null;
    report["groups"][0]["junit_sha256"] = Value::Null;
    report["groups"][0]["status"] = json!("invalid-evidence");
    report["status"] = json!("invalid-evidence");
    assert!(verify(&spec, &report, &files));
    files.remove("native_runtime.log");
    let row = &mut report["groups"][0];
    row["attempted"] = json!(false);
    row["exit_code"] = Value::Null;
    row["elapsed_millis"] = json!(0);
    row["log_sha256"] = Value::Null;
    row["reason"] = json!("declared-source-test-missing");
    assert!(verify(&spec, &report, &files));
    report["status"] = json!("passed");
    assert!(!verify(&spec, &report, &files));
}
