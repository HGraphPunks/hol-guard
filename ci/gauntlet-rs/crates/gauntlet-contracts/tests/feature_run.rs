use gauntlet_contracts::{
    canonicalize, FeatureRunIntent, FeatureRunPins, FEATURE_CATALOG_SHA256, FEATURE_NODE_SHA256,
};
use serde_json::{json, Value};

fn pins() -> Value {
    let mut p = json!({});
    for key in [
        "build_result_sha256",
        "controller_tree_sha256",
        "uv_base_image_id",
        "rust_base_image_id",
        "policy_sha256",
        "podman_sha256",
        "slirp4netns_sha256",
        "apparmor_parser_sha256",
        "seccomp_sha256",
        "runner_binary_sha256",
    ] {
        p[key] = json!("b".repeat(64));
    }
    p["build_job_id"] = json!("0123456789abcdef");
    p["controller_root"] = json!("/opt/hol-gauntlet/controller-0123456789abcdef");
    p["builder_image_id"] = json!(format!("sha256:{}", "c".repeat(64)));
    p["executor_spec"] = json!({
        "schema":"hol-gauntlet-feature-executor.v1","audit_id":"0123456789abcdee",
        "source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
        "candidate_archive_sha256":"c".repeat(64),"wheel_sha256":"d".repeat(64),
        "native_sha256":"e".repeat(64),"version":"3.58.0","node_sha256":FEATURE_NODE_SHA256,
        "catalog_sha256":FEATURE_CATALOG_SHA256,"executor_sha256":"f".repeat(64)});
    p
}

#[test]
fn feature_intent_binds_source_build_every_runtime_pin_target_and_nonce() {
    let p = FeatureRunPins::from_value(pins()).unwrap();
    let intent =
        FeatureRunIntent::new(p, "/opt/homebrew/bin/limactl", "owned-vm", &"a".repeat(64)).unwrap();
    assert_eq!(
        FeatureRunIntent::parse(&intent.bytes().unwrap()).unwrap(),
        intent
    );
    for (key, value) in [
        ("vm", json!("other-vm")),
        ("host_nonce_hex", json!("b".repeat(64))),
    ] {
        let mut v: Value = serde_json::from_slice(&intent.bytes().unwrap()).unwrap();
        v[key] = value;
        let changed =
            FeatureRunIntent::parse(&canonicalize(v.to_string().as_bytes()).unwrap()).unwrap();
        assert_ne!(changed.digest().unwrap(), intent.digest().unwrap());
    }
    for (key, wrong) in [
        ("build_job_id", json!("0123456789abcdee")),
        ("controller_root", json!("/tmp/controller")),
        ("builder_image_id", json!("c".repeat(64))),
        ("seccomp_sha256", json!(true)),
        ("command", json!("pytest --skip-anything")),
    ] {
        let mut p = pins();
        p[key] = wrong;
        assert!(FeatureRunPins::from_value(p).is_err(), "{key}");
    }
    let mut p = pins();
    p["executor_spec"]["selectors"] = json!(["tests/anything.py"]);
    assert!(FeatureRunPins::from_value(p).is_err());
}

#[test]
fn ambiguous_intents_and_unsafe_targets_refuse_before_dispatch() {
    let pins = FeatureRunPins::from_value(pins()).unwrap();
    for (transport, vm, nonce) in [
        ("relative/limactl", "owned-vm", "a".repeat(64)),
        ("/tmp/../bin/limactl", "owned-vm", "a".repeat(64)),
        ("/bin/limactl", "-other", "a".repeat(64)),
        ("/bin/limactl", "vm;anything", "a".repeat(64)),
        ("/bin/limactl", "owned-vm", "a".repeat(63)),
    ] {
        assert!(FeatureRunIntent::new(pins.clone(), transport, vm, &nonce).is_err());
    }
    assert!(FeatureRunIntent::parse(br#"{"schema":1,"schema":2}"#).is_err());
    let intent = FeatureRunIntent::new(pins, "/bin/limactl", "owned-vm", &"a".repeat(64)).unwrap();
    let mut raw = intent.bytes().unwrap();
    raw.push(b'\n');
    assert!(FeatureRunIntent::parse(&raw).is_err());
}

#[test]
fn root_feature_response_cannot_convert_diagnostic_execution_into_qualification() {
    let intent = FeatureRunIntent::new(
        FeatureRunPins::from_value(pins()).unwrap(),
        "/bin/limactl",
        "owned-vm",
        &"a".repeat(64),
    )
    .unwrap();
    let mut v = json!({"schema":"hol-gauntlet-native-feature-result.v1",
        "audit_id":intent.pins().audit_id(),"source_sha":intent.pins().spec().text("source_sha"),
        "intent_sha256":intent.digest().unwrap(),"worker_generation":intent.pins().text("runner_binary_sha256"),
        "container_id":"a".repeat(64),"client_pid":123,"client_start_ticks":456,"exit_code":1,
        "execution_error":null,"audit_status":"incomplete","feature_report_sha256":"b".repeat(64),
        "feature_readback_sha256":"c".repeat(64),"stdout_sha256":"d".repeat(64),"stderr_sha256":"e".repeat(64),
        "feature_artifacts_verified":true,"container_absent":true,"container_cgroup_absent":true,
        "client_cgroup_drained":true,"build_profile_removed":true,"status":"invalid-evidence",
        "rust_root_supervised":true,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0,"model_tokens":0});
    gauntlet_contracts::verify_feature_run_result(&intent, &v).unwrap();
    for (key, bad) in [
        ("qualification_eligible", json!(true)),
        ("model_requests", json!(1)),
        ("exit_code", json!(0)),
        ("status", json!("passed")),
        ("container_absent", json!(false)),
        ("intent_sha256", json!("f".repeat(64))),
        ("feature_artifacts_verified", json!(false)),
        ("client_pid", json!(1)),
    ] {
        let mut changed = v.clone();
        changed[key] = bad;
        assert!(
            gauntlet_contracts::verify_feature_run_result(&intent, &changed).is_err(),
            "{key}"
        );
    }
    v["feature_artifacts_verified"] = json!(false);
    v["feature_report_sha256"] = Value::Null;
    v["feature_readback_sha256"] = Value::Null;
    v["audit_status"] = json!("invalid-evidence");
    v["execution_error"] = json!("executor failed before producing a valid report");
    v["exit_code"] = json!(2);
    gauntlet_contracts::verify_feature_run_result(&intent, &v).unwrap();
}
