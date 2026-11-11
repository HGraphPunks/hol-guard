//! Synthetic dependency receipts and temporary ledgers only.
use super::*;
use gauntlet_contracts::DependencyPreparationState;
use std::{fs, os::unix::fs::PermissionsExt};
fn fixture() -> (tempfile::TempDir, Journal, Value) {
    let (temp, source) = super::super::source::tests::completed_profile("dependency-v1");
    let path = temp.path().canonicalize().unwrap().join("dependency-pins");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let i = intent_for(&source);
    let mut j = Journal::open(&path).unwrap();
    j.lock().unwrap();
    (temp, j, i)
}
fn intent_for(source: &Value) -> Value {
    let s = &source["intent"];
    let p=DependencyRunPins::from_value(json!({"job_id":s["job_id"],"source_sha":s["source_sha"],"source_archive_sha256":s["source_archive_sha256"],
        "capsule_sha256":"c".repeat(64),"capsule_bytes":1551712,"pyproject_sha256":"d".repeat(64),"uv_lock_sha256":"e".repeat(64),"exporter_sha256":"f".repeat(64),"capture_worker_sha256":"1".repeat(64),"capture_receipt_sha256":"2".repeat(64),
        "controller_root":"/opt/hol-gauntlet/controller-0123456789abcdef","controller_tree_sha256":"3".repeat(64),"uv_base_image_id":"4".repeat(64),"rust_base_image_id":"5".repeat(64),"builder_image_id":format!("sha256:{}","6".repeat(64)),"policy_sha256":"7".repeat(64),"podman_sha256":"8".repeat(64),"slirp4netns_sha256":"9".repeat(64),"apparmor_parser_sha256":"a".repeat(64),"seccomp_sha256":"b".repeat(64),"runner_binary_sha256":"c".repeat(64)})).unwrap();
    parse(&bytes(&json!({"schema":"hol-gauntlet-host-bounded-dependency.v1","job_id":p.text("job_id"),"source":source,"pins":p.value(),"execution_eligible":false,"qualification_eligible":false})).unwrap()).unwrap()
}
pub(crate) fn prefix_fixture(path: &Path, source: &Value) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    let i = intent_for(source);
    let mut j = Journal::open(path).unwrap();
    j.lock().unwrap();
    execute(&j, &i, |_, input, _, _, _| {
        Ok(frame(&report(&DependencyRunIntent::parse(input).unwrap())))
    })
    .unwrap();
    later(
        &j,
        &i,
        "read-bounded",
        &"c".repeat(64),
        None,
        |_, input, _, _, _| {
            Ok(frame(&read_response(
                &DependencyRunIntent::parse(input).unwrap(),
                &"c".repeat(64),
            )))
        },
    )
    .unwrap();
    prefix_inputs(path, source, text(&i, "job_id").unwrap()).unwrap();
}
fn report(d: &DependencyRunIntent) -> Value {
    json!({"schema":"hol-gauntlet-native-dependency-result.v1","intent_sha256":d.digest().unwrap(),"job_id":d.pins.text("job_id"),"source_sha":d.pins.text("source_sha"),"worker_generation":d.pins.text("runner_binary_sha256"),"intent":serde_json::from_slice::<Value>(&d.bytes().unwrap()).unwrap(),"status":"invalid-evidence","exit_code":0,"captured_dependencies_bytes":1024,"captured_dependencies_sha256":"e".repeat(64),"guard_causality_verified":false,"execution_eligible":false,"artifact_admitted":false,"qualification_eligible":false,"model_requests":0,"model_tokens":0,"container_absent":true,"container_cgroup_absent":true,"client_cgroup_drained":true,"build_profile_removed":true})
}
fn frame(v: &Value) -> Vec<u8> {
    let mut raw = bytes(v).unwrap();
    raw.push(b'\n');
    raw
}
fn read_response(d: &DependencyRunIntent, generation: &str) -> Value {
    let report = report(d);
    json!({"schema":"hol-gauntlet-native-dependency-read.v1","reader_generation":generation,"intent_sha256":d.digest().unwrap(),"report_sha256":sha(&bytes(&report).unwrap()),"terminal_sha256":"f".repeat(64),"report":report,"archive_proof":{"schema":"hol-gauntlet-native-dependency-archive-readback.v1","files":3,"directories":2,"decoded_bytes":100,"entry_bytes_sha256":"d".repeat(64),"archive_sha256":"e".repeat(64),"dependency_imported":false,"artifact_admitted":false,"execution_eligible":false},"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,"guard_causality_verified":false,"model_requests":0,"model_tokens":0})
}
#[test]
fn bounded_dependency_run_read_and_artifact_flow_preserve_opaque_original_context() {
    let (_temp, j, i) = fixture();
    let got = execute(&j, &i, |argv, input, _, _, _| {
        assert_eq!(argv[7], "--prepare-native-dependencies");
        let d = DependencyRunIntent::parse(input).unwrap();
        Ok(frame(&report(&d)))
    })
    .unwrap();
    assert_eq!(got["original_source_transport_verified"], true);
    assert!(execute(&j, &i, |_, _, _, _, _| panic!("dependency replay")).is_err());
    let read = later(
        &j,
        &i,
        "read-bounded",
        &"c".repeat(64),
        None,
        |argv, input, _, _, _| {
            assert_eq!(argv[7], "--read-native-dependencies");
            let d = DependencyRunIntent::parse(input).unwrap();
            Ok(frame(&read_response(&d, &"c".repeat(64))))
        },
    )
    .unwrap();
    assert_eq!(read["result"]["retained_result_reconciled"], true);
    let context = flow(
        &j.path,
        &i["source"],
        text(&i, "job_id").unwrap(),
        text(&read["result"], "private_result_sha256").unwrap(),
        &"e".repeat(64),
    )
    .unwrap();
    assert_eq!(
        context["host_binding_sha256"],
        got["dependency_intent_sha256"]
    );
    assert!(flow(
        &j.path,
        &i["source"],
        text(&i, "job_id").unwrap(),
        &"f".repeat(64),
        &"e".repeat(64)
    )
    .is_err());
    verify_idle_record(
        &j,
        &Journal::name(text(&i, "job_id").unwrap(), DISPATCH).unwrap(),
    )
    .unwrap();
}
#[test]
fn unknown_prepare_can_only_reconcile_then_authorize_exact_original_repair() {
    let (_temp, j, i) = fixture();
    assert!(execute(&j, &i, |_, _, _, _, _| Err(FixedProcessError::Failed)).is_err());
    assert!(verify_idle_record(
        &j,
        &Journal::name(text(&i, "job_id").unwrap(), DISPATCH).unwrap()
    )
    .is_err());
    let deps = DependencyIntentJournal::open(&j.path).unwrap();
    let d = deps.read(text(&i, "job_id").unwrap()).unwrap();
    let state =
        DependencyPreparationState::inspect(&d, Some(b"{"), Some(&"a".repeat(64)), None, None)
            .unwrap();
    let gen = "c".repeat(64);
    let result = later(
        &j,
        &i,
        "repair-bounded",
        &gen,
        Some(&state.expected_started_sha256),
        |argv, input, _, _, _| {
            let raw = if argv[7] == "--read-native-dependencies" {
                state.unknown(&d, &gen).unwrap()
            } else {
                assert_eq!(input, d.bytes().unwrap());
                state.retired(&d, &gen).unwrap()
            };
            let mut raw = raw;
            raw.push(b'\n');
            Ok(raw)
        },
    )
    .unwrap();
    assert_eq!(result["result"]["status"], "aborted");
    verify_idle_record(
        &j,
        &Journal::name(text(&i, "job_id").unwrap(), DISPATCH).unwrap(),
    )
    .unwrap();
    assert!(execute(&j, &i, |_, _, _, _, _| panic!("repair rearm")).is_err());
}
#[test]
fn wrong_source_profile_and_legacy_intents_refuse_before_prepare() {
    let (_temp, j, i) = fixture();
    let mut bad = i.clone();
    bad["source"]["intent"]["storage_profile"] = json!("build-v1");
    assert!(execute(&j, &bad, |_, _, _, _, _| panic!("wrong profile")).is_err());
    let deps = DependencyIntentJournal::open(&j.path).unwrap();
    let ops =
        crate::public_vm_operations(Some(text(&i["source"]["intent"], "vm").unwrap())).unwrap();
    deps.record(
        DependencyRunPins::from_value(i["pins"].clone()).unwrap(),
        &ops,
    )
    .unwrap();
    assert!(execute(&j, &i, |_, _, _, _, _| panic!("legacy promotion")).is_err());
    assert!(j.absent(text(&i, "job_id").unwrap(), INTENT).unwrap());
}
