//! Synthetic Root responses exercise the actual bounded Host journal chain.
//! No interpreter, VM, product or volume is started by these tests.
use super::*;
use std::{cell::Cell, fs, os::unix::fs::PermissionsExt, path::PathBuf};
struct Fixture {
    _temp: tempfile::TempDir,
    source: Value,
    candidate: PathBuf,
    dependency_source: Value,
    dependency: PathBuf,
}
fn fixture() -> Fixture {
    let (temp, source, candidate, _) =
        super::super::bounded::tests::artifact_fixture(&"e".repeat(64), 1024);
    let mut j = Journal::open(&candidate).unwrap();
    j.lock().unwrap();
    let s = &source["intent"];
    let job = text(s, "job_id").unwrap();
    let pin = crate::HostCandidateBuildPinJournal::open(&candidate)
        .unwrap()
        .read(job)
        .unwrap();
    let capture=super::super::parse(&bytes(&json!({"schema":"hol-gauntlet-host-candidate-artifact-intent.v1",
        "operation":"capture","job_id":job,"source_sha":s["source_sha"],"source_archive_sha256":s["source_archive_sha256"],
        "archive_sha256":"e".repeat(64),"version":pin.pins.version,"build_pin_sha256":pin.raw_sha256,
        "capture_proof_sha256":null,"worker_sha256":"a".repeat(64),"limactl":s["limactl"],"vm":s["vm"],
        "lima_sha256":s["lima_sha256"],"transport_context":s["transport_context"]})).unwrap()).unwrap();
    let captured = super::super::execute(&j, &capture, |i| {
        let mut v = super::super::tests::captured(i);
        v["wheel_sha256"] = json!("f".repeat(64));
        Ok(frame(&v))
    })
    .unwrap();
    let stage = super::super::tests::stage(&capture, &captured);
    super::super::execute(&j, &stage, |i| {
        let mut v = super::super::tests::staged(i);
        v["wheel_sha256"] = json!("f".repeat(64));
        Ok(frame(&v))
    })
    .unwrap();
    let root = temp.path().canonicalize().unwrap();
    let dep_source = super::super::source::tests::completed_sibling(
        &root.join("dep-source"),
        &source,
        &"2".repeat(16),
        "dependency-v1",
    );
    let dependency = root.join("dep-pins");
    super::super::dependencies::tests::prefix_fixture(&dependency, &dep_source);
    Fixture {
        _temp: temp,
        source,
        candidate,
        dependency_source: dep_source,
        dependency,
    }
}
fn frame(v: &Value) -> Vec<u8> {
    let mut raw = bytes(v).unwrap();
    raw.push(b'\n');
    raw
}
fn args(f: &Fixture, operation: &str) -> Vec<String> {
    let source = &f.source;
    let mut a = vec![
        operation.into(),
        f.candidate.to_str().unwrap().into(),
        text(source, "journal").unwrap().into(),
        text(source, "intent_sha256").unwrap().into(),
        text(&source["intent"], "job_id").unwrap().into(),
    ];
    match operation.strip_suffix("-read").unwrap_or(operation) {
        "prefix-stage" => {
            a[1] = f.dependency.to_str().unwrap().into();
            a[2] = text(&f.dependency_source, "journal").unwrap().into();
            a[3] = text(&f.dependency_source, "intent_sha256").unwrap().into();
            a[4] = text(&f.dependency_source["intent"], "job_id")
                .unwrap()
                .into();
            a.extend(["a".repeat(64), "b".repeat(64)]);
        }
        "prefix-clone" => a.extend([
            f.dependency.to_str().unwrap().into(),
            text(&f.dependency_source, "journal").unwrap().into(),
            text(&f.dependency_source, "intent_sha256").unwrap().into(),
            text(&f.dependency_source["intent"], "job_id")
                .unwrap()
                .into(),
            "c".repeat(64),
        ]),
        "runtime-publish" => a.extend(["3.12.3".into(), "d".repeat(64)]),
        _ => panic!("closed test operation"),
    }
    a
}
fn response(i: &Value) -> Value {
    let s = source(i);
    let mut v = match text(i, "operation").unwrap() {
        "prefix-stage" => {
            let p = &i["inputs"]["pins"];
            json!({"schema":"hol-gauntlet-native-dependency-prefix.v1","job_id":i["job_id"],"source_sha":s["source_sha"],
                "source_archive_sha256":s["source_archive_sha256"],"intent_sha256":i["inputs"]["dependency_intent_sha256"],
                "result_sha256":i["inputs"]["flow"]["result_sha256"],"dependency_archive_sha256":i["inputs"]["flow"]["archive_sha256"],
                "pyproject_sha256":p["pyproject_sha256"],"uv_lock_sha256":p["uv_lock_sha256"],"run_generation":p["runner_binary_sha256"],
                "stage_generation":i["worker_generation"],"python_sha256":i["python"],"python_path":"/usr/bin/python3.12",
                "prefix_tree_sha256":"e".repeat(64),"prefix_entries":120,"prefix_bytes":2048,"dependency_files":80,
                "dependency_entry_bytes_sha256":"f".repeat(64),"artifact_admitted":false,"execution_eligible":false,
                "guard_causality_verified":false,"model_requests":0})
        }
        "prefix-clone" => {
            json!({"schema":"hol-gauntlet-native-candidate-prefix.v1","job_id":i["job_id"],"source_sha":s["source_sha"],
            "source_archive_sha256":s["source_archive_sha256"],"archive_sha256":i["inputs"]["flow"]["archive_sha256"],"version":i["inputs"]["version"],
            "baseline_tree_sha256":i["dependency"]["receipt"]["prefix_tree_sha256"],"stage_tree_sha256":i["inputs"]["stage_tree_sha256"],
            "prefix_tree_sha256":"1".repeat(64),"prefix_entries":1700,"prefix_bytes":4096,"wheel_files":1646,
            "clone_generation":i["worker_generation"],"dependency_job_id":i["dependency"]["receipt"]["job_id"],
            "dependency_prefix_receipt_sha256":i["dependency"]["receipt_sha256"],"console_scripts":6,"candidate_executed":false,
            "dependency_validation_completed":false,"conformance_completed":false,"artifact_admitted":false,"execution_eligible":false,
            "guard_causality_verified":false,"model_requests":0})
        }
        "runtime-publish" => {
            let c = &i["inputs"]["candidate"];
            let clone = &i["inputs"]["clone"];
            json!({"schema":"hol-gauntlet-native-runtime-publication.v1","job_id":i["job_id"],"source_sha":s["source_sha"],"version":c["version"],
                "clone_receipt_sha256":clone["receipt_sha256"],"source_archive_sha256":s["source_archive_sha256"],"archive_sha256":c["flow"]["archive_sha256"],
                "dependency_prefix_receipt_sha256":clone["receipt"]["dependency_prefix_receipt_sha256"],"prefix":format!("/opt/hol-gauntlet/candidates/{}/prefix",text(s,"source_sha").unwrap()),
                "prefix_tree_sha256":clone["receipt"]["prefix_tree_sha256"],"prefix_entries":clone["receipt"]["prefix_entries"],"prefix_bytes":clone["receipt"]["prefix_bytes"],
                "native_sha256":c["native_sha256"],"publisher_generation":i["worker_generation"],
                "dependency_requirements":{"schema":"hol-gauntlet-candidate-dependencies-shadow.v1","job_id":i["job_id"],"source_sha":s["source_sha"],
                    "archive_sha256":c["flow"]["archive_sha256"],"native_sha256":c["native_sha256"],"prefix_tree_sha256":clone["receipt"]["prefix_tree_sha256"],
                    "python_full_version":i["python"],"installed_distributions":2,"requirements":3,"active_requirements":2,"inactive_requirements":1,
                    "active_names":["cryptography","mcp"],"all_active_requirements_satisfied":true,"candidate_executed":false,"conformance_completed":false,"artifact_admitted":false,"execution_eligible":false},
                "candidate_executed":false,"conformance_completed":false,"artifact_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0})
        }
        _ => panic!("closed test operation"),
    };
    if i["operation"] != "prefix-stage" {
        v["receipt_sha256"] = json!(sha(&bytes(&v).unwrap()));
    }
    v
}
fn perform(f: &Fixture, operation: &str) -> (Value, Value) {
    let a = args(f, operation);
    let (i, reading) = from_args(&a).unwrap();
    let mut j = Journal::open(Path::new(&a[1])).unwrap();
    j.lock().unwrap();
    let r = execute(&j, &i, reading, |argv, input| {
        assert!(input.is_empty());
        assert_eq!(
            argv.len(),
            match operation {
                "prefix-stage" => 8,
                "prefix-clone" => 12,
                _ => 10,
            }
        );
        Ok(frame(&response(&i)))
    })
    .unwrap();
    (i, r)
}
#[test]
fn bounded_readback_prefix_clone_and_runtime_form_one_original_chain() {
    let f = fixture();
    let (dep, staged) = perform(&f, "prefix-stage");
    assert_eq!(
        staged["receipt"]["intent_sha256"],
        dep["inputs"]["dependency_intent_sha256"]
    );
    let (clone, cloned) = perform(&f, "prefix-clone");
    assert_eq!(
        cloned["receipt"]["dependency_prefix_receipt_sha256"],
        staged["receipt_sha256"]
    );
    let (publish, published) = perform(&f, "runtime-publish");
    assert_eq!(
        published["receipt"]["clone_receipt_sha256"],
        cloned["receipt_sha256"]
    );
    assert_eq!(
        argv(&publish, false).unwrap()[5],
        text(&cloned, "receipt_sha256").unwrap()
    );
    assert_ne!(
        cloned["receipt_sha256"],
        sha(&bytes(&response(&clone)).unwrap())
    );
    assert_eq!(published["qualification_eligible"], false);
    assert_eq!(published["receipt"]["candidate_executed"], false);
    assert_eq!(
        publish["source"]["intent"]["transport_context"],
        clone["dependency"]["source"]["intent"]["transport_context"]
    );
}
#[test]
fn lost_or_malformed_stage_requires_original_read_and_keeps_failed_bytes() {
    for bad in [None, Some(b"{}\n".to_vec())] {
        let f = fixture();
        let a = args(&f, "prefix-stage");
        let (i, _) = from_args(&a).unwrap();
        let mut j = Journal::open(&f.dependency).unwrap();
        j.lock().unwrap();
        let calls = Cell::new(0);
        assert!(execute(&j, &i, false, |_, _| {
            calls.set(calls.get() + 1);
            bad.clone().ok_or("lost".into())
        })
        .is_err());
        let dispatch = j
            .read(text(&i, "job_id").unwrap(), &kind(&i, "dispatch").unwrap())
            .unwrap();
        assert!(super::super::idle(&j).is_err());
        assert!(execute(&j, &i, false, |_, _| panic!("prefix replay")).is_err());
        let r = execute(&j, &i, true, |argv, input| {
            calls.set(calls.get() + 1);
            assert!(input.is_empty());
            assert_eq!(argv[1], "--read-native-dependency-prefix");
            Ok(frame(&response(&i)))
        })
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(
            execute(&j, &i, true, |_, _| panic!("completed read replay")).unwrap(),
            r
        );
        assert_eq!(
            j.read(text(&i, "job_id").unwrap(), &kind(&i, "dispatch").unwrap())
                .unwrap(),
            dispatch
        );
        if let Some(bad) = bad {
            assert_eq!(
                j.read(
                    text(&i, "job_id").unwrap(),
                    &kind(&i, &format!("return-{}", sha(&bad))).unwrap()
                )
                .unwrap(),
                bad
            );
        }
        assert!(super::super::idle(&j).is_ok());
    }
}
#[test]
fn forged_readback_tree_receipt_or_admission_cannot_be_joined() {
    let f = fixture();
    perform(&f, "prefix-stage");
    for operation in ["prefix-stage", "prefix-clone"] {
        let (i, _) = from_args(&args(&f, operation)).unwrap();
        for key in [
            "source_sha",
            "source_archive_sha256",
            "prefix_entries",
            "execution_eligible",
            "extra",
        ] {
            let mut v = response(&i);
            v.as_object_mut().unwrap().remove("receipt_sha256");
            v[key] = match key {
                "prefix_entries" => json!(100001),
                "execution_eligible" => json!(true),
                _ => json!("0".repeat(64)),
            };
            if operation != "prefix-stage" {
                v["receipt_sha256"] = json!(sha(&bytes(&v).unwrap()));
            }
            assert!(
                protocol::receipt(&i, &frame(&v)).is_err(),
                "{operation}/{key}"
            );
        }
    }
    perform(&f, "prefix-clone");
    let (i, _) = from_args(&args(&f, "runtime-publish")).unwrap();
    for pointer in [
        "/clone_receipt_sha256",
        "/native_sha256",
        "/dependency_requirements/all_active_requirements_satisfied",
        "/dependency_requirements/active_requirements",
    ] {
        let mut v = response(&i);
        v.as_object_mut().unwrap().remove("receipt_sha256");
        *v.pointer_mut(pointer).unwrap() = if pointer.ends_with("satisfied") {
            json!(false)
        } else if pointer.ends_with("active_requirements") {
            json!(4)
        } else {
            json!("0".repeat(64))
        };
        v["receipt_sha256"] = json!(sha(&bytes(&v).unwrap()));
        assert!(protocol::receipt(&i, &frame(&v)).is_err(), "{pointer}");
    }
}
#[test]
fn read_without_dispatch_and_substituted_python_or_source_refuse() {
    let f = fixture();
    let (i, _) = from_args(&args(&f, "prefix-stage")).unwrap();
    let mut j = Journal::open(&f.dependency).unwrap();
    j.lock().unwrap();
    assert!(execute(&j, &i, true, |_, _| panic!("orphan read adoption")).is_err());
    j.retain(
        text(&i, "job_id").unwrap(),
        &kind(&i, "intent").unwrap(),
        &bytes(&i).unwrap(),
    )
    .unwrap();
    assert!(execute(&j, &i, true, |_, _| panic!("intent alone cannot adopt")).is_err());
    for pointer in [
        "/source/intent/source_sha",
        "/source/intent/storage_profile",
        "/inputs/flow/result_sha256",
        "/python",
    ] {
        let mut bad = i.clone();
        *bad.pointer_mut(pointer).unwrap() = json!("forged");
        assert!(
            execute(&j, &bad, false, |_, _| panic!("substituted dispatch")).is_err(),
            "{pointer}"
        );
    }
    assert!(j
        .absent(text(&i, "job_id").unwrap(), &kind(&i, "dispatch").unwrap())
        .unwrap());
}
#[test]
fn replacing_original_lima_instance_or_private_receipt_blocks_next_stage() {
    let f = fixture();
    perform(&f, "prefix-stage");
    let a = args(&f, "prefix-clone");
    assert!(from_args(&a).is_ok());
    let context = &f.source["intent"]["transport_context"];
    let instance = Path::new(text(&context["lima_home"], "path").unwrap())
        .join(text(&f.source["intent"], "vm").unwrap());
    fs::rename(&instance, instance.with_extension("held")).unwrap();
    fs::create_dir(&instance).unwrap();
    fs::set_permissions(&instance, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(from_args(&a).is_err());
}

#[test]
fn same_named_vm_under_other_original_homes_cannot_supply_the_baseline() {
    let mut candidate = fixture();
    let other = fixture();
    perform(&other, "prefix-stage");
    candidate.dependency = other.dependency.clone();
    candidate.dependency_source = other.dependency_source.clone();
    assert_eq!(
        candidate.source["intent"]["vm"],
        other.source["intent"]["vm"]
    );
    assert!(from_args(&args(&candidate, "prefix-clone")).is_err());
}
