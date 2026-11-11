use super::*;
use crate::HostCandidateBuildPins;
use std::{cell::Cell, fs, os::unix::fs::PermissionsExt};

const JOB: &str = "c04e7f93a2b15d68";
const VM: &str = "hol-artifact-fixture";
pub(super) fn pins(job: &str) -> HostCandidateBuildPins {
    HostCandidateBuildPins {
        job_id: job.into(),
        source_sha: "a".repeat(40),
        source_archive_sha256: "b".repeat(64),
        version: "3.49.0".into(),
        tag: format!("local-{}", "a".repeat(40)),
        controller_root: "/opt/hol-gauntlet/controller-1111111111111111".into(),
        controller_tree_sha256: "c".repeat(64),
        uv_base_image_id: "d".repeat(64),
        rust_base_image_id: "e".repeat(64),
        builder_image_id: format!("sha256:{}", "f".repeat(64)),
        policy_sha256: "1".repeat(64),
        podman_sha256: "2".repeat(64),
        slirp4netns_sha256: "3".repeat(64),
        apparmor_parser_sha256: "4".repeat(64),
        seccomp_sha256: "5".repeat(64),
        runner_binary_sha256: "6".repeat(64),
        result_reader_binary_sha256: "7".repeat(64),
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    journal: Journal,
    intent: Value,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    for name in ["journal", "ssh", "lima"] {
        fs::create_dir(root.join(name)).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::create_dir(root.join("lima").join(VM)).unwrap();
    let directory = root.join("journal");
    let pin = HostCandidateBuildPinJournal::open(&directory)
        .unwrap()
        .record_for_vm(&pins(JOB), LIMA, VM)
        .unwrap();
    let args = vec![
        "capture".into(),
        directory.to_str().unwrap().into(),
        JOB.into(),
        "a".repeat(40),
        "b".repeat(64),
        "c".repeat(64),
        "3.49.0".into(),
        pin.raw_sha256,
        "d".repeat(64),
        VM.into(),
        "e".repeat(64),
        root.join("ssh").to_str().unwrap().into(),
        root.join("lima").to_str().unwrap().into(),
    ];
    let intent = from_args(&args).unwrap();
    let mut journal = Journal::open(&directory).unwrap();
    journal.lock().unwrap();
    Fixture {
        _temp: temp,
        journal,
        intent,
    }
}
pub(super) fn captured(intent: &Value) -> Value {
    json!({"schema":"hol-gauntlet-candidate-capture-shadow.v1","job_id":intent["job_id"],
        "source_sha":intent["source_sha"],"source_archive_sha256":intent["source_archive_sha256"],
        "archive_sha256":intent["archive_sha256"],"archive_bytes":1024,"version":intent["version"],
        "wheel":"hol_guard-3.49.0-py3-none-linux_aarch64.whl","wheel_sha256":"1".repeat(64),
        "wheel_bytes":512,"native_sha256_claim":"2".repeat(64),"native_bytes_verified":false,
        "container_absent":true,"candidate_cgroup_absent":true,"build_profile_absent":true,
        "artifact_admitted":false,"execution_eligible":false})
}
pub(super) fn stage(intent: &Value, capture: &Value) -> Value {
    let mut intent = intent.clone();
    intent["operation"] = json!("wheel-stage");
    intent["worker_sha256"] = json!("f".repeat(64));
    intent["capture_proof_sha256"] = capture["proof_sha256"].clone();
    parse(&bytes(&intent).unwrap()).unwrap()
}
pub(super) fn staged(intent: &Value) -> Value {
    json!({"schema":"hol-gauntlet-candidate-wheel-stage-shadow.v1","job_id":intent["job_id"],
        "source_sha":intent["source_sha"],"archive_sha256":intent["archive_sha256"],
        "version":intent["version"],"wheel_sha256":"1".repeat(64),"wheel_entries":1646,
        "wheel_uncompressed_bytes":2048,"native_sha256":"2".repeat(64),
        "stage_tree_digest":"3".repeat(64),"stage_tree_entries":1697,"stage_tree_bytes":2048,
        "readback_verified":true,"candidate_executed":false,"installed_prefix_created":false,
        "artifact_admitted":false,"execution_eligible":false})
}
fn frame(value: &Value) -> Vec<u8> {
    let mut raw = bytes(value).unwrap();
    raw.push(b'\n');
    raw
}
fn bounded_fixture() -> Fixture {
    let (temp, source, path, _) = super::bounded::tests::artifact_fixture(&"e".repeat(64), 1024);
    let s = &source["intent"];
    let job = text(s, "job_id");
    let pin = HostCandidateBuildPinJournal::open(&path)
        .unwrap()
        .read(job)
        .unwrap();
    let intent=parse(&bytes(&json!({"schema":"hol-gauntlet-host-candidate-artifact-intent.v1","operation":"capture",
        "job_id":job,"source_sha":s["source_sha"],"source_archive_sha256":s["source_archive_sha256"],
        "archive_sha256":"e".repeat(64),"version":pin.pins.version,"build_pin_sha256":pin.raw_sha256,
        "capture_proof_sha256":null,"worker_sha256":"a".repeat(64),"vm":s["vm"],"limactl":s["limactl"],
        "lima_sha256":s["lima_sha256"],"transport_context":s["transport_context"]})).unwrap()).unwrap();
    let mut journal = Journal::open(&path).unwrap();
    journal.lock().unwrap();
    Fixture {
        _temp: temp,
        journal,
        intent,
    }
}
#[test]
fn completed_capture_read_preserves_initial_loss_and_authenticates_original_context() {
    for bad in [None, Some(b"{}\n".to_vec())] {
        let f = bounded_fixture();
        let job = text(&f.intent, "job_id");
        assert!(execute(&f.journal, &f.intent, |_| bad.clone().ok_or("lost".into())).is_err());
        let dispatch = f.journal.read(job, &suffix(&f.intent, "dispatch")).unwrap();
        let context = read_context(&f.journal, &f.intent, &"b".repeat(64)).unwrap();
        let response = archives::candidate_read_header(&f.intent, &context, &captured(&f.intent));
        let calls = Cell::new(0);
        let got = completed_read(&f.journal, &f.intent, &"b".repeat(64), |a, input| {
            calls.set(calls.get() + 1);
            assert!(input.is_empty());
            assert_eq!(a.len(), 12);
            assert_eq!(a[1], "--read-candidate-capture-v1");
            assert_eq!(a[7], text(&f.intent, "worker_sha256"));
            assert_eq!(a[8], text(&context, "host_pin_sha256"));
            Ok(frame(&response))
        })
        .unwrap();
        assert_eq!(got["proof"], captured(&f.intent));
        assert_eq!(got["qualification_eligible"], false);
        assert_eq!(
            execute(&f.journal, &f.intent, |_| panic!("capture replay")).unwrap(),
            got
        );
        assert_eq!(
            completed_read(&f.journal, &f.intent, &"b".repeat(64), |_, _| panic!(
                "completed read replay"
            ))
            .unwrap(),
            got
        );
        assert!(
            completed_read(&f.journal, &f.intent, &"c".repeat(64), |_, _| panic!(
                "different reader adoption"
            ))
            .is_err()
        );
        assert_eq!(calls.get(), 1);
        assert!(f.journal.absent(job, &suffix(&f.intent, "result")).unwrap());
        assert_eq!(
            f.journal.read(job, &suffix(&f.intent, "dispatch")).unwrap(),
            dispatch
        );
        if let Some(bad) = bad {
            assert_eq!(
                f.journal.read(job, &suffix(&f.intent, "return")).unwrap(),
                bad
            );
        }
        assert!(idle(&f.journal).is_ok());
    }
}
#[test]
fn completed_stage_read_refuses_substituted_pins_rehashed_proof_and_duplicate_result() {
    let f = bounded_fixture();
    let cap = execute(&f.journal, &f.intent, |_| Ok(frame(&captured(&f.intent)))).unwrap();
    let i = stage(&f.intent, &cap);
    let job = text(&i, "job_id");
    assert!(execute(&f.journal, &i, |_| Err("lost".into())).is_err());
    let context = read_context(&f.journal, &i, &"b".repeat(64)).unwrap();
    let response = archives::candidate_read_header(&i, &context, &staged(&i));
    for key in [
        "source_sha",
        "result_sha256",
        "host_pin_sha256",
        "storage_receipt_sha256",
        "original_producer_sha256",
        "reader_generation",
        "extra",
    ] {
        let mut bad = response.clone();
        bad[key] = json!("0".repeat(64));
        let raw = frame(&bad);
        assert!(
            completed_read(&f.journal, &i, &"b".repeat(64), |_, _| Ok(raw.clone())).is_err(),
            "{key}"
        );
        assert_eq!(
            f.journal
                .read(job, &suffix(&i, &format!("read-frame-{}", sha(&raw))))
                .unwrap(),
            raw
        );
        assert!(f.journal.absent(job, &suffix(&i, "read-result")).unwrap());
    }
    let mut bad = response.clone();
    bad["proof"]["candidate_executed"] = json!(true);
    assert!(completed_read(&f.journal, &i, &"b".repeat(64), |_, _| Ok(frame(&bad))).is_err());
    let got = completed_read(&f.journal, &i, &"b".repeat(64), |a, input| {
        assert!(input.is_empty());
        assert_eq!(a[1], "--read-candidate-wheel-stage-v1");
        Ok(frame(&response))
    })
    .unwrap();
    assert_eq!(got["proof"], staged(&i));
    assert!(idle(&f.journal).is_ok());
    f.journal
        .write(job, &suffix(&i, "result"), &bytes(&got).unwrap())
        .unwrap();
    assert!(retained(&f.journal, &i).is_err());
}
#[test]
fn artifact_completed_read_refuses_missing_dispatch_and_legacy_authority() {
    let f = bounded_fixture();
    assert!(
        completed_read(&f.journal, &f.intent, &"b".repeat(64), |_, _| panic!(
            "missing original dispatch"
        ))
        .is_err()
    );
    f.journal
        .retain(
            text(&f.intent, "job_id"),
            &suffix(&f.intent, "intent"),
            &bytes(&f.intent).unwrap(),
        )
        .unwrap();
    assert!(
        completed_read(&f.journal, &f.intent, &"b".repeat(64), |_, _| panic!(
            "intent-only adoption"
        ))
        .is_err()
    );
    let old = fixture();
    execute(&old.journal, &old.intent, |_| Err("lost legacy".into())).unwrap_err();
    assert!(
        completed_read(&old.journal, &old.intent, &"b".repeat(64), |_, _| panic!(
            "legacy v1 promotion"
        ))
        .is_err()
    );
}

#[test]
fn capture_then_stage_retains_original_proofs_and_never_replays() {
    let f = fixture();
    let calls = Cell::new(0);
    let response = captured(&f.intent);
    let captured = execute(&f.journal, &f.intent, |_| {
        calls.set(calls.get() + 1);
        Ok(frame(&response))
    })
    .unwrap();
    assert_eq!(captured["proof"], response);
    assert_eq!(captured["proof_sha256"], sha(&bytes(&response).unwrap()));
    assert_eq!(
        execute(&f.journal, &f.intent, |_| panic!("capture replay")).unwrap(),
        captured
    );
    let intent = stage(&f.intent, &captured);
    let staged = execute(&f.journal, &intent, |_| {
        calls.set(calls.get() + 1);
        Ok(frame(&staged(&intent)))
    })
    .unwrap();
    assert_eq!(
        execute(&f.journal, &intent, |_| panic!("stage replay")).unwrap(),
        staged
    );
    assert_eq!(staged["proof"]["readback_verified"], true);
    assert_eq!(staged["qualification_eligible"], false);
    assert_eq!(calls.get(), 2);
    let encoded = bytes(&staged).unwrap();
    assert!(!String::from_utf8(encoded).unwrap().contains("nonce"));
}
#[test]
fn uncertain_dispatch_blocks_other_jobs_and_preserves_return_evidence() {
    for response in [None, Some(b"{}\n".to_vec()), Some(b"{}\n\n".to_vec())] {
        let f = fixture();
        let calls = Cell::new(0);
        assert!(execute(&f.journal, &f.intent, |_| {
            calls.set(1);
            response.clone().ok_or("lost".into())
        })
        .is_err());
        let dispatch_before = f.journal.read(JOB, "artifact-capture-dispatch").unwrap();
        assert!(execute(&f.journal, &f.intent, |_| panic!("uncertain replay")).is_err());
        let other_job = "1111111111111111";
        let pin = HostCandidateBuildPinJournal::open(&f.journal.path)
            .unwrap()
            .record_for_vm(&pins(other_job), LIMA, VM)
            .unwrap();
        let mut other = f.intent.clone();
        other["job_id"] = json!(other_job);
        other["build_pin_sha256"] = json!(pin.raw_sha256);
        assert!(execute(&f.journal, &other, |_| panic!("unknown job bypass")).is_err());
        assert!(f
            .journal
            .absent(other_job, "artifact-capture-dispatch")
            .unwrap());
        assert_eq!(
            f.journal.read(JOB, "artifact-capture-dispatch").unwrap(),
            dispatch_before
        );
        assert_eq!(calls.get(), 1);
    }
}
#[test]
fn outside_build_identity_substitution_refuses_before_dispatch() {
    for key in [
        "source_sha",
        "source_archive_sha256",
        "build_pin_sha256",
        "version",
        "vm",
    ] {
        let f = fixture();
        let mut changed = f.intent.clone();
        changed[key] = json!(match key {
            "source_sha" => "f".repeat(40),
            "version" => "3.48.0".into(),
            "vm" => "hol-another-instance".into(),
            _ => "f".repeat(64),
        });
        assert!(
            execute(&f.journal, &changed, |_| panic!("identity substitution")).is_err(),
            "{key}"
        );
        assert!(f.journal.absent(JOB, "artifact-capture-dispatch").unwrap());
    }
}
#[test]
fn producer_proof_substitution_is_retained_but_never_accepted() {
    for key in [
        "source_archive_sha256",
        "archive_sha256",
        "container_absent",
        "execution_eligible",
        "extra",
    ] {
        let f = fixture();
        let mut response = captured(&f.intent);
        response[key] = if key.ends_with("sha256") {
            json!("f".repeat(64))
        } else {
            json!(true)
        };
        if key == "container_absent" {
            response[key] = json!(false);
        }
        assert!(
            execute(&f.journal, &f.intent, |_| Ok(frame(&response))).is_err(),
            "{key}"
        );
        assert_eq!(
            f.journal.read(JOB, "artifact-capture-return").unwrap(),
            frame(&response)
        );
        assert!(f.journal.absent(JOB, "artifact-capture-result").unwrap());
        assert!(execute(&f.journal, &f.intent, |_| panic!("forged proof replay")).is_err());
    }
}
#[test]
fn stage_requires_exact_outside_capture_digest_and_real_native_digest() {
    for key in [
        "capture_proof_sha256",
        "wheel_sha256",
        "native_sha256",
        "readback_verified",
    ] {
        let f = fixture();
        let capture = execute(&f.journal, &f.intent, |_| Ok(frame(&captured(&f.intent)))).unwrap();
        let mut intent = stage(&f.intent, &capture);
        let mut response = staged(&intent);
        if key == "capture_proof_sha256" {
            intent[key] = json!("f".repeat(64));
        } else {
            response[key] = if key == "readback_verified" {
                json!(false)
            } else {
                json!("f".repeat(64))
            };
        }
        assert!(
            execute(&f.journal, &intent, |_| Ok(frame(&response))).is_err(),
            "{key}"
        );
        assert_eq!(
            f.journal
                .absent(JOB, "artifact-wheel-stage-dispatch")
                .unwrap(),
            key == "capture_proof_sha256"
        );
        assert!(f
            .journal
            .absent(JOB, "artifact-wheel-stage-result")
            .unwrap());
    }
}
#[test]
fn original_instance_replacement_refuses_read_and_new_staging() {
    let f = fixture();
    let capture = execute(&f.journal, &f.intent, |_| Ok(frame(&captured(&f.intent)))).unwrap();
    let staging = stage(&f.intent, &capture);
    let lima = Path::new(text(&f.intent["transport_context"]["lima_home"], "path"));
    fs::rename(lima.join(VM), lima.join("retained-original")).unwrap();
    fs::create_dir(lima.join(VM)).unwrap();
    assert!(execute(&f.journal, &f.intent, |_| panic!(
        "redirected original read"
    ))
    .is_err());
    assert!(execute(&f.journal, &staging, |_| panic!("redirected stage")).is_err());
    assert!(f
        .journal
        .absent(JOB, "artifact-wheel-stage-dispatch")
        .unwrap());
}
