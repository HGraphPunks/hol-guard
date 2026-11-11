//! Pure mocked fixed-protocol boundaries; no candidate, VM or volume runs.
use super::*;
use std::{cell::Cell, fs, os::unix::fs::PermissionsExt};
struct Fixture {
    _temp: tempfile::TempDir,
    j: Journal,
    i: Value,
}
fn fixture() -> Fixture {
    let (temp, source) = super::super::source::tests::completed_fixture();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("build-pins");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let s = &source["intent"];
    let mut p = super::super::tests::pins(text(s, "job_id").unwrap());
    p.source_sha = text(s, "source_sha").unwrap().into();
    p.source_archive_sha256 = text(s, "source_archive_sha256").unwrap().into();
    let i=parse(&bytes(&json!({"schema":"hol-gauntlet-host-bounded-candidate-build.v1","job_id":p.job_id,
        "source":source,"build_pins":value(&p),"readiness_binary_sha256":"a".repeat(64),"execution_eligible":false,"qualification_eligible":false})).unwrap()).unwrap();
    let mut j = Journal::open(&path).unwrap();
    j.lock().unwrap();
    Fixture { _temp: temp, j, i }
}
fn ready(i: &Value) -> Value {
    let p = &i["build_pins"];
    json!({"schema":"hol-gauntlet-candidate-build-ready-shadow.v2","job_id":p["job_id"],"source_sha":p["source_sha"],
        "source_archive_sha256":p["source_archive_sha256"],"tag":p["tag"],"image_id":p["builder_image_id"],"policy_sha256":p["policy_sha256"],
        "free_disk_bytes":24_u64*1024*1024*1024,"ready_at_probe":true,"host_pin_recorded":false,"candidate_started":false,"artifact_admitted":false,"execution_eligible":false})
}
fn frame(v: &Value) -> Vec<u8> {
    let mut raw = bytes(v).unwrap();
    raw.push(b'\n');
    raw
}
fn terminal(j: &Journal, i: &Value) -> Value {
    // The nonce exists only inside the official temporary Rust pin API/wire.
    let r = HostCandidateBuildPinJournal::open(&j.path)
        .unwrap()
        .read(text(i, "job_id").unwrap())
        .unwrap();
    let p = &r.pins;
    let mut v = json!({"schema":"hol-gauntlet-candidate-build-result.v3","job_id":p.job_id,"source_sha":p.source_sha,
        "source_archive_sha256":p.source_archive_sha256,"source_bytes":source(i)["source_bytes"],"local_version":p.version,"tag":p.tag,
        "image_id":p.builder_image_id,"policy_sha256":p.policy_sha256,"runtime_pins":{"podman_sha256":p.podman_sha256,"slirp4netns_sha256":p.slirp4netns_sha256,"apparmor_parser_sha256":p.apparmor_parser_sha256,"seccomp_sha256":p.seccomp_sha256},
        "host_pin_sha256":r.raw_sha256,"host_nonce_hex":r.host_nonce_hex,"runner_binary_sha256":p.runner_binary_sha256,"result_reader_binary_sha256":p.result_reader_binary_sha256,
        "host_anchor_sha256":VmCandidateBuildInvocation::anchor_sha256(&r).unwrap(),"stdout_sha256":"a".repeat(64),"stderr_sha256":"b".repeat(64),"client_pid":123,"client_start_ticks":456,
        "status":"exited-zero","exit_code":0,"unadmitted_export_bytes":1024,"unadmitted_export_sha256":"e".repeat(64),
        "container_absent":true,"candidate_cgroup_drained":true,"build_profile_removed":true,"artifact_admitted":false,"execution_eligible":false});
    v["result_sha256"] = json!(sha(&bytes(&v).unwrap()));
    v
}
fn successful(f: &Fixture) -> Value {
    run(&f.j, &f.i, |i, argv, _, _| {
        if argv[6].contains("-build-ready-") {
            assert!(matches!(
                HostCandidateBuildPinJournal::open(&f.j.path)
                    .unwrap()
                    .read(text(i, "job_id").unwrap()),
                Err(crate::HostCandidateBuildPinError::Missing)
            ));
            Ok(frame(&ready(i)))
        } else {
            Ok(frame(&terminal(&f.j, i)))
        }
    })
    .unwrap()
}
pub(crate) fn artifact_fixture(
    archive: &str,
    archive_bytes: usize,
) -> (tempfile::TempDir, Value, std::path::PathBuf, String) {
    let f = fixture();
    let result = run(&f.j, &f.i, |i, argv, _, _| {
        if argv[6].contains("-build-ready-") {
            return Ok(frame(&ready(i)));
        }
        let mut v = terminal(&f.j, i);
        v.as_object_mut().unwrap().remove("result_sha256");
        v["unadmitted_export_sha256"] = json!(archive);
        v["unadmitted_export_bytes"] = json!(archive_bytes);
        v["result_sha256"] = json!(sha(&bytes(&v).unwrap()));
        Ok(frame(&v))
    })
    .unwrap();
    let result_sha = text(&result["claim"], "result_sha256").unwrap().to_owned();
    read(&f.j, &f.i, &result_sha, archive, |i, _, _, _| {
        let mut v = read_reply(&f.j, i, &result_sha);
        v["archive_sha256"] = json!(archive);
        Ok(frame(&v))
    })
    .unwrap();
    (f._temp, f.i["source"].clone(), f.j.path.clone(), result_sha)
}
fn artifact(f: &Fixture, result: &Value) -> Value {
    let s = source(&f.i);
    json!({"schema":"hol-gauntlet-host-candidate-artifact-intent.v1","operation":"capture","job_id":f.i["job_id"],
        "source_sha":f.i["build_pins"]["source_sha"],"source_archive_sha256":f.i["build_pins"]["source_archive_sha256"],
        "archive_sha256":"e".repeat(64),"version":f.i["build_pins"]["version"],"build_pin_sha256":result["claim"]["host_pin_sha256"],
        "capture_proof_sha256":null,"worker_sha256":"f".repeat(64),"limactl":s["limactl"],"vm":s["vm"],"lima_sha256":s["lima_sha256"],"transport_context":s["transport_context"]})
}
fn read_reply(j: &Journal, i: &Value, result_sha: &str) -> Value {
    let r = HostCandidateBuildPinJournal::open(&j.path)
        .unwrap()
        .read(text(i, "job_id").unwrap())
        .unwrap();
    let p = &r.pins;
    json!({"schema":"hol-gauntlet-candidate-result-read-shadow.v3","job_id":p.job_id,"source_sha":p.source_sha,"tag":p.tag,
        "result_sha256":result_sha,"archive_sha256":"e".repeat(64),"version":p.version,"host_pin_sha256":r.raw_sha256,
        "runner_binary_sha256":p.runner_binary_sha256,"result_reader_binary_sha256":p.result_reader_binary_sha256,"image_id":p.builder_image_id,"policy_sha256":p.policy_sha256,
        "host_anchor_sha256":VmCandidateBuildInvocation::anchor_sha256(&r).unwrap(),"wheel_sha256":"f".repeat(64),"client_pid":123,"client_start_ticks":456,
        "retained_files_match":true,"cleanup_absent":true,"host_anchor_present":true,"artifact_admitted":false,"execution_eligible":false})
}
fn lost_terminal(f: &Fixture, partial: bool) -> String {
    let mut digest = None;
    assert!(run(&f.j, &f.i, |i, argv, _, _| {
        if argv[6].contains("-build-ready-") {
            return Ok(frame(&ready(i)));
        }
        let v = terminal(&f.j, i);
        digest = Some(text(&v, "result_sha256").unwrap().to_owned());
        if partial {
            Ok(b"{".to_vec())
        } else {
            Err("lost terminal pipe".into())
        }
    })
    .is_err());
    digest.unwrap()
}
fn pending_artifact(f: &Fixture) -> Value {
    let pin = HostCandidateBuildPinJournal::open(&f.j.path)
        .unwrap()
        .read(text(&f.i, "job_id").unwrap())
        .unwrap();
    artifact(f, &json!({"claim":{"host_pin_sha256":pin.raw_sha256}}))
}
#[test]
fn lost_terminal_capture_then_authenticated_read_unblocks_without_forging_original() {
    for partial in [false, true] {
        let f = fixture();
        let result_sha = lost_terminal(&f, partial);
        let job = text(&f.i, "job_id").unwrap();
        assert!(super::super::idle(&f.j).is_err());
        let capture = pending_artifact(&f);
        let captured = super::super::execute(&f.j, &capture, |i| {
            let mut v = super::super::tests::captured(i);
            v["wheel_sha256"] = json!("f".repeat(64));
            Ok(frame(&v))
        })
        .unwrap();
        let stage = super::super::tests::stage(&capture, &captured);
        assert!(super::super::execute(&f.j, &stage, |_| panic!("stage before terminal")).is_err());
        read(&f.j, &f.i, &result_sha, &"e".repeat(64), |i, _, _, _| {
            Ok(frame(&read_reply(&f.j, i, &result_sha)))
        })
        .unwrap();
        let claim = retained_claim(&f.j, &f.i).unwrap();
        assert_eq!(
            claim["schema"],
            "hol-gauntlet-host-candidate-completed-read-terminal.v1"
        );
        assert_eq!(claim["exit_code"], 0);
        assert_eq!(claim["qualification_eligible"], false);
        assert!(f.j.absent(job, CLAIM).unwrap());
        if partial {
            assert_eq!(f.j.read(job, RETURN).unwrap(), b"{");
        } else {
            assert!(f.j.absent(job, RETURN).unwrap());
        }
        assert!(super::super::idle(&f.j).is_ok());
        super::super::execute(&f.j, &stage, |i| {
            let mut v = super::super::tests::staged(i);
            v["wheel_sha256"] = json!("f".repeat(64));
            Ok(frame(&v))
        })
        .unwrap();
        prefix_inputs(&f.j.path, &f.i["source"], job).unwrap();
        flow(&f.j.path, &f.i["source"], job, &result_sha, &"e".repeat(64)).unwrap();
        assert!(run(&f.j, &f.i, |_, _, _, _| panic!("recovered workload replay")).is_err());
        assert!(read(
            &f.j,
            &f.i,
            &"0".repeat(64),
            &"e".repeat(64),
            |_, _, _, _| panic!("different immutable result")
        )
        .is_err());
    }
}
#[test]
fn recovery_refuses_rehashed_wrong_nonce_anchor_identity_partial_or_nonzero_claims() {
    let f = fixture();
    let result_sha = lost_terminal(&f, false);
    let job = text(&f.i, "job_id").unwrap();
    let original = read_reply(&f.j, &f.i, &result_sha);
    let mut wrong_pin = HostCandidateBuildPinJournal::open(&f.j.path)
        .unwrap()
        .read(job)
        .unwrap();
    wrong_pin.host_nonce_hex = "0".repeat(64);
    let wrong_anchor = VmCandidateBuildInvocation::anchor_sha256(&wrong_pin).unwrap();
    for (key, value) in [
        ("host_anchor_sha256", json!(wrong_anchor)),
        ("source_sha", json!("0".repeat(40))),
        ("job_id", json!("0".repeat(16))),
        ("host_pin_sha256", json!("0".repeat(64))),
        ("cleanup_absent", json!(false)),
        ("exit_code", json!(1)),
        ("status", json!("unknown")),
    ] {
        let mut bad = original.clone();
        bad[key] = value;
        let raw = frame(&bad);
        assert!(
            read(&f.j, &f.i, &result_sha, &"e".repeat(64), |_, _, _, _| Ok(
                raw.clone()
            ))
            .is_err(),
            "{key}"
        );
        assert_eq!(
            f.j.read(job, &format!("bounded-build-read-frame-{}", sha(&raw)))
                .unwrap(),
            raw
        );
        assert!(f.j.absent(job, RECOVERED).unwrap());
    }
    assert!(
        read(&f.j, &f.i, &result_sha, &"e".repeat(64), |_, _, _, _| Ok(
            b"{".to_vec()
        ))
        .is_err()
    );
    assert!(retained_claim(&f.j, &f.i).is_err());
    read(&f.j, &f.i, &result_sha, &"e".repeat(64), |_, _, _, _| {
        Ok(frame(&original))
    })
    .unwrap();
    let mut body: Value = serde_json::from_slice(&f.j.read(job, RECOVERED).unwrap()).unwrap();
    body["terminal"]["result_sha256"] = json!("0".repeat(64));
    fs::write(
        f.j.path.join(Journal::name(job, RECOVERED).unwrap()),
        bytes(&body).unwrap(),
    )
    .unwrap();
    assert!(retained_claim(&f.j, &f.i).is_err());
    assert!(super::super::idle(&f.j).is_err());
}
#[test]
fn complete_original_return_without_claim_recovers_and_refuses_substituted_anchor() {
    for substituted_anchor in [false, true] {
        let f = fixture();
        let result_sha = lost_terminal(&f, false);
        let job = text(&f.i, "job_id").unwrap();
        let mut original = terminal(&f.j, &f.i);
        if substituted_anchor {
            original["host_anchor_sha256"] = json!("0".repeat(64));
            original.as_object_mut().unwrap().remove("result_sha256");
            original["result_sha256"] = json!(sha(&bytes(&original).unwrap()));
        }
        let result_sha = if substituted_anchor {
            text(&original, "result_sha256").unwrap().to_owned()
        } else {
            result_sha
        };
        let raw = frame(&original);
        f.j.write(job, RETURN, &raw).unwrap();
        let result = read(&f.j, &f.i, &result_sha, &"e".repeat(64), |i, _, _, _| {
            Ok(frame(&read_reply(&f.j, i, &result_sha)))
        });
        assert_eq!(result.is_err(), substituted_anchor);
        assert_eq!(f.j.read(job, RETURN).unwrap(), raw);
        assert!(f.j.absent(job, CLAIM).unwrap());
        if !substituted_anchor {
            assert_eq!(retained_claim(&f.j, &f.i).unwrap()["status"], "exited-zero");
        }
    }
}
#[test]
fn attached_build_observes_original_unknown_then_verified_recovery_without_dispatch() {
    let f = fixture();
    let result_sha = lost_terminal(&f, false);
    let job = text(&f.i, "job_id").unwrap();
    let root = f._temp.path().canonicalize().unwrap();
    let store =
        crate::HostLifecycleStore::initialize(&root, "hashgraph-online/hol-guard", 1000).unwrap();
    let attached = store
        .attach_job(
            "bounded-build",
            &f.j.path,
            job,
            &sha(&bytes(&f.i).unwrap()),
            1100,
        )
        .unwrap();
    assert_eq!(attached["state"], "unknown");
    assert_eq!(store.status(1200).unwrap()["unknown_jobs"], 1);
    let original = f.j.read(job, DISPATCH).unwrap();
    read(&f.j, &f.i, &result_sha, &"e".repeat(64), |i, _, _, _| {
        Ok(frame(&read_reply(&f.j, i, &result_sha)))
    })
    .unwrap();
    let refreshed = store
        .refresh_job(job, attached["attachment_sha256"].as_str().unwrap(), 1300)
        .unwrap();
    assert_eq!(refreshed["phase"], "result-reconciled");
    assert_eq!(refreshed["state"], "diagnostic-passed");
    assert_eq!(refreshed["execution_eligible"], false);
    assert_eq!(f.j.read(job, DISPATCH).unwrap(), original);
    let status = store.status(1400).unwrap();
    assert_eq!(status["unknown_jobs"], 0);
    assert_eq!(status["gate"]["status"], "unavailable");
    assert!(!status.to_string().contains(f.j.path.to_str().unwrap()));
}
#[test]
fn pending_capture_cannot_bypass_other_unknown_jobs_or_missing_original_launch() {
    let f = fixture();
    lost_terminal(&f, false);
    let capture = pending_artifact(&f);
    f.j.write(&"2".repeat(16), DISPATCH, b"{}").unwrap();
    assert!(
        super::super::execute(&f.j, &capture, |_| panic!("unknown other build bypass")).is_err()
    );
    assert!(f
        .j
        .absent(text(&f.i, "job_id").unwrap(), "artifact-capture-dispatch")
        .unwrap());
    fs::write(
        f.j.path
            .join(Journal::name(text(&f.i, "job_id").unwrap(), LAUNCH).unwrap()),
        b"{}",
    )
    .unwrap();
    assert!(verify_artifact_binding(&f.j, &capture).is_err());
}
#[test]
fn source_bound_run_and_read_use_original_opaque_protocol_and_never_rearm() {
    let f = fixture();
    let result = successful(&f);
    assert_eq!(result["original_source_transport_verified"], true);
    assert_eq!(result["qualification_eligible"], false);
    assert!(!String::from_utf8(bytes(&result).unwrap())
        .unwrap()
        .contains("nonce"));
    assert!(run(&f.j, &f.i, |_, _, _, _| panic!("bounded run replay")).is_err());
    let result_sha = text(&result["claim"], "result_sha256").unwrap();
    let report = read(&f.j, &f.i, result_sha, &"e".repeat(64), |i, argv, _, _| {
        assert!(argv[6].starts_with("/opt/hol-gauntlet/rust-candidate-result-hostbound-shadow-"));
        Ok(frame(&read_reply(&f.j, i, result_sha)))
    })
    .unwrap();
    assert_eq!(report["readback"]["host_pin_journal_match"], true);
    assert!(read(
        &f.j,
        &f.i,
        &"f".repeat(64),
        &"e".repeat(64),
        |_, _, _, _| panic!("outside result substitution")
    )
    .is_err());
}
#[test]
fn readiness_and_partial_run_loss_are_consumed_and_block_later_dispatch() {
    for fail_ready in [true, false] {
        let f = fixture();
        let calls = Cell::new(0);
        assert!(run(&f.j, &f.i, |i, _, _, _| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 && !fail_ready {
                Ok(frame(&ready(i)))
            } else {
                Err("lost".into())
            }
        })
        .is_err());
        assert!(run(&f.j, &f.i, |_, _, _, _| panic!("lost run replay")).is_err());
        assert!(super::super::idle(&f.j).is_err());
        assert_eq!(calls.get(), if fail_ready { 1 } else { 2 });
        assert!(f.j.absent(text(&f.i, "job_id").unwrap(), CLAIM).unwrap());
    }
}
#[test]
fn old_v4_pin_cannot_be_rebound_or_read_as_new_bounded_run() {
    let f = fixture();
    let keys = HostCandidateBuildPinJournal::open(&f.j.path).unwrap();
    plan(&f.i).unwrap().record_before_launch(&keys).unwrap();
    assert!(run(&f.j, &f.i, |_, _, _, _| panic!("old pin promotion")).is_err());
    assert!(f.j.absent(text(&f.i, "job_id").unwrap(), INTENT).unwrap());
    assert!(read(
        &f.j,
        &f.i,
        &"e".repeat(64),
        &"e".repeat(64),
        |_, _, _, _| panic!("old read promotion")
    )
    .is_err());
}
#[test]
fn source_job_archive_profile_and_journal_replacements_refuse_before_readiness() {
    for pointer in [
        "/build_pins/source_sha",
        "/build_pins/source_archive_sha256",
        "/source/intent/storage_profile",
        "/source/journal_custody/ancestry/0/inode",
    ] {
        let f = fixture();
        let mut bad = f.i.clone();
        *bad.pointer_mut(pointer).unwrap() = if pointer.ends_with("profile") {
            json!("dependency-v1")
        } else if pointer.ends_with("inode") {
            json!(0)
        } else if pointer.ends_with("source_sha") {
            json!("f".repeat(40))
        } else {
            json!("f".repeat(64))
        };
        assert!(
            run(&f.j, &bad, |_, _, _, _| panic!(
                "source custody substitution"
            ))
            .is_err(),
            "{pointer}"
        );
        assert!(f.j.absent(text(&f.i, "job_id").unwrap(), DISPATCH).unwrap());
    }
}
#[test]
fn bounded_artifacts_reject_new_homes_instance_or_terminal_export_digest() {
    let f = fixture();
    let result = successful(&f);
    let original = artifact(&f, &result);
    super::super::verify_build(&f.j, &original).unwrap();
    let mut changed = original.clone();
    changed["archive_sha256"] = json!("a".repeat(64));
    assert!(super::super::verify_build(&f.j, &changed).is_err());
    let root = f._temp.path().canonicalize().unwrap();
    let ssh = root.join("new-ssh-home");
    fs::create_dir(&ssh).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let mut changed = original.clone();
    changed["transport_context"] = context::TransportContext::from_paths(
        &ssh,
        Path::new(text(&source(&f.i)["transport_context"]["lima_home"], "path").unwrap()),
        text(source(&f.i), "vm").unwrap(),
    )
    .unwrap()
    .value()
    .clone();
    assert!(super::super::verify_build(&f.j, &changed).is_err());
    let lima = Path::new(text(&source(&f.i)["transport_context"]["lima_home"], "path").unwrap());
    let vm = text(source(&f.i), "vm").unwrap();
    fs::rename(lima.join(vm), lima.join("original-instance")).unwrap();
    fs::create_dir(lima.join(vm)).unwrap();
    assert!(read(
        &f.j,
        &f.i,
        &"e".repeat(64),
        &"e".repeat(64),
        |_, _, _, _| panic!("replacement VM read")
    )
    .is_err());
    assert!(super::super::verify_build(&f.j, &original).is_err());
}
#[test]
fn missing_or_substituted_original_readiness_blocks_later_read_and_artifacts() {
    for missing in [true, false] {
        let f = fixture();
        let result = successful(&f);
        let path = f.j.path.join(
            Journal::name(text(&f.i, "job_id").unwrap(), "bounded-build-ready-return").unwrap(),
        );
        if missing {
            fs::remove_file(&path).unwrap();
        } else {
            fs::write(&path, b"{}\n").unwrap();
        }
        assert!(read(
            &f.j,
            &f.i,
            &"e".repeat(64),
            &"e".repeat(64),
            |_, _, _, _| panic!("missing readiness read")
        )
        .is_err());
        assert!(super::super::verify_build(&f.j, &artifact(&f, &result)).is_err());
    }
}
