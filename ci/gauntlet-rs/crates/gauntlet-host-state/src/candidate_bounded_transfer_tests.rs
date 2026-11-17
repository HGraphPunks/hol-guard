//! Mocked Root wire replies only; no volume, VM or candidate is created.
use super::*;
use std::{cell::Cell, fs, os::unix::fs::PermissionsExt};
struct Fixture {
    _temp: tempfile::TempDir,
    j: Journal,
    i: Value,
    payload: Vec<u8>,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["journal", "ssh", "lima"] {
        fs::create_dir(root.join(name)).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let vm = "hol-bounded-source-fixture";
    fs::create_dir(root.join("lima").join(vm)).unwrap();
    let payload = b"inert source archive bytes".to_vec();
    let args = vec![
        "transfer-bounded".into(),
        root.join("source-not-opened").to_str().unwrap().into(),
        root.join("journal").to_str().unwrap().into(),
        "1".repeat(16),
        "a".repeat(40),
        sha(&payload),
        "b".repeat(64),
        "c".repeat(64),
        "build-v1".into(),
        vm.into(),
        "d".repeat(64),
        root.join("ssh").to_str().unwrap().into(),
        root.join("lima").to_str().unwrap().into(),
    ];
    let i = intent(&args, payload.len()).unwrap();
    let mut j = Journal::open(Path::new(&args[2])).unwrap();
    j.lock().unwrap();
    Fixture {
        _temp: temp,
        j,
        i,
        payload,
    }
}
fn storage(i: &Value) -> Value {
    crate::native_operation::job_storage_fixture(
        text(i, "source_sha"),
        text(i, "job_id"),
        text(i, "worker_generation"),
        text(i, "mke2fs_sha256"),
        text(i, "storage_profile"),
    )
}
fn response(i: &Value) -> Value {
    json!({"schema":"hol-gauntlet-native-source-capture.v2","job_id":i["job_id"],"source_sha":i["source_sha"],
        "source_archive_sha256":i["source_archive_sha256"],"source_bytes":i["source_bytes"],"worker_generation":i["worker_generation"],
        "builder_executed":false,"execution_eligible":false,"model_requests":0,"storage_profile":i["storage_profile"],"storage":storage(i)})
}
fn frame(v: &Value) -> Vec<u8> {
    let mut raw = bytes(v).unwrap();
    raw.push(b'\n');
    raw
}
pub(crate) fn completed_fixture() -> (tempfile::TempDir, Value) {
    completed_profile("build-v1")
}
pub(crate) fn completed_profile(profile: &str) -> (tempfile::TempDir, Value) {
    let mut f = fixture();
    f.i["storage_profile"] = json!(profile);
    execute(&f.j, &f.i, &f.payload, |i, _| Ok(frame(&response(i)))).unwrap();
    let context = completed(&f.j.path, text(&f.i, "job_id"), &sha(&bytes(&f.i).unwrap())).unwrap();
    (f._temp, context)
}
pub(crate) fn completed_sibling(path: &Path, original: &Value, job: &str, profile: &str) -> Value {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut i = original["intent"].clone();
    i["job_id"] = json!(job);
    i["storage_profile"] = json!(profile);
    let mut j = Journal::open(path).unwrap();
    j.lock().unwrap();
    execute(&j, &i, b"inert source archive bytes", |i, _| {
        Ok(frame(&response(i)))
    })
    .unwrap();
    completed(path, job, &sha(&bytes(&i).unwrap())).unwrap()
}
#[test]
fn bounded_transfer_joins_shared_storage_verifier_and_keeps_raw_receipt_private() {
    for profile in ["build-v1", "dependency-v1"] {
        let mut f = fixture();
        f.i["storage_profile"] = json!(profile);
        let calls = Cell::new(0);
        let got = execute(&f.j, &f.i, &f.payload, |i, payload| {
            calls.set(calls.get() + 1);
            assert_eq!(payload, f.payload);
            Ok(frame(&response(i)))
        })
        .unwrap();
        assert_eq!(
            got["storage_receipt_sha256"],
            response(&f.i)["storage"]["receipt_sha256"]
        );
        assert_eq!(
            execute(&f.j, &f.i, &f.payload, |_, _| panic!("source replay")).unwrap(),
            got
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(summary(&f.i, &got)["source_graph_verified"], true);
        assert_eq!(summary(&f.i, &got)["qualification_eligible"], false);
        assert!(summary(&f.i, &got).get("capture").is_none());
        assert!(summary(&f.i, &got).get("storage").is_none());
        let raw = f.j.read(text(&f.i, "job_id"), RESULT).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&raw).unwrap()["capture"],
            response(&f.i)
        );
    }
}
#[test]
fn rehashed_storage_substitution_and_unbounded_claims_consume_without_publication() {
    for (pointer, replacement) in [
        ("/storage/receipt/mke2fs_sha256", json!("f".repeat(64))),
        ("/storage/receipt/profile", json!("native-v1")),
        ("/storage/receipt/limits/bytes", json!(0)),
        ("/storage/receipt/backing/allocated_bytes", json!(1)),
        ("/storage/receipt/mount/target", json!("/arbitrary")),
        ("/storage/receipt/loop/backing_inode", json!(999)),
        ("/storage/receipt/qualification_eligible", json!(true)),
        ("/worker_generation", json!("f".repeat(64))),
        ("/source_archive_sha256", json!("f".repeat(64))),
    ] {
        let f = fixture();
        let mut reply = response(&f.i);
        *reply.pointer_mut(pointer).unwrap() = replacement;
        reply["storage"]["receipt_sha256"] =
            json!(sha(&bytes(&reply["storage"]["receipt"]).unwrap()));
        assert!(
            execute(&f.j, &f.i, &f.payload, |_, _| Ok(frame(&reply))).is_err(),
            "{pointer}"
        );
        assert!(!f.j.absent(text(&f.i, "job_id"), DISPATCH).unwrap());
        assert!(f.j.absent(text(&f.i, "job_id"), RESULT).unwrap());
        assert!(execute(&f.j, &f.i, &f.payload, |_, _| panic!(
            "forged source replay"
        ))
        .is_err());
    }
}
#[test]
fn source_bytes_and_closed_profiles_are_checked_before_dispatch() {
    for kind in ["hash", "size", "profile", "extra"] {
        let f = fixture();
        let mut i = f.i.clone();
        match kind {
            "hash" => i["source_archive_sha256"] = json!("0".repeat(64)),
            "size" => i["source_bytes"] = json!(f.payload.len() + 1),
            "profile" => i["storage_profile"] = json!("native-v1"),
            _ => i["approved"] = json!(true),
        }
        assert!(
            execute(&f.j, &i, &f.payload, |_, _| panic!(
                "unbound source dispatch"
            ))
            .is_err(),
            "{kind}"
        );
        assert!(f.j.absent(text(&f.i, "job_id"), DISPATCH).unwrap());
    }
}
#[test]
fn unknown_source_transfer_blocks_other_jobs_and_artifact_operations() {
    let f = fixture();
    assert!(execute(&f.j, &f.i, &f.payload, |_, _| Err("lost".into())).is_err());
    assert!(super::super::idle(&f.j).is_err());
    let mut other = f.i.clone();
    other["job_id"] = json!("2".repeat(16));
    assert!(execute(&f.j, &other, &f.payload, |_, _| panic!(
        "unknown source bypass"
    ))
    .is_err());
    assert!(f.j.absent(text(&other, "job_id"), DISPATCH).unwrap());
    assert!(execute(&f.j, &f.i, &f.payload, |_, _| panic!(
        "uncertain source replay"
    ))
    .is_err());
}

#[test]
fn completed_read_recovers_original_lost_or_malformed_reply_without_upload() {
    for malformed in [false, true] {
        let f = fixture();
        let original = if malformed {
            b"malformed\n".to_vec()
        } else {
            Vec::new()
        };
        assert!(execute(&f.j, &f.i, &f.payload, |_, _| {
            if malformed {
                Ok(original.clone())
            } else {
                Err("lost".into())
            }
        })
        .is_err());
        let dispatch = f.j.read(text(&f.i, "job_id"), DISPATCH).unwrap();
        let got = read_completed(&f.j, &f.i, |i, input| {
            assert!(input.is_empty(), "a read must never retransmit source");
            Ok(frame(&response(i)))
        })
        .unwrap();
        assert_eq!(got["capture"], response(&f.i));
        assert_eq!(f.j.read(text(&f.i, "job_id"), DISPATCH).unwrap(), dispatch);
        if malformed {
            assert_eq!(f.j.read(text(&f.i, "job_id"), RETURN).unwrap(), original);
        } else {
            assert!(f.j.absent(text(&f.i, "job_id"), RETURN).unwrap());
        }
        assert_eq!(
            read_completed(&f.j, &f.i, |_, _| panic!("completed read replay")).unwrap(),
            got
        );
        assert_eq!(
            execute(&f.j, &f.i, &f.payload, |_, _| panic!(
                "source upload replay"
            ))
            .unwrap(),
            got
        );
        assert!(super::super::idle(&f.j).is_ok());
        assert!(completed(&f.j.path, text(&f.i, "job_id"), &sha(&bytes(&f.i).unwrap())).is_ok());
    }
}

#[test]
fn completed_read_preserves_failed_read_and_refuses_new_or_substituted_job() {
    let f = fixture();
    assert!(read_completed(&f.j, &f.i, |_, _| panic!("read without dispatch")).is_err());
    assert!(execute(&f.j, &f.i, &f.payload, |_, _| Err("lost".into())).is_err());
    let mut other = f.i.clone();
    other["mke2fs_sha256"] = json!("f".repeat(64));
    assert!(read_completed(&f.j, &other, |_, _| panic!("different capture pins")).is_err());
    let bad = b"incomplete\n";
    assert!(read_completed(&f.j, &f.i, |_, input| {
        assert!(input.is_empty());
        Ok(bad.to_vec())
    })
    .is_err());
    let job = text(&f.i, "job_id");
    assert_eq!(
        f.j.read(job, &format!("bounded-source-read-{}", sha(bad)))
            .unwrap(),
        bad
    );
    assert!(f.j.absent(job, READ).unwrap());
    assert!(super::super::idle(&f.j).is_err());
    read_completed(&f.j, &f.i, |i, _| Ok(frame(&response(i)))).unwrap();
    assert_eq!(
        f.j.read(job, &format!("bounded-source-read-{}", sha(bad)))
            .unwrap(),
        bad
    );
    assert!(super::super::idle(&f.j).is_ok());
}
