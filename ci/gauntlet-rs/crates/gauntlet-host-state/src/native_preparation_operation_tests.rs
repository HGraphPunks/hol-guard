use super::super::tests::{intent, journal};
use super::*;
use initialization::storage::verify_abort;
use initialization::{abort_context, abort_execute, require_not_aborted};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

fn initialized(j: &Journal, i: &Intent, complete: bool) -> (Initialization, Value) {
    let init=Initialization::parse(&bytes(&json!({"schema":"hol-gauntlet-host-native-initialization-intent.v1",
        "job_id":i.job(),"source_sha":i.text("source_sha"),"worker_generation":i.text("worker_generation"),
        "vm":i.text("vm"),"limactl":i.text("limactl"),"lima_sha256":i.text("lima_sha256"),"transport_context":i.0["transport_context"]})).unwrap()).unwrap();
    let root = format!("/var/lib/hol-gauntlet-rust/native-jobs/{}", i.job());
    let r = json!({"schema":"hol-gauntlet-native-job-initialization.v1","source_sha":i.text("source_sha"),"job_id":i.job(),"worker_generation":i.text("worker_generation"),
        "job_directory":{"device":21,"inode":51,"uid":0,"gid":0,"mode":448},
        "workspace":{"source":format!("{root}/workspace"),"destination":"/runtime/home/project","custody_root":root,
            "device":21,"inode":52,"uid":10001,"gid":10001,"mode":448},
        "job_dispatched":false,"candidate_executed":false,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0});
    let v = json!({"schema":"hol-gauntlet-native-job-initialization-result.v1","receipt_sha256":sha(&bytes(&r).unwrap()),"receipt":r});
    j.write(i.job(), "initialize-intent", &bytes(&init.0).unwrap())
        .unwrap();
    j.write(i.job(), "initialize-dispatch", &init.dispatch().unwrap())
        .unwrap();
    if complete {
        j.write(i.job(), "initialize-result", &bytes(&v).unwrap())
            .unwrap();
    }
    (init, v)
}
fn preparation_fixture(j: &Journal, readonly: bool) -> (Intent, Vec<u8>, Value, String) {
    let mut i = intent(&"1".repeat(16), &j.path);
    if readonly {
        i.0["role"] = json!("readonly-utility");
    }
    let (_, initialized) = initialized(j, &i, true);
    let mut workspace = initialized["receipt"]["workspace"].clone();
    workspace.as_object_mut().unwrap().remove("uid");
    workspace.as_object_mut().unwrap().remove("gid");
    // This inert wire fixture exercises host byte/identity binding. Full rootfs
    // preparation validation belongs to the actual worker parser and VM tests.
    let p = json!({"schema":"hol-gauntlet-cell-preparation.v1","task_mounts":{"workspace":workspace},
        "runtime_prefix":format!("/opt/hol-gauntlet/candidates/{}/prefix",i.text("source_sha")),"runtime_tree_digest":"e".repeat(64),
        "launch":{"image_interpreter_sha256":i.text("interpreter_sha256"),"outside_observer_sha256":i.text("observer_sha256")}});
    i.0["preparation_sha256"] = json!(sha(&bytes(&p).unwrap()));
    let mut d = json!({"schema":"hol-gauntlet-native-worker-job.v7","profile":"native-host-pinned-control-v1",
        "source_sha":i.text("source_sha"),"job_id":i.job(),"worker_generation":i.text("worker_generation"),
        "preparation_sha256":i.text("preparation_sha256"),"role":i.text("role"),"sdk":{"publication_sha256":"f".repeat(64)}});
    if readonly {
        d["schema"] = json!("hol-gauntlet-native-worker-job.v8");
        d["profile"] = json!("native-host-pinned-readonly-hook-v1");
        d.as_object_mut().unwrap().remove("role");
        d.as_object_mut().unwrap().remove("sdk");
    }
    i.0["deployment_digest"] = json!(sha(&bytes(&d).unwrap()));
    let raw=bytes(&json!({"schema":"hol-gauntlet-native-host-pinned-preparation-input.v1","declaration":d,"preparation":p})).unwrap();
    let init_sha = initialized["receipt_sha256"].as_str().unwrap().to_owned();
    let r = json!({"schema":"hol-gauntlet-native-host-pinned-preparation.v1","source_sha":i.text("source_sha"),"job_id":i.job(),
        "deployment_digest":i.text("deployment_digest"),"worker_generation":i.text("worker_generation"),"preparation_sha256":i.text("preparation_sha256"),
        "bundle_sha256":sha(&raw),"initialization_sha256":init_sha,"control_role":i.text("role"),"runtime_tree_sha256":"e".repeat(64),
        "sdk_publication_sha256":if readonly {Value::Null}else{json!("f".repeat(64))},
        "job_dispatched":false,"candidate_executed":false,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0});
    let receipt = json!({"schema":"hol-gauntlet-native-host-pinned-preparation-result.v1","receipt_sha256":sha(&bytes(&r).unwrap()),"receipt":r});
    (i, raw, receipt, init_sha)
}
fn rehash(v: &mut Value) {
    v["receipt_sha256"] = json!(sha(&bytes(&v["receipt"]).unwrap()));
}

fn storage_fixture(i: &Intent, formatter: &str) -> Value {
    job_storage_fixture(
        i.text("source_sha"),
        i.job(),
        i.text("worker_generation"),
        formatter,
        "native-v1",
    )
}

#[test]
fn bounded_initialization_requires_original_capacity_loop_mount_and_formatter_after_rehash() {
    let (_temp, j) = journal();
    let i = intent(&"1".repeat(16), &j.path);
    let (legacy, mut reply) = initialized(&j, &i, false);
    let formatter = "a".repeat(64);
    let mut declaration = legacy.0.clone();
    declaration["schema"] = json!("hol-gauntlet-host-native-initialization-intent.v2");
    declaration["mke2fs_sha256"] = json!(formatter);
    let bounded = Initialization::parse(&bytes(&declaration).unwrap()).unwrap();
    reply["schema"] = json!("hol-gauntlet-native-job-initialization-result.v2");
    reply["receipt"]["schema"] = json!("hol-gauntlet-native-job-initialization.v2");
    reply["receipt"]["storage"] = storage_fixture(&i, &formatter);
    reply["receipt"]["job_directory"] =
        reply["receipt"]["storage"]["receipt"]["root_directory"].clone();
    reply["receipt"]["workspace"]["device"] = json!(1795);
    rehash(&mut reply);
    assert!(verify_initialization(&bounded, &bytes(&reply).unwrap()).is_ok());
    assert!(verify_initialization(&legacy, &bytes(&reply).unwrap()).is_err());
    for (pointer, replacement) in [
        ("/receipt/limits/bytes", json!(3_u64 * 1024 * 1024 * 1024)),
        ("/receipt/limits/inodes", json!(65537)),
        ("/receipt/filesystem/inodes", json!(65537)),
        ("/receipt/backing/allocated_bytes", json!(1)),
        ("/receipt/backing/links", json!(2)),
        ("/receipt/loop/backing_inode", json!(81)),
        ("/receipt/loop/flags", json!(0)),
        ("/receipt/mount/private", json!(false)),
        ("/receipt/mount/nodev", json!(false)),
        ("/receipt/mount/source", json!("/tmp/caller-device")),
        ("/receipt/schema", json!("hol-gauntlet-job-storage.v1")),
        ("/receipt/namespace_owner/source_sha", json!("f".repeat(40))),
        ("/receipt/namespace_owner/job_id", json!("f".repeat(16))),
        (
            "/receipt/namespace_owner/executable_sha256",
            json!("f".repeat(64)),
        ),
        ("/receipt/namespace_owner/owner_nonce_hex", json!(true)),
        ("/receipt/namespace_owner/process/pid", json!(1)),
        ("/receipt/namespace_owner/namespace/inode", json!(701)),
        (
            "/receipt/namespace_owner/original_namespace/inode",
            json!(700),
        ),
        (
            "/receipt/namespace_owner/cgroup/path",
            json!("/system.slice/sshd.service"),
        ),
        (
            "/receipt/namespace_owner/deadline_boottime_ns",
            json!(u64::MAX),
        ),
        ("/receipt/namespace_owner/state", json!("adopted")),
        ("/receipt/root_directory/inode", json!(51)),
        ("/receipt/covered_directory/uid", json!(10001)),
        ("/receipt/mke2fs_sha256", json!("b".repeat(64))),
        (
            "/receipt/formatter/configuration_sha256",
            json!("b".repeat(64)),
        ),
        ("/receipt/storage_state", json!("removed")),
        ("/receipt/qualification_eligible", json!(true)),
    ] {
        let mut wrong = reply.clone();
        *wrong["receipt"]["storage"].pointer_mut(pointer).unwrap() = replacement;
        rehash(&mut wrong["receipt"]["storage"]);
        rehash(&mut wrong);
        assert!(
            verify_initialization(&bounded, &bytes(&wrong).unwrap()).is_err(),
            "{pointer}"
        );
    }
    let mut fd_mount = reply.clone();
    fd_mount["receipt"]["storage"]["receipt"]["mount"]["source"] = json!("/proc/self/fd/16");
    rehash(&mut fd_mount["receipt"]["storage"]);
    rehash(&mut fd_mount);
    assert!(verify_initialization(&bounded, &bytes(&fd_mount).unwrap()).is_ok());
}

#[test]
fn bounded_preparation_cannot_drop_substitute_or_borrow_legacy_storage_binding() {
    let (_temp, j) = journal();
    let (i, raw, legacy, initialization) = preparation_fixture(&j, false);
    let storage = "3".repeat(64);
    let mut reply = legacy.clone();
    reply["schema"] = json!("hol-gauntlet-native-host-pinned-preparation-result.v2");
    reply["receipt"]["schema"] = json!("hol-gauntlet-native-host-pinned-preparation.v2");
    reply["receipt"]["storage_receipt_sha256"] = json!(storage);
    rehash(&mut reply);
    assert!(verify_preparation(
        &i,
        &bytes(&reply).unwrap(),
        &raw,
        &initialization,
        Some(&storage)
    )
    .is_ok());
    assert!(verify_preparation(&i, &bytes(&reply).unwrap(), &raw, &initialization, None).is_err());
    assert!(verify_preparation(
        &i,
        &bytes(&legacy).unwrap(),
        &raw,
        &initialization,
        Some(&storage)
    )
    .is_err());
    assert!(verify_preparation(
        &i,
        &bytes(&reply).unwrap(),
        &raw,
        &initialization,
        Some(&"4".repeat(64))
    )
    .is_err());
}

#[test]
fn pending_initialization_and_preparation_block_new_work_until_exact_readback() {
    let (_temp, j) = journal();
    let i = intent(&"1".repeat(16), &j.path);
    let (_, value) = initialized(&j, &i, false);
    assert!(j.require_idle().is_err());
    let reopened = Journal::open(&j.path).unwrap();
    assert!(reopened.require_idle().is_err());
    j.write(i.job(), "initialize-result", &bytes(&value).unwrap())
        .unwrap();
    assert!(reopened.require_idle().is_ok());
    let mut other = i.clone();
    other.0["vm"] = json!("hol-other-vm");
    assert!(initialization_for(&j, &other).is_err());

    let (_temp, j) = journal();
    let (i, raw, value, init_sha) = preparation_fixture(&j, false);
    j.write(i.job(), "intent", &i.raw().unwrap()).unwrap();
    j.write(i.job(), "prepare-bundle", &raw).unwrap();
    j.write(
        i.job(),
        "prepare-dispatch",
        &preparation_dispatch(&i, &raw, &init_sha).unwrap(),
    )
    .unwrap();
    assert!(j.require_idle().is_err());
    assert!(require_prepared(&j, &i).is_err());
    j.write(i.job(), "prepare-result", &bytes(&value).unwrap())
        .unwrap();
    assert!(Journal::open(&j.path).unwrap().require_idle().is_ok());
    assert_eq!(require_prepared(&j, &i).unwrap(), value);
    assert!(j
        .write(
            i.job(),
            "prepare-dispatch",
            &preparation_dispatch(&i, &raw, &init_sha).unwrap()
        )
        .is_err());
}

#[test]
fn source_workspace_ownership_and_credit_substitutions_refuse_even_after_rehash() {
    let (_temp, j) = journal();
    let i = intent(&"1".repeat(16), &j.path);
    let (init, value) = initialized(&j, &i, true);
    assert!(verify_initialization(&init, &bytes(&value).unwrap()).is_ok());
    for (pointer, bad) in [
        ("/receipt/source_sha", json!("f".repeat(40))),
        ("/receipt/job_id", json!("b".repeat(16))),
        ("/receipt/worker_generation", json!("e".repeat(64))),
        ("/receipt/workspace/uid", json!(0)),
        ("/receipt/workspace/source", json!("/tmp/adopted")),
        ("/receipt/workspace/custody_root", json!("/tmp/adopted")),
        ("/receipt/workspace/inode", json!(0)),
        ("/receipt/workspace/mode", json!(493)),
        ("/receipt/job_dispatched", json!(true)),
        ("/receipt/candidate_executed", json!(true)),
        ("/receipt/execution_eligible", json!(true)),
        ("/receipt/qualification_eligible", json!(true)),
        ("/receipt/model_requests", json!(1)),
    ] {
        let mut bad_value = value.clone();
        *bad_value.pointer_mut(pointer).unwrap() = bad;
        rehash(&mut bad_value);
        assert!(
            verify_initialization(&init, &bytes(&bad_value).unwrap()).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn preparation_reply_and_bundle_require_original_inode_exact_role_and_all_pins() {
    for readonly in [false, true] {
        let (_temp, j) = journal();
        let (i, raw, value, init_sha) = preparation_fixture(&j, readonly);
        assert!(bundle(&j, &i, &raw).is_ok());
        assert_eq!(
            verify_preparation(&i, &bytes(&value).unwrap(), &raw, &init_sha, None).unwrap(),
            value
        );
        for (pointer, bad) in [
            ("/receipt/preparation_sha256", json!("1".repeat(64))),
            ("/receipt/bundle_sha256", json!("1".repeat(64))),
            ("/receipt/initialization_sha256", json!("1".repeat(64))),
            ("/receipt/control_role", json!("success")),
            ("/receipt/runtime_tree_sha256", json!("1".repeat(64))),
            ("/receipt/execution_eligible", json!(true)),
            ("/receipt/sdk_publication_sha256", json!("1".repeat(64))),
        ] {
            let mut bad_value = value.clone();
            *bad_value.pointer_mut(pointer).unwrap() = bad;
            rehash(&mut bad_value);
            assert!(
                verify_preparation(&i, &bytes(&bad_value).unwrap(), &raw, &init_sha, None).is_err(),
                "{pointer}"
            );
        }
        for field in ["interpreter_sha256", "observer_sha256"] {
            let mut other = i.clone();
            other.0[field] = json!("1".repeat(64));
            assert!(bundle(&j, &other, &raw).is_err(), "{field}");
        }
        let mut changed: Value = serde_json::from_slice(&raw).unwrap();
        changed["preparation"]["task_mounts"]["workspace"]["inode"] = json!(992);
        let mut other = i.clone();
        other.0["preparation_sha256"] = json!(sha(&bytes(&changed["preparation"]).unwrap()));
        changed["declaration"]["preparation_sha256"] = other.0["preparation_sha256"].clone();
        other.0["deployment_digest"] = json!(sha(&bytes(&changed["declaration"]).unwrap()));
        assert!(bundle(&j, &other, &bytes(&changed).unwrap()).is_err());
    }
}

#[test]
fn preparation_input_custody_refuses_wrong_hash_links_and_oversize() {
    let (_temp, j) = journal();
    let path = j.path.join("bundle.json");
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(read_bundle(&path, &sha(b"{}")).unwrap(), b"{}");
    assert!(read_bundle(&path, &"0".repeat(64)).is_err());
    let link = j.path.join("linked.json");
    symlink(&path, &link).unwrap();
    assert!(read_bundle(&link, &sha(b"{}")).is_err());
    fs::hard_link(&path, j.path.join("hard.json")).unwrap();
    assert!(read_bundle(&path, &sha(b"{}")).is_err());
    let oversized = j.path.join("oversized.json");
    fs::write(&oversized, vec![b'x'; BUNDLE_LIMIT as usize + 1]).unwrap();
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_bundle(&oversized, &"0".repeat(64)).is_err());
}

pub(super) fn abort_fixture(j: &Journal) -> (Initialization, Value, Value) {
    let i = intent(&"1".repeat(16), &j.path);
    let (legacy, mut v) = initialized(j, &i, false);
    let mut declaration = legacy.0;
    declaration["schema"] = json!("hol-gauntlet-host-native-initialization-intent.v2");
    declaration["mke2fs_sha256"] = json!("a".repeat(64));
    let init = Initialization::parse(&bytes(&declaration).unwrap()).unwrap();
    v["schema"] = json!("hol-gauntlet-native-job-initialization-result.v2");
    v["receipt"]["schema"] = json!("hol-gauntlet-native-job-initialization.v2");
    v["receipt"]["storage"] = storage_fixture(&i, &"a".repeat(64));
    v["receipt"]["job_directory"] = v["receipt"]["storage"]["receipt"]["root_directory"].clone();
    v["receipt"]["workspace"]["device"] = json!(1795);
    rehash(&mut v);
    // Replace only this temporary fixture's synthetic legacy setup.
    fs::write(
        j.path
            .join(Journal::name(i.job(), "initialize-intent").unwrap()),
        bytes(&init.0).unwrap(),
    )
    .unwrap();
    fs::write(
        j.path
            .join(Journal::name(i.job(), "initialize-dispatch").unwrap()),
        init.dispatch().unwrap(),
    )
    .unwrap();
    j.write(i.job(), "initialize-result", &bytes(&v).unwrap())
        .unwrap();
    for (suffix, raw) in [
        ("prepare-bundle", b"{invalid preparation}".as_slice()),
        ("prepare-dispatch", b"{consumed}"),
        ("prepare-return", b"{rejected}"),
    ] {
        j.write(i.job(), suffix, raw).unwrap();
    }
    let a = abort_context(
        j,
        &init,
        &v,
        v["receipt_sha256"].as_str().unwrap(),
        v["receipt"]["storage"]["receipt_sha256"].as_str().unwrap(),
        &"b".repeat(64),
        &"c".repeat(64),
    )
    .unwrap();
    (init, v, a)
}
pub(super) fn abort_reply(i: &Initialization, v: &Value, a: &Value) -> Value {
    let snapshot = json!({"schema":"hol-gauntlet-native-unstarted-snapshot.v1","source_sha":i.text("source_sha"),"job_id":i.job(),
        "worker_generation":i.text("worker_generation"),"initialization_sha256":a["initialization_sha256"],"storage_receipt_sha256":a["storage_receipt_sha256"],
        "workspace":v["receipt"]["workspace"],"preparation":{"sha256":sha(b"{invalid preparation}"),"bytes":21,"device":1795,"inode":53,"uid":0,"gid":0,"mode":384,"links":1}});
    let authority = json!({"schema":"hol-gauntlet-native-unstarted-storage-authority.v1","initialization_sha256":a["initialization_sha256"],
        "storage_receipt_sha256":a["storage_receipt_sha256"],"snapshot_sha256":sha(&bytes(&snapshot).unwrap()),"podman_sha256":a["podman_sha256"]});
    let context = json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":i.text("source_sha"),"job_id":i.job(),
        "worker_generation":i.text("worker_generation"),"mke2fs_sha256":i.text("mke2fs_sha256"),"profile":"native-v1","retirer_generation":a["aborter_generation"],
        "authority":authority,"storage_receipt_sha256":a["storage_receipt_sha256"],"archive_sha256":null});
    let receipt = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":i.text("source_sha"),"job_id":i.job(),"worker_generation":i.text("worker_generation"),
        "profile":"native-v1","retirer_generation":a["aborter_generation"],"retirement_intent_sha256":sha(&bytes(&context).unwrap()),"storage_receipt_sha256":a["storage_receipt_sha256"],
        "archive_sha256":null,"partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,
        "job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":null});
    json!({"schema":"hol-gauntlet-native-initialization-abort-result.v1","snapshot":snapshot,"receipt_sha256":sha(&bytes(&receipt).unwrap()),"receipt":receipt})
}
#[test]
fn unstarted_abort_preserves_failed_preparation_and_requires_explicit_partial_resume() {
    let (_temp, j) = journal();
    let (i, v, a) = abort_fixture(&j);
    let run = |read: bool, resume: bool, reply: Result<Vec<u8>, String>| {
        abort_execute(&j, &i, &v, &a, read, resume, |argv| {
            assert_eq!(argv.len(), 10);
            assert_eq!(argv[2], i.text("source_sha"));
            assert_eq!(argv[6], a["initialization_sha256"].as_str().unwrap());
            assert_eq!(argv[8], a["podman_sha256"].as_str().unwrap());
            assert_eq!(argv[1].starts_with("--read-"), read);
            reply
        })
    };
    assert!(run(false, false, Err("reply lost after unmount".into())).is_err());
    assert!(run(true, false, Err("cleanup incomplete".into())).is_err());
    assert!(j.absent(i.job(), "initialize-abort-result").unwrap());
    let raw = bytes(&abort_reply(&i, &v, &a)).unwrap();
    let summary = run(false, true, Ok(raw.clone())).unwrap();
    assert_eq!(summary["model_requests"], Value::Null);
    assert_eq!(summary["exit_code"], Value::Null);
    assert_eq!(
        j.read(i.job(), "prepare-bundle").unwrap(),
        b"{invalid preparation}"
    );
    assert_eq!(j.read(i.job(), "prepare-return").unwrap(), b"{rejected}");
    assert!(j.require_idle().is_ok());
    assert!(run(true, false, Ok(raw)).is_ok());
    assert!(abort_execute(&j, &i, &v, &a, false, false, |_| panic!("replay")).is_err());
}
#[test]
fn unstarted_abort_refuses_rehashed_substitution_and_every_orphan_or_live_marker() {
    let (_temp, j) = journal();
    let (i, v, a) = abort_fixture(&j);
    let good = abort_reply(&i, &v, &a);
    assert!(verify_abort(&i, &v, &a, &bytes(&good).unwrap()).is_ok());
    for (pointer, bad) in [
        ("/snapshot/workspace/inode", json!(999)),
        ("/snapshot/preparation/links", json!(2)),
        ("/receipt/model_requests", json!(0)),
        ("/receipt/archive_sha256", json!("d".repeat(64))),
        ("/receipt/partial", json!(true)),
        ("/receipt/retirement_intent_sha256", json!("e".repeat(64))),
    ] {
        let mut wrong = good.clone();
        *wrong.pointer_mut(pointer).unwrap() = bad;
        rehash(&mut wrong);
        assert!(
            verify_abort(&i, &v, &a, &bytes(&wrong).unwrap()).is_err(),
            "{pointer}"
        );
    }
    for suffix in [
        "dispatch",
        "prelaunch",
        "live-provision-dispatch",
        "turn-1",
        "unknown",
    ] {
        let (_temp, j) = journal();
        let (i, v, _) = abort_fixture(&j);
        j.write(i.job(), suffix, b"{}").unwrap();
        assert!(
            abort_context(
                &j,
                &i,
                &v,
                v["receipt_sha256"].as_str().unwrap(),
                v["receipt"]["storage"]["receipt_sha256"].as_str().unwrap(),
                &"b".repeat(64),
                &"c".repeat(64)
            )
            .is_err(),
            "{suffix}"
        );
    }
    for suffix in ["return", "result", "read-intent", "frame-dead"] {
        let (_temp, j) = journal();
        let (i, v, a) = abort_fixture(&j);
        j.write(i.job(), &format!("initialize-abort-{suffix}"), b"{}")
            .unwrap();
        assert!(require_not_aborted(&j, i.job()).is_err());
        assert!(abort_execute(&j, &i, &v, &a, false, false, |_| panic!("orphan replay")).is_err());
        assert!(j.absent(i.job(), "initialize-abort-intent").unwrap());
    }
}
#[test]
fn unstarted_abort_missing_original_dispatch_or_changed_host_records_never_reconcile() {
    let (_temp, j) = journal();
    let (i, v, a) = abort_fixture(&j);
    assert!(abort_execute(&j, &i, &v, &a, false, true, |_| panic!("missing dispatch")).is_err());
    assert!(abort_execute(&j, &i, &v, &a, false, false, |_| Err("lost".into())).is_err());
    fs::remove_file(
        j.path
            .join(Journal::name(i.job(), "initialize-abort-intent").unwrap()),
    )
    .unwrap();
    assert!(abort_execute(&j, &i, &v, &a, false, false, |_| panic!("orphan dispatch")).is_err());
    assert!(abort_execute(&j, &i, &v, &a, true, false, |_| panic!("missing original")).is_err());
    j.write(i.job(), "initialize-abort-intent", &bytes(&a).unwrap())
        .unwrap();
    fs::write(
        j.path
            .join(Journal::name(i.job(), "prepare-return").unwrap()),
        b"{different rejection}",
    )
    .unwrap();
    assert!(abort_execute(&j, &i, &v, &a, false, true, |_| panic!("changed history")).is_err());
}
