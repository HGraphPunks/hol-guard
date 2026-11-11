use super::super::tests::{intent, journal};
use super::*;
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
            verify_preparation(&i, &bytes(&value).unwrap(), &raw, &init_sha).unwrap(),
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
                verify_preparation(&i, &bytes(&bad_value).unwrap(), &raw, &init_sha).is_err(),
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
