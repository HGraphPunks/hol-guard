use super::*;
use std::os::unix::fs::PermissionsExt;
fn prepared() -> PrelaunchPrepared {
    PrelaunchPrepared {
        source_sha: "a".repeat(40),
        job_id: "0123456789abcdef".into(),
        deployment_digest: "b".repeat(64),
        worker_generation: "c".repeat(64),
        started_marker_sha256: "d".repeat(64),
        controller_key_pin_sha256: "e".repeat(64),
        controller_public_key_hex: "f".repeat(64),
    }
}
fn receipt() -> Value {
    let p: Value = serde_json::from_slice(&prepared().to_bytes().unwrap()).unwrap();
    json!({"schema":SCHEMA,"prelaunch":p,"preparation_sha256":"1".repeat(64),"repair_generation":"2".repeat(64),
        "status":"aborted","controller_state":"never-released","exit_code":null,"model_requests":0,
        "execution_eligible":false,"guard_causality_verified":false,"cleanup":{}})
}
#[test]
fn repair_is_bound_to_every_public_pin_and_cannot_claim_a_result_or_ack() {
    let value = receipt();
    validate(&value, &prepared(), &"1".repeat(64)).unwrap();
    for key in [
        "source_sha",
        "job_id",
        "deployment_digest",
        "worker_generation",
        "started_marker_sha256",
        "controller_key_pin_sha256",
        "controller_public_key_hex",
    ] {
        let mut changed = value.clone();
        changed["prelaunch"][key] = json!("0".repeat(if key == "job_id" {
            16
        } else if key == "source_sha" {
            40
        } else {
            64
        }));
        assert!(
            validate(&changed, &prepared(), &"1".repeat(64)).is_err(),
            "{key}"
        );
    }
    for (key, bad) in [
        ("preparation_sha256", json!("0".repeat(64))),
        ("repair_generation", json!("bad")),
        ("exit_code", json!(0)),
        ("model_requests", json!(false)),
        ("model_requests", json!(0.0)),
        ("controller_state", json!("completed")),
        ("execution_eligible", json!(true)),
        ("guard_causality_verified", json!(true)),
        ("host_ack_received", json!(true)),
    ] {
        let mut changed = value.clone();
        changed[key] = bad;
        assert!(
            validate(&changed, &prepared(), &"1".repeat(64)).is_err(),
            "{key}"
        );
    }
    let mut missing = value;
    missing.as_object_mut().unwrap().remove("exit_code");
    assert!(validate(&missing, &prepared(), &"1".repeat(64)).is_err());
}
fn directory() -> Option<(tempfile::TempDir, Value)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let root = tempfile::Builder::new()
        .prefix("gkey-startup-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.path().join("preparation.v1.json"), b"{}").unwrap();
    let path = root.path().join("workspace");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::chown(&path, Some(10001), Some(10001)).unwrap();
    let s = std::fs::metadata(&path).unwrap();
    use std::os::unix::fs::MetadataExt;
    let expected = json!({"device":s.dev(),"inode":s.ino(),"mode":0o700,"source":path,"custody_root":root.path()});
    Some((root, expected))
}
#[test]
fn original_declared_task_inode_is_required_and_must_be_empty() {
    let Some((root, expected)) = directory() else {
        return;
    };
    assert_eq!(
        untouched_root(root.path(), &expected).unwrap()["workspace_uid"],
        10001
    );
    std::fs::write(
        root.path().join("workspace/output"),
        b"controller could have run",
    )
    .unwrap();
    assert!(untouched_root(root.path(), &expected).is_err());
    let Some((root, expected)) = directory() else {
        return;
    };
    std::fs::create_dir(root.path().join("cell")).unwrap();
    assert!(untouched_root(root.path(), &expected).is_err());
    let Some((root, expected)) = directory() else {
        return;
    };
    let retained = tempfile::Builder::new()
        .prefix("gkey-retained-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::rename(
        root.path().join("workspace"),
        retained.path().join("original"),
    )
    .unwrap();
    std::fs::create_dir(root.path().join("workspace")).unwrap();
    std::fs::set_permissions(
        root.path().join("workspace"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::os::unix::fs::chown(root.path().join("workspace"), Some(10001), Some(10001)).unwrap();
    assert!(untouched_root(root.path(), &expected).is_err());
}
#[test]
fn recovery_refuses_owner_modes_symlinks_and_foreign_declarations() {
    for changed in ["owner", "mode", "symlink", "declaration"] {
        let Some((root, mut expected)) = directory() else {
            return;
        };
        let path = root.path().join("workspace");
        match changed {
            "owner" => std::os::unix::fs::chown(&path, Some(0), Some(0)).unwrap(),
            "mode" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o770)).unwrap()
            }
            "symlink" => {
                std::fs::remove_dir(&path).unwrap();
                std::os::unix::fs::symlink("/var/lib", &path).unwrap();
            }
            "declaration" => expected["source"] = json!("/var/lib/foreign"),
            _ => unreachable!(),
        }
        assert!(untouched_root(root.path(), &expected).is_err(), "{changed}");
    }
}
