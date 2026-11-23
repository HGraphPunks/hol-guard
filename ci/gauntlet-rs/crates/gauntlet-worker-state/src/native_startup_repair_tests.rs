use super::*;
use std::os::unix::fs::PermissionsExt;

fn receipt() -> Value {
    json!({"schema":SCHEMA,"source_sha":"a".repeat(40),"job_id":"0123456789abcdef",
        "deployment_digest":"b".repeat(64),"worker_generation":"c".repeat(64),"started_marker_sha256":"d".repeat(64),
        "preparation_sha256":"e".repeat(64),"repair_generation":"f".repeat(64),"status":"aborted",
        "controller_state":"never-released","exit_code":null,"model_requests":0,"execution_eligible":false,
        "guard_causality_verified":false,"cleanup":{}})
}
fn check(value: &Value) -> Result<(), String> {
    validate(
        value,
        &"a".repeat(40),
        "0123456789abcdef",
        &"b".repeat(64),
        &"c".repeat(64),
        &"d".repeat(64),
        &"e".repeat(64),
    )
}
#[test]
fn pre_controller_receipt_cannot_claim_an_exit_keyed_handoff_or_different_job() {
    let value = receipt();
    check(&value).unwrap();
    for (name, bad) in [
        ("source_sha", json!("b".repeat(40))),
        ("job_id", json!("fedcba9876543210")),
        ("deployment_digest", json!("f".repeat(64))),
        ("worker_generation", json!("f".repeat(64))),
        ("started_marker_sha256", json!("f".repeat(64))),
        ("preparation_sha256", json!("f".repeat(64))),
        ("repair_generation", json!("bad")),
        ("exit_code", json!(0)),
        ("controller_state", json!("completed")),
        ("model_requests", json!(false)),
        ("model_requests", json!(0.0)),
        ("execution_eligible", json!(true)),
        ("guard_causality_verified", json!(true)),
        ("controller_public_key", json!("f".repeat(64))),
    ] {
        let mut changed = value.clone();
        changed[name] = bad;
        assert!(check(&changed).is_err(), "{name}");
    }
    let mut missing = value;
    missing.as_object_mut().unwrap().remove("exit_code");
    assert!(check(&missing).is_err());
}
fn directory() -> Option<(tempfile::TempDir, Value)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let root = tempfile::Builder::new()
        .prefix("gstartup-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.path().join("preparation.v1.json"), b"{}").unwrap();
    let path = root.path().join("workspace");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let fd = crate::open_root_owned_public_directory(&path).unwrap();
    let s = fstat(&fd).unwrap();
    Some((
        root,
        json!({"device":s.st_dev,"inode":s.st_ino,"mode":0o700}),
    ))
}
#[test]
fn only_the_original_private_empty_workspace_can_enter_startup_recovery() {
    let Some((root, expected)) = directory() else {
        return;
    };
    let before = untouched_root(root.path(), &expected).unwrap();
    assert_eq!(before["workspace_empty"], true);
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
    let backup = tempfile::Builder::new()
        .prefix("gstartup-retained-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::rename(
        root.path().join("workspace"),
        backup.path().join("original"),
    )
    .unwrap();
    std::fs::create_dir(root.path().join("workspace")).unwrap();
    std::fs::set_permissions(
        root.path().join("workspace"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(untouched_root(root.path(), &expected).is_err());
}
#[test]
fn startup_recovery_refuses_loose_directory_modes_symlinks_and_owner_changes() {
    for changed in ["mode", "symlink", "owner"] {
        let Some((root, expected)) = directory() else {
            return;
        };
        let workspace = root.path().join("workspace");
        match changed {
            "mode" => std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o770))
                .unwrap(),
            "symlink" => {
                std::fs::remove_dir(&workspace).unwrap();
                std::os::unix::fs::symlink("/var/lib", &workspace).unwrap();
            }
            "owner" => std::os::unix::fs::chown(&workspace, Some(10005), Some(10005)).unwrap(),
            _ => unreachable!(),
        }
        assert!(untouched_root(root.path(), &expected).is_err(), "{changed}");
    }
}
