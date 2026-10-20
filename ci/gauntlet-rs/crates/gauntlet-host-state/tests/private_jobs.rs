use gauntlet_host_state::{
    next_queued_job, read_private_jobs, read_private_operations, QueueConfig,
};
use serde_json::{json, Value};
use std::fs::{self, Permissions};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn fixture() -> (TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let private = state.join("private");
    let jobs = private.join("jobs");
    fs::create_dir(&state).unwrap();
    fs::create_dir(&private).unwrap();
    fs::create_dir(&jobs).unwrap();
    for directory in [&state, &private, &jobs] {
        fs::set_permissions(directory, Permissions::from_mode(0o700)).unwrap();
    }
    (temp, fs::canonicalize(state).unwrap())
}

fn write_job(state: &Path, id: &str, record: &Value) -> PathBuf {
    let path = state.join("private/jobs").join(format!("{id}.json"));
    fs::write(&path, serde_json::to_vec_pretty(record).unwrap()).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    path
}

#[test]
fn read_only_shadow_preserves_archived_unknown_blocker() {
    let (_temp, state) = fixture();
    write_job(
        &state,
        "0000000000000001",
        &json!({"id":"0000000000000001", "state":"queued", "kind":"release", "tag":"v3.48.0"}),
    );
    write_job(
        &state,
        "0000000000000002",
        &json!({"id":"0000000000000002", "state":"unknown", "kind":"pull-request", "archived_at":1}),
    );
    let jobs = read_private_jobs(&state).unwrap();
    assert_eq!(jobs.len(), 2);
    let config = QueueConfig::from_operations(&json!({
        "discovery_mode":"release-tags", "release_tags":["v3.48.0", "v3.49.0"]
    }))
    .unwrap();
    assert_eq!(
        next_queued_job(&config, &jobs, false, false, false).unwrap(),
        None
    );
}

#[test]
fn private_reader_refuses_symlink_wrong_identity_and_open_permissions() {
    let (_temp, state) = fixture();
    let id = "0000000000000001";
    let path = write_job(&state, id, &json!({"id":id, "state":"queued"}));
    assert_eq!(read_private_jobs(&state).unwrap().len(), 1);

    fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    assert!(read_private_jobs(&state).is_err());
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();

    fs::write(&path, br#"{"id":"ffffffffffffffff","state":"queued"}"#).unwrap();
    assert!(read_private_jobs(&state).is_err());
    fs::write(
        &path,
        serde_json::to_vec(&json!({"id":id, "state":"queued"})).unwrap(),
    )
    .unwrap();

    let link = state.join("private/jobs/0000000000000002.json");
    symlink(&path, &link).unwrap();
    assert!(read_private_jobs(&state).is_err());
}

#[test]
fn private_reader_refuses_changed_namespace_and_oversized_file() {
    let (_temp, state) = fixture();
    let id = "0000000000000001";
    let path = write_job(&state, id, &json!({"id":id, "state":"queued"}));
    let extra = state.join("private/jobs/unfinished.tmp");
    fs::write(&extra, b"partial").unwrap();
    assert!(read_private_jobs(&state).is_err());
    fs::remove_file(extra).unwrap();

    fs::write(&path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    assert!(read_private_jobs(&state).is_err());
}

#[test]
fn private_config_reader_validates_bytes_and_refuses_links() {
    let (_temp, state) = fixture();
    let path = state.join("config.json");
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let operations = read_private_operations(&state).unwrap();
    assert_eq!(operations["release_tags"], json!(["v3.48.0", "v3.49.0"]));

    fs::write(&path, br#"{"discovery_mode":"other"}"#).unwrap();
    assert!(read_private_operations(&state).is_err());
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    assert!(read_private_operations(&state).is_err());

    fs::remove_file(&path).unwrap();
    let target = state.join("private/target.json");
    fs::write(&target, b"{}").unwrap();
    symlink(&target, &path).unwrap();
    assert!(read_private_operations(&state).is_err());
}
