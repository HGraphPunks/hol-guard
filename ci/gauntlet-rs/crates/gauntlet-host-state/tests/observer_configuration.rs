use gauntlet_host_state::{read_observer_operations, HostLifecycleStore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn private_parent() -> tempfile::TempDir {
    let parent = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    parent
}

#[test]
fn immutable_configuration_requires_the_outside_pin_and_same_namespace() {
    let parent = private_parent();
    let store =
        HostLifecycleStore::initialize(parent.path(), "hashgraph-online/hol-guard", 1000).unwrap();
    let config = store
        .configure_observer(&json!({}), &"a".repeat(64))
        .unwrap();
    let path = parent.path().join("rust-host-v1/observer-config.json");
    let before = fs::read(&path).unwrap();
    assert_eq!(config.sha256, format!("{:x}", Sha256::digest(&before)));
    assert_eq!(
        store
            .configure_observer(&json!({}), &"a".repeat(64))
            .unwrap()
            .sha256,
        config.sha256
    );
    assert!(store
        .configure_observer(&json!({"telemetry_seconds":5}), &"a".repeat(64))
        .is_err());
    assert!(store
        .configure_observer(&json!({}), &"b".repeat(64))
        .is_err());
    assert!(store.read_observer_configuration(&"b".repeat(64)).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    let other = private_parent();
    let second =
        HostLifecycleStore::initialize(other.path(), "hashgraph-online/hol-guard", 1000).unwrap();
    fs::write(
        other.path().join("rust-host-v1/observer-config.json"),
        &before,
    )
    .unwrap();
    fs::set_permissions(
        other.path().join("rust-host-v1/observer-config.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(second.read_observer_configuration(&config.sha256).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.read_observer_configuration(&config.sha256).is_err());
}

#[test]
fn observer_rejects_other_queues_repositories_and_command_execution() {
    let parent = private_parent();
    let store =
        HostLifecycleStore::initialize(parent.path(), "hashgraph-online/hol-guard", 1000).unwrap();
    for value in [
        json!({"repository":"wrong/repo"}),
        json!({"discovery_mode":"pull-requests"}),
        json!({"release_build_backend":"github-actions"}),
        json!({"release_tags":["v3.50.0"]}),
        json!({"prepare_argv":["/bin/true"]}),
    ] {
        assert!(store.configure_observer(&value, &"a".repeat(64)).is_err());
        assert!(!parent
            .path()
            .join("rust-host-v1/observer-config.json")
            .exists());
    }
}

#[test]
fn operations_input_requires_private_regular_nonsymlink_duplicate_free_bytes() {
    let parent = private_parent();
    let path = parent.path().join("config.json");
    fs::write(&path, b"{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_observer_operations(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let value = read_observer_operations(&path).unwrap();
    assert_eq!(value["vm_memory_gib"], 16);
    fs::write(&path, br#"{"poll_seconds":60,"poll_seconds":30}"#).unwrap();
    assert!(read_observer_operations(&path).is_err());
    fs::remove_file(&path).unwrap();
    let outside = parent.path().join("outside.json");
    fs::write(&outside, b"{}").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    assert!(read_observer_operations(&path).is_err());
    let _: Value = value;
}
