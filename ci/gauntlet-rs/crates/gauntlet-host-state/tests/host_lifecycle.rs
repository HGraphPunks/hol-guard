use gauntlet_contracts::canonicalize;
use gauntlet_host_state::{HostLifecycleError as Error, HostLifecycleStore};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use tempfile::TempDir;

fn parent() -> TempDir {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp
}
fn initialize(parent: &Path) -> HostLifecycleStore {
    HostLifecycleStore::initialize(parent, "hashgraph-online/hol-guard", 1000).unwrap()
}
fn read(parent: &Path) -> Value {
    serde_json::from_slice(&fs::read(parent.join("rust-host-v1/state.json")).unwrap()).unwrap()
}
fn write(parent: &Path, value: &Value) {
    let bytes = canonicalize(value.to_string().as_bytes()).unwrap();
    fs::write(parent.join("rust-host-v1/state.json"), bytes).unwrap();
}
fn queue(store: &HostLifecycleStore) {
    store
        .enqueue_release("1111111111111111", "v3.48.0", &"a".repeat(40), 1100)
        .unwrap();
    store
        .enqueue_release("2222222222222222", "v3.49.0", &"b".repeat(40), 1200)
        .unwrap();
}

#[test]
fn isolated_default_hold_and_idempotent_operator_commands_survive_reopen() {
    let parent = parent();
    // Existing Python names are outside the new namespace and stay untouched.
    fs::write(parent.path().join("config.json"), b"existing Python config").unwrap();
    let store = initialize(parent.path());
    let initial = store.status(1000).unwrap();
    assert_eq!(initial["admissions_held"], true);
    assert_eq!(initial["observer"]["status"], "stopped");
    assert_eq!(initial["vm"]["status"], "unavailable");
    assert_eq!(initial["gate"]["required"], Value::Null);
    assert_eq!(initial["release_tags"], json!(["v3.48.0", "v3.49.0"]));
    store.set_hold(false, 1300).unwrap();
    let resumed = store.status(1400).unwrap();
    assert_eq!(resumed["admissions_held"], false);
    assert_eq!(resumed["execution_eligible"], false);
    assert_eq!(resumed["qualification_eligible"], false);
    assert_eq!(resumed["production_ci_activated"], false);
    store.set_hold(false, 1500).unwrap();
    assert_eq!(
        store.status(1600).unwrap()["generation"],
        resumed["generation"]
    );
    drop(store);
    let reopened = HostLifecycleStore::open(parent.path()).unwrap();
    assert_eq!(
        reopened.status(1700).unwrap()["instance_id"],
        initial["instance_id"]
    );
    reopened.set_hold(true, 1800).unwrap();
    assert_eq!(reopened.status(1900).unwrap()["admissions_held"], true);
    assert_eq!(
        fs::read(parent.path().join("config.json")).unwrap(),
        b"existing Python config"
    );
    assert!(matches!(
        HostLifecycleStore::initialize(parent.path(), "a/b", 2000),
        Err(Error::AlreadyInitialized)
    ));
    for name in ["state.json", "transaction.lock", "observer.lock"] {
        assert_eq!(
            fs::metadata(parent.path().join("rust-host-v1").join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn exact_release_queue_deduplicates_without_replacing_history_or_moved_source() {
    let parent = parent();
    let store = initialize(parent.path());
    queue(&store);
    let before = read(parent.path());
    assert_eq!(
        store
            .enqueue_release("3333333333333333", "v3.48.0", &"a".repeat(40), 1300)
            .unwrap(),
        "1111111111111111"
    );
    assert_eq!(read(parent.path()), before);
    assert_eq!(
        store.enqueue_release("3333333333333333", "v3.48.0", &"c".repeat(40), 1300),
        Err(Error::SourceMoved)
    );
    assert_eq!(read(parent.path()), before);
    for (id, tag, sha) in [
        ("bad", "v3.48.0", "a".repeat(40)),
        ("3333333333333333", "v3.50.0", "a".repeat(40)),
        ("3333333333333333", "v3.49.0", "a".repeat(39)),
    ] {
        assert_eq!(
            store.enqueue_release(id, tag, &sha, 1300),
            Err(Error::InvalidRelease)
        );
    }
    assert_eq!(
        store.status(1400).unwrap()["jobs"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn restart_recovery_retains_unknown_jobs_and_never_requeues_after_resume() {
    let parent = parent();
    let store = initialize(parent.path());
    queue(&store);
    // Synthetic interrupted checkpoint; no live work or product pass is made.
    let mut checkpoint = read(parent.path());
    checkpoint["jobs"][0]["state"] = json!("running");
    checkpoint["jobs"][1]["state"] = json!("preparing");
    write(parent.path(), &checkpoint);
    let orphaned = store.status(1900).unwrap();
    assert_eq!(orphaned["unknown_jobs"], 0);
    assert_eq!(orphaned["orphaned_jobs"], 2);
    assert_eq!(orphaned["unresolved_jobs"], 2);
    let lease = store.start_observer(2000).unwrap();
    let status = store.status(2100).unwrap();
    assert_eq!(status["unknown_jobs"], 2);
    assert!(status["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|j| j["state"] == "unknown"));
    assert_eq!(status["observer"]["lease_held"], true);
    assert_eq!(status["observer"]["status"], "online");
    assert!(matches!(store.start_observer(2200), Err(Error::Busy)));
    store.set_hold(false, 2300).unwrap();
    store.request_stop(2400).unwrap();
    assert!(lease.heartbeat(2500).unwrap());
    lease.finish(2600).unwrap();
    let stopped = store.status(2700).unwrap();
    assert_eq!(stopped["observer"]["status"], "stopped");
    assert_eq!(stopped["unknown_jobs"], 2);
    let restarted = store.start_observer(2800).unwrap();
    assert!(!restarted.heartbeat(2900).unwrap());
    assert_eq!(store.status(3000).unwrap()["unknown_jobs"], 2);
    restarted.finish(3100).unwrap();
}

#[test]
fn kernel_lease_and_heartbeat_age_are_distinct_and_dropped_lease_is_not_online() {
    let parent = parent();
    let store = initialize(parent.path());
    let lease = store.start_observer(2000).unwrap();
    assert_eq!(store.status(18000).unwrap()["observer"]["status"], "stale");
    assert!(!lease.heartbeat(19000).unwrap());
    assert_eq!(store.status(19500).unwrap()["observer"]["status"], "online");
    drop(lease);
    let offline = store.status(20000).unwrap();
    assert_eq!(offline["observer"]["lease_held"], false);
    assert_eq!(offline["observer"]["status"], "stopped");
    assert_eq!(offline["observer"]["heartbeat_age_ms"], 1000);
    assert_eq!(store.set_hold(false, 18999), Err(Error::Clock));
    assert_eq!(store.status(18999), Err(Error::Clock));
}

#[test]
fn refuses_symlinks_hardlinks_loose_files_and_partial_initialization() {
    for name in ["state.json", "transaction.lock", "observer.lock"] {
        for mutation in ["symlink", "hardlink", "permissions", "missing"] {
            let parent = parent();
            let _store = initialize(parent.path());
            let path = parent.path().join("rust-host-v1").join(name);
            let outside = parent.path().join("outside");
            fs::write(&outside, b"never overwritten").unwrap();
            match mutation {
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    symlink(&outside, &path).unwrap();
                }
                "hardlink" => {
                    fs::hard_link(&path, parent.path().join("linked")).unwrap();
                }
                "permissions" => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap()
                }
                "missing" => fs::remove_file(&path).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                HostLifecycleStore::open(parent.path()).is_err(),
                "{name} {mutation}"
            );
            assert_eq!(fs::read(outside).unwrap(), b"never overwritten");
        }
    }
    let parent = parent();
    fs::create_dir(parent.path().join("rust-host-v1")).unwrap();
    assert!(matches!(
        HostLifecycleStore::initialize(parent.path(), "a/b", 1000),
        Err(Error::AlreadyInitialized)
    ));
    assert!(HostLifecycleStore::open(parent.path()).is_err());
}

#[test]
fn rejects_unknown_keys_duplicate_json_versions_and_clock_or_generation_overflow() {
    let parent = parent();
    let store = initialize(parent.path());
    queue(&store);
    let original = read(parent.path());
    let mut cases = Vec::new();
    let mut value = original.clone();
    value["private_secret"] = json!("must not be exposed");
    cases.push(value);
    let mut value = original.clone();
    value["schema"] = json!("hol-gauntlet-rust-host-state.v2");
    cases.push(value);
    let mut value = original.clone();
    value["held"] = json!(0);
    cases.push(value);
    let mut value = original.clone();
    value["jobs"][1]["id"] = value["jobs"][0]["id"].clone();
    cases.push(value);
    let mut value = original.clone();
    value["jobs"][1]["tag"] = value["jobs"][0]["tag"].clone();
    cases.push(value);
    let mut value = original.clone();
    value["jobs"][0]["state"] = json!("invented");
    cases.push(value);
    let mut value = original.clone();
    value["jobs"][0]["created_at_ms"] = json!(9999);
    cases.push(value);
    let mut value = original.clone();
    value["jobs"][0]["deployment_digest"] = json!("bad");
    cases.push(value);
    for value in cases {
        write(parent.path(), &value);
        assert!(matches!(store.status(1300), Err(Error::InvalidState)));
    }
    fs::write(
        parent.path().join("rust-host-v1/state.json"),
        b"{\"schema\":1,\"schema\":2}",
    )
    .unwrap();
    assert_eq!(store.status(1300), Err(Error::InvalidState));
    let mut overflow = original.clone();
    overflow["generation"] = json!(u64::MAX);
    write(parent.path(), &overflow);
    assert_eq!(store.set_hold(false, 1300), Err(Error::TooLarge));
    assert_eq!(read(parent.path()), overflow);
    write(parent.path(), &original);
    assert_eq!(store.set_hold(false, 1100), Err(Error::Clock));
    assert_eq!(read(parent.path()), original);
}

#[test]
fn refuses_replaced_namespace_checkpoint_instance_and_permanent_lease() {
    for change in ["directory", "instance", "lock"] {
        let parent = parent();
        let store = initialize(parent.path());
        match change {
            "directory" => {
                fs::rename(
                    parent.path().join("rust-host-v1"),
                    parent.path().join("retained"),
                )
                .unwrap();
                let _replacement = initialize(parent.path());
            }
            "instance" => {
                let mut value = read(parent.path());
                value["instance_id"] = json!("f".repeat(32));
                write(parent.path(), &value);
            }
            "lock" => {
                let lease = store.start_observer(2000).unwrap();
                fs::rename(
                    parent.path().join("rust-host-v1/observer.lock"),
                    parent.path().join("retained.lock"),
                )
                .unwrap();
                let path = parent.path().join("rust-host-v1/observer.lock");
                fs::write(&path, []).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                assert_eq!(lease.heartbeat(2100), Err(Error::Changed));
                continue;
            }
            _ => unreachable!(),
        }
        assert_eq!(store.set_hold(false, 3000), Err(Error::Changed));
    }
}

#[test]
fn incomplete_temp_checkpoint_cannot_replace_last_committed_state() {
    let parent = parent();
    let store = initialize(parent.path());
    queue(&store);
    let before = store.status(1300).unwrap();
    // Simulate death before the atomic rename. The prior checkpoint remains
    // readable; the partial artifact is retained rather than repaired.
    let pending = parent
        .path()
        .join("rust-host-v1/checkpoint-interrupted.tmp");
    fs::write(&pending, b"{partial").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    drop(store);
    let reopened = HostLifecycleStore::open(parent.path()).unwrap();
    assert_eq!(reopened.status(1300).unwrap(), before);
    reopened.set_hold(false, 1400).unwrap();
    assert_eq!(fs::read(pending).unwrap(), b"{partial");
    assert_eq!(reopened.status(1500).unwrap()["jobs"], before["jobs"]);
}

#[test]
fn private_parent_and_fixed_namespace_refuse_public_modes_and_symlink_aliases() {
    let parent = parent();
    let store = initialize(parent.path());
    let alias = parent.path().join("alias");
    symlink(parent.path(), &alias).unwrap();
    assert!(matches!(
        HostLifecycleStore::open(&alias),
        Err(Error::UnsafeDirectory)
    ));
    let namespace = parent.path().join("rust-host-v1");
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(store.set_hold(false, 1100).is_err());
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        HostLifecycleStore::open(parent.path()),
        Err(Error::UnsafeDirectory)
    ));
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(store.status(1200).unwrap()["admissions_held"], true);
}

#[test]
fn moving_namespace_into_a_replaced_parent_invalidates_the_original_store() {
    let container = parent();
    let path = container.path().join("state");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let store = initialize(&path);
    let retained = container.path().join("retained-parent");
    fs::rename(&path, &retained).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(retained.join("rust-host-v1"), path.join("rust-host-v1")).unwrap();
    assert_eq!(store.set_hold(false, 1100), Err(Error::Changed));
    assert_eq!(
        HostLifecycleStore::open(&path)
            .unwrap()
            .status(1200)
            .unwrap()["admissions_held"],
        true
    );
}
