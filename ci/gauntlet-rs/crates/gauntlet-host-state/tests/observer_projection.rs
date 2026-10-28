use gauntlet_host_state::{compose_observer_snapshot, HostLifecycleStore};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn observations() -> Value {
    let metric = json!({"status":"running","checked_at":100,"name":"hol-beta-bootstrap-20261016-004",
        "cpus":2,"load":0.1,"memory_total":17_179_869_184_u64,"memory_available":15_000_000_000_u64,
        "disk_total":51_539_607_552_u64,"disk_free":20_000_000_000_u64,"private":"do-not-export"});
    let mut host = metric.clone();
    host["status"] = json!("online");
    host["platform"] = json!("Darwin");
    json!({"host":host,"vm":metric,"source_checked_at":100,
        "releases":[{"tag":"v3.48.0","sha":"a".repeat(40),"checked_at":100},
            {"tag":"v3.49.0","sha":"b".repeat(40),"checked_at":100}],"private":"do-not-export"})
}

#[test]
fn public_projection_filters_private_fields_and_keeps_qualification_red() {
    let parent = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store =
        HostLifecycleStore::initialize(parent.path(), "hashgraph-online/hol-guard", 1000).unwrap();
    let config = store
        .configure_observer(
            &json!({"guest_python":"/private/do-not-export"}),
            &"c".repeat(64),
        )
        .unwrap();
    store
        .enqueue_release("1111111111111111", "v3.48.0", &"a".repeat(40), 2000)
        .unwrap();
    let mut lifecycle = store.status(100_000).unwrap();
    lifecycle["jobs"][0]["deployment_digest"] = json!("do-not-export");
    let snapshot =
        compose_observer_snapshot(&config, &lifecycle, &observations(), 100_000).unwrap();
    assert!(!snapshot.to_string().contains("do-not-export"));
    assert_eq!(snapshot["github"]["status"], "connected");
    assert_eq!(
        snapshot["github"]["connection_scope"],
        "release-source-only"
    );
    assert_eq!(
        snapshot["observer"]["schema"],
        "hol-gauntlet-observer.stopped"
    );
    assert_eq!(snapshot["jobs"][0]["sha"], "a".repeat(40));
    assert_eq!(snapshot["vm"]["status"], "running");
    for key in [
        "execution_eligible",
        "qualification_eligible",
        "production_ci_activated",
    ] {
        assert_eq!(snapshot[key], false);
    }
    assert_eq!(snapshot["gate"]["required"], Value::Null);
}

#[test]
fn stale_future_bad_vm_and_moved_tags_never_turn_into_healthy_evidence() {
    let parent = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store =
        HostLifecycleStore::initialize(parent.path(), "hashgraph-online/hol-guard", 1000).unwrap();
    let config = store
        .configure_observer(&json!({}), &"c".repeat(64))
        .unwrap();
    store
        .enqueue_release("1111111111111111", "v3.48.0", &"a".repeat(40), 2000)
        .unwrap();
    let lifecycle = store.status(100_000).unwrap();
    for time in [1, 106] {
        let mut obs = observations();
        obs["vm"]["checked_at"] = json!(time);
        assert_eq!(
            compose_observer_snapshot(&config, &lifecycle, &obs, 100_000).unwrap()["vm"]["status"],
            "unavailable"
        );
    }
    let mut obs = observations();
    obs["vm"]["name"] = json!("wrong-vm");
    assert_eq!(
        compose_observer_snapshot(&config, &lifecycle, &obs, 100_000).unwrap()["vm"]["status"],
        "unavailable"
    );
    let mut obs = observations();
    obs["releases"][0]["sha"] = json!("d".repeat(40));
    let snapshot = compose_observer_snapshot(&config, &lifecycle, &obs, 100_000).unwrap();
    assert_eq!(snapshot["github"]["status"], "attention");
    assert!(snapshot["jobs"][0]["source_error"]
        .as_str()
        .unwrap()
        .contains("retained source pin"));
    assert_eq!(snapshot["jobs"][0]["sha"], "a".repeat(40));
    obs["releases"][0]["checked_at"] = json!(1);
    let snapshot = compose_observer_snapshot(&config, &lifecycle, &obs, 200_000).unwrap();
    assert!(snapshot["github"]["release_errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["error"].as_str().unwrap().contains("stale")));
    assert_eq!(
        store.status(200_000).unwrap()["jobs"][0]["sha"],
        "a".repeat(40)
    );
}
