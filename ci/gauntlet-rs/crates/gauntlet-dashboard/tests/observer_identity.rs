use gauntlet_dashboard::snapshot::PublicRoot;
use serde_json::{json, Value};
use std::fs;

#[test]
fn new_observer_identity_stopping_and_clock_are_not_greenwashed() {
    let dir = tempfile::tempdir().unwrap();
    let id = "a".repeat(32);
    let mut value = json!({"schema":"hol-gauntlet-dashboard.v1","instance_id":id,
        "updated_at":100,"jobs":[],"observer":{"schema":"hol-gauntlet-observer.v2"}});
    let root = PublicRoot::open(dir.path()).unwrap();
    let write =
        |value: &Value| fs::write(dir.path().join("snapshot.json"), value.to_string()).unwrap();
    write(&value);
    assert_eq!(root.snapshot(101.0)["collector_status"], "unavailable");
    fs::write(
        dir.path().join("dashboard-id.json"),
        json!({"instance_id":id}).to_string(),
    )
    .unwrap();
    assert_eq!(root.snapshot(101.0)["collector_status"], "online");
    value["instance_id"] = json!("b".repeat(32));
    write(&value);
    assert_eq!(root.snapshot(101.0)["collector_status"], "unavailable");
    value["instance_id"] = json!(id);
    value["observer"]["schema"] = json!("hol-gauntlet-observer.stopped");
    write(&value);
    assert_eq!(root.snapshot(101.0)["collector_status"], "stopped");
    assert_eq!(root.snapshot(200.0)["collector_status"], "stopped");
    value["updated_at"] = json!(110);
    write(&value);
    assert_eq!(root.snapshot(101.0)["collector_status"], "unavailable");
    assert_eq!(root.snapshot(f64::NAN)["collector_status"], "unavailable");
    value["updated_at"] = json!(0);
    write(&value);
    assert_eq!(root.snapshot(101.0)["collector_status"], "unavailable");
}

#[test]
fn future_auxiliary_publications_are_not_current() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("snapshot.json"),
        json!({"schema":"hol-gauntlet-dashboard.v1","updated_at":100,"jobs":[]}).to_string(),
    )
    .unwrap();
    fs::write(
        dir.path().join("live.json"),
        json!({"schema":"hol-gauntlet-live-operations.v1","updated_at":200,"status":"running"})
            .to_string(),
    )
    .unwrap();
    let root = PublicRoot::open(dir.path()).unwrap();
    assert_eq!(root.snapshot(101.0)["collector_status"], "online");
    assert!(root.snapshot(101.0).get("live_e2e").is_none());
}
