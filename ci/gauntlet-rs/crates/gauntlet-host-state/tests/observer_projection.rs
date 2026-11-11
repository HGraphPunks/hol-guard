use gauntlet_host_state::{compose_observer_snapshot, HostLifecycleStore};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

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
fn explicit_cli_attachment_reaches_dashboard_without_dispatch_or_false_availability() {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store =
        HostLifecycleStore::initialize(root.path(), "hashgraph-online/hol-guard", 1000).unwrap();
    let config = store
        .configure_observer(&json!({}), &"c".repeat(64))
        .unwrap();
    let journal = root.path().join("original-journal");
    fs::create_dir(&journal).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(journal.join("hol-observer-test")).unwrap();
    let job = "a".repeat(16);
    let path = journal.to_str().unwrap();
    let recorded = gauntlet_host_state::run_native_operation_command(&[
        "record".into(),
        path.into(),
        "hol-observer-test".into(),
        "b".repeat(64),
        "c".repeat(40),
        job.clone(),
        "d".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
        "timeout".into(),
        "1".repeat(64),
        "2".repeat(64),
        path.into(),
        path.into(),
    ])
    .unwrap();
    let run = |action: &str, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_gauntlet-host"))
            .args([action, "--state-parent", root.path().to_str().unwrap()])
            .args(args)
            .output()
            .unwrap()
    };
    let output = run(
        "attach-job",
        &[
            "--operation",
            "native",
            "--journal",
            path,
            "--job-id",
            &job,
            "--intent-sha256",
            recorded["intent_sha256"].as_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let attached: Value = serde_json::from_slice(&output.stdout).unwrap();
    let refresh = run(
        "refresh-job",
        &[
            "--job-id",
            &job,
            "--binding-sha256",
            attached["attachment_sha256"].as_str().unwrap(),
        ],
    );
    assert!(
        refresh.status.success(),
        "{}",
        String::from_utf8_lossy(&refresh.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&refresh.stdout).unwrap(),
        attached
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut lifecycle = store.status(now).unwrap();
    let snapshot = compose_observer_snapshot(&config, &lifecycle, &json!({}), now).unwrap();
    assert_eq!(snapshot["jobs"][0]["phase"], "recorded");
    assert_eq!(snapshot["jobs"][0]["tag"], Value::Null);
    assert_eq!(snapshot["deployment"]["status"], "unavailable");
    assert_eq!(snapshot["execution_eligible"], false);
    assert!(!snapshot.to_string().contains(path));
    assert!(!journal.join(format!("{job}.native-dispatch.json")).exists());
    let before = fs::read(root.path().join("rust-host-v1/state.json")).unwrap();
    assert_eq!(
        run(
            "refresh-job",
            &[
                "--job-id",
                &job,
                "--binding-sha256",
                attached["attachment_sha256"].as_str().unwrap(),
                "--journal",
                path
            ]
        )
        .status
        .code(),
        Some(2)
    );
    assert_eq!(
        fs::read(root.path().join("rust-host-v1/state.json")).unwrap(),
        before
    );
    lifecycle["jobs"][0]["result"]["private"] = json!("never-export");
    assert!(compose_observer_snapshot(&config, &lifecycle, &json!({}), now).is_err());
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
