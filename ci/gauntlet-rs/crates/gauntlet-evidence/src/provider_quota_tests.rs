use super::read_provider_quota_snapshot;
use rustix::fs::{flock, open, FlockOperation, Mode, OFlags};
use serde_json::Value;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

fn fixture() -> Value {
    let frozen: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_provider_quota_v1.json"
    ))
    .unwrap();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = baseline["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/benchmark/provider_quota.py")
        .unwrap();
    assert_eq!(frozen["source_sha256"], source["sha256"]);
    let json_data = baseline["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/benchmark/json_data.py")
        .unwrap();
    assert_eq!(frozen["json_data_sha256"], json_data["sha256"]);
    frozen
}

fn install_case(case: &Value) -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = base.join("quota");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, content) in [
        ("config.json", case["config"].as_str().unwrap()),
        ("events.jsonl", case["events"].as_str().unwrap()),
        ("quota.lock", ""),
    ] {
        let path = root.join(name);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (temporary, root)
}

fn read(case: &Value, root: &Path) -> crate::Result<Value> {
    read_provider_quota_snapshot(
        root,
        case["config_digest"].as_str().unwrap(),
        case["allowance_digest"].as_str(),
    )
}

#[test]
fn python_v1_quota_snapshots_and_refusals_match() {
    let frozen = fixture();
    assert_eq!(frozen["schema"], "gauntlet-provider-quota-fixtures.v1");
    let cases = frozen["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for case in cases {
        let (_temporary, root) = install_case(case);
        let name = case["name"].as_str().unwrap();
        let outcome = read(case, &root);
        if let Some(expected) = case.get("snapshot") {
            assert_eq!(outcome.unwrap(), *expected, "{name}");
            continue;
        }
        let reason = outcome.unwrap_err().to_string();
        let expected_stage = match name {
            "interrupted-append" => "interrupted quota append",
            "blank-row" | "duplicate-key" => "invalid bounded quota JSON",
            "wrong-previous" => "provider quota journal chain",
            "overlap" => "overlapping, repeated or halted",
            "wrong-settlement" => "settled usage differs",
            "unknown-event" => "unknown provider quota journal event",
            "wrong-config-pin" => "provider quota configuration differs",
            "wrong-allowance-pin" => "provider allowance differs",
            _ => panic!("unreviewed negative fixture: {name}"),
        };
        assert!(reason.contains(expected_stage), "{name}: {reason}");
    }
}

#[test]
fn quota_reader_refuses_mutable_custody_and_contended_lock() {
    let frozen = fixture();
    let case = &frozen["cases"][0];
    let (_temporary, root) = install_case(case);
    assert!(read(case, &root).is_ok());

    let parent = root.parent().unwrap();
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(read(case, &root).is_err());
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(read(case, &root).is_err());
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let lock = open(root.join("quota.lock"), OFlags::RDWR, Mode::empty()).unwrap();
    flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    assert!(read(case, &root).unwrap_err().to_string().contains("busy"));
    drop(lock);

    let events = root.join("events.jsonl");
    let hardlink = root.join("events-other");
    std::fs::hard_link(&events, &hardlink).unwrap();
    assert!(read(case, &root).is_err());
    std::fs::remove_file(hardlink).unwrap();
    std::fs::remove_file(&events).unwrap();
    symlink(root.join("config.json"), events).unwrap();
    assert!(read(case, &root).is_err());
}
