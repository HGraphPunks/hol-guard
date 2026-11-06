use gauntlet_contracts::DependencyRunPins;
use gauntlet_host_state::{public_vm_operations, DependencyIntentJournal};
use serde_json::json;
use std::os::unix::fs::{symlink, PermissionsExt};

fn pins(job: &str) -> DependencyRunPins {
    DependencyRunPins::from_value(json!({
        "job_id":job,"source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
        "capsule_sha256":"c".repeat(64),"capsule_bytes":1551712,"pyproject_sha256":"d".repeat(64),
        "uv_lock_sha256":"e".repeat(64),"exporter_sha256":"f".repeat(64),"capture_worker_sha256":"1".repeat(64),
        "capture_receipt_sha256":"2".repeat(64),"controller_root":"/opt/hol-gauntlet/controller-0123456789abcdef",
        "controller_tree_sha256":"3".repeat(64),"uv_base_image_id":"4".repeat(64),"rust_base_image_id":"5".repeat(64),
        "builder_image_id":format!("sha256:{}", "6".repeat(64)),"policy_sha256":"7".repeat(64),"podman_sha256":"8".repeat(64),
        "slirp4netns_sha256":"9".repeat(64),"apparmor_parser_sha256":"a".repeat(64),"seccomp_sha256":"b".repeat(64),"runner_binary_sha256":"c".repeat(64)
    })).unwrap()
}

#[test]
fn dependency_intent_survives_restart_and_replay_preserves_exact_target_pins() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let operations = public_vm_operations(Some("hol-gauntlet-rust-build-20261026-001")).unwrap();
    let journal = DependencyIntentJournal::open(&canonical).unwrap();
    let intent = journal
        .record(pins("0123456789abcdef"), &operations)
        .unwrap();
    let path = temp.path().join("0123456789abcdef.dependency-intent.json");
    let original = std::fs::read(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        DependencyIntentJournal::open(&canonical)
            .unwrap()
            .read("0123456789abcdef")
            .unwrap(),
        intent
    );
    assert!(journal
        .record(pins("0123456789abcdef"), &operations)
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let second = journal
        .record(pins("1123456789abcdef"), &operations)
        .unwrap();
    assert_ne!(intent.nonce, second.nonce);
    assert_eq!(intent.vm, "hol-gauntlet-rust-build-20261026-001");
    std::fs::write(&path, b"{}").unwrap();
    assert!(journal.read("0123456789abcdef").is_err());
    assert!(journal
        .record(pins("0123456789abcdef"), &operations)
        .is_err());
}

#[test]
fn dependency_journal_refuses_linked_records_and_a_replaced_directory() {
    let temp = tempfile::tempdir().unwrap();
    let canonical = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = canonical.join("journal");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = DependencyIntentJournal::open(&directory).unwrap();
    let outside = temp.path().join("outside");
    std::fs::write(&outside, b"retained").unwrap();
    symlink(
        &outside,
        directory.join("0123456789abcdef.dependency-intent.json"),
    )
    .unwrap();
    assert!(journal.read("0123456789abcdef").is_err());
    let operations = public_vm_operations(None).unwrap();
    assert!(journal
        .record(pins("0123456789abcdef"), &operations)
        .is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"retained");
    std::fs::rename(&directory, temp.path().join("retained-journal")).unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(journal
        .record(pins("1123456789abcdef"), &operations)
        .is_err());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
}
