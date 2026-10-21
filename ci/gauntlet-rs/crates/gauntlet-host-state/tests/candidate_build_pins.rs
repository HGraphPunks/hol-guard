//! Host journal mechanics only; these records do not authorize a VM build.

use gauntlet_host_state::{
    HostCandidateBuildPinError, HostCandidateBuildPinJournal, HostCandidateBuildPins,
};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use tempfile::tempdir;

const JOB: &str = "c04e7f93a2b15d68";

fn pins() -> HostCandidateBuildPins {
    HostCandidateBuildPins {
        job_id: JOB.to_owned(),
        source_sha: "76c31929833b5571d25a56d9783e24a0997d5422".to_owned(),
        source_archive_sha256: "bedd98ab7da8ca728484799e1ef6b13c854f7fcbb31a17ebdcc469c4c772af43"
            .to_owned(),
        version: "3.49.0".to_owned(),
        controller_tree_sha256: "33c98333891743e6976bee9a123365fe7fe95dcf1bf9b65ee39a59fb41043c68"
            .to_owned(),
        builder_image_id: "sha256:39a6e74e48b2619189e191b5f5038ce0e27fba1cb57177d713e2077e64c7bb29"
            .to_owned(),
        policy_sha256: "3aa6b76487e84ccede7093a1d79e8eb3d5688de8260cdfd12ebd6d12743667a8"
            .to_owned(),
        podman_sha256: "f93ee492920150e229b9b41729bfe675073a4df0569ee5d570a8106b5a64506a"
            .to_owned(),
        slirp4netns_sha256: "4211dca7736aeb6fdd055350c8138d095d3dc5170f2ebf2a68fed5cdd4372f1c"
            .to_owned(),
        apparmor_parser_sha256: "68556e4676aaf0849a33ef38ee5a6617d8686a84edf3d5b191ee73e291ecb0c8"
            .to_owned(),
        seccomp_sha256: "cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c"
            .to_owned(),
        runner_binary_sha256: "1920692134fab02440a8f32b66965aedcacb6c18a19f549fb318f13a036cdfdb"
            .to_owned(),
        result_reader_binary_sha256:
            "f977ae6a0da162392cd0c03360083d78a98b66cd6e6e12144f8f7756f1363c98".to_owned(),
    }
}

#[test]
fn one_use_host_pin_survives_reopen_and_refuses_replay() {
    let dir = tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostCandidateBuildPinJournal::open(&root).unwrap();
    let expected = pins();
    let record = journal.record(&expected).unwrap();
    assert_eq!(record.pins, expected);
    assert_eq!(record.host_nonce_hex.len(), 64);
    assert_eq!(record.raw_sha256.len(), 64);
    assert_eq!(record.to_json()["execution_eligible"], false);
    let file = root.join(format!("{JOB}.candidate-build-pin.json"));
    let meta = fs::symlink_metadata(file).unwrap();
    assert!(meta.file_type().is_file());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let reopened = HostCandidateBuildPinJournal::open(&root).unwrap();
    assert_eq!(reopened.read(JOB).unwrap(), record);
    assert_eq!(
        reopened.record(&expected),
        Err(HostCandidateBuildPinError::AlreadyRecorded)
    );
}

#[test]
fn invalid_identity_and_partial_or_linked_records_refuse() {
    let dir = tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostCandidateBuildPinJournal::open(&root).unwrap();
    let mut invalid = pins();
    invalid.builder_image_id = "sha256:mutable".to_owned();
    assert_eq!(
        journal.record(&invalid),
        Err(HostCandidateBuildPinError::InvalidPins)
    );
    assert_eq!(journal.read(JOB), Err(HostCandidateBuildPinError::Missing));
    let file = root.join(format!("{JOB}.candidate-build-pin.json"));
    fs::write(&file, b"{").unwrap();
    assert_eq!(
        journal.read(JOB),
        Err(HostCandidateBuildPinError::UnsafeRecord)
    );
    assert_eq!(
        journal.record(&pins()),
        Err(HostCandidateBuildPinError::AlreadyRecorded)
    );

    let linked = tempdir().unwrap();
    let linked_root = linked.path().canonicalize().unwrap();
    fs::set_permissions(&linked_root, fs::Permissions::from_mode(0o700)).unwrap();
    let target = linked_root.join("target.json");
    fs::write(&target, b"{}").unwrap();
    symlink(
        &target,
        linked_root.join(format!("{JOB}.candidate-build-pin.json")),
    )
    .unwrap();
    let linked_journal = HostCandidateBuildPinJournal::open(&linked_root).unwrap();
    assert_eq!(
        linked_journal.read(JOB),
        Err(HostCandidateBuildPinError::UnsafeRecord)
    );
}

#[test]
fn swapped_or_loose_host_directory_refuses() {
    let outer = tempdir().unwrap();
    let outer_root = outer.path().canonicalize().unwrap();
    let path = outer_root.join("pins");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = HostCandidateBuildPinJournal::open(&path).unwrap();
    journal.record(&pins()).unwrap();
    let old = outer_root.join("pins-old");
    fs::rename(&path, &old).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(journal.read(JOB), Err(HostCandidateBuildPinError::Changed));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        HostCandidateBuildPinJournal::open(&path),
        Err(HostCandidateBuildPinError::UnsafeDirectory)
    ));
}
