use super::files::SITE;
use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn unprivileged_clone_refuses_before_any_pins_or_files() {
    if geteuid().as_raw() == 0 {
        return;
    }
    let pins = CandidatePrefixClonePins {
        job_id: "",
        source_sha: "",
        source_archive_sha256: "",
        archive_sha256: "",
        version: "",
        baseline_path: Path::new(""),
        baseline_tree_sha256: "",
        stage_tree_sha256: "",
    };
    assert_eq!(
        clone_captured_candidate_prefix_ineligible(&pins),
        Err(CandidatePrefixCloneError::RootRequired)
    );
}

#[test]
#[ignore = "Root-owned fixture; run explicitly on the dedicated ARM VM"]
fn clone_keeps_reviewed_dependencies_and_replaces_only_product_files() {
    assert_eq!(geteuid().as_raw(), 0);
    let scratch = tempfile::tempdir().unwrap();
    let baseline = scratch.path().join("baseline");
    let stage = scratch.path().join("stage");
    let target = scratch.path().join("target");
    fs::create_dir(&baseline).unwrap();
    fs::create_dir(&stage).unwrap();
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(baseline.join("lib/python3.12/site-packages/dependency")).unwrap();
    fs::create_dir_all(baseline.join("lib/python3.12/site-packages/codex_plugin_scanner")).unwrap();
    fs::create_dir_all(baseline.join("lib/python3.12/site-packages/hol_guard-3.49.0.dist-info"))
        .unwrap();
    fs::write(
        baseline.join("lib/python3.12/site-packages/dependency/__init__.py"),
        b"reviewed dependency",
    )
    .unwrap();
    fs::write(
        baseline.join("lib/python3.12/site-packages/codex_plugin_scanner/old.py"),
        b"old product",
    )
    .unwrap();
    fs::write(
        baseline.join("lib/python3.12/site-packages/hol_guard-3.49.0.dist-info/METADATA"),
        b"old distribution",
    )
    .unwrap();
    fs::create_dir_all(stage.join("codex_plugin_scanner/_native")).unwrap();
    fs::create_dir_all(stage.join("hol_guard-3.48.0.dist-info")).unwrap();
    fs::write(
        stage.join("codex_plugin_scanner/_native/hol-guard-runtime"),
        b"inert new native",
    )
    .unwrap();
    fs::write(
        stage.join("hol_guard-3.48.0.dist-info/METADATA"),
        b"new distribution",
    )
    .unwrap();
    let baseline_fd = open(
        &baseline,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let stage_fd = open(
        &stage,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let target_fd = open(
        &target,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let mut entries_seen = 0;
    let mut bytes = 0;
    clone_baseline(
        &baseline_fd,
        &target_fd,
        "",
        0,
        &mut entries_seen,
        &mut bytes,
        true,
    )
    .unwrap();
    let mut wheel_files = 0;
    overlay_wheel(&stage_fd, &target_fd, "", 0, &mut wheel_files, &mut bytes).unwrap();
    fchmod(&target_fd, Mode::from_bits_truncate(0o755)).unwrap();
    let inventory = inventory_tree(&target, TreeKind::InstalledPrefix).unwrap();
    assert_eq!(inventory.bytes, bytes);
    assert_eq!(wheel_files, 2);
    let site = target.join(SITE);
    assert_eq!(
        fs::read(site.join("dependency/__init__.py")).unwrap(),
        b"reviewed dependency"
    );
    assert!(!site.join("codex_plugin_scanner/old.py").exists());
    assert!(!site.join("hol_guard-3.49.0.dist-info").exists());
    assert_eq!(
        fs::read(site.join("codex_plugin_scanner/_native/hol-guard-runtime")).unwrap(),
        b"inert new native"
    );
    assert_eq!(
        fs::metadata(site.join("codex_plugin_scanner/_native/hol-guard-runtime"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}
