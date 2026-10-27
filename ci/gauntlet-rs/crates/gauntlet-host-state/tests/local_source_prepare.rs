use gauntlet_host_state::{
    prepare_local_source_archive_one_use, verify_retained_source_archive_commit,
    LocalSourcePrepareError,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

const JOB: &str = "ecc175ad14890001";

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-C",
            repo.to_str().unwrap(),
            "-c",
            "user.name=Gauntlet fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn exact_older_commit_is_captured_without_checkout_or_hook_execution_and_replay_is_immutable() {
    let temp = tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let repository = root.join("source");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "-q", "--template="]);
    fs::write(repository.join("README"), b"exact first commit\n").unwrap();
    git(&repository, &["add", "README"]);
    git(&repository, &["commit", "-qm", "first"]);
    let first = git(&repository, &["rev-parse", "HEAD"]);
    fs::write(repository.join("README"), b"different newer commit\n").unwrap();
    git(&repository, &["add", "README"]);
    git(&repository, &["commit", "-qm", "second"]);
    let newest = git(&repository, &["rev-parse", "HEAD"]);
    assert_ne!(first, newest);
    let hooks = repository.join(".git/hooks");
    fs::create_dir(&hooks).unwrap();
    let hook = hooks.join("post-checkout");
    fs::write(
        &hook,
        format!("#!/bin/sh\ntouch '{}'\n", root.join("hook-ran").display()),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let report = prepare_local_source_archive_one_use(&state, JOB, &repository, &first).unwrap();
    assert_eq!(report["source_sha"], first);
    assert_eq!(report["git_graph_verified"], true);
    assert_eq!(report["execution_eligible"], false);
    assert!(!root.join("hook-ran").exists());
    let slot = state.join("private/local-builds").join(JOB);
    let archive = slot.join("source.tar.gz");
    let before = fs::read(&archive).unwrap();
    let hash = format!("{:x}", Sha256::digest(&before));
    assert_eq!(report["source_archive_sha256"], hash);
    let receipt = fs::read(slot.join("source-preparation.v1.json")).unwrap();
    let proof = verify_retained_source_archive_commit(
        &state,
        JOB,
        &hash,
        &first,
        &format!("refs/heads/local-{first}"),
    )
    .unwrap();
    assert!(proof.git_graph_verified());
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(before.as_slice()));
    let names: Vec<_> = tar
        .entries()
        .unwrap()
        .map(|p| p.unwrap().path().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(!names
        .iter()
        .any(|name| name.contains("hooks/") || name.ends_with("FETCH_HEAD")));
    assert_eq!(
        prepare_local_source_archive_one_use(&state, JOB, &repository, &newest),
        Err(LocalSourcePrepareError::Consumed)
    );
    assert_eq!(fs::read(archive).unwrap(), before);
    assert_eq!(
        fs::read(slot.join("source-preparation.v1.json")).unwrap(),
        receipt
    );
}

#[test]
fn unsafe_inputs_refuse_before_mutation_and_failed_fetch_consumes_its_slot() {
    let temp = tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let repository = root.join("source");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "-q", "--template="]);
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let linked = root.join("linked-source");
    symlink(&repository, &linked).unwrap();
    for (id, source, sha) in [
        ("../../bad", repository.as_path(), "a".repeat(40)),
        (JOB, linked.as_path(), "a".repeat(40)),
        (JOB, repository.as_path(), "not-a-commit".to_owned()),
    ] {
        assert_eq!(
            prepare_local_source_archive_one_use(&state, id, source, &sha),
            Err(LocalSourcePrepareError::InvalidInput)
        );
    }
    assert!(!state.join("private").exists());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        prepare_local_source_archive_one_use(&state, JOB, &repository, &"a".repeat(40)),
        Err(LocalSourcePrepareError::UnsafeState)
    );
    assert!(!state.join("private").exists());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        prepare_local_source_archive_one_use(&state, JOB, &repository, &"a".repeat(40)),
        Err(LocalSourcePrepareError::GitUnavailable)
    );
    let slot = state.join("private/local-builds").join(JOB);
    assert!(slot.join("repository.git").is_dir());
    assert!(!slot.join("source-preparation.v1.json").exists());
    assert_eq!(
        prepare_local_source_archive_one_use(&state, JOB, &repository, &"a".repeat(40)),
        Err(LocalSourcePrepareError::Consumed)
    );
}
