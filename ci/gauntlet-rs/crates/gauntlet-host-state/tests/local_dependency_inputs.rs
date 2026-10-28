use gauntlet_host_state::{prepare_local_dependency_inputs, prepare_local_source_archive_one_use};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;

const JOB: &str = "cc745baa19000001";
fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("/usr/bin/git")
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
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}
fn elf() -> Vec<u8> {
    let mut raw = vec![0u8; 128];
    raw[..4].copy_from_slice(b"\x7fELF");
    raw[4] = 2;
    raw[5] = 1;
    raw[6] = 1;
    raw[16..18].copy_from_slice(&2u16.to_le_bytes());
    raw[18..20].copy_from_slice(&183u16.to_le_bytes());
    raw[20..24].copy_from_slice(&1u32.to_le_bytes());
    raw[32..40].copy_from_slice(&64u64.to_le_bytes());
    raw[52..54].copy_from_slice(&64u16.to_le_bytes());
    raw[54..56].copy_from_slice(&56u16.to_le_bytes());
    raw[56..58].copy_from_slice(&1u16.to_le_bytes());
    raw[64..68].copy_from_slice(&1u32.to_le_bytes());
    raw
}
fn fixture(
    root: &Path,
    linked_project: bool,
) -> (std::path::PathBuf, std::path::PathBuf, String, String) {
    let repo = root.join("source");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "--template="]);
    if linked_project {
        symlink("../outside", repo.join("pyproject.toml")).unwrap();
    } else {
        fs::write(repo.join("pyproject.toml"), b"[project]\nversion='1.0.0'\n").unwrap();
    }
    fs::write(repo.join("uv.lock"), b"version = 1\n").unwrap();
    git(&repo, &["add", "pyproject.toml", "uv.lock"]);
    git(&repo, &["commit", "-qm", "source"]);
    let sha = git(&repo, &["rev-parse", "HEAD"]);
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let prepared = prepare_local_source_archive_one_use(&state, JOB, &repo, &sha).unwrap();
    let archive = prepared["source_archive_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    (repo, state, sha, archive)
}
#[test]
fn capsule_uses_exact_git_blobs_after_worktree_advances_and_preserves_source_and_replay() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let (repo, state, sha, archive) = fixture(&root, false);
    fs::write(repo.join("pyproject.toml"), b"newer different input").unwrap();
    git(&repo, &["add", "pyproject.toml"]);
    git(&repo, &["commit", "-qm", "newer"]);
    let binary = root.join("exporter");
    let raw = elf();
    fs::write(&binary, &raw).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o555)).unwrap();
    let pin = format!("{:x}", Sha256::digest(&raw));
    let source = state.join("private/local-builds").join(JOB);
    let source_before = fs::read(source.join("source.tar.gz")).unwrap();
    let source_receipt = fs::read(source.join("source-preparation.v1.json")).unwrap();
    let report =
        prepare_local_dependency_inputs(&state, JOB, &archive, &repo, &sha, &binary, &pin).unwrap();
    assert_eq!(report["source_sha"], sha);
    assert_eq!(report["execution_eligible"], false);
    let inputs = source.join("dependency-inputs");
    let bytes = fs::read(inputs.join("inputs.zip")).unwrap();
    assert_eq!(
        report["payload_sha256"],
        format!("{:x}", Sha256::digest(&bytes))
    );
    let receipt = fs::read(inputs.join("preparation.v1.json")).unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
    assert_eq!(zip.len(), 3);
    let mut project = Vec::new();
    zip.by_name("pyproject.toml")
        .unwrap()
        .read_to_end(&mut project)
        .unwrap();
    assert_eq!(project, b"[project]\nversion='1.0.0'\n");
    assert!(
        prepare_local_dependency_inputs(&state, JOB, &archive, &repo, &sha, &binary, &pin)
            .unwrap_err()
            .contains("consumed")
    );
    assert_eq!(fs::read(inputs.join("inputs.zip")).unwrap(), bytes);
    assert_eq!(
        fs::read(inputs.join("preparation.v1.json")).unwrap(),
        receipt
    );
    assert_eq!(
        fs::read(source.join("source.tar.gz")).unwrap(),
        source_before
    );
    assert_eq!(
        fs::read(source.join("source-preparation.v1.json")).unwrap(),
        source_receipt
    );
}
#[test]
fn linked_project_wrong_architecture_and_dynamic_exporters_refuse_before_capsule_mutation() {
    for linked_project in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let (repo, state, sha, archive) = fixture(&root, linked_project);
        let path = root.join("exporter");
        let mut dynamic = elf();
        dynamic[64..68].copy_from_slice(&3u32.to_le_bytes());
        let mut wrong = elf();
        wrong[18..20].copy_from_slice(&62u16.to_le_bytes());
        for bytes in [dynamic, wrong, vec![0u8; 128]] {
            fs::write(&path, &bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
            let pin = format!("{:x}", Sha256::digest(&bytes));
            assert!(prepare_local_dependency_inputs(
                &state, JOB, &archive, &repo, &sha, &path, &pin
            )
            .is_err());
            assert!(!state
                .join("private/local-builds")
                .join(JOB)
                .join("dependency-inputs")
                .exists());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
}
