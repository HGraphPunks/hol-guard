use flate2::write::GzEncoder;
use flate2::Compression;
use gauntlet_host_state::{verify_retained_source_archive_commit, SourceArchiveCommitError};
use sha2::{Digest, Sha256};
use std::fs::{self, Permissions};
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::{Builder, Header};
use tempfile::TempDir;

const JOB_ID: &str = "0123456789abcdef";

#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureMode {
    Direct,
    Shallow,
    Annotated,
}

fn git(args: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn add_file(tar: &mut Builder<GzEncoder<Vec<u8>>>, name: &str, bytes: &[u8]) {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, name, Cursor::new(bytes))
        .unwrap();
}

fn add_directory(tar: &mut Builder<GzEncoder<Vec<u8>>>, root: &Path, directory: &Path) {
    let mut entries = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            add_directory(tar, root, &path);
        } else {
            let relative = path.strip_prefix(root).unwrap();
            let name = format!("repository.git/{}", relative.display());
            add_file(tar, &name, &fs::read(&path).unwrap());
        }
    }
}

fn fixture(mode: FixtureMode, extra: Option<(&str, &[u8])>) -> (TempDir, PathBuf, String, String) {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("source");
    let bare = temp.path().join("repository.git");
    let repo_name = repo.to_str().unwrap();
    let bare_name = bare.to_str().unwrap();
    git(&["init", "-q", repo_name]);
    fs::write(repo.join("README"), b"source-bound fixture\n").unwrap();
    git(&["-C", repo_name, "add", "README"]);
    git(&[
        "-C",
        repo_name,
        "-c",
        "user.name=Gauntlet Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        "Fixture",
    ]);
    if mode == FixtureMode::Shallow {
        fs::write(repo.join("README"), b"second source-bound fixture\n").unwrap();
        git(&["-C", repo_name, "add", "README"]);
        git(&[
            "-C",
            repo_name,
            "-c",
            "user.name=Gauntlet Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "Second fixture",
        ]);
    }
    let source_sha = git(&["-C", repo_name, "rev-parse", "HEAD"]);
    if mode == FixtureMode::Annotated {
        git(&[
            "-C",
            repo_name,
            "-c",
            "user.name=Gauntlet Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "tag",
            "-a",
            "v3.49.0",
            "-m",
            "Annotated fixture",
        ]);
    }
    git(&["init", "-q", "--bare", "--template=", bare_name]);
    let mut fetch = vec![
        format!("--git-dir={bare_name}"),
        "fetch".to_owned(),
        "--no-tags".to_owned(),
    ];
    if mode == FixtureMode::Shallow {
        fetch.push("--depth=1".to_owned());
        fetch.push(format!("file://{repo_name}"));
    } else {
        fetch.push(repo_name.to_owned());
    }
    fetch.push(if mode == FixtureMode::Annotated {
        "refs/tags/v3.49.0:refs/tags/v3.49.0".to_owned()
    } else {
        format!("{source_sha}:refs/tags/v3.49.0")
    });
    git(&fetch.iter().map(String::as_str).collect::<Vec<_>>());
    if mode == FixtureMode::Shallow {
        assert!(bare.join("shallow").is_file());
    }
    let state = temp.path().join("state");
    let mut path = state.clone();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    for part in ["private", "local-builds", JOB_ID] {
        path.push(part);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    }
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = Builder::new(encoder);
    add_directory(&mut tar, &bare, &bare);
    if let Some((name, bytes)) = extra {
        add_file(&mut tar, name, bytes);
    }
    let bytes = tar.into_inner().unwrap().finish().unwrap();
    let archive_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let archive = path.join("source.tar.gz");
    fs::write(&archive, bytes).unwrap();
    fs::set_permissions(&archive, Permissions::from_mode(0o600)).unwrap();
    (
        temp,
        fs::canonicalize(state).unwrap(),
        source_sha,
        archive_sha256,
    )
}

#[test]
fn exact_ref_and_reachable_git_graph_verify_without_execution() {
    let (_temp, state, sha, archive_sha) = fixture(FixtureMode::Direct, None);
    let proof = verify_retained_source_archive_commit(
        &state,
        JOB_ID,
        &archive_sha,
        &sha,
        "refs/tags/v3.49.0",
    )
    .unwrap();
    assert_eq!(proof.source_sha, sha);
    assert_eq!(proof.ref_object_id, sha);
    assert_eq!(proof.archive.archive_sha256, archive_sha);
    assert!(proof.git_graph_verified);
    assert!(!proof.execution_eligible);
}

#[test]
fn wrong_commit_and_missing_ref_refuse() {
    let (_temp, state, sha, archive_sha) = fixture(FixtureMode::Direct, None);
    let wrong = format!(
        "{}{}",
        if sha.starts_with('0') { '1' } else { '0' },
        &sha[1..]
    );
    assert_eq!(
        verify_retained_source_archive_commit(
            &state,
            JOB_ID,
            &archive_sha,
            &wrong,
            "refs/tags/v3.49.0"
        ),
        Err(SourceArchiveCommitError::GitFailed)
    );
    assert_eq!(
        verify_retained_source_archive_commit(
            &state,
            JOB_ID,
            &archive_sha,
            &sha,
            "refs/tags/v3.48.0"
        ),
        Err(SourceArchiveCommitError::MissingRef)
    );
}

#[test]
fn archived_object_alternate_refuses() {
    let (_temp, state, sha, archive_sha) = fixture(
        FixtureMode::Direct,
        Some((
            "repository.git/objects/info/alternates",
            b"/outside/object-store\n",
        )),
    );
    assert_eq!(
        verify_retained_source_archive_commit(
            &state,
            JOB_ID,
            &archive_sha,
            &sha,
            "refs/tags/v3.49.0"
        ),
        Err(SourceArchiveCommitError::InvalidObjectPath)
    );
}

#[test]
fn shallow_fetch_graph_verifies() {
    let (_temp, state, sha, archive_sha) = fixture(FixtureMode::Shallow, None);
    let proof = verify_retained_source_archive_commit(
        &state,
        JOB_ID,
        &archive_sha,
        &sha,
        "refs/tags/v3.49.0",
    )
    .unwrap();
    assert!(proof.git_graph_verified);
    assert!(!proof.execution_eligible);
}

#[test]
fn annotated_tag_peels_to_exact_commit() {
    let (_temp, state, sha, archive_sha) = fixture(FixtureMode::Annotated, None);
    let proof = verify_retained_source_archive_commit(
        &state,
        JOB_ID,
        &archive_sha,
        &sha,
        "refs/tags/v3.49.0",
    )
    .unwrap();
    assert_ne!(proof.ref_object_id, sha);
    assert!(proof.git_graph_verified);
}
