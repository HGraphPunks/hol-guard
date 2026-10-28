//! One-use local Git-object capture. No checkout, candidate hooks, credential
//! broker or candidate build runs on the host. Failed slots remain consumed.

use crate::fixed_process::run_fixed_clean;
use crate::private_jobs::{child_directory, state_root};
use crate::verify_retained_source_archive_commit;
use gauntlet_contracts::is_git_sha;
use rustix::fs::{fchmod, fsync, mkdirat, openat, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalSourcePrepareError {
    InvalidInput,
    UnsafeState,
    Consumed,
    GitUnavailable,
    UnsafeObjects,
    Changed,
    TooLarge,
    InvalidGraph,
    Io,
}

impl fmt::Display for LocalSourcePrepareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "literal local repository, exact commit and job ID required",
            Self::UnsafeState => "private source capture state is unsafe",
            Self::Consumed => "source capture job already exists; preserve and reconcile",
            Self::GitUnavailable => "bounded fixed local Git operation failed; slot consumed",
            Self::UnsafeObjects => "ordinary private Git object files required",
            Self::Changed => "Git object or source directory changed during capture",
            Self::TooLarge => "Git object archive exceeds fixed limits",
            Self::InvalidGraph => "captured Git graph differs from exact source pin",
            Self::Io => "local source capture I/O failed; preserve slot",
        })
    }
}

impl std::error::Error for LocalSourcePrepareError {}

fn directory(
    parent: &OwnedFd,
    name: &str,
    owner: u32,
    exclusive: bool,
) -> Result<OwnedFd, LocalSourcePrepareError> {
    match mkdirat(parent, name, Mode::from_bits_truncate(0o700)) {
        Ok(()) => {
            let fd = openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| LocalSourcePrepareError::Io)?;
            fchmod(&fd, Mode::from_bits_truncate(0o700))
                .map_err(|_| LocalSourcePrepareError::Io)?;
            fsync(parent).map_err(|_| LocalSourcePrepareError::Io)?;
        }
        Err(Errno::EXIST) if !exclusive => {}
        Err(Errno::EXIST) => return Err(LocalSourcePrepareError::Consumed),
        Err(_) => return Err(LocalSourcePrepareError::Io),
    }
    child_directory(parent, name, owner).map_err(|_| LocalSourcePrepareError::UnsafeState)
}

fn git(bare: &Path, args: &[&str]) -> Result<Vec<u8>, LocalSourcePrepareError> {
    let mut argv = vec!["/usr/bin/git".to_owned()];
    for config in [
        "core.hooksPath=/dev/null",
        "credential.helper=",
        "fetch.fsckObjects=true",
        "maintenance.auto=false",
        "gc.auto=0",
        "protocol.allow=never",
        "protocol.file.allow=always",
    ] {
        argv.extend(["-c".to_owned(), config.to_owned()]);
    }
    argv.push(format!("--git-dir={}", bare.display()));
    argv.extend(args.iter().map(|arg| (*arg).to_owned()));
    run_fixed_clean(
        &argv,
        Duration::from_secs(300),
        4096,
        16 * 1024,
        &[
            ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_NO_LAZY_FETCH", "1"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
        ],
    )
    .map_err(|_| LocalSourcePrepareError::GitUnavailable)
}

/// Produce the bare-object format consumed by the fixed unprivileged builder.
/// The caller owns a preexisting 0700 state root. A local repository is the
/// only source; remote tag discovery and admission are separate operations.
pub fn prepare_local_source_archive_one_use(
    state: &Path,
    job_id: &str,
    repository: &Path,
    source_sha: &str,
) -> Result<Value, LocalSourcePrepareError> {
    if !is_git_sha(source_sha)
        || job_id.len() != 16
        || !job_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !repository.is_absolute()
        || repository.canonicalize().ok().as_deref() != Some(repository)
        || !repository.is_dir()
        || repository.to_str().is_none()
    {
        return Err(LocalSourcePrepareError::InvalidInput);
    }
    let owner = geteuid().as_raw();
    let root = state_root(state, owner).map_err(|_| LocalSourcePrepareError::UnsafeState)?;
    let private = directory(&root, "private", owner, false)?;
    let builds = directory(&private, "local-builds", owner, false)?;
    let job = directory(&builds, job_id, owner, true)?;
    let job_path = state.join("private/local-builds").join(job_id);
    let stable = || {
        let current = state_root(&job_path, owner).map_err(|_| LocalSourcePrepareError::Changed)?;
        let before = rustix::fs::fstat(&job).map_err(|_| LocalSourcePrepareError::Io)?;
        let now = rustix::fs::fstat(&current).map_err(|_| LocalSourcePrepareError::Io)?;
        if before.st_dev != now.st_dev
            || before.st_ino != now.st_ino
            || before.st_mode != now.st_mode
        {
            return Err(LocalSourcePrepareError::Changed);
        }
        Ok(())
    };
    stable()?;
    let bare = job_path.join("repository.git");
    git(
        &bare,
        &[
            "init",
            "--bare",
            "--template=",
            bare.to_str().ok_or(LocalSourcePrepareError::InvalidInput)?,
        ],
    )?;
    stable()?;
    let source_ref = format!("refs/heads/local-{source_sha}");
    let refspec = format!("{source_sha}:{source_ref}");
    git(
        &bare,
        &[
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            "--depth=1",
            repository
                .to_str()
                .ok_or(LocalSourcePrepareError::InvalidInput)?,
            &refspec,
        ],
    )?;
    stable()?;
    let resolved = git(&bare, &["rev-parse", &format!("{source_ref}^{{commit}}")])?;
    if resolved != format!("{source_sha}\n").as_bytes() {
        return Err(LocalSourcePrepareError::InvalidGraph);
    }
    git(&bare, &["symbolic-ref", "HEAD", &source_ref])?;
    stable()?;
    let packed = crate::local_source_pack::pack_local_source(&job, owner)?;
    stable()?;
    let graph =
        verify_retained_source_archive_commit(state, job_id, &packed.0, source_sha, &source_ref)
            .map_err(|_| LocalSourcePrepareError::InvalidGraph)?;
    stable()?;
    let report = json!({
        "schema":"hol-gauntlet-local-source-preparation.v1", "job_id":job_id,
        "source_sha":source_sha, "source_ref":source_ref,
        "source_archive_sha256":graph.archive().archive_sha256,
        "source_bytes":graph.archive().compressed_bytes,
        "archive_entries":graph.archive().entries,
        "git_graph_verified":true,"candidate_executed":false,
        "execution_eligible":false,"model_requests":0,
    });
    let bytes = gauntlet_contracts::canonicalize(report.to_string().as_bytes())
        .map_err(|_| LocalSourcePrepareError::Io)?;
    let fd = openat(
        &job,
        "source-preparation.v1.json",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| LocalSourcePrepareError::Io)?;
    let mut file = File::from(fd);
    file.write_all(&bytes)
        .map_err(|_| LocalSourcePrepareError::Io)?;
    file.sync_all().map_err(|_| LocalSourcePrepareError::Io)?;
    fsync(&job).map_err(|_| LocalSourcePrepareError::Io)?;
    stable()?;
    Ok(report)
}
