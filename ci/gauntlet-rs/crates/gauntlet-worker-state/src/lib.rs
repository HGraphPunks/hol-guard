//! Inert durable run reservation for a future, separately reviewed Linux worker.
//! A successful reservation consumes a job ID but never launches candidate code.

use gauntlet_contracts::{canonicalize, is_git_sha, WorkerAction, WorkerRequest};
use rustix::fs::{fsync, open, openat, statat, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

const MARKER_SCHEMA: &str = "hol-gauntlet-worker-started.v1";
const MAX_MARKER_BYTES: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedMarker {
    pub source_sha: String,
    pub job_id: String,
    pub deployment_digest: String,
    pub worker_generation: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationError {
    InvalidPins,
    WrongRequest,
    AlreadyStarted,
    InvalidMarker,
    Io(String),
}

impl fmt::Display for ReservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPins => f.write_str("invalid outside worker/deployment pins"),
            Self::WrongRequest => {
                f.write_str("run request differs from outside source/deployment pins")
            }
            Self::AlreadyStarted => f.write_str("job ID was already reserved for execution"),
            Self::InvalidMarker => {
                f.write_str("started marker is malformed or differs from outside pins")
            }
            Self::Io(message) => write!(f, "worker reservation I/O error: {message}"),
        }
    }
}

impl std::error::Error for ReservationError {}

pub struct RunReservationJournal {
    pub(crate) root: OwnedFd,
}

mod projection;
mod terminal;
pub use terminal::{ProcessIdentity, TerminalOutcome, TerminalReceipt};

pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn io(error: impl fmt::Display) -> ReservationError {
    ReservationError::Io(error.to_string())
}

pub(crate) fn marker_name(job_id: &str) -> Result<String, ReservationError> {
    if !hex(job_id, 16) {
        return Err(ReservationError::InvalidPins);
    }
    Ok(format!("{job_id}.started.json"))
}

pub(crate) fn read_bounded_regular(
    root: &OwnedFd,
    name: &str,
    limit: u64,
) -> Result<Option<Vec<u8>>, ReservationError> {
    let descriptor = match openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let mut file = File::from(descriptor);
    let before = file.metadata().map_err(io)?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit {
        return Err(ReservationError::InvalidMarker);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > limit {
        return Err(ReservationError::InvalidMarker);
    }
    let after = file.metadata().map_err(io)?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(ReservationError::InvalidMarker);
    }
    Ok(Some(bytes))
}

fn open_canonical_directory(path: &Path) -> Result<OwnedFd, ReservationError> {
    let literal = path.to_str().ok_or(ReservationError::InvalidPins)?;
    if !path.is_absolute()
        || literal != "/"
            && !literal.strip_prefix('/').is_some_and(|relative| {
                !relative.is_empty()
                    && relative
                        .split('/')
                        .all(|part| !part.is_empty() && part != "." && part != "..")
            })
    {
        return Err(ReservationError::InvalidPins);
    }
    let mut root = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                root = openat(
                    &root,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(io)?;
            }
            _ => return Err(ReservationError::InvalidPins),
        }
    }
    Ok(root)
}

impl RunReservationJournal {
    /// The caller must supply a trusted worker-owned directory. Root ownership,
    /// lease and Linux process identity checks belong to the future worker.
    pub fn open(path: &Path) -> Result<Self, ReservationError> {
        Ok(Self {
            root: open_canonical_directory(path)?,
        })
    }

    /// Persist an immutable, source/deployment/job-bound marker before any
    /// candidate launch. A failed or partial write still consumes the job ID.
    pub fn reserve(
        &self,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<StartedMarker, ReservationError> {
        if !is_git_sha(source_sha) || !hex(worker_generation, 64) || !hex(deployment_digest, 64) {
            return Err(ReservationError::InvalidPins);
        }
        if request.action() != WorkerAction::Run
            || !request.matches_deployment(source_sha, deployment_digest)
        {
            return Err(ReservationError::WrongRequest);
        }
        let name = marker_name(request.job_id())?;
        let terminal_name = format!("{}.terminal.json", request.job_id());
        match statat(
            &self.root,
            terminal_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => return Err(ReservationError::AlreadyStarted),
            Err(Errno::NOENT) => {}
            Err(error) => return Err(io(error)),
        }
        let value = json!({
            "schema": MARKER_SCHEMA,
            "source_sha": source_sha,
            "job_id": request.job_id(),
            "deployment_digest": deployment_digest,
            "worker_generation": worker_generation,
        });
        let bytes = canonicalize(value.to_string().as_bytes())
            .map_err(|_| ReservationError::InvalidMarker)?;
        if bytes.len() as u64 > MAX_MARKER_BYTES {
            return Err(ReservationError::InvalidMarker);
        }
        let descriptor = openat(
            &self.root,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| {
            if error == Errno::EXIST {
                ReservationError::AlreadyStarted
            } else {
                io(error)
            }
        })?;
        let mut file = File::from(descriptor);
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        fsync(&self.root).map_err(io)?;
        Ok(StartedMarker {
            source_sha: source_sha.to_owned(),
            job_id: request.job_id().to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }

    /// Read a marker against outside pins. An invalid marker is never treated
    /// as not-started; the host must surface it as unknown and block replay.
    pub fn started(
        &self,
        job_id: &str,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<Option<StartedMarker>, ReservationError> {
        if !is_git_sha(source_sha) || !hex(deployment_digest, 64) || !hex(worker_generation, 64) {
            return Err(ReservationError::InvalidPins);
        }
        let name = marker_name(job_id)?;
        let Some(bytes) = read_bounded_regular(&self.root, &name, MAX_MARKER_BYTES)? else {
            return Ok(None);
        };
        let canonical = canonicalize(&bytes).map_err(|_| ReservationError::InvalidMarker)?;
        if bytes != canonical {
            return Err(ReservationError::InvalidMarker);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| ReservationError::InvalidMarker)?;
        let fields = value.as_object().ok_or(ReservationError::InvalidMarker)?;
        if fields.len() != 5
            || value["schema"] != MARKER_SCHEMA
            || value["job_id"] != job_id
            || value["source_sha"] != source_sha
            || value["deployment_digest"] != deployment_digest
            || value["worker_generation"] != worker_generation
        {
            return Err(ReservationError::InvalidMarker);
        }
        Ok(Some(StartedMarker {
            source_sha: source_sha.to_owned(),
            job_id: job_id.to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }))
    }
}
