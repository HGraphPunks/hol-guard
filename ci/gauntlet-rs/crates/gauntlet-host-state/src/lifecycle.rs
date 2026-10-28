//! Opt-in, passive Rust host lifecycle. No Python state adoption, VM dispatch,
//! candidate execution, provider use or GitHub status publication occurs here.

use crate::lifecycle_document as document;
use crate::lifecycle_files::{nonce, LifecycleFiles, LifecycleLock};
use serde_json::{json, Value};
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLifecycleError {
    AlreadyInitialized,
    UnsafeDirectory,
    UnsafeFile,
    InvalidState,
    InvalidObserverConfig,
    ObserverStopped,
    DashboardUnavailable,
    InvalidRelease,
    SourceMoved,
    DuplicateJob,
    Busy,
    Changed,
    TooLarge,
    Clock,
    Random,
    CommitUncertain,
    Io,
}

impl fmt::Display for HostLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyInitialized => {
                "Rust host namespace already exists; it was not overwritten"
            }
            Self::UnsafeDirectory => "private, owner-only, non-symlink host state parent required",
            Self::UnsafeFile => "Rust host checkpoint or permanent lock is unsafe or missing",
            Self::InvalidState => "invalid or unsupported Rust host checkpoint",
            Self::InvalidObserverConfig => "observer configuration is absent, changed, unsafe or incompatible with this instance",
            Self::ObserverStopped => "observer stopped while read-only sampling was in progress",
            Self::DashboardUnavailable => "loopback dashboard port or public state is unavailable",
            Self::InvalidRelease => "exact v3.48.0/v3.49.0 release and source identities required",
            Self::SourceMoved => "release tag already has a different source pin; queue unchanged",
            Self::DuplicateJob => "job identity already belongs to another release",
            Self::Busy => "Rust host lifecycle lock is already owned",
            Self::Changed => "Rust host state identity changed during the operation",
            Self::TooLarge => "Rust host checkpoint exceeds its bounds",
            Self::Clock => "host timestamp is absent or moved backwards",
            Self::Random => "host CSPRNG unavailable",
            Self::CommitUncertain => {
                "host checkpoint may be committed; inspect before retrying work"
            }
            Self::Io => "Rust host lifecycle I/O failed",
        })
    }
}

impl std::error::Error for HostLifecycleError {}

pub struct HostLifecycleStore {
    pub(crate) files: LifecycleFiles,
    pub(crate) instance: String,
}

pub struct HostObserverLease<'a> {
    pub(crate) store: &'a HostLifecycleStore,
    lock: LifecycleLock,
    pub(crate) session: String,
}

impl HostLifecycleStore {
    /// Create only the fixed `rust-host-v1` child of an existing private parent.
    /// Existing or interrupted initialization is never overwritten or repaired.
    pub fn initialize(
        parent: &Path,
        repository: &str,
        now_ms: u64,
    ) -> Result<Self, HostLifecycleError> {
        if now_ms == 0 {
            return Err(HostLifecycleError::Clock);
        }
        if !document::repository(repository) {
            return Err(HostLifecycleError::InvalidState);
        }
        let instance = nonce()?;
        let bytes = document::encode(&document::initial(repository, &instance, now_ms))?;
        let files = LifecycleFiles::initialize(parent, &bytes)?;
        Ok(Self { files, instance })
    }

    pub fn open(parent: &Path) -> Result<Self, HostLifecycleError> {
        let files = LifecycleFiles::open(parent)?;
        let lock = files.lock(false, false)?;
        let value = document::parse(&files.read()?)?;
        files.check_lock(&lock)?;
        match files.lock(true, true) {
            Ok(_) | Err(HostLifecycleError::Busy) => {}
            Err(error) => return Err(error),
        }
        let instance = value["instance_id"]
            .as_str()
            .ok_or(HostLifecycleError::InvalidState)?
            .to_owned();
        Ok(Self { files, instance })
    }

    pub(crate) fn read(&self) -> Result<(Vec<u8>, Value), HostLifecycleError> {
        let bytes = self.files.read()?;
        let value = document::parse(&bytes)?;
        if value["instance_id"] != self.instance {
            return Err(HostLifecycleError::Changed);
        }
        Ok((bytes, value))
    }

    fn transact<T>(
        &self,
        now: u64,
        operation: impl FnOnce(&mut Value) -> Result<T, HostLifecycleError>,
    ) -> Result<T, HostLifecycleError> {
        let lock = self.files.lock(false, true)?;
        let (before, mut value) = self.read()?;
        if now == 0
            || now
                < value["updated_at_ms"]
                    .as_u64()
                    .ok_or(HostLifecycleError::InvalidState)?
        {
            return Err(HostLifecycleError::Clock);
        }
        let previous = value.clone();
        let result = operation(&mut value)?;
        if value != previous {
            value["generation"] = json!(value["generation"]
                .as_u64()
                .and_then(|n| n.checked_add(1))
                .ok_or(HostLifecycleError::TooLarge)?);
            value["updated_at_ms"] = json!(now);
            self.files
                .replace(&lock, &before, &document::encode(&value)?)?;
        } else {
            self.files.check_lock(&lock)?;
            if self.files.read()? != before {
                return Err(HostLifecycleError::Changed);
            }
        }
        Ok(result)
    }

    pub fn set_hold(&self, held: bool, now_ms: u64) -> Result<(), HostLifecycleError> {
        self.transact(now_ms, |value| {
            value["held"] = json!(held);
            Ok(())
        })
    }

    /// A durable stop request; never signals a PID or interrupts guest work.
    pub fn request_stop(&self, now_ms: u64) -> Result<(), HostLifecycleError> {
        self.transact(now_ms, |value| {
            value["stop_requested"] = json!(true);
            Ok(())
        })
    }

    /// Record an operator-supplied exact release tuple. Discovery and admission
    /// revalidation are separate; a queue entry grants no execution authority.
    /// The same tag/source returns its original ID, including terminal history.
    pub fn enqueue_release(
        &self,
        id: &str,
        tag: &str,
        source_sha: &str,
        now_ms: u64,
    ) -> Result<String, HostLifecycleError> {
        if !document::hex(id, 16)
            || !document::TAGS.contains(&tag)
            || !gauntlet_contracts::is_git_sha(source_sha)
        {
            return Err(HostLifecycleError::InvalidRelease);
        }
        self.transact(now_ms, |value| {
            let jobs = value["jobs"]
                .as_array_mut()
                .ok_or(HostLifecycleError::InvalidState)?;
            if let Some(job) = jobs.iter().find(|j| j["tag"] == tag) {
                if job["sha"] != source_sha {
                    return Err(HostLifecycleError::SourceMoved);
                }
                return Ok(job["id"]
                    .as_str()
                    .ok_or(HostLifecycleError::InvalidState)?
                    .to_owned());
            }
            if jobs.iter().any(|j| j["id"] == id) {
                return Err(HostLifecycleError::DuplicateJob);
            }
            jobs.push(
                json!({"id":id, "kind":"release", "tag":tag, "sha":source_sha,
                "state":"queued", "created_at_ms":now_ms, "updated_at_ms":now_ms,
                "reason":"Waiting for a qualified Rust worker", "deployment_digest":null}),
            );
            Ok(id.to_owned())
        })
    }

    pub fn start_observer(&self, now_ms: u64) -> Result<HostObserverLease<'_>, HostLifecycleError> {
        let lock = self.files.lock(true, true)?;
        let session = nonce()?;
        self.transact(now_ms, |value| {
            document::recover(value, now_ms);
            value["observer"] = json!({"session":session, "pid":std::process::id(),
                "started_at_ms":now_ms, "updated_at_ms":now_ms});
            value["stop_requested"] = json!(false);
            Ok(())
        })?;
        self.files.check_lock(&lock)?;
        Ok(HostObserverLease {
            store: self,
            lock,
            session,
        })
    }

    /// Coherent bounded metadata only. A held kernel lease and a heartbeat are
    /// reported separately; neither constitutes VM or benchmark readiness.
    pub fn status(&self, now_ms: u64) -> Result<Value, HostLifecycleError> {
        let lock = self.files.lock(false, false)?;
        let (bytes, value) = self.read()?;
        let updated = value["updated_at_ms"]
            .as_u64()
            .ok_or(HostLifecycleError::InvalidState)?;
        if now_ms < updated {
            return Err(HostLifecycleError::Clock);
        }
        let lease_held = match self.files.lock(true, true) {
            Ok(_) => false,
            Err(HostLifecycleError::Busy) => true,
            Err(error) => return Err(error),
        };
        let unknown = value["jobs"]
            .as_array()
            .ok_or(HostLifecycleError::InvalidState)?
            .iter()
            .filter(|j| j["state"] == "unknown")
            .count();
        let orphaned = value["jobs"]
            .as_array()
            .ok_or(HostLifecycleError::InvalidState)?
            .iter()
            .filter(|j| !lease_held && matches!(j["state"].as_str(), Some("preparing" | "running")))
            .count();
        let mut blocked = vec!["Rust worker has not been qualified"];
        if value["held"] == true {
            blocked.push("Operator holds admissions");
        }
        if unknown > 0 {
            blocked.push("Unknown jobs require exact receipt reconciliation");
        }
        if orphaned > 0 {
            blocked.push("Observer stopped with unresolved jobs");
        }
        let heartbeat = value["observer"]["updated_at_ms"].as_u64();
        self.files.check_lock(&lock)?;
        if self.files.read()? != bytes {
            return Err(HostLifecycleError::Changed);
        }
        Ok(
            json!({"schema":"hol-gauntlet-rust-host-status.v1", "instance_id":self.instance,
            "repository":value["repository"], "generation":value["generation"], "mode":"passive",
            "discovery_mode":"release-tags", "release_tags":document::TAGS,
            "admissions_held":value["held"], "stop_requested":value["stop_requested"],
            "observer":{"lease_held":lease_held, "heartbeat_age_ms":heartbeat.map(|at| now_ms-at),
                "status":if lease_held && heartbeat.is_some_and(|at| now_ms-at <= 15_000) {"online"}
                    else if lease_held {"stale"} else {"stopped"}},
            "jobs":value["jobs"], "unknown_jobs":unknown, "orphaned_jobs":orphaned,
            "unresolved_jobs":unknown+orphaned, "admission_reasons":blocked,
            "vm":{"status":"unavailable"}, "gate":{"required":null,"status":"unavailable"},
            "execution_eligible":false, "qualification_eligible":false,
            "production_ci_activated":false, "trust_status":"local-integrity-only"}),
        )
    }
}

impl HostObserverLease<'_> {
    pub(crate) fn verify_current(&self) -> Result<(), HostLifecycleError> {
        self.store.files.check_lock(&self.lock)?;
        let transaction = self.store.files.lock(false, false)?;
        let (_, value) = self.store.read()?;
        if value["observer"]["session"] != self.session {
            return Err(HostLifecycleError::Changed);
        }
        self.store.files.check_lock(&transaction)?;
        Ok(())
    }
    pub fn heartbeat(&self, now_ms: u64) -> Result<bool, HostLifecycleError> {
        self.store.files.check_lock(&self.lock)?;
        self.store.transact(now_ms, |value| {
            if value["observer"]["session"] != self.session {
                return Err(HostLifecycleError::Changed);
            }
            value["observer"]["updated_at_ms"] = json!(now_ms);
            Ok(value["stop_requested"] == true)
        })
    }

    /// Commit a clean local stop, preserving every uncertain job. Dropping a
    /// lease without this method leaves a stale heartbeat for the next start.
    pub fn finish(self, now_ms: u64) -> Result<(), HostLifecycleError> {
        self.store.files.check_lock(&self.lock)?;
        self.store.transact(now_ms, |value| {
            if value["observer"]["session"] != self.session {
                return Err(HostLifecycleError::Changed);
            }
            document::recover(value, now_ms);
            value["observer"] = Value::Null;
            Ok(())
        })
    }
}
