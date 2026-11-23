//! Immutable, caller-pinned configuration for the isolated passive observer.

use crate::lifecycle_document::{hex, TAGS};
use crate::private_jobs::{read_regular_bytes, state_root};
use crate::{load_operations_bytes, HostLifecycleError as Error, HostLifecycleStore};
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, fsync};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

const FILE: &str = "observer-config.json";
const SCHEMA: &str = "hol-gauntlet-rust-observer-config.v1";

#[derive(Debug, Clone)]
pub struct ObserverConfiguration {
    pub(crate) instance_id: String,
    pub(crate) operations: Value,
    pub(crate) vm_probe_sha256: String,
    pub sha256: String,
}

/// Read only an explicitly selected private `config.json`, rejecting duplicate
/// keys before invoking the existing versioned operations loader.
pub fn read_observer_operations(path: &Path) -> Result<Value, Error> {
    if path.file_name().is_none_or(|name| name != "config.json") {
        return Err(Error::InvalidObserverConfig);
    }
    let parent = path.parent().ok_or(Error::InvalidObserverConfig)?;
    let owner = geteuid().as_raw();
    let root = state_root(parent, owner).map_err(|_| Error::InvalidObserverConfig)?;
    let before = fstat(&root).map_err(|_| Error::InvalidObserverConfig)?;
    let bytes = read_regular_bytes(&root, "config.json", owner)
        .map_err(|_| Error::InvalidObserverConfig)?;
    let canonical = canonicalize(&bytes).map_err(|_| Error::InvalidObserverConfig)?;
    let visible = state_root(parent, owner).map_err(|_| Error::InvalidObserverConfig)?;
    let after = fstat(&visible).map_err(|_| Error::InvalidObserverConfig)?;
    if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
        return Err(Error::InvalidObserverConfig);
    }
    load_operations_bytes(&canonical).map_err(|_| Error::InvalidObserverConfig)
}

fn validate_operations(operations: &Value, repository: &Value) -> Result<Value, Error> {
    let merged = load_operations_bytes(operations.to_string().as_bytes())
        .map_err(|_| Error::InvalidObserverConfig)?;
    if merged["repository"] != *repository
        || merged["discovery_mode"] != "release-tags"
        || merged["release_tags"] != json!(TAGS)
        || merged["release_build_backend"] != "local-vm"
        || merged["prepare_argv"] != json!([])
    {
        return Err(Error::InvalidObserverConfig);
    }
    Ok(merged)
}

impl HostLifecycleStore {
    /// Configure this namespace once. An exact repeat is idempotent; a changed
    /// document requires a separate namespace instead of replacing old pins.
    pub fn configure_observer(
        &self,
        operations: &Value,
        vm_probe_sha256: &str,
    ) -> Result<ObserverConfiguration, Error> {
        if !hex(vm_probe_sha256, 64) {
            return Err(Error::InvalidObserverConfig);
        }
        let lock = self.files.lock(false, true)?;
        let (_, checkpoint) = self.read()?;
        let operations = validate_operations(operations, &checkpoint["repository"])?;
        let envelope = json!({"schema":SCHEMA,"instance_id":self.instance,
            "vm_probe_sha256":vm_probe_sha256,"operations":operations});
        let bytes = canonicalize(envelope.to_string().as_bytes())
            .map_err(|_| Error::InvalidObserverConfig)?;
        if bytes.len() > 1024 * 1024 {
            return Err(Error::TooLarge);
        }
        match self.files.read_named(FILE, 1024 * 1024) {
            Ok(existing) if existing == bytes => {}
            Ok(_) => return Err(Error::InvalidObserverConfig),
            Err(Error::UnsafeFile) => {
                let mut file = self.files.create(FILE)?;
                file.write_all(&bytes).map_err(|_| Error::Io)?;
                file.sync_all().map_err(|_| Error::CommitUncertain)?;
                fsync(self.files.directory()?).map_err(|_| Error::CommitUncertain)?;
            }
            Err(error) => return Err(error),
        }
        self.files.check_lock(&lock)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        drop(lock);
        self.read_observer_configuration(&digest)
    }

    pub fn read_observer_configuration(
        &self,
        expected_sha256: &str,
    ) -> Result<ObserverConfiguration, Error> {
        if !hex(expected_sha256, 64) {
            return Err(Error::InvalidObserverConfig);
        }
        let transaction = self.files.lock(false, false)?;
        let bytes = self
            .files
            .read_named(FILE, 1024 * 1024)
            .map_err(|_| Error::InvalidObserverConfig)?;
        if format!("{:x}", Sha256::digest(&bytes)) != expected_sha256
            || canonicalize(&bytes).map_err(|_| Error::InvalidObserverConfig)? != bytes
        {
            return Err(Error::InvalidObserverConfig);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidObserverConfig)?;
        if value.as_object().is_none_or(|o| o.len() != 4)
            || value["schema"] != SCHEMA
            || value["instance_id"] != self.instance
            || !value["vm_probe_sha256"]
                .as_str()
                .is_some_and(|s| hex(s, 64))
        {
            return Err(Error::InvalidObserverConfig);
        }
        let (_, checkpoint) = self.read()?;
        let operations = validate_operations(&value["operations"], &checkpoint["repository"])?;
        if operations != value["operations"] {
            return Err(Error::InvalidObserverConfig);
        }
        self.files.check_lock(&transaction)?;
        Ok(ObserverConfiguration {
            instance_id: self.instance.clone(),
            operations,
            vm_probe_sha256: value["vm_probe_sha256"]
                .as_str()
                .ok_or(Error::InvalidObserverConfig)?
                .to_owned(),
            sha256: expected_sha256.to_owned(),
        })
    }
}
