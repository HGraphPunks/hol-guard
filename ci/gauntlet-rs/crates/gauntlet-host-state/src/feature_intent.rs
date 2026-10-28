//! Host feature intents and one-use dispatch. An uncertain transport consumes
//! the attempt; restart reads/recovery use retained guest state, never a retry.
use crate::fixed_process::run_fixed_intent;
use crate::private_jobs::{read_regular_bytes, state_root};
use gauntlet_contracts::{
    canonicalize, verify_feature_run_result, FeatureRunIntent, FeatureRunPins,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{fchmod, fstat, fsync, openat, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct FeatureIntentJournal {
    root: OwnedFd,
    path: PathBuf,
    owner: u32,
}
impl FeatureIntentJournal {
    pub fn open(path: &Path) -> Result<Self, String> {
        let owner = geteuid().as_raw();
        Ok(Self {
            root: state_root(path, owner).map_err(|e| e.to_string())?,
            path: path.to_owned(),
            owner,
        })
    }
    fn stable(&self) -> Result<(), String> {
        let visible = state_root(&self.path, self.owner).map_err(|e| e.to_string())?;
        let a = fstat(&self.root).map_err(|e| e.to_string())?;
        let b = fstat(&visible).map_err(|e| e.to_string())?;
        if (a.st_dev, a.st_ino, a.st_uid, a.st_mode) != (b.st_dev, b.st_ino, b.st_uid, b.st_mode) {
            return Err("feature host journal replaced".into());
        }
        Ok(())
    }
    fn name(audit: &str, suffix: &str) -> Result<String, String> {
        if audit.len() != 16
            || !audit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !matches!(suffix, "intent" | "dispatch" | "result")
        {
            return Err("fixed feature audit journal name required".into());
        }
        Ok(format!("{audit}.feature-{suffix}.json"))
    }
    fn write(&self, name: &str, raw: &[u8]) -> Result<(), String> {
        self.stable()?;
        let fd = openat(
            &self.root,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| "feature host record already consumed or unavailable")?;
        fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
        let mut file = File::from(fd);
        file.write_all(raw)
            .and_then(|_| file.sync_all())
            .map_err(|_| "feature host commit uncertain")?;
        fsync(&self.root).map_err(|_| "feature host directory commit uncertain")?;
        if read_regular_bytes(&self.root, name, self.owner).map_err(|e| e.to_string())? != raw {
            return Err("feature host record differs after commit".into());
        }
        self.stable()
    }
    pub fn read(&self, audit: &str) -> Result<FeatureRunIntent, String> {
        self.stable()?;
        let raw = read_regular_bytes(&self.root, &Self::name(audit, "intent")?, self.owner)
            .map_err(|e| e.to_string())?;
        let intent = FeatureRunIntent::parse(&raw)?;
        if intent.pins().audit_id() != audit {
            return Err("feature host intent audit differs".into());
        }
        self.stable()?;
        Ok(intent)
    }
    pub fn record(
        &self,
        pins: FeatureRunPins,
        operations: &Value,
    ) -> Result<FeatureRunIntent, String> {
        let operations = crate::load_operations_bytes(operations.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        if operations["release_build_backend"] != "local-vm"
            || operations["build_memory_gib"] != 12
            || operations["vm_memory_gib"].as_u64().is_none_or(|n| n < 16)
            || operations["vm_cpus"].as_u64().is_none_or(|n| n < 2)
        {
            return Err("fixed feature VM capacity required".into());
        }
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "feature host nonce unavailable")?;
        let nonce = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let intent = FeatureRunIntent::new(
            pins,
            operations["limactl"]
                .as_str()
                .ok_or("feature transport missing")?,
            operations["vm"].as_str().ok_or("feature VM missing")?,
            &nonce,
        )?;
        self.write(
            &Self::name(intent.pins().audit_id(), "intent")?,
            &intent.bytes()?,
        )?;
        if self.read(intent.pins().audit_id())? != intent {
            return Err("feature host intent changed".into());
        }
        Ok(intent)
    }
    fn dispatch(&self, intent: &FeatureRunIntent) -> Result<(), String> {
        if self.read(intent.pins().audit_id())? != *intent {
            return Err("feature host intent changed before dispatch".into());
        }
        let raw = canonicalize(
            json!({"schema":"hol-gauntlet-host-feature-dispatch.v1",
            "audit_id":intent.pins().audit_id(),"intent_sha256":intent.digest()?,
            "retry_allowed":false})
            .to_string()
            .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        self.write(&Self::name(intent.pins().audit_id(), "dispatch")?, &raw)
    }
    pub fn execute_once(&self, intent: &FeatureRunIntent) -> Result<Value, String> {
        self.dispatch(intent)?;
        let generation = intent.pins().text("runner_binary_sha256");
        let argv = vec![
            intent.limactl().into(),
            "shell".into(),
            intent.vm().into(),
            "--".into(),
            "sudo".into(),
            "-n".into(),
            format!("/opt/hol-gauntlet/rust-feature-worker-{generation}"),
            "--run".into(),
            intent.digest()?,
            intent.bytes()?.len().to_string(),
            generation.into(),
        ];
        let raw = run_fixed_intent(
            &argv,
            &intent.bytes()?,
            Duration::from_secs(14700),
            16384,
            8192,
        )
        .map_err(|e| format!("feature VM execution uncertain; reconcile without retry: {e:?}"))?;
        let frame = raw
            .strip_suffix(b"\n")
            .ok_or("canonical feature response line required")?;
        if canonicalize(frame).map_err(|e| e.to_string())? != frame {
            return Err("ambiguous feature response".into());
        }
        let value: Value = serde_json::from_slice(frame).map_err(|e| e.to_string())?;
        verify_feature_run_result(intent, &value)?;
        if self.read(intent.pins().audit_id())? != *intent {
            return Err("feature host intent changed during execution".into());
        }
        self.write(&Self::name(intent.pins().audit_id(), "result")?, frame)?;
        Ok(value)
    }
}
pub fn read_feature_run_pins(path: &Path) -> Result<FeatureRunPins, String> {
    let parent = path
        .parent()
        .ok_or("private feature pins parent required")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("feature pins filename required")?;
    let owner = geteuid().as_raw();
    let root = state_root(parent, owner).map_err(|e| e.to_string())?;
    FeatureRunPins::parse(&read_regular_bytes(&root, name, owner).map_err(|e| e.to_string())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn pins(id: &str) -> FeatureRunPins {
        let spec = json!({"schema":"hol-gauntlet-feature-executor.v1","audit_id":id,
            "source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
            "candidate_archive_sha256":"c".repeat(64),"wheel_sha256":"d".repeat(64),
            "native_sha256":"e".repeat(64),"executor_sha256":"f".repeat(64),"version":"3.58.0",
            "catalog_sha256":gauntlet_contracts::FEATURE_CATALOG_SHA256,
            "node_sha256":gauntlet_contracts::FEATURE_NODE_SHA256});
        let mut p = json!({"executor_spec":spec,"build_job_id":"0123456789abcdee",
            "controller_root":"/opt/hol-gauntlet/controller-0123456789abcdee",
            "builder_image_id":format!("sha256:{}","a".repeat(64))});
        for k in [
            "build_result_sha256",
            "controller_tree_sha256",
            "uv_base_image_id",
            "rust_base_image_id",
            "policy_sha256",
            "podman_sha256",
            "slirp4netns_sha256",
            "apparmor_parser_sha256",
            "seccomp_sha256",
            "runner_binary_sha256",
        ] {
            p[k] = json!("b".repeat(64));
        }
        FeatureRunPins::from_value(p).unwrap()
    }
    #[test]
    fn private_feature_intent_survives_restart_and_consumed_ids_preserve_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ops = crate::public_vm_operations(Some("owned-vm")).unwrap();
        let journal = FeatureIntentJournal::open(&path).unwrap();
        let intent = journal.record(pins("0123456789abcdef"), &ops).unwrap();
        assert_eq!(
            FeatureIntentJournal::open(&path)
                .unwrap()
                .read("0123456789abcdef")
                .unwrap(),
            intent
        );
        let original = std::fs::read(path.join("0123456789abcdef.feature-intent.json")).unwrap();
        assert!(journal.record(pins("0123456789abcdef"), &ops).is_err());
        journal.dispatch(&intent).unwrap();
        let restarted = FeatureIntentJournal::open(&path).unwrap();
        assert!(restarted.dispatch(&intent).is_err());
        assert_eq!(
            std::fs::read(path.join("0123456789abcdef.feature-intent.json")).unwrap(),
            original
        );
    }
    #[test]
    fn transport_failure_leaves_consumed_dispatch_and_never_implicitly_retries() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let transport = path.join("limactl");
        std::fs::write(&transport, b"#!/bin/sh\ncat >/dev/null\nexit 2\n").unwrap();
        std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut ops = crate::public_vm_operations(Some("owned-vm")).unwrap();
        ops["limactl"] = json!(transport.to_str().unwrap());
        let journal = FeatureIntentJournal::open(&path).unwrap();
        let intent = journal.record(pins("0123456789abcdef"), &ops).unwrap();
        assert!(journal
            .execute_once(&intent)
            .unwrap_err()
            .contains("uncertain"));
        let dispatch = path.join("0123456789abcdef.feature-dispatch.json");
        let original = std::fs::read(&dispatch).unwrap();
        assert!(FeatureIntentJournal::open(&path)
            .unwrap()
            .execute_once(&intent)
            .unwrap_err()
            .contains("consumed"));
        assert_eq!(std::fs::read(dispatch).unwrap(), original);
    }
    #[test]
    fn linked_or_changed_host_state_blocks_before_any_dispatch() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = FeatureIntentJournal::open(&path).unwrap();
        let outside = path.join("outside");
        std::fs::write(&outside, b"retained").unwrap();
        symlink(&outside, path.join("0123456789abcdef.feature-intent.json")).unwrap();
        assert!(journal.read("0123456789abcdef").is_err());
        let ops = crate::public_vm_operations(None).unwrap();
        assert!(journal.record(pins("0123456789abcdef"), &ops).is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"retained");
        let wrong = json!({"build_memory_gib":1});
        assert!(journal.record(pins("1123456789abcdef"), &wrong).is_err());
    }
}
