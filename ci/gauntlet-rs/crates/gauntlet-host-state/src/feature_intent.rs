//! Host feature intents and one-use dispatch. An uncertain transport consumes
//! the attempt; restart reads/recovery use retained guest state, never a retry.
use crate::fixed_process::{run_fixed, run_fixed_intent};
use crate::private_jobs::{read_regular_bytes, state_root};
use gauntlet_contracts::{
    canonicalize, verify_feature_repair_result, verify_feature_run_result, FeatureRunIntent,
    FeatureRunPins,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{fchmod, fstat, fsync, openat, statat, AtFlags, Mode, OFlags};
use rustix::io::Errno;
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
            || !matches!(suffix, "intent" | "dispatch" | "result" | "repair")
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
    fn dispatch_bytes(intent: &FeatureRunIntent) -> Result<Vec<u8>, String> {
        canonicalize(
            json!({"schema":"hol-gauntlet-host-feature-dispatch.v1",
            "audit_id":intent.pins().audit_id(),"intent_sha256":intent.digest()?,
            "retry_allowed":false})
            .to_string()
            .as_bytes(),
        )
        .map_err(|e| e.to_string())
    }
    fn require_dispatch(&self, intent: &FeatureRunIntent) -> Result<(), String> {
        if self.read(intent.pins().audit_id())? != *intent {
            return Err("feature host intent changed after dispatch".into());
        }
        let raw = read_regular_bytes(
            &self.root,
            &Self::name(intent.pins().audit_id(), "dispatch")?,
            self.owner,
        )
        .map_err(|e| e.to_string())?;
        if raw != Self::dispatch_bytes(intent)? {
            return Err("feature host dispatch differs from intent".into());
        }
        self.stable()
    }
    fn dispatch(&self, intent: &FeatureRunIntent) -> Result<(), String> {
        if self.read(intent.pins().audit_id())? != *intent {
            return Err("feature host intent changed before dispatch".into());
        }
        self.write(
            &Self::name(intent.pins().audit_id(), "dispatch")?,
            &Self::dispatch_bytes(intent)?,
        )
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
        let (frame, value) = Self::response(&raw)?;
        verify_feature_run_result(intent, &value)?;
        self.require_dispatch(intent)?;
        self.write(&Self::name(intent.pins().audit_id(), "result")?, frame)?;
        Ok(value)
    }
    fn response(raw: &[u8]) -> Result<(&[u8], Value), String> {
        let frame = raw
            .strip_suffix(b"\n")
            .ok_or("canonical feature response line required")?;
        if canonicalize(frame).map_err(|e| e.to_string())? != frame {
            return Err("ambiguous feature response".into());
        }
        let value: Value = serde_json::from_slice(frame).map_err(|e| e.to_string())?;
        Ok((frame, value))
    }
    fn retain(&self, name: &str, raw: &[u8]) -> Result<(), String> {
        self.stable()?;
        match statat(&self.root, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => self.write(name, raw),
            Err(e) => Err(e.to_string()),
            Ok(_) => {
                if read_regular_bytes(&self.root, name, self.owner).map_err(|e| e.to_string())?
                    != raw
                {
                    return Err("retained feature host record differs".into());
                }
                self.stable()
            }
        }
    }
    fn repair_bytes(intent: &FeatureRunIntent, generation: &str) -> Result<Vec<u8>, String> {
        if generation.len() != 64
            || !generation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("exact outside feature repair executable digest required".into());
        }
        canonicalize(
            json!({"schema":"hol-gauntlet-host-feature-repair-intent.v1",
            "audit_id":intent.pins().audit_id(),"intent_sha256":intent.digest()?,
            "repair_generation":generation})
            .to_string()
            .as_bytes(),
        )
        .map_err(|e| e.to_string())
    }
    fn repair_generation(&self, intent: &FeatureRunIntent) -> Result<Option<String>, String> {
        let name = Self::name(intent.pins().audit_id(), "repair")?;
        match statat(&self.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.to_string()),
            Ok(_) => {}
        }
        let raw = read_regular_bytes(&self.root, &name, self.owner).map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let generation = value["repair_generation"]
            .as_str()
            .ok_or("feature repair pin missing")?;
        if raw != Self::repair_bytes(intent, generation)? {
            return Err("retained feature repair authorization differs".into());
        }
        Ok(Some(generation.into()))
    }
    /// Reopen a completed or explicitly repaired guest result. This never
    /// resends the run intent or grants artifact/qualification admission.
    pub fn read_retained(&self, intent: &FeatureRunIntent) -> Result<Value, String> {
        self.reconcile(intent, false)
    }
    /// Pin cleanup authorization before contacting the guest. Repeated repair
    /// can only reconcile that same generation; the workload remains consumed.
    pub fn repair(&self, intent: &FeatureRunIntent, generation: &str) -> Result<Value, String> {
        self.require_dispatch(intent)?;
        let name = Self::name(intent.pins().audit_id(), "result")?;
        match statat(&self.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => {}
            Err(e) => return Err(e.to_string()),
            Ok(_) => {
                let raw =
                    read_regular_bytes(&self.root, &name, self.owner).map_err(|e| e.to_string())?;
                let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
                verify_feature_repair_result(intent, &value, generation)?;
            }
        }
        self.retain(
            &Self::name(intent.pins().audit_id(), "repair")?,
            &Self::repair_bytes(intent, generation)?,
        )?;
        self.reconcile(intent, true)
    }
    fn reconcile(&self, intent: &FeatureRunIntent, repair: bool) -> Result<Value, String> {
        self.require_dispatch(intent)?;
        let authorized = self.repair_generation(intent)?;
        let generation = authorized
            .as_deref()
            .unwrap_or(intent.pins().text("runner_binary_sha256"));
        let argv = vec![
            intent.limactl().into(),
            "shell".into(),
            intent.vm().into(),
            "--".into(),
            "sudo".into(),
            "-n".into(),
            format!("/opt/hol-gauntlet/rust-feature-worker-{generation}"),
            if repair { "--repair" } else { "--read" }.into(),
            intent.pins().audit_id().into(),
            intent.digest()?,
            generation.into(),
        ];
        let raw = run_fixed(&argv, Duration::from_secs(90), 16384, 8192, &[]).map_err(|e| {
            format!("feature VM reconciliation unavailable; workload cannot retry: {e:?}")
        })?;
        let (frame, value) = Self::response(&raw)?;
        if value["schema"] == "hol-gauntlet-native-feature-repair.v1" {
            verify_feature_repair_result(
                intent,
                &value,
                authorized
                    .as_deref()
                    .ok_or("feature repair was not authorized")?,
            )?;
        } else if repair {
            return Err("repair cannot replace a completed feature result; use read".into());
        } else {
            verify_feature_run_result(intent, &value)?;
        }
        self.require_dispatch(intent)?;
        if self.repair_generation(intent)? != authorized {
            return Err("feature repair authorization changed during reconciliation".into());
        }
        self.retain(&Self::name(intent.pins().audit_id(), "result")?, frame)?;
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
#[path = "feature_intent_tests.rs"]
mod tests;
