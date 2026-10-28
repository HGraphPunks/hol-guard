//! A ready-file claim is input to outside kernel observation, never proof.
use crate::{NativeControlRole, Result};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) struct NativeLifecycleSpec {
    pub role: NativeControlRole,
    pub token: String,
    pub code: String,
}
impl NativeLifecycleSpec {
    pub fn new(stage: &Path, role: NativeControlRole) -> Result<Self> {
        let job = stage.parent().ok_or("lifecycle job required")?;
        let id = job
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("lifecycle job ID required")?;
        if !role.lifecycle()
            || !crate::hex(id, 16)
            || stage.file_name().and_then(|n| n.to_str()) != Some("cell")
            || job.parent() != Some(Path::new("/var/lib/hol-gauntlet-rust/native-jobs"))
        {
            return Err("exact owned lifecycle job and role required".into());
        }
        let token = format!("hol-gauntlet-native-detached-{}-{id}", role.as_str());
        let code = include_str!("../../../adapters/native_lifecycle_child_v2.py.txt")
            .replace("HOL_LIFECYCLE_ROLE_JSON", &json!(role.as_str()).to_string())
            .replace("HOL_LIFECYCLE_TOKEN_JSON", &json!(token).to_string());
        Ok(Self { role, token, code })
    }
    pub fn fixture(&self) -> String {
        include_str!("../../../adapters/native_lifecycle_parent_v2.py.txt")
            .replace("HOL_DETACHED_CODE_JSON", &json!(self.code).to_string())
    }
    pub fn argv(&self) -> Vec<String> {
        [
            vec![
                "/usr/bin/python3".into(),
                "-I".into(),
                "-B".into(),
                "-c".into(),
            ],
            vec![self.code.clone()],
        ]
        .concat()
    }
    pub fn ready(&self, raw: &[u8]) -> Result<Value> {
        if raw.is_empty() || raw.len() > 4096 {
            return Err("bounded lifecycle readiness required".into());
        }
        let canonical = gauntlet_contracts::canonicalize(raw).map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
        let pid = value["pid"]
            .as_u64()
            .filter(|n| (2..=u32::MAX as u64).contains(n))
            .ok_or("positive detached namespace PID required")?;
        if value.as_object().is_none_or(|v| v.len() != 6)
            || value["schema"] != "hol-gauntlet-native-detached-ready.v1"
            || value["role"] != self.role.as_str()
            || value["token"] != self.token
            || value["sid"] != pid
            || value["pgrp"] != pid
        {
            return Err("detached ready identity differs from exact job/role/session".into());
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_ready_claim_cannot_borrow_another_job_or_skip_detached_session_creation() {
        let s = NativeLifecycleSpec::new(
            Path::new("/var/lib/hol-gauntlet-rust/native-jobs/0123456789abcdef/cell"),
            NativeControlRole::Cancel,
        )
        .unwrap();
        assert!(s.argv().last().unwrap().contains(&s.token));
        assert!(s.fixture().contains(&json!(s.code).to_string()));
        let ready = json!({"schema":"hol-gauntlet-native-detached-ready.v1","role":"cancel","token":s.token,"pid":17,"sid":17,"pgrp":17});
        s.ready(ready.to_string().as_bytes()).unwrap();
        for (key, bad) in [
            ("token", json!("other-job")),
            ("role", json!("timeout")),
            ("sid", json!(1)),
            ("pid", json!(true)),
        ] {
            let mut v = ready.clone();
            v[key] = bad;
            assert!(s.ready(v.to_string().as_bytes()).is_err());
        }
        assert!(NativeLifecycleSpec::new(
            Path::new("/tmp/0123456789abcdef/cell"),
            NativeControlRole::Cancel
        )
        .is_err());
        assert!(NativeLifecycleSpec::new(
            Path::new("/var/lib/hol-gauntlet-rust/native-jobs/0123456789abcdef/cell"),
            NativeControlRole::Success
        )
        .is_err());
    }
}
