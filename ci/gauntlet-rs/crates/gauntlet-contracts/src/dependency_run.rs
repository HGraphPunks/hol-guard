//! Closed prelaunch dependency intent. A valid record supplies identity, never
//! execution admission or a claim that package installation was trustworthy.
use crate::canonicalize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

pub const DEPENDENCY_INTENT_LIMIT: usize = 8192;
const FIELDS: [&str; 21] = [
    "job_id",
    "source_sha",
    "source_archive_sha256",
    "capsule_sha256",
    "capsule_bytes",
    "pyproject_sha256",
    "uv_lock_sha256",
    "exporter_sha256",
    "capture_worker_sha256",
    "capture_receipt_sha256",
    "controller_root",
    "controller_tree_sha256",
    "uv_base_image_id",
    "rust_base_image_id",
    "builder_image_id",
    "policy_sha256",
    "podman_sha256",
    "slirp4netns_sha256",
    "apparmor_parser_sha256",
    "seccomp_sha256",
    "runner_binary_sha256",
];

fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyRunPins(Value);

impl DependencyRunPins {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > DEPENDENCY_INTENT_LIMIT {
            return Err("bounded dependency run pins required".into());
        }
        let raw = canonicalize(raw).map_err(|e| e.to_string())?;
        Self::from_value(serde_json::from_slice(&raw).map_err(|e| e.to_string())?)
    }

    pub fn from_value(value: Value) -> Result<Self, String> {
        if value.as_object().is_none_or(|o| o.len() != FIELDS.len())
            || FIELDS.iter().any(|k| value.get(k).is_none())
            || !value["capsule_bytes"]
                .as_u64()
                .is_some_and(|n| (1..=32 * 1024 * 1024).contains(&n))
        {
            return Err("closed dependency run identity required".into());
        }
        for field in FIELDS {
            if field == "capsule_bytes" {
                continue;
            }
            let s = value[field]
                .as_str()
                .ok_or("dependency identity string required")?;
            let valid = match field {
                "job_id" => hex(s, 16),
                "source_sha" => hex(s, 40),
                "controller_root" => s
                    .strip_prefix("/opt/hol-gauntlet/controller-")
                    .is_some_and(|s| hex(s, 16)),
                "builder_image_id" => s.strip_prefix("sha256:").is_some_and(|s| hex(s, 64)),
                _ => hex(s, 64),
            };
            if !valid {
                return Err(format!("invalid dependency pin: {field}"));
            }
        }
        Ok(Self(value))
    }

    pub fn text(&self, key: &str) -> &str {
        self.0[key].as_str().unwrap_or("")
    }
    pub fn value(&self) -> &Value {
        &self.0
    }
    pub fn capsule_bytes(&self) -> u64 {
        self.0["capsule_bytes"].as_u64().unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyRunIntent {
    pub pins: DependencyRunPins,
    pub limactl: String,
    pub vm: String,
    pub nonce: String,
}

impl DependencyRunIntent {
    pub fn new(
        pins: DependencyRunPins,
        limactl: &str,
        vm: &str,
        nonce: &str,
    ) -> Result<Self, String> {
        let path = Path::new(limactl);
        if !hex(nonce, 64)
            || !path.is_absolute()
            || path.file_name().is_none_or(|n| n != "limactl")
            || path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
            || vm.is_empty()
            || vm.len() > 64
            || vm.starts_with('-')
            || !vm
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err("exact dependency target and host nonce required".into());
        }
        let result = Self {
            pins,
            limactl: limactl.into(),
            vm: vm.into(),
            nonce: nonce.into(),
        };
        result.bytes()?;
        Ok(result)
    }

    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        let value = json!({"schema":"hol-gauntlet-host-dependency-intent.v1","pins":self.pins.value(),
            "limactl":self.limactl,"vm":self.vm,"host_nonce_hex":self.nonce});
        let raw = canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string())?;
        if raw.len() > DEPENDENCY_INTENT_LIMIT {
            return Err("dependency intent exceeds bound".into());
        }
        Ok(raw)
    }

    pub fn digest(&self) -> Result<String, String> {
        Ok(format!("{:x}", Sha256::digest(self.bytes()?)))
    }

    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.is_empty()
            || raw.len() > DEPENDENCY_INTENT_LIMIT
            || canonicalize(raw).map_err(|e| e.to_string())? != raw
        {
            return Err("bounded canonical dependency intent required".into());
        }
        let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        if v.as_object().is_none_or(|o| o.len() != 5)
            || v["schema"] != "hol-gauntlet-host-dependency-intent.v1"
        {
            return Err("closed dependency intent required".into());
        }
        let text = |k: &str| v[k].as_str().ok_or("dependency intent string missing");
        Self::new(
            DependencyRunPins::from_value(v["pins"].clone())?,
            text("limactl")?,
            text("vm")?,
            text("host_nonce_hex")?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pins() -> Value {
        let mut v = json!({});
        for field in FIELDS {
            v[field] = json!("a".repeat(64));
        }
        v["job_id"] = json!("0123456789abcdef");
        v["source_sha"] = json!("b".repeat(40));
        v["controller_root"] = json!("/opt/hol-gauntlet/controller-0123456789abcdef");
        v["builder_image_id"] = json!(format!("sha256:{}", "a".repeat(64)));
        v["capsule_bytes"] = json!(1234);
        v
    }
    #[test]
    fn intent_roundtrip_binds_every_pin_target_and_nonce() {
        let pins = DependencyRunPins::from_value(pins()).unwrap();
        let intent = DependencyRunIntent::new(
            pins,
            "/opt/homebrew/bin/limactl",
            "owned-vm",
            &"c".repeat(64),
        )
        .unwrap();
        assert_eq!(
            DependencyRunIntent::parse(&intent.bytes().unwrap()).unwrap(),
            intent
        );
        let changed = DependencyRunIntent {
            vm: "other-vm".into(),
            ..intent.clone()
        };
        assert_ne!(changed.digest().unwrap(), intent.digest().unwrap());
        let mut extra: Value = serde_json::from_slice(&intent.bytes().unwrap()).unwrap();
        extra["command"] = json!("anything");
        assert!(
            DependencyRunIntent::parse(&canonicalize(extra.to_string().as_bytes()).unwrap())
                .is_err()
        );
        for (field, wrong) in [
            ("exporter_sha256", json!("f")),
            ("capsule_bytes", json!(0)),
            ("controller_root", json!("/tmp/controller")),
        ] {
            let mut v = self::pins();
            v[field] = wrong;
            assert!(DependencyRunPins::from_value(v).is_err());
        }
        assert!(DependencyRunIntent::parse(br#"{"schema":1,"schema":2}"#).is_err());
    }
}
