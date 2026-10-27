//! Closed data-only declaration for the fixed public SDK bootstrap input.
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSdkAssetPins {
    pub source_archive_sha256: String,
    pub source_sdk_tree_sha256: String,
    pub sdk_tree_sha256: String,
    pub bun_sha256: String,
    pub sdk_entries: u64,
    pub sdk_bytes: u64,
    pub bun_bytes: u64,
}

impl NativeSdkAssetPins {
    pub fn parse(raw: &[u8], outside: &str) -> Result<Self, String> {
        if raw.len() > 8192
            || !crate::hex(outside, 64)
            || format!("{:x}", Sha256::digest(raw)) != outside
        {
            return Err("SDK source declaration differs from outside hash".into());
        }
        let raw = canonicalize(raw).map_err(|_| "ambiguous SDK source declaration")?;
        let v: Value = serde_json::from_slice(&raw).map_err(|_| "SDK source declaration JSON")?;
        let fields = [
            "schema",
            "source_archive_sha256",
            "source_sdk_tree_sha256",
            "sdk_tree_sha256",
            "bun_sha256",
            "sdk_entries",
            "sdk_bytes",
            "bun_bytes",
        ];
        if v.as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
            || v["schema"] != "hol-gauntlet-native-sdk-source.v1"
        {
            return Err("closed SDK source declaration required".into());
        }
        let pin = |key: &str| {
            v[key]
                .as_str()
                .filter(|s| crate::hex(s, 64))
                .map(str::to_owned)
                .ok_or("exact SDK file/tree/archive digest required")
        };
        let integer = |key: &str, max: u64| {
            v[key]
                .as_u64()
                .filter(|n| *n > 0 && *n <= max)
                .ok_or("bounded SDK entry/byte count required")
        };
        Ok(Self {
            source_archive_sha256: pin("source_archive_sha256")?,
            source_sdk_tree_sha256: pin("source_sdk_tree_sha256")?,
            sdk_tree_sha256: pin("sdk_tree_sha256")?,
            bun_sha256: pin("bun_sha256")?,
            sdk_entries: integer("sdk_entries", 100000)?,
            sdk_bytes: integer("sdk_bytes", 2 * 1024 * 1024 * 1024)?,
            bun_bytes: integer("bun_bytes", 256 * 1024 * 1024)?,
        })
    }
    pub fn directory(&self) -> PathBuf {
        PathBuf::from("/opt/hol-gauntlet/sdk-assets")
            .join(format!("{}-{}", self.sdk_tree_sha256, self.bun_sha256))
    }
    pub fn to_json(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-source.v1","source_archive_sha256":self.source_archive_sha256,
            "source_sdk_tree_sha256":self.source_sdk_tree_sha256,"sdk_tree_sha256":self.sdk_tree_sha256,
            "bun_sha256":self.bun_sha256,"sdk_entries":self.sdk_entries,"sdk_bytes":self.sdk_bytes,"bun_bytes":self.bun_bytes})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_sdk_paths_require_closed_outside_pins_before_filesystem_work() {
        let pins = NativeSdkAssetPins {
            source_archive_sha256: "a".repeat(64),
            source_sdk_tree_sha256: "b".repeat(64),
            sdk_tree_sha256: "c".repeat(64),
            bun_sha256: "d".repeat(64),
            sdk_entries: 1,
            sdk_bytes: 1,
            bun_bytes: 64,
        };
        let value = pins.to_json();
        let raw = value.to_string();
        let pin = format!("{:x}", Sha256::digest(raw.as_bytes()));
        assert_eq!(
            NativeSdkAssetPins::parse(raw.as_bytes(), &pin).unwrap(),
            pins
        );
        assert_eq!(
            pins.directory(),
            PathBuf::from("/opt/hol-gauntlet/sdk-assets").join(format!(
                "{}-{}",
                "c".repeat(64),
                "d".repeat(64)
            ))
        );
        let mut next_bun = pins.clone();
        next_bun.bun_sha256 = "e".repeat(64);
        assert_ne!(pins.directory(), next_bun.directory());
        assert!(NativeSdkAssetPins::parse(raw.as_bytes(), &"0".repeat(64)).is_err());
        for (key, bad) in [
            ("sdk_entries", json!(true)),
            ("sdk_bytes", json!(2147483649_u64)),
            ("bun_bytes", json!(0)),
            ("sdk_tree_sha256", json!("../root")),
            ("command", json!("/bin/sh")),
            ("execution_eligible", json!(true)),
            ("schema", json!("other")),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            let raw = changed.to_string();
            let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
            assert!(NativeSdkAssetPins::parse(raw.as_bytes(), &digest).is_err());
        }
    }
}
