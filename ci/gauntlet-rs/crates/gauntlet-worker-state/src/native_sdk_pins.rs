//! Closed SDK transport inputs. Paths and agent commands are derived by Rust.
use serde_json::{json, Value};
use std::path::PathBuf;
pub const NATIVE_SDK_AGENT_IMAGE: &str =
    "sha256:827eaec482942aa5805beac1a75afd755b0daebade43024883b7d1637c27e52d";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSdkPins {
    pub sdk_tree_sha256: String,
    pub bun_sha256: String,
    pub publication_sha256: String,
}
impl NativeSdkPins {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let fields = [
            "schema",
            "sdk_tree_sha256",
            "bun_sha256",
            "publication_sha256",
            "agent_image_id",
        ];
        if value
            .as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
            || value["schema"] != "hol-gauntlet-native-sdk-pins.v1"
            || value["agent_image_id"] != NATIVE_SDK_AGENT_IMAGE
        {
            return Err("closed fixed SDK transport pins required".into());
        }
        let pin = |key: &str| {
            value[key]
                .as_str()
                .filter(|s| crate::hex(s, 64))
                .map(str::to_owned)
                .ok_or("exact outside SDK/Bun/publication pin required")
        };
        Ok(Self {
            sdk_tree_sha256: pin("sdk_tree_sha256")?,
            bun_sha256: pin("bun_sha256")?,
            publication_sha256: pin("publication_sha256")?,
        })
    }
    pub fn directory(&self) -> PathBuf {
        PathBuf::from("/opt/hol-gauntlet/sdk-assets")
            .join(format!("{}-{}", self.sdk_tree_sha256, self.bun_sha256))
    }
    pub fn to_json(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-pins.v1","sdk_tree_sha256":self.sdk_tree_sha256,
            "bun_sha256":self.bun_sha256,"publication_sha256":self.publication_sha256,"agent_image_id":NATIVE_SDK_AGENT_IMAGE})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_paths_and_fixed_agent_image_cannot_be_selected_by_commands_or_claims() {
        let pins = NativeSdkPins {
            sdk_tree_sha256: "a".repeat(64),
            bun_sha256: "b".repeat(64),
            publication_sha256: "c".repeat(64),
        };
        assert_eq!(NativeSdkPins::parse(&pins.to_json()).unwrap(), pins);
        for (key, value) in [
            ("agent_image_id", json!("other")),
            ("sdk_tree_sha256", json!("../root")),
            ("command", json!("/bin/sh")),
            ("directory", json!("/root")),
            ("execution_eligible", json!(true)),
            ("schema", json!("other")),
        ] {
            let mut changed = pins.to_json();
            changed[key] = value;
            assert!(NativeSdkPins::parse(&changed).is_err());
        }
    }
}
