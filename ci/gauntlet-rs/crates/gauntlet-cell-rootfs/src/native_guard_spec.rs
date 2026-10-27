//! Closed outside product pins for the separate Native hook transport profile.
use crate::{hex, Result};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeGuardPins {
    pub source_sha: String,
    pub package_version: String,
    pub native_sha256: String,
    pub bwrap_sha256: String,
}

impl NativeGuardPins {
    pub fn parse(value: &Value) -> Result<Self> {
        let fields = [
            "schema",
            "source_sha",
            "package_version",
            "native_sha256",
            "bwrap_sha256",
        ];
        if value
            .as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
            || value["schema"] != "hol-gauntlet-native-hook-product-pins.v1"
        {
            return Err("closed outside Native hook product pins required".into());
        }
        let text = |key: &str| {
            value[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "typed Native product pin required".to_owned())
        };
        let pins = Self {
            source_sha: text("source_sha")?,
            package_version: text("package_version")?,
            native_sha256: text("native_sha256")?,
            bwrap_sha256: text("bwrap_sha256")?,
        };
        if !hex(&pins.source_sha, 40)
            || !gauntlet_evidence::valid_package_version(&pins.package_version)
            || !hex(&pins.native_sha256, 64)
            || !hex(&pins.bwrap_sha256, 64)
        {
            return Err("exact Native source/version/runtime/backend pins required".into());
        }
        Ok(pins)
    }
    pub fn to_json(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-hook-product-pins.v1","source_sha":self.source_sha,
            "package_version":self.package_version,"native_sha256":self.native_sha256,"bwrap_sha256":self.bwrap_sha256})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn product_pins_cannot_select_programs_paths_policy_or_eligibility() {
        let v = json!({"schema":"hol-gauntlet-native-hook-product-pins.v1","source_sha":"a".repeat(40),
            "package_version":"3.57.0","native_sha256":"b".repeat(64),"bwrap_sha256":"c".repeat(64)});
        assert_eq!(NativeGuardPins::parse(&v).unwrap().to_json(), v);
        for (key, bad) in [
            ("source_sha", json!("main")),
            ("package_version", json!("3.57")),
            ("native_sha256", json!(true)),
            ("bwrap_sha256", json!("latest")),
            ("command", json!("sh")),
            ("approval", json!(true)),
            ("execution_eligible", json!(true)),
        ] {
            let mut changed = v.clone();
            changed[key] = bad;
            assert!(NativeGuardPins::parse(&changed).is_err(), "{key}");
        }
    }
}
