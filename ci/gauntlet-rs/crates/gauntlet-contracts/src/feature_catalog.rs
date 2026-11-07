//! Frozen product-test selection. Callers cannot replace or narrow its groups.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const FEATURE_CATALOG_SHA256: &str =
    "1955516522cccd5235c565498a7e28c8871e31361609d52f0bdebb6e0b91677f";
const RAW: &[u8] = include_bytes!("../../../feature-catalog.v1.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureCatalogError;
impl fmt::Display for FeatureCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed source-bound feature catalog required")
    }
}
impl std::error::Error for FeatureCatalogError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureGroup {
    id: String,
    label: String,
    tests: Vec<String>,
    source_native: bool,
}
impl FeatureGroup {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn tests(&self) -> &[String] {
        &self.tests
    }
    pub fn source_native(&self) -> bool {
        self.source_native
    }
    pub fn evidence_kind(&self) -> &'static str {
        if self.source_native {
            "source-native-contract"
        } else {
            "installed-product-contract"
        }
    }
    pub fn to_json(&self) -> Value {
        json!({"id":self.id,"label":self.label,"tests":self.tests,"evidence_kind":self.evidence_kind()})
    }
    /// The fixed pytest adapter argv, without shell interpolation or a caller
    /// command selector. The owner supplies only the current catalog group.
    pub fn pytest_argv(&self) -> Vec<String> {
        let mut argv = [
            "run",
            "--no-sync",
            "python",
            "-B",
            "-m",
            "pytest",
            "-q",
            "-o",
            "addopts=",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        argv.push(format!("--junitxml=/output/{}.xml", self.id));
        argv.extend(self.tests.iter().cloned());
        argv
    }
}

/// Preserve all 28 Python groups, their labels, 52 selectors and source versus
/// installed contexts. This inventory is not execution or a feature verdict.
pub fn fixed_feature_catalog() -> Result<Vec<FeatureGroup>, FeatureCatalogError> {
    if format!("{:x}", Sha256::digest(RAW)) != FEATURE_CATALOG_SHA256 {
        return Err(FeatureCatalogError);
    }
    let value: Value = serde_json::from_slice(RAW).map_err(|_| FeatureCatalogError)?;
    let rows = value["groups"].as_array().ok_or(FeatureCatalogError)?;
    let mut result = Vec::new();
    for row in rows {
        let text = |key: &str| {
            row[key]
                .as_str()
                .map(str::to_owned)
                .ok_or(FeatureCatalogError)
        };
        let tests = row["tests"]
            .as_array()
            .ok_or(FeatureCatalogError)?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or(FeatureCatalogError))
            .collect::<Result<Vec<_>, _>>()?;
        result.push(FeatureGroup {
            id: text("id")?,
            label: text("label")?,
            tests,
            source_native: match text("evidence_kind")?.as_str() {
                "source-native-contract" => true,
                "installed-product-contract" => false,
                _ => return Err(FeatureCatalogError),
            },
        });
    }
    Ok(result)
}

/// The Python audit completes source imports before reinstalling the wheel.
/// Preserve that mutually exclusive context transition and declaration order.
pub fn fixed_feature_schedule() -> Result<Vec<FeatureGroup>, FeatureCatalogError> {
    let groups = fixed_feature_catalog()?;
    Ok(groups
        .iter()
        .filter(|g| g.source_native)
        .cloned()
        .chain(groups.iter().filter(|g| !g.source_native).cloned())
        .collect())
}
