//! Inert, source-pinned legacy scenario inventory. No fixture or product executes.
//!
//! Only the four compiled catalogs are accepted. This is not the general Python
//! catalog loader, a candidate catalog admission API, or a qualification result.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};

const SCHEMA: &str = "hol.guard-gauntlet.scenarios.v1";
const MAX_CATALOG_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyCatalogKind {
    Core,
    ApprovalRetry,
    ConnectorSetup,
    FullTasks,
}

impl LegacyCatalogKind {
    pub const ALL: [Self; 4] = [
        Self::Core,
        Self::ApprovalRetry,
        Self::ConnectorSetup,
        Self::FullTasks,
    ];

    pub fn profile(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::ApprovalRetry => "approval-retry",
            Self::ConnectorSetup => "connector-setup",
            Self::FullTasks => "full-tasks",
        }
    }

    pub fn sha256(self) -> &'static str {
        match self {
            Self::Core => "20b85a784c707e472eb1231d8a3a6f02db8776a8c2b62a48386415a3e6f7ef54",
            Self::ApprovalRetry => {
                "9f27cef5f9312cd6fdd3c4084dbb47f6cc07bc06acc3afc87897c00dbb19d7d7"
            }
            Self::ConnectorSetup => {
                "df96a3ef882dc1c1b8f064cdb9f42b3382cbba350db6abc7c380e689b2a500e6"
            }
            Self::FullTasks => "fd335da0b43599061661ab0e3f4ef2b390cf01039f3473b5d15d550f24d9f6e2",
        }
    }

    fn raw(self) -> &'static [u8] {
        match self {
            Self::Core => include_bytes!("../../../../gauntlet/scenarios.json"),
            Self::ApprovalRetry => include_bytes!("../../../../gauntlet/approval_retry.json"),
            Self::ConnectorSetup => include_bytes!("../../../../gauntlet/connector_setup.json"),
            Self::FullTasks => include_bytes!("../../../../gauntlet/full_tasks.json"),
        }
    }

    fn count(self) -> usize {
        match self {
            Self::Core => 308,
            Self::ApprovalRetry => 16,
            Self::ConnectorSetup => 11,
            Self::FullTasks => 15,
        }
    }
}

impl TryFrom<&str> for LegacyCatalogKind {
    type Error = LegacyCatalogError;

    fn try_from(profile: &str) -> Result<Self, Self::Error> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.profile() == profile)
            .ok_or(LegacyCatalogError::UnsupportedProfile)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyCatalogError {
    UnsupportedProfile,
    SourcePin,
    InvalidCatalog,
}

impl fmt::Display for LegacyCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedProfile => "profile has no supported fixed legacy data catalog",
            Self::SourcePin => "fixed legacy catalog source bytes do not match their pin",
            Self::InvalidCatalog => "invalid fixed legacy catalog",
        })
    }
}
impl std::error::Error for LegacyCatalogError {}

#[derive(Debug)]
pub struct LegacyCatalog {
    kind: LegacyCatalogKind,
    scenarios: Vec<Value>,
}

impl LegacyCatalog {
    pub fn kind(&self) -> LegacyCatalogKind {
        self.kind
    }
    /// All eleven Python row fields, including defaults, in declaration order.
    pub fn scenarios(&self) -> &[Value] {
        &self.scenarios
    }
    /// The legacy list projection, in original declaration order.
    pub fn listing(&self) -> Value {
        json!(self
            .scenarios
            .iter()
            .map(|row| {
                json!({"id":row["id"],"expectation":row["expectation"],"oracle":row["oracle"]})
            })
            .collect::<Vec<_>>())
    }
    pub fn inventory(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-legacy-catalog-inventory.v1",
            "catalog_schema":SCHEMA,
            "profile":self.kind.profile(),
            "catalog_sha256":self.kind.sha256(),
            "scenario_count":self.scenarios.len(),
            "scenarios":self.scenarios,
            "execution_eligible":false,
            "qualification_eligible":false,
        })
    }
}

/// Preserve all reviewed row fields and defaults without exposing a path, source
/// pin, command selector or candidate-supplied catalog as a trusted input.
pub fn fixed_legacy_catalog(kind: LegacyCatalogKind) -> Result<LegacyCatalog, LegacyCatalogError> {
    parse_fixed_catalog(kind, kind.raw())
}

fn parse_fixed_catalog(
    kind: LegacyCatalogKind,
    raw: &[u8],
) -> Result<LegacyCatalog, LegacyCatalogError> {
    if raw.len() > MAX_CATALOG_BYTES || format!("{:x}", Sha256::digest(raw)) != kind.sha256() {
        return Err(LegacyCatalogError::SourcePin);
    }
    let canonical = crate::canonicalize(raw).map_err(|_| LegacyCatalogError::InvalidCatalog)?;
    let data: Value =
        serde_json::from_slice(&canonical).map_err(|_| LegacyCatalogError::InvalidCatalog)?;
    let mut document = data
        .as_object()
        .filter(|object| object.len() == 2 && object.get("schema") == Some(&json!(SCHEMA)))
        .cloned()
        .ok_or(LegacyCatalogError::InvalidCatalog)?;
    let mut scenarios = document
        .remove("scenarios")
        .and_then(|value| value.as_array().cloned())
        .filter(|rows| rows.len() == kind.count())
        .ok_or(LegacyCatalogError::InvalidCatalog)?;
    for row in &mut scenarios {
        normalize_row(row)?;
    }
    let ids: BTreeSet<_> = scenarios.iter().map(|row| row["id"].as_str()).collect();
    if ids.len() != scenarios.len()
        || scenarios
            .iter()
            .any(|row| row["profiles"] != json!([kind.profile()]))
    {
        return Err(LegacyCatalogError::InvalidCatalog);
    }
    Ok(LegacyCatalog { kind, scenarios })
}

fn normalize_row(value: &mut Value) -> Result<(), LegacyCatalogError> {
    let row = value
        .as_object_mut()
        .ok_or(LegacyCatalogError::InvalidCatalog)?;
    for key in ["id", "expectation", "oracle", "prompt"] {
        if row
            .get(key)
            .and_then(Value::as_str)
            .is_none_or(|text| text.is_empty())
        {
            return Err(LegacyCatalogError::InvalidCatalog);
        }
    }
    for key in [
        "commands",
        "required_tools",
        "profiles",
        "benign_exit_commands",
        "decision_paths",
    ] {
        row.entry(key).or_insert_with(|| {
            if key == "profiles" {
                json!(["core"])
            } else {
                json!([])
            }
        });
        if !row[key].as_array().is_some_and(|items| {
            items
                .iter()
                .all(|item| item.as_str().is_some_and(|text| !text.is_empty()))
        }) {
            return Err(LegacyCatalogError::InvalidCatalog);
        }
    }
    let path = row.entry("path").or_insert(Value::Null);
    if !path.is_null() && path.as_str().is_none_or(|text| text.is_empty()) {
        return Err(LegacyCatalogError::InvalidCatalog);
    }
    let contained = row.entry("contained_ok").or_insert(Value::Bool(false));
    if !contained.is_boolean() || row.len() != 11 {
        return Err(LegacyCatalogError::InvalidCatalog);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_fields_and_defaults_match_frozen_python_v1_vectors() {
        // SHA-256 of canonical JSON over dataclasses.asdict(load_catalog(...)):
        // the Python source is 1acb014b980db01f026b71655474e353f277bc0e7ea316704a5c150a74ef869c.
        let vectors = [
            (
                LegacyCatalogKind::Core,
                308,
                "275d2e2cb1656e8391749b35e35714cfc57e6251ef1775122a5bd070c8111458",
            ),
            (
                LegacyCatalogKind::ApprovalRetry,
                16,
                "5cac33fa1e5b1319373dffee43071a1e606c042b07c573e073060a0b40973449",
            ),
            (
                LegacyCatalogKind::ConnectorSetup,
                11,
                "32062e20f396c7edbb46e74efa5301db87ec51b8f8bfc8af0f66337a0f5eb156",
            ),
            (
                LegacyCatalogKind::FullTasks,
                15,
                "6498c1e9fb6ef5d9bf33b553ba62573b9181dfbcb3de47c8887e0b24be3f4827",
            ),
        ];
        for (kind, count, digest) in vectors {
            let catalog = fixed_legacy_catalog(kind).unwrap();
            assert_eq!(catalog.scenarios().len(), count);
            let raw = serde_json::to_vec(catalog.scenarios()).unwrap();
            assert_eq!(crate::canonical_sha256(&raw).unwrap(), digest);
            let inventory = catalog.inventory();
            assert_eq!(inventory["execution_eligible"], false);
            assert_eq!(inventory["qualification_eligible"], false);
            assert_eq!(inventory["profile"], kind.profile());
        }
    }

    #[test]
    fn changed_or_wrong_catalog_bytes_never_acquire_the_fixed_identity() {
        let kind = LegacyCatalogKind::Core;
        let mut changed = kind.raw().to_vec();
        changed[0] ^= 1;
        for raw in [
            changed,
            LegacyCatalogKind::ConnectorSetup.raw().to_vec(),
            vec![b' '; MAX_CATALOG_BYTES + 1],
        ] {
            assert_eq!(
                parse_fixed_catalog(kind, &raw).unwrap_err(),
                LegacyCatalogError::SourcePin
            );
        }
    }

    #[test]
    fn unknown_or_execution_only_profiles_do_not_default_to_core() {
        for kind in LegacyCatalogKind::ALL {
            assert_eq!(LegacyCatalogKind::try_from(kind.profile()).unwrap(), kind);
        }
        for profile in ["", "CORE", "contained-bun-vitest", "beta-e2e"] {
            assert_eq!(
                LegacyCatalogKind::try_from(profile),
                Err(LegacyCatalogError::UnsupportedProfile)
            );
        }
    }
}
