//! Explicit v2 private-cell artifacts: a pinned Rust actor replaces the public
//! Python actor/gate modules. Every byte is bound by the outside manifest hash.
use crate::crypto::{is_sha256, sha256};
use crate::{fixed_private_cell_sources, EvidenceError, PrivateCellManifest, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const NATIVE_CELL_ACTOR: &str = "public/gauntlet-product-cell";
const INITIALIZER: &str = "public/initializer";
const INVALID: EvidenceError =
    EvidenceError::Invalid("native cell manifest differs from outside pins or controller source");

pub fn fixed_native_private_cell_sources() -> BTreeMap<String, &'static [u8]> {
    fixed_private_cell_sources()
        .into_iter()
        .filter(|(name, _)| {
            !name.starts_with("public/") || name == "public/product_vm_seccomp_oci_v1.json"
        })
        .collect()
}

pub fn verify_native_private_cell_manifest(
    raw: &[u8],
    expected_manifest_sha256: &str,
    expected_initializer_sha256: &str,
) -> Result<PrivateCellManifest> {
    if raw.len() > 1024 * 1024
        || !is_sha256(expected_manifest_sha256)
        || !is_sha256(expected_initializer_sha256)
        || sha256(raw) != expected_manifest_sha256
    {
        return Err(INVALID);
    }
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    if value.as_object().is_none_or(|o| o.len() != 3)
        || value["schema"] != "product-cell-artifacts.v2"
        || value["runtime"].as_object().is_none_or(|o| o.len() != 2)
        || value["runtime"]["schema"] != "product-cell-native-runtime.v1"
    {
        return Err(INVALID);
    }
    let actor = value["runtime"]["actor_sha256"]
        .as_str()
        .filter(|s| is_sha256(s))
        .ok_or(INVALID)?;
    let declared = value["files"].as_object().ok_or(INVALID)?;
    let fixed = fixed_native_private_cell_sources();
    let required: BTreeSet<_> = fixed
        .keys()
        .map(String::as_str)
        .chain([NATIVE_CELL_ACTOR, INITIALIZER])
        .collect();
    if declared.keys().map(String::as_str).collect::<BTreeSet<_>>() != required {
        return Err(INVALID);
    }
    let mut files = BTreeMap::new();
    for (name, pin) in declared {
        let pin = pin.as_str().filter(|s| is_sha256(s)).ok_or(INVALID)?;
        if fixed.get(name).is_some_and(|raw| sha256(raw) != pin) {
            return Err(INVALID);
        }
        files.insert(name.clone(), pin.to_owned());
    }
    if files.get(INITIALIZER).map(String::as_str) != Some(expected_initializer_sha256)
        || files.get(NATIVE_CELL_ACTOR).map(String::as_str) != Some(actor)
    {
        return Err(INVALID);
    }
    Ok(PrivateCellManifest {
        manifest_sha256: expected_manifest_sha256.to_owned(),
        initializer_sha256: expected_initializer_sha256.to_owned(),
        files,
    })
}

/// A signed observation can select the native measured argv only when its
/// complete manifest bytes match the independently supplied configuration pin.
/// This is a declaration relation, not a process observation or control score.
pub fn native_cell_runtime_from_observations(
    observations: &Value,
    expected_manifest_sha256: &str,
    expected_initializer_sha256: &str,
) -> Result<Option<String>> {
    if !is_sha256(expected_manifest_sha256) || !is_sha256(expected_initializer_sha256) {
        return Err(INVALID);
    }
    let rows = observations
        .as_array()
        .filter(|rows| rows.len() <= 10000)
        .ok_or(INVALID)?;
    let mut native = rows
        .iter()
        .filter(|row| row["kind"] == "native-cell-runtime");
    let Some(row) = native.next() else {
        return Ok(None);
    };
    if native.next().is_some() || row.as_object().is_none_or(|o| o.len() != 2) {
        return Err(INVALID);
    }
    let raw = row["artifact_manifest_raw"].as_str().ok_or(INVALID)?;
    let manifest = verify_native_private_cell_manifest(
        raw.as_bytes(),
        expected_manifest_sha256,
        expected_initializer_sha256,
    )?;
    manifest
        .native_actor_sha256()
        .map(|s| Some(s.to_owned()))
        .ok_or(INVALID)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value {
        let mut files: BTreeMap<String, String> = fixed_native_private_cell_sources()
            .into_iter()
            .map(|(p, b)| (p, sha256(b)))
            .collect();
        files.insert(INITIALIZER.into(), "a".repeat(64));
        files.insert(NATIVE_CELL_ACTOR.into(), "b".repeat(64));
        json!({"schema":"product-cell-artifacts.v2","files":files,"runtime":{"schema":"product-cell-native-runtime.v1","actor_sha256":"b".repeat(64)}})
    }
    fn verify(value: &Value) -> Result<PrivateCellManifest> {
        let raw = value.to_string();
        crate::verify_private_cell_manifest(
            raw.as_bytes(),
            &sha256(raw.as_bytes()),
            &"a".repeat(64),
        )
    }
    #[test]
    fn native_manifest_binds_exact_source_files_actor_and_initializer() {
        let value = fixture();
        let manifest = verify(&value).unwrap();
        assert_eq!(
            manifest.native_actor_sha256(),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(manifest.files.len(), 25);
        assert!(!manifest.files.contains_key("public/actor.py"));
        for pointer in [
            "/runtime/actor_sha256",
            "/files/public~1gauntlet-product-cell",
            "/files/public~1initializer",
            "/files/code~1ci~1gauntlet~1benchmark~1product_vm_rootfs.py",
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("c".repeat(64));
            assert!(verify(&changed).is_err(), "{pointer}");
        }
        let mut extra = value.clone();
        extra["files"]["public/actor.py"] = json!("d".repeat(64));
        assert!(verify(&extra).is_err());
        let mut mixed = value;
        mixed["schema"] = json!("product-cell-artifacts.v1");
        assert!(verify(&mixed).is_err());
    }
    #[test]
    fn reported_native_runtime_cannot_select_itself_without_the_outside_manifest_pin() {
        let raw = fixture().to_string();
        let pin = sha256(raw.as_bytes());
        let initializer = "a".repeat(64);
        let row = json!({"kind":"native-cell-runtime","artifact_manifest_raw":raw});
        assert_eq!(
            native_cell_runtime_from_observations(&json!([]), &pin, &initializer).unwrap(),
            None
        );
        assert_eq!(
            native_cell_runtime_from_observations(&json!([row]), &pin, &initializer).unwrap(),
            Some("b".repeat(64))
        );
        assert!(native_cell_runtime_from_observations(
            &json!([row]),
            &"f".repeat(64),
            &initializer
        )
        .is_err());
        assert!(
            native_cell_runtime_from_observations(&json!([row, row]), &pin, &initializer).is_err()
        );
        let mut extra = row;
        extra["trusted"] = json!(true);
        assert!(
            native_cell_runtime_from_observations(&json!([extra]), &pin, &initializer).is_err()
        );
    }

    #[test]
    fn native_source_selection_matches_independently_frozen_python_map() {
        let hashes: BTreeMap<_, _> = fixed_native_private_cell_sources()
            .into_iter()
            .map(|(name, raw)| (name, sha256(raw)))
            .collect();
        assert_eq!(hashes.len(), 23);
        let raw = serde_json::to_vec(&hashes).unwrap();
        assert_eq!(
            sha256(&canonicalize(&raw).unwrap()),
            "05b2510a6d822ddb105c55acb030e24e38e20c9e2a35ed7a980a6545c80a7f77"
        );
    }
}
