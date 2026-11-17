//! Exact caller-custodied original catalog; no embedded replacement inventory.
use super::*;
pub(super) const COMMIT: &str = "b4efd8171b06d0e13cbe12a077c376ecdc891fd1";
const SHA256: &str = "6195060feea1e25a69a9dfe8ff75d971b2d0d73241ff8eb8dbb547a4cb900d79";
const BLOB: &str = "379531e861c3c8cdba28fefed72defa28661ff23";

pub(super) fn read(raw: &[u8]) -> Result<Vec<Value>> {
    if raw.len() != 81965 || sha256(raw) != SHA256 {
        return Err(invalid("original frozen 128-row catalog bytes required"));
    }
    let mut blob = format!("blob {}\0", raw.len()).into_bytes();
    blob.extend_from_slice(raw);
    let observed = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &blob)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if observed != BLOB {
        return Err(invalid("frozen baseline Git blob mismatch"));
    }
    let value = crate::native_diagnostic_artifacts::parse(raw)?;
    if value["schema"] != "hol.guard-gauntlet.scenarios.v1"
        || value["scenarios"]
            .as_array()
            .is_none_or(|rows| rows.len() != 128)
    {
        return Err(invalid("frozen catalog schema/count mismatch"));
    }
    let mut normalized = value["scenarios"].as_array().expect("checked rows").clone();
    for row in &mut normalized {
        let fields = row
            .as_object_mut()
            .ok_or(invalid("frozen scenario object required"))?;
        for key in [
            "commands",
            "required_tools",
            "benign_exit_commands",
            "decision_paths",
        ] {
            fields.entry(key).or_insert_with(|| json!([]));
        }
        fields.entry("path").or_insert(Value::Null);
        fields.entry("profiles").or_insert_with(|| json!(["core"]));
        fields.entry("contained_ok").or_insert(json!(false));
    }
    Ok(normalized)
}
pub(super) fn observation(raw: &[u8]) -> Result<Value> {
    let rows = read(raw)?;
    Ok(
        json!({"schema":"hol-gauntlet-frozen-legacy-catalog-observation.v1","source_sha":COMMIT,
        "catalog_sha256":SHA256,"catalog_git_blob":BLOB,"scenario_count":rows.len(),
        "execution_eligible":false,"qualification_eligible":false}),
    )
}
