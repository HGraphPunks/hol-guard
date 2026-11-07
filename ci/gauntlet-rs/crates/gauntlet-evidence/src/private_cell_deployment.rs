//! Shared fixed shadow-path and authenticated artifact-runtime relation.
use crate::crypto::is_sha256;
use crate::{
    verify_private_cell_artifacts, EvidenceError, PrivateCellInventory, Result, NATIVE_CELL_ACTOR,
};
use serde_json::Value;
use std::path::{Path, PathBuf};

const INVALID: EvidenceError =
    EvidenceError::Invalid("private-cell directory differs from authenticated runtime");

fn selection<'a>(job: &str, config: &'a Value, manifest: &str) -> Result<(PathBuf, bool, &'a str)> {
    if job.len() != 16
        || !job
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !is_sha256(manifest)
        || config["assets"]["private_cell"]["sha256"] != manifest
    {
        return Err(INVALID);
    }
    let declared = config["assets"]["private_cell"]["path"]
        .as_str()
        .ok_or(INVALID)?;
    let base = format!("hol-gauntlet/rust-shadow-candidates/{job}");
    let native = if declared == format!("{base}/cell-artifacts-rust-v2") {
        true
    } else if declared == format!("{base}/cell-artifacts") {
        false
    } else {
        return Err(INVALID);
    };
    let initializer = config["runtime"]["private_cell"]["initializer_sha256"]
        .as_str()
        .filter(|pin| is_sha256(pin))
        .ok_or(INVALID)?;
    Ok((Path::new("/opt").join(declared), native, initializer))
}

/// Authenticate the complete Root-owned bundle with outside pins and the
/// embedded controller-source map, then require the matching fixed directory.
/// Neither a filename nor a producer runtime label selects the actor.
pub fn verify_shadow_private_cell_artifacts(
    job: &str,
    config: &Value,
    manifest: &str,
) -> Result<PrivateCellInventory> {
    let (path, native, initializer) = selection(job, config, manifest)?;
    let inventory = verify_private_cell_artifacts(&path, manifest, initializer)?;
    if inventory.files.contains_key(NATIVE_CELL_ACTOR) != native {
        return Err(INVALID);
    }
    Ok(inventory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn config(suffix: &str) -> Value {
        json!({
        "assets":{"private_cell":{"path":format!("hol-gauntlet/rust-shadow-candidates/aabbccddeeff0011/{suffix}"),"sha256":"a".repeat(64)}},
        "runtime":{"private_cell":{"initializer_sha256":"b".repeat(64)}}})
    }
    #[test]
    fn both_directories_require_the_same_outside_manifest_and_initializer() {
        for (suffix, native) in [("cell-artifacts", false), ("cell-artifacts-rust-v2", true)] {
            let value = config(suffix);
            let (path, selected, initializer) =
                selection("aabbccddeeff0011", &value, &"a".repeat(64)).unwrap();
            assert_eq!(selected, native);
            assert!(path.ends_with(suffix));
            assert_eq!(initializer, "b".repeat(64));
            assert!(selection("1122334455667788", &value, &"a".repeat(64)).is_err());
            assert!(selection("aabbccddeeff0011", &value, &"f".repeat(64)).is_err());
        }
    }
    #[test]
    fn arbitrary_or_aliased_directories_and_missing_pins_refuse_before_io() {
        for suffix in [
            "cell-artifacts/../cell-artifacts-rust-v2",
            "other",
            "cell-artifacts-rust-v2/",
            "",
        ] {
            assert!(selection("aabbccddeeff0011", &config(suffix), &"a".repeat(64)).is_err());
        }
        let mut value = config("cell-artifacts-rust-v2");
        value["runtime"]["private_cell"]["initializer_sha256"] = Value::Null;
        assert!(selection("aabbccddeeff0011", &value, &"a".repeat(64)).is_err());
    }
}
