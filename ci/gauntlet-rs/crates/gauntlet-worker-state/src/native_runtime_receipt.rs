//! Closed byte-bound clone receipt for one-use inert runtime publication.
//! Parsing a receipt grants no execution or deployment authority.
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct NativeRuntimePins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub version: &'a str,
    pub clone_receipt_sha256: &'a str,
    pub prefix_tree_sha256: &'a str,
    pub native_sha256: &'a str,
    pub python_full_version: &'a str,
    pub generation: &'a str,
}

pub(crate) fn parse(raw: &[u8], pins: &NativeRuntimePins<'_>) -> Result<Value, String> {
    let patch = pins.python_full_version.strip_prefix("3.12.");
    if !crate::hex(pins.job_id, 16)
        || !crate::hex(pins.source_sha, 40)
        || !gauntlet_evidence::valid_package_version(pins.version)
        || ![
            pins.clone_receipt_sha256,
            pins.prefix_tree_sha256,
            pins.native_sha256,
            pins.generation,
        ]
        .iter()
        .all(|s| crate::hex(s, 64))
        || patch.is_none_or(|s| {
            s.is_empty()
                || s.len() > 3
                || !s.bytes().all(|b| b.is_ascii_digit())
                || s.len() > 1 && s.starts_with('0')
        })
        || raw.is_empty()
        || raw.len() > 8192
        || format!("{:x}", Sha256::digest(raw)) != pins.clone_receipt_sha256
        || canonicalize(raw).map_err(|e| e.to_string())? != raw
    {
        return Err(
            "complete runtime pins and canonical outside-bound clone receipt required".into(),
        );
    }
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if v.as_object().is_none_or(|m| m.len() != 23)
        || v["schema"] != "hol-gauntlet-native-candidate-prefix.v1"
        || v["job_id"] != pins.job_id
        || v["source_sha"] != pins.source_sha
        || v["version"] != pins.version
        || v["prefix_tree_sha256"] != pins.prefix_tree_sha256
        || [
            "candidate_executed",
            "dependency_validation_completed",
            "conformance_completed",
            "artifact_admitted",
            "execution_eligible",
            "guard_causality_verified",
        ]
        .iter()
        .any(|k| v[*k] != false)
        || v["console_scripts"] != 6
        || v["model_requests"] != 0
        || v["prefix_entries"]
            .as_u64()
            .is_none_or(|n| !(1..=100_000).contains(&n))
        || v["prefix_bytes"]
            .as_u64()
            .is_none_or(|n| n > 2 * 1024 * 1024 * 1024)
        || v["wheel_files"]
            .as_u64()
            .is_none_or(|n| !(1..=20_000).contains(&n))
        || [
            "source_archive_sha256",
            "archive_sha256",
            "baseline_tree_sha256",
            "stage_tree_sha256",
            "clone_generation",
            "dependency_prefix_receipt_sha256",
        ]
        .iter()
        .any(|k| !v[*k].as_str().is_some_and(|s| crate::hex(s, 64)))
        || !v["dependency_job_id"]
            .as_str()
            .is_some_and(|s| crate::hex(s, 16) && s != pins.job_id)
    {
        return Err(
            "native clone receipt differs from identity, bounds or its ineligible contract".into(),
        );
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value {
        json!({"schema":"hol-gauntlet-native-candidate-prefix.v1", "job_id":"0123456789abcdef", "source_sha":"a".repeat(40), "version":"3.57.0",
            "source_archive_sha256":"b".repeat(64), "archive_sha256":"c".repeat(64), "baseline_tree_sha256":"d".repeat(64), "stage_tree_sha256":"e".repeat(64), "prefix_tree_sha256":"f".repeat(64),
            "clone_generation":"1".repeat(64), "dependency_job_id":"0123456789abcdee", "dependency_prefix_receipt_sha256":"2".repeat(64),
            "prefix_entries":4411, "prefix_bytes":117018000, "wheel_files":1705, "console_scripts":6, "model_requests":0,
            "candidate_executed":false,"dependency_validation_completed":false,"conformance_completed":false,"artifact_admitted":false,"execution_eligible":false,"guard_causality_verified":false})
    }
    fn check(raw: &[u8], python: &str) -> Result<Value, String> {
        let digest = format!("{:x}", Sha256::digest(raw));
        parse(
            raw,
            &NativeRuntimePins {
                job_id: "0123456789abcdef",
                source_sha: &"a".repeat(40),
                version: "3.57.0",
                clone_receipt_sha256: &digest,
                prefix_tree_sha256: &"f".repeat(64),
                native_sha256: &"3".repeat(64),
                python_full_version: python,
                generation: &"4".repeat(64),
            },
        )
    }
    fn bytes(v: &Value) -> Vec<u8> {
        canonicalize(v.to_string().as_bytes()).unwrap()
    }
    #[test]
    fn source_version_bytes_and_claims_are_closed_before_publication() {
        let v = fixture();
        assert_eq!(check(&bytes(&v), "3.12.3").unwrap(), v);
        for (key, value) in [
            ("source_sha", json!("0".repeat(40))),
            ("version", json!("3.57.1")),
            ("execution_eligible", json!(true)),
            ("dependency_validation_completed", json!(true)),
            ("model_requests", json!(1)),
            ("console_scripts", json!(3)),
            ("prefix_entries", json!(100001)),
            ("wheel_files", json!(0)),
            ("dependency_job_id", json!("0123456789abcdef")),
            ("extra", json!(0)),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(check(&bytes(&bad), "3.12.3").is_err(), "{key}");
        }
    }
    #[test]
    fn ambiguous_json_missing_fields_and_interpreter_versions_refuse() {
        let v = fixture();
        let raw = bytes(&v);
        for python in ["3.12.", "3.12.03", "3.13.3", "3.12.3;command", "3.12.1000"] {
            assert!(check(&raw, python).is_err(), "{python}");
        }
        let mut missing = v.clone();
        missing.as_object_mut().unwrap().remove("clone_generation");
        assert!(check(&bytes(&missing), "3.12.3").is_err());
        let duplicate = format!(
            "{{\"model_requests\":0,{}",
            std::str::from_utf8(&raw)
                .unwrap()
                .strip_prefix('{')
                .unwrap()
        );
        assert!(check(duplicate.as_bytes(), "3.12.3").is_err());
        let mut spaced = raw;
        spaced.push(b' ');
        assert!(check(&spaced, "3.12.3").is_err());
    }
}
