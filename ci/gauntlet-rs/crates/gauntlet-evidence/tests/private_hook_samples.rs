use gauntlet_evidence::verify_private_hook_samples;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

#[path = "support/private_custody_source.rs"]
mod private_custody_source;

#[test]
fn python_primary_and_nested_hook_samples_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private_hook_samples_v1.json")).unwrap();
    assert_eq!(fixture["schema"], "gauntlet-python-private-hook-samples.v1");
    private_custody_source::assert_private_custody_source(&fixture, &["_hook_samples"]);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    assert_eq!(
        fixture["product_sha256"],
        format!(
            "{:x}",
            Sha256::digest(
                std::fs::read(root.join("ci/gauntlet/benchmark/product_custody.py")).unwrap()
            )
        )
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 23);
    assert_eq!(
        cases.iter().filter(|row| row["accepted"] == true).count(),
        4
    );
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let observed = verify_private_hook_samples(
            &row["samples"],
            &row["controller"],
            row["agent"].as_object().map(|_| &row["agent"]),
            row["product_user_namespace"].as_str().unwrap(),
            row["command_hash"].as_str().unwrap(),
        );
        if row["accepted"] == true {
            let samples = row["samples"].as_array().unwrap();
            let primary = samples
                .iter()
                .filter(|sample| sample["command_sha256"] == row["command_hash"])
                .count();
            assert_eq!(
                observed.unwrap_or_else(|error| panic!("{name}: {error}")),
                json!({"primary_sample_count": primary,
                       "nested_sample_count": samples.len() - primary,
                       "execution_eligible": false}),
                "{name}"
            );
        } else {
            assert_eq!(
                observed.unwrap_err().to_string(),
                row["reason"].as_str().unwrap(),
                "{name}"
            );
        }
    }
}
