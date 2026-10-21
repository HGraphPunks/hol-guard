//! Assemble one host-owned, immutable six-role diagnostic pin manifest.
//! Each public key comes from a durable prelaunch host journal, never a
//! guest control record. Record SHA-256 pins remain caller-supplied.

use gauntlet_contracts::{canonicalize, is_git_sha};
use gauntlet_evidence::valid_package_version;
use gauntlet_host_state::HostControllerKeyPinJournal;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::path::Path;

const ROLES: [&str; 6] = [
    "success",
    "input-binding",
    "injection",
    "boundary",
    "timeout",
    "cancel",
];

fn hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct SuiteIdentity<'a> {
    build_job_id: &'a str,
    source_sha: &'a str,
    version: &'a str,
    config_digest: &'a str,
    private_manifest_sha256: &'a str,
    prefix_tree_sha256: &'a str,
    worker_generation_sha256: &'a str,
}

fn assemble(
    journal: &HostControllerKeyPinJournal,
    identity: &SuiteIdentity<'_>,
    selectors: &[(&str, &str); 6],
) -> Result<Vec<u8>, String> {
    if !hex(identity.build_job_id, 16)
        || !is_git_sha(identity.source_sha)
        || !valid_package_version(identity.version)
        || ![
            identity.config_digest,
            identity.private_manifest_sha256,
            identity.prefix_tree_sha256,
            identity.worker_generation_sha256,
        ]
        .iter()
        .all(|value| hex(value, 64))
    {
        return Err("invalid outside suite identity".to_owned());
    }
    let mut runs = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut roles = Map::new();
    for (role, (run_id, record_sha256)) in ROLES.iter().zip(selectors) {
        if !hex(run_id, 16) || !hex(record_sha256, 64) || !runs.insert(*run_id) {
            return Err("duplicate or invalid one-use suite run/record pin".to_owned());
        }
        let pin = journal
            .read(run_id)
            .map_err(|error| format!("host key pin unavailable for {role}: {error}"))?;
        if pin.pins.job_id != *run_id
            || pin.pins.source_sha != identity.source_sha
            || pin.pins.deployment_digest != identity.config_digest
            || pin.pins.worker_generation != identity.worker_generation_sha256
            || !keys.insert(pin.pins.controller_public_key_hex.clone())
        {
            return Err("suite role differs from prelaunch host pin".to_owned());
        }
        roles.insert(
            (*role).to_owned(),
            json!({
                "run_id":run_id,
                "record_sha256":record_sha256,
                "controller_public_key_hex":pin.pins.controller_public_key_hex,
                "host_record_sha256":pin.raw_sha256,
                "controller_key_pin_sha256":pin.pins.controller_key_pin_sha256,
                "started_marker_sha256":pin.pins.started_marker_sha256,
            }),
        );
    }
    let manifest: Value = json!({
        "schema":"hol-gauntlet-staging-suite-pins.v1",
        "build_job_id":identity.build_job_id,
        "source_sha":identity.source_sha,
        "version":identity.version,
        "config_digest":identity.config_digest,
        "private_manifest_sha256":identity.private_manifest_sha256,
        "prefix_tree_sha256":identity.prefix_tree_sha256,
        "worker_generation_sha256":identity.worker_generation_sha256,
        "roles":roles,
        "execution_eligible":false,
    });
    canonicalize(manifest.to_string().as_bytes())
        .map_err(|_| "suite pin manifest could not be canonicalized".to_owned())
}

fn run() -> Result<Value, String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS host suite pin artifact required".to_owned());
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 21 {
        return Err("usage: gauntlet-host-staging-suite-pins PRIVATE_HOST_PIN_DIR BUILD_JOB SOURCE_SHA VERSION CONFIG_SHA PRIVATE_MANIFEST_SHA PREFIX_TREE_SHA WORKER_SHA SUCCESS_RUN SUCCESS_RECORD INPUT_RUN INPUT_RECORD INJECTION_RUN INJECTION_RECORD BOUNDARY_RUN BOUNDARY_RECORD TIMEOUT_RUN TIMEOUT_RECORD CANCEL_RUN CANCEL_RECORD".to_owned());
    }
    let identity = SuiteIdentity {
        build_job_id: &args[2],
        source_sha: &args[3],
        version: &args[4],
        config_digest: &args[5],
        private_manifest_sha256: &args[6],
        prefix_tree_sha256: &args[7],
        worker_generation_sha256: &args[8],
    };
    let selectors = [
        (args[9].as_str(), args[10].as_str()),
        (args[11].as_str(), args[12].as_str()),
        (args[13].as_str(), args[14].as_str()),
        (args[15].as_str(), args[16].as_str()),
        (args[17].as_str(), args[18].as_str()),
        (args[19].as_str(), args[20].as_str()),
    ];
    let journal = HostControllerKeyPinJournal::open(Path::new(&args[1]))
        .map_err(|error| format!("private host pin directory unavailable: {error}"))?;
    let bytes = assemble(&journal, &identity, &selectors)?;
    let digest = journal
        .record_staging_suite_manifest(identity.build_job_id, &bytes)
        .map_err(|error| format!("one-use suite pin write failed: {error}"))?;
    Ok(json!({
        "schema":"hol-gauntlet-host-staging-suite-pins-diagnostic.v1",
        "path":format!("{}/{}.staging-suite-pins.json",args[1],identity.build_job_id),
        "manifest_sha256":digest,
        "roles":ROLES,
        "execution_eligible":false,
    }))
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("host staging suite pins unavailable: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gauntlet_host_state::HostControllerKeyPins;

    #[test]
    fn host_journal_keys_must_match_one_source_config_and_generation() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            temp.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let root = temp.path().canonicalize().unwrap();
        let journal = HostControllerKeyPinJournal::open(&root).unwrap();
        let source = "a".repeat(40);
        let config = "b".repeat(64);
        let worker = "c".repeat(64);
        let private = "d".repeat(64);
        let prefix = "e".repeat(64);
        let records: Vec<_> = (0..6)
            .map(|index| (format!("{index:016x}"), format!("{index:064x}")))
            .collect();
        for (index, (run, _)) in records.iter().enumerate() {
            journal
                .record(&HostControllerKeyPins {
                    job_id: run.clone(),
                    source_sha: source.clone(),
                    deployment_digest: config.clone(),
                    worker_generation: worker.clone(),
                    started_marker_sha256: "1".repeat(64),
                    controller_key_pin_sha256: "2".repeat(64),
                    controller_public_key_hex: format!("{:064x}", index + 1),
                })
                .unwrap();
        }
        let identity = SuiteIdentity {
            build_job_id: "0123456789abcdef",
            source_sha: &source,
            version: "3.49.0",
            config_digest: &config,
            private_manifest_sha256: &private,
            prefix_tree_sha256: &prefix,
            worker_generation_sha256: &worker,
        };
        let selectors: [(&str, &str); 6] =
            std::array::from_fn(|index| (records[index].0.as_str(), records[index].1.as_str()));
        assert!(hex(identity.build_job_id, 16));
        assert!(is_git_sha(identity.source_sha));
        assert!(valid_package_version(identity.version));
        assert!(hex(identity.config_digest, 64));
        assert!(hex(identity.private_manifest_sha256, 64));
        assert!(hex(identity.prefix_tree_sha256, 64));
        assert!(hex(identity.worker_generation_sha256, 64));
        let raw = assemble(&journal, &identity, &selectors).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["roles"]["cancel"]["run_id"], records[5].0);
        assert_eq!(value["execution_eligible"], false);
        assert!(assemble(
            &journal,
            &identity,
            &[
                selectors[0],
                selectors[0],
                selectors[2],
                selectors[3],
                selectors[4],
                selectors[5]
            ]
        )
        .is_err());
        let wrong = SuiteIdentity {
            worker_generation_sha256: &"f".repeat(64),
            ..identity
        };
        assert!(assemble(&journal, &wrong, &selectors).is_err());
        let digest = journal
            .record_staging_suite_manifest("0123456789abcdef", &raw)
            .unwrap();
        assert!(hex(&digest, 64));
        assert!(journal
            .record_staging_suite_manifest("0123456789abcdef", &raw)
            .is_err());
    }
}
