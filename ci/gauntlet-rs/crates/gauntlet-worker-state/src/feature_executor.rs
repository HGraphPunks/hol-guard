//! Fixed 28-group product audit. This is diagnostic execution, never a model
//! campaign or qualification verdict. The outside owner authenticates custody.
use super::feature_executor_files as files;
use super::feature_executor_prepare::{self as prepare, COMPILER, RUNTIME, SOURCE, SOURCE_RUNTIME};
use super::feature_executor_process::{environment, execute, LOG_LIMIT};
use super::feature_executor_scope::FeatureBox;
use gauntlet_contracts::{
    canonicalize, fixed_feature_catalog, fixed_feature_schedule, FeatureExecutorSpec, FeatureGroup,
    FEATURE_SPEC_LIMIT,
};
use gauntlet_evidence::{
    verify_feature_junit_v2, verify_feature_report_v2, EvidenceError, MAX_FEATURE_JUNIT_BYTES,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn artifact(name: &str, bound: usize) -> Result<Option<Vec<u8>>, String> {
    let path = Path::new("/output").join(name);
    match path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
        Ok(meta) if meta.uid() == 65532 && meta.gid() == 65532 && meta.nlink() == 1 => {}
        Ok(_) => return Err("ordinary single-link owned feature artifact required".into()),
    }
    files::read(&path, bound).map(Some)
}

fn absent(group: &FeatureGroup) -> Result<(), String> {
    for suffix in ["xml", "log"] {
        if artifact(&format!("{}.{suffix}", group.id()), LOG_LIMIT)?.is_some() {
            return Err("feature group artifact existed before its command".into());
        }
    }
    Ok(())
}

fn test_environment(group: &FeatureGroup) -> BTreeMap<String, String> {
    let mut env = environment();
    // Preparation isolates Git configuration for clone/checkout. These extra
    // variables are not in Python's product-test environment: their names
    // change Native's Git authority proof even when the value is /dev/null.
    for key in [
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT",
    ] {
        env.remove(key);
    }
    env.insert("HOL_GUARD_NATIVE".into(), "force".into());
    env.insert(
        "HOL_GUARD_NATIVE_BINARY".into(),
        if group.source_native() {
            SOURCE_RUNTIME
        } else {
            RUNTIME
        }
        .into(),
    );
    if group.source_native() {
        env.insert("PYTHONPATH".into(), format!("{SOURCE}/src"));
        if group.id() == "native_runtime" {
            env.insert(
                "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER".into(),
                COMPILER.into(),
            );
        }
    } else {
        env.insert("HOL_GUARD_TEST_USE_INSTALLED".into(), "1".into());
    }
    env
}

fn missing_source(group: &FeatureGroup) -> bool {
    group.tests().iter().any(|test| {
        let relative = test.split("::").next().expect("fixed selector");
        !Path::new(SOURCE).join(relative).is_file()
    })
}

fn group_result(owner: &FeatureBox, group: &FeatureGroup) -> Result<Value, String> {
    absent(group)?;
    let mut result = group.to_json();
    if missing_source(group) {
        for (key, value) in [
            ("attempted", json!(false)),
            ("status", json!("invalid-evidence")),
            ("counts", Value::Null),
            ("exit_code", Value::Null),
            ("elapsed_millis", json!(0)),
            ("junit_sha256", Value::Null),
            ("log_sha256", Value::Null),
            ("reason", json!("declared-source-test-missing")),
        ] {
            result[key] = value;
        }
        return Ok(result);
    }
    let output = execute(
        owner,
        "/usr/local/bin/uv",
        &group.pytest_argv(),
        SOURCE,
        &test_environment(group),
        group.id(),
        600,
        false,
    )?;
    let xml = artifact(&format!("{}.xml", group.id()), MAX_FEATURE_JUNIT_BYTES)?;
    let log = artifact(&format!("{}.log", group.id()), LOG_LIMIT)?
        .ok_or("feature command log missing")?;
    let counts = xml
        .as_deref()
        .and_then(|raw| verify_feature_junit_v2(raw).ok());
    result["attempted"] = json!(true);
    result["status"] = json!(counts
        .as_ref()
        .map_or("invalid-evidence", |v| v.status(output.code)));
    result["counts"] = counts.map_or(Value::Null, |v| v.to_json());
    result["exit_code"] = json!(output.code);
    result["elapsed_millis"] = json!(output.elapsed_millis);
    result["junit_sha256"] = xml.as_deref().map_or(Value::Null, |v| json!(sha(v)));
    result["log_sha256"] = json!(sha(&log));
    result["reason"] = Value::Null;
    Ok(result)
}

fn report_status(groups: &[Value]) -> &'static str {
    if groups.iter().any(|g| g["status"] == "invalid-evidence") {
        "invalid-evidence"
    } else if groups.iter().any(|g| g["status"] == "failed") {
        "failed"
    } else if groups.iter().any(|g| g["status"] == "incomplete") {
        "incomplete"
    } else {
        "passed"
    }
}

/// Run only as PID 1, UID/GID 65532 in the fixed ARM builder. `spec_sha256`
/// is supplied by the outside Root owner over argv, not by candidate files.
/// The returned canonical bytes go to that owner's stdout channel; children
/// receive their own bounded log pipes. A report is always diagnostic.
pub fn run_fixed_feature_executor(spec_sha256: &str) -> Result<Vec<u8>, String> {
    FeatureBox::preflight()?;
    if !crate::hex(spec_sha256, 64) {
        return Err("outside feature spec pin required".into());
    }
    let mut input = files::root_input(
        Path::new("/input/feature-spec.json"),
        FEATURE_SPEC_LIMIT as u64,
        spec_sha256,
    )?;
    let mut raw = Vec::new();
    input.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let spec = FeatureExecutorSpec::parse(&raw).map_err(|e| e.to_string())?;
    if raw != spec.canonical_bytes() || files::running_hash()? != spec.text("executor_sha256") {
        return Err("feature spec or running executor differs from outside pins".into());
    }
    let owner = FeatureBox::activate(&spec)?;
    owner.drain_children()?;
    let prepared = prepare::prepare(&owner, &spec)?;
    let mut results = BTreeMap::new();
    let mut installed = false;
    for group in fixed_feature_schedule().map_err(|e| e.to_string())? {
        if !group.source_native() && !installed {
            prepare::install(&owner, &spec, &prepared.wheel, "installed-reinstall")?;
            installed = true;
        }
        prepare::native_pin(
            &spec,
            if group.source_native() {
                SOURCE_RUNTIME
            } else {
                RUNTIME
            },
        )?;
        if files::hash(Path::new(COMPILER), 64 * 1024 * 1024)? != prepared.compiler_sha256 {
            return Err("feature source compiler changed during audit".into());
        }
        let row = group_result(&owner, &group)?;
        prepare::native_pin(
            &spec,
            if group.source_native() {
                SOURCE_RUNTIME
            } else {
                RUNTIME
            },
        )?;
        results.insert(group.id().to_owned(), row);
    }
    owner.drain_children()?;
    let groups: Vec<Value> = fixed_feature_catalog()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|g| {
            results
                .remove(g.id())
                .ok_or_else(|| "feature result missing from full schedule".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let status = report_status(&groups);
    let report = json!({
        "schema":"hol-gauntlet-feature-contracts.v2","audit_id":spec.text("audit_id"),
        "source_sha":spec.text("source_sha"),"version":spec.text("version"),
        "wheel_sha256":spec.text("wheel_sha256"),"native_sha256":spec.text("native_sha256"),
        "node_version":"v22.22.2","catalog_sha256":spec.text("catalog_sha256"),
        "feature_executor_sha256":spec.text("executor_sha256"),"source_compiler_sha256":prepared.compiler_sha256,
        "evidence_kind":"mixed-source-installed-contract","status":status,"groups":groups,
        "model_requests":0,"model_tokens":0,"qualification_eligible":false,
    });
    let raw = canonicalize(report.to_string().as_bytes()).map_err(|e| e.to_string())?;
    // Re-read every artifact after all candidate descendants are gone, matching
    // the protected in-memory hashes collected immediately after each group.
    verify_feature_report_v2(&spec, &raw, |name, bound| {
        artifact(name, bound)
            .map_err(|_| EvidenceError::Invalid("feature artifact custody changed"))
    })
    .map_err(|e| e.to_string())?;
    owner.verify()?;
    files::save(Path::new("/output/contracts.v2.json"), &raw, 0o600)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_contexts_and_all_52_selectors_are_preserved() {
        let schedule = fixed_feature_schedule().unwrap();
        assert_eq!(schedule.len(), 28);
        assert_eq!(schedule.iter().map(|g| g.tests().len()).sum::<usize>(), 52);
        for (index, group) in schedule.iter().enumerate() {
            assert_eq!(group.source_native(), index < 13);
            let env = test_environment(group);
            for key in [
                "GIT_CONFIG_NOSYSTEM",
                "GIT_CONFIG_GLOBAL",
                "GIT_TERMINAL_PROMPT",
            ] {
                assert!(environment().contains_key(key));
                assert!(
                    !env.contains_key(key),
                    "setup Git variable leaked to {}",
                    group.id()
                );
            }
            assert_eq!(env["HOL_GUARD_NATIVE"], "force");
            assert_eq!(env.contains_key("PYTHONPATH"), index < 13);
            assert_eq!(
                env.contains_key("HOL_GUARD_TEST_USE_INSTALLED"),
                index >= 13
            );
            assert_eq!(
                env.contains_key("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"),
                group.id() == "native_runtime"
            );
            assert_eq!(
                env["HOL_GUARD_NATIVE_BINARY"],
                if index < 13 { SOURCE_RUNTIME } else { RUNTIME }
            );
        }
    }

    #[test]
    fn outcome_priority_preserves_invalid_failed_and_skipped() {
        assert_eq!(report_status(&[json!({"status":"passed"})]), "passed");
        assert_eq!(
            report_status(&[json!({"status":"incomplete"}), json!({"status":"passed"})]),
            "incomplete"
        );
        assert_eq!(
            report_status(&[json!({"status":"failed"}), json!({"status":"incomplete"})]),
            "failed"
        );
        assert_eq!(
            report_status(&[
                json!({"status":"invalid-evidence"}),
                json!({"status":"failed"})
            ]),
            "invalid-evidence"
        );
    }
}
