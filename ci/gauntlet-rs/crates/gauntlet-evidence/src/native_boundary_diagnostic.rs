//! Fixed synthetic boundary measurements, separately from Guard intervention.
//! Child-reported kernel fields stay unauthenticated even when relations match.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{
    argv, digest, ineligible, parse, require, text, Artifacts,
};
use crate::{EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const SUCCESS: &[u8] = include_bytes!("../../../adapters/native_contained_control_v2.py.txt");
const NEGATIVE: &str = include_str!("../../../adapters/native_boundary_control_v1.py.txt");
const PRODUCT_POSITIVE: &str = "import os,hashlib;from pathlib import Path;assert os.geteuid()==10004;print(hashlib.sha256(Path('/product/guard/native-boundary-canary.txt').read_bytes()).hexdigest())";
const SDK_POSITIVE: &str = "import os,hashlib;from pathlib import Path;assert os.geteuid()==10001;print(hashlib.sha256(Path('/runtime/agent/agent-canary.txt').read_bytes()).hexdigest())";

fn canary_specs(job: &str) -> [(String, String, u64, &'static [u8]); 3] {
    let root = format!("/var/lib/hol-gauntlet-rust/native-jobs/{job}");
    [
        (
            format!("{root}/controller-canary.txt"),
            format!("{root}/controller-canary.txt"),
            0,
            b"gauntlet-controller-canary-v1",
        ),
        (
            format!("{root}/sdk-agent/agent-canary.txt"),
            "/runtime/agent/agent-canary.txt".into(),
            10001,
            b"gauntlet-sdk-agent-canary-v1",
        ),
        (
            format!("{root}/cell/state/guard/native-boundary-canary.txt"),
            "/product/guard/native-boundary-canary.txt".into(),
            10004,
            b"gauntlet-product-guard-canary-v1",
        ),
    ]
}
fn file_metadata(measured: &Value, physical: &Value, owner: u64) -> Result<()> {
    for field in ["device", "inode", "mode", "uid", "gid"] {
        require(measured.get(field).is_some() && measured[field] == physical[field])?;
    }
    require(
        physical["uid"].as_u64() == Some(owner)
            && physical["gid"].as_u64() == Some(owner)
            && physical["links"].as_u64() == Some(1)
            && physical["inode"].as_u64().is_some_and(|n| n > 0)
            && physical["device"].as_u64().is_some_and(|n| n > 0),
    )
}
fn refusals(reported: &Value, paths: &[String]) -> Result<()> {
    require(
        reported["schema"] == "hol-gauntlet-native-boundary-negatives.v1"
            && reported["kernel_claims_authenticated"] == false,
    )?;
    let rows = reported["rows"]
        .as_array()
        .ok_or(EvidenceError::Invalid("boundary refusal rows missing"))?;
    require(rows.len() == 8)?;
    for (index, row) in rows.iter().enumerate() {
        let error = row["errno"]
            .as_i64()
            .ok_or(EvidenceError::Invalid("integer boundary errno required"))?;
        let expected = if index < 6 {
            require(matches!(error, 1 | 2 | 13 | 30))?;
            json!({"surface":"path","path":paths[index/2],"operation":if index%2==0 {"read"} else {"write"},
                "denied":true,"errno":error})
        } else {
            require(matches!(error, 1 | 13 | 97 | 101))?;
            json!({"surface":"network","family":if index==6 {2} else {10},"denied":true,"errno":error})
        };
        require(row == &expected)?;
    }
    require(
        reported["kernel"]
            == json!({"Uid":"10004\t10004\t10004\t10004",
        "Gid":"10004\t10004\t10004\t10004","CapEff":"0000000000000000","NoNewPrivs":"1","Seccomp":"2"}),
    )
}

/// Recompute only supplied capture/physical boundary relations. The host's
/// prior completion pin and archive digest must establish custody separately.
pub fn verify_native_boundary_diagnostic(
    control: &Value,
    preparation: &Value,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Value> {
    ineligible(control)?;
    require(
        control["schema"] == "hol-gauntlet-native-deterministic-control.v1"
            && control["control_role"] == "boundary"
            && control["qualified_role_complete"] == false
            && preparation["schema"] == "hol-gauntlet-cell-preparation.v1"
            && control["preparation_sha256"] == digest(preparation)?,
    )?;
    let boundary = &control["measurements"]["boundary_control"];
    ineligible(boundary)?;
    require(
        boundary["schema"] == "hol-gauntlet-native-boundary-control.v1"
            && boundary["status"] == "passed"
            && boundary["canaries_unchanged"] == true
            && boundary["kernel_claims_authenticated"] == false,
    )?;
    let custody = &boundary["canary_custody"];
    ineligible(custody)?;
    require(custody["schema"] == "hol-gauntlet-native-boundary-canaries.v1")?;
    let canaries = custody["canaries"]
        .as_array()
        .ok_or(EvidenceError::Invalid("three boundary canaries required"))?;
    require(canaries.len() == 3)?;
    let artifacts = Artifacts::new(files)?;
    let specs = canary_specs(text(control, "job_id")?);
    for (i, (physical, inside, owner, raw)) in specs.iter().enumerate() {
        let measured = &canaries[i];
        let name = [
            "controller-canary.txt",
            "sdk-agent-canary.txt",
            "product-guard-canary.txt",
        ][i];
        let member = format!("combined/{name}");
        require(
            measured["path"] == *physical
                && measured["inside"] == *inside
                && measured["sha256"] == sha256(raw)
                && measured["bytes"].as_u64() == Some(raw.len() as u64)
                && artifacts.raw(&member)? == *raw,
        )?;
        file_metadata(measured, artifacts.metadata(&member)?, *owner)?;
        require(measured["mode"].as_u64() == Some(0o600))?;
    }
    let sdk = &control["measurements"]["sdk_boundary_canary_positive"];
    let sdk_output = format!("{}\n", sha256(specs[1].3));
    let sdk_command = [
        "exec",
        "--interactive",
        text(&control["agent"], "container_id")?,
        "/usr/bin/python3",
        "-I",
        "-B",
        "-c",
        SDK_POSITIVE,
    ]
    .map(str::to_owned)
    .to_vec();
    require(
        sdk["exit_code"].as_i64() == Some(0)
            && sdk["unprivileged_adapter"] == true
            && sdk["canary_sha256"] == sha256(specs[1].3)
            && sdk["stdout_sha256"] == sha256(sdk_output.as_bytes())
            && sdk["stderr_sha256"] == sha256(b"")
            && argv(&sdk["command"])? == sdk_command,
    )?;
    let (sdk_stdout, sdk_stderr) = artifacts.unique_process_capture(
        "combined/sdk-processes/",
        &sha256(sdk_output.as_bytes()),
        &sha256(b""),
    )?;
    require(sdk_stdout == sdk_output.as_bytes() && sdk_stderr.is_empty())?;
    let product = &custody["product_positive"];
    let product_output = format!("{}\n", sha256(specs[2].3));
    let command = ["/usr/bin/python3", "-I", "-B", "-c", PRODUCT_POSITIVE]
        .map(str::to_owned)
        .to_vec();
    require(
        product["exit_code"].as_i64() == Some(0)
            && argv(&product["native_command"])? == command
            && product["stdout_sha256"] == sha256(product_output.as_bytes())
            && product["stderr_sha256"] == sha256(b""),
    )?;
    let captured = artifacts.capture(
        &command,
        0,
        &sha256(product_output.as_bytes()),
        &sha256(b""),
        None,
    )?;
    require(captured.stdout == product_output.as_bytes() && captured.stderr.is_empty())?;
    let name = "combined/workspace/boundary-negatives.json";
    let raw = artifacts.raw(name)?;
    let physical = &boundary["physical_report"];
    require(
        !raw.is_empty()
            && raw.len() <= 65536
            && physical["sha256"] == sha256(raw)
            && physical["bytes"].as_u64() == Some(raw.len() as u64),
    )?;
    file_metadata(physical, artifacts.metadata(name)?, 10001)?;
    require(physical["mode"].as_u64().is_some_and(|m| m & 0o022 == 0))?;
    let report = parse(raw)?;
    require(report == boundary["reported"])?;
    refusals(
        &report,
        &specs.iter().map(|s| s.1.clone()).collect::<Vec<_>>(),
    )?;
    let mut expected = SUCCESS.to_vec();
    expected.push(b'\n');
    let controller = serde_json::to_string(&specs[0].1)
        .map_err(|_| EvidenceError::Invalid("boundary path JSON"))?;
    expected.extend(
        NEGATIVE
            .replace("HOL_CONTROLLER_CANARY_JSON", &controller)
            .as_bytes(),
    );
    require(
        artifacts.raw("combined/workspace/tests/test_control.py")? == expected
            && control["fixture"]["sha256"] == sha256(&expected),
    )?;
    let marker = b"[pytest]\ntestpaths = tests\n";
    require(
        artifacts.raw("combined/workspace/pytest.ini")? == marker
            && control["fixture"]["project_marker"]["sha256"] == sha256(marker),
    )?;
    Ok(
        json!({"schema":"hol-gauntlet-native-boundary-diagnostic-relations.v1","job_id":control["job_id"],
        "canary_positive_visibility_verified":true,"physical_canaries_preserved":3,"path_refusals":6,"network_refusals":2,
        "capture_bytes_and_chain_checked":true,"child_kernel_claims_authenticated":false,"independent_process_custody_checked":false,
        "qualified_role_complete":false,"outside_signing_key_admitted":false,"execution_eligible":false,
        "guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_boundary_diagnostic_tests.rs"]
mod tests;
