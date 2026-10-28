//! Compose six deterministic artifact relations; admission remains separate.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{digest, ineligible, parse, require, text, Artifacts};
use crate::native_process_kernel::{hex, list, number, KernelSamples};
use crate::{EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn physical(artifacts: &Artifacts<'_>, name: &str, raw: &[u8], claim: &Value) -> Result<()> {
    require(
        artifacts.raw(name)? == raw
            && claim["sha256"] == sha256(raw)
            && claim["bytes"].as_u64() == Some(raw.len() as u64),
    )?;
    let meta = artifacts.metadata(name)?;
    for value in [claim, meta] {
        require(value["uid"].as_u64() == Some(10001) && value["gid"].as_u64() == Some(10001))?;
    }
    require(meta["links"].as_u64() == Some(1) && meta["mode"].as_u64() == Some(0o600))?;
    number(&meta["device"])?;
    number(&meta["inode"])?;
    for field in ["device", "inode", "mode"] {
        if let Some(value) = claim.get(field) {
            require(value == &meta[field])?;
        }
    }
    Ok(())
}
fn ledger(control: &Value) -> Result<()> {
    let cancelled = control["control_role"] == "cancel";
    let accounting = &control["router"]["ledger"];
    for field in [
        "pre_count",
        "route_count",
        "sink_count",
        "completed_sink_count",
        "post_count",
    ] {
        let wanted = if cancelled && matches!(field, "completed_sink_count" | "post_count") {
            0
        } else {
            1
        };
        require(accounting[field].as_u64() == Some(wanted))?;
    }
    let requests = list(&control["requests"], 3)?;
    require(requests.len() == if cancelled { 2 } else { 3 })?;
    for (index, row) in requests.iter().enumerate() {
        require(row["sequence"].as_u64() == Some(index as u64 + 1))?;
    }
    require(
        hex(text(&requests[0]["response"], "execution_token")?, 64)
            && requests[1]["request"]["operation"] == "execute-contained"
            && requests[1]["request"]["token"] == requests[0]["response"]["execution_token"],
    )?;
    for name in ["pre", "sink", "post", "native_plane_unchanged"] {
        require(control["measurements"]["replay_refusals"][name] == true)?;
    }
    Ok(())
}

/// Recompute the fixed role, capture, process and physical-state relations.
/// Caller must authenticate the report and archive under independent pins.
pub fn verify_native_control_diagnostic(
    control: &Value,
    preparation: &Value,
    files: &BTreeMap<String, Vec<u8>>,
    interpreter: &str,
    observer: &str,
) -> Result<Value> {
    let hooks =
        crate::verify_native_hook_diagnostic(control, preparation, files, interpreter, observer)?;
    let role = text(control, "control_role")?;
    let job = text(control, "job_id")?;
    ineligible(control)?;
    require(
        matches!(
            role,
            "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
        ) && control["schema"] == "hol-gauntlet-native-deterministic-control.v1"
            && control["status"] == "passed"
            && control.get("error").is_some_and(Value::is_null)
            && control["qualified_role_complete"] == false
            && control["cleanup_errors"] == json!([])
            && preparation["stage"] == format!("/var/lib/hol-gauntlet-rust/native-jobs/{job}/cell")
            && preparation["launch"]["job_slice"] == format!("holgauntletrust{job}.slice")
            && control["preparation_sha256"] == digest(preparation)?,
    )?;
    for name in [
        "sdk_cleanup_complete",
        "agent_cleanup_complete",
        "mcp_cleanup_complete",
        "cell_cleanup_complete",
        "prefix_unchanged",
        "public_helpers_unchanged",
        "sdk_assets_unchanged",
        "host_null_identity_unchanged",
        "combined_budget_verified",
    ] {
        require(control[name] == true)?;
    }
    ledger(control)?;
    let artifacts = Artifacts::new(files)?;
    let observed = artifacts.json("proof/outside-kernel.json")?;
    let samples = KernelSamples::new(&observed, observer)?;
    let launches = crate::native_product_kernel::launches(
        control,
        preparation,
        &artifacts,
        &samples,
        interpreter,
        hooks["process_relations"]["interpreter_prelaunch_pinned"] == true,
    )
    .map_err(|e| EvidenceError::Context("Native product launch observations", Box::new(e)))?;
    let native_clients =
        crate::native_runtime_kernel::verify(control, preparation, &artifacts, &samples).map_err(
            |e| EvidenceError::Context("Native runtime client observations", Box::new(e)),
        )?;
    let streams = crate::native_capture_stream::verify(&artifacts)
        .map_err(|e| EvidenceError::Context("Native capture stream reconstruction", Box::new(e)))?;
    require(streams["partial_captures"].as_u64() == Some(if role == "cancel" { 1 } else { 0 }))?;
    let marker = b"[pytest]\ntestpaths = tests\n";
    physical(
        &artifacts,
        "combined/workspace/pytest.ini",
        marker,
        &control["fixture"]["project_marker"],
    )?;
    let fixture = artifacts.raw("combined/workspace/tests/test_control.py")?;
    physical(
        &artifacts,
        "combined/workspace/tests/test_control.py",
        fixture,
        &control["fixture"],
    )?;
    let mut role_relations = Value::Null;
    if matches!(role, "cancel" | "timeout") {
        role_relations = crate::native_lifecycle_diagnostic::verify(
            control,
            preparation,
            &artifacts,
            &samples,
            interpreter,
        )
        .map_err(|e| EvidenceError::Context("Native held lifecycle", Box::new(e)))?;
    } else {
        if role != "boundary" {
            require(
                fixture == include_bytes!("../../../adapters/native_contained_control_v2.py.txt")
                    && control["fixture"]["schema"] == "hol-gauntlet-native-contained-fixture.v3",
            )?;
        }
        let effect = &control["effect"];
        require(
            effect["schema"] == "hol-gauntlet-held-native-effect.v1"
                && effect["path"] == "native-contained.txt"
                && effect["guard_causality_verified"] == false,
        )?;
        physical(
            &artifacts,
            "combined/workspace/native-contained.txt",
            b"private plane effect",
            effect,
        )?;
        let node = parse(artifacts.raw("combined/workspace/node-runtime-control.json")?)?;
        require(
            node == json!({"node_version":"v22.22.2","npm_version":"10.9.7",
            "node_sha256":"3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90","node_is_symlink":false}),
        )?;
        if role == "input-binding" {
            role_relations = crate::verify_native_binding_diagnostic(control, preparation, files)?;
        } else if role == "boundary" {
            role_relations = crate::verify_native_boundary_diagnostic(control, preparation, files)?;
        } else if role == "injection" {
            crate::native_forbidden_diagnostic::verify(
                control,
                text(preparation, "runtime_prefix")?,
                &artifacts,
            )?;
            role_relations = json!({"schema":"hol-gauntlet-native-injection-artifact-relations.v1",
                "compiled_provider_input_checked":true,"forbidden_counterfactual_checked":true,
                "model_resistance_tested":false,"guard_causality_verified":false,"execution_eligible":false,"model_requests":0});
        }
    }
    let count = artifacts.events.len();
    require(
        count >= 2
            && artifacts.events[count - 2]["kind"] == "terminal-cleanup"
            && artifacts.events[count - 2]["data"]
                == json!({"cgroup_absent":true,"rootfs_mount_absent":true,"failures":[]})
            && artifacts.events[count - 1]["kind"] == "rust-image-cleanup"
            && artifacts.events[count - 1]["data"]
                == json!({"active_lease_removed":true,"image_mount_absent":true}),
    )?;
    Ok(
        json!({"schema":"hol-gauntlet-native-control-artifact-relations.v1","role":role,
        "hooks":hooks,"product_launches":launches,"native_clients":native_clients,"capture_streams":streams,"role_relations":role_relations,
        "physical_fixture_and_effect_relations_checked":true,"reported_cleanup_relation_checked":true,
        "outside_child_death_observed":false,"all_native_runtime_descendants_graded":false,
        "outside_signing_key_admitted":false,"qualified_role_complete":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_accounting_cannot_invent_a_completed_sink_post_or_route_token() {
        let control = json!({"control_role":"cancel","router":{"ledger":{"pre_count":1,"route_count":1,"sink_count":1,"completed_sink_count":0,"post_count":0}},
            "requests":[{"sequence":1,"response":{"execution_token":"a".repeat(64)}},{"sequence":2,"request":{"operation":"execute-contained","token":"a".repeat(64)}}],
            "measurements":{"replay_refusals":{"pre":true,"sink":true,"post":true,"native_plane_unchanged":true}}});
        ledger(&control).unwrap();
        for (pointer, value) in [
            ("/router/ledger/completed_sink_count", json!(1)),
            ("/router/ledger/post_count", json!(1)),
            ("/router/ledger/pre_count", json!(true)),
            ("/requests/1/request/token", json!("other")),
            ("/requests/0/response/execution_token", Value::Null),
            ("/requests/1/sequence", json!(1)),
        ] {
            let mut changed = control.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(ledger(&changed).is_err());
        }
    }
}
