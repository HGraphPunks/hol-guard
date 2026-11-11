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

/// Recompute the explicitly selected read-only diagnostic's actual hook inputs,
/// capture bytes, v2 transports and fixed fixture. This grants no SDK role,
/// independent writer attribution, observer admission or qualification.
pub fn verify_native_readonly_diagnostic(
    control: &Value,
    preparation: &Value,
    files: &BTreeMap<String, Vec<u8>>,
    interpreter: &str,
    observer: &str,
) -> Result<Value> {
    let job = text(control, "job_id")?;
    let route = crate::NativeContainmentRoute::PythonReadonlyV1;
    let artifacts = Artifacts::new(files)?;
    let preparation_raw = artifacts.raw("combined/preparation.v1.json")?;
    ineligible(control)?;
    require(
        hex(job, 16)
            && hex(interpreter, 64)
            && hex(observer, 64)
            && control["schema"] == "hol-gauntlet-native-hook-transport.v2"
            && control["status"] == "passed"
            && control["sdk_exercised"] == false
            && control["artifact_admitted"] == false
            && control["qualified_role_complete"] == false
            && control.get("control_role").is_none()
            && control.get("sdk_pins").is_none()
            && control.get("guard_pins").is_none()
            && control.get("requests").is_none()
            && preparation["schema"] == "hol-gauntlet-cell-preparation.v2"
            && preparation["control_profile"] == "python-readonly.v1"
            && preparation["task_mounts"]["providers"] == json!([])
            && preparation["stage"] == format!("/var/lib/hol-gauntlet-rust/native-jobs/{job}/cell")
            && preparation["launch"]["job_slice"] == format!("holgauntletrust{job}.slice")
            && preparation["launch"]["schema"] == "hol-gauntlet-cell-supervisor.v5"
            && preparation["launch"]["image_interpreter_sha256"] == interpreter
            && preparation["launch"]["outside_observer_sha256"] == observer
            && parse(preparation_raw)? == *preparation
            && control["preparation_sha256"] == sha256(preparation_raw)
            && control["prefix_tree_sha256"] == preparation["runtime_tree_digest"],
    )?;
    for name in ["error", "cleanup_error", "effect_error"] {
        require(control.get(name).is_some_and(Value::is_null))?;
    }
    for name in ["cell_cleanup_complete", "prefix_unchanged"] {
        require(control[name] == true)?;
    }
    let plane = &control["plane"];
    require(
        plane["sdk_exercised"] == false
            && plane["containment_contract"]
                == json!({
        "schema":"hol-gauntlet-native-containment-contract.v2",
        "reason_code":route.reason(),"required_execution_profile":route.profile()}),
    )?;
    let output = crate::native_hook_diagnostic::readonly_output(control)?;
    let expected = crate::native_hook_diagnostic::readonly_payloads(control, &output)?;
    let mut hooks = crate::native_hook_diagnostic::captures(
        control,
        preparation,
        files,
        expected,
        Some(output),
        route,
    )?;
    require(control["measurements"]["prompt"] == plane["hooks"][0]["response"])?;
    let process =
        crate::native_process_trace_diagnostic::verify(preparation, plane, &artifacts, true)?
            .ok_or(EvidenceError::Invalid("read-only trace missing"))?;
    let images = crate::native_runtime_trace::verify(control, preparation, &artifacts)
        .map_err(|e| EvidenceError::Context("read-only Native image history", Box::new(e)))?
        .ok_or(EvidenceError::Invalid(
            "read-only Native image history missing",
        ))?;
    let transport =
        crate::native_stdio_diagnostic::verify(control, preparation, &artifacts, &images, &hooks)?
            .ok_or(EvidenceError::Invalid("read-only transport missing"))?;
    require(transport["schema"] == "hol-gauntlet-native-transport-readback.v2")?;
    require(
        transport["copied_hook_relations"]["schema"]
            == "hol-gauntlet-copied-native-hook-relations.v2"
            && transport["copied_hook_relations"]["outer_hooks_joined"] == 3
            && transport["copied_hook_relations"]["contained_reauthorizations_checked"]
                .as_u64()
                .is_some_and(|n| n > 0),
    )?;
    let streams = crate::native_capture_stream::verify(&artifacts)?;
    require(streams["partial_captures"].as_u64() == Some(0))?;
    let positive = &control["measurements"]["unprotected_write_positive"];
    let probe = "import os\nfd=os.open('readonly-write-probe.txt',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\nwith os.fdopen(fd,'w') as effect:effect.write('unexpected')\n";
    let command = vec![
        "/usr/bin/python3".into(),
        "-I".into(),
        "-B".into(),
        "-c".into(),
        probe.into(),
    ];
    require(
        positive["schema"] == "hol-gauntlet-native-readonly-write-positive.v1"
            && positive["native_command"] == json!(command)
            && positive["retired"] == true
            && positive["exit_code"] == 0
            && positive["execution_eligible"] == false
            && positive["guard_causality_verified"] == false
            && positive["stdout_sha256"] == sha256(b"")
            && positive["stderr_sha256"] == sha256(b""),
    )?;
    let captured = artifacts.capture(&command, 0, &sha256(b""), &sha256(b""), None)?;
    let positive_input =
        crate::verify_native_capture_input(&artifacts.events, captured.sequence, &command, b"")?;
    require(positive_input["input_delivery_checked"] == true)?;
    let observed = &positive["observed"];
    require(
        observed["file"] == "readonly-write-probe.txt"
            && observed["sha256"] == sha256(b"unexpected")
            && observed["bytes"] == 10
            && observed["uid"] == 10001
            && observed["gid"] == 10001
            && observed["mode"] == 0o600
            && observed["links"] == 1,
    )?;
    number(&observed["device"])?;
    number(&observed["inode"])?;
    // The v7 fixture is immutable; no reported test body can define its own oracle.
    let fixture = artifacts.raw("combined/workspace/tests/test_control.py")?;
    require(
        fixture.len() == 821
            && sha256(fixture)
                == "2b829ab76812e1cc72fd964367b8659f5d61e60a6f75fa14218204827b8fb9a6",
    )?;
    let effect = &control["effect"];
    require(
        control["fixture"]["schema"] == "hol-gauntlet-native-contained-fixture.v7"
            && control["fixture"]["control_profile"] == "python-readonly.v1"
            && control["fixture"]["required_execution_profile"] == route.profile()
            && control["fixture"]["utility_tests"] == 3
            && effect["schema"] == "hol-gauntlet-held-native-readonly-state.v1"
            && effect["write_probe_absent"] == true
            && effect["workspace_write_effect_expected"] == false
            && effect["effect_writer_attribution_checked"] == false
            && effect["execution_eligible"] == false
            && effect["guard_causality_verified"] == false,
    )?;
    for (name, raw, claim) in [
        (
            "combined/workspace/tests/test_control.py",
            fixture,
            &effect["fixture"],
        ),
        (
            "combined/workspace/pytest.ini",
            b"[pytest]\ntestpaths = tests\n".as_slice(),
            &effect["project_marker"],
        ),
    ] {
        physical(&artifacts, name, raw, claim)?;
    }
    require(
        control["fixture"]["sha256"] == sha256(fixture)
            && control["fixture"]["bytes"] == fixture.len(),
    )?;
    for key in [
        "file", "bytes", "sha256", "device", "inode", "uid", "gid", "mode",
    ] {
        require(control["fixture"]["project_marker"][key] == effect["project_marker"][key])?;
    }
    for name in ["pre", "sink", "post", "native_hook_count_unchanged"] {
        require(control["measurements"]["replay_refusals"][name] == true)?;
    }
    hooks["process_relations"] = process;
    Ok(
        json!({"schema":"hol-gauntlet-native-readonly-artifact-relations.v1",
        "hook_relations":hooks,"transport_relations":transport,"stream_relations":streams,
        "runtime_image_relations":images,
        "positive_write_input":positive_input,"fixed_readonly_fixture_checked":true,"utility_tests":3,
        "signed_write_refusal_claim_retained":true,"outside_observer_admitted":false,
        "effect_writer_attribution_checked":false,"physical_effect_causality_checked":false,
        "qualified_role_complete":false,"sdk_exercised":false,"execution_eligible":false,
        "guard_causality_verified":false,"model_requests":0}),
    )
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
    let samples = KernelSamples::for_launch(&observed, observer, &preparation["launch"])?;
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
        crate::native_runtime_kernel::verify(control, preparation, &artifacts, &samples, &hooks)
            .map_err(|e| {
                EvidenceError::Context("Native runtime client observations", Box::new(e))
            })?;
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
        "outside_child_death_observed":false,"all_native_runtime_descendants_graded":native_clients["all_native_runtime_descendants_graded"]==true,
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
