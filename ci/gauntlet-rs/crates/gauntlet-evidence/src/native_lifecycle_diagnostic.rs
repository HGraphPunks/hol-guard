//! Join held child/readiness, actual capture outcome and physical closed state.
//! The outside observer and historical journal still require separate admission.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{
    argv, digest, handoff, ineligible, request_argv, require, text, Artifacts,
};
use crate::native_lifecycle_fixture::{fixture, held_file, readiness};
use crate::native_process_kernel::{list, number, KernelSamples};
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const CANCEL: &str = "controller requested product-cell cancellation after held detached readiness";
const DISPATCH: &str = "controlled SDK sink cancellation after detached readiness";

pub(crate) fn verify(
    control: &Value,
    preparation: &Value,
    artifacts: &Artifacts<'_>,
    samples: &KernelSamples<'_>,
    interpreter: &str,
) -> Result<Value> {
    let role = text(control, "control_role")?;
    let job = text(control, "job_id")?;
    let spec = fixture(role, job)?;
    let life = &control["router"]["lifecycle"];
    ineligible(life)?;
    require(
        life["schema"] == "hol-gauntlet-native-detached-lifecycle.v2"
            && life["role"] == role
            && life["status"] == "passed"
            && life.get("error").is_some_and(Value::is_null)
            && life["detached_child_dead"] == true
            && life["late_effect_absent"] == true,
    )?;
    let observations = list(&control["plane"]["observations"], 10_000)?;
    let reports = observations
        .iter()
        .filter(|r| r["kind"] == "native-detached-lifecycle-control")
        .map(|r| &r["observation"])
        .collect::<Vec<_>>();
    require(reports == [life])?;
    let child = &life["detached_child"];
    let ready = &life["ready"];
    let file = &life["ready_file"];
    readiness(ready, role, job, number(&child["namespace_pid"])?)?;
    held_file(file, ready)?;
    let expected = [
        "/usr/bin/python3".into(),
        "-I".into(),
        "-B".into(),
        "-c".into(),
        spec.code.clone(),
    ];
    require(
        argv(&child["argv"])? == expected
            && child["argv_sha256"] == sha256(format!("{}\0", expected.join("\0")).as_bytes())
            && child["executable_sha256"] == interpreter
            && child["pidfd_held"] == true,
    )?;
    let measured =
        crate::native_product_kernel::matching(samples, child, &expected, interpreter, job)?;
    let parents = list(&child["ancestry"], 64)?;
    require(
        parents.len() >= 2
            && parents[0]["pid"] == child["pid"]
            && parents[0]["start_ticks"] == child["start_ticks"],
    )?;
    let mut seen = BTreeSet::new();
    for parent in parents {
        require(
            seen.insert(number(&parent["pid"])?)
                && number(&parent["pid"])? <= i32::MAX as u64
                && number(&parent["parent_pid"])? <= i32::MAX as u64,
        )?;
        number(&parent["start_ticks"])?;
    }
    for pair in parents.windows(2) {
        require(pair[0]["parent_pid"] == pair[1]["pid"])?;
    }
    let last = parents.last().unwrap();
    let anchors = artifacts
        .events
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r["kind"] == "gated-product-process"
                && r["data"]["identity"]["pid"] == last["pid"]
                && r["data"]["identity"]["start_ticks"] == last["start_ticks"]
        })
        .collect::<Vec<_>>();
    require(anchors.len() == 1)?;
    let anchor = &anchors[0].1["data"]["identity"];
    require(anchor["cgroup"] == child["cgroup"] && anchor["lsm_label"] == child["lsm_label"])?;
    for name in ["mnt", "pid", "net", "user"] {
        require(anchor["namespaces"][name] != child["namespaces"][name])?;
    }
    let handoffs = observations
        .iter()
        .filter(|r| r["kind"] == "native-contained-request-handoff")
        .collect::<Vec<_>>();
    require(handoffs.len() == 1)?;
    let call = handoffs[0];
    let request = &call["request"];
    let raw = canonical_value(
        &json!({"schema":"guard-contained-test-request.v1","workspace":"/runtime/home/project",
        "payload":control["plane"]["hooks"][1]["payload"]}),
    )?;
    handoff(request, &raw)?;
    let mut command = request_argv(
        text(preparation, "runtime_prefix")?,
        text(request, "path")?,
        &sha256(&raw),
    );
    if role == "cancel" {
        *command.last_mut().unwrap() = "30".into();
    }
    let mut gated = vec!["/public/gauntlet-product-cell".into(), "exec-gate".into()];
    gated.extend(command.clone());
    require(
        argv(&anchor["argv"])? == gated
            && call["cleanup_complete"] == true
            && call.get("cleanup_error").is_some_and(Value::is_null)
            && call["capture_error"] == life["capture_error"],
    )?;
    let captures = artifacts
        .events
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r["kind"] == "capture-terminal"
                && r["data"]["argv_sha256"] == sha256(command.join("\0").as_bytes())
        })
        .collect::<Vec<_>>();
    require(captures.len() == 1 && captures[0].0 > anchors[0].0)?;
    let capture = &captures[0].1["data"];
    require(
        capture["returncode"] == life["capture_exit_code"]
            && capture["error"] == life["capture_error"],
    )?;
    if role == "cancel" {
        require(
            life.get("capture_exit_code").is_some_and(Value::is_null)
                && life["capture_error"] == CANCEL
                && life["cancel_requested_after_kernel_readiness"] == true
                && life["product_cell_closed"] == true
                && control["plane"]["executions"] == json!([])
                && control["measurements"].get("sdk").is_none(),
        )?;
        let abort = &control["measurements"]["controlled_sdk_abort"];
        require(
            abort["dispatch_error"] == DISPATCH
                && abort["actual_sdk_result_available"] == false
                && abort["post_tool_use_available"] == false,
        )?;
        let requests = list(&control["requests"], 3)?;
        require(
            requests.len() == 2
                && requests[1]["dispatch_error"] == DISPATCH
                && requests[1].get("response").is_none()
                && requests[1].get("response_sha256").is_none()
                && requests[1]["peer_rechecked_before_response"] == false,
        )?;
    } else {
        require(
            life["capture_exit_code"].as_i64() == Some(124)
                && life.get("capture_error").is_some_and(Value::is_null)
                && life["cancel_requested_after_kernel_readiness"] == false
                && life["product_cell_closed"] == false,
        )?;
    }
    let mut ready_samples = 0;
    for row in &measured {
        require(row["parent_pid"] == parents[0]["parent_pid"])?;
        let view = &row["synthetic_lifecycle_view"];
        let directory = &child["workspace_view"];
        require(
            view["cwd"] == "/runtime/home/project"
                && directory["path"] == view["cwd"]
                && directory["source"] == "kernel-held-process-cwd.v1",
        )?;
        for name in ["device", "inode", "uid", "gid", "mode"] {
            require(
                view["directory"].get(name).is_some() && view["directory"][name] == directory[name],
            )?;
        }
        require(
            directory["uid"].as_u64() == Some(10004)
                && directory["gid"].as_u64() == Some(10004)
                && directory["mode"].as_u64() == Some(0o700),
        )?;
        number(&directory["device"])?;
        number(&directory["inode"])?;
        let files = view["files"]
            .as_object()
            .ok_or(EvidenceError::Invalid("held lifecycle files missing"))?;
        require(
            files.len() == 3
                && files.contains_key("detached-ready.json")
                && files.contains_key("detached-ready.pending")
                && files
                    .get("late-detached-effect.txt")
                    .is_some_and(Value::is_null),
        )?;
        let seen = &files["detached-ready.json"];
        if !seen.is_null() {
            for name in ["device", "inode", "uid", "gid", "mode", "sha256", "utf8"] {
                require(seen.get(name).is_some() && seen[name] == file[name])?;
            }
            require(
                seen["links"].as_u64() == Some(1) && files["detached-ready.pending"].is_null(),
            )?;
            ready_samples += 1;
        }
    }
    require(ready_samples > 0)?;
    let fixture = &control["fixture"];
    require(
        artifacts.raw("combined/workspace/tests/test_control.py")? == spec.body.as_bytes()
            && fixture["schema"] == "hol-gauntlet-native-contained-fixture.v6"
            && fixture["file"] == "tests/test_control.py"
            && fixture["sha256"] == sha256(spec.body.as_bytes())
            && fixture["bytes"].as_u64() == Some(spec.body.len() as u64)
            && fixture["lifecycle_role"] == role
            && fixture["detached_token"] == spec.token
            && fixture["detached_code_sha256"] == sha256(spec.code.as_bytes())
            && fixture["product_code_executed"] == false,
    )?;
    let effect = &control["effect"];
    ineligible(effect)?;
    require(
        effect["schema"] == "hol-gauntlet-native-closed-lifecycle.v2"
            && effect["control_sha256"] == digest(life)?
            && effect["detached_child_dead"] == true
            && effect["late_effect_absent"] == true
            && effect["physical_lower_lifecycle_paths_absent"] == true,
    )?;
    held_file(&effect["ready_file"], ready)?;
    for name in [
        "device", "inode", "sha256", "utf8", "bytes", "uid", "gid", "mode",
    ] {
        require(effect["ready_file"][name] == file[name])?;
    }
    require(effect["ready_file"]["final_links"].as_u64() <= file["final_links"].as_u64())?;
    let physical = artifacts.json("combined/physical-lifecycle-absence.json")?;
    require(
        physical
            == json!({"schema":"hol-gauntlet-native-lifecycle-absence.v1",
            "absent":["detached-ready.json","detached-ready.pending","late-detached-effect.txt"],
            "execution_eligible":false,"model_requests":0}),
    )?;
    let input =
        crate::verify_native_capture_input(&artifacts.events, captures[0].0, &command, b"")?;
    Ok(
        json!({"schema":"hol-gauntlet-native-lifecycle-artifact-relations.v1","role":role,
        "compiled_fixture_checked":true,"actual_child_kernel_samples":measured.len(),"ready_generation_samples":ready_samples,
        "native_cli_ancestry_checked":true,"held_ready_generation_checked":true,"closed_effect_relation_checked":true,
        "root_reported_child_death":true,"outside_child_death_observed":false,
        "actual_timeout_capture_checked":role=="timeout","missing_cancel_result_and_post_preserved":role=="cancel",
        "contained_sink_input":input,"independent_process_custody_checked":false,
        "qualified_role_complete":false,"outside_signing_key_admitted":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}
