//! Fixed Lima transport and keyed quiescent recovery for the normal host CLI.
//! Remote output is private until the signature/identity readers accept it.
pub(super) use super::context::Lima;
use super::{bytes, hex, sha, Intent, Journal};
use crate::{HostControllerKeyPinJournal, HostKeyPinRecord};
use gauntlet_contracts::{PrelaunchPrepared, WorkerRequest};
use serde_json::{json, Value};
use std::time::Duration;

pub(crate) fn observe_native_job(
    path: &std::path::Path,
    job: &str,
    expected: &str,
) -> Result<Value, String> {
    let j = Journal::open(path)?;
    let i = j.intent(job)?;
    if !hex(expected, 64) || i.digest()? != expected {
        return Err("original Native attachment intent differs".into());
    }
    super::context::TransportContext::parse(&i.0["transport_context"])?;
    let reference = json!({"schema":"hol-gauntlet-host-operation-reference.v1","operation":"native","job_id":job,"source_sha":i.text("source_sha"),
        "intent_sha256":expected,"vm":i.text("vm"),"transport_context":i.0["transport_context"],"deployment_digest":i.text("deployment_digest"),"source_binding_sha256":null});
    type Phase = (
        &'static str,
        &'static str,
        Option<String>,
        Option<String>,
        Option<u64>,
    );
    let observed = (|| -> Result<Phase, String> {
        if !j.absent(job, "initialize-abort-intent")? {
            super::preparation::verify_idle_record(
                &j,
                &Journal::name(job, "initialize-abort-intent")?,
            )?;
            return Ok((
                "invalid-evidence",
                "aborted-unstarted",
                Some(sha(&j.read(job, "initialize-abort-result")?)),
                None,
                None,
            ));
        }
        super::preparation::retained_storage(&j, &i)?;
        if !j.absent(job, "storage-retirement-intent")? {
            super::public_export::verify_retirement_idle_record(
                &j,
                &Journal::name(job, "storage-retirement-intent")?,
            )?;
            return Ok((
                "invalid-evidence",
                "storage-retired",
                Some(sha(&j.read(job, "storage-retirement-result")?)),
                Some(sha(&j.read(job, "completion")?)),
                None,
            ));
        }
        if !j.absent(job, "dispatch")? {
            j.require_dispatch(&i)?;
            if !j.absent(job, "repair-intent")? {
                let repaired = if i.is_live() {
                    super::live::verify_retained_repair(&j, &i)?
                } else {
                    verify_retained_repair(&j, &i)?
                };
                return Ok((
                    "invalid-evidence",
                    "repaired",
                    Some(sha(&j.read(job, "repair")?)),
                    None,
                    repaired["model_requests"].as_u64(),
                ));
            }
            let raw = j.read(job, "completion")?;
            let verified = j.verify(&i, &raw)?;
            return Ok((
                "invalid-evidence",
                "completed",
                Some(
                    verified.observation()["host_pin_sha256"]
                        .as_str()
                        .ok_or("Native pin absent")?
                        .into(),
                ),
                Some(sha(&raw)),
                verified.observation()["model_requests"].as_u64(),
            ));
        }
        if !j.absent(job, "prepare-dispatch")? {
            super::preparation::require_prepared(&j, &i)?;
            return Ok((
                "waiting",
                "prepared",
                Some(sha(&j.read(job, "prepare-result")?)),
                None,
                None,
            ));
        }
        Ok(("waiting", "recorded", None, None, None))
    })();
    j.stable()?;
    let (state, phase, authority, completion, model) =
        observed.unwrap_or(("unknown", "reconciliation-required", None, None, None));
    Ok(crate::observer_runtime::operation_projection(
        reference, state, phase, authority, completion, model, None,
    ))
}

fn pin(
    journal: &Journal,
    intent: &Intent,
) -> Result<(HostControllerKeyPinJournal, HostKeyPinRecord), String> {
    let keys = HostControllerKeyPinJournal::open(&journal.path).map_err(|e| e.to_string())?;
    let record = keys.read(intent.job()).map_err(|e| e.to_string())?;
    if record.pins.source_sha != intent.text("source_sha")
        || record.pins.deployment_digest != intent.text("deployment_digest")
        || record.pins.worker_generation != intent.text("worker_generation")
    {
        return Err("native retained Host pin differs from original intent".into());
    }
    Ok((keys, record))
}

pub(super) fn execute(
    journal: &Journal,
    intent: &Intent,
    lima: &mut Lima,
    run: bool,
) -> Result<Vec<u8>, String> {
    journal.require_dispatch(intent)?;
    let keys = HostControllerKeyPinJournal::open(&journal.path).map_err(|e| e.to_string())?;
    match (run, keys.read(intent.job())) {
        (true, Err(crate::HostKeyPinError::Missing)) => {}
        (true, _) => {
            return Err("native Host pin already exists or is uncertain; never rerun".into())
        }
        (false, _) => {
            pin(journal, intent)?;
        }
    }
    let mut value = json!({"schema":"hol-gauntlet-worker-request.v1","action":if run {"run"}else{"reconcile"},"source_sha":intent.text("source_sha"),"job_id":intent.job()});
    if run {
        value["deployment_digest"] = json!(intent.text("deployment_digest"));
    }
    let request = WorkerRequest::parse(&bytes(&value)?).map_err(|e| e.to_string())?;
    let worker = format!(
        "/opt/hol-gauntlet/rust-native-host-pinned-worker-{}",
        intent.text("worker_generation")
    );
    let child = lima
        .command(intent.text("vm"))?
        .args([
            worker.as_str(),
            if run {
                "--native-host-pinned-v1"
            } else {
                "--read-native-host-pinned-v1"
            },
            intent.text("source_sha"),
            intent.text("deployment_digest"),
            intent.text("worker_generation"),
        ])
        .spawn()
        .map_err(|_| {
            "native VM transport unavailable; dispatch consumed, reconcile without retry"
        })?;
    let expected = intent.expected();
    let mut accepted = if run {
        keys.send_native_run_request_and_accept_prepared_child(
            child,
            &request,
            &expected,
            Duration::from_secs(210),
        )
    } else {
        keys.send_native_readback_request_and_bind_child(
            child,
            &request,
            &expected,
            Duration::from_secs(60),
        )
    }
    .map_err(|e| {
        format!(
            "native transport refused: {}; dispatch consumed, reconcile without retry",
            e.reason
        )
    })?;
    let output = accepted
        .wait_bounded_native_completion(Duration::from_secs(if run { 420 } else { 60 }))
        .map_err(|e| format!("native completion uncertain; retain consumed job: {e}"))?;
    lima.recheck()?;
    if keys.read(intent.job()).map_err(|e| e.to_string())? != *accepted.record() {
        return Err("native Host pin changed during transport".into());
    }
    journal.require_dispatch(intent)?;
    Ok(output)
}

fn prepared(record: &HostKeyPinRecord) -> PrelaunchPrepared {
    let p = &record.pins;
    PrelaunchPrepared {
        job_id: p.job_id.clone(),
        source_sha: p.source_sha.clone(),
        deployment_digest: p.deployment_digest.clone(),
        worker_generation: p.worker_generation.clone(),
        started_marker_sha256: p.started_marker_sha256.clone(),
        controller_key_pin_sha256: p.controller_key_pin_sha256.clone(),
        controller_public_key_hex: p.controller_public_key_hex.clone(),
    }
}
pub(super) fn repair_intent(
    intent: &Intent,
    generation: &str,
    startup: bool,
) -> Result<Vec<u8>, String> {
    if !hex(generation, 64) {
        return Err("exact native repair generation required".into());
    }
    bytes(
        &json!({"schema":"hol-gauntlet-host-native-repair-intent.v1","job_id":intent.job(),"intent_sha256":intent.digest()?,
        "repair_generation":generation,"never_released":startup}),
    )
}
fn authorization(journal: &Journal, intent: &Intent) -> Result<(String, bool), String> {
    let raw = journal.read(intent.job(), "repair-intent")?;
    let value: Value =
        serde_json::from_slice(&raw).map_err(|_| "native repair authorization invalid")?;
    let generation = value["repair_generation"]
        .as_str()
        .ok_or("native repair generation absent")?;
    let startup = value["never_released"]
        .as_bool()
        .ok_or("native repair kind absent")?;
    if raw != repair_intent(intent, generation, startup)? {
        return Err("native repair authorization differs".into());
    }
    Ok((generation.into(), startup))
}
pub(super) fn verify_repair(
    journal: &Journal,
    intent: &Intent,
    raw: &[u8],
) -> Result<Value, String> {
    let (_, record) = pin(journal, intent)?;
    let (generation, startup) = authorization(journal, intent)?;
    let value: Value = serde_json::from_slice(raw).map_err(|_| "native repair receipt invalid")?;
    let cleanup = &value["cleanup"];
    let prelaunch: Value =
        serde_json::from_slice(&prepared(&record).to_bytes().map_err(|e| e.to_string())?)
            .map_err(|_| "native prelaunch encoding invalid")?;
    let expected_schema = if startup {
        "hol-gauntlet-native-keyed-pre-controller-repair.v1"
    } else {
        "hol-gauntlet-native-keyed-worker-repair.v1"
    };
    let expected_fields = if startup { 11 } else { 14 };
    if raw != bytes(&value)?
        || value.as_object().is_none_or(|o| o.len() != expected_fields)
        || value["schema"] != expected_schema
        || value["prelaunch"] != prelaunch
        || value["preparation_sha256"] != intent.text("preparation_sha256")
        || value["repair_generation"] != generation
        || value["status"] != "aborted"
        || value["controller_state"]
            != if startup {
                "never-released"
            } else {
                "released-exit-unavailable"
            }
        || !value.get("exit_code").is_some_and(Value::is_null)
        || value["model_requests"].as_u64() != Some(0)
        || value["execution_eligible"] != false
        || value["guard_causality_verified"] != false
    {
        return Err("native repair receipt differs from original keyed authorization".into());
    }
    let required = if startup {
        &[
            "controller_marker_absent",
            "controller_logs_absent",
            "controller_cgroup_absent",
            "product_slice_absent",
            "product_stage_absent",
            "sdk_container_and_profile_absent",
            "mcp_container_and_profile_absent",
            "image_lease_absent",
            "public_key_retained",
        ][..]
    } else {
        &[
            "controller_process_absent",
            "controller_cgroup_absent",
            "product_slice_absent",
            "sdk_agent_absent",
            "sdk_profile_absent",
            "mcp_agent_absent",
            "mcp_profile_absent",
            "image_lease_absent",
            "public_key_retained",
        ][..]
    };
    if cleanup.as_object().is_none()
        || required.iter().any(|k| cleanup[*k] != true)
        || (!startup
            && (!value["running_marker_sha256"]
                .as_str()
                .is_some_and(|s| hex(s, 64))
                || value["artifact_admitted"] != false
                || value["qualification_eligible"] != false))
    {
        return Err("native repair lacks verified resource absence".into());
    }
    if startup {
        if cleanup["untouched"]["workspace_empty"] != true
            || cleanup["untouched"]["only_preparation_and_workspace"] != true
        {
            return Err("never-released repair lacks untouched workspace custody".into());
        }
    } else {
        let quiescent = &cleanup["quiescent"];
        if cleanup["image_unmounted"] != true
            || cleanup["active_pointer_absent"] != true
            || !matches!(
                quiescent["image_history"].as_str(),
                Some("already-closed-v1" | "recovered-pending-v1")
            )
            || !(cleanup
                .get("active_pointer_sha256")
                .is_some_and(Value::is_null)
                || cleanup["active_pointer_sha256"]
                    .as_str()
                    .is_some_and(|s| hex(s, 64)))
        {
            return Err("native repair image history remains uncertain".into());
        }
    }
    Ok(
        json!({"schema":"hol-gauntlet-host-deterministic-repair.v1","job_id":intent.job(),"source_sha":intent.text("source_sha"),
        "intent_sha256":intent.digest()?,"repair_receipt_sha256":sha(raw),"repair_generation":generation,
        "status":"aborted","controller_state":value["controller_state"],"exit_code":null,
        "resource_absence_reported":true,"retry_allowed":false,"execution_eligible":false,"qualification_eligible":false,"model_requests":0}),
    )
}
pub(super) fn verify_retained_repair(journal: &Journal, intent: &Intent) -> Result<Value, String> {
    let (generation, startup) = authorization(journal, intent)?;
    if journal.read(intent.job(), "repair-dispatch")?
        != repair_intent(intent, &generation, startup)?
    {
        return Err("native repair dispatch differs".into());
    }
    verify_repair(journal, intent, &journal.read(intent.job(), "repair")?)
}
pub(super) fn repair(
    journal: &Journal,
    intent: &Intent,
    generation: &str,
    startup: bool,
) -> Result<Value, String> {
    journal.require_dispatch(intent)?;
    if !journal.absent(intent.job(), "completion")? {
        return Err("completed native job cannot be repaired; use read/report".into());
    }
    let mut lima = Lima::open(intent)?;
    pin(journal, intent)?;
    journal.retain(
        intent.job(),
        "repair-intent",
        &repair_intent(intent, generation, startup)?,
    )?;
    if !journal.absent(intent.job(), "repair-dispatch")? {
        return repair_transport(journal, intent, &mut lima, true);
    }
    journal.write(
        intent.job(),
        "repair-dispatch",
        &repair_intent(intent, generation, startup)?,
    )?;
    repair_transport(journal, intent, &mut lima, false)
}
pub(super) fn read_repair(journal: &Journal, intent: &Intent) -> Result<Value, String> {
    let mut lima = Lima::open(intent)?;
    repair_transport(journal, intent, &mut lima, true)
}
fn repair_transport(
    journal: &Journal,
    intent: &Intent,
    lima: &mut Lima,
    read: bool,
) -> Result<Value, String> {
    journal.require_dispatch(intent)?;
    let (generation, startup) = authorization(journal, intent)?;
    if journal.read(intent.job(), "repair-dispatch")?
        != repair_intent(intent, &generation, startup)?
    {
        return Err("native repair dispatch differs; preserve uncertain state".into());
    }
    let (keys, record) = pin(journal, intent)?;
    let p = &record.pins;
    let worker = format!("/opt/hol-gauntlet/rust-native-host-pinned-worker-{generation}");
    let operation = match (startup, read) {
        (true, false) => "--repair-native-keyed-pre-controller-v1",
        (true, true) => "--read-native-keyed-pre-controller-repair-v1",
        (false, false) => "--repair-native-keyed-v1",
        (false, true) => "--read-native-keyed-repair-v1",
    };
    let child = lima
        .command(intent.text("vm"))?
        .args([
            &worker,
            operation,
            &p.source_sha,
            &p.job_id,
            &p.deployment_digest,
            &p.worker_generation,
            &p.started_marker_sha256,
            &p.controller_key_pin_sha256,
            &p.controller_public_key_hex,
            intent.text("preparation_sha256"),
            &generation,
        ])
        .spawn()
        .map_err(|_| "native repair transport unavailable; authorization retained")?;
    let mut accepted = keys
        .bind_native_readback_child(child, &intent.expected())
        .map_err(|e| e.reason.to_string())?;
    let output = accepted
        .wait_bounded_result(Duration::from_secs(90), 8192)
        .map_err(|_| "native repair unknown; retain authorization and read without rerunning")?;
    lima.recheck()?;
    let raw = output
        .strip_suffix(b"\n")
        .ok_or("native repair response newline required")?;
    let result = verify_repair(journal, intent, raw)?;
    if keys.read(intent.job()).map_err(|e| e.to_string())? != record
        || authorization(journal, intent)? != (generation, startup)
    {
        return Err("native repair Host pin or authorization changed".into());
    }
    journal.require_dispatch(intent)?;
    journal.retain(intent.job(), "repair", raw)?;
    Ok(result)
}
