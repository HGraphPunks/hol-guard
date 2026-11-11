//! Original-key live recovery never invents controller exit or model usage.
use super::*;
use std::time::Duration;
fn repair_intent(
    i: &Intent,
    generation: &str,
    startup: bool,
    prepared_sha: &str,
) -> Result<Vec<u8>, String> {
    if !hex(generation, 64) {
        return Err("outside live repair generation required".into());
    }
    bytes(
        &json!({"schema":"hol-gauntlet-host-live-repair-intent.v1","job_id":i.job(),"intent_sha256":i.digest()?,"repair_generation":generation,"never_released":startup,"live_prepared_sha256":prepared_sha}),
    )
}
fn authorization(j: &Journal, i: &Intent) -> Result<(String, bool, String), String> {
    let raw = j.read(i.job(), "repair-intent")?;
    let v = parse(&raw)?;
    let generation = text(&v, "repair_generation")?;
    let startup = v["never_released"]
        .as_bool()
        .ok_or("live repair kind absent")?;
    let prepared = provisioned(j, i)?;
    let pin = text(&prepared, "receipt_sha256")?;
    if raw != repair_intent(i, generation, startup, pin)? {
        return Err("outside live repair authorization changed".into());
    }
    Ok((generation.into(), startup, pin.into()))
}
fn verify_repair(j: &Journal, i: &Intent, raw: &[u8]) -> Result<Value, String> {
    let (generation, startup, pin) = authorization(j, i)?;
    let (_, _, prelaunch) = results::host_pins(j, i)?;
    let v = parse(raw)?;
    let cleanup = &v["cleanup"];
    let mut fields = vec![
        "schema",
        "prelaunch",
        "preparation_sha256",
        "repair_generation",
        "status",
        "controller_state",
        "exit_code",
        "model_requests",
        "execution_eligible",
        "guard_causality_verified",
        "cleanup",
        "live_prepared_sha256",
    ];
    if !startup {
        fields.extend([
            "running_marker_sha256",
            "artifact_admitted",
            "qualification_eligible",
        ]);
    }
    if !exact(&v, &fields)
        || v["schema"]
            != if startup {
                "hol-gauntlet-native-live-keyed-pre-controller-repair.v1"
            } else {
                "hol-gauntlet-native-live-keyed-worker-repair.v1"
            }
        || v["prelaunch"]
            != parse(
                &prelaunch
                    .to_bytes()
                    .map_err(|_| "live original prelaunch encoding invalid")?,
            )?
        || v["preparation_sha256"] != i.text("preparation_sha256")
        || v["live_prepared_sha256"] != pin
        || v["repair_generation"] != generation
        || v["status"] != "aborted"
        || v["controller_state"]
            != if startup {
                "never-released"
            } else {
                "released-exit-unavailable"
            }
        || !v["exit_code"].is_null()
        || v["execution_eligible"] != false
        || v["guard_causality_verified"] != false
        || if startup {
            v["model_requests"] != 0
        } else {
            !v["model_requests"].is_null()
                || v["artifact_admitted"] != false
                || v["qualification_eligible"] != false
                || !v["running_marker_sha256"]
                    .as_str()
                    .is_some_and(|s| hex(s, 64))
        }
    {
        return Err("live repair differs from original pins or invents known usage/exit".into());
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
    if required.iter().any(|k| cleanup[*k] != true) {
        return Err("live repair resource absence incomplete".into());
    }
    if startup {
        let untouched = &cleanup["untouched"];
        let world = &untouched["live_world"];
        let prepared = provisioned(j, i)?;
        let bundle = parse(&j.read(i.job(), "prepare-bundle")?)?;
        let workspace = &bundle["preparation"]["task_mounts"]["workspace"];
        if untouched["workspace_empty"] != true
            || untouched["only_preparation_workspace_and_live_custody"] != true
            || untouched["workspace_device"] != workspace["device"]
            || untouched["workspace_inode"] != workspace["inode"]
            || untouched["workspace_uid"] != 10001
            || untouched["workspace_gid"] != 10001
            || world["live_prepared_sha256"] != pin
            || world["world_snapshot_sha256"] != prepared["receipt"]["world_initial_sha256"]
            || world["world_receipt_count"] != 0
            || [
                "world_key_retained",
                "cleanup_key_retained",
                "live_private_inventory_exact",
            ]
            .iter()
            .any(|k| world[*k] != true)
            || world["database"]["uid"] != 0
            || world["database"]["gid"] != 0
            || world["database"]["mode"] != 0o600
            || world["database"]["links"] != 1
        {
            return Err("never-released live World/workspace custody is not pristine".into());
        }
        channel::turn_pins(j, i, 0)?;
    } else if cleanup["image_unmounted"] != true
        || cleanup["active_pointer_absent"] != true
        || !matches!(
            cleanup["quiescent"]["image_history"].as_str(),
            Some("already-closed-v1" | "recovered-pending-v1")
        )
        || !(cleanup["active_pointer_sha256"].is_null()
            || cleanup["active_pointer_sha256"]
                .as_str()
                .is_some_and(|s| hex(s, 64)))
    {
        return Err("released live image history remains uncertain".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-host-live-repair.v1","job_id":i.job(),"source_sha":i.text("source_sha"),"intent_sha256":i.digest()?,"repair_receipt_sha256":sha(raw),"live_prepared_sha256":pin,"repair_generation":generation,"status":"aborted","controller_state":v["controller_state"],"exit_code":null,"model_requests":v["model_requests"],"resource_absence_reported":true,"retry_allowed":false,"execution_eligible":false,"qualification_eligible":false}),
    )
}
pub(super) fn verify_retained_repair(j: &Journal, i: &Intent) -> Result<Value, String> {
    let (generation, startup, pin) = authorization(j, i)?;
    if j.read(i.job(), "repair-dispatch")? != repair_intent(i, &generation, startup, &pin)? {
        return Err("live repair dispatch differs".into());
    }
    verify_repair(j, i, &j.read(i.job(), "repair")?)
}
pub(super) fn repair(
    j: &Journal,
    i: &Intent,
    request: Option<(&str, bool)>,
) -> Result<Value, String> {
    j.require_dispatch(i)?;
    if !j.absent(i.job(), "completion")? {
        return Err("completed live job cannot be repaired; read/report instead".into());
    }
    if let Some((generation, startup)) = request {
        let prepared = provisioned(j, i)?;
        j.retain(
            i.job(),
            "repair-intent",
            &repair_intent(i, generation, startup, text(&prepared, "receipt_sha256")?)?,
        )?;
    }
    let (generation, startup, pin) = authorization(j, i)?;
    let read = !j.absent(i.job(), "repair-dispatch")?;
    let raw_authorization = repair_intent(i, &generation, startup, &pin)?;
    if read {
        if j.read(i.job(), "repair-dispatch")? != raw_authorization {
            return Err("live repair dispatch changed".into());
        }
    } else {
        j.write(i.job(), "repair-dispatch", &raw_authorization)?;
    }
    let (keys, record, _) = results::host_pins(j, i)?;
    let p = &record.pins;
    let mut lima = super::super::transport::Lima::open(i)?;
    let operation = match (startup, read) {
        (true, false) => "--repair-native-live-keyed-pre-controller-v1",
        (true, true) => "--read-native-live-keyed-pre-controller-repair-v1",
        (false, false) => "--repair-native-live-keyed-v1",
        (false, true) => "--read-native-live-keyed-repair-v1",
    };
    let worker = format!("/opt/hol-gauntlet/rust-native-host-pinned-worker-{generation}");
    let child = lima
        .command(i.text("vm"))?
        .args([
            worker.as_str(),
            operation,
            &p.source_sha,
            &p.job_id,
            &p.deployment_digest,
            &p.worker_generation,
            &p.started_marker_sha256,
            &p.controller_key_pin_sha256,
            &p.controller_public_key_hex,
            i.text("preparation_sha256"),
            &generation,
            &pin,
        ])
        .spawn()
        .map_err(|_| "live repair dispatch consumed; read without replay")?;
    let mut accepted = keys
        .bind_native_readback_child(child, &i.expected())
        .map_err(|_| "original live repair pin unavailable")?;
    let raw = accepted
        .wait_bounded_result(Duration::from_secs(90), 8192)
        .map_err(|_| "live repair unknown; retain original dispatch")?;
    lima.recheck()?;
    let raw = raw
        .strip_suffix(b"\n")
        .ok_or("live repair terminal newline required")?;
    let result = verify_repair(j, i, raw)?;
    if keys
        .read(i.job())
        .map_err(|_| "live repair Host pin unavailable")?
        != record
        || authorization(j, i)? != (generation, startup, pin)
    {
        return Err("live repair original Host authorization changed".into());
    }
    j.require_dispatch(i)?;
    j.retain(i.job(), "repair", raw)?;
    Ok(result)
}
