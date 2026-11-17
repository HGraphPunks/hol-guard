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

const CREATED: &str = "live-created-repair-intent";
const CREATED_DISPATCH: &str = "live-created-repair-dispatch";
const CREATED_RECEIPT: &str = "live-created-repair";
const CREATED_FIELDS: [&str; 13] = [
    "source_sha",
    "job_id",
    "deployment_digest",
    "worker_generation",
    "preparation_sha256",
    "live_prepared_sha256",
    "storage_receipt_sha256",
    "host_pin_sha256",
    "container_id",
    "creation_sha256",
    "inspection_sha256",
    "policy_sha256",
    "repair_generation",
];
pub(super) fn created_context(j: &Journal, i: &Intent, pins: &Value) -> Result<Value, String> {
    if !i.is_live() || j.intent(i.job())? != *i || !j.absent(i.job(), "completion")? {
        return Err("original consumed unknown Live job required".into());
    }
    j.require_dispatch(i)?;
    preparation::require_prepared(j, i)?;
    let live = provisioned(j, i)?;
    let storage =
        preparation::retained_storage(j, i)?.ok_or("original bounded Live storage required")?;
    let (_, record, prelaunch) = results::host_pins(j, i)?;
    if prelaunch.host_record_sha256().map_err(|e| e.to_string())? != record.raw_sha256 {
        return Err("original Live Host pin digest differs".into());
    }
    let mut expected = json!({"source_sha":i.text("source_sha"),"job_id":i.job(),"deployment_digest":i.text("deployment_digest"),"worker_generation":i.text("worker_generation"),
        "preparation_sha256":i.text("preparation_sha256"),"live_prepared_sha256":live["receipt_sha256"],"storage_receipt_sha256":storage["receipt_sha256"],"host_pin_sha256":record.raw_sha256});
    for k in [
        "container_id",
        "creation_sha256",
        "inspection_sha256",
        "policy_sha256",
        "repair_generation",
    ] {
        let v = text(pins, k)?;
        if !hex(v, 64) {
            return Err("outside original created-container pins required".into());
        }
        expected[k] = json!(v);
    }
    if *pins != expected {
        return Err("original Live created-repair pins differ".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-host-native-live-created-repair-intent.v1","native_intent_sha256":i.digest()?,"pins":pins,
        "prelaunch":parse(&prelaunch.to_bytes().map_err(|e|e.to_string())?)?,"parent_custody":context::snapshot(&j.path)?}),
    )
}
pub(super) fn created_result(f: &Value, raw: &[u8]) -> Result<Value, String> {
    let v = parse(raw)?;
    let intent = text(&v, "intent_sha256")?;
    if !hex(intent, 64) {
        return Err("Root created-repair intent SHA required".into());
    }
    let expected = json!({"schema":"hol-gauntlet-native-live-sdk-created-repair.v1","intent_sha256":intent,
        "pins_sha256":sha(&bytes(&f["pins"])?),"container_id_sha256":sha(text(&f["pins"],"container_id")?.as_bytes()),
        "sdk_agent_absent":true,"sdk_profile_absent":true,"process_signalled":false,"image_adopted":false,"job_terminal_written":false,
        "model_requests":null,"exit_code":null,"execution_eligible":false,"qualification_eligible":false});
    if v != expected {
        return Err("Root Live created repair differs or invents usage/exit".into());
    }
    Ok(v)
}
pub(super) fn created_finish(
    j: &Journal,
    i: &Intent,
    f: &Value,
    action: &str,
    mut call: impl FnMut(bool) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    let raw = bytes(f)?;
    if j.read(i.job(), CREATED)? != raw {
        return Err("original Live created-repair intent changed".into());
    }
    let dispatch = bytes(
        &json!({"schema":"hol-gauntlet-host-live-created-repair-dispatch.v1","intent_sha256":sha(&raw),"retry_allowed":false}),
    )?;
    if j.absent(i.job(), CREATED_DISPATCH)? {
        if action == "failure-created-read" {
            return Err("original Live created-repair dispatch absent".into());
        }
        j.write(i.job(), CREATED_DISPATCH, &dispatch)?;
    }
    if j.read(i.job(), CREATED_DISPATCH)? != dispatch {
        return Err("original Live created-repair dispatch differs".into());
    }
    let receipt = if j.absent(i.job(), CREATED_RECEIPT)? {
        let received = if action == "failure-created-repair" {
            call(false)?
        } else {
            match call(true) {
                Ok(v) => v,
                Err(_) if action == "failure-created-resume" => call(false)?,
                Err(e) => return Err(e),
            }
        };
        j.retain(
            i.job(),
            &format!("live-created-repair-frame-{}", sha(&received)),
            &received,
        )?;
        let v = created_result(f, &received)?;
        if created_context(j, i, &f["pins"])? != *f
            || j.read(i.job(), CREATED_DISPATCH)? != dispatch
        {
            return Err("Live created-repair custody changed".into());
        }
        j.write(i.job(), CREATED_RECEIPT, &bytes(&v)?)?;
        v
    } else {
        created_result(f, &j.read(i.job(), CREATED_RECEIPT)?)?
    };
    Ok(
        json!({"schema":"hol-gauntlet-host-native-live-created-repair.v1","job_id":i.job(),"source_sha":i.text("source_sha"),"native_intent_sha256":i.digest()?,
        "created_repair_intent_sha256":sha(&raw),"created_repair_receipt_sha256":sha(&bytes(&receipt)?),"sdk_metadata_absence_reported":true,
        "process_signalled":false,"job_terminal_written":false,"retry_allowed":false,"model_requests":null,"exit_code":null,"execution_eligible":false,"qualification_eligible":false}),
    )
}
pub(super) fn created_command(args: &[String]) -> Result<Value, String> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("Live created-repair action absent")?;
    if !matches!(
        (action, args.len()),
        ("failure-created-repair", 9) | ("failure-created-read" | "failure-created-resume", 4)
    ) || !hex(&args[2], 16)
        || !hex(&args[3], 64)
    {
        return Err("failure-created-repair J JOB INTENT REPAIRER CID CREATION_SHA INSPECTION_SHA POLICY_SHA; failure-created-read|failure-created-resume J JOB INTENT".into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let i = j.intent(&args[2])?;
    if !i.is_live() || i.digest()? != args[3] {
        return Err("outside original Live intent SHA differs".into());
    }
    let f = if action == "failure-created-repair" {
        for s in [
            CREATED,
            CREATED_DISPATCH,
            CREATED_RECEIPT,
            "repair-intent",
            "repair-dispatch",
            "repair",
        ] {
            if !j.absent(i.job(), s)? {
                return Err("Live created repair consumed or normal repair already requested; use original read/resume".into());
            }
        }
        let mut p = json!({"container_id":args[5],"creation_sha256":args[6],"inspection_sha256":args[7],"policy_sha256":args[8],"repair_generation":args[4]});
        let live = provisioned(&j, &i)?;
        let storage = preparation::retained_storage(&j, &i)?
            .ok_or("original bounded Live storage required")?;
        let (_, record, _) = results::host_pins(&j, &i)?;
        for (k, v) in [
            ("source_sha", json!(i.text("source_sha"))),
            ("job_id", json!(i.job())),
            ("deployment_digest", json!(i.text("deployment_digest"))),
            ("worker_generation", json!(i.text("worker_generation"))),
            ("preparation_sha256", json!(i.text("preparation_sha256"))),
            ("live_prepared_sha256", live["receipt_sha256"].clone()),
            ("storage_receipt_sha256", storage["receipt_sha256"].clone()),
            ("host_pin_sha256", json!(record.raw_sha256)),
        ] {
            p[k] = v;
        }
        let f = created_context(&j, &i, &p)?;
        j.write(i.job(), CREATED, &bytes(&f)?)?;
        f
    } else {
        let f = parse(&j.read(i.job(), CREATED)?)?;
        if created_context(&j, &i, &f["pins"])? != f {
            return Err("original Live created-repair context changed".into());
        }
        f
    };
    let mut lima = super::super::transport::Lima::open(&i)?;
    created_finish(&j, &i, &f, action, |read| {
        let p = &f["pins"];
        let generation = text(p, "repair_generation")?;
        let mut command = lima.command(i.text("vm"))?;
        command
            .arg(format!(
                "/opt/hol-gauntlet/rust-native-host-pinned-worker-{generation}"
            ))
            .arg(if read {
                "--read-native-live-sdk-created-repair-v1"
            } else {
                "--repair-native-live-sdk-created-v1"
            });
        for k in CREATED_FIELDS {
            command.arg(text(p, k)?);
        }
        let raw = crate::stream_process::run_streamed_command(
            command,
            b"",
            Duration::from_secs(1020),
            8193,
        )
        .map_err(|_| {
            "Live created repair uncertain; retain original intent and use exact read/resume"
        })?;
        lima.recheck()?;
        Ok(raw)
    })
}
pub(super) fn verify_created_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    if let Some((job, _)) = name
        .split_once(".native-live-created-repair")
        .filter(|(job, _)| hex(job, 16))
    {
        let i = j.intent(job)?;
        let f = parse(&j.read(job, CREATED)?)?;
        if created_context(j, &i, &f["pins"])? != f {
            return Err("orphan Live created-repair context blocks new work".into());
        }
        let dispatch = bytes(
            &json!({"schema":"hol-gauntlet-host-live-created-repair-dispatch.v1","intent_sha256":sha(&bytes(&f)?),"retry_allowed":false}),
        )?;
        if j.read(job, CREATED_DISPATCH)? != dispatch {
            return Err("unknown Live created-repair dispatch blocks new work".into());
        }
        created_result(&f, &j.read(job, CREATED_RECEIPT)?)?;
    }
    Ok(())
}
