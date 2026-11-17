//! A signed failed Live controller plus original repair, never an outer completion.
use super::*;
use crate::native_operation::live as campaign;
use gauntlet_evidence::{verify_native_control_envelope, NativeControlReportPins};
pub(super) const BASE: [&str; 11] = [
    "source_sha",
    "job_id",
    "deployment_digest",
    "original_worker_generation",
    "preparation_sha256",
    "storage_receipt_sha256",
    "live_prepared_sha256",
    "created_repair_sha256",
    "repair_sha256",
    "signed_envelope_sha256",
    "reader_generation",
];
pub(super) const USAGE:&str="Live failure custody: failure-record PRIVATE_JOURNAL JOB ORIGINAL_LIVE_INTENT_SHA READER_SHA; failure-download|failure-download-read|failure-download-resume|failure-ack|failure-ack-read|failure-ack-resume PRIVATE_JOURNAL JOB FAILURE_INTENT_SHA; failure-retire PRIVATE_JOURNAL JOB FAILURE_INTENT_SHA RETIRER_SHA; failure-retire-read|failure-retire-resume PRIVATE_JOURNAL JOB FAILURE_INTENT_SHA. Only original bounded v9 signed failures with exact never-started SDK repair and normal released Live repair are supported. Original Host ACK and private actual archive bytes remain required. No completion, controller exit, model usage or qualification is invented; no replay or quota reset.";
fn context(j: &Journal, i: &Intent, reader: &str) -> Result<Value, String> {
    require(i.is_live() && hex(reader, 64) && j.intent(i.job())? == *i)?;
    j.require_dispatch(i)?;
    for suffix in [
        "completion",
        "return",
        "export-dispatch",
        "storage-retirement-intent",
        "readonly-failure-intent",
    ] {
        require(j.absent(i.job(), suffix)?)?;
    }
    let normal = preparation::require_prepared(j, i)?;
    let storage = preparation::retained_storage(j, i)?
        .ok_or("original bounded Live initialization required")?;
    campaign::verify_retained_repair(j, i)?;
    let repair = parse(&j.read(i.job(), "repair")?)?;
    require(
        repair["controller_state"] == "released-exit-unavailable"
            && repair["model_requests"].is_null()
            && repair["exit_code"].is_null(),
    )?;
    campaign::verify_idle_record(
        j,
        &format!("{}.native-live-created-repair-intent.json", i.job()),
    )?;
    let created = parse(&j.read(i.job(), "live-created-repair")?)?;
    let live = parse(&j.read(i.job(), "live-prepared")?)?;
    let keys = HostControllerKeyPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    let record = keys.read(i.job()).map_err(|e| e.to_string())?;
    let p = &record.pins;
    require(
        p.source_sha == i.text("source_sha")
            && p.job_id == i.job()
            && p.deployment_digest == i.text("deployment_digest")
            && p.worker_generation == i.text("worker_generation"),
    )?;
    let pre = PrelaunchPrepared {
        source_sha: p.source_sha.clone(),
        job_id: p.job_id.clone(),
        deployment_digest: p.deployment_digest.clone(),
        worker_generation: p.worker_generation.clone(),
        started_marker_sha256: p.started_marker_sha256.clone(),
        controller_key_pin_sha256: p.controller_key_pin_sha256.clone(),
        controller_public_key_hex: p.controller_public_key_hex.clone(),
    };
    require(pre.host_record_sha256().map_err(|e| e.to_string())? == record.raw_sha256)?;
    let initial = parse(&j.read(i.job(), "initialize-result")?)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-native-live-failure-intent.v1","source_sha":i.text("source_sha"),"job_id":i.job(),"deployment_digest":i.text("deployment_digest"),"original_worker_generation":i.text("worker_generation"),"preparation_sha256":i.text("preparation_sha256"),"storage_receipt_sha256":storage["receipt_sha256"],"live_prepared_sha256":live["receipt_sha256"],"created_repair_sha256":sha(&bytes(&created)?),"repair_sha256":sha(&bytes(&repair)?),"reader_generation":reader,
        "prelaunch":parse(&pre.to_bytes().map_err(|e|e.to_string())?)?,"host_pin_sha256":record.raw_sha256,"native_intent_sha256":i.digest()?,"initialization_sha256":initial["receipt_sha256"],"preparation_receipt_sha256":normal["receipt_sha256"],"formatter_sha256":storage["receipt"]["mke2fs_sha256"],"created_host_context_sha256":sha(&j.read(i.job(),"live-created-repair-intent")?),"parent_custody":context::snapshot(&j.path)?}),
    )
}
fn observed(j: &Journal, i: &Intent, mut f: Value, o: &Value) -> Result<Value, String> {
    let pre = PrelaunchPrepared::parse(&bytes(&f["prelaunch"])?).map_err(|e| e.to_string())?;
    let live = parse(&j.read(i.job(), "live-prepared")?)?;
    let repair = parse(&j.read(i.job(), "repair")?)?;
    let raw = text(o, "signed_envelope_utf8")?.as_bytes();
    require(!raw.is_empty() && raw.len() <= 32768 && o["signed_envelope_sha256"] == sha(raw))?;
    let signed = verify_native_control_envelope(
        raw,
        &NativeControlReportPins {
            prelaunch: pre.clone(),
            preparation_sha256: i.text("preparation_sha256").into(),
            role: i.text("role").into(),
        },
    )
    .map_err(|_| "original signed Live failure differs from Host pin")?;
    require(
        signed.report()["status"] == "failed"
            && signed.report()["error"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            && signed.report()["controller_identity"] == o["controller"],
    )?;
    f["signed_envelope_sha256"] = json!(sha(raw));
    let mut expected = base(&f, "hol-gauntlet-native-live-failure-observation.v1");
    for (k, v) in [
        ("prelaunch", f["prelaunch"].clone()),
        ("live_prepared", live["receipt"].clone()),
        ("controller", signed.report()["controller_identity"].clone()),
        ("signed_envelope_utf8", o["signed_envelope_utf8"].clone()),
        ("stderr_sha256", o["stderr_sha256"].clone()),
        ("records_sha256", o["records_sha256"].clone()),
        ("quiescent", repair["cleanup"].clone()),
        ("model_requests", Value::Null),
        ("exit_code", Value::Null),
        ("execution_eligible", json!(false)),
        ("qualification_eligible", json!(false)),
    ] {
        expected[k] = v;
    }
    let hashes = &o["records_sha256"];
    require(
        *o == expected
            && exact(
                hashes,
                &["started", "controller-key", "running", "native-repair"],
            )
            && hashes["started"] == pre.started_marker_sha256
            && hashes["controller-key"] == pre.controller_key_pin_sha256
            && hashes["running"] == repair["running_marker_sha256"]
            && hashes["native-repair"] == f["repair_sha256"]
            && o["stderr_sha256"].as_str().is_some_and(|s| hex(s, 64)),
    )?;
    f["observation"] = o.clone();
    f["observation_sha256"] = json!(sha(&bytes(o)?));
    Ok(f)
}
pub(super) fn record(j: &Journal, i: &Intent, reader: &str) -> Result<Value, String> {
    let name = row(i, INTENT);
    if !j.absent(i.job(), &name)? {
        return original(j, i, reader);
    }
    let f = context(j, i, reader)?;
    let input = bytes(&f["prelaunch"])?;
    require(input.len() <= 1024)?;
    let mut lima = Lima::open(i)?;
    let mut command = lima.command(i.text("vm"))?;
    command
        .arg(format!(
            "/opt/hol-gauntlet/rust-native-host-pinned-worker-{reader}"
        ))
        .arg("--observe-native-live-failure-v1");
    for k in BASE.into_iter().filter(|k| *k != "signed_envelope_sha256") {
        command.arg(text(&f, k)?);
    }
    command.arg(input.len().to_string());
    let raw = crate::stream_process::run_streamed_command(
        command,
        &input,
        std::time::Duration::from_secs(1020),
        65537,
    )
    .map_err(|_| "original Live failure observation unavailable; no work replayed")?;
    lima.recheck()?;
    let o = parse(&raw)?;
    let result = observed(j, i, f, &o)?;
    require(context(j, i, reader)? == context_without_observation(&result))?;
    Ok(result)
}
fn context_without_observation(f: &Value) -> Value {
    let mut v = f.clone();
    for k in [
        "observation",
        "observation_sha256",
        "signed_envelope_sha256",
    ] {
        v.as_object_mut().unwrap().remove(k);
    }
    v
}
pub(super) fn original(j: &Journal, i: &Intent, reader: &str) -> Result<Value, String> {
    let f = parse(&j.read(i.job(), &row(i, INTENT))?)?;
    observed(j, i, context(j, i, reader)?, &f["observation"])
}
pub(super) fn retirement(
    f: &Value,
    e: &Value,
    h: &Value,
    a: &Value,
    generation: &str,
) -> Result<Value, String> {
    let authority = json!({"schema":"hol-gauntlet-native-live-failure-storage-retirement-authority.v1","export_receipt_sha256":e["receipt_sha256"],"host_ack_sha256":a["receipt_sha256"],"host_receipt_sha256":sha(&bytes(h)?),"prelaunch_sha256":sha(&bytes(&f["prelaunch"])?),"live_prepared_sha256":f["live_prepared_sha256"],"repair_sha256":f["repair_sha256"],"created_repair_sha256":f["created_repair_sha256"],"signed_envelope_sha256":f["signed_envelope_sha256"],"manifest_sha256":e["receipt"]["manifest_sha256"]});
    Ok(
        json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":f["source_sha"],"job_id":f["job_id"],"worker_generation":f["original_worker_generation"],"mke2fs_sha256":f["formatter_sha256"],"profile":"native-v1","retirer_generation":generation,"authority":authority,"storage_receipt_sha256":f["storage_receipt_sha256"],"archive_sha256":e["receipt"]["archive_sha256"]}),
    )
}
pub(super) fn summary(j: &Journal, i: &Intent, f: &Value, action: &str) -> Result<Value, String> {
    let exported = if j.absent(i.job(), &row(i, EXPORT))? {
        Value::Null
    } else {
        parse(&j.read(i.job(), &row(i, EXPORT))?)?["receipt"]["archive_sha256"].clone()
    };
    Ok(
        json!({"schema":"hol-gauntlet-host-native-live-failure.v1","operation":action,"job_id":i.job(),"source_sha":i.text("source_sha"),"native_intent_sha256":i.digest()?,"failure_intent_sha256":sha(&bytes(f)?),"signed_envelope_sha256":f["signed_envelope_sha256"],"repair_sha256":f["repair_sha256"],"created_repair_sha256":f["created_repair_sha256"],"reader_generation":f["reader_generation"],"archive_retained":!j.absent(i.job(),&row(i,RECEIPT))?,"archive_sha256":exported,"host_ack_retained":!j.absent(i.job(),&row(i,ACK))?,"storage_retired":!j.absent(i.job(),&row(i,RETIRED))?,"controller_failure_authenticated":true,"outer_completion_available":false,"exit_code":null,"model_requests":null,"execution_eligible":false,"guard_causality_verified":false,"qualification_eligible":false}),
    )
}

const REQUIRED: [&str; 24] = [
    "worker/started.json",
    "worker/controller-key.json",
    "worker/running.json",
    "worker/native-repair.json",
    "native.stdout",
    "native.stderr",
    "preparation.json",
    "initialization.json",
    "declaration.json",
    "live/prepared.json",
    "sdk/created-intent.json",
    "sdk/created-repair.json",
    "sdk/003.stdout",
    "sdk/004.stdout",
    "sdk/policy.apparmor",
    "cell/native-rootfs.v1.json",
    "cell/native-supervisor.v1.json",
    "cell/system.json",
    "cell/runtime.json",
    "cell/task-mounts.json",
    "cell/cell-artifact-manifest.json",
    "cell/native-wire.v1.json",
    "cell/native-cell.apparmor",
    "results.sha256.json",
];
const OPTIONAL: [&str; 8] = [
    "cell/native-image-events.v1.jsonl",
    "cell/native-supervisor-events.v1.jsonl",
    "cell/native-process-events.v1.jsonl",
    "cell/native-pipe-events.v1.jsonl",
    "live/evidence.v1.json",
    "live/context.v1.json",
    "live/live-cleanup-before.v1.json",
    "live/live-cleanup.v1.json",
];
pub(super) fn archive(
    j: &Journal,
    i: &Intent,
    f: &Value,
    e: &Value,
    raw: &[u8],
) -> Result<(), String> {
    require(
        raw.len() <= LIMIT
            && e["receipt"]["archive_bytes"] == raw.len()
            && e["receipt"]["archive_sha256"] == sha(raw),
    )?;
    let files = crate::native_diagnostic_archive::members(raw)?;
    require(
        REQUIRED.iter().all(|n| files.contains_key(*n))
            && files
                .keys()
                .all(|n| REQUIRED.contains(&n.as_str()) || OPTIONAL.contains(&n.as_str())),
    )?;
    let manifest = &files["results.sha256.json"];
    require(e["receipt"]["manifest_sha256"] == sha(manifest))?;
    let v = parse(manifest)?;
    let o = &f["observation"];
    let mut expected = base(f, "hol-gauntlet-native-live-failure-evidence.v1");
    for (k, val) in [
        (
            "status",
            json!("signed-controller-failure-outer-exit-unavailable"),
        ),
        ("prelaunch", f["prelaunch"].clone()),
        ("controller", o["controller"].clone()),
        ("quiescent", o["quiescent"].clone()),
        ("observation_sha256", f["observation_sha256"].clone()),
        ("exit_code", Value::Null),
        ("qualification_eligible", json!(false)),
        ("execution_eligible", json!(false)),
        ("guard_causality_verified", json!(false)),
        ("model_requests", Value::Null),
        ("files", v["files"].clone()),
        ("filesystem", v["filesystem"].clone()),
    ] {
        expected[k] = val;
    }
    require(
        v == expected
            && bytes(&v)? == *manifest
            && v["files"]
                .as_object()
                .is_some_and(|o| o.len() == files.len() - 1)
            && v["filesystem"]
                .as_object()
                .is_some_and(|o| o.len() == files.len() - 1),
    )?;
    for (name, raw) in files
        .iter()
        .filter(|(n, _)| n.as_str() != "results.sha256.json")
    {
        let mode = if name.ends_with(".apparmor") {
            0o400
        } else if name.starts_with("cell/") && !name.ends_with(".jsonl") {
            0o444
        } else {
            0o600
        };
        let m = &v["filesystem"][name];
        require(
            v["files"][name] == json!({"bytes":raw.len(),"sha256":sha(raw)})
                && exact(
                    m,
                    &[
                        "device",
                        "inode",
                        "uid",
                        "gid",
                        "mode",
                        "links",
                        "bytes",
                        "mtime",
                        "mtime_nsec",
                        "ctime",
                        "ctime_nsec",
                    ],
                )
                && m["uid"] == 0
                && m["gid"] == 0
                && m["mode"] == mode
                && m["links"] == 1
                && m["bytes"] == raw.len()
                && ["device", "inode"].iter().all(|k| m[*k].as_u64().is_some())
                && ["mtime", "mtime_nsec", "ctime", "ctime_nsec"]
                    .iter()
                    .all(|k| m[*k].as_i64().is_some()),
        )?;
    }
    for (name, pin) in [
        ("preparation.json", "preparation_sha256"),
        ("initialization.json", "initialization_sha256"),
        ("declaration.json", "deployment_digest"),
        ("live/prepared.json", "live_prepared_sha256"),
        ("worker/native-repair.json", "repair_sha256"),
        ("native.stdout", "signed_envelope_sha256"),
        ("sdk/created-repair.json", "created_repair_sha256"),
    ] {
        require(sha(&files[name]) == text(f, pin)?)?;
    }
    for (name, key) in [
        ("worker/started.json", "started"),
        ("worker/controller-key.json", "controller-key"),
        ("worker/running.json", "running"),
    ] {
        require(sha(&files[name]) == text(&o["records_sha256"], key)?)?;
    }
    require(
        files["native.stdout"] == text(o, "signed_envelope_utf8")?.as_bytes()
            && sha(&files["native.stderr"]) == text(o, "stderr_sha256")?
            && files["worker/native-repair.json"] == j.read(i.job(), "repair")?
            && files["sdk/created-repair.json"] == j.read(i.job(), "live-created-repair")?,
    )?;
    require(
        files["initialization.json"]
            == bytes(&parse(&j.read(i.job(), "initialize-result")?)?["receipt"])?
            && files["live/prepared.json"]
                == bytes(&parse(&j.read(i.job(), "live-prepared")?)?["receipt"])?,
    )?;
    let ci = parse(&files["sdk/created-intent.json"])?;
    let cr = parse(&files["sdk/created-repair.json"])?;
    let host = parse(&j.read(i.job(), "live-created-repair-intent")?)?;
    require(
        ci["schema"] == "hol-gauntlet-native-live-sdk-created-repair-intent.v1"
            && cr["intent_sha256"] == sha(&files["sdk/created-intent.json"])
            && ci["pins"] == host["pins"]
            && ci["prelaunch"] == f["prelaunch"]
            && ci["running_marker_sha256"] == o["records_sha256"]["running"]
            && ci["model_requests"].is_null()
            && ci["exit_code"].is_null()
            && ci["execution_eligible"] == false,
    )?;
    let pins = &ci["pins"];
    for (name, key) in [
        ("sdk/003.stdout", "creation_sha256"),
        ("sdk/004.stdout", "inspection_sha256"),
        ("sdk/policy.apparmor", "policy_sha256"),
    ] {
        require(sha(&files[name]) == text(pins, key)?)?;
    }
    require(files["sdk/003.stdout"] == format!("{}\n", text(pins, "container_id")?).as_bytes())?;
    let inspect: Value = serde_json::from_slice(&files["sdk/004.stdout"])
        .map_err(|_| "original SDK inspection JSON invalid")?;
    require(
        inspect.as_array().is_some_and(|a| a.len() == 1)
            && inspect[0]["Id"] == pins["container_id"],
    )?;
    let s = &inspect[0]["State"];
    require(
        s["Status"] == "created"
            && s["Pid"] == 0
            && ["Running", "Paused", "Restarting", "Dead", "OOMKilled"]
                .iter()
                .all(|k| s[*k] == false)
            && s["ExitCode"] == 0
            && s["Error"] == ""
            && s["StartedAt"] == "0001-01-01T00:00:00Z"
            && s["FinishedAt"] == "0001-01-01T00:00:00Z",
    )?;
    stable(j, i, f)
}
#[cfg(test)]
#[path = "native_failed_live_tests.rs"]
mod tests;
