//! A readonly controller failure has outer custody, never controller authentication.
use super::*;
use crate::{HostControllerKeyPinJournal, NativeControlReadbackError};
use gauntlet_contracts::PrelaunchPrepared;
use serde_json::{json, Value};
#[path = "native_failed_archive.rs"]
mod archive;
#[path = "native_failed_live.rs"]
mod live;
pub(super) use archive::recover;
#[cfg(test)]
pub(super) use archive::MEMBERS;
pub(super) const LIVE_USAGE: &str = live::USAGE;
pub(super) fn is_live(f: &Value) -> bool {
    f["schema"] == "hol-gauntlet-host-native-live-failure-intent.v1"
        || f["receipt"]["schema"] == "hol-gauntlet-native-live-failure-export.v1"
}
pub(super) fn schema(f: &Value, value: &str) -> String {
    if is_live(f) {
        value.replace("native-readonly-failure", "native-live-failure")
    } else {
        value.into()
    }
}
pub(super) fn row(i: &Intent, value: &str) -> String {
    if i.is_live() {
        value.replacen("readonly-failure", "live-failure", 1)
    } else {
        value.into()
    }
}
pub(super) fn archive_name_for(i: &Intent, n: usize) -> String {
    if i.is_live() {
        format!("{}.native-live-failure-{n:04}.tar", i.job())
    } else {
        archive_name(i.job(), n)
    }
}
pub(super) fn has_intent(j: &Journal, i: &Intent) -> Result<bool, String> {
    Ok(!j.absent(i.job(), &row(i, INTENT))?)
}
pub(super) fn fields(f: &Value) -> &'static [&'static str] {
    if is_live(f) {
        &live::BASE
    } else {
        &BASE
    }
}
pub(super) fn record(j: &Journal, i: &Intent, reader: &str) -> Result<Value, String> {
    if i.is_live() {
        live::record(j, i, reader)
    } else {
        original(j, i, reader)
    }
}
pub(super) fn archive(
    j: &Journal,
    i: &Intent,
    f: &Value,
    e: &Value,
    raw: &[u8],
) -> Result<(), String> {
    if i.is_live() {
        live::archive(j, i, f, e, raw)
    } else {
        archive::archive(j, i, f, e, raw)
    }
}
pub(super) fn live_summary(
    j: &Journal,
    i: &Intent,
    f: &Value,
    action: &str,
) -> Result<Value, String> {
    live::summary(j, i, f, action)
}
pub(super) fn marker(f: &Value, operation: &str, binding: &Value) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":schema(f,"hol-gauntlet-host-native-readonly-failure-dispatch.v1"),"failure_intent_sha256":sha(&bytes(f)?),"operation":operation,"binding_sha256":sha(&bytes(binding)?),"retry_allowed":false}),
    )
}
pub(super) fn archive_name(job: &str, attempt: usize) -> String {
    format!("{job}.native-readonly-failure-{attempt:04}.tar")
}

pub(super) const BASE: [&str; 9] = [
    "source_sha",
    "job_id",
    "deployment_digest",
    "original_worker_generation",
    "preparation_sha256",
    "storage_receipt_sha256",
    "terminal_sha256",
    "report_sha256",
    "reader_generation",
];
pub(super) fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str()
        .ok_or_else(|| format!("readonly failure {k} absent"))
}
fn require(ok: bool) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err("readonly failure custody or closed protocol differs".into())
    }
}
fn exact(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}
pub(super) fn parse(raw: &[u8]) -> Result<Value, String> {
    let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
    let v: Value = serde_json::from_slice(raw).map_err(|_| "readonly failure JSON invalid")?;
    require(bytes(&v)? == raw)?;
    Ok(v)
}
pub(super) fn base(i: &Value, schema: &str) -> Value {
    let mut v = json!({"schema":schema});
    for &k in fields(i) {
        v[k] = i[k].clone();
    }
    v
}
pub(super) fn original(j: &Journal, i: &Intent, reader: &str) -> Result<Value, String> {
    if i.is_live() {
        return live::original(j, i, reader);
    }
    require(!i.is_live() && i.text("role") == "readonly-utility" && hex(reader, 64))?;
    j.require_dispatch(i)?;
    for s in [
        "completion",
        "repair-intent",
        "repair-dispatch",
        "repair",
        "export-dispatch",
        "storage-retirement-intent",
    ] {
        require(j.absent(i.job(), s)?)?;
    }
    let prepared = preparation::require_prepared(j, i)?;
    let storage = preparation::retained_storage(j, i)?
        .ok_or("readonly failure requires original bounded initialization")?;
    let keys = HostControllerKeyPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    let pin = keys.read(i.job()).map_err(|e| e.to_string())?;
    let raw = j.read(i.job(), "return")?;
    let frame = parse(&raw)?;
    require(bytes(&frame)? == raw)?;
    require(matches!(
        keys.verify_native_bounded_completion(
            &raw,
            &i.expected(),
            i.text("preparation_sha256"),
            "readonly-utility",
            None,
            &storage
        ),
        Err(NativeControlReadbackError::Signature)
    ))?;
    let r = &frame["report"];
    require(
        r["exit_code"]
            .as_i64()
            .is_some_and(|n| (1..=255).contains(&n))
            && r.get("execution_error").is_some_and(Value::is_null)
            && r.get("interruption").is_some_and(Value::is_null)
            && r["controller_stdout_sha256"] == sha(b"")
            && r["controller_envelope_utf8"] == ""
            && r.get("controller_report").is_some_and(Value::is_null)
            && r.get("controller_signature_verification")
                .is_some_and(Value::is_null)
            && r["controller_signature_error"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 1024),
    )?;
    let p = &pin.pins;
    let prelaunch = PrelaunchPrepared {
        source_sha: p.source_sha.clone(),
        job_id: p.job_id.clone(),
        deployment_digest: p.deployment_digest.clone(),
        worker_generation: p.worker_generation.clone(),
        started_marker_sha256: p.started_marker_sha256.clone(),
        controller_key_pin_sha256: p.controller_key_pin_sha256.clone(),
        controller_public_key_hex: p.controller_public_key_hex.clone(),
    };
    require(prelaunch.host_record_sha256().map_err(|e| e.to_string())? == pin.raw_sha256)?;
    let initial = parse(&j.read(i.job(), "initialize-result")?)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-native-readonly-failure-intent.v1",
        "source_sha":i.text("source_sha"),"job_id":i.job(),"deployment_digest":i.text("deployment_digest"),
        "original_worker_generation":i.text("worker_generation"),"preparation_sha256":i.text("preparation_sha256"),
        "storage_receipt_sha256":storage["receipt_sha256"],"terminal_sha256":frame["terminal_sha256"],"report_sha256":frame["terminal"]["report_sha256"],"reader_generation":reader,
        "prelaunch":parse(&prelaunch.to_bytes().map_err(|e|e.to_string())?)?,"host_pin_sha256":pin.raw_sha256,
        "native_intent_sha256":i.digest()?,"return_sha256":sha(&raw),"initialization_sha256":initial["receipt_sha256"],
        "preparation_receipt_sha256":prepared["receipt_sha256"],"formatter_sha256":storage["receipt"]["mke2fs_sha256"],"parent_custody":context::snapshot(&j.path)?}),
    )
}
pub(super) fn stable(j: &Journal, i: &Intent, f: &Value) -> Result<(), String> {
    require(j.intent(i.job())? == *i && original(j, i, text(f, "reader_generation")?)? == *f)?;
    require(j.read(i.job(), &row(i, INTENT))? == bytes(f)?)
}
pub(super) fn export_intent(f: &Value) -> Value {
    let mut v = base(
        f,
        &schema(f, "hol-gauntlet-native-readonly-failure-export-intent.v1"),
    );
    v["prelaunch"] = f["prelaunch"].clone();
    v
}
fn wrapped(raw: &[u8], schema: &str) -> Result<Value, String> {
    require(raw.len() <= 8193)?;
    let v = parse(raw)?;
    require(
        exact(&v, &["schema", "receipt", "receipt_sha256"])
            && v["schema"] == schema
            && v["receipt_sha256"] == sha(&bytes(&v["receipt"])?),
    )?;
    Ok(v)
}
pub(super) fn export(f: &Value, raw: &[u8], exit: &Value) -> Result<Value, String> {
    let v = wrapped(
        raw,
        &schema(f, "hol-gauntlet-native-readonly-failure-export-result.v1"),
    )?;
    let r = &v["receipt"];
    let mut expected = base(
        f,
        &schema(f, "hol-gauntlet-native-readonly-failure-export.v1"),
    );
    for k in ["archive_sha256", "archive_bytes", "manifest_sha256"] {
        expected[k] = r[k].clone();
    }
    expected["exit_code"] = exit.clone();
    if is_live(f) {
        expected["model_requests"] = Value::Null;
    }
    expected["execution_eligible"] = json!(false);
    expected["qualification_eligible"] = json!(false);
    require(
        *r == expected
            && r["archive_bytes"]
                .as_u64()
                .is_some_and(|n| (1024..=LIMIT as u64).contains(&n))
            && ["archive_sha256", "manifest_sha256"]
                .iter()
                .all(|k| r[*k].as_str().is_some_and(|s| hex(s, 64))),
    )?;
    Ok(v)
}
pub(super) fn state(f: &Value, raw: &[u8], exit: &Value) -> Result<Option<Value>, String> {
    let v = parse(raw)?;
    require(
        raw.len() <= 8193
            && exact(
                &v,
                &[
                    "schema",
                    "intent_sha256",
                    "export",
                    "export_complete",
                    "retry_allowed",
                ],
            )
            && v["schema"] == schema(f, "hol-gauntlet-native-readonly-failure-export-state.v1")
            && v["intent_sha256"] == sha(&bytes(&export_intent(f))?)
            && v["retry_allowed"] == false,
    )?;
    if v["export_complete"] == false {
        require(v["export"].is_null())?;
        return Ok(None);
    }
    require(v["export_complete"] == true)?;
    export(f, &bytes(&v["export"])?, exit).map(Some)
}
pub(super) fn ack(e: &Value, receipt: &Value, raw: &[u8]) -> Result<Value, String> {
    let v = wrapped(
        raw,
        &schema(e, "hol-gauntlet-native-readonly-failure-ack-result.v1"),
    )?;
    let mut expected = e["receipt"].clone();
    expected["schema"] = json!(schema(e, "hol-gauntlet-native-readonly-failure-ack.v1"));
    expected["export_receipt_sha256"] = e["receipt_sha256"].clone();
    expected["host_receipt_sha256"] = json!(sha(&bytes(receipt)?));
    require(v["receipt"] == expected)?;
    Ok(v)
}
pub(super) fn retirement(
    f: &Value,
    e: &Value,
    h: &Value,
    a: &Value,
    generation: &str,
) -> Result<Value, String> {
    require(hex(generation, 64))?;
    if is_live(f) {
        return live::retirement(f, e, h, a, generation);
    }
    let authority = json!({"schema":"hol-gauntlet-native-readonly-failure-storage-retirement-authority.v1",
        "export_receipt_sha256":e["receipt_sha256"],"host_ack_sha256":a["receipt_sha256"],"host_receipt_sha256":sha(&bytes(h)?),
        "terminal_sha256":f["terminal_sha256"],"report_sha256":f["report_sha256"],"prelaunch_sha256":sha(&bytes(&f["prelaunch"])?),"manifest_sha256":e["receipt"]["manifest_sha256"]});
    Ok(
        json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":f["source_sha"],"job_id":f["job_id"],"worker_generation":f["original_worker_generation"],
        "mke2fs_sha256":f["formatter_sha256"],"profile":"native-v1","retirer_generation":generation,"authority":authority,
        "storage_receipt_sha256":f["storage_receipt_sha256"],"archive_sha256":e["receipt"]["archive_sha256"]}),
    )
}
pub(super) fn retired(r: &Value, raw: &[u8]) -> Result<Value, String> {
    require(raw.len() <= 8193)?;
    let v = parse(raw)?;
    let expected = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":r["source_sha"],"job_id":r["job_id"],"worker_generation":r["worker_generation"],"profile":"native-v1",
        "retirer_generation":r["retirer_generation"],"retirement_intent_sha256":sha(&bytes(r)?),"storage_receipt_sha256":r["storage_receipt_sha256"],"archive_sha256":r["archive_sha256"],
        "partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":null});
    require(v == expected)?;
    Ok(v)
}

pub(super) fn args(
    f: &Value,
    selector: &str,
    input: &[u8],
    tail: &[String],
    generation: Option<&str>,
) -> Result<Vec<String>, String> {
    let g = generation.unwrap_or(text(f, "reader_generation")?);
    let mut a = vec![
        format!("/opt/hol-gauntlet/rust-native-host-pinned-worker-{g}"),
        schema(f, selector),
    ];
    for &k in fields(f) {
        a.push(text(f, k)?.into());
    }
    a.extend(tail.iter().cloned());
    if !input.is_empty() {
        if input.len() > 1024 {
            return Err("bounded original prelaunch required".into());
        }
        a.push(input.len().to_string());
    }
    Ok(a)
}

pub(super) fn retired_context(
    j: &Journal,
    i: &Intent,
    f: &Value,
) -> Result<(Value, Value, Value, Value, artifact::HeldPrivateArchive), String> {
    let (e, h, held) = custody(j, i, f)?;
    let a = retained_ack(j, i, f, &e, &h)?;
    let request = parse(&j.read(i.job(), &row(i, REQUEST))?)?;
    let g = text(&request, "retirer_generation")?;
    if request
        != json!({"schema":schema(f,"hol-gauntlet-host-native-readonly-failure-retirement-request.v1"),"failure_intent_sha256":sha(&bytes(f)?),"retirer_generation":g})
    {
        return Err("original readonly failure retirement request differs".into());
    }
    let r = retirement(f, &e, &h, &a, g)?;
    Ok((e, h, a, r, held))
}
