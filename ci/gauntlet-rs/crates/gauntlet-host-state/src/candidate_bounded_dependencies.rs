//! Bounded dependency operations share the original source's owned transport.
use super::super::{bytes, context, sha, Journal};
use crate::fixed_process::FixedProcessError;
use crate::{read_dependency_run_pins, DependencyIntentJournal};
use gauntlet_contracts::{DependencyRunIntent, DependencyRunPins};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
const INTENT: &str = "bounded-dependency-intent";
const DISPATCH: &str = "bounded-dependency-dispatch";
const BINDING: &str = "bounded-dependency-binding";
const COMPLETE: &str = "bounded-dependency-complete";
pub(super)const USAGE:&str="run-bounded PRIVATE_INTENT_DIR PRIVATE_TRANSFER_DIR SOURCE_TRANSFER_INTENT_SHA256 PRIVATE_RUN_PINS_JSON\nread-bounded PRIVATE_INTENT_DIR PRIVATE_TRANSFER_DIR SOURCE_TRANSFER_INTENT_SHA256 JOB_ID READER_SHA256\nrepair-bounded PRIVATE_INTENT_DIR PRIVATE_TRANSFER_DIR SOURCE_TRANSFER_INTENT_SHA256 JOB_ID EXPECTED_STARTED_SHA256 REPAIR_SHA256\nOnly completed dependency-v1 Source contexts may create the new binding. Original Lima/homes/instance and opaque nonce stay retained; old v1 cannot borrow bounded authority.";
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str()
        .ok_or_else(|| format!("bounded dependency {k} absent"))
}
fn parse(raw: &[u8]) -> Result<Value, String> {
    let i: Value =
        serde_json::from_slice(raw).map_err(|_| "bounded dependency intent JSON invalid")?;
    let p = DependencyRunPins::from_value(i["pins"].clone())?;
    if bytes(&i)? != raw
        || i.as_object().is_none_or(|o| o.len() != 6)
        || i["schema"] != "hol-gauntlet-host-bounded-dependency.v1"
        || i["job_id"] != p.text("job_id")
        || i["execution_eligible"] != false
        || i["qualification_eligible"] != false
        || i["source"]["intent"]["storage_profile"] != "dependency-v1"
        || ["job_id", "source_sha", "source_archive_sha256"]
            .iter()
            .any(|k| i["source"]["intent"][*k] != p.text(k))
    {
        return Err(
            "exact versioned dependency/source identity and dependency-v1 profile required".into(),
        );
    }
    recheck(&i)?;
    Ok(i)
}
fn recheck(i: &Value) -> Result<(), String> {
    let s = &i["source"];
    if super::source::completed(
        Path::new(text(s, "journal")?),
        text(i, "job_id")?,
        text(s, "intent_sha256")?,
    )? != *s
    {
        return Err("original bounded dependency Source context changed".into());
    }
    Ok(())
}
fn dispatch(i: &Value) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-bounded-dependency-dispatch.v1","intent_sha256":sha(&bytes(i)?),"retry_allowed":false}),
    )
}
fn binding(i: &Value, d: &DependencyRunIntent) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-bounded-dependency-binding.v1","intent_sha256":sha(&bytes(i)?),"dependency_intent_sha256":d.digest()?,"storage_receipt_sha256":i["source"]["storage_receipt_sha256"]}),
    )
}
fn stable(j: &Journal, i: &Value) -> Result<(), String> {
    let job = text(i, "job_id")?;
    if j.read(job, INTENT)? != bytes(i)? || j.read(job, DISPATCH)? != dispatch(i)? {
        return Err("bounded dependency intent or dispatch changed".into());
    }
    recheck(i)?;
    j.stable()
}
fn original(
    j: &Journal,
    i: &Value,
) -> Result<(DependencyIntentJournal, DependencyRunIntent), String> {
    stable(j, i)?;
    let deps = DependencyIntentJournal::open(&j.path)?;
    let d = deps.read(text(i, "job_id")?)?;
    if d.pins.value() != &i["pins"]
        || d.limactl != text(&i["source"]["intent"], "limactl")?
        || d.vm != text(&i["source"]["intent"], "vm")?
        || j.read(text(i, "job_id")?, BINDING)? != binding(i, &d)?
    {
        return Err("original opaque dependency intent binding differs".into());
    }
    deps.require_dispatch(&d)?;
    Ok((deps, d))
}
fn frame_public(j: &Journal, i: &Value, event: &Value) -> Result<Value, String> {
    let (deps, d) = original(j, i)?;
    let raw = j.read(
        text(i, "job_id")?,
        &format!("dependency-frame-{}", text(event, "frame_sha256")?),
    )?;
    if sha(&raw) != text(event, "frame_sha256")? {
        return Err("retained dependency frame changed".into());
    }
    let v: Value =
        serde_json::from_slice(&raw).map_err(|_| "retained dependency frame JSON invalid")?;
    let generation = text(event, "reader_generation")?;
    let public = if v["schema"] == "hol-gauntlet-native-dependency-read.v1" {
        gauntlet_contracts::verify_dependency_read_response(&d, generation, &raw)?
    } else {
        let auth = deps
            .repair_pins(&d)?
            .ok_or("retained recovery authorization absent")?;
        let mut p = gauntlet_contracts::verify_dependency_recovery_reply(
            &d,
            &auth.started,
            &auth.generation,
            generation,
            &raw,
        )?;
        if p.get("repair_generation").is_some() {
            DependencyIntentJournal::check_repair_view(&p, &auth)?;
        } else if auth.preparation.is_some() || auth.completion.is_some() {
            return Err("snapshot retirement cannot finalize a result".into());
        }
        if event["operation"] == "read-bounded" {
            p["reader_generation"] = json!(generation);
            p["retained_result_reconciled"] = json!(true);
        }
        p
    };
    if public != event["public"] || public["status"] == "unknown" {
        return Err("retained dependency completion differs or remains unknown".into());
    }
    Ok(public)
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    if let Some(job) = name.strip_suffix(".native-bounded-dependency-dispatch.json") {
        let i = parse(&j.read(job, INTENT)?)?;
        let (deps, d) = original(j, &i)?;
        if deps.retained_result(&d)?.is_none() {
            let event: Value = serde_json::from_slice(&j.read(job, COMPLETE)?)
                .map_err(|_| "unknown bounded dependency blocks dispatch")?;
            frame_public(j, &i, &event)?;
        }
    }
    Ok(())
}
fn execute(
    j: &Journal,
    i: &Value,
    mut rpc: impl FnMut(&[String], &[u8], Duration, usize, usize) -> Result<Vec<u8>, FixedProcessError>,
) -> Result<Value, String> {
    parse(&bytes(i)?)?;
    let job = text(i, "job_id")?;
    if !matches!(
        rustix::fs::statat(
            &j.root,
            format!("{job}.dependency-intent.json"),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW
        ),
        Err(rustix::io::Errno::NOENT)
    ) || !j.absent(job, INTENT)?
        || !j.absent(job, DISPATCH)?
        || !j.absent(job, BINDING)?
    {
        return Err("existing dependency cannot acquire a new bounded binding".into());
    }
    super::idle(j)?;
    j.write(job, INTENT, &bytes(i)?)?;
    j.write(job, DISPATCH, &dispatch(i)?)?;
    let operations = crate::public_vm_operations(Some(text(&i["source"]["intent"], "vm")?))
        .map_err(|e| e.to_string())?;
    let deps = DependencyIntentJournal::open(&j.path)?;
    let d = deps.record(
        DependencyRunPins::from_value(i["pins"].clone())?,
        &operations,
    )?;
    j.write(job, BINDING, &binding(i, &d)?)?;
    let public = deps.execute_once_using(&d, &mut |a, b, t, o, e| {
        stable(j, i).map_err(|_| FixedProcessError::Unavailable)?;
        let raw = rpc(a, b, t, o, e)?;
        stable(j, i).map_err(|_| FixedProcessError::Unavailable)?;
        Ok(raw)
    })?;
    original(j, i)?;
    summary(i, &d, "run-bounded", public)
}
fn later(
    j: &Journal,
    i: &Value,
    action: &str,
    generation: &str,
    started: Option<&str>,
    mut rpc: impl FnMut(&[String], &[u8], Duration, usize, usize) -> Result<Vec<u8>, FixedProcessError>,
) -> Result<Value, String> {
    let (deps, d) = original(j, i)?;
    let mut last = None;
    let mut transport = |a: &[String], b: &[u8], t, o, e| {
        original(j, i).map_err(|_| FixedProcessError::Unavailable)?;
        let raw = rpc(a, b, t, o, e)?;
        original(j, i).map_err(|_| FixedProcessError::Unavailable)?;
        let frame = raw.strip_suffix(b"\n").ok_or(FixedProcessError::Failed)?;
        j.retain(
            text(i, "job_id").map_err(|_| FixedProcessError::Unavailable)?,
            &format!("dependency-frame-{}", sha(frame)),
            frame,
        )
        .map_err(|_| FixedProcessError::Unavailable)?;
        last = Some(sha(frame));
        Ok(raw)
    };
    let public = if let Some(started) = started {
        deps.repair_using(
            d.pins.text("job_id"),
            started,
            generation,
            None,
            &mut transport,
        )?
    } else {
        deps.reconcile_using(d.pins.text("job_id"), generation, None, &mut transport)?
    };
    original(j, i)?;
    if public["status"] != "unknown" {
        let event = json!({"operation":action,"reader_generation":generation,"frame_sha256":last.ok_or("completed dependency frame absent")?,"public":public});
        frame_public(j, i, &event)?;
        j.retain(d.pins.text("job_id"), COMPLETE, &bytes(&event)?)?;
    }
    summary(i, &d, action, public)
}
fn summary(
    i: &Value,
    d: &DependencyRunIntent,
    action: &str,
    public: Value,
) -> Result<Value, String> {
    Ok(
        json!({"schema":"hol-gauntlet-host-bounded-dependency-operation.v1","operation":action,"job_id":d.pins.text("job_id"),"intent_sha256":sha(&bytes(i)?),"dependency_intent_sha256":d.digest()?,"source_intent_sha256":i["source"]["intent_sha256"],"storage_receipt_sha256":i["source"]["storage_receipt_sha256"],"original_source_transport_verified":true,"result":public,"execution_eligible":false,"qualification_eligible":false}),
    )
}
pub(super) fn flow(
    path: &Path,
    source: &Value,
    job: &str,
    result: &str,
    archive: &str,
) -> Result<Value, String> {
    let j = Journal::open(path)?;
    let i = parse(&j.read(job, INTENT)?)?;
    if i["source"] != *source {
        return Err("artifact Source differs from bounded dependency".into());
    }
    let event: Value = serde_json::from_slice(&j.read(job, COMPLETE)?)
        .map_err(|_| "dependency read completion absent")?;
    let public = frame_public(&j, &i, &event)?;
    let (_, d) = original(&j, &i)?;
    if public["schema"] != "hol-gauntlet-host-dependency-reconciled.v1"
        || public["exit_code"] != 0
        || public["private_result_sha256"] != result
        || public["captured_dependencies_sha256"] != archive
    {
        return Err("artifact requires actual successful original dependency readback".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-host-source-artifact-flow.v1","kind":"dependency","journal":path,"journal_custody":context::snapshot(path)?,"flow_intent_sha256":sha(&bytes(&i)?),"host_binding_sha256":d.digest()?,"result_sha256":result,"archive_sha256":archive}),
    )
}
pub(super) fn run_command(args: &[String]) -> Result<Value, String> {
    let run = match (args.first().map(String::as_str), args.len()) {
        (Some("run-bounded"), 5) => true,
        (Some("read-bounded"), 6) | (Some("repair-bounded"), 7) => false,
        _ => return Err(USAGE.into()),
    };
    let p = if run {
        Some(read_dependency_run_pins(Path::new(&args[4]))?)
    } else {
        None
    };
    let job = if let Some(p) = &p {
        p.text("job_id")
    } else {
        &args[4]
    }
    .to_owned();
    let source = super::source::completed(Path::new(&args[2]), &job, &args[3])?;
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let i = if let Some(p) = p {
        parse(&bytes(
            &json!({"schema":"hol-gauntlet-host-bounded-dependency.v1","job_id":p.text("job_id"),"source":source,"pins":p.value(),"execution_eligible":false,"qualification_eligible":false}),
        )?)?
    } else {
        let i = parse(&j.read(&job, INTENT)?)?;
        if i["source"] != source {
            return Err("original bounded dependency Source differs".into());
        }
        i
    };
    let s = &i["source"]["intent"];
    let mut lima = context::Lima::open_pinned(
        text(s, "limactl")?,
        text(s, "lima_sha256")?,
        &s["transport_context"],
    )?;
    let mut rpc = |a: &[String], b: &[u8], t, o, _| {
        if a.len() < 7
            || a[0] != text(s, "limactl").map_err(|_| FixedProcessError::Unavailable)?
            || a[1] != "shell"
            || a[2] != text(s, "vm").map_err(|_| FixedProcessError::Unavailable)?
            || a[3..6] != ["--", "sudo", "-n"]
        {
            return Err(FixedProcessError::Unavailable);
        }
        let mut c = lima
            .command(text(s, "vm").map_err(|_| FixedProcessError::Unavailable)?)
            .map_err(|_| FixedProcessError::Unavailable)?;
        c.args(&a[6..]);
        let raw = crate::stream_process::run_streamed_command(c, b, t, o)
            .map_err(|_| FixedProcessError::Failed)?;
        lima.recheck().map_err(|_| FixedProcessError::Unavailable)?;
        Ok(raw)
    };
    if run {
        execute(&j, &i, &mut rpc)
    } else {
        later(
            &j,
            &i,
            &args[0],
            if args.len() == 7 { &args[6] } else { &args[5] },
            args.get(5).map(String::as_str).filter(|_| args.len() == 7),
            &mut rpc,
        )
    }
}

/// Public input pins and the official opaque intent digest, selected only by
/// a completed original read. Private intent bytes stay inside their API.
pub(super) fn prefix_inputs(path: &Path, source: &Value, job: &str) -> Result<Value, String> {
    let j = Journal::open(path)?;
    let i = parse(&j.read(job, INTENT)?)?;
    let event: Value = serde_json::from_slice(&j.read(job, COMPLETE)?)
        .map_err(|_| "completed original dependency readback required")?;
    let public = frame_public(&j, &i, &event)?;
    let flow = flow(
        path,
        source,
        job,
        text(&public, "private_result_sha256")?,
        text(&public, "captured_dependencies_sha256")?,
    )?;
    let (_, d) = original(&j, &i)?;
    Ok(json!({"flow":flow,"pins":i["pins"],"dependency_intent_sha256":d.digest()?}))
}

#[cfg(test)]
#[path = "candidate_bounded_dependencies_tests.rs"]
pub(crate) mod tests;
