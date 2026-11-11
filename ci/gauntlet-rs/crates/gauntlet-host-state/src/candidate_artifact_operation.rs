//! Durable normal build artifact custody. The fixed Root helpers only inspect
//! and materialize data; a lost response never authorizes another dispatch.
use super::{bytes, context, hex, sha, Journal};
use crate::HostCandidateBuildPinJournal;
use gauntlet_contracts::is_git_sha;
use rustix::fs::Dir;
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

#[path = "source_artifact_operation.rs"]
mod archives;
#[path = "candidate_bounded_build.rs"]
mod bounded;
#[path = "candidate_bounded_dependencies.rs"]
mod dependencies;
#[path = "candidate_prefix_operation.rs"]
mod prefix;
pub use archives::{run_source_artifact_command, SOURCE_ARTIFACT_USAGE};
pub(crate) fn run_dependency_bounded_command(args: &[String]) -> Result<Value, String> {
    if args.first().is_some_and(|a| prefix::handles(a)) {
        return prefix::run_command(args);
    }
    dependencies::run_command(args)
}
#[path = "candidate_bounded_transfer.rs"]
mod source;

pub(crate) const USAGE: &str = "capture PRIVATE_PIN_DIR JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 EXPORT_ARCHIVE_SHA256 VERSION BUILD_PIN_SHA256 CAPTURE_BINARY_SHA256 VM LIMA_SHA256 SSH_HOME LIMA_HOME\nwheel-stage PRIVATE_PIN_DIR JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 EXPORT_ARCHIVE_SHA256 VERSION BUILD_PIN_SHA256 CAPTURE_PROOF_SHA256 WHEEL_STAGE_BINARY_SHA256 VM LIMA_SHA256 SSH_HOME LIMA_HOME\nThe original private build pin and VM must match. Unknown dispatches cannot be retried; proofs remain ineligible for artifact admission and qualification.";
const LIMA: &str = "/opt/homebrew/bin/limactl";
pub(crate) fn handles(action: &str) -> bool {
    (prefix::handles(action) && !action.starts_with("prefix-stage"))
        || matches!(
            action,
            "capture"
                | "capture-read"
                | "wheel-stage"
                | "wheel-stage-read"
                | "transfer-bounded"
                | "transfer-bounded-read"
                | "run-bounded"
                | "read-bounded"
        )
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}
fn suffix(intent: &Value, kind: &str) -> String {
    format!("artifact-{}-{kind}", text(intent, "operation"))
}
fn parse(raw: &[u8]) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| "artifact intent JSON invalid")?;
    let keys = [
        "schema",
        "operation",
        "job_id",
        "source_sha",
        "source_archive_sha256",
        "archive_sha256",
        "version",
        "build_pin_sha256",
        "capture_proof_sha256",
        "worker_sha256",
        "limactl",
        "vm",
        "lima_sha256",
        "transport_context",
    ];
    if bytes(&value)? != raw
        || value
            .as_object()
            .is_none_or(|v| v.len() != keys.len() || keys.iter().any(|k| !v.contains_key(*k)))
        || value["schema"] != "hol-gauntlet-host-candidate-artifact-intent.v1"
        || !matches!(text(&value, "operation"), "capture" | "wheel-stage")
        || !hex(text(&value, "job_id"), 16)
        || !is_git_sha(text(&value, "source_sha"))
        || !gauntlet_evidence::valid_package_version(text(&value, "version"))
        || ![
            "source_archive_sha256",
            "archive_sha256",
            "build_pin_sha256",
            "worker_sha256",
            "lima_sha256",
        ]
        .iter()
        .all(|k| hex(text(&value, k), 64))
        || (if value["operation"] == "capture" {
            !value["capture_proof_sha256"].is_null()
        } else {
            !hex(text(&value, "capture_proof_sha256"), 64)
        })
        || value["limactl"] != LIMA
        || value["transport_context"]["vm"] != value["vm"]
    {
        return Err("closed artifact intent and exact outside pins required".into());
    }
    context::TransportContext::parse(&value["transport_context"])?;
    Ok(value)
}
fn from_args(args: &[String]) -> Result<Value, String> {
    let stage = match (args.first().map(String::as_str), args.len()) {
        (Some("capture"), 13) => false,
        (Some("wheel-stage"), 14) => true,
        _ => return Err(USAGE.into()),
    };
    let offset = usize::from(stage);
    let vm = &args[9 + offset];
    let context = context::TransportContext::from_paths(
        Path::new(&args[11 + offset]),
        Path::new(&args[12 + offset]),
        vm,
    )?;
    parse(&bytes(
        &json!({"schema":"hol-gauntlet-host-candidate-artifact-intent.v1",
        "operation":args[0],"job_id":args[2],"source_sha":args[3],
        "source_archive_sha256":args[4],"archive_sha256":args[5],"version":args[6],
        "build_pin_sha256":args[7],"capture_proof_sha256":if stage {json!(args[8])} else {Value::Null},
        "worker_sha256":args[8 + offset],"vm":vm,"limactl":LIMA,
        "lima_sha256":args[10 + offset],"transport_context":context.value()}),
    )?)
}
fn verify_build(journal: &Journal, intent: &Value) -> Result<bool, String> {
    journal.stable()?;
    let record = HostCandidateBuildPinJournal::open(&journal.path)
        .map_err(|e| e.to_string())?
        .read(text(intent, "job_id"))
        .map_err(|e| e.to_string())?;
    if record.raw_sha256 != text(intent, "build_pin_sha256")
        || record.pins.source_sha != text(intent, "source_sha")
        || record.pins.source_archive_sha256 != text(intent, "source_archive_sha256")
        || record.pins.version != text(intent, "version")
        || record
            .vm_target
            .as_ref()
            .is_none_or(|(lima, vm)| lima != LIMA || vm != text(intent, "vm"))
    {
        return Err("artifact identity differs from original private build pin or VM".into());
    }
    context::TransportContext::parse(&intent["transport_context"])?;
    let pending = bounded::verify_artifact_binding(journal, intent)?;
    journal.stable()?;
    Ok(pending)
}
fn dispatch(intent: &Value) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-candidate-artifact-dispatch.v1",
        "intent_sha256":sha(&bytes(intent)?),"retry_allowed":false}),
    )
}
fn stable(journal: &Journal, intent: &Value) -> Result<(), String> {
    let job = text(intent, "job_id");
    if journal.read(job, &suffix(intent, "intent"))? != bytes(intent)?
        || journal.read(job, &suffix(intent, "dispatch"))? != dispatch(intent)?
    {
        return Err("artifact intent or consumed dispatch changed".into());
    }
    verify_build(journal, intent).map(|_| ())
}
fn capture(journal: &Journal, intent: &Value) -> Result<Option<Value>, String> {
    if intent["operation"] == "capture" {
        return Ok(None);
    }
    let original = parse(&journal.read(text(intent, "job_id"), "artifact-capture-intent")?)?;
    if original["operation"] != "capture"
        || [
            "job_id",
            "source_sha",
            "source_archive_sha256",
            "archive_sha256",
            "version",
            "build_pin_sha256",
            "limactl",
            "vm",
            "lima_sha256",
            "transport_context",
        ]
        .iter()
        .any(|key| original[*key] != intent[*key])
    {
        return Err("wheel staging differs from retained original capture custody".into());
    }
    let result = retained(journal, &original)?;
    if result["proof_sha256"] != intent["capture_proof_sha256"] {
        return Err("outside capture proof digest differs".into());
    }
    Ok(Some(result["proof"].clone()))
}
fn result(journal: &Journal, intent: &Value, raw: &[u8]) -> Result<Value, String> {
    let frame = raw
        .strip_suffix(b"\n")
        .filter(|v| !v.contains(&b'\n'))
        .ok_or("artifact response framing invalid; dispatch consumed")?;
    if frame.len() > 8192 {
        return Err("artifact response exceeds bound".into());
    }
    let value: Value = serde_json::from_slice(frame).map_err(|_| "artifact proof JSON invalid")?;
    if bytes(&value)? != frame {
        return Err("artifact proof must be canonical".into());
    }
    archives::candidate_proof(intent, &value, capture(journal, intent)?.as_ref())?;
    Ok(
        json!({"schema":"hol-gauntlet-host-candidate-artifact-result.v1",
        "operation":intent["operation"],"job_id":intent["job_id"],"source_sha":intent["source_sha"],
        "archive_sha256":intent["archive_sha256"],"intent_sha256":sha(&bytes(intent)?),
        "dispatch_sha256":sha(&dispatch(intent)?),"proof_sha256":sha(frame),"proof":value,
        "artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false}),
    )
}
fn retained(journal: &Journal, intent: &Value) -> Result<Value, String> {
    stable(journal, intent)?;
    let job = text(intent, "job_id");
    if journal.absent(job, &suffix(intent, "result"))? {
        let raw = journal.read(job, &suffix(intent, "read-result"))?;
        let v: Value =
            serde_json::from_slice(&raw).map_err(|_| "artifact recovered result invalid")?;
        let context = read_context(journal, intent, text(&v, "reader_generation"))?;
        if journal.read(job, &suffix(intent, "read-intent"))? != bytes(&context)? {
            return Err("artifact read intent changed".into());
        }
        let frame = journal.read(
            job,
            &suffix(
                intent,
                &format!("read-frame-{}", text(&v, "read_return_sha256")),
            ),
        )?;
        let expected = read_result(journal, intent, &context, &frame)?;
        if raw != bytes(&expected)? {
            return Err("artifact recovered proof changed".into());
        }
        return Ok(expected["result"].clone());
    }
    if !journal.absent(job, &suffix(intent, "read-result"))? {
        return Err("duplicate original/recovered artifact result".into());
    }
    let result = result(
        journal,
        intent,
        &journal.read(job, &suffix(intent, "return"))?,
    )?;
    if journal.read(job, &suffix(intent, "result"))? != bytes(&result)? {
        return Err("artifact result missing or changed; preserve consumed dispatch".into());
    }
    Ok(result)
}
fn read_context(j: &Journal, i: &Value, reader: &str) -> Result<Value, String> {
    stable(j, i)?;
    if !hex(reader, 64) || verify_build(j, i)? {
        return Err("artifact read requires authenticated terminal and exact reader pin".into());
    }
    let bounded = bounded::parse(&j.read(text(i, "job_id"), bounded::INTENT)?)?;
    let claim = bounded::retained_claim(j, &bounded)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-candidate-artifact-read.v1","artifact_intent_sha256":sha(&bytes(i)?),
        "source_intent_sha256":bounded["source"]["intent_sha256"],"storage_receipt_sha256":bounded["source"]["storage_receipt_sha256"],
        "host_pin_sha256":claim["host_pin_sha256"],"result_sha256":claim["result_sha256"],"reader_generation":reader}),
    )
}
fn read_result(j: &Journal, i: &Value, context: &Value, raw: &[u8]) -> Result<Value, String> {
    let frame = raw
        .strip_suffix(b"\n")
        .filter(|b| !b.contains(&b'\n') && b.len() <= 16384)
        .ok_or("bounded artifact read frame required")?;
    let v: Value = serde_json::from_slice(frame).map_err(|_| "artifact read JSON invalid")?;
    if bytes(&v)? != frame || v != archives::candidate_read_header(i, context, &v["proof"]) {
        return Err("artifact read differs from original outside pins".into());
    }
    let mut proof = bytes(&v["proof"])?;
    proof.push(b'\n');
    let proof = result(j, i, &proof)?;
    let original = if j.absent(text(i, "job_id"), &suffix(i, "return"))? {
        None
    } else {
        Some(sha(&j.read(text(i, "job_id"), &suffix(i, "return"))?))
    };
    Ok(
        json!({"schema":"hol-gauntlet-host-candidate-artifact-recovered.v1","read_intent_sha256":sha(&bytes(context)?),
        "read_return_sha256":sha(raw),"original_return_sha256":original,"reader_generation":context["reader_generation"],"result":proof}),
    )
}
fn completed_read(
    j: &Journal,
    i: &Value,
    reader: &str,
    run: impl FnOnce(&[String], &[u8]) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    let context = read_context(j, i, reader)?;
    j.retain(
        text(i, "job_id"),
        &suffix(i, "read-intent"),
        &bytes(&context)?,
    )?;
    if !j.absent(text(i, "job_id"), &suffix(i, "result"))?
        || !j.absent(text(i, "job_id"), &suffix(i, "read-result"))?
    {
        return retained(j, i);
    }
    let raw = run(&archives::candidate_read_args(i, &context)?, b"")
        .map_err(|_| "completed artifact read unavailable; never recreate data")?;
    stable(j, i)?;
    j.retain(
        text(i, "job_id"),
        &suffix(i, &format!("read-frame-{}", sha(&raw))),
        &raw,
    )?;
    let value = read_result(j, i, &context, &raw)?;
    j.write(
        text(i, "job_id"),
        &suffix(i, "read-result"),
        &bytes(&value)?,
    )?;
    retained(j, i)
}
fn read_command(args: &[String]) -> Result<Value, String> {
    if !matches!(
        (args.first().map(String::as_str), args.len()),
        (Some("capture-read"), 14) | (Some("wheel-stage-read"), 15)
    ) || !args.last().is_some_and(|v| hex(v, 64))
    {
        return Err(USAGE.into());
    }
    let mut original = args[..args.len() - 1].to_vec();
    original[0] = original[0].strip_suffix("-read").ok_or(USAGE)?.into();
    let i = from_args(&original)?;
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let mut lima =
        context::Lima::open_pinned(LIMA, text(&i, "lima_sha256"), &i["transport_context"])?;
    completed_read(&j, &i, args.last().ok_or(USAGE)?, |a, input| {
        let mut command = lima.command(text(&i, "vm"))?;
        command.args(a);
        let raw = crate::stream_process::run_streamed_command(
            command,
            input,
            Duration::from_secs(180),
            16385,
        )
        .map_err(|_| "artifact read transport uncertain")?;
        lima.recheck()?;
        Ok(raw)
    })
}
fn idle(journal: &Journal) -> Result<(), String> {
    idle_with_pending_capture(journal, None)
}
fn idle_with_pending_capture(journal: &Journal, pending: Option<&str>) -> Result<(), String> {
    let mut count = 0;
    for entry in
        Dir::read_from(&journal.root).map_err(|_| "artifact journal listing unavailable")?
    {
        let entry = entry.map_err(|_| "artifact journal entry unavailable")?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "artifact record name invalid")?;
        source::verify_idle_record(journal, name)?;
        if !pending.is_some_and(|job| name == format!("{job}.native-bounded-build-dispatch.json")) {
            bounded::verify_idle_record(journal, name)?;
        }
        dependencies::verify_idle_record(journal, name)?;
        archives::verify_idle_record(journal, name)?;
        prefix::verify_idle_record(journal, name)?;
        for operation in ["capture", "wheel-stage"] {
            if let Some(job) =
                name.strip_suffix(&format!(".native-artifact-{operation}-dispatch.json"))
            {
                count += 1;
                if count > 4096 {
                    return Err("artifact dispatch bound exceeded".into());
                }
                let intent = parse(&journal.read(job, &format!("artifact-{operation}-intent"))?)?;
                if text(&intent, "job_id") != job || text(&intent, "operation") != operation {
                    return Err("artifact journal identity differs".into());
                }
                retained(journal, &intent)
                    .map_err(|_| "unknown artifact job blocks new dispatch")?;
            }
        }
    }
    journal.stable()
}
fn execute(
    journal: &Journal,
    intent: &Value,
    run: impl FnOnce(&Value) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    let job = text(intent, "job_id");
    let pending = verify_build(journal, intent)?;
    journal.retain(job, &suffix(intent, "intent"), &bytes(intent)?)?;
    if !journal.absent(job, &suffix(intent, "dispatch"))? {
        return retained(journal, intent);
    }
    if !journal.absent(job, &suffix(intent, "result"))?
        || !journal.absent(job, &suffix(intent, "return"))?
    {
        return Err("orphan artifact result blocks dispatch".into());
    }
    idle_with_pending_capture(journal, if pending { Some(job) } else { None })?;
    capture(journal, intent)?;
    journal.write(job, &suffix(intent, "dispatch"), &dispatch(intent)?)?;
    stable(journal, intent)?;
    let raw =
        run(intent).map_err(|_| "artifact operation uncertain; dispatch consumed, never retry")?;
    stable(journal, intent)?;
    journal.write(job, &suffix(intent, "return"), &raw)?;
    let value = result(journal, intent, &raw)?;
    journal.write(job, &suffix(intent, "result"), &bytes(&value)?)?;
    retained(journal, intent)
}
pub(crate) fn run_candidate_artifact_command(args: &[String]) -> Result<Value, String> {
    if args
        .first()
        .is_some_and(|a| matches!(a.as_str(), "capture-read" | "wheel-stage-read"))
    {
        return read_command(args);
    }
    if args.first().is_some_and(|a| prefix::handles(a)) {
        return prefix::run_command(args);
    }
    if args
        .first()
        .is_some_and(|a| matches!(a.as_str(), "run-bounded" | "read-bounded"))
    {
        return bounded::run_command(args);
    }
    if args
        .first()
        .is_some_and(|a| matches!(a.as_str(), "transfer-bounded" | "transfer-bounded-read"))
    {
        return source::run_command(args);
    }
    let intent = from_args(args)?;
    let mut journal = Journal::open(Path::new(&args[1]))?;
    journal.lock()?;
    let mut lima = context::Lima::open_pinned(
        LIMA,
        text(&intent, "lima_sha256"),
        &intent["transport_context"],
    )?;
    execute(&journal, &intent, |intent| {
        let mut command = lima.command(text(intent, "vm"))?;
        let role = if intent["operation"] == "capture" {
            "capture"
        } else {
            "wheel-stage"
        };
        command
            .arg(format!(
                "/opt/hol-gauntlet/rust-candidate-{role}-shadow-{}",
                text(intent, "worker_sha256")
            ))
            .args([
                text(intent, "job_id"),
                text(intent, "source_sha"),
                text(intent, "source_archive_sha256"),
                text(intent, "archive_sha256"),
                text(intent, "version"),
            ]);
        let raw = crate::stream_process::run_streamed_command(
            command,
            b"",
            Duration::from_secs(180),
            8193,
        )
        .map_err(|_| "artifact transport uncertain")?;
        lima.recheck()?;
        Ok(raw)
    })
}

#[cfg(test)]
#[path = "candidate_artifact_operation_tests.rs"]
mod tests;
