//! Source graph verification precedes any Root bounded-volume allocation.
use super::super::{bytes, context, hex, sha, verify_job_storage, Journal};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

const INTENT: &str = "bounded-source-intent";
const DISPATCH: &str = "bounded-source-dispatch";
const RETURN: &str = "bounded-source-return";
const RESULT: &str = "bounded-source-result";
const READ: &str = "bounded-source-read-result";
pub(super) const USAGE: &str = "transfer-bounded|transfer-bounded-read PRIVATE_SOURCE_STATE PRIVATE_TRANSFER_DIR JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 CAPTURE_WORKER_SHA256 MKE2FS_SHA256 STORAGE_PROFILE VM LIMA_SHA256 SSH_HOME LIMA_HOME\nProfiles: build-v1|dependency-v1. Original source graph, transport and finite storage limits are pinned before dispatch; uncertain work cannot be retried. transfer-bounded-read only checks the original completed capture with empty stdin.";
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}
fn parse(raw: &[u8]) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|_| "bounded source intent JSON invalid")?;
    let fields = [
        "schema",
        "job_id",
        "source_sha",
        "source_archive_sha256",
        "source_bytes",
        "worker_generation",
        "mke2fs_sha256",
        "storage_profile",
        "vm",
        "limactl",
        "lima_sha256",
        "transport_context",
    ];
    if bytes(&v)? != raw
        || v.as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
        || v["schema"] != "hol-gauntlet-host-bounded-source-intent.v1"
        || !hex(text(&v, "job_id"), 16)
        || !hex(text(&v, "source_sha"), 40)
        || ![
            "source_archive_sha256",
            "worker_generation",
            "mke2fs_sha256",
            "lima_sha256",
        ]
        .iter()
        .all(|k| hex(text(&v, k), 64))
        || !v["source_bytes"]
            .as_u64()
            .is_some_and(|n| (1..=256 * 1024 * 1024).contains(&n))
        || !matches!(text(&v, "storage_profile"), "build-v1" | "dependency-v1")
        || v["limactl"] != super::LIMA
        || v["transport_context"]["vm"] != v["vm"]
    {
        return Err(
            "exact source, transport, formatter and finite storage profile pins required".into(),
        );
    }
    context::TransportContext::parse(&v["transport_context"])?;
    Ok(v)
}
fn intent(args: &[String], size: usize) -> Result<Value, String> {
    if args.len() != 13
        || !matches!(
            args[0].as_str(),
            "transfer-bounded" | "transfer-bounded-read"
        )
    {
        return Err(USAGE.into());
    }
    let context = context::TransportContext::from_paths(
        Path::new(&args[11]),
        Path::new(&args[12]),
        &args[9],
    )?;
    parse(&bytes(
        &json!({"schema":"hol-gauntlet-host-bounded-source-intent.v1", "job_id":args[3],
        "source_sha":args[4],"source_archive_sha256":args[5],"source_bytes":size,"worker_generation":args[6],
        "mke2fs_sha256":args[7],"storage_profile":args[8],"vm":args[9],"limactl":super::LIMA,
        "lima_sha256":args[10],"transport_context":context.value()}),
    )?)
}
fn dispatch(i: &Value) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-bounded-source-dispatch.v1","intent_sha256":sha(&bytes(i)?),"retry_allowed":false}),
    )
}
fn stable(j: &Journal, i: &Value) -> Result<(), String> {
    parse(&bytes(i)?)?;
    if j.read(text(i, "job_id"), INTENT)? != bytes(i)?
        || j.read(text(i, "job_id"), DISPATCH)? != dispatch(i)?
    {
        return Err("bounded source intent or consumed dispatch changed".into());
    }
    j.stable()
}
fn result(i: &Value, raw: &[u8]) -> Result<Value, String> {
    let frame = raw
        .strip_suffix(b"\n")
        .filter(|b| !b.contains(&b'\n') && b.len() <= 16384)
        .ok_or("bounded source response framing differs; preserve consumed dispatch")?;
    let response: Value =
        serde_json::from_slice(frame).map_err(|_| "bounded source reply JSON invalid")?;
    if bytes(&response)? != frame {
        return Err("canonical bounded source reply required".into());
    }
    let expected = json!({"schema":"hol-gauntlet-native-source-capture.v2","job_id":i["job_id"],
        "source_sha":i["source_sha"],"source_archive_sha256":i["source_archive_sha256"],"source_bytes":i["source_bytes"],
        "worker_generation":i["worker_generation"],"storage_profile":i["storage_profile"],"storage":response["storage"],
        "builder_executed":false,"execution_eligible":false,"model_requests":0});
    if response != expected {
        return Err("source capture differs from exact outside intent".into());
    }
    verify_job_storage(
        &response["storage"],
        text(i, "source_sha"),
        text(i, "job_id"),
        text(i, "worker_generation"),
        text(i, "mke2fs_sha256"),
        text(i, "storage_profile"),
    )?;
    Ok(
        json!({"schema":"hol-gauntlet-host-bounded-source-result.v1","intent_sha256":sha(&bytes(i)?),
        "dispatch_sha256":sha(&dispatch(i)?),"capture_sha256":sha(frame),"storage_receipt_sha256":response["storage"]["receipt_sha256"],
        "capture":response,"source_graph_verified":true,"execution_eligible":false,"qualification_eligible":false}),
    )
}
fn retained(j: &Journal, i: &Value) -> Result<Value, String> {
    stable(j, i)?;
    let job = text(i, "job_id");
    if !j.absent(job, RESULT)? {
        let value = result(i, &j.read(job, RETURN)?)?;
        if j.read(job, RESULT)? != bytes(&value)? {
            return Err("bounded source result changed; never retry".into());
        }
        return Ok(value);
    }
    let raw = j.read(job, READ)?;
    let read: Value = serde_json::from_slice(&raw).map_err(|_| "source read result invalid")?;
    let frame = j.read(
        job,
        &format!("bounded-source-read-{}", text(&read, "raw_sha256")),
    )?;
    let value = result(i, &frame)?;
    if raw
        != bytes(&json!({"schema":"hol-gauntlet-host-bounded-source-read.v1",
        "intent_sha256":sha(&bytes(i)?),"raw_sha256":sha(&frame),"result":value}))?
    {
        return Err("original source read binding changed".into());
    }
    Ok(value)
}
fn read_completed(
    j: &Journal,
    i: &Value,
    run: impl FnOnce(&Value, &[u8]) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    stable(j, i)?;
    let job = text(i, "job_id");
    if !j.absent(job, RESULT)? || !j.absent(job, READ)? {
        return retained(j, i);
    }
    let raw = run(i, b"")
        .map_err(|_| "original source read unavailable; never retransmit or allocate again")?;
    stable(j, i)?;
    let raw_sha = sha(&raw);
    j.retain(job, &format!("bounded-source-read-{raw_sha}"), &raw)?;
    let value = result(i, &raw)?;
    j.write(
        job,
        READ,
        &bytes(&json!({"schema":"hol-gauntlet-host-bounded-source-read.v1",
        "intent_sha256":sha(&bytes(i)?),"raw_sha256":raw_sha,"result":value}))?,
    )?;
    retained(j, i)
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    if let Some(job) = name.strip_suffix(".native-bounded-source-dispatch.json") {
        let i = parse(&j.read(job, INTENT)?)?;
        if text(&i, "job_id") != job {
            return Err("bounded source journal identity differs".into());
        }
        retained(j, &i).map_err(|_| "unknown bounded source job blocks dispatch")?;
    }
    Ok(())
}
fn execute(
    j: &Journal,
    i: &Value,
    payload: &[u8],
    run: impl FnOnce(&Value, &[u8]) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    parse(&bytes(i)?)?;
    if i["source_bytes"] != payload.len() || text(i, "source_archive_sha256") != sha(payload) {
        return Err("outside source archive byte binding differs before dispatch".into());
    }
    let job = text(i, "job_id");
    j.retain(job, INTENT, &bytes(i)?)?;
    if !j.absent(job, DISPATCH)? {
        return retained(j, i);
    }
    if !j.absent(job, RETURN)? || !j.absent(job, RESULT)? {
        return Err("orphan bounded source result blocks dispatch".into());
    }
    super::idle(j)?;
    j.write(job, DISPATCH, &dispatch(i)?)?;
    stable(j, i)?;
    let raw = run(i, payload)
        .map_err(|_| "bounded source transfer uncertain; dispatch consumed, never retry")?;
    stable(j, i)?;
    j.write(job, RETURN, &raw)?;
    let value = result(i, &raw)?;
    j.write(job, RESULT, &bytes(&value)?)?;
    retained(j, i)
}
fn summary(i: &Value, result: &Value) -> Value {
    json!({"schema":"hol-gauntlet-host-bounded-source-transfer.v1","job_id":i["job_id"],"source_sha":i["source_sha"],
        "source_archive_sha256":i["source_archive_sha256"],"source_bytes":i["source_bytes"],"worker_generation":i["worker_generation"],
        "storage_profile":i["storage_profile"],"intent_sha256":result["intent_sha256"],"capture_sha256":result["capture_sha256"],
        "storage_receipt_sha256":result["storage_receipt_sha256"],"source_graph_verified":true,"builder_executed":false,
        "execution_eligible":false,"qualification_eligible":false,"model_requests":0})
}
pub(super) fn run_command(args: &[String]) -> Result<Value, String> {
    if args.len() != 13
        || !matches!(
            args[0].as_str(),
            "transfer-bounded" | "transfer-bounded-read"
        )
    {
        return Err(USAGE.into());
    }
    // Complete argument validation before any source-state bytes are opened.
    intent(args, 1)?;
    let (payload, inventory) =
        crate::source_archive::verified_archive_bytes(Path::new(&args[1]), &args[3], &args[5])
            .map_err(|e| e.to_string())?;
    crate::source_archive_commit::verify_archive_commit_bytes(
        &args[3],
        &payload,
        inventory,
        &args[4],
        &format!("refs/heads/local-{}", args[4]),
    )
    .map_err(|e| e.to_string())?;
    let i = intent(args, payload.len())?;
    let mut j = Journal::open(Path::new(&args[2]))?;
    j.lock()?;
    let mut lima = context::Lima::open_pinned(
        super::LIMA,
        text(&i, "lima_sha256"),
        &i["transport_context"],
    )?;
    let reading = args[0] == "transfer-bounded-read";
    let rpc = |i: &Value, input: &[u8]| {
        let mut command = lima.command(text(i, "vm"))?;
        command.args([
            format!(
                "/opt/hol-gauntlet/rust-native-dependency-worker-{}",
                text(i, "worker_generation")
            ),
            if reading {
                "--read-build-source-capture-v2"
            } else {
                "--capture-build-source-v2"
            }
            .into(),
            text(i, "job_id").into(),
            text(i, "source_sha").into(),
            text(i, "source_archive_sha256").into(),
            i["source_bytes"]
                .as_u64()
                .ok_or("source byte bound absent")?
                .to_string(),
            text(i, "worker_generation").into(),
            text(i, "storage_profile").into(),
            text(i, "mke2fs_sha256").into(),
        ]);
        let output = crate::stream_process::run_streamed_command(
            command,
            input,
            Duration::from_secs(360),
            16385,
        )
        .map_err(|_| "bounded source transport uncertain")?;
        lima.recheck()?;
        Ok(output)
    };
    let value = if reading {
        read_completed(&j, &i, rpc)?
    } else {
        execute(&j, &i, &payload, rpc)?
    };
    Ok(summary(&i, &value))
}

/// Safe closed context for a later build. The original source journal's whole
/// ancestry and completed storage proof are checked without exposing any key.
pub(super) fn completed(path: &Path, job: &str, outside: &str) -> Result<Value, String> {
    if !hex(job, 16) || !hex(outside, 64) {
        return Err("outside completed source pins required".into());
    }
    let j = Journal::open(path)?;
    let raw = j.read(job, INTENT)?;
    if sha(&raw) != outside {
        return Err("outside bounded source intent digest differs".into());
    }
    let i = parse(&raw)?;
    if text(&i, "job_id") != job {
        return Err("bounded source job differs".into());
    }
    let done = retained(&j, &i)?;
    let context = context::snapshot(path)?;
    j.stable()?;
    Ok(
        json!({"schema":"hol-gauntlet-host-bounded-source-context.v1","journal":path,
        "journal_custody":context,"intent":i,"intent_sha256":outside,
        "capture_sha256":done["capture_sha256"],"storage_receipt_sha256":done["storage_receipt_sha256"],
        "source_graph_verified":true,"qualification_eligible":false}),
    )
}

#[cfg(test)]
#[path = "candidate_bounded_transfer_tests.rs"]
pub(crate) mod tests;
