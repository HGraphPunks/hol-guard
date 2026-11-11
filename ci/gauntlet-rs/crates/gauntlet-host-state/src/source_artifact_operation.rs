//! Original Source artifact bytes must exist durably on Host before Root ack.
use super::super::{bytes, context, hex, sha, Journal};
use serde_json::{json, Value};
use std::{fs::File, path::Path, time::Duration};
#[path = "source_artifact_file.rs"]
mod file;
#[path = "source_artifact_protocol.rs"]
mod protocol;
pub(super) use protocol::{candidate_proof, candidate_read_args, candidate_read_header};
const INTENT: &str = "source-artifact-intent";
const DOWNLOAD: &str = "source-artifact-download-dispatch";
const EXPORT: &str = "source-artifact-export";
const RECEIPT: &str = "source-artifact-host-receipt";
const ACK: &str = "source-artifact-ack";
const ACK_DISPATCH: &str = "source-artifact-ack-dispatch";
const RETIRE: &str = "source-artifact-retirement-intent";
const RETIRE_DISPATCH: &str = "source-artifact-retirement-dispatch";
const RETIRED: &str = "source-artifact-retired";
pub const SOURCE_ARTIFACT_USAGE:&str="artifacts commands:\nrecord PRIVATE_0700_JOURNAL PRIVATE_TRANSFER_DIR SOURCE_TRANSFER_INTENT_SHA256 PRIVATE_FLOW_DIR JOB_ID candidate|dependency RESULT_SHA256 ARCHIVE_SHA256 EXPORTER_SHA256\ndownload|download-read|ack|ack-read PRIVATE_JOURNAL JOB_ID INTENT_SHA256\nretire PRIVATE_JOURNAL JOB_ID INTENT_SHA256 RETIRER_SHA256\nretire-read|retire-resume PRIVATE_JOURNAL JOB_ID INTENT_SHA256\nZIP bytes stay in files created once with mode 0600 under the 0700 journal. Partial files are preserved; at most 4 explicit read attempts. Ack and retirement verify actual retained bytes and the original bounded Source/readback. Retire-resume continues only the original consumed cleanup; retire-read never mutates Root state. Host receipt hashes are derived internally; workloads are never replayed.";
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str()
        .ok_or_else(|| format!("Source artifact {k} absent"))
}
fn parse(raw: &[u8]) -> Result<Value, String> {
    let i: Value =
        serde_json::from_slice(raw).map_err(|_| "Source artifact intent JSON invalid")?;
    if bytes(&i)? != raw
        || i.as_object().is_none_or(|o| o.len() != 10)
        || i["schema"] != "hol-gauntlet-host-source-artifact-intent.v1"
        || !hex(text(&i, "job_id")?, 16)
        || !["result_sha256", "archive_sha256", "exporter_generation"]
            .iter()
            .all(|k| i[*k].as_str().is_some_and(|s| hex(s, 64)))
        || i["execution_eligible"] != false
        || i["qualification_eligible"] != false
        || !matches!(text(&i, "kind")?, "candidate" | "dependency")
        || i["source"]["intent"]["job_id"] != i["job_id"]
        || i["source"]["intent"]["storage_profile"]
            != if i["kind"] == "candidate" {
                "build-v1"
            } else {
                "dependency-v1"
            }
    {
        return Err("exact original bounded Source/artifact pins required".into());
    }
    recheck(&i)?;
    Ok(i)
}
fn flow(i: &Value) -> Result<Value, String> {
    let path = Path::new(text(&i["flow"], "journal")?);
    let job = text(i, "job_id")?;
    let result = text(i, "result_sha256")?;
    let archive = text(i, "archive_sha256")?;
    if i["kind"] == "candidate" {
        super::bounded::flow(path, &i["source"], job, result, archive)
    } else {
        super::dependencies::flow(path, &i["source"], job, result, archive)
    }
}
fn recheck(i: &Value) -> Result<(), String> {
    let s = &i["source"];
    if super::source::completed(
        Path::new(text(s, "journal")?),
        text(i, "job_id")?,
        text(s, "intent_sha256")?,
    )? != *s
        || flow(i)? != i["flow"]
    {
        return Err("original Source, flow or transport custody changed".into());
    }
    Ok(())
}
fn stable(j: &Journal, i: &Value) -> Result<(), String> {
    if j.read(text(i, "job_id")?, INTENT)? != bytes(i)? {
        return Err("Source artifact intent changed".into());
    }
    recheck(i)?;
    j.stable()
}
fn marker(i: &Value, operation: &str) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-source-artifact-dispatch.v1","intent_sha256":sha(&bytes(i)?),"operation":operation,"retry_allowed":false}),
    )
}
fn value(j: &Journal, i: &Value, suffix: &str) -> Result<Value, String> {
    let raw = j.read(text(i, "job_id")?, suffix)?;
    let v: Value =
        serde_json::from_slice(&raw).map_err(|_| "Source artifact record JSON invalid")?;
    if raw != bytes(&v)? {
        return Err("canonical Source artifact record required".into());
    }
    Ok(v)
}
trait Rpc {
    fn control(&mut self, argv: &[String]) -> Result<Vec<u8>, String>;
    fn archive(&mut self, argv: &[String], file: &mut File) -> Result<usize, String>;
}
struct Owned<'a> {
    lima: context::Lima,
    i: &'a Value,
}
impl Owned<'_> {
    fn command(&mut self, argv: &[String]) -> Result<std::process::Command, String> {
        let mut c = self
            .lima
            .command(text(&self.i["source"]["intent"], "vm")?)?;
        c.args(argv);
        Ok(c)
    }
}
impl Rpc for Owned<'_> {
    fn control(&mut self, argv: &[String]) -> Result<Vec<u8>, String> {
        let c = self.command(argv)?;
        let raw =
            crate::stream_process::run_streamed_command(c, b"", Duration::from_secs(180), 32769)
                .map_err(|_| "Source artifact control return uncertain")?;
        self.lima.recheck()?;
        Ok(raw)
    }
    fn archive(&mut self, argv: &[String], file: &mut File) -> Result<usize, String> {
        let c = self.command(argv)?;
        let n = crate::stream_process::run_streamed_to_file(
            c,
            file,
            Duration::from_secs(360),
            file::LIMIT,
        )
        .map_err(|_| "Source ZIP download uncertain; preserve partial private file")?;
        self.lima.recheck()?;
        Ok(n)
    }
}
fn reply(raw: &[u8]) -> Result<Value, String> {
    let frame = raw.strip_suffix(b"\n").unwrap_or(raw);
    if frame.len() > 32768 {
        return Err("bounded Source artifact reply required".into());
    }
    let v: Value =
        serde_json::from_slice(frame).map_err(|_| "Source artifact reply JSON invalid")?;
    if bytes(&v)? != frame {
        return Err("canonical Source artifact reply required".into());
    }
    Ok(v)
}
fn exported(j: &Journal, i: &Value) -> Result<Value, String> {
    protocol::export(i, &value(j, i, EXPORT)?)
}
fn observe_export(j: &Journal, i: &Value, rpc: &mut impl Rpc) -> Result<Value, String> {
    stable(j, i)?;
    let raw = rpc.control(&protocol::export_args(
        i,
        "--read-source-job-artifact-export-v1",
    )?)?;
    stable(j, i)?;
    let state = protocol::export(i, &reply(&raw)?)?;
    j.retain(text(i, "job_id")?, EXPORT, &bytes(&state)?)?;
    Ok(state)
}
fn seal(j: &Journal, i: &Value, export: &Value, h: &mut file::Held) -> Result<Value, String> {
    h.finish(j, text(i, "archive_sha256")?)?;
    if h.facts["bytes"] != export["receipt"]["archive_bytes"] {
        return Err("actual Host file length differs from Root export".into());
    }
    stable(j, i)?;
    let receipt = file::receipt(j, i, export, h)?;
    j.write(text(i, "job_id")?, RECEIPT, &bytes(&receipt)?)?;
    h.verify(j, text(i, "archive_sha256")?)?;
    Ok(receipt)
}
fn download(j: &Journal, i: &Value, read: bool, rpc: &mut impl Rpc) -> Result<Value, String> {
    stable(j, i)?;
    let job = text(i, "job_id")?;
    if !read {
        if !j.absent(job, DOWNLOAD)? || !j.absent(job, RECEIPT)? {
            return Err("Source download already consumed; use explicit download-read".into());
        }
        for n in 1..=4 {
            if !file::absent(j, job, n)? {
                return Err("orphan archive file blocks initial download".into());
            }
        }
        super::idle(j)?;
        j.write(job, DOWNLOAD, &marker(i, "download")?)?;
    } else if j.read(job, DOWNLOAD)? != marker(i, "download")? {
        return Err("original consumed Source download required".into());
    }
    if !j.absent(job, RECEIPT)? {
        let e = exported(j, i)?;
        file::retained(j, i, &e)?;
        return summary(j, i, "downloaded");
    }
    if read {
        // A complete file whose SSH completion was lost can be reconciled
        // without downloading again. Partial attempts are never truncated.
        for n in 1..=4 {
            if !file::absent(j, job, n)? {
                let mut h = file::open_attempt(j, job, n)?;
                if h.verify(j, text(i, "archive_sha256")?).is_ok() {
                    let e = observe_export(j, i, rpc)?;
                    seal(j, i, &e, &mut h)?;
                    return summary(j, i, "downloaded");
                }
            }
        }
    }
    let attempt = (1..=4)
        .find(|n| file::absent(j, job, *n).unwrap_or(false))
        .ok_or("Source download attempts exhausted; preserve all private evidence")?;
    let mut h = file::create(j, job, attempt)?;
    j.write(job,&format!("source-artifact-attempt-{attempt:04}"),&bytes(&json!({"schema":"hol-gauntlet-host-source-artifact-attempt.v1","intent_sha256":sha(&bytes(i)?),"attempt":attempt,"read_only":read,"file":h.name}))?)?;
    stable(j, i)?;
    rpc.archive(
        &protocol::export_args(
            i,
            if read {
                "--read-source-job-artifact-v1"
            } else {
                "--export-source-job-artifact-v1"
            },
        )?,
        &mut h.file,
    )?;
    h.finish(j, text(i, "archive_sha256")?)?;
    stable(j, i)?;
    let e = observe_export(j, i, rpc)?;
    seal(j, i, &e, &mut h)?;
    summary(j, i, "downloaded")
}
fn acknowledge(j: &Journal, i: &Value, read: bool, rpc: &mut impl Rpc) -> Result<Value, String> {
    stable(j, i)?;
    let job = text(i, "job_id")?;
    let e = exported(j, i)?;
    let (mut h, _, host_sha) = file::retained(j, i, &e)?;
    let dispatch = marker(i, "ack")?;
    if read {
        if j.read(job, ACK_DISPATCH)? != dispatch {
            return Err("original Source ack dispatch required".into());
        }
    } else {
        j.write(job, ACK_DISPATCH, &dispatch)?;
    }
    let mut args = protocol::export_args(
        i,
        if read {
            "--read-source-job-artifact-ack-v1"
        } else {
            "--ack-source-job-artifact-v1"
        },
    )?;
    args.extend([text(&e, "receipt_sha256")?.into(), host_sha.clone()]);
    h.verify(j, text(i, "archive_sha256")?)?;
    let raw = rpc.control(&args)?;
    stable(j, i)?;
    h.verify(j, text(i, "archive_sha256")?)?;
    let a = protocol::ack(i, &e, &host_sha, &reply(&raw)?)?;
    j.retain(job, ACK, &bytes(&a)?)?;
    summary(j, i, "acknowledged")
}
fn retire(
    j: &Journal,
    i: &Value,
    generation: Option<&str>,
    rpc: &mut impl Rpc,
) -> Result<Value, String> {
    retire_operation(j, i, generation, false, rpc)
}
fn retire_operation(
    j: &Journal,
    i: &Value,
    generation: Option<&str>,
    resume: bool,
    rpc: &mut impl Rpc,
) -> Result<Value, String> {
    stable(j, i)?;
    let job = text(i, "job_id")?;
    let e = exported(j, i)?;
    let (mut h, _, host_sha) = file::retained(j, i, &e)?;
    let a = protocol::ack(i, &e, &host_sha, &value(j, i, ACK)?)?;
    if resume && generation.is_some() {
        return Err("resumed retirement must retain its original generation".into());
    }
    let read = generation.is_none() && !resume;
    let intent = if let Some(g) = generation {
        if !hex(g, 64) {
            return Err("exact Source retirer SHA required".into());
        }
        let expected = protocol::retirement_intent(i, &e, &a, &host_sha, g);
        j.write(job, RETIRE, &bytes(&expected)?)?;
        expected
    } else {
        let old = value(j, i, RETIRE)?;
        let expected =
            protocol::retirement_intent(i, &e, &a, &host_sha, text(&old, "retirer_generation")?);
        if old != expected {
            return Err("Source retirement intent changed".into());
        }
        old
    };
    let marker = bytes(
        &json!({"schema":"hol-gauntlet-host-source-retirement-dispatch.v1","intent_sha256":sha(&bytes(i)?),"retirement_intent_sha256":sha(&bytes(&intent)?),"retry_allowed":false}),
    )?;
    if read || resume {
        if j.read(job, RETIRE_DISPATCH)? != marker {
            return Err("original Source retirement dispatch required".into());
        }
    } else {
        j.write(job, RETIRE_DISPATCH, &marker)?;
    }
    let s = &i["source"]["intent"];
    let g = text(&intent, "retirer_generation")?;
    let args = vec![
        format!("/opt/hol-gauntlet/rust-native-dependency-worker-{g}"),
        if read {
            "--read-source-job-storage-retirement-v1".into()
        } else {
            "--retire-source-job-storage-v1".into()
        },
        text(s, "source_sha")?.into(),
        job.into(),
        text(s, "worker_generation")?.into(),
        text(s, "storage_profile")?.into(),
        text(s, "mke2fs_sha256")?.into(),
        text(&i["source"], "storage_receipt_sha256")?.into(),
        text(i, "archive_sha256")?.into(),
        text(i, "result_sha256")?.into(),
        text(&i["flow"], "host_binding_sha256")?.into(),
        g.into(),
        host_sha,
    ];
    h.verify(j, text(i, "archive_sha256")?)?;
    let raw = rpc.control(&args)?;
    stable(j, i)?;
    h.verify(j, text(i, "archive_sha256")?)?;
    let retired = protocol::retirement(i, &intent, &reply(&raw)?)?;
    j.retain(job, RETIRED, &bytes(&retired)?)?;
    summary(j, i, "retired")
}
fn summary(j: &Journal, i: &Value, state: &str) -> Result<Value, String> {
    let host = if j.absent(text(i, "job_id")?, RECEIPT)? {
        Value::Null
    } else {
        let e = exported(j, i)?;
        let (_, _, actual) = file::retained(j, i, &e)?;
        json!(actual)
    };
    Ok(
        json!({"schema":"hol-gauntlet-host-source-artifact-operation.v1","state":state,"job_id":i["job_id"],"kind":i["kind"],"intent_sha256":sha(&bytes(i)?),"archive_sha256":i["archive_sha256"],"host_receipt_sha256":host,"execution_eligible":false,"qualification_eligible":false}),
    )
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    if let Some(job) = name.strip_suffix(".native-source-artifact-download-dispatch.json") {
        let i = parse(&j.read(job, INTENT)?)?;
        stable(j, &i)?;
        if j.read(job, DOWNLOAD)? != marker(&i, "download")? {
            return Err("Source artifact dispatch changed".into());
        }
        let e = exported(j, &i)?;
        let (_, _, host_sha) = file::retained(j, &i, &e)?;
        if !j.absent(job, RETIRE_DISPATCH)? {
            let a = protocol::ack(&i, &e, &host_sha, &value(j, &i, ACK)?)?;
            let intent = value(j, &i, RETIRE)?;
            let expected = protocol::retirement_intent(
                &i,
                &e,
                &a,
                &host_sha,
                text(&intent, "retirer_generation")?,
            );
            if intent != expected {
                return Err("outside Source retirement authority changed".into());
            }
            protocol::retirement(&i, &expected, &value(j, &i, RETIRED)?)?;
        }
    }
    Ok(())
}
fn record(args: &[String]) -> Result<Value, String> {
    let source = super::source::completed(Path::new(&args[2]), &args[5], &args[3])?;
    let mut i = json!({"schema":"hol-gauntlet-host-source-artifact-intent.v1","job_id":args[5],"kind":args[6],"source":source,"flow":{"journal":args[4]},"result_sha256":args[7],"archive_sha256":args[8],"exporter_generation":args[9],"execution_eligible":false,"qualification_eligible":false});
    if !matches!(args[6].as_str(), "candidate" | "dependency") {
        return Err("closed artifact kind required".into());
    }
    i["flow"] = flow(&i)?;
    let i = parse(&bytes(&i)?)?;
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    j.retain(text(&i, "job_id")?, INTENT, &bytes(&i)?)?;
    summary(&j, &i, "recorded")
}
pub fn run_source_artifact_command(args: &[String]) -> Result<Value, String> {
    match (args.first().map(String::as_str), args.len()) {
        (Some("record"), 10) => return record(args),
        (
            Some(
                "download" | "download-read" | "ack" | "ack-read" | "retire-read" | "retire-resume",
            ),
            4,
        ) => {}
        (Some("retire"), 5) => {}
        _ => return Err(SOURCE_ARTIFACT_USAGE.into()),
    }
    if !hex(&args[2], 16) || !hex(&args[3], 64) {
        return Err("outside Source artifact job/intent pins required".into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let raw = j.read(&args[2], INTENT)?;
    if sha(&raw) != args[3] {
        return Err("outside Source artifact intent differs".into());
    }
    let i = parse(&raw)?;
    if i["job_id"] != args[2] {
        return Err("Source artifact job differs".into());
    }
    let s = &i["source"]["intent"];
    let lima = context::Lima::open_pinned(
        text(s, "limactl")?,
        text(s, "lima_sha256")?,
        &s["transport_context"],
    )?;
    let mut rpc = Owned { lima, i: &i };
    match args[0].as_str() {
        "download" | "download-read" => download(&j, &i, args[0] == "download-read", &mut rpc),
        "ack" | "ack-read" => acknowledge(&j, &i, args[0] == "ack-read", &mut rpc),
        "retire" => retire(&j, &i, Some(&args[4]), &mut rpc),
        "retire-read" => retire(&j, &i, None, &mut rpc),
        "retire-resume" => retire_operation(&j, &i, None, true, &mut rpc),
        _ => unreachable!(),
    }
}

#[cfg(test)]
#[path = "source_artifact_operation_tests.rs"]
mod tests;
