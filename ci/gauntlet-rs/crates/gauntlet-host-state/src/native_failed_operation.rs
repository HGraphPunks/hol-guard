//! Explicit custody and cleanup of an original unsigned readonly startup failure.
use super::{artifact, bytes, context, hex, preparation, sha, transport::Lima, Intent, Journal};
use crate::stream_process::{
    run_streamed_command as pipe_json, run_streamed_input_to_file as pipe_file,
};
use serde_json::{json, Value};
use std::{fs::File, path::Path, time::Duration};
#[path = "native_failed_protocol.rs"]
mod protocol;
use protocol::{archive_name, marker, parse, text};
const LIMIT: usize = 32 * 1024 * 1024 + 65536;
pub(super) const INTENT: &str = "readonly-failure-intent";
const DOWNLOAD: &str = "readonly-failure-download-dispatch";
const EXPORT: &str = "readonly-failure-export";
const RECEIPT: &str = "readonly-failure-host-receipt";
const AD: &str = "readonly-failure-ack-dispatch";
const ACK: &str = "readonly-failure-ack";
const REQUEST: &str = "readonly-failure-retirement-request";
const RETIRE: &str = "readonly-failure-retirement-intent";
const RD: &str = "readonly-failure-retirement-dispatch";
const RETIRED: &str = "readonly-failure-retired";
pub(super) const USAGE: &str = "failure-record PRIVATE_JOURNAL JOB_ID ORIGINAL_NATIVE_INTENT_SHA READER_SHA\nfailure-download|failure-download-read|failure-download-resume|failure-ack|failure-ack-read|failure-ack-resume PRIVATE_JOURNAL JOB_ID FAILURE_INTENT_SHA\nfailure-retire PRIVATE_JOURNAL JOB_ID FAILURE_INTENT_SHA RETIRER_SHA\nfailure-retire-read|failure-retire-resume PRIVATE_JOURNAL JOB_ID FAILURE_INTENT_SHA\nOnly original bounded readonly jobs with an empty unsigned controller output and an actual nonzero ordinary exit qualify for failure custody. This is not a verified controller completion. Private archives preserve actual records, logs and historical cleanup failures. ACK and retirement require durable actual Host bytes; explicit resumes retain original authority and never replay work. Model usage remains unknown.";
pub(super) fn handles(args: &[String]) -> bool {
    args.first().is_some_and(|a| a.starts_with("failure-"))
}
trait Rpc {
    fn call(
        &mut self,
        args: &[String],
        input: &[u8],
        output: Option<&mut File>,
    ) -> Result<Vec<u8>, String>;
}
struct Transport<'a> {
    lima: Lima,
    intent: &'a Intent,
}
impl Rpc for Transport<'_> {
    fn call(
        &mut self,
        args: &[String],
        input: &[u8],
        output: Option<&mut File>,
    ) -> Result<Vec<u8>, String> {
        let mut command = self.lima.command(self.intent.text("vm"))?;
        command.args(args);
        let timeout = Duration::from_secs(1020);
        let raw = match output {
            Some(file) => pipe_file(command, input, file, timeout, LIMIT).map(|_| Vec::new()),
            None => pipe_json(command, input, timeout, 8193),
        }
        .map_err(|_| {
            "readonly failure operation uncertain; preserve bytes and use exact read or resume"
        })?;
        self.lima.recheck()?;
        Ok(raw)
    }
}
fn args(
    f: &Value,
    selector: &str,
    input: &[u8],
    tail: &[String],
    generation: Option<&str>,
) -> Result<Vec<String>, String> {
    let g = generation.unwrap_or(text(f, "reader_generation")?);
    let mut a = vec![
        format!("/opt/hol-gauntlet/rust-native-host-pinned-worker-{g}"),
        selector.into(),
    ];
    for k in protocol::BASE {
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
fn stored(j: &Journal, i: &Intent) -> Result<Value, String> {
    let f = parse(&j.read(i.job(), INTENT)?)?;
    protocol::stable(j, i, &f)?;
    Ok(f)
}
fn exit(j: &Journal, i: &Intent) -> Result<Value, String> {
    Ok(parse(&j.read(i.job(), "return")?)?["report"]["exit_code"].clone())
}
fn export(j: &Journal, i: &Intent, f: &Value) -> Result<Value, String> {
    if j.read(i.job(), DOWNLOAD)? != marker(f, "download", &protocol::export_intent(f))? {
        return Err("original readonly failure download dispatch differs".into());
    }
    protocol::export(f, &j.read(i.job(), EXPORT)?, &exit(j, i)?)
}
fn observe(
    j: &Journal,
    i: &Intent,
    f: &Value,
    rpc: &mut impl Rpc,
) -> Result<Option<Value>, String> {
    protocol::stable(j, i, f)?;
    let raw = rpc.call(
        &args(
            f,
            "--read-native-readonly-failure-export-v1",
            b"",
            &[],
            None,
        )?,
        b"",
        None,
    )?;
    protocol::stable(j, i, f)?;
    protocol::state(f, &raw, &exit(j, i)?)
}
fn receipt(f: &Value, e: &Value, held: &artifact::HeldPrivateArchive) -> Result<Value, String> {
    Ok(
        json!({"schema":"hol-gauntlet-host-native-readonly-failure-file.v1","failure_intent_sha256":sha(&bytes(f)?),"export_receipt_sha256":e["receipt_sha256"],"archive_sha256":e["receipt"]["archive_sha256"],"archive_bytes":e["receipt"]["archive_bytes"],"file":held.facts,"parent_custody":f["parent_custody"]}),
    )
}
fn custody(
    j: &Journal,
    i: &Intent,
    f: &Value,
) -> Result<(Value, Value, artifact::HeldPrivateArchive), String> {
    protocol::stable(j, i, f)?;
    let e = export(j, i, f)?;
    let h = parse(&j.read(i.job(), RECEIPT)?)?;
    let name = text(&h["file"], "name")?;
    if !(1..=4).any(|n| name == archive_name(i.job(), n)) {
        return Err("original readonly failure file name required".into());
    }
    let mut held = artifact::open_private_archive(j, name.into())?;
    held.verify(j, text(&e["receipt"], "archive_sha256")?)?;
    if h != receipt(f, &e, &held)? || j.read(i.job(), RECEIPT)? != bytes(&h)? {
        return Err("actual readonly failure Host receipt differs".into());
    }
    let raw = crate::native_diagnostic_archive::read_stable(
        &j.path.join(name),
        text(&e["receipt"], "archive_sha256")?,
    )?;
    protocol::archive(j, i, f, &e, &raw)?;
    Ok((e, h, held))
}
fn tail(e: &Value, h: &Value) -> Result<Vec<String>, String> {
    Ok(vec![text(e, "receipt_sha256")?.into(), sha(&bytes(h)?)])
}
fn download(
    j: &Journal,
    i: &Intent,
    f: &Value,
    action: &str,
    rpc: &mut impl Rpc,
) -> Result<Value, String> {
    protocol::stable(j, i, f)?;
    let m = marker(f, "download", &protocol::export_intent(f))?;
    if action == "failure-download" {
        for s in [DOWNLOAD, EXPORT, RECEIPT] {
            if !j.absent(i.job(), s)? {
                return Err(
                    "readonly failure download consumed; use read or explicit resume".into(),
                );
            }
        }
        j.write(i.job(), DOWNLOAD, &m)?;
    } else if j.read(i.job(), DOWNLOAD)? != m {
        return Err("original readonly failure download dispatch required".into());
    }
    if !j.absent(i.job(), RECEIPT)? {
        custody(j, i, f)?;
        return summary(j, i, f, action);
    }
    if action != "failure-download" {
        let e = match observe(j, i, f, rpc) {
            Ok(e) => e,
            Err(_) if action == "failure-download-resume" => None,
            Err(e) => return Err(e),
        };
        if let Some(e) = e {
            if protocol::recover(j, i, f, &e)? {
                custody(j, i, f)?;
                return summary(j, i, f, action);
            }
        }
    }
    let mut next = None;
    for n in 1..=4 {
        let s = format!("readonly-failure-download-attempt-{n:04}");
        if j.absent(i.job(), &s)? {
            next = Some((n, s));
            break;
        }
    }
    let (n, s) =
        next.ok_or("readonly failure archive attempt limit reached; preserve every partial")?;
    let attempt = json!({"schema":"hol-gauntlet-host-native-readonly-failure-attempt.v1","failure_intent_sha256":sha(&bytes(f)?),"attempt":n,"operation":action});
    j.write(i.job(), &s, &bytes(&attempt)?)?;
    let mut held = artifact::create_private_archive(j, archive_name(i.job(), n))?;
    let initial = action == "failure-download";
    let resume = action == "failure-download-resume";
    let input = if initial || resume {
        bytes(&f["prelaunch"])?
    } else {
        Vec::new()
    };
    let selector = if initial {
        "--export-native-readonly-failure-v1"
    } else if resume {
        "--resume-native-readonly-failure-v1"
    } else {
        "--read-native-readonly-failure-v1"
    };
    protocol::stable(j, i, f)?;
    let outcome = rpc.call(
        &args(f, selector, &input, &[], None)?,
        &input,
        Some(&mut held.file),
    );
    held.file
        .sync_all()
        .map_err(|_| "partial readonly failure bytes could not sync")?;
    outcome?;
    protocol::stable(j, i, f)?;
    let e = observe(j, i, f, rpc)?
        .ok_or("Root readonly failure export incomplete; use explicit resume")?;
    held.finish(j, text(&e["receipt"], "archive_sha256")?)?;
    let raw = crate::native_diagnostic_archive::read_stable(
        &j.path.join(&held.name),
        text(&e["receipt"], "archive_sha256")?,
    )?;
    protocol::archive(j, i, f, &e, &raw)?;
    let h = receipt(f, &e, &held)?;
    j.retain(i.job(), EXPORT, &bytes(&e)?)?;
    j.write(i.job(), RECEIPT, &bytes(&h)?)?;
    custody(j, i, f)?;
    summary(j, i, f, action)
}
fn retained_ack(j: &Journal, i: &Intent, f: &Value, e: &Value, h: &Value) -> Result<Value, String> {
    if j.read(i.job(), AD)?
        != marker(
            f,
            "ack",
            &json!({"export":e["receipt_sha256"],"host_receipt_sha256":sha(&bytes(h)?)}),
        )?
    {
        return Err("original readonly failure ACK dispatch differs".into());
    }
    protocol::ack(e, h, &j.read(i.job(), ACK)?)
}
fn acknowledge(
    j: &Journal,
    i: &Intent,
    f: &Value,
    action: &str,
    rpc: &mut impl Rpc,
) -> Result<Value, String> {
    let (e, h, mut held) = custody(j, i, f)?;
    let m = marker(
        f,
        "ack",
        &json!({"export":e["receipt_sha256"],"host_receipt_sha256":sha(&bytes(&h)?)}),
    )?;
    if action == "failure-ack" {
        if !j.absent(i.job(), AD)? || !j.absent(i.job(), ACK)? {
            return Err("readonly failure ACK consumed; use read or resume".into());
        }
        j.write(i.job(), AD, &m)?;
    } else if j.read(i.job(), AD)? != m {
        return Err("original readonly failure ACK dispatch required".into());
    }
    if !j.absent(i.job(), ACK)? {
        retained_ack(j, i, f, &e, &h)?;
        return summary(j, i, f, action);
    }
    let t = tail(&e, &h)?;
    let read = action != "failure-ack";
    let read_args = args(f, "--read-native-readonly-failure-ack-v1", b"", &t, None)?;
    let raw = if read {
        match rpc.call(&read_args, b"", None) {
            Ok(raw) => raw,
            Err(_) if action == "failure-ack-resume" => {
                custody(j, i, f)?;
                rpc.call(
                    &args(f, "--ack-native-readonly-failure-v1", b"", &t, None)?,
                    b"",
                    None,
                )?
            }
            Err(e) => return Err(e),
        }
    } else {
        rpc.call(
            &args(f, "--ack-native-readonly-failure-v1", b"", &t, None)?,
            b"",
            None,
        )?
    };
    j.retain(
        i.job(),
        &format!("readonly-failure-ack-frame-{}", sha(&raw)),
        &raw,
    )?;
    let a = protocol::ack(&e, &h, &raw)?;
    held.verify(j, text(&e["receipt"], "archive_sha256")?)?;
    custody(j, i, f)?;
    if j.read(i.job(), AD)? != m {
        return Err("readonly failure ACK dispatch changed".into());
    }
    j.retain(i.job(), ACK, &bytes(&a)?)?;
    summary(j, i, f, action)
}
fn retired_context(
    j: &Journal,
    i: &Intent,
    f: &Value,
) -> Result<(Value, Value, Value, Value, artifact::HeldPrivateArchive), String> {
    let (e, h, held) = custody(j, i, f)?;
    let a = retained_ack(j, i, f, &e, &h)?;
    let request = parse(&j.read(i.job(), REQUEST)?)?;
    let g = text(&request, "retirer_generation")?;
    if request
        != json!({"schema":"hol-gauntlet-host-native-readonly-failure-retirement-request.v1","failure_intent_sha256":sha(&bytes(f)?),"retirer_generation":g})
    {
        return Err("original readonly failure retirement request differs".into());
    }
    let r = protocol::retirement(f, &e, &h, &a, g)?;
    Ok((e, h, a, r, held))
}
fn retire(
    j: &Journal,
    i: &Intent,
    f: &Value,
    action: &str,
    generation: Option<&str>,
    rpc: &mut impl Rpc,
) -> Result<Value, String> {
    if action == "failure-retire" {
        custody(j, i, f)?;
        let g = generation
            .filter(|s| hex(s, 64))
            .ok_or("outside readonly failure retirer SHA required")?;
        for s in [REQUEST, RETIRE, RD, RETIRED] {
            if !j.absent(i.job(), s)? {
                return Err(
                    "readonly failure retirement consumed; use read or explicit resume".into(),
                );
            }
        }
        let (e, h, _) = custody(j, i, f)?;
        retained_ack(j, i, f, &e, &h)?;
        j.write(i.job(),REQUEST,&bytes(&json!({"schema":"hol-gauntlet-host-native-readonly-failure-retirement-request.v1","failure_intent_sha256":sha(&bytes(f)?),"retirer_generation":g}))?)?;
    }
    let (e, h, _, r, mut held) = retired_context(j, i, f)?;
    let rb = bytes(&r)?;
    let m = marker(f, "retire", &r)?;
    if j.absent(i.job(), RETIRE)? && action != "failure-retire-read" {
        j.write(i.job(), RETIRE, &rb)?;
    }
    if j.read(i.job(), RETIRE)? != rb {
        return Err("original readonly failure retirement intent differs".into());
    }
    if j.absent(i.job(), RD)? && action != "failure-retire-read" {
        j.write(i.job(), RD, &m)?;
    }
    if j.read(i.job(), RD)? != m {
        return Err("original readonly failure retirement dispatch differs".into());
    }
    if !j.absent(i.job(), RETIRED)? {
        protocol::retired(&r, &j.read(i.job(), RETIRED)?)?;
        return summary(j, i, f, action);
    }
    let g = text(&r, "retirer_generation")?;
    let mut t = tail(&e, &h)?;
    t.push(g.into());
    let selector = if action == "failure-retire-read" {
        "--read-native-readonly-failure-retirement-v1"
    } else {
        "--retire-native-readonly-failure-storage-v1"
    };
    let raw = rpc.call(&args(f, selector, b"", &t, Some(g))?, b"", None)?;
    j.retain(
        i.job(),
        &format!("readonly-failure-retirement-frame-{}", sha(&raw)),
        &raw,
    )?;
    let result = protocol::retired(&r, &raw)?;
    held.verify(j, text(&e["receipt"], "archive_sha256")?)?;
    let (_, _, _, again, _) = retired_context(j, i, f)?;
    if again != r || j.read(i.job(), RETIRE)? != rb || j.read(i.job(), RD)? != m {
        return Err("readonly failure cleanup custody changed".into());
    }
    j.retain(i.job(), RETIRED, &bytes(&result)?)?;
    summary(j, i, f, action)
}
fn summary(j: &Journal, i: &Intent, f: &Value, action: &str) -> Result<Value, String> {
    Ok(
        json!({"schema":"hol-gauntlet-host-native-readonly-failure.v1","operation":action,"job_id":i.job(),"source_sha":i.text("source_sha"),"native_intent_sha256":i.digest()?,"failure_intent_sha256":sha(&bytes(f)?),"return_sha256":f["return_sha256"],"reader_generation":f["reader_generation"],
        "archive_retained":!j.absent(i.job(),RECEIPT)?,"archive_sha256":if j.absent(i.job(),EXPORT)? {Value::Null} else {parse(&j.read(i.job(),EXPORT)?)?["receipt"]["archive_sha256"].clone()},
        "host_ack_retained":!j.absent(i.job(),ACK)?,"storage_retired":!j.absent(i.job(),RETIRED)?,"controller_authenticated":false,"execution_eligible":false,"qualification_eligible":false,"model_requests":null}),
    )
}
pub(super) fn run_command(args: &[String]) -> Result<Value, String> {
    let action = args.first().map(String::as_str).ok_or(USAGE)?;
    if !matches!(
        (action, args.len()),
        ("failure-record" | "failure-retire", 5)
            | (
                "failure-download"
                    | "failure-download-read"
                    | "failure-download-resume"
                    | "failure-ack"
                    | "failure-ack-read"
                    | "failure-ack-resume"
                    | "failure-retire-read"
                    | "failure-retire-resume",
                4
            )
    ) || !hex(&args[2], 16)
        || !hex(&args[3], 64)
    {
        return Err(USAGE.into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let i = j.intent(&args[2])?;
    if action == "failure-record" {
        if i.digest()? != args[3] {
            return Err("original Native intent SHA differs".into());
        }
        if j.absent(i.job(), INTENT)? {
            for row in rustix::fs::Dir::read_from(&j.root).map_err(|e| e.to_string())? {
                let row = row.map_err(|e| e.to_string())?;
                if row
                    .file_name()
                    .to_bytes()
                    .starts_with(format!("{}.native-readonly-failure-", i.job()).as_bytes())
                {
                    return Err("orphan readonly failure state blocks new authority".into());
                }
            }
        }
        let f = protocol::original(&j, &i, &args[4])?;
        j.retain(i.job(), INTENT, &bytes(&f)?)?;
        return summary(&j, &i, &f, action);
    }
    let f = stored(&j, &i)?;
    if sha(&bytes(&f)?) != args[3] {
        return Err("original readonly failure intent SHA differs".into());
    }
    let mut rpc = Transport {
        lima: Lima::open(&i)?,
        intent: &i,
    };
    if action.starts_with("failure-download") {
        download(&j, &i, &f, action, &mut rpc)
    } else if action.starts_with("failure-ack") {
        acknowledge(&j, &i, &f, action, &mut rpc)
    } else {
        retire(
            &j,
            &i,
            &f,
            action,
            args.get(4).map(String::as_str),
            &mut rpc,
        )
    }
}
pub(super) fn verify_idle(j: &Journal, i: &Intent) -> Result<(), String> {
    let f = stored(j, i)?;
    let (_, _, _, r, _) = retired_context(j, i, &f)?;
    if j.read(i.job(), RETIRE)? != bytes(&r)? || j.read(i.job(), RD)? != marker(&f, "retire", &r)? {
        return Err("unknown readonly failure cleanup blocks dispatch".into());
    }
    protocol::retired(&r, &j.read(i.job(), RETIRED)?)?;
    Ok(())
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    if let Some((job, _)) = name
        .split_once(".native-readonly-failure-")
        .filter(|(job, _)| hex(job, 16))
    {
        let i = j.intent(job)?;
        stored(j, &i)?;
        if name == format!("{job}.native-{INTENT}.json") {
            verify_idle(j, &i)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_failed_tests.rs"]
mod tests;
