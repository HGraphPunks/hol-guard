//! Failed builds retain real logs under their original consumed authority.
use super::file::seal_failure as seal;
use super::protocol::{failure_marker as marker, retained_failure_export as exported};
pub(super) use super::FailureRpc as Rpc;
use super::{
    bytes, context, failure_summary as summary, file, hex, protocol, reply, sha, text, value,
    Journal,
};
use crate::{HostCandidateBuildPinJournal, VmCandidateBuildInvocation};
use serde_json::{json, Value};
use std::path::Path;
pub(super) const INTENT: &str = "failed-build-intent";
pub(super) const DOWNLOAD: &str = "failed-build-download-dispatch";
pub(super) const EXPORT: &str = "failed-build-export";
pub(super) const RECEIPT: &str = "failed-build-host-receipt";
const ACK_DISPATCH: &str = "failed-build-ack-dispatch";
const ACK: &str = "failed-build-ack";
const REQUEST: &str = "failed-build-retirement-request";
const RETIRE: &str = "failed-build-retirement-intent";
const RETIRE_DISPATCH: &str = "failed-build-retirement-dispatch";
const RETIRED: &str = "failed-build-retired";
pub(super) const USAGE: &str = "failure-record PRIVATE_0700_JOURNAL PRIVATE_TRANSFER_DIR SOURCE_INTENT_SHA PRIVATE_PIN_DIR JOB_ID READER_SHA\nfailure-download|failure-download-read|failure-download-resume|failure-ack|failure-ack-read|failure-ack-resume PRIVATE_JOURNAL JOB_ID FAILURE_INTENT_SHA\nfailure-retire PRIVATE_JOURNAL JOB_ID FAILURE_INTENT_SHA RETIRER_SHA\nfailure-retire-read|failure-retire-resume PRIVATE_JOURNAL JOB_ID FAILURE_INTENT_SHA\nFailure evidence is a private USTAR of original result-bound logs and a sanitized manifest, never a candidate ZIP or artifact admission. Unknown usage remains null; incomplete dispatches require explicit original read/resume, never workload replay.";
fn original(
    source: &Value,
    path: &Path,
    job: &str,
) -> Result<(Value, VmCandidateBuildInvocation), String> {
    let j = Journal::open(path)?;
    let i = super::super::bounded::parse(&j.read(job, super::super::bounded::INTENT)?)?;
    if i["job_id"] != job || i["source"] != *source {
        return Err("original bounded failed-build Source differs".into());
    }
    let claim = super::super::bounded::retained_claim(&j, &i)?;
    if claim["status"] != "build-failed" || claim["exit_code"].as_i64().is_none_or(|n| n == 0) {
        return Err("actual retained nonzero failed-build terminal required".into());
    }
    let keys = HostCandidateBuildPinJournal::open(path)
        .map_err(|_| "original private build pin unavailable")?;
    let inv = super::super::bounded::plan(&i)?
        .retained_invocation(&keys)
        .map_err(|_| "original build invocation unavailable")?;
    super::super::bounded::require_launch(&j, &i, &inv)?;
    let raw = j.read(job, "bounded-build-return")?;
    if inv
        .parse_terminal_claim(&raw)
        .map_err(|_| "original failed terminal changed")?
        != claim
    {
        return Err("original failed terminal differs from retained claim".into());
    }
    let result: Value =
        serde_json::from_slice(&raw).map_err(|_| "private failed terminal invalid")?;
    let anchor = VmCandidateBuildInvocation::anchor_sha256(inv.record())?;
    if result["host_anchor_sha256"] != anchor {
        return Err("failed terminal differs from original private Host anchor".into());
    }
    let mut flow = json!({"schema":"hol-gauntlet-host-bounded-build-failure.v1","journal":path,
        "intent_sha256":sha(&bytes(&i)?),"host_pin_sha256":claim["host_pin_sha256"],"host_anchor_sha256":anchor,
        "result_sha256":claim["result_sha256"],"status":"build-failed","exit_code":claim["exit_code"],
        "original_runner_generation":i["build_pins"]["runner_binary_sha256"],
        "original_result_reader_generation":i["build_pins"]["result_reader_binary_sha256"]});
    for key in [
        "stdout_sha256",
        "stderr_sha256",
        "client_pid",
        "client_start_ticks",
    ] {
        flow[key] = result[key].clone();
    }
    j.stable()?;
    Ok((flow, inv))
}
pub(super) fn parse(raw: &[u8]) -> Result<Value, String> {
    let i: Value = serde_json::from_slice(raw).map_err(|_| "failure intent JSON invalid")?;
    if bytes(&i)? != raw
        || i.as_object().is_none_or(|o| o.len() != 8)
        || i["schema"] != "hol-gauntlet-host-failed-build-evidence-intent.v1"
        || !hex(text(&i, "job_id")?, 16)
        || !hex(text(&i, "reader_generation")?, 64)
        || i["source"]["intent"]["storage_profile"] != "build-v1"
        || i["execution_eligible"] != false
        || i["qualification_eligible"] != false
        || !i.get("model_requests").is_some_and(Value::is_null)
    {
        return Err("closed original failed-build evidence intent required".into());
    }
    recheck(&i)?;
    Ok(i)
}
fn recheck(i: &Value) -> Result<(), String> {
    let s = &i["source"];
    if super::super::source::completed(
        Path::new(text(s, "journal")?),
        text(i, "job_id")?,
        text(s, "intent_sha256")?,
    )? != *s
        || original(
            s,
            Path::new(text(&i["flow"], "journal")?),
            text(i, "job_id")?,
        )?
        .0 != i["flow"]
    {
        return Err("original failed-build source, terminal or VM custody changed".into());
    }
    Ok(())
}
pub(super) fn stable(j: &Journal, i: &Value) -> Result<(), String> {
    if j.read(text(i, "job_id")?, INTENT)? != bytes(i)? {
        return Err("failure evidence intent changed".into());
    }
    recheck(i)?;
    j.stable()
}
fn observe(j: &Journal, i: &Value, rpc: &mut impl Rpc) -> Result<Option<Value>, String> {
    stable(j, i)?;
    let raw = rpc.control(&protocol::failure_args(i, "--read-failed-build-export-v1")?)?;
    j.retain(
        text(i, "job_id")?,
        &format!("failed-build-state-{}", sha(&raw)),
        &raw,
    )?;
    stable(j, i)?;
    let state = reply(&raw)?;
    let e = protocol::failure_state(i, &state)?;
    if let Some(e) = &e {
        j.retain(text(i, "job_id")?, EXPORT, &bytes(e)?)?;
    }
    Ok(e)
}
pub(super) fn download(
    j: &Journal,
    i: &Value,
    mode: &str,
    rpc: &mut impl Rpc,
) -> Result<Value, String> {
    let read = mode == "failure-download-read";
    stable(j, i)?;
    let job = text(i, "job_id")?;
    if mode != "failure-download" {
        if j.read(job, DOWNLOAD)? != marker(i, "download")? {
            return Err("original failure download dispatch required".into());
        }
    } else {
        if !j.absent(job, DOWNLOAD)? || !j.absent(job, RECEIPT)? || !j.absent(job, EXPORT)? {
            return Err("failure download consumed; use explicit failure-download-read".into());
        }
        for n in 1..=4 {
            if !file::failure_absent(j, job, n)? {
                return Err("orphan failure archive blocks download".into());
            }
        }
        super::super::idle(j)?;
        j.write(job, DOWNLOAD, &marker(i, "download")?)?;
    }
    if !j.absent(job, RECEIPT)? {
        file::retained_failure(j, i, &exported(j, i)?)?;
        return summary(j, i, "downloaded");
    }
    if read {
        if let Some(e) = observe(j, i, rpc)? {
            for n in 1..=4 {
                if !file::failure_absent(j, job, n)? {
                    let mut h = file::open_failure(j, job, n)?;
                    if file::verify_failure(j, i, &e, &mut h).is_ok() {
                        seal(j, i, &e, &mut h)?;
                        return summary(j, i, "downloaded");
                    }
                }
            }
        }
    }
    let attempt = (1..=4)
        .find(|n| file::failure_absent(j, job, *n).unwrap_or(false))
        .ok_or("failure evidence attempts exhausted; retain all original files")?;
    let mut h = file::create_failure(j, job, attempt)?;
    j.write(job,&format!("failed-build-attempt-{attempt:04}"),&bytes(&json!({"schema":"hol-gauntlet-host-failed-build-attempt.v1","intent_sha256":sha(&bytes(i)?),"attempt":attempt,"read_only":read,"file":h.name}))?)?;
    let mut argv = protocol::failure_args(
        i,
        if read {
            "--read-failed-build-evidence-v1"
        } else if mode == "failure-download-resume" {
            "--resume-failed-build-evidence-v1"
        } else {
            "--export-failed-build-evidence-v1"
        },
    )?;
    let input = if read {
        Vec::new()
    } else {
        let (_, inv) = original(&i["source"], Path::new(text(&i["flow"], "journal")?), job)?;
        inv.failure_anchor_bytes(text(&i["flow"], "host_anchor_sha256")?)?
    };
    if !read {
        argv.push(input.len().to_string());
    }
    stable(j, i)?;
    rpc.archive(&argv, &input, &mut h.file)?;
    let e = observe(j, i, rpc)?.ok_or("original Root failure export remains incomplete")?;
    seal(j, i, &e, &mut h)?;
    summary(j, i, "downloaded")
}
pub(super) fn acknowledge(
    j: &Journal,
    i: &Value,
    mode: &str,
    rpc: &mut impl Rpc,
) -> Result<Value, String> {
    let read = mode == "failure-ack-read";
    stable(j, i)?;
    let job = text(i, "job_id")?;
    let e = exported(j, i)?;
    let (mut h, host) = file::retained_failure(j, i, &e)?;
    let m = marker(i, "ack")?;
    if mode != "failure-ack" {
        if j.read(job, ACK_DISPATCH)? != m {
            return Err("original failure ACK dispatch required".into());
        }
    } else {
        j.write(job, ACK_DISPATCH, &m)?;
    }
    if mode == "failure-ack-resume" && !j.absent(job, ACK)? {
        protocol::failure_ack(&e, &host, &value(j, i, ACK)?)?;
        return summary(j, i, "acknowledged");
    }
    let mut argv = protocol::failure_args(
        i,
        if read {
            "--read-failed-build-ack-v1"
        } else {
            "--ack-failed-build-evidence-v1"
        },
    )?;
    argv.extend([text(&e, "receipt_sha256")?.into(), host.clone()]);
    let raw = rpc.control(&argv)?;
    j.retain(job, &format!("failed-build-ack-frame-{}", sha(&raw)), &raw)?;
    stable(j, i)?;
    file::verify_failure(j, i, &e, &mut h)?;
    let a = protocol::failure_ack(&e, &host, &reply(&raw)?)?;
    j.retain(job, ACK, &bytes(&a)?)?;
    summary(j, i, "acknowledged")
}
pub(super) fn retire(
    j: &Journal,
    i: &Value,
    mode: &str,
    generation: Option<&str>,
    rpc: &mut impl Rpc,
) -> Result<Value, String> {
    stable(j, i)?;
    let job = text(i, "job_id")?;
    let e = exported(j, i)?;
    let (mut h, host) = file::retained_failure(j, i, &e)?;
    if j.read(job, ACK_DISPATCH)? != marker(i, "ack")? {
        return Err("original failure ACK dispatch differs".into());
    }
    let a = protocol::failure_ack(&e, &host, &value(j, i, ACK)?)?;
    let intent = if mode == "failure-retire" {
        let g = generation
            .filter(|g| hex(g, 64))
            .ok_or("outside failure retirer generation required")?;
        for k in [REQUEST, RETIRE, RETIRE_DISPATCH, RETIRED] {
            if !j.absent(job, k)? {
                return Err("failure retirement consumed; use original read/resume".into());
            }
        }
        let v = protocol::failure_retirement(i, &e, &a, &host, g);
        j.write(
            job,
            REQUEST,
            &bytes(&protocol::failure_retirement_request(i, &v)?)?,
        )?;
        j.write(job, RETIRE, &bytes(&v)?)?;
        v
    } else {
        let request = value(j, i, REQUEST)?;
        let v =
            protocol::failure_retirement(i, &e, &a, &host, text(&request, "retirer_generation")?);
        if request != protocol::failure_retirement_request(i, &v)? {
            return Err("original failure retirement authority changed".into());
        }
        if j.absent(job, RETIRE)? && mode == "failure-retire-resume" {
            j.write(job, RETIRE, &bytes(&v)?)?;
        }
        if value(j, i, RETIRE)? != v {
            return Err("original failure retirement intent changed".into());
        }
        v
    };
    let m = bytes(
        &json!({"schema":"hol-gauntlet-host-failed-build-retirement-dispatch.v1","intent_sha256":sha(&bytes(i)?),"retirement_intent_sha256":sha(&bytes(&intent)?),"retry_allowed":false}),
    )?;
    if mode == "failure-retire"
        || (mode == "failure-retire-resume" && j.absent(job, RETIRE_DISPATCH)?)
    {
        j.write(job, RETIRE_DISPATCH, &m)?;
    } else if j.read(job, RETIRE_DISPATCH)? != m {
        return Err("original consumed failure retirement required".into());
    }
    let g = text(&intent, "retirer_generation")?;
    let mut argv = protocol::failure_args(
        i,
        if mode == "failure-retire-read" {
            "--read-failed-build-retirement-v1"
        } else {
            "--retire-failed-build-storage-v1"
        },
    )?;
    argv[0] = format!("/opt/hol-gauntlet/rust-native-dependency-worker-{g}");
    argv.extend([text(&e, "receipt_sha256")?.into(), host, g.into()]);
    let raw = rpc.control(&argv)?;
    j.retain(
        job,
        &format!("failed-build-retirement-frame-{}", sha(&raw)),
        &raw,
    )?;
    stable(j, i)?;
    file::verify_failure(j, i, &e, &mut h)?;
    let mut effective = i.clone();
    effective["archive_sha256"] = e["receipt"]["archive_sha256"].clone();
    let result = protocol::retirement(&effective, &intent, &reply(&raw)?)?;
    j.retain(job, RETIRED, &bytes(&result)?)?;
    summary(j, i, "retired")
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    let Some((job, _)) = name
        .split_once(".native-failed-build-")
        .or_else(|| name.split_once(".failed-build-evidence-"))
    else {
        return Ok(());
    };
    let i = parse(&j.read(job, INTENT)?)?;
    stable(j, &i)?;
    if j.absent(job, DOWNLOAD)? {
        if name != Journal::name(job, INTENT)? {
            return Err("orphan failure evidence blocks new dispatch".into());
        }
        return Ok(());
    }
    if j.read(job, DOWNLOAD)? != marker(&i, "download")? {
        return Err("failure download marker changed".into());
    }
    let e = exported(j, &i)?;
    let (_, host) = file::retained_failure(j, &i, &e)?;
    if !j.absent(job, ACK_DISPATCH)? {
        if j.read(job, ACK_DISPATCH)? != marker(&i, "ack")? {
            return Err("failure ACK marker changed".into());
        }
        let a = protocol::failure_ack(&e, &host, &value(j, &i, ACK)?)?;
        if !j.absent(job, REQUEST)?
            || !j.absent(job, RETIRE)?
            || !j.absent(job, RETIRE_DISPATCH)?
            || !j.absent(job, RETIRED)?
        {
            let v = value(j, &i, RETIRE)?;
            let expected =
                protocol::failure_retirement(&i, &e, &a, &host, text(&v, "retirer_generation")?);
            let m = bytes(
                &json!({"schema":"hol-gauntlet-host-failed-build-retirement-dispatch.v1","intent_sha256":sha(&bytes(&i)?),"retirement_intent_sha256":sha(&bytes(&v)?),"retry_allowed":false}),
            )?;
            let mut effective = i.clone();
            effective["archive_sha256"] = e["receipt"]["archive_sha256"].clone();
            if v != expected
                || value(j, &i, REQUEST)? != protocol::failure_retirement_request(&i, &v)?
                || j.read(job, RETIRE_DISPATCH)? != m
            {
                return Err("failure retirement intent/dispatch changed".into());
            }
            protocol::retirement(&effective, &v, &value(j, &i, RETIRED)?)?;
        }
    } else if !j.absent(job, ACK)?
        || !j.absent(job, REQUEST)?
        || !j.absent(job, RETIRE)?
        || !j.absent(job, RETIRE_DISPATCH)?
        || !j.absent(job, RETIRED)?
    {
        return Err("orphan failure cleanup authority blocks dispatch".into());
    }
    Ok(())
}
pub(super) fn run_command(args: &[String]) -> Result<Value, String> {
    if matches!(
        (args.first().map(String::as_str), args.len()),
        (Some("failure-record"), 7)
    ) {
        let source = super::super::source::completed(Path::new(&args[2]), &args[5], &args[3])?;
        let flow = original(&source, Path::new(&args[4]), &args[5])?.0;
        let i = parse(&bytes(
            &json!({"schema":"hol-gauntlet-host-failed-build-evidence-intent.v1","job_id":args[5],"source":source,"flow":flow,
            "reader_generation":args[6],"model_requests":null,"execution_eligible":false,"qualification_eligible":false}),
        )?)?;
        let mut j = Journal::open(Path::new(&args[1]))?;
        j.lock()?;
        super::super::idle(&j)?;
        j.write(&args[5], INTENT, &bytes(&i)?)?;
        return summary(&j, &i, "recorded");
    }
    match (args.first().map(String::as_str), args.len()) {
        (
            Some(
                "failure-download"
                | "failure-download-read"
                | "failure-download-resume"
                | "failure-ack"
                | "failure-ack-read"
                | "failure-ack-resume"
                | "failure-retire-read"
                | "failure-retire-resume",
            ),
            4,
        )
        | (Some("failure-retire"), 5) => {}
        _ => return Err(USAGE.into()),
    }
    if !hex(&args[2], 16) || !hex(&args[3], 64) {
        return Err("outside failed-build job/intent pins required".into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let raw = j.read(&args[2], INTENT)?;
    if sha(&raw) != args[3] {
        return Err("outside failure evidence intent differs".into());
    }
    let i = parse(&raw)?;
    if i["job_id"] != args[2] {
        return Err("failure evidence job differs".into());
    }
    let s = &i["source"]["intent"];
    let lima = context::Lima::open_pinned(
        text(s, "limactl")?,
        text(s, "lima_sha256")?,
        &s["transport_context"],
    )?;
    let mut rpc = super::Owned { lima, i: &i };
    match args[0].as_str() {
        "failure-download" | "failure-download-read" | "failure-download-resume" => {
            download(&j, &i, &args[0], &mut rpc)
        }
        "failure-ack" | "failure-ack-read" | "failure-ack-resume" => {
            acknowledge(&j, &i, &args[0], &mut rpc)
        }
        _ => retire(&j, &i, &args[0], args.get(4).map(String::as_str), &mut rpc),
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    #[test]
    fn explicit_failure_cleanup_resume_seals_only_original_intent_missing_dispatch() {
        for kind in ["ok", "changed-intent", "changed-file", "partial-dispatch"] {
            let (_temp, j, i, mut rpc) = super::super::tests::failure_fixture("");
            download(&j, &i, "failure-download", &mut rpc).unwrap();
            acknowledge(&j, &i, "failure-ack", &mut rpc).unwrap();
            let job = text(&i, "job_id").unwrap();
            let e = exported(&j, &i).unwrap();
            let (h, host) = file::retained_failure(&j, &i, &e).unwrap();
            let a = value(&j, &i, ACK).unwrap();
            let intent = protocol::failure_retirement(&i, &e, &a, &host, &"e".repeat(64));
            j.write(
                job,
                REQUEST,
                &bytes(&protocol::failure_retirement_request(&i, &intent).unwrap()).unwrap(),
            )
            .unwrap();
            j.write(job, RETIRE, &bytes(&intent).unwrap()).unwrap();
            let before = rpc.calls;
            assert!(retire(&j, &i, "failure-retire-read", None, &mut rpc).is_err());
            assert_eq!(rpc.calls, before);
            match kind {
                "changed-intent" => {
                    let mut changed = intent.clone();
                    changed["retirer_generation"] = json!("d".repeat(64));
                    std::fs::write(
                        j.path.join(Journal::name(job, RETIRE).unwrap()),
                        bytes(&changed).unwrap(),
                    )
                    .unwrap();
                }
                "changed-file" => std::fs::write(j.path.join(h.name), b"changed custody").unwrap(),
                "partial-dispatch" => j.write(job, RETIRE_DISPATCH, b"{").unwrap(),
                _ => {}
            }
            let result = retire(&j, &i, "failure-retire-resume", None, &mut rpc);
            if kind == "ok" {
                let result = result.unwrap();
                assert!(result["model_requests"].is_null());
                assert_eq!(rpc.calls, before + 1);
                assert_eq!(j.read(job, RETIRE).unwrap(), bytes(&intent).unwrap());
                assert!(!j.absent(job, RETIRE_DISPATCH).unwrap());
            } else {
                assert!(result.is_err(), "{kind}");
                assert_eq!(rpc.calls, before);
            }
        }
    }
}
