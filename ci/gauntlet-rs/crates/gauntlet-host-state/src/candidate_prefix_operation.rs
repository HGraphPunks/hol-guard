//! One-use inert prefix operations share the completed Source's original VM.
//! Explicit completed-read reconciles data publication, never workload replay.
use super::super::{bytes, context, hex, sha, Journal};
use crate::{public_vm_operations, HostCandidateBuildPinJournal, VmHostBoundCandidateResultPlan};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
#[path = "candidate_prefix_protocol.rs"]
mod protocol;

pub(super) const USAGE: &str = "prefix-stage|prefix-stage-read PRIVATE_INTENT_DIR PRIVATE_TRANSFER_DIR SOURCE_INTENT_SHA256 JOB_ID PYTHON_SHA256 STAGER_SHA256\nprefix-clone|prefix-clone-read PRIVATE_PIN_DIR PRIVATE_CANDIDATE_TRANSFER_DIR CANDIDATE_SOURCE_INTENT_SHA256 CANDIDATE_JOB_ID PRIVATE_DEPENDENCY_INTENT_DIR PRIVATE_DEPENDENCY_TRANSFER_DIR DEPENDENCY_SOURCE_INTENT_SHA256 DEPENDENCY_JOB_ID CLONER_SHA256\nruntime-publish|runtime-publish-read PRIVATE_PIN_DIR PRIVATE_TRANSFER_DIR SOURCE_INTENT_SHA256 JOB_ID PYTHON_FULL_VERSION PUBLISHER_SHA256\nPins derive from original bounded readbacks and completed prefix receipts. Both jobs must retain the same original Lima homes and VM instance. Mutations are one-use; explicit reads send empty stdin and accept only original completed data. No artifact admission or qualification is granted.";
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str().ok_or_else(|| format!("prefix {k} absent"))
}
fn kind(i: &Value, suffix: &str) -> Result<String, String> {
    Ok(format!("{}-{suffix}", text(i, "operation")?))
}
fn source(i: &Value) -> &Value {
    &i["source"]["intent"]
}
fn candidate_inputs(i: &Value) -> &Value {
    if i["operation"] == "runtime-publish" {
        &i["inputs"]["candidate"]
    } else {
        &i["inputs"]
    }
}
fn recheck_source(s: &Value, job: &str) -> Result<(), String> {
    if super::source::completed(
        Path::new(text(s, "journal")?),
        job,
        text(s, "intent_sha256")?,
    )? != *s
    {
        return Err("original prefix Source context changed".into());
    }
    Ok(())
}
fn validate(i: &Value) -> Result<(), String> {
    let fields = [
        "schema",
        "operation",
        "job_id",
        "source",
        "inputs",
        "dependency",
        "worker_generation",
        "python",
        "artifact_admitted",
        "execution_eligible",
        "qualification_eligible",
    ];
    if i.as_object()
        .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
        || i["schema"] != "hol-gauntlet-host-native-prefix-intent.v1"
        || !hex(text(i, "job_id")?, 16)
        || !hex(text(i, "worker_generation")?, 64)
        || [
            "artifact_admitted",
            "execution_eligible",
            "qualification_eligible",
        ]
        .iter()
        .any(|k| i[*k] != false)
        || i["job_id"] != source(i)["job_id"]
    {
        return Err("closed original bounded prefix intent required".into());
    }
    let job = text(i, "job_id")?;
    recheck_source(&i["source"], job)?;
    match text(i, "operation")? {
        "prefix-stage" => {
            if source(i)["storage_profile"] != "dependency-v1"
                || !i["dependency"].is_null()
                || !hex(text(i, "python")?, 64)
                || super::dependencies::prefix_inputs(
                    Path::new(text(&i["inputs"]["flow"], "journal")?),
                    &i["source"],
                    job,
                )? != i["inputs"]
            {
                return Err(
                    "original successful dependency readback and Python pin required".into(),
                );
            }
        }
        "prefix-clone" | "runtime-publish" => {
            let inputs = candidate_inputs(i);
            let path = Path::new(text(&inputs["flow"], "journal")?);
            if source(i)["storage_profile"] != "build-v1"
                || super::bounded::prefix_inputs(path, &i["source"], job)? != *inputs
            {
                return Err("original candidate readback and inert wheel stage required".into());
            }
            if i["operation"] == "prefix-clone" {
                let dep = &i["dependency"];
                let djob = text(&dep["receipt"], "job_id")?;
                if !i["python"].is_null()
                    || djob == job
                    || completed(
                        Path::new(text(dep, "journal")?),
                        &dep["source"],
                        djob,
                        "prefix-stage",
                    )? != *dep
                    || dep["source"]["intent"]["source_sha"] != source(i)["source_sha"]
                    || ["vm", "limactl", "lima_sha256", "transport_context"]
                        .iter()
                        .any(|k| dep["source"]["intent"][*k] != source(i)[*k])
                {
                    return Err(
                        "distinct dependency job on the original source and Lima instance required"
                            .into(),
                    );
                }
            } else if !i["dependency"].is_null()
                || !protocol::python_version(text(i, "python")?)
                || i["inputs"].as_object().is_none_or(|o| o.len() != 2)
                || completed(path, &i["source"], job, "prefix-clone")? != i["inputs"]["clone"]
            {
                return Err(
                    "original completed clone and exact Python full version required".into(),
                );
            }
        }
        _ => return Err("closed prefix operation required".into()),
    }
    Ok(())
}
fn parse(raw: &[u8]) -> Result<Value, String> {
    let i: Value = serde_json::from_slice(raw).map_err(|_| "prefix intent JSON invalid")?;
    if bytes(&i)? != raw {
        return Err("canonical prefix intent required".into());
    }
    validate(&i)?;
    Ok(i)
}
fn dispatch(i: &Value) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-native-prefix-dispatch.v1","intent_sha256":sha(&bytes(i)?),"retry_allowed":false}),
    )
}
fn stable(j: &Journal, i: &Value) -> Result<(), String> {
    validate(i)?;
    let job = text(i, "job_id")?;
    let path = Path::new(text(&candidate_inputs(i)["flow"], "journal")?);
    if j.path != path
        || j.read(job, &kind(i, "intent")?)? != bytes(i)?
        || j.read(job, &kind(i, "dispatch")?)? != dispatch(i)?
    {
        return Err("original prefix journal or consumed dispatch changed".into());
    }
    j.stable()
}
fn result(i: &Value, raw: &[u8]) -> Result<Value, String> {
    let (receipt, digest) = protocol::receipt(i, raw)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-native-prefix-result.v1","operation":i["operation"],"job_id":i["job_id"],
        "intent_sha256":sha(&bytes(i)?),"dispatch_sha256":sha(&dispatch(i)?),"raw_sha256":sha(raw),
        "receipt_sha256":digest,"receipt":receipt,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false}),
    )
}
fn retained(j: &Journal, i: &Value) -> Result<Value, String> {
    stable(j, i)?;
    let raw = j.read(text(i, "job_id")?, &kind(i, "result")?)?;
    let r: Value = serde_json::from_slice(&raw).map_err(|_| "prefix result invalid")?;
    let frame = j.read(
        text(i, "job_id")?,
        &kind(i, &format!("return-{}", text(&r, "raw_sha256")?))?,
    )?;
    let expected = result(i, &frame)?;
    if raw != bytes(&expected)? {
        return Err("retained prefix result changed".into());
    }
    Ok(expected)
}
fn completed(path: &Path, source: &Value, job: &str, operation: &str) -> Result<Value, String> {
    let j = Journal::open(path)?;
    let i = parse(&j.read(job, &format!("{operation}-intent"))?)?;
    if i["source"] != *source || i["job_id"] != job || i["operation"] != operation {
        return Err("completed prefix identity differs".into());
    }
    let r = retained(&j, &i)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-native-prefix-context.v1","source":source,"journal":path,
        "journal_custody":context::snapshot(path)?,"intent_sha256":sha(&bytes(&i)?),
        "receipt_sha256":r["receipt_sha256"],"receipt":r["receipt"]}),
    )
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    for operation in ["prefix-stage", "prefix-clone", "runtime-publish"] {
        if let Some(job) = name.strip_suffix(&format!(".native-{operation}-dispatch.json")) {
            let i = parse(&j.read(job, &format!("{operation}-intent"))?)?;
            if i["job_id"] != job || i["operation"] != operation {
                return Err("prefix dispatch identity differs".into());
            }
            retained(j, &i).map_err(|_| "unknown prefix operation blocks dispatch")?;
        }
    }
    Ok(())
}
fn execute(
    j: &Journal,
    i: &Value,
    reading: bool,
    run: impl FnOnce(&[String], &[u8]) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    validate(i)?;
    if j.path != Path::new(text(&candidate_inputs(i)["flow"], "journal")?) {
        return Err("prefix mutation requires the original private flow journal".into());
    }
    let job = text(i, "job_id")?;
    if reading {
        stable(j, i)?;
    } else {
        j.retain(job, &kind(i, "intent")?, &bytes(i)?)?;
        if !j.absent(job, &kind(i, "dispatch")?)? {
            return retained(j, i);
        }
        if !j.absent(job, &kind(i, "result")?)? {
            return Err("orphan prefix result blocks dispatch".into());
        }
        super::idle(j)?;
        j.write(job, &kind(i, "dispatch")?, &dispatch(i)?)?;
    }
    stable(j, i)?;
    if !j.absent(job, &kind(i, "result")?)? {
        return retained(j, i);
    }
    let raw = run(&argv(i, reading)?, b"")
        .map_err(|_| "prefix operation uncertain; use only original completed-read")?;
    stable(j, i)?;
    j.retain(job, &kind(i, &format!("return-{}", sha(&raw)))?, &raw)?;
    let r = result(i, &raw)?;
    j.write(job, &kind(i, "result")?, &bytes(&r)?)?;
    retained(j, i)
}
fn argv(i: &Value, reading: bool) -> Result<Vec<String>, String> {
    let get = |v: &Value, k: &str| text(v, k).map(str::to_owned);
    let s = source(i);
    let worker = get(i, "worker_generation")?;
    let mut a = vec![format!(
        "/opt/hol-gauntlet/rust-native-dependency-worker-{worker}"
    )];
    match text(i, "operation")? {
        "prefix-stage" => a.extend([
            if reading {
                "--read-native-dependency-prefix"
            } else {
                "--stage-native-dependency-prefix"
            }
            .into(),
            get(i, "job_id")?,
            get(&i["inputs"], "dependency_intent_sha256")?,
            get(&i["inputs"]["flow"], "result_sha256")?,
            get(&i["inputs"]["flow"], "archive_sha256")?,
            get(i, "python")?,
            worker,
        ]),
        "prefix-clone" => a.extend([
            if reading {
                "--read-native-candidate-prefix"
            } else {
                "--clone-native-candidate-prefix"
            }
            .into(),
            get(i, "job_id")?,
            get(s, "source_sha")?,
            get(s, "source_archive_sha256")?,
            get(&i["inputs"]["flow"], "archive_sha256")?,
            get(&i["inputs"], "version")?,
            get(&i["dependency"]["receipt"], "job_id")?,
            get(&i["dependency"], "receipt_sha256")?,
            get(&i["dependency"]["receipt"], "prefix_tree_sha256")?,
            get(&i["inputs"], "stage_tree_sha256")?,
            worker,
        ]),
        "runtime-publish" => a.extend([
            if reading {
                "--read-native-runtime-publication"
            } else {
                "--publish-native-runtime"
            }
            .into(),
            get(i, "job_id")?,
            get(s, "source_sha")?,
            get(&i["inputs"]["candidate"], "version")?,
            get(&i["inputs"]["clone"], "receipt_sha256")?,
            get(&i["inputs"]["clone"]["receipt"], "prefix_tree_sha256")?,
            get(&i["inputs"]["candidate"], "native_sha256")?,
            get(i, "python")?,
            worker,
        ]),
        _ => return Err("closed prefix operation required".into()),
    }
    Ok(a)
}
fn from_args(args: &[String]) -> Result<(Value, bool), String> {
    let reading = args.first().is_some_and(|a| a.ends_with("-read"));
    let operation = args
        .first()
        .map(|a| a.strip_suffix("-read").unwrap_or(a))
        .ok_or(USAGE)?;
    if !matches!(
        (operation, args.len()),
        ("prefix-stage", 7) | ("prefix-clone", 10) | ("runtime-publish", 7)
    ) {
        return Err(USAGE.into());
    }
    if !hex(&args[4], 16)
        || !hex(&args[3], 64)
        || !hex(args.last().ok_or(USAGE)?, 64)
        || operation == "prefix-stage" && !hex(&args[5], 64)
        || operation == "runtime-publish" && !protocol::python_version(&args[5])
        || operation == "prefix-clone" && (!hex(&args[7], 64) || !hex(&args[8], 16))
    {
        return Err("complete original prefix argument pins required".into());
    }
    let job = &args[4];
    let source = super::source::completed(Path::new(&args[2]), job, &args[3])?;
    let (inputs, dependency, python) = if operation == "prefix-stage" {
        (
            super::dependencies::prefix_inputs(Path::new(&args[1]), &source, job)?,
            Value::Null,
            json!(args[5]),
        )
    } else {
        let candidate = super::bounded::prefix_inputs(Path::new(&args[1]), &source, job)?;
        if operation == "prefix-clone" {
            let dep = super::source::completed(Path::new(&args[6]), &args[8], &args[7])?;
            (
                candidate,
                completed(Path::new(&args[5]), &dep, &args[8], "prefix-stage")?,
                Value::Null,
            )
        } else {
            let clone = completed(Path::new(&args[1]), &source, job, "prefix-clone")?;
            (
                json!({"candidate":candidate,"clone":clone}),
                Value::Null,
                json!(args[5]),
            )
        }
    };
    let i = json!({"schema":"hol-gauntlet-host-native-prefix-intent.v1","operation":operation,"job_id":job,
        "source":source,"inputs":inputs,"dependency":dependency,"worker_generation":args.last().ok_or(USAGE)?,
        "python":python,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false});
    validate(&i)?;
    Ok((i, reading))
}
pub(super) fn handles(action: &str) -> bool {
    matches!(
        action,
        "prefix-stage"
            | "prefix-stage-read"
            | "prefix-clone"
            | "prefix-clone-read"
            | "runtime-publish"
            | "runtime-publish-read"
    )
}
pub(super) fn run_command(args: &[String]) -> Result<Value, String> {
    let (i, reading) = from_args(args)?;
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let s = source(&i);
    let mut lima = context::Lima::open_pinned(
        text(s, "limactl")?,
        text(s, "lima_sha256")?,
        &s["transport_context"],
    )?;
    let r = execute(&j, &i, reading, |a, input| {
        let mut command = lima.command(text(s, "vm")?)?;
        command.args(a);
        let raw = crate::stream_process::run_streamed_command(
            command,
            input,
            Duration::from_secs(360),
            131073,
        )
        .map_err(|_| "prefix transport uncertain")?;
        lima.recheck()?;
        Ok(raw)
    })?;
    Ok(
        json!({"schema":"hol-gauntlet-host-native-prefix-operation.v1","operation":i["operation"],"job_id":i["job_id"],
        "source_sha":s["source_sha"],"intent_sha256":r["intent_sha256"],"receipt_sha256":r["receipt_sha256"],
        "prefix_tree_sha256":r["receipt"]["prefix_tree_sha256"],"native_sha256":candidate_inputs(&i)["native_sha256"],
        "original_source_transport_verified":true,"candidate_executed":false,"artifact_admitted":false,
        "execution_eligible":false,"qualification_eligible":false,"model_requests":0}),
    )
}

pub(super) fn candidate_flow(
    path: &Path,
    source_context: &Value,
    job: &str,
    result_sha: &str,
    archive_sha: &str,
) -> Result<Value, String> {
    let j = Journal::open(path)?;
    let i = super::bounded::parse(&j.read(job, super::bounded::INTENT)?)?;
    if i["source"] != *source_context {
        return Err("artifact Source differs from original bounded candidate".into());
    }
    let keys = HostCandidateBuildPinJournal::open(path).map_err(|e| e.to_string())?;
    let inv = super::bounded::plan(&i)?
        .retained_invocation(&keys)
        .map_err(|e| e.to_string())?;
    super::bounded::require_launch(&j, &i, &inv)?;
    let claim = super::bounded::retained_claim(&j, &i)?;
    if claim["status"] != "exited-zero"
        || claim["exit_code"] != 0
        || claim["result_sha256"] != result_sha
        || claim["unadmitted_export_sha256"] != archive_sha
    {
        return Err(
            "artifact candidate result/export differs from original successful terminal".into(),
        );
    }
    let operations =
        public_vm_operations(Some(text(source(&i), "vm")?)).map_err(|e| e.to_string())?;
    let reader =
        VmHostBoundCandidateResultPlan::new(&operations, &keys, job, result_sha, archive_sha)
            .map_err(|e| e.to_string())?;
    let report = reader
        .parse_response(&j.read(job, "bounded-build-read-return")?)
        .map_err(|_| "original actual candidate readback missing or changed")?;
    let expected = super::bounded::read_record(&i, &report)?;
    if j.read(job, "bounded-build-read-result")? != bytes(&expected)? {
        return Err("actual candidate readback differs from private receipt".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-host-source-artifact-flow.v1","kind":"candidate","journal":path,"journal_custody":context::snapshot(path)?,"flow_intent_sha256":sha(&bytes(&i)?),
        "host_binding_sha256":claim["host_pin_sha256"],"result_sha256":result_sha,"archive_sha256":archive_sha}),
    )
}
/// Data selected by the original private pin and completed readback. The
/// private nonce remains inside the official journal/parser APIs.
pub(super) fn candidate_read_inputs(
    path: &Path,
    source: &Value,
    job: &str,
) -> Result<Value, String> {
    let j = Journal::open(path)?;
    let i = super::bounded::parse(&j.read(job, super::bounded::INTENT)?)?;
    let claim = super::bounded::retained_claim(&j, &i)?;
    let flow = candidate_flow(
        path,
        source,
        job,
        text(&claim, "result_sha256")?,
        text(&claim, "unadmitted_export_sha256")?,
    )?;
    let stage = super::parse(&j.read(job, "artifact-wheel-stage-intent")?)?;
    if stage["operation"] != "wheel-stage" || stage["job_id"] != job {
        return Err("completed original candidate wheel stage required".into());
    }
    let result = super::retained(&j, &stage)?;
    let read: Value = serde_json::from_slice(&j.read(job, "bounded-build-read-result")?)
        .map_err(|_| "actual candidate readback invalid")?;
    if result["proof"]["wheel_sha256"] != read["readback"]["wheel_sha256"] {
        return Err("staged wheel differs from original authenticated readback".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-host-native-prefix-inputs.v1","job_id":job,"flow":flow,
        "version":i["build_pins"]["version"],"stage_proof_sha256":result["proof_sha256"],
        "stage_tree_sha256":result["proof"]["stage_tree_digest"],"native_sha256":result["proof"]["native_sha256"]}),
    )
}

pub(super) fn candidate_read_record(i: &Value, report: &Value) -> Result<Value, String> {
    Ok(
        json!({"schema":"hol-gauntlet-host-bounded-candidate-read.v1","job_id":i["job_id"],"intent_sha256":sha(&bytes(i)?),
        "source_intent_sha256":i["source"]["intent_sha256"],"storage_receipt_sha256":i["source"]["storage_receipt_sha256"],
        "original_source_transport_verified":true,"readback":report,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false}),
    )
}

#[cfg(test)]
#[path = "candidate_prefix_operation_tests.rs"]
mod tests;
