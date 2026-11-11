//! Inert workspace initialization and exact preparation publication precede
//! native execution. Their one-use transports share the operational journal.
use super::{bytes, hex, sha, transport::Lima, Intent, Journal};
use crate::private_jobs::{read_regular_bytes_bounded, state_root};
use gauntlet_contracts::is_git_sha;
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

const BUNDLE_LIMIT: u64 = 65536;
#[derive(Clone)]
struct Initialization(Value);
impl Initialization {
    fn parse(raw: &[u8]) -> Result<Self, String> {
        let v: Value = serde_json::from_slice(raw).map_err(|_| "initialization intent invalid")?;
        let fields = [
            "schema",
            "job_id",
            "source_sha",
            "worker_generation",
            "vm",
            "limactl",
            "lima_sha256",
            "transport_context",
        ];
        let text = |k: &str| v[k].as_str().unwrap_or("");
        let vm = text("vm");
        if bytes(&v)? != raw
            || v.as_object().is_none_or(|o| {
                o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k))
            })
            || v["schema"] != "hol-gauntlet-host-native-initialization-intent.v1"
            || !hex(text("job_id"), 16)
            || !is_git_sha(text("source_sha"))
            || !hex(text("worker_generation"), 64)
            || !hex(text("lima_sha256"), 64)
            || text("limactl") != "/opt/homebrew/bin/limactl"
            || !vm.starts_with("hol-")
            || vm.len() > 96
            || !vm
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("exact initialization VM/source/job/worker pins required".into());
        }
        super::context::TransportContext::parse(&v["transport_context"])?;
        if v["transport_context"]["vm"] != v["vm"] {
            return Err("initialization Lima instance differs".into());
        }
        Ok(Self(v))
    }
    fn text(&self, k: &str) -> &str {
        self.0[k].as_str().expect("validated initialization")
    }
    fn job(&self) -> &str {
        self.text("job_id")
    }
    fn digest(&self) -> Result<String, String> {
        Ok(sha(&bytes(&self.0)?))
    }
    fn dispatch(&self) -> Result<Vec<u8>, String> {
        bytes(
            &json!({"schema":"hol-gauntlet-host-native-initialization-dispatch.v1","job_id":self.job(),"initialization_intent_sha256":self.digest()?,"retry_allowed":false}),
        )
    }
}
fn frame(raw: &[u8], schema: &str, count: usize) -> Result<Value, String> {
    let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
    if raw.len() > 8192 {
        return Err("inert native receipt exceeds bound".into());
    }
    let v: Value = serde_json::from_slice(raw).map_err(|_| "inert native receipt invalid")?;
    if bytes(&v)? != raw
        || v.as_object().is_none_or(|o| o.len() != 3)
        || v["schema"] != schema
        || v["receipt"].as_object().is_none_or(|o| o.len() != count)
        || v["receipt_sha256"] != sha(&bytes(&v["receipt"])?)
    {
        return Err("canonical inert native receipt and digest required".into());
    }
    let r = &v["receipt"];
    if [
        "job_dispatched",
        "candidate_executed",
        "artifact_admitted",
        "execution_eligible",
        "qualification_eligible",
        "guard_causality_verified",
    ]
    .iter()
    .any(|k| r[*k] != false)
        || r["model_requests"].as_u64() != Some(0)
    {
        return Err("inert native preparation cannot claim execution credit".into());
    }
    Ok(v)
}
fn verify_initialization(i: &Initialization, raw: &[u8]) -> Result<Value, String> {
    let v = frame(raw, "hol-gauntlet-native-job-initialization-result.v1", 13)?;
    let r = &v["receipt"];
    let root = format!("/var/lib/hol-gauntlet-rust/native-jobs/{}", i.job());
    let d = &r["job_directory"];
    let w = &r["workspace"];
    if r["schema"] != "hol-gauntlet-native-job-initialization.v1"
        || r["source_sha"] != i.text("source_sha")
        || r["job_id"] != i.job()
        || r["worker_generation"] != i.text("worker_generation")
        || d.as_object().is_none_or(|o| o.len() != 5)
        || d["device"].as_u64().is_none()
        || d["inode"].as_u64().is_none_or(|n| n == 0)
        || d["uid"] != 0
        || d["gid"] != 0
        || d["mode"] != 448
        || w.as_object().is_none_or(|o| o.len() != 8)
        || w["source"] != format!("{root}/workspace")
        || w["custody_root"] != root
        || w["destination"] != "/runtime/home/project"
        || w["device"] != d["device"]
        || w["inode"].as_u64().is_none_or(|n| n == 0)
        || w["uid"] != 10001
        || w["gid"] != 10001
        || w["mode"] != 448
    {
        return Err("initialized native workspace differs from exact host identity".into());
    }
    Ok(v)
}
fn retained_initialization(j: &Journal, job: &str) -> Result<(Initialization, Value), String> {
    let i = Initialization::parse(&j.read(job, "initialize-intent")?)?;
    if i.job() != job || j.read(job, "initialize-dispatch")? != i.dispatch()? {
        return Err("native initialization dispatch differs".into());
    }
    let value = verify_initialization(&i, &j.read(job, "initialize-result")?)?;
    Ok((i, value))
}
fn initialization_for(j: &Journal, intent: &Intent) -> Result<Value, String> {
    let (i, value) = retained_initialization(j, intent.job())?;
    if [
        "job_id",
        "source_sha",
        "worker_generation",
        "vm",
        "limactl",
        "lima_sha256",
    ]
    .iter()
    .any(|k| i.text(k) != intent.text(k))
        || i.0["transport_context"] != intent.0["transport_context"]
    {
        return Err("native preparation differs from original initialized VM or worker".into());
    }
    Ok(value)
}
fn inert_transport(
    lima: &mut Lima,
    vm: &str,
    argv: &[String],
    input: &[u8],
) -> Result<Vec<u8>, String> {
    let mut command = lima.command(vm)?;
    command.args(argv);
    let result =
        crate::stream_process::run_streamed_command(command, input, Duration::from_secs(180), 8193)
            .map_err(|_| {
                "inert native transport uncertain; retain dispatch and reconcile with read"
            })?;
    lima.recheck()?;
    Ok(result)
}
fn initialize(args: &[String]) -> Result<Value, String> {
    let publish = args[0] == "initialize";
    let new = if publish {
        Some(Initialization::parse(&bytes(
            &json!({"schema":"hol-gauntlet-host-native-initialization-intent.v1",
            "vm":args[2],"limactl":"/opt/homebrew/bin/limactl","lima_sha256":args[3],"source_sha":args[4],"job_id":args[5],"worker_generation":args[6],
            "transport_context":super::context::TransportContext::from_paths(Path::new(&args[7]),Path::new(&args[8]),&args[2])?.value()}),
        )?)?)
    } else {
        if !hex(&args[2], 16) || !hex(&args[3], 64) {
            return Err("exact initialization job and intent digest required".into());
        }
        None
    };
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let i = if let Some(i) = new {
        i
    } else {
        Initialization::parse(&j.read(&args[2], "initialize-intent")?)?
    };
    if !publish
        && (i.job() != args[2]
            || i.digest()? != args[3]
            || j.read(i.job(), "initialize-dispatch")? != i.dispatch()?)
    {
        return Err("outside initialization digest or dispatch differs".into());
    }
    let mut lima = Lima::open_pinned(
        i.text("limactl"),
        i.text("lima_sha256"),
        &i.0["transport_context"],
    )?;
    if publish {
        j.require_idle()?;
        for suffix in [
            "intent",
            "dispatch",
            "completion",
            "initialize-dispatch",
            "initialize-result",
            "initialize-return",
            "prepare-bundle",
            "prepare-dispatch",
        ] {
            if !j.absent(i.job(), suffix)? {
                return Err("existing or uncertain native job blocks initialization".into());
            }
        }
        j.write(i.job(), "initialize-intent", &bytes(&i.0)?)?;
        j.write(i.job(), "initialize-dispatch", &i.dispatch()?)?;
    }
    let argv = vec![
        format!(
            "/opt/hol-gauntlet/rust-native-host-pinned-worker-{}",
            i.text("worker_generation")
        ),
        if publish {
            "--initialize-native-job-v1"
        } else {
            "--read-native-job-initialization-v1"
        }
        .into(),
        i.text("source_sha").into(),
        i.job().into(),
        i.text("worker_generation").into(),
    ];
    if j.read(i.job(), "initialize-dispatch")? != i.dispatch()? {
        return Err("native initialization dispatch changed".into());
    }
    let raw = inert_transport(&mut lima, i.text("vm"), &argv, &[])?;
    if publish {
        j.write(i.job(), "initialize-return", &raw)?;
    }
    let v = verify_initialization(&i, &raw)?;
    if Initialization::parse(&j.read(i.job(), "initialize-intent")?)?.digest()? != i.digest()?
        || j.read(i.job(), "initialize-dispatch")? != i.dispatch()?
    {
        return Err("native initialization intent changed".into());
    }
    j.retain(i.job(), "initialize-result", &bytes(&v)?)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-deterministic-initialization.v1","job_id":i.job(),"source_sha":i.text("source_sha"),
        "worker_generation":i.text("worker_generation"),"initialization_intent_sha256":i.digest()?,"initialization_receipt_sha256":v["receipt_sha256"],
        "job_directory":v["receipt"]["job_directory"],"workspace":v["receipt"]["workspace"],"next_operation":"record",
        "candidate_executed":false,"execution_eligible":false,"qualification_eligible":false,"model_requests":0}),
    )
}
fn read_bundle(path: &Path, expected: &str) -> Result<Vec<u8>, String> {
    let parent = path.parent().ok_or("private bundle parent required")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("private bundle filename required")?;
    let owner = rustix::process::geteuid().as_raw();
    let root = state_root(parent, owner).map_err(|e| e.to_string())?;
    let raw =
        read_regular_bytes_bounded(&root, name, owner, BUNDLE_LIMIT).map_err(|e| e.to_string())?;
    if sha(&raw) != expected {
        return Err("outside preparation bundle digest differs".into());
    }
    Ok(raw)
}
fn bundle(j: &Journal, intent: &Intent, raw: &[u8]) -> Result<(String, Value), String> {
    if raw.is_empty() || raw.len() as u64 > BUNDLE_LIMIT {
        return Err("native preparation bundle exceeds bound".into());
    }
    let v: Value = serde_json::from_slice(raw).map_err(|_| "native preparation bundle invalid")?;
    let initialized = initialization_for(j, intent)?;
    let d = &v["declaration"];
    let p = &v["preparation"];
    let readonly = intent.text("role") == "readonly-utility";
    if bytes(&v)? != raw
        || v.as_object().is_none_or(|o| o.len() != 3)
        || v["schema"] != "hol-gauntlet-native-host-pinned-preparation-input.v1"
        || bytes(d)?.len() > 8192
        || bytes(p)?.len() > 49152
        || sha(&bytes(d)?) != intent.text("deployment_digest")
        || sha(&bytes(p)?) != intent.text("preparation_sha256")
        || d["source_sha"] != intent.text("source_sha")
        || d["job_id"] != intent.job()
        || d["worker_generation"] != intent.text("worker_generation")
        || d["preparation_sha256"] != intent.text("preparation_sha256")
        || p["launch"]["image_interpreter_sha256"] != intent.text("interpreter_sha256")
        || p["launch"]["outside_observer_sha256"] != intent.text("observer_sha256")
        || p["runtime_prefix"]
            != format!(
                "/opt/hol-gauntlet/candidates/{}/prefix",
                intent.text("source_sha")
            )
        || d["schema"]
            != if readonly {
                "hol-gauntlet-native-worker-job.v8"
            } else {
                "hol-gauntlet-native-worker-job.v7"
            }
        || d["profile"]
            != if readonly {
                "native-host-pinned-readonly-hook-v1"
            } else {
                "native-host-pinned-control-v1"
            }
        || (readonly && (d.get("role").is_some() || d.get("sdk").is_some()))
        || (!readonly && d["role"] != intent.text("role"))
        || [
            "source",
            "destination",
            "custody_root",
            "device",
            "inode",
            "mode",
        ]
        .iter()
        .any(|k| p["task_mounts"]["workspace"][*k] != initialized["receipt"]["workspace"][*k])
    {
        return Err("native preparation bundle differs from original host/workspace pins".into());
    }
    Ok((
        initialized["receipt_sha256"]
            .as_str()
            .ok_or("initialization digest unavailable")?
            .into(),
        v,
    ))
}
fn preparation_dispatch(
    intent: &Intent,
    raw: &[u8],
    initialization: &str,
) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-native-preparation-dispatch.v1","job_id":intent.job(),"intent_sha256":intent.digest()?,
        "bundle_sha256":sha(raw),"bundle_bytes":raw.len(),"initialization_sha256":initialization,"retry_allowed":false}),
    )
}
fn verify_preparation(
    intent: &Intent,
    raw: &[u8],
    bundle_raw: &[u8],
    initialization: &str,
) -> Result<Value, String> {
    let v = frame(
        raw,
        "hol-gauntlet-native-host-pinned-preparation-result.v1",
        18,
    )?;
    let r = &v["receipt"];
    let bundle: Value =
        serde_json::from_slice(bundle_raw).map_err(|_| "native retained bundle invalid")?;
    let readonly = intent.text("role") == "readonly-utility";
    if r["schema"] != "hol-gauntlet-native-host-pinned-preparation.v1"
        || r["source_sha"] != intent.text("source_sha")
        || r["job_id"] != intent.job()
        || r["deployment_digest"] != intent.text("deployment_digest")
        || r["worker_generation"] != intent.text("worker_generation")
        || r["preparation_sha256"] != intent.text("preparation_sha256")
        || r["bundle_sha256"] != sha(bundle_raw)
        || r["initialization_sha256"] != initialization
        || r["control_role"] != intent.text("role")
        || !r["runtime_tree_sha256"]
            .as_str()
            .is_some_and(|s| hex(s, 64))
        || r["runtime_tree_sha256"] != bundle["preparation"]["runtime_tree_digest"]
        || (!readonly
            && r["sdk_publication_sha256"] != bundle["declaration"]["sdk"]["publication_sha256"])
        || if readonly {
            !r.get("sdk_publication_sha256").is_some_and(Value::is_null)
        } else {
            !r["sdk_publication_sha256"]
                .as_str()
                .is_some_and(|s| hex(s, 64))
        }
    {
        return Err("native preparation receipt differs from exact immutable bundle".into());
    }
    Ok(v)
}
pub(super) fn require_prepared(j: &Journal, intent: &Intent) -> Result<Value, String> {
    let raw = j.read(intent.job(), "prepare-bundle")?;
    let (initialized, _) = bundle(j, intent, &raw)?;
    if j.read(intent.job(), "prepare-dispatch")?
        != preparation_dispatch(intent, &raw, &initialized)?
    {
        return Err("native preparation dispatch differs".into());
    }
    verify_preparation(
        intent,
        &j.read(intent.job(), "prepare-result")?,
        &raw,
        &initialized,
    )
}
fn prepare(args: &[String]) -> Result<Value, String> {
    let publish = args[0] == "prepare";
    if !hex(&args[2], 16)
        || !hex(&args[3], 64)
        || (publish && (!Path::new(&args[4]).is_absolute() || !hex(&args[5], 64)))
    {
        return Err("exact native preparation job/intent/bundle pins required".into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let intent = j.intent(&args[2])?;
    if intent.digest()? != args[3] {
        return Err("outside native preparation intent digest differs".into());
    }
    let raw = if publish {
        read_bundle(Path::new(&args[4]), &args[5])?
    } else {
        j.read(intent.job(), "prepare-bundle")?
    };
    let (initialized, _) = bundle(&j, &intent, &raw)?;
    let mut lima = Lima::open(&intent)?;
    if publish {
        j.require_idle()?;
        if !j.absent(intent.job(), "dispatch")? || !j.absent(intent.job(), "prepare-result")? {
            return Err(
                "started or prepared job cannot be prepared again; use prepare-read".into(),
            );
        }
        j.write(intent.job(), "prepare-bundle", &raw)?;
        j.write(
            intent.job(),
            "prepare-dispatch",
            &preparation_dispatch(&intent, &raw, &initialized)?,
        )?;
    }
    if j.read(intent.job(), "prepare-dispatch")?
        != preparation_dispatch(&intent, &raw, &initialized)?
    {
        return Err("native preparation dispatch changed".into());
    }
    let argv = vec![
        format!(
            "/opt/hol-gauntlet/rust-native-host-pinned-worker-{}",
            intent.text("worker_generation")
        ),
        if publish {
            "--prepare-native-host-pinned-v1"
        } else {
            "--read-native-host-pinned-preparation-v1"
        }
        .into(),
        intent.text("source_sha").into(),
        intent.job().into(),
        intent.text("deployment_digest").into(),
        intent.text("worker_generation").into(),
        intent.text("preparation_sha256").into(),
        sha(&raw),
        raw.len().to_string(),
    ];
    let result = inert_transport(&mut lima, intent.text("vm"), &argv, &raw)?;
    if publish {
        j.write(intent.job(), "prepare-return", &result)?;
    }
    let value = verify_preparation(&intent, &result, &raw, &initialized)?;
    if j.intent(intent.job())? != intent
        || j.read(intent.job(), "prepare-dispatch")?
            != preparation_dispatch(&intent, &raw, &initialized)?
    {
        return Err("native preparation intent or dispatch changed".into());
    }
    j.retain(intent.job(), "prepare-result", &bytes(&value)?)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-deterministic-preparation.v1","job_id":intent.job(),"source_sha":intent.text("source_sha"),
        "intent_sha256":intent.digest()?,"preparation_receipt_sha256":value["receipt_sha256"],"bundle_sha256":sha(&raw),
        "runtime_tree_sha256":value["receipt"]["runtime_tree_sha256"],"next_operation":"run",
        "candidate_executed":false,"execution_eligible":false,"qualification_eligible":false,"model_requests":0}),
    )
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    if let Some(job) = name.strip_suffix(".native-initialize-dispatch.json") {
        retained_initialization(j, job)?;
    }
    if let Some(job) = name.strip_suffix(".native-prepare-dispatch.json") {
        require_prepared(j, &j.intent(job)?)?;
    }
    Ok(())
}
pub(super) fn run_command(args: &[String]) -> Result<Value, String> {
    match (args.first().map(String::as_str), args.len()) {
        (Some("initialize"), 9) | (Some("initialize-read"), 4) => initialize(args),
        (Some("prepare"), 6) | (Some("prepare-read"), 4) => prepare(args),
        _ => Err(super::NATIVE_OPERATION_USAGE.into()),
    }
}

#[cfg(test)]
#[path = "native_preparation_operation_tests.rs"]
mod tests;
