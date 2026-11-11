//! Inert workspace initialization and exact preparation publication precede
//! native execution. Their one-use transports share the operational journal.
use super::{bytes, hex, sha, transport::Lima, Intent, Journal};
use crate::private_jobs::{read_regular_bytes_bounded, state_root};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

const BUNDLE_LIMIT: u64 = 65536;
#[path = "native_initialization_operation.rs"]
mod initialization;
#[cfg(test)]
pub(crate) use initialization::storage::fixture as job_storage_fixture;
pub(crate) use initialization::verify_storage;
use initialization::{initialization_for, initialize, retained_initialization};
#[cfg(test)]
use initialization::{verify_initialization, Initialization};

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
fn inert_transport(
    lima: &mut Lima,
    vm: &str,
    argv: &[String],
    input: &[u8],
) -> Result<Vec<u8>, String> {
    bounded_transport(lima, vm, argv, input, Duration::from_secs(180))
}
pub(super) fn prepared_job_transport(
    lima: &mut Lima,
    vm: &str,
    argv: &[String],
    input: &[u8],
) -> Result<Vec<u8>, String> {
    // Full preparation verifies both original and published inert trees twice.
    // Match the fixed 990-second preparation budget with 30 seconds for transport.
    bounded_transport(lima, vm, argv, input, Duration::from_secs(1020))
}
fn bounded_transport(
    lima: &mut Lima,
    vm: &str,
    argv: &[String],
    input: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut command = lima.command(vm)?;
    command.args(argv);
    let result = crate::stream_process::run_streamed_command(command, input, timeout, 8193)
        .map_err(|error| {
            format!("inert native transport {error:?}; retain dispatch and reconcile with read")
        })?;
    lima.recheck()?;
    Ok(result)
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
    if intent.is_live() {
        super::live::verify_bundle_binding(intent, d)?;
    }
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
        || d["schema"] != intent.declaration_version().0
        || d["profile"] != intent.declaration_version().1
        || (readonly && (d.get("role").is_some() || d.get("sdk").is_some()))
        || (!readonly && !intent.is_live() && d["role"] != intent.text("role"))
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
    storage: Option<&str>,
) -> Result<Value, String> {
    let v = frame(
        raw,
        if storage.is_some() {
            "hol-gauntlet-native-host-pinned-preparation-result.v2"
        } else {
            "hol-gauntlet-native-host-pinned-preparation-result.v1"
        },
        if storage.is_some() { 19 } else { 18 },
    )?;
    let r = &v["receipt"];
    let bundle: Value =
        serde_json::from_slice(bundle_raw).map_err(|_| "native retained bundle invalid")?;
    let readonly = intent.text("role") == "readonly-utility";
    if r["schema"]
        != if storage.is_some() {
            "hol-gauntlet-native-host-pinned-preparation.v2"
        } else {
            "hol-gauntlet-native-host-pinned-preparation.v1"
        }
        || r["source_sha"] != intent.text("source_sha")
        || r["job_id"] != intent.job()
        || r["deployment_digest"] != intent.text("deployment_digest")
        || r["worker_generation"] != intent.text("worker_generation")
        || r["preparation_sha256"] != intent.text("preparation_sha256")
        || r["bundle_sha256"] != sha(bundle_raw)
        || r["initialization_sha256"] != initialization
        || storage.is_some_and(|s| !hex(s, 64) || r["storage_receipt_sha256"] != s)
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
    let initial = initialization_for(j, intent)?;
    verify_preparation(
        intent,
        &j.read(intent.job(), "prepare-result")?,
        &raw,
        &initialized,
        initial["receipt"]["storage"]["receipt_sha256"].as_str(),
    )
}

pub(super) fn retained_storage(j: &Journal, intent: &Intent) -> Result<Option<Value>, String> {
    let mut present = false;
    for suffix in [
        "initialize-intent",
        "initialize-dispatch",
        "initialize-return",
        "initialize-result",
    ] {
        present |= !j.absent(intent.job(), suffix)?;
    }
    if !present {
        return Ok(None);
    }
    let initial = initialization_for(j, intent)?;
    Ok(initial["receipt"].get("storage").cloned())
}

pub(super) fn verify_completion(
    j: &Journal,
    intent: &Intent,
    raw: &[u8],
) -> Result<crate::HostNativeControlReadback, String> {
    let keys = crate::HostControllerKeyPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    let storage = retained_storage(j, intent)?;
    match storage {
        Some(storage) => keys.verify_native_bounded_completion(
            raw,
            &intent.expected(),
            intent.text("preparation_sha256"),
            intent.text("role"),
            None,
            &storage,
        ),
        None => keys.verify_native_completion(
            raw,
            &intent.expected(),
            intent.text("preparation_sha256"),
            intent.text("role"),
        ),
    }
    .map_err(|e| e.to_string())
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
    let result = prepared_job_transport(&mut lima, intent.text("vm"), &argv, &raw)?;
    if publish {
        j.write(intent.job(), "prepare-return", &result)?;
    }
    let initial = initialization_for(&j, &intent)?;
    let value = verify_preparation(
        &intent,
        &result,
        &raw,
        &initialized,
        initial["receipt"]["storage"]["receipt_sha256"].as_str(),
    )?;
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
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<bool, String> {
    if let Some((job, _)) = name.split_once(".native-").filter(|(job, _)| hex(job, 16)) {
        let abort_row = name.contains(".native-initialize-abort-");
        if abort_row
            || !j.absent(job, "initialize-abort-intent")?
            || !j.absent(job, "initialize-abort-dispatch")?
        {
            initialization::verify_abort_record(j, job)?;
            if name.ends_with(".native-dispatch.json") {
                let a: Value = serde_json::from_slice(&j.read(job, "initialize-abort-intent")?)
                    .map_err(|_| "abort intent JSON")?;
                if a["schema"] == "hol-gauntlet-host-native-initialization-abort-unreleased.v1" {
                    return Ok(true);
                }
            }
            if abort_row
                || name.ends_with(".native-initialize-dispatch.json")
                || name.ends_with(".native-prepare-dispatch.json")
            {
                return Ok(false);
            }
        }
    }
    if let Some(job) = name.strip_suffix(".native-initialize-dispatch.json") {
        retained_initialization(j, job)?;
    }
    if let Some(job) = name.strip_suffix(".native-prepare-dispatch.json") {
        require_prepared(j, &j.intent(job)?)?;
    }
    Ok(false)
}
pub(super) fn run_command(args: &[String]) -> Result<Value, String> {
    match (args.first().map(String::as_str), args.len()) {
        (Some("initialize"), 9 | 10) | (Some("initialize-read"), 4) => initialize(args),
        (Some("initialize-abort" | "initialize-abort-unreleased"), 8)
        | (Some("initialize-abort-read" | "initialize-abort-resume"), 4) => {
            initialization::abort(args)
        }
        (Some("prepare"), 6) | (Some("prepare-read"), 4) => prepare(args),
        _ => Err(super::NATIVE_OPERATION_USAGE.into()),
    }
}

#[cfg(test)]
#[path = "native_preparation_operation_tests.rs"]
mod tests;
