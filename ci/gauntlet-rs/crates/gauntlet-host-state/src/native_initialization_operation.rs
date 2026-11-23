//! One-use native initialization with retained original transport custody.
use super::{bytes, frame, hex, inert_transport, sha, Intent, Journal, Lima};
use gauntlet_contracts::is_git_sha;
use serde_json::{json, Value};
use std::path::Path;

#[path = "native_storage_claim.rs"]
pub(crate) mod storage;
pub(super) use storage::require_not_aborted;
pub(crate) use storage::verify as verify_storage;
use storage::{abort_records, verify_abort};

#[derive(Clone)]
pub(super) struct Initialization(pub(super) Value);
impl Initialization {
    pub(super) fn parse(raw: &[u8]) -> Result<Self, String> {
        let v: Value = serde_json::from_slice(raw).map_err(|_| "initialization intent invalid")?;
        let bounded = v["schema"] == "hol-gauntlet-host-native-initialization-intent.v2";
        let mut fields = vec![
            "schema",
            "job_id",
            "source_sha",
            "worker_generation",
            "vm",
            "limactl",
            "lima_sha256",
            "transport_context",
        ];
        if bounded {
            fields.push("mke2fs_sha256");
        }
        let text = |k: &str| v[k].as_str().unwrap_or("");
        let vm = text("vm");
        if bytes(&v)? != raw
            || v.as_object().is_none_or(|o| {
                o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k))
            })
            || (!bounded && v["schema"] != "hol-gauntlet-host-native-initialization-intent.v1")
            || (bounded && !hex(text("mke2fs_sha256"), 64))
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
        super::super::context::TransportContext::parse(&v["transport_context"])?;
        if v["transport_context"]["vm"] != v["vm"] {
            return Err("initialization Lima instance differs".into());
        }
        Ok(Self(v))
    }
    pub(super) fn text(&self, k: &str) -> &str {
        self.0[k].as_str().expect("validated initialization")
    }
    pub(super) fn bounded(&self) -> bool {
        self.0["schema"] == "hol-gauntlet-host-native-initialization-intent.v2"
    }
    pub(super) fn job(&self) -> &str {
        self.text("job_id")
    }
    pub(super) fn digest(&self) -> Result<String, String> {
        Ok(sha(&bytes(&self.0)?))
    }
    pub(super) fn dispatch(&self) -> Result<Vec<u8>, String> {
        bytes(
            &json!({"schema":"hol-gauntlet-host-native-initialization-dispatch.v1","job_id":self.job(),"initialization_intent_sha256":self.digest()?,"retry_allowed":false}),
        )
    }
}
pub(super) fn verify_initialization(i: &Initialization, raw: &[u8]) -> Result<Value, String> {
    let v = frame(
        raw,
        if i.bounded() {
            "hol-gauntlet-native-job-initialization-result.v2"
        } else {
            "hol-gauntlet-native-job-initialization-result.v1"
        },
        if i.bounded() { 14 } else { 13 },
    )?;
    let r = &v["receipt"];
    let root = format!("/var/lib/hol-gauntlet-rust/native-jobs/{}", i.job());
    let d = &r["job_directory"];
    let w = &r["workspace"];
    if r["schema"]
        != if i.bounded() {
            "hol-gauntlet-native-job-initialization.v2"
        } else {
            "hol-gauntlet-native-job-initialization.v1"
        }
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
    if i.bounded() {
        verify_storage(
            &r["storage"],
            i.text("source_sha"),
            i.job(),
            i.text("worker_generation"),
            i.text("mke2fs_sha256"),
            "native-v1",
        )?;
        if r["storage"]["receipt"]["root_directory"] != *d {
            return Err("native job directory differs from original bounded filesystem".into());
        }
    }
    Ok(v)
}
pub(super) fn retained_initialization(
    j: &Journal,
    job: &str,
) -> Result<(Initialization, Value), String> {
    let i = Initialization::parse(&j.read(job, "initialize-intent")?)?;
    if i.job() != job || j.read(job, "initialize-dispatch")? != i.dispatch()? {
        return Err("native initialization dispatch differs".into());
    }
    let value = verify_initialization(&i, &j.read(job, "initialize-result")?)?;
    Ok((i, value))
}
pub(super) fn initialization_for(j: &Journal, intent: &Intent) -> Result<Value, String> {
    require_not_aborted(j, intent.job())?;
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
fn unreleased(j: &Journal, i: &Initialization) -> Result<Value, String> {
    let native = j.intent(i.job())?;
    j.require_dispatch(&native)?;
    if [
        "job_id",
        "source_sha",
        "worker_generation",
        "vm",
        "limactl",
        "lima_sha256",
    ]
    .iter()
    .any(|k| i.0[*k] != native.0[*k])
        || i.0["transport_context"] != native.0["transport_context"]
    {
        return Err("unreleased Native dispatch differs from original initialization".into());
    }
    let pins = crate::HostControllerKeyPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    if !matches!(pins.read(i.job()), Err(crate::HostKeyPinError::Missing)) {
        return Err("only an absent official Host pin may abandon an unreleased dispatch".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-host-native-unreleased.v1","native_intent_sha256":native.digest()?,
        "native_dispatch_sha256":sha(&j.read(i.job(),"dispatch")?),"host_pin_missing":true}),
    )
}
pub(super) fn abort_context(
    j: &Journal,
    i: &Initialization,
    v: &Value,
    initial: &str,
    storage: &str,
    podman: &str,
    generation: &str,
) -> Result<Value, String> {
    abort_context_mode(j, i, v, initial, storage, podman, generation, false)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn abort_context_mode(
    j: &Journal,
    i: &Initialization,
    v: &Value,
    initial: &str,
    storage: &str,
    podman: &str,
    generation: &str,
    never_accepted: bool,
) -> Result<Value, String> {
    if !i.bounded()
        || ![initial, storage, podman, generation]
            .iter()
            .all(|s| hex(s, 64))
        || v["receipt_sha256"] != initial
        || v["receipt"]["storage"]["receipt_sha256"] != storage
    {
        return Err("exact outside admitted initialization/storage/helper pins required".into());
    }
    let mut context = json!({"schema":"hol-gauntlet-host-native-initialization-abort.v1","job_id":i.job(),
        "initialization_intent_sha256":i.digest()?,"initialization_sha256":initial,"storage_receipt_sha256":storage,
        "podman_sha256":podman,"aborter_generation":generation,"host_records":abort_records(j,i.job(),never_accepted)?});
    if never_accepted {
        context["schema"] = json!("hol-gauntlet-host-native-initialization-abort-unreleased.v1");
        context["unreleased"] = unreleased(j, i)?;
    }
    Ok(context)
}
fn abort_dispatch(a: &Value) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-native-initialization-abort-dispatch.v1","abort_intent_sha256":sha(&bytes(a)?),"retry_allowed":false}),
    )
}
pub(super) fn verify_abort_record(j: &Journal, job: &str) -> Result<(), String> {
    let (i, v) = retained_initialization(j, job)?;
    let raw = j.read(job, "initialize-abort-intent")?;
    let a: Value = serde_json::from_slice(&raw).map_err(|_| "abort intent JSON invalid")?;
    let get = |k: &str| a[k].as_str().ok_or("abort intent pin absent");
    if raw
        != bytes(&abort_context_mode(
            j,
            &i,
            &v,
            get("initialization_sha256")?,
            get("storage_receipt_sha256")?,
            get("podman_sha256")?,
            get("aborter_generation")?,
            a["schema"] == "hol-gauntlet-host-native-initialization-abort-unreleased.v1",
        )?)?
        || j.read(job, "initialize-abort-dispatch")? != abort_dispatch(&a)?
    {
        return Err("original initialization abort binding changed".into());
    }
    verify_abort(&i, &v, &a, &j.read(job, "initialize-abort-result")?)?;
    Ok(())
}
pub(super) fn abort_execute(
    j: &Journal,
    i: &Initialization,
    v: &Value,
    a: &Value,
    read: bool,
    resume: bool,
    run: impl FnOnce(&[String]) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    let job = i.job();
    let get = |k: &str| a[k].as_str().ok_or("abort intent pin absent");
    if *a
        != abort_context_mode(
            j,
            i,
            v,
            get("initialization_sha256")?,
            get("storage_receipt_sha256")?,
            get("podman_sha256")?,
            get("aborter_generation")?,
            a["schema"] == "hol-gauntlet-host-native-initialization-abort-unreleased.v1",
        )?
    {
        return Err("initialization abort original custody changed".into());
    }
    if read || resume {
        if j.read(job, "initialize-abort-intent")? != bytes(a)?
            || j.read(job, "initialize-abort-dispatch")? != abort_dispatch(a)?
        {
            return Err("original abort dispatch required".into());
        }
    } else {
        require_not_aborted(j, job)?;
        j.retain(job, "initialize-abort-intent", &bytes(a)?)?;
        if !j.absent(job, "initialize-abort-dispatch")? {
            return Err("initialization abort already dispatched; explicit read required".into());
        }
        j.write(job, "initialize-abort-dispatch", &abort_dispatch(a)?)?;
    }
    let argv = vec![
        format!(
            "/opt/hol-gauntlet/rust-native-host-pinned-worker-{}",
            get("aborter_generation")?
        ),
        if read {
            "--read-native-initialization-abort-v1"
        } else {
            "--abort-native-initialization-v1"
        }
        .into(),
        i.text("source_sha").into(),
        job.into(),
        i.text("worker_generation").into(),
        i.text("mke2fs_sha256").into(),
        get("initialization_sha256")?.into(),
        get("storage_receipt_sha256")?.into(),
        get("podman_sha256")?.into(),
        get("aborter_generation")?.into(),
    ];
    let raw = run(&argv).map_err(|_| {
        "initialization abort uncertain; retain intent and reconcile without replay"
    })?;
    j.retain(job, &format!("initialize-abort-frame-{}", sha(&raw)), &raw)?;
    let result = verify_abort(i, v, a, &raw)?;
    if abort_records(j, job, a.get("unreleased").is_some())? != a["host_records"] {
        return Err("native state changed during abort".into());
    }
    j.retain(job, "initialize-abort-result", &bytes(&result)?)?;
    verify_abort_record(j, job)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-native-initialization-aborted.v1","job_id":job,"source_sha":i.text("source_sha"),
        "abort_intent_sha256":sha(&bytes(a)?),"receipt_sha256":result["receipt_sha256"],"snapshot_sha256":sha(&bytes(&result["snapshot"])?),
        "status":"aborted-unstarted","job_consumed":true,"exit_code":null,"model_requests":null,"qualification_eligible":false}),
    )
}
pub(super) fn abort(args: &[String]) -> Result<Value, String> {
    let read = args.first().is_some_and(|s| s == "initialize-abort-read");
    let resume = args.first().is_some_and(|s| s == "initialize-abort-resume");
    if !matches!((read || resume, args.len()), (false, 8) | (true, 4))
        || !hex(&args[2], 16)
        || !args[3..].iter().all(|s| hex(s, 64))
    {
        return Err("exact original initialization abort arguments required".into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let (i, v) = retained_initialization(&j, &args[2])?;
    let a = if read || resume {
        let raw = j.read(i.job(), "initialize-abort-intent")?;
        if sha(&raw) != args[3] {
            return Err("outside abort intent SHA differs".into());
        }
        serde_json::from_slice(&raw).map_err(|_| "abort intent JSON invalid")?
    } else {
        if i.digest()? != args[3] {
            return Err("outside initialization intent SHA differs".into());
        }
        if args[0] == "initialize-abort-unreleased" {
            abort_context_mode(&j, &i, &v, &args[4], &args[5], &args[6], &args[7], true)?
        } else {
            abort_context(&j, &i, &v, &args[4], &args[5], &args[6], &args[7])?
        }
    };
    let mut lima = Lima::open_pinned(
        i.text("limactl"),
        i.text("lima_sha256"),
        &i.0["transport_context"],
    )?;
    abort_execute(&j, &i, &v, &a, read, resume, |a| {
        inert_transport(&mut lima, i.text("vm"), a, &[])
    })
}
pub(super) fn initialize(args: &[String]) -> Result<Value, String> {
    let publish = args[0] == "initialize";
    let new = if publish {
        let bounded = args.len() == 10;
        let offset = usize::from(bounded);
        let mut value = json!({"schema":if bounded {"hol-gauntlet-host-native-initialization-intent.v2"} else {"hol-gauntlet-host-native-initialization-intent.v1"},
            "vm":args[2],"limactl":"/opt/homebrew/bin/limactl","lima_sha256":args[3],"source_sha":args[4],"job_id":args[5],"worker_generation":args[6],
            "transport_context":super::super::context::TransportContext::from_paths(Path::new(&args[7+offset]),Path::new(&args[8+offset]),&args[2])?.value()});
        if bounded {
            value["mke2fs_sha256"] = json!(args[7]);
        }
        Some(Initialization::parse(&bytes(&value)?)?)
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
    let mut argv = vec![
        format!(
            "/opt/hol-gauntlet/rust-native-host-pinned-worker-{}",
            i.text("worker_generation")
        ),
        match (publish, i.bounded()) {
            (true, false) => "--initialize-native-job-v1",
            (false, false) => "--read-native-job-initialization-v1",
            (true, true) => "--initialize-native-job-v2",
            (false, true) => "--read-native-job-initialization-v2",
        }
        .into(),
        i.text("source_sha").into(),
        i.job().into(),
        i.text("worker_generation").into(),
    ];
    if i.bounded() {
        argv.push(i.text("mke2fs_sha256").into());
    }
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
    let mut result = json!({"schema":if i.bounded() {"hol-gauntlet-host-deterministic-initialization.v2"} else {"hol-gauntlet-host-deterministic-initialization.v1"},"job_id":i.job(),"source_sha":i.text("source_sha"),
        "worker_generation":i.text("worker_generation"),"initialization_intent_sha256":i.digest()?,"initialization_receipt_sha256":v["receipt_sha256"],
        "job_directory":v["receipt"]["job_directory"],"workspace":v["receipt"]["workspace"],"next_operation":"record",
        "candidate_executed":false,"execution_eligible":false,"qualification_eligible":false,"model_requests":0});
    if i.bounded() {
        let storage = &v["receipt"]["storage"];
        result["storage"] = json!({"receipt_sha256":storage["receipt_sha256"],
            "profile":storage["receipt"]["profile"],"limits":storage["receipt"]["limits"],
            "original_initialization_bound":true});
    }
    Ok(result)
}

#[cfg(test)]
#[path = "native_initialization_abort_tests.rs"]
mod abort_tests;
