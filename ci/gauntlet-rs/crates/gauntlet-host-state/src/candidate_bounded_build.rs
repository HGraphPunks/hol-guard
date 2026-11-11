//! New builds consume the original completed bounded-source transport context.
use super::super::{bytes, context, hex, sha, Journal};
use crate::{
    public_vm_operations, HostCandidateBuildPinJournal, HostCandidateBuildPins,
    VmCandidateBuildInvocation, VmCandidateBuildPlan, VmHostBoundCandidateResultPlan,
};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
pub(super) const INTENT: &str = "bounded-build-intent";
pub(super) use super::prefix::{
    candidate_flow as flow, candidate_read_inputs as prefix_inputs,
    candidate_read_record as read_record,
};
const DISPATCH: &str = "bounded-build-dispatch";
const BINDING: &str = "bounded-build-pin-binding";
const LAUNCH: &str = "bounded-build-launch";
const RETURN: &str = "bounded-build-return";
const CLAIM: &str = "bounded-build-claim";
const RECOVERED: &str = "bounded-build-recovered-terminal";
pub(super) const USAGE:&str="run-bounded PRIVATE_PIN_DIR PRIVATE_TRANSFER_DIR SOURCE_TRANSFER_INTENT_SHA256 JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 VERSION TAG CONTROLLER_ROOT CONTROLLER_TREE_SHA256 UV_BASE_IMAGE_ID RUST_BASE_IMAGE_ID BUILDER_IMAGE_ID POLICY_SHA256 PODMAN_SHA256 SLIRP_SHA256 APPARMOR_PARSER_SHA256 SECCOMP_SHA256 RUNNER_SHA256 RESULT_READER_SHA256 READINESS_SHA256\nread-bounded PRIVATE_PIN_DIR PRIVATE_TRANSFER_DIR SOURCE_TRANSFER_INTENT_SHA256 JOB_ID RESULT_SHA256 EXPORT_ARCHIVE_SHA256\nThe completed build-v1 source receipt owns VM, homes and Lima identity. Old v4-only jobs cannot acquire this versioned binding. Unknown work cannot be rerun; all admission and qualification remain false.";
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str()
        .ok_or_else(|| format!("bounded build {k} absent"))
}
fn closed(v: &Value, fields: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|k| o.contains_key(*k)))
}
fn pins(v: &Value) -> Result<HostCandidateBuildPins, String> {
    let get = |k| text(v, k).map(str::to_owned);
    let p = HostCandidateBuildPins {
        job_id: get("job_id")?,
        source_sha: get("source_sha")?,
        source_archive_sha256: get("source_archive_sha256")?,
        version: get("version")?,
        tag: get("tag")?,
        controller_root: get("controller_root")?,
        controller_tree_sha256: get("controller_tree_sha256")?,
        uv_base_image_id: get("uv_base_image_id")?,
        rust_base_image_id: get("rust_base_image_id")?,
        builder_image_id: get("builder_image_id")?,
        policy_sha256: get("policy_sha256")?,
        podman_sha256: get("podman_sha256")?,
        slirp4netns_sha256: get("slirp4netns_sha256")?,
        apparmor_parser_sha256: get("apparmor_parser_sha256")?,
        seccomp_sha256: get("seccomp_sha256")?,
        runner_binary_sha256: get("runner_binary_sha256")?,
        result_reader_binary_sha256: get("result_reader_binary_sha256")?,
    };
    if !p.valid() || value(&p) != *v {
        return Err("exact public build identity pins required".into());
    }
    Ok(p)
}
fn value(p: &HostCandidateBuildPins) -> Value {
    json!({"job_id":p.job_id,"source_sha":p.source_sha,"source_archive_sha256":p.source_archive_sha256,
        "version":p.version,"tag":p.tag,"controller_root":p.controller_root,"controller_tree_sha256":p.controller_tree_sha256,
        "uv_base_image_id":p.uv_base_image_id,"rust_base_image_id":p.rust_base_image_id,"builder_image_id":p.builder_image_id,
        "policy_sha256":p.policy_sha256,"podman_sha256":p.podman_sha256,"slirp4netns_sha256":p.slirp4netns_sha256,
        "apparmor_parser_sha256":p.apparmor_parser_sha256,"seccomp_sha256":p.seccomp_sha256,
        "runner_binary_sha256":p.runner_binary_sha256,"result_reader_binary_sha256":p.result_reader_binary_sha256})
}
fn source(i: &Value) -> &Value {
    &i["source"]["intent"]
}
pub(super) fn parse(raw: &[u8]) -> Result<Value, String> {
    let i: Value = serde_json::from_slice(raw).map_err(|_| "bounded build intent JSON invalid")?;
    let p = pins(&i["build_pins"])?;
    if bytes(&i)? != raw
        || !closed(
            &i,
            &[
                "schema",
                "job_id",
                "source",
                "build_pins",
                "readiness_binary_sha256",
                "execution_eligible",
                "qualification_eligible",
            ],
        )
        || i["schema"] != "hol-gauntlet-host-bounded-candidate-build.v1"
        || i["job_id"] != p.job_id
        || !hex(text(&i, "readiness_binary_sha256")?, 64)
        || i["execution_eligible"] != false
        || i["qualification_eligible"] != false
        || i["source"]["schema"] != "hol-gauntlet-host-bounded-source-context.v1"
        || i["source"]["source_graph_verified"] != true
        || source(&i)["job_id"] != p.job_id
        || source(&i)["source_sha"] != p.source_sha
        || source(&i)["source_archive_sha256"] != p.source_archive_sha256
        || source(&i)["storage_profile"] != "build-v1"
    {
        return Err("versioned bounded build/source identity and build-v1 profile required".into());
    }
    recheck_source(&i)?;
    Ok(i)
}
fn recheck_source(i: &Value) -> Result<(), String> {
    let s = &i["source"];
    if super::source::completed(
        Path::new(text(s, "journal")?),
        text(i, "job_id")?,
        text(s, "intent_sha256")?,
    )? != *s
    {
        return Err("original completed source journal, storage or transport changed".into());
    }
    Ok(())
}
pub(super) fn plan(i: &Value) -> Result<VmCandidateBuildPlan, String> {
    let operations =
        public_vm_operations(Some(text(source(i), "vm")?)).map_err(|e| e.to_string())?;
    VmCandidateBuildPlan::new(&operations, pins(&i["build_pins"])?).map_err(|e| e.to_string())
}
fn dispatch(i: &Value) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-bounded-build-dispatch.v1","intent_sha256":sha(&bytes(i)?),"retry_allowed":false}),
    )
}
fn binding(i: &Value, inv: &VmCandidateBuildInvocation) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-bounded-build-pin.v1","intent_sha256":sha(&bytes(i)?),
        "host_pin_sha256":inv.to_json()["host_pin_sha256"],"storage_receipt_sha256":i["source"]["storage_receipt_sha256"]}),
    )
}
fn stable(j: &Journal, i: &Value) -> Result<(), String> {
    if j.read(text(i, "job_id")?, INTENT)? != bytes(i)?
        || j.read(text(i, "job_id")?, DISPATCH)? != dispatch(i)?
    {
        return Err("bounded build intent or consumed dispatch changed".into());
    }
    recheck_source(i)?;
    j.stable()
}
pub(super) fn require_launch(
    j: &Journal,
    i: &Value,
    inv: &VmCandidateBuildInvocation,
) -> Result<(), String> {
    stable(j, i)?;
    let job = text(i, "job_id")?;
    let readiness = plan(i)?
        .preflight_plan(text(i, "readiness_binary_sha256")?)
        .map_err(|e| e.to_string())?;
    let ready = readiness
        .parse_response(&j.read(job, "bounded-build-ready-return")?)
        .map_err(|_| "original bounded readiness record unavailable or changed")?;
    if j.read(job, "bounded-build-ready")? != bytes(&ready)? {
        return Err("original bounded readiness summary changed".into());
    }
    if j.read(job, BINDING)? != binding(i, inv)? || j.read(job, LAUNCH)? != binding(i, inv)? {
        return Err("original bounded build launch binding unavailable".into());
    }
    let keys = HostCandidateBuildPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    if keys.read(job).map_err(|e| e.to_string())? != *inv.record() {
        return Err("original private build pin changed".into());
    }
    let raw = crate::private_jobs::read_regular_bytes(
        keys.directory().map_err(|e| e.to_string())?,
        &format!("{job}.candidate-build-dispatch.json"),
        j.owner,
    )
    .map_err(|e| e.to_string())?;
    if raw
        != bytes(
            &json!({"schema":"hol-gauntlet-host-candidate-dispatch.v1","job_id":job,
        "host_pin_sha256":inv.to_json()["host_pin_sha256"],"retry_allowed":false,"execution_eligible":false}),
        )?
    {
        return Err("original official candidate dispatch missing or changed".into());
    }
    Ok(())
}
pub(super) fn retained_claim(j: &Journal, i: &Value) -> Result<Value, String> {
    let keys = HostCandidateBuildPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    let inv = plan(i)?
        .retained_invocation(&keys)
        .map_err(|e| e.to_string())?;
    require_launch(j, i, &inv)?;
    if j.absent(text(i, "job_id")?, CLAIM)? {
        let expected = completed_observation(j, i, &inv)?;
        if j.read(text(i, "job_id")?, RECOVERED)? != bytes(&expected)? {
            return Err("recovered terminal observation changed".into());
        }
        return Ok(expected["terminal"].clone());
    }
    if !j.absent(text(i, "job_id")?, RECOVERED)? {
        return Err("duplicate original and recovered terminal authorities".into());
    }
    let claim = inv
        .parse_terminal_claim(&j.read(text(i, "job_id")?, RETURN)?)
        .map_err(|_| "bounded build terminal is incomplete or changed")?;
    if j.read(text(i, "job_id")?, CLAIM)? != bytes(&claim)? {
        return Err("bounded build sanitized claim changed".into());
    }
    Ok(claim)
}
fn completed_observation(
    j: &Journal,
    i: &Value,
    inv: &VmCandidateBuildInvocation,
) -> Result<Value, String> {
    require_launch(j, i, inv)?;
    let job = text(i, "job_id")?;
    let input = j.read(job, "bounded-build-read-intent")?;
    let pins: Value =
        serde_json::from_slice(&input).map_err(|_| "completed read intent invalid")?;
    let result = text(&pins, "result_sha256")?;
    let archive = text(&pins, "archive_sha256")?;
    if input
        != bytes(
            &json!({"schema":"hol-gauntlet-host-bounded-build-read.v1","intent_sha256":sha(&bytes(i)?),"result_sha256":result,"archive_sha256":archive}),
        )?
    {
        return Err("original completed-read intent differs".into());
    }
    let keys = HostCandidateBuildPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    let operations =
        public_vm_operations(Some(text(source(i), "vm")?)).map_err(|e| e.to_string())?;
    let reader = VmHostBoundCandidateResultPlan::new(&operations, &keys, job, result, archive)
        .map_err(|e| e.to_string())?;
    let raw = j.read(job, "bounded-build-read-return")?;
    let report = reader
        .parse_response(&raw)
        .map_err(|_| "authenticated original completed read required")?;
    let terminal = inv.completed_terminal(&report)?;
    let read_result = j.read(job, "bounded-build-read-result")?;
    if read_result != bytes(&read_record(i, &report)?)? {
        return Err("completed read receipt differs".into());
    }
    let original = if j.absent(job, RETURN)? {
        None
    } else {
        let initial = j.read(job, RETURN)?;
        Some(inv.prior_terminal_sha256(&initial, &terminal)?)
    };
    Ok(
        json!({"schema":"hol-gauntlet-host-bounded-build-recovered-terminal.v1","intent_sha256":sha(&bytes(i)?),
        "dispatch_sha256":sha(&dispatch(i)?),"read_intent_sha256":sha(&input),"read_return_sha256":sha(&raw),
        "read_result_sha256":sha(&read_result),"original_return_sha256":original,"terminal":terminal,
        "execution_eligible":false,"qualification_eligible":false}),
    )
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    if let Some(job) = name.strip_suffix(".native-bounded-build-dispatch.json") {
        let i = parse(&j.read(job, INTENT)?)?;
        if text(&i, "job_id")? != job {
            return Err("bounded build journal identity differs".into());
        }
        retained_claim(j, &i).map_err(|_| "unknown bounded build blocks new dispatch")?;
    }
    Ok(())
}
pub(super) fn verify_artifact_binding(j: &Journal, artifact: &Value) -> Result<bool, String> {
    let job = text(artifact, "job_id")?;
    if j.absent(job, INTENT)? {
        return Ok(false);
    }
    let i = parse(&j.read(job, INTENT)?)?;
    if ["source_sha", "source_archive_sha256", "version"]
        .iter()
        .any(|k| artifact[*k] != i["build_pins"][*k])
        || ["limactl", "vm", "lima_sha256", "transport_context"]
            .iter()
            .any(|k| artifact[*k] != source(&i)[*k])
    {
        return Err(
            "artifact differs from original bounded build/source context or terminal export".into(),
        );
    }
    if j.absent(job, CLAIM)? && j.absent(job, RECOVERED)? {
        let keys = HostCandidateBuildPinJournal::open(&j.path).map_err(|e| e.to_string())?;
        let inv = plan(&i)?
            .retained_invocation(&keys)
            .map_err(|e| e.to_string())?;
        require_launch(j, &i, &inv)?;
        if artifact["operation"] != "capture"
            || artifact["build_pin_sha256"] != inv.to_json()["host_pin_sha256"]
        {
            return Err("only inert capture may precede authenticated completed terminal".into());
        }
        return Ok(true);
    }
    let claim = retained_claim(j, &i)?;
    if artifact["build_pin_sha256"] != claim["host_pin_sha256"]
        || claim["status"] != "exited-zero"
        || claim["exit_code"] != 0
        || artifact["archive_sha256"] != claim["unadmitted_export_sha256"]
    {
        return Err("artifact differs from original successful terminal/export".into());
    }
    Ok(false)
}
fn invoke(
    lima: &mut context::Lima,
    i: &Value,
    argv: &[String],
    timeout: Duration,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let s = source(i);
    if argv.len() < 7
        || argv[0] != text(s, "limactl")?
        || argv[1] != "shell"
        || argv[2] != text(s, "vm")?
        || argv[3..6] != ["--", "sudo", "-n"]
    {
        return Err("official candidate transport differs from retained source".into());
    }
    let mut command = lima.command(text(s, "vm")?)?;
    // The official opaque argv owns any private pin values. Never serialize it.
    command.args(&argv[6..]);
    let raw = crate::stream_process::run_streamed_command(command, b"", timeout, limit)
        .map_err(|_| "bounded candidate transport uncertain; never replay workload")?;
    lima.recheck()?;
    Ok(raw)
}
fn run(
    j: &Journal,
    i: &Value,
    mut transport: impl FnMut(&Value, &[String], Duration, usize) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    parse(&bytes(i)?)?;
    let job = text(i, "job_id")?;
    let keys = HostCandidateBuildPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    if !matches!(
        keys.read(job),
        Err(crate::HostCandidateBuildPinError::Missing)
    ) {
        return Err("existing private build pin cannot acquire a new bounded binding".into());
    }
    for suffix in [
        INTENT,
        DISPATCH,
        BINDING,
        LAUNCH,
        RETURN,
        CLAIM,
        "bounded-build-ready-return",
        "bounded-build-ready",
        "bounded-build-read-intent",
        "bounded-build-read-result",
    ] {
        if !j.absent(job, suffix)? {
            return Err("bounded build already planned or consumed; read without replay".into());
        }
    }
    super::idle(j)?;
    j.write(job, INTENT, &bytes(i)?)?;
    j.write(job, DISPATCH, &dispatch(i)?)?;
    stable(j, i)?;
    let plan = plan(i)?;
    let readiness = plan
        .preflight_plan(text(i, "readiness_binary_sha256")?)
        .map_err(|e| e.to_string())?;
    let raw = transport(i, readiness.argv(), Duration::from_secs(120), 2049)?;
    stable(j, i)?;
    j.write(job, "bounded-build-ready-return", &raw)?;
    let ready = readiness
        .parse_response(&raw)
        .map_err(|_| "bounded readiness differs; dispatch consumed")?;
    j.write(job, "bounded-build-ready", &bytes(&ready)?)?;
    let inv = plan
        .record_before_launch(&keys)
        .map_err(|e| e.to_string())?;
    j.write(job, BINDING, &binding(i, &inv)?)?;
    j.write(job, LAUNCH, &binding(i, &inv)?)?;
    stable(j, i)?;
    keys.consume_dispatch(inv.record())?;
    require_launch(j, i, &inv)?;
    let raw = transport(
        i,
        inv.argv(),
        Duration::from_secs(gauntlet_contracts::CANDIDATE_BUILD_TIMEOUT_SECONDS + 120),
        8193,
    )?;
    require_launch(j, i, &inv)?;
    j.write(job, RETURN, &raw)?;
    let claim = inv
        .parse_terminal_claim(&raw)
        .map_err(|_| "bounded terminal differs; original dispatch remains consumed")?;
    j.write(job, CLAIM, &bytes(&claim)?)?;
    let claim = retained_claim(j, i)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-bounded-candidate-run.v1","job_id":job,"source_sha":i["build_pins"]["source_sha"],
        "intent_sha256":sha(&bytes(i)?),"source_intent_sha256":i["source"]["intent_sha256"],
        "storage_receipt_sha256":i["source"]["storage_receipt_sha256"],"original_source_transport_verified":true,
        "claim":claim,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false}),
    )
}
fn read(
    j: &Journal,
    i: &Value,
    result_sha: &str,
    archive_sha: &str,
    mut transport: impl FnMut(&Value, &[String], Duration, usize) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    if !hex(result_sha, 64) || !hex(archive_sha, 64) {
        return Err("outside result and export digests required".into());
    }
    let job = text(i, "job_id")?;
    let keys = HostCandidateBuildPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    let inv = plan(i)?
        .retained_invocation(&keys)
        .map_err(|e| e.to_string())?;
    require_launch(j, i, &inv)?;
    let operations =
        public_vm_operations(Some(text(source(i), "vm")?)).map_err(|e| e.to_string())?;
    let reader =
        VmHostBoundCandidateResultPlan::new(&operations, &keys, job, result_sha, archive_sha)
            .map_err(|e| e.to_string())?;
    let intent = bytes(
        &json!({"schema":"hol-gauntlet-host-bounded-build-read.v1","intent_sha256":sha(&bytes(i)?),"result_sha256":result_sha,"archive_sha256":archive_sha}),
    )?;
    j.retain(job, "bounded-build-read-intent", &intent)?;
    let raw = transport(i, reader.argv(), Duration::from_secs(30), 4097)?;
    require_launch(j, i, &inv)?;
    if j.read(job, "bounded-build-read-intent")? != intent {
        return Err("outside bounded read pins changed".into());
    }
    j.retain(
        job,
        &format!("bounded-build-read-frame-{}", sha(&raw)),
        &raw,
    )?;
    let report = reader
        .parse_response(&raw)
        .map_err(|_| "bounded retained result differs from original private build pin")?;
    if j.absent(job, CLAIM)? {
        inv.completed_terminal(&report)?;
    }
    j.retain(job, "bounded-build-read-return", &raw)?;
    let result = read_record(i, &report)?;
    j.retain(job, "bounded-build-read-result", &bytes(&result)?)?;
    if j.absent(job, CLAIM)? {
        j.retain(job, RECOVERED, &bytes(&completed_observation(j, i, &inv)?)?)?;
    }
    Ok(result)
}
pub(super) fn run_command(args: &[String]) -> Result<Value, String> {
    let run_mode = match (args.first().map(String::as_str), args.len()) {
        (Some("run-bounded"), 22) => true,
        (Some("read-bounded"), 7) => false,
        _ => return Err(USAGE.into()),
    };
    let source_context = super::source::completed(Path::new(&args[2]), &args[4], &args[3])?;
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let i = if run_mode {
        let p = HostCandidateBuildPins {
            job_id: args[4].clone(),
            source_sha: args[5].clone(),
            source_archive_sha256: args[6].clone(),
            version: args[7].clone(),
            tag: args[8].clone(),
            controller_root: args[9].clone(),
            controller_tree_sha256: args[10].clone(),
            uv_base_image_id: args[11].clone(),
            rust_base_image_id: args[12].clone(),
            builder_image_id: args[13].clone(),
            policy_sha256: args[14].clone(),
            podman_sha256: args[15].clone(),
            slirp4netns_sha256: args[16].clone(),
            apparmor_parser_sha256: args[17].clone(),
            seccomp_sha256: args[18].clone(),
            runner_binary_sha256: args[19].clone(),
            result_reader_binary_sha256: args[20].clone(),
        };
        parse(&bytes(
            &json!({"schema":"hol-gauntlet-host-bounded-candidate-build.v1","job_id":args[4],"source":source_context,
            "build_pins":value(&p),"readiness_binary_sha256":args[21],"execution_eligible":false,"qualification_eligible":false}),
        )?)?
    } else {
        let i = parse(&j.read(&args[4], INTENT)?)?;
        if i["source"] != source_context || i["job_id"] != args[4] {
            return Err("bounded read requires original source journal and outside intent".into());
        }
        i
    };
    let s = source(&i);
    let mut lima = context::Lima::open_pinned(
        text(s, "limactl")?,
        text(s, "lima_sha256")?,
        &s["transport_context"],
    )?;
    if run_mode {
        run(&j, &i, |i, argv, t, l| invoke(&mut lima, i, argv, t, l))
    } else {
        read(&j, &i, &args[5], &args[6], |i, argv, t, l| {
            invoke(&mut lima, i, argv, t, l)
        })
    }
}

#[cfg(test)]
#[path = "candidate_bounded_build_tests.rs"]
pub(crate) mod tests;
