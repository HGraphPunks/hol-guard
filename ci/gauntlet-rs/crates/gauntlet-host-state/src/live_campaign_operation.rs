//! Normal source-bound live cells reuse the durable native lifecycle.
use super::{bytes, context, hex, preparation, sha, Intent, Journal};
use crate::{HostControllerKeyPinJournal, HostNativeControlReadback};
use gauntlet_evidence::feature_ai_support_spec;
use serde_json::{json, Value};
use std::path::Path;

#[path = "live_campaign_transport.rs"]
mod channel;
#[path = "live_campaign_recovery.rs"]
mod recovery;
#[path = "live_campaign_results.rs"]
mod results;
pub const LIVE_CAMPAIGN_USAGE:&str="live commands:\ninitialize|initialize-read|prepare|prepare-read: same private journal and exact pins as deterministic preparation\nrecord PRIVATE_JOURNAL VM LIMA_SHA SOURCE JOB DEPLOY WORKER PREPARATION ROLE INTERPRETER OBSERVER SSH_HOME LIMA_HOME PROVIDER_JOURNAL PROVIDER_INTENT_SHA\nprovision|provision-read|run|read|report PRIVATE_JOURNAL JOB INTENT_SHA\nrepair PRIVATE_JOURNAL JOB INTENT_SHA REPAIR_SHA [--never-released]\npair PRIVATE_JOURNAL BASE_JOB BASE_INTENT_SHA PROTECTED_JOB PROTECTED_INTENT_SHA\nRoles: feature-ai-unprotected|feature-ai-protected. Original VM, outside World/cleanup keys, actual provider turns and one-use dispatch are retained privately. Raw archives and model frames never appear in command summaries. Unknown work blocks new dispatch; no inference retry or quota reset.";
fn exact(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str().ok_or_else(|| format!("live {k} text absent"))
}
fn parse(raw: &[u8]) -> Result<Value, String> {
    let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
    let v: Value = serde_json::from_slice(raw).map_err(|_| "live JSON invalid")?;
    if bytes(&v)? != raw {
        return Err("canonical live JSON required".into());
    }
    Ok(v)
}
fn spec() -> Result<(Value, String), String> {
    let v = feature_ai_support_spec().map_err(|_| "source-owned live specification unavailable")?;
    let hash = sha(&bytes(&v)?);
    Ok((v, hash))
}
fn cell_index(role: &str) -> Result<usize, String> {
    match role {
        "feature-ai-unprotected" => Ok(0),
        "feature-ai-protected" => Ok(1),
        _ => Err("explicit source-owned live role required".into()),
    }
}
fn context_value(intent: &Intent) -> &Value {
    &intent.0["live"]
}
fn binding(intent: &Intent) -> &Value {
    &context_value(intent)["provider_binding"]
}
fn recheck_provider(intent: &Intent) -> Result<(), String> {
    let live = context_value(intent);
    if crate::read_live_provider_binding(
        Path::new(text(live, "provider_journal")?),
        text(live, "provider_intent_sha256")?,
    )? != live["provider_binding"]
    {
        return Err("original provider source, job or budget binding changed".into());
    }
    Ok(())
}
fn require_pair_order(j: &Journal, i: &Intent) -> Result<(), String> {
    let cells = &binding(i)["cells"];
    if cell_index(i.text("role"))? == 0 {
        if !j.absent(text(&cells[1], "job_id")?, "dispatch")? {
            return Err("protected dispatch already consumed; baseline cannot be resumed".into());
        }
        return Ok(());
    }
    let baseline = j.intent(text(&cells[0], "job_id")?)?;
    if !baseline.is_live()
        || cell_index(baseline.text("role"))? != 0
        || binding(&baseline) != binding(i)
        || baseline.text("source_sha") != i.text("source_sha")
    {
        return Err("exact original baseline binding required before protected dispatch".into());
    }
    j.require_dispatch(&baseline)?;
    let completed = verify_completion(j, &baseline, &j.read(baseline.job(), "completion")?)?;
    if completed.observation()["model_requests"]
        .as_u64()
        .unwrap_or(0)
        == 0
        || preparation::require_prepared(j, &baseline)?["receipt"]["runtime_tree_sha256"]
            != preparation::require_prepared(j, i)?["receipt"]["runtime_tree_sha256"]
    {
        return Err("completed baseline inference and matching prepared runtime required".into());
    }
    Ok(())
}

pub(super) fn validate_intent(v: &Value) -> Result<(), String> {
    let live = &v["live"];
    let index = cell_index(text(v, "role")?)?;
    let (source, source_sha) = spec()?;
    let b = &live["provider_binding"];
    if v["schema"] != "hol-gauntlet-host-native-live-intent.v1"
        || !exact(
            live,
            &[
                "cell_id",
                "spec_sha256",
                "provider_journal",
                "provider_intent_sha256",
                "provider_binding",
            ],
        )
        || live["cell_id"] != source["cells"][index]["id"]
        || live["spec_sha256"] != source_sha
        || !Path::new(text(live, "provider_journal")?).is_absolute()
        || !hex(text(live, "provider_intent_sha256")?, 64)
        || !exact(
            b,
            &[
                "schema",
                "source_sha",
                "provider_job_id",
                "budget_digest",
                "provider_spec_sha256",
                "source_authorization_sha256",
                "model_id",
                "maximum_accounted_tokens",
                "known_tokens_before",
                "job_tokens",
                "cells",
                "status_pins",
                "private_unix_channel",
                "qualification_eligible",
            ],
        )
        || b["schema"] != "hol-gauntlet-rust-provider-binding.v1"
        || b["source_sha"] != v["source_sha"]
        || b["budget_digest"] != live["provider_intent_sha256"]
        || b["job_tokens"] != 200_000
        || b["private_unix_channel"] != true
        || b["qualification_eligible"] != false
        || !hex(text(b, "provider_job_id")?, 16)
        || !["provider_spec_sha256", "source_authorization_sha256"]
            .iter()
            .all(|k| b[*k].as_str().is_some_and(|s| hex(s, 64)))
        || b["model_id"] != "mlx-community/Qwen3.6-35B-A3B-8bit"
    {
        return Err(
            "closed source-owned live intent and retained provider binding required".into(),
        );
    }
    let pins = &b["status_pins"];
    if !exact(
        pins,
        &[
            "profile",
            "source_sha",
            "provider_job_id",
            "binding_sha256",
            "adapter_sha256",
            "server_sha256",
            "producer_sha256",
            "model_identity_digest",
            "quota_config_digest",
            "quota_allowance_digest",
            "token_cap",
            "maximum_requests",
        ],
    ) || pins["profile"] != "owned-mlx-rust-serial.v2"
        || pins["source_sha"] != v["source_sha"]
        || pins["provider_job_id"] != b["provider_job_id"]
        || pins["binding_sha256"] != live["provider_intent_sha256"]
        || ![
            "adapter_sha256",
            "server_sha256",
            "producer_sha256",
            "model_identity_digest",
            "quota_config_digest",
            "quota_allowance_digest",
        ]
        .iter()
        .all(|k| pins[*k].as_str().is_some_and(|s| hex(s, 64)))
        || b["known_tokens_before"]
            .as_u64()
            .and_then(|n| n.checked_add(200_000))
            != b["maximum_accounted_tokens"].as_u64()
        || b["maximum_accounted_tokens"]
            .as_u64()
            .is_none_or(|n| n > pins["token_cap"].as_u64().unwrap_or(0))
    {
        return Err("outside Rust provider status and absolute budget pins required".into());
    }
    let cells = b["cells"]
        .as_array()
        .filter(|c| c.len() == 2)
        .ok_or("outside provider pair absent")?;
    for (i, c) in cells.iter().enumerate() {
        if !exact(c, &["job_id", "episode_id", "token_budget"])
            || !hex(text(c, "job_id")?, 16)
            || c["episode_id"] != source["cells"][i]["id"]
            || c["token_budget"] != 100_000
        {
            return Err("source-owned pair and per-cell budgets required".into());
        }
    }
    if cells[0]["job_id"] == cells[1]["job_id"] || cells[index]["job_id"] != v["job_id"] {
        return Err("live cell job differs from outside provider pair".into());
    }
    Ok(())
}
pub(super) fn verify_bundle_binding(intent: &Intent, d: &Value) -> Result<(), String> {
    validate_intent(&intent.0)?;
    let l = &d["live"];
    let model = &l["model"];
    if !exact(
        d,
        &[
            "schema",
            "profile",
            "source_sha",
            "job_id",
            "worker_generation",
            "preparation_sha256",
            "guard",
            "sdk",
            "live",
        ],
    ) || d["schema"] != "hol-gauntlet-native-worker-job.v9"
        || d["profile"] != "native-host-pinned-live-omp-v1"
        || d["source_sha"] != intent.text("source_sha")
        || d["job_id"] != intent.job()
        || d["worker_generation"] != intent.text("worker_generation")
        || d["preparation_sha256"] != intent.text("preparation_sha256")
        || sha(&bytes(d)?) != intent.text("deployment_digest")
        || !exact(l, &["schema", "cell_id", "spec_sha256", "model"])
        || l["schema"] != "hol-gauntlet-native-live-omp-job.v1"
        || l["cell_id"] != context_value(intent)["cell_id"]
        || l["spec_sha256"] != context_value(intent)["spec_sha256"]
        || !exact(
            model,
            &[
                "schema",
                "provider_job_id",
                "budget_digest",
                "model_id",
                "max_turns",
                "token_limit",
            ],
        )
        || model["schema"] != "hol-gauntlet-native-live-model-pins.v1"
        || model["provider_job_id"] != binding(intent)["provider_job_id"]
        || model["budget_digest"] != binding(intent)["budget_digest"]
        || model["model_id"] != binding(intent)["model_id"]
        || model["max_turns"] != 64
        || model["token_limit"] != 100_000
    {
        return Err("live declaration differs from exact source cell and provider budget".into());
    }
    Ok(())
}
fn initial_hash() -> Result<String, String> {
    let (mut source, _) = spec()?;
    source["initial_snapshot"]["records"]
        .as_array_mut()
        .ok_or("source World records absent")?
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(sha(&bytes(&source["initial_snapshot"])?))
}
fn verify_prepared(j: &Journal, i: &Intent, raw: &[u8]) -> Result<Value, String> {
    let normal = preparation::require_prepared(j, i)?;
    let v = parse(raw)?;
    let r = &v["receipt"];
    if !exact(&v, &["schema", "receipt", "receipt_sha256"])
        || v["schema"] != "hol-gauntlet-native-live-preparation-result.v1"
        || !exact(
            r,
            &[
                "schema",
                "source_sha",
                "job_id",
                "deployment_digest",
                "worker_generation",
                "preparation_sha256",
                "normal_preparation_receipt_sha256",
                "role",
                "cell_id",
                "spec_sha256",
                "world_public_key_hex",
                "world_initial_sha256",
                "cleanup_public_key_hex",
            ],
        )
        || r["schema"] != "hol-gauntlet-native-live-prepared.v2"
        || v["receipt_sha256"] != sha(&bytes(r)?)
        || r["source_sha"] != i.text("source_sha")
        || r["job_id"] != i.job()
        || r["deployment_digest"] != i.text("deployment_digest")
        || r["worker_generation"] != i.text("worker_generation")
        || r["preparation_sha256"] != i.text("preparation_sha256")
        || r["normal_preparation_receipt_sha256"] != normal["receipt_sha256"]
        || r["role"] != i.text("role")
        || r["cell_id"] != context_value(i)["cell_id"]
        || r["spec_sha256"] != context_value(i)["spec_sha256"]
        || r["world_initial_sha256"] != initial_hash()?
        || !["world_public_key_hex", "cleanup_public_key_hex"]
            .iter()
            .all(|k| r[*k].as_str().is_some_and(|s| hex(s, 64)))
        || r["world_public_key_hex"] == r["cleanup_public_key_hex"]
    {
        return Err("live preparation differs from outside normal/source/World pins".into());
    }
    Ok(v)
}
fn provision_dispatch(i: &Intent) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-live-provision-dispatch.v1","job_id":i.job(),"intent_sha256":i.digest()?,"spec_sha256":context_value(i)["spec_sha256"],"retry_allowed":false}),
    )
}
fn provisioned(j: &Journal, i: &Intent) -> Result<Value, String> {
    if j.read(i.job(), "live-provision-dispatch")? != provision_dispatch(i)? {
        return Err("live provision dispatch differs".into());
    }
    verify_prepared(j, i, &j.read(i.job(), "live-prepared")?)
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    if let Some(job) = name.strip_suffix(".native-live-provision-dispatch.json") {
        provisioned(j, &j.intent(job)?)?;
    }
    Ok(())
}
pub(super) fn verify_completion(
    j: &Journal,
    i: &Intent,
    raw: &[u8],
) -> Result<HostNativeControlReadback, String> {
    let prepared = provisioned(j, i)?;
    let keys = HostControllerKeyPinJournal::open(&j.path)
        .map_err(|_| "outside live Host pins unavailable")?;
    let original = preparation::retained_storage(j, i)?;
    let verified = if let Some(storage) = original {
        keys.verify_native_bounded_completion(
            raw,
            &i.expected(),
            i.text("preparation_sha256"),
            i.text("role"),
            Some((&prepared["receipt"], text(&prepared, "receipt_sha256")?)),
            &storage,
        )
    } else {
        keys.verify_native_live_completion(
            raw,
            &i.expected(),
            i.text("preparation_sha256"),
            i.text("role"),
            &prepared["receipt"],
            text(&prepared, "receipt_sha256")?,
        )
    }
    .map_err(|_| "live completion differs from outside prepared identity")?;
    let count = verified.observation()["model_requests"]
        .as_u64()
        .filter(|n| *n <= 64)
        .ok_or("actual live model count absent")?;
    channel::turn_pins(j, i, count)?;
    Ok(verified)
}
fn record(args: &[String]) -> Result<Value, String> {
    let index = cell_index(&args[9])?;
    let (source, spec_sha) = spec()?;
    let provider = crate::read_live_provider_binding(Path::new(&args[14]), &args[15])?;
    let i = Intent::parse(&bytes(
        &json!({"schema":"hol-gauntlet-host-native-live-intent.v1","vm":args[2],"limactl":"/opt/homebrew/bin/limactl","lima_sha256":args[3],"source_sha":args[4],"job_id":args[5],"deployment_digest":args[6],"worker_generation":args[7],"preparation_sha256":args[8],"role":args[9],"interpreter_sha256":args[10],"observer_sha256":args[11],"transport_context":context::TransportContext::from_paths(Path::new(&args[12]),Path::new(&args[13]),&args[2])?.value(),"live":{"cell_id":source["cells"][index]["id"],"spec_sha256":spec_sha,"provider_journal":args[14],"provider_intent_sha256":args[15],"provider_binding":provider}}),
    )?)?;
    validate_intent(&i.0)?;
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    for suffix in [
        "dispatch",
        "completion",
        "repair-intent",
        "repair",
        "live-provision-dispatch",
        "live-prepared",
    ] {
        if !j.absent(i.job(), suffix)? {
            return Err("existing or uncertain live job blocks recording".into());
        }
    }
    if !matches!(
        HostControllerKeyPinJournal::open(&j.path)
            .map_err(|_| "live Host journal unavailable")?
            .read(i.job()),
        Err(crate::HostKeyPinError::Missing)
    ) {
        return Err("existing or uncertain live Host pin blocks recording".into());
    }
    j.write(i.job(), "intent", &i.raw()?)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-live-record.v1","job_id":i.job(),"source_sha":i.text("source_sha"),"intent_sha256":i.digest()?,"cell_id":context_value(&i)["cell_id"],"spec_sha256":spec_sha,"next_operation":"prepare","execution_eligible":false,"qualification_eligible":false}),
    )
}

pub fn run_live_campaign_command(args: &[String]) -> Result<Value, String> {
    if args.first().is_some_and(|s| {
        matches!(
            s.as_str(),
            "initialize" | "initialize-read" | "prepare" | "prepare-read"
        )
    }) {
        return preparation::run_command(args);
    }
    match (args.first().map(String::as_str), args.len()) {
        (Some("record"), 16) => return record(args),
        (Some("pair"), 6) => return results::pair(args),
        (Some("provision" | "provision-read" | "run" | "read" | "report"), 4) => {}
        (Some("repair"), 5) => {}
        (Some("repair"), 6) if args[5] == "--never-released" => {}
        _ => return Err(LIVE_CAMPAIGN_USAGE.into()),
    }
    if !hex(&args[2], 16) || !hex(&args[3], 64) {
        return Err("exact live job and intent pins required".into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let i = j.intent(&args[2])?;
    if !i.is_live() || i.digest()? != args[3] {
        return Err("outside live intent digest differs".into());
    }
    validate_intent(&i.0)?;
    match args[0].as_str() {
        "provision" | "provision-read" => {
            let publish = args[0] == "provision";
            preparation::require_prepared(&j, &i)?;
            recheck_provider(&i)?;
            if publish {
                j.require_idle()?;
                if !j.absent(i.job(), "dispatch")? || !j.absent(i.job(), "live-prepared")? {
                    return Err("live provisioning already consumed".into());
                }
                j.write(i.job(), "live-provision-dispatch", &provision_dispatch(&i)?)?;
            } else if j.read(i.job(), "live-provision-dispatch")? != provision_dispatch(&i)? {
                return Err("original live provision dispatch required".into());
            }
            let raw = channel::provision(&i, publish)?;
            let prepared = verify_prepared(&j, &i, &raw)?;
            j.retain(i.job(), "live-prepared", &bytes(&prepared)?)?;
            Ok(
                json!({"schema":"hol-gauntlet-host-live-provision.v1","job_id":i.job(),"source_sha":i.text("source_sha"),"intent_sha256":i.digest()?,"live_prepared_sha256":prepared["receipt_sha256"],"next_operation":"run","candidate_executed":false,"model_requests":0,"qualification_eligible":false}),
            )
        }
        "run" => {
            provisioned(&j, &i)?;
            j.require_idle()?;
            require_pair_order(&j, &i)?;
            recheck_provider(&i)?;
            for s in ["return", "completion", "repair-intent", "repair"] {
                if !j.absent(i.job(), s)? {
                    return Err("orphan live result blocks dispatch".into());
                }
            }
            let mut lima = super::transport::Lima::open(&i)?;
            j.write(i.job(), "dispatch", &Journal::dispatch_raw(&i)?)?;
            let raw = channel::execute(&j, &i, &mut lima, true)?;
            j.observe(&i, "run", &raw)
        }
        "read" => {
            j.require_dispatch(&i)?;
            if !j.absent(i.job(), "repair-intent")? {
                return recovery::repair(&j, &i, None);
            }
            let mut lima = super::transport::Lima::open(&i)?;
            let raw = channel::execute(&j, &i, &mut lima, false)?;
            j.observe(&i, "read", &raw)
        }
        "repair" => recovery::repair(&j, &i, Some((&args[4], args.len() == 6))),
        "report" => results::report(&j, &i),
        _ => unreachable!(),
    }
}
pub(super) fn verify_retained_repair(j: &Journal, i: &Intent) -> Result<Value, String> {
    recovery::verify_retained_repair(j, i)
}
