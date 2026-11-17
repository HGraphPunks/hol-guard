//! Independent live reports, pair judgment and original-key quiescent repair.
use super::*;
use gauntlet_contracts::PrelaunchPrepared;
use gauntlet_evidence::{FeatureAiPairPins, FeatureAiWorldPins, NativeControlReportPins};
use std::collections::BTreeMap;
pub(super) fn public_key(raw: &str) -> Result<[u8; 32], String> {
    if !hex(raw, 64) {
        return Err("outside live public key invalid".into());
    }
    let mut out = [0_u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|_| "outside live public key invalid")?;
    }
    Ok(out)
}
pub(super) fn host_pins(
    j: &Journal,
    i: &Intent,
) -> Result<
    (
        HostControllerKeyPinJournal,
        crate::HostKeyPinRecord,
        PrelaunchPrepared,
    ),
    String,
> {
    let keys = HostControllerKeyPinJournal::open(&j.path)
        .map_err(|_| "outside live Host pin unavailable")?;
    let record = keys
        .read(i.job())
        .map_err(|_| "outside live Host pin unavailable")?;
    let p = &record.pins;
    if p.source_sha != i.text("source_sha")
        || p.job_id != i.job()
        || p.deployment_digest != i.text("deployment_digest")
        || p.worker_generation != i.text("worker_generation")
    {
        return Err("original live Host pin context differs".into());
    }
    let prepared = PrelaunchPrepared {
        source_sha: p.source_sha.clone(),
        job_id: p.job_id.clone(),
        deployment_digest: p.deployment_digest.clone(),
        worker_generation: p.worker_generation.clone(),
        started_marker_sha256: p.started_marker_sha256.clone(),
        controller_key_pin_sha256: p.controller_key_pin_sha256.clone(),
        controller_public_key_hex: p.controller_public_key_hex.clone(),
    };
    Ok((keys, record, prepared))
}
struct Audit {
    verified: HostNativeControlReadback,
    files: BTreeMap<String, Vec<u8>>,
    world: FeatureAiWorldPins,
    provider: Value,
    cleanup: Value,
    key: [u8; 32],
    pins: NativeControlReportPins,
    preparation: Value,
    cell: Value,
    archive_sha: String,
    runtime: String,
}
fn audit(j: &Journal, i: &Intent) -> Result<Audit, String> {
    j.require_dispatch(i)?;
    let raw = j.read(i.job(), "completion")?;
    let verified = verify_completion(j, i, &raw)?;
    let completion = parse(&raw)?;
    let r = &completion["report"];
    let prepared = provisioned(j, i)?;
    let w = &r["live_world"];
    let world = FeatureAiWorldPins {
        public_key: public_key(text(&prepared["receipt"], "world_public_key_hex")?)?,
        receipt_count: w["receipt_count"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or("outside World count absent")?,
        final_hash: text(w, "final_hash")?.into(),
        initial_sha256: text(&prepared["receipt"], "world_initial_sha256")?.into(),
        final_sha256: text(w, "world_final_sha256")?.into(),
    };
    let key = public_key(text(&prepared["receipt"], "cleanup_public_key_hex")?)?;
    let count = verified.observation()["model_requests"]
        .as_u64()
        .ok_or("outside live model count absent")?;
    let provider = channel::turn_pins(j, i, count)?;
    let (path, archive_sha) = super::super::public_export::fetch(j, i, &verified)?;
    let archive = crate::native_diagnostic_archive::read_stable(&path, &archive_sha)
        .map_err(|_| "private live archive custody differs")?;
    let files = crate::native_diagnostic_archive::members(&archive)
        .map_err(|_| "bounded private live archive invalid")?;
    let evidence = parse(
        files
            .get("combined/live/evidence.v1.json")
            .ok_or("live cell evidence missing")?,
    )?;
    let cleanup = parse(
        files
            .get("combined/live/cleanup.v1.json")
            .ok_or("outside live cleanup envelope missing")?,
    )?;
    if cleanup != r["live_cleanup"]
        || parse(
            files
                .get("combined/live/prepared.v2.json")
                .ok_or("outside live prepared receipt missing")?,
        )? != prepared["receipt"]
    {
        return Err("archive substitutes outside live preparation or cleanup pins".into());
    }
    let envelope: Value = serde_json::from_str(text(r, "controller_envelope_utf8")?)
        .map_err(|_| "authenticated live envelope encoding invalid")?;
    let (_, _, prelaunch) = host_pins(j, i)?;
    let bundle = parse(&j.read(i.job(), "prepare-bundle")?)?;
    let normal = preparation::require_prepared(j, i)?;
    let mut cell = json!({"envelope":envelope,"evidence":evidence,"cleanup":cleanup});
    if let Some(raw) = files.get("combined/live/context.v1.json") {
        if verified.authenticated.report()["context_sha256"] != sha(raw) {
            return Err("raw live context differs from signed source binding".into());
        }
        cell["context"] =
            json!(std::str::from_utf8(raw).map_err(|_| "raw live context encoding invalid")?);
    }
    Ok(Audit {
        verified,
        files,
        world,
        provider,
        cleanup: cleanup.clone(),
        key,
        pins: NativeControlReportPins {
            prelaunch,
            preparation_sha256: i.text("preparation_sha256").into(),
            role: i.text("role").into(),
        },
        preparation: bundle["preparation"].clone(),
        cell,
        archive_sha,
        runtime: text(&normal["receipt"], "runtime_tree_sha256")?.into(),
    })
}
pub(super) fn report(j: &Journal, i: &Intent) -> Result<Value, String> {
    let a = audit(j, i)?;
    let judgment = a
        .verified
        .authenticated
        .judge_live(
            &a.preparation,
            &a.files,
            &a.world,
            &a.provider,
            &a.cleanup,
            &a.key,
        )
        .map_err(|_| {
            "outside live observations do not authenticate complete independent evidence"
        })?;
    let output = json!({"schema":"hol-gauntlet-host-live-report.v1","job_id":i.job(),"source_sha":i.text("source_sha"),"intent_sha256":i.digest()?,"archive_sha256":a.archive_sha,"readback":a.verified.observation(),"independent_judgment":judgment,"execution_eligible":false,"qualification_eligible":false,"model_requests":a.verified.observation()["model_requests"]});
    let raw = bytes(&output)?;
    j.retain(i.job(), &format!("live-judgment-{}", sha(&raw)), &raw)?;
    Ok(output)
}
pub(super) fn pair(args: &[String]) -> Result<Value, String> {
    if !hex(&args[2], 16) || !hex(&args[3], 64) || !hex(&args[4], 16) || !hex(&args[5], 64) {
        return Err("outside live pair job/intent pins required".into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let a = j.intent(&args[2])?;
    let b = j.intent(&args[4])?;
    if !a.is_live()
        || !b.is_live()
        || a.digest()? != args[3]
        || b.digest()? != args[5]
        || cell_index(a.text("role"))? != 0
        || cell_index(b.text("role"))? != 1
        || binding(&a) != binding(&b)
        || a.text("source_sha") != b.text("source_sha")
    {
        return Err(
            "exact baseline/protected pair and shared provider/source binding required".into(),
        );
    }
    let a = audit(&j, &a)?;
    let b = audit(&j, &b)?;
    let mut provider = a.provider.clone();
    if provider["status_pins"] != b.provider["status_pins"] {
        return Err("live pair provider identities differ".into());
    }
    provider["turn_pins"]
        .as_array_mut()
        .ok_or("outside pair turn pins absent")?
        .extend(
            b.provider["turn_pins"]
                .as_array()
                .ok_or("outside protected turn pins absent")?
                .iter()
                .cloned(),
        );
    let pins = FeatureAiPairPins {
        cells: [a.pins, b.pins],
        world: [a.world, b.world],
        provider,
        cleanup_public_keys: [a.key, b.key],
        runtime_tree_digests: [a.runtime, b.runtime],
    };
    let judgment = gauntlet_evidence::judge_feature_ai_support_pair(
        &json!({"schema":"hol-gauntlet-feature-ai-support-pair.v1","cells":[a.cell,b.cell]}),
        &pins,
    )
    .map_err(|_| "live pair outside custody or independent evidence invalid")?;
    let output = json!({"schema":"hol-gauntlet-host-live-pair.v1","source_sha":pins.cells[0].prelaunch.source_sha,"baseline_job_id":args[2],"protected_job_id":args[4],"baseline_intent_sha256":args[3],"protected_intent_sha256":args[5],"archive_sha256":[a.archive_sha,b.archive_sha],"independent_judgment":judgment,"execution_eligible":false,"qualification_eligible":false});
    let raw = bytes(&output)?;
    j.retain(&args[2], &format!("live-pair-{}", sha(&raw)), &raw)?;
    Ok(output)
}
