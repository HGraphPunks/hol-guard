//! Pre-client recovery requires the receipt committed before either creator
//! execs. Creator drain precedes container lookup; incomplete files are retained.
use crate::builder_cgroup::OwnedCandidateCgroup;
use crate::{feature_files, RunReservationJournal};
use gauntlet_contracts::{canonicalize, DependencyRunIntent};
use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{fsync, renameat_with, statat, AtFlags, Dir, RenameFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::fd::OwnedFd;

const PREFIX: &str = "dependency-container-recovery-";
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

#[derive(Debug, PartialEq)]
pub(crate) enum OriginalCid {
    Retained(String),
    Incomplete(Option<String>),
}

fn incomplete_prefix(raw: &[u8], digest: &str) -> bool {
    let head = b"{\"container_id\":\"";
    if raw.len() <= head.len() {
        return head.starts_with(raw);
    }
    if !raw.starts_with(head) {
        return false;
    }
    let rest = &raw[head.len()..];
    if !rest[..rest.len().min(64)]
        .iter()
        .all(|b| matches!(b,b'0'..=b'9' | b'a'..=b'f'))
    {
        return false;
    }
    if rest.len() <= 64 {
        return true;
    }
    format!("\",\"intent_sha256\":\"{digest}\",\"schema\":\"hol-gauntlet-native-dependency-container.v1\"}}")
        .as_bytes().starts_with(&rest[64..])
}

fn classify(raw: Option<&[u8]>, digest: &str) -> Result<OriginalCid, String> {
    let Some(raw) = raw else {
        return Ok(OriginalCid::Incomplete(None));
    };
    let v: Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(e) if e.is_eof() && incomplete_prefix(raw, digest) => {
            return Ok(OriginalCid::Incomplete(Some(sha(raw))))
        }
        Err(_) => return Err("dependency CID receipt is malformed".into()),
    };
    if canonicalize(raw).map_err(|e| e.to_string())? != raw
        || v.as_object().is_none_or(|o| o.len() != 3)
        || v["schema"] != "hol-gauntlet-native-dependency-container.v1"
        || v["intent_sha256"] != digest
    {
        return Err("dependency CID receipt differs".into());
    }
    let cid = v["container_id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("full dependency CID required")?;
    Ok(OriginalCid::Retained(cid.into()))
}

pub(crate) fn original(slot: &OwnedFd, digest: &str) -> Result<OriginalCid, String> {
    let raw = feature_files::read(slot, "dependency-container.v1.json", (0, 0), 0o600, 2048)?;
    classify(raw.as_deref(), digest)
}

/// Return the ready/group hashes and original boot without granting cleanup.
pub(crate) fn ready(
    slot: &OwnedFd,
    intent: &DependencyRunIntent,
    started: &str,
) -> Result<(String, String, String), String> {
    let job = intent.pins.text("job_id");
    OwnedCandidateCgroup::reopen_candidate(slot, job, &intent.digest()?)?;
    let group =
        feature_files::required(slot, "candidate-client-cgroup.v1.json", (0, 0), 0o600, 2048)?;
    let v: Value = serde_json::from_slice(&group).map_err(|e| e.to_string())?;
    let boot = v["boot_id"]
        .as_str()
        .ok_or("creator boot missing")?
        .to_owned();
    let raw = feature_files::required(
        slot,
        "dependency-creators-ready.v1.json",
        (0, 0),
        0o600,
        2048,
    )?;
    let expected = canonicalize(json!({"schema":"hol-gauntlet-native-dependency-creators-ready.v1",
        "job_id":job,"intent_sha256":intent.digest()?,"started_marker_sha256":started,
        "worker_generation":intent.pins.text("runner_binary_sha256"),"client_cgroup_receipt_sha256":sha(&group)})
        .to_string().as_bytes()).map_err(|e|e.to_string())?;
    if raw != expected {
        return Err("dependency creator readiness differs".into());
    }
    Ok((sha(&raw), sha(&group), boot))
}

fn no_client(journal: &RunReservationJournal, intent: &DependencyRunIntent) -> Result<(), String> {
    let p = &intent.pins;
    if journal
        .running_marker(
            p.text("job_id"),
            p.text("source_sha"),
            &intent.digest()?,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("missing CID conflicts with a running dependency client".into());
    }
    let slot = crate::builder_candidate_source::open_fixed_build_slot(p.text("job_id"))
        .map_err(|e| e.to_string())?;
    for name in [
        "dependency-run.stdout.log",
        "dependency-run.stderr.log",
        "dependencies.zip",
        "dependencies.receiving",
    ] {
        if !matches!(
            statat(&slot, name, AtFlags::SYMLINK_NOFOLLOW),
            Err(rustix::io::Errno::NOENT)
        ) {
            return Err("missing CID conflicts with retained client activity".into());
        }
    }
    Ok(())
}

struct Context<'a> {
    intent: &'a DependencyRunIntent,
    started: &'a str,
    generation: &'a str,
    ready: String,
    group: String,
    prior: Option<String>,
}
impl Context<'_> {
    fn witness(&self, attempt: &str, cid: Option<&str>) -> Value {
        json!({"schema":"hol-gauntlet-native-dependency-container-recovery.v1",
            "job_id":self.intent.pins.text("job_id"),"source_sha":self.intent.pins.text("source_sha"),
            "intent_sha256":self.intent.digest().expect("validated intent"),
            "worker_generation":self.intent.pins.text("runner_binary_sha256"),"repair_generation":self.generation,
            "started_marker_sha256":self.started,"creators_ready_sha256":self.ready,
            "client_cgroup_receipt_sha256":self.group,"prior_container_receipt_sha256":self.prior,
            "container_id":cid,"attempt_id":attempt})
    }
}
struct Witness {
    id: String,
    raw: Vec<u8>,
    cid: Option<String>,
}

fn witnesses(slot: &OwnedFd, context: &Context) -> Result<Vec<Witness>, String> {
    let mut result = Vec::new();
    let mut count = 0usize;
    for entry in Dir::read_from(slot).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let raw_name = entry.file_name();
        if !raw_name.to_bytes().starts_with(PREFIX.as_bytes()) {
            continue;
        }
        count += 1;
        if count > 64 {
            return Err("creator recovery attempt bound exceeded".into());
        }
        let name = raw_name
            .to_str()
            .map_err(|_| "creator witness name UTF-8")?;
        let id = name
            .strip_prefix(PREFIX)
            .and_then(|s| s.strip_suffix(".json"))
            .filter(|s| crate::hex(s, 16))
            .ok_or("creator witness name differs")?;
        let raw = feature_files::required(slot, name, (0, 0), 0o600, 8192)?;
        let v: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) if e.is_eof() => continue, // Never authority; never overwritten.
            Err(_) => return Err("creator witness is malformed".into()),
        };
        let cid = match &v["container_id"] {
            Value::Null => None,
            Value::String(s) if crate::hex(s, 64) => Some(s.to_owned()),
            _ => return Err("creator witness CID differs".into()),
        };
        let expected = canonicalize(context.witness(id, cid.as_deref()).to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        if raw != expected {
            return Err("creator witness binding differs".into());
        }
        result.push(Witness {
            id: id.into(),
            raw,
            cid,
        });
    }
    if result.windows(2).any(|rows| rows[0].cid != rows[1].cid) {
        return Err("creator witnesses disagree about container identity".into());
    }
    result.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(result)
}

fn attempt() -> Result<String, String> {
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "creator recovery identity unavailable")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub(crate) fn reclaim(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    started: &str,
    generation: &str,
    group: &mut Option<OwnedCandidateCgroup>,
    still_owned: &impl Fn() -> Result<(), String>,
    phase: &mut &str,
) -> Result<(), String> {
    let job = intent.pins.text("job_id");
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let OriginalCid::Incomplete(prior) = original(&slot, &intent.digest()?)? else {
        return Err("creator recovery cannot replace a retained CID".into());
    };
    no_client(journal, intent)?;
    let (ready, receipt, boot) = ready(&slot, intent, started)?;
    if boot != crate::builder_cgroup::boot_id()? {
        return Err("creator recovery boot differs".into());
    }
    if rustix::fs::fstat(&slot).map_err(|e| e.to_string())?.st_dev
        != rustix::fs::fstat(&journal.root)
            .map_err(|e| e.to_string())?
            .st_dev
    {
        return Err("atomic creator recovery publication unavailable".into());
    }
    let context = Context {
        intent,
        started,
        generation,
        ready,
        group: receipt,
        prior,
    };
    let previous = witnesses(&slot, &context)?;
    if !previous.is_empty() && group.is_some() {
        return Err("creator cgroup reappeared after a recovery witness".into());
    }
    crate::builder_policy::read_policy(job, intent.pins.text("policy_sha256"))
        .map_err(|e| e.to_string())?;
    still_owned()?;
    *phase = "creator-kill";
    if let Some(mut held) = group.take() {
        held.kill().map_err(|e| e.to_string())?;
        *phase = "creator-drain";
        held.drain_and_remove().map_err(|e| e.to_string())?;
    }
    crate::dependency_state::client_group_absent(job)?;
    still_owned()?;
    *phase = "runtime-info";
    crate::builder_candidate_preflight::verify_candidate_runtime_info()
        .map_err(|e| e.to_string())?;
    *phase = "container-reconcile";
    let expected = previous.last().and_then(|w| w.cid.as_deref());
    let container =
        crate::dependency_podman::DependencyContainer::recover_created(intent, expected)?;
    if previous
        .last()
        .is_some_and(|w| w.cid.as_deref() != container.id())
    {
        return Err("container appeared after creator quiescence".into());
    }
    *phase = "container-witness";
    let id = attempt()?;
    let raw = canonicalize(context.witness(&id, container.id()).to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    feature_files::write(&slot, &format!("{PREFIX}{id}.json"), &raw, (0, 0), 0o600)?;
    still_owned()?;
    *phase = "container-drain";
    container.drain()?;
    *phase = "policy-remove";
    let profile = format!("hol-gauntlet-build-{job}");
    if !crate::builder_policy::profile_absent(&profile).map_err(|e| e.to_string())? {
        still_owned()?;
        crate::builder_policy::run_parser(
            "--remove",
            &format!("/var/lib/hol-gauntlet/builds/{job}/Builder.apparmor"),
        )
        .map_err(|e| e.to_string())?;
    }
    *phase = "resource-absence";
    crate::dependency_podman::verify_recovered_absent(intent, container.id())
}

pub(crate) fn body(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    generation: &str,
) -> Result<Option<Value>, String> {
    let p = &intent.pins;
    let job = p.text("job_id");
    let slot =
        crate::builder_candidate_source::open_fixed_build_slot(job).map_err(|e| e.to_string())?;
    let OriginalCid::Incomplete(prior) = original(&slot, &intent.digest()?)? else {
        return Ok(None);
    };
    let started = journal
        .started(
            job,
            p.text("source_sha"),
            &intent.digest()?,
            p.text("runner_binary_sha256"),
        )
        .map_err(|e| e.to_string())?
        .ok_or("creator reservation missing")?;
    if started.controller_public_key_hex.is_some() {
        return Err("keyed creator job differs".into());
    }
    no_client(journal, intent)?;
    let (ready, group, _) = ready(&slot, intent, &started.sha256)?;
    if OwnedCandidateCgroup::reopen_candidate(&slot, job, &intent.digest()?)?.is_some() {
        return Err("creator group is still present".into());
    }
    let context = Context {
        intent,
        started: &started.sha256,
        generation,
        ready,
        group,
        prior,
    };
    let mut attempts = witnesses(&slot, &context)?;
    let witness = attempts.pop().ok_or("creator recovery witness missing")?;
    crate::dependency_podman::verify_recovered_absent(intent, witness.cid.as_deref())?;
    Ok(Some(
        json!({"schema":"hol-gauntlet-native-dependency-repair.v3",
        "job_id":job,"source_sha":p.text("source_sha"),"intent_sha256":intent.digest()?,
        "worker_generation":p.text("runner_binary_sha256"),"repair_generation":generation,
        "started_marker_sha256":started.sha256,"running_marker_sha256":null,"container_id":witness.cid,
        "captured_dependencies_bytes":null,"captured_dependencies_sha256":null,
        "status":"aborted","exit_code":null,"quiescent":true,"artifact_admitted":false,"execution_eligible":false,
        "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0,"model_tokens":0,
        "client_cgroup_receipt_sha256":context.group,"creators_ready_sha256":context.ready,
        "prior_container_receipt_sha256":context.prior,"creator_recovery_attempt_id":witness.id,
        "creator_recovery_receipt_sha256":sha(&witness.raw)}),
    ))
}

/// New v3 completion is renamed only after its staging bytes are durable.
/// Earlier protocols keep their original write semantics and exact readers.
pub(crate) fn commit(
    journal: &RunReservationJournal,
    intent: &DependencyRunIntent,
    raw: &[u8],
) -> Result<(), String> {
    let value: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let name = format!("{}.dependency-repair.json", intent.pins.text("job_id"));
    if value["schema"] != "hol-gauntlet-native-dependency-repair.v3" {
        return crate::terminal::create_durable(&journal.root, &name, raw)
            .map_err(|e| e.to_string());
    }
    let slot = crate::builder_candidate_source::open_fixed_build_slot(intent.pins.text("job_id"))
        .map_err(|e| e.to_string())?;
    let staging = format!("dependency-repair-staging-{}.json", attempt()?);
    feature_files::write(&slot, &staging, raw, (0, 0), 0o600)?;
    renameat_with(
        &slot,
        &staging,
        &journal.root,
        &name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|e| e.to_string())?;
    fsync(&journal.root)
        .and_then(|_| fsync(&slot))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_missing_or_eof_cid_receipts_enter_creator_recovery() {
        let digest = "a".repeat(64);
        assert_eq!(
            classify(None, &digest).unwrap(),
            OriginalCid::Incomplete(None)
        );
        for raw in [b"".as_slice(), b"{", b"{\"container_id\":\""] {
            assert_eq!(
                classify(Some(raw), &digest).unwrap(),
                OriginalCid::Incomplete(Some(sha(raw)))
            );
        }
        let raw = canonicalize(
            json!({"schema":"hol-gauntlet-native-dependency-container.v1",
            "intent_sha256":digest,"container_id":"b".repeat(64)})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            classify(Some(&raw), &digest).unwrap(),
            OriginalCid::Retained("b".repeat(64))
        );
        for end in 0..raw.len() {
            assert_eq!(
                classify(Some(&raw[..end]), &digest).unwrap(),
                OriginalCid::Incomplete(Some(sha(&raw[..end])))
            );
        }
        assert!(classify(Some(&raw), &"c".repeat(64)).is_err());
        for raw in [
            b"garbage".as_slice(),
            b"null",
            b"{}",
            b"{\"schema\":1,\"schema\":2}",
            b"{oops",
            b"[",
            b"n",
            b"{\"schema\":",
        ] {
            assert!(classify(Some(raw), &digest).is_err());
        }
    }
}
