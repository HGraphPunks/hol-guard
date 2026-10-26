//! Strict versioned checkpoint; never an execution or evidence authority.

use crate::HostLifecycleError as Error;
use gauntlet_contracts::{canonicalize, is_git_sha};
use serde_json::{json, Value};
use std::collections::HashSet;

pub(crate) const SCHEMA: &str = "hol-gauntlet-rust-host-state.v1";
pub(crate) const TAGS: [&str; 2] = ["v3.48.0", "v3.49.0"];
pub(crate) const RESTART_REASON: &str =
    "Agent restarted during work; reconcile the same VM job before continuing";

pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn repository(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    value.len() <= 200
        && !owner.is_empty()
        && !name.is_empty()
        && !name.contains('/')
        && owner
            .bytes()
            .chain(name.bytes())
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}

fn timestamp(value: &Value) -> Option<u64> {
    value.as_u64().filter(|n| *n > 0)
}

pub(crate) fn valid_job(job: &Value, checkpoint_time: u64) -> bool {
    exact_keys(
        job,
        &[
            "id",
            "kind",
            "tag",
            "sha",
            "state",
            "created_at_ms",
            "updated_at_ms",
            "reason",
            "deployment_digest",
        ],
    ) && job["id"].as_str().is_some_and(|id| hex(id, 16))
        && job["kind"] == "release"
        && job["tag"].as_str().is_some_and(|tag| TAGS.contains(&tag))
        && job["sha"].as_str().is_some_and(is_git_sha)
        && job["state"].as_str().is_some_and(|state| {
            matches!(
                state,
                "queued"
                    | "waiting"
                    | "waiting-candidate"
                    | "preparing"
                    | "running"
                    | "unknown"
                    | "passed"
                    | "diagnostic-passed"
                    | "failed"
                    | "build-failed"
                    | "conformance-failed"
                    | "invalid-evidence"
                    | "superseded"
                    | "archived"
            )
        })
        && job["reason"]
            .as_str()
            .is_some_and(|s| s.len() <= 1000 && !s.chars().any(char::is_control))
        && (job["deployment_digest"].is_null()
            || job["deployment_digest"]
                .as_str()
                .is_some_and(|s| hex(s, 64)))
        && timestamp(&job["created_at_ms"]).is_some_and(|created| {
            timestamp(&job["updated_at_ms"])
                .is_some_and(|updated| created <= updated && updated <= checkpoint_time)
        })
}

pub(crate) fn validate(value: &Value) -> Result<(), Error> {
    if !exact_keys(
        value,
        &[
            "schema",
            "instance_id",
            "repository",
            "generation",
            "updated_at_ms",
            "held",
            "stop_requested",
            "observer",
            "jobs",
        ],
    ) || value["schema"] != SCHEMA
        || !value["instance_id"].as_str().is_some_and(|s| hex(s, 32))
        || !value["repository"].as_str().is_some_and(repository)
        || value["generation"].as_u64().is_none()
        || !value["held"].is_boolean()
        || !value["stop_requested"].is_boolean()
    {
        return Err(Error::InvalidState);
    }
    let now = timestamp(&value["updated_at_ms"]).ok_or(Error::InvalidState)?;
    let observer = &value["observer"];
    if !(observer.is_null()
        || (exact_keys(
            observer,
            &["session", "pid", "started_at_ms", "updated_at_ms"],
        ) && observer["session"].as_str().is_some_and(|s| hex(s, 32))
            && observer["pid"]
                .as_u64()
                .is_some_and(|pid| pid > 0 && pid <= i32::MAX as u64)
            && timestamp(&observer["started_at_ms"]).is_some_and(|start| {
                timestamp(&observer["updated_at_ms"])
                    .is_some_and(|updated| start <= updated && updated <= now)
            })))
    {
        return Err(Error::InvalidState);
    }
    let jobs = value["jobs"].as_array().ok_or(Error::InvalidState)?;
    if jobs.len() > 4096 {
        return Err(Error::TooLarge);
    }
    let mut ids = HashSet::new();
    let mut tags = HashSet::new();
    for job in jobs {
        if !valid_job(job, now)
            || !ids.insert(job["id"].as_str().ok_or(Error::InvalidState)?)
            || !tags.insert(job["tag"].as_str().ok_or(Error::InvalidState)?)
        {
            return Err(Error::InvalidState);
        }
    }
    Ok(())
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > super::lifecycle_files::MAX_BYTES {
        return Err(Error::TooLarge);
    }
    if canonicalize(bytes).map_err(|_| Error::InvalidState)? != bytes {
        return Err(Error::InvalidState);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| Error::InvalidState)?;
    validate(&value)?;
    Ok(value)
}

pub(crate) fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    validate(value)?;
    let bytes = canonicalize(value.to_string().as_bytes()).map_err(|_| Error::InvalidState)?;
    if bytes.len() > super::lifecycle_files::MAX_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

pub(crate) fn initial(repository: &str, instance: &str, now: u64) -> Value {
    json!({"schema":SCHEMA, "instance_id":instance, "repository":repository,
        "generation":0, "updated_at_ms":now, "held":true, "stop_requested":false,
        "observer":null, "jobs":[]})
}

pub(crate) fn recover(value: &mut Value, now: u64) {
    for job in value["jobs"].as_array_mut().expect("validated jobs") {
        if matches!(job["state"].as_str(), Some("preparing" | "running")) {
            job["state"] = json!("unknown");
            job["reason"] = json!(RESTART_REASON);
            job["updated_at_ms"] = json!(now);
        }
    }
}
