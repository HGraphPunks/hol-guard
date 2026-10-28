//! Public compatibility projection for the Rust observer. Only operational
//! fields cross this boundary; configuration and private job pins stay private.

use crate::lifecycle_document::TAGS;
use crate::{resource_admission_reasons, HostLifecycleError as Error, ObserverConfiguration};
use gauntlet_contracts::is_git_sha;
use serde_json::{json, Map, Value};

fn number(value: &Value, key: &str) -> Option<f64> {
    value[key].as_f64().filter(|v| v.is_finite() && *v >= 0.0)
}

fn unavailable(name: &str, checked: f64) -> Value {
    json!({"status":"unavailable","checked_at":checked,"error":format!("{name} telemetry is absent, stale or invalid")})
}

fn resource(value: &Value, now: f64, vm: bool, name: &str) -> Value {
    let checked = number(value, "checked_at").unwrap_or(0.0);
    let valid = value["status"] == (if vm { "running" } else { "online" })
        && checked > 0.0
        && checked <= now + 5.0
        && now - checked <= 90.0
        && value["cpus"]
            .as_u64()
            .is_some_and(|n| (1..=512).contains(&n))
        && number(value, "load").is_some()
        && number(value, "disk_total").is_some_and(|total| {
            total > 0.0 && number(value, "disk_free").is_some_and(|free| free <= total)
        })
        && (!vm
            || (value["name"] == name
                && number(value, "memory_total").is_some_and(|total| {
                    total > 0.0
                        && number(value, "memory_available").is_some_and(|free| free <= total)
                })));
    if !valid {
        return unavailable(if vm { "VM" } else { "Host" }, 0.0);
    }
    let mut public = Map::new();
    for key in [
        "status",
        "checked_at",
        "cpus",
        "load",
        "disk_total",
        "disk_free",
    ] {
        public.insert(key.to_owned(), value[key].clone());
    }
    if vm {
        public.insert("name".to_owned(), json!(name));
    } else if matches!(value["platform"].as_str(), Some("Linux" | "Darwin")) {
        public.insert("platform".to_owned(), value["platform"].clone());
    }
    for key in ["memory_total", "memory_available"] {
        public.insert(
            key.to_owned(),
            if number(value, key).is_some() {
                value[key].clone()
            } else {
                Value::Null
            },
        );
    }
    Value::Object(public)
}

pub fn compose_observer_snapshot(
    config: &ObserverConfiguration,
    lifecycle: &Value,
    observations: &Value,
    now_ms: u64,
) -> Result<Value, Error> {
    if lifecycle["schema"] != "hol-gauntlet-rust-host-status.v1"
        || lifecycle["instance_id"] != config.instance_id
        || lifecycle["repository"] != config.operations["repository"]
        || now_ms == 0
    {
        return Err(Error::InvalidState);
    }
    let now = now_ms as f64 / 1000.0;
    let vm_name = config.operations["vm"]
        .as_str()
        .ok_or(Error::InvalidObserverConfig)?;
    let host = resource(&observations["host"], now, false, "");
    let vm = resource(&observations["vm"], now, true, vm_name);
    let mut snapshot = json!({"host":host,"vm":vm,
        "deployment":{"status":"unavailable","error":"Rust worker readiness has not been established"}});
    let mut reasons: Vec<String> = resource_admission_reasons(&snapshot, &config.operations, now)
        .map_err(|_| Error::InvalidState)?
        .into_iter()
        .map(str::to_owned)
        .collect();
    reasons.push("Rust worker has not been qualified".into());
    if lifecycle["admissions_held"] == true {
        reasons.push("Operator holds admissions".into());
    }
    if lifecycle["unresolved_jobs"].as_u64().unwrap_or(0) > 0 {
        reasons.push("Unresolved jobs require exact receipt reconciliation".into());
    }
    let source_time = observations["source_checked_at"]
        .as_f64()
        .filter(|v| v.is_finite() && *v > 0.0);
    let source_current = source_time.is_some_and(|at| at <= now + 5.0 && now - at <= 150.0);
    let releases = observations["releases"].as_array();
    let jobs = lifecycle["jobs"].as_array().ok_or(Error::InvalidState)?;
    let mut source_errors = Vec::new();
    let mut expected_sources = std::collections::BTreeMap::new();
    for tag in TAGS {
        let rows: Vec<_> = releases
            .into_iter()
            .flatten()
            .filter(|row| row["tag"] == tag)
            .collect();
        let row = (rows.len() == 1).then(|| rows[0]);
        let sha = row
            .and_then(|row| row["sha"].as_str())
            .filter(|sha| is_git_sha(sha));
        let known = jobs.iter().find(|job| job["tag"] == tag);
        let row_current = row
            .and_then(|row| number(row, "checked_at"))
            .is_some_and(|at| at > 0.0 && at <= now + 5.0 && now - at <= 150.0);
        let error = if !source_current || !row_current {
            Some("Release source observation is absent or stale")
        } else if sha.is_none() {
            Some("Exact release source lookup failed")
        } else if known.is_some_and(|job| job["sha"] != sha.unwrap_or("")) {
            Some("Release tag differs from its retained source pin")
        } else {
            None
        };
        if let Some(error) = error {
            source_errors.push(json!({"tag":tag,"error":error}));
        }
        expected_sources.insert(tag, error);
    }
    if !source_errors.is_empty() {
        reasons.push("Exact release source requires attention".into());
    }
    let mut public_jobs = Vec::new();
    for job in jobs {
        let mut row = Map::new();
        for key in ["id", "kind", "tag", "sha", "state", "reason"] {
            row.insert(key.to_owned(), job[key].clone());
        }
        for (source, target) in [
            ("created_at_ms", "created_at"),
            ("updated_at_ms", "updated_at"),
        ] {
            row.insert(
                target.to_owned(),
                json!(job[source].as_u64().ok_or(Error::InvalidState)? as f64 / 1000.0),
            );
        }
        let tag = job["tag"].as_str().ok_or(Error::InvalidState)?;
        row.insert("title".into(), json!(format!("{tag} release benchmark")));
        row.insert(
            "url".into(),
            json!(format!(
                "https://github.com/{}/releases/tag/{tag}",
                config.operations["repository"]
                    .as_str()
                    .ok_or(Error::InvalidState)?
            )),
        );
        if let Some(Some(error)) = expected_sources.get(tag) {
            row.insert("source_error".into(), json!(error));
        }
        row.insert(
            "phase".into(),
            json!(if job["state"] == "unknown" {
                "reconciliation-required"
            } else {
                "waiting-for-worker"
            }),
        );
        public_jobs.push(Value::Object(row));
    }
    let online = lifecycle["observer"]["status"] == "online";
    snapshot["schema"] = json!("hol-gauntlet-dashboard.v1");
    snapshot["instance_id"] = json!(config.instance_id);
    snapshot["updated_at"] = json!(now);
    snapshot["repository"] = config.operations["repository"].clone();
    snapshot["observer"] = json!({"schema":if online {"hol-gauntlet-observer.v2"} else {"hol-gauntlet-observer.stopped"},
        "implementation":"rust","mode":"passive","configuration_sha256":config.sha256,
        "lease_held":lifecycle["observer"]["lease_held"]});
    snapshot["github"] = json!({"status":if source_errors.is_empty() {"connected"} else if source_current {"attention"} else {"disconnected"},
        "connection_scope":"release-source-only","checked_at":source_time,"release_errors":source_errors});
    snapshot["jobs"] = json!(public_jobs);
    snapshot["archived_jobs"] = json!(0);
    snapshot["discovery_mode"] = json!("release-tags");
    snapshot["release_tags"] = json!(TAGS);
    snapshot["release_build_backend"] = json!("local-vm");
    snapshot["admissions_held"] = lifecycle["admissions_held"].clone();
    snapshot["admission_reasons"] = json!(reasons);
    snapshot["artifact_build"] = json!({"status":"local","name":"Disposable ARM64 VM builder"});
    snapshot["ci_runs"] = json!([]);
    snapshot["gate"] = json!({"required":null,"status":"unavailable"});
    snapshot["context"] = json!("hol-gauntlet/deterministic");
    snapshot["profile"] = json!("deterministic");
    snapshot["execution_eligible"] = json!(false);
    snapshot["qualification_eligible"] = json!(false);
    snapshot["production_ci_activated"] = json!(false);
    snapshot["trust_status"] = json!("local-integrity-only");
    let mut allocation = Map::new();
    for key in [
        "vm_cpus",
        "vm_memory_gib",
        "vm_disk_gib",
        "build_memory_gib",
        "host_disk_floor_gib",
        "vm_disk_floor_gib",
    ] {
        allocation.insert(key.to_owned(), config.operations[key].clone());
    }
    snapshot["allocation"] = Value::Object(allocation);
    Ok(snapshot)
}
