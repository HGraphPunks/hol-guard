//! Bind the separate process history to the signed v3 cell lifecycle and every
//! measured gate. This does not admit an observer or grade every Native image.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{argv, parse, require, text, Artifacts};
use crate::native_process_kernel::{decimal, number};
use crate::payload::exact_keys;
use crate::{verify_native_process_events, EvidenceError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const FILE: &str = "combined/cell/native-process-events.v1.jsonl";

fn unique<'a>(events: &'a [Value], kind: &str) -> Result<(usize, &'a Value)> {
    let rows = events
        .iter()
        .enumerate()
        .filter(|(_, r)| r["kind"] == kind)
        .collect::<Vec<_>>();
    require(rows.len() == 1)?;
    Ok((rows[0].0, &rows[0].1["data"]))
}

fn matches_image(image: &Value, identity: &Value, tracer: u64) -> Result<()> {
    require(
        image["task"]["tid"] == identity["pid"]
            && image["task"]["tgid"] == identity["pid"]
            && image["task"]["start_ticks"] == identity["start_ticks"]
            && image["task"]["cgroup"] == identity["cgroup"]
            && image["executable"]["sha256"] == identity["executable_sha256"]
            && image["namespaces"] == identity["namespaces"]
            && image["lsm_label"] == identity["lsm_label"]
            && decimal(text(&image["task"]["status"], "TracerPid")?)? == tracer,
    )?;
    let command = argv(&identity["argv"])?;
    let raw = format!("{}\0", command.join("\0"));
    require(
        image["argv_sha256"] == sha256(raw.as_bytes())
            && image["argv_base64"] == STANDARD.encode(raw.as_bytes()),
    )?;
    let status = identity["status"]
        .as_object()
        .filter(|v| !v.is_empty())
        .ok_or(EvidenceError::Invalid(
            "held cell status missing for process trace join",
        ))?;
    for (key, value) in status {
        require(image["task"]["status"].get(key) == Some(value))?;
    }
    Ok(())
}

pub(crate) fn verify(
    preparation: &Value,
    plane: &Value,
    artifacts: &Artifacts<'_>,
    journal_bound: bool,
) -> Result<Option<Value>> {
    let stdio = preparation["launch"]["schema"] == "hol-gauntlet-cell-supervisor.v4";
    let traced = stdio || preparation["launch"]["schema"] == "hol-gauntlet-cell-supervisor.v3";
    if !stdio {
        require(!artifacts.contains("combined/cell/native-stdio-events.v1.jsonl"))?;
    }
    if !traced {
        require(
            plane.get("process_events").is_none()
                && !artifacts.contains(FILE)
                && !artifacts.events.iter().any(|r| {
                    matches!(
                        r["kind"].as_str(),
                        Some("process-events-started" | "process-events-closed")
                    )
                }),
        )?;
        return Ok(None);
    }
    require(
        journal_bound
            && preparation["launch"]["process_events"]
                == (if stdio {
                    "outside-root-ptrace.v2"
                } else {
                    "outside-root-ptrace.v1"
                })
            && plane["schema"]
                == (if stdio {
                    "hol-gauntlet-native-hook-plane.v3"
                } else {
                    "hol-gauntlet-native-hook-plane.v2"
                })
            && plane["cleanup_complete"] == true,
    )?;
    let observation = &plane["process_events"];
    require(
        exact_keys(observation, &["schema", "available", "checkpoint"])
            && observation["schema"]
                == (if stdio {
                    "hol-gauntlet-native-process-recorder.v2"
                } else {
                    "hol-gauntlet-native-process-recorder.v1"
                })
            && observation["available"] == true,
    )?;
    let checkpoint = &observation["checkpoint"];
    require(
        checkpoint["schema"]
            == (if stdio {
                "hol-gauntlet-native-process-events.v2"
            } else {
                "hol-gauntlet-native-process-events.v1"
            }),
    )?;
    if stdio {
        require(
            preparation["launch"]["native_stdio"] == "outside-root-native-stdio.v1"
                && checkpoint["native_stdio"]["declaration"]["scope"]
                    == "owned-product-native-stream"
                && checkpoint["native_stdio"]["declaration"]["native_runtime_sha256"]
                    == preparation["launch"]["native_runtime_sha256"],
        )?;
    }
    let raw = artifacts.raw(FILE)?;
    let readback = verify_native_process_events(raw, checkpoint)?;
    let metadata = artifacts.metadata(FILE)?;
    for field in ["device", "inode", "uid", "gid", "mode", "links"] {
        require(metadata.get(field).is_some() && checkpoint["journal"][field] == metadata[field])?;
    }
    let events = raw[..raw.len() - 1]
        .split(|b| *b == b'\n')
        .map(parse)
        .collect::<Result<Vec<_>>>()?;
    let (filtered, actor) = unique(&artifacts.events, "filtered-cell")?;
    let (started, start) = unique(&artifacts.events, "process-events-started")?;
    let (ready, _) = unique(&artifacts.events, "actor-ready")?;
    let (closed, close) = unique(&artifacts.events, "process-events-closed")?;
    require(
        filtered < started
            && started < ready
            && ready < closed
            && exact_keys(
                start,
                &[
                    "schema",
                    "mode",
                    "tracer_tid",
                    "actor",
                    "execution_eligible",
                ],
            )
            && start["schema"]
                == (if stdio {
                    "hol-gauntlet-native-process-recorder-started.v2"
                } else {
                    "hol-gauntlet-native-process-recorder-started.v1"
                })
            && start["mode"]
                == (if stdio {
                    "outside-root-ptrace.v2"
                } else {
                    "outside-root-ptrace.v1"
                })
            && start["execution_eligible"] == false
            && start["actor"] == *actor
            && close == observation
            && actor["argv"] == json!(["/public/gauntlet-product-cell", "actor"]),
    )?;
    let tracer = number(&start["tracer_tid"])?;
    let image = &events[0]["data"]["actor"];
    matches_image(image, actor, tracer)?;
    require(events[0]["data"]["cgroup"] == actor["cgroup"])?;
    let mut handles = BTreeSet::new();
    for (sequence, row) in artifacts.events.iter().enumerate() {
        if row["kind"] != "gated-product-process" {
            continue;
        }
        require(
            ready < sequence && sequence < closed && handles.insert(text(&row["data"], "handle")?),
        )?;
        let identity = &row["data"]["identity"];
        let command = argv(&identity["argv"])?;
        require(
            command.len() > 2
                && command[..2] == ["/public/gauntlet-product-cell", "exec-gate"]
                && identity["executable_sha256"] == actor["executable_sha256"]
                && identity["cgroup"] == actor["cgroup"]
                && identity["namespaces"] == actor["namespaces"]
                && identity["lsm_label"] == actor["lsm_label"],
        )?;
        let pin = sha256(format!("{}\0", command.join("\0")).as_bytes());
        let matches = events
            .iter()
            .filter(|r| {
                r["kind"] == "task-exec"
                    && r["data"]["image"]["task"]["tid"] == identity["pid"]
                    && r["data"]["image"]["task"]["start_ticks"] == identity["start_ticks"]
                    && r["data"]["image"]["argv_sha256"] == pin
            })
            .collect::<Vec<_>>();
        require(matches.len() == 1)?;
        matches_image(&matches[0]["data"]["image"], identity, tracer)?;
    }
    Ok(Some(
        json!({"schema":"hol-gauntlet-native-process-trace-relations.v1","root_process_journal_bound":true,
        "actor_before_first_spawn_verified":true,"gated_process_exec_joins":handles.len(),"task_history":readback,
        "all_native_descendants_verified":false,"outside_observer_admitted":false,"outside_signing_key_admitted":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    ))
}

#[cfg(test)]
#[path = "native_process_trace_diagnostic_tests.rs"]
mod tests;
