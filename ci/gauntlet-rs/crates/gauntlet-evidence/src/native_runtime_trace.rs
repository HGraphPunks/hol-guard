//! Complete event-derived Native image lineage, separate from request semantics.
//! Fork inheritance records the last observed image; it does not attest memory,
//! internal wire bytes, effect writers or an admitted outside observer.
use crate::native_diagnostic_artifacts::{parse, require, text, Artifacts};
use crate::native_process_kernel::{decimal, hex, number};
use crate::{EvidenceError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const FILE: &str = "combined/cell/native-process-events.v1.jsonl";
type GateKey = (u64, u64, String);

#[derive(Clone)]
struct TaskImage {
    gate: Option<usize>,
    parent: Option<u64>,
    native: bool,
    checked_client: bool,
    setup: bool,
    descendant: bool,
}

fn identifier(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .filter(|n| *n < 65536)
        .ok_or(EvidenceError::Invalid("bounded traced task ID required"))
}

pub(crate) fn command_bytes(image: &Value) -> Result<Vec<u8>> {
    let raw = STANDARD
        .decode(text(image, "argv_base64")?)
        .map_err(|_| EvidenceError::Invalid("traced Native argv unavailable"))?;
    require(raw.ends_with(&[0]))?;
    Ok(raw)
}

fn command(bytes: &[u8]) -> Result<Vec<String>> {
    let bytes = bytes
        .strip_suffix(&[0])
        .ok_or(EvidenceError::Invalid("traced argv terminator missing"))?;
    bytes
        .split(|b| *b == 0)
        .map(|v| {
            std::str::from_utf8(v)
                .map(str::to_owned)
                .map_err(|_| EvidenceError::Invalid("traced Native argv is not UTF-8"))
        })
        .collect()
}

pub(crate) fn floors(task: &Value) -> Result<()> {
    let status = &task["status"];
    for field in ["Uid", "Gid"] {
        let ids = text(status, field)?
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        require(ids == ["10004"; 4])?;
    }
    require(
        text(status, "Groups")?
            .split_ascii_whitespace()
            .next()
            .is_none(),
    )?;
    for field in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
        require(status[field] == "0000000000000000")?;
    }
    require(
        status["NoNewPrivs"] == "1"
            && status["Seccomp"] == "2"
            && decimal(text(status, "Seccomp_filters")?)? > 0,
    )
}

fn image_profile(image: &Value, actor: &Value, setup: bool) -> Result<Option<&'static str>> {
    let executable = &image["executable"];
    let mode = number(&executable["mode"])?;
    // The measured Native bytes must remain an inert, Root-owned image. A
    // matching digest does not make writable or set-id custody acceptable.
    require(
        executable["uid"] == 0
            && executable["gid"] == 0
            && executable["links"].as_u64().is_some_and(|n| n > 0)
            && mode & 0o6022 == 0
            && mode & 0o111 != 0
            && image["task"]["cgroup"] == actor["task"]["cgroup"]
            && image["lsm_label"] == actor["lsm_label"],
    )?;
    if image["task"].get("isolation").is_some() {
        crate::native_process_event_identity::isolation::matches_image(image)?;
        return crate::native_process_event_identity::isolation::profile(
            &image["task"],
            actor,
            setup,
        );
    }
    if image["namespaces"] != actor["namespaces"] {
        // A namespace identity is not proof of its parent or owning user
        // namespace. The old dialect cannot grade setup capabilities there.
        return Ok(None);
    }
    floors(&image["task"])?;
    require(
        decimal(text(&image["task"]["status"], "Seccomp_filters")?)?
            >= decimal(text(&actor["task"]["status"], "Seccomp_filters")?)?,
    )?;
    Ok(Some("outer"))
}

pub(crate) fn inventory(
    events: &[Value],
    native: &str,
    gates: &BTreeMap<GateKey, usize>,
    clients_only: bool,
) -> Result<Value> {
    require(hex(native, 64) && !events.is_empty() && events.len() <= 65536)?;
    let actor = &events[0]["data"]["actor"];
    let isolated = actor["task"].get("isolation").is_some();
    require(actor["executable"]["sha256"] != native)?;
    let mut tasks = BTreeMap::<u64, TaskImage>::new();
    let mut births = BTreeMap::<u64, TaskImage>::new();
    let mut ever_native = BTreeSet::new();
    let mut joined = BTreeSet::new();
    let mut native_images = Vec::new();
    let mut inherited = 0;
    let mut image_counts = BTreeMap::<String, usize>::new();
    let mut checked_clients = 0;
    let mut outer_images_verified = 0;
    let mut images_verified = 0;
    let mut inheritances_verified = 0;
    let mut other_descendant_execs = 0;
    let mut incomplete_execs = Vec::new();
    let mut incomplete_births = Vec::new();
    for (sequence, row) in events.iter().enumerate() {
        let data = &row["data"];
        match row["kind"].as_str() {
            Some("trace-start") => {
                require(sequence == 0 && identifier(&data["id"])? == 0)?;
                tasks.insert(
                    0,
                    TaskImage {
                        gate: None,
                        parent: None,
                        native: false,
                        checked_client: false,
                        setup: false,
                        descendant: false,
                    },
                );
                *image_counts
                    .entry(text(&actor["executable"], "sha256")?.into())
                    .or_default() += 1;
            }
            Some("kernel-creation") => {
                let parent_id = identifier(&data["parent_id"])?;
                let parent = tasks
                    .get(&parent_id)
                    .ok_or(EvidenceError::Invalid("traced image parent missing"))?;
                // Snapshot at the actual fork/clone event. The parent may exec
                // or exit before the child's first consumed stop arrives.
                let child = TaskImage {
                    gate: parent.gate,
                    parent: Some(parent_id),
                    native: parent.native,
                    checked_client: parent.checked_client,
                    setup: parent.setup,
                    descendant: parent.descendant,
                };
                require(births.insert(number(&data["child_tid"])?, child).is_none())?;
            }
            Some("task-created") => {
                let id = identifier(&data["id"])?;
                let parent_id = identifier(&data["parent_id"])?;
                let child = births
                    .remove(&number(&data["task"]["tid"])?)
                    .ok_or(EvidenceError::Invalid("traced image birth missing"))?;
                require(
                    !tasks.contains_key(&id) && child.parent == Some(parent_id) && parent_id < id,
                )?;
                if child.native {
                    if !isolated && (!clients_only || child.checked_client) {
                        floors(&data["task"])?;
                    }
                    ever_native.insert(id);
                    inherited += 1;
                    let profile = if isolated {
                        crate::native_process_event_identity::isolation::birth_profile(
                            &data["task"],
                            actor,
                            child.setup,
                        )?
                    } else {
                        None
                    };
                    inheritances_verified += usize::from(profile.is_some());
                    if profile.is_none() {
                        incomplete_births.push(json!({"task_id":id,"parent_task_id":parent_id,
                            "trace_sequence":sequence,"reason_code":if isolated && ["uid_map","gid_map"].iter().any(|name|
                                data["task"]["isolation"][*name].as_array().is_some_and(Vec::is_empty)) {
                                "user-namespace-mapping-not-established-at-birth"
                            } else if isolated {"namespace-ancestry-bound-exceeded"}
                            else {"task-created-isolation-observations-missing"}}));
                    }
                }
                tasks.insert(id, child);
            }
            Some("task-exec") => {
                let id = identifier(&data["id"])?;
                let task = tasks
                    .get_mut(&id)
                    .ok_or(EvidenceError::Invalid("traced image task missing"))?;
                let image = &data["image"];
                let pin = text(&image["executable"], "sha256")?;
                *image_counts.entry(pin.into()).or_default() += 1;
                let key = (
                    number(&image["task"]["tid"])?,
                    number(&image["task"]["start_ticks"])?,
                    text(image, "argv_sha256")?.into(),
                );
                if let Some(gate) = gates.get(&key) {
                    require(joined.insert(*gate))?;
                    task.gate = Some(*gate);
                }
                let raw = command_bytes(image)?;
                if raw
                    .split(|b| *b == 0)
                    .next()
                    .is_some_and(|v| v.ends_with(b"/hol-guard-runtime"))
                {
                    require(pin == native)?;
                }
                task.native = pin == native;
                task.checked_client = false;
                task.setup = false;
                if task.native {
                    let args = command(&raw)?;
                    let gate = task
                        .gate
                        .ok_or(EvidenceError::Invalid("Native image has no gated ancestor"))?;
                    require(args.len() >= 2 && !args[0].is_empty() && !args[1].is_empty())?;
                    task.checked_client = args[1] == "resident-client-stream";
                    task.setup = args[1] == "restricted-linux-launch";
                    task.descendant = true;
                    if task.setup {
                        require(args.len() == 3 && hex(&args[2], 64))?;
                    }
                    let profile = image_profile(image, actor, task.setup)?;
                    let outer_verified = profile == Some("outer");
                    images_verified += usize::from(profile.is_some());
                    outer_images_verified += usize::from(outer_verified);
                    if profile.is_none() {
                        incomplete_execs.push(json!({"task_id":id,"trace_sequence":sequence,
                            "reason_code":if isolated {"namespace-ancestry-bound-exceeded"}
                            else {"namespace-ownership-observations-missing"}}));
                    }
                    if !isolated && (!clients_only || task.checked_client) {
                        floors(&image["task"])?;
                        require(
                            image["namespaces"] == actor["namespaces"]
                                && image["lsm_label"] == actor["lsm_label"],
                        )?;
                    }
                    if task.checked_client && isolated {
                        require(profile == Some("outer"))?;
                    }
                    checked_clients += usize::from(task.checked_client);
                    ever_native.insert(id);
                    // The journal retains exact argv. Do not duplicate large
                    // operands into every readback; the raw digest binds them.
                    let operation = (args[1].len() <= 128
                        && !args[1].chars().any(char::is_control))
                    .then_some(&args[1]);
                    native_images.push(json!({"task_id":id,"parent_task_id":task.parent,"trace_sequence":sequence,
                        "gate_sequence":gate,"pid":image["task"]["tid"],"start_ticks":image["task"]["start_ticks"],
                        "program_sha256":crate::crypto::sha256(args[0].as_bytes()),"operation":operation,
                        "operation_sha256":crate::crypto::sha256(args[1].as_bytes()),"argument_count":args.len(),
                        "argv_sha256":image["argv_sha256"],"executable":image["executable"],
                        "outer_image_isolation_verified":outer_verified,"image_isolation_profile":profile}));
                } else if task.descendant {
                    other_descendant_execs += 1;
                }
            }
            _ => {}
        }
    }
    require(births.is_empty() && joined.len() == gates.len())?;
    let mut result = json!({"schema":"hol-gauntlet-native-runtime-image-lineage.v1",
        "complete_task_history_checked":true,"native_runtime_sha256":native,
        "created_tasks":tasks.len(),"gates_joined":joined.len(),"native_exec_images_checked":native_images.len(),
        "tasks_with_observed_or_inherited_native_image":ever_native.len(),"native_image_inheritances":inherited,
        "native_execs":native_images,"observed_image_sha256_counts":image_counts,
        "outer_native_exec_images_isolation_verified":outer_images_verified,
        "native_exec_images_isolation_verified":images_verified,"native_inherited_tasks_isolation_verified":inheritances_verified,
        "non_native_descendant_execs_requiring_outside_role_pins":other_descendant_execs,
        "native_exec_images_requiring_isolation_observations":incomplete_execs,
        "native_inherited_tasks_requiring_isolation_observations":incomplete_births,
        "all_native_exec_images_isolation_verified":!native_images.is_empty()&&images_verified==native_images.len(),
        "native_image_privilege_floors_checked":!native_images.is_empty()&&images_verified==native_images.len(),"internal_native_request_bytes_checked":false,
        "inherited_memory_contents_authenticated":false,"effect_writer_attribution_checked":false,
        "all_native_runtime_descendants_graded":isolated&&!native_images.is_empty()&&images_verified==native_images.len()&&inheritances_verified==inherited&&other_descendant_execs==0,
        "image_grade_scope":"Native exec and inherited-task isolation at observed stops","outside_observer_admitted":false,
        "outside_signing_key_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    if clients_only {
        result["schema"] = json!("hol-gauntlet-native-runtime-image-lineage.v2");
        result["resident_client_privilege_floors_checked"] = json!(checked_clients > 0);
        result["resident_client_execs_checked"] = json!(checked_clients);
        result["other_native_execs_ungraded"] = json!(incomplete_execs.len());
        result["other_native_execs_isolation_verified"] = json!(images_verified - checked_clients);
    }
    if isolated {
        result["schema"] = json!("hol-gauntlet-native-runtime-image-lineage.v3");
        result["task_isolation_schema"] =
            json!(crate::native_process_event_identity::isolation::SCHEMA);
    }
    Ok(result)
}

pub(crate) fn verify(
    control: &Value,
    preparation: &Value,
    artifacts: &Artifacts<'_>,
) -> Result<Option<Value>> {
    if !matches!(
        preparation["launch"]["schema"].as_str(),
        Some(
            "hol-gauntlet-cell-supervisor.v3"
                | "hol-gauntlet-cell-supervisor.v4"
                | "hol-gauntlet-cell-supervisor.v5"
        )
    ) {
        return Ok(None);
    }
    let bound = crate::native_capture_input::journal_binding(&control["plane"], artifacts)?;
    require(
        crate::native_process_trace_diagnostic::verify(
            preparation,
            &control["plane"],
            artifacts,
            bound,
        )?
        .is_some(),
    )?;
    let raw = artifacts.raw(FILE)?;
    let events = raw[..raw.len() - 1]
        .split(|b| *b == b'\n')
        .map(parse)
        .collect::<Result<Vec<_>>>()?;
    let mut gates = BTreeMap::new();
    for (sequence, row) in artifacts.events.iter().enumerate() {
        if row["kind"] != "gated-product-process" {
            continue;
        }
        let identity = &row["data"]["identity"];
        let argv = crate::native_diagnostic_artifacts::argv(&identity["argv"])?;
        let pin = crate::crypto::sha256(format!("{}\0", argv.join("\0")).as_bytes());
        require(
            gates
                .insert(
                    (
                        number(&identity["pid"])?,
                        number(&identity["start_ticks"])?,
                        pin,
                    ),
                    sequence,
                )
                .is_none(),
        )?;
    }
    let pins = if control["schema"] == "hol-gauntlet-native-hook-transport.v2" {
        require(
            preparation["control_profile"] == "python-readonly.v1"
                && control.get("guard_pins").is_none()
                && control.get("control_role").is_none(),
        )?;
        &control["pins"]
    } else {
        &control["guard_pins"]
    };
    inventory(
        &events,
        text(pins, "native_sha256")?,
        &gates,
        control["schema"] == "hol-gauntlet-native-hook-transport.v2",
    )
    .map(Some)
}

#[cfg(test)]
#[path = "native_runtime_trace_tests.rs"]
mod tests;
