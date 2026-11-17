//! Join every selected stream to its actual exec and subsequent kernel ending.
use crate::native_diagnostic_artifacts::{parse, require, text};
use crate::native_process_kernel::number;
use crate::{EvidenceError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) struct Expected {
    pub(super) selected: Value,
    pub(super) close_reason: &'static str,
    pub(super) close_sequence: usize,
}

fn selected(image: &Value, actor: &Value, declaration: &Value) -> Result<bool> {
    let raw = STANDARD
        .decode(text(image, "argv_base64")?)
        .map_err(|_| EvidenceError::Invalid("Native stdio argv unavailable"))?;
    require(raw.ends_with(&[0]))?;
    let args = raw[..raw.len() - 1].split(|b| *b == 0).collect::<Vec<_>>();
    let fixture = declaration["scope"] == "owned-process-fixture";
    let wanted = if fixture {
        args.get(1).is_some_and(|v| {
            matches!(
                *v,
                b"stdio-scalar-leaf"
                    | b"stdio-vector-leaf"
                    | b"stdio-partial-leaf"
                    | b"stdio-linger-leaf"
                    | b"stdio-rebind-leaf"
                    | b"stdio-oversize-leaf"
            )
        })
    } else {
        args.get(1) == Some(&b"resident-client-stream".as_slice())
    };
    if !wanted {
        return Ok(false);
    }
    require(image["executable"]["sha256"] == declaration["native_runtime_sha256"])?;
    if fixture {
        require(args.len() == 2)?;
    } else {
        require(
            args.len() == 4
                && args[0].starts_with(b"/")
                && args[0].ends_with(b"/hol-guard-runtime")
                && args[2] == b"--stdin"
                && args[3] == b"/product/guard/native-runtime",
        )?;
    }
    let task = &image["task"];
    require(
        task["tid"] == task["tgid"]
            && image["namespaces"] == actor["namespaces"]
            && image["lsm_label"] == actor["lsm_label"],
    )?;
    for key in ["Uid", "Gid"] {
        require(
            text(&task["status"], key)?
                .split_ascii_whitespace()
                .collect::<Vec<_>>()
                == ["10004"; 4],
        )?;
    }
    require(
        text(&task["status"], "Groups")?.trim().is_empty()
            && task["status"]["NoNewPrivs"] == "1"
            && (fixture || task["status"]["Seccomp"] == "2"),
    )?;
    for key in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
        require(task["status"][key] == "0000000000000000")?;
    }
    require(
        image["executable"]["uid"] == 0
            && image["executable"]["gid"] == 0
            && image["executable"]["links"] == 1
            && image["executable"]["mode"]
                .as_u64()
                .is_some_and(|v| v & 0o6022 == 0),
    )?;
    Ok(true)
}

pub(super) fn events(raw: &[u8]) -> Result<Vec<Value>> {
    require(raw.ends_with(b"\n"))?;
    raw[..raw.len() - 1]
        .split(|b| *b == b'\n')
        .map(parse)
        .collect()
}

pub(super) fn expected(events: &[Value], declaration: &Value) -> Result<BTreeMap<u64, Expected>> {
    let actor = &events[0]["data"]["actor"];
    let mut output = BTreeMap::new();
    for (sequence, row) in events.iter().enumerate() {
        if row["kind"] != "task-exec" {
            continue;
        }
        let data = &row["data"];
        let image = &data["image"];
        if !selected(image, actor, declaration)? {
            continue;
        }
        let id = &data["id"];
        let ending = events
            .iter()
            .enumerate()
            .skip(sequence + 1)
            .find_map(|(n, row)| {
                if row["kind"] == "task-final-wait" && row["data"]["id"] == *id {
                    Some((n, "final-wait"))
                } else if row["kind"] == "task-exec"
                    && (row["data"]["id"] == *id
                        || row["data"]["retired"]
                            .as_array()
                            .is_some_and(|v| v.iter().any(|r| r["id"] == *id)))
                {
                    Some((n, "exec-replacement"))
                } else {
                    None
                }
            })
            .ok_or(EvidenceError::Invalid(
                "Native stdio task has no kernel ending",
            ))?;
        require(output.len() < 1024)?;
        output.insert(sequence as u64,Expected{
            selected:json!({"task_id":id,"tid":image["task"]["tid"],"tgid":image["task"]["tgid"],
                "start_ticks":image["task"]["start_ticks"],"process_exec_sequence":sequence,
                "argv_sha256":image["argv_sha256"],"executable_sha256":image["executable"]["sha256"]}),
            close_reason:ending.1,close_sequence:ending.0});
    }
    Ok(output)
}

pub(super) fn start(data: &Value, actor: &Value, declaration: &Value) -> Result<()> {
    require(
        crate::payload::exact_keys(
            data,
            &[
                "declaration",
                "actor_argv_sha256",
                "actor_executable_sha256",
                "actor_tid",
                "actor_start_ticks",
                "cgroup",
            ],
        ) && data["declaration"] == *declaration
            && data["actor_argv_sha256"] == actor["argv_sha256"]
            && data["actor_executable_sha256"] == actor["executable"]["sha256"]
            && data["actor_tid"] == actor["task"]["tid"]
            && data["actor_start_ticks"] == actor["task"]["start_ticks"]
            && data["cgroup"] == actor["task"]["cgroup"],
    )?;
    number(&data["actor_tid"])?;
    Ok(())
}
