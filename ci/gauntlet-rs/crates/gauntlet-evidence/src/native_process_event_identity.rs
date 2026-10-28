//! Validate bounded kernel observations without admitting images or privileges.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{require, text};
use crate::native_process_kernel::{decimal, hex, number, NAMESPACES};
use crate::payload::exact_keys;
use crate::{EvidenceError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

#[derive(Clone, Copy)]
pub(super) struct Task {
    pub tid: u64,
    pub tgid: u64,
    pub start: u64,
}

pub(super) fn pid(value: &Value) -> Result<u64> {
    let value = number(value)?;
    require(value <= i32::MAX as u64)?;
    Ok(value)
}

fn integers(value: &str, maximum: usize) -> Result<Vec<u64>> {
    require(value.len() <= 4096)?;
    let values = value
        .split_ascii_whitespace()
        .map(decimal)
        .collect::<Result<Vec<_>>>()?;
    require(values.len() <= maximum && values.iter().all(|v| *v <= u32::MAX as u64))?;
    Ok(values)
}

pub(super) fn task(value: &Value, cgroup: &str, tracer: &mut Option<u64>) -> Result<Task> {
    require(exact_keys(
        value,
        &[
            "tid",
            "tgid",
            "start_ticks",
            "parent_pid",
            "cgroup",
            "status",
        ],
    ))?;
    let result = Task {
        tid: pid(&value["tid"])?,
        tgid: pid(&value["tgid"])?,
        start: number(&value["start_ticks"])?,
    };
    require(
        value["parent_pid"]
            .as_u64()
            .is_some_and(|v| v <= i32::MAX as u64)
            && value["cgroup"] == cgroup,
    )?;
    let status = &value["status"];
    require(exact_keys(
        status,
        &[
            "Uid",
            "Gid",
            "Groups",
            "CapAmb",
            "CapBnd",
            "CapEff",
            "CapInh",
            "CapPrm",
            "NoNewPrivs",
            "Seccomp",
            "Seccomp_filters",
            "NSpid",
            "TracerPid",
            "Threads",
            "Cpus_allowed_list",
        ],
    ))?;
    for name in ["Uid", "Gid"] {
        require(integers(text(status, name)?, 4)?.len() == 4)?;
    }
    integers(text(status, "Groups")?, 128)?;
    for name in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
        require(hex(text(status, name)?, 16))?;
    }
    require(
        matches!(text(status, "NoNewPrivs")?, "0" | "1")
            && matches!(text(status, "Seccomp")?, "0" | "1" | "2"),
    )?;
    require(decimal(text(status, "Seccomp_filters")?)? <= 128)?;
    let ids = integers(text(status, "NSpid")?, 8)?;
    require(!ids.is_empty() && ids[0] == result.tid && ids.iter().all(|v| *v > 0))?;
    let actual = decimal(text(status, "TracerPid")?)?;
    require(actual > 0 && actual <= i32::MAX as u64 && tracer.is_none_or(|v| v == actual))?;
    *tracer = Some(actual);
    require((1..=128).contains(&decimal(text(status, "Threads")?)?))?;
    let cpus = text(status, "Cpus_allowed_list")?;
    require(
        !cpus.is_empty()
            && cpus.len() <= 4096
            && cpus
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b',' | b'-')),
    )?;
    Ok(result)
}

pub(super) fn image(value: &Value, cgroup: &str, tracer: &mut Option<u64>) -> Result<Task> {
    require(exact_keys(
        value,
        &[
            "task",
            "argv_base64",
            "argv_sha256",
            "executable",
            "lsm_label",
            "namespaces",
        ],
    ))?;
    let result = task(&value["task"], cgroup, tracer)?;
    let encoded = text(value, "argv_base64")?;
    require(encoded.len() <= 87384)?;
    let argv = STANDARD
        .decode(encoded)
        .map_err(|_| EvidenceError::Invalid("invalid traced argv base64"))?;
    require(
        !argv.is_empty()
            && argv.len() <= 65536
            && argv.ends_with(b"\0")
            && STANDARD.encode(&argv) == encoded
            && value["argv_sha256"] == sha256(&argv),
    )?;
    let exe = &value["executable"];
    require(exact_keys(
        exe,
        &[
            "device", "inode", "uid", "gid", "mode", "links", "bytes", "sha256",
        ],
    ))?;
    number(&exe["inode"])?;
    require(
        exe["device"].as_u64().is_some()
            && exe["links"].as_u64().is_some()
            && exe["uid"].as_u64().is_some_and(|v| v <= u32::MAX as u64)
            && exe["gid"].as_u64().is_some_and(|v| v <= u32::MAX as u64)
            && exe["mode"].as_u64().is_some_and(|v| v <= 0o7777)
            && exe["bytes"]
                .as_u64()
                .is_some_and(|v| (1..=128 * 1024 * 1024).contains(&v))
            && hex(text(exe, "sha256")?, 64),
    )?;
    let label = text(value, "lsm_label")?;
    require(!label.is_empty() && label.len() <= 4096 && !label.contains(['\0', '\n', '\r']))?;
    let namespaces = &value["namespaces"];
    require(exact_keys(namespaces, &NAMESPACES))?;
    for name in NAMESPACES {
        let identity = text(namespaces, name)?;
        require(identity.len() <= 41)?;
        let (device, inode) = identity
            .split_once(':')
            .ok_or(EvidenceError::Invalid("traced namespace identity missing"))?;
        decimal(device)?;
        require(decimal(inode)? > 0)?;
    }
    Ok(result)
}

pub(super) fn final_status(value: &Value) -> Result<()> {
    match text(value, "kind")? {
        "exit" => require(
            exact_keys(value, &["kind", "code"])
                && value["code"].as_u64().is_some_and(|v| v <= 255),
        ),
        "signal" => require(
            exact_keys(value, &["kind", "signal", "core_dumped"])
                && value["signal"]
                    .as_u64()
                    .is_some_and(|v| (1..=64).contains(&v))
                && value["core_dumped"].is_boolean(),
        ),
        _ => Err(EvidenceError::Invalid("final traced wait status required")),
    }
}
