//! Validate actual outside-kernel status for a still-gated native process.
use crate::{hex, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) const FIELDS: &[&str] = &[
    "Uid",
    "Gid",
    "Groups",
    "NSpid",
    "NoNewPrivs",
    "CapEff",
    "CapPrm",
    "CapInh",
    "CapBnd",
    "CapAmb",
    "Seccomp",
    "Seccomp_filters",
    "Cpus_allowed_list",
];

pub(crate) fn status(
    raw: &[u8],
    host_pid: u32,
    local_pid: u32,
    filtered: bool,
    cpu: Option<u32>,
) -> Result<Value> {
    if raw.len() > 65536 {
        return Err("kernel status byte bound".into());
    }
    let text = std::str::from_utf8(raw).map_err(|_| "kernel status UTF-8 required")?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if FIELDS.contains(&key) && values.insert(key, value.trim()).is_some() {
            return Err("duplicate kernel identity field".into());
        }
    }
    for key in FIELDS {
        if !values.contains_key(key) {
            return Err(format!("kernel identity lacks {key}"));
        }
    }
    for key in ["Uid", "Gid"] {
        if values[key].split_ascii_whitespace().collect::<Vec<_>>() != ["10004"; 4] {
            return Err("all four kernel IDs must be product UID/GID10004".into());
        }
    }
    if !values["Groups"].is_empty() || values["NoNewPrivs"] != "1" {
        return Err("empty groups and no new privileges required".into());
    }
    for key in ["CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"] {
        let text = values[key];
        if text.len() != 16 || !hex(text, 16) || u64::from_str_radix(text, 16).ok() != Some(0) {
            return Err("all product capability sets must be empty".into());
        }
    }
    let ids = values["NSpid"]
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "invalid namespace PID")?;
    if !(2..=8).contains(&ids.len())
        || ids[0] != host_pid
        || ids.last() != Some(&local_pid)
        || ids.contains(&0)
    {
        return Err("actual host and namespace PIDs differ from expected owned process".into());
    }
    if filtered
        && (values["Seccomp"] != "2"
            || values["Seccomp_filters"]
                .parse::<u64>()
                .ok()
                .is_none_or(|n| n < 2))
    {
        return Err("both product syscall filters required".into());
    }
    if cpu.is_some_and(|n| values["Cpus_allowed_list"] != n.to_string()) {
        return Err("actual product CPU affinity differs from outside allocation".into());
    }
    Ok(json!(values))
}

pub(crate) fn start_ticks(raw: &[u8], pid: u32) -> Result<u64> {
    let text = std::str::from_utf8(raw).map_err(|_| "invalid proc stat UTF-8")?;
    if raw.len() > 4096 {
        return Err("proc stat byte bound".into());
    }
    let (head, tail) = text.rsplit_once(')').ok_or("invalid proc stat comm")?;
    let (actual, _) = head.split_once(" (").ok_or("invalid proc stat PID")?;
    let fields: Vec<_> = tail.split_ascii_whitespace().collect();
    if actual.parse::<u32>().ok() != Some(pid)
        || fields.len() < 22
        || !matches!(fields[0], "R" | "S" | "D")
    {
        return Err("live exact proc stat PID required".into());
    }
    fields[19]
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| "positive proc start tick required".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> String {
        let mut text="Uid:\t10004 10004 10004 10004\nGid:\t10004 10004 10004 10004\nGroups:\t\nNSpid:\t42 1\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\nCpus_allowed_list:\t0\n".to_owned();
        for key in ["CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"] {
            text += &format!("{key}:\t0000000000000000\n");
        }
        text
    }
    #[test]
    fn saved_ids_caps_groups_and_two_filters_cannot_be_self_reported_away() {
        let raw = fixture();
        assert!(status(raw.as_bytes(), 42, 1, true, Some(0)).is_ok());
        for changed in [
            raw.replace("10004 10004 10004 10004", "10004 0 10004 10004"),
            raw.replace("Groups:\t\n", "Groups:\t10004\n"),
            raw.replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001"),
            raw.replace("NSpid:\t42 1", "NSpid:\t43 1"),
            raw.replace("Seccomp_filters:\t2", "Seccomp_filters:\t1"),
            raw.replace("Cpus_allowed_list:\t0", "Cpus_allowed_list:\t0-1"),
            format!("{raw}Uid:\t10004 10004 10004 10004\n"),
        ] {
            assert!(status(changed.as_bytes(), 42, 1, true, Some(0)).is_err());
        }
        let initial = raw
            .replace("Seccomp:\t2", "Seccomp:\t0")
            .replace("Seccomp_filters:\t2", "Seccomp_filters:\t0");
        assert!(status(initial.as_bytes(), 42, 1, false, Some(0)).is_ok());
        assert!(status(initial.as_bytes(), 42, 1, true, Some(0)).is_err());
    }
    #[test]
    fn start_tick_parser_handles_parentheses_and_refuses_reused_or_dead_pids() {
        let mut fields = vec!["0"; 22];
        fields[0] = "S";
        fields[19] = "1234";
        let raw = format!("42 (comm) with) parens) {}", fields.join(" "));
        assert_eq!(start_ticks(raw.as_bytes(), 42).unwrap(), 1234);
        assert!(start_ticks(raw.as_bytes(), 43).is_err());
        fields[0] = "Z";
        assert!(start_ticks(format!("42 (init) {}", fields.join(" ")).as_bytes(), 42).is_err());
    }
}
