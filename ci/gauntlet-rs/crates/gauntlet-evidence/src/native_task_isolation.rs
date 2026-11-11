//! Bounded nsfs ownership snapshots and the fixed Native isolation profiles.
//! Namespace ancestry is kernel evidence; a parent lookup refusal alone never
//! establishes the initial user namespace or authorizes setup capabilities.
use crate::native_diagnostic_artifacts::{require, text};
use crate::native_process_kernel::{decimal, number, NAMESPACES};
use crate::payload::exact_keys;
use crate::{EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(crate) const SCHEMA: &str = "hol-gauntlet-native-task-isolation.v1";
type Namespace = (u64, u64);

fn identity(value: &Value) -> Result<Namespace> {
    require(exact_keys(value, &["device", "inode"]))?;
    Ok((number(&value["device"])?, number(&value["inode"])?))
}

fn namespace(value: &Value) -> Result<Namespace> {
    Ok((number(&value["device"])?, number(&value["inode"])?))
}

fn maps(value: &Value) -> Result<()> {
    let rows = value
        .as_array()
        .filter(|v| v.len() <= 340)
        .ok_or(EvidenceError::Invalid("bounded kernel ID map required"))?;
    let mut inside = Vec::new();
    let mut outside = Vec::new();
    for row in rows {
        let row = row
            .as_array()
            .filter(|v| v.len() == 3)
            .ok_or(EvidenceError::Invalid("kernel ID map triple required"))?;
        let start = |index: usize| {
            row[index]
                .as_u64()
                .filter(|n| *n < u32::MAX as u64)
                .ok_or(EvidenceError::Invalid(
                    "bounded kernel ID map offset required",
                ))
        };
        let a = start(0)?;
        let b = start(1)?;
        let length = number(&row[2])?;
        require(
            length <= u32::MAX as u64
                && a + length <= u32::MAX as u64
                && b + length <= u32::MAX as u64,
        )?;
        inside.push((a, a + length));
        outside.push((b, b + length));
    }
    for ranges in [&mut inside, &mut outside] {
        ranges.sort_unstable();
        require(ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0))?;
    }
    Ok(())
}

pub(crate) fn validate(value: &Value) -> Result<()> {
    require(
        exact_keys(
            value,
            &[
                "schema",
                "namespaces",
                "user_namespace_chain",
                "user_namespace_chain_end_reason",
                "uid_map",
                "gid_map",
                "setgroups",
                "lsm_label",
            ],
        ) && value["schema"] == SCHEMA
            && exact_keys(&value["namespaces"], &NAMESPACES),
    )?;
    let chain = value["user_namespace_chain"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 32)
        .ok_or(EvidenceError::Invalid(
            "bounded user namespace ancestry required",
        ))?;
    let mut seen = BTreeSet::new();
    for row in chain {
        require(seen.insert(identity(row)?))?;
    }
    require(identity(&chain[0])? == namespace(&value["namespaces"]["user"])?)?;
    require(match text(value, "user_namespace_chain_end_reason")? {
        "parent-unavailable" => true,
        "bound-exceeded" => chain.len() == 32,
        _ => false,
    })?;
    for name in NAMESPACES {
        let row = &value["namespaces"][name];
        require(exact_keys(
            row,
            &["device", "inode", "owner_user_namespace"],
        ))?;
        namespace(row)?;
        if name == "user" {
            require(row["owner_user_namespace"].is_null())?;
        } else {
            identity(&row["owner_user_namespace"])?;
        }
    }
    maps(&value["uid_map"])?;
    maps(&value["gid_map"])?;
    let label = text(value, "lsm_label")?;
    require(
        matches!(text(value, "setgroups")?, "allow" | "deny")
            && !label.is_empty()
            && label.len() <= 4096
            && !label.contains(['\0', '\n', '\r']),
    )
}

pub(crate) fn matches_image(value: &Value) -> Result<()> {
    let isolation = &value["task"]["isolation"];
    validate(isolation)?;
    require(value["lsm_label"] == isolation["lsm_label"])?;
    for name in NAMESPACES {
        let (device, inode) = namespace(&isolation["namespaces"][name])?;
        require(value["namespaces"][name] == format!("{device}:{inode}"))?;
    }
    Ok(())
}

fn initial(snapshot: &Value) -> Result<()> {
    validate(snapshot)?;
    let user = namespace(&snapshot["namespaces"]["user"])?;
    require(
        snapshot["uid_map"] == json!([[0, 0, u32::MAX]])
            && snapshot["gid_map"] == json!([[0, 0, u32::MAX]])
            && snapshot["setgroups"] == "allow"
            && snapshot["user_namespace_chain"]
                .as_array()
                .is_some_and(|v| v.len() == 1)
            && snapshot["user_namespace_chain_end_reason"] == "parent-unavailable",
    )?;
    for name in NAMESPACES.into_iter().filter(|name| *name != "user") {
        require(identity(&snapshot["namespaces"][name]["owner_user_namespace"])? == user)?;
    }
    Ok(())
}

fn descendant_namespaces(snapshot: &Value, original: &Value) -> Result<bool> {
    let actor_user = namespace(&original["namespaces"]["user"])?;
    require(namespace(&snapshot["namespaces"]["user"])? != actor_user)?;
    if snapshot["user_namespace_chain_end_reason"] == "bound-exceeded" {
        return Ok(false);
    }
    let chain = snapshot["user_namespace_chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(identity)
        .collect::<Result<Vec<_>>>()?;
    require(chain.len() >= 2 && chain.last() == Some(&actor_user))?;
    for name in NAMESPACES.into_iter().filter(|name| *name != "user") {
        let row = &snapshot["namespaces"][name];
        let owner = identity(&row["owner_user_namespace"])?;
        require(chain.contains(&owner))?;
        if owner == actor_user {
            require(namespace(row)? == namespace(&original["namespaces"][name])?)?;
        } else {
            require(namespace(row)? != namespace(&original["namespaces"][name])?)?;
        }
    }
    Ok(true)
}

/// An unmapped newborn is valid kernel evidence but cannot receive a mapped
/// execution grade. Its fresh capabilities do not relax any exec profile.
pub(crate) fn birth_profile(
    task: &Value,
    actor: &Value,
    setup: bool,
) -> Result<Option<&'static str>> {
    let snapshot = &task["isolation"];
    validate(snapshot)?;
    let unmapped = ["uid_map", "gid_map"]
        .iter()
        .any(|name| snapshot[*name].as_array().unwrap().is_empty());
    if !unmapped {
        return profile(task, actor, setup);
    }
    let original = &actor["task"]["isolation"];
    initial(original)?;
    require(
        task["cgroup"] == actor["task"]["cgroup"] && snapshot["lsm_label"] == original["lsm_label"],
    )?;
    let status = &task["status"];
    for name in ["Uid", "Gid"] {
        let values = text(status, name)?
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        require(values == ["10004"; 4] || values == ["65534"; 4])?;
    }
    require(
        text(status, "Groups")?
            .split_ascii_whitespace()
            .next()
            .is_none()
            && status["NoNewPrivs"] == "1"
            && status["Seccomp"] == "2"
            && decimal(text(status, "Seccomp_filters")?)? > 0
            && decimal(text(status, "Seccomp_filters")?)?
                >= decimal(text(&actor["task"]["status"], "Seccomp_filters")?)?
            && status["CapAmb"] == "0000000000000000"
            && status["CapInh"] == "0000000000000000",
    )?;
    descendant_namespaces(snapshot, original)?;
    for name in ["uid_map", "gid_map"] {
        let rows = snapshot[name].as_array().unwrap();
        require(rows.is_empty() || (rows.len() == 1 && rows[0][1] == 10004 && rows[0][2] == 1))?;
    }
    Ok(None)
}

/// Grade the isolation present at this exec or initial child stop. The actor
/// must separately join the outside filtered-cell identity in the same trace.
/// An exhausted ancestry bound is incomplete evidence, never a relaxed pass.
pub(crate) fn profile(task: &Value, actor: &Value, setup: bool) -> Result<Option<&'static str>> {
    let snapshot = &task["isolation"];
    let original = &actor["task"]["isolation"];
    validate(snapshot)?;
    initial(original)?;
    require(
        task["cgroup"] == actor["task"]["cgroup"] && snapshot["lsm_label"] == original["lsm_label"],
    )?;
    let status = &task["status"];
    for name in ["Uid", "Gid"] {
        require(
            text(status, name)?
                .split_ascii_whitespace()
                .collect::<Vec<_>>()
                == ["10004"; 4],
        )?;
    }
    require(
        text(status, "Groups")?
            .split_ascii_whitespace()
            .next()
            .is_none()
            && status["NoNewPrivs"] == "1"
            && status["Seccomp"] == "2"
            && decimal(text(status, "Seccomp_filters")?)? > 0
            && decimal(text(status, "Seccomp_filters")?)?
                >= decimal(text(&actor["task"]["status"], "Seccomp_filters")?)?,
    )?;
    let user = namespace(&snapshot["namespaces"]["user"])?;
    let actor_user = namespace(&original["namespaces"]["user"])?;
    if user == actor_user {
        require(snapshot == original)?;
        crate::native_runtime_trace::floors(task)?;
        return Ok(Some("outer"));
    }
    if !descendant_namespaces(snapshot, original)? {
        return Ok(None);
    }
    for name in ["uid_map", "gid_map"] {
        let rows = snapshot[name].as_array().unwrap();
        require(rows.len() == 1 && rows[0][1] == 10004 && rows[0][2] == 1)?;
    }
    require(snapshot["setgroups"] == "deny")?;
    let mut capabilities = 0;
    let mut effective = 0;
    let mut permitted = 0;
    let mut bounding = 0;
    for name in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
        let bits = u64::from_str_radix(text(status, name)?, 16)
            .map_err(|_| EvidenceError::Invalid("bounded capability mask required"))?;
        let allowed = if setup && !matches!(name, "CapAmb" | "CapInh") {
            0x20_0100
        } else {
            0
        };
        require(bits & !allowed == 0)?;
        match name {
            "CapEff" => effective = bits,
            "CapPrm" => permitted = bits,
            "CapBnd" => bounding = bits,
            _ => {}
        }
        capabilities |= bits;
    }
    require(effective & !permitted == 0 && permitted & !bounding == 0)?;
    if !setup {
        require(identity(&snapshot["namespaces"]["mnt"]["owner_user_namespace"])? == user)?;
    }
    Ok(Some(if capabilities == 0 {
        "contained"
    } else {
        "namespace-setup"
    }))
}

#[cfg(test)]
#[path = "native_task_isolation_tests.rs"]
pub(crate) mod tests;
