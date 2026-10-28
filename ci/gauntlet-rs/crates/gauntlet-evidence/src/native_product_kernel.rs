//! Separate product samples at the gate, after exec and in a held child view.
//! Matching observations does not admit their producer or signing key.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{argv, require, text, Artifacts};
use crate::native_process_kernel::{decimal, hex, number, status, KernelSamples, NAMESPACES};
use crate::{EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn profile(identity: &Value, job: &str) -> Result<()> {
    require(hex(job, 16))?;
    let nonce = text(identity, "lsm_label")?
        .strip_prefix("hol-product-cell-")
        .and_then(|s| s.strip_suffix(" (enforce)"))
        .ok_or(EvidenceError::Invalid("enforcing product profile required"))?;
    require(
        hex(nonce, 32)
            && identity["cgroup"]
                == format!("/holgauntletrust{job}.slice/hol-product-cell-{nonce}.service")
            && number(&identity["pid"])? <= i32::MAX as u64,
    )?;
    number(&identity["start_ticks"])?;
    let namespaces = identity["namespaces"]
        .as_object()
        .ok_or(EvidenceError::Invalid("product namespaces missing"))?;
    require(namespaces.len() == NAMESPACES.len())?;
    for name in NAMESPACES {
        require(
            decimal(
                text(&identity["namespaces"], name)?
                    .strip_prefix("4:")
                    .ok_or(EvidenceError::Invalid("product namespace device differs"))?,
            )? > 0,
        )?;
    }
    status(
        &identity["status"],
        number(&identity["pid"])?,
        "10004",
        None,
    )
}

pub(crate) fn matching<'a>(
    samples: &'a KernelSamples<'_>,
    identity: &Value,
    command: &[String],
    executable: &str,
    job: &str,
) -> Result<Vec<&'a Value>> {
    profile(identity, job)?;
    require(hex(executable, 64) && !command.is_empty() && command.len() <= 64)?;
    let wire = format!("{}\0", command.join("\0"));
    require(wire.len() <= 32768 && command.iter().all(|s| !s.is_empty() && !s.contains('\0')))?;
    let matches = samples
        .rows
        .iter()
        .filter(|r| {
            r["pid"] == identity["pid"]
                && r["start_ticks"] == identity["start_ticks"]
                && r["argv_sha256"] == sha256(wire.as_bytes())
        })
        .collect::<Vec<_>>();
    require(!matches.is_empty())?;
    for row in &matches {
        require(
            row["argv_utf8"] == wire
                && row["executable_sha256"] == executable
                && row["pidfd_held"] == true
                && row["cgroup"] == identity["cgroup"]
                && row["lsm_label"] == identity["lsm_label"]
                && row["limits"]
                    == json!({"memory.max":"1073741824","pids.max":"128","cpu.max":"100000 100000"}),
        )?;
        let ns = row["namespaces"]
            .as_object()
            .ok_or(EvidenceError::Invalid("outside product namespaces missing"))?;
        require(ns.len() == NAMESPACES.len())?;
        for name in NAMESPACES {
            require(
                number(&row["namespaces"][name])?
                    == decimal(
                        text(&identity["namespaces"], name)?
                            .strip_prefix("4:")
                            .unwrap(),
                    )?,
            )?;
        }
        status(&row["status"], number(&identity["pid"])?, "10004", None)?;
        status(
            &identity["status"],
            number(&identity["pid"])?,
            "10004",
            Some(&row["namespace_pids"]),
        )?;
        for name in ["executable_device", "executable_inode"] {
            if let Some(value) = identity.get(name) {
                require(number(value)? == number(&row[name])?)?;
            }
        }
    }
    Ok(matches)
}

/// Check actual gate and post-exec observations for every prefix-Python launch.
/// Short non-prefix helper commands are explicitly outside this count.
pub(crate) fn launches(
    control: &Value,
    preparation: &Value,
    artifacts: &Artifacts<'_>,
    samples: &KernelSamples<'_>,
    interpreter: &str,
) -> Result<Value> {
    let job = text(control, "job_id")?;
    let actor = &control["actor"];
    let actor_command = ["/public/gauntlet-product-cell".into(), "actor".into()];
    require(argv(&actor["argv"])? == actor_command)?;
    matching(
        samples,
        actor,
        &actor_command,
        text(actor, "executable_sha256")?,
        job,
    )?;
    let python = format!("{}/bin/python", text(preparation, "runtime_prefix")?);
    let mut handles = BTreeSet::new();
    let mut pids = BTreeSet::new();
    let mut checked = Vec::new();
    let mut helper_count = 0;
    for (sequence, row) in artifacts.events.iter().enumerate() {
        if row["kind"] != "gated-product-process" {
            continue;
        }
        let gate = &row["data"]["identity"];
        let handle = text(&row["data"], "handle")?;
        require(handles.insert(handle) && pids.insert(number(&gate["pid"])?))?;
        let command = argv(&gate["argv"])?;
        require(command.len() > 2 && command[0] == actor_command[0] && command[1] == "exec-gate")?;
        let mut actual = command[2..].to_vec();
        if actual.starts_with(&["/usr/bin/env".into(), "HOME=/runtime/home".into()]) {
            actual = actual[2..].to_vec();
        }
        if actual.first() != Some(&python) {
            helper_count += 1;
            continue;
        }
        require(
            gate["executable_sha256"] == actor["executable_sha256"]
                && gate["namespaces"] == actor["namespaces"]
                && gate["cgroup"] == actor["cgroup"]
                && gate["lsm_label"] == actor["lsm_label"],
        )?;
        let gated = matching(
            samples,
            gate,
            &command,
            text(actor, "executable_sha256")?,
            job,
        )?;
        let executed = matching(samples, gate, &actual, interpreter, job)?;
        for observed in gated.iter().chain(&executed) {
            require(observed["parent_pid"] == actor["pid"])?;
        }
        let releases = artifacts
            .events
            .iter()
            .enumerate()
            .filter(|(_, r)| r["kind"] == "product-release" && r["data"]["handle"] == handle)
            .collect::<Vec<_>>();
        require(releases.len() == 1 && releases[0].0 > sequence)?;
        checked.push(
            json!({"gate_sequence":sequence,"release_sequence":releases[0].0,
            "handle":handle,"pid":gate["pid"],"start_ticks":gate["start_ticks"],
            "gate_samples":gated.len(),"interpreter_samples":executed.len(),
            "actual_argv_sha256":sha256(format!("{}\0",actual.join("\0")).as_bytes())}),
        );
    }
    require(!checked.is_empty() && checked.len() <= 256)?;
    Ok(
        json!({"schema":"hol-gauntlet-native-product-launch-relations.v1",
        "actor_observed":true,"prefix_python_launches_checked":checked.len(),"launches":checked,
        "non_prefix_helper_launches_not_graded":helper_count,"all_product_launches_graded":helper_count==0,
        "actor_digest_prelaunch_admitted":false,"interpreter_prelaunch_pinned":false,
        "outside_signing_key_admitted":false,"independent_process_custody_checked":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_product_kernel_tests.rs"]
mod tests;
