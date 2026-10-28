//! Explicit removal of one outside-pinned, never-started SDK container.
//! This does not terminate a process, adopt an image or fabricate a job exit.
use crate::native_sdk_agent_spec::check_inspection;
use crate::native_sdk_process::run_pinned_podman;
use crate::native_sdk_public::APPARMOR;
use crate::{NativeJobExecution, NativeSdkPins, RunReservationJournal};
use gauntlet_contracts::{canonicalize, WorkerRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn json(raw: &[u8]) -> Result<Value, String> {
    let canonical = canonicalize(raw).map_err(|_| "SDK created-repair ambiguous JSON")?;
    serde_json::from_slice(&canonical).map_err(|_| "SDK created-repair JSON".into())
}
fn one(raw: &[u8]) -> Result<Value, String> {
    json(raw)?
        .as_array()
        .filter(|v| v.len() == 1)
        .map(|v| v[0].clone())
        .ok_or("one exact SDK created container required".into())
}
fn never_started(value: &Value) -> Result<(), String> {
    let state = &value["State"];
    if state["Status"] != "created"
        || state["Pid"] != 0
        || state["Running"] != false
        || state["Paused"] != false
        || state["Restarting"] != false
        || state["Dead"] != false
        || state["OOMKilled"] != false
        || state["ExitCode"] != 0
        || state["Error"] != ""
        || state["StartedAt"] != "0001-01-01T00:00:00Z"
        || state["FinishedAt"] != "0001-01-01T00:00:00Z"
    {
        return Err("SDK created repair refuses any started or uncertain container".into());
    }
    Ok(())
}
fn mounts(root: &Path, sdk: &NativeSdkPins) -> BTreeMap<String, (String, bool)> {
    [
        (root.join("sdk-home"), "/runtime/home", true),
        (root.join("workspace"), "/runtime/home/project", true),
        (root.join("sdk-agent"), "/runtime/agent", true),
        (
            sdk.directory().join("node_modules"),
            "/sdk/node_modules",
            false,
        ),
        (sdk.directory().join("bun"), "/runtime/bun", false),
        (root.join("sdk-public"), "/runtime/public", false),
        (root.join("sdk-gate"), "/runtime/sdk-gate", false),
        (root.join("sdk-hooks"), "/runtime/guard-hook", false),
    ]
    .into_iter()
    .map(|(s, t, r)| (t.into(), (s.to_string_lossy().into_owned(), r)))
    .collect()
}
pub fn repair_native_sdk_created(args: &[String]) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if args.len() != 11 || args[1] != "--repair-sdk-created" {
        return Err("fixed SDK created-repair arguments required".into());
    }
    let (source, deployment, generation, job, started_pin, cid, creation_pin, inspection_pin, own) = (
        &args[2], &args[3], &args[4], &args[5], &args[6], &args[7], &args[8], &args[9], &args[10],
    );
    if !crate::hex(source, 40)
        || !crate::hex(job, 16)
        || [
            deployment,
            generation,
            started_pin,
            cid,
            creation_pin,
            inspection_pin,
            own,
        ]
        .iter()
        .any(|s| !crate::hex(s, 64))
    {
        return Err("outside source/job/start/CID/creation/inspection/repair pins required".into());
    }
    crate::verify_running_binary(own).map_err(|e| e.to_string())?;
    let journal = RunReservationJournal::open_root_owned(Path::new(
        "/var/lib/hol-gauntlet-rust/worker-state",
    ))
    .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let request = WorkerRequest::parse(
        json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
        "source_sha":source,"job_id":job,"deployment_digest":deployment})
        .to_string()
        .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let (spec, preparation) = crate::native_job_io::load(&request, generation)?;
    let NativeJobExecution::SdkTransport { sdk, .. } = &spec.execution else {
        return Err("SDK created repair requires the original closed SDK profile".into());
    };
    let started = journal
        .started(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("SDK started marker absent")?;
    if started.sha256 != *started_pin || started.controller_public_key_hex.is_some() {
        return Err("SDK created repair differs from original unkeyed reservation".into());
    }
    for suffix in [
        "terminal.json",
        "report.json",
        "native-repair.json",
        "controller-key.json",
    ] {
        if crate::read_bounded_regular(&journal.root, &format!("{job}.{suffix}"), 16 * 1024 * 1024)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("SDK created repair requires a retained unknown job".into());
        }
    }
    let running = journal
        .running_marker(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("SDK running marker absent")?;
    crate::native_repair::controller_absent(&running)?;
    let quiescent = gauntlet_cell_rootfs::verify_closed_native_preparation(&preparation)?;
    let root =
        crate::open_root_owned_public_directory(&spec.job_root()).map_err(|e| e.to_string())?;
    let logs = crate::open_root_owned_public_directory(&spec.job_root().join("sdk-processes"))
        .map_err(|e| e.to_string())?;
    // This version is restricted to the v1 create-before-start sequence.
    let creation = crate::read_bounded_regular(&logs, "003.stdout", 128)
        .map_err(|e| e.to_string())?
        .ok_or("original SDK creation capture absent")?;
    let captured = crate::read_bounded_regular(&logs, "004.stdout", 1024 * 1024)
        .map_err(|e| e.to_string())?
        .ok_or("original SDK inspection capture absent")?;
    if sha(&creation) != *creation_pin
        || creation != format!("{cid}\n").as_bytes()
        || sha(&captured) != *inspection_pin
    {
        return Err("original SDK creation/inspection differ from outside pins".into());
    }
    let old = one(&captured)?;
    let nonce = old["Config"]["Labels"]["hol.gauntlet.sdk.nonce"]
        .as_str()
        .filter(|s| crate::hex(s, 32))
        .ok_or("SDK original nonce missing")?;
    let name = format!("hol-gauntlet-sdk-{job}-{nonce}");
    let label = crate::native_sdk_peer::sdk_label(&name)?;
    let expected_mounts = mounts(&spec.job_root(), sdk);
    never_started(&old)?;
    let (old_id, _) = check_inspection(&old, &name, job, nonce, &expected_mounts, false)?;
    if old_id != *cid {
        return Err("SDK original CID differs".into());
    }
    let policy = crate::read_bounded_regular(&root, "sdk-agent.apparmor", 1024 * 1024)
        .map_err(|e| e.to_string())?
        .ok_or("SDK original policy absent")?;
    if policy != APPARMOR.replace("HOL_WORKER_PROFILE", &name).as_bytes() {
        return Err("SDK original policy differs from fixed template and nonce".into());
    }
    if !crate::builder_policy::profile_absent(&name).map_err(|e| e.to_string())? {
        return Err("SDK created repair requires its profile already absent".into());
    }
    let intent = json!({"schema":"hol-gauntlet-native-sdk-created-repair-intent.v1","source_sha":source,"job_id":job,
        "deployment_digest":deployment,"worker_generation":generation,"started_marker_sha256":started_pin,
        "container_id":cid,"name":name,"declared_lsm_label":label,"creation_sha256":creation_pin,
        "inspection_sha256":inspection_pin,"policy_sha256":sha(&policy),"quiescent":quiescent,
        "repair_generation":own,"execution_eligible":false,"model_requests":0});
    let intent_raw = canonicalize(intent.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let prior = crate::read_bounded_regular(&root, "sdk-created-repair-intent.v1.json", 8192)
        .map_err(|e| e.to_string())?;
    if prior.as_ref().is_some_and(|r| *r != intent_raw) {
        return Err("SDK created-repair intent differs".into());
    }
    if let Some(receipt) = crate::read_bounded_regular(&root, "sdk-created-repair.v1.json", 8192)
        .map_err(|e| e.to_string())?
    {
        let value = json(&receipt)?;
        let expected = json!({"schema":"hol-gauntlet-native-sdk-created-repair.v1","intent_sha256":sha(&intent_raw),
            "container_id":cid,"status":value["status"],"sdk_agent_absent":true,"sdk_profile_absent":true,
            "process_signalled":false,"image_adopted":false,"job_terminal_written":false,"execution_eligible":false,"model_requests":0});
        if !matches!(
            value["status"].as_str(),
            Some("removed-never-started" | "absent-after-recorded-intent")
        ) || value != expected
            || canonicalize(&receipt).map_err(|e| e.to_string())? != receipt
        {
            return Err("SDK created-repair receipt differs".into());
        }
        crate::native_sdk_quiescence::require_sdk_quiescence(&spec, &preparation)?;
        return Ok(receipt);
    }
    let exists = run_pinned_podman(
        &preparation.podman_sha256,
        &["container".into(), "exists".into(), cid.clone()],
    )?;
    let mut removed = false;
    match exists.status.code() {
        Some(0) => {
            let current =
                run_pinned_podman(&preparation.podman_sha256, &["inspect".into(), cid.clone()])?;
            if !current.status.success() {
                return Err("SDK current created inspection unavailable".into());
            }
            let current = one(&current.stdout)?;
            never_started(&current)?;
            let (actual, _) =
                check_inspection(&current, &name, job, nonce, &expected_mounts, false)?;
            if actual != *cid {
                return Err("SDK current CID differs".into());
            }
            if prior.is_none() {
                crate::terminal::create_durable(
                    &root,
                    "sdk-created-repair-intent.v1.json",
                    &intent_raw,
                )
                .map_err(|e| e.to_string())?;
            }
            lease.verify(&journal.root).map_err(|e| e.to_string())?;
            crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
            // No force, process signal, name-based removal or image operation.
            let result =
                run_pinned_podman(&preparation.podman_sha256, &["rm".into(), cid.clone()])?;
            if !result.status.success()
                || std::str::from_utf8(&result.stdout)
                    .map_err(|_| "SDK removal CID UTF-8")?
                    .trim()
                    != cid
            {
                return Err("SDK exact created-container removal uncertain".into());
            }
            removed = true;
        }
        Some(1) if prior.is_some() => {}
        _ => {
            return Err(
                "SDK created container absent without retained intent, or state unavailable".into(),
            )
        }
    }
    crate::native_sdk_quiescence::require_sdk_quiescence(&spec, &preparation)?;
    crate::native_repair::controller_absent(&running)?;
    if gauntlet_cell_rootfs::verify_closed_native_preparation(&preparation)? != quiescent {
        return Err("SDK product evidence changed during metadata repair".into());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    crate::verify_running_binary(own).map_err(|e| e.to_string())?;
    let receipt = json!({"schema":"hol-gauntlet-native-sdk-created-repair.v1","intent_sha256":sha(&intent_raw),
        "container_id":cid,"status":if removed{"removed-never-started"}else{"absent-after-recorded-intent"},
        "sdk_agent_absent":true,"sdk_profile_absent":true,"process_signalled":false,"image_adopted":false,
        "job_terminal_written":false,"execution_eligible":false,"model_requests":0});
    let raw = canonicalize(receipt.to_string().as_bytes()).map_err(|e| e.to_string())?;
    crate::terminal::create_durable(&root, "sdk-created-repair.v1.json", &raw)
        .map_err(|e| e.to_string())?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn created_repair_refuses_exited_running_and_ambiguous_states() {
        let value = json!({"State":{"Status":"created","Pid":0,"Running":false,"Paused":false,
            "Restarting":false,"Dead":false,"OOMKilled":false,"ExitCode":0,"Error":"",
            "StartedAt":"0001-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}});
        never_started(&value).unwrap();
        for (key, bad) in [
            ("Status", json!("exited")),
            ("Pid", json!(42)),
            ("Running", json!(true)),
            ("OOMKilled", json!(true)),
            ("StartedAt", json!("2026-10-27T00:00:00Z")),
            ("ExitCode", json!(2)),
            ("Error", json!("unknown")),
        ] {
            let mut changed = value.clone();
            changed["State"][key] = bad;
            assert!(never_started(&changed).is_err(), "{key}");
        }
        let mut changed = value;
        changed["State"]
            .as_object_mut()
            .unwrap()
            .remove("StartedAt");
        assert!(never_started(&changed).is_err());
    }
}
