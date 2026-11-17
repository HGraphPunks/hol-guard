//! Exact keyed Live recovery of metadata from a container that never started.
//! No workload or image operation, process signal, exit or usage is invented.
use super::{never_started, one, sha};
use crate::native_sdk_agent_spec::check_live_inspection;
use crate::native_sdk_process::{run_pinned_podman, verify_helper};
use crate::{NativeJobExecution, RunReservationJournal};
use gauntlet_contracts::{PrelaunchPrepared, WorkerRequest};
use serde_json::{json, Value};
use std::{io::Read, path::Path};

const FIELDS: [&str; 13] = [
    "source_sha",
    "job_id",
    "deployment_digest",
    "worker_generation",
    "preparation_sha256",
    "live_prepared_sha256",
    "storage_receipt_sha256",
    "host_pin_sha256",
    "container_id",
    "creation_sha256",
    "inspection_sha256",
    "policy_sha256",
    "repair_generation",
];
const INTENT: &str = "live-sdk-created-repair-intent.v1.json";
const RECEIPT: &str = "live-sdk-created-repair.v1.json";
fn text<'a>(p: &'a Value, key: &str) -> &'a str {
    p[key].as_str().unwrap_or("")
}
fn parse(args: &[String]) -> Result<Value, String> {
    if args.len() != 15
        || !matches!(
            args[1].as_str(),
            "--repair-native-live-sdk-created-v1" | "--read-native-live-sdk-created-repair-v1"
        )
    {
        return Err("exact keyed Live created-repair arguments required".into());
    }
    let mut p = json!({});
    for (k, v) in FIELDS.into_iter().zip(&args[2..]) {
        if !crate::hex(
            v,
            if k == "source_sha" {
                40
            } else if k == "job_id" {
                16
            } else {
                64
            },
        ) {
            return Err("original Live created-repair SHA/CID pins required".into());
        }
        p[k] = json!(v);
    }
    Ok(p)
}
fn binding(
    p: &Value,
    pre: &PrelaunchPrepared,
    live: &Value,
    storage: &Value,
) -> Result<(), String> {
    if pre.source_sha != text(p, "source_sha")
        || pre.job_id != text(p, "job_id")
        || pre.deployment_digest != text(p, "deployment_digest")
        || pre.worker_generation != text(p, "worker_generation")
        || pre.host_record_sha256().map_err(|e| e.to_string())? != text(p, "host_pin_sha256")
        || sha(&crate::native_job_storage::linux::canonical(live)?)
            != text(p, "live_prepared_sha256")
        || live["source_sha"] != p["source_sha"]
        || live["job_id"] != p["job_id"]
        || live["deployment_digest"] != p["deployment_digest"]
        || live["worker_generation"] != p["worker_generation"]
        || live["preparation_sha256"] != p["preparation_sha256"]
        || storage["receipt_sha256"] != p["storage_receipt_sha256"]
    {
        return Err(
            "created repair differs from original Host pin, Live preparation or storage".into(),
        );
    }
    Ok(())
}
fn inventory(p: &Value, podman: &str, label: &str, present: bool) -> Result<(), String> {
    let job = text(p, "job_id");
    let cid = text(p, "container_id");
    let output = run_pinned_podman(
        podman,
        &[
            "ps".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--filter".into(),
            format!("label=hol.gauntlet.sdk.job={job}"),
            "--format={{.ID}}".into(),
        ],
    )?;
    if !output.status.success() {
        return Err("original SDK metadata inventory unavailable".into());
    }
    let ids = std::str::from_utf8(&output.stdout)
        .map_err(|_| "SDK inventory UTF-8")?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if ids != if present { vec![cid] } else { vec![] } {
        return Err("unexpected SDK metadata blocks keyed repair".into());
    }
    let mut raw = Vec::new();
    std::fs::File::open("/sys/kernel/security/apparmor/profiles")
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 65536 {
        return Err("SDK profile inventory bound".into());
    }
    let profiles = std::str::from_utf8(&raw).map_err(|_| "SDK profile UTF-8")?;
    if profiles
        .lines()
        .filter(|line| line.starts_with(&format!("hol-gauntlet-sdk-{job}-")))
        .any(|line| line != label)
    {
        return Err("foreign SDK profile blocks keyed repair".into());
    }
    if Path::new(&format!("/sys/fs/cgroup/holgauntletrust{job}.slice"))
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Err("SDK job cgroup survives; metadata-only repair refused".into());
    }
    Ok(())
}
fn check_cancelled() -> Result<(), String> {
    if crate::native_worker::cancellation_requested() {
        Err("Live created repair interrupted; retain original intent".into())
    } else {
        Ok(())
    }
}
fn cid_absent(podman: &str, cid: &str) -> Result<(), String> {
    let absent = run_pinned_podman(podman, &["container".into(), "exists".into(), cid.into()])?;
    if absent.status.code() != Some(1) {
        return Err("original SDK CID absence is unknown".into());
    }
    Ok(())
}
pub fn repair_native_live_sdk_created(args: &[String]) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    let p = parse(args)?;
    let publish = args[1] == "--repair-native-live-sdk-created-v1";
    crate::verify_running_binary(text(&p, "repair_generation")).map_err(|e| e.to_string())?;
    let _scope = crate::native_job_storage::owner::scope()?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let (pre, spec) = crate::native_keyed_startup_repair::retained(
        &journal,
        text(&p, "source_sha"),
        text(&p, "job_id"),
        text(&p, "deployment_digest"),
        text(&p, "worker_generation"),
    )?;
    let NativeJobExecution::HostPinnedLive { sdk, .. } = &spec.execution else {
        return Err("keyed created repair requires the original Live profile".into());
    };
    if spec.preparation_sha256 != text(&p, "preparation_sha256") {
        return Err("Live preparation pin differs".into());
    }
    let request=WorkerRequest::parse(json!({"schema":"hol-gauntlet-worker-request.v1","action":"run","source_sha":p["source_sha"],"job_id":p["job_id"],"deployment_digest":p["deployment_digest"]}).to_string().as_bytes()).map_err(|e|e.to_string())?;
    let (_, preparation) = crate::native_job_io::load(&request, text(&p, "worker_generation"))?;
    let live = crate::native_live_prepare::retained(&spec, text(&p, "deployment_digest"))?;
    let storage = crate::native_job_storage::native::retained_storage(&spec.job_id)?
        .ok_or("bounded original Live storage required")?;
    binding(&p, &pre, &live.value, &storage)?;
    for suffix in [
        "terminal.json",
        "report.json",
        "native-startup-repair.json",
        "native-keyed-startup-repair.json",
    ] {
        if crate::read_bounded_regular(
            &journal.root,
            &format!("{}.{suffix}", spec.job_id),
            16 * 1024 * 1024,
        )
        .map_err(|e| e.to_string())?
        .is_some()
        {
            return Err("completed or partial Live job blocks created repair".into());
        }
    }
    let running = journal
        .running_marker(
            &spec.job_id,
            &spec.source_sha,
            text(&p, "deployment_digest"),
            &spec.worker_generation,
        )
        .map_err(|e| e.to_string())?
        .ok_or("original Live running marker absent")?;
    crate::native_repair::controller_absent(&running)?;
    crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
    crate::native_mcp_quiescence::require_mcp_base_quiescence(&spec, &preparation)?;
    let quiescent = gauntlet_cell_rootfs::verify_closed_native_preparation(&preparation)?;
    let root =
        crate::open_root_owned_public_directory(&spec.job_root()).map_err(|e| e.to_string())?;
    let logs = crate::open_root_owned_public_directory(&spec.job_root().join("sdk-processes"))
        .map_err(|e| e.to_string())?;
    let creation = crate::feature_files::required(&logs, "003.stdout", (0, 0), 0o600, 128)?;
    let captured = crate::feature_files::required(&logs, "004.stdout", (0, 0), 0o600, 1024 * 1024)?;
    let cid = text(&p, "container_id");
    if creation != format!("{cid}\n").as_bytes()
        || sha(&creation) != text(&p, "creation_sha256")
        || sha(&captured) != text(&p, "inspection_sha256")
    {
        return Err("original created SDK captures differ".into());
    }
    let old = one(&captured)?;
    never_started(&old)?;
    let nonce = old["Config"]["Labels"]["hol.gauntlet.sdk.nonce"]
        .as_str()
        .filter(|s| crate::hex(s, 32))
        .ok_or("original SDK instance identity absent")?;
    let name = format!("hol-gauntlet-sdk-{}-{nonce}", spec.job_id);
    let label = crate::native_sdk_peer::sdk_label(&name)?;
    let mut mounts = super::mounts(&spec.job_root(), sdk);
    mounts.insert(
        "/runtime/resources".into(),
        (
            spec.job_root().join("sdk-r").to_string_lossy().into_owned(),
            false,
        ),
    );
    mounts.insert(
        "/runtime/live-model".into(),
        (
            spec.job_root()
                .join("sdk-model")
                .to_string_lossy()
                .into_owned(),
            false,
        ),
    );
    let check = |v: &Value| -> Result<(), String> {
        never_started(v)?;
        crate::native_job_storage::native::check_for_cleanup(&spec.job_id, v, false)?;
        let (actual, _) = check_live_inspection(v, &name, &spec.job_id, nonce, &mounts, false)?;
        if actual != cid {
            return Err("original Live SDK CID differs".into());
        }
        Ok(())
    };
    let (old_id, _) = check_live_inspection(&old, &name, &spec.job_id, nonce, &mounts, false)?;
    if old_id != cid {
        return Err("original Live SDK CID differs".into());
    }
    let temporary = crate::open_root_owned_public_directory(
        &Path::new(crate::native_job_storage::lifecycle::BASE)
            .join(&spec.job_id)
            .join("temporary/sdk"),
    )
    .map_err(|e| e.to_string())?;
    let temporary_intent =
        crate::feature_files::required(&temporary, "intent.json", (0, 0), 0o600, 24576)?;
    let temporary_complete =
        crate::feature_files::required(&temporary, "complete.json", (0, 0), 0o600, 24576)?;
    let policy =
        crate::feature_files::required(&root, "sdk-agent.apparmor", (0, 0), 0o400, 1024 * 1024)?;
    if sha(&policy) != text(&p, "policy_sha256")
        || policy
            != crate::native_sdk_public::APPARMOR
                .replace("HOL_WORKER_PROFILE", &name)
                .as_bytes()
    {
        return Err("original Live SDK policy differs".into());
    }
    let intent = json!({"schema":"hol-gauntlet-native-live-sdk-created-repair-intent.v1","pins":p,"prelaunch":serde_json::from_slice::<Value>(&pre.to_bytes().map_err(|e|e.to_string())?).map_err(|e|e.to_string())?,"running_marker_sha256":running.sha256,"quiescent":quiescent,"temporary_intent_sha256":sha(&temporary_intent),"temporary_complete_sha256":sha(&temporary_complete),"model_requests":null,"exit_code":null,"execution_eligible":false});
    let raw = crate::native_job_storage::linux::canonical(&intent)?;
    let prior = crate::feature_files::read(&root, INTENT, (0, 0), 0o600, 8192)?;
    if prior.as_ref().is_some_and(|v| v != &raw) {
        return Err("original Live created-repair intent changed".into());
    }
    let expected = json!({"schema":"hol-gauntlet-native-live-sdk-created-repair.v1","intent_sha256":sha(&raw),"pins_sha256":sha(&crate::native_job_storage::linux::canonical(&p)?),"container_id_sha256":sha(cid.as_bytes()),"sdk_agent_absent":true,"sdk_profile_absent":true,"process_signalled":false,"image_adopted":false,"job_terminal_written":false,"model_requests":null,"exit_code":null,"execution_eligible":false,"qualification_eligible":false});
    let prior_receipt = crate::feature_files::read(&root, RECEIPT, (0, 0), 0o600, 8192)?;
    if let Some(receipt) = prior_receipt {
        if prior.is_none() || receipt != crate::native_job_storage::linux::canonical(&expected)? {
            return Err("Live created repair receipt changed".into());
        }
        inventory(&p, &preparation.podman_sha256, &label, false)?;
        cid_absent(&preparation.podman_sha256, cid)?;
        if crate::native_job_storage::native::check_for_cleanup(&spec.job_id, &old, false).is_err()
        {
            // A later original keyed repair may close these mounts. Their
            // original immutable intent/complete hashes above must still match.
            crate::native_job_storage::temporary::require_absent(
                &spec.job_id,
                crate::native_job_storage::temporary::Scope::Sdk,
            )?;
        }
        crate::native_sdk_quiescence::require_sdk_base_quiescence(&spec, &preparation)?;
        return Ok(receipt);
    }
    if !publish {
        return Err("original Live created repair incomplete; use explicit resume".into());
    }
    check(&old)?;
    check_cancelled()?;
    let exists = run_pinned_podman(
        &preparation.podman_sha256,
        &["container".into(), "exists".into(), cid.into()],
    )?;
    match exists.status.code() {
        Some(0) => {
            inventory(&p, &preparation.podman_sha256, &label, true)?;
            let now =
                run_pinned_podman(&preparation.podman_sha256, &["inspect".into(), cid.into()])?;
            if !now.status.success() {
                return Err("current created SDK inspection unavailable".into());
            }
            check(&one(&now.stdout)?)?;
            if prior.is_none() {
                crate::terminal::create_durable(&root, INTENT, &raw).map_err(|e| e.to_string())?;
            }
            check_cancelled()?;
            lease.verify(&journal.root).map_err(|e| e.to_string())?;
            let removed =
                run_pinned_podman(&preparation.podman_sha256, &["rm".into(), cid.into()])?;
            if !removed.status.success()
                || std::str::from_utf8(&removed.stdout)
                    .map_err(|_| "SDK removal UTF-8")?
                    .trim()
                    != cid
            {
                return Err("exact never-started SDK removal uncertain".into());
            }
        }
        Some(1) if prior.is_some() => {}
        _ => return Err("created SDK absent without original intent or state uncertain".into()),
    }
    cid_absent(&preparation.podman_sha256, cid)?;
    inventory(&p, &preparation.podman_sha256, &label, false)?;
    check_cancelled()?;
    let parser = preparation
        .host_helper_sha256("/usr/sbin/apparmor_parser")
        .ok_or("original AppArmor helper pin absent")?;
    verify_helper("/usr/sbin/apparmor_parser", parser)?;
    if !crate::builder_policy::profile_absent(&name).map_err(|e| e.to_string())? {
        crate::builder_policy::run_parser(
            "--remove",
            spec.job_root()
                .join("sdk-agent.apparmor")
                .to_str()
                .ok_or("fixed SDK policy UTF-8")?,
        )
        .map_err(|e| e.to_string())?;
    }
    verify_helper("/usr/sbin/apparmor_parser", parser)?;
    crate::native_sdk_quiescence::require_sdk_base_quiescence(&spec, &preparation)?;
    crate::native_repair::controller_absent(&running)?;
    if gauntlet_cell_rootfs::verify_closed_native_preparation(&preparation)? != quiescent {
        return Err("original product quiescence changed during SDK repair".into());
    }
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    crate::verify_running_binary(text(&p, "repair_generation")).map_err(|e| e.to_string())?;
    let result = crate::native_job_storage::linux::canonical(&expected)?;
    crate::terminal::create_durable(&root, RECEIPT, &result).map_err(|e| e.to_string())?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyed_created_arguments_never_accept_partial_foreign_or_unkeyed_context() {
        let mut args = vec![
            "worker".into(),
            "--repair-native-live-sdk-created-v1".into(),
        ];
        for k in FIELDS {
            args.push("a".repeat(if k == "source_sha" {
                40
            } else if k == "job_id" {
                16
            } else {
                64
            }));
        }
        assert!(parse(&args).is_ok());
        for index in 2..args.len() {
            let mut changed = args.clone();
            changed[index] = "not-a-pin".into();
            assert!(parse(&changed).is_err());
        }
        args[1] = "--repair-sdk-created".into();
        assert!(parse(&args).is_err());
    }

    #[test]
    fn created_repair_requires_the_prior_host_key_live_preparation_and_storage() {
        let pre = PrelaunchPrepared {
            source_sha: "a".repeat(40),
            job_id: "b".repeat(16),
            deployment_digest: "c".repeat(64),
            worker_generation: "d".repeat(64),
            started_marker_sha256: "e".repeat(64),
            controller_key_pin_sha256: "f".repeat(64),
            controller_public_key_hex: "1".repeat(64),
        };
        let live = json!({"source_sha":pre.source_sha,"job_id":pre.job_id,
            "deployment_digest":pre.deployment_digest,"worker_generation":pre.worker_generation,
            "preparation_sha256":"2".repeat(64)});
        let storage = json!({"receipt_sha256":"3".repeat(64)});
        let p = json!({"source_sha":pre.source_sha,"job_id":pre.job_id,
            "deployment_digest":pre.deployment_digest,"worker_generation":pre.worker_generation,
            "preparation_sha256":live["preparation_sha256"],"live_prepared_sha256":sha(&crate::native_job_storage::linux::canonical(&live).unwrap()),
            "storage_receipt_sha256":storage["receipt_sha256"],"host_pin_sha256":pre.host_record_sha256().unwrap()});
        binding(&p, &pre, &live, &storage).unwrap();
        for key in [
            "source_sha",
            "job_id",
            "deployment_digest",
            "worker_generation",
            "preparation_sha256",
            "live_prepared_sha256",
            "storage_receipt_sha256",
            "host_pin_sha256",
        ] {
            let mut changed = p.clone();
            changed[key] = json!("0".repeat(if key == "job_id" {
                16
            } else if key == "source_sha" {
                40
            } else {
                64
            }));
            assert!(binding(&changed, &pre, &live, &storage).is_err(), "{key}");
        }
        let mut foreign = live.clone();
        foreign["job_id"] = json!("0".repeat(16));
        let mut rehashed = p.clone();
        rehashed["live_prepared_sha256"] = json!(sha(
            &crate::native_job_storage::linux::canonical(&foreign).unwrap()
        ));
        assert!(binding(&rehashed, &pre, &foreign, &storage).is_err());
    }
}
