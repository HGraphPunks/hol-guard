//! Genuine source-selected OMP episodes over the actual Root World and normal
//! Native MCP transport. The deterministic synthetic-stream profiles stay separate.
use crate::native_live_provider::NativeLiveProvider;
use crate::native_operation_budget::NativeOperationBudget;
use crate::native_sdk_agent::NativeSdkAgent;
use crate::native_sdk_mcp_binding::{bind, BindingArtifacts};
use crate::native_sdk_mcp_plane::NativeSdkMcpPlane;
use crate::native_sdk_process::RootChild;
use crate::native_sdk_public::NativeSdkPublic;
use crate::native_sdk_router::NativeSdkRouter;
use crate::{
    NativeJobSpec, NativeLiveJob, NativeSdkPins, NativeSdkSockets, VerifiedNativeSdkAssets,
};
use gauntlet_cell_rootfs::{NativeApparatusReport, NativeGuardPins, NativeHookPlane};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

fn paused(cancel: &AtomicBool, deadline: Instant) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err("live OMP controller cancelled or expired".into());
    }
    std::thread::sleep(Duration::from_millis(10));
    Ok(())
}
fn serve(
    sockets: &NativeSdkSockets,
    peer: &crate::NativeSdkPeer,
    sdk: &mut RootChild,
    router: &mut NativeSdkRouter,
    plane: &mut NativeHookPlane,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, String> {
    let deadline =
        Instant::now() + Duration::from_secs(crate::native_live_spec::PREPARATION_SECONDS);
    let mut count = 0;
    loop {
        if let Some(mut stream) = sockets.accept_hook()? {
            count += 1;
            if count > 256 {
                return Err("live SDK hook operation bound exhausted".into());
            }
            let raw = crate::read_native_sdk_line(
                &mut stream,
                1024 * 1024,
                deadline.min(Instant::now() + Duration::from_secs(5)),
                cancel,
            )?;
            let request = crate::NativeSdkRequest::parse(&raw)?;
            let identity = peer.authenticate(
                &stream,
                matches!(request, crate::NativeSdkRequest::Execute { .. }),
            )?;
            let response = router.handle(&request, plane)?;
            identity.recheck(&stream)?;
            let raw = gauntlet_contracts::canonicalize(response.to_string().as_bytes())
                .map_err(|e| e.to_string())?;
            crate::write_native_sdk_line(&mut stream, &raw, deadline, cancel)?;
        }
        if let Some(output) = sdk.poll()? {
            if !output.status.success() {
                return Err("actual live OMP process did not complete".into());
            }
            let rows = gauntlet_evidence::parse_omp_transcript(&output.stdout)
                .map_err(|_| "actual live OMP transcript malformed")?;
            if !rows
                .iter()
                .any(|r| r["type"] == "episode_end" && r["status"] == "finished")
                || rows.iter().any(|r| r["type"] == "episode_error")
            {
                return Err("actual live OMP episode did not finish normally".into());
            }
            return Ok(output.stdout);
        }
        paused(cancel, deadline)?;
    }
}

pub(crate) fn run(
    job: &NativeJobSpec,
    deployment: &str,
    pins: &NativeGuardPins,
    sdk_pins: &NativeSdkPins,
    live: &NativeLiveJob,
    cancel: Arc<AtomicBool>,
) -> Result<NativeApparatusReport, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    let prepared = crate::native_live_prepare::retained(job, deployment)?;
    let world_key = crate::native_controller_key::consume_inherited_native_world_key(
        prepared.value["world_public_key_hex"]
            .as_str()
            .ok_or("prepared World public key absent")?,
    )?;
    let channel = crate::native_live_provider::inherited_channel(&job.worker_generation)?;
    let mut world = prepared.open_world(job, world_key)?;
    let spec = crate::native_live_prepare::source_spec(live)?;
    let initial = gauntlet_contracts::canonicalize(world.snapshot()?.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    if crate::native_live_model::sha(&initial) != prepared.value["world_initial_sha256"]
        || !world.receipts()?.is_empty()
    {
        return Err("live World changed before one-use execution".into());
    }
    let host_null = crate::native_sdk_host_device::NativeSdkHostNull::open()?;
    let root =
        crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
    let raw = crate::feature_files::required(&root, "preparation.v1.json", (0, 0), 0o600, 49152)?;
    let preparation = job.preparation(&raw)?;
    let assets = VerifiedNativeSdkAssets::load(sdk_pins)?;
    gauntlet_cell_rootfs::seed_native_sdk_fixture(&preparation)?;
    let prompt = spec["task_prompt"]
        .as_str()
        .ok_or("source-selected live task prompt absent")?;
    let public =
        NativeSdkPublic::prepare_live(&job.job_root(), prompt, live, &job.worker_generation)?;
    let mut sockets = NativeSdkSockets::new_live(&job.job_id)?;
    let budget = Arc::new(Mutex::new(NativeOperationBudget::new(128)?));
    let mut mcp = NativeSdkMcpPlane::prepare_live(
        job,
        budget.clone(),
        spec.clone(),
        live.protected(),
        world,
    )?;
    let cell = gauntlet_cell_rootfs::prepare_and_start(
        &job.preparation_path(),
        &job.preparation_sha256,
        cancel.clone(),
    )?;
    let prefix = cell.runtime_prefix().to_owned();
    let actor = cell
        .actor_observation()
        .cloned()
        .ok_or("live product actor unavailable")?;
    let mut plane =
        NativeHookPlane::new(cell, pins.clone(), &format!("gauntlet-live-{}", job.job_id))?;
    let mut router = NativeSdkRouter::with_budget(budget.clone())?;
    let mut agent = None;
    let mut sdk = None;
    let mut bridge = None;
    let mut provider = None;
    let mut channel = Some(channel);
    let mut sdk_raw = Vec::new();
    let mut binding = Value::Null;
    let attempted = (|| -> Result<(), String> {
        plane.start()?;
        if live.protected() {
            let reviewed = plane.submit_prompt(prompt)?;
            if reviewed["decision"] != "allow" {
                return Err("actual Native prompt did not allow live setup".into());
            }
        }
        mcp.start(job, &preparation, pins, &actor, &cancel)?;
        agent = Some(NativeSdkAgent::prepare_live(
            &job.job_id,
            &preparation,
            &assets,
            &sockets,
            &public,
            &mut mcp.sockets,
        )?);
        let owner = agent.as_mut().unwrap();
        let boundary = owner.launch(&assets, &public, &actor, &cancel)?;
        mcp.check_sdk_boundary(&boundary.observation())?;
        bridge = Some(owner.launch_live_model_bridge(
            &job.source_sha,
            &job.worker_generation,
            &live.model.budget_digest,
            &cancel,
        )?);
        provider = Some(NativeLiveProvider::bind(
            job,
            live,
            &sockets,
            boundary.retain()?,
            public.live_bridge()?,
            channel
                .take()
                .ok_or("live model channel already consumed")?,
            cancel.clone(),
        )?);
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let child = bridge.as_mut().unwrap();
            if child.poll()?.is_some() {
                return Err("SDK model HTTP bridge exited before live import".into());
            }
            let raw = child.stdout_prefix(4096)?;
            if raw.ends_with(b"\n") {
                let value: Value =
                    serde_json::from_slice(&raw).map_err(|_| "SDK model readiness JSON invalid")?;
                if value
                    != json!({"schema":"hol-gauntlet-native-live-http-listening.v1","job_id":job.job_id,"budget_digest":live.model.budget_digest})
                {
                    return Err("SDK model listener pins differ".into());
                }
                break;
            }
            paused(&cancel, ready_deadline)?;
        }
        sdk = Some(owner.launch_live_sdk(&cancel)?);
        let process = sdk.as_mut().unwrap();
        let (peer, observed) = bind(
            owner,
            &sockets,
            &mut mcp.sockets,
            boundary,
            BindingArtifacts {
                assets: &assets,
                public: &public,
            },
            process,
            &cancel,
        )?;
        binding = observed;
        mcp.connect_sdk(&peer, &cancel)?;
        sdk_raw = serve(&sockets, &peer, process, &mut router, &mut plane, &cancel)?;
        budget
            .lock()
            .map_err(|_| "live operation budget poisoned")?
            .verify_completed()?;
        Ok(())
    })();
    let sdk_cleanup = sdk.as_mut().map_or(Ok(()), RootChild::stop);
    let provider_value = provider
        .as_mut()
        .map(NativeLiveProvider::close)
        .unwrap_or_else(
            || json!({"ledger":null,"provider_turns":[],"error":"live provider did not start"}),
        );
    let bridge_cleanup = bridge.as_mut().map_or(Ok(()), RootChild::stop);
    let mcp_cleanup = mcp.close(attempted.is_err());
    let agent_cleanup = agent.as_mut().map_or(Ok(()), NativeSdkAgent::close);
    let socket_cleanup = sockets.close();
    let cell_cleanup = plane.close();
    let mcp_value = mcp.observation();
    let budget_value = budget
        .lock()
        .map(|b| b.observation())
        .unwrap_or(Value::Null);
    let public_after = public.verify();
    let assets_after = assets.verify_after_cleanup();
    let null_after = host_null.recheck();
    let prefix_after =
        gauntlet_evidence::inventory_tree(&prefix, gauntlet_evidence::TreeKind::InstalledPrefix)
            .map_err(|e| e.to_string());
    let prefix_unchanged = prefix_after
        .as_ref()
        .is_ok_and(|t| t.digest == preparation.runtime_tree_digest);
    let artifact_hashes = crate::native_live_artifacts::retain(
        job,
        live,
        &sdk_raw,
        mcp_value.as_ref().unwrap_or(&Value::Null),
        &provider_value,
        &budget_value,
    );
    let model_requests = provider_value["ledger"]["turns_consumed"]
        .as_u64()
        .unwrap_or(0);
    let complete = attempted.is_ok()
        && [
            sdk_cleanup.is_ok(),
            bridge_cleanup.is_ok(),
            mcp_cleanup.is_ok(),
            agent_cleanup.is_ok(),
            socket_cleanup.is_ok(),
            cell_cleanup.is_ok(),
            mcp_value.is_ok(),
            public_after.is_ok(),
            assets_after.is_ok(),
            null_after.is_ok(),
            artifact_hashes.is_ok(),
            prefix_unchanged,
        ]
        .into_iter()
        .all(|v| v)
        && provider_value["error"].is_null()
        && provider_value["ledger"]["pending_turn"].is_null()
        && provider_value["ledger"]["turns"]
            .as_array()
            .is_some_and(|a| a.iter().all(|t| t["delivered_to_sdk"] == true))
        && provider_value["ledger"]["turns_completed"].as_u64() == Some(model_requests)
        && model_requests > 0;
    let error=(!complete).then(||"live OMP execution or retained observation did not complete; private artifacts preserve the attempt".to_owned());
    let (artifact_hashes, context_sha256) = artifact_hashes
        .map(|a| (a.hashes, json!(a.context_sha256)))
        .unwrap_or_else(|_| (json!({}), Value::Null));
    let report = json!({"schema":"hol-gauntlet-native-live-omp.v1","job_id":job.job_id,"preparation_sha256":job.preparation_sha256,
        "control_role":live.role(),"cell_id":live.cell_id,"spec_sha256":live.spec_sha256,"guard_pins":pins.to_json(),"sdk_pins":sdk_pins.to_json(),
        "model_requests":model_requests,"artifact_sha256":artifact_hashes,"context_sha256":context_sha256,"pre_import_binding_sha256":crate::native_live_model::sha(&gauntlet_contracts::canonicalize(binding.to_string().as_bytes()).map_err(|e|e.to_string())?),
        "status":if complete{"passed"}else{"failed"},"error":error,"qualified_role_complete":false,"execution_eligible":false,"guard_causality_verified":false});
    Ok(NativeApparatusReport { report, error })
}
