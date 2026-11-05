//! Live Rust-owned SDK/Bash diagnostic. This v1 SDK profile deliberately has
//! no MCP, model requests, host signing key, or Guard-causality eligibility.
use crate::native_sdk_agent::NativeSdkAgent;
use crate::native_sdk_process::RootChild;
use crate::native_sdk_public::{NativeSdkPublic, PROMPT};
use crate::native_sdk_router::NativeSdkRouter;
use crate::{
    read_native_sdk_line, write_native_sdk_line, NativeJobSpec, NativeSdkBoundary, NativeSdkPeer,
    NativeSdkPins, NativeSdkRequest, NativeSdkSockets, VerifiedNativeSdkAssets,
};
use gauntlet_cell_rootfs::{NativeApparatusReport, NativeGuardPins, NativeHookPlane};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::Shutdown;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

fn paused(cancel: &AtomicBool, deadline: Instant) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err("SDK control cancelled or timed out".into());
    }
    std::thread::sleep(Duration::from_millis(10));
    Ok(())
}
pub(crate) fn same_uid_negative(
    agent: &mut NativeSdkAgent,
    sockets: &NativeSdkSockets,
    peer: &NativeSdkPeer,
    cgroup: &str,
    cancel: &AtomicBool,
) -> Result<Value, String> {
    let mut probe = agent.launch_peer_probe()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let rejected = loop {
        if let Some(stream) = sockets.accept_hook()? {
            let (pin, held) = crate::observe_sdk_relay_peer_in_cgroup_ineligible(&stream, cgroup)?;
            if peer.authenticate(&stream, false).is_ok() {
                return Err("unrelated same-UID peer authenticated as SDK".into());
            }
            held.recheck(&stream)?;
            let observed = held.observation().to_json();
            let _ = stream.shutdown(Shutdown::Both);
            drop(stream);
            break json!({"kernel_peer":observed,"pid":pin.pid,"rejected":true});
        }
        if probe.poll()?.is_some() {
            return Err("same-UID probe exited before outside rejection".into());
        }
        paused(cancel, deadline)?;
    };
    let output = loop {
        if let Some(output) = probe.poll()? {
            break output;
        }
        paused(cancel, deadline)?;
    };
    let result: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "SDK same-UID probe JSON")?;
    if !output.status.success()
        || result["schema"] != "sdk-same-uid-peer-control.v1"
        || result["uid"] != 10001
        || result["denied"] != true
    {
        return Err("SDK same-UID negative control failed".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-native-sdk-same-uid-negative.v1","outside":rejected,
        "unprivileged_result":result,"refused_before_sdk_import":true,"execution_eligible":false}),
    )
}
fn bind(
    agent: &mut NativeSdkAgent,
    sockets: &NativeSdkSockets,
    boundary: NativeSdkBoundary,
    assets: &VerifiedNativeSdkAssets,
    public: &NativeSdkPublic,
    sdk: &mut RootChild,
    cancel: &AtomicBool,
) -> Result<(NativeSdkPeer, Value), String> {
    let cgroup = boundary.observation()["identity"]["cgroup"]
        .as_str()
        .ok_or("SDK boundary cgroup missing")?
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut gate = loop {
        if let Some(gate) = sockets.accept_gate()? {
            break gate;
        }
        if sdk.poll()?.is_some() {
            return Err("SDK exited before pre-import binding".into());
        }
        paused(cancel, deadline)?;
    };
    if read_native_sdk_line(&mut gate, 128, deadline, cancel)? != b"developer-sdk-ready.v1" {
        return Err("SDK ready handshake differs".into());
    }
    let mut response = gate.try_clone().map_err(|e| e.to_string())?;
    let peer = NativeSdkPeer::bind(gate, boundary, assets.bun(), &assets.pins().bun_sha256)?;
    public.verify()?;
    assets.recheck_custody()?;
    let negative = same_uid_negative(agent, sockets, &peer, &cgroup, cancel)?;
    peer.recheck()?;
    write_native_sdk_line(&mut response, b"developer-sdk-bound.v1", deadline, cancel)?;
    let joined = json!({"schema":"hol-gauntlet-native-sdk-pre-import-binding.v1","peer":peer.observation(),
        "public_helpers":public.observation(),"assets":assets.observation(),"same_uid_negative":negative,
        "entrypoint_bytes_verified":true,"readonly_mounts_verified":true,"sdk_source_pinned":true,
        "bound_before_sdk_import":true,"guard_causality_verified":false,"execution_eligible":false});
    Ok((peer, joined))
}
pub(crate) fn serve(
    sockets: &NativeSdkSockets,
    peer: &NativeSdkPeer,
    sdk: &mut RootChild,
    router: &mut NativeSdkRouter,
    plane: &mut NativeHookPlane,
    cancel: &AtomicBool,
    requests: &mut Vec<Value>,
) -> Result<Value, String> {
    let deadline = Instant::now() + Duration::from_secs(130);
    let mut accepted = 0;
    loop {
        if let Some(mut stream) = sockets.accept_hook()? {
            accepted += 1;
            if accepted > 16 {
                return Err("SDK connection budget exhausted".into());
            }
            let raw = read_native_sdk_line(
                &mut stream,
                1024 * 1024,
                deadline.min(Instant::now() + Duration::from_secs(5)),
                cancel,
            )?;
            let request = NativeSdkRequest::parse(&raw)?;
            let identity =
                peer.authenticate(&stream, matches!(request, NativeSdkRequest::Execute { .. }))?;
            let observation = identity.observation();
            let index = requests.len();
            requests.push(json!({"schema":"hol-gauntlet-native-sdk-request-capture.v2",
                "sequence":accepted,"request_sha256":format!("{:x}",Sha256::digest(&raw)),
                "request_wire_utf8":std::str::from_utf8(&raw).map_err(|_|"SDK retained request UTF-8")?,
                "request":serde_json::from_slice::<Value>(&raw).map_err(|_|"SDK retained request JSON")?,
                "peer":observation,"peer_rechecked_before_response":false,"product_claims_authenticated":false}));
            let response = match router.handle(&request, plane) {
                Ok(response) => response,
                Err(error) => {
                    requests[index]["dispatch_error"] = json!(error);
                    return Err(error);
                }
            };
            identity.recheck(&stream)?;
            let response = gauntlet_contracts::canonicalize(response.to_string().as_bytes())
                .map_err(|e| e.to_string())?;
            write_native_sdk_line(&mut stream, &response, deadline, cancel)?;
            requests[index]["response_sha256"] = json!(format!("{:x}", Sha256::digest(&response)));
            requests[index]["response_wire_utf8"] =
                json!(std::str::from_utf8(&response).map_err(|_| "SDK retained response UTF-8")?);
            requests[index]["response"] = serde_json::from_slice::<Value>(&response)
                .map_err(|_| "SDK retained response JSON")?;
            requests[index]["peer_rechecked_before_response"] = json!(true);
        }
        if let Some(output) = sdk.poll()? {
            let result = serde_json::from_slice::<Value>(&output.stdout).ok();
            let observation = json!({"exit_code":output.status.code(),"stdout_sha256":format!("{:x}",Sha256::digest(&output.stdout)),
                "stderr_sha256":format!("{:x}",Sha256::digest(&output.stderr)),"stderr":String::from_utf8_lossy(&output.stderr),"result":result});
            if !output.status.success() {
                return Err(format!("SDK process failed: {observation}"));
            }
            return Ok(observation);
        }
        paused(cancel, deadline)?;
    }
}
fn verify_result(sdk: &Value, router: &NativeSdkRouter) -> Result<(), String> {
    router.verify_completed()?;
    let event = router
        .events
        .iter()
        .find(|v| v["kind"] == "sdk-contained-completed")
        .ok_or("SDK Root capture absent")?;
    crate::native_sdk_result::verify(sdk, &event["output"])
}
pub(crate) fn run_native_sdk_transport(
    job: &NativeJobSpec,
    pins: &NativeGuardPins,
    sdk_pins: &NativeSdkPins,
    cancelled: Arc<AtomicBool>,
) -> Result<NativeApparatusReport, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    let host_null = crate::native_sdk_host_device::NativeSdkHostNull::open()?;
    let declaration = job.preparation_path();
    let root =
        crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
    let raw = crate::read_bounded_regular(&root, "preparation.v1.json", 49152)
        .map_err(|e| e.to_string())?
        .ok_or("SDK preparation absent")?;
    let preparation = job.preparation(&raw)?;
    let assets = VerifiedNativeSdkAssets::load(sdk_pins)?;
    let fixture = gauntlet_cell_rootfs::seed_native_sdk_fixture(&preparation)?;
    let public = NativeSdkPublic::prepare(&job.job_root())?;
    let mut sockets = NativeSdkSockets::new(&job.job_id)?;
    let cell = gauntlet_cell_rootfs::prepare_and_start(
        &declaration,
        &job.preparation_sha256,
        cancelled.clone(),
    )?;
    let prefix = cell.runtime_prefix().to_owned();
    let actor = cell
        .actor_observation()
        .cloned()
        .ok_or("SDK product actor unavailable")?;
    let mut plane = NativeHookPlane::new(
        cell,
        pins.clone(),
        &format!("gauntlet-native-sdk-{}", job.job_id),
    )?;
    let mut agent = None;
    let mut sdk = None;
    let mut router = NativeSdkRouter::new()?;
    let mut requests = Vec::new();
    let mut measurements = serde_json::Map::new();
    let attempted = (|| {
        plane.start()?;
        let prompt = plane.submit_prompt(PROMPT)?;
        measurements.insert("prompt".into(), prompt.clone());
        if prompt["decision"] != "allow" {
            return Err("actual Native prompt did not allow SDK setup".into());
        }
        let owner = NativeSdkAgent::prepare(&job.job_id, &preparation, &assets, &sockets, &public)?;
        agent = Some(owner);
        let owner = agent.as_mut().unwrap();
        let boundary = owner.launch(&assets, &public, &actor, &cancelled)?;
        sdk = Some(owner.launch_sdk(&cancelled)?);
        let process = sdk.as_mut().unwrap();
        let (peer, binding) = bind(
            owner, &sockets, boundary, &assets, &public, process, &cancelled,
        )?;
        measurements.insert("pre_import_binding".into(), binding);
        let result = serve(
            &sockets,
            &peer,
            process,
            &mut router,
            &mut plane,
            &cancelled,
            &mut requests,
        )?;
        measurements.insert("sdk".into(), result.clone());
        verify_result(&result, &router)?;
        measurements.insert("replay_refusals".into(), router.refuse_replays(&mut plane)?);
        Ok::<(), String>(())
    })();
    let sdk_cleanup = sdk.as_mut().map_or(Ok(()), RootChild::stop);
    let agent_cleanup = agent.as_mut().map_or(Ok(()), NativeSdkAgent::close);
    let socket_cleanup = sockets.close();
    let cell_cleanup = plane.close();
    let public_after = public.verify();
    let assets_after = assets.verify_after_cleanup();
    let host_null_after = host_null.recheck();
    let tree =
        gauntlet_evidence::inventory_tree(&prefix, gauntlet_evidence::TreeKind::InstalledPrefix)
            .map_err(|e| e.to_string());
    let prefix_unchanged = tree
        .as_ref()
        .is_ok_and(|t| t.digest == preparation.runtime_tree_digest);
    let effect = if cell_cleanup.is_ok() && agent_cleanup.is_ok() {
        gauntlet_cell_rootfs::read_native_hook_fixture_effect(&preparation)
    } else {
        Err("effect readback requires drained product and agent".into())
    };
    let sdk_exercised = measurements
        .get("sdk")
        .is_some_and(|v| verify_result(v, &router).is_ok());
    let errors = [
        sdk_cleanup.as_ref().err(),
        agent_cleanup.as_ref().err(),
        socket_cleanup.as_ref().err(),
        cell_cleanup.as_ref().err(),
        public_after.as_ref().err(),
        assets_after.as_ref().err(),
        host_null_after.as_ref().err(),
        effect.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect::<Vec<_>>();
    let error = attempted
        .err()
        .or_else(|| errors.first().cloned())
        .or_else(|| (!prefix_unchanged).then(|| "SDK runtime prefix changed after cleanup".into()));
    let report = json!({"schema":"hol-gauntlet-native-sdk-transport.v1","status":if error.is_none(){"passed"}else{"failed"},"error":error,
        "job_id":job.job_id,"preparation_sha256":job.preparation_sha256,"guard_pins":pins.to_json(),"sdk_pins":sdk_pins.to_json(),
        "fixture":fixture,"actor":actor,"measurements":measurements,"requests":requests,"router":router.observation(),
        "plane":plane.observation(),"agent":agent.as_ref().map(NativeSdkAgent::observation),"sockets":sockets.observation(),
        "public_helpers":public.observation(),"assets":assets.observation(),"effect":effect.as_ref().ok(),
        "host_null_before":host_null.before(),"host_null_after":host_null_after.as_ref().ok(),
        "host_null_check":"identity-and-permissions-v1","host_null_identity_unchanged":host_null_after.is_ok(),
        "host_null_timestamps_changed":host_null_after.as_ref().ok().map(|now|now != &host_null.before()),
        "prefix_unchanged":prefix_unchanged,"prefix_tree_sha256":tree.as_ref().ok().map(|t|&t.digest),
        "sdk_cleanup_complete":sdk_cleanup.is_ok(),"agent_cleanup_complete":agent_cleanup.is_ok(),
        "cell_cleanup_complete":cell_cleanup.is_ok(),"cleanup_errors":errors,"public_helpers_unchanged":public_after.is_ok(),
        "sdk_assets_unchanged":assets_after.is_ok(),"sdk_exercised":sdk_exercised,"mcp_exercised":false,
        "guard_causality_verified":false,"artifact_admitted":false,"execution_eligible":false,"model_requests":0,
        "unavailable_reason":"Bash-only actual SDK transport diagnostic; MCP, independent request/decision/effect scoring, six-role conformance and host signing-key admission remain open"});
    Ok(NativeApparatusReport { report, error })
}
