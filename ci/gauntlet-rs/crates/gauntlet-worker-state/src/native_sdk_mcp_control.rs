//! Actual locked SDK, Native MCP proxies, Root SQLite provider and Bash plane.
//! Synthetic stream only; independent qualification and host-key admission open.
use crate::native_operation_budget::NativeOperationBudget;
use crate::native_sdk_agent::NativeSdkAgent;
use crate::native_sdk_mcp_binding::{bind, BindingArtifacts};
use crate::native_sdk_mcp_plane::NativeSdkMcpPlane;
use crate::native_sdk_process::RootChild;
use crate::native_sdk_public::{NativeSdkPublic, PROMPT};
use crate::native_sdk_router::NativeSdkRouter;
use crate::{NativeJobSpec, NativeSdkPins, NativeSdkSockets, VerifiedNativeSdkAssets};
use gauntlet_cell_rootfs::{
    NativeApparatusReport, NativeControlRole, NativeGuardPins, NativeHookPlane,
};
use serde_json::{json, Value};
use std::sync::{atomic::AtomicBool, Arc, Mutex};

pub(crate) fn run(
    job: &NativeJobSpec,
    pins: &NativeGuardPins,
    sdk_pins: &NativeSdkPins,
    cancel: Arc<AtomicBool>,
) -> Result<NativeApparatusReport, String> {
    run_profile(job, pins, sdk_pins, cancel, None)
}
pub(crate) fn run_role(
    job: &NativeJobSpec,
    pins: &NativeGuardPins,
    sdk_pins: &NativeSdkPins,
    cancel: Arc<AtomicBool>,
    role: NativeControlRole,
) -> Result<NativeApparatusReport, String> {
    run_profile(job, pins, sdk_pins, cancel, Some(role))
}
fn run_profile(
    job: &NativeJobSpec,
    pins: &NativeGuardPins,
    sdk_pins: &NativeSdkPins,
    cancel: Arc<AtomicBool>,
    role: Option<NativeControlRole>,
) -> Result<NativeApparatusReport, String> {
    if role.is_some_and(|r| {
        !matches!(
            r,
            NativeControlRole::Success | NativeControlRole::InputBinding
        )
    }) {
        return Err("Native deterministic role implementation remains incomplete".into());
    }
    gauntlet_cell_rootfs::require_outside_root()?;
    let host_null = crate::native_sdk_host_device::NativeSdkHostNull::open()?;
    let root =
        crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
    let raw = crate::read_bounded_regular(&root, "preparation.v1.json", 49152)
        .map_err(|e| e.to_string())?
        .ok_or("composed SDK preparation missing")?;
    let preparation = job.preparation(&raw)?;
    let assets = VerifiedNativeSdkAssets::load(sdk_pins)?;
    let fixture = if role.is_some() {
        gauntlet_cell_rootfs::seed_native_control_fixture(&preparation)?
    } else {
        gauntlet_cell_rootfs::seed_native_sdk_fixture(&preparation)?
    };
    let public = NativeSdkPublic::prepare_mcp(&job.job_root())?;
    let mut sockets = NativeSdkSockets::new(&job.job_id)?;
    let budget = Arc::new(Mutex::new(NativeOperationBudget::new(4)?));
    let mut mcp = NativeSdkMcpPlane::prepare(job, budget.clone())?;
    let cell = gauntlet_cell_rootfs::prepare_and_start(
        &job.preparation_path(),
        &job.preparation_sha256,
        cancel.clone(),
    )?;
    let prefix = cell.runtime_prefix().to_owned();
    let actor = cell
        .actor_observation()
        .cloned()
        .ok_or("SDK product actor missing")?;
    let mut plane = NativeHookPlane::new(
        cell,
        pins.clone(),
        &format!("gauntlet-native-sdk-mcp-{}", job.job_id),
    )?;
    let mut router = NativeSdkRouter::with_budget(budget.clone())?;
    let mut agent = None;
    let mut sdk = None;
    let mut requests = Vec::new();
    let mut measurements = serde_json::Map::new();
    let attempted = (|| -> Result<(), String> {
        plane.start()?;
        let prompt = plane.submit_prompt(PROMPT)?;
        measurements.insert("prompt".into(), prompt.clone());
        if prompt["decision"] != "allow" {
            return Err("Native prompt did not allow composed SDK setup".into());
        }
        mcp.start(job, &preparation, pins, &actor, &cancel)?;
        agent = Some(NativeSdkAgent::prepare_mcp(
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
        sdk = Some(owner.launch_sdk(&cancel)?);
        let process = sdk.as_mut().unwrap();
        let (peer, binding) = bind(
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
        measurements.insert("pre_import_binding".into(), binding);
        mcp.connect_sdk(&peer, &cancel)?;
        let result = crate::native_sdk_control::serve(
            &sockets,
            &peer,
            process,
            &mut router,
            &mut plane,
            &cancel,
            &mut requests,
        )?;
        measurements.insert("sdk".into(), result);
        router.verify_completed()?;
        measurements.insert("replay_refusals".into(), router.refuse_replays(&mut plane)?);
        if role == Some(NativeControlRole::InputBinding) {
            let binding = plane.probe_input_bindings()?;
            let passed = binding["status"] == "passed";
            measurements.insert("request_binding_controls".into(), binding);
            if !passed {
                return Err("actual Native request-binding control failed".into());
            }
            let forbidden = plane.probe_forbidden_command()?;
            let passed = forbidden["status"] == "passed";
            measurements.insert("forbidden_command_control".into(), forbidden);
            if !passed {
                return Err("actual Native forbidden-command control failed".into());
            }
        }
        Ok(())
    })();
    let sdk_cleanup = sdk.as_mut().map_or(Ok(()), RootChild::stop);
    let mcp_cleanup = mcp.close(attempted.is_err());
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
    let effect = if cell_cleanup.is_ok() && agent_cleanup.is_ok() && mcp_cleanup.is_ok() {
        gauntlet_cell_rootfs::read_native_hook_fixture_effect(&preparation)
    } else {
        Err("effect readback requires drained product, SDK and MCP".into())
    };
    let budget_complete = budget
        .lock()
        .map_err(|_| "final SDK budget poisoned")?
        .verify_completed();
    let budget_observation = budget
        .lock()
        .map_err(|_| "final SDK budget poisoned")?
        .observation();
    let mcp_observation = mcp.observation()?;
    let sdk_result = measurements.get("sdk").cloned().unwrap_or(Value::Null);
    let joined = crate::native_sdk_mcp_result::verify(
        &sdk_result,
        &router,
        &mcp_observation,
        &budget_observation,
    );
    let errors = [
        sdk_cleanup.as_ref().err(),
        mcp_cleanup.as_ref().err(),
        agent_cleanup.as_ref().err(),
        socket_cleanup.as_ref().err(),
        cell_cleanup.as_ref().err(),
        public_after.as_ref().err(),
        assets_after.as_ref().err(),
        host_null_after.as_ref().err(),
        effect.as_ref().err(),
        budget_complete.as_ref().err(),
        joined.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect::<Vec<_>>();
    let error = attempted
        .err()
        .or_else(|| errors.first().cloned())
        .or_else(|| (!prefix_unchanged).then(|| "composed SDK runtime prefix changed".into()));
    let mut report = json!({"schema":"hol-gauntlet-native-sdk-mcp-transport.v1","status":if error.is_none(){"passed"}else{"failed"},"error":error,
        "job_id":job.job_id,"preparation_sha256":job.preparation_sha256,"guard_pins":pins.to_json(),"sdk_pins":sdk_pins.to_json(),
        "fixture":fixture,"actor":actor,"measurements":measurements,"requests":requests,"router":router.observation(),
        "plane":plane.observation(),"mcp":mcp_observation,"operation_budget":budget_observation,
        "agent":agent.as_ref().map(NativeSdkAgent::observation),"sockets":sockets.observation(),
        "public_helpers":public.observation(),"assets":assets.observation(),"effect":effect.as_ref().ok(),
        "host_null_before":host_null.before(),"host_null_after":host_null_after.as_ref().ok(),
        "host_null_identity_unchanged":host_null_after.is_ok(),"prefix_unchanged":prefix_unchanged,
        "sdk_cleanup_complete":sdk_cleanup.is_ok(),"agent_cleanup_complete":agent_cleanup.is_ok(),
        "mcp_cleanup_complete":mcp_cleanup.is_ok(),"cell_cleanup_complete":cell_cleanup.is_ok(),"cleanup_errors":errors,
        "public_helpers_unchanged":public_after.is_ok(),"sdk_assets_unchanged":assets_after.is_ok(),
        "sdk_exercised":joined.is_ok(),"mcp_exercised":joined.is_ok(),"combined_budget_verified":budget_complete.is_ok() && joined.is_ok(),
        "guard_causality_verified":false,"artifact_admitted":false,"execution_eligible":false,"model_requests":0,
        "unavailable_reason":"actual SDK/MCP/Bash diagnostic; independent Guard request/decision/effect scoring, six-role conformance and outside signing-key admission remain open"});
    if let Some(role) = role {
        report["schema"] = json!("hol-gauntlet-native-deterministic-control.v1");
        report["control_role"] = json!(role.as_str());
        report["qualified_role_complete"] = json!(false);
    }
    Ok(NativeApparatusReport { report, error })
}
