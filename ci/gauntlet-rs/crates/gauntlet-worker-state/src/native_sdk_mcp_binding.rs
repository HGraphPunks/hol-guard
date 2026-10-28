//! Bind the actual SDK before import, including both hook and MCP same-UID
//! negative controls. No MCP bytes reach Native during these controls.
use crate::native_sdk_agent::NativeSdkAgent;
use crate::native_sdk_process::RootChild;
use crate::native_sdk_public::NativeSdkPublic;
use crate::{
    read_native_sdk_line, write_native_sdk_line, NativeMcpSockets, NativeSdkBoundary,
    NativeSdkPeer, NativeSdkSockets, VerifiedNativeSdkAssets,
};
use gauntlet_mcp_service::Family;
use serde_json::{json, Value};
use std::{
    net::Shutdown,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub(crate) struct BindingArtifacts<'a> {
    pub assets: &'a VerifiedNativeSdkAssets,
    pub public: &'a NativeSdkPublic,
}
fn pause(deadline: Instant, cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err("SDK MCP binding deadline/cancel".into());
    }
    std::thread::sleep(Duration::from_millis(10));
    Ok(())
}
fn mcp_negative(
    agent: &mut NativeSdkAgent,
    sockets: &mut NativeMcpSockets,
    peer: &Arc<NativeSdkPeer>,
    cgroup: &str,
    cancel: &AtomicBool,
) -> Result<Value, String> {
    let mut probe = agent.launch_mcp_peer_probe()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let rejected = loop {
        if let Some(stream) = sockets.accept_resource(Family::Docs)? {
            let (pin, held) = crate::observe_sdk_relay_peer_in_cgroup_ineligible(&stream, cgroup)?;
            if peer.authenticate_mcp(&stream, Family::Docs).is_ok() {
                return Err("unrelated same-UID MCP peer authenticated as SDK".into());
            }
            held.recheck(&stream)?;
            let observation = held.observation().to_json();
            stream.shutdown(Shutdown::Both).map_err(|e| e.to_string())?;
            break json!({"pid":pin.pid,"kernel_peer":observation,"rejected_before_native_forward":true});
        }
        if probe.poll()?.is_some() {
            return Err("MCP same-UID probe exited before outside refusal".into());
        }
        pause(deadline, cancel)?;
    };
    let output = loop {
        if let Some(output) = probe.poll()? {
            break output;
        }
        pause(deadline, cancel)?;
    };
    let result: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "MCP peer control JSON")?;
    if !output.status.success()
        || result["schema"] != "sdk-mcp-same-uid-peer-control.v1"
        || result["uid"] != 10001
        || result["denied"] != true
        || result["model_requests"] != 0
    {
        return Err("MCP peer control did not observe refusal".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-native-sdk-mcp-same-uid-negative.v1","outside":rejected,
        "unprivileged_result":result,"refused_before_sdk_import":true,"execution_eligible":false}),
    )
}
pub(crate) fn bind(
    agent: &mut NativeSdkAgent,
    sdk_sockets: &NativeSdkSockets,
    mcp_sockets: &mut NativeMcpSockets,
    boundary: NativeSdkBoundary,
    artifacts: BindingArtifacts<'_>,
    sdk: &mut RootChild,
    cancel: &AtomicBool,
) -> Result<(Arc<NativeSdkPeer>, Value), String> {
    let cgroup = boundary.observation()["identity"]["cgroup"]
        .as_str()
        .ok_or("SDK cgroup missing")?
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut gate = loop {
        if let Some(stream) = sdk_sockets.accept_gate()? {
            break stream;
        }
        if sdk.poll()?.is_some() {
            return Err("SDK exited before MCP pre-import binding".into());
        }
        pause(deadline, cancel)?;
    };
    if read_native_sdk_line(&mut gate, 128, deadline, cancel)? != b"developer-sdk-ready.v1" {
        return Err("SDK ready handshake differs".into());
    }
    let mut reply = gate.try_clone().map_err(|e| e.to_string())?;
    let peer = Arc::new(NativeSdkPeer::bind(
        gate,
        boundary,
        artifacts.assets.bun(),
        &artifacts.assets.pins().bun_sha256,
    )?);
    artifacts.public.verify()?;
    artifacts.assets.recheck_custody()?;
    let hook_negative =
        crate::native_sdk_control::same_uid_negative(agent, sdk_sockets, &peer, &cgroup, cancel)?;
    let mcp_negative = mcp_negative(agent, mcp_sockets, &peer, &cgroup, cancel)?;
    peer.recheck()?;
    write_native_sdk_line(&mut reply, b"developer-sdk-bound.v1", deadline, cancel)?;
    let observation = json!({"schema":"hol-gauntlet-native-sdk-pre-import-binding.v2","peer":peer.observation(),
        "public_helpers":artifacts.public.observation(),"assets":artifacts.assets.observation(),
        "same_uid_negative":hook_negative,"mcp_same_uid_negative":mcp_negative,
        "entrypoint_bytes_verified":true,"readonly_mounts_verified":true,"sdk_source_pinned":true,
        "bound_before_sdk_import":true,"guard_causality_verified":false,"execution_eligible":false});
    Ok((peer, observation))
}
