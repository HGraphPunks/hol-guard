//! Bind one real Native CLI proxy and its independently measured resident
//! relay. A successful transport binding is not a Guard decision.
use crate::{
    read_native_sdk_line, write_native_sdk_line, NativeMcpAgent, NativeMcpBoundary,
    NativeMcpProcess, NativeMcpProxyClient, NativeMcpSockets,
};
use gauntlet_mcp_service::Family;
use serde_json::{json, Value};
use std::{
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub(crate) struct NativeMcpRoute {
    pub client: NativeMcpProxyClient,
    pub process: NativeMcpProcess,
    pub upstream: UnixStream,
    pub relay: NativeMcpProcess,
    pub observation: Value,
}
pub(crate) fn pause(deadline: Instant, cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err("Native MCP binding deadline/cancel".into());
    }
    std::thread::sleep(Duration::from_millis(10));
    Ok(())
}
pub(crate) fn bind(
    owner: &mut NativeMcpAgent,
    sockets: &mut NativeMcpSockets,
    boundary: Arc<NativeMcpBoundary>,
    family: Family,
    cancel: &AtomicBool,
) -> Result<NativeMcpRoute, String> {
    let mut client = owner.launch_proxy(family, cancel)?;
    let deadline = Instant::now() + Duration::from_secs(35);
    let mut gate = loop {
        if let Some(stream) = sockets.accept_gate()? {
            break stream;
        }
        if client.poll()?.is_some() {
            return Err("Native proxy exited before Root binding".into());
        }
        pause(deadline, cancel)?;
    };
    if read_native_sdk_line(&mut gate, 128, deadline, cancel)?
        != format!("native-mcp-proxy-ready.v1 {}", family.name()).as_bytes()
    {
        return Err("Native MCP proxy gate differs".into());
    }
    let python = boundary.python()?;
    let mut reply = gate.try_clone().map_err(|e| e.to_string())?;
    let mut process = NativeMcpProcess::bind(
        gate,
        boundary.clone(),
        &python,
        &owner.bootstrap_argv(family),
    )?;
    let bootstrap = process.observation();
    write_native_sdk_line(&mut reply, b"native-mcp-proxy-bound.v1", deadline, cancel)?;
    while process.observe_exec(&owner.proxy_argv(family)).is_err() {
        pause(deadline, cancel)?;
    }
    let native_proxy = process.observation();
    let stream = loop {
        if let Some(stream) = sockets.accept_upstream(family)? {
            break stream;
        }
        if client.poll()?.is_some() {
            return Err("Native proxy exited before upstream connection".into());
        }
        process.recheck()?;
        pause(deadline, cancel)?;
    };
    let relay_args = vec![
        "/usr/bin/python3.12".into(),
        "/product/public/service_relay.py".into(),
        "--socket".into(),
        format!("/upstream/{}.sock", family.name()),
    ];
    let relay = NativeMcpProcess::bind(
        stream.try_clone().map_err(|e| e.to_string())?,
        boundary,
        &python,
        &relay_args,
    )?;
    Ok(NativeMcpRoute {
        client,
        process,
        upstream: stream,
        relay,
        observation: json!({"family":family.name(),
        "bootstrap":bootstrap,"native_proxy":native_proxy,"relay_proxy_ancestry_verified":false}),
    })
}
