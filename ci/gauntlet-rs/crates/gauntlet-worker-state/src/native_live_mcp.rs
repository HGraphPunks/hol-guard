//! Explicit unprotected live baseline over the same signed Root-owned World.
//! It records actual requests/results and never labels the baseline as Guard.
use crate::native_operation_budget::NativeOperationBudget;
use crate::{NativeMcpWorld, NativeSdkMcpPeer};
use gauntlet_mcp_service::{Family, McpStream, Session};
use serde_json::{json, Value};
use std::{
    os::unix::net::UnixStream,
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::{Duration, Instant},
};

pub(crate) fn serve_baseline(
    socket: UnixStream,
    peer: NativeSdkMcpPeer,
    family: Family,
    world: Arc<Mutex<NativeMcpWorld>>,
    budget: Arc<Mutex<NativeOperationBudget>>,
    cancel: Arc<AtomicBool>,
) -> Result<Value, String> {
    let mut stream = McpStream::new(socket).map_err(|e| e.to_string())?;
    let mut session = Session::new(family).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(crate::native_live_spec::ACTIVE_SECONDS);
    let mut frames = Vec::new();
    let attempted = (|| -> Result<(), String> {
        loop {
            let Some(raw) = stream
                .read_frame(deadline, &cancel)
                .map_err(|e| e.to_string())?
            else {
                break;
            };
            peer.recheck(stream.socket())?;
            let value: Value = serde_json::from_slice(
                &gauntlet_contracts::canonicalize(&raw).map_err(|e| e.to_string())?,
            )
            .map_err(|_| "baseline MCP request JSON")?;
            frames.push(json!({"sequence":frames.len()+1,"direction":"sdk-request","sha256":crate::native_live_model::sha(&raw),
                "wire_utf8":std::str::from_utf8(&raw).map_err(|_|"baseline MCP request UTF8")?,"frame":value,"forwarded":false}));
            let permit = {
                let mut ledger = budget
                    .lock()
                    .map_err(|_| "baseline operation budget poisoned")?;
                let permit = ledger.reserve_mcp(family, &raw)?;
                if permit.is_some() {
                    ledger.admit_upstream(family, &raw)?;
                }
                permit
            };
            let response = session
                .process(
                    &raw,
                    &mut *world.lock().map_err(|_| "baseline World poisoned")?,
                )
                .map_err(|e| e.to_string())?;
            frames.last_mut().unwrap()["forwarded"] = json!(true);
            peer.recheck(stream.socket())?;
            if let Some(response) = response {
                let raw = gauntlet_contracts::canonicalize(response.to_string().as_bytes())
                    .map_err(|e| e.to_string())?;
                if let Some(permit) = permit {
                    budget
                        .lock()
                        .map_err(|_| "baseline operation budget poisoned")?
                        .complete_mcp(family, permit, &raw)?;
                }
                stream
                    .write_frame(&raw, deadline, &cancel)
                    .map_err(|e| e.to_string())?;
                peer.recheck(stream.socket())?;
                frames.push(json!({"sequence":frames.len()+1,"direction":"root-world-response","sha256":crate::native_live_model::sha(&raw),
                    "wire_utf8":std::str::from_utf8(&raw).map_err(|_|"baseline MCP response UTF8")?,"frame":response,"written":true}));
            }
        }
        Ok(())
    })();
    let error = attempted.err();
    Ok(
        json!({"schema":"hol-gauntlet-native-live-baseline-mcp.v1","family":family.name(),
        "status":if error.is_none(){"closed"}else{"failed"},"error":error,"peer":peer.observation(),"frames":frames,
        "guard_interposed":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}
