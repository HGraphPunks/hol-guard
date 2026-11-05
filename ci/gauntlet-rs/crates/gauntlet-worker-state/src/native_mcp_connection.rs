//! Root-owned provider serving over an independently measured product peer.
use crate::native_operation_budget::NativeOperationBudget;
use crate::{NativeMcpProcess, NativeMcpWorld};
use gauntlet_mcp_service::{Family, McpStream, Session};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

pub(crate) enum ConnectionBudget {
    Diagnostic(Arc<AtomicUsize>),
    Sdk(Arc<Mutex<NativeOperationBudget>>),
}
impl ConnectionBudget {
    fn admit(&self, family: Family, raw: &[u8]) -> Result<(), String> {
        match self {
            Self::Diagnostic(counter) => {
                if counter.fetch_add(1, Ordering::AcqRel) >= 4 {
                    return Err("Root upstream operation budget exhausted before dispatch".into());
                }
                Ok(())
            }
            Self::Sdk(ledger) => ledger
                .lock()
                .map_err(|_| "shared SDK operation budget poisoned")?
                .admit_upstream(family, raw),
        }
    }
}
pub(crate) fn serve(
    socket: UnixStream,
    peer: NativeMcpProcess,
    family: Family,
    world: Arc<Mutex<NativeMcpWorld>>,
    budget: ConnectionBudget,
    closing: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
) -> Result<Value, String> {
    let mut stream = McpStream::new(socket).map_err(|e| e.to_string())?;
    let mut session = Session::new(family).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut frames = Vec::new();
    let mut operations = 0;
    let served = (|| -> Result<(), String> {
        loop {
            peer.recheck()?;
            let Some(raw) = stream
                .read_frame(deadline, &cancel)
                .map_err(|e| e.to_string())?
            else {
                break;
            };
            peer.recheck()?;
            let canonical = gauntlet_contracts::canonicalize(&raw).map_err(|e| e.to_string())?;
            let frame: Value =
                serde_json::from_slice(&canonical).map_err(|_| "upstream MCP JSON")?;
            frames.push(json!({"sequence":frames.len()+1,"direction":"request","wire_utf8":std::str::from_utf8(&raw).map_err(|_|"MCP wire UTF-8")?,
            "sha256":format!("{:x}",Sha256::digest(&raw)),"frame":frame}));
            if matches!(
                frame["method"].as_str(),
                Some("tools/call" | "resources/read" | "prompts/get")
            ) {
                budget.admit(family, &raw)?;
                operations += 1;
            }
            let response = {
                let mut world = world.lock().map_err(|_| "MCP world mutex poisoned")?;
                session
                    .process(&raw, &mut *world)
                    .map_err(|e| e.to_string())?
            };
            peer.recheck()?;
            if let Some(response) = response {
                let raw = gauntlet_contracts::canonicalize(response.to_string().as_bytes())
                    .map_err(|e| e.to_string())?;
                stream
                    .write_frame(&raw, deadline, &cancel)
                    .map_err(|e| e.to_string())?;
                peer.recheck()?;
                frames.push(json!({"sequence":frames.len()+1,"direction":"response","wire_utf8":std::str::from_utf8(&raw).map_err(|_|"MCP response UTF-8")?,
                "sha256":format!("{:x}",Sha256::digest(&raw)),"frame":response,"written":true}));
            }
        }
        Ok(())
    })();
    let error = served.err();
    // The owner sets closing only after independently reading the complete
    // expected proxy result. Keep the peer retirement/cancel diagnostic in
    // full; it cannot stand in for the later outside process-drain check.
    let expected_close = closing.load(Ordering::Acquire);
    Ok(
        json!({"schema":"hol-gauntlet-native-mcp-upstream-session.v1","family":family.name(),
        "status":if error.is_some() && !expected_close {"failed"} else {"closed"},
        "peer":peer.observation(),"frames":frames,"operations":operations,
        "shutdown_observation":error,"owner_requested_close":expected_close,
        "shared_upstream_operation_limit":4,"sdk_builtin_budget_composed":matches!(budget,ConnectionBudget::Sdk(_)),
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}
