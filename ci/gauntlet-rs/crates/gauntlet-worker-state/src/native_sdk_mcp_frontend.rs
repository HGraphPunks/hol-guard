//! Actual SDK relay -> normal Native proxy, with one-use Root operation
//! reservations. Retain original frames even if a later forwarding step fails.
use crate::native_operation_budget::NativeOperationBudget;
use crate::{NativeMcpProcess, NativeMcpProxyClient, NativeSdkMcpPeer};
use gauntlet_mcp_service::{Family, McpStream};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

pub(crate) struct Frontend {
    pub socket: UnixStream,
    pub peer: NativeSdkMcpPeer,
    pub client: NativeMcpProxyClient,
    pub proxy: NativeMcpProcess,
    pub family: Family,
    pub budget: Arc<Mutex<NativeOperationBudget>>,
    pub closing: Arc<AtomicBool>,
    pub cancel: Arc<AtomicBool>,
}
fn retain(frames: &mut Vec<Value>, direction: &str, raw: &[u8]) -> Result<Value, String> {
    let canonical = gauntlet_contracts::canonicalize(raw).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| "SDK MCP frame JSON")?;
    frames.push(json!({"sequence":frames.len()+1,"direction":direction,
        "wire_utf8":std::str::from_utf8(raw).map_err(|_|"SDK MCP frame UTF-8")?,
        "sha256":format!("{:x}",Sha256::digest(raw)),"frame":value,"forwarded":false}));
    Ok(value)
}
impl Frontend {
    pub(crate) fn serve(mut self) -> Result<Value, String> {
        let mut stream = McpStream::new(self.socket).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(160);
        let mut frames = Vec::new();
        let mut completion = Value::Null;
        let attempted = (|| -> Result<(), String> {
            loop {
                // Idle/EOF is not authority. Authenticate each actual frame
                // before reserving budget or writing any byte to Native.
                let Some(raw) = stream
                    .read_frame(deadline, &self.cancel)
                    .map_err(|e| e.to_string())?
                else {
                    break;
                };
                let request = retain(&mut frames, "sdk-request", &raw)?;
                self.peer.recheck(stream.socket())?;
                self.proxy.recheck()?;
                let permit = self
                    .budget
                    .lock()
                    .map_err(|_| "SDK MCP budget poisoned")?
                    .reserve_mcp(self.family, &raw)?;
                self.client.write_frame(&raw, deadline, &self.cancel)?;
                frames.last_mut().unwrap()["forwarded"] = json!(true);
                if request.get("id").is_none() {
                    continue;
                }
                loop {
                    let raw = self
                        .client
                        .read_frame(deadline, &self.cancel)?
                        .ok_or("Native MCP ended before SDK response")?;
                    let response = retain(&mut frames, "native-response", &raw)?;
                    self.peer.recheck(stream.socket())?;
                    self.proxy.recheck()?;
                    let matching = response.get("id") == request.get("id");
                    if matching {
                        if response["jsonrpc"] != "2.0"
                            || response.get("result").is_some() == response.get("error").is_some()
                        {
                            return Err(
                                "Native response does not have a unique result/error".into()
                            );
                        }
                        if let Some(sequence) = permit {
                            self.budget
                                .lock()
                                .map_err(|_| "SDK MCP budget poisoned")?
                                .complete_mcp(self.family, sequence, &raw)?;
                        }
                    } else if response.get("id").is_some() || !response["method"].is_string() {
                        return Err(
                            "unsolicited Native MCP response/request cannot be attributed to SDK"
                                .into(),
                        );
                    }
                    stream
                        .write_frame(&raw, deadline, &self.cancel)
                        .map_err(|e| e.to_string())?;
                    self.peer.recheck(stream.socket())?;
                    frames.last_mut().unwrap()["forwarded"] = json!(true);
                    if matching {
                        break;
                    }
                }
            }
            self.proxy.recheck()?;
            completion = self
                .client
                .finish(Instant::now() + Duration::from_secs(10), &self.cancel)?;
            if completion["exit_code"] != 0 {
                return Err("Native proxy failed after SDK disconnect".into());
            }
            self.closing.store(true, Ordering::Release);
            Ok(())
        })();
        let cleanup = self.client.close();
        let error = attempted.err().or_else(|| cleanup.err());
        Ok(
            json!({"schema":"hol-gauntlet-native-sdk-mcp-frontend.v1","family":self.family.name(),
            "status":if error.is_none(){"passed"}else{"failed"},"error":error,"peer":self.peer.observation(),
            "frames":frames,"completion":completion,"client":self.client.observation(),
            "sdk_ancestry_rechecked_per_frame":true,"guard_causality_verified":false,"execution_eligible":false,"model_requests":0}),
        )
    }
}
