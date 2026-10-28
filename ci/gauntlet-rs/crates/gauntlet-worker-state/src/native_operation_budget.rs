//! One Root-owned budget and per-family operation handoff. The unprivileged
//! Native plane cannot mint a provider call without its SDK ingress permit.
use gauntlet_mcp_service::Family;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

struct Pending {
    sequence: usize,
    id: Value,
    frame_sha256: String,
    reached: bool,
}
pub(crate) struct NativeOperationBudget {
    limit: usize,
    events: Vec<Value>,
    builtin: BTreeSet<(String, String)>,
    pending: BTreeMap<String, Pending>,
}
fn frame(raw: &[u8]) -> Result<(Value, String), String> {
    if raw.is_empty() || raw.len() > gauntlet_mcp_service::MAX_FRAME_BYTES {
        return Err("bounded MCP operation frame required".into());
    }
    let canonical =
        gauntlet_contracts::canonicalize(raw).map_err(|_| "ambiguous MCP operation frame")?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| "MCP operation JSON")?;
    if value["jsonrpc"] != "2.0" || !value["method"].is_string() {
        return Err("MCP operation envelope differs".into());
    }
    Ok((value, format!("{:x}", Sha256::digest(canonical))))
}
fn counted(value: &Value) -> bool {
    matches!(
        value["method"].as_str(),
        Some("tools/call" | "resources/read" | "prompts/get")
    )
}
fn id(value: &Value) -> Result<Value, String> {
    let id = value.get("id").ok_or("MCP operation requires request ID")?;
    if !id.is_string()
        && id
            .as_number()
            .is_none_or(|n| n.to_string().contains(['.', 'e', 'E']))
    {
        return Err("MCP operation ID must be string or integer literal".into());
    }
    Ok(id.clone())
}
impl NativeOperationBudget {
    pub(crate) fn new(limit: usize) -> Result<Self, String> {
        if !(1..=500).contains(&limit) {
            return Err("bounded shared Root operation limit required".into());
        }
        Ok(Self {
            limit,
            events: Vec::new(),
            builtin: BTreeSet::new(),
            pending: BTreeMap::new(),
        })
    }
    fn consume(&mut self, event: Value) -> Result<usize, String> {
        if self.events.len() >= self.limit {
            return Err(
                "shared SDK builtin/MCP operation budget exhausted before forwarding".into(),
            );
        }
        self.events.push(event);
        Ok(self.events.len())
    }
    pub(crate) fn reserve_builtin(&mut self, session: &str, call: &str) -> Result<(), String> {
        if session.is_empty()
            || call.is_empty()
            || session.len() > 256
            || call.len() > 256
            || self.builtin.contains(&(session.into(), call.into()))
        {
            return Err("fresh bounded SDK builtin identity required".into());
        }
        self.consume(json!({"surface":"builtin","session":session,"call_id":call}))?;
        self.builtin.insert((session.into(), call.into()));
        Ok(())
    }
    pub(crate) fn reserve_mcp(
        &mut self,
        family: Family,
        raw: &[u8],
    ) -> Result<Option<usize>, String> {
        let (value, digest) = frame(raw)?;
        if !counted(&value) {
            return Ok(None);
        }
        let id = id(&value)?;
        let name = family.name();
        if self.pending.contains_key(name) {
            return Err("one in-flight MCP operation per measured route required".into());
        }
        let sequence=self.consume(json!({"surface":"mcp","family":name,"request_id":id,
            "method":value["method"],"frame_sha256":digest,"backend_reached":false,"response_completed":false}))?;
        self.pending.insert(
            name.into(),
            Pending {
                sequence,
                id,
                frame_sha256: digest,
                reached: false,
            },
        );
        Ok(Some(sequence))
    }
    pub(crate) fn admit_upstream(&mut self, family: Family, raw: &[u8]) -> Result<(), String> {
        let (value, digest) = frame(raw)?;
        if !counted(&value) {
            return Ok(());
        }
        let pending = self
            .pending
            .get_mut(family.name())
            .ok_or("Native provider call has no SDK ingress permit")?;
        if pending.reached || id(&value)? != pending.id || digest != pending.frame_sha256 {
            return Err("Native provider call differs from the one-use original SDK frame".into());
        }
        // Consume before dispatch. A storage or transport failure cannot replay.
        pending.reached = true;
        self.events[pending.sequence - 1]["backend_reached"] = json!(true);
        Ok(())
    }
    pub(crate) fn complete_mcp(
        &mut self,
        family: Family,
        sequence: usize,
        raw: &[u8],
    ) -> Result<(), String> {
        let canonical =
            gauntlet_contracts::canonicalize(raw).map_err(|_| "ambiguous Native MCP response")?;
        let response: Value =
            serde_json::from_slice(&canonical).map_err(|_| "Native response JSON")?;
        let pending = self
            .pending
            .get(family.name())
            .ok_or("MCP ingress permit absent at completion")?;
        if pending.sequence != sequence
            || response["jsonrpc"] != "2.0"
            || response.get("id") != Some(&pending.id)
            || (response.get("result").is_some() == response.get("error").is_some())
        {
            return Err("Native MCP response differs from original SDK ingress permit".into());
        }
        self.events[sequence - 1]["response_completed"] = json!(true);
        self.events[sequence - 1]["response_sha256"] =
            json!(format!("{:x}", Sha256::digest(canonical)));
        self.pending.remove(family.name());
        Ok(())
    }
    pub(crate) fn verify_completed(&self) -> Result<(), String> {
        if !self.pending.is_empty() {
            return Err("unresolved SDK MCP ingress permits remain".into());
        }
        Ok(())
    }
    pub(crate) fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-shared-operation-budget.v1","limit":self.limit,"used":self.events.len(),
            "builtin":self.builtin.len(),"mcp":self.events.len()-self.builtin.len(),"events":self.events,
            "pending":self.pending.keys().collect::<Vec<_>>(),"guard_approval_authority":false,"execution_eligible":false})
    }
}

#[cfg(test)]
#[path = "native_operation_budget_tests.rs"]
mod tests;
