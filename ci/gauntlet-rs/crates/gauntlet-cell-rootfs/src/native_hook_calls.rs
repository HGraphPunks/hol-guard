//! Root's one-use input/output ledger. A route requests Native's normal sink;
//! it never changes a Native denial into an approval.
use crate::Result;
use serde_json::Value;
use std::collections::BTreeMap;

struct Call {
    payload: Value,
    response: Option<Value>,
    sink_used: bool,
    result: Option<Value>,
    post_used: bool,
}

#[derive(Default)]
pub(crate) struct NativeHookCalls {
    calls: BTreeMap<String, Call>,
}

impl NativeHookCalls {
    pub(crate) fn reserve(&mut self, payload: &Value) -> Result<()> {
        let id = payload["tool_call_id"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or("bounded Native tool-call identity required")?;
        if self.calls.len() >= 500
            || self.calls.contains_key(id)
            || payload["hook_event_name"] != "PreToolUse"
            || payload["tool_name"] != "bash"
            || !payload["tool_input"]["command"].is_string()
        {
            return Err("Native Pre input is invalid, duplicate or exhausted".into());
        }
        self.calls.insert(
            id.into(),
            Call {
                payload: payload.clone(),
                response: None,
                sink_used: false,
                result: None,
                post_used: false,
            },
        );
        Ok(())
    }

    pub(crate) fn record_review(&mut self, id: &str, response: &Value) -> Result<()> {
        let call = self
            .calls
            .get_mut(id)
            .ok_or("Native Pre reservation missing")?;
        if call.response.is_some() {
            return Err("Native Pre response is already recorded".into());
        }
        call.response = Some(response.clone());
        Ok(())
    }

    pub(crate) fn begin_sink(&mut self, id: &str) -> Result<Value> {
        let call = self
            .calls
            .get_mut(id)
            .ok_or("Native Pre reservation missing")?;
        let response = call
            .response
            .as_ref()
            .ok_or("actual Native Pre response missing")?;
        if call.sink_used
            || response["decision"] != "deny"
            || response["policy_action"] != "sandbox-required"
            || response["required_execution_profile"] != "workspace-contained-v1"
            || response["observe_mode"] == true
        {
            return Err("Native response does not supply an unused contained route".into());
        }
        // Consume before the native CLI, filesystem handoff or product launch.
        call.sink_used = true;
        Ok(call.payload.clone())
    }

    pub(crate) fn record_sink(&mut self, id: &str, result: &Value) -> Result<()> {
        let call = self
            .calls
            .get_mut(id)
            .ok_or("Native Pre reservation missing")?;
        if !call.sink_used
            || call.result.is_some()
            || result["payload_digest"]
                != crate::hash(
                    &gauntlet_contracts::canonicalize(call.payload.to_string().as_bytes())
                        .map_err(|e| e.to_string())?,
                )
        {
            return Err("contained result lacks its consumed original input".into());
        }
        gauntlet_evidence::captured_contained_output(result).map_err(|e| e.to_string())?;
        call.result = Some(result.clone());
        Ok(())
    }

    pub(crate) fn begin_post(&mut self, id: &str) -> Result<(Value, Value)> {
        let call = self
            .calls
            .get_mut(id)
            .ok_or("Native Pre reservation missing")?;
        if !call.sink_used || call.post_used {
            return Err("Native Post is premature or replayed".into());
        }
        let result = call
            .result
            .as_ref()
            .ok_or("Native Post lacks a captured sink result")?;
        let output =
            gauntlet_evidence::captured_contained_output(result).map_err(|e| e.to_string())?;
        let mut payload = call.payload.clone();
        payload["hook_event_name"] = Value::String("PostToolUse".into());
        payload["tool_response"] = output["tool_response"].clone();
        payload["is_error"] = output["is_error"].clone();
        call.post_used = true;
        Ok((payload, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn one_use_native_input_survives_detachment_and_sink_failures_cannot_replay() {
        let mut ledger = NativeHookCalls::default();
        let mut payload = json!({"hook_event_name":"PreToolUse","tool_call_id":"call","tool_name":"bash","tool_input":{"command":"python3 -m unittest discover -s tests -v","timeout":30,"label":"complete original SDK options"}});
        let original = payload.clone();
        ledger.reserve(&payload).unwrap();
        payload["tool_input"]["command"] = json!("changed");
        assert!(ledger.reserve(&payload).is_err());
        assert!(ledger.begin_sink("call").is_err());
        let mut response = json!({"decision":"deny","policy_action":"sandbox-required","required_execution_profile":"workspace-contained-v1"});
        ledger.record_review("call", &response).unwrap();
        response["decision"] = json!("allow");
        assert_eq!(ledger.begin_sink("call").unwrap(), original);
        assert!(ledger.begin_sink("call").is_err());
        assert!(ledger.begin_post("call").is_err());
        assert!(ledger.record_review("call", &response).is_err());
    }
    #[test]
    fn post_uses_only_the_completed_original_capture_and_is_one_use() {
        let mut ledger = NativeHookCalls::default();
        let payload = json!({"hook_event_name":"PreToolUse","tool_call_id":"call","tool_name":"bash","tool_input":{"command":"test"}});
        ledger.reserve(&payload).unwrap();
        ledger.record_review("call",&json!({"decision":"deny","policy_action":"sandbox-required","required_execution_profile":"workspace-contained-v1"})).unwrap();
        ledger.begin_sink("call").unwrap();
        let mut result = json!({"exit_code":0,"stdout":"exact captured bytes","stderr":"","stdout_sha256":crate::hash(b"exact captured bytes"),"stderr_sha256":crate::hash(b""),
            "payload_digest":crate::hash(&gauntlet_contracts::canonicalize(payload.to_string().as_bytes()).unwrap())});
        let original = result.clone();
        result["payload_digest"] = json!("wrong");
        assert!(ledger.record_sink("call", &result).is_err());
        ledger.record_sink("call", &original).unwrap();
        result["stdout"] = json!("forged SDK text");
        assert!(ledger.record_sink("call", &result).is_err());
        let (post, output) = ledger.begin_post("call").unwrap();
        assert_eq!(post["tool_input"], payload["tool_input"]);
        assert_eq!(post["tool_response"], output["tool_response"]);
        assert!(post["tool_response"][0]["text"]
            .as_str()
            .unwrap()
            .contains("exact captured bytes"));
        assert!(ledger.begin_post("call").is_err());
    }
    #[test]
    fn other_decisions_and_observe_mode_never_create_a_contained_route() {
        for response in [
            json!({"decision":"allow"}),
            json!({"decision":"deny"}),
            json!({"decision":"deny","policy_action":"sandbox-required","required_execution_profile":"workspace-contained-v1","observe_mode":true}),
        ] {
            let mut ledger = NativeHookCalls::default();
            ledger.reserve(&json!({"hook_event_name":"PreToolUse","tool_call_id":"call","tool_name":"bash","tool_input":{"command":"test"}})).unwrap();
            ledger.record_review("call", &response).unwrap();
            assert!(ledger.begin_sink("call").is_err());
        }
    }
}
