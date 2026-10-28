//! Closed Bash-only SDK ingress and one-use transport bindings. Parsing does
//! not authenticate a peer, grant an approval or run a Native operation.
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeSdkRequest {
    Hook(NativeSdkHook),
    Execute { token: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSdkHook {
    pub session: String,
    pub call_id: String,
    pub post: bool,
    pub input: Value,
    pub environment: Value,
    pub reported_output: Option<Value>,
    pub request_sha256: String,
}

fn exact(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|key| o.contains_key(*key)))
}

fn identity(value: &Value) -> Result<String, String> {
    value
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256 && !s.contains('\0'))
        .map(str::to_owned)
        .ok_or("bounded SDK session/call identity required".into())
}

impl NativeSdkRequest {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > 1024 * 1024 {
            return Err("bounded SDK request required".into());
        }
        let canonical = canonicalize(raw).map_err(|_| "ambiguous SDK request JSON")?;
        let value: Value = serde_json::from_slice(&canonical).map_err(|_| "SDK request JSON")?;
        if value["operation"] == "execute-contained" {
            if !exact(&value, &["schema_version", "operation", "token"])
                || value["schema_version"] != "1.0"
            {
                return Err("closed SDK contained route required".into());
            }
            let token = value["token"]
                .as_str()
                .filter(|s| crate::hex(s, 64))
                .ok_or("exact SDK contained route token required")?;
            return Ok(Self::Execute {
                token: token.into(),
            });
        }
        let post = value["hook_event_name"] == "PostToolUse";
        let mut fields = vec![
            "schema_version",
            "hook_event_name",
            "session_id",
            "tool_call_id",
            "tool_name",
            "tool_input",
            "cwd",
            "execution_environment",
        ];
        if post {
            fields.extend(["tool_response", "is_error"]);
        }
        if !exact(&value, &fields)
            || value["schema_version"] != "1.0"
            || !matches!(
                value["hook_event_name"].as_str(),
                Some("PreToolUse" | "PostToolUse")
            )
            || value["tool_name"] != "bash"
            || value["cwd"] != "/runtime/home/project"
            || !value["tool_input"].is_object()
            || !value["tool_input"]["command"].is_string()
            || !value["execution_environment"].is_object()
        {
            return Err("closed fixed-workspace SDK Bash hook required".into());
        }
        let output = if post {
            if !value["is_error"].is_boolean()
                || value["tool_response"].as_array().is_none_or(|a| {
                    a.iter().any(|v| {
                        !exact(v, &["type", "text"])
                            || v["type"] != "text"
                            || !v["text"].is_string()
                    })
                })
            {
                return Err("typed SDK text output required".into());
            }
            Some(json!({"tool_response":value["tool_response"],"is_error":value["is_error"]}))
        } else {
            None
        };
        Ok(Self::Hook(NativeSdkHook {
            session: identity(&value["session_id"])?,
            call_id: identity(&value["tool_call_id"])?,
            post,
            input: value["tool_input"].clone(),
            environment: value["execution_environment"].clone(),
            reported_output: output,
            request_sha256: format!("{:x}", Sha256::digest(raw)),
        }))
    }
}

struct Call {
    original: NativeSdkHook,
    token: Option<String>,
    sink_used: bool,
    sink_completed: bool,
    post_used: bool,
}

pub struct NativeSdkLedger {
    session: Option<String>,
    calls: BTreeMap<String, Call>,
    tokens: BTreeMap<String, String>,
    max_calls: usize,
}

impl NativeSdkLedger {
    pub fn new(max_calls: usize) -> Result<Self, String> {
        if !(1..=500).contains(&max_calls) {
            return Err("bounded serial SDK operation budget required".into());
        }
        Ok(Self {
            session: None,
            calls: BTreeMap::new(),
            tokens: BTreeMap::new(),
            max_calls,
        })
    }

    pub fn reserve_pre(&mut self, request: &NativeSdkHook) -> Result<(), String> {
        if request.post
            || self.calls.len() >= self.max_calls
            || self.calls.contains_key(&request.call_id)
            || self.session.as_ref().is_some_and(|s| *s != request.session)
        {
            return Err("SDK Pre is changed, duplicate or exhausted".into());
        }
        self.session.get_or_insert_with(|| request.session.clone());
        self.calls.insert(
            request.call_id.clone(),
            Call {
                original: request.clone(),
                token: None,
                sink_used: false,
                sink_completed: false,
                post_used: false,
            },
        );
        Ok(())
    }

    /// The caller must first observe the actual Native containment response.
    /// This opaque transport ticket is never a Guard approval or decision.
    pub fn issue_route(&mut self, call_id: &str, token: &str) -> Result<(), String> {
        if !crate::hex(token, 64) || self.tokens.contains_key(token) {
            return Err("fresh SDK transport ticket required".into());
        }
        let call = self
            .calls
            .get_mut(call_id)
            .ok_or("SDK Pre reservation missing")?;
        if call.token.is_some() || call.sink_used || call.post_used {
            return Err("SDK route is already issued or consumed".into());
        }
        call.token = Some(token.into());
        self.tokens.insert(token.into(), call_id.into());
        Ok(())
    }

    pub fn begin_sink(&mut self, token: &str) -> Result<String, String> {
        let id = self
            .tokens
            .get(token)
            .ok_or("unknown SDK transport ticket")?;
        let call = self
            .calls
            .get_mut(id)
            .ok_or("SDK route lost its original input")?;
        if call.sink_used || call.post_used {
            return Err("SDK transport ticket was consumed".into());
        }
        // Consume before a filesystem handoff or product process can start.
        call.sink_used = true;
        Ok(id.clone())
    }

    pub fn finish_sink(&mut self, id: &str) -> Result<(), String> {
        let call = self
            .calls
            .get_mut(id)
            .ok_or("SDK Pre reservation missing")?;
        if !call.sink_used || call.sink_completed || call.post_used {
            return Err("SDK sink completion is premature or duplicated".into());
        }
        call.sink_completed = true;
        Ok(())
    }

    pub fn begin_post(&mut self, request: &NativeSdkHook) -> Result<(), String> {
        let call = self
            .calls
            .get_mut(&request.call_id)
            .ok_or("SDK Post has no original input")?;
        if !request.post
            || request.session != call.original.session
            || request.input != call.original.input
            || request.environment != call.original.environment
            || !call.sink_completed
            || call.post_used
        {
            return Err("SDK Post differs from its completed original input/context".into());
        }
        call.post_used = true;
        Ok(())
    }

    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-call-ledger.v1","session":self.session,
            "pre_count":self.calls.len(),"max_calls":self.max_calls,
            "route_count":self.tokens.len(),"sink_count":self.calls.values().filter(|c|c.sink_used).count(),
            "completed_sink_count":self.calls.values().filter(|c|c.sink_completed).count(),
            "post_count":self.calls.values().filter(|c|c.post_used).count(),
            "guard_approval_authority":false,"execution_eligible":false})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pre() -> Value {
        json!({"schema_version":"1.0","hook_event_name":"PreToolUse","session_id":"session",
            "tool_call_id":"call","tool_name":"bash","tool_input":{"command":"python3 -m unittest discover -s tests -v","timeout":30},
            "cwd":"/runtime/home/project","execution_environment":{"path":"/usr/bin:/bin"}})
    }
    fn hook(value: &Value) -> NativeSdkHook {
        match NativeSdkRequest::parse(value.to_string().as_bytes()).unwrap() {
            NativeSdkRequest::Hook(h) => h,
            _ => panic!("expected a hook"),
        }
    }
    #[test]
    fn closed_requests_preserve_original_arguments_and_exact_sender_bytes() {
        let raw = format!(" {} ", pre());
        let NativeSdkRequest::Hook(request) = NativeSdkRequest::parse(raw.as_bytes()).unwrap()
        else {
            panic!()
        };
        assert_eq!(request.input, pre()["tool_input"]);
        assert_eq!(
            request.request_sha256,
            format!("{:x}", Sha256::digest(raw.as_bytes()))
        );
        for (field, value) in [
            ("tool_name", json!("read")),
            ("cwd", json!("/root")),
            ("command", json!("root")),
            ("execution_environment", json!(null)),
            ("session_id", json!("")),
            ("sdk_pid", json!(12)),
        ] {
            let mut changed = pre();
            changed[field] = value;
            assert!(NativeSdkRequest::parse(changed.to_string().as_bytes()).is_err());
        }
        assert!(
            NativeSdkRequest::parse(br#"{"schema_version":"1.0","schema_version":"1.0"}"#).is_err()
        );
        let mut post = pre();
        post["hook_event_name"] = json!("PostToolUse");
        post["is_error"] = json!(false);
        post["tool_response"] = json!([{"type":"text","text":"actual SDK output"}]);
        assert!(hook(&post).post);
        post["is_error"] = json!(0);
        assert!(NativeSdkRequest::parse(post.to_string().as_bytes()).is_err());
        post["is_error"] = json!(false);
        post["tool_response"] = json!([{"type":"text","text":"x","authority":true}]);
        assert!(NativeSdkRequest::parse(post.to_string().as_bytes()).is_err());
    }
    #[test]
    fn consumed_route_failure_cannot_replay_and_post_waits_for_completion() {
        let request = hook(&pre());
        let mut ledger = NativeSdkLedger::new(2).unwrap();
        ledger.reserve_pre(&request).unwrap();
        assert!(ledger.reserve_pre(&request).is_err());
        let token = "a".repeat(64);
        ledger.issue_route("call", &token).unwrap();
        let mut post = request.clone();
        post.post = true;
        assert!(ledger.begin_post(&post).is_err());
        assert_eq!(ledger.begin_sink(&token).unwrap(), "call");
        assert!(ledger.begin_sink(&token).is_err());
        assert!(ledger.begin_post(&post).is_err());
        ledger.finish_sink("call").unwrap();
        assert!(ledger.finish_sink("call").is_err());
        for field in ["input", "environment", "session"] {
            let mut changed = post.clone();
            match field {
                "input" => changed.input["command"] = json!("changed"),
                "environment" => changed.environment["path"] = json!("/tmp"),
                _ => changed.session = "changed".into(),
            }
            assert!(ledger.begin_post(&changed).is_err());
        }
        ledger.begin_post(&post).unwrap();
        assert!(ledger.begin_post(&post).is_err());
        assert!(ledger.issue_route("call", &"b".repeat(64)).is_err());
        assert_eq!(ledger.observation()["post_count"], 1);
    }
    #[test]
    fn session_and_budget_are_bound_before_any_product_forwarding() {
        let mut ledger = NativeSdkLedger::new(1).unwrap();
        let request = hook(&pre());
        ledger.reserve_pre(&request).unwrap();
        let mut second = request.clone();
        second.call_id = "next".into();
        assert!(ledger.reserve_pre(&second).is_err());
        let mut ledger = NativeSdkLedger::new(2).unwrap();
        ledger.reserve_pre(&request).unwrap();
        second.session = "other".into();
        assert!(ledger.reserve_pre(&second).is_err());
        assert!(NativeSdkRequest::parse(
            br#"{"schema_version":"1.0","operation":"execute-contained","token":"wrong"}"#
        )
        .is_err());
        let ticket =
            json!({"schema_version":"1.0","operation":"execute-contained","token":"a".repeat(64)});
        assert!(matches!(
            NativeSdkRequest::parse(ticket.to_string().as_bytes()).unwrap(),
            NativeSdkRequest::Execute { .. }
        ));
    }
}
