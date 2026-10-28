//! Authenticated SDK-to-Native bindings. Only the normal Native response can
//! offer containment; opaque tickets convey transport state, never approval.
use crate::native_operation_budget::NativeOperationBudget;
use crate::{NativeSdkHook, NativeSdkLedger, NativeSdkRequest};
use gauntlet_cell_rootfs::{NativeControlRole, NativeHookPlane};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub(crate) struct NativeSdkRouter {
    ledger: NativeSdkLedger,
    captured: BTreeMap<String, Value>,
    originals: Vec<NativeSdkHook>,
    tokens: Vec<String>,
    pub(crate) events: Vec<Value>,
    budget: Option<Arc<Mutex<NativeOperationBudget>>>,
    role: Option<NativeControlRole>,
    lifecycle: Option<Value>,
}
impl NativeSdkRouter {
    pub(crate) fn new() -> Result<Self, String> {
        Ok(Self {
            ledger: NativeSdkLedger::new(1)?,
            captured: BTreeMap::new(),
            originals: Vec::new(),
            tokens: Vec::new(),
            events: Vec::new(),
            budget: None,
            role: None,
            lifecycle: None,
        })
    }
    pub(crate) fn with_budget(budget: Arc<Mutex<NativeOperationBudget>>) -> Result<Self, String> {
        let mut router = Self::new()?;
        router.budget = Some(budget);
        Ok(router)
    }
    pub(crate) fn with_role(
        budget: Arc<Mutex<NativeOperationBudget>>,
        role: Option<NativeControlRole>,
    ) -> Result<Self, String> {
        let mut router = Self::with_budget(budget)?;
        router.role = role.filter(|r| r.lifecycle());
        Ok(router)
    }
    pub(crate) fn lifecycle(&self) -> Option<&Value> {
        self.lifecycle.as_ref()
    }
    pub(crate) fn verify_cancelled(&self) -> Result<(), String> {
        let ledger = self.ledger.observation();
        if self.role != Some(NativeControlRole::Cancel)
            || self
                .lifecycle
                .as_ref()
                .is_none_or(|v| v["status"] != "passed" || v["role"] != "cancel")
            || ["pre_count", "route_count", "sink_count"]
                .iter()
                .any(|k| ledger[*k] != 1)
            || ledger["completed_sink_count"] != 0
            || ledger["post_count"] != 0
        {
            return Err("actual SDK cancellation lifecycle not established".into());
        }
        Ok(())
    }
    pub(crate) fn handle(
        &mut self,
        request: &NativeSdkRequest,
        plane: &mut NativeHookPlane,
    ) -> Result<Value, String> {
        if self.events.len() >= 16 {
            return Err("serial SDK transport operation budget".into());
        }
        match request {
            NativeSdkRequest::Execute { token } => {
                let id = self.ledger.begin_sink(token)?;
                self.events
                    .push(json!({"kind":"sdk-contained-start","call_id":id,"token_consumed":true}));
                let result = if let Some(role) = self.role {
                    let observed = plane.execute_lifecycle(&id, role)?;
                    self.lifecycle = Some(observed.lifecycle);
                    if self
                        .lifecycle
                        .as_ref()
                        .is_none_or(|v| v["status"] != "passed")
                    {
                        return Err("actual detached lifecycle control failed".into());
                    }
                    if observed.execution.is_none() {
                        self.verify_cancelled()?;
                        return Err(
                            "controlled SDK sink cancellation after detached readiness".into()
                        );
                    }
                    observed
                        .execution
                        .ok_or("actual lifecycle capture missing")?
                } else {
                    plane.execute_contained(&id, 30)?
                };
                let output = gauntlet_evidence::captured_contained_output(&result)
                    .map_err(|e| e.to_string())?;
                self.ledger.finish_sink(&id)?;
                let mut output = output;
                output["pre_payload_digest"] = result["payload_digest"].clone();
                self.captured.insert(id.clone(), output.clone());
                self.events
                    .push(json!({"kind":"sdk-contained-completed","call_id":id,
                    "pre_payload_digest":result["payload_digest"],"output":output}));
                Ok(
                    json!({"kind":"actual-contained-result","result":result,"product_claims_authenticated":false}),
                )
            }
            NativeSdkRequest::Hook(hook) => {
                let mut envelope = json!({"schema_version":"1.0","tool_call_id":hook.call_id,
                    "request_digest":hook.request_sha256,"product_claims_authenticated":false});
                if hook.post {
                    self.ledger.begin_post(hook)?;
                    let (response, output) = plane.review_after(&hook.call_id)?;
                    let captured = self
                        .captured
                        .get(&hook.call_id)
                        .ok_or("SDK Post lost actual captured output")?;
                    let mut expected = captured.clone();
                    expected
                        .as_object_mut()
                        .unwrap()
                        .remove("pre_payload_digest");
                    if output != expected {
                        return Err("SDK Post output changed after capture".into());
                    }
                    envelope["product_response"] = response.clone();
                    envelope["contained_output"] = captured.clone();
                    self.events
                        .push(json!({"kind":"sdk-post-review","call_id":hook.call_id,
                        "request_sha256":hook.request_sha256,"reported_output":hook.reported_output,
                        "actual_output":captured,"product_response":response}));
                } else {
                    self.ledger.reserve_pre(hook)?;
                    if let Some(budget) = &self.budget {
                        budget
                            .lock()
                            .map_err(|_| "shared SDK operation budget poisoned")?
                            .reserve_builtin(&hook.session, &hook.call_id)?;
                    }
                    self.originals.push(hook.clone());
                    let response =
                        plane.review_before_input(&hook.call_id, &hook.input, &hook.environment)?;
                    if response["decision"] == "deny"
                        && response["policy_action"] == "sandbox-required"
                        && response["required_execution_profile"] == "workspace-contained-v1"
                        && response["observe_mode"] != true
                    {
                        let mut random = [0; 32];
                        SystemRandom::new()
                            .fill(&mut random)
                            .map_err(|_| "SDK Root ticket randomness unavailable")?;
                        let token = random
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>();
                        self.ledger.issue_route(&hook.call_id, &token)?;
                        self.tokens.push(token.clone());
                        envelope["containment_execution_supported"] = json!(true);
                        envelope["execution_token"] = json!(token);
                        envelope["contained_output_binding"] =
                            json!("controller-contained-output.v1");
                    }
                    envelope["product_response"] = response.clone();
                    self.events.push(json!({"kind":"sdk-pre-review","call_id":hook.call_id,"session_id":hook.session,
                        "request_sha256":hook.request_sha256,"input":hook.input,"execution_environment":hook.environment,
                        "product_response":response,"transport_route_issued":envelope["containment_execution_supported"]==true}));
                }
                Ok(envelope)
            }
        }
    }
    pub(crate) fn verify_completed(&self) -> Result<(), String> {
        let value = self.ledger.observation();
        if [
            "pre_count",
            "route_count",
            "sink_count",
            "completed_sink_count",
            "post_count",
        ]
        .iter()
        .any(|k| value[*k] != 1)
        {
            return Err("actual SDK Pre/contained execution/Post lifecycle incomplete".into());
        }
        Ok(())
    }
    pub(crate) fn refuse_replays(&mut self, plane: &mut NativeHookPlane) -> Result<Value, String> {
        self.verify_completed()?;
        self.refuse_replays_inner(plane)
    }
    pub(crate) fn refuse_cancel_replays(
        &mut self,
        plane: &mut NativeHookPlane,
    ) -> Result<Value, String> {
        self.verify_cancelled()?;
        self.refuse_replays_inner(plane)
    }
    fn refuse_replays_inner(&mut self, plane: &mut NativeHookPlane) -> Result<Value, String> {
        let original = self
            .originals
            .first()
            .ok_or("original SDK Pre absent")?
            .clone();
        let before = plane.observation();
        let pre = self
            .handle(&NativeSdkRequest::Hook(original.clone()), plane)
            .is_err();
        let token = self
            .tokens
            .first()
            .ok_or("actual SDK route absent")?
            .clone();
        let sink = self
            .handle(&NativeSdkRequest::Execute { token }, plane)
            .is_err();
        let mut post = original;
        post.post = true;
        let post = self.handle(&NativeSdkRequest::Hook(post), plane).is_err();
        let after = plane.observation();
        if !pre || !sink || !post || before != after {
            return Err("real SDK replay reached the product plane".into());
        }
        Ok(
            json!({"schema":"hol-gauntlet-native-sdk-replays.v1","pre":true,"sink":true,"post":true,
            "native_plane_unchanged":true,"execution_eligible":false}),
        )
    }
    pub(crate) fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-router.v1","ledger":self.ledger.observation(),"events":self.events,"lifecycle":self.lifecycle,
            "guard_approval_authority":false,"guard_causality_verified":false,"execution_eligible":false})
    }
}
