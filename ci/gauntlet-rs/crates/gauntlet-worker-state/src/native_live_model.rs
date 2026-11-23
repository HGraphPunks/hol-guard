//! Closed live-model channel. A consumed turn is never retried or reconstructed.
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
use base64::{engine::general_purpose::STANDARD, Engine};
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
use sha2::{Digest, Sha256};

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) const REQUEST_LIMIT: usize = 1024 * 1024;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) const REQUEST_FRAME_LIMIT: usize = 2 * 1024 * 1024;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) const RESPONSE_FRAME_LIMIT: usize = 6 * 1024 * 1024;
pub(crate) const MODEL: &str = "mlx-community/Qwen3.6-35B-A3B-8bit";

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn exact(value: &Value, names: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == names.len() && names.iter().all(|name| o.contains_key(*name)))
}
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
fn canonical(raw: &[u8], limit: usize) -> Result<Value, String> {
    if raw.is_empty() || raw.len() > limit {
        return Err("bounded live-model JSON required".into());
    }
    let raw = canonicalize(raw).map_err(|_| "unambiguous live-model JSON required")?;
    serde_json::from_slice(&raw).map_err(|_| "live-model JSON required".into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLiveModelPins {
    pub provider_job_id: String,
    pub budget_digest: String,
    pub model_id: String,
    pub max_turns: u64,
    pub token_limit: u64,
}
impl NativeLiveModelPins {
    pub fn parse(value: &Value) -> Result<Self, String> {
        if !exact(
            value,
            &[
                "schema",
                "provider_job_id",
                "budget_digest",
                "model_id",
                "max_turns",
                "token_limit",
            ],
        ) || value["schema"] != "hol-gauntlet-native-live-model-pins.v1"
            || value["provider_job_id"]
                .as_str()
                .is_none_or(|s| !crate::hex(s, 16))
            || value["budget_digest"]
                .as_str()
                .is_none_or(|s| !crate::hex(s, 64))
            || value["model_id"] != MODEL
            || value["max_turns"]
                .as_u64()
                .is_none_or(|n| !(1..=64).contains(&n))
            || value["token_limit"]
                .as_u64()
                .is_none_or(|n| !(1..=100_000).contains(&n))
        {
            return Err("outside-bound live-model pins required".into());
        }
        Ok(Self {
            provider_job_id: value["provider_job_id"].as_str().unwrap().into(),
            budget_digest: value["budget_digest"].as_str().unwrap().into(),
            model_id: MODEL.into(),
            max_turns: value["max_turns"].as_u64().unwrap(),
            token_limit: value["token_limit"].as_u64().unwrap(),
        })
    }
    pub fn to_json(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-live-model-pins.v1", "provider_job_id":self.provider_job_id,
            "budget_digest":self.budget_digest,"model_id":self.model_id,"max_turns":self.max_turns,"token_limit":self.token_limit})
    }
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
struct Pending {
    turn: u64,
    request_sha256: String,
    sdk_request_sha256: String,
}
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) struct NativeLiveModelLedger {
    source: String,
    job: String,
    pins: NativeLiveModelPins,
    next: u64,
    pending: Option<Pending>,
    receipts: Vec<Value>,
    tokens: u64,
}
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
impl NativeLiveModelLedger {
    pub(crate) fn new(source: &str, job: &str, pins: &NativeLiveModelPins) -> Result<Self, String> {
        NativeLiveModelPins::parse(&pins.to_json())?;
        if !crate::hex(source, 40) || !crate::hex(job, 16) {
            return Err("exact live-model source and cell job required".into());
        }
        Ok(Self {
            source: source.into(),
            job: job.into(),
            pins: pins.clone(),
            next: 1,
            pending: None,
            receipts: Vec::new(),
            tokens: 0,
        })
    }
    /// Mark the turn consumed before the caller can send it to the provider.
    /// A transport error leaves `pending` populated and blocks every later turn.
    pub(crate) fn begin(&mut self, raw: &[u8], sdk_sha256: &str) -> Result<Value, String> {
        if self.pending.is_some()
            || self.next > self.pins.max_turns
            || self.tokens >= self.pins.token_limit
            || self
                .receipts
                .last()
                .is_some_and(|r| r["delivered_to_sdk"] != true)
            || !crate::hex(sdk_sha256, 64)
        {
            return Err("live-model turn is pending, consumed or exhausted".into());
        }
        let value = canonical(raw, REQUEST_LIMIT)?;
        if value["model"] != self.pins.model_id
            || value["stream"] != false
            || value["max_tokens"]
                .as_u64()
                .is_none_or(|n| !(1..=4096).contains(&n))
            || value["messages"]
                .as_array()
                .is_none_or(|a| a.is_empty() || a.len() > 256)
            || value.get("stream_options").is_some()
            || value.get("n").is_some_and(|n| n.as_u64() != Some(1))
        {
            return Err("fixed live-model chat request required".into());
        }
        let turn = self.next;
        let request_sha256 = sha(raw);
        self.pending = Some(Pending {
            turn,
            request_sha256: request_sha256.clone(),
            sdk_request_sha256: sdk_sha256.into(),
        });
        self.next += 1;
        Ok(
            json!({"schema":"hol-gauntlet-native-live-model-request.v1","source_sha":self.source,
            "provider_job_id":self.pins.provider_job_id,"job_id":self.job,"budget_digest":self.pins.budget_digest,
            "turn":turn,"request_sha256":request_sha256,"body_b64":STANDARD.encode(raw)}),
        )
    }
    pub(crate) fn finish(&mut self, raw: &[u8]) -> Result<Vec<u8>, String> {
        let pending = self
            .pending
            .as_ref()
            .ok_or("live-model response has no consumed turn")?;
        let response = canonical(raw, RESPONSE_FRAME_LIMIT)?;
        if !exact(
            &response,
            &[
                "schema",
                "source_sha",
                "provider_job_id",
                "job_id",
                "budget_digest",
                "turn",
                "request_sha256",
                "response_sha256",
                "body_b64",
                "usage_receipt",
                "before",
                "after",
            ],
        ) || response["schema"] != "hol-gauntlet-native-live-model-response.v1"
            || response["source_sha"] != self.source
            || response["provider_job_id"] != self.pins.provider_job_id
            || response["job_id"] != self.job
            || response["budget_digest"] != self.pins.budget_digest
            || response["turn"] != pending.turn
            || response["request_sha256"] != pending.request_sha256
        {
            return Err("live-model response differs from original consumed turn".into());
        }
        let encoded = response["body_b64"]
            .as_str()
            .ok_or("live-model response bytes missing")?;
        let body = STANDARD
            .decode(encoded)
            .map_err(|_| "live-model response encoding differs")?;
        if body.is_empty()
            || body.len() > RESPONSE_LIMIT
            || STANDARD.encode(&body) != encoded
            || response["response_sha256"] != sha(&body)
        {
            return Err("live-model response byte pin differs".into());
        }
        let receipt = &response["usage_receipt"];
        if !exact(
            receipt,
            &[
                "schema",
                "source_sha",
                "provider_job_id",
                "cell_job_id",
                "budget_digest",
                "turn",
                "request_sha256",
                "response_sha256",
                "response_bytes",
                "model_id",
                "reservation_id",
                "prepared_input_sha256",
                "prompt_tokens",
                "output_tokens",
                "complete",
                "quota_before_sha256",
                "quota_after_sha256",
                "quota_journal_before",
                "quota_journal_after",
                "quota_requests_before",
                "quota_requests_after",
                "qualification_eligible",
            ],
        ) || receipt["schema"] != "hol-gauntlet-rust-provider-usage.v1"
            || receipt["source_sha"] != self.source
            || receipt["provider_job_id"] != self.pins.provider_job_id
            || receipt["cell_job_id"] != self.job
            || receipt["budget_digest"] != self.pins.budget_digest
            || receipt["turn"] != pending.turn
            || receipt["request_sha256"] != pending.request_sha256
            || receipt["response_sha256"] != response["response_sha256"]
            || receipt["response_bytes"] != body.len()
            || receipt["model_id"] != self.pins.model_id
            || receipt["complete"] != true
            || receipt["qualification_eligible"] != false
            || receipt["reservation_id"]
                .as_str()
                .is_none_or(|s| !crate::hex(s, 32))
            || [
                "prepared_input_sha256",
                "quota_before_sha256",
                "quota_after_sha256",
                "quota_journal_before",
                "quota_journal_after",
            ]
            .iter()
            .any(|name| receipt[*name].as_str().is_none_or(|s| !crate::hex(s, 64)))
        {
            return Err("live-model actual usage receipt differs from consumed turn".into());
        }
        for (status, pin) in [
            ("before", "quota_before_sha256"),
            ("after", "quota_after_sha256"),
        ] {
            if !response[status].is_object()
                || !response[status]["quota"].is_object()
                || receipt[pin]
                    != sha(
                        &canonicalize(response[status]["quota"].to_string().as_bytes())
                            .map_err(|_| "canonical actual quota status required")?,
                    )
            {
                return Err("live-model actual quota status differs from usage receipt".into());
            }
        }
        let prompt = receipt["prompt_tokens"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("actual prompt usage required")?;
        let output = receipt["output_tokens"]
            .as_u64()
            .filter(|n| *n <= 4096)
            .ok_or("bounded actual output usage required")?;
        let before = receipt["quota_requests_before"]
            .as_u64()
            .ok_or("quota request counter required")?;
        if before.checked_add(1) != receipt["quota_requests_after"].as_u64() {
            return Err("live-model quota request was not settled exactly once".into());
        }
        let tokens = self
            .tokens
            .checked_add(prompt)
            .and_then(|n| n.checked_add(output))
            .ok_or("live-model usage overflow")?;
        if tokens > self.pins.token_limit {
            return Err("live-model cell token allowance exhausted".into());
        }
        if let Some(last) = self.receipts.last() {
            let last = &last["usage_receipt"];
            if receipt["quota_before_sha256"] != last["quota_after_sha256"]
                || receipt["quota_journal_before"] != last["quota_journal_after"]
                || receipt["quota_requests_before"] != last["quota_requests_after"]
            {
                return Err("live-model quota history changed between serial turns".into());
            }
        }
        let chat = canonical(&body, RESPONSE_LIMIT)?;
        if chat["model"] != self.pins.model_id
            || chat["choices"].as_array().is_none_or(|a| a.len() != 1)
            || chat["usage"]["prompt_tokens"] != prompt
            || chat["usage"]["completion_tokens"] != output
        {
            return Err("live-model response does not carry its actual counted usage".into());
        }
        self.receipts.push(json!({"turn":pending.turn,"sdk_request_sha256":pending.sdk_request_sha256,
            "request_sha256":pending.request_sha256,"response_sha256":response["response_sha256"],"response_bytes":body.len(),
            "usage_receipt":receipt,"delivered_to_sdk":false}));
        self.tokens = tokens;
        self.pending = None;
        Ok(body)
    }
    pub(crate) fn delivered(&mut self) -> Result<(), String> {
        let last = self
            .receipts
            .last_mut()
            .ok_or("no completed live-model response")?;
        if last["delivered_to_sdk"] != false || self.pending.is_some() {
            return Err("live-model delivery already consumed or changed".into());
        }
        last["delivered_to_sdk"] = json!(true);
        Ok(())
    }
    pub(crate) fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-live-model-observation.v1","source_sha":self.source,"job_id":self.job,
            "provider_job_id":self.pins.provider_job_id,"budget_digest":self.pins.budget_digest,"model_id":self.pins.model_id,
            "turns_consumed":self.next-1,"turns_completed":self.receipts.len(),"tokens_counted":self.tokens,
            "pending_turn":self.pending.as_ref().map(|p|p.turn),"turns":self.receipts,"retries":0,
            "qualification_eligible":false,"execution_eligible":false})
    }
}

#[cfg(test)]
#[path = "native_live_model_tests.rs"]
mod tests;
