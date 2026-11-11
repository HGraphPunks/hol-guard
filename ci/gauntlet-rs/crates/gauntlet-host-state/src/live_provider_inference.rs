//! One-use live requests: tokenize, durably reserve, generate, durably settle.
use super::assets::Assets;
use super::custody::Journal;
use super::{adapter, bytes, exact, idle, num, output::Tape, sha, text, Intent, MODEL};
use base64::Engine as _;
use gauntlet_evidence::ProviderQuotaWriter;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

pub(super) struct Request {
    pub body: Value,
    pub raw: Vec<u8>,
    pub job: String,
    pub turn: u64,
    pub max_tokens: u64,
}
pub(super) fn validate(intent: &Intent, value: &Value) -> Result<Request, String> {
    if !exact(
        value,
        &[
            "schema",
            "source_sha",
            "provider_job_id",
            "job_id",
            "budget_digest",
            "turn",
            "request_sha256",
            "body_b64",
        ],
    ) || value["schema"] != "hol-gauntlet-native-live-model-request.v1"
        || value["source_sha"] != intent.spec()["source_sha"]
        || value["provider_job_id"] != intent.spec()["provider_job_id"]
        || value["budget_digest"] != intent.digest()?
        || !intent.spec()["cells"]
            .as_array()
            .is_some_and(|cells| cells.iter().any(|c| c["job_id"] == value["job_id"]))
        || !(1..=64).contains(&num(value, "turn")?)
    {
        return Err("outside source, provider, cell and budget request pins required".into());
    }
    let encoded = text(value, "body_b64")?;
    if encoded.len() > 1_398_104 {
        return Err("live model request exceeds bound".into());
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "live model request encoding invalid")?;
    if raw.is_empty()
        || raw.len() > 1024 * 1024
        || base64::engine::general_purpose::STANDARD.encode(&raw) != encoded
        || sha(&raw) != text(value, "request_sha256")?
    {
        return Err("exact bounded live model body required".into());
    }
    let body = super::parse(&raw)?;
    let allowed = [
        "model",
        "messages",
        "tools",
        "tool_choice",
        "stream",
        "max_tokens",
        "temperature",
        "top_p",
        "stop",
        "parallel_tool_calls",
        "seed",
        "presence_penalty",
        "frequency_penalty",
    ];
    if body
        .as_object()
        .is_none_or(|o| o.keys().any(|k| !allowed.contains(&k.as_str())))
        || body["model"] != MODEL
        || body["stream"] != false
        || !body["messages"]
            .as_array()
            .is_some_and(|m| !m.is_empty() && m.len() <= 4096)
        || !(1..=4096).contains(&num(&body, "max_tokens")?)
        || body
            .get("tools")
            .is_some_and(|t| t.as_array().is_none_or(|t| t.len() > 256))
        || body
            .get("tool_choice")
            .is_some_and(|v| v != "auto" && !v.is_null())
        || body.get("seed").is_some_and(|v| v != 0)
        || ["presence_penalty", "frequency_penalty"]
            .iter()
            .any(|k| body.get(*k).is_some_and(|v| v.as_f64() != Some(0.0)))
        || body
            .get("parallel_tool_calls")
            .is_some_and(|v| !v.is_boolean())
        || body
            .get("temperature")
            .is_some_and(|v| v.as_f64().is_none_or(|n| !(0.0..=2.0).contains(&n)))
        || body
            .get("top_p")
            .is_some_and(|v| v.as_f64().is_none_or(|n| !(0.0..=1.0).contains(&n)))
        || body.get("stop").is_some_and(|v| {
            !v.as_array().is_some_and(|v| {
                v.len() <= 16
                    && v.iter()
                        .all(|s| s.as_str().is_some_and(|s| s.len() <= 1024))
            })
        })
    {
        return Err("bounded original OpenAI chat generation profile required".into());
    }
    Ok(Request {
        max_tokens: num(&body, "max_tokens")?,
        body,
        raw,
        job: text(value, "job_id")?.into(),
        turn: num(value, "turn")?,
    })
}
struct Lease {
    writer: ProviderQuotaWriter,
    id: String,
    settled: bool,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self
                .writer
                .uncertain(&self.id, "rust-provider-incomplete-generation");
        }
    }
}

#[derive(Default)]
struct Cell {
    turn: u64,
    tokens: u64,
    started: Option<std::time::Instant>,
}
pub(super) struct Inference {
    cells: BTreeMap<String, Cell>,
    pub tokens: u64,
    pub requests: u64,
    protected_started: bool,
}
impl Inference {
    pub fn new() -> Self {
        Self {
            cells: BTreeMap::new(),
            tokens: 0,
            requests: 0,
            protected_started: false,
        }
    }
    #[cfg(test)]
    pub fn complete(
        &mut self,
        intent: &Intent,
        journal: &Journal,
        assets: &Assets,
        numerical: &mut impl adapter::Numerical,
        value: &Value,
    ) -> Result<Value, String> {
        self.complete_bounded(
            intent,
            journal,
            assets,
            numerical,
            value,
            Duration::from_secs(900),
        )
    }
    pub fn complete_bounded(
        &mut self,
        intent: &Intent,
        journal: &Journal,
        assets: &Assets,
        numerical: &mut impl adapter::Numerical,
        value: &Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let call_started = std::time::Instant::now();
        let request = validate(intent, value)?;
        let digest = intent.digest()?;
        let first = &intent.spec()["cells"][0]["job_id"];
        if self.protected_started && first == &json!(request.job) {
            return Err("completed baseline cell cannot be resumed".into());
        }
        let cell = self.cells.entry(request.job.clone()).or_default();
        let start = *cell.started.get_or_insert(call_started);
        let deadline = call_started
            .checked_add(
                Duration::from_secs(900)
                    .saturating_sub(start.elapsed())
                    .min(timeout),
            )
            .ok_or("model deadline invalid")?;
        if request.turn != cell.turn + 1 {
            return Err("model turn already consumed or out of order".into());
        }
        if first != &json!(request.job) {
            self.protected_started = true;
        }
        let prefix = format!("model-{}-{:05}", request.job, request.turn);
        journal.put(&format!("{prefix}-request.json"), value)?;
        cell.turn = request.turn;
        assets.stable()?;
        let before = intent.snapshot()?;
        idle(&before, intent.spec())?;
        if num(&before, "known_tokens")?
            != num(&intent.0["quota_at_prepare"], "known_tokens")? + self.tokens
            || num(&before, "requests")?
                != num(&intent.0["quota_at_prepare"], "requests")? + self.requests
        {
            return Err("provider quota changed outside retained serial owner".into());
        }
        let before_status = intent.status(before.clone())?;
        journal.put(&format!("{prefix}-before.json"), &before_status)?;
        numerical.send_bounded(&json!({"schema":"hol-gauntlet-mlx-numerical-prepare.v1","request_sha256":value["request_sha256"],"request":request.body}),journal,&digest,remaining(deadline,Duration::from_secs(30))?)?;
        let prepared = numerical.receive(
            journal,
            &digest,
            remaining(deadline, Duration::from_secs(60))?,
        )?;
        let (prompt, input_sha) = adapter::prepared(
            &prepared,
            text(value, "request_sha256")?,
            request.max_tokens,
        )?;
        journal.put(&format!("{prefix}-prepared.json"), &prepared)?;
        if prompt + request.max_tokens > 32768
            || cell.tokens + prompt + request.max_tokens > 100_000
        {
            return Err("complete request exceeds cell or model context reservation".into());
        }
        let writer = ProviderQuotaWriter::open_existing(
            Path::new(intent.text("quota_root")?),
            intent.text("quota_config_digest")?,
            intent.spec()["quota_allowance_digest"].as_str(),
        )
        .map_err(|_| "retained quota writer refused")?;
        let reservation = writer
            .reserve(
                prompt,
                request.max_tokens,
                &input_sha,
                Some(num(&intent.0, "maximum_accounted_tokens")?),
            )
            .map_err(|_| "request exceeds retained provider quota")?;
        let mut lease = Lease {
            writer,
            id: reservation,
            settled: false,
        };
        journal.put(&format!("{prefix}-reservation.json"),&json!({"schema":"hol-gauntlet-rust-provider-reservation.v1","binding_sha256":digest,"source_sha":intent.text("source_sha")?,"provider_job_id":intent.text("provider_job_id")?,"cell_job_id":request.job,"turn":request.turn,"request_sha256":value["request_sha256"],"prepared_input_sha256":input_sha,"reservation_id":lease.id,"prompt_tokens":prompt,"output_limit":request.max_tokens}))?;
        let reserved = intent.snapshot()?;
        if reserved["halted"] != false
            || reserved["pending_requests"] != 1
            || num(&reserved, "requests")? != num(&before, "requests")? + 1
            || reserved["known_tokens"] != before["known_tokens"]
            || num(&reserved, "reserved_tokens")? != prompt + request.max_tokens
        {
            return Err("quota reservation state changed before generation".into());
        }
        assets.stable()?;
        numerical.send_bounded(&json!({"schema":"hol-gauntlet-mlx-numerical-admit.v1","request_sha256":value["request_sha256"],"prepared_input_sha256":input_sha}),journal,&digest,remaining(deadline,Duration::from_secs(30))?)?;
        let mut tape = Tape::new(request.max_tokens);
        loop {
            let remaining = remaining(deadline, Duration::from_secs(900))?;
            if tape.accept(
                numerical.receive(journal, &digest, remaining)?,
                &input_sha,
                prompt,
            )? {
                break;
            }
        }
        assets.stable()?;
        journal.put(&format!("{prefix}-numerical-output.json"),&json!({"schema":"hol-gauntlet-rust-provider-token-tape.v1","prepared_input_sha256":input_sha,"tokens":tape.tokens,"prompt_tokens":prompt,"output_tokens":tape.output,"complete":true}))?;
        lease
            .writer
            .settle(&lease.id, prompt, tape.output)
            .map_err(|_| "complete usage settlement failed")?;
        lease.settled = true;
        let after = intent.snapshot()?;
        idle(&after, intent.spec())?;
        if num(&after, "known_tokens")? != num(&before, "known_tokens")? + prompt + tape.output
            || num(&after, "requests")? != num(&before, "requests")? + 1
        {
            return Err("settled usage differs from exact producer output".into());
        }
        let after_status = intent.status(after.clone())?;
        journal.put(&format!("{prefix}-after.json"), &after_status)?;
        let response = tape.response(
            prompt,
            &format!("{}-{:05}", request.job, request.turn),
            request.body.get("tools"),
        )?;
        let response_sha = sha(&response);
        let usage = json!({"schema":"hol-gauntlet-rust-provider-usage.v1","source_sha":intent.text("source_sha")?,"provider_job_id":intent.text("provider_job_id")?,"cell_job_id":request.job,"budget_digest":digest,"turn":request.turn,"request_sha256":sha(&request.raw),"response_sha256":response_sha,"response_bytes":response.len(),"model_id":MODEL,"reservation_id":lease.id,"prepared_input_sha256":input_sha,"prompt_tokens":prompt,"output_tokens":tape.output,"complete":true,"quota_before_sha256":sha(&bytes(&before)?),"quota_after_sha256":sha(&bytes(&after)?),"quota_journal_before":before["journal_hash"],"quota_journal_after":after["journal_hash"],"quota_requests_before":before["requests"],"quota_requests_after":after["requests"],"qualification_eligible":false});
        journal.put(&format!("{prefix}-usage.json"), &usage)?;
        let response = json!({"schema":"hol-gauntlet-native-live-model-response.v1","source_sha":intent.text("source_sha")?,"provider_job_id":intent.text("provider_job_id")?,"job_id":request.job,"budget_digest":digest,"turn":request.turn,"request_sha256":value["request_sha256"],"response_sha256":response_sha,"body_b64":base64::engine::general_purpose::STANDARD.encode(response),"usage_receipt":usage,"before":before_status,"after":after_status});
        journal.put(&format!("{prefix}-response.json"), &response)?;
        self.tokens += prompt + tape.output;
        self.requests += 1;
        cell.tokens += prompt + tape.output;
        Ok(response)
    }
}
fn remaining(deadline: std::time::Instant, limit: Duration) -> Result<Duration, String> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|d| !d.is_zero())
        .map(|d| d.min(limit))
        .ok_or_else(|| "model generation deadline reached".into())
}
