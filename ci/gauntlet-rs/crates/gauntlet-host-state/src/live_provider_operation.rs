//! Rust owns provider authorization, dispatch, inference accounting and cleanup.
//! Only the pinned MLX numerical seam executes outside this process.
use gauntlet_contracts::{canonicalize, is_git_sha};
use gauntlet_evidence::{read_provider_quota_snapshot, verify_provider_quota_observations};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

#[path = "live_provider_adapter.rs"]
mod adapter;
#[path = "live_provider_assets.rs"]
mod assets;
#[path = "live_provider_custody.rs"]
mod custody;
#[path = "live_provider_http.rs"]
mod http;
#[path = "live_provider_inference.rs"]
mod inference;
#[path = "live_provider_lifetime.rs"]
mod lifetime;
#[path = "live_provider_numerical.rs"]
mod numerical;
#[path = "live_provider_output.rs"]
mod output;
#[path = "live_provider_relay.rs"]
mod relay;
use assets::Assets;
use custody::Journal;

pub const LIVE_PROVIDER_USAGE:&str="provider commands:\nprepare PRIVATE_0700_JOURNAL PRIVATE_SPEC_JSON SPEC_SHA256 PRIVATE_SOURCE_AUTHORIZATION_JSON AUTHORIZATION_SHA256\nstart|read|stop PRIVATE_JOURNAL INTENT_SHA256\nstart owns the foreground Rust provider until stop/signal/deadline. Only approved source bindings may reuse the retained quota; no reset or cap extension. Start is one-use and uncertain startup cannot be replayed. Inference uses the private source/job-bound channel; stdout contains sanitized status only.";
const MODEL: &str = "mlx-community/Qwen3.6-35B-A3B-8bit";
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    canonicalize(value.to_string().as_bytes())
        .map_err(|_| "canonical provider JSON required".into())
}
fn parse(raw: &[u8]) -> Result<Value, String> {
    let canonical = canonicalize(raw).map_err(|_| "provider JSON invalid")?;
    serde_json::from_slice(&canonical).map_err(|_| "provider JSON invalid".into())
}
fn exact(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str()
        .ok_or_else(|| format!("provider {k} text absent"))
}
fn num(v: &Value, k: &str) -> Result<u64, String> {
    v[k].as_u64()
        .ok_or_else(|| format!("provider {k} integer absent"))
}
fn random_key() -> Result<String, String> {
    let mut b = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "provider random identity unavailable")?;
    Ok(b.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Clone)]
struct Intent(Value);
impl Intent {
    fn spec(&self) -> &Value {
        &self.0["spec"]
    }
    fn text(&self, k: &str) -> Result<&str, String> {
        text(self.spec(), k)
    }
    fn digest(&self) -> Result<String, String> {
        Ok(sha(&bytes(&self.0)?))
    }
    fn snapshot(&self) -> Result<Value, String> {
        snapshot(self.spec())
    }
    fn load(journal: &mut Journal, digest: &str) -> Result<Self, String> {
        if !hex(digest, 64) {
            return Err("outside provider intent SHA256 required".into());
        }
        let raw = journal.read("provider-intent.json")?;
        if sha(&raw) != digest {
            return Err("provider intent differs from outside pin".into());
        }
        let value = parse(&raw)?;
        if raw != bytes(&value)?
            || !exact(
                &value,
                &[
                    "schema",
                    "spec",
                    "spec_sha256",
                    "source_authorization",
                    "source_authorization_sha256",
                    "quota_at_prepare",
                    "maximum_accounted_tokens",
                    "asset_custody",
                    "socket_directory_custody",
                    "channel_key_sha256",
                    "asset_directory_custody",
                ],
            )
            || value["schema"] != "hol-gauntlet-rust-provider-intent.v1"
        {
            return Err("closed Rust provider intent required".into());
        }
        validate_spec(&value["spec"])?;
        if !hex(text(&value, "channel_key_sha256")?, 64) {
            return Err("outside-bound provider channel key required".into());
        }
        journal.configure_socket(
            Path::new(text(&value["spec"], "socket_directory")?),
            &value["socket_directory_custody"],
        )?;
        validate_authorization(
            &value["source_authorization"],
            &value["spec"],
            text(&value, "spec_sha256")?,
        )?;
        if sha(&bytes(&value["spec"])?) != text(&value, "spec_sha256")?
            || sha(&bytes(&value["source_authorization"])?)
                != text(&value, "source_authorization_sha256")?
            || num(&value, "maximum_accounted_tokens")?
                != num(&value["quota_at_prepare"], "known_tokens")?
                    .checked_add(200_000)
                    .ok_or("provider ceiling overflow")?
            || num(&value, "maximum_accounted_tokens")? > num(&value["spec"], "token_cap")?
        {
            return Err("provider intent binding differs".into());
        }
        if journal.json("provider-prepared.json")?
            != json!({"schema":"hol-gauntlet-rust-provider-prepared.v1","binding_sha256":digest})
        {
            return Err("provider preparation incomplete".into());
        }
        Ok(Self(value))
    }
    fn status(&self, quota: Value) -> Result<Value, String> {
        Ok(
            json!({"adapter":{"schema":"gauntlet-mlx-quota-adapter.v2","source_sha":self.text("source_sha")?,"provider_job_id":self.text("provider_job_id")?,"producer_sha256":self.text("producer_sha256")?,"server_sha256":self.text("server_sha256")?,"adapter_sha256":sha(numerical::CODE.as_bytes()),"quota_config_digest":self.text("quota_config_digest")?,"quota_allowance_digest":self.spec()["quota_allowance_digest"],"producer_mode":"serial-original-tokenization-and-generation","counting":"full prompt including cached input plus every producer-emitted response token","batching":false,"draft":false,"qualification_eligible":false},"binding_sha256":self.digest()?,"qualification":false,"quota":quota}),
        )
    }
}
fn validate_spec(v: &Value) -> Result<(), String> {
    let keys = [
        "schema",
        "source_sha",
        "provider_job_id",
        "model_id",
        "model_identity_digest",
        "quota_root",
        "quota_config_digest",
        "quota_allowance_digest",
        "token_cap",
        "maximum_requests",
        "python",
        "site_packages",
        "model_directory",
        "server_sha256",
        "producer_sha256",
        "assets",
        "cells",
        "socket_directory",
    ];
    if !exact(v, &keys)
        || v["schema"] != "hol-gauntlet-rust-provider-spec.v1"
        || !is_git_sha(text(v, "source_sha")?)
        || !hex(text(v, "provider_job_id")?, 16)
        || v["model_id"] != MODEL
        || ![
            "model_identity_digest",
            "quota_config_digest",
            "server_sha256",
            "producer_sha256",
        ]
        .iter()
        .all(|k| v[*k].as_str().is_some_and(|s| hex(s, 64)))
        || !v["quota_allowance_digest"]
            .as_str()
            .is_some_and(|s| hex(s, 64))
        || !(1..=1_000_000_000).contains(&num(v, "token_cap")?)
        || !(1..=10_000).contains(&num(v, "maximum_requests")?)
    {
        return Err("exact source-bound Rust provider specification required".into());
    }
    for key in [
        "quota_root",
        "python",
        "site_packages",
        "model_directory",
        "socket_directory",
    ] {
        if !Path::new(text(v, key)?).is_absolute() {
            return Err("absolute numerical and quota paths required".into());
        }
    }
    let cells = v["cells"]
        .as_array()
        .filter(|c| c.len() == 2)
        .ok_or("exact two-cell feature pair required")?;
    let episodes = [
        "episode-a9344653386e0c30b3bd63437f283047",
        "episode-406531b0394f2bfaba126c5ec3ddfadb",
    ];
    for (cell, episode) in cells.iter().zip(episodes) {
        if !exact(cell, &["job_id", "episode_id", "token_budget"])
            || !hex(text(cell, "job_id")?, 16)
            || cell["episode_id"] != episode
            || cell["token_budget"] != 100_000
        {
            return Err("fixed feature pair and 100k cell bounds required".into());
        }
    }
    if cells[0]["job_id"] == cells[1]["job_id"] {
        return Err("distinct cell jobs required".into());
    }
    let assets = v["assets"].as_object().ok_or("numerical assets absent")?;
    let server = Path::new(text(v, "site_packages")?).join("mlx_lm/server.py");
    if assets
        .get(text(v, "python")?)
        .is_none_or(|p| p["sha256"].as_str().is_none_or(|s| !hex(s, 64)))
        || assets
            .get(server.to_str().ok_or("server path invalid")?)
            .is_none_or(|p| p["sha256"] != v["server_sha256"])
    {
        return Err("pinned original interpreter and MLX server required".into());
    }
    for leaf in [
        "generate.py",
        "utils.py",
        "tokenizer_utils.py",
        "sample_utils.py",
        "models/cache.py",
    ] {
        if !assets.contains_key(
            Path::new(text(v, "site_packages")?)
                .join("mlx_lm")
                .join(leaf)
                .to_str()
                .ok_or("MLX dependency path invalid")?,
        ) {
            return Err("pinned MLX numerical dependencies required".into());
        }
    }
    for leaf in ["config.json", "tokenizer_config.json"] {
        if !assets.contains_key(
            Path::new(text(v, "model_directory")?)
                .join(leaf)
                .to_str()
                .ok_or("model path invalid")?,
        ) {
            return Err("pinned model and tokenizer configuration required".into());
        }
    }
    if !assets.keys().any(|p| {
        Path::new(p).starts_with(text(v, "model_directory").unwrap_or(""))
            && p.ends_with(".safetensors")
    }) {
        return Err("pinned local model weights required".into());
    }
    Ok(())
}
fn validate_authorization(a: &Value, s: &Value, spec_sha: &str) -> Result<(), String> {
    let keys = [
        "schema",
        "authority",
        "source_sha",
        "provider_job_id",
        "profile",
        "provider_spec_sha256",
        "quota_root",
        "quota_config_digest",
        "quota_allowance_digest",
        "model_identity_digest",
        "token_cap",
        "retained_quota",
        "job_tokens",
        "allowance_reset",
        "token_cap_increase",
    ];
    if !exact(a, &keys)
        || a["schema"] != "hol-gauntlet-rust-provider-source-authorization.v1"
        || a["authority"] != "operator-approved-source-binding-preserve-retained-quota"
        || a["profile"] != "feature-ai"
        || a["provider_spec_sha256"] != spec_sha
        || a["job_tokens"] != 200_000
        || a["allowance_reset"] != false
        || a["token_cap_increase"] != false
        || ![
            "source_sha",
            "provider_job_id",
            "quota_root",
            "quota_config_digest",
            "quota_allowance_digest",
            "model_identity_digest",
            "token_cap",
        ]
        .iter()
        .all(|k| a[*k] == s[*k])
        || a["retained_quota"]["token_cap"] != s["token_cap"]
        || a["retained_quota"]["config_digest"] != s["quota_config_digest"]
        || a["retained_quota"]["model_identity_digest"] != s["model_identity_digest"]
        || !a["retained_quota"]["journal_hash"]
            .as_str()
            .is_some_and(|v| hex(v, 64))
    {
        return Err(
            "outside source authorization must preserve retained quota identity and cap".into(),
        );
    }
    Ok(())
}
fn snapshot(spec: &Value) -> Result<Value, String> {
    read_provider_quota_snapshot(
        Path::new(text(spec, "quota_root")?),
        text(spec, "quota_config_digest")?,
        spec["quota_allowance_digest"].as_str(),
    )
    .map_err(|_| "retained provider quota unavailable or unsettled".into())
}
fn idle(q: &Value, s: &Value) -> Result<(), String> {
    if q["halted"] != false
        || q["pending_requests"] != 0
        || q["reserved_tokens"] != 0
        || q["known_tokens"] != q["charged_tokens"]
        || q["token_cap"] != s["token_cap"]
        || q["model_identity_digest"] != s["model_identity_digest"]
        || q["maximum_requests"] != s["maximum_requests"]
    {
        return Err("retained provider quota identity, cap or usage uncertain".into());
    }
    Ok(())
}
fn prepare(journal: &mut Journal, spec_raw: &[u8], auth_raw: &[u8]) -> Result<Value, String> {
    journal.lock()?;
    if journal.exists("provider-intent.json")? || journal.exists("provider-dispatch.json")? {
        return Err("provider preparation already consumed".into());
    }
    let spec = parse(spec_raw)?;
    let authorization = parse(auth_raw)?;
    if bytes(&spec)? != spec_raw || bytes(&authorization)? != auth_raw {
        return Err("canonical provider inputs required".into());
    }
    validate_spec(&spec)?;
    validate_authorization(&authorization, &spec, &sha(spec_raw))?;
    if Path::new(text(&spec, "quota_root")?) == journal.path {
        return Err("provider artifacts require a journal separate from retained quota".into());
    }
    lifetime::available(&spec)?;
    let socket_custody = custody::socket_context(Path::new(text(&spec, "socket_directory")?))?;
    journal.configure_socket(Path::new(text(&spec, "socket_directory")?), &socket_custody)?;
    if journal.socket_path()?.exists() {
        return Err("private provider socket directory already consumed".into());
    }
    let quota = snapshot(&spec)?;
    idle(&quota, &spec)?;
    verify_provider_quota_observations(
        Path::new(text(&spec, "quota_root")?),
        text(&spec, "quota_config_digest")?,
        spec["quota_allowance_digest"].as_str(),
        text(&quota, "journal_hash")?,
        &[authorization["retained_quota"].clone(), quota.clone()],
    )
    .map_err(|_| "source authorization is not a retained quota history prefix")?;
    let ceiling = num(&quota, "known_tokens")?
        .checked_add(200_000)
        .filter(|n| *n <= num(&spec, "token_cap").unwrap_or(0))
        .ok_or("complete feature pair does not fit retained cap")?;
    let assets = Assets::capture_spec(&spec)?;
    let producer =
        std::env::current_exe().map_err(|_| "provider executable identity unavailable")?;
    let producer =
        std::fs::canonicalize(producer).map_err(|_| "provider executable identity unavailable")?;
    if spec["assets"][producer
        .to_str()
        .ok_or("provider executable path invalid")?]["sha256"]
        != spec["producer_sha256"]
    {
        return Err("running Rust producer must be in outside-pinned inventory".into());
    }
    let channel_key = random_key()?;
    let intent = Intent(
        json!({"schema":"hol-gauntlet-rust-provider-intent.v1","spec":spec,"spec_sha256":sha(spec_raw),"source_authorization":authorization,"source_authorization_sha256":sha(auth_raw),"quota_at_prepare":quota,"maximum_accounted_tokens":ceiling,"asset_custody":assets.facts,"asset_directory_custody":assets.directories,"socket_directory_custody":socket_custody,"channel_key_sha256":sha(channel_key.as_bytes())}),
    );
    let digest = intent.digest()?;
    journal.put("provider-intent.json", &intent.0)?;
    journal.put("provider-channel.json",&json!({"schema":"hol-gauntlet-rust-provider-private-channel.v1","binding_sha256":digest,"key":channel_key}))?;
    journal.put(
        "provider-prepared.json",
        &json!({"schema":"hol-gauntlet-rust-provider-prepared.v1","binding_sha256":digest}),
    )?;
    Ok(
        json!({"schema":"hol-gauntlet-rust-provider-operation.v1","state":"prepared","binding_sha256":digest,"source_sha":intent.text("source_sha")?,"provider_job_id":intent.text("provider_job_id")?,"job_tokens":200_000,"maximum_accounted_tokens":ceiling,"inference_started":false,"qualification_eligible":false}),
    )
}

/// Normal operations never print channel secrets, raw prompts or model replies.
pub fn run_live_provider_command(args: &[String]) -> Result<Value, String> {
    match args {
        [op, root, spec, spec_sha, auth, auth_sha] if op == "prepare" => {
            if !hex(spec_sha, 64) || !hex(auth_sha, 64) {
                return Err("outside provider input pins required".into());
            }
            let spec = custody::private_input(Path::new(spec), spec_sha)?;
            let auth = custody::private_input(Path::new(auth), auth_sha)?;
            prepare(&mut Journal::open(Path::new(root))?, &spec, &auth)
        }
        [op, root, digest] if matches!(op.as_str(), "start" | "read" | "stop") => {
            let mut journal = Journal::open(Path::new(root))?;
            let intent = Intent::load(&mut journal, digest)?;
            match op.as_str() {
                "start" => relay::serve(&mut journal, &intent),
                "stop" => {
                    if !journal.exists("provider-dispatch.json")? {
                        return Err("provider has not been dispatched".into());
                    }
                    if !journal.exists("provider-stop.json")? {
                        journal.put("provider-stop.json",&json!({"schema":"hol-gauntlet-rust-provider-stop.v1","binding_sha256":digest}))?;
                    }
                    relay::read(&journal, &intent)
                }
                _ => relay::read(&journal, &intent),
            }
        }
        _ => Err(LIVE_PROVIDER_USAGE.into()),
    }
}

/// The live Host transport calls this directly; the private token never enters
/// guest artifacts or user-facing command output.
pub fn relay_live_model_request(
    journal: &Path,
    intent_sha256: &str,
    request: &Value,
) -> Result<Value, String> {
    relay_live_model_request_bounded(
        journal,
        intent_sha256,
        request,
        std::time::Duration::from_secs(900),
    )
}
pub(crate) fn relay_live_model_request_bounded(
    journal: &Path,
    intent_sha256: &str,
    request: &Value,
    timeout: std::time::Duration,
) -> Result<Value, String> {
    let mut journal = Journal::open(journal)?;
    let intent = Intent::load(&mut journal, intent_sha256)?;
    relay::validate_request(&intent, request)?;
    http::client_bounded(
        &journal,
        &intent,
        "POST",
        "/v1/chat/completions",
        Some(request),
        timeout,
    )
}

/// Closed internal handoff from an outside-pinned immutable intent. No channel
/// secret, numerical asset contents or private source-authorization bytes escape.
pub fn read_live_provider_binding(journal: &Path, intent_sha256: &str) -> Result<Value, String> {
    let mut journal = Journal::open(journal)?;
    let intent = Intent::load(&mut journal, intent_sha256)?;
    let s = intent.spec();
    let pins = json!({"profile":"owned-mlx-rust-serial.v2","source_sha":s["source_sha"],"provider_job_id":s["provider_job_id"],"binding_sha256":intent_sha256,"adapter_sha256":sha(numerical::CODE.as_bytes()),"server_sha256":s["server_sha256"],"producer_sha256":s["producer_sha256"],"model_identity_digest":s["model_identity_digest"],"quota_config_digest":s["quota_config_digest"],"quota_allowance_digest":s["quota_allowance_digest"],"token_cap":s["token_cap"],"maximum_requests":s["maximum_requests"]});
    Ok(
        json!({"schema":"hol-gauntlet-rust-provider-binding.v1","source_sha":s["source_sha"],"provider_job_id":s["provider_job_id"],"budget_digest":intent_sha256,"provider_spec_sha256":intent.0["spec_sha256"],"source_authorization_sha256":intent.0["source_authorization_sha256"],"model_id":MODEL,"maximum_accounted_tokens":intent.0["maximum_accounted_tokens"],"known_tokens_before":intent.0["quota_at_prepare"]["known_tokens"],"job_tokens":200_000,"cells":s["cells"],"status_pins":pins,"private_unix_channel":true,"qualification_eligible":false}),
    )
}

#[cfg(test)]
#[path = "live_provider_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "live_provider_transport_tests.rs"]
mod transport_tests;
