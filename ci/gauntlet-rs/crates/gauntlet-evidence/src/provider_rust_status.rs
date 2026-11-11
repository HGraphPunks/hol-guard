//! Rust producer identities and exact, settled one-request quota transitions.
//! Operational accounting is never source authorization or Guard qualification.

use crate::crypto::{is_sha256, sha256};
use crate::payload::{exact_keys, segment_ok};
use crate::provider_status::verify_idle_quota;
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};

const STATUS_PINS: &[&str] = &[
    "profile",
    "source_sha",
    "provider_job_id",
    "binding_sha256",
    "adapter_sha256",
    "server_sha256",
    "producer_sha256",
    "model_identity_digest",
    "quota_config_digest",
    "quota_allowance_digest",
    "token_cap",
    "maximum_requests",
];
const USAGE_PINS: &[&str] = &[
    "cell_job_id",
    "budget_digest",
    "turn",
    "request_sha256",
    "response_sha256",
    "response_bytes",
    "model_id",
    "reservation_id",
    "prepared_input_sha256",
];

fn invalid(message: &'static str) -> EvidenceError {
    EvidenceError::Invalid(message)
}

fn digest<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|v| is_sha256(v))
        .ok_or(invalid("outside Rust provider digest required"))
}

/// Verify a distinct Rust v2 producer, bound to outside source, job and budget pins.
/// The returned quota is idle and exact; authentication of its custody is separate.
pub fn verify_rust_provider_status(value: &Value, pins: &Value) -> Result<Value> {
    if !exact_keys(pins, STATUS_PINS)
        || pins["profile"] != "owned-mlx-rust-serial.v2"
        || !pins["source_sha"].as_str().is_some_and(|v| {
            v.len() == 40
                && v.bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
        || !pins["provider_job_id"].as_str().is_some_and(segment_ok)
    {
        return Err(invalid("exact outside Rust provider v2 pins required"));
    }
    for key in [
        "binding_sha256",
        "adapter_sha256",
        "server_sha256",
        "producer_sha256",
        "model_identity_digest",
        "quota_config_digest",
        "quota_allowance_digest",
    ] {
        digest(pins, key)?;
    }
    let token_cap = pins["token_cap"]
        .as_u64()
        .filter(|v| (1..=1_000_000_000).contains(v))
        .ok_or(invalid("outside Rust provider cap required"))?;
    let maximum_requests = pins["maximum_requests"]
        .as_u64()
        .filter(|v| (1..=10_000).contains(v))
        .ok_or(invalid("outside Rust provider request cap required"))?;
    if !exact_keys(
        value,
        &["adapter", "binding_sha256", "qualification", "quota"],
    ) || value["binding_sha256"] != pins["binding_sha256"]
        || value["qualification"] != false
    {
        return Err(invalid("Rust provider deployment binding mismatch"));
    }
    let expected = json!({
        "schema":"gauntlet-mlx-quota-adapter.v2", "source_sha":pins["source_sha"],
        "provider_job_id":pins["provider_job_id"], "producer_sha256":pins["producer_sha256"],
        "server_sha256":pins["server_sha256"], "adapter_sha256":pins["adapter_sha256"],
        "quota_config_digest":pins["quota_config_digest"], "quota_allowance_digest":pins["quota_allowance_digest"],
        "producer_mode":"serial-original-tokenization-and-generation",
        "counting":"full prompt including cached input plus every producer-emitted response token",
        "batching":false, "draft":false, "qualification_eligible":false,
    });
    if value["adapter"] != expected {
        return Err(invalid("Rust provider adapter/source identity mismatch"));
    }
    verify_idle_quota(
        &value["quota"],
        digest(pins, "quota_config_digest")?,
        digest(pins, "model_identity_digest")?,
        Some(digest(pins, "quota_allowance_digest")?),
        token_cap,
        maximum_requests,
    )
}

/// Join exact request/response identity to a single independently retained quota
/// transition. Partial or uncertain generation remains unverified, even if charged.
pub fn verify_rust_provider_usage(
    value: &Value,
    pins: &Value,
    before: &Value,
    after: &Value,
) -> Result<Value> {
    let mut keys = STATUS_PINS.to_vec();
    keys.extend_from_slice(USAGE_PINS);
    if !exact_keys(pins, &keys) {
        return Err(invalid("exact outside Rust usage pins required"));
    }
    let mut status_pins = pins.clone();
    for key in USAGE_PINS {
        status_pins
            .as_object_mut()
            .expect("exact object")
            .remove(*key);
    }
    let before_quota = verify_rust_provider_status(before, &status_pins)?;
    let after_quota = verify_rust_provider_status(after, &status_pins)?;
    if !exact_keys(
        value,
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
    ) || value["schema"] != "hol-gauntlet-rust-provider-usage.v1"
        || value["complete"] != true
        || value["qualification_eligible"] != false
    {
        return Err(invalid(
            "complete exact Rust provider usage record required",
        ));
    }
    for key in ["source_sha", "provider_job_id"]
        .into_iter()
        .chain(USAGE_PINS.iter().copied())
    {
        if value[key] != pins[key] {
            return Err(invalid(
                "Rust usage request identity differs from outside pins",
            ));
        }
    }
    for key in [
        "budget_digest",
        "request_sha256",
        "response_sha256",
        "prepared_input_sha256",
    ] {
        digest(pins, key)?;
    }
    if !pins["cell_job_id"].as_str().is_some_and(segment_ok)
        || !pins["reservation_id"].as_str().is_some_and(segment_ok)
        || pins["turn"].as_u64().is_none_or(|n| n == 0)
        || pins["response_bytes"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > 4 * 1024 * 1024)
        || !pins["model_id"]
            .as_str()
            .is_some_and(|v| !v.is_empty() && v.len() <= 512)
    {
        return Err(invalid("invalid bounded Rust usage identity"));
    }
    let prompt = value["prompt_tokens"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(invalid("complete prompt token count required"))?;
    let output = value["output_tokens"]
        .as_u64()
        .ok_or(invalid("producer output token count required"))?;
    let total = prompt
        .checked_add(output)
        .ok_or(invalid("Rust usage overflow"))?;
    let charged_before = before_quota["charged_tokens"]
        .as_u64()
        .expect("verified quota");
    let charged_after = after_quota["charged_tokens"]
        .as_u64()
        .expect("verified quota");
    let requests_before = before_quota["requests"].as_u64().expect("verified quota");
    let requests_after = after_quota["requests"].as_u64().expect("verified quota");
    if charged_before.checked_add(total) != Some(charged_after)
        || requests_before.checked_add(1) != Some(requests_after)
        || value["quota_requests_before"] != requests_before
        || value["quota_requests_after"] != requests_after
        || value["quota_before_sha256"] != sha256(&canonical_value(&before_quota)?)
        || value["quota_after_sha256"] != sha256(&canonical_value(&after_quota)?)
        || value["quota_journal_before"] != before_quota["journal_hash"]
        || value["quota_journal_after"] != after_quota["journal_hash"]
        || before_quota["journal_hash"] == after_quota["journal_hash"]
    {
        return Err(invalid(
            "Rust usage does not reconcile exact retained quota transition",
        ));
    }
    Ok(
        json!({"schema":"hol-gauntlet-rust-provider-usage-verification.v1",
        "cell_job_id":pins["cell_job_id"], "turn":pins["turn"], "request_sha256":pins["request_sha256"],
        "response_sha256":pins["response_sha256"], "model_tokens":total, "usage_known":true,
        "qualification_eligible":false}),
    )
}

#[cfg(test)]
#[path = "provider_rust_status_tests.rs"]
mod tests;
