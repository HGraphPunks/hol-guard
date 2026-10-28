//! Reauthenticate a v7 completion against the host's durable prelaunch record.
//! A signed controller diagnostic remains separate from independent scoring.
use crate::{HostControllerKeyPinJournal, HostKeyPinError, HostPrelaunchIdentity};
use gauntlet_contracts::{canonicalize, PrelaunchPrepared, NATIVE_HOST_PINNED_COMPLETION_LIMIT};
use gauntlet_evidence::{verify_native_control_envelope, NativeControlReportPins};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug)]
pub enum NativeControlReadbackError {
    InvalidFrame,
    WrongIdentity,
    HostPin(HostKeyPinError),
    Signature,
}
impl fmt::Display for NativeControlReadbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidFrame => {
                "native completion frame is malformed or has inconsistent records"
            }
            Self::WrongIdentity => "native completion differs from host prelaunch identity",
            Self::HostPin(_) => "host durable native controller pin is unavailable or unsafe",
            Self::Signature => "native controller signature differs from host-pinned context",
        })
    }
}
impl std::error::Error for NativeControlReadbackError {}
type Result<T> = std::result::Result<T, NativeControlReadbackError>;
fn digest(value: &Value) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(
            canonicalize(value.to_string().as_bytes())
                .map_err(|_| NativeControlReadbackError::InvalidFrame)?
        )
    ))
}
fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(NativeControlReadbackError::InvalidFrame)
    }
}

#[derive(Debug, Clone)]
pub struct HostNativeControlReadback {
    diagnostic: Value,
    observation: Value,
}
impl HostNativeControlReadback {
    pub fn diagnostic(&self) -> &Value {
        &self.diagnostic
    }
    pub fn observation(&self) -> &Value {
        &self.observation
    }
}

impl HostControllerKeyPinJournal {
    pub fn verify_native_completion(
        &self,
        raw: &[u8],
        expected: &HostPrelaunchIdentity,
        preparation_sha256: &str,
        role: &str,
    ) -> Result<HostNativeControlReadback> {
        if raw.is_empty() || raw.len() > NATIVE_HOST_PINNED_COMPLETION_LIMIT {
            return Err(NativeControlReadbackError::InvalidFrame);
        }
        let record = self
            .read(&expected.job_id)
            .map_err(NativeControlReadbackError::HostPin)?;
        let p = &record.pins;
        if p.job_id != expected.job_id
            || p.source_sha != expected.source_sha
            || p.deployment_digest != expected.deployment_digest
            || p.worker_generation != expected.worker_generation
        {
            return Err(NativeControlReadbackError::WrongIdentity);
        }
        let canonical = canonicalize(raw).map_err(|_| NativeControlReadbackError::InvalidFrame)?;
        let frame: Value = serde_json::from_slice(&canonical)
            .map_err(|_| NativeControlReadbackError::InvalidFrame)?;
        require(
            frame.as_object().is_some_and(|o| o.len() == 9)
                && frame["schema"] == "hol-gauntlet-native-host-pinned-completion.v1"
                && frame["execution_eligible"] == false
                && frame["guard_causality_verified"] == false
                && frame["model_requests"].as_u64() == Some(0),
        )?;
        let prepared = PrelaunchPrepared {
            job_id: p.job_id.clone(),
            source_sha: p.source_sha.clone(),
            deployment_digest: p.deployment_digest.clone(),
            worker_generation: p.worker_generation.clone(),
            started_marker_sha256: p.started_marker_sha256.clone(),
            controller_key_pin_sha256: p.controller_key_pin_sha256.clone(),
            controller_public_key_hex: p.controller_public_key_hex.clone(),
        };
        let prepared_raw = prepared
            .to_bytes()
            .map_err(|_| NativeControlReadbackError::WrongIdentity)?;
        let started = &frame["started"];
        let pin = &frame["controller_key_pin"];
        let terminal = &frame["terminal"];
        let report = &frame["report"];
        require(
            digest(started)? == p.started_marker_sha256
                && digest(pin)? == p.controller_key_pin_sha256
                && digest(terminal)? == frame["terminal_sha256"].as_str().unwrap_or("")
                && digest(report)? == terminal["report_sha256"].as_str().unwrap_or(""),
        )?;
        require(
            started["schema"] == "hol-gauntlet-worker-started.v2"
                && pin["schema"] == "hol-gauntlet-controller-key-pin.v1"
                && terminal["schema"] == "hol-gauntlet-worker-terminal.v2"
                && report["schema"] == "hol-gauntlet-native-worker-report.v7",
        )?;
        for value in [started, pin, terminal, report] {
            require(
                value["source_sha"] == p.source_sha
                    && value["job_id"] == p.job_id
                    && value["deployment_digest"] == p.deployment_digest
                    && value["worker_generation"] == p.worker_generation,
            )?;
        }
        for value in [started, pin, terminal] {
            require(value["controller_public_key_hex"] == p.controller_public_key_hex)?;
        }
        for value in [pin, terminal, report] {
            require(value["started_marker_sha256"] == p.started_marker_sha256)?;
        }
        require(
            terminal["controller_key_pin_sha256"] == p.controller_key_pin_sha256
                && terminal["pid"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= u32::MAX as u64)
                && terminal["process_start_ticks"]
                    .as_u64()
                    .is_some_and(|n| n > 0)
                && terminal["exit_code"]
                    .as_i64()
                    .is_some_and(|n| (-128..=255).contains(&n))
                && terminal["status"] == "invalid-evidence"
                && report["status"] == "invalid-evidence"
                && terminal["exit_code"] == report["exit_code"]
                && terminal["pid"] == report["controller"]["pid"]
                && terminal["process_start_ticks"] == report["controller"]["start_ticks"]
                && report["profile"] == "native-host-pinned-control-v1"
                && report["preparation_sha256"] == preparation_sha256
                && report["execution_eligible"] == false
                && report["guard_causality_verified"] == false
                && report["model_requests"].as_u64() == Some(0),
        )?;
        let custody = &report["prelaunch_custody"];
        require(
            canonicalize(custody["prepared"].to_string().as_bytes())
                .map_err(|_| NativeControlReadbackError::InvalidFrame)?
                == prepared_raw
                && custody["host_ack_received_before_controller_spawn"] == true,
        )?;
        let ack = prepared
            .acknowledgement(&record.raw_sha256)
            .map_err(|_| NativeControlReadbackError::WrongIdentity)?;
        require(custody["acknowledgement_sha256"] == format!("{:x}", Sha256::digest(&ack)))?;
        let envelope = report["controller_envelope_utf8"]
            .as_str()
            .ok_or(NativeControlReadbackError::InvalidFrame)?;
        require(
            report["controller_stdout_sha256"]
                == format!("{:x}", Sha256::digest(envelope.as_bytes())),
        )?;
        let authenticated = verify_native_control_envelope(
            envelope.as_bytes(),
            &NativeControlReportPins {
                prelaunch: prepared,
                preparation_sha256: preparation_sha256.into(),
                role: role.into(),
            },
        )
        .map_err(|_| NativeControlReadbackError::Signature)?;
        require(
            authenticated.report() == &report["controller_report"]
                && authenticated.report()["controller_identity"] == report["controller"]
                && report
                    .get("controller_signature_error")
                    .is_some_and(Value::is_null)
                && report["controller_signature_verification"] == authenticated.observation(),
        )?;
        for name in [
            "controller_cgroup_drained",
            "product_slice_absent",
            "image_lease_absent",
            "sdk_agent_absent",
            "sdk_profile_absent",
            "mcp_agent_absent",
            "mcp_profile_absent",
        ] {
            require(report[name] == true)?;
        }
        Ok(HostNativeControlReadback {
            diagnostic: authenticated.report().clone(),
            observation: json!({
            "schema":"hol-gauntlet-host-native-control-readback.v1","job_id":p.job_id,"source_sha":p.source_sha,
            "deployment_digest":p.deployment_digest,"worker_generation":p.worker_generation,
            "host_pin_sha256":record.raw_sha256,"report_sha256":terminal["report_sha256"],"terminal_sha256":frame["terminal_sha256"],
            "controller_signature":authenticated.observation(),"host_prelaunch_tuple_bound":true,
            "reported_status":authenticated.report()["status"],"independent_effects_scored":false,"qualified_role_complete":false,
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
        })
    }
}

#[cfg(test)]
#[path = "native_control_readback_tests.rs"]
mod tests;
