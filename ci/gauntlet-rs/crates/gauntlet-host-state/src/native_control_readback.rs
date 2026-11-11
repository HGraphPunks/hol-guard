//! Reauthenticate an explicitly selected completion against the host's durable pin.
//! A signed controller diagnostic remains separate from independent scoring.
use crate::{HostControllerKeyPinJournal, HostKeyPinError, HostPrelaunchIdentity};
use gauntlet_contracts::{canonicalize, PrelaunchPrepared, NATIVE_HOST_PINNED_COMPLETION_LIMIT};
use gauntlet_evidence::{
    verify_native_control_envelope, AuthenticatedNativeControlReport, NativeControlReportPins,
};
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

fn initial_world_hash(spec: &Value) -> Result<String> {
    let mut initial = spec["initial_snapshot"].clone();
    initial["records"]
        .as_array_mut()
        .ok_or(NativeControlReadbackError::InvalidFrame)?
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    digest(&initial)
}

fn live_preparation(
    value: &Value,
    outside_sha: &str,
    expected: &HostPrelaunchIdentity,
    preparation: &str,
    role: &str,
) -> Result<[u8; 32]> {
    let fields = [
        "schema",
        "source_sha",
        "job_id",
        "deployment_digest",
        "worker_generation",
        "preparation_sha256",
        "role",
        "cell_id",
        "spec_sha256",
        "normal_preparation_receipt_sha256",
        "world_public_key_hex",
        "world_initial_sha256",
        "cleanup_public_key_hex",
    ];
    let spec = gauntlet_evidence::feature_ai_support_spec()
        .map_err(|_| NativeControlReadbackError::InvalidFrame)?;
    let protected = match role {
        "feature-ai-unprotected" => false,
        "feature-ai-protected" => true,
        _ => return Err(NativeControlReadbackError::WrongIdentity),
    };
    let cell = spec["cells"]
        .as_array()
        .and_then(|cells| {
            cells
                .iter()
                .find(|cell| cell["protected"].as_bool() == Some(protected))
        })
        .ok_or(NativeControlReadbackError::InvalidFrame)?;
    require(
        value.as_object().is_some_and(|o| {
            o.len() == fields.len() && fields.iter().all(|field| o.contains_key(*field))
        }) && value["schema"] == "hol-gauntlet-native-live-prepared.v2"
            && digest(value)? == outside_sha
            && value["source_sha"] == expected.source_sha
            && value["job_id"] == expected.job_id
            && value["deployment_digest"] == expected.deployment_digest
            && value["worker_generation"] == expected.worker_generation
            && value["preparation_sha256"] == preparation
            && value["role"] == role
            && value["cell_id"] == cell["id"]
            && value["spec_sha256"] == digest(&spec)?
            && value["world_initial_sha256"] == initial_world_hash(&spec)?
            && [
                "normal_preparation_receipt_sha256",
                "world_public_key_hex",
                "cleanup_public_key_hex",
            ]
            .iter()
            .all(|field| {
                value[*field].as_str().is_some_and(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            }),
    )?;
    let key = value["cleanup_public_key_hex"]
        .as_str()
        .ok_or(NativeControlReadbackError::InvalidFrame)?;
    let mut decoded = [0; 32];
    for (index, part) in key.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = u8::from_str_radix(
            std::str::from_utf8(part).map_err(|_| NativeControlReadbackError::InvalidFrame)?,
            16,
        )
        .map_err(|_| NativeControlReadbackError::InvalidFrame)?;
    }
    Ok(decoded)
}

#[derive(Debug, Clone)]
pub struct HostNativeControlReadback {
    diagnostic: Value,
    observation: Value,
    pub(crate) authenticated: AuthenticatedNativeControlReport,
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
        self.verify_completion_inner(raw, expected, preparation_sha256, role, None, None)
    }

    pub fn verify_native_live_completion(
        &self,
        raw: &[u8],
        expected: &HostPrelaunchIdentity,
        preparation_sha256: &str,
        role: &str,
        prepared: &Value,
        prepared_sha256: &str,
    ) -> Result<HostNativeControlReadback> {
        live_preparation(
            prepared,
            prepared_sha256,
            expected,
            preparation_sha256,
            role,
        )?;
        self.verify_completion_inner(
            raw,
            expected,
            preparation_sha256,
            role,
            Some((prepared, prepared_sha256)),
            None,
        )
    }

    /// The storage pin is the original, verified initialization-v2 receipt,
    /// retained before controller release, never a field copied from this return.
    pub fn verify_native_bounded_completion(
        &self,
        raw: &[u8],
        expected: &HostPrelaunchIdentity,
        preparation_sha256: &str,
        role: &str,
        live: Option<(&Value, &str)>,
        original_storage: &Value,
    ) -> Result<HostNativeControlReadback> {
        if let Some((prepared, pin)) = live {
            live_preparation(prepared, pin, expected, preparation_sha256, role)?;
        }
        let formatter = original_storage["receipt"]["mke2fs_sha256"]
            .as_str()
            .ok_or(NativeControlReadbackError::WrongIdentity)?;
        crate::native_operation::verify_job_storage(
            original_storage,
            &expected.source_sha,
            &expected.job_id,
            &expected.worker_generation,
            formatter,
            "native-v1",
        )
        .map_err(|_| NativeControlReadbackError::WrongIdentity)?;
        self.verify_completion_inner(
            raw,
            expected,
            preparation_sha256,
            role,
            live,
            Some(original_storage),
        )
    }

    fn verify_completion_inner(
        &self,
        raw: &[u8],
        expected: &HostPrelaunchIdentity,
        preparation_sha256: &str,
        role: &str,
        live: Option<(&Value, &str)>,
        original_storage: Option<&Value>,
    ) -> Result<HostNativeControlReadback> {
        let readonly = role == "readonly-utility";
        if live.is_none() && matches!(role, "feature-ai-unprotected" | "feature-ai-protected") {
            return Err(NativeControlReadbackError::WrongIdentity);
        }
        let (completion, report_schema, profile) = if live.is_some() {
            (
                "hol-gauntlet-native-host-pinned-completion.v3",
                "hol-gauntlet-native-worker-report.v9",
                "native-host-pinned-live-omp-v1",
            )
        } else if readonly {
            (
                "hol-gauntlet-native-host-pinned-completion.v2",
                "hol-gauntlet-native-worker-report.v8",
                "native-host-pinned-readonly-hook-v1",
            )
        } else {
            (
                "hol-gauntlet-native-host-pinned-completion.v1",
                "hol-gauntlet-native-worker-report.v7",
                "native-host-pinned-control-v1",
            )
        };
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
                && frame["schema"] == completion
                && frame["execution_eligible"] == false
                && frame["guard_causality_verified"] == false
                && if live.is_some() {
                    frame["model_requests"].as_u64().is_some_and(|n| n <= 64)
                } else {
                    frame["model_requests"].as_u64() == Some(0)
                },
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
        require(report.get("retained_storage") == original_storage)?;
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
                && report["schema"] == report_schema,
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
                && report["profile"] == profile
                && report["preparation_sha256"] == preparation_sha256
                && report["execution_eligible"] == false
                && report["guard_causality_verified"] == false
                && report["model_requests"] == frame["model_requests"],
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
        if let Some((prepared, prepared_sha)) = live {
            let world = &report["live_world"];
            require(
                report["live_prepared_sha256"] == prepared_sha
                    && report["model_channel_pending"] == false
                    && authenticated.report()["model_requests"] == frame["model_requests"]
                    && authenticated.report()["cell_id"] == prepared["cell_id"]
                    && world.as_object().is_some_and(|o| o.len() == 8)
                    && world["schema"] == "hol-gauntlet-native-live-world-final.v1"
                    && world["prepared_sha256"] == prepared_sha
                    && world["world_public_key_hex"] == prepared["world_public_key_hex"]
                    && world["world_initial_sha256"] == prepared["world_initial_sha256"]
                    && world["receipt_count"]
                        .as_u64()
                        .is_some_and(|n| n <= 100_000)
                    && ["world_final_sha256", "final_hash"].iter().all(|field| {
                        world[*field].as_str().is_some_and(|s| {
                            s.len() == 64
                                && s.bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        })
                    })
                    && prepared["cleanup_public_key_hex"] != prepared["world_public_key_hex"]
                    && prepared["cleanup_public_key_hex"] != p.controller_public_key_hex
                    && prepared["world_public_key_hex"] != p.controller_public_key_hex,
            )?;
            let key = live_preparation(prepared, prepared_sha, expected, preparation_sha256, role)?;
            require(
                gauntlet_evidence::verify_feature_ai_support_cleanup(
                    &report["live_cleanup"],
                    authenticated.report(),
                    &key,
                )
                .map_err(|_| NativeControlReadbackError::Signature)?,
            )?;
        }
        for name in [
            "controller_cgroup_drained",
            "product_slice_absent",
            "image_lease_absent",
        ] {
            require(report[name] == true)?;
        }
        if !readonly {
            for name in [
                "sdk_agent_absent",
                "sdk_profile_absent",
                "mcp_agent_absent",
                "mcp_profile_absent",
            ] {
                require(report[name] == true)?;
            }
        }
        let mut result = HostNativeControlReadback {
            diagnostic: authenticated.report().clone(),
            observation: json!({
            "schema":if live.is_some() {"hol-gauntlet-host-native-control-readback.v3"}else if readonly {"hol-gauntlet-host-native-control-readback.v2"}else{"hol-gauntlet-host-native-control-readback.v1"},"job_id":p.job_id,"source_sha":p.source_sha,
            "deployment_digest":p.deployment_digest,"worker_generation":p.worker_generation,
            "host_pin_sha256":record.raw_sha256,"report_sha256":terminal["report_sha256"],"terminal_sha256":frame["terminal_sha256"],
            "controller_signature":authenticated.observation(),"host_prelaunch_tuple_bound":true,
            "reported_status":authenticated.report()["status"],"independent_effects_scored":false,"qualified_role_complete":false,
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":frame["model_requests"]}),
            authenticated,
        };
        if let Some(storage) = original_storage {
            result.observation["bounded_storage"] = json!({"receipt_sha256":storage["receipt_sha256"],
                "profile":storage["receipt"]["profile"],"limits":storage["receipt"]["limits"],
                "original_initialization_bound":true});
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "native_control_readback_tests.rs"]
pub(crate) mod tests;
