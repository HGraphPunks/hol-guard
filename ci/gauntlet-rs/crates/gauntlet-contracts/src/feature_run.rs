//! Closed outside intent for one Rust-owned feature audit. No caller-controlled
//! command, selector, resource limit or candidate path crosses this boundary.
use crate::{canonicalize, FeatureExecutorSpec};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

pub const FEATURE_INTENT_LIMIT: usize = 16 * 1024;
const FIELDS: &[&str] = &[
    "executor_spec",
    "build_job_id",
    "build_result_sha256",
    "controller_root",
    "controller_tree_sha256",
    "uv_base_image_id",
    "rust_base_image_id",
    "builder_image_id",
    "policy_sha256",
    "podman_sha256",
    "slirp4netns_sha256",
    "apparmor_parser_sha256",
    "seccomp_sha256",
    "runner_binary_sha256",
];

fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, PartialEq)]
pub struct FeatureRunPins {
    value: Value,
    spec: FeatureExecutorSpec,
}
impl FeatureRunPins {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > FEATURE_INTENT_LIMIT {
            return Err("bounded feature run pins required".into());
        }
        let bytes = canonicalize(raw).map_err(|e| e.to_string())?;
        Self::from_value(serde_json::from_slice(&bytes).map_err(|e| e.to_string())?)
    }
    pub fn from_value(value: Value) -> Result<Self, String> {
        if value.as_object().is_none_or(|v| v.len() != FIELDS.len())
            || FIELDS.iter().any(|k| value.get(*k).is_none())
        {
            return Err("closed feature run pins required".into());
        }
        let spec = FeatureExecutorSpec::parse(value["executor_spec"].to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        for &field in FIELDS {
            if field == "executor_spec" {
                continue;
            }
            let text = value[field].as_str().ok_or("feature pin string required")?;
            let valid = match field {
                "build_job_id" => hex(text, 16) && text != spec.text("audit_id"),
                "controller_root" => text
                    .strip_prefix("/opt/hol-gauntlet/controller-")
                    .is_some_and(|s| hex(s, 16)),
                "builder_image_id" => text.strip_prefix("sha256:").is_some_and(|s| hex(s, 64)),
                _ => hex(text, 64),
            };
            if !valid {
                return Err(format!("invalid feature pin: {field}"));
            }
        }
        Ok(Self { value, spec })
    }
    pub fn text(&self, key: &str) -> &str {
        self.value[key].as_str().unwrap_or("")
    }
    pub fn value(&self) -> &Value {
        &self.value
    }
    pub fn spec(&self) -> &FeatureExecutorSpec {
        &self.spec
    }
    pub fn audit_id(&self) -> &str {
        self.spec.text("audit_id")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FeatureRunIntent {
    pins: FeatureRunPins,
    limactl: String,
    vm: String,
    nonce: String,
}
impl FeatureRunIntent {
    pub fn new(pins: FeatureRunPins, limactl: &str, vm: &str, nonce: &str) -> Result<Self, String> {
        let path = Path::new(limactl);
        if !hex(nonce, 64)
            || !path.is_absolute()
            || path.file_name().is_none_or(|n| n != "limactl")
            || path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
            || vm.is_empty()
            || vm.len() > 64
            || vm.starts_with('-')
            || !vm
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err("exact feature target and host nonce required".into());
        }
        let intent = Self {
            pins,
            limactl: limactl.into(),
            vm: vm.into(),
            nonce: nonce.into(),
        };
        intent.bytes()?;
        Ok(intent)
    }
    pub fn pins(&self) -> &FeatureRunPins {
        &self.pins
    }
    pub fn limactl(&self) -> &str {
        &self.limactl
    }
    pub fn vm(&self) -> &str {
        &self.vm
    }
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        let v = json!({"schema":"hol-gauntlet-host-feature-intent.v1","pins":self.pins.value(),
            "limactl":self.limactl,"vm":self.vm,"host_nonce_hex":self.nonce});
        let raw = canonicalize(v.to_string().as_bytes()).map_err(|e| e.to_string())?;
        if raw.len() > FEATURE_INTENT_LIMIT {
            return Err("feature intent exceeds bound".into());
        }
        Ok(raw)
    }
    pub fn digest(&self) -> Result<String, String> {
        Ok(format!("{:x}", Sha256::digest(self.bytes()?)))
    }
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.is_empty()
            || raw.len() > FEATURE_INTENT_LIMIT
            || canonicalize(raw).map_err(|e| e.to_string())? != raw
        {
            return Err("bounded canonical feature intent required".into());
        }
        let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        if v.as_object().is_none_or(|v| v.len() != 5)
            || v["schema"] != "hol-gauntlet-host-feature-intent.v1"
        {
            return Err("closed feature intent required".into());
        }
        let text = |k: &str| v[k].as_str().ok_or("feature intent string missing");
        Self::new(
            FeatureRunPins::from_value(v["pins"].clone())?,
            text("limactl")?,
            text("vm")?,
            text("host_nonce_hex")?,
        )
    }
}

/// Validate the Root worker's closed diagnostic response against the retained
/// outside intent. This binds a supervisor claim; it grants no qualification.
pub fn verify_feature_run_result(intent: &FeatureRunIntent, v: &Value) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "schema",
        "audit_id",
        "source_sha",
        "intent_sha256",
        "worker_generation",
        "container_id",
        "client_pid",
        "client_start_ticks",
        "exit_code",
        "execution_error",
        "audit_status",
        "feature_report_sha256",
        "feature_readback_sha256",
        "stdout_sha256",
        "stderr_sha256",
        "feature_artifacts_verified",
        "container_absent",
        "container_cgroup_absent",
        "client_cgroup_drained",
        "build_profile_removed",
        "status",
        "rust_root_supervised",
        "artifact_admitted",
        "execution_eligible",
        "qualification_eligible",
        "guard_causality_verified",
        "model_requests",
        "model_tokens",
    ];
    if v.as_object().is_none_or(|v| v.len() != FIELDS.len())
        || FIELDS.iter().any(|k| v.get(*k).is_none())
        || v["schema"] != "hol-gauntlet-native-feature-result.v1"
        || v["audit_id"] != intent.pins().audit_id()
        || v["source_sha"] != intent.pins().spec().text("source_sha")
        || v["intent_sha256"] != intent.digest()?
        || v["worker_generation"] != intent.pins().text("runner_binary_sha256")
        || v["status"] != "invalid-evidence"
        || !["container_id", "stdout_sha256", "stderr_sha256"]
            .iter()
            .all(|k| v[*k].as_str().is_some_and(|s| hex(s, 64)))
        || !v["client_pid"]
            .as_u64()
            .is_some_and(|n| n > 1 && n <= u32::MAX as u64)
        || v["client_start_ticks"].as_u64().is_none_or(|n| n == 0)
        || !v["exit_code"]
            .as_i64()
            .is_some_and(|n| (0..=255).contains(&n))
        || ![
            "container_absent",
            "container_cgroup_absent",
            "client_cgroup_drained",
            "build_profile_removed",
            "rust_root_supervised",
        ]
        .iter()
        .all(|k| v[*k] == true)
        || ![
            "artifact_admitted",
            "execution_eligible",
            "qualification_eligible",
            "guard_causality_verified",
        ]
        .iter()
        .all(|k| v[*k] == false)
        || v["model_requests"].as_u64() != Some(0)
        || v["model_tokens"].as_u64() != Some(0)
        || !v["execution_error"].is_null()
            && !v["execution_error"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 1024)
    {
        return Err("feature response differs from reserved diagnostic execution".into());
    }
    let verified = v["feature_artifacts_verified"]
        .as_bool()
        .ok_or("feature verification flag required")?;
    if verified {
        if !["feature_report_sha256", "feature_readback_sha256"]
            .iter()
            .all(|k| v[*k].as_str().is_some_and(|s| hex(s, 64)))
            || !matches!(
                v["audit_status"].as_str(),
                Some("passed" | "failed" | "incomplete" | "invalid-evidence")
            )
            || !v["execution_error"].is_null()
            || v["exit_code"] != if v["audit_status"] == "passed" { 0 } else { 1 }
        {
            return Err("verified feature response contradicts report status".into());
        }
    } else if !v["feature_report_sha256"].is_null()
        || !v["feature_readback_sha256"].is_null()
        || v["audit_status"] != "invalid-evidence"
        || v["execution_error"].is_null()
    {
        return Err("unverified feature response claims report authority".into());
    }
    Ok(())
}

/// Bind an aborted supervisor receipt to the outside intent and an explicitly
/// authorized repair executable. Physical cleanup is rechecked by the guest;
/// this structural check never establishes artifact or qualification authority.
pub fn verify_feature_repair_result(
    intent: &FeatureRunIntent,
    v: &Value,
    repair_generation: &str,
) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "schema",
        "audit_id",
        "source_sha",
        "intent_sha256",
        "worker_generation",
        "repair_generation",
        "running_sha256",
        "container_id",
        "status",
        "exit_code",
        "quiescent",
        "artifact_admitted",
        "execution_eligible",
        "qualification_eligible",
        "guard_causality_verified",
        "model_requests",
        "model_tokens",
    ];
    if !hex(repair_generation, 64)
        || v.as_object().is_none_or(|v| v.len() != FIELDS.len())
        || FIELDS.iter().any(|k| v.get(*k).is_none())
        || v["schema"] != "hol-gauntlet-native-feature-repair.v1"
        || v["audit_id"] != intent.pins().audit_id()
        || v["source_sha"] != intent.pins().spec().text("source_sha")
        || v["intent_sha256"] != intent.digest()?
        || v["worker_generation"] != intent.pins().text("runner_binary_sha256")
        || v["repair_generation"] != repair_generation
        || v["status"] != "aborted"
        || !v["exit_code"].is_null()
        || v["quiescent"] != true
        || !["running_sha256", "container_id"]
            .iter()
            .all(|k| v[*k].is_null() || v[*k].as_str().is_some_and(|s| hex(s, 64)))
        || !v["running_sha256"].is_null() && v["container_id"].is_null()
        || ![
            "artifact_admitted",
            "execution_eligible",
            "qualification_eligible",
            "guard_causality_verified",
        ]
        .iter()
        .all(|k| v[*k] == false)
        || v["model_requests"].as_u64() != Some(0)
        || v["model_tokens"].as_u64() != Some(0)
    {
        return Err("feature repair differs from reserved aborted execution".into());
    }
    Ok(())
}
