//! Fixed read-only Lima call into a separately installed Rust telemetry image.

use crate::observer_process::{run_probe, ProbeError};
use crate::{TelemetryError, VmProbePlan};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmNativeProbePlan {
    pub argv: Vec<String>,
    parser: VmProbePlan,
}

impl VmNativeProbePlan {
    pub fn new(operations: &Value, binary_sha256: &str) -> Result<Self, TelemetryError> {
        if !crate::lifecycle_document::hex(binary_sha256, 64) {
            return Err(TelemetryError::InvalidConfig);
        }
        let parser = VmProbePlan::new(operations)?;
        Ok(Self {
            argv: vec![
                parser.argv[0].clone(),
                "shell".into(),
                parser.name.clone(),
                "--".into(),
                format!("/opt/hol-gauntlet/gauntlet-vm-telemetry-{binary_sha256}"),
            ],
            parser,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({"argv":self.argv,"read_only":true,"timeout_seconds":12,"admission_eligible":false})
    }

    pub fn parse_response(&self, raw: &[u8]) -> Result<Value, TelemetryError> {
        if raw.len() > 8192 {
            return Err(TelemetryError::TooLarge);
        }
        let bytes = canonicalize(raw).map_err(|_| TelemetryError::InvalidProbe)?;
        let mut value: Value =
            serde_json::from_slice(&bytes).map_err(|_| TelemetryError::InvalidProbe)?;
        let object = value.as_object_mut().ok_or(TelemetryError::InvalidProbe)?;
        if object.len() != 10
            || object.remove("schema") != Some(json!("hol-gauntlet-vm-telemetry.v1"))
            || object.remove("platform") != Some(json!("Linux"))
        {
            return Err(TelemetryError::InvalidProbe);
        }
        self.parser.parse_response(value.to_string().as_bytes())
    }

    pub fn execute_read_only(&self, cancel: &AtomicBool) -> Result<Value, TelemetryError> {
        let raw =
            run_probe(&self.argv, Duration::from_secs(12), 8192, &[], cancel).map_err(|error| {
                match error {
                    ProbeError::TooLarge => TelemetryError::TooLarge,
                    ProbeError::TimedOut => TelemetryError::TimedOut,
                    _ => TelemetryError::Unavailable,
                }
            })?;
        self.parse_response(&raw)
    }
}
