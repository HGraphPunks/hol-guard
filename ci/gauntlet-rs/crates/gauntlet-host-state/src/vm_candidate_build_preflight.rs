//! Existing read-only readiness contract, shared by both transport paths.
use super::*;

const MAX_PREFLIGHT_BYTES: usize = 2048;
const MIN_START_FREE: u64 = 12 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmCandidateBuildPreflightError {
    InvalidBinaryPin,
    InvalidResponse,
    Unavailable,
    TimedOut,
    TooLarge,
}
impl fmt::Display for VmCandidateBuildPreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBinaryPin => "exact outside candidate readiness binary SHA-256 required",
            Self::InvalidResponse => "VM candidate readiness differs from outside build pins",
            Self::Unavailable => "VM candidate readiness probe unavailable",
            Self::TimedOut => "VM candidate readiness probe timed out",
            Self::TooLarge => "VM candidate readiness response too large",
        })
    }
}
impl std::error::Error for VmCandidateBuildPreflightError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmCandidateBuildPreflightPlan {
    argv: Vec<String>,
    pins: HostCandidateBuildPins,
    storage_sha256: Option<String>,
}
impl VmCandidateBuildPlan {
    /// Read-only VM check, intentionally before the host journal consumes a
    /// job ID. The actual run repeats these checks under its own locks.
    pub fn preflight_plan(
        &self,
        binary_sha256: &str,
    ) -> Result<VmCandidateBuildPreflightPlan, VmCandidateBuildPreflightError> {
        if !lower_hex(binary_sha256, 64) {
            return Err(VmCandidateBuildPreflightError::InvalidBinaryPin);
        }
        let pins = &self.pins;
        Ok(VmCandidateBuildPreflightPlan {
            argv: vec![
                self.limactl.clone(),
                "shell".to_owned(),
                self.vm.clone(),
                "--".to_owned(),
                "sudo".to_owned(),
                "-n".to_owned(),
                format!("/opt/hol-gauntlet/rust-candidate-build-ready-shadow-{binary_sha256}"),
                pins.controller_root.clone(),
                pins.controller_tree_sha256.clone(),
                pins.job_id.clone(),
                pins.uv_base_image_id.clone(),
                pins.rust_base_image_id.clone(),
                pins.builder_image_id.clone(),
                pins.source_sha.clone(),
                pins.source_archive_sha256.clone(),
                pins.version.clone(),
                pins.tag.clone(),
                pins.podman_sha256.clone(),
                pins.slirp4netns_sha256.clone(),
                pins.apparmor_parser_sha256.clone(),
                pins.seccomp_sha256.clone(),
                pins.policy_sha256.clone(),
            ],
            pins: pins.clone(),
            storage_sha256: None,
        })
    }

    pub(crate) fn bounded_preflight_plan(
        &self,
        binary_sha256: &str,
        original_source: &Value,
    ) -> Result<VmCandidateBuildPreflightPlan, VmCandidateBuildPreflightError> {
        let storage_sha256 = original_source["storage_receipt_sha256"]
            .as_str()
            .ok_or(VmCandidateBuildPreflightError::InvalidBinaryPin)?;
        if !lower_hex(storage_sha256, 64) {
            return Err(VmCandidateBuildPreflightError::InvalidBinaryPin);
        }
        let mut plan = self.preflight_plan(binary_sha256)?;
        plan.storage_sha256 = Some(storage_sha256.into());
        Ok(plan)
    }

    // Only reconstruction of a complete consumed launch may call this. Fresh
    // bounded dispatch always uses bounded_preflight_plan and refuses v2.
    pub(crate) fn parse_retained_bounded_preflight(
        &self,
        binary: &str,
        source: &Value,
        original: &[u8],
    ) -> Result<Value, VmCandidateBuildPreflightError> {
        let value: Value = serde_json::from_slice(original)
            .map_err(|_| VmCandidateBuildPreflightError::InvalidResponse)?;
        let plan = if value["schema"] == "hol-gauntlet-candidate-build-ready-shadow.v2" {
            self.preflight_plan(binary)?
        } else {
            self.bounded_preflight_plan(binary, source)?
        };
        plan.parse_response(original)
    }
}
impl VmCandidateBuildPreflightPlan {
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, VmCandidateBuildPreflightError> {
        if stdout.len() > MAX_PREFLIGHT_BYTES + 1 {
            return Err(VmCandidateBuildPreflightError::TooLarge);
        }
        let frame = stdout
            .strip_suffix(b"\n")
            .filter(|frame| !frame.is_empty() && !frame.contains(&b'\n'))
            .ok_or(VmCandidateBuildPreflightError::InvalidResponse)?;
        if canonicalize(frame).map_err(|_| VmCandidateBuildPreflightError::InvalidResponse)?
            != frame
        {
            return Err(VmCandidateBuildPreflightError::InvalidResponse);
        }
        let value: Value = serde_json::from_slice(frame)
            .map_err(|_| VmCandidateBuildPreflightError::InvalidResponse)?;
        let object = value
            .as_object()
            .ok_or(VmCandidateBuildPreflightError::InvalidResponse)?;
        let profile = match &self.storage_sha256 {
            None => {
                object.len() == 13
                    && value["schema"] == "hol-gauntlet-candidate-build-ready-shadow.v2"
            }
            Some(storage) => {
                object.len() == 15
                    && value["schema"] == "hol-gauntlet-candidate-build-ready-shadow.v3"
                    && value["storage_receipt_sha256"] == *storage
                    && matches!(
                        value["builder_inputs_state"].as_str(),
                        Some("preparable" | "complete")
                    )
            }
        };
        if !profile
            || value["job_id"] != self.pins.job_id
            || value["source_sha"] != self.pins.source_sha
            || value["source_archive_sha256"] != self.pins.source_archive_sha256
            || value["tag"] != self.pins.tag
            || value["image_id"] != self.pins.builder_image_id
            || value["policy_sha256"] != self.pins.policy_sha256
            || value["free_disk_bytes"]
                .as_u64()
                .is_none_or(|bytes| bytes < MIN_START_FREE)
            || value["ready_at_probe"] != true
            || value["host_pin_recorded"] != false
            || value["candidate_started"] != false
            || value["artifact_admitted"] != false
            || value["execution_eligible"] != false
        {
            return Err(VmCandidateBuildPreflightError::InvalidResponse);
        }
        let mut result = json!({"schema":"hol-gauntlet-host-candidate-build-ready-shadow.v2","job_id":self.pins.job_id,
            "source_sha":self.pins.source_sha,"tag":self.pins.tag,"free_disk_bytes":value["free_disk_bytes"],
            "ready_at_probe":true,"host_pin_recorded":false,"candidate_started":false,"execution_eligible":false});
        if let Some(storage) = &self.storage_sha256 {
            result["schema"] = json!("hol-gauntlet-host-candidate-build-ready-shadow.v3");
            result["storage_receipt_sha256"] = json!(storage);
            result["builder_inputs_state"] = value["builder_inputs_state"].clone();
        }
        Ok(result)
    }
    pub fn execute_read_only(&self) -> Result<Value, VmCandidateBuildPreflightError> {
        let output = run_fixed(
            &self.argv,
            Duration::from_secs(120),
            MAX_PREFLIGHT_BYTES + 1,
            1500,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                VmCandidateBuildPreflightError::Unavailable
            }
            FixedProcessError::TimedOut => VmCandidateBuildPreflightError::TimedOut,
            FixedProcessError::TooLarge => VmCandidateBuildPreflightError::TooLarge,
        })?;
        self.parse_response(&output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> VmCandidateBuildPlan {
        let pin = "a".repeat(64);
        VmCandidateBuildPlan {
            limactl: "/opt/homebrew/bin/limactl".into(),
            vm: "fresh-vm".into(),
            pins: HostCandidateBuildPins {
                job_id: "0123456789abcdef".into(),
                source_sha: "b".repeat(40),
                source_archive_sha256: pin.clone(),
                version: "3.49.0".into(),
                tag: "v3.49.0".into(),
                controller_root: "/opt/hol-gauntlet/controller".into(),
                controller_tree_sha256: pin.clone(),
                uv_base_image_id: pin.clone(),
                rust_base_image_id: pin.clone(),
                builder_image_id: format!("sha256:{pin}"),
                policy_sha256: pin.clone(),
                podman_sha256: pin.clone(),
                slirp4netns_sha256: pin.clone(),
                apparmor_parser_sha256: pin.clone(),
                seccomp_sha256: pin.clone(),
                runner_binary_sha256: pin.clone(),
                result_reader_binary_sha256: pin,
            },
        }
    }
    fn frame(v: &Value) -> Vec<u8> {
        let mut raw = canonicalize(v.to_string().as_bytes()).unwrap();
        raw.push(b'\n');
        raw
    }
    fn ready(p: &HostCandidateBuildPins) -> Value {
        json!({"schema":"hol-gauntlet-candidate-build-ready-shadow.v3","job_id":p.job_id,
            "source_sha":p.source_sha,"source_archive_sha256":p.source_archive_sha256,"tag":p.tag,
            "image_id":p.builder_image_id,"policy_sha256":p.policy_sha256,"free_disk_bytes":MIN_START_FREE,
            "ready_at_probe":true,"host_pin_recorded":false,"candidate_started":false,
            "artifact_admitted":false,"execution_eligible":false,"builder_inputs_state":"preparable",
            "storage_receipt_sha256":"c".repeat(64)})
    }
    #[test]
    fn bounded_readiness_binds_original_storage_and_never_admits_partial_or_legacy() {
        let p = plan();
        let source = json!({"storage_receipt_sha256":"c".repeat(64)});
        let bounded = p.bounded_preflight_plan(&"d".repeat(64), &source).unwrap();
        let generic = p.preflight_plan(&"d".repeat(64)).unwrap();
        for state in ["preparable", "complete"] {
            let mut v = ready(&p.pins);
            v["builder_inputs_state"] = json!(state);
            let result = bounded.parse_response(&frame(&v)).unwrap();
            assert_eq!(result["builder_inputs_state"], state);
            assert_eq!(
                result["storage_receipt_sha256"],
                source["storage_receipt_sha256"]
            );
            assert!(generic.parse_response(&frame(&v)).is_err());
        }
        let v = ready(&p.pins);
        for (key, changed) in [
            ("storage_receipt_sha256", json!("e".repeat(64))),
            ("source_sha", json!("e".repeat(40))),
            ("job_id", json!("fedcba9876543210")),
            ("source_archive_sha256", json!("e".repeat(64))),
            ("builder_inputs_state", json!("partial")),
            ("builder_inputs_state", Value::Null),
            (
                "schema",
                json!("hol-gauntlet-candidate-build-ready-shadow.v2"),
            ),
            ("free_disk_bytes", json!(1)),
            ("host_pin_recorded", json!(true)),
            ("execution_eligible", json!(true)),
        ] {
            let mut changed_v = v.clone();
            changed_v[key] = changed;
            assert!(bounded.parse_response(&frame(&changed_v)).is_err(), "{key}");
        }
        let mut legacy = v;
        legacy["schema"] = json!("hol-gauntlet-candidate-build-ready-shadow.v2");
        legacy
            .as_object_mut()
            .unwrap()
            .remove("storage_receipt_sha256");
        legacy
            .as_object_mut()
            .unwrap()
            .remove("builder_inputs_state");
        assert!(bounded.parse_response(&frame(&legacy)).is_err());
        assert!(generic.parse_response(&frame(&legacy)).is_ok());
        let original = frame(&legacy);
        assert!(p
            .parse_retained_bounded_preflight(&"d".repeat(64), &source, &original)
            .is_ok());
        assert_eq!(original, frame(&legacy));
    }
}
