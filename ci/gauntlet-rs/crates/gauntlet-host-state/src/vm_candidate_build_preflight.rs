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
        })
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
        if object.len() != 13
            || value["schema"] != "hol-gauntlet-candidate-build-ready-shadow.v2"
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
        Ok(
            json!({"schema":"hol-gauntlet-host-candidate-build-ready-shadow.v2","job_id":self.pins.job_id,
            "source_sha":self.pins.source_sha,"tag":self.pins.tag,"free_disk_bytes":value["free_disk_bytes"],
            "ready_at_probe":true,"host_pin_recorded":false,"candidate_started":false,"execution_eligible":false}),
        )
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
