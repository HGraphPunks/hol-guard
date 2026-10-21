//! One-use host plan for a future host-bound candidate compile. Constructing
//! the invocation durably records the outside pins before a caller can spawn
//! the fixed guest binary. This module does not execute or admit a build.

use crate::{
    load_operations_bytes, HostCandidateBuildPinError, HostCandidateBuildPinJournal,
    HostCandidateBuildPinRecord, HostCandidateBuildPins,
};
use serde_json::{json, Value};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmCandidateBuildError {
    InvalidConfig,
    InvalidPins,
    HostPin(HostCandidateBuildPinError),
}

impl fmt::Display for VmCandidateBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("fixed local VM builder configuration required"),
            Self::InvalidPins => f.write_str("complete outside candidate build pins required"),
            Self::HostPin(error) => write!(f, "prelaunch host pin: {error}"),
        }
    }
}

impl std::error::Error for VmCandidateBuildError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmCandidateBuildPlan {
    limactl: String,
    vm: String,
    pins: HostCandidateBuildPins,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmCandidateBuildInvocation {
    argv: Vec<String>,
    record: HostCandidateBuildPinRecord,
}

impl VmCandidateBuildPlan {
    pub fn new(
        operations: &Value,
        pins: HostCandidateBuildPins,
    ) -> Result<Self, VmCandidateBuildError> {
        if !pins.valid() {
            return Err(VmCandidateBuildError::InvalidPins);
        }
        let raw =
            serde_json::to_vec(operations).map_err(|_| VmCandidateBuildError::InvalidConfig)?;
        let config =
            load_operations_bytes(&raw).map_err(|_| VmCandidateBuildError::InvalidConfig)?;
        if config["release_build_backend"] != "local-vm"
            || config["build_memory_gib"] != 12
            || config["vm_memory_gib"]
                .as_u64()
                .is_none_or(|memory| memory < 16)
            || config["vm_cpus"].as_u64().is_none_or(|cpus| cpus < 2)
        {
            return Err(VmCandidateBuildError::InvalidConfig);
        }
        let limactl = config["limactl"]
            .as_str()
            .ok_or(VmCandidateBuildError::InvalidConfig)?;
        let vm = config["vm"]
            .as_str()
            .ok_or(VmCandidateBuildError::InvalidConfig)?;
        Ok(Self {
            limactl: limactl.to_owned(),
            vm: vm.to_owned(),
            pins,
        })
    }

    /// Fsync the one-use host record before returning any executable argv.
    /// A partial or uncertain record consumes the job ID; callers must not
    /// retry on transport failure without independent guest reconciliation.
    pub fn record_before_launch(
        &self,
        journal: &HostCandidateBuildPinJournal,
    ) -> Result<VmCandidateBuildInvocation, VmCandidateBuildError> {
        let record = journal
            .record(&self.pins)
            .map_err(VmCandidateBuildError::HostPin)?;
        let pins = &record.pins;
        let argv = vec![
            self.limactl.clone(),
            "shell".to_owned(),
            self.vm.clone(),
            "--".to_owned(),
            "sudo".to_owned(),
            "-n".to_owned(),
            format!(
                "/opt/hol-gauntlet/rust-candidate-run-hostbound-shadow-{}",
                pins.runner_binary_sha256
            ),
            pins.controller_root.clone(),
            pins.controller_tree_sha256.clone(),
            pins.job_id.clone(),
            pins.uv_base_image_id.clone(),
            pins.rust_base_image_id.clone(),
            pins.builder_image_id.clone(),
            pins.source_sha.clone(),
            pins.source_archive_sha256.clone(),
            pins.version.clone(),
            pins.podman_sha256.clone(),
            pins.slirp4netns_sha256.clone(),
            pins.apparmor_parser_sha256.clone(),
            pins.seccomp_sha256.clone(),
            pins.policy_sha256.clone(),
            pins.result_reader_binary_sha256.clone(),
            record.raw_sha256.clone(),
            record.host_nonce_hex.clone(),
        ];
        Ok(VmCandidateBuildInvocation { argv, record })
    }
}

impl VmCandidateBuildInvocation {
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn record(&self) -> &HostCandidateBuildPinRecord {
        &self.record
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-vm-candidate-build-invocation-shadow.v1",
            "job_id":self.record.pins.job_id,
            "source_sha":self.record.pins.source_sha,
            "host_pin_sha256":self.record.raw_sha256,
            "host_pin_durable":true,
            "vm_started":false,
            "artifact_admitted":false,
            "execution_eligible":false,
        })
    }
}
