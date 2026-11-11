//! Durable one-use candidate dispatch; retained result claims never admit a build.

use crate::fixed_process::{run_fixed, FixedProcessError};
use crate::{
    load_operations_bytes, HostCandidateBuildPinError, HostCandidateBuildPinJournal,
    HostCandidateBuildPinRecord, HostCandidateBuildPins,
};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;

const MAX_TERMINAL_BYTES: usize = 8192;
#[path = "vm_candidate_build_preflight.rs"]
mod preflight;
pub use preflight::{VmCandidateBuildPreflightError, VmCandidateBuildPreflightPlan};

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmCandidateBuildLaunchError {
    HostPinChanged,
    DispatchUnavailable,
    GuestUncertain,
    TimedOut,
    TooLarge,
    InvalidTerminal,
}

impl fmt::Display for VmCandidateBuildLaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HostPinChanged => "prelaunch host candidate pin changed",
            Self::DispatchUnavailable => "candidate dispatch consumed; reconcile without retry",
            Self::GuestUncertain => "candidate VM execution uncertain; reconcile without retry",
            Self::TimedOut => "candidate VM transport timed out; reconcile without retry",
            Self::TooLarge => "candidate VM terminal output exceeded bound",
            Self::InvalidTerminal => "candidate VM terminal claim differs from host pins",
        })
    }
}

impl std::error::Error for VmCandidateBuildLaunchError {}

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
            .record_for_vm(&self.pins, &self.limactl, &self.vm)
            .map_err(VmCandidateBuildError::HostPin)?;
        Ok(self.invocation(record))
    }

    /// Reconstruct an opaque existing invocation only after its original pin
    /// identity and VM match. This never records or rearms a dispatch.
    pub(crate) fn retained_invocation(
        &self,
        journal: &HostCandidateBuildPinJournal,
    ) -> Result<VmCandidateBuildInvocation, VmCandidateBuildError> {
        let record = journal
            .read(&self.pins.job_id)
            .map_err(VmCandidateBuildError::HostPin)?;
        if record.pins != self.pins
            || record
                .vm_target
                .as_ref()
                .is_none_or(|(l, v)| l != &self.limactl || v != &self.vm)
        {
            return Err(VmCandidateBuildError::InvalidPins);
        }
        Ok(self.invocation(record))
    }

    fn invocation(&self, record: HostCandidateBuildPinRecord) -> VmCandidateBuildInvocation {
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
            pins.tag.clone(),
            pins.podman_sha256.clone(),
            pins.slirp4netns_sha256.clone(),
            pins.apparmor_parser_sha256.clone(),
            pins.seccomp_sha256.clone(),
            pins.policy_sha256.clone(),
            pins.result_reader_binary_sha256.clone(),
            record.raw_sha256.clone(),
            record.host_nonce_hex.clone(),
        ];
        VmCandidateBuildInvocation { argv, record }
    }
}

impl VmCandidateBuildInvocation {
    /// Recompute the fixed Root marker from the original opaque pin. Neither
    /// its canonical bytes nor the private nonce leave this API.
    pub(crate) fn anchor_sha256(record: &HostCandidateBuildPinRecord) -> Result<String, String> {
        let p = &record.pins;
        let tagged = record.schema != "hol-gauntlet-host-candidate-build-pin.v2";
        let mut v = json!({"schema":"hol-gauntlet-candidate-host-anchor.v1","job_id":p.job_id,"source_sha":p.source_sha,
            "source_archive_sha256":p.source_archive_sha256,"version":p.version,"controller_tree_sha256":p.controller_tree_sha256,
            "image_id":p.builder_image_id,"policy_sha256":p.policy_sha256,
            "runtime_pins":{"podman_sha256":p.podman_sha256,"slirp4netns_sha256":p.slirp4netns_sha256,
                "apparmor_parser_sha256":p.apparmor_parser_sha256,"seccomp_sha256":p.seccomp_sha256},
            "runner_binary_sha256":p.runner_binary_sha256,"result_reader_binary_sha256":p.result_reader_binary_sha256,
            "host_pin_sha256":record.raw_sha256,"host_nonce_hex":record.host_nonce_hex,
            "pre_candidate_run":true,"artifact_admitted":false,"execution_eligible":false});
        if tagged {
            v["schema"] = json!("hol-gauntlet-candidate-host-anchor.v2");
            v["tag"] = json!(p.tag);
        }
        let raw = canonicalize(v.to_string().as_bytes())
            .map_err(|_| "original anchor encoding invalid")?;
        Ok(format!("{:x}", Sha256::digest(raw)))
    }
    /// Only a response already checked by the fixed host-bound reader may
    /// supply these facts. That Root reader admits only a complete zero exit,
    /// checks the original nonce, and rehashes the actual retained files.
    pub(crate) fn completed_terminal(&self, report: &Value) -> Result<Value, String> {
        let p = &self.record.pins;
        let anchor = Self::anchor_sha256(&self.record)?;
        if report["job_id"] != p.job_id
            || report["source_sha"] != p.source_sha
            || report["version"] != p.version
            || report["host_pin_sha256"] != self.record.raw_sha256
            || report["host_anchor_sha256"] != anchor
            || [
                "retained_files_match",
                "cleanup_absent",
                "host_pin_journal_match",
            ]
            .iter()
            .any(|k| report[*k] != true)
            || ["result_sha256", "archive_sha256"]
                .iter()
                .any(|k| !report[*k].as_str().is_some_and(|s| lower_hex(s, 64)))
        {
            return Err(
                "completed read differs from original Host nonce/anchor or terminal custody".into(),
            );
        }
        Ok(
            json!({"schema":"hol-gauntlet-host-candidate-completed-read-terminal.v1","job_id":p.job_id,
            "source_sha":p.source_sha,"source_archive_sha256":p.source_archive_sha256,"version":p.version,
            "result_sha256":report["result_sha256"],"unadmitted_export_sha256":report["archive_sha256"],
            "host_pin_sha256":self.record.raw_sha256,"host_anchor_sha256":anchor,"status":"exited-zero","exit_code":0,
            "authority":"original-host-bound-completed-read","artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false}),
        )
    }
    pub(crate) fn prior_terminal_sha256(
        &self,
        initial: &[u8],
        completed: &Value,
    ) -> Result<String, String> {
        if let Ok(original) = serde_json::from_slice::<Value>(initial) {
            let claim = self
                .parse_terminal_claim(initial)
                .map_err(|_| "complete original terminal conflicts with recovery")?;
            if [
                "status",
                "exit_code",
                "result_sha256",
                "unadmitted_export_sha256",
            ]
            .iter()
            .any(|k| claim[*k] != completed[*k])
                || original["host_anchor_sha256"] != completed["host_anchor_sha256"]
            {
                return Err("original terminal conflicts with completed read".into());
            }
        }
        Ok(format!("{:x}", Sha256::digest(initial)))
    }
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn record(&self) -> &HostCandidateBuildPinRecord {
        &self.record
    }

    pub fn to_json(&self) -> Value {
        json!({"schema":"hol-gauntlet-vm-candidate-build-invocation-shadow.v1",
            "job_id":self.record.pins.job_id,"source_sha":self.record.pins.source_sha,"host_pin_sha256":self.record.raw_sha256,
            "host_pin_durable":true,"vm_started":false,"artifact_admitted":false,"execution_eligible":false})
    }

    pub fn parse_terminal_claim(
        &self,
        stdout: &[u8],
    ) -> Result<Value, VmCandidateBuildLaunchError> {
        if stdout.len() > MAX_TERMINAL_BYTES + 1 {
            return Err(VmCandidateBuildLaunchError::TooLarge);
        }
        let frame = stdout
            .strip_suffix(b"\n")
            .filter(|frame| !frame.is_empty() && !frame.contains(&b'\n'))
            .ok_or(VmCandidateBuildLaunchError::InvalidTerminal)?;
        if canonicalize(frame).map_err(|_| VmCandidateBuildLaunchError::InvalidTerminal)? != frame {
            return Err(VmCandidateBuildLaunchError::InvalidTerminal);
        }
        let value: Value = serde_json::from_slice(frame)
            .map_err(|_| VmCandidateBuildLaunchError::InvalidTerminal)?;
        let object = value
            .as_object()
            .ok_or(VmCandidateBuildLaunchError::InvalidTerminal)?;
        let expected_keys = [
            "artifact_admitted",
            "build_profile_removed",
            "candidate_cgroup_drained",
            "client_pid",
            "client_start_ticks",
            "container_absent",
            "execution_eligible",
            "exit_code",
            "host_anchor_sha256",
            "host_nonce_hex",
            "host_pin_sha256",
            "image_id",
            "job_id",
            "local_version",
            "policy_sha256",
            "result_reader_binary_sha256",
            "result_sha256",
            "runner_binary_sha256",
            "runtime_pins",
            "schema",
            "source_archive_sha256",
            "source_bytes",
            "source_sha",
            "status",
            "stderr_sha256",
            "stdout_sha256",
            "unadmitted_export_bytes",
            "unadmitted_export_sha256",
        ];
        let pins = &self.record.pins;
        let tagged = self.record.schema != "hol-gauntlet-host-candidate-build-pin.v2";
        let exited_zero = value["status"] == "exited-zero" && value["exit_code"] == 0;
        let failed = value["status"] == "build-failed"
            && value["exit_code"].as_i64().is_some_and(|code| code != 0);
        let export = match (
            value["unadmitted_export_bytes"].as_u64(),
            value["unadmitted_export_sha256"].as_str(),
        ) {
            (None, None)
                if value["unadmitted_export_bytes"].is_null()
                    && value["unadmitted_export_sha256"].is_null() =>
            {
                false
            }
            (Some(bytes), Some(digest))
                if (1..=256 * 1024 * 1024).contains(&bytes) && lower_hex(digest, 64) =>
            {
                true
            }
            _ => return Err(VmCandidateBuildLaunchError::InvalidTerminal),
        };
        if object.len() != expected_keys.len() + usize::from(tagged)
            || !expected_keys.iter().all(|key| object.contains_key(*key))
            || value["schema"]
                != if tagged {
                    "hol-gauntlet-candidate-build-result.v3"
                } else {
                    "hol-gauntlet-candidate-build-result.v2"
                }
            || tagged && value["tag"] != pins.tag
            || value["job_id"] != pins.job_id
            || value["source_sha"] != pins.source_sha
            || value["source_archive_sha256"] != pins.source_archive_sha256
            || value["local_version"]
                != if tagged && !pins.tag.starts_with("local-") {
                    Value::Null
                } else {
                    json!(pins.version)
                }
            || value["image_id"] != pins.builder_image_id
            || value["policy_sha256"] != pins.policy_sha256
            || value["runtime_pins"]
                != json!({
                    "podman_sha256":pins.podman_sha256,
                    "slirp4netns_sha256":pins.slirp4netns_sha256,
                    "apparmor_parser_sha256":pins.apparmor_parser_sha256,
                    "seccomp_sha256":pins.seccomp_sha256,
                })
            || value["host_pin_sha256"] != self.record.raw_sha256
            || value["host_nonce_hex"] != self.record.host_nonce_hex
            || value["runner_binary_sha256"] != pins.runner_binary_sha256
            || value["result_reader_binary_sha256"] != pins.result_reader_binary_sha256
            || ![
                "result_sha256",
                "host_anchor_sha256",
                "stdout_sha256",
                "stderr_sha256",
            ]
            .iter()
            .all(|key| {
                value[*key]
                    .as_str()
                    .is_some_and(|digest| lower_hex(digest, 64))
            })
            || value["client_pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > u32::MAX as u64)
            || value["client_start_ticks"]
                .as_u64()
                .is_none_or(|ticks| ticks == 0)
            || value["source_bytes"]
                .as_u64()
                .is_none_or(|bytes| bytes == 0)
            || value["artifact_admitted"] != false
            || value["execution_eligible"] != false
            || value["container_absent"] != true
            || value["candidate_cgroup_drained"] != true
            || value["build_profile_removed"] != true
            || !(exited_zero || failed)
            || exited_zero && !export
        {
            return Err(VmCandidateBuildLaunchError::InvalidTerminal);
        }
        let mut body = value.clone();
        body.as_object_mut()
            .ok_or(VmCandidateBuildLaunchError::InvalidTerminal)?
            .remove("result_sha256");
        let raw = canonicalize(body.to_string().as_bytes())
            .map_err(|_| VmCandidateBuildLaunchError::InvalidTerminal)?;
        if value["result_sha256"] != format!("{:x}", Sha256::digest(&raw)) {
            return Err(VmCandidateBuildLaunchError::InvalidTerminal);
        }
        Ok(
            json!({"schema":"hol-gauntlet-host-candidate-run-claim-shadow.v1",
            "job_id":pins.job_id,"source_sha":pins.source_sha,
            "status":value["status"],"exit_code":value["exit_code"],
            "result_sha256":value["result_sha256"],
            "unadmitted_export_sha256":value["unadmitted_export_sha256"],
            "host_pin_sha256":self.record.raw_sha256,
            "host_pin_journal_match":true,"retained_result_reconciled":false,
            "artifact_admitted":false,"execution_eligible":false}),
        )
    }

    /// Consume dispatch before Lima. Any transport failure stays unresolved;
    /// a zero exit still requires independent retained-result reconciliation.
    pub fn execute_once(
        &self,
        journal: &HostCandidateBuildPinJournal,
    ) -> Result<Value, VmCandidateBuildLaunchError> {
        if journal.read(&self.record.pins.job_id).ok() != Some(self.record.clone()) {
            return Err(VmCandidateBuildLaunchError::HostPinChanged);
        }
        journal
            .consume_dispatch(&self.record)
            .map_err(|_| VmCandidateBuildLaunchError::DispatchUnavailable)?;
        let output = run_fixed(
            &self.argv,
            Duration::from_secs(gauntlet_contracts::CANDIDATE_BUILD_TIMEOUT_SECONDS + 120),
            MAX_TERMINAL_BYTES + 1,
            4096,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                VmCandidateBuildLaunchError::GuestUncertain
            }
            FixedProcessError::TimedOut => VmCandidateBuildLaunchError::TimedOut,
            FixedProcessError::TooLarge => VmCandidateBuildLaunchError::TooLarge,
        })?;
        self.parse_terminal_claim(&output)
    }
}
