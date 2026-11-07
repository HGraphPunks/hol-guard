//! Read-only Lima reconciliation of a v2 candidate result against the
//! prelaunch, one-use host pin journal. The guest result is still a local
//! supervisor claim; this plan never admits a wheel or a benchmark pass.

use crate::fixed_process::{run_fixed, FixedProcessError};
use crate::{load_operations_bytes, HostCandidateBuildPinJournal, HostCandidateBuildPinRecord};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmHostBoundCandidateResultError {
    InvalidConfig,
    InvalidPins,
    HostPinUnavailable,
    InvalidResponse,
    Unavailable,
    TimedOut,
    TooLarge,
}

/// Explicit recovery of the exact host-reserved build. Its durable authorization
/// permits cleanup and an aborted/null-exit receipt, never a workload retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmHostBoundCandidateRepairPlan {
    argv: Vec<String>,
    record: HostCandidateBuildPinRecord,
    anchor_sha256: String,
    generation: String,
}

fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

impl VmHostBoundCandidateRepairPlan {
    pub fn new(
        operations: &Value,
        journal: &HostCandidateBuildPinJournal,
        job: &str,
        generation: &str,
    ) -> Result<Self, String> {
        if !lower_hex(job, 16) || !lower_hex(generation, 64) {
            return Err("exact candidate repair job and binary pins required".into());
        }
        let config =
            load_operations_bytes(operations.to_string().as_bytes()).map_err(|e| e.to_string())?;
        let record = journal.read(job).map_err(|e| e.to_string())?;
        let limactl = config["limactl"]
            .as_str()
            .ok_or("candidate repair transport missing")?;
        let vm = config["vm"].as_str().ok_or("candidate repair VM missing")?;
        if config["release_build_backend"] != "local-vm"
            || record
                .vm_target
                .as_ref()
                .is_none_or(|(l, v)| l != limactl || v != vm)
        {
            return Err("candidate repair requires the original host-reserved VM".into());
        }
        let p = &record.pins;
        let anchor = json!({"schema":"hol-gauntlet-candidate-host-anchor.v2",
            "job_id":p.job_id,"source_sha":p.source_sha,"source_archive_sha256":p.source_archive_sha256,
            "version":p.version,"tag":p.tag,"controller_tree_sha256":p.controller_tree_sha256,
            "image_id":p.builder_image_id,"policy_sha256":p.policy_sha256,
            "runtime_pins":{"podman_sha256":p.podman_sha256,"slirp4netns_sha256":p.slirp4netns_sha256,
                "apparmor_parser_sha256":p.apparmor_parser_sha256,"seccomp_sha256":p.seccomp_sha256},
            "runner_binary_sha256":p.runner_binary_sha256,"result_reader_binary_sha256":p.result_reader_binary_sha256,
            "host_pin_sha256":record.raw_sha256,"host_nonce_hex":record.host_nonce_hex,
            "pre_candidate_run":true,"artifact_admitted":false,"execution_eligible":false});
        let anchor_sha256 =
            digest(&canonicalize(anchor.to_string().as_bytes()).map_err(|e| e.to_string())?);
        let argv = vec![
            limactl.into(),
            "shell".into(),
            vm.into(),
            "--".into(),
            "sudo".into(),
            "-n".into(),
            format!("/opt/hol-gauntlet/rust-candidate-run-hostbound-shadow-{generation}"),
            "--repair".into(),
            job.into(),
            p.source_sha.clone(),
            anchor_sha256.clone(),
        ];
        Ok(Self {
            argv,
            record,
            anchor_sha256,
            generation: generation.into(),
        })
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, String> {
        if stdout.len() > 8193 {
            return Err("candidate repair response exceeds boundary".into());
        }
        let raw = stdout
            .strip_suffix(b"\n")
            .filter(|v| !v.is_empty() && !v.contains(&b'\n'))
            .ok_or("one candidate repair frame required")?;
        if canonicalize(raw).map_err(|e| e.to_string())? != raw {
            return Err("canonical candidate repair frame required".into());
        }
        let mut v: Value =
            serde_json::from_slice(raw).map_err(|_| "candidate repair JSON invalid")?;
        let p = &self.record.pins;
        let fields = [
            "schema",
            "job_id",
            "source_sha",
            "host_anchor_sha256",
            "host_pin_sha256",
            "runner_binary_sha256",
            "repair_generation",
            "container_id",
            "client_cgroup_receipt_sha256",
            "status",
            "exit_code",
            "quiescent",
            "artifact_admitted",
            "execution_eligible",
            "qualification_eligible",
            "guard_causality_verified",
            "model_requests",
            "model_tokens",
            "repair_receipt_sha256",
        ];
        if v.as_object()
            .is_none_or(|v| v.len() != fields.len() || fields.iter().any(|k| !v.contains_key(*k)))
            || v["schema"] != "hol-gauntlet-candidate-build-repair.v1"
            || v["job_id"] != p.job_id
            || v["source_sha"] != p.source_sha
            || v["host_anchor_sha256"] != self.anchor_sha256
            || v["host_pin_sha256"] != self.record.raw_sha256
            || v["runner_binary_sha256"] != p.runner_binary_sha256
            || v["repair_generation"] != self.generation
            || v["container_id"].as_str().is_none_or(|s| !lower_hex(s, 64))
            || !(v["client_cgroup_receipt_sha256"].is_null()
                || v["client_cgroup_receipt_sha256"]
                    .as_str()
                    .is_some_and(|s| lower_hex(s, 64)))
            || v["status"] != "aborted"
            || !v["exit_code"].is_null()
            || v["quiescent"] != true
            || [
                "artifact_admitted",
                "execution_eligible",
                "qualification_eligible",
                "guard_causality_verified",
            ]
            .iter()
            .any(|k| v[k] != false)
            || v["model_requests"] != 0
            || v["model_tokens"] != 0
        {
            return Err("candidate repair differs from retained outside pins".into());
        }
        let receipt = v
            .as_object_mut()
            .unwrap()
            .remove("repair_receipt_sha256")
            .ok_or("candidate repair receipt missing")?;
        if receipt != digest(&canonicalize(v.to_string().as_bytes()).map_err(|e| e.to_string())?) {
            return Err("candidate repair receipt digest differs".into());
        }
        v["repair_receipt_sha256"] = receipt;
        Ok(v)
    }

    pub fn execute_repair(&self, journal: &HostCandidateBuildPinJournal) -> Result<Value, String> {
        let current = || {
            if journal
                .read(&self.record.pins.job_id)
                .map_err(|e| e.to_string())?
                != self.record
            {
                return Err("candidate host pin changed before recovery".to_owned());
            }
            Ok(())
        };
        current()?;
        let auth = canonicalize(
            json!({"schema":"hol-gauntlet-host-candidate-repair-authorization.v1",
            "job_id":self.record.pins.job_id,"host_pin_sha256":self.record.raw_sha256,
            "host_anchor_sha256":self.anchor_sha256,"repair_generation":self.generation,
            "retry_allowed":false,"execution_eligible":false})
            .to_string()
            .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        self.commit(journal, "authorization", &auth)?;
        current()?;
        let raw =
            run_fixed(&self.argv, Duration::from_secs(120), 8193, 2048, &[]).map_err(|e| {
                format!("candidate recovery uncertain; reconcile without workload retry: {e:?}")
            })?;
        let result = self.parse_response(&raw)?;
        current()?;
        self.commit(
            journal,
            "result",
            &canonicalize(result.to_string().as_bytes()).map_err(|e| e.to_string())?,
        )?;
        Ok(result)
    }

    fn commit(
        &self,
        journal: &HostCandidateBuildPinJournal,
        suffix: &str,
        raw: &[u8],
    ) -> Result<(), String> {
        use rustix::fs::{fchmod, fsync, openat, Mode, OFlags};
        use std::io::Write;
        let dir = journal.directory().map_err(|e| e.to_string())?;
        let name = format!("{}.candidate-repair-{suffix}.json", self.record.pins.job_id);
        let fd = match openat(
            dir,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => Some(fd),
            Err(rustix::io::Errno::EXIST) => None,
            Err(_) => return Err("candidate repair host commit unavailable".into()),
        };
        if let Some(fd) = fd {
            fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
            let mut file = std::fs::File::from(fd);
            file.write_all(raw)
                .and_then(|_| file.sync_all())
                .map_err(|_| "candidate repair host commit uncertain")?;
            fsync(dir).map_err(|e| e.to_string())?;
        }
        if crate::private_jobs::read_regular_bytes(dir, &name, rustix::process::geteuid().as_raw())
            .map_err(|e| e.to_string())?
            != raw
        {
            return Err("candidate repair authorization or result differs".into());
        }
        journal.directory().map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl fmt::Display for VmHostBoundCandidateResultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid fixed VM operations configuration",
            Self::InvalidPins => "invalid outside terminal result or archive digest",
            Self::HostPinUnavailable => "durable prelaunch host candidate pin unavailable",
            Self::InvalidResponse => "VM terminal result differs from prelaunch host pins",
            Self::Unavailable => "VM host-bound result reader unavailable",
            Self::TimedOut => "VM host-bound result reader timed out",
            Self::TooLarge => "VM host-bound result response too large",
        })
    }
}

impl std::error::Error for VmHostBoundCandidateResultError {}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmHostBoundCandidateResultPlan {
    argv: Vec<String>,
    record: HostCandidateBuildPinRecord,
    result_sha256: String,
    archive_sha256: String,
}

impl VmHostBoundCandidateResultPlan {
    pub fn new(
        operations: &Value,
        journal: &HostCandidateBuildPinJournal,
        job_id: &str,
        result_sha256: &str,
        archive_sha256: &str,
    ) -> Result<Self, VmHostBoundCandidateResultError> {
        if !lower_hex(job_id, 16) || !lower_hex(result_sha256, 64) || !lower_hex(archive_sha256, 64)
        {
            return Err(VmHostBoundCandidateResultError::InvalidPins);
        }
        let raw = serde_json::to_vec(operations)
            .map_err(|_| VmHostBoundCandidateResultError::InvalidConfig)?;
        let config = load_operations_bytes(&raw)
            .map_err(|_| VmHostBoundCandidateResultError::InvalidConfig)?;
        if config["release_build_backend"] != "local-vm" {
            return Err(VmHostBoundCandidateResultError::InvalidConfig);
        }
        let limactl = config["limactl"]
            .as_str()
            .ok_or(VmHostBoundCandidateResultError::InvalidConfig)?;
        let vm = config["vm"]
            .as_str()
            .ok_or(VmHostBoundCandidateResultError::InvalidConfig)?;
        let record = journal
            .read(job_id)
            .map_err(|_| VmHostBoundCandidateResultError::HostPinUnavailable)?;
        if record
            .vm_target
            .as_ref()
            .is_some_and(|(transport, target)| transport != limactl || target != vm)
        {
            return Err(VmHostBoundCandidateResultError::InvalidConfig);
        }
        let pins = &record.pins;
        let tagged = record.schema != "hol-gauntlet-host-candidate-build-pin.v2";
        let mut argv = vec![
            limactl.to_owned(),
            "shell".to_owned(),
            vm.to_owned(),
            "--".to_owned(),
            "sudo".to_owned(),
            "-n".to_owned(),
            format!(
                "/opt/hol-gauntlet/rust-candidate-result-hostbound-shadow-{}",
                pins.result_reader_binary_sha256
            ),
            pins.job_id.clone(),
            pins.source_sha.clone(),
            pins.source_archive_sha256.clone(),
            result_sha256.to_owned(),
            archive_sha256.to_owned(),
            pins.version.clone(),
        ];
        if tagged {
            argv.push(pins.tag.clone());
        }
        argv.extend([
            pins.controller_tree_sha256.clone(),
            pins.builder_image_id.clone(),
            pins.policy_sha256.clone(),
            pins.podman_sha256.clone(),
            pins.slirp4netns_sha256.clone(),
            pins.apparmor_parser_sha256.clone(),
            pins.seccomp_sha256.clone(),
            pins.runner_binary_sha256.clone(),
            pins.result_reader_binary_sha256.clone(),
            record.raw_sha256.clone(),
            record.host_nonce_hex.clone(),
        ]);
        Ok(Self {
            argv,
            record,
            result_sha256: result_sha256.to_owned(),
            archive_sha256: archive_sha256.to_owned(),
        })
    }

    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, VmHostBoundCandidateResultError> {
        if stdout.len() > MAX_RESPONSE_BYTES + 1 {
            return Err(VmHostBoundCandidateResultError::TooLarge);
        }
        let frame = stdout
            .strip_suffix(b"\n")
            .filter(|frame| !frame.is_empty() && !frame.contains(&b'\n'))
            .ok_or(VmHostBoundCandidateResultError::InvalidResponse)?;
        if canonicalize(frame).map_err(|_| VmHostBoundCandidateResultError::InvalidResponse)?
            != frame
        {
            return Err(VmHostBoundCandidateResultError::InvalidResponse);
        }
        let value: Value = serde_json::from_slice(frame)
            .map_err(|_| VmHostBoundCandidateResultError::InvalidResponse)?;
        let object = value
            .as_object()
            .ok_or(VmHostBoundCandidateResultError::InvalidResponse)?;
        let pins = &self.record.pins;
        let tagged = self.record.schema != "hol-gauntlet-host-candidate-build-pin.v2";
        if object.len() != 20 + usize::from(tagged)
            || value["schema"]
                != if tagged {
                    "hol-gauntlet-candidate-result-read-shadow.v3"
                } else {
                    "hol-gauntlet-candidate-result-read-shadow.v2"
                }
            || tagged && value["tag"] != pins.tag
            || value["job_id"] != pins.job_id
            || value["source_sha"] != pins.source_sha
            || value["result_sha256"] != self.result_sha256
            || value["archive_sha256"] != self.archive_sha256
            || value["version"] != pins.version
            || value["host_pin_sha256"] != self.record.raw_sha256
            || value["runner_binary_sha256"] != pins.runner_binary_sha256
            || value["result_reader_binary_sha256"] != pins.result_reader_binary_sha256
            || value["image_id"] != pins.builder_image_id
            || value["policy_sha256"] != pins.policy_sha256
            || value["host_anchor_sha256"]
                .as_str()
                .is_none_or(|digest| !lower_hex(digest, 64))
            || value["wheel_sha256"]
                .as_str()
                .is_none_or(|digest| !lower_hex(digest, 64))
            || value["client_pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > u32::MAX as u64)
            || value["client_start_ticks"]
                .as_u64()
                .is_none_or(|ticks| ticks == 0)
            || value["retained_files_match"] != true
            || value["cleanup_absent"] != true
            || value["host_anchor_present"] != true
            || value["artifact_admitted"] != false
            || value["execution_eligible"] != false
        {
            return Err(VmHostBoundCandidateResultError::InvalidResponse);
        }
        let mut report = json!({
            "schema":if tagged {"hol-gauntlet-host-candidate-result-shadow.v3"} else {"hol-gauntlet-host-candidate-result-shadow.v2"},
            "job_id":pins.job_id,
            "source_sha":pins.source_sha,
            "result_sha256":self.result_sha256,
            "archive_sha256":self.archive_sha256,
            "wheel_sha256":value["wheel_sha256"],
            "version":pins.version,
            "client_pid":value["client_pid"],
            "client_start_ticks":value["client_start_ticks"],
            "host_pin_sha256":self.record.raw_sha256,
            "host_anchor_sha256":value["host_anchor_sha256"],
            "retained_files_match":true,
            "cleanup_absent":true,
            "host_pin_journal_match":true,
            "artifact_admitted":false,
            "execution_eligible":false,
        });
        if tagged {
            report["tag"] = json!(pins.tag);
        }
        Ok(report)
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn execute_read_only(&self) -> Result<Value, VmHostBoundCandidateResultError> {
        let output = run_fixed(
            &self.argv,
            Duration::from_secs(30),
            MAX_RESPONSE_BYTES + 1,
            1500,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                VmHostBoundCandidateResultError::Unavailable
            }
            FixedProcessError::TimedOut => VmHostBoundCandidateResultError::TimedOut,
            FixedProcessError::TooLarge => VmHostBoundCandidateResultError::TooLarge,
        })?;
        self.parse_response(&output)
    }
}
