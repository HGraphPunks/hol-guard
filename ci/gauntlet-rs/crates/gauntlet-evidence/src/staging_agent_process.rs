//! Match a signed staging control's declared agent container PID/start tick
//! with a bounded kernel sample retained by the Rust owner. This establishes
//! one live container-process identity, not SDK, Native or Guard causality.

use crate::crypto::{is_sha256, sha256};
use crate::io::open_absolute_directory;
use crate::python_worker_files::{private_directory, read_private_file};
use crate::staging_control_record::read_one;
use crate::staging_suite::{cgroup_targets, require_absent_cgroup};
use crate::{
    observe_staging_physical_files_root_owned_ineligible, EvidenceError, Result,
    StagingEvidencePins,
};
use gauntlet_contracts::canonicalize;
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

const STAGING: &str = "/var/lib/hol-gauntlet-rust/staging-state";
const INVALID: EvidenceError = EvidenceError::Invalid("invalid live staging agent process");

#[derive(Debug, Clone, Copy)]
pub struct StagingAgentProcessPins<'a> {
    pub evidence: StagingEvidencePins<'a>,
    pub worker_generation_sha256: &'a str,
    pub started_marker_sha256: &'a str,
    pub controller_key_pin_sha256: &'a str,
    pub report_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingAgentProcessShadow {
    pub run_id: String,
    pub record_sha256: String,
    pub report_sha256: String,
    pub container_id: String,
    pub agent_pid: u32,
    pub agent_start_ticks: u64,
    pub sampled_container_processes: usize,
}

impl StagingAgentProcessShadow {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-staging-agent-process-shadow.v1",
            "run_id":self.run_id,
            "record_sha256":self.record_sha256,
            "report_sha256":self.report_sha256,
            "container_id":self.container_id,
            "agent_pid":self.agent_pid,
            "agent_start_ticks":self.agent_start_ticks,
            "sampled_container_processes":self.sampled_container_processes,
            "caller_host_prelaunch_fields_matched":true,
            "agent_kernel_identity_matched":true,
            "independent_sdk_native_guard_causality_verified":false,
            "execution_eligible":false,
        })
    }
}

fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn positive_decimal(raw: &str) -> Option<u64> {
    if raw.is_empty() || raw.len() > 20 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u64>().ok().filter(|value| *value > 0)
}

fn matching_agent_process(record: &Value, activity: &Value) -> Result<(String, u32, u64, usize)> {
    let container_id = record["agent_container_inspection"]["Id"]
        .as_str()
        .filter(|value| is_sha256(value))
        .ok_or(INVALID)?;
    let pid = record["agent_container_inspection"]["State"]["Pid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(INVALID)?;
    let start_ticks = record["agent_identity"]["start_time"]
        .as_str()
        .and_then(positive_decimal)
        .ok_or(INVALID)?;
    if !exact_keys(
        activity,
        &[
            "schema",
            "sample_count",
            "max_controller_tasks",
            "product_slice_observed",
            "product_slice_populated",
            "max_product_tasks",
            "container_processes",
            "container_processes_exhaustively_observed",
            "control_processes_exhaustively_observed",
            "guard_causality_verified",
            "execution_eligible",
        ],
    ) || activity["schema"] != "hol-gauntlet-staging-kernel-samples.v2"
        || activity["sample_count"]
            .as_u64()
            .is_none_or(|count| count == 0)
        || activity["max_controller_tasks"]
            .as_u64()
            .is_none_or(|count| count == 0)
        || activity["product_slice_observed"] != true
        || activity["product_slice_populated"] != true
        || activity["max_product_tasks"]
            .as_u64()
            .is_none_or(|count| count == 0)
        || activity["container_processes_exhaustively_observed"] != false
        || activity["control_processes_exhaustively_observed"] != false
        || activity["guard_causality_verified"] != false
        || activity["execution_eligible"] != false
    {
        return Err(INVALID);
    }
    let rows = activity["container_processes"].as_array().ok_or(INVALID)?;
    if rows.is_empty() || rows.len() > 64 {
        return Err(INVALID);
    }
    let mut seen = BTreeSet::new();
    let mut matched = 0;
    for row in rows {
        if !exact_keys(row, &["container_id", "pid", "start_ticks", "cgroup"]) {
            return Err(INVALID);
        }
        let id = row["container_id"]
            .as_str()
            .filter(|value| is_sha256(value))
            .ok_or(INVALID)?;
        let observed_pid = row["pid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(INVALID)?;
        let observed_start = row["start_ticks"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or(INVALID)?;
        let expected_cgroup = format!("/machine.slice/libpod-{id}.scope/container");
        if row["cgroup"] != expected_cgroup || !seen.insert((id, observed_pid, observed_start)) {
            return Err(INVALID);
        }
        if id == container_id && observed_pid == pid && observed_start == start_ticks {
            matched += 1;
        }
    }
    if matched != 1 {
        return Err(INVALID);
    }
    Ok((container_id.to_owned(), pid, start_ticks, rows.len()))
}

/// The caller supplies the independently retained host prelaunch fields and
/// raw report hash. The signed control is reopened before comparing the
/// producer's agent claim to the Rust owner's live pidfd/cgroup samples.
pub fn observe_staging_agent_process_root_owned_ineligible(
    pins: &StagingAgentProcessPins<'_>,
) -> Result<StagingAgentProcessShadow> {
    if geteuid().as_raw() != 0
        || ![
            pins.worker_generation_sha256,
            pins.started_marker_sha256,
            pins.controller_key_pin_sha256,
            pins.report_sha256,
        ]
        .iter()
        .all(|value| is_sha256(value))
    {
        return Err(INVALID);
    }
    observe_staging_physical_files_root_owned_ineligible(&pins.evidence)?;
    let record_raw = read_one(pins.evidence.run_id, pins.evidence.role)?;
    if sha256(&record_raw) != pins.evidence.record_sha256 {
        return Err(INVALID);
    }
    let record: Value = serde_json::from_slice(&record_raw).map_err(|_| INVALID)?;
    let journal = open_absolute_directory(Path::new(STAGING))?;
    private_directory(&journal, 0)?;
    let report_name = format!("{}.report.json", pins.evidence.run_id);
    let terminal_name = format!("{}.terminal.json", pins.evidence.run_id);
    let report_raw = read_private_file(&journal, &report_name, 0, 16 * 1024)?.ok_or(INVALID)?;
    let terminal_raw = read_private_file(&journal, &terminal_name, 0, 16 * 1024)?.ok_or(INVALID)?;
    if sha256(&report_raw) != pins.report_sha256 {
        return Err(INVALID);
    }
    let report: Value = serde_json::from_slice(&canonicalize(&report_raw).map_err(|_| INVALID)?)
        .map_err(|_| INVALID)?;
    let terminal: Value =
        serde_json::from_slice(&canonicalize(&terminal_raw).map_err(|_| INVALID)?)
            .map_err(|_| INVALID)?;
    if report["schema"] != "hol-gauntlet-staging-control-run-report.v1"
        || report["source_sha"] != pins.evidence.source_sha
        || report["build_job_id"] != pins.evidence.build_job_id
        || report["run_id"] != pins.evidence.run_id
        || report["role"] != pins.evidence.role
        || report["provisional_config_digest"] != pins.evidence.config_digest
        || report["controller_public_key_hex"] != pins.evidence.controller_public_key_hex
        || report["exit_code"] != 0
        || report["timed_out"] != false
        || report["controller_and_product_slice_cleanup_verified"] != true
        || report["post_run_controller_custody"] != true
        || report["record_scored"] != false
        || report["execution_eligible"] != false
        || terminal["schema"] != "hol-gauntlet-worker-terminal.v2"
        || terminal["status"] != "invalid-evidence"
        || terminal["source_sha"] != pins.evidence.source_sha
        || terminal["job_id"] != pins.evidence.run_id
        || terminal["deployment_digest"] != pins.evidence.config_digest
        || terminal["worker_generation"] != pins.worker_generation_sha256
        || terminal["controller_public_key_hex"] != pins.evidence.controller_public_key_hex
        || terminal["controller_key_pin_sha256"] != pins.controller_key_pin_sha256
        || terminal["started_marker_sha256"] != pins.started_marker_sha256
        || terminal["report_sha256"] != pins.report_sha256
        || terminal["exit_code"] != 0
    {
        return Err(INVALID);
    }
    let (container_id, agent_pid, agent_start_ticks, sampled_container_processes) =
        matching_agent_process(&record, &report["live_kernel_activity"])?;
    for (parent, name) in cgroup_targets(pins.evidence.run_id) {
        require_absent_cgroup(Path::new(parent), &name, 0)?;
    }
    if record_raw != read_one(pins.evidence.run_id, pins.evidence.role)?
        || report_raw != read_private_file(&journal, &report_name, 0, 16 * 1024)?.ok_or(INVALID)?
        || terminal_raw
            != read_private_file(&journal, &terminal_name, 0, 16 * 1024)?.ok_or(INVALID)?
    {
        return Err(INVALID);
    }
    Ok(StagingAgentProcessShadow {
        run_id: pins.evidence.run_id.to_owned(),
        record_sha256: pins.evidence.record_sha256.to_owned(),
        report_sha256: pins.report_sha256.to_owned(),
        container_id,
        agent_pid,
        agent_start_ticks,
        sampled_container_processes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_agent_claim_must_match_one_live_kernel_tuple() {
        let id = "a".repeat(64);
        let record = json!({
            "agent_container_inspection":{"Id":id,"State":{"Pid":123}},
            "agent_identity":{"start_time":"456"},
        });
        let mut activity = json!({
            "schema":"hol-gauntlet-staging-kernel-samples.v2",
            "sample_count":5,
            "max_controller_tasks":2,
            "product_slice_observed":true,
            "product_slice_populated":true,
            "max_product_tasks":3,
            "container_processes_exhaustively_observed":false,
            "control_processes_exhaustively_observed":false,
            "guard_causality_verified":false,
            "execution_eligible":false,
            "container_processes":[{
                "container_id":id,
                "pid":123,
                "start_ticks":456,
                "cgroup":format!("/machine.slice/libpod-{}.scope/container", "a".repeat(64)),
            }],
        });
        assert!(matching_agent_process(&record, &activity).is_ok());
        activity["container_processes"][0]["start_ticks"] = json!(457);
        assert!(matching_agent_process(&record, &activity).is_err());
        activity["container_processes"][0]["start_ticks"] = json!(456);
        activity["container_processes"][0]["cgroup"] = json!("/system.slice/other");
        assert!(matching_agent_process(&record, &activity).is_err());
    }
}
