//! Match a signed staging control's declared agent container PID/start tick
//! with a bounded kernel sample retained by the Rust owner. This establishes
//! one live container-process identity, not SDK, Native or Guard causality.

use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::io::open_absolute_directory;
use crate::python_worker_files::{private_directory, read_private_file};
use crate::staging_control_record::read_one;
use crate::staging_suite::{cgroup_targets, require_absent_cgroup};
use crate::verify_controller_envelope;
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
const SDK_ARGV: &[u8] =
    b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json";

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

pub(crate) fn matching_agent_process(
    record: &Value,
    activity: &Value,
) -> Result<(String, u32, u64, usize)> {
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
    let sdk_executable_samples = activity["schema"] == "hol-gauntlet-staging-kernel-samples.v3";
    let mut fields = vec![
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
    ];
    if sdk_executable_samples {
        fields.push("sdk_executables");
    }
    if !exact_keys(activity, &fields)
        || (!sdk_executable_samples
            && activity["schema"] != "hol-gauntlet-staging-kernel-samples.v2")
        || activity["sample_count"]
            .as_u64()
            .is_none_or(|count| !(1..=10_000).contains(&count))
        || activity["max_controller_tasks"]
            .as_u64()
            .is_none_or(|count| !(1..=256).contains(&count))
        || activity["product_slice_observed"] != true
        || activity["product_slice_populated"] != true
        || activity["max_product_tasks"]
            .as_u64()
            .is_none_or(|count| !(1..=1_000_000).contains(&count))
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
    if sdk_executable_samples {
        let sdk_rows = activity["sdk_executables"].as_array().ok_or(INVALID)?;
        if sdk_rows.len() > 16 {
            return Err(INVALID);
        }
        let mut sdk_seen = BTreeSet::new();
        for row in sdk_rows {
            if !exact_keys(
                row,
                &[
                    "container_id",
                    "pid",
                    "start_ticks",
                    "cgroup",
                    "argv_sha256",
                    "executable_sha256",
                ],
            ) {
                return Err(INVALID);
            }
            let id = row["container_id"]
                .as_str()
                .filter(|id| is_sha256(id))
                .ok_or(INVALID)?;
            let pid = row["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .ok_or(INVALID)?;
            let start = row["start_ticks"]
                .as_u64()
                .filter(|start| *start > 0)
                .ok_or(INVALID)?;
            if row["cgroup"] != format!("/machine.slice/libpod-{id}.scope/container")
                || !seen.contains(&(id, pid, start))
                || !sdk_seen.insert((id, pid, start))
                || row["argv_sha256"]
                    .as_str()
                    .is_none_or(|hash| !is_sha256(hash))
                || row["executable_sha256"]
                    .as_str()
                    .is_none_or(|hash| !is_sha256(hash))
            {
                return Err(INVALID);
            }
        }
    }
    Ok((container_id.to_owned(), pid, start_ticks, rows.len()))
}

/// The SDK gate's producer-declared process must be a second, distinct live
/// process in the same sampled Podman scope. The sample does not authenticate
/// its executable or establish that an SDK tool call occurred.
pub(crate) fn matching_sdk_gate_process(record: &Value, activity: &Value) -> Result<(u32, u64)> {
    let (container_id, agent_pid, _, _) = matching_agent_process(record, activity)?;
    let pid = record["sdk_gate"]["observation"]["pid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0 && *value != agent_pid)
        .ok_or(INVALID)?;
    let start_ticks = record["sdk_gate"]["observation"]["identity"]["start_time"]
        .as_str()
        .and_then(positive_decimal)
        .ok_or(INVALID)?;
    let cgroup = format!("/machine.slice/libpod-{container_id}.scope/container");
    let matches = activity["container_processes"]
        .as_array()
        .ok_or(INVALID)?
        .iter()
        .filter(|row| {
            row["container_id"] == container_id
                && row["pid"] == pid
                && row["start_ticks"] == start_ticks
                && row["cgroup"] == cgroup
        })
        .count();
    if matches != 1 {
        return Err(INVALID);
    }
    Ok((pid, start_ticks))
}

/// Require the Rust owner's live kernel executable bytes and complete Bun
/// command to match an outside-pinned asset hash for the signed gate process.
/// This is process identity, not proof of an SDK tool call or Guard decision.
pub(crate) fn matching_sdk_executable(
    record: &Value,
    activity: &Value,
    expected_bun_sha256: &str,
) -> Result<()> {
    if activity["schema"] != "hol-gauntlet-staging-kernel-samples.v3"
        || !is_sha256(expected_bun_sha256)
    {
        return Err(INVALID);
    }
    let (pid, start_ticks) = matching_sdk_gate_process(record, activity)?;
    let container_id = record["agent_container_inspection"]["Id"]
        .as_str()
        .ok_or(INVALID)?;
    let cgroup = format!("/machine.slice/libpod-{container_id}.scope/container");
    let count = activity["sdk_executables"]
        .as_array()
        .ok_or(INVALID)?
        .iter()
        .filter(|row| {
            row["container_id"] == container_id
                && row["pid"] == pid
                && row["start_ticks"] == start_ticks
                && row["cgroup"] == cgroup
                && row["argv_sha256"] == sha256(SDK_ARGV)
                && row["executable_sha256"] == expected_bun_sha256
        })
        .count();
    if count != 1 {
        return Err(INVALID);
    }
    Ok(())
}

fn matching_verified_native_mcp_processes(
    audit: &Value,
    activity: &Value,
    agent_container_id: &str,
) -> Result<(String, usize)> {
    if audit["kind"] != "isolated-native-mcp-observation"
        || audit["schema_version"] != "1.0"
        || audit["active_children"] != 0
        || audit["active_sessions"] != 0
        || audit["qualification_eligible"] != false
        || audit["product_claims_authenticated"] != false
    {
        return Err(INVALID);
    }
    let plane = &audit["product_plane"];
    if plane["kind"] != "isolated-product-plane.v2"
        || plane["schema_version"] != "2.0"
        || plane["cleanup_complete"] != true
        || plane["qualification_eligible"] != false
        || plane["product_claims_authenticated"] != false
        || plane["container"]
            .as_str()
            .is_none_or(|name| !name.starts_with("native-product-"))
    {
        return Err(INVALID);
    }
    let observations = plane["observations"].as_array().ok_or(INVALID)?;
    if observations.len() != 3 || observations[0]["kind"] != "container-boundary" {
        return Err(INVALID);
    }
    let boundary_identity = &observations[0]["identity"];
    let boundary_start = boundary_identity["start_time"]
        .as_str()
        .and_then(positive_decimal)
        .ok_or(INVALID)?;
    let rows = activity["container_processes"].as_array().ok_or(INVALID)?;
    let boundary_rows: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["container_id"] != agent_container_id && row["start_ticks"] == boundary_start
        })
        .collect();
    if boundary_rows.len() != 1 {
        return Err(INVALID);
    }
    let product_container_id = boundary_rows[0]["container_id"]
        .as_str()
        .filter(|id| is_sha256(id))
        .ok_or(INVALID)?;
    let expected_cgroup = format!("/machine.slice/libpod-{product_container_id}.scope/container");
    if boundary_rows[0]["cgroup"] != expected_cgroup {
        return Err(INVALID);
    }
    let mut proxy_pids = BTreeSet::new();
    for observation in &observations[1..] {
        if observation["kind"] != "proxy-process" {
            return Err(INVALID);
        }
        let pid = observation["product_pid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(INVALID)?;
        let start = observation["identity"]["start_time"]
            .as_str()
            .and_then(positive_decimal)
            .ok_or(INVALID)?;
        if !proxy_pids.insert(pid)
            || [
                "boot_id",
                "effective_uid",
                "effective_gid",
                "mount_namespace",
                "network_namespace",
                "pid_namespace",
                "no_new_privileges",
            ]
            .iter()
            .any(|field| {
                observation["identity"][field].is_null()
                    || observation["identity"][field] != boundary_identity[field]
            })
            || rows
                .iter()
                .filter(|row| {
                    row["container_id"] == product_container_id
                        && row["pid"] == pid
                        && row["start_ticks"] == start
                        && row["cgroup"] == expected_cgroup
                })
                .count()
                != 1
        {
            return Err(INVALID);
        }
    }
    Ok((product_container_id.to_owned(), proxy_pids.len()))
}

/// Independently sampled Podman tuples must contain the signed Native MCP
/// boundary and both proxy children in one container distinct from the SDK
/// agent. This binds process identity only, not MCP frames or Guard decisions.
pub(crate) fn matching_native_mcp_processes(
    record: &Value,
    activity: &Value,
    outside_public_key_hex: &str,
) -> Result<(String, usize)> {
    let (agent_container_id, _, _, _) = matching_agent_process(record, activity)?;
    if record["controller_public_key_hex"] != outside_public_key_hex {
        return Err(INVALID);
    }
    let key = decode_hex(outside_public_key_hex, 32).map_err(|_| INVALID)?;
    let runtime_envelope = serde_json::to_vec(&record["developer_runtime"]).map_err(|_| INVALID)?;
    let runtime = verify_controller_envelope(&runtime_envelope, &key)?;
    let audit_envelope = serde_json::to_vec(&runtime["native_mcp_audit"]).map_err(|_| INVALID)?;
    let audit = verify_controller_envelope(&audit_envelope, &key)?;
    matching_verified_native_mcp_processes(&audit, activity, &agent_container_id)
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

    #[test]
    fn sdk_gate_requires_a_second_exact_live_process_in_the_agent_scope() {
        let id = "a".repeat(64);
        let record = json!({
            "agent_container_inspection":{"Id":id,"State":{"Pid":123}},
            "agent_identity":{"start_time":"456"},
            "sdk_gate":{"observation":{"pid":124,"identity":{"start_time":"457"}}},
        });
        let cgroup = format!("/machine.slice/libpod-{}.scope/container", "a".repeat(64));
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
            "container_processes":[
                {"container_id":id,"pid":123,"start_ticks":456,"cgroup":cgroup},
                {"container_id":id,"pid":124,"start_ticks":457,"cgroup":cgroup},
            ],
        });
        assert_eq!(
            matching_sdk_gate_process(&record, &activity).unwrap(),
            (124, 457)
        );
        activity["container_processes"][1]["start_ticks"] = json!(458);
        assert!(matching_sdk_gate_process(&record, &activity).is_err());
        activity["container_processes"][1]["start_ticks"] = json!(457);
        activity["container_processes"][1]["cgroup"] = json!("/system.slice/other");
        assert!(matching_sdk_gate_process(&record, &activity).is_err());
    }

    #[test]
    fn sdk_executable_requires_outside_bun_bytes_and_exact_argv() {
        let id = "a".repeat(64);
        let bun = "b".repeat(64);
        let cgroup = format!("/machine.slice/libpod-{id}.scope/container");
        let record = json!({
            "agent_container_inspection":{"Id":id,"State":{"Pid":123}},
            "agent_identity":{"start_time":"456"},
            "sdk_gate":{"observation":{"pid":124,"identity":{"start_time":"457"}}},
        });
        let mut activity = json!({
            "schema":"hol-gauntlet-staging-kernel-samples.v3",
            "sample_count":5,
            "max_controller_tasks":2,
            "product_slice_observed":true,
            "product_slice_populated":true,
            "max_product_tasks":3,
            "container_processes_exhaustively_observed":false,
            "control_processes_exhaustively_observed":false,
            "guard_causality_verified":false,
            "execution_eligible":false,
            "container_processes":[
                {"container_id":id,"pid":123,"start_ticks":456,"cgroup":cgroup},
                {"container_id":id,"pid":124,"start_ticks":457,"cgroup":cgroup},
            ],
            "sdk_executables":[{
                "container_id":id,
                "pid":124,
                "start_ticks":457,
                "cgroup":cgroup,
                "argv_sha256":sha256(SDK_ARGV),
                "executable_sha256":bun,
            }],
        });
        assert!(matching_sdk_executable(&record, &activity, &bun).is_ok());
        assert!(matching_sdk_executable(&record, &activity, &"c".repeat(64)).is_err());
        activity["sdk_executables"][0]["argv_sha256"] = json!("d".repeat(64));
        assert!(matching_sdk_executable(&record, &activity, &bun).is_err());
        activity["sdk_executables"][0]["argv_sha256"] = json!(sha256(SDK_ARGV));
        activity["sdk_executables"][0]["start_ticks"] = json!(458);
        assert!(matching_sdk_executable(&record, &activity, &bun).is_err());
        activity["sdk_executables"][0]["start_ticks"] = json!(457);
        let duplicate = activity["sdk_executables"][0].clone();
        activity["sdk_executables"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(matching_sdk_executable(&record, &activity, &bun).is_err());
    }

    #[test]
    fn native_mcp_children_require_one_distinct_sampled_product_scope() {
        let agent_id = "a".repeat(64);
        let product_id = "b".repeat(64);
        let identity = json!({
            "boot_id":"test-boot",
            "effective_uid":10005,
            "effective_gid":10005,
            "mount_namespace":"mnt:[100]",
            "network_namespace":"net:[101]",
            "pid_namespace":"pid:[102]",
            "no_new_privileges":1,
            "start_time":"100",
        });
        let mut first = identity.clone();
        first["start_time"] = json!("102");
        let mut second = identity.clone();
        second["start_time"] = json!("103");
        let audit = json!({
            "kind":"isolated-native-mcp-observation",
            "schema_version":"1.0",
            "active_children":0,
            "active_sessions":0,
            "qualification_eligible":false,
            "product_claims_authenticated":false,
            "product_plane":{
                "kind":"isolated-product-plane.v2",
                "schema_version":"2.0",
                "container":"native-product-test",
                "cleanup_complete":true,
                "qualification_eligible":false,
                "product_claims_authenticated":false,
                "observations":[
                    {"kind":"container-boundary","identity":identity},
                    {"kind":"proxy-process","product_pid":12,"identity":first},
                    {"kind":"proxy-process","product_pid":13,"identity":second},
                ],
            },
        });
        let cgroup = format!("/machine.slice/libpod-{product_id}.scope/container");
        let activity = json!({
            "container_processes":[
                {"container_id":product_id,"pid":10,"start_ticks":100,"cgroup":cgroup},
                {"container_id":product_id,"pid":12,"start_ticks":102,"cgroup":cgroup},
                {"container_id":product_id,"pid":13,"start_ticks":103,"cgroup":cgroup},
            ],
        });
        assert_eq!(
            matching_verified_native_mcp_processes(&audit, &activity, &agent_id).unwrap(),
            (product_id.clone(), 2)
        );
        let mut wrong = audit.clone();
        wrong["product_plane"]["observations"][1]["identity"]["start_time"] = json!("104");
        assert!(matching_verified_native_mcp_processes(&wrong, &activity, &agent_id).is_err());
        wrong = audit.clone();
        wrong["product_plane"]["observations"][2]["product_pid"] = json!(12);
        assert!(matching_verified_native_mcp_processes(&wrong, &activity, &agent_id).is_err());
        wrong = audit.clone();
        wrong["product_plane"]["observations"][2]["identity"]["pid_namespace"] = json!("pid:[999]");
        assert!(matching_verified_native_mcp_processes(&wrong, &activity, &agent_id).is_err());
        let mut wrong_activity = activity.clone();
        wrong_activity["container_processes"][2]["container_id"] = json!(agent_id);
        assert!(
            matching_verified_native_mcp_processes(&audit, &wrong_activity, &agent_id).is_err()
        );
    }
}
