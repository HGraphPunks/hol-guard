//! Explicit candidate operations shared by the primary host command and its
//! historical diagnostic entrypoints. The existing journals own all custody,
//! one-use dispatch, response validation and recovery authorization.

use crate::{
    prepare_local_source_archive_one_use, public_vm_operations, HostCandidateBuildPinJournal,
    HostCandidateBuildPins, VmCandidateBuildPlan, VmHostBoundCandidateRepairPlan,
    VmHostBoundCandidateResultPlan,
};
use serde_json::Value;
use std::path::Path;

pub const CANDIDATE_BUILD_USAGE: &str = "candidate commands:\nsource PRIVATE_STATE JOB_ID ABSOLUTE_REPOSITORY SOURCE_SHA\nrun PRIVATE_PIN_DIR JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 VERSION TAG CONTROLLER_ROOT CONTROLLER_TREE_SHA256 UV_BASE_IMAGE_ID RUST_BASE_IMAGE_ID BUILDER_IMAGE_ID POLICY_SHA256 PODMAN_SHA256 SLIRP_SHA256 APPARMOR_PARSER_SHA256 SECCOMP_SHA256 RUNNER_BINARY_SHA256 RESULT_READER_BINARY_SHA256 READINESS_BINARY_SHA256 [--vm VM_NAME]\nread PRIVATE_PIN_DIR JOB_ID RESULT_SHA256 EXPORT_ARCHIVE_SHA256 [--vm VM_NAME]\nrepair PRIVATE_PIN_DIR JOB_ID REPAIR_BINARY_SHA256 [--vm VM_NAME]\nAll operations remain ineligible for execution admission and qualification.";

/// Parse the entire command before opening a journal or contacting the VM.
/// The private host nonce is never an operator argument or a public result.
pub fn run_candidate_build_command(args: &[String]) -> Result<Value, String> {
    let action = match (args.first().map(String::as_str), args.len()) {
        (Some("source"), 5) => "source",
        (Some("run"), 20) => "run",
        (Some("run"), 22) if args[20] == "--vm" => "run",
        (Some("read"), 5) => "read",
        (Some("read"), 7) if args[5] == "--vm" => "read",
        (Some("repair"), 4) => "repair",
        (Some("repair"), 6) if args[4] == "--vm" => "repair",
        _ => return Err(CANDIDATE_BUILD_USAGE.into()),
    };
    if action == "source" {
        return prepare_local_source_archive_one_use(
            Path::new(&args[1]),
            &args[2],
            Path::new(&args[3]),
            &args[4],
        )
        .map_err(|e| e.to_string());
    }
    if action == "run" {
        return run(args);
    }
    let vm_index = if action == "repair" { 5 } else { 6 };
    let operations =
        public_vm_operations(args.get(vm_index).map(String::as_str)).map_err(|e| e.to_string())?;
    let journal =
        HostCandidateBuildPinJournal::open(Path::new(&args[1])).map_err(|e| e.to_string())?;
    if action == "repair" {
        VmHostBoundCandidateRepairPlan::new(&operations, &journal, &args[2], &args[3])?
            .execute_repair(&journal)
    } else {
        VmHostBoundCandidateResultPlan::new(&operations, &journal, &args[2], &args[3], &args[4])
            .map_err(|e| e.to_string())?
            .execute_read_only()
            .map_err(|e| e.to_string())
    }
}

fn run(args: &[String]) -> Result<Value, String> {
    let operations =
        public_vm_operations(args.get(21).map(String::as_str)).map_err(|e| e.to_string())?;
    let pins = HostCandidateBuildPins {
        job_id: args[2].clone(),
        source_sha: args[3].clone(),
        source_archive_sha256: args[4].clone(),
        version: args[5].clone(),
        tag: args[6].clone(),
        controller_root: args[7].clone(),
        controller_tree_sha256: args[8].clone(),
        uv_base_image_id: args[9].clone(),
        rust_base_image_id: args[10].clone(),
        builder_image_id: args[11].clone(),
        policy_sha256: args[12].clone(),
        podman_sha256: args[13].clone(),
        slirp4netns_sha256: args[14].clone(),
        apparmor_parser_sha256: args[15].clone(),
        seccomp_sha256: args[16].clone(),
        runner_binary_sha256: args[17].clone(),
        result_reader_binary_sha256: args[18].clone(),
    };
    let plan = VmCandidateBuildPlan::new(&operations, pins).map_err(|e| e.to_string())?;
    let journal =
        HostCandidateBuildPinJournal::open(Path::new(&args[1])).map_err(|e| e.to_string())?;
    plan.preflight_plan(&args[19])
        .map_err(|e| e.to_string())?
        .execute_read_only()
        .map_err(|e| e.to_string())?;
    plan.record_before_launch(&journal)
        .map_err(|e| e.to_string())?
        .execute_once(&journal)
        .map_err(|e| e.to_string())
}
