//! One-use host diagnostic: fsync exact outside build pins, launch the fixed
//! guest runner, and print only its ineligible terminal claim.

use gauntlet_host_state::{
    HostCandidateBuildPinJournal, HostCandidateBuildPins, VmCandidateBuildPlan,
};
use serde_json::Value;
use std::path::Path;

fn run() -> Result<Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 18 {
        return Err("usage: gauntlet-host-shadow-hostbound-candidate-run PRIVATE_PIN_DIR JOB_ID SOURCE_COMMIT SOURCE_ARCHIVE_SHA256 VERSION CONTROLLER_ROOT CONTROLLER_TREE_SHA256 UV_BASE_IMAGE_ID RUST_BASE_IMAGE_ID BUILDER_IMAGE_ID POLICY_SHA256 PODMAN_SHA256 SLIRP_SHA256 APPARMOR_PARSER_SHA256 SECCOMP_SHA256 RUNNER_BINARY_SHA256 RESULT_READER_BINARY_SHA256".to_owned());
    }
    let operations: Value = serde_json::from_str(include_str!("../../operations-defaults-v1.json"))
        .map_err(|_| "compiled public VM defaults invalid".to_owned())?;
    let pins = HostCandidateBuildPins {
        job_id: args[2].clone(),
        source_sha: args[3].clone(),
        source_archive_sha256: args[4].clone(),
        version: args[5].clone(),
        controller_root: args[6].clone(),
        controller_tree_sha256: args[7].clone(),
        uv_base_image_id: args[8].clone(),
        rust_base_image_id: args[9].clone(),
        builder_image_id: args[10].clone(),
        policy_sha256: args[11].clone(),
        podman_sha256: args[12].clone(),
        slirp4netns_sha256: args[13].clone(),
        apparmor_parser_sha256: args[14].clone(),
        seccomp_sha256: args[15].clone(),
        runner_binary_sha256: args[16].clone(),
        result_reader_binary_sha256: args[17].clone(),
    };
    let journal = HostCandidateBuildPinJournal::open(Path::new(&args[1]))
        .map_err(|error| error.to_string())?;
    let plan = VmCandidateBuildPlan::new(&operations, pins).map_err(|error| error.to_string())?;
    let invocation = plan
        .record_before_launch(&journal)
        .map_err(|error| error.to_string())?;
    invocation
        .execute_once(&journal)
        .map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("host-bound candidate run unavailable: {error}");
            std::process::exit(2);
        }
    }
}
