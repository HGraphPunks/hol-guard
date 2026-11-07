//! Uninstalled host-bound result readback and explicit owned-resource repair.

use gauntlet_host_state::{
    public_vm_operations, HostCandidateBuildPinJournal, VmHostBoundCandidateRepairPlan,
    VmHostBoundCandidateResultPlan,
};
use serde_json::Value;
use std::path::Path;

fn run() -> Result<Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "--repair")
        && args.len() != 5
        && !(args.len() == 7 && args[5] == "--vm")
    {
        return Err("usage: gauntlet-host-shadow-hostbound-candidate-result --repair PRIVATE_PIN_DIR JOB_ID REPAIR_BINARY_SHA256 [--vm VM_NAME]".into());
    }
    if args.len() != 5 && !(args.len() == 7 && args[5] == "--vm") {
        return Err("usage: gauntlet-host-shadow-hostbound-candidate-result PRIVATE_PIN_DIR JOB_ID RESULT_SHA256 EXPORT_ARCHIVE_SHA256 [--vm VM_NAME]".to_owned());
    }
    let operations =
        public_vm_operations(args.get(6).map(String::as_str)).map_err(|error| error.to_string())?;
    let repair = args[1] == "--repair";
    let journal = HostCandidateBuildPinJournal::open(Path::new(&args[if repair { 2 } else { 1 }]))
        .map_err(|error| error.to_string())?;
    if repair {
        return VmHostBoundCandidateRepairPlan::new(&operations, &journal, &args[3], &args[4])?
            .execute_repair(&journal);
    }
    let plan =
        VmHostBoundCandidateResultPlan::new(&operations, &journal, &args[2], &args[3], &args[4])
            .map_err(|error| error.to_string())?;
    plan.execute_read_only().map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("host-bound candidate result unavailable: {error}");
            std::process::exit(2);
        }
    }
}
