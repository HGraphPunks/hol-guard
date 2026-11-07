//! Read-only Linux VM resource telemetry, with no interpreter or Root request.

use gauntlet_host_state::sample_host;
use serde_json::json;
use std::path::Path;

fn main() {
    if std::env::args_os().len() != 1 || !cfg!(target_os = "linux") {
        eprintln!("gauntlet-vm-telemetry takes no arguments and requires Linux");
        std::process::exit(2);
    }
    let sample = match sample_host(Path::new("/")) {
        Ok(value) if value["memory_total"].is_u64() && value["memory_available"].is_u64() => value,
        _ => {
            eprintln!("VM resource sample unavailable");
            std::process::exit(2);
        }
    };
    println!(
        "{}",
        json!({"schema":"hol-gauntlet-vm-telemetry.v1", "platform":"Linux",
        "status":"running", "checked_at":sample["checked_at"], "cpus":sample["cpus"],
        "load":sample["load"], "memory_total":sample["memory_total"],
        "memory_available":sample["memory_available"], "disk_total":sample["disk_total"],
        "disk_free":sample["disk_free"]})
    );
}
