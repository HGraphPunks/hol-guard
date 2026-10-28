//! Public diagnostic readback of the fixed v2 feature audit.
use gauntlet_evidence::{verify_feature_report_files_v2, EvidenceError};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.len() == 5 {
        verify_feature_report_files_v2(
            Path::new(&args[0]),
            &args[1],
            Path::new(&args[2]),
            &args[3],
            Path::new(&args[4]),
        )
    } else {
        Err(EvidenceError::Invalid(
            "usage: gauntlet-feature-report-verify SPEC SHA256 REPORT SHA256 ARTIFACT_DIRECTORY",
        ))
    };
    match result {
        Ok(value) => {
            println!("{value}");
            if value["status"] != "passed" {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("feature audit readback unavailable: {error}");
            std::process::exit(2);
        }
    }
}
