//! Diagnostic readback of exact caller-pinned Native pipe snapshots.
use gauntlet_evidence::{verify_native_stdio_files, EvidenceError};
use std::path::Path;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let result = if args.len() == 7 {
        verify_native_stdio_files(
            Path::new(&args[1]),
            &args[2],
            Path::new(&args[3]),
            &args[4],
            Path::new(&args[5]),
            &args[6],
        )
    } else {
        Err(EvidenceError::Invalid("usage: gauntlet-native-stdio-verify STDIO_JOURNAL SHA256 PROCESS_JOURNAL SHA256 PROCESS_CHECKPOINT SHA256"))
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("Native stdio snapshots unavailable: {error}");
            std::process::exit(2);
        }
    }
}
