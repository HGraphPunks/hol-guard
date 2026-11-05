//! Diagnostic public readback only; source and observer admission stay false.
use gauntlet_evidence::verify_native_process_event_files;
use std::path::Path;

fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();
    let result = if args.len() == 5 {
        match (args[2].to_str(), args[4].to_str()) {
            (Some(journal_pin), Some(checkpoint_pin)) => verify_native_process_event_files(
                Path::new(&args[1]),
                journal_pin,
                Path::new(&args[3]),
                checkpoint_pin,
            ),
            _ => Err(gauntlet_evidence::EvidenceError::Invalid(
                "ASCII outside pins required",
            )),
        }
    } else {
        Err(gauntlet_evidence::EvidenceError::Invalid("usage: gauntlet-native-process-events-verify JOURNAL JOURNAL_SHA256 CHECKPOINT CHECKPOINT_SHA256"))
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("Native process events unavailable: {error}");
            std::process::exit(2);
        }
    }
}
