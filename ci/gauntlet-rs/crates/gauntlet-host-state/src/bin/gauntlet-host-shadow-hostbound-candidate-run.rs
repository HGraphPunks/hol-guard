//! One-use host diagnostic: fsync exact outside build pins, launch the fixed
//! guest runner, and print only its ineligible terminal claim.

use gauntlet_host_state::run_candidate_build_command;
use serde_json::Value;

fn run() -> Result<Value, String> {
    let args = std::iter::once("run".to_owned())
        .chain(std::env::args().skip(1))
        .collect::<Vec<_>>();
    run_candidate_build_command(&args)
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
