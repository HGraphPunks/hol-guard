//! Uninstalled host-bound result readback and explicit owned-resource repair.

use gauntlet_host_state::run_candidate_build_command;
use serde_json::Value;

fn run() -> Result<Value, String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let action = if args.first().is_some_and(|arg| arg == "--repair") {
        args.remove(0);
        "repair"
    } else {
        "read"
    };
    args.insert(0, action.into());
    run_candidate_build_command(&args)
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
