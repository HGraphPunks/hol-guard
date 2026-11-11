//! Explicit one-use local source producer; no remote fetch, VM or candidate exec.

fn main() {
    let args = std::iter::once("source".to_owned())
        .chain(std::env::args().skip(1))
        .collect::<Vec<_>>();
    let result = gauntlet_host_state::run_candidate_build_command(&args);
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("local source preparation unavailable: {error}");
            std::process::exit(2);
        }
    }
}
