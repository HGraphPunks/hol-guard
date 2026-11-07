//! Explicit one-use feature audit. This does not install a production worker.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = gauntlet_host_state::run_feature_audit_command(&args);
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("feature audit unavailable: {error}");
            std::process::exit(2);
        }
    }
}
