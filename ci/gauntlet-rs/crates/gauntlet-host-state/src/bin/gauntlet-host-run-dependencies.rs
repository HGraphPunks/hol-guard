fn run() -> Result<serde_json::Value, String> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if !matches!(args.first().map(String::as_str), Some("read" | "run")) {
        args.insert(0, "run".into());
    }
    gauntlet_host_state::run_dependency_command(&args)
}
fn main() {
    match run() {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("dependency preparation unavailable: {e}");
            std::process::exit(2);
        }
    }
}
