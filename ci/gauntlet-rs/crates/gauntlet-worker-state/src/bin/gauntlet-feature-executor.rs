//! Fixed unprivileged ARM feature audit. No arbitrary command or selector API.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn main() {
    use std::io::Write;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.len() == 1 {
        gauntlet_worker_state::run_fixed_feature_executor(&args[0])
    } else {
        Err("one outside feature-spec SHA-256 argument required".into())
    };
    match result {
        Ok(raw) => {
            let passed = serde_json::from_slice::<serde_json::Value>(&raw)
                .is_ok_and(|value| value["status"] == "passed");
            if std::io::stdout().lock().write_all(&raw).is_err() {
                std::process::exit(2);
            }
            std::process::exit(if passed { 0 } else { 1 });
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn main() {
    eprintln!("dedicated Linux ARM64 feature PID-1 container required");
    std::process::exit(2);
}
