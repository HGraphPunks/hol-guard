//! Fixed UID-65532 dependency adapter; never run as host or VM Root.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<serde_json::Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: gauntlet-dependency-exporter JOB_ID SOURCE_SHA PYPROJECT_SHA256 UV_LOCK_SHA256"
                .to_owned(),
        );
    }
    gauntlet_worker_state::export_native_dependencies(&args[1], &args[2], &args[3], &args[4])
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux ARM64 unprivileged adapter required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("dependency export unavailable: {error}");
            std::process::exit(2);
        }
    }
}
