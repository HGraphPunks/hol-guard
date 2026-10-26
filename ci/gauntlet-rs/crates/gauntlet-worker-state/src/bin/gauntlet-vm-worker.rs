//! Explicit native successor; historical Python and read-only shadow stay separate.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<(), String> {
    use std::io::{Read, Write};
    gauntlet_worker_state::install_native_worker_signals()?;
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() == 3 && args[1] == "--initialize-native" {
        let raw = gauntlet_worker_state::initialize_native_worker(&args[2])?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 8 && args[1] == "--repair-native" {
        let raw = gauntlet_worker_state::repair_native_worker(
            &args[2], &args[3], &args[4], &args[5], &args[6], &args[7],
        )?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 6 && args[1] == "--native-controller" {
        let result = gauntlet_worker_state::execute_native_controller(&args)?;
        println!("{}", result.report);
        return match result.error {
            Some(error) => Err(error),
            None => Ok(()),
        };
    }
    if args.len() != 4 {
        return Err("usage: gauntlet-vm-worker OUTSIDE_SOURCE_SHA OUTSIDE_DEPLOYMENT_SHA256 OUTSIDE_WORKER_GENERATION_SHA256".into());
    }
    let mut raw = Vec::new();
    std::io::stdin()
        .take(1025)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 1024 {
        return Err("native worker request exceeds 1024 bytes".into());
    }
    let response =
        gauntlet_worker_state::dispatch_native_worker(&args[1], &args[2], &args[3], &raw)?;
    let mut output = std::io::stdout().lock();
    output
        .write_all(&response)
        .and_then(|_| output.write_all(b"\n"))
        .map_err(|e| e.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<(), String> {
    Err("owned native Linux ARM64 Root worker required".into())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native worker unavailable: {error}");
        std::process::exit(2);
    }
}
