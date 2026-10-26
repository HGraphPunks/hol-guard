//! Dedicated-VM zero-model apparatus proof. It cannot publish qualification.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    if !(args.len() == 4 || (args.len() == 5 && args[4] == "--prepared")) {
        return Err("usage: gauntlet-native-cell-proof ROOT_DECLARATION_JSON OUTSIDE_SHA256 success|timeout|cancel [--prepared]".into());
    }
    let report = gauntlet_cell_rootfs::run_native_apparatus(
        std::path::Path::new(&args[1]),
        &args[2],
        args[3].parse()?,
        args.len() == 5,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    println!("{}", report.report);
    match report.error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<(), String> {
    Err("owned native Linux ARM64 VM required".into())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native cell proof: {error}");
        std::process::exit(2);
    }
}
