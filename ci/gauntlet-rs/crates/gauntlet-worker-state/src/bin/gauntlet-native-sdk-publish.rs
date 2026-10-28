//! Fixed inert public SDK publication; no package process runs as Root.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = if args.len() == 3 {
        gauntlet_worker_state::publish_native_sdk_assets(&args[0], &args[1], &args[2])
    } else {
        Err("usage: gauntlet-native-sdk-publish JOB DECLARATION_SHA256 OWN_GENERATION".into())
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("native SDK publication unavailable: {error}");
            std::process::exit(2)
        }
    }
}
#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn main() {
    eprintln!("native SDK publication requires Linux ARM64 Root");
    std::process::exit(2)
}
