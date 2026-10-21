//! Read-only host-manifest and six-role guest staging reconciliation.

#[cfg(target_os = "linux")]
fn run() -> Result<serde_json::Value, String> {
    use gauntlet_evidence::observe_staging_suite_root_owned_ineligible;
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err(
            "usage: gauntlet-staging-suite-shadow BUILD_JOB HOST_MANIFEST_SHA256".to_owned(),
        );
    }
    observe_staging_suite_root_owned_ineligible(&args[1], &args[2])
        .map(|proof| proof.to_json())
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux Root staging suite audit required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("staging suite audit unavailable: {error}");
            std::process::exit(2);
        }
    }
}
