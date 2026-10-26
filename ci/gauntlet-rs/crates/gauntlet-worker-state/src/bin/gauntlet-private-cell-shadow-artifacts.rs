//! Inert current-source private-cell bootstrap for a retained shadow candidate.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let mut args: Vec<String> = std::env::args().collect();
    let native = args.get(1).is_some_and(|value| value == "--rust-actor");
    if native {
        args.remove(1);
    }
    if args.len() != 6 {
        return Err("usage: gauntlet-private-cell-shadow-artifacts [--rust-actor] JOB_ID SOURCE_ARTIFACTS ACTOR_SHA256 INITIALIZER_SHA256 SOURCE_MAP_SHA256".to_owned());
    }
    let pins = gauntlet_worker_state::PrivateCellShadowPins {
        job_id: &args[1],
        source_artifacts: &args[2],
        actor_sha256: &args[3],
        initializer_sha256: &args[4],
        source_map_sha256: &args[5],
    };
    let result = if native {
        gauntlet_worker_state::prepare_native_private_cell_shadow_artifacts_ineligible(&pins)
    } else {
        gauntlet_worker_state::prepare_private_cell_shadow_artifacts_ineligible(&pins)
    };
    result
        .map(|proof| proof.to_json().to_string())
        .map_err(|error| error.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("private-cell shadow artifacts unavailable: {error}");
            std::process::exit(2);
        }
    }
}
