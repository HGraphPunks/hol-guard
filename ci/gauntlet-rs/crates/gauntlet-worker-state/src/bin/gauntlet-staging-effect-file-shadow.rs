//! Read-only, ineligible held-file/writer diagnostic for a completed run.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<serde_json::Value, String> {
    use gauntlet_worker_state::staging_effect_file::observe_staging_fixed_provider_effect_ineligible;
    use gauntlet_worker_state::RunReservationJournal;
    use std::path::Path;

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 10 {
        return Err("usage: gauntlet-staging-effect-file-shadow RUN_ID SOURCE_SHA DEPLOYMENT_SHA WORKER_SHA STARTED_SHA EFFECT_JOURNAL_SHA ROLE PROVIDER_SURFACE OUTSIDE_PRODUCT_CGROUP".to_owned());
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(
        "/var/lib/hol-gauntlet-rust/staging-state",
    ))
    .map_err(|error| error.to_string())?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|error| error.to_string())?;
    let started = journal
        .started(&args[1], &args[2], &args[3], &args[4])
        .map_err(|error| error.to_string())?
        .ok_or("outside-pinned started marker is absent")?;
    if started.sha256 != args[5] || started.controller_public_key_hex.is_none() {
        return Err("effect file lacks the keyed outside started pin".to_owned());
    }
    observe_staging_fixed_provider_effect_ineligible(
        &journal, &lease, &started, &args[6], &args[7], &args[8], &args[9],
    )
    .map(|proof| proof.to_json())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux ARM64 Root effect-file diagnostic required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("staging effect-file diagnostic unavailable: {error}");
            std::process::exit(2);
        }
    }
}
