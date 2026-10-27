//! One-use dependency capsule producer; no VM or candidate execution.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = if args.len() == 8 {
        gauntlet_host_state::prepare_local_dependency_inputs(
            std::path::Path::new(&args[1]),
            &args[2],
            &args[3],
            std::path::Path::new(&args[4]),
            &args[5],
            std::path::Path::new(&args[6]),
            &args[7],
        )
    } else {
        Err("usage: gauntlet-host-prepare-dependency-inputs SOURCE_STATE JOB_ID SOURCE_ARCHIVE_SHA256 LOCAL_REPOSITORY EXACT_SOURCE_SHA EXPORTER_ELF EXPORTER_SHA256".to_owned())
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("dependency input preparation unavailable: {error}");
            std::process::exit(2);
        }
    }
}
