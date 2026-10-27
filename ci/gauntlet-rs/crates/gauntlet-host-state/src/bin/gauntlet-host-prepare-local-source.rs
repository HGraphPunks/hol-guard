//! Explicit one-use local source producer; no remote fetch, VM or candidate exec.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = if args.len() == 5 {
        gauntlet_host_state::prepare_local_source_archive_one_use(
            std::path::Path::new(&args[1]),
            &args[2],
            std::path::Path::new(&args[3]),
            &args[4],
        )
        .map_err(|error| error.to_string())
    } else {
        Err("usage: gauntlet-host-prepare-local-source PRIVATE_STATE JOB_ID ABSOLUTE_LOCAL_REPOSITORY EXACT_COMMIT".to_owned())
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("local source preparation unavailable: {error}");
            std::process::exit(2);
        }
    }
}
