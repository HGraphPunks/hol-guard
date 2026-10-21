#[cfg(target_os = "linux")]
fn main() {
    use gauntlet_evidence::observe_local_conformance_package_from_paths_ineligible;
    use std::path::Path;

    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 6 {
        eprintln!("usage: gauntlet-local-conformance-shadow ABSOLUTE_CONFIG_JSON EXTERNAL_CONFIG_SHA256 ABSOLUTE_ASSET_ROOT ABSOLUTE_CONTROLLER_ROOT EXTERNAL_CONTROLLER_TREE_SHA256");
        std::process::exit(2);
    }
    let (Some(config_digest), Some(controller_digest)) = (args[2].to_str(), args[5].to_str())
    else {
        eprintln!("outside SHA-256 pins must be lowercase ASCII");
        std::process::exit(2);
    };
    let result = observe_local_conformance_package_from_paths_ineligible(
        Path::new(&args[1]),
        config_digest,
        Path::new(&args[3]),
        Path::new(&args[4]),
        controller_digest,
    );
    match result {
        Ok(shadow) => println!("{}", shadow.to_json()),
        Err(error) => {
            eprintln!("local conformance shadow refused: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux Root required for local conformance shadow");
    std::process::exit(2);
}
