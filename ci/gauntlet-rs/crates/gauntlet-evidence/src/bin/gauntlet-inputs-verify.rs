use gauntlet_evidence::{load_runner_config_from_paths, verify_runner_file_assets};
use serde_json::json;
use std::path::Path;

fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 4 {
        eprintln!(
            "usage: gauntlet-inputs-verify ABSOLUTE_CONFIG_JSON EXTERNAL_CONFIG_SHA256 ABSOLUTE_ASSET_ROOT"
        );
        std::process::exit(2);
    }
    let config = Path::new(&arguments[1]);
    let Some(pin) = arguments[2].to_str() else {
        eprintln!("external config SHA-256 must be lowercase ASCII");
        std::process::exit(2);
    };
    let asset_root = Path::new(&arguments[3]);
    if !config.is_absolute() || !asset_root.is_absolute() {
        eprintln!("config and asset root must be absolute paths");
        std::process::exit(2);
    }
    let result = load_runner_config_from_paths(config, pin, asset_root).and_then(|loaded| {
        let files = verify_runner_file_assets(&loaded.verified, asset_root)?;
        Ok(json!({
            "profile": "gauntlet-runner-inputs.v1",
            "schema": loaded.verified.config.value()["schema"],
            "config_digest": pin,
            "selected_episodes": loaded.verified.config.value()["selection"].as_array().map(Vec::len),
            "shards": loaded.verified.shards,
            "selection_reservations": loaded.verified.selection_reservations.to_json(),
            "file_assets_verified": files,
            "installed_package_version_metadata": loaded.installed_package_version,
            "tree_and_installed_assets_verified": false,
            "execution_eligible": false,
        }))
    });
    match result {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("gauntlet runner inputs invalid: {error}");
            std::process::exit(1);
        }
    }
}
