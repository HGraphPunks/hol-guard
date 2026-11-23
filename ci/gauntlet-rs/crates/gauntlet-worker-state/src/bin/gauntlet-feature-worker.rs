//! Root ARM feature lifecycle. Every action uses fixed namespaces and hashes.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn main() {
    use gauntlet_worker_state as worker;
    use std::io::Write;
    if let Err(error) = worker::install_native_worker_signals() {
        eprintln!("{error}");
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = (|| -> Result<Vec<u8>, String> {
        match args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["--initialize", generation] => worker::initialize_native_worker(generation),
            ["--capture-asset", kind, digest, bytes, generation] => {
                worker::capture_native_feature_asset(
                    kind,
                    digest,
                    bytes
                        .parse()
                        .map_err(|_| "feature asset byte count required")?,
                    generation,
                )
            }
            ["--run", digest, bytes, generation] => {
                let raw = worker::receive_native_feature_intent(
                    0,
                    bytes
                        .parse()
                        .map_err(|_| "feature intent byte count required")?,
                    digest,
                )?;
                worker::run_native_features(&raw, digest, generation)
            }
            ["--read", audit, digest, generation] => {
                worker::read_native_feature_result(audit, digest, generation)
            }
            ["--repair", audit, digest, generation] => {
                worker::repair_native_features(audit, digest, generation)
            }
            _ => Err(
                "fixed feature initialize/capture/run/read/repair action and exact pins required"
                    .into(),
            ),
        }
    })();
    match result {
        Ok(mut raw) => {
            raw.push(b'\n');
            if std::io::stdout().lock().write_all(&raw).is_err() {
                std::process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn main() {
    eprintln!("outside Linux ARM64 Root feature worker required");
    std::process::exit(2);
}
