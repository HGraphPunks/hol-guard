//! Explicit passive lifecycle; the existing operator entrypoint is unchanged.

use gauntlet_host_state::{
    collect_observer_once, compose_observer_snapshot, read_observer_operations,
    run_passive_observer, HostLifecycleError, HostLifecycleStore,
};
#[path = "gauntlet-host/signals.rs"]
mod signals;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage: gauntlet-host <init|configure|up|status|doctor|hold|resume|agent|down|enqueue-release> --state-parent ABSOLUTE_PRIVATE_DIRECTORY\ninit: --repository OWNER/REPO\nconfigure/up: --operations ABSOLUTE_PRIVATE_CONFIG_JSON --vm-probe-sha256 HEX64\nup/agent/doctor/status: --config-sha256 HEX64\nup: [--port 8794] [--once]; agent: [--once]\nenqueue-release: --job-id HEX16 --tag v3.48.0|v3.49.0 --source-sha HEX40\nState is isolated in rust-host-v1. The passive observer never dispatches VM work or publishes GitHub status.";

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "host clock unavailable".to_owned())
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        println!("{USAGE}");
        return Ok(());
    };
    if matches!(command.as_str(), "--help" | "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    let mut options = std::collections::BTreeMap::new();
    let mut once = false;
    while let Some(key) = args.next() {
        if key == "--once" && !once {
            once = true;
            continue;
        }
        if !matches!(
            key.as_str(),
            "--state-parent"
                | "--repository"
                | "--job-id"
                | "--tag"
                | "--source-sha"
                | "--operations"
                | "--vm-probe-sha256"
                | "--config-sha256"
                | "--port"
        ) {
            return Err(USAGE.to_owned());
        }
        let value = args
            .next()
            .filter(|value| !value.starts_with("--"))
            .ok_or(USAGE)?;
        if options.insert(key, value).is_some() {
            return Err(USAGE.to_owned());
        }
    }
    let parent = PathBuf::from(options.remove("--state-parent").ok_or(USAGE)?);
    let repository = options.remove("--repository");
    let id = options.remove("--job-id");
    let tag = options.remove("--tag");
    let sha = options.remove("--source-sha");
    let operations_path = options.remove("--operations");
    let probe_sha = options.remove("--vm-probe-sha256");
    let config_sha = options.remove("--config-sha256");
    let port = options
        .remove("--port")
        .map(|value| value.parse::<u16>())
        .transpose()
        .map_err(|_| USAGE)?;
    if (once && !matches!(command.as_str(), "agent" | "up"))
        || (repository.is_some() && command != "init")
        || ((operations_path.is_some() || probe_sha.is_some())
            && !matches!(command.as_str(), "configure" | "up"))
        || (operations_path.is_some() != probe_sha.is_some())
        || (config_sha.is_some()
            && !matches!(command.as_str(), "agent" | "up" | "doctor" | "status"))
        || (port.is_some() && command != "up")
        || ([id.is_some(), tag.is_some(), sha.is_some()]
            .into_iter()
            .any(|v| v)
            && command != "enqueue-release")
    {
        return Err(USAGE.to_owned());
    }
    let operations = operations_path
        .as_ref()
        .map(|path| read_observer_operations(std::path::Path::new(path)))
        .transpose()
        .map_err(|e| e.to_string())?;
    let store = if command == "init" {
        HostLifecycleStore::initialize(&parent, repository.as_deref().ok_or(USAGE)?, now()?)
    } else if command == "up" && operations.is_some() {
        match HostLifecycleStore::open(&parent) {
            Ok(store) => Ok(store),
            Err(HostLifecycleError::UnsafeDirectory) => HostLifecycleStore::initialize(
                &parent,
                operations
                    .as_ref()
                    .and_then(|value| value["repository"].as_str())
                    .ok_or(USAGE)?,
                now()?,
            ),
            Err(error) => Err(error),
        }
    } else {
        HostLifecycleStore::open(&parent)
    }
    .map_err(|e| e.to_string())?;
    match command.as_str() {
        "init" => {}
        "status" => {
            if let Some(digest) = config_sha.as_deref() {
                println!(
                    "{}",
                    store
                        .published_observer_snapshot(digest, now()?)
                        .map_err(|e| e.to_string())?
                );
                return Ok(());
            }
        }
        "configure" | "up" => {
            let configured = if let Some(operations) = &operations {
                Some(
                    store
                        .configure_observer(operations, probe_sha.as_deref().ok_or(USAGE)?)
                        .map_err(|e| e.to_string())?,
                )
            } else {
                None
            };
            let digest = config_sha
                .as_deref()
                .or_else(|| configured.as_ref().map(|value| value.sha256.as_str()))
                .ok_or(USAGE)?;
            let config = store
                .read_observer_configuration(digest)
                .map_err(|e| e.to_string())?;
            if command == "configure" {
                println!(
                    "{}",
                    serde_json::json!({"configuration_sha256":config.sha256,"execution_eligible":false})
                );
                return Ok(());
            }
            let _signals = signals::Signals::install()?;
            let snapshot = run_passive_observer(
                &store,
                digest,
                &parent,
                Some(port.unwrap_or(8794)),
                once,
                &signals::STOP,
            )
            .map_err(|e| e.to_string())?;
            println!("{snapshot}");
            return Ok(());
        }
        "doctor" => {
            let config = store
                .read_observer_configuration(config_sha.as_deref().ok_or(USAGE)?)
                .map_err(|e| e.to_string())?;
            let _signals = signals::Signals::install()?;
            let observations = collect_observer_once(&config, &parent, &signals::STOP)
                .map_err(|e| e.to_string())?;
            let snapshot = compose_observer_snapshot(
                &config,
                &store.status(now()?).map_err(|e| e.to_string())?,
                &observations,
                now()?,
            )
            .map_err(|e| e.to_string())?;
            println!("{snapshot}");
            return Ok(());
        }
        "hold" => store.set_hold(true, now()?).map_err(|e| e.to_string())?,
        "resume" => store.set_hold(false, now()?).map_err(|e| e.to_string())?,
        "down" => store.request_stop(now()?).map_err(|e| e.to_string())?,
        "enqueue-release" => {
            store
                .enqueue_release(
                    id.as_deref().ok_or(USAGE)?,
                    tag.as_deref().ok_or(USAGE)?,
                    sha.as_deref().ok_or(USAGE)?,
                    now()?,
                )
                .map_err(|e| e.to_string())?;
        }
        "agent" => {
            if let Some(digest) = config_sha.as_deref() {
                let _signals = signals::Signals::install()?;
                let snapshot =
                    run_passive_observer(&store, digest, &parent, None, once, &signals::STOP)
                        .map_err(|e| e.to_string())?;
                println!("{snapshot}");
                return Ok(());
            }
            let lease = store.start_observer(now()?).map_err(|e| e.to_string())?;
            loop {
                match lease.heartbeat(now()?) {
                    Ok(stop) if stop || once => break,
                    Ok(_) | Err(HostLifecycleError::Busy) => {}
                    Err(error) => return Err(error.to_string()),
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            lease.finish(now()?).map_err(|e| e.to_string())?;
        }
        _ => return Err(USAGE.to_owned()),
    }
    println!("{}", store.status(now()?).map_err(|e| e.to_string())?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
