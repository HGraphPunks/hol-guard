//! Explicit passive lifecycle; the existing operator entrypoint is unchanged.

use gauntlet_host_state::{HostLifecycleError, HostLifecycleStore};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage: gauntlet-host <init|status|hold|resume|agent|down|enqueue-release> --state-parent ABSOLUTE_PRIVATE_DIRECTORY [--repository OWNER/REPO] [--job-id HEX16 --tag v3.48.0|v3.49.0 --source-sha HEX40] [--once]\nState is isolated in rust-host-v1. This passive lifecycle never dispatches VM work or publishes GitHub status.";

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
            "--state-parent" | "--repository" | "--job-id" | "--tag" | "--source-sha"
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
    if (once && command != "agent")
        || (repository.is_some() && command != "init")
        || ([id.is_some(), tag.is_some(), sha.is_some()]
            .into_iter()
            .any(|v| v)
            && command != "enqueue-release")
    {
        return Err(USAGE.to_owned());
    }
    let store = if command == "init" {
        HostLifecycleStore::initialize(&parent, repository.as_deref().ok_or(USAGE)?, now()?)
    } else {
        HostLifecycleStore::open(&parent)
    }
    .map_err(|e| e.to_string())?;
    match command.as_str() {
        "init" | "status" => {}
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
