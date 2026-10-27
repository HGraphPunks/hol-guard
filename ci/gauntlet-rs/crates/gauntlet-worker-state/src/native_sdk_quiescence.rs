//! Outside-worker postcondition. A controller's own cleanup claim cannot
//! close a job while SDK container metadata or its scoped LSM profile survives.
use crate::native_sdk_process::RootCommands;
use crate::NativeJobSpec;
use gauntlet_cell_rootfs::CellPreparation;
use std::io::Read;
use std::sync::atomic::AtomicBool;
pub(crate) fn require_sdk_quiescence(
    job: &NativeJobSpec,
    spec: &CellPreparation,
) -> Result<(), String> {
    let parser = spec
        .host_helper_sha256("/usr/sbin/apparmor_parser")
        .ok_or("SDK post parser pin required")?;
    let mut commands = RootCommands::for_post(&job.job_root(), &spec.podman_sha256, parser)?;
    let output = commands.run(
        false,
        &[
            "ps".into(),
            "--all".into(),
            "--filter".into(),
            format!("label=hol.gauntlet.sdk.job={}", job.job_id),
            "--format=json".into(),
        ],
        20,
        &AtomicBool::new(false),
    )?;
    if !output.status.success() {
        return Err("SDK post container inventory unavailable".into());
    }
    let raw =
        gauntlet_contracts::canonicalize(&output.stdout).map_err(|_| "SDK post container JSON")?;
    let values: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| "SDK post container JSON")?;
    if values.as_array().is_none_or(|a| !a.is_empty()) {
        return Err("SDK container metadata survives outside controller cleanup".into());
    }
    let mut raw = Vec::new();
    std::fs::File::open("/sys/kernel/security/apparmor/profiles")
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 65536 {
        return Err("SDK profile inventory bound".into());
    }
    let profiles = std::str::from_utf8(&raw).map_err(|_| "SDK profile inventory UTF-8")?;
    if profiles
        .lines()
        .any(|line| line.starts_with(&format!("hol-gauntlet-sdk-{}-", job.job_id)))
    {
        return Err("SDK scoped profile survives outside controller cleanup".into());
    }
    Ok(())
}
