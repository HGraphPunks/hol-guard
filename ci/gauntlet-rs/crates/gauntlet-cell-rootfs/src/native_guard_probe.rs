//! Explicit unprivileged product-test adapters; Rust owns budgets and checks.
use crate::{fs_input, NativeCell, NativeGuardPins, Result};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub(crate) const IDENTITY: &str = include_str!("../../../adapters/native_guard_identity_v1.py");
pub(crate) const READINESS: &str =
    include_str!("../../../adapters/native_workspace_readiness_v1.py");
pub(crate) const PIPE_LAUNCH: &str = include_str!("../../../adapters/native_pipe_launch_v1.py");

pub(crate) fn python_command(
    prefix: &std::path::Path,
    args: &[&str],
    pipe_transport: bool,
) -> Vec<String> {
    let mut command = vec![
        prefix.join("bin/python").to_string_lossy().into_owned(),
        "-I".into(),
        "-B".into(),
    ];
    if pipe_transport {
        // Preserve automatic selection, bundled-manifest checks and the real
        // Core digest used to authenticate policy snapshots. Only process
        // launching uses the separately measured, unprivileged connector.
        command.extend([
            "-c".into(),
            PIPE_LAUNCH.into(),
            prefix
                .join("lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime")
                .to_string_lossy()
                .into_owned(),
        ]);
    }
    command.extend(args.iter().map(|s| (*s).into()));
    command
}

pub(crate) fn inert_native(cell: &NativeCell, pins: &NativeGuardPins) -> Result<()> {
    gauntlet_evidence::verify_installed_version_metadata(
        cell.runtime_prefix(),
        &pins.package_version,
        &pins.source_sha,
        &pins.native_sha256,
    )
    .map_err(|e| e.to_string())?;
    fs_input::pinned(
        &cell
            .runtime_prefix()
            .join("lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime"),
        128 * 1024 * 1024,
        &pins.native_sha256,
    )?;
    fs_input::pinned(
        &cell.inputs.system.root.join("usr/bin/bwrap"),
        2 * 1024 * 1024,
        &pins.bwrap_sha256,
    )?;
    Ok(())
}

pub(crate) fn identity(cell: &mut NativeCell, pins: &NativeGuardPins) -> Result<Value> {
    let argv = cell.product_python_command(&["-c", IDENTITY]);
    let output = cell.capture(&argv, b"", Duration::from_secs(30))?;
    if output.returncode != 0 || output.stdout.len() > 65536 {
        return Err("unprivileged Native identity adapter failed".into());
    }
    let raw = gauntlet_contracts::canonicalize(&output.stdout).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if ["available", "compatible", "installed"]
        .iter()
        .any(|k| v[*k] != true)
        || v["package_version"] != pins.package_version
        || v["runtime_sha256"] != pins.native_sha256
        || v["manifest"]["source_sha"] != pins.source_sha
        || v["manifest"]["package_version"] != pins.package_version
        || v["manifest"]["runtime_sha256"] != pins.native_sha256
        || v["capabilities"]["build_sha"] != pins.source_sha
        || v["capabilities"]["runtime_version"] != pins.package_version
    {
        return Err("Native product identity claim differs from outside pins".into());
    }
    Ok(v)
}

pub(crate) fn readiness(
    cell: &mut NativeCell,
    setup: Instant,
    observations: &mut Vec<Value>,
) -> Result<Value> {
    let seconds = setup
        .saturating_duration_since(Instant::now())
        .as_secs()
        .min(35);
    if seconds < 2 {
        return Err("Native workspace readiness setup deadline".into());
    }
    let seconds_text = seconds.to_string();
    let argv =
        cell.product_python_command(&["-c", READINESS, cell.workspace_path(), &seconds_text]);
    // A single normal readiness request; no response is retried or fabricated.
    let output = cell.capture(&argv, b"", Duration::from_secs(seconds))?;
    observations.push(json!({"kind":"native-workspace-readiness-capture",
        "exit_code":output.returncode,"stdout_sha256":crate::hash(&output.stdout),
        "stderr_sha256":crate::hash(&output.stderr),
        "response":if output.stdout.len() <= 4096 {
            gauntlet_contracts::canonicalize(&output.stdout).ok()
                .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        } else {None}}));
    if output.returncode != 0 || output.stdout.len() > 4096 {
        return Err("Native workspace readiness adapter failed".into());
    }
    let raw = gauntlet_contracts::canonicalize(&output.stdout).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let expected = json!({"ready":true,"native_required":true,"native_route":"native_resident","workspace_acknowledged":true,"worker_ready":true});
    if value != expected {
        return Err("Native workspace readiness differs from the required barrier".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_launch_keeps_bundled_identity_and_the_original_python_arguments() {
        let prefix = std::path::Path::new("/opt/hol-gauntlet/candidates/pinned/prefix");
        for args in [
            vec!["-m", "codex_plugin_scanner.cli", "guard"],
            vec!["-c", "pass", "a b"],
        ] {
            let old = python_command(prefix, &args, false);
            assert_eq!(
                &old[..3],
                &[
                    format!("{}/bin/python", prefix.display()),
                    "-I".into(),
                    "-B".into()
                ]
            );
            assert_eq!(&old[3..], args);
            let wire = python_command(prefix, &args, true);
            assert_eq!(&wire[..3], &old[..3]);
            assert_eq!(&wire[3..5], &["-c", PIPE_LAUNCH]);
            assert_eq!(wire[5], format!("{}/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime", prefix.display()));
            assert_eq!(&wire[6..], args);
            assert!(wire.iter().all(|arg| !arg.starts_with("HOL_GUARD_NATIVE=")));
        }
    }
}
