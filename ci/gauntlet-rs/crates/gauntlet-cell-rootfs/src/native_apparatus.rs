//! Fixed zero-model apparatus cases shared by worker execution and VM proof.
//! A successful case cannot qualify Guard or score its decisions.
pub fn run_native_apparatus(
    declaration: &std::path::Path,
    expected_sha256: &str,
    case: crate::NativeCase,
    prepared: bool,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> crate::Result<crate::NativeApparatusReport> {
    use crate::{NativeCell, Result};
    use serde_json::json;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    let mut cell = if prepared {
        crate::prepare_and_start(declaration, expected_sha256, cancelled.clone())?
    } else {
        NativeCell::start(declaration, expected_sha256, cancelled.clone())?
    };
    let supervisor_digest = cell.supervisor_declaration_sha256().to_owned();
    let rust_image_owned = cell.image_lease_owned();
    let workspace = cell.workspace_source().to_owned();
    let effect = workspace.join("rust-supervisor-effect");
    let actor = cell
        .actor_observation()
        .cloned()
        .ok_or("actor observation unavailable")?;
    let mut native_started = false;
    let result = (|| -> Result<()> {
        let command = |arguments: &[&str]| -> Vec<String> {
            let mut argv = vec![
                cell.runtime_prefix()
                    .join("bin/python")
                    .to_string_lossy()
                    .into_owned(),
                "-I".into(),
                "-B".into(),
                "-m".into(),
                "codex_plugin_scanner.cli".into(),
                "guard".into(),
            ];
            argv.extend(arguments.iter().map(|s| s.to_string()));
            argv
        };
        let mut daemon = vec!["/usr/bin/env".into(), "HOME=/runtime/home".into()];
        daemon.extend(command(&[
            "daemon",
            "--serve",
            "--guard-home",
            "/product/guard",
            "--home",
            "/product/home",
            "--port",
            "18765",
            "--workspace",
            cell.workspace_path(),
        ]));
        let status = command(&[
            "daemon",
            "status",
            "--json",
            "--guard-home",
            "/product/guard",
            "--home",
            "/product/home",
        ]);
        let handle = cell.spawn(&daemon, Instant::now() + Duration::from_secs(5))?;
        cell.release(&handle, Instant::now() + Duration::from_secs(5))?;
        cell.end_input(&handle, Instant::now() + Duration::from_secs(5))?;
        let setup = Instant::now() + Duration::from_secs(60);
        for _ in 0..60 {
            let chunk = cell.read_process(&handle, 0, setup)?;
            if chunk.returncode.is_some() {
                return Err("Native daemon exited before readiness".into());
            }
            let status = cell.capture(
                &status,
                b"",
                setup
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(30)),
            )?;
            if status.returncode == 0
                && serde_json::from_slice::<serde_json::Value>(&status.stdout)
                    .ok()
                    .is_some_and(|v| v["running"] == true)
            {
                native_started = true;
                break;
            }
            if Instant::now() >= setup {
                return Err("Native daemon readiness deadline".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !native_started {
            return Err("Native daemon readiness attempts exhausted".into());
        }
        if effect.exists() {
            return Err("fresh physical effect must be absent".into());
        }
        if case == crate::NativeCase::Success {
            let program="from pathlib import Path;Path('/runtime/home/project/rust-supervisor-effect').write_bytes(b'Rust supervisor released\\n')";
            let argv = ["/usr/bin/python3", "-I", "-B", "-c", program].map(str::to_owned);
            let gate = cell.spawn(&argv, Instant::now() + Duration::from_secs(5))?;
            if effect.exists() {
                return Err("physical effect occurred before Root release".into());
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            cell.release(&gate, deadline)?;
            cell.end_input(&gate, deadline)?;
            loop {
                let chunk = cell.read_process(&gate, 100, deadline)?;
                if chunk.returncode.is_some() && chunk.stdout_eof && chunk.stderr_eof {
                    if chunk.returncode != Some(0) {
                        return Err("released physical effect program failed".into());
                    }
                    cell.retire(&gate, deadline)?;
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("gated physical effect deadline".into());
                }
            }
            let raw = b"Rust supervisor binary stdin\x00\xff\n";
            let argv=["/usr/bin/python3","-I","-B","-c","import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.stderr.write('Rust stderr\\n')"].map(str::to_owned);
            let echoed = cell.capture(&argv, raw, Duration::from_secs(15))?;
            if echoed.returncode != 0 || echoed.stdout != raw || echoed.stderr != b"Rust stderr\n" {
                return Err("Rust supervisor binary I/O differs".into());
            }
        } else {
            let program="from pathlib import Path;import time;Path('/runtime/home/project/rust-supervisor-effect').write_bytes(b'Rust supervisor released\\n');time.sleep(30)";
            let argv = ["/usr/bin/python3", "-I", "-B", "-c", program].map(str::to_owned);
            let thread = if case == crate::NativeCase::Cancel {
                let cancelled = cancelled.clone();
                Some(std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(500));
                    cancelled.store(true, Ordering::Release);
                }))
            } else {
                None
            };
            let attempted = cell.capture(
                &argv,
                b"",
                Duration::from_secs(if case == crate::NativeCase::Timeout {
                    1
                } else {
                    30
                }),
            );
            if let Some(thread) = thread {
                thread.join().map_err(|_| "cancel signal thread failed")?;
            }
            match attempted {
                Err(error)
                    if error.contains(if case == crate::NativeCase::Timeout {
                        "deadline"
                    } else {
                        "cancel"
                    }) => {}
                Err(error) => return Err(format!("unexpected interruption: {error}")),
                Ok(_) => return Err("expected real product interruption did not occur".into()),
            }
            if !cell.cleanup_complete() {
                return Err("interrupted Rust cell did not complete cleanup".into());
            }
        }
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&effect).map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.uid() != 10001
            || metadata.gid() != 10001
            || metadata.nlink() != 1
            || std::fs::read(&effect).map_err(|e| e.to_string())? != b"Rust supervisor released\n"
        {
            return Err("physical idmapped effect differs from expected bytes/ownership".into());
        }
        Ok(())
    })();
    let cleanup = cell.close();
    let report = json!({"schema":"hol-gauntlet-rust-supervisor-vm-proof.v1","case":case.as_str(),
        "supervisor_declaration_sha256":supervisor_digest,"preparation_declaration_sha256":if rust_image_owned {Some(expected_sha256)}else{None},
        "rust_image_lease_owned":rust_image_owned,"status":if result.is_ok() && cleanup.is_ok(){"passed"}else{"failed"},
        "error":result.as_ref().err(),"cleanup_error":cleanup.as_ref().err(),"cell_cleanup_complete":cell.cleanup_complete(),
        "rust_supervisor_owned":true,"native_daemon_started":native_started,"actor":actor,
        "model_requests":0,"execution_eligible":false,"guard_causality_verified":false});
    let error = result.err().or_else(|| cleanup.err());
    Ok(crate::NativeApparatusReport { report, error })
}
