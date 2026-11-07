//! Explicit native successor; historical Python and read-only shadow stay separate.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<(), String> {
    use std::io::{Read, Write};
    gauntlet_worker_state::install_native_worker_signals()?;
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() == 11 && args[1] == "--repair-native-keyed-pre-controller-v1" {
        let prelaunch = gauntlet_contracts::PrelaunchPrepared {
            source_sha: args[2].clone(),
            job_id: args[3].clone(),
            deployment_digest: args[4].clone(),
            worker_generation: args[5].clone(),
            started_marker_sha256: args[6].clone(),
            controller_key_pin_sha256: args[7].clone(),
            controller_public_key_hex: args[8].clone(),
        };
        let pins = gauntlet_worker_state::NativePrelaunchRepairPins {
            prelaunch: &prelaunch,
            preparation_sha256: &args[9],
            repair_generation: &args[10],
        };
        let raw = gauntlet_worker_state::repair_native_host_pinned_pre_controller(&pins)?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 11 && args[1] == "--repair-sdk-created" {
        let raw = gauntlet_worker_state::repair_native_sdk_created(&args)?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 10 && args[1] == "--publish-native-runtime" {
        let pins = gauntlet_worker_state::NativeRuntimePins {
            job_id: &args[2],
            source_sha: &args[3],
            version: &args[4],
            clone_receipt_sha256: &args[5],
            prefix_tree_sha256: &args[6],
            native_sha256: &args[7],
            python_full_version: &args[8],
            generation: &args[9],
        };
        println!("{}", gauntlet_worker_state::publish_native_runtime(&pins)?);
        return Ok(());
    }
    if args.len() == 12 && args[1] == "--clone-native-candidate-prefix" {
        let pins = gauntlet_worker_state::NativeCandidatePrefixPins {
            job_id: &args[2],
            source_sha: &args[3],
            source_archive_sha256: &args[4],
            archive_sha256: &args[5],
            version: &args[6],
            dependency_job_id: &args[7],
            dependency_prefix_receipt_sha256: &args[8],
            dependency_prefix_tree_sha256: &args[9],
            stage_tree_sha256: &args[10],
            generation: &args[11],
        };
        println!(
            "{}",
            gauntlet_worker_state::clone_native_candidate_prefix(&pins)?
        );
        return Ok(());
    }
    if args.len() == 8 && args[1] == "--stage-native-dependency-prefix" {
        let pins = gauntlet_worker_state::DependencyPrefixPins {
            job_id: &args[2],
            intent_sha256: &args[3],
            result_sha256: &args[4],
            archive_sha256: &args[5],
            python_sha256: &args[6],
            stage_generation: &args[7],
        };
        let raw = gauntlet_worker_state::stage_native_dependency_prefix(&pins)?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 7 && args[1] == "--repair-native-dependencies" {
        let raw = gauntlet_worker_state::repair_native_dependencies(
            &args[2], &args[3], &args[4], &args[5], &args[6],
        )?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 5 && args[1] == "--prepare-native-dependencies" {
        use std::os::fd::AsRawFd;
        gauntlet_cell_rootfs::require_outside_root()?;
        gauntlet_worker_state::verify_running_binary(&args[4]).map_err(|e| e.to_string())?;
        let count = args[3]
            .parse::<u64>()
            .map_err(|_| "exact dependency intent byte count required")?;
        if count == 0 || count > gauntlet_contracts::DEPENDENCY_INTENT_LIMIT as u64 {
            return Err("bounded dependency intent required".into());
        }
        let mut raw = Vec::new();
        gauntlet_worker_state::receive_native_dependency_intent(
            std::io::stdin().as_raw_fd(),
            &mut raw,
            count,
            &args[2],
        )?;
        let raw = gauntlet_worker_state::run_native_dependencies(&raw, &args[2], &args[4])?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 11 && args[1] == "--capture-dependency-inputs" {
        let pins = gauntlet_worker_state::NativeDependencyInputPins {
            job: &args[2],
            source: &args[3],
            source_archive: &args[4],
            payload_sha256: &args[5],
            payload_bytes: args[6]
                .parse()
                .map_err(|_| "exact dependency capsule byte count required")?,
            project_sha256: &args[7],
            lock_sha256: &args[8],
            exporter_sha256: &args[9],
            generation: &args[10],
        };
        let raw = gauntlet_worker_state::capture_native_dependency_inputs(&pins)?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 7 && args[1] == "--capture-build-source" {
        let bytes = args[5]
            .parse::<u64>()
            .map_err(|_| "exact source byte count required")?;
        let raw = gauntlet_worker_state::capture_native_build_source(
            &args[2], &args[3], &args[4], bytes, &args[6],
        )?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 3 && args[1] == "--initialize-native" {
        let raw = gauntlet_worker_state::initialize_native_worker(&args[2])?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 8 && args[1] == "--repair-native-pre-controller" {
        let raw = gauntlet_worker_state::repair_native_pre_controller(
            &args[2], &args[3], &args[4], &args[5], &args[6], &args[7],
        )?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 8 && args[1] == "--repair-native" {
        let raw = gauntlet_worker_state::repair_native_worker(
            &args[2], &args[3], &args[4], &args[5], &args[6], &args[7],
        )?;
        println!("{}", String::from_utf8(raw).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if args.len() == 6
        && matches!(
            args[1].as_str(),
            "--native-controller" | "--native-keyed-controller"
        )
    {
        let result = gauntlet_worker_state::execute_native_controller(&args)?;
        println!("{}", result.report);
        return match result.error {
            Some(error) => Err(error),
            None => Ok(()),
        };
    }
    if args.len() == 5 && args[1] == "--native-host-pinned-v1" {
        let raw = gauntlet_worker_state::dispatch_native_worker_host_pinned_pipe(
            &args[2],
            &args[3],
            &args[4],
            &std::io::stdin(),
            &std::io::stdout(),
        )?;
        std::io::stdout()
            .write_all(&raw)
            .and_then(|_| std::io::stdout().write_all(b"\n"))
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    if args.len() == 5 && args[1] == "--read-native-host-pinned-v1" {
        let mut request = Vec::new();
        std::io::stdin()
            .take(1025)
            .read_to_end(&mut request)
            .map_err(|e| e.to_string())?;
        if request.len() > 1024 {
            return Err("native report request exceeds 1024 bytes".into());
        }
        let raw = gauntlet_worker_state::read_native_host_pinned_result(
            &args[2], &args[3], &args[4], &request,
        )?;
        std::io::stdout()
            .write_all(&raw)
            .and_then(|_| std::io::stdout().write_all(b"\n"))
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    if args.len() != 4 {
        return Err("usage: gauntlet-vm-worker OUTSIDE_SOURCE_SHA OUTSIDE_DEPLOYMENT_SHA256 OUTSIDE_WORKER_GENERATION_SHA256".into());
    }
    let mut raw = Vec::new();
    std::io::stdin()
        .take(1025)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 1024 {
        return Err("native worker request exceeds 1024 bytes".into());
    }
    let response =
        gauntlet_worker_state::dispatch_native_worker(&args[1], &args[2], &args[3], &raw)?;
    let mut output = std::io::stdout().lock();
    output
        .write_all(&response)
        .and_then(|_| output.write_all(b"\n"))
        .map_err(|e| e.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<(), String> {
    Err("owned native Linux ARM64 Root worker required".into())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native worker unavailable: {error}");
        std::process::exit(2);
    }
}
