//! Versioned selectors on the existing worker; no free path or command input.
use super::{JobStoragePins, JobStorageProfile};
pub fn dispatch_native_job_storage(args: &[String]) -> Result<Option<Vec<u8>>, String> {
    let selector = args.get(1).map(String::as_str).unwrap_or("");
    let raw = match selector {
        "--abort-native-initialization-v1" | "--read-native-initialization-abort-v1"
            if args.len() == 10 =>
        {
            let pins = JobStoragePins {
                source_sha: &args[2],
                job_id: &args[3],
                worker_generation: &args[4],
                mke2fs_sha256: &args[5],
            };
            super::abort_initialized_native_job_storage(
                &pins,
                &args[6],
                &args[7],
                &args[8],
                &args[9],
                selector == "--abort-native-initialization-v1",
            )?
        }
        "--read-candidate-capture-v1" | "--read-candidate-wheel-stage-v1" if args.len() == 12 => {
            let pins = crate::candidate_capture::NativeCandidateArtifactReadPins {
                job_id: &args[2],
                source_sha: &args[3],
                source_archive_sha256: &args[4],
                archive_sha256: &args[5],
                version: &args[6],
                original_producer_sha256: &args[7],
                host_pin_sha256: &args[8],
                result_sha256: &args[9],
                storage_receipt_sha256: &args[10],
                reader_generation: &args[11],
            };
            let value = if selector == "--read-candidate-capture-v1" {
                crate::candidate_capture::read_native_candidate_capture(&pins)?
            } else {
                crate::candidate_capture::read_native_candidate_wheel_stage(&pins)?
            };
            super::linux::canonical(&value)?
        }
        "--read-native-dependency-prefix" if args.len() == 8 => {
            crate::dependency_prefix::read_native_dependency_prefix(&crate::DependencyPrefixPins {
                job_id: &args[2],
                intent_sha256: &args[3],
                result_sha256: &args[4],
                archive_sha256: &args[5],
                python_sha256: &args[6],
                stage_generation: &args[7],
            })?
        }
        "--read-native-candidate-prefix" if args.len() == 12 => {
            let value = crate::native_candidate_prefix::read_native_candidate_prefix(
                &crate::NativeCandidatePrefixPins {
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
                },
            )?;
            super::linux::canonical(&value)?
        }
        "--read-native-runtime-publication" if args.len() == 10 => {
            let value = crate::native_runtime_publish::read_native_runtime_publication(
                &crate::NativeRuntimePins {
                    job_id: &args[2],
                    source_sha: &args[3],
                    version: &args[4],
                    clone_receipt_sha256: &args[5],
                    prefix_tree_sha256: &args[6],
                    native_sha256: &args[7],
                    python_full_version: &args[8],
                    generation: &args[9],
                },
            )?;
            super::linux::canonical(&value)?
        }
        "--export-source-job-artifact-v1"
        | "--read-source-job-artifact-v1"
        | "--read-source-job-artifact-export-v1"
        | "--ack-source-job-artifact-v1"
        | "--read-source-job-artifact-ack-v1"
            if (args.len() == 11
                && !selector.contains("-ack-")
                && selector != "--ack-source-job-artifact-v1")
                || (args.len() == 13
                    && (selector.contains("-ack-")
                        || selector == "--ack-source-job-artifact-v1")) =>
        {
            let p = super::artifact::Pins {
                source: &args[2],
                job: &args[3],
                original_worker: &args[4],
                kind: &args[5],
                storage_sha: &args[6],
                archive_sha: &args[7],
                result_sha: &args[8],
                host_binding: &args[9],
                exporter: &args[10],
            };
            match selector {
                "--export-source-job-artifact-v1" => super::artifact::export(&p, false)?,
                "--read-source-job-artifact-v1" => super::artifact::export(&p, true)?,
                "--read-source-job-artifact-export-v1" => super::artifact::read_export(&p)?,
                _ => super::artifact::acknowledge(
                    &p,
                    &args[11],
                    &args[12],
                    selector == "--ack-source-job-artifact-v1",
                )?,
            }
        }
        "--initialize-native-job-v2" | "--read-native-job-initialization-v2" if args.len() == 6 => {
            let p = JobStoragePins {
                source_sha: &args[2],
                job_id: &args[3],
                worker_generation: &args[4],
                mke2fs_sha256: &args[5],
            };
            super::initialize_native_job_v2(&p, selector == "--initialize-native-job-v2")?
        }
        "--capture-build-source-v2" | "--read-build-source-capture-v2" if args.len() == 9 => {
            if selector == "--read-build-source-capture-v2" {
                return crate::native_source_capture::read_native_build_source_v2(
                    &args[2],
                    &args[3],
                    &args[4],
                    args[5]
                        .parse()
                        .map_err(|_| "exact Source byte count required")?,
                    &args[6],
                    &args[7],
                    &args[8],
                )
                .map(Some);
            }
            crate::native_source_capture::capture_native_build_source_v2(
                &args[2],
                &args[3],
                &args[4],
                args[5]
                    .parse()
                    .map_err(|_| "exact source byte count required")?,
                &args[6],
                &args[7],
                &args[8],
            )?
        }
        "--capture-dependency-inputs-v2" | "--read-captured-dependency-inputs-v2"
            if args.len() == 12 =>
        {
            let p = crate::NativeDependencyInputPins {
                job: &args[2],
                source: &args[3],
                source_archive: &args[4],
                payload_sha256: &args[5],
                payload_bytes: args[6]
                    .parse()
                    .map_err(|_| "exact capsule byte count required")?,
                project_sha256: &args[7],
                lock_sha256: &args[8],
                exporter_sha256: &args[9],
                generation: &args[10],
            };
            if selector == "--read-captured-dependency-inputs-v2" {
                crate::native_dependency_capture::read_native_dependency_inputs_v2(&p, &args[11])?
            } else {
                crate::native_dependency_capture::capture_native_dependency_inputs_v2(
                    &p, &args[11],
                )?
            }
        }
        "--retire-native-job-storage-v1" | "--read-native-job-storage-retirement-v1"
            if args.len() == 14 =>
        {
            let prelaunch = gauntlet_contracts::PrelaunchPrepared {
                source_sha: args[2].clone(),
                job_id: args[3].clone(),
                deployment_digest: args[4].clone(),
                worker_generation: args[5].clone(),
                started_marker_sha256: args[6].clone(),
                controller_key_pin_sha256: args[7].clone(),
                controller_public_key_hex: args[8].clone(),
            };
            let p = crate::NativePublicExportPins {
                prelaunch: &prelaunch,
                preparation_sha256: &args[9],
                role: &args[10],
                exporter_generation: &args[11],
            };
            super::retire_native_job_storage(
                &p,
                &args[12],
                &args[13],
                selector == "--retire-native-job-storage-v1",
            )?
        }
        "--abort-native-job-storage-v1" | "--read-native-job-storage-abort-v1"
            if args.len() == 8 =>
        {
            let p = JobStoragePins {
                source_sha: &args[2],
                job_id: &args[3],
                worker_generation: &args[4],
                mke2fs_sha256: &args[6],
            };
            let profile = args[5].parse::<JobStorageProfile>()?;
            super::abort_native_job_storage(
                &p,
                profile,
                &args[7],
                selector == "--abort-native-job-storage-v1",
            )?
        }
        "--retire-source-job-storage-v1" | "--read-source-job-storage-retirement-v1"
            if args.len() == 13 =>
        {
            let p = JobStoragePins {
                source_sha: &args[2],
                job_id: &args[3],
                worker_generation: &args[4],
                mke2fs_sha256: &args[6],
            };
            super::retire_source_job_storage(
                &p,
                args[5].parse()?,
                &args[7],
                &args[8],
                &args[9],
                &args[10],
                &args[11],
                &args[12],
                selector == "--retire-source-job-storage-v1",
            )?
        }
        _ => return Ok(None),
    };
    Ok(Some(raw))
}
