//! Export only an outside-bound completed Native job after fresh quiescence.
//! A public archive supplies bytes to the independent judge, never admission.
use crate::native_public_archive::{self as archive, CaptureKind, PublicFiles};
use crate::{NativeJobSpec, RunReservationJournal, RunningMarker};
use gauntlet_contracts::PrelaunchPrepared;
use gauntlet_evidence::{verify_native_control_envelope, NativeControlReportPins};
use rustix::fs::{fstat, statat, AtFlags};
use serde_json::{json, Value};
use std::{os::fd::OwnedFd, path::Path};

pub struct NativePublicExportPins<'a> {
    pub prelaunch: &'a PrelaunchPrepared,
    pub preparation_sha256: &'a str,
    pub role: &'a str,
    pub exporter_generation: &'a str,
}

pub(crate) fn capture_sdk_public(
    files: &mut PublicFiles,
    job: &OwnedFd,
    owner: (u32, u32),
) -> Result<(), String> {
    for name in [
        "private_cell_sdk_conformance.ts",
        "developer_omp_episode.ts",
        "builtin_guard_bridge.ts",
        "contained_exec_relay.py",
        "same_uid_peer_probe.py",
        "episode.json",
        "bunfig.toml",
        "startup-noop.mjs",
        "service_relay.py",
        "same_uid_mcp_peer_probe.py",
    ] {
        files.capture(
            job,
            &format!("sdk-public/{name}"),
            &format!("combined/sdk-public/{name}"),
            owner,
            0o444,
        )?;
    }
    Ok(())
}

fn collect(
    journal: &OwnedFd,
    job_id: &str,
    job: &OwnedFd,
    declarations: &OwnedFd,
    deployment: &str,
) -> Result<PublicFiles, String> {
    let mut files = PublicFiles::default();
    capture_sdk_public(&mut files, job, (0, 0))?;
    if crate::native_job_storage::native::verify(job_id)? {
        let storage = crate::open_root_owned_public_directory(
            &Path::new(crate::native_job_storage::lifecycle::BASE).join(job_id),
        )
        .map_err(|e| e.to_string())?;
        files.capture(
            &storage,
            "storage.json",
            "combined/storage/receipt.v1.json",
            (0, 0),
            0o600,
        )?;
        for scope in ["sdk", "mcp"] {
            for leaf in [
                "intent", "complete", "inside", "closed", "tmp", "var-tmp", "run", "shm",
            ] {
                files.capture(
                    &storage,
                    &format!("temporary/{scope}/{leaf}.json"),
                    &format!("combined/storage/temporary/{scope}/{leaf}.json"),
                    (0, 0),
                    0o600,
                )?;
            }
        }
        let initialized = crate::open_root_owned_public_directory(Path::new(
            "/var/lib/hol-gauntlet-rust/native-initialization",
        ))
        .map_err(|e| e.to_string())?;
        files.capture(
            &initialized,
            &format!("{job_id}.job.json"),
            "combined/storage/initialization.v2.json",
            (0, 0),
            0o600,
        )?;
        files.capture(
            &initialized,
            &format!("{job_id}.preparation.json"),
            "combined/storage/preparation.v2.json",
            (0, 0),
            0o600,
        )?;
        for suffix in ["native.stdout", "native.stderr"] {
            files.capture(
                job,
                &format!("{job_id}.{suffix}"),
                &format!("combined/worker/{suffix}"),
                (0, 0),
                0o600,
            )?;
        }
    }
    files.capture_report(journal, job_id, (0, 0))?;
    if !files.capture(
        job,
        "preparation.v1.json",
        "combined/preparation.v1.json",
        (0, 0),
        0o600,
    )? || !files.capture(
        declarations,
        &format!("{deployment}.json"),
        "combined/declaration.json",
        (0, 0),
        0o600,
    )? {
        return Err("complete Native preparation/declaration required for public export".into());
    }
    for name in [
        "native-rootfs.v1.json",
        "native-supervisor.v1.json",
        "native-wire.v1.json",
        "system.json",
        "runtime.json",
        "task-mounts.json",
        "cell-artifact-manifest.json",
    ] {
        files.capture(
            job,
            &format!("cell/{name}"),
            &format!("combined/cell/{name}"),
            (0, 0),
            0o444,
        )?;
    }
    for (relative, member) in [
        ("live/evidence.v1.json", "combined/live/evidence.v1.json"),
        ("live/context.v1.json", "combined/live/context.v1.json"),
        ("live-cleanup.v1.json", "combined/live/cleanup.v1.json"),
        (
            "live-private/prepared.json",
            "combined/live/prepared.v2.json",
        ),
    ] {
        files.capture(job, relative, member, (0, 0), 0o600)?;
    }
    for name in [
        "native-supervisor-events.v1.jsonl",
        "native-image-events.v1.jsonl",
        "native-process-events.v1.jsonl",
        "native-stdio-events.v1.jsonl",
        "native-pipe-events.v1.jsonl",
    ] {
        files.capture(
            job,
            &format!("cell/{name}"),
            &format!("combined/cell/{name}"),
            (0, 0),
            0o600,
        )?;
    }
    for (directory, kind) in [
        ("cell", CaptureKind::Cell),
        ("sdk-processes", CaptureKind::Process),
        ("mcp-processes", CaptureKind::Mcp),
    ] {
        files.capture_flat(job, directory, kind, (0, 0))?;
    }
    for relative in [
        "workspace/pytest.ini",
        "workspace/tests/test_control.py",
        "workspace/native-contained.txt",
        "workspace/node-runtime-control.json",
        "workspace/negative_tests/test_trap.py",
        "workspace/boundary-negatives.json",
        "workspace/forbidden-command-target/synthetic-marker.txt",
    ] {
        files.capture(
            job,
            relative,
            &format!("combined/{relative}"),
            (10001, 10001),
            0o600,
        )?;
    }
    for name in [
        "service_relay.py",
        "native_mcp_proxy_v1.py",
        "native_mcp_identity_v1.py",
        "mcp.json",
        "prefix.json",
        "live-prompt.json",
    ] {
        files.capture(
            job,
            &format!("mcp-public/{name}"),
            &format!("combined/mcp-public/{name}"),
            (0, 0),
            0o444,
        )?;
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        if !matches!(
            statat(
                job,
                format!("mcp-world.db{suffix}"),
                AtFlags::SYMLINK_NOFOLLOW
            ),
            Err(rustix::io::Errno::NOENT)
        ) {
            return Err("Native provider database has an active or uncertain sidecar".into());
        }
    }
    for name in [
        "mcp-world.db",
        "physical-control-readback.json",
        "physical-lifecycle-absence.json",
    ] {
        files.capture(job, name, &format!("combined/{name}"), (0, 0), 0o600)?;
    }
    files.capture(
        job,
        "outside-kernel.json",
        "proof/outside-kernel.json",
        (0, 0),
        0o600,
    )?;
    for (relative, member, owner) in [
        ("controller-canary.txt", "combined/controller-canary.txt", 0),
        (
            "sdk-agent/agent-canary.txt",
            "combined/sdk-agent-canary.txt",
            10001,
        ),
        (
            "cell/state/guard/native-boundary-canary.txt",
            "combined/product-guard-canary.txt",
            10004,
        ),
    ] {
        files.capture(job, relative, member, (owner, owner), 0o600)?;
    }
    Ok(files)
}

pub(crate) fn quiescent(
    spec: &NativeJobSpec,
    preparation: &gauntlet_cell_rootfs::CellPreparation,
    running: &RunningMarker,
) -> Result<(), String> {
    crate::native_repair::controller_absent(running)?;
    crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
    gauntlet_cell_rootfs::require_image_lease_absent(
        &preparation.image_id,
        &preparation.podman_sha256,
    )?;
    crate::native_sdk_quiescence::require_sdk_quiescence(spec, preparation)?;
    crate::native_mcp_quiescence::require_mcp_quiescence(spec, preparation)
}

/// Raw USTAR is returned only after complete assembly and a second identical
/// descriptor-based read. Repeated exports are read-only; a job can never rerun.
pub fn export_native_host_pinned_public(
    pins: &NativePublicExportPins<'_>,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(pins.exporter_generation).map_err(|e| e.to_string())?;
    pins.prelaunch.to_bytes().map_err(|e| e.to_string())?;
    if !crate::hex(pins.preparation_sha256, 64) {
        return Err("outside Native public preparation pin required".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let p = pins.prelaunch;
    let (original, spec) = crate::native_keyed_startup_repair::retained(
        &journal,
        &p.source_sha,
        &p.job_id,
        &p.deployment_digest,
        &p.worker_generation,
    )?;
    if original != *p
        || spec.preparation_sha256 != pins.preparation_sha256
        || spec.case() != pins.role
    {
        return Err("Native public export differs from exact original Host pins".into());
    }
    let request = gauntlet_contracts::WorkerRequest::parse(
        json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
        "source_sha":p.source_sha,"job_id":p.job_id,"deployment_digest":p.deployment_digest})
        .to_string()
        .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let (_, preparation) = crate::native_job_io::load(&request, &p.worker_generation)?;
    let running = journal
        .running_marker(
            &p.job_id,
            &p.source_sha,
            &p.deployment_digest,
            &p.worker_generation,
        )
        .map_err(|e| e.to_string())?
        .ok_or("Native public export lacks original running marker")?;
    let completion = crate::native_completion::read_completion(
        &journal,
        &p.source_sha,
        &p.job_id,
        &p.deployment_digest,
        &p.worker_generation,
    )?;
    let frame: Value = serde_json::from_slice(&completion).map_err(|e| e.to_string())?;
    let report = &frame["report"];
    let envelope = report["controller_envelope_utf8"]
        .as_str()
        .ok_or("Native public export requires complete signed report")?;
    let authenticated = verify_native_control_envelope(
        envelope.as_bytes(),
        &NativeControlReportPins {
            prelaunch: p.clone(),
            preparation_sha256: pins.preparation_sha256.into(),
            role: pins.role.into(),
        },
    )
    .map_err(|e| e.to_string())?;
    if authenticated.report() != &report["controller_report"]
        || authenticated.report()["controller_identity"]
            != json!({"pid":running.process.pid,"start_ticks":running.process.start_ticks})
        || report["controller"] != authenticated.report()["controller_identity"]
        || report["preparation_sha256"] != pins.preparation_sha256
    {
        return Err("Native public report differs from authenticated original controller".into());
    }
    let stable = || {
        lease.verify(&journal.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
        if crate::native_worker::cancellation_requested() {
            return Err("Native public export cancelled before completion".into());
        }
        let (again, again_spec) = crate::native_keyed_startup_repair::retained(
            &journal,
            &p.source_sha,
            &p.job_id,
            &p.deployment_digest,
            &p.worker_generation,
        )?;
        if again != *p
            || again_spec.preparation_sha256 != pins.preparation_sha256
            || again_spec.case() != pins.role
            || crate::native_completion::read_completion(
                &journal,
                &p.source_sha,
                &p.job_id,
                &p.deployment_digest,
                &p.worker_generation,
            )? != completion
        {
            return Err("Native public completion or original pins changed".into());
        }
        quiescent(&spec, &preparation, &running)
    };
    stable()?;
    let job =
        crate::open_root_owned_public_directory(&spec.job_root()).map_err(|e| e.to_string())?;
    let declarations = crate::open_root_owned_public_directory(Path::new(
        crate::native_job_spec::NATIVE_DEPLOYMENTS,
    ))
    .map_err(|e| e.to_string())?;
    let job_stat = fstat(&job).map_err(|e| e.to_string())?;
    let declarations_stat = fstat(&declarations).map_err(|e| e.to_string())?;
    let directories_stable = || {
        for (held, path, expected) in [
            (&job, spec.job_root(), &job_stat),
            (
                &declarations,
                Path::new(crate::native_job_spec::NATIVE_DEPLOYMENTS).to_path_buf(),
                &declarations_stat,
            ),
        ] {
            let visible =
                crate::open_root_owned_public_directory(&path).map_err(|e| e.to_string())?;
            if !crate::dependency_prefix_meta::same(
                expected,
                &fstat(held).map_err(|e| e.to_string())?,
            ) || !crate::dependency_prefix_meta::same(
                expected,
                &fstat(&visible).map_err(|e| e.to_string())?,
            ) {
                return Err("Native public export directory was replaced or changed".into());
            }
        }
        Ok::<(), String>(())
    };
    let files = collect(
        &journal.root,
        &p.job_id,
        &job,
        &declarations,
        &p.deployment_digest,
    )?;
    if archive::sha(
        files
            .files
            .get("combined/declaration.json")
            .ok_or("Native public declaration absent")?,
    ) != p.deployment_digest
        || archive::sha(
            files
                .files
                .get("combined/preparation.v1.json")
                .ok_or("Native public preparation absent")?,
        ) != pins.preparation_sha256
        || archive::sha(
            files
                .files
                .get("combined/worker/report.json")
                .ok_or("Native public report absent")?,
        ) != frame["terminal"]["report_sha256"]
    {
        return Err("Native public archive inputs differ from exact completed bytes".into());
    }
    stable()?;
    directories_stable()?;
    if collect(
        &journal.root,
        &p.job_id,
        &job,
        &declarations,
        &p.deployment_digest,
    )? != files
    {
        return Err("Native public files changed during assembly".into());
    }
    directories_stable()?;
    stable()?;
    crate::verify_running_binary(pins.exporter_generation).map_err(|e| e.to_string())?;
    let binding = json!({"source_sha":p.source_sha,"job_id":p.job_id,"deployment_digest":p.deployment_digest,
        "worker_generation":p.worker_generation,"preparation_sha256":pins.preparation_sha256,"control_role":pins.role,
        "terminal_sha256":frame["terminal_sha256"],"report_sha256":frame["terminal"]["report_sha256"]});
    let raw = if matches!(
        spec.execution,
        crate::NativeJobExecution::HostPinnedLive { .. }
    ) {
        for name in [
            "combined/live/evidence.v1.json",
            "combined/live/context.v1.json",
            "combined/live/cleanup.v1.json",
            "combined/live/prepared.v2.json",
        ] {
            if !files.files.contains_key(name) {
                return Err("complete retained live artifacts required for export".into());
            }
        }
        archive::encode_live(
            files,
            binding,
            frame["model_requests"]
                .as_u64()
                .ok_or("actual live request count required for export")?,
        )
    } else {
        archive::encode(files, binding)
    }?;
    crate::native_job_storage::native::record_export(pins, &raw, &frame)?;
    Ok(raw)
}
