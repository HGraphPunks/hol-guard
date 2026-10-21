//! First Rust-owned staging control execution. The host pins the signing key
//! before spawn, and Rust owns the one-use lease, deadline and both cleanup
//! domains. It deliberately writes only an invalid-evidence diagnostic; no
//! conformance package or benchmark admission can result from this path.

use crate::candidate_conformance_readiness::{
    inspect_candidate_staging_readiness_ineligible, CandidateConformanceReadinessPins,
};
use crate::contained_probe::OwnedJobCgroup;
use crate::controller_exec::{exchange_prelaunch_pipe, spawn_root_fd};
use crate::controller_key::{
    pin_controller_key_under_lease, require_pinned_controller_key_under_lease, SealedControllerKey,
};
use crate::controller_run::{cleanup, observe_child, wait_for_child, WaitOutcome};
use crate::{
    fixed_staging_control_plan, open_root_owned_public_directory, read_fixed_interpreter_path_held,
    ActiveLease, BoottimeDeadline, RunReservationJournal, StagingControlPins, StagingRole,
    TerminalOutcome,
};
use gauntlet_contracts::{canonicalize, PrelaunchPrepared, WorkerRequest};
use gauntlet_evidence::verify_controller_tree;
use rustix::fs::{fstat, fsync, openat, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};

const STAGING_STATE: &str = "/var/lib/hol-gauntlet-rust/staging-state";

#[derive(Debug, Clone, Copy)]
pub struct CandidateStagingRunPins<'a> {
    pub build_job_id: &'a str,
    pub run_id: &'a str,
    pub source_sha: &'a str,
    pub version: &'a str,
    pub config_digest: &'a str,
    pub private_manifest_sha256: &'a str,
    pub prefix_tree_sha256: &'a str,
    pub controller_path: &'a str,
    pub controller_tree_sha256: &'a str,
    pub python_path: &'a str,
    pub interpreter_sha256: &'a str,
    pub worker_generation_sha256: &'a str,
    pub role: StagingRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateStagingRunProof {
    run_id: String,
    source_sha: String,
    role: String,
    controller_public_key_hex: String,
    controller_key_pin_sha256: String,
    started_marker_sha256: String,
    terminal_sha256: String,
    exit_code: i32,
    timed_out: bool,
    post_run_controller_custody: bool,
}

impl CandidateStagingRunProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-staging-run-diagnostic.v1",
            "run_id":self.run_id,
            "source_sha":self.source_sha,
            "role":self.role,
            "controller_public_key_hex":self.controller_public_key_hex,
            "controller_key_pin_sha256":self.controller_key_pin_sha256,
            "started_marker_sha256":self.started_marker_sha256,
            "terminal_sha256":self.terminal_sha256,
            "exit_code":self.exit_code,
            "timed_out":self.timed_out,
            "post_run_controller_custody":self.post_run_controller_custody,
            "record_scored":false,
            "conformance_package_created":false,
            "execution_eligible":false,
        })
    }
}

fn staging_log(journal: &RunReservationJournal, run_id: &str) -> Result<File, String> {
    let name = format!("{run_id}.log");
    let descriptor = openat(
        &journal.root,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| format!("one-use staging log unavailable: {error}"))?;
    let metadata = fstat(&descriptor).map_err(|error| error.to_string())?;
    if metadata.st_uid != 0 || metadata.st_nlink != 1 || metadata.st_mode & 0o7777 != 0o600 {
        return Err("staging log lacks Root-only custody".to_owned());
    }
    fsync(&descriptor).map_err(|error| error.to_string())?;
    fsync(&journal.root).map_err(|error| error.to_string())?;
    Ok(File::from(descriptor))
}

fn recheck_prelaunch(
    pins: &CandidateStagingRunPins<'_>,
    interpreter: &crate::HeldInterpreter,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
) -> Result<(), String> {
    lease
        .verify(&journal.root)
        .map_err(|error| error.to_string())?;
    verify_controller_tree(Path::new(pins.controller_path), pins.controller_tree_sha256)
        .map_err(|error| error.to_string())?;
    interpreter
        .assert_unchanged()
        .map_err(|error| error.to_string())
}

/// The `deployment_digest` field of the versioned run frame is the outside
/// provisional config digest in this isolated staging journal. It cannot be
/// read as a final deployment: the namespace is distinct and this function
/// always writes an `invalid-evidence` terminal for later independent scoring.
#[allow(clippy::too_many_arguments)]
pub fn run_fixed_candidate_staging_control_ineligible(
    pins: &CandidateStagingRunPins<'_>,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
) -> Result<CandidateStagingRunProof, String> {
    if !cfg!(all(target_os = "linux", target_arch = "aarch64")) || geteuid().as_raw() != 0 {
        return Err("Linux ARM64 Root staging owner required".to_owned());
    }
    if cancellation.load(Ordering::Acquire)
        || !request.matches_deployment(pins.source_sha, pins.config_digest)
        || request.job_id() != pins.run_id
        || pins.worker_generation_sha256.len() != 64
        || !pins
            .worker_generation_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "fixed staging request or worker generation differs from outside pins".to_owned(),
        );
    }
    let plan = fixed_staging_control_plan(
        &StagingControlPins {
            build_job_id: pins.build_job_id,
            run_id: pins.run_id,
            source_sha: pins.source_sha,
            version: pins.version,
            config_digest: pins.config_digest,
            private_manifest_sha256: pins.private_manifest_sha256,
            controller_path: pins.controller_path,
            python_path: pins.python_path,
            interpreter_sha256: pins.interpreter_sha256,
        },
        pins.role,
    )
    .map_err(|error| error.to_string())?;
    let readiness =
        inspect_candidate_staging_readiness_ineligible(&CandidateConformanceReadinessPins {
            job_id: pins.build_job_id,
            source_sha: pins.source_sha,
            version: pins.version,
            config_digest: pins.config_digest,
            private_manifest_sha256: pins.private_manifest_sha256,
            prefix_tree_sha256: pins.prefix_tree_sha256,
            controller_path: pins.controller_path,
            controller_tree_sha256: pins.controller_tree_sha256,
        })
        .map_err(|error| error.to_string())?;
    if !readiness.contained_completion_present() {
        return Err("candidate lacks contained-output completion capability".to_owned());
    }
    let interpreter = read_fixed_interpreter_path_held(pins.python_path, pins.interpreter_sha256)
        .map_err(|error| error.to_string())?;
    let journal = RunReservationJournal::open_root_owned(Path::new(STAGING_STATE))
        .map_err(|error| error.to_string())?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|error| error.to_string())?;
    recheck_prelaunch(pins, &interpreter, &journal, &lease)?;
    let mut group = OwnedJobCgroup::create(pins.run_id).map_err(|error| error.to_string())?;
    run_with_group(
        pins,
        request,
        deadline,
        cancellation,
        prepared_writer,
        acknowledgement_reader,
        &plan,
        &interpreter,
        &journal,
        &lease,
        &mut group,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_with_group(
    pins: &CandidateStagingRunPins<'_>,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
    plan: &crate::FixedStagingControlPlan,
    interpreter: &crate::HeldInterpreter,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    group: &mut OwnedJobCgroup,
) -> Result<CandidateStagingRunProof, String> {
    let launched = launch_control(
        pins,
        request,
        deadline,
        cancellation,
        prepared_writer,
        acknowledgement_reader,
        plan,
        interpreter,
        journal,
        lease,
        group,
    );
    let (mut child, started, key_pin) = match launched {
        Ok(value) => value,
        Err(error) => {
            cleanup(group, None, pins.run_id, false)
                .map_err(|cleanup| format!("staging prelaunch cleanup uncertain: {cleanup}"))?;
            return Err(error);
        }
    };
    let observed = (|| {
        let process = observe_child(&child, group.path()).map_err(|error| error.to_string())?;
        journal
            .mark_running_under_lease(
                lease,
                request,
                pins.source_sha,
                pins.config_digest,
                pins.worker_generation_sha256,
                &started.sha256,
                process,
                group.path(),
            )
            .map_err(|error| error.to_string())?;
        let outcome = wait_for_child(
            &mut child,
            deadline,
            || {
                lease
                    .verify(&journal.root)
                    .map_err(crate::controller_run::ControllerRunError::Lease)
            },
            || cancellation.load(Ordering::Acquire),
        )
        .map_err(|error| error.to_string())?;
        Ok::<_, String>((process, outcome))
    })();
    cleanup(group, Some(&mut child), pins.run_id, true)
        .map_err(|error| format!("staging child cleanup uncertain: {error}"))?;
    let (process, outcome) = observed?;
    let (exit_code, timed_out) = match outcome {
        WaitOutcome::Exited(status) => (
            status
                .code()
                .or_else(|| status.signal().map(|signal| 128 + signal))
                .ok_or("staging child exit status unavailable")?,
            false,
        ),
        WaitOutcome::TimedOut => (124, true),
    };
    let post_run_controller_custody = recheck_prelaunch(pins, interpreter, journal, lease).is_ok();
    require_pinned_controller_key_under_lease(journal, lease, &started, &key_pin)
        .map_err(|error| error.to_string())?;
    let report = json!({
        "schema":"hol-gauntlet-staging-control-run-report.v1",
        "source_sha":pins.source_sha,
        "build_job_id":pins.build_job_id,
        "run_id":pins.run_id,
        "role":pins.role.as_str(),
        "provisional_config_digest":pins.config_digest,
        "controller_public_key_hex":key_pin.public_key_hex,
        "process":{"pid":process.pid,"start_ticks":process.start_ticks},
        "exit_code":exit_code,
        "timed_out":timed_out,
        "controller_and_product_slice_cleanup_verified":true,
        "post_run_controller_custody":post_run_controller_custody,
        "record_scored":false,
        "execution_eligible":false,
    });
    let raw = canonicalize(report.to_string().as_bytes()).map_err(|error| error.to_string())?;
    let terminal = journal
        .finish_under_lease(
            lease,
            request,
            pins.source_sha,
            pins.config_digest,
            pins.worker_generation_sha256,
            &started.sha256,
            &raw,
            process,
            exit_code,
            TerminalOutcome::InvalidEvidence,
            Some(&key_pin.raw_sha256),
        )
        .map_err(|error| error.to_string())?;
    Ok(CandidateStagingRunProof {
        run_id: pins.run_id.to_owned(),
        source_sha: pins.source_sha.to_owned(),
        role: pins.role.as_str().to_owned(),
        controller_public_key_hex: key_pin.public_key_hex.clone(),
        controller_key_pin_sha256: key_pin.raw_sha256.clone(),
        started_marker_sha256: started.sha256.clone(),
        terminal_sha256: terminal.sha256,
        exit_code,
        timed_out,
        post_run_controller_custody,
    })
}

#[allow(clippy::too_many_arguments)]
fn launch_control(
    pins: &CandidateStagingRunPins<'_>,
    request: &WorkerRequest,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    prepared_writer: &impl AsRawFd,
    acknowledgement_reader: &impl AsRawFd,
    plan: &crate::FixedStagingControlPlan,
    interpreter: &crate::HeldInterpreter,
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    group: &OwnedJobCgroup,
) -> Result<
    (
        std::process::Child,
        crate::StartedMarker,
        crate::controller_key::ControllerKeyPin,
    ),
    String,
> {
    let key = SealedControllerKey::generate().map_err(|error| error.to_string())?;
    let started = journal
        .reserve_keyed_under_lease(
            lease,
            request,
            pins.source_sha,
            pins.config_digest,
            pins.worker_generation_sha256,
            key.public_key_hex(),
        )
        .map_err(|error| error.to_string())?;
    let key_pin = pin_controller_key_under_lease(journal, lease, &started, &key)
        .map_err(|error| error.to_string())?;
    let prepared = PrelaunchPrepared {
        job_id: started.job_id.clone(),
        source_sha: started.source_sha.clone(),
        deployment_digest: started.deployment_digest.clone(),
        worker_generation: started.worker_generation.clone(),
        started_marker_sha256: started.sha256.clone(),
        controller_key_pin_sha256: key_pin.raw_sha256.clone(),
        controller_public_key_hex: key_pin.public_key_hex.clone(),
    };
    let frame = prepared.to_bytes().map_err(|error| error.to_string())?;
    exchange_prelaunch_pipe(
        &frame,
        prepared_writer,
        acknowledgement_reader,
        deadline,
        cancellation,
    )
    .map_err(|error| error.to_string())?;
    if cancellation.load(Ordering::Acquire)
        || deadline
            .remaining()
            .map_err(|error| error.to_string())?
            .is_zero()
    {
        return Err("staging cancelled or expired before spawn".to_owned());
    }
    recheck_prelaunch(pins, interpreter, journal, lease)?;
    require_pinned_controller_key_under_lease(journal, lease, &started, &key_pin)
        .map_err(|error| error.to_string())?;
    let log = staging_log(journal, pins.run_id)?;
    let cwd = open_root_owned_public_directory(Path::new(plan.cwd()))
        .map_err(|error| error.to_string())?;
    let writer = group.writer().map_err(|error| error.to_string())?;
    let mut environment = plan.environment();
    environment.insert(
        "HOL_GAUNTLET_RUST_SIGNING_KEY_FD",
        key.fd().as_raw_fd().to_string(),
    );
    let child = spawn_root_fd(
        interpreter,
        plan.argv(),
        &environment,
        cwd,
        writer,
        Some(key.fd()),
        Stdio::from(log.try_clone().map_err(|error| error.to_string())?),
        Stdio::from(log),
    )
    .map_err(|error| error.to_string())?;
    Ok((child, started, key_pin))
}
