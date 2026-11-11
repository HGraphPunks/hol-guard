//! Private native job input custody and global unknown-job admission check.
use crate::native_job_spec::{NativeJobSpec, NATIVE_DEPLOYMENTS};
use crate::{open_root_owned_public_directory, read_bounded_regular, RunReservationJournal};
use gauntlet_cell_rootfs::CellPreparation;
use gauntlet_contracts::{canonicalize, WorkerRequest};
use rustix::fs::{fstat, Dir};
use serde_json::Value;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;
use std::time::Duration;

/// Admission only reads retained state. End this guard before generating a key
/// or reserving a job: its watchdog may exit the entire worker, closing leases,
/// when a nested historical verifier cannot respond to cancellation itself.
pub(crate) struct NativeAdmissionGuard {
    stop: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
    deadline: crate::BoottimeDeadline,
}
impl NativeAdmissionGuard {
    pub(crate) fn start() -> Result<Self, String> {
        // Original retained jobs are authenticated before any new reservation.
        // Keep this bounded while allowing a full history read on the 2-CPU VM.
        // The Host reserves another 30 seconds for the prepared transport.
        Self::start_seconds(180)
    }
    fn start_seconds(seconds: u64) -> Result<Self, String> {
        let deadline = crate::BoottimeDeadline::start(seconds).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let finished = stop.clone();
        let watcher = std::thread::Builder::new()
            .name("native-admission".into())
            .spawn(move || {
                while !finished.load(Ordering::Acquire) {
                    if crate::native_worker::cancellation_requested()
                        || deadline.remaining().map_or(true, |left| left.is_zero())
                    {
                        eprintln!("native admission cancelled or expired before reservation");
                        std::process::exit(2);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            stop,
            watcher: Some(watcher),
            deadline,
        })
    }
    fn join(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::Release);
        if let Some(watcher) = self.watcher.take() {
            watcher
                .join()
                .map_err(|_| "native admission watchdog failed")?;
        }
        Ok(())
    }
    pub(crate) fn finish(mut self) -> Result<(), String> {
        self.join()?;
        if crate::native_worker::cancellation_requested()
            || self
                .deadline
                .remaining()
                .map_err(|e| e.to_string())?
                .is_zero()
        {
            return Err("native admission cancelled or expired before reservation".into());
        }
        Ok(())
    }
}
impl Drop for NativeAdmissionGuard {
    fn drop(&mut self) {
        let _ = self.join();
    }
}

pub(crate) fn load(
    request: &WorkerRequest,
    generation: &str,
) -> Result<(NativeJobSpec, CellPreparation), String> {
    let digest = request
        .deployment_digest()
        .ok_or("native run deployment pin required")?;
    let directory = open_root_owned_public_directory(Path::new(NATIVE_DEPLOYMENTS))
        .map_err(|e| e.to_string())?;
    let declaration_raw = read_bounded_regular(&directory, &format!("{digest}.json"), 8192)
        .map_err(|e| e.to_string())?
        .ok_or("native deployment missing")?;
    let spec = NativeJobSpec::parse(&declaration_raw, digest, request, generation)?;
    crate::native_job_storage::owner::enter_pinned(
        &spec.source_sha,
        &spec.job_id,
        &spec.worker_generation,
    )?;
    let root = open_root_owned_public_directory(&spec.job_root()).map_err(|e| e.to_string())?;
    let info = fstat(&root).map_err(|e| e.to_string())?;
    if info.st_gid != 0 || info.st_mode & 0o7777 != 0o700 {
        return Err("private Root native job directory required".into());
    }
    let raw = read_bounded_regular(&root, "preparation.v1.json", 49152)
        .map_err(|e| e.to_string())?
        .ok_or("native preparation missing")?;
    let preparation = spec.preparation(&raw)?;
    crate::native_job_prepare::verify_staged_job(&spec, digest, &declaration_raw, &raw)?;
    Ok((spec, preparation))
}

pub(crate) fn require_no_unknown_jobs(journal: &RunReservationJournal) -> Result<(), String> {
    let _namespace_scope = crate::native_job_storage::owner::scope()?;
    crate::feature_state::require_idle()?;
    let mut jobs = std::collections::BTreeSet::new();
    let mut started = std::collections::BTreeMap::new();
    let mut count = 0usize;
    for entry in Dir::read_from(&journal.root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "native state filename UTF-8")?;
        if matches!(name, "." | ".." | "active.lock") {
            continue;
        }
        count += 1;
        if count > 4096 {
            return Err("native state inventory bound exceeded".into());
        }
        let (job, suffix) = name
            .split_once('.')
            .filter(|(id, _)| crate::hex(id, 16))
            .ok_or("unrecognized worker state entry")?;
        if !matches!(
            suffix,
            "started.json"
                | "running.json"
                | "terminal.json"
                | "report.json"
                | "controller-key.json"
                | "native.stdout"
                | "native.stderr"
                | "native-repair.json"
                | "native-startup-repair.json"
                | "native-keyed-startup-repair.json"
        ) {
            return Err("unrecognized worker sidecar blocks native dispatch".into());
        }
        jobs.insert(job.to_owned());
        if suffix == "started.json" {
            let raw = read_bounded_regular(&journal.root, name, 1024)
                .map_err(|e| e.to_string())?
                .ok_or("started marker disappeared")?;
            let raw = canonicalize(&raw).map_err(|_| "ambiguous started marker")?;
            let value: Value = serde_json::from_slice(&raw).map_err(|_| "started marker JSON")?;
            let text = |key: &str| {
                value[key]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or("started marker identity missing")
            };
            started.insert(
                job.to_owned(),
                (
                    text("source_sha")?,
                    text("deployment_digest")?,
                    text("worker_generation")?,
                ),
            );
        }
    }
    for job in jobs {
        let (source, deployment, generation) = started
            .get(&job)
            .ok_or("orphan worker sidecar blocks new work")?;
        let reserved = journal
            .started(&job, source, deployment, generation)
            .map_err(|e| e.to_string())?
            .is_some();
        let terminal = journal
            .terminal(&job, source, deployment, generation)
            .map_err(|e| e.to_string())?
            .is_some();
        let repair =
            crate::native_repair::verified_receipt(journal, source, &job, deployment, generation)?
                .is_some();
        let startup = crate::native_startup_repair::verified_receipt(
            journal, source, &job, deployment, generation,
        )?
        .is_some();
        let keyed_startup = crate::native_keyed_startup_repair::verified_receipt(
            journal, source, &job, deployment, generation,
        )?
        .is_some();
        if !reserved
            || [terminal, repair, startup, keyed_startup]
                .into_iter()
                .filter(|value| *value)
                .count()
                != 1
        {
            return Err("active or unknown prior job blocks new work".into());
        }
        crate::require_rust_job_slice_absent(&job).map_err(|e| e.to_string())?;
    }
    crate::require_no_product_cell_units().map_err(|e| e.to_string())
}

pub(crate) fn own_identity(
    child: &std::process::Child,
    spec: &NativeJobSpec,
    deployment: &str,
    cgroup: &str,
) -> Result<crate::ProcessIdentity, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let process = crate::controller_run::observe_child(child, cgroup).map_err(|e| e.to_string())?;
    let root = format!("/proc/{}", child.id());
    let read = |name: &str, maximum: u64| -> Result<Vec<u8>, String> {
        let mut raw = Vec::new();
        std::fs::File::open(format!("{root}/{name}"))
            .map_err(|e| e.to_string())?
            .take(maximum + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() as u64 > maximum {
            return Err("native controller kernel file bound".into());
        }
        Ok(raw)
    };
    let executable = read("exe", 128 * 1024 * 1024)?;
    let argv = [
        "gauntlet-vm-worker",
        if matches!(
            spec.execution,
            crate::NativeJobExecution::HostPinnedLive { .. }
        ) {
            "--native-live-keyed-controller"
        } else if spec.requires_host_pin() {
            "--native-keyed-controller"
        } else {
            "--native-controller"
        },
        &spec.source_sha,
        &spec.job_id,
        deployment,
        &spec.worker_generation,
    ];
    let wanted = argv
        .into_iter()
        .flat_map(|s| s.as_bytes().iter().copied().chain([0]))
        .collect::<Vec<_>>();
    if format!("{:x}", Sha256::digest(&executable)) != spec.worker_generation
        || read("cmdline", 4096)? != wanted
    {
        return Err("actual native controller executable/argv differs".into());
    }
    let status =
        String::from_utf8(read("status", 65536)?).map_err(|_| "native controller status UTF-8")?;
    for (field, wanted) in [
        ("Uid:", vec!["0"; 4]),
        ("Gid:", vec!["0"; 4]),
        ("Groups:", vec![]),
        ("NoNewPrivs:", vec!["1"]),
    ] {
        if status
            .lines()
            .find_map(|row| row.strip_prefix(field))
            .map(|s| s.split_ascii_whitespace().collect::<Vec<_>>())
            != Some(wanted)
        {
            return Err("native controller Root identity or gate changed".into());
        }
    }
    let second = crate::controller_run::observe_child(child, cgroup).map_err(|e| e.to_string())?;
    if process != second {
        return Err("native controller changed across gate samples".into());
    }
    Ok(process)
}

#[cfg(test)]
mod tests {
    use super::*;
    const CHILD: &str = "HOL_GAUNTLET_ADMISSION_GUARD_CHILD";
    const ENTERED: &str = "admission-entered";
    const RESERVED: &str = "reservation-boundary-reached";

    #[test]
    fn admission_watchdog_child() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        crate::install_native_worker_signals().unwrap();
        let guard = NativeAdmissionGuard::start_seconds(1).unwrap();
        println!("{ENTERED}");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        match mode.as_str() {
            "blocked" => std::thread::sleep(Duration::from_secs(4)),
            "cancelled" => {
                assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
                std::thread::sleep(Duration::from_secs(4));
            }
            "finished" => {
                guard.finish().unwrap();
                std::thread::sleep(Duration::from_millis(1100));
                println!("{RESERVED}");
            }
            "early-error" => {
                drop(guard);
                std::thread::sleep(Duration::from_millis(1100));
            }
            _ => panic!("unknown owned admission test mode"),
        }
    }

    #[test]
    fn blocked_or_cancelled_admission_exits_before_reservation_and_completed_guards_join() {
        for mode in ["blocked", "cancelled", "finished", "early-error"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "native_job_io::tests::admission_watchdog_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_clear()
                .env(CHILD, mode)
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stdout.contains(ENTERED), "{mode}: {stderr}");
            assert_eq!(stdout.contains(RESERVED), mode == "finished", "{mode}");
            let refused = matches!(mode, "blocked" | "cancelled");
            assert_eq!(
                output.status.code(),
                Some(if refused { 2 } else { 0 }),
                "{mode}: {stderr}"
            );
            assert_eq!(
                stderr.contains("native admission cancelled or expired before reservation"),
                refused,
                "{mode}"
            );
        }
    }
}
