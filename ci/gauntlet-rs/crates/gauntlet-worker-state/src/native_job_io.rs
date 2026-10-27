//! Private native job input custody and global unknown-job admission check.
use crate::native_job_spec::{NativeJobSpec, NATIVE_DEPLOYMENTS};
use crate::{open_root_owned_public_directory, read_bounded_regular, RunReservationJournal};
use gauntlet_cell_rootfs::CellPreparation;
use gauntlet_contracts::{canonicalize, WorkerRequest};
use rustix::fs::{fstat, Dir};
use serde_json::Value;
use std::path::Path;

pub(crate) fn load(
    request: &WorkerRequest,
    generation: &str,
) -> Result<(NativeJobSpec, CellPreparation), String> {
    let digest = request
        .deployment_digest()
        .ok_or("native run deployment pin required")?;
    let directory = open_root_owned_public_directory(Path::new(NATIVE_DEPLOYMENTS))
        .map_err(|e| e.to_string())?;
    let raw = read_bounded_regular(&directory, &format!("{digest}.json"), 8192)
        .map_err(|e| e.to_string())?
        .ok_or("native deployment missing")?;
    let spec = NativeJobSpec::parse(&raw, digest, request, generation)?;
    let root = open_root_owned_public_directory(&spec.job_root()).map_err(|e| e.to_string())?;
    let info = fstat(&root).map_err(|e| e.to_string())?;
    if info.st_gid != 0 || info.st_mode & 0o7777 != 0o700 {
        return Err("private Root native job directory required".into());
    }
    let raw = read_bounded_regular(&root, "preparation.v1.json", 49152)
        .map_err(|e| e.to_string())?
        .ok_or("native preparation missing")?;
    let preparation = spec.preparation(&raw)?;
    Ok((spec, preparation))
}

pub(crate) fn require_no_unknown_jobs(journal: &RunReservationJournal) -> Result<(), String> {
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
        if spec.requires_host_pin() {
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
