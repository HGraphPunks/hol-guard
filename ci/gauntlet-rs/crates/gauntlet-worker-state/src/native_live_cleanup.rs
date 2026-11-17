//! Parent-only cleanup observer. Capture occurs while the controller is gated;
//! its key is never inherited by the controller, product or SDK processes.
use crate::{NativeJobSpec, ProcessIdentity};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustix::fs::{fstat, open, Mode, OFlags};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde_json::{json, Value};
use std::{
    os::fd::{AsRawFd, OwnedFd},
    path::{Path, PathBuf},
};

struct Resource {
    path: PathBuf,
    held: OwnedFd,
    value: Value,
}
pub(crate) struct LiveCleanupObserver {
    task: Value,
    pidfd: OwnedFd,
    _namespace: OwnedFd,
    resources: Vec<Resource>,
}
fn resource(path: PathBuf) -> Result<Resource, String> {
    let held = open(
        &path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let info = fstat(&held).map_err(|e| e.to_string())?;
    if info.st_uid != 0 || info.st_gid != 0 || info.st_mode & 0o022 != 0 {
        return Err("Root cleanup resource custody differs".into());
    }
    let value =
        json!({"kind":"cgroup","name":path,"identity":format!("{}:{}",info.st_dev,info.st_ino)});
    Ok(Resource { path, held, value })
}
impl LiveCleanupObserver {
    pub(crate) fn before(
        job: &NativeJobSpec,
        process: ProcessIdentity,
        cgroup: &str,
    ) -> Result<Self, String> {
        crate::observe_process(process.pid, process.start_ticks, cgroup)
            .map_err(|_| "original live controller identity was not observed before release")?;
        let pid =
            Pid::from_raw(i32::try_from(process.pid).map_err(|_| "live cleanup PID overflow")?)
                .ok_or("live cleanup PID invalid")?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(|e| e.to_string())?;
        let namespace = open(
            format!("/proc/{}/ns/pid", process.pid),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let ns = fstat(&namespace).map_err(|e| e.to_string())?;
        let boot = std::fs::read("/proc/sys/kernel/random/boot_id").map_err(|e| e.to_string())?;
        let boot = std::str::from_utf8(&boot)
            .map_err(|_| "kernel boot identity UTF8")?
            .trim();
        if boot.is_empty() || boot.len() > 64 || ns.st_ino == 0 {
            return Err("actual live cleanup boot/namespace identity missing".into());
        }
        let task = json!({"boot_id":boot,"pid":process.pid,"start_ticks":process.start_ticks,"pid_namespace":ns.st_ino,"cgroup":cgroup});
        let resources = vec![
            resource(Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/')))?,
            resource(
                Path::new("/sys/fs/cgroup").join(format!("holgauntletrust{}.slice", job.job_id)),
            )?,
        ];
        crate::observe_process(process.pid, process.start_ticks, cgroup)
            .map_err(|_| "original live controller identity changed before release")?;
        let root =
            crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
        let record = json!({"schema":"hol-gauntlet-native-live-cleanup-before.v1","source_sha":job.source_sha,"job_id":job.job_id,
            "preparation_sha256":job.preparation_sha256,"tasks":[task],"resources":resources.iter().map(|r|r.value.clone()).collect::<Vec<_>>()});
        let raw = gauntlet_contracts::canonicalize(record.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        crate::feature_files::write(&root, "live-cleanup-before.v1.json", &raw, (0, 0), 0o600)?;
        Ok(Self {
            task,
            pidfd,
            _namespace: namespace,
            resources,
        })
    }
    pub(crate) fn finish(
        &self,
        job: &NativeJobSpec,
        prepared: &crate::native_live_prepare::LivePrepared,
    ) -> Result<Value, String> {
        let mut pid = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pid, 1, 0) } != 1 || pid.revents & libc::POLLIN == 0 {
            return Err("original live controller death not observed".into());
        }
        for resource in &self.resources {
            let held = fstat(&resource.held).map_err(|e| e.to_string())?;
            if resource.value["identity"] != format!("{}:{}", held.st_dev, held.st_ino)
                || !matches!(
                    rustix::fs::statat(
                        rustix::fs::CWD,
                        &resource.path,
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW
                    ),
                    Err(rustix::io::Errno::NOENT)
                )
            {
                return Err("owned live cleanup resource survived or changed".into());
            }
        }
        let live = match &job.execution {
            crate::NativeJobExecution::HostPinnedLive { live, .. } => live,
            _ => return Err("parent live cleanup profile differs".into()),
        };
        let record = json!({"schema":"hol-gauntlet-feature-ai-cleanup.v1","source_sha":job.source_sha,"job_id":job.job_id,
            "preparation_sha256":job.preparation_sha256,"cell_id":live.cell_id,"owned_tasks":[self.task],"before_tasks":[self.task],
            "after_tasks":[],"owned_resources":self.resources.iter().map(|r|r.value.clone()).collect::<Vec<_>>(),"after_resources":[]});
        let raw = gauntlet_contracts::canonicalize(record.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        let key = prepared.cleanup_key()?;
        let envelope =
            json!({"record":record,"signature":STANDARD.encode(key.sign(&raw).as_ref())});
        let raw = gauntlet_contracts::canonicalize(envelope.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        let root =
            crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
        crate::feature_files::write(&root, "live-cleanup.v1.json", &raw, (0, 0), 0o600)?;
        Ok(envelope)
    }
}
