//! Actual bounded-volume fixture helpers; no candidate, SDK or model execution.
use serde_json::{json, Value};
use std::{
    io::Read,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::net::UnixStream,
};

pub(super) struct Runtime {
    pub(super) commands: Option<crate::native_sdk_process::RootCommands>,
    name: String,
    cid: Option<String>,
    pub(super) root: OwnedFd,
    profile: std::path::PathBuf,
    policy_sha256: String,
    policy_attempted: bool,
    create_attempted: bool,
    pub(super) closed: bool,
    logs: Vec<Vec<u8>>,
    temporary: Option<(String, super::super::temporary::Scope)>,
    kernel: Option<Value>,
}
impl Runtime {
    pub(super) fn new(path: &std::path::Path, job: &str) -> Result<Self, String> {
        Self::new_scoped(path, job, None)
    }
    pub(super) fn new_scoped(
        path: &std::path::Path,
        job: &str,
        scope: Option<super::super::temporary::Scope>,
    ) -> Result<Self, String> {
        let podman = std::env::var("GAUNTLET_STORAGE_TEST_PODMAN_SHA")
            .map_err(|_| "outside fixture Podman SHA required")?;
        let parser = std::env::var("GAUNTLET_STORAGE_TEST_APPARMOR_SHA")
            .map_err(|_| "outside fixture AppArmor parser SHA required")?;
        let name = format!("hol-gauntlet-storage-fixture-{job}");
        let policy = crate::native_sdk_public::APPARMOR.replace("HOL_WORKER_PROFILE", &name);
        let root = crate::open_root_owned_public_directory(path).map_err(|e| e.to_string())?;
        let commands = crate::native_sdk_process::RootCommands::new(path, &podman, &parser)?;
        let mut value = Self {
            commands: Some(commands),
            name,
            cid: None,
            root,
            profile: path.join("storage-fixture.apparmor"),
            policy_sha256: super::super::linux::sha(policy.as_bytes()),
            policy_attempted: false,
            create_attempted: false,
            closed: false,
            logs: Vec::new(),
            kernel: None,
            temporary: scope.map(|scope| (job.to_owned(), scope)),
        };
        if !crate::builder_policy::profile_absent(&value.name).map_err(|e| e.to_string())?
            || value
                .call(
                    false,
                    vec!["container".into(), "exists".into(), value.name.clone()],
                )?
                .status
                .code()
                != Some(1)
        {
            return Err("fresh storage fixture runtime identity already exists".into());
        }
        crate::feature_files::write(
            &value.root,
            "storage-fixture.apparmor",
            policy.as_bytes(),
            (0, 0),
            0o400,
        )?;
        value.policy_attempted = true;
        let profile = value.profile.to_string_lossy().into_owned();
        if !value
            .call(true, vec!["--add".into(), profile])?
            .status
            .success()
        {
            return Err("fixture profile load failed".into());
        }
        value.create_attempted = true;
        let mut args = vec![
            "create".into(),
            "--pull=never".into(),
            "--network=none".into(),
            "--read-only".into(),
            "--read-only-tmpfs=false".into(),
            "--user=10001:10001".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            "--memory=64m".into(),
            "--pids-limit=16".into(),
            "--cpus=0.25".into(),
            format!("--name={}", value.name),
            format!("--security-opt=apparmor={}", value.name),
            "--volume".into(),
            format!("{}:/work:rw,rprivate", path.join("workspace").display()),
            "--entrypoint=/usr/bin/sleep".into(),
            crate::NATIVE_SDK_AGENT_IMAGE.into(),
            "600".into(),
        ];
        if let Some(scope) = scope {
            args.splice(1..1, super::super::temporary::create(job, scope)?);
        }
        let output = value.call(false, args)?;
        let cid = String::from_utf8(output.stdout)
            .map_err(|_| "fixture CID UTF8")?
            .trim()
            .to_owned();
        if !output.status.success() || !crate::hex(&cid, 64) {
            return Err("fixture create failed".into());
        }
        value.cid = Some(cid.clone());
        if !value
            .call(false, vec!["start".into(), cid])?
            .status
            .success()
        {
            return Err("fixture start failed".into());
        }
        value.inspect(true)?;
        value.logs = inventory(&crate::feature_files::open_directory(
            &value.root,
            "sdk-processes",
            (0, 0),
        )?)?;
        Ok(value)
    }
    fn call(&mut self, parser: bool, args: Vec<String>) -> Result<std::process::Output, String> {
        self.commands
            .as_mut()
            .ok_or("fixture helpers retired")?
            .run(
                parser,
                &args,
                20,
                &std::sync::atomic::AtomicBool::new(false),
            )
    }
    fn inspect(&mut self, require_running: bool) -> Result<Value, String> {
        let output = self.call(
            false,
            vec![
                "inspect".into(),
                self.cid.as_ref().unwrap_or(&self.name).clone(),
            ],
        )?;
        let values: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
        let v = &values[0];
        let cid = v["Id"]
            .as_str()
            .filter(|v| crate::hex(v, 64))
            .ok_or("fixture actual CID absent")?;
        if !output.status.success()
            || values.as_array().is_none_or(|v| v.len() != 1)
            || self.cid.as_ref().is_some_and(|expected| expected != cid)
            || v["Name"]
                .as_str()
                .map(|name| name.strip_prefix('/').unwrap_or(name))
                != Some(self.name.as_str())
            || v["Image"]
                .as_str()
                .map(|image| image.strip_prefix("sha256:").unwrap_or(image))
                != crate::NATIVE_SDK_AGENT_IMAGE.strip_prefix("sha256:")
            || v["State"]["Running"].as_bool().is_none()
            || (require_running && v["State"]["Running"] != true)
        {
            return Err("original fixture container identity differs".into());
        }
        self.cid = Some(cid.into());
        if self.commands.as_ref().is_some_and(|c| c.is_cleanup()) {
            crate::native_sdk_agent_spec::check_retained_cleanup_task(v, self.kernel.as_ref())?;
        }
        if require_running {
            if let Some((job, scope)) = &self.temporary {
                if !super::super::temporary::observe(job, *scope, v)? {
                    return Err("fixture temporary task was not actually running".into());
                }
            }
        }
        if require_running {
            let pid = v["State"]["Pid"]
                .as_u64()
                .and_then(|p| u32::try_from(p).ok())
                .ok_or("fixture PID absent")?;
            let held = crate::linux_process::HeldProcessRoot::open(pid)?;
            let mut kernel = held.observation()?;
            kernel["cgroup"] = json!(held.cgroup()?);
            self.kernel = Some(kernel);
        }
        Ok(v.clone())
    }
    pub(super) fn close(&mut self) -> Result<Value, String> {
        self.commands
            .as_mut()
            .ok_or("fixture helpers retired")?
            .begin_cleanup();
        let container = (|| -> Result<(), String> {
            if self.create_attempted {
                let id = self.cid.as_ref().unwrap_or(&self.name).clone();
                let exists =
                    self.call(false, vec!["container".into(), "exists".into(), id.clone()])?;
                match exists.status.code() {
                    Some(0) => {
                        self.inspect(false)?;
                        if !self
                            .call(
                                false,
                                vec!["rm".into(), "--force".into(), "--time=0".into(), id.clone()],
                            )?
                            .status
                            .success()
                        {
                            return Err("fixture container removal failed".into());
                        }
                    }
                    Some(1) => {}
                    _ => return Err("fixture container absence uncertain".into()),
                }
                if self
                    .call(false, vec!["container".into(), "exists".into(), id])?
                    .status
                    .code()
                    != Some(1)
                {
                    return Err("fixture container survived".into());
                }
            }
            if let Some(kernel) = &self.kernel {
                let group = std::path::PathBuf::from("/sys/fs/cgroup").join(
                    kernel["cgroup"]
                        .as_str()
                        .ok_or("fixture cgroup absent")?
                        .trim_start_matches('/'),
                );
                let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while group.try_exists().map_err(|e| e.to_string())? {
                    if std::time::Instant::now() >= until {
                        return Err("fixture container cgroup remains".into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
            Ok(())
        })();
        let policy = (|| -> Result<(), String> {
            if container.is_err() {
                return Err("fixture container uncertain; retain AppArmor enforcement".into());
            }
            if self.policy_attempted {
                let bytes = crate::feature_files::required(
                    &self.root,
                    "storage-fixture.apparmor",
                    (0, 0),
                    0o400,
                    1024 * 1024,
                )?;
                if super::super::linux::sha(&bytes) != self.policy_sha256 {
                    return Err("fixture policy identity changed".into());
                }
                if !crate::builder_policy::profile_absent(&self.name).map_err(|e| e.to_string())? {
                    let path = self.profile.to_string_lossy().into_owned();
                    if !self
                        .call(true, vec!["--remove".into(), path])?
                        .status
                        .success()
                    {
                        return Err("fixture policy removal failed".into());
                    }
                }
                if !crate::builder_policy::profile_absent(&self.name).map_err(|e| e.to_string())? {
                    return Err("fixture policy survived".into());
                }
            }
            Ok(())
        })();
        let temporary = if container.is_ok() {
            self.temporary
                .as_ref()
                .map(|(job, scope)| super::super::temporary::close(job, *scope))
                .transpose()
        } else {
            Ok(None)
        };
        container?;
        policy?;
        temporary?;
        let logs = inventory(&crate::feature_files::open_directory(
            &self.root,
            "sdk-processes",
            (0, 0),
        )?)?;
        if !self.logs.is_empty() && logs != self.logs {
            return Err("cleanup attempted a new volume log".into());
        }
        self.closed = true;
        Ok(
            json!({"container_id":self.cid,"container_absent":true,"profile_absent":true,"cleanup_wrote_no_volume_logs":true}),
        )
    }
}
impl Runtime {
    pub(super) fn lose_owner(
        &mut self,
        job: &str,
        p: &super::super::JobStoragePins<'_>,
    ) -> Result<Value, String> {
        use super::super::{lifecycle::JobVolume, owner, JobStoragePins, JobStorageProfile};
        self.commands
            .as_mut()
            .ok_or("fixture helper absent")?
            .begin_cleanup();
        let held = owner::lose_fixture_owner(job)?;
        if JobVolume::read(p, JobStorageProfile::Native).is_ok() {
            return Err("lost owner allowed ordinary launch/read".into());
        }
        JobVolume::read_for_cleanup(p, JobStorageProfile::Native)?;
        let bad = JobStoragePins {
            source_sha: "0000000000000000000000000000000000000000",
            job_id: job,
            worker_generation: p.worker_generation,
            mke2fs_sha256: p.mke2fs_sha256,
        };
        if JobVolume::read_for_cleanup(&bad, JobStorageProfile::Native).is_ok() {
            return Err("cleanup adopted another Source identity".into());
        }
        if unsafe { libc::setns(held.original.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
            return Err("fixture original namespace switch failed".into());
        }
        let refused = JobVolume::read_for_cleanup(p, JobStorageProfile::Native).is_err();
        if unsafe { libc::setns(held.namespace.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
            return Err("fixture held namespace restore failed".into());
        }
        if !refused {
            return Err("cleanup accepted a namespace without original custody".into());
        }
        let value = self.inspect(false)?;
        super::super::temporary::verify_for_cleanup(
            job,
            super::super::temporary::Scope::Mcp,
            Some(&value),
        )?;
        let original = self.cid.clone();
        self.cid = Some("0".repeat(64));
        let rejected = self.close().is_err();
        self.cid = original;
        if !rejected
            || !crate::builder_policy::profile_is_loaded(&self.name).map_err(|e| e.to_string())?
        {
            return Err("failed teardown removed a live container policy".into());
        }
        self.inspect(false)?;
        Ok(
            json!({"original_owner":held.value,"normal_launch_refused":true,"foreign_source_refused":true,
            "foreign_namespace_refused":true,"failed_cleanup_retained_profile":true}),
        )
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        if !self.closed && self.commands.is_some() {
            let _ = self.close();
        }
    }
}
pub(super) fn fill(work: &OwnedFd, inodes: bool) -> Result<serde_json::Value, String> {
    let (mut rx, tx) = UnixStream::pair().map_err(|e| e.to_string())?;
    rx.set_read_timeout(Some(std::time::Duration::from_secs(300)))
        .map_err(|e| e.to_string())?;
    let work = high(work)?;
    let output = high(&tx)?;
    let parent = unsafe { libc::getpid() };
    // SAFETY: the child uses only fixed libc syscalls and stack buffers;
    // no allocator, candidate code, inherited Root data or command exec.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("fixture fork failed".into());
    }
    if pid == 0 {
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent
                || libc::dup2(work.as_raw_fd(), 3) != 3
                || libc::dup2(output.as_raw_fd(), 4) != 4
                || libc::syscall(libc::SYS_close_range, 5u32, u32::MAX, 0) != 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(10001) != 0
                || libc::setuid(10001) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                libc::_exit(125);
            }
            libc::umask(0o077);
            let mut count = 0u64;
            let mut written = 0u64;
            let error;
            if inodes {
                loop {
                    if count > 65536 {
                        libc::_exit(126);
                    }
                    let mut name = [0u8; 18];
                    name[0] = b'i';
                    for i in 0..16 {
                        name[i + 1] =
                            b"0123456789abcdef"[((count >> ((15 - i) * 4)) & 15) as usize];
                    }
                    let fd = libc::openat(
                        3,
                        name.as_ptr().cast(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    );
                    if fd < 0 {
                        error = *libc::__errno_location();
                        break;
                    }
                    libc::close(fd);
                    count += 1;
                }
            } else {
                let fd = libc::openat(
                    3,
                    c"byte-enospc".as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                );
                if fd < 0 {
                    libc::_exit(127);
                }
                let buffer = [0u8; 65536];
                loop {
                    let n = libc::write(fd, buffer.as_ptr().cast(), buffer.len());
                    if n < 0 {
                        error = *libc::__errno_location();
                        break;
                    }
                    if n == 0 || written > 2 * 1024 * 1024 * 1024 {
                        libc::_exit(126);
                    }
                    written += n as u64;
                    if written % (1024 * 1024) == 0 && libc::fsync(fd) != 0 {
                        error = *libc::__errno_location();
                        break;
                    }
                }
                libc::close(fd);
            }
            let mut record = [0u8; 32];
            record[..8].copy_from_slice(&written.to_le_bytes());
            record[8..16].copy_from_slice(&count.to_le_bytes());
            record[16..20].copy_from_slice(&error.to_le_bytes());
            record[20..24].copy_from_slice(&libc::getuid().to_le_bytes());
            record[24..28].copy_from_slice(&libc::getgid().to_le_bytes());
            if libc::write(4, record.as_ptr().cast(), record.len()) != record.len() as isize {
                libc::_exit(124);
            }
            libc::_exit(0);
        }
    }
    drop(output);
    drop(tx);
    drop(work);
    let mut record = [0u8; 32];
    let observed = rx.read_exact(&mut record);
    if observed.is_err() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
        || !libc::WIFEXITED(status)
        || libc::WEXITSTATUS(status) != 0
    {
        return Err("owned storage fixture child failed".into());
    }
    observed.map_err(|e| e.to_string())?;
    Ok(
        serde_json::json!({"written_bytes":u64::from_le_bytes(record[..8].try_into().unwrap()),"created_files":u64::from_le_bytes(record[8..16].try_into().unwrap()),
        "errno":i32::from_le_bytes(record[16..20].try_into().unwrap()),"uid":u32::from_le_bytes(record[20..24].try_into().unwrap()),"gid":u32::from_le_bytes(record[24..28].try_into().unwrap())}),
    )
}
pub(super) use super::super::admission::{
    test_capacity as capacity, test_file_name as file_name, test_high as high,
    test_inventory as inventory,
};
