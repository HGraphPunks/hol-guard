//! Root ownership of one fixed, unprivileged SDK agent container. Create and
//! start are separate so the CID is retained before any image code executes.
use crate::native_sdk_agent_spec::{check_inspection, check_mcp_inspection};
use crate::native_sdk_process::{RootChild, RootCommands};
use crate::native_sdk_public::{write_file, NativeSdkPublic, APPARMOR};
use crate::{
    NativeSdkBoundary, NativeSdkSockets, SdkWirePeerPin, VerifiedNativeSdkAssets,
    NATIVE_SDK_AGENT_IMAGE,
};
use gauntlet_cell_rootfs::CellPreparation;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

pub(crate) struct NativeSdkAgent {
    job: String,
    nonce: String,
    name: String,
    root: PathBuf,
    commands: RootCommands,
    mounts: BTreeMap<String, (String, bool)>,
    profile: PathBuf,
    profile_sha256: String,
    policy_attempted: bool,
    create_attempted: bool,
    cid: Option<String>,
    cgroup: Option<PathBuf>,
    inspection: Option<Value>,
    kernel: Option<Value>,
    closed: bool,
    mcp: bool,
}
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as u64 > limit {
        return Err("SDK kernel read bound".into());
    }
    Ok(raw)
}
impl NativeSdkAgent {
    pub(crate) fn prepare(
        job: &str,
        spec: &CellPreparation,
        assets: &VerifiedNativeSdkAssets,
        sockets: &NativeSdkSockets,
        public: &NativeSdkPublic,
    ) -> Result<Self, String> {
        if !crate::hex(job, 16) {
            return Err("fixed SDK job required".into());
        }
        let root = PathBuf::from(crate::native_job_spec::NATIVE_JOBS).join(job);
        let parser = spec
            .host_helper_sha256("/usr/sbin/apparmor_parser")
            .ok_or("SDK parser pin required")?;
        let commands = RootCommands::new(&root, &spec.podman_sha256, parser)?;
        let mut random = [0; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| "SDK Root nonce unavailable")?;
        let nonce = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let name = format!("hol-gauntlet-sdk-{job}-{nonce}");
        let mut mounts = BTreeMap::new();
        for (source, target, rw) in [
            (root.join("sdk-home"), "/runtime/home", true),
            (root.join("workspace"), "/runtime/home/project", true),
            (root.join("sdk-agent"), "/runtime/agent", true),
            (assets.sdk_directory(), "/sdk/node_modules", false),
            (assets.bun_path(), "/runtime/bun", false),
            (public.path().to_owned(), "/runtime/public", false),
            (sockets.gate_directory(), "/runtime/sdk-gate", false),
            (sockets.hook_directory(), "/runtime/guard-hook", false),
        ] {
            mounts.insert(target.into(), (source.to_string_lossy().into_owned(), rw));
        }
        let policy = APPARMOR.replace("HOL_WORKER_PROFILE", &name);
        let profile = root.join("sdk-agent.apparmor");
        let agent = Self {
            job: job.into(),
            nonce,
            name,
            root,
            commands,
            mounts,
            profile,
            profile_sha256: format!("{:x}", Sha256::digest(policy.as_bytes())),
            policy_attempted: false,
            create_attempted: false,
            cid: None,
            cgroup: None,
            inspection: None,
            kernel: None,
            closed: false,
            mcp: false,
        };
        Ok(agent)
    }
    pub(crate) fn prepare_mcp(
        job: &str,
        spec: &CellPreparation,
        assets: &VerifiedNativeSdkAssets,
        sockets: &NativeSdkSockets,
        public: &NativeSdkPublic,
        mcp: &mut crate::NativeMcpSockets,
    ) -> Result<Self, String> {
        mcp.verify_for_job(job)?;
        let mut agent = Self::prepare(job, spec, assets, sockets, public)?;
        agent.mcp = true;
        agent.mounts.insert(
            "/runtime/resources".into(),
            (
                mcp.resource_directory().to_string_lossy().into_owned(),
                false,
            ),
        );
        Ok(agent)
    }
    fn check(&self, value: &Value, running: bool) -> Result<(String, u32), String> {
        if self.mcp {
            check_mcp_inspection(
                value,
                &self.name,
                &self.job,
                &self.nonce,
                &self.mounts,
                running,
            )
        } else {
            check_inspection(
                value,
                &self.name,
                &self.job,
                &self.nonce,
                &self.mounts,
                running,
            )
        }
    }
    pub(crate) fn launch(
        &mut self,
        assets: &VerifiedNativeSdkAssets,
        public: &NativeSdkPublic,
        actor: &Value,
        cancel: &AtomicBool,
    ) -> Result<NativeSdkBoundary, String> {
        let agent = self;
        let job = agent.job.clone();
        let policy = APPARMOR.replace("HOL_WORKER_PROFILE", &agent.name);
        let launched = (|| {
            public.verify()?;
            assets.recheck_custody()?;
            if !crate::builder_policy::profile_absent(&agent.name).map_err(|e| e.to_string())? {
                return Err("fresh SDK profile already exists".into());
            }
            let directory =
                crate::open_root_owned_public_directory(&agent.root).map_err(|e| e.to_string())?;
            write_file(&directory, "sdk-agent.apparmor", policy.as_bytes(), 0o400)?;
            agent.policy_attempted = true;
            agent.command(
                true,
                vec!["--add".into(), agent.profile.to_string_lossy().into()],
                10,
                cancel,
            )?;
            let expected_label = crate::native_sdk_peer::sdk_label(&agent.name)?;
            let loaded = String::from_utf8(read(
                Path::new("/sys/kernel/security/apparmor/profiles"),
                1024 * 1024,
            )?)
            .map_err(|_| "SDK profile inventory UTF-8")?;
            if !loaded.lines().any(|line| line == expected_label) {
                let actual = loaded
                    .lines()
                    .filter(|line| line.starts_with(&format!("{} ", agent.name)))
                    .collect::<Vec<_>>();
                return Err(format!(
                    "SDK declared template mode not observed: {actual:?}"
                ));
            }
            let absent = agent.commands.run(
                false,
                &strings(&["container", "exists", &agent.name]),
                20,
                cancel,
            )?;
            if absent.status.code() != Some(1) {
                return Err("fresh SDK container name unavailable".into());
            }
            let mut args = strings(&[
                "create",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--user=10001:10001",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=256",
                "--memory=2g",
                "--cpus=2",
                "--cpuset-cpus=0-1",
                "--timeout=240",
                "--env=HOME=/runtime/home",
                "--env=PATH=/usr/bin:/bin",
                "--workdir=/runtime/home/project",
            ]);
            args.extend([
                format!("--name={}", agent.name),
                format!("--security-opt=apparmor={}", agent.name),
                format!("--cgroup-parent=holgauntletrust{job}.slice"),
                format!("--label=hol.gauntlet.sdk.job={job}"),
                format!("--label=hol.gauntlet.sdk.nonce={}", agent.nonce),
                format!(
                    "--label=hol.gauntlet.sdk.profile={}",
                    if agent.mcp {
                        "native-sdk-mcp-transport-v1"
                    } else {
                        "native-sdk-transport-v1"
                    }
                ),
            ]);
            for (target, (source, rw)) in &agent.mounts {
                args.extend([
                    "--volume".into(),
                    format!(
                        "{source}:{target}:{}",
                        if *rw { "rw,rprivate" } else { "ro,rprivate" }
                    ),
                ]);
            }
            args.extend([
                "--entrypoint=/usr/bin/sleep".into(),
                NATIVE_SDK_AGENT_IMAGE.into(),
                "240".into(),
            ]);
            agent.create_attempted = true;
            let output = agent.command(false, args, 30, cancel)?;
            let cid = std::str::from_utf8(&output)
                .map_err(|_| "SDK create CID UTF-8")?
                .trim();
            if !crate::hex(cid, 64) {
                return Err("SDK create did not return one exact CID".into());
            }
            agent.cid = Some(cid.into());
            let value = agent.inspect(cancel)?;
            let (actual, _) = agent.check(&value, false)?;
            if actual != cid {
                return Err("SDK created CID and inspect differ".into());
            }
            agent.command(false, strings(&["start", cid]), 20, cancel)?;
            let value = agent.inspect(cancel)?;
            let (_, pid) = agent.check(&value, true)?;
            let proc = PathBuf::from(format!("/proc/{pid}"));
            let raw = read(&proc.join("stat"), 4096)?;
            let stat = crate::linux_process::parse_proc_stat(&raw, pid)
                .ok_or("SDK init start tick unavailable")?;
            let cgroup = String::from_utf8(read(&proc.join("cgroup"), 4096)?)
                .map_err(|_| "SDK cgroup UTF-8")?;
            let cgroup = cgroup
                .trim()
                .strip_prefix("0::")
                .filter(|s| crate::linux_process::valid_cgroup(s))
                .ok_or("SDK unified cgroup missing")?;
            if !cgroup.starts_with(&format!("/holgauntletrust{job}.slice/")) {
                return Err("SDK agent not owned by the exact job slice".into());
            }
            let group = PathBuf::from("/sys/fs/cgroup").join(&cgroup[1..]);
            agent.cgroup = Some(group.clone());
            let mut limits = serde_json::Map::new();
            for (name, expected) in [
                ("memory.max", "2147483648"),
                ("pids.max", "256"),
                ("cpu.max", "200000 100000"),
                ("cpuset.cpus.effective", "0-1"),
            ] {
                let actual = String::from_utf8(read(&group.join(name), 4096)?)
                    .map_err(|_| "SDK cgroup limit UTF-8")?;
                if actual.trim() != expected {
                    return Err(format!("actual SDK {name} differs"));
                }
                limits.insert(name.into(), json!(expected));
            }
            let label = String::from_utf8(read(&proc.join("attr/current"), 4096)?)
                .map_err(|_| "SDK init LSM label UTF-8")?;
            agent.kernel = Some(json!({"pid":pid,"start_ticks":stat.start_ticks,
                "cgroup":cgroup,"limits":limits,"lsm_label":label.trim(),
                "declared_lsm_label":expected_label}));
            let boundary = NativeSdkBoundary::observe(
                agent.cid.as_ref().unwrap(),
                &SdkWirePeerPin {
                    pid,
                    start_ticks: stat.start_ticks,
                    cgroup: cgroup.into(),
                },
                &expected_label,
                actor,
            )?;
            agent.inspection = Some(value);
            agent.kernel.as_mut().unwrap()["init"] = boundary.observation();
            Ok(boundary)
        })();
        launched
    }
    fn command(
        &mut self,
        parser: bool,
        args: Vec<String>,
        seconds: u64,
        cancel: &AtomicBool,
    ) -> Result<Vec<u8>, String> {
        let output = self.commands.run(parser, &args, seconds, cancel)?;
        if !output.status.success() {
            return Err(format!(
                "SDK helper {:?} failed: {}",
                args.first(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(output.stdout)
    }
    fn inspect(&mut self, cancel: &AtomicBool) -> Result<Value, String> {
        let target = self.cid.as_ref().unwrap_or(&self.name).clone();
        let raw = self.command(false, strings(&["inspect", &target]), 20, cancel)?;
        let values: Value =
            serde_json::from_slice(&raw).map_err(|_| "SDK inspect JSON unavailable")?;
        let rows = values
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or("SDK inspect must have one result")?;
        self.inspection = Some(rows[0].clone());
        Ok(rows[0].clone())
    }
    pub(crate) fn close(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        let cancel = AtomicBool::new(false);
        let removed: Result<(), String> = (|| {
            if self.create_attempted {
                let absent = self.commands.run(
                    false,
                    &strings(&[
                        "container",
                        "exists",
                        self.cid.as_ref().unwrap_or(&self.name),
                    ]),
                    20,
                    &cancel,
                )?;
                match absent.status.code() {
                    Some(1) => {}
                    Some(0) => {
                        let value = self.inspect(&cancel)?;
                        let running = value["State"]["Running"]
                            .as_bool()
                            .ok_or("SDK cleanup state missing")?;
                        let (id, _) = self.check(&value, running)?;
                        if self.cid.as_ref().is_some_and(|cid| *cid != id) {
                            return Err("SDK cleanup CID differs".into());
                        }
                        self.cid = Some(id.clone());
                        self.command(
                            false,
                            strings(&["rm", "--force", "--time=0", &id]),
                            20,
                            &cancel,
                        )?;
                        let absent = self.commands.run(
                            false,
                            &strings(&["container", "exists", &id]),
                            20,
                            &cancel,
                        )?;
                        if absent.status.code() != Some(1) {
                            return Err("owned SDK container survived".into());
                        }
                    }
                    _ => return Err("SDK container absence uncertain".into()),
                }
            }
            if let Some(group) = &self.cgroup {
                let deadline = Instant::now() + Duration::from_secs(5);
                while group.try_exists().map_err(|e| e.to_string())? {
                    if Instant::now() >= deadline {
                        return Err("SDK cgroup survived removal".into());
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
            Ok(())
        })();
        let policy: Result<(), String> = (|| {
            if self.policy_attempted {
                let bytes = read(&self.profile, 1024 * 1024)?;
                if format!("{:x}", Sha256::digest(bytes)) != self.profile_sha256 {
                    return Err("SDK policy bytes changed".into());
                }
                if !crate::builder_policy::profile_absent(&self.name).map_err(|e| e.to_string())? {
                    self.command(
                        true,
                        vec!["--remove".into(), self.profile.to_string_lossy().into()],
                        10,
                        &cancel,
                    )?;
                }
                if !crate::builder_policy::profile_absent(&self.name).map_err(|e| e.to_string())? {
                    return Err("SDK profile survived removal".into());
                }
            }
            Ok(())
        })();
        match (removed, policy) {
            (Ok(()), Ok(())) => {
                self.closed = true;
                Ok(())
            }
            (a, b) => Err(format!(
                "SDK cleanup uncertain: container={a:?}; profile={b:?}"
            )),
        }
    }
    pub(crate) fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-agent-owner.v1","job_id":self.job,"nonce":self.nonce,
            "name":self.name,"container_id":self.cid,"cgroup":self.cgroup,"inspection":self.inspection,"kernel":self.kernel,
            "apparmor_sha256":self.profile_sha256,"cleanup_complete":self.closed,"execution_eligible":false})
    }
}
impl Drop for NativeSdkAgent {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[path = "native_sdk_agent_calls.rs"]
mod calls;
