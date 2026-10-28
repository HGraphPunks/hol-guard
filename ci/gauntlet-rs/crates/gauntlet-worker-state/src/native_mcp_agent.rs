//! Root ownership of one fixed, unprivileged MCP agent container. Create and
//! start are separate so the CID is retained before any image code executes.
use crate::native_mcp_agent_spec::check_inspection;
use crate::native_mcp_public::{write_file, NativeMcpPublic};
use crate::native_sdk_process::RootCommands;
use crate::native_sdk_public::APPARMOR;
use crate::{NativeMcpBoundary, NativeMcpSockets, SdkWirePeerPin, NATIVE_SDK_AGENT_IMAGE};
use gauntlet_cell_rootfs::CellPreparation;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

pub struct NativeMcpAgent {
    public: NativeMcpPublic,
    prefix: PathBuf,
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
        return Err("MCP kernel read bound".into());
    }
    Ok(raw)
}
impl NativeMcpAgent {
    pub fn prepare(
        job: &str,
        spec: &CellPreparation,
        sockets: &mut NativeMcpSockets,
    ) -> Result<Self, String> {
        if !crate::hex(job, 16) {
            return Err("fixed MCP job required".into());
        }
        let root = PathBuf::from(crate::native_job_spec::NATIVE_JOBS).join(job);
        gauntlet_cell_rootfs::require_outside_root()?;
        sockets.verify_for_job(job)?;
        if spec.stage != root.join("cell")
            || spec.job_slice() != Some(format!("holgauntletrust{job}.slice").as_str())
        {
            return Err("MCP preparation belongs to another native job".into());
        }
        let public = NativeMcpPublic::prepare(&root, &spec.runtime_prefix)?;
        let parser = spec
            .host_helper_sha256("/usr/sbin/apparmor_parser")
            .ok_or("MCP parser pin required")?;
        let commands = RootCommands::new_mcp(&root, &spec.podman_sha256, parser)?;
        let mut random = [0; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| "MCP Root nonce unavailable")?;
        let nonce = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let name = format!("hol-gauntlet-mcp-{job}-{nonce}");
        let mut mounts = BTreeMap::new();
        for (source, target, rw) in [
            (root.join("mcp-home"), "/product/home", true),
            (root.join("mcp-guard"), "/product/guard", true),
            (public.path().to_owned(), "/product/public", false),
            (sockets.upstream_directory(), "/upstream", false),
            (sockets.gate_directory(), "/product/proxy-gate", false),
            (
                spec.runtime_prefix.clone(),
                spec.runtime_prefix.to_str().ok_or("MCP prefix UTF-8")?,
                false,
            ),
        ] {
            mounts.insert(target.into(), (source.to_string_lossy().into_owned(), rw));
        }
        let policy = APPARMOR.replace("HOL_WORKER_PROFILE", &name);
        let profile = root.join("mcp-agent.apparmor");
        let agent = Self {
            public,
            prefix: spec.runtime_prefix.clone(),
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
        };
        Ok(agent)
    }
    pub fn launch(
        &mut self,
        actor: &Value,
        cancel: &AtomicBool,
    ) -> Result<std::sync::Arc<NativeMcpBoundary>, String> {
        let agent = self;
        let job = agent.job.clone();
        let policy = APPARMOR.replace("HOL_WORKER_PROFILE", &agent.name);
        let launched = (|| {
            agent.public.verify()?;
            if !crate::builder_policy::profile_absent(&agent.name).map_err(|e| e.to_string())? {
                return Err("fresh MCP profile already exists".into());
            }
            let directory =
                crate::open_root_owned_public_directory(&agent.root).map_err(|e| e.to_string())?;
            write_file(&directory, "mcp-agent.apparmor", policy.as_bytes(), 0o400)?;
            agent.policy_attempted = true;
            agent.command(
                true,
                vec!["--add".into(), agent.profile.to_string_lossy().into()],
                10,
                cancel,
            )?;
            let expected_label = crate::native_mcp_peer::label(&agent.name)?;
            let loaded = String::from_utf8(read(
                Path::new("/sys/kernel/security/apparmor/profiles"),
                1024 * 1024,
            )?)
            .map_err(|_| "MCP profile inventory UTF-8")?;
            if !loaded.lines().any(|line| line == expected_label) {
                let actual = loaded
                    .lines()
                    .filter(|line| line.starts_with(&format!("{} ", agent.name)))
                    .collect::<Vec<_>>();
                return Err(format!(
                    "MCP declared template mode not observed: {actual:?}"
                ));
            }
            let absent = agent.commands.run(
                false,
                &strings(&["container", "exists", &agent.name]),
                20,
                cancel,
            )?;
            if absent.status.code() != Some(1) {
                return Err("fresh MCP container name unavailable".into());
            }
            let mut args = strings(&[
                "create",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--user=10005:10005",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=256",
                "--memory=1g",
                "--cpus=1",
                "--cpuset-cpus=0",
                "--timeout=240",
                "--env=HOME=/product/home",
                "--env=PATH=/usr/bin:/bin",
                "--workdir=/product/home/project",
            ]);
            args.extend([
                format!("--name={}", agent.name),
                format!("--security-opt=apparmor={}", agent.name),
                format!("--cgroup-parent=holgauntletrust{job}.slice"),
                format!("--label=hol.gauntlet.mcp.job={job}"),
                format!("--label=hol.gauntlet.mcp.nonce={}", agent.nonce),
                "--label=hol.gauntlet.mcp.profile=native-mcp-transport-v1".into(),
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
                .map_err(|_| "MCP create CID UTF-8")?
                .trim();
            if !crate::hex(cid, 64) {
                return Err("MCP create did not return one exact CID".into());
            }
            agent.cid = Some(cid.into());
            let value = agent.inspect(cancel)?;
            let (actual, _) = check_inspection(
                &value,
                &agent.name,
                &agent.job,
                &agent.nonce,
                &agent.mounts,
                false,
            )?;
            if actual != cid {
                return Err("MCP created CID and inspect differ".into());
            }
            agent.command(false, strings(&["start", cid]), 20, cancel)?;
            let value = agent.inspect(cancel)?;
            let (_, pid) = check_inspection(
                &value,
                &agent.name,
                &agent.job,
                &agent.nonce,
                &agent.mounts,
                true,
            )?;
            let proc = PathBuf::from(format!("/proc/{pid}"));
            let raw = read(&proc.join("stat"), 4096)?;
            let stat = crate::linux_process::parse_proc_stat(&raw, pid)
                .ok_or("MCP init start tick unavailable")?;
            let cgroup = String::from_utf8(read(&proc.join("cgroup"), 4096)?)
                .map_err(|_| "MCP cgroup UTF-8")?;
            let cgroup = cgroup
                .trim()
                .strip_prefix("0::")
                .filter(|s| crate::linux_process::valid_cgroup(s))
                .ok_or("MCP unified cgroup missing")?;
            if !cgroup.starts_with(&format!("/holgauntletrust{job}.slice/")) {
                return Err("MCP agent not owned by the exact job slice".into());
            }
            let group = PathBuf::from("/sys/fs/cgroup").join(&cgroup[1..]);
            agent.cgroup = Some(group.clone());
            let mut limits = serde_json::Map::new();
            for (name, expected) in [
                ("memory.max", "1073741824"),
                ("pids.max", "256"),
                ("cpu.max", "100000 100000"),
                ("cpuset.cpus.effective", "0"),
            ] {
                let actual = String::from_utf8(read(&group.join(name), 4096)?)
                    .map_err(|_| "MCP cgroup limit UTF-8")?;
                if actual.trim() != expected {
                    return Err(format!("actual MCP {name} differs"));
                }
                limits.insert(name.into(), json!(expected));
            }
            let label = String::from_utf8(read(&proc.join("attr/current"), 4096)?)
                .map_err(|_| "MCP init LSM label UTF-8")?;
            agent.kernel = Some(json!({"pid":pid,"start_ticks":stat.start_ticks,
                "cgroup":cgroup,"limits":limits,"lsm_label":label.trim(),
                "declared_lsm_label":expected_label}));
            let boundary = NativeMcpBoundary::observe(
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
                "MCP helper {:?} failed: {}",
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
            serde_json::from_slice(&raw).map_err(|_| "MCP inspect JSON unavailable")?;
        let rows = values
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or("MCP inspect must have one result")?;
        self.inspection = Some(rows[0].clone());
        Ok(rows[0].clone())
    }
    pub fn close(&mut self) -> Result<(), String> {
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
                            .ok_or("MCP cleanup state missing")?;
                        let (id, _) = check_inspection(
                            &value,
                            &self.name,
                            &self.job,
                            &self.nonce,
                            &self.mounts,
                            running,
                        )?;
                        if self.cid.as_ref().is_some_and(|cid| *cid != id) {
                            return Err("MCP cleanup CID differs".into());
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
                            return Err("owned MCP container survived".into());
                        }
                    }
                    _ => return Err("MCP container absence uncertain".into()),
                }
            }
            if let Some(group) = &self.cgroup {
                let deadline = Instant::now() + Duration::from_secs(5);
                while group.try_exists().map_err(|e| e.to_string())? {
                    if Instant::now() >= deadline {
                        return Err("MCP cgroup survived removal".into());
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
                    return Err("MCP policy bytes changed".into());
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
                    return Err("MCP profile survived removal".into());
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
                "MCP cleanup uncertain: container={a:?}; profile={b:?}"
            )),
        }
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-mcp-agent-owner.v1","job_id":self.job,"nonce":self.nonce,
            "name":self.name,"container_id":self.cid,"cgroup":self.cgroup,"inspection":self.inspection,"kernel":self.kernel,
            "apparmor_sha256":self.profile_sha256,"cleanup_complete":self.closed,"execution_eligible":false})
    }
}
impl Drop for NativeMcpAgent {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[path = "native_mcp_agent_calls.rs"]
mod calls;
