//! Fixed product service launch; lifecycle ownership remains with NativeCell.
use super::NativeCell;
use crate::supervisor_io::{kernel_file, marker, nonblocking, release_initializer};
use crate::Result;
use gauntlet_agent_bridge::{BootstrapKind, BridgeChannel, BridgeClient, OutboundBootstrap};
use serde_json::json;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

impl NativeCell {
    pub(super) fn launch(&mut self) -> Result<()> {
        self.recheck_image_interpreter()?;
        let profile_path = self.inputs.spec.stage.join("native-cell.apparmor");
        let template = include_str!("../../../../gauntlet/benchmark/product_vm.apparmor");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&profile_path)
            .map_err(|e| e.to_string())?;
        use std::io::Write;
        file.write_all(
            template
                .replace("HOL_PRODUCT_VM_PROFILE", &self.profile)
                .as_bytes(),
        )
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
        // The parser may have changed kernel policy before an uncertain exit.
        // Always retain and attempt cleanup of this fresh, exclusively owned name.
        self.loaded = true;
        self.run_helper(
            "/usr/sbin/apparmor_parser",
            &["--add".into(), profile_path.to_string_lossy().into()],
            Duration::from_secs(10),
        )?;
        let mut argv = vec![
            "--quiet".into(),
            "--collect".into(),
            "--wait".into(),
            "--pipe".into(),
            format!("--unit={}.service", self.profile),
            "--property=MemoryMax=1G".into(),
            "--property=TasksMax=128".into(),
            "--property=CPUQuota=100%".into(),
            format!("--property=RuntimeMaxSec={}", self.spec.wall_seconds),
            "--property=TimeoutStopSec=2".into(),
            "--property=KillMode=control-group".into(),
        ];
        if let Some(slice) = &self.spec.job_slice {
            argv.push(format!("--slice={slice}"));
        }
        if let Some(cpu) = self.cpu {
            argv.extend([
                format!("--property=AllowedCPUs={cpu}"),
                format!("--property=CPUAffinity={cpu}"),
            ]);
        }
        argv.extend([
            "/usr/bin/aa-exec".into(),
            "-p".into(),
            self.profile.clone(),
            "--".into(),
            "/usr/bin/unshare".into(),
            "--mount".into(),
            "--pid".into(),
            "--net".into(),
            "--ipc".into(),
            "--uts".into(),
            "--cgroup".into(),
            "--fork".into(),
            "--kill-child=KILL".into(),
            self.spec.constructor.to_string_lossy().into(),
            self.spec.rootfs_declaration.to_string_lossy().into(),
            self.spec.rootfs_sha256.clone(),
        ]);
        crate::fs_input::pinned(
            &self.spec.constructor,
            16 * 1024 * 1024,
            &self.spec.constructor_sha256,
        )?;
        if let Some(image) = &mut self.image {
            image.before_cell_launch()?;
        }
        let mut child = Command::new("/usr/bin/systemd-run")
            .args(argv)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|e| e.to_string())?;
        self.service_started = true;
        let reader: OwnedFd = child
            .stdout
            .take()
            .ok_or("product stdout pipe missing")?
            .into();
        let writer: OwnedFd = child
            .stdin
            .take()
            .ok_or("product stdin pipe missing")?
            .into();
        self.errors = Some(
            child
                .stderr
                .take()
                .ok_or("product stderr pipe missing")?
                .into(),
        );
        self.process = Some(child);
        nonblocking(&reader)?;
        nonblocking(&writer)?;
        nonblocking(self.errors.as_ref().unwrap())?;
        marker(
            &reader,
            b"HOL_CELL_READY_V1\n",
            Instant::now() + Duration::from_secs(5),
            &self.cancelled,
        )?;
        let initial = self.find(self.expectation(
            false,
            1,
            vec![
                "/public/initializer".into(),
                "/public/gauntlet-product-cell".into(),
                "actor".into(),
            ],
        )?)?;
        self.service_observed = true;
        let mounts =
            initial.verify_task_mounts(&self.inputs.tasks, &self.inputs.runtime.mountpoint)?;
        self.journal.append("idmapped-task-mounts", mounts)?;
        self.journal
            .append("before-cell-gate", initial.observation().clone())?;
        release_initializer(
            &writer,
            Instant::now() + Duration::from_secs(5),
            &self.cancelled,
        )?;
        marker(
            &reader,
            b"HOL_CELL_FILTER_READY_V1\n",
            Instant::now() + Duration::from_secs(5),
            &self.cancelled,
        )?;
        let filtered = initial.after_filter_gate(self.expectation(
            true,
            1,
            vec!["/public/gauntlet-product-cell".into(), "actor".into()],
        )?)?;
        self.journal
            .append("filtered-cell", filtered.observation().clone())?;
        self.actor = Some(filtered);
        for (name, expected) in [
            ("memory.max", "1073741824"),
            ("pids.max", "128"),
            ("cpu.max", "100000 100000"),
        ] {
            let actual = String::from_utf8(kernel_file(&self.cgroup.join(name), 4096)?)
                .map_err(|_| "cgroup value UTF-8")?;
            if actual.trim() != expected {
                return Err("actual product cgroup resource ceiling differs".into());
            }
        }
        if let Some(cpu) = self.cpu {
            let actual = String::from_utf8(kernel_file(
                &self.cgroup.join("cpuset.cpus.effective"),
                4096,
            )?)
            .map_err(|_| "cpuset UTF-8")?;
            if actual.trim() != cpu.to_string() {
                return Err("actual product cpuset differs".into());
            }
        }
        self.journal.append("resource-ceilings",json!({"memory_max":1073741824,"pids_max":128,"cpu_max":"100000 100000","cpu":self.cpu}))?;
        self.start_process_events()?;
        let boot = String::from_utf8(kernel_file(
            Path::new("/proc/sys/kernel/random/boot_id"),
            128,
        )?)
        .map_err(|_| "boot identity UTF-8")?;
        let codec = OutboundBootstrap::generate(
            BootstrapKind::ProductCellSupervisor,
            boot.trim(),
            boot.trim(),
            None,
        )
        .and_then(|b| {
            b.deliver(
                &writer,
                Instant::now() + Duration::from_secs(5),
                &self.cancelled,
                10000,
                256 * 1024 * 1024,
            )
        })
        .map_err(|e| e.to_string())?;
        self.client = Some(BridgeClient::new(
            BridgeChannel::new(reader, writer, codec).map_err(|e| e.to_string())?,
        ));
        let hello = self.call("hello", &json!({}), Instant::now() + Duration::from_secs(5))?;
        if hello
            != json!({"schema":"product-cell-actor.v2","local_pid":1,"uid":10004,"gid":10004,
            "limits":{"active_children":64,"total_spawns":1024,"read_wait_ms":100}})
        {
            return Err("actual actor hello differs".into());
        }
        self.journal
            .append("actor-ready", json!({"schema":"product-cell-actor.v2"}))
    }
}
