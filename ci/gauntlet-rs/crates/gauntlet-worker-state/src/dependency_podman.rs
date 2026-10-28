//! Fixed dependency container creation and exact-ID teardown. A name alone is
//! never authority to stop a container. The caller holds both worker leases.
use crate::builder_candidate_preflight::{podman_info, verify_file};
use crate::builder_run_plan::BuilderRunPlan;
use gauntlet_contracts::DependencyRunIntent;
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use serde_json::Value;
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn drain(fd: &OwnedFd, bytes: &mut Vec<u8>) -> Result<bool, String> {
    loop {
        let mut buffer = [0u8; 8192];
        match rustix::io::read(fd, &mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) if bytes.len() + n <= 128 * 1024 => bytes.extend_from_slice(&buffer[..n]),
            Ok(_) => return Err("dependency helper output exceeds bound".into()),
            Err(rustix::io::Errno::AGAIN) => return Ok(false),
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn run(pin: &str, args: &[String]) -> Result<Vec<u8>, String> {
    verify_file("/usr/bin/podman", pin, true, 64 * 1024 * 1024).map_err(|e| e.to_string())?;
    let mut child = Command::new("/usr/bin/podman")
        .args(args)
        .env_clear()
        .env("HOME", "/root")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("TMPDIR", "/var/tmp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let out: OwnedFd = child
        .stdout
        .take()
        .ok_or("dependency helper stdout missing")?
        .into();
    let err: OwnedFd = child
        .stderr
        .take()
        .ok_or("dependency helper stderr missing")?
        .into();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = (|| {
        for fd in [&out, &err] {
            fcntl_setfl(
                fd,
                fcntl_getfl(fd).map_err(|e| e.to_string())? | OFlags::NONBLOCK,
            )
            .map_err(|e| e.to_string())?;
        }
        let started = Instant::now();
        loop {
            let a = drain(&out, &mut stdout)?;
            let b = drain(&err, &mut stderr)?;
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                if a && b {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(format!(
                            "fixed dependency helper failed: {}",
                            String::from_utf8_lossy(&stderr)
                        ))
                    };
                }
            }
            if started.elapsed() >= Duration::from_secs(30) {
                return Err("dependency helper deadline exceeded".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        crate::process_reap::reap_probe_child_bounded(&mut child)
            .map_err(|_| "dependency helper reap uncertain")?;
    }
    result?;
    verify_file("/usr/bin/podman", pin, true, 64 * 1024 * 1024).map_err(|e| e.to_string())?;
    Ok(stdout)
}

fn arguments(intent: &DependencyRunIntent) -> Vec<String> {
    let p = &intent.pins;
    let job = p.text("job_id");
    let root = format!("/var/lib/hol-gauntlet/builds/{job}");
    let mut args = vec![
        "create".into(),
        "--rm".into(),
        "--pull=never".into(),
        "--name".into(),
        format!("hol-gauntlet-build-{job}"),
        "--label".into(),
        format!(
            "hol-gauntlet.dependency-intent={}",
            intent.digest().expect("validated intent")
        ),
        "--user=65532:65532".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        format!("--security-opt=apparmor=hol-gauntlet-build-{job}"),
        "--memory=12g".into(),
        "--memory-swap=12g".into(),
        "--cpus=2".into(),
        "--pids-limit=512".into(),
        "--network=slirp4netns".into(),
        "--ipc=private".into(),
        "--cgroup-parent=system.slice".into(),
        "--entrypoint=/input/gauntlet-dependency-exporter".into(),
    ];
    for name in ["pyproject.toml", "uv.lock", "gauntlet-dependency-exporter"] {
        args.extend([
            "--volume".into(),
            format!("{root}/dependency-inputs/{name}:/input/{name}:ro"),
        ]);
    }
    args.extend([
        "--volume".into(),
        format!("{root}/export:/output:rw"),
        p.text("builder_image_id").into(),
        job.into(),
        p.text("source_sha").into(),
        p.text("pyproject_sha256").into(),
        p.text("uv_lock_sha256").into(),
    ]);
    args
}

pub(crate) struct DependencyContainer<'a> {
    intent: &'a DependencyRunIntent,
    cid: Option<String>,
}
impl<'a> DependencyContainer<'a> {
    pub(crate) fn new(intent: &'a DependencyRunIntent) -> Self {
        Self { intent, cid: None }
    }
    fn pin(&self) -> &str {
        self.intent.pins.text("podman_sha256")
    }
    fn identity(&self) -> Result<Option<String>, String> {
        let job = self.intent.pins.text("job_id");
        if crate::builder_candidate_process::container_absent(job).map_err(|e| e.to_string())?
            && self
                .cid
                .as_deref()
                .map(crate::builder_candidate_process::container_id_absent)
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or(true)
        {
            return Ok(None);
        }
        let target = self
            .cid
            .clone()
            .unwrap_or_else(|| format!("hol-gauntlet-build-{job}"));
        let raw = run(self.pin(), &["container".into(), "inspect".into(), target])?;
        let v: Value =
            serde_json::from_slice(&raw).map_err(|_| "dependency container inspect JSON")?;
        let v = v
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or("one dependency container required")?
            .first()
            .ok_or("dependency container missing")?;
        let cid = validated_identity(v, self.intent)?;
        if self.cid.as_ref().is_some_and(|wanted| wanted != &cid) {
            return Err("dependency CID changed".into());
        }
        Ok(Some(cid))
    }
    pub(crate) fn create(&mut self) -> Result<BuilderRunPlan, String> {
        if self.identity()?.is_some() {
            return Err("dependency container already exists".into());
        }
        let info = podman_info().map_err(|e| e.to_string())?;
        if info["host"]["cgroupManager"] != "systemd" || info["host"]["cgroupVersion"] != "v2" {
            return Err("fixed dependency cgroup manager required".into());
        }
        let result = run(self.pin(), &arguments(self.intent));
        let observed = self.identity()?;
        self.cid = observed;
        let raw = result?;
        let cid = std::str::from_utf8(&raw)
            .map_err(|_| "dependency CID UTF-8")?
            .trim();
        if self.cid.as_deref() != Some(cid) {
            return Err("created dependency CID differs from independent inspect".into());
        }
        let body = serde_json::json!({"schema":"hol-gauntlet-native-dependency-container.v1","container_id":cid,"intent_sha256":self.intent.digest()?});
        let job =
            crate::builder_candidate_source::open_fixed_build_slot(self.intent.pins.text("job_id"))
                .map_err(|e| e.to_string())?;
        crate::builder_candidate_receipt::write_root_canonical_job_file(
            &job,
            "dependency-container.v1.json",
            &body,
        )
        .map_err(|e| e.to_string())?;
        Ok(BuilderRunPlan {
            argv: vec![
                "/usr/bin/podman".into(),
                "start".into(),
                "--attach".into(),
                cid.into(),
            ],
            job_id: self.intent.pins.text("job_id").into(),
            source_archive_sha256: self.intent.pins.text("source_archive_sha256").into(),
            execution_eligible: false,
        })
    }
    pub(crate) fn drain(&self) -> Result<(), String> {
        let observed = self.identity()?;
        if let Some(cid) = observed {
            run(
                self.pin(),
                &["rm".into(), "--force".into(), "--time=5".into(), cid],
            )?;
        }
        if self.identity()?.is_some() {
            return Err("dependency container survived cleanup".into());
        }
        if let Some(cid) = &self.cid {
            let path = format!("/sys/fs/cgroup/system.slice/libpod-{cid}.scope");
            let started = Instant::now();
            loop {
                match std::fs::symlink_metadata(&path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Ok(_) if started.elapsed() < Duration::from_secs(10) => {
                        std::thread::sleep(Duration::from_millis(25))
                    }
                    _ => return Err("dependency container cgroup absence uncertain".into()),
                }
            }
        }
        Ok(())
    }
    pub(crate) fn id(&self) -> Option<&str> {
        self.cid.as_deref()
    }
}

fn validated_identity(v: &Value, intent: &DependencyRunIntent) -> Result<String, String> {
    let cid = v["Id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("full dependency CID required")?;
    let job = intent.pins.text("job_id");
    let image_matches = v["Image"].as_str().is_some_and(|s| {
        s.strip_prefix("sha256:").unwrap_or(s)
            == intent
                .pins
                .text("builder_image_id")
                .trim_start_matches("sha256:")
    });
    if v["Name"] != format!("hol-gauntlet-build-{job}")
        || !image_matches
        || v["Config"]["Labels"]["hol-gauntlet.dependency-intent"] != intent.digest()?
        || v["Config"]["User"] != "65532:65532"
    {
        return Err("dependency container identity differs from intent".into());
    }
    Ok(cid.into())
}

pub(crate) fn verify_completed_absent(
    intent: &DependencyRunIntent,
    cid: &str,
) -> Result<(), String> {
    if !crate::hex(cid, 64) {
        return Err("completed dependency CID missing".into());
    }
    verify_file(
        "/usr/bin/podman",
        intent.pins.text("podman_sha256"),
        true,
        64 * 1024 * 1024,
    )
    .map_err(|e| e.to_string())?;
    if !crate::builder_candidate_process::container_absent(intent.pins.text("job_id"))
        .map_err(|e| e.to_string())?
        || !crate::builder_candidate_process::container_id_absent(cid).map_err(|e| e.to_string())?
    {
        return Err("completed dependency container name exists".into());
    }
    let path = format!("/sys/fs/cgroup/system.slice/libpod-{cid}.scope");
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("completed dependency container cgroup exists or is unknown".into()),
    }
    crate::dependency_state::client_group_absent(intent.pins.text("job_id"))?;
    if !crate::builder_policy::profile_absent(&format!(
        "hol-gauntlet-build-{}",
        intent.pins.text("job_id")
    ))
    .map_err(|e| e.to_string())?
    {
        return Err("completed dependency profile still exists".into());
    }
    Ok(())
}
