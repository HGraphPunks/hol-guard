//! Fixed-container child ownership, bounded combined logs and exact stdout.
use super::feature_executor_scope::FeatureBox;
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(super) const LOG_LIMIT: usize = 8 * 1024 * 1024;
pub(super) struct Outcome {
    pub(super) code: i32,
    pub(super) stdout: Vec<u8>,
    pub(super) elapsed_millis: u64,
}
pub(super) fn environment() -> BTreeMap<String, String> {
    [
        ("PATH", "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin"),
        ("HOME", "/work/home"),
        ("CARGO_HOME", "/work/cargo"),
        ("RUSTUP_HOME", "/usr/local/rustup"),
        ("CARGO_BUILD_JOBS", "2"),
        ("CARGO_INCREMENTAL", "0"),
        ("UV_CACHE_DIR", "/work/uv-cache"),
        ("UV_LINK_MODE", "copy"),
        ("UV_PYTHON_INSTALL_DIR", "/opt/gauntlet-python"),
        ("UV_PYTHON_DOWNLOADS", "never"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}
fn drain(
    fd: &OwnedFd,
    log: &mut std::fs::File,
    total: &mut usize,
    capture: Option<&mut Vec<u8>>,
) -> Result<bool, String> {
    let mut capture = capture;
    loop {
        let mut buffer = [0u8; 8192];
        match rustix::io::read(fd, &mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if *total + n > LOG_LIMIT {
                    return Err("feature command log exceeds bound".into());
                }
                log.write_all(&buffer[..n]).map_err(|e| e.to_string())?;
                *total += n;
                if let Some(output) = capture.as_deref_mut() {
                    if output.len() + n > 2 * 1024 * 1024 {
                        return Err("feature command stdout exceeds bound".into());
                    }
                    output.extend_from_slice(&buffer[..n]);
                }
            }
            Err(rustix::io::Errno::AGAIN) => return Ok(false),
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute(
    owner: &FeatureBox,
    program: &str,
    args: &[String],
    cwd: &str,
    env: &BTreeMap<String, String>,
    label: &str,
    seconds: u64,
    capture: bool,
) -> Result<Outcome, String> {
    owner.verify()?;
    if !program.starts_with('/')
        || label.is_empty()
        || !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
        || !matches!(seconds, 10 | 20 | 120 | 600 | 1800)
    {
        return Err("fixed feature child command required".into());
    }
    let mut log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(format!("/output/{label}.log"))
        .map_err(|e| e.to_string())?;
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let out: OwnedFd = child.stdout.take().ok_or("feature stdout missing")?.into();
    let err: OwnedFd = child.stderr.take().ok_or("feature stderr missing")?.into();
    let started = Instant::now();
    let mut stdout = Vec::new();
    let mut total = 0;
    let result: Result<i32, String> = (|| {
        for fd in [&out, &err] {
            fcntl_setfl(
                fd,
                fcntl_getfl(fd).map_err(|e| e.to_string())? | OFlags::NONBLOCK,
            )
            .map_err(|e| e.to_string())?;
        }
        loop {
            let a = drain(
                &out,
                &mut log,
                &mut total,
                if capture { Some(&mut stdout) } else { None },
            )?;
            let b = drain(&err, &mut log, &mut total, None)?;
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                owner.drain_children()?;
                let a = a
                    || drain(
                        &out,
                        &mut log,
                        &mut total,
                        if capture { Some(&mut stdout) } else { None },
                    )?;
                let b = b || drain(&err, &mut log, &mut total, None)?;
                if !a || !b {
                    return Err("feature command output cleanup uncertain".into());
                }
                return Ok(status
                    .code()
                    .unwrap_or_else(|| -status.signal().unwrap_or(1)));
            }
            if started.elapsed() >= Duration::from_secs(seconds) {
                let pid = child.id();
                if pid <= 1 {
                    return Err("feature child identity invalid".into());
                }
                let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                crate::process_reap::reap_probe_child_bounded(&mut child)
                    .map_err(|_| "feature child reap uncertain")?;
                owner.drain_children()?;
                drain(
                    &out,
                    &mut log,
                    &mut total,
                    if capture { Some(&mut stdout) } else { None },
                )?;
                drain(&err, &mut log, &mut total, None)?;
                return Ok(124);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() {
        let pid = child.id();
        if pid > 1 {
            let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
        }
        crate::process_reap::reap_probe_child_bounded(&mut child)
            .map_err(|_| "feature child reap uncertain")?;
        owner.drain_children()?;
    }
    log.sync_all().map_err(|e| e.to_string())?;
    Ok(Outcome {
        code: result?,
        stdout,
        elapsed_millis: started.elapsed().as_millis() as u64,
    })
}
