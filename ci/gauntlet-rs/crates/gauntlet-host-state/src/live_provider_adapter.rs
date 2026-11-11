//! Exclusive process-group custody and bounded numerical protocol transport.
use super::assets::Assets;
use super::custody::Journal;
use super::{bytes, numerical, text, Intent};
use crate::observer_process::Owner;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

pub(super) struct Adapter {
    owner: Owner,
    input: ChildStdin,
    output: ChildStdout,
    error: ChildStderr,
    buffered: Vec<u8>,
    diagnostics: Vec<u8>,
}
pub(super) trait Numerical {
    fn send(&mut self, value: &Value, journal: &Journal, digest: &str) -> Result<(), String>;
    fn receive(
        &mut self,
        journal: &Journal,
        digest: &str,
        timeout: Duration,
    ) -> Result<Value, String>;
    fn send_bounded(
        &mut self,
        value: &Value,
        journal: &Journal,
        digest: &str,
        _timeout: Duration,
    ) -> Result<(), String> {
        self.send(value, journal, digest)
    }
}
impl Numerical for Adapter {
    fn send_bounded(
        &mut self,
        value: &Value,
        journal: &Journal,
        digest: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        self.send_until(value, journal, digest, timeout)
    }
    fn send(&mut self, value: &Value, journal: &Journal, digest: &str) -> Result<(), String> {
        Adapter::send(self, value, journal, digest)
    }
    fn receive(
        &mut self,
        journal: &Journal,
        digest: &str,
        timeout: Duration,
    ) -> Result<Value, String> {
        Adapter::receive(self, journal, digest, timeout)
    }
}
fn nonblocking(fd: i32) -> Result<(), String> {
    // SAFETY: descriptors belong to live owned child pipes.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("numerical pipe unavailable".into());
    }
    Ok(())
}
impl Adapter {
    pub fn spawn(intent: &Intent, journal: &Journal, assets: &Assets) -> Result<Self, String> {
        assets.stable()?;
        let _interpreter = assets.executable_file(intent.text("python")?)?;
        let state = journal.numerical_state()?;
        let mut command = Command::new(intent.text("python")?);
        command
            .arg0(intent.text("python")?)
            .args(["-I", "-S", "-B", "-X"])
            .arg(format!(
                "pycache_prefix={}",
                state.join("pycache").display()
            ))
            .args([
                "-c",
                numerical::CODE,
                intent.text("site_packages")?,
                intent.text("model_directory")?,
            ])
            .env_clear()
            .env("HOME", &state)
            .env("HF_HOME", &state)
            .env("HF_HUB_OFFLINE", "1")
            .env("TRANSFORMERS_OFFLINE", "1")
            .env("TOKENIZERS_PARALLELISM", "false")
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut owner = Owner::spawn(command).map_err(|_| "numerical adapter spawn failed")?;
        assets.stable()?;
        journal.put("provider-child.json",&json!({"schema":"hol-gauntlet-rust-provider-child.v1","binding_sha256":intent.digest()?,"pid":owner.child.id(),"owned_process_group":true,"producer_sha256":intent.text("producer_sha256")?}))?;
        let input = owner
            .child
            .stdin
            .take()
            .ok_or("numerical input unavailable")?;
        let output = owner
            .child
            .stdout
            .take()
            .ok_or("numerical output unavailable")?;
        let error = owner
            .child
            .stderr
            .take()
            .ok_or("numerical diagnostics unavailable")?;
        for fd in [input.as_raw_fd(), output.as_raw_fd(), error.as_raw_fd()] {
            nonblocking(fd)?;
        }
        let mut adapter = Self {
            owner,
            input,
            output,
            error,
            buffered: Vec::new(),
            diagnostics: Vec::new(),
        };
        let ready = adapter.receive(journal, &intent.digest()?, Duration::from_secs(300))?;
        if ready
            != json!({"schema":"hol-gauntlet-mlx-numerical-ready.v1","model_loaded":true,"chat_template":true,"tool_calling":true,"batching":false,"draft":false})
        {
            return Err("numerical model readiness differs".into());
        }
        verify_executable(&adapter.owner, &_interpreter)?;
        assets.stable()?;
        Ok(adapter)
    }
    fn drain(&mut self) -> Result<(), String> {
        let mut buffer = [0_u8; 8192];
        for _ in 0..8 {
            match self.error.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if self.diagnostics.len() + n > 65536 {
                        return Err("numerical diagnostics exceed bound".into());
                    }
                    self.diagnostics.extend_from_slice(&buffer[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("numerical diagnostics unavailable".into()),
            }
        }
        Ok(())
    }
    fn check(
        &mut self,
        journal: &Journal,
        digest: &str,
        start: Instant,
        timeout: Duration,
    ) -> Result<(), String> {
        self.drain()?;
        if super::relay::cancelled() || journal.stop_requested(digest)? {
            return Err("provider stop requested".into());
        }
        if start.elapsed() >= timeout {
            return Err("numerical operation deadline reached".into());
        }
        if self
            .owner
            .exited()
            .map_err(|_| "numerical wait custody lost")?
        {
            return Err("numerical adapter exited".into());
        }
        Ok(())
    }
    pub fn send(&mut self, value: &Value, journal: &Journal, digest: &str) -> Result<(), String> {
        self.send_until(value, journal, digest, Duration::from_secs(30))
    }
    fn send_until(
        &mut self,
        value: &Value,
        journal: &Journal,
        digest: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut raw = bytes(value)?;
        raw.push(b'\n');
        if raw.len() > 2 * 1024 * 1024 {
            return Err("numerical request exceeds bound".into());
        }
        let start = Instant::now();
        let mut offset = 0;
        while offset < raw.len() {
            self.check(journal, digest, start, timeout)?;
            match self.input.write(&raw[offset..]) {
                Ok(0) => return Err("numerical input closed".into()),
                Ok(n) => offset += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err("numerical request transport failed".into()),
            }
        }
        Ok(())
    }
    pub fn receive(
        &mut self,
        journal: &Journal,
        digest: &str,
        timeout: Duration,
    ) -> Result<Value, String> {
        let start = Instant::now();
        let mut buffer = [0_u8; 8192];
        loop {
            self.check(journal, digest, start, timeout)?;
            if let Some(end) = self.buffered.iter().position(|b| *b == b'\n') {
                let raw = self.buffered.drain(..=end).collect::<Vec<_>>();
                return super::parse(&raw[..raw.len() - 1]);
            }
            match self.output.read(&mut buffer) {
                Ok(0) => return Err("numerical output closed".into()),
                Ok(n) => {
                    self.buffered.extend_from_slice(&buffer[..n]);
                    if self.buffered.len() > 1024 * 1024 {
                        return Err("numerical frame exceeds bound".into());
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err("numerical output transport failed".into()),
            }
        }
    }
    pub fn stop(&mut self, journal: &Journal) -> Result<Value, String> {
        let status = self
            .owner
            .finish()
            .map_err(|_| "numerical process-group cleanup uncertain")?;
        if !self.diagnostics.is_empty() && !journal.exists("provider-diagnostics.json")? {
            use base64::Engine;
            journal.put("provider-diagnostics.json",&json!({"schema":"hol-gauntlet-rust-provider-private-diagnostics.v1","stderr_b64":base64::engine::general_purpose::STANDARD.encode(&self.diagnostics)}))?;
        }
        Ok(
            json!({"owned_process_group_stopped":true,"child_reaped":true,"exit_code":status.code(),"signal":std::os::unix::process::ExitStatusExt::signal(&status)}),
        )
    }
}

fn verify_executable(owner: &Owner, expected: &std::fs::File) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let actual = {
        #[link(name = "proc")]
        unsafe extern "C" {
            fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, size: u32) -> libc::c_int;
        }
        let mut buffer = [0_u8; 4096];
        // SAFETY: the child is still under exclusive unreaped wait custody;
        // proc_pidpath writes at most the supplied in-process buffer length.
        let count = unsafe {
            proc_pidpath(
                owner.child.id() as i32,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
            )
        };
        if count <= 0 || count as usize >= buffer.len() {
            return Err("numerical kernel executable unavailable".into());
        }
        let end = buffer
            .iter()
            .position(|b| *b == 0)
            .ok_or("numerical executable path invalid")?;
        std::path::PathBuf::from(
            std::str::from_utf8(&buffer[..end]).map_err(|_| "numerical executable path invalid")?,
        )
    };
    #[cfg(not(target_os = "macos"))]
    let actual = std::fs::read_link(format!("/proc/{}/exe", owner.child.id()))
        .map_err(|_| "numerical kernel executable unavailable")?;
    use std::os::unix::fs::MetadataExt;
    let actual = std::fs::symlink_metadata(actual)
        .map_err(|_| "kernel numerical executable metadata unavailable")?;
    let expected = expected
        .metadata()
        .map_err(|_| "retained interpreter metadata unavailable")?;
    if !actual.is_file()
        || (
            actual.dev(),
            actual.ino(),
            actual.mode(),
            actual.uid(),
            actual.gid(),
        ) != (
            expected.dev(),
            expected.ino(),
            expected.mode(),
            expected.uid(),
            expected.gid(),
        )
    {
        return Err("owned numerical process executed another interpreter".into());
    }
    Ok(())
}

pub(super) fn prepared(
    value: &Value,
    request_sha: &str,
    max_tokens: u64,
) -> Result<(u64, String), String> {
    if !super::exact(
        value,
        &[
            "schema",
            "request_sha256",
            "prompt_token_ids",
            "generation_args",
        ],
    ) || value["schema"] != "hol-gauntlet-mlx-numerical-prepared.v1"
        || value["request_sha256"] != request_sha
    {
        return Err("numerical prepared request differs".into());
    }
    let ids = value["prompt_token_ids"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 32768)
        .ok_or("exact bounded prompt token IDs required")?;
    if ids
        .iter()
        .any(|v| v.as_u64().is_none_or(|n| n > u32::MAX as u64))
        || value["generation_args"]["max_tokens"] != max_tokens
        || text(&value["generation_args"]["model"], "model")? != "default_model"
        || !value["generation_args"]["model"]["draft"].is_null()
        || !value["generation_args"]["model"]["adapter"].is_null()
        || value["generation_args"]["num_draft_tokens"] != 0
        || value["generation_args"]["seed"] != 0
    {
        return Err("bounded original serial generation arguments required".into());
    }
    Ok((
        ids.len() as u64,
        super::sha(&bytes(
            &json!({"prompt_token_ids":value["prompt_token_ids"],"generation_args":value["generation_args"]}),
        )?),
    ))
}
