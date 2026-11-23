//! Duplex fixed Podman exec client. Private socket stdio keeps host device
//! descriptors out of crun. Root captures frames; product claims stay untrusted.
use crate::native_sdk_process::{RootCommands, LIMIT};
use gauntlet_mcp_service::{Family, McpStream, MAX_SESSION_BYTES, MAX_SESSION_MESSAGES};
use rustix::fs::OFlags;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::OwnedFd,
    os::unix::{net::UnixStream, process::CommandExt},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub struct NativeMcpProxyClient {
    child: Child,
    stream: McpStream,
    input: File,
    output: File,
    errors: File,
    pump: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    stderr_complete: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    messages: usize,
    bytes: usize,
    events: Vec<Value>,
    closed: bool,
    poisoned: bool,
}
impl NativeMcpProxyClient {
    pub(crate) fn spawn(
        commands: &mut RootCommands,
        cid: &str,
        prefix: &Path,
        family: Family,
    ) -> Result<Self, String> {
        if !crate::hex(cid, 64)
            || !prefix.is_absolute()
            || prefix
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
        {
            return Err("fixed MCP container and installed prefix required".into());
        }
        let args = vec![
            "exec".into(),
            "--interactive".into(),
            cid.into(),
            prefix.join("bin/python").to_string_lossy().into_owned(),
            "-I".into(),
            "-B".into(),
            "/product/public/native_mcp_proxy_v1.py".into(),
            family.name().into(),
        ];
        Self::spawn_process("/usr/bin/podman", &args, commands.mcp_logs()?)
    }
    fn spawn_process(path: &str, args: &[String], logs: [File; 3]) -> Result<Self, String> {
        let [input, output, errors] = logs;
        let (socket, child_socket) = UnixStream::pair().map_err(|e| e.to_string())?;
        let child_input: OwnedFd = child_socket.try_clone().map_err(|e| e.to_string())?.into();
        let child_output: OwnedFd = child_socket.into();
        let stream = McpStream::new(socket).map_err(|e| e.to_string())?;
        let mut error_log = errors.try_clone().map_err(|e| e.to_string())?;
        let mut command = Command::new(path);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("HOME", "/root")
            .env("TMPDIR", "/var/tmp")
            .stdin(Stdio::from(child_input))
            .stdout(Stdio::from(child_output))
            .stderr(Stdio::piped());
        // SAFETY: fixed async-signal-safe syscall; no candidate code as Root.
        unsafe {
            command.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        let pipe: OwnedFd = child
            .stderr
            .take()
            .ok_or("MCP helper stderr absent")?
            .into();
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let stderr_complete = Arc::new(AtomicBool::new(false));
        let mut owner = Self {
            child,
            stream,
            input,
            output,
            errors,
            pump: None,
            stop: stop.clone(),
            stderr_complete: stderr_complete.clone(),
            failure: failure.clone(),
            messages: 0,
            bytes: 0,
            events: Vec::new(),
            closed: false,
            poisoned: false,
        };
        let configured = (|| {
            let flags = rustix::fs::fcntl_getfl(&pipe).map_err(|e| e.to_string())?;
            rustix::fs::fcntl_setfl(&pipe, flags | OFlags::NONBLOCK).map_err(|e| e.to_string())
        })();
        if let Err(error) = configured {
            owner.close()?;
            return Err(error);
        }
        owner.pump = Some(std::thread::spawn(move || {
            let result = (|| -> Result<(), String> {
                let mut buffer = [0; 8192];
                let mut bytes = 0u64;
                while !stop.load(Ordering::Acquire) {
                    match rustix::io::read(&pipe, &mut buffer) {
                        Ok(0) => {
                            stderr_complete.store(true, Ordering::Release);
                            break;
                        }
                        Ok(n) => {
                            if bytes + n as u64 > LIMIT {
                                return Err("MCP stderr bound; retained prefix incomplete".into());
                            }
                            error_log
                                .write_all(&buffer[..n])
                                .map_err(|e| e.to_string())?;
                            bytes += n as u64;
                        }
                        Err(rustix::io::Errno::AGAIN) => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(rustix::io::Errno::INTR) => {}
                        Err(e) => return Err(e.to_string()),
                    }
                }
                error_log.sync_all().map_err(|e| e.to_string())
            })();
            if let Err(error) = result {
                if let Ok(mut slot) = failure.lock() {
                    *slot = Some(error);
                }
            }
        }));
        Ok(owner)
    }
    fn check(&self) -> Result<(), String> {
        if self.poisoned || self.closed {
            return Err("MCP proxy client closed or poisoned".into());
        }
        if let Some(error) = self
            .failure
            .lock()
            .map_err(|_| "MCP stderr observer panicked")?
            .as_ref()
        {
            return Err(error.clone());
        }
        Ok(())
    }
    fn retain(&mut self, input: bool, raw: &[u8]) -> Result<(), String> {
        self.messages += 1;
        self.bytes = self
            .bytes
            .checked_add(raw.len())
            .ok_or("MCP capture byte overflow")?;
        if self.messages > MAX_SESSION_MESSAGES || self.bytes > MAX_SESSION_BYTES {
            return Err("MCP combined capture budget exhausted".into());
        }
        let file = if input {
            &mut self.input
        } else {
            &mut self.output
        };
        file.write_all(raw)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        self.events.push(json!({"sequence":self.events.len()+1,"kind":if input {"input-attempt"} else {"output-read"},
            "bytes":raw.len(),"sha256":format!("{:x}",Sha256::digest(raw))}));
        Ok(())
    }
    pub fn write_frame(
        &mut self,
        raw: &[u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let result = (|| {
            self.check()?;
            self.retain(true, raw)?;
            self.stream
                .write_frame(raw, deadline, cancel)
                .map_err(|e| e.to_string())?;
            self.check()?;
            self.events.push(
                json!({"sequence":self.events.len()+1,"kind":"input-written",
                "sha256":format!("{:x}",Sha256::digest(raw))}),
            );
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn read_frame(
        &mut self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Option<Vec<u8>>, String> {
        let result = (|| {
            self.check()?;
            let raw = self
                .stream
                .read_frame(deadline, cancel)
                .map_err(|e| e.to_string())?;
            if let Some(raw) = &raw {
                self.retain(false, raw)?;
            }
            self.check()?;
            Ok(raw)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn poll(&mut self) -> Result<Option<ExitStatus>, String> {
        self.check()?;
        self.child.try_wait().map_err(|e| e.to_string())
    }
    pub fn finish(&mut self, deadline: Instant, cancel: &AtomicBool) -> Result<Value, String> {
        self.stream
            .socket()
            .shutdown(std::net::Shutdown::Write)
            .map_err(|e| e.to_string())?;
        let status = loop {
            self.check()?;
            if let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                self.close()?;
                return Err("MCP helper completion deadline/cancellation".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        while !self.stderr_complete.load(Ordering::Acquire) {
            self.check()?;
            if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                self.close()?;
                return Err("MCP stderr drain incomplete".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.close()?;
        let mut stderr = Vec::new();
        self.errors
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        (&mut self.errors)
            .take(LIMIT + 1)
            .read_to_end(&mut stderr)
            .map_err(|e| e.to_string())?;
        if stderr.len() as u64 > LIMIT {
            return Err("MCP final stderr bound".into());
        }
        Ok(
            json!({"exit_code":status.code(),"stderr_sha256":format!("{:x}",Sha256::digest(&stderr)),
            "stderr":String::from_utf8_lossy(&stderr),"client":self.observation()}),
        )
    }
    pub fn close(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        let _ = self.stream.socket().shutdown(std::net::Shutdown::Both);
        if self.child.try_wait().map_err(|e| e.to_string())?.is_none() {
            self.child.kill().map_err(|e| e.to_string())?;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().map_err(|e| e.to_string())?.is_none() {
            if Instant::now() >= deadline {
                return Err("MCP helper reap uncertain".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.stop.store(true, Ordering::Release);
        if let Some(pump) = self.pump.take() {
            pump.join().map_err(|_| "MCP stderr observer panicked")?;
        }
        for file in [&self.input, &self.output, &self.errors] {
            file.sync_all().map_err(|e| e.to_string())?;
        }
        self.closed = true;
        if let Some(error) = self
            .failure
            .lock()
            .map_err(|_| "MCP observer mutex poisoned")?
            .as_ref()
        {
            return Err(error.clone());
        }
        Ok(())
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-mcp-proxy-client.v1","host_exec_pid":self.child.id(),
            "events":self.events,"messages":self.messages,"bytes":self.bytes,"poisoned":self.poisoned,
            "host_client_reaped":self.closed,"product_process_drained":false,
            "stderr_complete":self.stderr_complete.load(Ordering::Acquire),
            "guard_causality_verified":false,"execution_eligible":false})
    }
}
impl Drop for NativeMcpProxyClient {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
#[path = "native_mcp_proxy_client_tests.rs"]
mod tests;
