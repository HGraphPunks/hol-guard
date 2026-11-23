//! The same eight bounded operations as the Python unprivileged cell actor.
use crate::actor_process::{exit_code, handle, ProductProcess};
use crate::{validate_product_argv, CellError, CellLayout, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::time::{Duration, Instant};

const INVALID: CellError = CellError("exact bounded owned product process fields required");
pub(crate) struct Actor {
    children: BTreeMap<String, ProductProcess>,
    spawns: usize,
    orphans_reaped: usize,
    layout: CellLayout,
}
fn fields(payload: &Value, names: &[&str]) -> bool {
    payload
        .as_object()
        .is_some_and(|o| o.len() == names.len() && names.iter().all(|key| o.contains_key(*key)))
}
fn key<'a>(payload: &'a Value, names: &[&str]) -> Result<&'a str> {
    if !fields(payload, names) {
        return Err(INVALID);
    }
    payload["handle"].as_str().ok_or(INVALID)
}
impl Actor {
    pub(crate) fn new(layout: CellLayout) -> Self {
        Self {
            children: BTreeMap::new(),
            spawns: 0,
            orphans_reaped: 0,
            layout,
        }
    }
    fn spawn(&mut self, payload: &Value) -> Result<Value> {
        if !fields(payload, &["argv"]) || self.children.len() >= 64 || self.spawns >= 1024 {
            return Err(INVALID);
        }
        let argv = payload["argv"]
            .as_array()
            .ok_or(INVALID)?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or(INVALID))
            .collect::<Result<Vec<_>>>()?;
        validate_product_argv(&argv)?;
        self.spawns += 1;
        let id = handle()?;
        self.children
            .insert(id.clone(), ProductProcess::spawn(&argv, self.layout)?);
        let process = self.children.get_mut(&id).ok_or(INVALID)?;
        process.ready()?;
        Ok(json!({"handle":id,"local_pid":process.child.id(),"gate_ready":true}))
    }
    pub(crate) fn reap(&mut self) -> Result<()> {
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid == 0 {
                return Ok(());
            }
            if pid < 0 {
                return match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::ECHILD) => Ok(()),
                    Some(libc::EINTR) => continue,
                    _ => Err(CellError("product child reap failed")),
                };
            }
            if let Some(process) = self
                .children
                .values_mut()
                .find(|child| child.child.id() == pid as u32)
            {
                if process.returncode.is_some() {
                    return Err(CellError("product child reaped twice"));
                }
                process.returncode = Some(exit_code(status)?);
            } else {
                self.orphans_reaped = self.orphans_reaped.saturating_add(1);
            }
        }
    }
    fn close(&mut self, payload: &Value) -> Result<Value> {
        if !fields(payload, &[]) {
            return Err(INVALID);
        }
        self.reap()?;
        // This actor owns every wait; its signal handlers never reap a PID.
        for process in self.children.values_mut() {
            if process.returncode.is_none()
                && unsafe { libc::kill(process.child.id() as i32, libc::SIGKILL) } != 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(CellError("product child stop uncertain"));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            self.reap()?;
            if self.children.values().all(|p| p.returncode.is_some()) {
                break;
            }
            if Instant::now() >= deadline {
                return Err(CellError(
                    "product child wait uncertain; outside cleanup required",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.children.clear();
        Ok(json!({"closed":true,"outside_descendant_cleanup_required":true}))
    }
    pub(crate) fn call(&mut self, operation: &str, payload: &Value) -> Result<Value> {
        self.reap()?;
        match operation {
            "hello" => {
                if !fields(payload, &[]) {
                    return Err(INVALID);
                }
                Ok(
                    json!({"schema":"product-cell-actor.v2","local_pid":unsafe{libc::getpid()},
                    "uid":unsafe{libc::getuid()},"gid":unsafe{libc::getgid()},
                    "limits":{"active_children":64,"total_spawns":1024,"read_wait_ms":100}}),
                )
            }
            "spawn" => self.spawn(payload),
            "release" => {
                self.children
                    .get_mut(key(payload, &["handle"])?)
                    .ok_or(INVALID)?
                    .release()?;
                Ok(json!({"released":true}))
            }
            "write" => {
                let item = self
                    .children
                    .get_mut(key(payload, &["handle", "data"])?)
                    .ok_or(INVALID)?;
                let encoded = payload["data"]
                    .as_str()
                    .filter(|s| s.len() <= 350000)
                    .ok_or(INVALID)?;
                if !item.released {
                    return Err(INVALID);
                }
                let data = STANDARD.decode(encoded).map_err(|_| INVALID)?;
                if data.len() > 256 * 1024
                    || item.input_bytes.saturating_add(data.len()) > 8 * 1024 * 1024
                {
                    return Err(INVALID);
                }
                let pipe = item.child.stdin.as_mut().ok_or(INVALID)?;
                let count = if data.is_empty() {
                    0
                } else {
                    match pipe.write(&data) {
                        Ok(n) => n,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
                        Err(_) => return Err(INVALID),
                    }
                };
                item.input_bytes += count;
                Ok(json!({"written":count}))
            }
            "end_input" => {
                let item = self
                    .children
                    .get_mut(key(payload, &["handle"])?)
                    .ok_or(INVALID)?;
                if !item.released {
                    return Err(INVALID);
                }
                item.child.stdin.take();
                Ok(json!({"stdin_closed":true}))
            }
            "read" => {
                let names = if payload.get("wait_ms").is_some() {
                    vec!["handle", "wait_ms"]
                } else {
                    vec!["handle"]
                };
                let wait = payload
                    .get("wait_ms")
                    .map(|v| v.as_u64().filter(|n| *n <= 100).ok_or(INVALID))
                    .transpose()?
                    .unwrap_or(0);
                let item = self
                    .children
                    .get_mut(key(payload, &names)?)
                    .ok_or(INVALID)?;
                let (stdout, stderr) = item.read_output(wait)?;
                Ok(
                    json!({"stdout":STANDARD.encode(stdout),"stderr":STANDARD.encode(stderr),"stdout_eof":item.stdout_eof,
                    "stderr_eof":item.stderr_eof,"returncode":item.returncode,"output_bytes":item.output_bytes}),
                )
            }
            "retire" => {
                let id = key(payload, &["handle"])?;
                let item = self.children.get(id).ok_or(INVALID)?;
                if !item.released
                    || item.returncode.is_none()
                    || !item.stdout_eof
                    || !item.stderr_eof
                {
                    return Err(INVALID);
                }
                self.children.remove(id);
                Ok(json!({"retired":true}))
            }
            "close" => self.close(payload),
            _ => Err(INVALID),
        }
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        if !self.children.is_empty() {
            let _ = self.close(&json!({}));
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_operations_cannot_spawn_or_select_an_unowned_process() {
        let mut actor = Actor::new(CellLayout::default());
        for (name, payload) in [
            ("spawn", json!({"argv":["relative"]})),
            ("spawn", json!({"argv":[],"extra":true})),
            ("read", json!({"handle":"unknown","wait_ms":true})),
            ("write", json!({"handle":"unknown","data":"YQ=="})),
            ("release", json!({"handle":"unknown"})),
            ("close", json!({"extra":true})),
        ] {
            if name == "spawn" {
                assert!(actor.spawn(&payload).is_err());
            } else {
                assert!(
                    key(&payload, &["handle"]).is_err()
                        || !actor
                            .children
                            .contains_key(payload["handle"].as_str().unwrap_or(""))
                );
            }
        }
        assert_eq!(actor.spawns, 0);
        assert!(actor.children.is_empty());
    }
}
