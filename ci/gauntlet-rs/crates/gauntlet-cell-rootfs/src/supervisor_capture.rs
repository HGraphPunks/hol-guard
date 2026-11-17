//! Root checks measured gates and actual retirement around authenticated RPCs.
use crate::supervisor_capture_input::CaptureInput;
use crate::{NativeCell, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedProcess {
    pub returncode: i64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessChunk {
    pub returncode: Option<i64>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_eof: bool,
    pub stderr_eof: bool,
    pub output_bytes: u64,
}

impl ProcessChunk {
    fn validate_after(&self, previous: u64) -> Result<()> {
        if previous.checked_add((self.stdout.len() + self.stderr.len()) as u64)
            != Some(self.output_bytes)
        {
            return Err("product stream cumulative byte count differs".into());
        }
        Ok(())
    }
}

fn parse_chunk(reply: &Value) -> Result<ProcessChunk> {
    if !exact(
        reply,
        &[
            "stdout",
            "stderr",
            "returncode",
            "stdout_eof",
            "stderr_eof",
            "output_bytes",
        ],
    ) {
        return Err("exact product stream result required".into());
    }
    let decode = |name: &str| -> Result<Vec<u8>> {
        let text = reply[name]
            .as_str()
            .filter(|s| s.len() <= 131072)
            .ok_or("bounded product stream encoding required")?;
        let raw = STANDARD
            .decode(text)
            .map_err(|_| "invalid product stream base64")?;
        if raw.len() > 65536 {
            return Err("product stream chunk exceeds bound".into());
        }
        Ok(raw)
    };
    let code = if reply["returncode"].is_null() {
        None
    } else {
        Some(
            reply["returncode"]
                .as_i64()
                .filter(|n| (-255..=255).contains(n))
                .ok_or("bounded product exit code required")?,
        )
    };
    Ok(ProcessChunk {
        returncode: code,
        stdout: decode("stdout")?,
        stderr: decode("stderr")?,
        stdout_eof: reply["stdout_eof"]
            .as_bool()
            .ok_or("stdout EOF must be boolean")?,
        stderr_eof: reply["stderr_eof"]
            .as_bool()
            .ok_or("stderr EOF must be boolean")?,
        output_bytes: reply["output_bytes"]
            .as_u64()
            .filter(|n| *n <= 8 * 1024 * 1024)
            .ok_or("bounded product output byte count required")?,
    })
}

fn exact(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|v| v.len() == keys.len() && keys.iter().all(|k| v.contains_key(*k)))
}

impl NativeCell {
    fn operation_failed(&mut self, error: String) -> String {
        let _ = self
            .journal
            .append("operation-failure", json!({"error":error}));
        match self.close() {
            Ok(()) => error,
            Err(cleanup) => format!("{error}; cleanup uncertain: {cleanup}"),
        }
    }

    pub fn spawn(&mut self, argv: &[String], deadline: Instant) -> Result<String> {
        let result = (|| {
            self.recheck_image_interpreter()?;
            gauntlet_product_cell::validate_product_argv(argv).map_err(|e| e.to_string())?;
            if self.children.len() >= 64 {
                return Err("Root active product process bound".into());
            }
            let child_pipes = self
                .children
                .values()
                .flat_map(|child| {
                    child.observation()["fds"]
                        .as_object()
                        .into_iter()
                        .flat_map(|fds| {
                            fds.values()
                                .filter_map(|value| value.as_str().map(str::to_owned))
                        })
                })
                .collect();
            let actor = self
                .actor
                .as_ref()
                .ok_or("outside actor identity unavailable")?
                .recheck_actor(&child_pipes)?;
            self.journal.append("actor-rechecked", actor)?;
            let value = self.call("spawn", &json!({"argv":argv}), deadline)?;
            if !exact(&value, &["handle", "local_pid", "gate_ready"]) || value["gate_ready"] != true
            {
                return Err("exact product gate reply required".into());
            }
            let handle = value["handle"]
                .as_str()
                .filter(|s| {
                    uuid::Uuid::parse_str(s)
                        .ok()
                        .is_some_and(|id| id.to_string() == *s && id.get_version_num() == 4)
                })
                .ok_or("owned product handle required")?
                .to_owned();
            let local = value["local_pid"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n > 1)
                .ok_or("positive product child namespace PID required")?;
            if self.children.contains_key(&handle) {
                return Err("replayed product process handle".into());
            }
            let process = self.find(self.child_expectation(local, argv)?)?;
            self.journal.append(
                "gated-product-process",
                json!({"handle":handle,"identity":process.observation()}),
            )?;
            self.children.insert(handle.clone(), process);
            self.output_counts.insert(handle.clone(), 0);
            Ok(handle)
        })();
        result.map_err(|e| self.operation_failed(e))
    }

    pub fn release(&mut self, handle: &str, deadline: Instant) -> Result<()> {
        let result = (|| {
            self.recheck_image_interpreter()?;
            self.children
                .get(handle)
                .ok_or("foreign product handle")?
                .recheck()?;
            let reply = self.call("release", &json!({"handle":handle}), deadline)?;
            if reply != json!({"released":true}) {
                return Err("product release acknowledgement differs".into());
            }
            self.journal
                .append("product-release", json!({"handle":handle}))
        })();
        result.map_err(|e| self.operation_failed(e))
    }

    pub fn retire(&mut self, handle: &str, deadline: Instant) -> Result<()> {
        let result = (|| {
            let process = self.children.get(handle).ok_or("foreign product handle")?;
            if process.is_alive()? {
                return Err("owned product process survived terminal reply".into());
            }
            let pid = process.observation()["pid"].clone();
            let reply = self.call("retire", &json!({"handle":handle}), deadline)?;
            if reply != json!({"retired":true}) {
                return Err("product retirement acknowledgement differs".into());
            }
            self.children.remove(handle);
            self.output_counts.remove(handle);
            self.journal.append(
                "retired-product-process",
                json!({"handle":handle,"pid":pid}),
            )
        })();
        result.map_err(|e| self.operation_failed(e))
    }

    pub fn end_input(&mut self, handle: &str, deadline: Instant) -> Result<()> {
        let result = (|| {
            if !self.children.contains_key(handle) {
                return Err("foreign product handle".into());
            }
            if self.call("end_input", &json!({"handle":handle}), deadline)?
                != json!({"stdin_closed":true})
            {
                return Err("product input close acknowledgement differs".into());
            }
            Ok(())
        })();
        result.map_err(|e| self.operation_failed(e))
    }

    pub fn read_process(
        &mut self,
        handle: &str,
        wait_ms: u64,
        deadline: Instant,
    ) -> Result<ProcessChunk> {
        let result = (|| {
            if !self.children.contains_key(handle) || wait_ms > 100 {
                return Err("owned bounded product read required".into());
            }
            let reply = self.call(
                "read",
                &json!({"handle":handle,"wait_ms":wait_ms}),
                deadline,
            )?;
            let chunk = match parse_chunk(&reply) {
                Ok(chunk) => chunk,
                Err(error) => {
                    self.journal.append(
                        "invalid-read-response",
                        json!({"handle":handle,"reply":reply}),
                    )?;
                    return Err(error);
                }
            };
            let previous = *self
                .output_counts
                .get(handle)
                .ok_or("owned product output count required")?;
            if let Err(error) = chunk.validate_after(previous) {
                self.journal.append(
                    "invalid-read-response",
                    json!({"handle":handle,"previous":previous,"reply":reply}),
                )?;
                return Err(error);
            }
            self.output_counts
                .insert(handle.to_owned(), chunk.output_bytes);
            if !chunk.stdout.is_empty() || !chunk.stderr.is_empty() || chunk.returncode.is_some() {
                self.journal
                    .append("product-stream", json!({"handle":handle,"chunk":reply}))?;
            }
            Ok(chunk)
        })();
        result.map_err(|e| self.operation_failed(e))
    }

    pub fn capture(
        &mut self,
        argv: &[String],
        raw: &[u8],
        timeout: Duration,
    ) -> Result<CapturedProcess> {
        self.capture_observed(argv, raw, timeout, |_, _| Ok(()))
    }

    pub(crate) fn capture_observed(
        &mut self,
        argv: &[String],
        raw: &[u8],
        timeout: Duration,
        mut observe: impl FnMut(&NativeCell, &str) -> Result<()>,
    ) -> Result<CapturedProcess> {
        if raw.len() > 8 * 1024 * 1024
            || timeout.is_zero()
            || timeout > Duration::from_secs(self.spec.wall_seconds.min(930))
        {
            return Err("bounded product capture input/deadline required".into());
        }
        let deadline = Instant::now() + timeout;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut input = CaptureInput::new(argv, raw)?;
        let result: Result<i64> = (|| {
            if self.cancelled.load(Ordering::Acquire) {
                return Err("product capture cancelled before admission".into());
            }
            let handle = self.spawn(argv, deadline)?;
            self.journal
                .append("capture-input-bound", input.bind(&handle)?)?;
            self.release(&handle, deadline)?;
            let mut offset = 0usize;
            let mut ended = false;
            loop {
                if self.cancelled.load(Ordering::Acquire) {
                    return Err("product capture cancelled".into());
                }
                if Instant::now() >= deadline {
                    return Err("product capture deadline exceeded".into());
                }
                observe(self, &handle)?;
                if offset < raw.len() {
                    let count = (raw.len() - offset).min(65536);
                    let reply=self.call("write",&json!({"handle":handle,"data":STANDARD.encode(&raw[offset..offset+count])}),deadline)?;
                    let written = reply["written"]
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                        .filter(|n| *n <= count)
                        .ok_or("bounded actual product input write required")?;
                    if !exact(&reply, &["written"]) {
                        return Err("exact product write result required".into());
                    }
                    input.delivered(&raw[offset..offset + written])?;
                    offset += written;
                } else if !ended {
                    if self.call("end_input", &json!({"handle":handle}), deadline)?
                        != json!({"stdin_closed":true})
                    {
                        return Err("product input close acknowledgement differs".into());
                    }
                    input.closed()?;
                    ended = true;
                }
                let chunk =
                    self.read_process(&handle, if offset < raw.len() { 0 } else { 100 }, deadline)?;
                stdout.extend_from_slice(&chunk.stdout);
                stderr.extend_from_slice(&chunk.stderr);
                if stdout.len().saturating_add(stderr.len()) > 8 * 1024 * 1024 {
                    return Err("product capture output byte bound".into());
                }
                if let Some(code) = chunk.returncode {
                    if chunk.stdout_eof && chunk.stderr_eof {
                        if offset != raw.len() {
                            return Err(
                                "product exited before all bound input was delivered".into()
                            );
                        }
                        if !ended {
                            self.end_input(&handle, deadline)?;
                            input.closed()?;
                        }
                        self.retire(&handle, deadline)?;
                        return Ok(code);
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        })();
        let result = match self
            .journal
            .append("capture-input-terminal", input.observation())
        {
            Ok(()) => result,
            Err(error) => Err(match result {
                Ok(_) => format!("capture input custody uncertain: {error}"),
                Err(prior) => format!("{prior}; capture input custody uncertain: {error}"),
            }),
        };
        match result {
            Ok(code) => {
                self.journal
                    .capture(argv, &stdout, &stderr, Some(code), None)?;
                Ok(CapturedProcess {
                    returncode: code,
                    stdout,
                    stderr,
                })
            }
            Err(error) => {
                let retained = self
                    .journal
                    .capture(argv, &stdout, &stderr, None, Some(&error));
                let error = self.operation_failed(error);
                match retained {
                    Ok(()) => Err(error),
                    Err(e) => Err(format!("{error}; partial output custody uncertain: {e}")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_streams_and_exact_typed_terminal_fields_are_preserved() {
        let raw = [0, 255, 10];
        // Field names and counter match the actor's actual `read` response.
        let mut value = json!({"stdout":STANDARD.encode(raw),"stderr":"","returncode":null,"stdout_eof":false,"stderr_eof":false,"output_bytes":3});
        let chunk = parse_chunk(&value).unwrap();
        assert_eq!(chunk.stdout, raw);
        assert!(chunk.validate_after(0).is_ok());
        assert!(chunk.validate_after(1).is_err());
        for (field, bad) in [
            ("stdout", json!("%%%")),
            ("stdout_eof", json!(1)),
            ("returncode", json!(true)),
            ("returncode", json!(256)),
            ("output_bytes", json!(true)),
            ("output_bytes", json!(-1)),
            ("output_bytes", json!(8388609)),
            ("extra", json!(false)),
        ] {
            let mut changed = value.clone();
            changed[field] = bad;
            assert!(parse_chunk(&changed).is_err(), "{field}");
        }
        value["returncode"] = json!(-9);
        value["stdout_eof"] = json!(true);
        value["stderr_eof"] = json!(true);
        assert_eq!(parse_chunk(&value).unwrap().returncode, Some(-9));
    }
}
