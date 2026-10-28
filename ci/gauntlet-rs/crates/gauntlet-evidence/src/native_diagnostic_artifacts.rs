//! Bounded public bytes and capture chains. Custody belongs to the host reader;
//! this relation checker never turns a controller claim into qualification.
use crate::crypto::sha256;
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(EvidenceError::Invalid(
            "Native diagnostic artifact relation differs",
        ))
    }
}
pub(crate) fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(EvidenceError::Invalid("Native diagnostic string missing"))
}
pub(crate) fn parse(raw: &[u8]) -> Result<Value> {
    let bytes = gauntlet_contracts::canonicalize(raw)
        .map_err(|_| EvidenceError::Invalid("invalid Native diagnostic JSON"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| EvidenceError::Invalid("invalid Native diagnostic JSON"))
}
pub(crate) fn digest(v: &Value) -> Result<String> {
    Ok(sha256(&canonical_value(v)?))
}
pub(crate) fn ineligible(v: &Value) -> Result<()> {
    require(
        v["execution_eligible"] == false
            && v["guard_causality_verified"] == false
            && v["model_requests"].as_u64() == Some(0),
    )
}
pub(crate) fn argv(v: &Value) -> Result<Vec<String>> {
    let values = v
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 64)
        .ok_or(EvidenceError::Invalid("bounded Native argv required"))?;
    values
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty() && s.len() <= 16_384 && !s.contains('\0'))
                .map(str::to_owned)
                .ok_or(EvidenceError::Invalid("invalid Native argv argument"))
        })
        .collect()
}
pub(crate) fn guard_argv(prefix: &str, tail: &[&str]) -> Vec<String> {
    let mut result = vec![
        format!("{prefix}/bin/python"),
        "-I".into(),
        "-B".into(),
        "-m".into(),
        "codex_plugin_scanner.cli".into(),
        "guard".into(),
    ];
    result.extend(tail.iter().map(|v| (*v).to_owned()));
    result
}
pub(crate) fn request_argv(prefix: &str, path: &str, pin: &str) -> Vec<String> {
    guard_argv(
        prefix,
        &[
            "execute-contained-test",
            "--harness",
            "omp",
            "--guard-home",
            "/product/guard",
            "--home",
            "/runtime/home",
            "--workspace",
            "/runtime/home/project",
            "--request-file",
            path,
            "--request-sha256",
            pin,
            "--timeout-seconds",
            "5",
        ],
    )
}
pub(crate) fn handoff(v: &Value, raw: &[u8]) -> Result<()> {
    let path = text(v, "path")?;
    let nonce = path
        .strip_prefix("/product/home/hol-guard-contained-test-")
        .and_then(|s| s.strip_suffix("/request.json"))
        .ok_or(EvidenceError::Invalid("fixed Native request path required"))?;
    require(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && v["schema"] == "hol-gauntlet-native-contained-request.v1"
            && v["uid"].as_u64() == Some(10004)
            && v["gid"].as_u64() == Some(10004)
            && v["device"].as_u64().is_some_and(|n| n > 0)
            && v["inode"].as_u64().is_some_and(|n| n > 0)
            && v["bytes"].as_u64() == Some(raw.len() as u64)
            && v["sha256"] == sha256(raw),
    )
}

pub(crate) struct Artifacts<'a> {
    files: &'a BTreeMap<String, Vec<u8>>,
    index: Value,
    pub(crate) events: Vec<Value>,
}
pub(crate) struct Capture<'a> {
    pub(crate) sequence: usize,
    pub(crate) stdout: &'a [u8],
    pub(crate) stderr: &'a [u8],
}
impl<'a> Artifacts<'a> {
    pub(crate) fn new(files: &'a BTreeMap<String, Vec<u8>>) -> Result<Self> {
        require(
            !files.is_empty()
                && files.len() <= 2048
                && files.values().all(|v| v.len() <= 32 * 1024 * 1024)
                && files.values().map(Vec::len).sum::<usize>() <= 128 * 1024 * 1024,
        )?;
        let index = parse(
            files
                .get("results.sha256.json")
                .ok_or(EvidenceError::Invalid("public diagnostic index missing"))?,
        )?;
        require(
            index["execution_eligible"] == false
                && index["model_requests"].as_u64() == Some(0)
                && index["guard_causality_verified"] == false,
        )?;
        let pins = index["files"]
            .as_object()
            .ok_or(EvidenceError::Invalid("diagnostic file inventory missing"))?;
        require(pins.len() + 1 == files.len())?;
        for (name, pin) in pins {
            let raw = files
                .get(name)
                .ok_or(EvidenceError::Invalid("diagnostic member missing"))?;
            require(pin == &json!({"bytes":raw.len(),"sha256":sha256(raw)}))?;
        }
        let mut result = Self {
            files,
            index,
            events: Vec::new(),
        };
        let raw = result.raw("combined/cell/native-supervisor-events.v1.jsonl")?;
        require(raw.ends_with(b"\n"))?;
        let mut previous = "0".repeat(64);
        let mut capture_names = BTreeSet::new();
        for (sequence, line) in raw[..raw.len() - 1].split(|b| *b == b'\n').enumerate() {
            require(sequence < 10_000 && !line.is_empty())?;
            let row = parse(line)?;
            require(
                row["schema"] == "hol-gauntlet-cell-event.v1"
                    && row["sequence"].as_u64() == Some(sequence as u64)
                    && row["previous_sha256"] == previous,
            )?;
            previous = digest(&row)?;
            if row["kind"] == "capture-terminal" {
                let fields = row["data"]["files"]
                    .as_object()
                    .ok_or(EvidenceError::Invalid("capture file inventory missing"))?;
                require(
                    fields.len() == 2
                        && fields.contains_key("stdout")
                        && fields.contains_key("stderr"),
                )?;
                for (stream, pin) in fields {
                    let name = text(pin, "file")?;
                    let nonce = name
                        .strip_prefix("capture-")
                        .and_then(|s| s.strip_suffix(&format!(".{stream}")))
                        .ok_or(EvidenceError::Invalid("invalid capture filename"))?;
                    require(
                        nonce.len() == 32
                            && nonce
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                            && capture_names.insert(name.to_owned()),
                    )?;
                    let bytes = result.raw(&format!("combined/cell/{name}"))?;
                    require(
                        pin["sha256"] == sha256(bytes)
                            && pin["bytes"].as_u64() == Some(bytes.len() as u64),
                    )?;
                }
            }
            result.events.push(row);
        }
        require(!result.events.is_empty())?;
        Ok(result)
    }
    pub(crate) fn raw(&self, name: &str) -> Result<&'a [u8]> {
        self.files
            .get(name)
            .map(Vec::as_slice)
            .ok_or(EvidenceError::Invalid(
                "required public diagnostic bytes missing",
            ))
    }
    pub(crate) fn json(&self, name: &str) -> Result<Value> {
        parse(self.raw(name)?)
    }
    pub(crate) fn unique_process_capture(
        &self,
        prefix: &str,
        out_pin: &str,
        err_pin: &str,
    ) -> Result<(&'a [u8], &'a [u8])> {
        let mut matches = self.files.iter().filter(|(name, raw)| {
            name.starts_with(prefix) && name.ends_with(".stdout") && sha256(raw) == out_pin
        });
        let first = matches
            .next()
            .ok_or(EvidenceError::Invalid("public process capture missing"))?;
        require(matches.next().is_none())?;
        let stderr = self.raw(&format!(
            "{}.stderr",
            first.0.strip_suffix(".stdout").unwrap()
        ))?;
        require(sha256(stderr) == err_pin)?;
        Ok((first.1, stderr))
    }
    pub(crate) fn metadata(&self, name: &str) -> Result<&Value> {
        self.index["filesystem"]
            .get(name)
            .ok_or(EvidenceError::Invalid(
                "physical diagnostic metadata missing",
            ))
    }
    pub(crate) fn capture(
        &self,
        command: &[String],
        code: i64,
        stdout: &str,
        stderr: &str,
        after: Option<usize>,
    ) -> Result<Capture<'a>> {
        let command_pin = sha256(command.join("\0").as_bytes());
        for (sequence, row) in self.events.iter().enumerate() {
            let d = &row["data"];
            if after.is_none_or(|n| sequence > n)
                && row["kind"] == "capture-terminal"
                && d["argv_sha256"] == command_pin
                && d["returncode"].as_i64() == Some(code)
                && d["files"]["stdout"]["sha256"] == stdout
                && d["files"]["stderr"]["sha256"] == stderr
            {
                require(d.get("error").is_some_and(Value::is_null))?;
                return Ok(Capture {
                    sequence,
                    stdout: self.raw(&format!(
                        "combined/cell/{}",
                        text(&d["files"]["stdout"], "file")?
                    ))?,
                    stderr: self.raw(&format!(
                        "combined/cell/{}",
                        text(&d["files"]["stderr"], "file")?
                    ))?,
                });
            }
        }
        Err(EvidenceError::Invalid(
            "actual Native capture missing or out of order",
        ))
    }
}
