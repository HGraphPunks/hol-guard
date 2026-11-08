//! Independent pipe-journal replay. Caller pins and hash chains do not admit
//! an observer, authenticate physical writers, or establish Guard causality.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{parse, require, text};
use crate::native_process_kernel::{decimal, hex, number};
use crate::payload::exact_keys;
use crate::{canonical_value, EvidenceError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const CONNECTOR: &[u8] = b"/public/gauntlet-product-cell";
struct Session {
    phase: u8,
    wrapper: Value,
    gate: Value,
    gate_event: usize,
    pipes: [[u64; 2]; 4],
    exec: Option<usize>,
    read: [Vec<u8>; 2],
    written: [usize; 2],
    eof: [bool; 2],
}
fn integer(value: &Value) -> Result<usize> {
    value
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(EvidenceError::Invalid("Native pipe integer required"))
}
fn command(image: &Value) -> Result<Vec<Vec<u8>>> {
    let raw = crate::native_runtime_trace::command_bytes(image)?;
    Ok(raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(<[u8]>::to_vec)
        .collect())
}
fn config(value: &Value) -> Result<()> {
    require(
        exact_keys(
            value,
            &["schema", "endpoint", "native_program", "native_sha256"],
        ) && value["schema"] == "product-cell-native-wire.v1",
    )?;
    let endpoint = text(value, "endpoint")?
        .strip_prefix("hol-native-wire-")
        .ok_or(EvidenceError::Invalid("Native pipe endpoint required"))?;
    let program = text(value, "native_program")?;
    require(
        hex(endpoint, 32)
            && hex(text(value, "native_sha256")?, 64)
            && program.len() <= 2048
            && program.bytes().all(|b| b.is_ascii_graphic())
            && program.starts_with("/opt/hol-gauntlet/")
            && program.ends_with(
                "/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime",
            )
            && program[1..]
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != ".."),
    )
}
fn image(events: &[Value], event: usize, observed: &Value, pin: &str, actor: &Value) -> Result<()> {
    let row = events
        .get(event)
        .ok_or(EvidenceError::Invalid("Native pipe exec event missing"))?;
    require(
        row["kind"] == "task-exec"
            && row["data"]["image"] == *observed
            && observed["executable"]["sha256"] == pin
            && observed["namespaces"] == actor["namespaces"]
            && observed["lsm_label"] == actor["lsm_label"]
            && observed["task"]["tid"] == observed["task"]["tgid"]
            && observed["executable"]["uid"] == 0
            && observed["executable"]["gid"] == 0
            && observed["executable"]["links"] == 1
            && observed["executable"]["mode"]
                .as_u64()
                .is_some_and(|v| v & 0o6022 == 0),
    )?;
    crate::native_runtime_trace::floors(&observed["task"])
}
fn pipes(value: &Value) -> Result<[[u64; 2]; 4]> {
    let rows = value
        .as_array()
        .filter(|v| v.len() == 4)
        .ok_or(EvidenceError::Invalid("four Native pipe objects required"))?;
    let mut out = [[0; 2]; 4];
    for (pair, value) in out.iter_mut().zip(rows) {
        let row = value
            .as_array()
            .filter(|v| v.len() == 2)
            .ok_or(EvidenceError::Invalid("Native pipe object pair required"))?;
        pair[0] = row[0]
            .as_u64()
            .ok_or(EvidenceError::Invalid("pipe device required"))?;
        pair[1] = number(&row[1])?;
    }
    require(out.iter().collect::<BTreeSet<_>>().len() == 4)?;
    Ok(out)
}
impl Session {
    fn handoff(data: &Value, events: &[Value], actor: &Value, connector: &str) -> Result<Self> {
        require(
            exact_keys(
                data,
                &[
                    "session",
                    "wrapper",
                    "gate",
                    "wrapper_exec_event",
                    "gate_exec_event",
                    "pipes",
                    "execution_eligible",
                ],
            ) && data["execution_eligible"] == false,
        )?;
        let wrapper_event = integer(&data["wrapper_exec_event"])?;
        let gate_event = integer(&data["gate_exec_event"])?;
        let wrapper = &data["wrapper"];
        let gate = &data["gate"];
        image(events, wrapper_event, wrapper, connector, actor)?;
        image(events, gate_event, gate, connector, actor)?;
        require(
            wrapper_event < gate_event
                && command(wrapper)?.first().map(Vec::as_slice) == Some(CONNECTOR)
                && gate["task"]["parent_pid"] == wrapper["task"]["tid"]
                && events[wrapper_event]["data"]["id"] != events[gate_event]["data"]["id"],
        )?;
        Ok(Self {
            phase: 0,
            wrapper: wrapper.clone(),
            gate: gate.clone(),
            gate_event,
            pipes: pipes(&data["pipes"])?,
            exec: None,
            read: [Vec::new(), Vec::new()],
            written: [0; 2],
            eof: [false; 2],
        })
    }
    fn bind(
        &mut self,
        data: &Value,
        events: &[Value],
        actor: &Value,
        config: &Value,
    ) -> Result<()> {
        require(
            self.phase == 1
                && exact_keys(data, &["session", "process", "stdio_pipes", "exec_event"]),
        )?;
        let event = integer(&data["exec_event"])?;
        let native = &data["process"];
        image(events, event, native, text(config, "native_sha256")?, actor)?;
        let mut expected = vec![text(config, "native_program")?.as_bytes().to_vec()];
        expected.extend_from_slice(&command(&self.wrapper)?[1..]);
        let mut gated = vec![CONNECTOR.to_vec(), b"native-gate".to_vec()];
        gated.extend_from_slice(&expected);
        require(
            event > self.gate_event
                && command(&self.gate)? == gated
                && command(native)? == expected
                && events[event]["data"]["id"] == events[self.gate_event]["data"]["id"]
                && native["task"]["tid"] == self.gate["task"]["tid"]
                && native["task"]["start_ticks"] == self.gate["task"]["start_ticks"]
                && data["stdio_pipes"] == json!([self.pipes[1], self.pipes[2]]),
        )?;
        // A replacement exec is an ending, never the original Native process's
        // death. A complete v1 session requires its actual final wait.
        let id = &events[event]["data"]["id"];
        let end = events
            .iter()
            .skip(event + 1)
            .find(|r| {
                (r["kind"] == "task-final-wait" || r["kind"] == "task-exec")
                    && r["data"]["id"] == *id
            })
            .ok_or(EvidenceError::Invalid("Native pipe final wait missing"))?;
        require(end["kind"] == "task-final-wait")?;
        self.exec = Some(event);
        self.phase = 2;
        Ok(())
    }
    fn bytes(&mut self, data: &Value, total: &mut usize) -> Result<()> {
        require(self.phase == 2)?;
        let direction = integer(&data["direction"])?;
        require(direction < 2 && !self.eof[direction])?;
        let kind = text(data, "kind")?;
        if kind == "eof" {
            require(
                exact_keys(data, &["session", "kind", "direction", "bytes"])
                    && integer(&data["bytes"])? == self.read[direction].len()
                    && self.written[direction] == self.read[direction].len(),
            )?;
            self.eof[direction] = true;
            return Ok(());
        }
        require(
            matches!(kind, "read" | "write")
                && exact_keys(
                    data,
                    &["session", "kind", "direction", "offset", "bytes_base64"],
                ),
        )?;
        let encoded = text(data, "bytes_base64")?;
        require(!encoded.is_empty() && encoded.len() <= 87_384)?;
        let raw = STANDARD
            .decode(encoded)
            .map_err(|_| EvidenceError::Invalid("Native pipe bytes invalid"))?;
        require(!raw.is_empty() && raw.len() <= 65536 && STANDARD.encode(&raw) == encoded)?;
        let offset = integer(&data["offset"])?;
        if kind == "read" {
            require(
                offset == self.read[direction].len() && *total <= 32 * 1024 * 1024 - raw.len(),
            )?;
            *total += raw.len();
            self.read[direction].extend(raw);
        } else {
            require(
                offset == self.written[direction]
                    && offset <= self.read[direction].len()
                    && raw.len() <= self.read[direction].len() - offset
                    && self.read[direction][offset..offset + raw.len()] == raw,
            )?;
            self.written[direction] += raw.len();
        }
        Ok(())
    }
    fn complete(&mut self, data: &Value) -> Result<()> {
        require(
            self.phase == 2
                && self.eof == [true; 2]
                && exact_keys(
                    data,
                    &[
                        "session",
                        "read",
                        "written",
                        "execution_eligible",
                        "exclusive_product_authorship_verified",
                    ],
                )
                && data["read"] == json!(self.written)
                && data["written"] == data["read"]
                && data["execution_eligible"] == false
                && data["exclusive_product_authorship_verified"] == false,
        )?;
        self.phase = 3;
        Ok(())
    }
}

/// Recompute relations from caller-pinned bytes. Even a complete result grants
/// no signed custody, source/preparation admission, or exclusive writer credit.
pub(crate) fn verify(
    raw: &[u8],
    process_raw: &[u8],
    checkpoint: &Value,
    binding: &Value,
    expected_config: &Value,
    connector: &str,
) -> Result<Value> {
    config(expected_config)?;
    require(hex(connector, 64) && checkpoint["schema"] == "hol-gauntlet-native-process-events.v1")?;
    let process = crate::verify_native_process_events(process_raw, checkpoint)?;
    let events = crate::native_stdio_process::events(process_raw)?;
    let actor = &events[0]["data"]["actor"];
    require(
        actor["executable"]["sha256"] == connector
            && !raw.is_empty()
            && raw.len() <= 64 * 1024 * 1024
            && raw.ends_with(b"\n")
            && exact_keys(
                binding,
                &[
                    "schema",
                    "available",
                    "events",
                    "bytes",
                    "tail_sha256",
                    "device",
                    "inode",
                    "uid",
                    "gid",
                    "mode",
                    "links",
                ],
            )
            && binding["schema"] == "hol-gauntlet-cell-journal-binding.v1"
            && binding["available"] == true
            && binding["bytes"].as_u64() == Some(raw.len() as u64)
            && binding["uid"] == 0
            && binding["gid"] == 0
            && binding["mode"] == 0o600
            && binding["links"] == 1,
    )?;
    number(&binding["device"])?;
    number(&binding["inode"])?;
    let mut previous = "0".repeat(64);
    let mut sessions = BTreeMap::<usize, Session>::new();
    let mut joined = BTreeSet::new();
    let mut closed = false;
    let mut total = 0;
    let mut count = 0;
    for (sequence, line) in raw[..raw.len() - 1].split(|b| *b == b'\n').enumerate() {
        require(!closed && sequence < 65536 && !line.is_empty() && line.len() <= 256 * 1024)?;
        let row = parse(line)?;
        require(
            exact_keys(
                &row,
                &["schema", "sequence", "previous_sha256", "kind", "data"],
            ) && row["schema"] == "hol-gauntlet-cell-event.v1"
                && row["sequence"].as_u64() == Some(sequence as u64)
                && row["previous_sha256"] == previous
                && canonical_value(&row)? == line,
        )?;
        previous = sha256(line);
        count += 1;
        let data = &row["data"];
        let kind = text(&row, "kind")?;
        if sequence == 0 {
            require(
                kind == "native-pipe-owner-started"
                    && exact_keys(
                        data,
                        &[
                            "schema",
                            "config",
                            "actor",
                            "kernel_pipe_bytes",
                            "execution_eligible",
                            "exclusive_product_authorship_verified",
                        ],
                    )
                    && data["schema"] == "hol-gauntlet-native-pipes.v1"
                    && data["config"] == *expected_config
                    && data["actor"]["argv"] == json!(["/public/gauntlet-product-cell", "actor"])
                    && data["kernel_pipe_bytes"] == true
                    && data["execution_eligible"] == false
                    && data["exclusive_product_authorship_verified"] == false,
            )?;
            crate::native_process_trace_diagnostic::matches_image(
                actor,
                &data["actor"],
                decimal(text(&actor["task"]["status"], "TracerPid")?)?,
            )?;
            continue;
        }
        if kind == "native-pipe-owner-closed" {
            require(
                exact_keys(data, &["sessions", "execution_eligible"])
                    && integer(&data["sessions"])? == sessions.len()
                    && data["execution_eligible"] == false
                    && sessions.values().all(|s| s.phase == 3)
                    && sessions.keys().copied().eq(0..sessions.len()),
            )?;
            closed = true;
            continue;
        }
        let id = integer(&data["session"])?;
        require(id < 1024)?;
        if kind == "native-pipe-handoff" {
            require(
                !sessions.contains_key(&id)
                    && sessions.values().filter(|s| s.phase < 3).count() < 16,
            )?;
            let new = Session::handoff(data, &events, actor, connector)?;
            require(
                sessions
                    .values()
                    .filter(|s| s.phase < 3)
                    .all(|s| s.pipes.iter().all(|p| !new.pipes.contains(p))),
            )?;
            sessions.insert(id, new);
            continue;
        }
        let session = sessions
            .get_mut(&id)
            .ok_or(EvidenceError::Invalid("Native pipe session missing"))?;
        match kind {
            "native-pipe-sender-closed" => {
                require(
                    session.phase == 0
                        && exact_keys(data, &["session", "all_four_sender_copies_absent"])
                        && data["all_four_sender_copies_absent"] == true,
                )?;
                session.phase = 1;
            }
            "native-pipe-exec-bound" => {
                session.bind(data, &events, actor, expected_config)?;
                require(joined.insert(session.exec.unwrap()))?;
            }
            "native-pipe-bytes" => session.bytes(data, &mut total)?,
            "native-pipe-complete" => session.complete(data)?,
            _ => {
                return Err(EvidenceError::Invalid(
                    "Native pipe history incomplete or unsupported",
                ))
            }
        }
    }
    require(
        closed
            && binding["events"].as_u64() == Some(count as u64)
            && binding["tail_sha256"] == previous,
    )?;
    let mut selected = BTreeSet::new();
    for (sequence, row) in events
        .iter()
        .enumerate()
        .filter(|(_, r)| r["kind"] == "task-exec")
    {
        let native = &row["data"]["image"];
        let args = command(native)?;
        if args.first().map(Vec::as_slice)
            == Some(text(expected_config, "native_program")?.as_bytes())
        {
            require(native["executable"]["sha256"] == expected_config["native_sha256"])?;
        }
        if native["executable"]["sha256"] == expected_config["native_sha256"]
            && args.get(1).map(Vec::as_slice) == Some(b"resident-client-stream")
        {
            require(
                args.len() == 4
                    && args[2] == b"--stdin"
                    && args[3] == b"/product/guard/native-runtime"
                    && joined.contains(&sequence),
            )?;
            selected.insert(sequence);
        }
    }
    let mut streams = Vec::new();
    for (id, session) in &sessions {
        let event = session.exec.unwrap();
        let framed = if selected.contains(&event) {
            Some(
                json!({"request":crate::native_stdio_frames::summary(&session.read[0], 6 * 1024 * 1024)?,
                "response":crate::native_stdio_frames::summary(&session.read[1], 2 * 1024 * 1024)?}),
            )
        } else {
            None
        };
        streams.push(json!({"session":id,"exec_event":event,"read":session.written,"written":session.written,
            "stream_sha256":session.read.each_ref().map(|v| sha256(v)),"actual_eof_rows_checked":true,"native_frames":framed}));
    }
    Ok(
        json!({"schema":"hol-gauntlet-native-pipe-readback.v1","pipe_event_relations_verified":true,
        "journal_sha256":sha256(raw),"journal_events":count,"sessions":streams,"session_count":sessions.len(),
        "native_client_streams":selected.len(),"opaque_sessions":sessions.len()-selected.len(),"bytes_read":total,
        "actual_pipe_byte_rows_present":total>0,"complete_process_history":process,
        "outside_preparation_joined":false,"outside_observer_admitted":false,"outside_signing_key_admitted":false,
        "exclusive_product_authorship_verified":false,"request_semantics_verified":false,"effect_writer_attribution_checked":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}
