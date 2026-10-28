//! Replay the separate Root snapshot chain. This never asserts atomic wire I/O.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{parse, require, text};
use crate::native_stdio_process::{self as process, Expected};
use crate::payload::exact_keys;
use crate::{canonical_value, EvidenceError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::BTreeMap;

struct Call {
    number: u64,
    requested: usize,
    write: bool,
}
struct Stream {
    identity: Value,
    reason: &'static str,
    ending: usize,
    calls: u64,
    pending: Option<Call>,
    read: Vec<u8>,
    written: Vec<u8>,
    ended: bool,
    eof: bool,
    interrupted: bool,
}
struct Bytes {
    stream: u64,
    call: u64,
    write: bool,
    count: usize,
    digest: String,
    raw: Vec<u8>,
}
struct Replay {
    expected: BTreeMap<u64, Expected>,
    streams: BTreeMap<u64, Stream>,
    bytes: Option<Bytes>,
    total: usize,
    pending: usize,
    calls: u64,
    transfers: u64,
    done: bool,
}
pub(crate) struct SnapshotStream {
    pub(crate) stream: u64,
    pub(crate) identity: Value,
    pub(crate) read: Vec<u8>,
    pub(crate) written: Vec<u8>,
}
pub(crate) struct Readback {
    pub(crate) summary: Value,
    pub(crate) streams: Vec<SnapshotStream>,
}
fn integer(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or(EvidenceError::Invalid("Native stdio integer required"))
}
impl Replay {
    fn stream(&mut self, data: &Value) -> Result<&mut Stream> {
        self.streams
            .get_mut(&integer(&data["stream"])?)
            .ok_or(EvidenceError::Invalid("Native stdio stream missing"))
    }
    fn event(&mut self, kind: &str, data: &Value, counts: &Value) -> Result<()> {
        require(!self.done && (self.bytes.is_none() || kind == "stdio-bytes"))?;
        match kind {
            "stdio-selected" => {
                require(exact_keys(
                    data,
                    &[
                        "stream",
                        "task_id",
                        "tid",
                        "tgid",
                        "start_ticks",
                        "process_exec_sequence",
                        "argv_sha256",
                        "executable_sha256",
                        "pipes",
                    ],
                ))?;
                let stream = integer(&data["stream"])?;
                require(
                    stream == self.streams.len() as u64 + 1
                        && self.streams.values().filter(|v| !v.ended).count() < 16,
                )?;
                let expected = self
                    .expected
                    .remove(&integer(&data["process_exec_sequence"])?)
                    .ok_or(EvidenceError::Invalid(
                        "Native stream has no unique measured exec",
                    ))?;
                for (key, value) in expected.selected.as_object().unwrap() {
                    require(data[key] == *value)?;
                }
                let pipes = &data["pipes"];
                require(
                    exact_keys(
                        pipes,
                        &[
                            "stdin",
                            "stdout",
                            "held_with",
                            "pipe_readers_or_writers_added",
                        ],
                    ) && pipes["held_with"] == "O_PATH"
                        && pipes["pipe_readers_or_writers_added"] == false,
                )?;
                for key in ["stdin", "stdout"] {
                    require(exact_keys(&pipes[key], &["device", "inode"]))?;
                    integer(&pipes[key]["device"])?;
                    require(integer(&pipes[key]["inode"])? > 0)?;
                }
                require(pipes["stdin"] != pipes["stdout"])?;
                self.streams.insert(
                    stream,
                    Stream {
                        identity: data.clone(),
                        reason: expected.close_reason,
                        ending: expected.close_sequence,
                        calls: 0,
                        pending: None,
                        read: Vec::new(),
                        written: Vec::new(),
                        ended: false,
                        eof: false,
                        interrupted: false,
                    },
                );
            }
            "stdio-call" => {
                require(exact_keys(
                    data,
                    &[
                        "stream",
                        "call",
                        "syscall",
                        "descriptor",
                        "direction",
                        "requested",
                        "vector_lengths",
                    ],
                ))?;
                let number = integer(&data["syscall"])?;
                let write = match (
                    number,
                    integer(&data["descriptor"])?,
                    text(data, "direction")?,
                ) {
                    (63 | 65, 0, "read") => false,
                    (64 | 66, 1, "write") => true,
                    _ => return Err(EvidenceError::Invalid("unsupported Native pipe syscall")),
                };
                let lengths = data["vector_lengths"]
                    .as_array()
                    .filter(|v| v.len() <= 1024)
                    .ok_or(EvidenceError::Invalid(
                        "bounded Native vector lengths required",
                    ))?;
                require(matches!(number, 65 | 66) || lengths.len() == 1)?;
                let mut requested = 0usize;
                for length in lengths {
                    let length = usize::try_from(integer(length)?)
                        .map_err(|_| EvidenceError::Invalid("Native vector length overflow"))?;
                    requested = requested
                        .checked_add(length)
                        .filter(|v| *v <= 8 * 1024 * 1024)
                        .ok_or(EvidenceError::Invalid("Native pipe request too large"))?;
                }
                require(integer(&data["requested"])? == requested as u64 && self.calls < 8192)?;
                if write {
                    self.pending += requested;
                    require(self.pending <= 16 * 1024 * 1024)?;
                }
                self.calls += 1;
                let stream = self.stream(data)?;
                require(
                    !stream.ended
                        && stream.pending.is_none()
                        && integer(&data["call"])? == stream.calls + 1,
                )?;
                stream.calls += 1;
                stream.pending = Some(Call {
                    number,
                    requested,
                    write,
                });
            }
            "stdio-transfer" => {
                require(exact_keys(
                    data,
                    &[
                        "stream",
                        "call",
                        "result",
                        "is_error",
                        "completed",
                        "bytes",
                        "sha256",
                    ],
                ))?;
                let stream = self.stream(data)?;
                require(!stream.ended && integer(&data["call"])? == stream.calls)?;
                let call = stream
                    .pending
                    .take()
                    .ok_or(EvidenceError::Invalid("Native pipe entry missing"))?;
                let result = data["result"].as_i64().ok_or(EvidenceError::Invalid(
                    "signed Native syscall result required",
                ))?;
                let error = data["is_error"]
                    .as_bool()
                    .ok_or(EvidenceError::Invalid("Native syscall error flag required"))?;
                let count = if error {
                    require((-4095..=-1).contains(&result) && data["completed"].is_null())?;
                    0
                } else {
                    require(
                        result >= 0
                            && result as u64 <= call.requested as u64
                            && integer(&data["completed"])? == result as u64,
                    )?;
                    result as usize
                };
                require(integer(&data["bytes"])? == count as u64)?;
                if !call.write && !error && count == 0 && call.requested > 0 {
                    stream.eof = true;
                }
                if call.write {
                    self.pending = self
                        .pending
                        .checked_sub(call.requested)
                        .ok_or(EvidenceError::Invalid("Native pending byte underflow"))?;
                }
                self.transfers += 1;
                require(self.total + count <= 32 * 1024 * 1024)?;
                let digest = text(data, "sha256")?.to_owned();
                if count == 0 {
                    require(digest == sha256(b""))?;
                } else {
                    self.bytes = Some(Bytes {
                        stream: integer(&data["stream"])?,
                        call: integer(&data["call"])?,
                        write: call.write,
                        count,
                        digest,
                        raw: Vec::with_capacity(count),
                    });
                }
            }
            "stdio-bytes" => {
                require(exact_keys(data, &["stream", "call", "offset", "base64"]))?;
                let pending = self
                    .bytes
                    .as_mut()
                    .ok_or(EvidenceError::Invalid("uncredited Native pipe bytes"))?;
                require(
                    integer(&data["stream"])? == pending.stream
                        && integer(&data["call"])? == pending.call
                        && integer(&data["offset"])? == pending.raw.len() as u64,
                )?;
                let encoded = text(data, "base64")?;
                let raw = STANDARD
                    .decode(encoded)
                    .map_err(|_| EvidenceError::Invalid("Native pipe bytes encoding"))?;
                require(
                    raw.len() == (pending.count - pending.raw.len()).min(65536)
                        && !raw.is_empty()
                        && STANDARD.encode(&raw) == encoded,
                )?;
                pending.raw.extend(raw);
                if pending.raw.len() == pending.count {
                    let pending = self.bytes.take().unwrap();
                    require(sha256(&pending.raw) == pending.digest)?;
                    self.total += pending.raw.len();
                    let stream = self.streams.get_mut(&pending.stream).unwrap();
                    if pending.write {
                        stream.written.extend(pending.raw);
                    } else {
                        stream.read.extend(pending.raw);
                    }
                }
            }
            "stdio-ended" => {
                require(exact_keys(
                    data,
                    &[
                        "stream",
                        "tid",
                        "reason",
                        "interrupted_stdio_call",
                        "pending_syscall_number",
                        "pipe_eof_inferred",
                    ],
                ))?;
                let stream = self.stream(data)?;
                require(
                    !stream.ended
                        && data["tid"] == stream.identity["tid"]
                        && text(data, "reason")? == stream.reason
                        && data["pipe_eof_inferred"] == false,
                )?;
                let pending = stream.pending.take();
                if let Some(call) = &pending {
                    require(
                        integer(&data["interrupted_stdio_call"])? == stream.calls
                            && integer(&data["pending_syscall_number"])? == call.number,
                    )?;
                    stream.interrupted = true;
                } else {
                    require(
                        data["interrupted_stdio_call"].is_null()
                            && (data["pending_syscall_number"].is_null()
                                || data["pending_syscall_number"].as_u64().is_some()),
                    )?;
                }
                stream.ended = true;
                if let Some(call) = pending.filter(|v| v.write) {
                    self.pending =
                        self.pending
                            .checked_sub(call.requested)
                            .ok_or(EvidenceError::Invalid(
                                "Native interrupted pending byte underflow",
                            ))?;
                }
            }
            "stdio-complete" => {
                require(
                    data == counts
                        && self.expected.is_empty()
                        && self.pending == 0
                        && self.streams.values().all(|v| v.ended)
                        && integer(&data["streams"])? == self.streams.len() as u64
                        && data["closed_streams"] == data["streams"]
                        && integer(&data["calls"])? == self.calls
                        && integer(&data["bytes"])? == self.total as u64
                        && integer(&data["syscall_stops"])? >= self.calls + self.transfers,
                )?;
                self.done = true;
            }
            _ => {
                return Err(EvidenceError::Invalid(
                    "unsupported or incomplete Native pipe history",
                ))
            }
        }
        Ok(())
    }
}

/// The checkpoint must be independently bound by its caller. Hash chains and
/// stopped-buffer snapshots do not admit an observer or attest kernel bytes.
pub fn verify_native_stdio_events(
    raw: &[u8],
    process_raw: &[u8],
    checkpoint: &Value,
) -> Result<Value> {
    Ok(replay(raw, process_raw, checkpoint)?.summary)
}

pub(crate) fn replay(raw: &[u8], process_raw: &[u8], checkpoint: &Value) -> Result<Readback> {
    require(checkpoint["schema"] == "hol-gauntlet-native-process-events.v2")?;
    let task_history = crate::verify_native_process_events(process_raw, checkpoint)?;
    let capture = &checkpoint["native_stdio"];
    crate::native_stdio_contract::checkpoint(capture)?;
    let declaration = &capture["declaration"];
    let pin = &capture["journal"];
    require(
        !raw.is_empty()
            && raw.len() <= 64 * 1024 * 1024
            && raw.ends_with(b"\n")
            && integer(&pin["bytes"])? == raw.len() as u64,
    )?;
    let process_events = process::events(process_raw)?;
    let expected = process::expected(&process_events, declaration)?;
    let mut replay = Replay {
        expected,
        streams: BTreeMap::new(),
        bytes: None,
        total: 0,
        pending: 0,
        calls: 0,
        transfers: 0,
        done: false,
    };
    let mut previous = "0".repeat(64);
    let mut count = 0;
    for (sequence, line) in raw[..raw.len() - 1].split(|b| *b == b'\n').enumerate() {
        require(sequence < 65536 && !line.is_empty() && line.len() <= 256 * 1024)?;
        let row = parse(line)?;
        require(
            exact_keys(
                &row,
                &["schema", "sequence", "previous_sha256", "kind", "data"],
            ) && row["schema"] == "hol-gauntlet-cell-event.v1"
                && integer(&row["sequence"])? == sequence as u64
                && row["previous_sha256"] == previous
                && canonical_value(&row)? == line,
        )?;
        previous = sha256(line);
        count += 1;
        if sequence == 0 {
            require(row["kind"] == "stdio-start")?;
            process::start(
                &row["data"],
                &process_events[0]["data"]["actor"],
                declaration,
            )?;
        } else {
            replay.event(text(&row, "kind")?, &row["data"], &capture["counts"])?;
        }
    }
    require(replay.done && integer(&pin["events"])? == count && pin["tail_sha256"] == previous)?;
    let mut streams = Vec::new();
    let mut measured = Vec::new();
    let mut frame_count = 0;
    for (id, stream) in replay.streams {
        let read = crate::native_stdio_frames::summary(&stream.read, 6 * 1024 * 1024)?;
        let written = crate::native_stdio_frames::summary(&stream.written, 2 * 1024 * 1024)?;
        frame_count += integer(&read["complete_frames"])? + integer(&written["complete_frames"])?;
        require(frame_count <= 8192)?;
        streams.push(
            json!({"stream":id,"identity":stream.identity,"kernel_ending_sequence":stream.ending,
            "ending":stream.reason,"calls":stream.calls,"read_eof_observed":stream.eof,
            "interrupted_stdio_call_observed":stream.interrupted,"read":read,"written":written}),
        );
        measured.push(SnapshotStream {
            stream: id,
            identity: stream.identity,
            read: stream.read,
            written: stream.written,
        });
    }
    Ok(Readback {
        streams: measured,
        summary: json!({"schema":"hol-gauntlet-native-stdio-readback.v1","scope":declaration["scope"],
        "journal_sha256":sha256(raw),"process_journal_sha256":sha256(process_raw),
        "task_history":task_history,"kernel_task_exec_and_end_joins_checked":true,
        "counts":capture["counts"],"streams":streams,"complete_frames":frame_count,
        "atomic_kernel_pipe_bytes_verified":false,"concurrent_memory_authenticated":false,
        "request_semantics_verified":false,"all_native_runtime_descendants_graded":false,
        "outside_observer_admitted":false,"outside_signing_key_admitted":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    })
}

#[cfg(test)]
#[path = "native_stdio_events_tests.rs"]
mod tests;
