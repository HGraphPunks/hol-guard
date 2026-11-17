//! Outside, source-specific snapshots of Native client pipe syscall buffers.
use crate::native_stdio_identity as identity;
use crate::native_stdio_syscall::*;
use crate::native_stdio_task::Pipes;
use crate::native_trace_task::Task;
use crate::supervisor_journal::Journal;
use crate::{hash, hex, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

const MAX_CAPTURED: usize = 32 * 1024 * 1024;
const MAX_PENDING: usize = 16 * 1024 * 1024;

struct Pending {
    entry: NativeSyscallEntry,
    transfer: NativeStdioTransfer,
    ranges: Vec<NativeMemoryRange>,
    requested: usize,
    submitted: Vec<u8>,
    call: u64,
}
struct Stream {
    number: u64,
    pipes: Pipes,
    sequence: NativeSyscallSequence,
    pending: Option<Pending>,
    calls: u64,
}

pub(super) struct Recorder {
    journal: Journal,
    native: String,
    actor: Value,
    streams: BTreeMap<u32, Stream>,
    created: u64,
    closed: u64,
    calls: u64,
    stops: u64,
    bytes: usize,
    pending_bytes: usize,
    fixture: bool,
}

impl Recorder {
    pub(super) fn create(stage: &Path, native: &str) -> Result<Self> {
        if !hex(native, 64) {
            return Err("exact prelaunch Native stdio digest required".into());
        }
        Ok(Self {
            journal: Journal::create_native_stdio(stage)?,
            native: native.into(),
            actor: Value::Null,
            streams: BTreeMap::new(),
            created: 0,
            closed: 0,
            calls: 0,
            stops: 0,
            bytes: 0,
            pending_bytes: 0,
            fixture: false,
        })
    }

    #[cfg(all(test, feature = "owned-process-trace-fixture"))]
    pub(super) fn create_fixture(stage: &Path, native: &str) -> Result<Self> {
        let mut recorder = Self::create(stage, native)?;
        recorder.fixture = true;
        Ok(recorder)
    }

    pub(super) fn declaration(&self) -> Value {
        json!({"mode":identity::MODE,"native_runtime_sha256":self.native,
            "scope":if self.fixture {"owned-process-fixture"}else{"owned-product-native-stream"},
            "memory_or_register_mutation":false,"atomic_kernel_pipe_bytes_verified":false,
            "concurrent_tracees_frozen":false,"execution_eligible":false})
    }

    pub(super) fn start(&mut self, actor: &Value) -> Result<()> {
        if !self.actor.is_null() {
            return Err("Native stdio recorder is one use".into());
        }
        self.actor = actor.clone();
        self.journal.append("stdio-start",json!({"declaration":self.declaration(),
            "actor_argv_sha256":actor["argv_sha256"],"actor_executable_sha256":actor["executable"]["sha256"],
            "actor_tid":actor["task"]["tid"],"actor_start_ticks":actor["task"]["start_ticks"],
            "cgroup":actor["task"]["cgroup"]}))
    }

    fn selected(&self, image: &Value) -> Result<bool> {
        #[cfg(all(test, feature = "owned-process-trace-fixture"))]
        if self.fixture {
            let args = identity::command(image)?;
            if !args.get(1).is_some_and(|s| {
                matches!(
                    s.as_slice(),
                    b"stdio-scalar-leaf"
                        | b"stdio-vector-leaf"
                        | b"stdio-partial-leaf"
                        | b"stdio-rebind-leaf"
                        | b"stdio-linger-leaf"
                        | b"stdio-oversize-leaf"
                )
            }) {
                return Ok(false);
            }
            if image["executable"]["sha256"] != self.native {
                return Err("owned stdio fixture executable changed".into());
            }
            identity::privilege_floor(image, &self.actor)?;
            return Ok(true);
        }
        identity::selected(image, &self.actor, &self.native)
    }

    pub(super) fn consider(
        &mut self,
        task: &Task,
        image: &Value,
        id: u64,
        exec: u64,
    ) -> Result<()> {
        if !self.selected(image)? {
            return Ok(());
        }
        if self.streams.len() >= 16 || self.created >= 1024 || self.streams.contains_key(&task.tid)
        {
            return Err("Native stream count or lifetime bound exceeded".into());
        }
        let pipes = Pipes::open(task, image)?;
        pipes.recheck(
            task,
            image["task"]["cgroup"]
                .as_str()
                .ok_or("stdio cgroup required")?,
            &|v| self.selected(v),
        )?;
        self.created += 1;
        self.journal.append(
            "stdio-selected",
            json!({"stream":self.created,"task_id":id,
            "tid":task.tid,"tgid":task.tgid,"start_ticks":task.start,"process_exec_sequence":exec,
            "argv_sha256":image["argv_sha256"],"executable_sha256":image["executable"]["sha256"],
            "pipes":pipes.observation()}),
        )?;
        self.streams.insert(
            task.tid,
            Stream {
                number: self.created,
                pipes,
                sequence: NativeSyscallSequence::after_exec(),
                pending: None,
                calls: 0,
            },
        );
        Ok(())
    }

    pub(super) fn stepping(&self, tid: u32) -> bool {
        self.streams.contains_key(&tid)
    }

    pub(super) fn observe(
        &mut self,
        task: &Task,
        cgroup: &str,
        stop: NativeSyscallStop,
    ) -> Result<()> {
        self.stops += 1;
        if self.stops > 1_000_000 {
            return Err("Native syscall stop bound exceeded".into());
        }
        let mut stream = self
            .streams
            .remove(&task.tid)
            .ok_or("syscall stop without selected Native stream")?;
        let result = self.observe_stream(&mut stream, task, cgroup, stop);
        self.streams.insert(task.tid, stream);
        result
    }

    fn observe_stream(
        &mut self,
        stream: &mut Stream,
        task: &Task,
        cgroup: &str,
        stop: NativeSyscallStop,
    ) -> Result<()> {
        let completion = stream.sequence.observe(stop)?;
        if let NativeSyscallStop::Entry(entry) = stop {
            let Some(transfer) = native_stdio_transfer(entry)? else {
                return Ok(());
            };
            if stream.pending.is_some() || self.calls >= 8192 {
                return Err("Native pipe call bound or ordering".into());
            }
            stream.pipes.recheck(task, cgroup, &|v| self.selected(v))?;
            let ranges = match transfer.buffers {
                NativeStdioBuffers::Scalar(range) => vec![range],
                NativeStdioBuffers::Vector { table, count } => {
                    let raw = stream
                        .pipes
                        .copy(task, cgroup, &[table], table.length, &|v| self.selected(v))?;
                    decode_native_iovecs(&raw, count)?
                }
            };
            let requested = ranges.iter().map(|v| v.length).sum::<usize>();
            let submitted = if transfer.direction == NativeStdioDirection::Write {
                if self.pending_bytes.saturating_add(requested) > MAX_PENDING
                    || self.bytes.saturating_add(requested) > MAX_CAPTURED
                {
                    return Err("Native pending or total pipe snapshot bound exceeded".into());
                }
                stream
                    .pipes
                    .copy(task, cgroup, &ranges, requested, &|v| self.selected(v))?
            } else {
                Vec::new()
            };
            stream.calls += 1;
            self.calls += 1;
            self.pending_bytes += submitted.len();
            self.journal.append("stdio-call",json!({"stream":stream.number,"call":stream.calls,
                "syscall":entry.number,"descriptor":transfer.descriptor,
                "direction":if transfer.direction==NativeStdioDirection::Read {"read"}else{"write"},
                "requested":requested,"vector_lengths":ranges.iter().map(|v|v.length).collect::<Vec<_>>()}))?;
            stream.pending = Some(Pending {
                entry,
                transfer,
                ranges,
                requested,
                submitted,
                call: stream.calls,
            });
            return Ok(());
        }
        let Some((entry, result, is_error)) = completion else {
            return Ok(());
        };
        if native_stdio_transfer(entry)?.is_some() != stream.pending.is_some() {
            return Err("Native pipe completion lacks its selected entry".into());
        }
        let Some(pending) = stream.pending.take() else {
            return Ok(());
        };
        self.pending_bytes = self
            .pending_bytes
            .checked_sub(pending.submitted.len())
            .ok_or("Native pending bytes underflow")?;
        if pending.entry != entry {
            return Err("Native pipe completion changed syscall".into());
        }
        stream.pipes.recheck(task, cgroup, &|v| self.selected(v))?;
        let completed = completed_native_stdio_bytes(result, is_error, pending.requested)?;
        let count = completed.unwrap_or(0);
        if self.bytes.saturating_add(count) > MAX_CAPTURED {
            return Err("Native pipe total byte bound exceeded".into());
        }
        let raw = if pending.transfer.direction == NativeStdioDirection::Read {
            stream
                .pipes
                .copy(task, cgroup, &pending.ranges, count, &|v| self.selected(v))?
        } else {
            pending.submitted[..count].to_vec()
        };
        self.bytes += raw.len();
        self.journal.append("stdio-transfer",json!({"stream":stream.number,"call":pending.call,
            "result":result,"is_error":is_error,"completed":completed,"bytes":raw.len(),"sha256":hash(&raw)}))?;
        for (chunk, raw) in raw.chunks(65536).enumerate() {
            self.journal.append(
                "stdio-bytes",
                json!({"stream":stream.number,"call":pending.call,
                "offset":chunk*65536,"base64":STANDARD.encode(raw)}),
            )?;
        }
        Ok(())
    }

    pub(super) fn end(&mut self, tid: u32, reason: &str) -> Result<()> {
        let Some(mut stream) = self.streams.remove(&tid) else {
            return Ok(());
        };
        if !matches!(reason, "final-wait" | "exec-replacement") {
            return Err("Native stream close reason required".into());
        }
        let interrupted = stream.sequence.finish()?;
        let call = stream.pending.take();
        if let Some(pending) = &call {
            if interrupted != Some(pending.entry) {
                return Err("Native interrupted syscall changed".into());
            }
            self.pending_bytes = self
                .pending_bytes
                .checked_sub(pending.submitted.len())
                .ok_or("Native pending bytes underflow")?;
        }
        self.journal.append("stdio-ended",json!({"stream":stream.number,"tid":tid,"reason":reason,
            "interrupted_stdio_call":call.map(|v|v.call),"pending_syscall_number":interrupted.map(|v|v.number),
            "pipe_eof_inferred":false}))?;
        self.closed += 1;
        Ok(())
    }

    pub(super) fn fail(&mut self, error: &str) {
        let _ = self.journal.append(
            "stdio-failed",
            json!({"error":error,"complete":false,"execution_eligible":false}),
        );
    }

    pub(super) fn finish(&mut self) -> Result<Value> {
        if !self.streams.is_empty() || self.created != self.closed || self.pending_bytes != 0 {
            return Err("Native pipe history not drained".into());
        }
        let counts = json!({"streams":self.created,"closed_streams":self.closed,"calls":self.calls,
            "syscall_stops":self.stops,"bytes":self.bytes});
        self.journal.append("stdio-complete", counts.clone())?;
        Ok(
            json!({"schema":"hol-gauntlet-native-stdio.v1","complete":true,
            "declaration":self.declaration(),"counts":counts,"journal":self.journal.binding()?,
            "execution_eligible":false}),
        )
    }
}
