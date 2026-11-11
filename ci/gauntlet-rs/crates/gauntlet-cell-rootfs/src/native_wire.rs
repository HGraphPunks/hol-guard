//! Root-owned pipe relay and measured socket-helper handoff. Socket bytes,
//! operation/effect grading and exclusive authorship remain unverified.
use crate::native_trace::{PipeProcessImage, ProcessImages};
use crate::native_trace_task::Task;
use crate::supervisor_journal::Journal;
use crate::{NativePipeEvent, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_product_cell::{NativeWireConfig, NATIVE_WIRE_MARKER};
use serde_json::{json, Value};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[path = "native_wire_socket.rs"]
mod socket_helper;

pub(crate) const SCHEMA: &str = "hol-gauntlet-native-transports.v2";

pub(crate) struct NativeWire {
    stop: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    result: Arc<Mutex<Option<Result<Value>>>>,
    thread: Option<JoinHandle<()>>,
}
#[derive(Clone)]
struct Context {
    config: NativeWireConfig,
    actor: Value,
    actor_sha256: String,
    cgroup: PathBuf,
    images: ProcessImages,
    journal: Arc<Mutex<Journal>>,
    cancel: Arc<AtomicBool>,
    deadline: Instant,
}
impl Context {
    fn append(&self, kind: &str, data: Value) -> Result<()> {
        self.journal
            .lock()
            .map_err(|_| "Native pipe journal poisoned")?
            .append(kind, data)
    }
    fn image(&self, task: &Task, pin: &str) -> Result<PipeProcessImage> {
        let record = self
            .images
            .get(task.tid, task.start)?
            .ok_or("actual process exec stop missing")?;
        crate::native_stdio_identity::privilege_floor(&record.image, &self.actor)?;
        if record.image["executable"]["sha256"] != pin
            || record.image["task"]["status"]["Seccomp"] != "2"
            || record.image["task"]["status"]["Threads"] != "1"
        {
            return Err("Native pipe process executable or isolation differs".into());
        }
        Ok(record)
    }
    fn cgroup(&self) -> Result<&str> {
        self.actor["cgroup"]
            .as_str()
            .ok_or_else(|| "held product cgroup missing".into())
    }
    fn child(&self, parent: &Task, local_pid: u32) -> Result<Task> {
        let raw = crate::supervisor_io::kernel_file(&self.cgroup.join("cgroup.procs"), 4096)?;
        let pids = std::str::from_utf8(&raw)
            .map_err(|_| "product PID list UTF-8")?
            .split_ascii_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| "product PID list syntax")?;
        if pids.len() > 128 || local_pid <= 1 {
            return Err("bounded Native child PID required".into());
        }
        let mut found = None;
        for pid in pids {
            let Ok(task) = Task::open(pid, self.cgroup()?) else {
                continue;
            };
            if task.local_pid()? != local_pid {
                continue;
            }
            let record = self.image(&task, &self.actor_sha256)?;
            if record.final_wait.is_some()
                || record.image["task"]["parent_pid"] != parent.tid
                || found.is_some()
            {
                return Err("Native child ancestry or uniqueness differs".into());
            }
            found = Some(task);
        }
        found.ok_or_else(|| "actual held Native gate child missing".into())
    }
}

fn peer(socket: &UnixStream) -> Result<u32> {
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of_val(&peer)
        || peer.pid <= 0
        || peer.uid != 10004
        || peer.gid != 10004
    {
        return Err("actual UID/GID 10004 Native connector peer required".into());
    }
    Ok(peer.pid as u32)
}
fn pipe(task: &Task, descriptor: u8) -> Result<(u64, u64)> {
    let info = rustix::fs::fstat(task.stdio_pipe(descriptor)?).map_err(|e| e.to_string())?;
    Ok((info.st_dev, info.st_ino))
}
fn send(socket: &mut UnixStream, byte: u8, deadline: Instant, cancel: &AtomicBool) -> Result<()> {
    gauntlet_agent_bridge::send_control_bytes(socket, &[byte], deadline, cancel)
        .map_err(|e| e.to_string())
}
fn receive<const N: usize>(
    socket: &mut UnixStream,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<[u8; N]> {
    let mut raw = [0; N];
    gauntlet_agent_bridge::receive_control_bytes(socket, &mut raw, deadline, cancel)
        .map_err(|e| e.to_string())?;
    Ok(raw)
}

fn live_input_required(
    expected: u64,
    current: u64,
    finished: bool,
    direction: usize,
) -> Result<bool> {
    if direction > 1 || current != expected || (direction == 0 && finished) {
        return Err("Native process changed before pipe forwarding".into());
    }
    // Output has already been read from the original held pipe object. Its
    // buffered bytes remain valid after exit, including before the recorder
    // publishes the final wait. Only writing stdin needs a live recipient.
    Ok(direction == 0)
}

fn session(mut socket: UnixStream, context: Context, id: u64) -> Result<()> {
    let deadline = (Instant::now() + Duration::from_secs(5)).min(context.deadline);
    let wrapper = Task::open(peer(&socket)?, context.cgroup()?)?;
    let image = context.image(&wrapper, &context.actor_sha256)?;
    let argv = crate::native_stdio_identity::command(&image.image)?;
    if image.final_wait.is_some()
        || argv.first().map(Vec::as_slice) != Some(b"/public/gauntlet-product-cell")
    {
        return Err("measured Native wrapper command differs".into());
    }
    if gauntlet_product_cell::native_socket_helper(&argv)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return socket_helper::session(socket, context, id, wrapper, image, argv);
    }
    let endpoints: [OwnedFd; 4] = gauntlet_agent_bridge::receive_fd_frame(
        &socket,
        NATIVE_WIRE_MARKER,
        4,
        deadline,
        &context.cancel,
    )
    .map_err(|e| e.to_string())?
    .try_into()
    .map_err(|_| "four Native pipe ends required")?;
    send(&mut socket, 1, deadline, &context.cancel)?;
    let child = context.child(
        &wrapper,
        u32::from_be_bytes(receive(&mut socket, deadline, &context.cancel)?),
    )?;
    let gate = context.image(&child, &context.actor_sha256)?;
    let gate_argv = crate::native_stdio_identity::command(&gate.image)?;
    let expected_argv = [
        vec![
            b"/public/gauntlet-product-cell".to_vec(),
            b"native-gate".to_vec(),
            context.config.native_program.as_bytes().to_vec(),
        ],
        argv[1..].to_vec(),
    ]
    .concat();
    if gate_argv != expected_argv {
        return Err("Native gate argv differs from its actual wrapper".into());
    }
    let expected = [
        pipe(&wrapper, 0)?,
        pipe(&child, 0)?,
        pipe(&child, 1)?,
        pipe(&wrapper, 1)?,
    ];
    for (fd, expected) in endpoints.iter().zip(expected) {
        let info = rustix::fs::fstat(fd).map_err(|e| e.to_string())?;
        if (info.st_dev, info.st_ino) != expected {
            return Err("Native handoff differs from actual process pipes".into());
        }
    }
    if image.pipes != Some([expected[0], expected[3]])
        || gate.pipes != Some([expected[1], expected[2]])
    {
        return Err("Native pipe objects differ from their actual exec stops".into());
    }
    context.append("native-pipe-handoff", json!({"session":id,"wrapper":image.image,"gate":gate.image,
        "wrapper_exec_event":image.event,"gate_exec_event":gate.event,"pipes":expected,"execution_eligible":false}))?;
    wrapper.recheck(context.cgroup()?)?;
    child.recheck(context.cgroup()?)?;
    send(&mut socket, 2, deadline, &context.cancel)?;
    if receive::<1>(&mut socket, deadline, &context.cancel)? != [3]
        || wrapper.holds_pipe(&expected)?
    {
        return Err("Native connector retained a handed-off pipe".into());
    }
    wrapper.recheck(context.cgroup()?)?;
    child.recheck(context.cgroup()?)?;
    context.append(
        "native-pipe-sender-closed",
        json!({"session":id,"all_four_sender_copies_absent":true}),
    )?;
    send(&mut socket, 4, deadline, &context.cancel)?;
    drop(socket);
    let actual = loop {
        if context.cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err("actual Native exec stop join unavailable".into());
        }
        let row = context
            .images
            .get(child.tid, child.start)?
            .ok_or("Native child exec history lost")?;
        if row.event != gate.event {
            break row;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    crate::native_stdio_identity::privilege_floor(&actual.image, &context.actor)?;
    let native_argv = crate::native_stdio_identity::command(&actual.image)?;
    if actual.image["executable"]["sha256"] != context.config.native_sha256
        || actual.image["task"]["status"]["Seccomp"] != "2"
        || actual.pipes != Some([expected[1], expected[2]])
        || native_argv != expected_argv[2..]
    {
        return Err("actual Native exec or stdin/stdout objects differ from the handoff".into());
    }
    context.append(
        "native-pipe-exec-bound",
        json!({"session":id,"process":actual.image,"stdio_pipes":actual.pipes,"exec_event":actual.event}),
    )?;
    let counts = crate::relay_native_pipe_bytes(
        endpoints,
        expected,
        context.deadline,
        &context.cancel,
        |event| {
            if let NativePipeEvent::BeforeWrite { direction, .. } = event {
                let current = context
                    .images
                    .get(child.tid, child.start)?
                    .ok_or("Native exec join disappeared")?;
                if live_input_required(
                    actual.event,
                    current.event,
                    current.final_wait.is_some(),
                    direction,
                )
                .map_err(|error| {
                    format!(
                        "{error}: session={id} pid={} start={} direction={direction} expected_exec={} current_exec={} finished={}",
                        child.tid, child.start, actual.event, current.event, current.final_wait.is_some()
                    )
                })? {
                    child.recheck(context.cgroup()?)?;
                }
                return Ok(());
            }
            let data = match event {
                NativePipeEvent::Read {
                    direction,
                    offset,
                    bytes,
                } => {
                    json!({"session":id,"kind":"read","direction":direction,"offset":offset,"bytes_base64":STANDARD.encode(bytes)})
                }
                NativePipeEvent::Write {
                    direction,
                    offset,
                    bytes,
                } => {
                    json!({"session":id,"kind":"write","direction":direction,"offset":offset,"bytes_base64":STANDARD.encode(bytes)})
                }
                NativePipeEvent::Eof { direction, bytes } => {
                    json!({"session":id,"kind":"eof","direction":direction,"bytes":bytes})
                }
                NativePipeEvent::BeforeWrite { .. } => unreachable!(),
            };
            context.append("native-pipe-bytes", data)
        },
    )?;
    context.append(
        "native-pipe-complete",
        json!({"session":id,"read":counts.read,"written":counts.written,
        "execution_eligible":false,"exclusive_product_authorship_verified":false}),
    )
}

impl NativeWire {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        namespace: OwnedFd,
        config: NativeWireConfig,
        actor: Value,
        actor_sha256: String,
        cgroup: PathBuf,
        images: ProcessImages,
        stage: &Path,
        wall: Duration,
    ) -> Result<Self> {
        crate::kernel_process::root_proc()?;
        let journal = Arc::new(Mutex::new(Journal::create_native_pipes(stage)?));
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let result = Arc::new(Mutex::new(None));
        let context = Context {
            config,
            actor,
            actor_sha256,
            cgroup,
            images,
            journal: journal.clone(),
            cancel: cancel.clone(),
            deadline: Instant::now() + wall,
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let thread_stop = stop.clone();
        let thread_result = result.clone();
        let thread = std::thread::Builder::new().name("gauntlet-native-pipes".into()).spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Value> {
                if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                    return Err("held product network namespace join failed".into());
                }
                let address = SocketAddr::from_abstract_name(context.config.endpoint.as_bytes()).map_err(|e| e.to_string())?;
                let listener = UnixListener::bind_addr(&address).map_err(|e| e.to_string())?;
                listener.set_nonblocking(true).map_err(|e| e.to_string())?;
                context.append("native-pipe-owner-started", json!({"schema":SCHEMA,"config":context.config.to_json(),
                    "actor":context.actor,"kernel_pipe_bytes":true,"execution_eligible":false,"exclusive_product_authorship_verified":false}))?;
                ready_tx.send(Ok(())).map_err(|_| "Native pipe owner startup receiver lost")?;
                let mut threads: Vec<JoinHandle<Result<()>>> = Vec::new();
                let mut sessions = 0u64;
                let mut failure = None;
                while !thread_stop.load(Ordering::Acquire) && Instant::now() < context.deadline {
                    let mut index = 0;
                    while index < threads.len() {
                        if !threads[index].is_finished() { index += 1; continue; }
                        if let Err(error) = threads.swap_remove(index).join().unwrap_or_else(|_| Err("Native pipe session panicked".into())) {
                            failure = Some(error); break;
                        }
                    }
                    if failure.is_some() { break; }
                    match listener.accept() {
                        Ok((socket, _)) => {
                            if threads.len() >= 16 || sessions >= 1024 { failure = Some("Native pipe session bound exhausted".into()); break; }
                            let child_context = context.clone();
                            let id = sessions;
                            sessions += 1;
                            threads.push(std::thread::Builder::new().name("gauntlet-native-pipe".into())
                                .spawn(move || session(socket, child_context, id)).map_err(|e| e.to_string())?);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                        Err(e) => { failure = Some(e.to_string()); break; }
                    }
                }
                drop(listener);
                if failure.is_some() { context.cancel.store(true, Ordering::Release); }
                for thread in threads {
                    if let Err(error) = thread.join().unwrap_or_else(|_| Err("Native pipe session panicked".into())) { failure.get_or_insert(error); }
                }
                if let Some(error) = failure {
                    context.append("native-pipe-owner-failed", json!({"error":error,"execution_eligible":false}))?;
                    return Err(error);
                }
                context.append("native-pipe-owner-closed", json!({"sessions":sessions,"execution_eligible":false}))?;
                journal.lock().map_err(|_| "Native pipe journal poisoned")?.binding()
            })).unwrap_or_else(|_| Err("Native pipe owner panicked".into()));
            context.cancel.store(true, Ordering::Release);
            if let Err(error) = &outcome { let _ = ready_tx.try_send(Err(error.clone())); }
            if let Ok(mut slot) = thread_result.lock() { *slot = Some(outcome); }
        }).map_err(|e| e.to_string())?;
        let mut owner = Self {
            stop,
            cancel,
            result,
            thread: Some(thread),
        };
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(owner),
            Ok(Err(error)) => {
                owner.cancel.store(true, Ordering::Release);
                Err(error)
            }
            Err(_) => {
                let _ = owner.finish();
                Err("Native pipe owner readiness missing".into())
            }
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        if let Some(result) = &*self
            .result
            .lock()
            .map_err(|_| "Native pipe owner result poisoned")?
        {
            return match result {
                Err(error) => Err(error.clone()),
                Ok(_) => Err("Native pipe owner ended before cell cleanup".into()),
            };
        }
        Ok(())
    }
    pub(crate) fn finish(&mut self) -> Result<Value> {
        self.stop.store(true, Ordering::Release);
        let began = Instant::now();
        loop {
            if self.thread.as_ref().is_some_and(|t| t.is_finished()) {
                self.thread
                    .take()
                    .unwrap()
                    .join()
                    .map_err(|_| "Native pipe owner join failed")?;
                return self
                    .result
                    .lock()
                    .map_err(|_| "Native pipe owner result poisoned")?
                    .clone()
                    .ok_or("Native pipe owner result missing")?;
            }
            if began.elapsed() > Duration::from_secs(4) {
                self.cancel.store(true, Ordering::Release);
            }
            if began.elapsed() > Duration::from_secs(6) {
                return Err("Native pipe owner drain uncertain".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for NativeWire {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.cancel.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffered_output_can_drain_before_or_after_the_final_wait_without_a_live_task() {
        for finished in [false, true] {
            assert!(!live_input_required(7, 7, finished, 1).unwrap());
            for direction in [0, 1] {
                assert!(live_input_required(7, 8, finished, direction).is_err());
            }
        }
        assert!(live_input_required(7, 7, false, 0).unwrap());
        assert!(live_input_required(7, 7, true, 0).is_err());
        assert!(live_input_required(7, 7, false, 2).is_err());
    }
}
