//! One dedicated tracer thread owns every wait and the private event journal.
use crate::native_trace_sys as sys;
use crate::native_trace_task::Task;
use crate::native_trace_wait::{Event, Wait};
use crate::supervisor_journal::Journal;
use crate::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::SyncSender,
    Arc,
};
use std::time::{Duration, Instant};

struct Entry {
    id: u64,
    task: Task,
}
struct Birth {
    parent_id: u64,
    parent_tid: u32,
    kind: &'static str,
}
pub(super) struct Engine {
    pub(super) journal: Journal,
    cgroup: String,
    active: BTreeMap<u32, Entry>,
    births: BTreeMap<u32, Birth>,
    pending: BTreeMap<u32, Wait>,
    retired: BTreeMap<u32, u64>,
    next: u64,
    final_waits: u64,
    exec_retirements: u64,
    execs: u64,
    abort: Arc<AtomicBool>,
    expected_actor: Option<Value>,
    stdio: Option<crate::native_stdio_recorder::Recorder>,
}

impl Engine {
    pub(super) fn new(
        task: Task,
        cgroup: String,
        journal: Journal,
        abort: Arc<AtomicBool>,
        expected_actor: Option<Value>,
        stdio: Option<crate::native_stdio_recorder::Recorder>,
    ) -> Self {
        Self {
            journal,
            cgroup,
            active: BTreeMap::from([(task.tid, Entry { id: 0, task })]),
            births: BTreeMap::new(),
            pending: BTreeMap::new(),
            retired: BTreeMap::new(),
            next: 1,
            final_waits: 0,
            exec_retirements: 0,
            execs: 0,
            abort,
            expected_actor,
            stdio,
        }
    }

    fn append(&mut self, kind: &str, data: Value) -> Result<()> {
        self.journal.append(kind, data)
    }

    fn resume(&mut self, tid: u32, signal: u8) -> Result<()> {
        let resumed = if self.stdio.as_ref().is_some_and(|v| v.stepping(tid)) {
            sys::resume_syscall(tid, signal)?
        } else {
            sys::resume(tid, signal)?
        };
        if !resumed {
            self.append(
                "resume-stop-lost",
                json!({"tid":tid,"signal":signal,"death_observed":false}),
            )?;
        }
        Ok(())
    }

    fn wait(&self) -> Result<sys::WaitResult> {
        if self.stdio.is_some() {
            sys::wait_stdio()
        } else {
            sys::wait()
        }
    }

    pub(super) fn fail_stdio(&mut self, error: &str) {
        if let Some(stdio) = &mut self.stdio {
            stdio.fail(error);
        }
    }

    pub(super) fn run(&mut self, ready: &SyncSender<Result<u32>>) -> Result<Value> {
        let tid = *self.active.keys().next().ok_or("initial actor required")?;
        if self.stdio.is_some() {
            sys::seize_stdio(tid)?;
        } else {
            sys::seize(tid)?;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.abort.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err("initial recorder stop deadline or abort".into());
            }
            match self.wait()? {
                sys::WaitResult::Event(
                    actual,
                    Wait::Event {
                        event: Event::SeizeStop,
                        signal: 5,
                    },
                ) if actual == tid => break,
                sys::WaitResult::Idle => std::thread::sleep(Duration::from_millis(1)),
                _ => return Err("expected the held actor's initial seize stop".into()),
            }
        }
        let image = self.active[&tid].task.exec_image(&self.cgroup)?;
        if image["task"]["status"]["Threads"] != "1" {
            return Err("single-threaded actor required at the initial trace stop".into());
        }
        if let Some(expected) = &self.expected_actor {
            if image["executable"]["sha256"] != expected["executable_sha256"]
                || image["namespaces"] != expected["namespaces"]
                || image["lsm_label"] != expected["lsm_label"]
            {
                return Err("stopped actor image, namespaces or enforcing label changed".into());
            }
            for key in crate::kernel_status::FIELDS {
                if image["task"]["status"][key] != expected["status"][key] {
                    return Err(format!("stopped actor {key} differs from held expectation"));
                }
            }
        }
        let mut start = json!({"id":0,"actor":image,"cgroup":self.cgroup,
            "options":["exit-kill","fork","vfork","clone","exec","exit","vfork-done"],
            "memory_or_register_mutation":false,"execution_eligible":false});
        if let Some(stdio) = &mut self.stdio {
            stdio.start(&image)?;
            start["options"]
                .as_array_mut()
                .unwrap()
                .push(json!("syscall-good"));
            start["native_stdio"] = stdio.declaration();
        }
        self.append("trace-start", start)?;
        self.resume(tid, 0)?;
        ready
            .send(Ok(sys::thread_id()?))
            .map_err(|_| "recorder readiness receiver disappeared")?;
        loop {
            if self.abort.load(Ordering::Acquire) {
                return Err("owned process recorder aborted; no complete history".into());
            }
            match self.wait()? {
                sys::WaitResult::Event(tid, event) => self.event(tid, event)?,
                sys::WaitResult::Idle => std::thread::sleep(Duration::from_millis(1)),
                sys::WaitResult::Empty => {
                    if !self.active.is_empty()
                        || !self.births.is_empty()
                        || !self.pending.is_empty()
                    {
                        return Err(
                            "kernel lost owned tasks before final wait or exec replacement".into(),
                        );
                    }
                    break;
                }
            }
        }
        self.append(
            "trace-complete",
            json!({"created_tasks":self.next,"final_waits":self.final_waits,
            "exec_retirements":self.exec_retirements,"execs":self.execs,"active_tasks":0,
            "pending_births":0,"pending_stops":0,"execution_eligible":false}),
        )?;
        let mut checkpoint = json!({"schema":"hol-gauntlet-native-process-events.v1","complete":true,
            "created_tasks":self.next,"final_waits":self.final_waits,"exec_retirements":self.exec_retirements,
            "execs":self.execs,"journal":self.journal.binding()?,"execution_eligible":false});
        if let Some(stdio) = &mut self.stdio {
            checkpoint["schema"] = json!("hol-gauntlet-native-process-events.v2");
            checkpoint["native_stdio"] = stdio.finish()?;
        }
        Ok(checkpoint)
    }

    fn register(&mut self, tid: u32, event: Wait) -> Result<()> {
        if event
            != (Wait::Event {
                event: Event::SeizeStop,
                signal: 5,
            })
        {
            return Err("new task lacks initial seized stop".into());
        }
        let birth = self
            .births
            .remove(&tid)
            .ok_or("creation event missing for new task")?;
        let task = Task::open(tid, &self.cgroup)?;
        let anchor = task.anchor(&self.cgroup)?;
        let id = self.next;
        self.next = self.next.checked_add(1).ok_or("task sequence exhausted")?;
        self.retired.remove(&tid);
        self.append(
            "task-created",
            json!({"id":id,"parent_id":birth.parent_id,
            "parent_tid":birth.parent_tid,"creation":birth.kind,"task":anchor}),
        )?;
        if self.active.insert(tid, Entry { id, task }).is_some() {
            return Err("duplicate live trace TID".into());
        }
        self.resume(tid, 0)
    }

    fn event(&mut self, tid: u32, event: Wait) -> Result<()> {
        if !self.active.contains_key(&tid) {
            if self.births.contains_key(&tid) {
                return self.register(tid, event);
            }
            if matches!(event, Wait::Exited(_) | Wait::Killed { .. }) {
                if let Some(id) = self.retired.remove(&tid) {
                    return self.append(
                        "exec-retired-final-wait",
                        json!({"id":id,"tid":tid,"status":final_value(event)?}),
                    );
                }
            }
            // The child's auto-attach stop can precede its parent's creation
            // notification. Keep it stopped until its kernel parent is known.
            if event
                != (Wait::Event {
                    event: Event::SeizeStop,
                    signal: 5,
                })
                || self.pending.len() >= 128
                || self.pending.insert(tid, event).is_some()
            {
                return Err("unaccounted or duplicate kernel trace task".into());
            }
            return Ok(());
        }
        let id = self.active[&tid].id;
        match event {
            Wait::Syscall => {
                let entry = &self.active[&tid];
                self.stdio
                    .as_mut()
                    .ok_or("undeclared Native syscall stop")?
                    .observe(
                        &entry.task,
                        &self.cgroup,
                        crate::native_stdio_syscall::stopped_native_syscall_info(tid)?,
                    )?;
                self.resume(tid, 0)
            }
            Wait::Exited(_) | Wait::Killed { .. } => {
                if let Some(stdio) = &mut self.stdio {
                    stdio.end(tid, "final-wait")?;
                }
                let task = self.active.remove(&tid).ok_or("final task disappeared")?;
                self.final_waits += 1;
                self.append("task-final-wait",json!({"id":id,"tid":tid,"tgid":task.task.tgid,
                    "start_ticks":task.task.start,"status":final_value(event)?,"death_observed":true}))
            }
            Wait::Delivery(signal) => {
                self.append(
                    "signal-delivery",
                    json!({"id":id,"tid":tid,"signal":signal}),
                )?;
                self.resume(tid, signal)
            }
            Wait::Event {
                event: Event::Fork | Event::Vfork | Event::Clone,
                ..
            } => {
                self.active[&tid].task.recheck(&self.cgroup)?;
                let child = u32::try_from(sys::message(tid)?)
                    .ok()
                    .filter(|n| *n > 0 && *n <= i32::MAX as u32)
                    .ok_or("positive created TID required")?;
                let kind = match event {
                    Wait::Event {
                        event: Event::Fork, ..
                    } => "fork",
                    Wait::Event {
                        event: Event::Vfork,
                        ..
                    } => "vfork",
                    _ => "clone",
                };
                if self.active.len() + self.births.len() >= 128
                    || self.active.contains_key(&child)
                    || self
                        .births
                        .insert(
                            child,
                            Birth {
                                parent_id: id,
                                parent_tid: tid,
                                kind,
                            },
                        )
                        .is_some()
                {
                    return Err("duplicate creation or owned task bound exceeded".into());
                }
                self.append(
                    "kernel-creation",
                    json!({"parent_id":id,"parent_tid":tid,"child_tid":child,"creation":kind}),
                )?;
                if let Some(stop) = self.pending.remove(&child) {
                    self.register(child, stop)?;
                }
                self.resume(tid, 0)
            }
            Wait::Event {
                event: Event::Exec, ..
            } => self.exec(tid),
            Wait::Event {
                event: Event::Exiting,
                ..
            } => {
                let raw =
                    i32::try_from(sys::message(tid)?).map_err(|_| "early exit status bound")?;
                let status = final_value(crate::native_trace_wait::decode(raw)?)?;
                self.append(
                    "task-exit-stop",
                    json!({"id":id,"tid":tid,"status":status,"death_observed":false}),
                )?;
                self.resume(tid, 0)
            }
            Wait::Event {
                event: Event::VforkDone,
                ..
            } => {
                self.append(
                    "vfork-done",
                    json!({"id":id,"tid":tid,"child_tid":sys::message(tid)?}),
                )?;
                self.resume(tid, 0)
            }
            Wait::Event {
                event: Event::SeizeStop,
                signal,
            } => {
                self.append("seized-stop", json!({"id":id,"tid":tid,"signal":signal}))?;
                if matches!(signal, 19..=22) {
                    if !sys::listen(tid)? {
                        self.append(
                            "listen-stop-lost",
                            json!({"id":id,"tid":tid,"death_observed":false}),
                        )?;
                    }
                    Ok(())
                } else {
                    self.resume(tid, 0)
                }
            }
        }
    }

    fn exec(&mut self, tid: u32) -> Result<()> {
        let old = u32::try_from(sys::message(tid)?).map_err(|_| "former exec TID bound")?;
        let caller = self
            .active
            .get(&old)
            .ok_or("exec caller was not recorded")?;
        if caller.task.tgid != tid {
            return Err("exec caller group differs from reported leader".into());
        }
        let id = caller.id;
        let old_start = caller.task.start;
        let task = Task::open(tid, &self.cgroup)?;
        if task.tgid != tid {
            return Err("exec did not leave a single group leader".into());
        }
        let image = task.exec_image(&self.cgroup)?;
        let group = self
            .active
            .iter()
            .filter(|(_, v)| v.task.tgid == tid)
            .map(|(t, _)| *t)
            .collect::<Vec<_>>();
        let mut retired = Vec::new();
        for other in group {
            if let Some(stdio) = &mut self.stdio {
                stdio.end(other, "exec-replacement")?;
            }
            let entry = self.active.remove(&other).ok_or("exec group changed")?;
            if entry.id != id {
                retired.push(
                    json!({"id":entry.id,"tid":other,"start_ticks":entry.task.start,
                    "reason":"kernel-exec-thread-replacement","final_wait_observed":false}),
                );
                self.retired.insert(other, entry.id);
                self.exec_retirements += 1;
            }
        }
        if self.retired.len() > 65536 {
            return Err("retired exec task bound exceeded".into());
        }
        self.append(
            "task-exec",
            json!({"id":id,"old_tid":old,"old_start_ticks":old_start,
            "retired":retired,"image":image}),
        )?;
        if let Some(stdio) = &mut self.stdio {
            stdio.consider(&task, &image, id, self.journal.events() - 1)?;
        }
        self.active.insert(tid, Entry { id, task });
        self.execs += 1;
        self.resume(tid, 0)
    }
}

fn final_value(event: Wait) -> Result<Value> {
    match event {
        Wait::Exited(code) => Ok(json!({"kind":"exit","code":code})),
        Wait::Killed {
            signal,
            core_dumped,
        } => Ok(json!({"kind":"signal","signal":signal,"core_dumped":core_dumped})),
        _ => Err("final wait status required".into()),
    }
}
