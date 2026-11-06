//! Opt-in, outside-Root recording bound to an already held product actor.
use crate::native_trace_engine::Engine;
use crate::native_trace_task::Task;
use crate::supervisor_journal::Journal;
use crate::{HeldCellProcess, Result};
use serde_json::Value;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

type SharedResult = Arc<Mutex<Option<Result<Value>>>>;

/// Dropping a live recorder requests failure and leaves EXITKILL in force.
/// Success requires the kernel's final statuses or explicit exec replacements
/// for all recorded tasks. This API grants no image or benchmark admission.
pub struct NativeProcessEvents {
    abort: Arc<AtomicBool>,
    result: SharedResult,
    thread: Option<JoinHandle<()>>,
    tracer_tid: u32,
}

impl NativeProcessEvents {
    pub fn start(actor: &HeldCellProcess, stage: &Path) -> Result<Self> {
        Self::start_mode(actor, stage, None)
    }

    pub fn start_with_stdio(actor: &HeldCellProcess, stage: &Path, native: &str) -> Result<Self> {
        Self::start_mode(actor, stage, Some(native))
    }

    fn start_mode(actor: &HeldCellProcess, stage: &Path, native: Option<&str>) -> Result<Self> {
        actor.recheck()?;
        let expected = actor.observation().clone();
        if expected["argv"] != serde_json::json!(["/public/gauntlet-product-cell", "actor"]) {
            return Err("only the measured filtered product PID1 actor may be traced".into());
        }
        let pid = expected["pid"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or("held actor PID required")?;
        let start = expected["start_ticks"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("held actor generation required")?;
        let cgroup = expected["cgroup"]
            .as_str()
            .ok_or("held actor cgroup required")?
            .to_owned();
        let stdio = native
            .map(|pin| crate::native_stdio_recorder::Recorder::create(stage, pin))
            .transpose()?;
        Self::launch(pid, start, cgroup, stage, Some(expected), stdio)
    }

    fn launch(
        pid: u32,
        start: u64,
        cgroup: String,
        stage: &Path,
        expected: Option<Value>,
        stdio: Option<crate::native_stdio_recorder::Recorder>,
    ) -> Result<Self> {
        crate::kernel_process::root_proc()?;
        let journal = Journal::create_process_events(stage)?;
        let abort = Arc::new(AtomicBool::new(false));
        let result: SharedResult = Arc::new(Mutex::new(None));
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread_abort = abort.clone();
        let thread_result = result.clone();
        let thread=std::thread::Builder::new().name("gauntlet-cell-events".into()).spawn(move||{
            let outcome=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
                let task=Task::open(pid,&cgroup)?;
                if task.start!=start {return Err("actor generation changed before trace attachment".into());}
                if expected.is_some() {task.initial_actor(start,&cgroup)?;}
                let mut engine=Engine::new(task,cgroup,journal,thread_abort,expected,stdio);
                let outcome=engine.run(&sender);
                if let Err(error)=&outcome {
                    engine.fail_stdio(error);
                    let _=engine.journal.append("trace-failed",serde_json::json!({"error":error,"complete":false,"execution_eligible":false}));
                }
                outcome
            })).unwrap_or_else(|_|Err("owned process recorder panicked; history incomplete".into()));
            if let Ok(mut slot)=thread_result.lock() {*slot=Some(outcome.clone());}
            if let Err(error)=outcome {let _=sender.try_send(Err(error));}
            // Exiting this very tracer thread keeps PTRACE_O_EXITKILL effective
            // on every surviving tracee. No detach or foreign signal is used.
        }).map_err(|e|e.to_string())?;
        let mut recorder = Self {
            abort,
            result,
            thread: Some(thread),
            tracer_tid: 0,
        };
        match receiver.recv_timeout(Duration::from_secs(6)) {
            Ok(Ok(tid)) => {
                recorder.tracer_tid = tid;
                Ok(recorder)
            }
            Ok(Err(error)) => {
                recorder.abort.store(true, Ordering::Release);
                Err(error)
            }
            Err(_) => {
                recorder.abort.store(true, Ordering::Release);
                let _ = recorder.reap_finished();
                Err("owned recorder readiness unavailable; retain incomplete journal".into())
            }
        }
    }

    pub fn check(&self) -> Result<()> {
        let slot = self
            .result
            .lock()
            .map_err(|_| "owned recorder result poisoned")?;
        if let Some(Err(error)) = &*slot {
            return Err(error.clone());
        }
        if self.thread.as_ref().is_some_and(|t| t.is_finished()) && slot.is_none() {
            return Err("owned recorder exited without a result".into());
        }
        Ok(())
    }

    pub fn tracer_tid(&self) -> u32 {
        self.tracer_tid
    }

    fn reap_finished(&mut self) -> Result<()> {
        if self.thread.as_ref().is_some_and(|t| t.is_finished()) {
            self.thread
                .take()
                .unwrap()
                .join()
                .map_err(|_| "owned recorder thread join failed")?;
        }
        Ok(())
    }

    /// Call after the cell owner has stopped the unit. A timeout never becomes
    /// death evidence, and an early-exit stop never becomes a final status.
    pub fn finish(&mut self, timeout: Duration) -> Result<Value> {
        if timeout > Duration::from_secs(10) {
            return Err("recorder drain bound is ten seconds".into());
        }
        let deadline = Instant::now() + timeout;
        loop {
            self.reap_finished()?;
            let value = self
                .result
                .lock()
                .map_err(|_| "owned recorder result poisoned")?
                .clone();
            if let Some(value) = value {
                return value;
            }
            if Instant::now() >= deadline {
                self.abort.store(true, Ordering::Release);
                return Err("owned recorder drain timed out; no complete history".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[cfg(all(test, feature = "owned-process-trace-fixture"))]
    pub(crate) fn start_fixture(pid: u32, cgroup: String, stage: &Path) -> Result<Self> {
        let task = Task::open(pid, &cgroup)?;
        Self::launch(pid, task.start, cgroup, stage, None, None)
    }

    #[cfg(all(test, feature = "owned-process-trace-fixture"))]
    pub(crate) fn start_stdio_fixture(
        pid: u32,
        cgroup: String,
        stage: &Path,
        native: &str,
    ) -> Result<Self> {
        let task = Task::open(pid, &cgroup)?;
        let stdio = crate::native_stdio_recorder::Recorder::create_fixture(stage, native)?;
        Self::launch(pid, task.start, cgroup, stage, None, Some(stdio))
    }
}

impl Drop for NativeProcessEvents {
    fn drop(&mut self) {
        self.abort.store(true, Ordering::Release);
        let _ = self.reap_finished();
    }
}
