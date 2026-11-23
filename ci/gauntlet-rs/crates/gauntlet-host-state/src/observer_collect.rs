//! Independent bounded samplers; they send data and never mutate host state.

use crate::lifecycle_document::TAGS;
use crate::observer_process::run_probe;
use crate::{sample_host, ObserverConfiguration, TagLookupPlan, VmNativeProbePlan};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn now_ms() -> Result<u64, crate::HostLifecycleError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .filter(|n| *n > 0)
        .ok_or(crate::HostLifecycleError::Clock)
}

pub(crate) enum Update {
    Host(Value),
    Vm(Value),
    Release(Value),
    TelemetryDone,
    SourcesDone,
}

struct Completion(mpsc::Sender<Update>, bool);
impl Drop for Completion {
    fn drop(&mut self) {
        let _ = self.0.send(if self.1 {
            Update::TelemetryDone
        } else {
            Update::SourcesDone
        });
    }
}

pub(crate) struct Samplers {
    stop: Arc<AtomicBool>,
    telemetry: Option<JoinHandle<()>>,
    sources: Option<JoinHandle<()>>,
    pub(crate) sender: mpsc::Sender<Update>,
}

impl Samplers {
    pub(crate) fn new(sender: mpsc::Sender<Update>) -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            telemetry: None,
            sources: None,
            sender,
        }
    }
    pub(crate) fn telemetry_idle(&self) -> bool {
        self.telemetry.is_none()
    }
    pub(crate) fn sources_idle(&self) -> bool {
        self.sources.is_none()
    }
    pub(crate) fn telemetry(&mut self, config: ObserverConfiguration, path: PathBuf) {
        let sender = self.sender.clone();
        let cancel = Arc::clone(&self.stop);
        self.telemetry = Some(thread::spawn(move || {
            let _completion = Completion(sender.clone(), true);
            thread::scope(|scope| {
                let host_sender = sender.clone();
                scope.spawn(move || {
                    let value = sample_host(&path)
                        .unwrap_or_else(|_| json!({"status":"unavailable","checked_at":0}));
                    let _ = host_sender.send(Update::Host(value));
                });
                scope.spawn(|| {
                    let value = VmNativeProbePlan::new(&config.operations, &config.vm_probe_sha256)
                        .and_then(|plan| plan.execute_read_only(&cancel))
                        .unwrap_or_else(|_| json!({"status":"unavailable","checked_at":0}));
                    let _ = sender.send(Update::Vm(value));
                });
            });
        }));
    }
    pub(crate) fn sources(&mut self, config: ObserverConfiguration) {
        let sender = self.sender.clone();
        let cancel = Arc::clone(&self.stop);
        self.sources = Some(thread::spawn(move || {
            let _completion = Completion(sender.clone(), false);
            thread::scope(|scope| {
                for tag in TAGS {
                    let sender = sender.clone();
                    let operations = &config.operations;
                    let cancel = &cancel;
                    scope.spawn(move||{
                        let source=TagLookupPlan::new(operations,tag).ok().and_then(|plan|{
                            let raw=run_probe(&plan.argv,Duration::from_secs(60),64*1024,
                                &[("GIT_TERMINAL_PROMPT","0")],cancel).ok()?;
                            plan.parse_response(&raw).ok()
                        });
                        let checked=now_ms().map(|n|n as f64/1000.0).unwrap_or(0.0);
                        let _=sender.send(Update::Release(json!({"tag":tag,"sha":source.map(|v|v["sha"].clone()),"checked_at":checked})));
                    });
                }
            });
        }));
    }
    pub(crate) fn apply(
        &mut self,
        update: Update,
        observations: &mut Value,
    ) -> Result<(), crate::HostLifecycleError> {
        match update {
            Update::Host(value) => observations["host"] = value,
            Update::Vm(value) => observations["vm"] = value,
            Update::Release(value) => {
                observations["source_checked_at"] = value["checked_at"].clone();
                let rows = observations["releases"]
                    .as_array_mut()
                    .ok_or(crate::HostLifecycleError::InvalidState)?;
                if let Some(row) = rows.iter_mut().find(|row| row["tag"] == value["tag"]) {
                    *row = value;
                } else {
                    rows.push(value);
                }
            }
            Update::TelemetryDone => {
                if let Some(handle) = self.telemetry.take() {
                    handle.join().map_err(|_| crate::HostLifecycleError::Io)?;
                }
            }
            Update::SourcesDone => {
                if let Some(handle) = self.sources.take() {
                    handle.join().map_err(|_| crate::HostLifecycleError::Io)?;
                }
            }
        }
        Ok(())
    }
}

impl Drop for Samplers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.telemetry.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.sources.take() {
            let _ = handle.join();
        }
    }
}

pub fn collect_observer_once(
    config: &ObserverConfiguration,
    path: &std::path::Path,
    shutdown: &AtomicBool,
) -> Result<Value, crate::HostLifecycleError> {
    let (sender, receiver) = mpsc::channel();
    let mut samplers = Samplers::new(sender);
    let mut observations = json!({"releases":[]});
    samplers.telemetry(config.clone(), path.to_owned());
    samplers.sources(config.clone());
    while !(samplers.telemetry_idle() && samplers.sources_idle()) {
        if shutdown.load(Ordering::Acquire) {
            return Err(crate::HostLifecycleError::ObserverStopped);
        }
        if let Ok(update) = receiver.recv_timeout(Duration::from_millis(50)) {
            samplers.apply(update, &mut observations)?;
        }
    }
    Ok(observations)
}
