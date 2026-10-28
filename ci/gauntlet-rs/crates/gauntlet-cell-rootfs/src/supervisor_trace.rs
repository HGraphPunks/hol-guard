//! Opt-in launch v3 binds the recorder before any private workload request.
use crate::{NativeCell, NativeProcessEvents, Result};
use serde_json::{json, Value};
use std::time::Duration;

impl NativeCell {
    pub(crate) fn start_process_events(&mut self) -> Result<()> {
        if !self.spec.process_events {
            return Ok(());
        }
        if self.process_events.is_some() || self.process_events_result.is_some() {
            return Err("process recorder is one use".into());
        }
        let actor = self
            .actor
            .as_ref()
            .ok_or("held filtered actor required before recorder startup")?;
        let recorder = NativeProcessEvents::start(actor, &self.inputs.spec.stage)?;
        let tracer = recorder.tracer_tid();
        self.process_events = Some(recorder);
        let actor = self.actor.as_mut().unwrap();
        actor.adopt_trace_owner(tracer)?;
        self.journal.append("process-events-started",json!({"schema":"hol-gauntlet-native-process-recorder-started.v1",
            "mode":"outside-root-ptrace.v1","tracer_tid":tracer,"actor":actor.observation(),"execution_eligible":false}))
    }

    pub(crate) fn recorder_health(&self) -> Result<()> {
        if !self.spec.process_events {
            return Ok(());
        }
        self.process_events
            .as_ref()
            .ok_or("required owned process recorder unavailable")?
            .check()
    }

    pub(crate) fn close_process_events(&mut self) -> Result<()> {
        if !self.spec.process_events {
            return Ok(());
        }
        if self.process_events_result.is_none() {
            let result = self
                .process_events
                .as_mut()
                .ok_or_else(|| "required process recorder was not established".to_owned())
                .and_then(|recorder| recorder.finish(Duration::from_secs(5)));
            self.process_events_result = Some(result);
            self.process_events = None;
        }
        if !self.process_events_journaled {
            let observation = self
                .process_events_observation()
                .ok_or("required process recorder observation missing")?;
            self.journal.append("process-events-closed", observation)?;
            self.process_events_journaled = true;
        }
        self.process_events_result
            .as_ref()
            .unwrap()
            .as_ref()
            .map(|_| ())
            .map_err(Clone::clone)
    }

    pub(crate) fn process_events_observation(&self) -> Option<Value> {
        if !self.spec.process_events {
            return None;
        }
        Some(match &self.process_events_result {
            Some(Ok(checkpoint)) => {
                json!({"schema":"hol-gauntlet-native-process-recorder.v1","available":true,"checkpoint":checkpoint})
            }
            Some(Err(error)) => {
                json!({"schema":"hol-gauntlet-native-process-recorder.v1","available":false,"error":error})
            }
            None => {
                json!({"schema":"hol-gauntlet-native-process-recorder.v1","available":false,"error":"recorder not closed"})
            }
        })
    }
}
