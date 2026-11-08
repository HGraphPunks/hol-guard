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
        let recorder = if self.spec.native_pipe_transport {
            NativeProcessEvents::start_with_pipes(actor, &self.inputs.spec.stage)?
        } else if let Some(native) = &self.spec.native_stdio_sha256 {
            NativeProcessEvents::start_with_stdio(actor, &self.inputs.spec.stage, native)?
        } else {
            NativeProcessEvents::start(actor, &self.inputs.spec.stage)?
        };
        let tracer = recorder.tracer_tid();
        self.process_events = Some(recorder);
        let actor = self.actor.as_mut().unwrap();
        actor.adopt_trace_owner(tracer)?;
        let stdio = self.spec.native_stdio_sha256.is_some() && !self.spec.native_pipe_transport;
        self.journal.append("process-events-started",json!({"schema":if stdio {"hol-gauntlet-native-process-recorder-started.v2"}else{"hol-gauntlet-native-process-recorder-started.v1"},
            "mode":if stdio {"outside-root-ptrace.v2"}else{"outside-root-ptrace.v1"},"tracer_tid":tracer,"actor":actor.observation(),"execution_eligible":false}))
    }

    pub(crate) fn recorder_health(&self) -> Result<()> {
        if let Some(wire) = &self.native_wire {
            wire.check()?;
        }
        if !self.spec.process_events {
            return Ok(());
        }
        self.process_events
            .as_ref()
            .ok_or("required owned process recorder unavailable")?
            .check()
    }

    pub(crate) fn start_native_wire(&mut self) -> Result<()> {
        if !self.spec.native_pipe_transport {
            return Ok(());
        }
        let actor = self.actor.as_ref().ok_or("held Native actor required")?;
        let config = gauntlet_product_cell::NativeWireConfig::parse(
            self.inputs
                .native_wire
                .as_deref()
                .ok_or("Native wire configuration missing")?,
        )
        .map_err(|e| e.to_string())?;
        let images = self
            .process_events
            .as_ref()
            .ok_or("Native process recorder missing")?
            .images
            .clone();
        let owner = crate::native_wire::NativeWire::start(
            actor.network_namespace()?,
            config,
            actor.observation().clone(),
            self.native_interface_sha256()
                .ok_or("Native interface pin missing")?
                .to_owned(),
            self.cgroup.clone(),
            images,
            &self.inputs.spec.stage,
            Duration::from_secs(self.spec.wall_seconds),
        )?;
        self.native_wire = Some(owner);
        self.journal.append(
            "native-pipe-owner-ready",
            json!({"schema":"hol-gauntlet-native-pipes.v1","execution_eligible":false}),
        )
    }

    pub(crate) fn close_native_wire(&mut self) -> Result<()> {
        if !self.spec.native_pipe_transport {
            return Ok(());
        }
        if self.native_wire_result.is_none() {
            let result = self
                .native_wire
                .as_mut()
                .ok_or_else(|| "Native pipe owner was not established".to_owned())
                .and_then(|wire| wire.finish());
            self.journal.append(
                "native-pipe-owner-terminal",
                match &result {
                    Ok(binding) => {
                        json!({"available":true,"binding":binding,"execution_eligible":false})
                    }
                    Err(error) => {
                        json!({"available":false,"error":error,"execution_eligible":false})
                    }
                },
            )?;
            self.native_wire_result = Some(result);
            self.native_wire = None;
        }
        self.native_wire_result
            .as_ref()
            .unwrap()
            .as_ref()
            .map(|_| ())
            .map_err(Clone::clone)
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
        let schema = if self.spec.native_stdio_sha256.is_some() && !self.spec.native_pipe_transport
        {
            "hol-gauntlet-native-process-recorder.v2"
        } else {
            "hol-gauntlet-native-process-recorder.v1"
        };
        Some(match &self.process_events_result {
            Some(Ok(checkpoint)) => {
                json!({"schema":schema,"available":true,"checkpoint":checkpoint})
            }
            Some(Err(error)) => {
                json!({"schema":schema,"available":false,"error":error})
            }
            None => {
                json!({"schema":schema,"available":false,"error":"recorder not closed"})
            }
        })
    }

    pub(crate) fn native_wire_observation(&self) -> Option<Value> {
        if !self.spec.native_pipe_transport {
            return None;
        }
        Some(match &self.native_wire_result {
            Some(Ok(binding)) => json!({"schema":"hol-gauntlet-native-pipes.v1","available":true,
                "binding":binding,"execution_eligible":false,"exclusive_product_authorship_verified":false}),
            Some(Err(error)) => {
                json!({"schema":"hol-gauntlet-native-pipes.v1","available":false,"error":error,"execution_eligible":false})
            }
            None => {
                json!({"schema":"hol-gauntlet-native-pipes.v1","available":false,"error":"pipe owner not closed","execution_eligible":false})
            }
        })
    }
}
