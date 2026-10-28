//! Rust-owned normal OMP hook and contained-sink transport. SDK authority and
//! independent physical-effect scoring are separate from these measurements.
use crate::native_hook_calls::NativeHookCalls;
use crate::native_request::NativeRequest;
use crate::{hash, NativeCell, NativeGuardPins, Result};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub struct NativeHookPlane {
    pub(crate) cell: NativeCell,
    pub(crate) pins: NativeGuardPins,
    pub(crate) session: String,
    pub(crate) ready: bool,
    prompt: Option<Value>,
    calls: NativeHookCalls,
    pub(crate) observations: Vec<Value>,
    pub(crate) hooks: Vec<Value>,
    pub(crate) executions: Vec<Value>,
    lifecycle_witness: Option<crate::native_lifecycle_control::NativeLifecycleControl>,
}
pub struct NativeLifecycleExecution {
    pub execution: Option<Value>,
    pub lifecycle: Value,
}

impl NativeCell {
    pub(crate) fn product_python_command(&self, args: &[&str]) -> Vec<String> {
        [
            vec![
                self.runtime_prefix()
                    .join("bin/python")
                    .to_string_lossy()
                    .into_owned(),
                "-I".into(),
                "-B".into(),
            ],
            args.iter().map(|s| (*s).into()).collect(),
        ]
        .concat()
    }
    pub(crate) fn guard_command(&self, args: &[&str]) -> Vec<String> {
        let mut command = self.product_python_command(&["-m", "codex_plugin_scanner.cli", "guard"]);
        command.extend(args.iter().map(|s| (*s).into()));
        command
    }
}

impl NativeHookPlane {
    pub fn new(cell: NativeCell, pins: NativeGuardPins, session: &str) -> Result<Self> {
        if session.is_empty() || session.len() > 256 {
            return Err("bounded fixed Native controller session required".into());
        }
        NativeGuardPins::parse(&pins.to_json())?;
        Ok(Self {
            cell,
            pins,
            session: session.into(),
            ready: false,
            prompt: None,
            calls: NativeHookCalls::default(),
            observations: Vec::new(),
            hooks: Vec::new(),
            executions: Vec::new(),
            lifecycle_witness: None,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        if self.ready || !self.observations.is_empty() {
            return Err("Native hook plane is one use".into());
        }
        self.observations.push(
            json!({"kind":"native-hook-plane-start-attempt","product_claims_authenticated":false}),
        );
        crate::native_guard_probe::inert_native(&self.cell, &self.pins)?;
        let claim = crate::native_guard_probe::identity(&mut self.cell, &self.pins)?;
        self.observations.push(json!({"kind":"unprivileged-identity-adapter","claim":claim,"product_claims_authenticated":false}));
        // Native path trust uses the explicit configured home. HOME alone
        // cannot place the idmapped task beneath that root. Guard state and
        // the public OMP config remain at their separately fixed paths.
        let mut argv = vec!["/usr/bin/env".into(), "HOME=/runtime/home".into()];
        argv.extend(self.cell.guard_command(&[
            "daemon",
            "--serve",
            "--guard-home",
            "/product/guard",
            "--home",
            "/runtime/home",
            "--port",
            "18765",
            "--workspace",
            self.cell.workspace_path(),
        ]));
        let handle = self
            .cell
            .spawn(&argv, Instant::now() + Duration::from_secs(5))?;
        self.cell
            .release(&handle, Instant::now() + Duration::from_secs(5))?;
        self.cell
            .end_input(&handle, Instant::now() + Duration::from_secs(5))?;
        let setup = Instant::now() + Duration::from_secs(60);
        let command = self.cell.guard_command(&[
            "daemon",
            "status",
            "--json",
            "--guard-home",
            "/product/guard",
            "--home",
            "/runtime/home",
        ]);
        let mut started = false;
        for _ in 0..60 {
            if self
                .cell
                .read_process(&handle, 0, setup)?
                .returncode
                .is_some()
            {
                return Err("Native daemon exited before hook readiness".into());
            }
            let left = setup
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(30));
            let status = self.cell.capture(&command, b"", left)?;
            self.observations.push(json!({"kind":"native-daemon-readiness","exit_code":status.returncode,"stdout_sha256":hash(&status.stdout)}));
            if status.returncode == 0
                && serde_json::from_slice::<Value>(&status.stdout)
                    .ok()
                    .is_some_and(|v| v["running"] == true)
            {
                started = true;
                break;
            }
            if Instant::now() >= setup {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !started {
            return Err("Native daemon hook readiness deadline".into());
        }
        let barrier =
            crate::native_guard_probe::readiness(&mut self.cell, setup, &mut self.observations)?;
        self.observations
            .push(json!({"kind":"native-workspace-readiness","response":barrier}));
        self.ready = true;
        Ok(())
    }

    pub(crate) fn invoke(&mut self, payload: &Value) -> Result<Value> {
        if !self.ready
            || self.cell.cleanup_complete()
            || payload["config_path"] != "/product/home/omp.json"
            || !matches!(
                payload["hook_event_name"].as_str(),
                Some("UserPromptSubmit" | "PreToolUse" | "PostToolUse")
            )
        {
            return Err("live fixed Native hook context required".into());
        }
        let mut raw = gauntlet_contracts::canonicalize(payload.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        let payload_digest = hash(&raw);
        raw.push(b'\n');
        if raw.len() > 1024 * 1024 || self.hooks.len() >= 1001 {
            return Err("Native hook input/observation bound".into());
        }
        let argv = self.cell.guard_command(&[
            "hook",
            "--json",
            "--harness",
            "omp",
            "--guard-home",
            "/product/guard",
            "--home",
            "/runtime/home",
            "--workspace",
            self.cell.workspace_path(),
        ]);
        let completed = self.cell.capture(&argv, &raw, Duration::from_secs(30))?;
        let normalized = if completed.stdout.len() <= 1024 * 1024 {
            gauntlet_evidence::normalize_native_hook_response(
                &completed.stdout,
                completed.returncode,
                payload["hook_event_name"].as_str(),
            )
            .map_err(|e| e.to_string())
        } else {
            Err("Native hook output exceeds response bound".into())
        };
        self.hooks.push(json!({"hook_event_name":payload["hook_event_name"],"payload":payload,"payload_digest":payload_digest,
            "returncode":completed.returncode,"stdout_sha256":hash(&completed.stdout),"stderr_sha256":hash(&completed.stderr),
            "response":normalized.as_ref().ok(),"normalization_error":normalized.as_ref().err(),"product_claims_authenticated":false}));
        normalized
    }

    pub fn submit_prompt(&mut self, prompt: &str) -> Result<Value> {
        if self.prompt.is_some() || prompt.is_empty() || prompt.len() > 1024 * 1024 {
            return Err("one bounded public Native prompt required".into());
        }
        let prompt_digest = hash(
            &gauntlet_contracts::canonicalize(json!(prompt).to_string().as_bytes())
                .map_err(|e| e.to_string())?,
        );
        self.prompt = Some(json!({"digest":prompt_digest,"response":null}));
        let value=self.invoke(&json!({"hook_event_name":"UserPromptSubmit","config_path":"/product/home/omp.json","session_id":self.session,"prompt":prompt}))?;
        self.prompt.as_mut().unwrap()["response"] = value.clone();
        Ok(value)
    }

    pub fn review_before(&mut self, id: &str, command: &str, environment: &Value) -> Result<Value> {
        self.review_before_input(id, &json!({"command":command}), environment)
    }

    /// Preserve the complete SDK input, including any declared Bash options.
    /// Session selection stays with the Root controller, never the sender.
    pub fn review_before_input(
        &mut self,
        id: &str,
        input: &Value,
        environment: &Value,
    ) -> Result<Value> {
        if self
            .prompt
            .as_ref()
            .is_none_or(|v| v["response"]["decision"] != "allow")
            || !environment.is_object()
            || !input.is_object()
            || !input["command"].is_string()
        {
            return Err("actual allowed public prompt and typed execution context required".into());
        }
        let payload = json!({"hook_event_name":"PreToolUse","config_path":"/product/home/omp.json","session_id":self.session,
            "tool_call_id":id,"tool_name":"bash","tool_input":input,"guard_execution_environment":environment,
            "guard_contained_output_profile":"controller-contained-output.v1"});
        self.calls.reserve(&payload)?;
        let response = self.invoke(&payload)?;
        self.calls.record_review(id, &response)?;
        Ok(response)
    }

    pub fn execute_contained(&mut self, id: &str, timeout: u64) -> Result<Value> {
        self.execute_profile(id, timeout, None)?
            .0
            .ok_or("normal Native sink lacks actual capture".into())
    }
    pub fn execute_lifecycle(
        &mut self,
        id: &str,
        role: crate::NativeControlRole,
    ) -> Result<NativeLifecycleExecution> {
        if !role.lifecycle() {
            return Err("closed lifecycle role required".into());
        }
        let timeout = if role == crate::NativeControlRole::Timeout {
            5
        } else {
            30
        };
        let (execution, lifecycle) = self.execute_profile(id, timeout, Some(role))?;
        Ok(NativeLifecycleExecution {
            execution,
            lifecycle: lifecycle.ok_or("lifecycle observation missing")?,
        })
    }
    fn execute_profile(
        &mut self,
        id: &str,
        timeout: u64,
        role: Option<crate::NativeControlRole>,
    ) -> Result<(Option<Value>, Option<Value>)> {
        if !(1..=90).contains(&timeout) {
            return Err("bounded native transport sink deadline required".into());
        }
        let payload = self.calls.begin_sink(id)?;
        let mut lifecycle = role
            .map(|r| crate::native_lifecycle_control::NativeLifecycleControl::new(&self.cell, r))
            .transpose()?;
        let raw=gauntlet_contracts::canonicalize(json!({"schema":"guard-contained-test-request.v1","workspace":self.cell.workspace_path(),"payload":payload}).to_string().as_bytes()).map_err(|e|e.to_string())?;
        let mut request = NativeRequest::for_cell(&self.cell, &raw)?;
        let observation = request.observation();
        let path = request.path();
        let pin = request.sha256().to_owned();
        let seconds = timeout.to_string();
        let argv = self.cell.guard_command(&[
            "execute-contained-test",
            "--harness",
            "omp",
            "--guard-home",
            "/product/guard",
            "--home",
            "/runtime/home",
            "--workspace",
            self.cell.workspace_path(),
            "--request-file",
            &path,
            "--request-sha256",
            &pin,
            "--timeout-seconds",
            &seconds,
        ]);
        request.verify_before_execution()?;
        let captured = if let Some(control) = lifecycle.as_mut() {
            self.cell.capture_observed(
                &argv,
                b"",
                Duration::from_secs(timeout + 30),
                |cell, handle| control.observe(cell, handle),
            )
        } else {
            self.cell
                .capture(&argv, b"", Duration::from_secs(timeout + 30))
        };
        let lifecycle_observation = lifecycle.as_mut().map(|v| v.finish(&self.cell, &captured));
        self.lifecycle_witness = lifecycle;
        let lifecycle = lifecycle_observation;
        if let Some(control) = &lifecycle {
            self.observations
                .push(json!({"kind":"native-detached-lifecycle-control","observation":control}));
        }
        let cleanup = request.cleanup();
        self.observations.push(json!({"kind":"native-contained-request-handoff","request":observation,"cleanup_complete":cleanup.is_ok(),"cleanup_error":cleanup.as_ref().err(),"capture_error":captured.as_ref().err()}));
        cleanup?;
        if role == Some(crate::NativeControlRole::Cancel)
            && lifecycle.as_ref().is_some_and(|v| v["status"] == "passed")
            && captured.is_err()
        {
            return Ok((None, lifecycle));
        }
        let completed = captured?;
        let result = json!({"schema_version":"1.0","exit_code":completed.returncode,"stdout":String::from_utf8_lossy(&completed.stdout),"stderr":String::from_utf8_lossy(&completed.stderr),
            "stdout_sha256":hash(&completed.stdout),"stderr_sha256":hash(&completed.stderr),"payload_digest":hash(&gauntlet_contracts::canonicalize(payload.to_string().as_bytes()).map_err(|e|e.to_string())?),
            "request_sha256":pin,"native_command":argv,"product_claims_authenticated":false,"containment_conformance_established":false});
        self.executions.push(result.clone());
        self.calls.record_sink(id, &result)?;
        Ok((Some(result), lifecycle))
    }

    pub fn review_after(&mut self, id: &str) -> Result<(Value, Value)> {
        let (payload, output) = self.calls.begin_post(id)?;
        let response = self.invoke(&payload)?;
        Ok((response, output))
    }
    pub fn close(&mut self) -> Result<()> {
        self.ready = false;
        self.cell.close()
    }
    pub fn verify_closed_lifecycle(
        &mut self,
        preparation: &crate::CellPreparation,
        role: crate::NativeControlRole,
        control: &Value,
    ) -> Result<Value> {
        if !self.cell.cleanup_complete() {
            return Err("closed lifecycle requires drained product cell".into());
        }
        self.lifecycle_witness
            .as_mut()
            .ok_or("actual held lifecycle witness missing")?
            .verify_closed(preparation, role, control)
    }
    pub fn observation(&self) -> Value {
        let journal = self.cell.capture_journal_binding().unwrap_or_else(|error| {
            json!({
            "schema":"hol-gauntlet-cell-journal-binding.v1","available":false,"error":error})
        });
        json!({"schema":"hol-gauntlet-native-hook-plane.v1","pins":self.pins.to_json(),"controller_session_id":self.session,
            "capture_input_receipt_schema":"hol-gauntlet-capture-input-terminal.v1","capture_journal":journal,
            "prompt":self.prompt,"observations":self.observations,"hooks":self.hooks,"executions":self.executions,
            "cleanup_complete":self.cell.cleanup_complete(),"identity_adapter_sha256":hash(crate::native_guard_probe::IDENTITY.as_bytes()),
            "readiness_adapter_sha256":hash(crate::native_guard_probe::READINESS.as_bytes()),
            "sdk_exercised":false,"product_claims_authenticated":false,"guard_causality_verified":false,"execution_eligible":false,"model_requests":0})
    }
}
