//! Real installed Native request-binding refusals, with independent physical
//! trap readback. Root probes do not debit or impersonate SDK operations.
use crate::native_binding_fixture::NativeBindingFixture;
use crate::native_guard_negative_cases::{rejected, request, NAMES};
use crate::native_request::NativeRequest;
use crate::{hash, NativeHookPlane, Result};
use serde_json::{json, Value};
use std::time::Duration;

impl NativeHookPlane {
    pub fn probe_input_bindings(&mut self) -> Result<Value> {
        if !self.ready || self.cell.cleanup_complete() {
            return Err("live Native plane required for binding controls".into());
        }
        let mut fixture = NativeBindingFixture::create(&self.cell.inputs.tasks[0])?;
        let mut rows = Vec::new();
        for case in NAMES {
            fixture.verify()?;
            let (raw, declared) = request(case, &self.session)?;
            let mut handoff = NativeRequest::for_cell(&self.cell, &raw)?;
            let observation = handoff.observation();
            let argv = self.cell.guard_command(&[
                "execute-contained-test",
                "--harness",
                "omp",
                "--guard-home",
                "/product/guard",
                "--home",
                "/runtime/home",
                "--workspace",
                "/runtime/home/project",
                "--request-file",
                &handoff.path(),
                "--request-sha256",
                &declared,
                "--timeout-seconds",
                "5",
            ]);
            handoff.verify_before_execution()?;
            let capture = self.cell.capture(&argv, b"", Duration::from_secs(15));
            let cleanup = handoff.cleanup();
            let marker = fixture.marker_present();
            let (exit, stdout, stderr, error) = match capture {
                Ok(value) => (
                    Some(value.returncode),
                    Some(value.stdout),
                    Some(value.stderr),
                    None,
                ),
                Err(error) => (None, None, None, Some(error)),
            };
            let passed = exit == Some(126)
                && stderr.as_ref().is_some_and(|bytes| rejected(bytes))
                && cleanup.is_ok()
                && marker.as_ref() == Ok(&false);
            let row = json!({"case":case,"native_command":argv,"actual_request_sha256":hash(&raw),"declared_request_sha256":declared,
                "request_wire_utf8":std::str::from_utf8(&raw).map_err(|_|"inert Native control UTF-8")?,"handoff":observation,
                "exit_code":exit,"stdout_sha256":stdout.as_ref().map(|bytes|hash(bytes)),
                "stderr":stderr.as_ref().map(|bytes|String::from_utf8_lossy(bytes).into_owned()),
                "stderr_sha256":stderr.as_ref().map(|bytes|hash(bytes)),
                "trap_effect_present":marker.as_ref().ok(),"trap_readback_error":marker.as_ref().err(),
                "cleanup_complete":cleanup.is_ok(),"cleanup_error":cleanup.as_ref().err(),"capture_error":error,"refused":passed});
            self.observations
                .push(json!({"kind":"native-request-binding-control","observation":row}));
            rows.push(row);
            if !passed {
                break;
            }
        }
        let passed = rows.len() == NAMES.len() && rows.iter().all(|r| r["refused"] == true);
        Ok(
            json!({"schema":"hol-gauntlet-native-request-binding-controls.v1","status":if passed{"passed"}else{"failed"},
            "fixture":fixture.observation(),"rows":rows,"root_control_probe_not_sdk_operation":true,
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
        )
    }
}
