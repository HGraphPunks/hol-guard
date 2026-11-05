//! A reachable synthetic effect and actual Native Pre/sink refusal are
//! recorded separately. A runtime failure never stands in for a Guard deny.
use crate::native_forbidden_fixture::{require_absent, NativeForbiddenFixture, INSIDE, SEED};
use crate::native_request::NativeRequest;
use crate::{hash, CapturedProcess, NativeHookPlane, Result};
use serde_json::{json, Value};
use std::time::Duration;

fn capture(
    plane: &mut NativeHookPlane,
    phase: &str,
    argv: &[String],
    input: &[u8],
    timeout: u64,
) -> Result<CapturedProcess> {
    let result = plane
        .cell
        .capture(argv, input, Duration::from_secs(timeout));
    plane.observations.push(json!({"kind":"native-forbidden-control-capture","phase":phase,"native_command":argv,
        "input_sha256":hash(input),"exit_code":result.as_ref().ok().map(|v|v.returncode),
        "stdout_sha256":result.as_ref().ok().map(|v|hash(&v.stdout)),
        "stderr_sha256":result.as_ref().ok().map(|v|hash(&v.stderr)),"error":result.as_ref().err()}));
    result
}
fn seed(plane: &mut NativeHookPlane) -> Result<()> {
    let argv = ["/usr/bin/python3", "-I", "-B", "-c", SEED].map(String::from);
    let result = capture(plane, "seed-synthetic-target", &argv, b"", 5)?;
    if result.returncode != 0 {
        return Err("fixed synthetic forbidden-command seed failed".into());
    }
    Ok(())
}
impl NativeHookPlane {
    pub fn probe_forbidden_command(&mut self) -> Result<Value> {
        if !self.ready || self.cell.cleanup_complete() {
            return Err("live Native plane required for forbidden control".into());
        }
        let task = self.cell.inputs.tasks[0].clone();
        require_absent(&task)?;
        seed(self)?;
        let positive_before = NativeForbiddenFixture::open(&task)?;
        let positive = capture(
            self,
            "positive-unguarded-deletion",
            &["/usr/bin/rm", "-rf", "--", INSIDE].map(String::from),
            b"",
            5,
        )?;
        let positive_retired = positive_before.retired();
        self.observations.push(json!({"kind":"native-forbidden-positive-readback","marker":positive_before.observation(),
            "exit_code":positive.returncode,"retired":positive_retired.is_ok(),"error":positive_retired.as_ref().err()}));
        positive_retired?;
        if positive.returncode != 0 {
            return Err("synthetic unguarded forbidden effect was not reachable".into());
        }
        seed(self)?;
        let mut protected = NativeForbiddenFixture::open(&task)?;
        let before = protected.observation();
        let command = format!("rm -rf {INSIDE}");
        let payload = json!({"hook_event_name":"PreToolUse","config_path":"/product/home/omp.json","tool_name":"bash",
            "tool_call_id":"forbidden-command-probe","session_id":self.session,"tool_input":{"command":command}});
        let decision = self.invoke(&payload)?;
        let raw = gauntlet_contracts::canonicalize(
            json!({"schema":"guard-contained-test-request.v1",
            "workspace":"/runtime/home/project","payload":payload})
            .to_string()
            .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        let mut handoff = NativeRequest::for_cell(&self.cell, &raw)?;
        let request = handoff.observation();
        let path = handoff.path();
        let pin = handoff.sha256().to_owned();
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
            &path,
            "--request-sha256",
            &pin,
            "--timeout-seconds",
            "5",
        ]);
        handoff.verify_before_execution()?;
        let executed = capture(self, "protected-contained-sink", &argv, b"", 15);
        let cleanup = handoff.cleanup();
        let preserved = protected.preserved();
        let exit = executed.as_ref().ok().map(|v| v.returncode);
        let actual_deny = matches!(decision["decision"].as_str(), Some("deny" | "block"))
            && decision["reason"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty())
            && decision.get("policy_action").is_none_or(|v| {
                v.as_str()
                    .is_some_and(|s| !matches!(s, "allow" | "warn" | "sandbox-required"))
            })
            && decision.get("required_execution_profile").is_none()
            && decision["observe_mode"] != true;
        let authorization_refused = executed
            .as_ref()
            .is_ok_and(|v| crate::native_guard_negative_cases::rejected(&v.stderr));
        let passed = exit == Some(126)
            && authorization_refused
            && actual_deny
            && cleanup.is_ok()
            && preserved.as_ref() == Ok(&true);
        let result = json!({"schema":"hol-gauntlet-native-forbidden-command-control.v1","status":if passed{"passed"}else{"failed"},
            "positive_exit_code":positive.returncode,"positive_effect_observed":true,
            "positive_marker":positive_before.observation(),"marker_before":before,
            "native_pre_decision":decision,"native_pre_payload":payload,"request":request,"native_command":argv,
            "exit_code":exit,"stdout_sha256":executed.as_ref().ok().map(|v|hash(&v.stdout)),
            "stderr":executed.as_ref().ok().map(|v|String::from_utf8_lossy(&v.stderr).into_owned()),
            "capture_error":executed.as_ref().err(),"native_sink_authorization_refused":authorization_refused,
            "effect_present":preserved.as_ref().ok().map(|v|!v),
            "marker_sha256_after":preserved.as_ref().ok().filter(|v|**v).map(|_|hash(b"preserve")),
            "marker_custody_error":preserved.as_ref().err(),"cleanup_complete":cleanup.is_ok(),"cleanup_error":cleanup.as_ref().err(),
            "root_control_probe_not_sdk_operation":true,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
        self.observations
            .push(json!({"kind":"native-forbidden-command-control","observation":result}));
        Ok(result)
    }
}
