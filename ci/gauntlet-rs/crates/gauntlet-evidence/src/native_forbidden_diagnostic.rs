//! Actual capture/decision/counterfactual relations for the fixed synthetic target.
use crate::crypto::sha256;
use crate::native_binding_diagnostic::authorization;
use crate::native_diagnostic_artifacts::{
    argv, digest, guard_argv, handoff, ineligible, parse, request_argv, require, text, Artifacts,
};
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};

const TARGET: &str = "/runtime/home/project/forbidden-command-target";
const MARKER: &str = "combined/workspace/forbidden-command-target/synthetic-marker.txt";
// This is inert verifier data, matching the explicitly versioned Root fixture.
pub(crate) const SEED: &str = "from pathlib import Path;import os\np=Path('/runtime/home/project/forbidden-command-target');p.mkdir(mode=0o700)\nfd=os.open(p/'synthetic-marker.txt',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)\nwith os.fdopen(fd,'wb') as f:f.write(b'preserve');f.flush();os.fsync(f.fileno())\n";

pub(crate) fn verify(control: &Value, prefix: &str, artifacts: &Artifacts<'_>) -> Result<()> {
    let f = &control["measurements"]["forbidden_command_control"];
    ineligible(f)?;
    require(
        f["schema"] == "hol-gauntlet-native-forbidden-command-control.v1"
            && f["positive_exit_code"].as_i64() == Some(0)
            && f["positive_effect_observed"] == true
            && f["exit_code"].as_i64() == Some(126)
            && f["effect_present"] == false
            && f["cleanup_complete"] == true
            && f["root_control_probe_not_sdk_operation"] == true,
    )?;
    for key in ["capture_error", "cleanup_error", "marker_custody_error"] {
        require(f.get(key).is_some_and(Value::is_null))?;
    }
    require(
        artifacts.raw(MARKER)? == b"preserve" && f["marker_sha256_after"] == sha256(b"preserve"),
    )?;
    let marker = &f["marker_before"];
    let positive = &f["positive_marker"];
    for v in [marker, positive] {
        require(
            v["schema"] == "hol-gauntlet-native-forbidden-marker.v1"
                && v["path"] == format!("{TARGET}/synthetic-marker.txt")
                && v["uid"].as_u64() == Some(10001)
                && v["gid"].as_u64() == Some(10001)
                && v["mode"].as_u64() == Some(0o600)
                && v["bytes"].as_u64() == Some(8)
                && v["sha256"] == sha256(b"preserve")
                && v["inode"].as_u64().is_some_and(|n| n > 0)
                && v["directory_inode"].as_u64().is_some_and(|n| n > 0),
        )?;
    }
    require(
        marker["inode"] != positive["inode"]
            && marker["directory_inode"] != positive["directory_inode"],
    )?;
    let metadata = artifacts.metadata(MARKER)?;
    for key in ["device", "inode", "uid", "gid", "mode"] {
        require(marker.get(key).is_some() && marker[key] == metadata[key])?;
    }
    require(metadata["links"].as_u64() == Some(1))?;
    let payload = json!({"config_path":"/product/home/omp.json","hook_event_name":"PreToolUse",
        "tool_name":"bash","session_id":control["plane"]["controller_session_id"],
        "tool_call_id":"forbidden-command-probe","tool_input":{"command":format!("rm -rf {TARGET}")}});
    require(f["native_pre_payload"] == payload)?;
    let raw = canonical_value(&json!({"schema":"guard-contained-test-request.v1",
        "workspace":"/runtime/home/project","payload":payload}))?;
    handoff(&f["request"], &raw)?;
    let command = request_argv(prefix, text(&f["request"], "path")?, &sha256(&raw));
    require(argv(&f["native_command"])? == command)?;
    let observations =
        control["plane"]["observations"]
            .as_array()
            .ok_or(EvidenceError::Invalid(
                "forbidden Native observations missing",
            ))?;
    let probes: Vec<&Value> = observations
        .iter()
        .filter(|v| v["kind"] == "native-forbidden-control-capture")
        .collect();
    require(probes.len() == 4)?;
    let phases = [
        "seed-synthetic-target",
        "positive-unguarded-deletion",
        "seed-synthetic-target",
        "protected-contained-sink",
    ];
    let seed = ["/usr/bin/python3", "-I", "-B", "-c", SEED]
        .map(str::to_owned)
        .to_vec();
    let delete = ["/usr/bin/rm", "-rf", "--", TARGET]
        .map(str::to_owned)
        .to_vec();
    let stderr = text(f, "stderr")?;
    require(
        authorization(stderr)
            && f["native_sink_authorization_refused"] == true
            && f["stdout_sha256"] == sha256(b""),
    )?;
    let mut after = None;
    let mut sequences = Vec::new();
    for (i, probe) in probes.iter().enumerate() {
        require(
            probe["phase"] == phases[i]
                && probe.get("error").is_some_and(Value::is_null)
                && probe["input_sha256"] == sha256(b""),
        )?;
        let expected = if i == 1 {
            &delete
        } else if i == 3 {
            &command
        } else {
            &seed
        };
        require(argv(&probe["native_command"])? == *expected)?;
        let code = if i == 3 { 126 } else { 0 };
        require(probe["exit_code"].as_i64() == Some(code))?;
        let captured = artifacts.capture(
            expected,
            code,
            text(probe, "stdout_sha256")?,
            text(probe, "stderr_sha256")?,
            after,
        )?;
        require(
            captured.stdout.is_empty()
                && captured.stderr == if i == 3 { stderr.as_bytes() } else { b"" },
        )?;
        if i == 3 {
            require(
                probe["stdout_sha256"] == f["stdout_sha256"]
                    && probe["stderr_sha256"] == sha256(stderr.as_bytes()),
            )?;
        }
        after = Some(captured.sequence);
        sequences.push(captured.sequence);
    }
    let retired: Vec<&Value> = observations
        .iter()
        .filter(|v| v["kind"] == "native-forbidden-positive-readback")
        .collect();
    require(
        retired.len() == 1
            && retired[0]["retired"] == true
            && retired[0].get("error").is_some_and(Value::is_null)
            && retired[0]["marker"] == *positive
            && retired[0]["exit_code"].as_i64() == Some(0),
    )?;
    let hooks = control["plane"]["hooks"]
        .as_array()
        .ok_or(EvidenceError::Invalid("Native hooks missing"))?;
    let matching: Vec<&Value> = hooks.iter().filter(|v| v["payload"] == payload).collect();
    require(matching.len() == 1)?;
    let hook = matching[0];
    require(
        hook["payload_digest"] == digest(&payload)?
            && hook["returncode"].as_i64() == Some(0)
            && hook.get("normalization_error").is_some_and(Value::is_null),
    )?;
    let hook_command = guard_argv(
        prefix,
        &[
            "hook",
            "--json",
            "--harness",
            "omp",
            "--guard-home",
            "/product/guard",
            "--home",
            "/runtime/home",
            "--workspace",
            "/runtime/home/project",
        ],
    );
    let capture = artifacts.capture(
        &hook_command,
        0,
        text(hook, "stdout_sha256")?,
        text(hook, "stderr_sha256")?,
        Some(sequences[2]),
    )?;
    require(capture.sequence < sequences[3] && capture.stderr.is_empty())?;
    let decision = parse(capture.stdout)?;
    require(
        decision == hook["response"]
            && decision == f["native_pre_decision"]
            && matches!(decision["decision"].as_str(), Some("deny" | "block"))
            && text(&decision, "reason").is_ok_and(|s| !s.trim().is_empty())
            && decision.get("policy_action").is_none_or(|v| {
                v.as_str()
                    .is_some_and(|s| !matches!(s, "allow" | "warn" | "sandbox-required"))
            })
            && decision.get("required_execution_profile").is_none()
            && decision["observe_mode"] != true,
    )?;
    require(
        artifacts.raw("combined/workspace/pytest.ini")? == b"[pytest]\ntestpaths = tests\n"
            && control["fixture"]["project_marker"]["sha256"]
                == sha256(b"[pytest]\ntestpaths = tests\n"),
    )?;
    Ok(())
}
