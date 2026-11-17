//! Retain actual live observations separately from the bounded signed report.
//! Request/result projection never assigns a Guard verdict or a business score.
use crate::{NativeJobSpec, NativeLiveJob};
use serde_json::{json, Value};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use std::collections::BTreeSet;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) struct LiveArtifacts {
    pub hashes: Value,
    pub context_sha256: String,
}

/// Only an observed owned-helper wait supplies an exit code. A successful
/// stop without such a wait must not manufacture the SDK's terminal status.
#[derive(Default)]
pub(crate) struct SdkObservation {
    pub stdout: Vec<u8>,
    exit: Option<ExitStatus>,
    timed_out: Option<bool>,
    stderr_sha256: Option<String>,
}
impl SdkObservation {
    pub fn observe_exit(&mut self, output: Output, deadline_expired: bool) {
        self.stdout = output.stdout;
        self.exit = Some(output.status);
        self.timed_out = Some(self.timed_out.unwrap_or(false) || deadline_expired);
        self.stderr_sha256 = Some(crate::native_live_model::sha(&output.stderr));
    }
    pub fn observe_deadline(&mut self) {
        self.timed_out = Some(true);
    }
    pub fn terminal(&self, binding: &Value, cleanup: Option<&Result<(), String>>) -> Value {
        json!({"returncode":self.exit.and_then(|s|s.code()),"signal":self.exit.and_then(|s|s.signal()),
            "timed_out":self.timed_out,"pid":binding["peer"]["identity"]["pid"],
            "start_ticks":binding["peer"]["identity"]["start_ticks"],
            "status_source":self.exit.map(|_|"owned-podman-exec-kernel-exit.v1"),
            "cleanup_complete":cleanup.map(Result::is_ok),"cleanup_error":cleanup.and_then(|r|r.as_ref().err()),
            "stderr_sha256":self.stderr_sha256})
    }
}

pub(crate) struct LiveContext<'a> {
    pub binding: &'a Value,
    pub agent: &'a Value,
    pub sdk_terminal: &'a Value,
    pub budget: &'a Value,
}

fn context(
    job: &NativeJobSpec,
    live: &NativeLiveJob,
    mcp: &Value,
    observed: &LiveContext<'_>,
) -> Result<Vec<u8>, String> {
    let value = json!({"schema":"hol-gauntlet-native-live-context.v2","source_sha":job.source_sha,
        "job_id":job.job_id,"worker_generation":job.worker_generation,"preparation_sha256":job.preparation_sha256,
        "cell_id":live.cell_id,"spec_sha256":live.spec_sha256,"mcp":mcp,"binding":observed.binding,
        "agent":observed.agent,"sdk_terminal":observed.sdk_terminal,"budget":observed.budget});
    let raw = gauntlet_contracts::canonicalize(value.to_string().as_bytes())
        .map_err(|_| "live context canonicalization failed")?;
    if raw.len() > 32 * 1024 * 1024 {
        return Err("live context artifact bound exceeded".into());
    }
    Ok(raw)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn raw_event(value: &Value) -> &Value {
    if value["type"] == "agent_event" {
        &value["event"]
    } else {
        value
    }
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn native_calls(mcp: &Value, budget: &Value, sdk: &[Value]) -> Value {
    let metadata = sdk.iter().find(|r| r["type"] == "episode_start");
    let mut calls = Vec::new();
    let mut used = BTreeSet::new();
    let Some(events) = budget["events"].as_array() else {
        return json!([]);
    };
    for event in events {
        if event["surface"] != "mcp" || event["method"] != "tools/call" {
            continue;
        }
        let family = &event["family"];
        let id = &event["request_id"];
        let frontend = mcp["frontends"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["family"] == *family));
        let request = frontend
            .and_then(|f| f["frames"].as_array())
            .and_then(|rows| {
                rows.iter()
                    .find(|r| r["direction"] == "sdk-request" && r["frame"]["id"] == *id)
            })
            .map(|r| r["frame"].clone())
            .unwrap_or(Value::Null);
        if request.is_null() {
            continue;
        }
        let response = frontend
            .and_then(|f| f["frames"].as_array())
            .and_then(|rows| {
                rows.iter().find(|r| {
                    matches!(
                        r["direction"].as_str(),
                        Some("native-response" | "root-world-response")
                    ) && r["frame"]["id"] == *id
                })
            })
            .map(|r| r["frame"].clone())
            .unwrap_or(Value::Null);
        let upstream = mcp["upstreams"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["family"] == *family));
        let upstream_request = upstream
            .and_then(|f| f["frames"].as_array())
            .and_then(|rows| {
                rows.iter()
                    .find(|r| r["direction"] == "request" && r["frame"]["id"] == *id)
            })
            .map(|r| r["frame"].clone());
        let upstream_response = upstream
            .and_then(|f| f["frames"].as_array())
            .and_then(|rows| {
                rows.iter()
                    .find(|r| r["direction"] == "response" && r["frame"]["id"] == *id)
            })
            .map(|r| r["frame"].clone());
        let baseline = mcp["protected"] == false;
        let display = metadata
            .and_then(|m| m["resourceTools"].as_array())
            .and_then(|tools| {
                tools
                    .iter()
                    .find(|t| t["server"] == *family && t["rawTool"] == request["params"]["name"])
            })
            .and_then(|t| t["name"].as_str());
        let tool_call_id = sdk
            .iter()
            .map(raw_event)
            .find(|e| {
                e["type"] == "tool_execution_start"
                    && display.is_some_and(|name| e["toolName"] == name)
                    && family
                        .as_str()
                        .zip(request["params"]["name"].as_str())
                        .is_some_and(|(family, operation)| {
                            gauntlet_evidence::project_feature_ai_mcp_arguments(
                                family, operation, &e["args"],
                            )
                            .is_ok_and(|args| args == request["params"]["arguments"])
                        })
                    && e["toolCallId"]
                        .as_str()
                        .is_some_and(|id| !used.contains(id))
            })
            .and_then(|e| e["toolCallId"].as_str());
        if let Some(id) = tool_call_id {
            used.insert(id.to_owned());
        }
        calls.push(json!({"sequence":calls.len()+1,"tool_call_id":tool_call_id,"request":request,
            "upstream_request":if baseline{Some(request.clone())}else{upstream_request},
            "upstream_response":if baseline{Some(response.clone())}else{upstream_response},"native_response":response}));
    }
    json!(calls)
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) fn retain(
    job: &NativeJobSpec,
    live: &NativeLiveJob,
    sdk_raw: &[u8],
    mcp: &Value,
    provider: &Value,
    observed: &LiveContext<'_>,
) -> Result<LiveArtifacts, String> {
    let sdk_text = std::str::from_utf8(sdk_raw).ok();
    let parsed = sdk_text.and_then(|_| gauntlet_evidence::parse_omp_transcript(sdk_raw).ok());
    let artifacts = json!({"initial_snapshot":mcp["initial"],"final_snapshot":mcp["final"],"world_receipts":mcp["receipts"],
        "world_calls":mcp["world_calls"],"sdk_events":sdk_text,"provider_turns":provider["provider_turns"],
        "native_calls":parsed.as_ref().map(|rows|native_calls(mcp,observed.budget,rows)).unwrap_or_else(||json!([])),"cleanup":null});
    let mut hashes = serde_json::Map::new();
    for (name, value) in artifacts.as_object().unwrap() {
        let raw = gauntlet_contracts::canonicalize(value.to_string().as_bytes())
            .map_err(|_| "live artifact canonicalization failed")?;
        hashes.insert(name.clone(), json!(crate::native_live_model::sha(&raw)));
    }
    let envelope = json!({"schema":"hol-gauntlet-feature-ai-support-cell.v1","cell_id":live.cell_id,"artifacts":artifacts});
    let raw = gauntlet_contracts::canonicalize(envelope.to_string().as_bytes())
        .map_err(|_| "live artifact envelope encoding failed")?;
    if raw.len() > 32 * 1024 * 1024 {
        return Err("live artifact aggregate exceeds archive member budget".into());
    }
    let root =
        crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
    let directory = crate::feature_files::directory(&root, "live", (0, 0), true)?;
    crate::feature_files::write(&directory, "evidence.v1.json", &raw, (0, 0), 0o600)?;
    let context = context(job, live, mcp, observed)?;
    crate::feature_files::write(&directory, "context.v1.json", &context, (0, 0), 0o600)?;
    Ok(LiveArtifacts {
        hashes: Value::Object(hashes),
        context_sha256: crate::native_live_model::sha(&context),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> (NativeJobSpec, NativeLiveJob) {
        let job = NativeJobSpec {
            source_sha: "a".repeat(40),
            job_id: "b".repeat(16),
            worker_generation: "c".repeat(64),
            preparation_sha256: "d".repeat(64),
            execution: crate::NativeJobExecution::Apparatus(
                gauntlet_cell_rootfs::NativeCase::Success,
            ),
        };
        let live = NativeLiveJob {
            cell_id: crate::native_live_spec::FEATURE_AI_BASELINE.into(),
            spec_sha256: "e".repeat(64),
            model: crate::NativeLiveModelPins::parse(&json!({
                "schema":"hol-gauntlet-native-live-model-pins.v1","provider_job_id":"f".repeat(16),
                "budget_digest":"0".repeat(64),"model_id":crate::native_live_model::MODEL,
                "max_turns":2,"token_limit":100000
            }))
            .unwrap(),
        };
        (job, live)
    }

    #[test]
    fn live_context_retains_full_binding_and_final_cleanup_instead_of_a_hash_only() {
        let (job, live) = pins();
        let binding = json!({"schema":"hol-gauntlet-native-sdk-pre-import-binding.v4",
            "peer":{"identity":{"pid":123,"start_ticks":456},"startup":{"configuration":{"sha256":"1".repeat(64)}}},
            "public_helpers":{"files":[{"name":"episode.json","sha256":"2".repeat(64)}]},
            "assets":{"sdk":{"publication_sha256":"3".repeat(64)}},
            "same_uid_negative":{"outside":{"rejected_before_native_forward":true}},
            "mcp_same_uid_negative":{"outside":{"rejected_before_native_forward":true}}});
        let agent = json!({"schema":"hol-gauntlet-native-sdk-agent-owner.v1",
            "container_id":"4".repeat(64),"cgroup":"/machine.slice/original.scope","cleanup_complete":false});
        let stop: Result<(), String> = Err("original helper cleanup uncertain".into());
        let terminal = SdkObservation::default().terminal(&binding, Some(&stop));
        let budget = json!({"events":[{"request_id":7,"method":"tools/call"}]});
        let mcp = json!({"frontends":[{"family":"docs","frames":[]}]});
        let raw = context(
            &job,
            &live,
            &mcp,
            &LiveContext {
                binding: &binding,
                agent: &agent,
                sdk_terminal: &terminal,
                budget: &budget,
            },
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 12);
        assert_eq!(value["schema"], "hol-gauntlet-native-live-context.v2");
        assert_eq!(value["source_sha"], job.source_sha);
        assert_eq!(value["job_id"], job.job_id);
        assert_eq!(value["binding"], binding);
        assert_eq!(value["agent"], agent);
        assert_eq!(value["sdk_terminal"], terminal);
        assert_eq!(value["budget"], budget);
        assert_eq!(value["mcp"], mcp);
        assert_eq!(value["sdk_terminal"]["returncode"], Value::Null);
        assert_eq!(value["sdk_terminal"]["cleanup_complete"], false);
        assert_eq!(
            value["sdk_terminal"]["cleanup_error"],
            "original helper cleanup uncertain"
        );
        assert_eq!(gauntlet_contracts::canonicalize(&raw).unwrap(), raw);
    }

    #[test]
    fn sdk_stop_or_deadline_cannot_manufacture_a_successful_kernel_exit() {
        let binding = json!({"peer":{"identity":{"pid":123,"start_ticks":456}}});
        let mut observed = SdkObservation::default();
        let stopped: Result<(), String> = Ok(());
        let unknown = observed.terminal(&binding, Some(&stopped));
        assert_eq!(unknown.as_object().unwrap().len(), 9);
        for field in [
            "returncode",
            "signal",
            "timed_out",
            "status_source",
            "stderr_sha256",
        ] {
            assert_eq!(unknown[field], Value::Null, "{field}");
        }
        assert_eq!(unknown["cleanup_complete"], true);
        assert_eq!(observed.terminal(&Value::Null, None)["pid"], Value::Null);
        observed.observe_deadline();
        assert_eq!(observed.terminal(&binding, None)["timed_out"], true);
        let mut observed = SdkObservation::default();
        observed.observe_exit(
            Output {
                status: ExitStatus::from_raw(9 << 8),
                stdout: b"actual partial transcript".to_vec(),
                stderr: b"actual helper failure".to_vec(),
            },
            false,
        );
        let actual = observed.terminal(&binding, Some(&stopped));
        assert_eq!(observed.stdout, b"actual partial transcript");
        assert_eq!(actual["returncode"], 9);
        assert_eq!(actual["signal"], Value::Null);
        assert_eq!(actual["timed_out"], false);
        assert_eq!(actual["pid"], 123);
        assert_eq!(actual["start_ticks"], 456);
        assert_eq!(actual["status_source"], "owned-podman-exec-kernel-exit.v1");
        assert_eq!(
            actual["stderr_sha256"],
            crate::native_live_model::sha(b"actual helper failure")
        );
        observed.observe_deadline();
        observed.observe_exit(
            Output {
                status: ExitStatus::from_raw(0),
                stdout: vec![],
                stderr: vec![],
            },
            false,
        );
        assert_eq!(observed.terminal(&binding, None)["timed_out"], true);
    }
}
