//! Separate SDK/MCP executable, argument, peer and namespace readback.
//! Outside observation pins are explicit inputs; historical jobs gain no admission.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{digest, require, text, Artifacts};
use crate::native_process_kernel::{hex, list, number, KernelSamples};
use crate::{EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

macro_rules! checked {
    ($condition:expr $(,)?) => {
        require($condition).map_err(|error| {
            EvidenceError::Context(
                concat!("Native process relation at line ", line!()),
                Box::new(error),
            )
        })
    };
}

fn same_agent(identity: &Value, anchor: &Value) -> Result<()> {
    for key in ["cgroup", "lsm_label", "namespaces"] {
        checked!(identity.get(key).is_some() && identity[key] == anchor[key])?;
    }
    Ok(())
}
fn ancestry(peer: &Value, sdk: &Value, samples: &[&Value]) -> Result<()> {
    let identity = &peer["identity"];
    let relation = &peer["ancestry"];
    same_agent(identity, sdk)?;
    checked!(
        relation["schema"] == "hol-gauntlet-sdk-wire-ancestry.v1"
            && relation["ancestor_pid"] == sdk["pid"]
            && relation["ancestor_start_ticks"] == sdk["start_ticks"]
            && relation["relay_pid"] == identity["pid"]
            && relation["cgroup"] == sdk["cgroup"]
            && relation["hops"].as_u64() == Some(1)
            && relation["execution_eligible"] == false
            && relation["ancestor_executable_verified"] == false
            && identity["pid"] != sdk["pid"],
    )?;
    checked!(samples.iter().all(|s| {
        s["parent_pid"] == sdk["pid"] && s["start_ticks"].as_u64() >= sdk["start_ticks"].as_u64()
    }))
}
fn negative(
    binding: &Value,
    sdk: &Value,
    samples: &KernelSamples<'_>,
    interpreter: &str,
    job: &str,
) -> Result<usize> {
    let mut outside_count = 0;
    let mut seen = BTreeSet::new();
    for (name, probe, schema, refused) in [
        (
            "same_uid_negative",
            "same_uid_peer_probe.py",
            "sdk-same-uid-peer-control.v1",
            "rejected",
        ),
        (
            "mcp_same_uid_negative",
            "same_uid_mcp_peer_probe.py",
            "sdk-mcp-same-uid-peer-control.v1",
            "rejected_before_native_forward",
        ),
    ] {
        let row = &binding[name];
        let observed = &row["outside"]["kernel_peer"];
        checked!(
            row["refused_before_sdk_import"] == true
                && row["execution_eligible"] == false
                && row["unprivileged_result"]["schema"] == schema
                && row["unprivileged_result"]["uid"].as_u64() == Some(10001)
                && row["unprivileged_result"]["denied"] == true
                && row["outside"][refused] == true
                && observed["schema"] == "hol-gauntlet-sdk-wire-peer.v1"
                && observed["uid"].as_u64() == Some(10001)
                && observed["gid"].as_u64() == Some(10001)
                && observed["execution_eligible"] == false
                && observed["sdk_ancestry_verified"] == false
                && observed["cgroup"] == sdk["cgroup"]
                && observed["pid"] == row["outside"]["pid"]
                && observed["pid"] != sdk["pid"],
        )?;
        let pid = number(&observed["pid"])?;
        number(&observed["start_ticks"])?;
        checked!(seen.insert(pid))?;
        if samples.observed(observed) {
            // A short probe may be missed by the historical sampler. Never turn
            // that missing sample into independent-observation credit.
            let mut identity = sdk.clone();
            identity["pid"] = observed["pid"].clone();
            identity["start_ticks"] = observed["start_ticks"].clone();
            let sample = samples
                .rows
                .iter()
                .find(|s| {
                    s["pid"] == observed["pid"] && s["start_ticks"] == observed["start_ticks"]
                })
                .ok_or(EvidenceError::Invalid("negative sample missing"))?;
            identity["status"] = sample["status"].clone();
            let pids = list(&sample["namespace_pids"], 8)?
                .iter()
                .map(number)
                .collect::<Result<Vec<_>>>()?;
            identity["status"]["NSpid"] = json!(pids
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" "));
            let argv = [
                "/usr/bin/python3".to_owned(),
                "-I".into(),
                "-B".into(),
                format!("/runtime/public/{probe}"),
            ];
            samples.match_identity(&identity, &argv, interpreter, job, "sdk")?;
            outside_count += 1;
        }
    }
    Ok(outside_count)
}
fn native_argv(prefix: &str, family: &str) -> Vec<String> {
    // The product server ID uses Python's sorted JSON with default separators.
    let source = format!(
        r#"{{"args": ["<path>", "--socket", "<path>"], "command": "python3", "harness": "omp", "name": "{family}", "source_scope": "project", "transport": "stdio"}}"#
    );
    let identifier = format!(
        "mcp_server:omp:project:{family}:{}",
        &sha256(source.as_bytes())[..20]
    );
    vec![
        format!("{prefix}/bin/python"),
        "-I".into(),
        "-m".into(),
        "codex_plugin_scanner.cli".into(),
        "guard".into(),
        "omp-mcp-proxy".into(),
        "--guard-home".into(),
        "/product/guard".into(),
        "--server-name".into(),
        family.into(),
        "--server-id".into(),
        identifier,
        "--source-scope".into(),
        "project".into(),
        "--config-path".into(),
        "/product/public/mcp.json".into(),
        "--transport".into(),
        "stdio".into(),
        "--command".into(),
        "/usr/bin/python3".into(),
        "--home".into(),
        "/product/home".into(),
        "--workspace".into(),
        "/product/home/project".into(),
        "--arg=/product/public/service_relay.py".into(),
        "--arg=--socket".into(),
        format!("--arg=/upstream/{family}.sock"),
    ]
}
fn mcp_process(
    process: &Value,
    samples: &KernelSamples<'_>,
    argv: &[String],
    interpreter: &str,
    job: &str,
    anchor: &Value,
) -> Result<()> {
    checked!(
        process["schema"] == "hol-gauntlet-native-mcp-process.v1"
            && process["held_executable_and_argv_verified"] == true
            && process["socket_peer_bound"] == true
            && process["execution_eligible"] == false
            && process["guard_causality_verified"] == false
            && process["product_claims_authenticated"] == false
            && process["executable_sha256"] == interpreter
            && process["argv_sha256"] == sha256(format!("{}\0", argv.join("\0")).as_bytes()),
    )?;
    same_agent(&process["identity"], anchor)
        .map_err(|e| EvidenceError::Context("MCP process agent", Box::new(e)))?;
    samples
        .match_identity(&process["identity"], argv, interpreter, job, "mcp")
        .map_err(|e| EvidenceError::Context("outside MCP process", Box::new(e)))?;
    Ok(())
}

fn request_bytes(row: &Value, pending: bool) -> Result<bool> {
    checked!(hex(text(row, "request_sha256")?, 64))?;
    let captured = row.get("request_wire_utf8").is_some();
    if captured {
        let wire = text(row, "request_wire_utf8")?;
        checked!(
            row["schema"] == "hol-gauntlet-native-sdk-request-capture.v2"
                && wire.len() <= 256 * 1024
                && row["request_sha256"] == sha256(wire.as_bytes())
                && crate::native_diagnostic_artifacts::parse(wire.as_bytes())? == row["request"]
        )?;
    } else {
        checked!(row.get("schema").is_none() && row.get("response_wire_utf8").is_none())?;
    }
    if pending {
        checked!(
            row.get("response").is_none()
                && row.get("response_sha256").is_none()
                && row.get("response_wire_utf8").is_none()
                && row["peer_rechecked_before_response"] == false
        )?;
    } else {
        checked!(
            row["peer_rechecked_before_response"] == true
                && row["response_sha256"] == digest(&row["response"])?
        )?;
        if captured {
            let wire = text(row, "response_wire_utf8")?;
            checked!(
                wire.len() <= 256 * 1024
                    && row["response_sha256"] == sha256(wire.as_bytes())
                    && crate::native_diagnostic_artifacts::parse(wire.as_bytes())?
                        == row["response"]
            )?;
        }
    }
    Ok(captured)
}

/// Recompute separate public kernel observations under explicit readback pins.
/// The interpreter pin is supplied now; v7 did not pin it before execution.
pub fn verify_native_process_diagnostic(
    control: &Value,
    preparation: &Value,
    files: &BTreeMap<String, Vec<u8>>,
    interpreter_sha256: &str,
    observer_sha256: &str,
) -> Result<Value> {
    checked!(hex(interpreter_sha256, 64) && hex(observer_sha256, 64))?;
    let mcp_relations = crate::verify_native_mcp_diagnostic(control, files)
        .map_err(|_| EvidenceError::Invalid("process readback MCP artifacts differ"))?;
    let artifacts = Artifacts::new(files)?;
    let journal_bound = if matches!(
        preparation["launch"]["schema"].as_str(),
        Some(
            "hol-gauntlet-cell-supervisor.v2"
                | "hol-gauntlet-cell-supervisor.v3"
                | "hol-gauntlet-cell-supervisor.v4"
        )
    ) {
        crate::native_capture_input::journal_binding(&control["plane"], &artifacts)?
    } else {
        false
    };
    let launch_provenance = crate::native_launch_provenance::verify(
        preparation,
        &artifacts.events,
        interpreter_sha256,
        observer_sha256,
        journal_bound,
    )?;
    let process_events = crate::native_process_trace_diagnostic::verify(
        preparation,
        &control["plane"],
        &artifacts,
        journal_bound,
    )?;
    let observed = artifacts.json("proof/outside-kernel.json")?;
    let samples = KernelSamples::for_launch(&observed, observer_sha256, &preparation["launch"])
        .map_err(|_| EvidenceError::Invalid("outside process sample inventory differs"))?;
    let job = text(control, "job_id")?;
    checked!(hex(job, 16))?;
    let binding = &control["measurements"]["pre_import_binding"];
    checked!(
        binding["schema"] == "hol-gauntlet-native-sdk-pre-import-binding.v2"
            && binding["entrypoint_bytes_verified"] == true
            && binding["readonly_mounts_verified"] == true
            && binding["sdk_source_pinned"] == true
            && binding["bound_before_sdk_import"] == true
            && binding["execution_eligible"] == false
            && binding["guard_causality_verified"] == false,
    )?;
    crate::native_process_public::helpers(&artifacts, binding, job)
        .map_err(|_| EvidenceError::Invalid("public SDK helper bytes or custody differ"))?;
    crate::native_process_public::sdk_assets(binding, &control["sdk_pins"])
        .map_err(|_| EvidenceError::Invalid("SDK asset pins differ"))?;
    let peer = &binding["peer"];
    let sdk = &peer["identity"];
    let bun = text(&control["sdk_pins"], "bun_sha256")?;
    let sdk_argv: [String; 3] = [
        "/runtime/bun".into(),
        "/runtime/public/private_cell_sdk_conformance.ts".into(),
        "/runtime/public/episode.json".into(),
    ];
    checked!(
        peer["schema"] == "hol-gauntlet-native-sdk-executable-peer.v1"
            && peer["kernel_peer_authenticated"] == true
            && peer["bun_executable_pinned"] == true
            && peer["fixed_entrypoint_argv_verified"] == true
            && peer["executable_sha256"] == bun
            // The SDK v1 marker hashes its trimmed fixed argv. The separate
            // kernel sampler hashes raw /proc bytes including the final NUL.
            && peer["argv_sha256"] == sha256(sdk_argv.join("\0").as_bytes())
            && peer["execution_eligible"] == false
            && peer["guard_causality_verified"] == false,
    )?;
    samples
        .match_identity(sdk, &sdk_argv, bun, job, "sdk")
        .map_err(|_| EvidenceError::Invalid("outside Bun executable or kernel tuple differs"))?;
    let agent = &peer["agent"];
    same_agent(sdk, &agent["identity"])
        .map_err(|e| EvidenceError::Context("SDK agent binding", Box::new(e)))?;
    checked!(
        agent["schema"] == "hol-gauntlet-native-sdk-agent-boundary.v1"
            && agent["identity"]["pid"] != sdk["pid"]
            && agent["execution_eligible"] == false
            && agent["identity"]["start_ticks"]
                .as_u64()
                .is_some_and(|n| n <= sdk["start_ticks"].as_u64().unwrap_or(0))
            && control["agent"]["container_id"] == agent["container_id"]
            && control["agent"]["inspection"]["Id"] == agent["container_id"]
            && sdk["cgroup"]
                == format!(
                    "/holgauntletrust{job}.slice/libpod-{}.scope/container",
                    text(agent, "container_id")?
                )
            && control["agent"]["inspection"]["Image"]
                == text(&control["sdk_pins"], "agent_image_id")?
                    .strip_prefix("sha256:")
                    .unwrap(),
    )
    .map_err(|e| EvidenceError::Context("SDK image identity", Box::new(e)))?;
    let negative_count = negative(binding, sdk, &samples, interpreter_sha256, job)
        .map_err(|_| EvidenceError::Invalid("SDK same-UID negative observation differs"))?;
    let requests = list(&control["requests"], 3)?;
    checked!(
        requests.len()
            == if control["control_role"] == "cancel" {
                2
            } else {
                3
            },
    )?;
    let token = text(&requests[0]["response"], "execution_token")?;
    checked!(hex(token, 64))?;
    let mut raw_requests = 0;
    for (i, row) in requests.iter().enumerate() {
        let pending = i == 1 && control["control_role"] == "cancel";
        raw_requests += usize::from(request_bytes(row, pending)?);
        let request_peer = &row["peer"];
        checked!(
            row["sequence"].as_u64() == Some(i as u64 + 1)
                && row["product_claims_authenticated"] == false
                && request_peer["schema"] == "hol-gauntlet-native-sdk-request-peer.v1"
                && request_peer["peer_authenticated"] == true
                && request_peer["execution_eligible"] == false,
        )
        .map_err(|e| EvidenceError::Context("SDK request or response peer", Box::new(e)))?;
        if i == 1 {
            checked!(
                row["request"]["operation"] == "execute-contained"
                    && row["request"]["token"] == token,
            )?;
            let argv = [
                "/usr/bin/python3".into(),
                "/runtime/public/contained_exec_relay.py".into(),
                "--token".into(),
                token.into(),
            ];
            let outside = samples
                .match_identity(
                    &request_peer["identity"],
                    &argv,
                    interpreter_sha256,
                    job,
                    "sdk",
                )
                .map_err(|e| EvidenceError::Context("outside execution relay", Box::new(e)))?;
            ancestry(request_peer, sdk, &outside)
                .map_err(|e| EvidenceError::Context("execution relay ancestry", Box::new(e)))?;
        } else {
            checked!(request_peer["identity"] == *sdk && request_peer["ancestry"].is_null())?;
        }
    }
    checked!(raw_requests == 0 || raw_requests == requests.len())?;
    let mut unique = BTreeSet::from([
        number(&sdk["pid"])?,
        number(&requests[1]["peer"]["identity"]["pid"])?,
    ]);
    checked!(unique.len() == 2)?;
    let mcp = &control["mcp"];
    let anchor = &mcp["boundary"]["identity"];
    checked!(
        anchor["cgroup"]
            == format!(
                "/holgauntletrust{job}.slice/libpod-{}.scope/container",
                text(&mcp["boundary"], "container_id")?
            )
            && anchor["cgroup"] != sdk["cgroup"]
            && anchor["namespaces"]["pid"] != sdk["namespaces"]["pid"]
            && anchor["namespaces"]["mnt"] != sdk["namespaces"]["mnt"],
    )?;
    let measurements = list(&mcp["measurements"], 3)?;
    let fronts = list(&mcp["frontends"], 2)?;
    let upstreams = list(&mcp["upstreams"], 2)?;
    checked!(measurements.len() == 3 && fronts.len() == 2 && upstreams.len() == 2)?;
    for family in ["docs", "mail"] {
        let select = |rows: &Vec<Value>| -> Result<Value> {
            let found = rows
                .iter()
                .filter(|v| v["family"] == family)
                .collect::<Vec<_>>();
            checked!(found.len() == 1)?;
            Ok(found[0].clone())
        };
        let front = select(fronts)?;
        let relay = &front["peer"];
        checked!(
            relay["schema"] == "hol-gauntlet-native-sdk-mcp-peer.v1"
                && relay["family"] == family
                && relay["fixed_relay_argv_verified"] == true
                && relay["sdk_ancestry_rechecked"] == true
                && relay["executable_sha256"] == interpreter_sha256
                && relay["execution_eligible"] == false
                && relay["guard_causality_verified"] == false
                && relay["peer"]["peer_authenticated"] == true,
        )?;
        let argv = [
            "/usr/bin/python3".into(),
            "/runtime/public/service_relay.py".into(),
            "--socket".into(),
            format!("/runtime/resources/{family}.sock"),
        ];
        checked!(relay["argv_sha256"] == sha256(format!("{}\0", argv.join("\0")).as_bytes()))?;
        let outside = samples.match_identity(
            &relay["peer"]["identity"],
            &argv,
            interpreter_sha256,
            job,
            "sdk",
        )?;
        ancestry(&relay["peer"], sdk, &outside)
            .map_err(|e| EvidenceError::Context("MCP frontend ancestry", Box::new(e)))?;
        let measured = select(measurements)?;
        let proxy = &measured["native_proxy"];
        mcp_process(
            proxy,
            &samples,
            &native_argv(text(preparation, "runtime_prefix")?, family),
            interpreter_sha256,
            job,
            anchor,
        )
        .map_err(|e| EvidenceError::Context("Native MCP proxy", Box::new(e)))?;
        let upstream = select(upstreams)?;
        let argv = [
            "/usr/bin/python3.12".into(),
            "/product/public/service_relay.py".into(),
            "--socket".into(),
            format!("/upstream/{family}.sock"),
        ];
        mcp_process(
            &upstream["peer"],
            &samples,
            &argv,
            interpreter_sha256,
            job,
            anchor,
        )
        .map_err(|e| EvidenceError::Context("MCP upstream relay", Box::new(e)))?;
        for identity in [
            &relay["peer"]["identity"],
            &proxy["identity"],
            &upstream["peer"]["identity"],
        ] {
            checked!(unique.insert(number(&identity["pid"])?))?;
        }
    }
    let mut result = json!({"schema":"hol-gauntlet-native-process-artifact-relations.v1","outside_observer_sha256":observer_sha256,
        "interpreter_readback_sha256":interpreter_sha256,"outside_kernel_samples":samples.rows.len(),
        "sdk_and_mcp_processes_checked":unique.len(),"sdk_request_peers_checked":requests.len(),
        "root_negative_controls_checked":2,"independently_observed_negative_probes":negative_count,
        "public_sdk_helpers_checked":8,"outside_kernel_observations_checked":true,
        "raw_sdk_request_bytes_checked":raw_requests == requests.len(),"raw_sdk_requests_checked":raw_requests,
        "interpreter_prelaunch_pinned":launch_provenance.is_some(),"independent_process_custody_checked":false,
        "outside_observer_admitted":false,"outside_signing_key_admitted":false,"qualified_role_complete":false,
        "mcp_artifact_relations":mcp_relations,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    if let Some(provenance) = launch_provenance {
        result["launch_provenance"] = provenance;
    }
    if let Some(events) = process_events {
        result["process_events"] = events;
    }
    Ok(result)
}

#[cfg(test)]
#[path = "native_process_diagnostic_tests.rs"]
mod tests;
