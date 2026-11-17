//! Check actual installed Native clients below measured prefix-Python CLIs.
//! A missed internal client remains a gap, never a fabricated observation.
use crate::native_diagnostic_artifacts::{argv, require, text, Artifacts};
use crate::native_process_kernel::{list, number, KernelSamples};
use crate::Result;
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn client(
    samples: &KernelSamples<'_>,
    gate: &Value,
    row: &Value,
    command: &[String],
    native: &str,
    job: &str,
) -> Result<()> {
    require(
        row["parent_pid"] == gate["pid"]
            && number(&row["start_ticks"])? >= number(&gate["start_ticks"])?,
    )?;
    let mut identity = gate.clone();
    for name in [
        "pid",
        "start_ticks",
        "executable_device",
        "executable_inode",
    ] {
        identity[name] = row[name].clone();
    }
    let pids = list(&row["namespace_pids"], 8)?;
    require(pids.len() >= 2 && pids.first() == Some(&row["pid"]))?;
    let nspid = pids
        .iter()
        .map(|v| number(v).map(|n| n.to_string()))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    identity["status"]["NSpid"] = json!(nspid);
    crate::native_product_kernel::matching(samples, &identity, command, native, job)?;
    Ok(())
}

fn pipe_clients(
    control: &Value,
    prefix: &str,
    artifacts: &Artifacts<'_>,
    images: Value,
    pipes: Value,
) -> Result<Value> {
    let mut joined = BTreeSet::new();
    for session in list(&pipes["sessions"], 1024)? {
        require(joined.insert(number(&session["exec_event"])?))?;
    }
    let native = list(&images["native_execs"], 65536)?;
    let mut checked = Vec::new();
    let mut missing = Vec::new();
    for (sequence, event) in artifacts.events.iter().enumerate() {
        if event["kind"] != "gated-product-process" {
            continue;
        }
        let gate = &event["data"]["identity"];
        let args = argv(&gate["argv"])?;
        let Some(operation) = args.get(11).map(String::as_str) else {
            continue;
        };
        if args.get(2) != Some(&format!("{prefix}/bin/python"))
            || !matches!(operation, "hook" | "execute-contained-test")
        {
            continue;
        }
        let actual = &args[2..];
        let mut original = actual[..3].to_vec();
        original.extend_from_slice(&actual[6..]);
        require(
            crate::native_diagnostic_artifacts::transport_argv(&control["plane"], original)?
                == actual,
        )?;
        let clients = native
            .iter()
            .filter(|r| {
                r["gate_sequence"].as_u64() == Some(sequence as u64)
                    && r["operation"] == "resident-client-stream"
            })
            .collect::<Vec<_>>();
        for client in &clients {
            require(joined.contains(&number(&client["trace_sequence"])?))?;
        }
        let record = json!({"gate_sequence":sequence,"cli_pid":gate["pid"],"operation":operation,"native_client_pipe_sessions":clients.len()});
        if clients.is_empty() {
            require(
                control["control_role"] == "input-binding" && operation == "execute-contained-test",
            )?;
            missing.push(record);
        } else {
            checked.push(record);
        }
    }
    require(!checked.is_empty())?;
    Ok(
        json!({"schema":"hol-gauntlet-native-runtime-client-relations.v2",
        "native_runtime_sha256":control["guard_pins"]["native_sha256"],"installed_runtime_clients_checked":pipes["native_client_streams"],
        "cli_relations":checked,"missing_internal_client_observations":missing,"all_selected_cli_clients_observed":missing.is_empty(),
        "process_event_images":images,"native_pipe_bytes":pipes,
        "native_transport_byte_relations_checked":true,"internal_native_request_bytes_checked":false,
        "all_native_runtime_descendants_graded":images["all_native_runtime_descendants_graded"]==true,
        "all_native_exec_images_isolation_verified":images["all_native_exec_images_isolation_verified"]==true,
        "independent_process_custody_checked":false,
        "outside_signing_key_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

pub(crate) fn verify(
    control: &Value,
    preparation: &Value,
    artifacts: &Artifacts<'_>,
    samples: &KernelSamples<'_>,
    hooks: &Value,
) -> Result<Value> {
    if crate::native_launch_provenance::pipe_launch(&preparation["launch"])? {
        let images = crate::native_runtime_trace::verify(control, preparation, artifacts)?.ok_or(
            crate::EvidenceError::Invalid("pipe-launch process image history required"),
        )?;
        let pipes = crate::native_stdio_diagnostic::verify(
            control,
            preparation,
            artifacts,
            &images,
            hooks,
        )?
        .ok_or(crate::EvidenceError::Invalid(
            "pipe-launch Native pipe history required",
        ))?;
        require(
            pipes["native_client_streams"]
                .as_u64()
                .is_some_and(|n| n > 0),
        )?;
        return pipe_clients(
            control,
            text(preparation, "runtime_prefix")?,
            artifacts,
            images,
            pipes,
        );
    }
    let prefix = text(preparation, "runtime_prefix")?;
    let path = format!(
        "{prefix}/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime"
    );
    let command = vec![
        path,
        "resident-client-stream".into(),
        "--stdin".into(),
        "/product/guard/native-runtime".into(),
    ];
    let wire = format!("{}\0", command.join("\0"));
    let job = text(control, "job_id")?;
    let native = text(&control["guard_pins"], "native_sha256")?;
    let mut clients = BTreeSet::new();
    let mut checked = Vec::new();
    let mut missing = Vec::new();
    for (sequence, event) in artifacts.events.iter().enumerate() {
        if event["kind"] != "gated-product-process" {
            continue;
        }
        let gate = &event["data"]["identity"];
        let args = argv(&gate["argv"])?;
        let Some(operation) = args.get(8).map(String::as_str) else {
            continue;
        };
        if args.get(2) != Some(&format!("{prefix}/bin/python"))
            || !matches!(operation, "hook" | "execute-contained-test")
        {
            continue;
        }
        let mut count = 0;
        for row in samples.rows {
            if row["parent_pid"] != gate["pid"] || row["argv_utf8"] != wire {
                continue;
            }
            client(samples, gate, row, &command, native, job)?;
            clients.insert((number(&row["pid"])?, number(&row["start_ticks"])?));
            count += 1;
        }
        let record = json!({"gate_sequence":sequence,"cli_pid":gate["pid"],"operation":operation,"native_client_samples":count});
        if count == 0 {
            // The original nine malformed-input probes have no sampled internal
            // client. Their actual outer CLI/capture checks remain independent.
            require(
                control["control_role"] == "input-binding" && operation == "execute-contained-test",
            )?;
            missing.push(record);
        } else {
            checked.push(record);
        }
    }
    require(!checked.is_empty())?;
    let mut result = json!({"schema":"hol-gauntlet-native-runtime-client-relations.v1",
        "native_runtime_sha256":native,"installed_runtime_clients_checked":clients.len(),"cli_relations":checked,
        "missing_internal_client_observations":missing,"all_selected_cli_clients_observed":missing.is_empty(),
        "internal_native_request_bytes_checked":false,"all_native_runtime_descendants_graded":false,
        "independent_process_custody_checked":false,"outside_signing_key_admitted":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    if let Some(images) = crate::native_runtime_trace::verify(control, preparation, artifacts)? {
        result["all_native_runtime_descendants_graded"] =
            images["all_native_runtime_descendants_graded"].clone();
        result["all_native_exec_images_isolation_verified"] =
            images["all_native_exec_images_isolation_verified"].clone();
        result["process_event_images"] = images;
    }
    if let Some(stdio) = crate::native_stdio_diagnostic::verify(
        control,
        preparation,
        artifacts,
        &result["process_event_images"],
        hooks,
    )? {
        result["native_stdio_snapshots"] = stdio;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_diagnostic_artifacts::{guard_argv, transport_argv};
    use crate::native_process_trace_diagnostic::tests::pipe_fixture;

    fn gate(control: &Value, prefix: &str, operation: &str) -> Value {
        let mut command = vec![
            "/public/gauntlet-product-cell".to_owned(),
            "exec-gate".into(),
        ];
        command
            .extend(transport_argv(&control["plane"], guard_argv(prefix, &[operation])).unwrap());
        json!({"kind":"gated-product-process","data":{"identity":{"pid":45,"argv":command}}})
    }
    #[test]
    fn every_v5_cli_requires_its_own_traced_native_client_and_completed_pipe_session() {
        let (mut control, prep, files) = pipe_fixture();
        control["control_role"] = json!("success");
        let prefix = text(&prep, "runtime_prefix").unwrap();
        let mut artifacts = Artifacts::new(&files).unwrap();
        artifacts.events.insert(6, gate(&control, prefix, "hook"));
        let images = json!({"native_execs":[{"gate_sequence":6,"operation":"resident-client-stream","trace_sequence":10}]});
        let pipes = json!({"sessions":[{"exec_event":10}],"native_client_streams":1});
        let value =
            pipe_clients(&control, prefix, &artifacts, images.clone(), pipes.clone()).unwrap();
        assert_eq!(value["all_selected_cli_clients_observed"], true);
        assert_eq!(value["cli_relations"][0]["native_client_pipe_sessions"], 1);
        assert_eq!(value["execution_eligible"], false);
        for (key, value) in [
            ("gate_sequence", json!(7)),
            ("trace_sequence", json!(11)),
            ("operation", json!("version")),
        ] {
            let mut changed = images.clone();
            changed["native_execs"][0][key] = value;
            assert!(
                pipe_clients(&control, prefix, &artifacts, changed, pipes.clone()).is_err(),
                "{key}"
            );
        }
        let mut changed = pipes.clone();
        changed["sessions"] = json!([]);
        assert!(pipe_clients(&control, prefix, &artifacts, images.clone(), changed).is_err());
        artifacts.events[6]["data"]["identity"]["argv"][6] = json!("unreviewed bootstrap");
        assert!(pipe_clients(&control, prefix, &artifacts, images, pipes).is_err());
    }
    #[test]
    fn only_explicit_malformed_input_controls_may_retain_a_missing_native_client() {
        let (mut control, prep, files) = pipe_fixture();
        control["control_role"] = json!("input-binding");
        let prefix = text(&prep, "runtime_prefix").unwrap();
        let mut artifacts = Artifacts::new(&files).unwrap();
        artifacts.events.insert(6, gate(&control, prefix, "hook"));
        artifacts
            .events
            .insert(7, gate(&control, prefix, "execute-contained-test"));
        let images = json!({"native_execs":[{"gate_sequence":6,"operation":"resident-client-stream","trace_sequence":10}]});
        let pipes = json!({"sessions":[{"exec_event":10}],"native_client_streams":1});
        let value =
            pipe_clients(&control, prefix, &artifacts, images.clone(), pipes.clone()).unwrap();
        assert_eq!(value["all_selected_cli_clients_observed"], false);
        assert_eq!(
            value["missing_internal_client_observations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        control["control_role"] = json!("success");
        assert!(pipe_clients(&control, prefix, &artifacts, images, pipes).is_err());
    }
}
