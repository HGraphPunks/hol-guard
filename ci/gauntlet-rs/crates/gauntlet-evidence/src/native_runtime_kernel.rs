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
pub(crate) fn verify(
    control: &Value,
    preparation: &Value,
    artifacts: &Artifacts<'_>,
    samples: &KernelSamples<'_>,
    hooks: &Value,
) -> Result<Value> {
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
