//! Correlate copied hook frames with measured gates and acknowledged inputs.
//! FIFO correspondence uses the separately pinned serial Native client loop.
use crate::native_diagnostic_artifacts::{argv, digest, require, text, Artifacts};
use crate::native_process_kernel::{list, number};
use crate::native_stdio_events::Readback;
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn gate_for_handle(artifacts: &Artifacts<'_>, input: &Value) -> Result<usize> {
    let handle = text(input, "handle")?;
    let gates = artifacts
        .events
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            row["kind"] == "gated-product-process" && row["data"]["handle"] == handle
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    require(gates.len() == 1)?;
    Ok(gates[0])
}

pub(super) fn payload_relation(
    request: &Value,
    expected: &Value,
    reauthorization: bool,
) -> Result<bool> {
    let mut payload = expected
        .as_object()
        .ok_or(EvidenceError::Invalid(
            "expected outer hook payload missing",
        ))?
        .clone();
    let context = payload.remove("guard_execution_environment");
    if reauthorization {
        require(payload["hook_event_name"] == "PreToolUse")?;
        payload.insert("guard_containment_receipt_only".into(), json!(true));
    } else if let Some(context) = &context {
        require(request["source"]["execution_environment"] == *context)?;
    }
    require(request["raw_payload"] == Value::Object(payload))?;
    Ok(!reauthorization && context.is_some())
}

struct Outer<'a> {
    gate: usize,
    payload: Value,
    row: &'a Value,
}

pub(crate) fn verify(
    control: &Value,
    artifacts: &Artifacts<'_>,
    snapshots: &Readback,
    images: &Value,
    hooks: &Value,
) -> Result<Value> {
    let output = crate::native_hook_diagnostic::completed_output(control)?;
    let expected = crate::native_hook_diagnostic::hook_payloads(control, output.as_ref())?;
    let rows = list(&control["plane"]["hooks"], 4)?;
    let inputs = list(&hooks["hook_input_relations"], 4)?;
    require(
        rows.len() == expected.len()
            && inputs.len() == expected.len()
            && hooks["journal_report_binding_checked"] == true,
    )?;
    let mut outer = Vec::new();
    for ((payload, row), input) in expected.into_iter().zip(rows).zip(inputs) {
        require(row["payload"] == payload && input["input_delivery_checked"] == true)?;
        let gate = gate_for_handle(artifacts, input)?;
        require(number(&input["capture_sequence"])? > gate as u64)?;
        outer.push(Outer { gate, payload, row });
    }
    let native_images = list(&images["native_execs"], 65536)?;
    let mut checked_outer = BTreeSet::new();
    let mut operations = BTreeMap::<String, usize>::new();
    let mut pairs = Vec::new();
    let mut unanswered = Vec::new();
    let mut streams = Vec::new();
    let mut requests = 0;
    let mut responses = 0;
    let mut reauthorizations = 0;
    for stream in &snapshots.streams {
        let candidates = native_images
            .iter()
            .filter(|image| image["trace_sequence"] == stream.identity["process_exec_sequence"])
            .collect::<Vec<_>>();
        require(candidates.len() == 1)?;
        let image = candidates[0];
        require(
            image["task_id"] == stream.identity["task_id"]
                && image["pid"] == stream.identity["tid"]
                && image["start_ticks"] == stream.identity["start_ticks"]
                && image["argv_sha256"] == stream.identity["argv_sha256"]
                && image["operation"] == "resident-client-stream",
        )?;
        let gate = usize::try_from(number(&image["gate_sequence"])?)
            .map_err(|_| EvidenceError::Invalid("Native hook gate overflow"))?;
        let gate_row = artifacts
            .events
            .get(gate)
            .ok_or(EvidenceError::Invalid("Native hook gate missing"))?;
        require(gate_row["kind"] == "gated-product-process")?;
        let command = argv(&gate_row["data"]["identity"]["argv"])?;
        let request_frames = crate::native_stdio_frames::objects(&stream.read, 6 * 1024 * 1024)?;
        let response_frames =
            crate::native_stdio_frames::objects(&stream.written, 2 * 1024 * 1024)?;
        require(response_frames.len() <= request_frames.len())?;
        requests += request_frames.len();
        responses += response_frames.len();
        for (index, request) in request_frames.iter().enumerate() {
            if request.get("operation").is_some() {
                require(request.get("schema").is_none() && request["request"].is_object())?;
                let operation = text(request, "operation")?;
                require(
                    !operation.is_empty()
                        && operation.len() <= 128
                        && operation
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b == b'_'),
                )?;
                *operations.entry(operation.into()).or_default() += 1;
                if index >= response_frames.len() {
                    unanswered.push(json!({"stream":stream.stream,"frame_index":index,"operation":operation,
                        "request_sha256":digest(request)?,"response_observed":false,"disposition_inferred":false}));
                }
                continue;
            }
            let response = response_frames
                .get(index)
                .ok_or(EvidenceError::Invalid("copied hook response unavailable"))?;
            let identities = crate::native_stdio_hook_identity::verify(request, response)?;
            let reauthorization = command
                .get(8)
                .is_some_and(|v| v == "execute-contained-test");
            let context = if reauthorization {
                require(request["event"] == "PreToolUse")?;
                if hooks["contained_sink_input"].is_object() {
                    require(gate_for_handle(artifacts, &hooks["contained_sink_input"])? == gate)?;
                } else {
                    // Cancellation has no completed sink input receipt. Keep
                    // this action correlation separate from delivery credit.
                    require(control["control_role"] == "cancel")?;
                }
                reauthorizations += 1;
                outer
                    .iter()
                    .find(|value| value.payload["hook_event_name"] == "PreToolUse")
            } else {
                require(command.get(8).is_some_and(|v| v == "hook") && checked_outer.insert(gate))?;
                outer.iter().find(|value| value.gate == gate)
            }
            .ok_or(EvidenceError::Invalid(
                "copied hook has no outer input relation",
            ))?;
            let caller_context = payload_relation(request, &context.payload, reauthorization)?;
            let code = context.row["returncode"]
                .as_i64()
                .ok_or(EvidenceError::Invalid("outer hook return code missing"))?;
            let normalized = crate::normalize_native_hook_response(
                &canonical_value(&response["harness_response"])?,
                code,
                Some(text(request, "event")?),
            )?;
            require(normalized == context.row["response"])?;
            pairs.push(json!({"stream":stream.stream,"frame_index":index,"process_exec_sequence":stream.identity["process_exec_sequence"],
                "gate_sequence":gate,"outer_hook_gate_sequence":context.gate,
                "event":request["event"],"request_sha256":digest(request)?,"response_sha256":digest(response)?,
                "outer_payload_sha256":digest(&context.payload)?,"contained_reauthorization":reauthorization,
                "outer_input_delivery_checked":!reauthorization,"supplied_caller_execution_context_checked":caller_context,
                "copied_response_matches_outer_hook":true,"identity":identities}));
        }
        streams.push(json!({"stream":stream.stream,"gate_sequence":gate,
            "request_frames":request_frames.len(),"response_frames":response_frames.len()}));
    }
    require(checked_outer.len() == outer.len())?;
    Ok(
        json!({"schema":"hol-gauntlet-copied-native-hook-relations.v1",
        "stream_frames":streams,"request_frames":requests,"response_frames":responses,
        "copied_hook_pairs_checked":pairs.len(),"outer_hooks_joined":checked_outer.len(),
        "contained_reauthorizations_checked":reauthorizations,"pairs":pairs,
        "operation_requests_observed":operations,"operation_request_semantics_verified":false,
        "unanswered_requests":unanswered,"fifo_correspondence_uses_pinned_serial_client_loop":true,
        "all_request_semantics_verified":false,"atomic_kernel_pipe_bytes_verified":false,
        "concurrent_memory_authenticated":false,"physical_effect_writers_verified":false,
        "outside_observer_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_stdio_hook_relations_tests.rs"]
mod tests;
