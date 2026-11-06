//! Input-delivery relations inside an already authenticated supervisor journal.
//! A receipt establishes supplied byte relations, not Native causality by itself.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{argv, digest, require, text, Artifacts};
use crate::{EvidenceError, Result};
use serde_json::{json, Value};

pub(crate) fn journal_binding(plane: &Value, artifacts: &Artifacts<'_>) -> Result<bool> {
    let receipts = artifacts.events.iter().any(|r| {
        matches!(
            r["kind"].as_str(),
            Some("capture-input-bound" | "capture-input-terminal")
        )
    });
    let pin = plane.get("capture_journal");
    let schema = plane.get("capture_input_receipt_schema");
    if pin.is_none() && schema.is_none() {
        require(!receipts)?;
        return Ok(false);
    }
    require(schema == Some(&json!("hol-gauntlet-capture-input-terminal.v1")) && receipts)?;
    check_journal_binding(
        pin.ok_or(EvidenceError::Invalid("signed journal binding missing"))?,
        artifacts.raw("combined/cell/native-supervisor-events.v1.jsonl")?,
        &artifacts.events,
        artifacts.metadata("combined/cell/native-supervisor-events.v1.jsonl")?,
    )?;
    Ok(true)
}
fn check_journal_binding(
    pin: &Value,
    raw: &[u8],
    events: &[Value],
    metadata: &Value,
) -> Result<()> {
    require(
        !events.is_empty()
            && pin["schema"] == "hol-gauntlet-cell-journal-binding.v1"
            && pin["available"] == true
            && pin["events"].as_u64() == Some(events.len() as u64)
            && pin["bytes"].as_u64() == Some(raw.len() as u64)
            && pin["tail_sha256"] == digest(events.last().unwrap())?,
    )?;
    for name in ["device", "inode"] {
        require(pin[name].as_u64().is_some_and(|n| n > 0) && pin[name] == metadata[name])?;
    }
    for (name, expected) in [("uid", 0), ("gid", 0), ("mode", 0o600), ("links", 1)] {
        require(pin[name].as_u64() == Some(expected) && metadata[name] == pin[name])?;
    }
    Ok(())
}

/// Join one output capture to the measured gate, pre-release input binding and
/// actual acknowledged delivery. Old journals receive no input-delivery credit.
/// The caller must authenticate the complete event chain and original bytes.
pub fn verify_native_capture_input(
    events: &[Value],
    capture_sequence: usize,
    command: &[String],
    expected: &[u8],
) -> Result<Value> {
    require(
        !events.is_empty()
            && events.len() <= 10_000
            && capture_sequence < events.len()
            && expected.len() <= 8 * 1024 * 1024
            && !command.is_empty()
            && command.len() <= 62
            && command
                .iter()
                .all(|s| !s.is_empty() && s.len() <= 16_384 && !s.contains('\0')),
    )?;
    for (sequence, row) in events.iter().enumerate() {
        require(
            row["schema"] == "hol-gauntlet-cell-event.v1"
                && row["sequence"].as_u64() == Some(sequence as u64),
        )?;
    }
    let capture = &events[capture_sequence];
    let command_sha = sha256(command.join("\0").as_bytes());
    require(
        capture["kind"] == "capture-terminal" && capture["data"]["argv_sha256"] == command_sha,
    )?;
    let receipts_exist = events.iter().any(|r| {
        matches!(
            r["kind"].as_str(),
            Some("capture-input-bound" | "capture-input-terminal")
        )
    });
    if !receipts_exist {
        return Ok(
            json!({"schema":"hol-gauntlet-native-capture-input-readback.v1",
            "input_binding_available":false,"input_delivery_checked":false,"historical_input_receipt_missing":true,
            "independent_process_custody_checked":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
        );
    }
    let terminal_sequence = capture_sequence
        .checked_sub(1)
        .ok_or(EvidenceError::Invalid("capture input terminal missing"))?;
    let row = &events[terminal_sequence];
    let terminal = &row["data"];
    require(
        row["kind"] == "capture-input-terminal"
            && terminal["schema"] == "hol-gauntlet-capture-input-terminal.v1",
    )?;
    let handle = text(terminal, "handle")?;
    require(
        handle.len() == 36
            && handle.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            }),
    )?;
    let bound = events
        .iter()
        .enumerate()
        .filter(|(_, r)| r["kind"] == "capture-input-bound" && r["data"]["handle"] == handle)
        .collect::<Vec<_>>();
    let gates = events
        .iter()
        .enumerate()
        .filter(|(_, r)| r["kind"] == "gated-product-process" && r["data"]["handle"] == handle)
        .collect::<Vec<_>>();
    let releases = events
        .iter()
        .enumerate()
        .filter(|(_, r)| r["kind"] == "product-release" && r["data"]["handle"] == handle)
        .collect::<Vec<_>>();
    let terminals = events
        .iter()
        .filter(|r| r["kind"] == "capture-input-terminal" && r["data"]["handle"] == handle)
        .count();
    require(bound.len() == 1 && gates.len() == 1 && releases.len() == 1 && terminals == 1)?;
    require(
        gates[0].0 < bound[0].0 && bound[0].0 < releases[0].0 && releases[0].0 < terminal_sequence,
    )?;
    let binding = &bound[0].1["data"];
    require(binding["schema"] == "hol-gauntlet-capture-input-binding.v1")?;
    let mut gated = vec![
        "/public/gauntlet-product-cell".to_owned(),
        "exec-gate".into(),
    ];
    gated.extend_from_slice(command);
    require(argv(&gates[0].1["data"]["identity"]["argv"])? == gated)?;
    let expected_sha = sha256(expected);
    for v in [binding, terminal] {
        require(
            v["argv_sha256"] == command_sha
                && v["expected_sha256"] == expected_sha
                && v["expected_bytes"].as_u64() == Some(expected.len() as u64),
        )?;
    }
    let delivered = terminal["delivered_bytes"]
        .as_u64()
        .filter(|n| *n <= expected.len() as u64)
        .ok_or(EvidenceError::Invalid(
            "bounded delivered capture input required",
        ))? as usize;
    require(terminal["delivered_sha256"] == sha256(&expected[..delivered]))?;
    let closed = terminal["stdin_close_acknowledged"]
        .as_bool()
        .ok_or(EvidenceError::Invalid(
            "typed capture input-close acknowledgement required",
        ))?;
    let complete = closed && delivered == expected.len();
    require(
        (!closed || delivered == expected.len())
            && terminal["input_complete"].as_bool() == Some(complete)
            && terminal["execution_eligible"] == false
            && terminal["guard_causality_verified"] == false
            && terminal["model_requests"].as_u64() == Some(0),
    )?;
    Ok(
        json!({"schema":"hol-gauntlet-native-capture-input-readback.v1","input_binding_available":true,
        "input_delivery_checked":complete,"historical_input_receipt_missing":false,"handle":handle,
        "capture_sequence":capture_sequence,"binding_sequence":bound[0].0,"expected_bytes":expected.len(),
        "expected_sha256":expected_sha,"delivered_bytes":delivered,"stdin_close_acknowledged":closed,
        "independent_process_custody_checked":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_capture_input_tests.rs"]
mod tests;
