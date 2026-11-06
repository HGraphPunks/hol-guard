//! Reconstruct bounded capture bytes from the released handle's stream journal.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{argv, require, text, Artifacts};
use crate::{EvidenceError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn decode(chunk: &Value, name: &str) -> Result<Vec<u8>> {
    let encoded = text(chunk, name)?;
    require(encoded.len() <= 131072)?;
    let raw = STANDARD
        .decode(encoded)
        .map_err(|_| EvidenceError::Invalid("invalid capture stream base64"))?;
    require(raw.len() <= 65536 && STANDARD.encode(&raw) == encoded)?;
    Ok(raw)
}
fn read(
    events: &[Value],
    handle: &str,
    released: usize,
    terminal: usize,
    expected: [&[u8]; 2],
    code: Option<i64>,
) -> Result<usize> {
    let mut output = [Vec::new(), Vec::new()];
    let mut ended = [false, false];
    let mut exit = None;
    let mut count = 0;
    for (sequence, row) in events.iter().enumerate() {
        if row["kind"] != "product-stream" || row["data"]["handle"] != handle {
            continue;
        }
        require(sequence > released && sequence < terminal)?;
        let chunk = &row["data"]["chunk"];
        let keys = [
            "stdout",
            "stderr",
            "stdout_eof",
            "stderr_eof",
            "returncode",
            "output_bytes",
        ];
        require(
            chunk
                .as_object()
                .is_some_and(|v| v.len() == keys.len() && keys.iter().all(|k| v.contains_key(*k))),
        )?;
        for (index, name) in ["stdout", "stderr"].iter().enumerate() {
            let raw = decode(chunk, name)?;
            require(!ended[index] || raw.is_empty())?;
            output[index].extend(raw);
            let eof = chunk[format!("{name}_eof")]
                .as_bool()
                .ok_or(EvidenceError::Invalid("typed stream EOF required"))?;
            require(!ended[index] || eof)?;
            ended[index] = eof;
        }
        let bytes = output.iter().map(Vec::len).sum::<usize>();
        require(bytes <= 8 * 1024 * 1024 && chunk["output_bytes"].as_u64() == Some(bytes as u64))?;
        if !chunk["returncode"].is_null() {
            let value = chunk["returncode"]
                .as_i64()
                .filter(|n| (-255..=255).contains(n))
                .ok_or(EvidenceError::Invalid("typed stream exit required"))?;
            require(exit.is_none_or(|prior| prior == value))?;
            exit = Some(value);
        } else {
            require(exit.is_none())?;
        }
        count += 1;
    }
    require(output[0] == expected[0] && output[1] == expected[1])?;
    if let Some(code) = code {
        require(exit == Some(code) && ended == [true, true] && count > 0)?;
    }
    Ok(count)
}

pub(crate) fn verify(artifacts: &Artifacts<'_>) -> Result<Value> {
    let mut used = BTreeSet::new();
    let mut captures = Vec::new();
    let mut partial = 0;
    for (sequence, row) in artifacts.events.iter().enumerate() {
        if row["kind"] != "capture-terminal" {
            continue;
        }
        let data = &row["data"];
        let mut candidates = Vec::new();
        for (gate_sequence, gate) in artifacts.events[..sequence].iter().enumerate() {
            if gate["kind"] != "gated-product-process" {
                continue;
            }
            let command = argv(&gate["data"]["identity"]["argv"])?;
            require(
                command.len() > 2
                    && command[0] == "/public/gauntlet-product-cell"
                    && command[1] == "exec-gate",
            )?;
            if data["argv_sha256"] == sha256(command[2..].join("\0").as_bytes()) {
                candidates.push((gate_sequence, &gate["data"]));
            }
        }
        let (gate_sequence, gate) = candidates
            .last()
            .ok_or(EvidenceError::Invalid("capture has no measured gate"))?;
        let handle = text(gate, "handle")?;
        require(!handle.is_empty() && handle.len() <= 128 && used.insert(handle))?;
        let released = artifacts
            .events
            .iter()
            .enumerate()
            .filter(|(_, r)| r["kind"] == "product-release" && r["data"]["handle"] == handle)
            .collect::<Vec<_>>();
        require(released.len() == 1 && released[0].0 > *gate_sequence && released[0].0 < sequence)?;
        let code = if data.get("error").is_some_and(Value::is_null) {
            Some(
                data["returncode"]
                    .as_i64()
                    .filter(|n| (-255..=255).contains(n))
                    .ok_or(EvidenceError::Invalid("capture exit required"))?,
            )
        } else {
            require(
                data.get("returncode").is_some_and(Value::is_null)
                    && !text(data, "error")?.is_empty(),
            )?;
            partial += 1;
            None
        };
        let raw = |name| {
            artifacts.raw(&format!(
                "combined/cell/{}",
                text(&data["files"][name], "file")?
            ))
        };
        let chunks = read(
            &artifacts.events,
            handle,
            released[0].0,
            sequence,
            [raw("stdout")?, raw("stderr")?],
            code,
        )?;
        let retired = artifacts
            .events
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r["kind"] == "retired-product-process" && r["data"]["handle"] == handle
            })
            .collect::<Vec<_>>();
        if code.is_some() {
            require(
                retired.len() == 1
                    && retired[0].0 > released[0].0
                    && retired[0].0 < sequence
                    && retired[0].1["data"]["pid"] == gate["identity"]["pid"],
            )?;
        } else {
            require(retired.is_empty())?;
        }
        captures.push(
            json!({"capture_sequence":sequence,"gate_sequence":gate_sequence,
            "handle":handle,"stream_chunks":chunks,"completed":code.is_some()}),
        );
    }
    require(!captures.is_empty() && captures.len() <= 256)?;
    Ok(
        json!({"schema":"hol-gauntlet-native-capture-stream-relations.v1","captures_checked":captures.len(),
        "partial_captures":partial,"captures":captures,"all_capture_bytes_reconstructed":true,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(chunk: Value) -> Value {
        json!({"kind":"product-stream","data":{"handle":"held","chunk":chunk}})
    }
    fn chunks() -> Vec<Value> {
        vec![
            Value::Null,
            event(
                json!({"stdout":"AP8K","stderr":"","stdout_eof":false,"stderr_eof":false,"returncode":null,"output_bytes":3}),
            ),
            event(
                json!({"stdout":"","stderr":"","stdout_eof":true,"stderr_eof":true,"returncode":-9,"output_bytes":3}),
            ),
            Value::Null,
        ]
    }
    #[test]
    fn binary_stream_terminal_and_cumulative_bytes_must_match() {
        let rows = chunks();
        assert_eq!(
            read(&rows, "held", 0, 3, [&[0, 255, 10], b""], Some(-9)).unwrap(),
            2
        );
        for (field, bad) in [
            ("output_bytes", json!(4)),
            ("returncode", json!(true)),
            ("stdout_eof", json!(1)),
            ("stdout", json!("%%%")),
        ] {
            let mut changed = rows.clone();
            changed[1]["data"]["chunk"][field] = bad;
            assert!(read(&changed, "held", 0, 3, [&[0, 255, 10], b""], Some(-9)).is_err());
        }
        assert!(read(&rows, "held", 0, 3, [b"changed", b""], Some(-9)).is_err());
    }
    #[test]
    fn partial_output_does_not_gain_a_terminal_and_eof_cannot_reopen() {
        let mut rows = chunks();
        rows.remove(2);
        assert_eq!(
            read(&rows, "held", 0, 2, [&[0, 255, 10], b""], None).unwrap(),
            1
        );
        assert!(read(&rows, "held", 0, 2, [&[0, 255, 10], b""], Some(0)).is_err());
        let mut rows = chunks();
        rows[1]["data"]["chunk"]["stdout_eof"] = json!(true);
        rows[2]["data"]["chunk"]["stdout_eof"] = json!(false);
        assert!(read(&rows, "held", 0, 3, [&[0, 255, 10], b""], Some(-9)).is_err());
        assert!(read(&chunks(), "held", 1, 3, [&[0, 255, 10], b""], Some(-9)).is_err());
    }
}
