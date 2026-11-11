//! Independent length-prefixed framing. Partial/malformed streams stay explicit.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{parse, require};
use crate::Result;
use serde_json::{json, Value};

pub(crate) fn summary(raw: &[u8], maximum: usize) -> Result<Value> {
    require(raw.len() <= 32 * 1024 * 1024 && matches!(maximum, 2_097_152 | 6_291_456))?;
    let mut offset = 0;
    let mut frames = Vec::new();
    let mut status = "complete";
    while offset < raw.len() {
        require(frames.len() < 8192)?;
        if raw.len() - offset < 4 {
            status = "partial-header";
            break;
        }
        let count = u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
        if count == 0 || count > maximum {
            status = "invalid-length";
            break;
        }
        if raw.len() - offset - 4 < count {
            status = "partial-payload";
            break;
        }
        let payload = &raw[offset + 4..offset + 4 + count];
        let value = parse(payload).ok();
        frames.push(json!({"offset":offset,"bytes":count,"sha256":sha256(payload),
            "json_valid":value.is_some(),"json_object":value.as_ref().is_some_and(Value::is_object),
            "canonical_json_sha256":value.as_ref().map(crate::canonical_value).transpose()?.map(|v|sha256(&v))}));
        offset += 4 + count;
    }
    Ok(
        json!({"bytes":raw.len(),"sha256":sha256(raw),"complete_frames":frames.len(),"frames":frames,
        "status":status,"framed_bytes":offset,"remaining_bytes":raw.len()-offset,
        "stream_eof_inferred":false,"request_semantics_verified":false}),
    )
}

/// Decode complete copied JSON objects for a separate, scoped relation check.
/// Generic framing still retains malformed and interrupted streams unchanged.
pub(crate) fn objects(raw: &[u8], maximum: usize) -> Result<Vec<Value>> {
    let framed = summary(raw, maximum)?;
    require(framed["status"] == "complete")?;
    let mut values = Vec::new();
    for frame in framed["frames"].as_array().unwrap() {
        require(frame["json_object"] == true)?;
        let start = frame["offset"].as_u64().unwrap() as usize + 4;
        let count = frame["bytes"].as_u64().unwrap() as usize;
        values.push(parse(&raw[start..start + count])?);
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(raw: &[u8]) -> Vec<u8> {
        [(raw.len() as u32).to_be_bytes().as_slice(), raw].concat()
    }
    #[test]
    fn complete_requests_and_responses_keep_exact_payload_and_json_digests() {
        let first = frame(br#"{"x":1}"#);
        let second = frame(br#"{"x":2}"#);
        let raw = [first.clone(), second].concat();
        let value = summary(&raw, 6 * 1024 * 1024).unwrap();
        assert_eq!(value["complete_frames"], 2);
        assert_eq!(value["status"], "complete");
        assert_eq!(value["frames"][1]["offset"], first.len());
        assert_eq!(value["frames"][0]["sha256"], sha256(br#"{"x":1}"#));
        assert_eq!(value["request_semantics_verified"], false);
    }
    #[test]
    fn cancellation_prefixes_remain_partial_without_inventing_eof() {
        let raw = frame(br#"{"x":1}"#);
        for length in 1..raw.len() {
            let value = summary(&raw[..length], 2 * 1024 * 1024).unwrap();
            assert_eq!(value["complete_frames"], 0);
            assert_eq!(value["remaining_bytes"], length);
            assert_eq!(
                value["status"],
                if length < 4 {
                    "partial-header"
                } else {
                    "partial-payload"
                }
            );
            assert_eq!(value["stream_eof_inferred"], false);
        }
    }
    #[test]
    fn zero_oversized_and_non_json_frames_remain_invalid_diagnostic_data() {
        for raw in [0u32.to_be_bytes(), (2 * 1024 * 1024 + 1u32).to_be_bytes()] {
            assert_eq!(
                summary(&raw, 2 * 1024 * 1024).unwrap()["status"],
                "invalid-length"
            );
        }
        for raw in [b"not-json".as_slice(), br#"{"x":1,"x":2}"#] {
            let value = summary(&frame(raw), 6 * 1024 * 1024).unwrap();
            assert_eq!(value["frames"][0]["json_valid"], false);
        }
    }
}
