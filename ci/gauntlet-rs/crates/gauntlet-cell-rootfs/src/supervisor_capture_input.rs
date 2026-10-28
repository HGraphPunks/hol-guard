//! Root-owned input accounting for one actual gated process capture.
//! Hash bytes only; no hook credentials or arbitrary stdin are published.
use crate::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) struct CaptureInput {
    handle: Option<String>,
    argv_sha256: String,
    expected_sha256: String,
    expected_bytes: usize,
    delivered: Sha256,
    delivered_bytes: usize,
    closed: bool,
}
impl CaptureInput {
    pub(crate) fn new(argv: &[String], raw: &[u8]) -> Result<Self> {
        if argv.is_empty()
            || argv.len() > 64
            || raw.len() > 8 * 1024 * 1024
            || argv
                .iter()
                .any(|s| s.is_empty() || s.contains('\0') || s.len() > 16_384)
        {
            return Err("bounded capture input/argv required".into());
        }
        Ok(Self {
            handle: None,
            argv_sha256: crate::hash(argv.join("\0").as_bytes()),
            expected_sha256: crate::hash(raw),
            expected_bytes: raw.len(),
            delivered: Sha256::new(),
            delivered_bytes: 0,
            closed: false,
        })
    }
    pub(crate) fn bind(&mut self, handle: &str) -> Result<Value> {
        if self.handle.is_some() || handle.is_empty() || handle.len() > 128 {
            return Err("one owned capture handle required".into());
        }
        self.handle = Some(handle.to_owned());
        Ok(
            json!({"schema":"hol-gauntlet-capture-input-binding.v1","handle":handle,
            "argv_sha256":self.argv_sha256,"expected_bytes":self.expected_bytes,"expected_sha256":self.expected_sha256}),
        )
    }
    pub(crate) fn delivered(&mut self, raw: &[u8]) -> Result<()> {
        if self.handle.is_none()
            || self.closed
            || self.delivered_bytes.saturating_add(raw.len()) > self.expected_bytes
        {
            return Err("capture input delivery exceeds bound or phase".into());
        }
        self.delivered.update(raw);
        self.delivered_bytes += raw.len();
        Ok(())
    }
    pub(crate) fn closed(&mut self) -> Result<()> {
        if self.handle.is_none()
            || self.closed
            || self.delivered_bytes != self.expected_bytes
            || format!("{:x}", self.delivered.clone().finalize()) != self.expected_sha256
        {
            return Err("capture input close before exact delivery".into());
        }
        self.closed = true;
        Ok(())
    }
    pub(crate) fn observation(&self) -> Value {
        let actual = format!("{:x}", self.delivered.clone().finalize());
        json!({"schema":"hol-gauntlet-capture-input-terminal.v1","handle":self.handle,
            "argv_sha256":self.argv_sha256,"expected_sha256":self.expected_sha256,"expected_bytes":self.expected_bytes,
            "delivered_sha256":actual,"delivered_bytes":self.delivered_bytes,"stdin_close_acknowledged":self.closed,
            "input_complete":self.handle.is_some() && self.closed && self.expected_bytes == self.delivered_bytes && actual == self.expected_sha256,
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":0})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(raw: &[u8]) -> CaptureInput {
        CaptureInput::new(&["/usr/bin/cat".into()], raw).unwrap()
    }
    #[test]
    fn partial_input_and_early_close_never_become_complete() {
        let mut value = input(b"abc");
        assert!(value.delivered(b"a").is_err());
        value.bind("owned-handle").unwrap();
        value.delivered(b"a").unwrap();
        assert!(value.closed().is_err());
        assert!(value.delivered(b"bcd").is_err());
        let row = value.observation();
        assert_eq!(row["delivered_bytes"], 1);
        assert_eq!(
            row["delivered_sha256"],
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
        assert_eq!(
            row["expected_sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(row["input_complete"], false);
    }
    #[test]
    fn exact_binary_chunks_close_once_and_cannot_be_rebound_or_extended() {
        let raw = [255, 0, 10];
        let mut value = input(&raw);
        let binding = value.bind("one").unwrap();
        assert_eq!(binding["expected_sha256"], crate::hash(&raw));
        value.delivered(&raw[..2]).unwrap();
        value.delivered(&raw[2..]).unwrap();
        value.closed().unwrap();
        let row = value.observation();
        assert_eq!(row["input_complete"], true);
        assert!(value.bind("two").is_err());
        assert!(value.closed().is_err());
        assert!(value.delivered(b"").is_err());
        assert_eq!(value.observation(), row);
    }
    #[test]
    fn equal_length_changed_input_and_unstarted_empty_capture_stay_unverified() {
        let mut value = input(b"abc");
        value.bind("one").unwrap();
        value.delivered(b"abd").unwrap();
        assert!(value.closed().is_err());
        assert_eq!(value.observation()["input_complete"], false);
        let mut empty = input(b"");
        assert_eq!(empty.observation()["input_complete"], false);
        empty.bind("empty").unwrap();
        assert_eq!(empty.observation()["input_complete"], false);
        empty.closed().unwrap();
        assert_eq!(empty.observation()["input_complete"], true);
        assert!(CaptureInput::new(&["/usr/bin/cat\0extra".into()], b"").is_err());
    }
}
