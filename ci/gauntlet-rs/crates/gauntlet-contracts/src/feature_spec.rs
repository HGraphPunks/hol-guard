//! Closed inputs for the fixed unprivileged feature executor, never a command
//! or test-selector channel. The outside owner separately admits every asset.
use crate::{canonicalize, is_git_sha, FEATURE_CATALOG_SHA256};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

pub const FEATURE_SPEC_LIMIT: usize = 16 * 1024;
pub const FEATURE_NODE_SHA256: &str =
    "3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90";
const FIELDS: [&str; 11] = [
    "schema",
    "audit_id",
    "source_sha",
    "source_archive_sha256",
    "candidate_archive_sha256",
    "wheel_sha256",
    "native_sha256",
    "version",
    "node_sha256",
    "catalog_sha256",
    "executor_sha256",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureSpecError;
impl fmt::Display for FeatureSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed feature source, runtime and executor pins required")
    }
}
impl std::error::Error for FeatureSpecError {}

#[derive(Debug, Clone, PartialEq)]
pub struct FeatureExecutorSpec {
    body: Value,
    bytes: Vec<u8>,
}
impl FeatureExecutorSpec {
    pub fn parse(raw: &[u8]) -> Result<Self, FeatureSpecError> {
        if raw.is_empty() || raw.len() > FEATURE_SPEC_LIMIT {
            return Err(FeatureSpecError);
        }
        let bytes = canonicalize(raw).map_err(|_| FeatureSpecError)?;
        let body: Value = serde_json::from_slice(&bytes).map_err(|_| FeatureSpecError)?;
        let row = body.as_object().ok_or(FeatureSpecError)?;
        if row.len() != FIELDS.len()
            || FIELDS
                .iter()
                .any(|key| !row.get(*key).is_some_and(Value::is_string))
        {
            return Err(FeatureSpecError);
        }
        let text = |key: &str| body[key].as_str().expect("all fixed fields typed");
        let hex = |key: &str, n: usize| {
            let s = text(key);
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if text("schema") != "hol-gauntlet-feature-executor.v1"
            || !hex("audit_id", 16)
            || !is_git_sha(text("source_sha"))
            || [
                "source_archive_sha256",
                "candidate_archive_sha256",
                "wheel_sha256",
                "native_sha256",
                "executor_sha256",
            ]
            .iter()
            .any(|key| !hex(key, 64))
            || text("catalog_sha256") != FEATURE_CATALOG_SHA256
            || text("node_sha256") != FEATURE_NODE_SHA256
            || text("version").is_empty()
            || text("version").len() > 64
            || !text("version")
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'))
        {
            return Err(FeatureSpecError);
        }
        Ok(Self { body, bytes })
    }
    pub fn text(&self, key: &str) -> &str {
        self.body[key].as_str().expect("fixed feature spec field")
    }
    pub fn to_json(&self) -> Value {
        self.body.clone()
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest(&self) -> String {
        format!("{:x}", Sha256::digest(&self.bytes))
    }
}
