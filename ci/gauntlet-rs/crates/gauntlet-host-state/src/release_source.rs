//! Fixed, data-only release tag lookup and bounded response parser. No Git
//! subprocess or credential broker is invoked by this crate.

use crate::{git_sha, load_operations_bytes, QueueConfig};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseSourceError {
    InvalidConfig,
    TagNotAllowed,
    InvalidResponse,
    MissingTag,
    TooLarge,
}

impl fmt::Display for ReleaseSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid reviewed Git lookup configuration",
            Self::TagNotAllowed => "explicit stable tag allowlist required",
            Self::InvalidResponse => "unexpected or ambiguous Git tag response",
            Self::MissingTag => "exact release tag is missing",
            Self::TooLarge => "Git tag response exceeds byte limit",
        })
    }
}

impl std::error::Error for ReleaseSourceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagLookupPlan {
    pub tag: String,
    pub argv: Vec<String>,
    repository: String,
    reference: String,
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    let safe = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
            )
    });
    if safe {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

impl TagLookupPlan {
    /// Validate the complete operations object and freeze Python's fixed Git
    /// argv without invoking it. A future caller still needs an independently
    /// authenticated configuration file and a trusted Git executable.
    pub fn new(operations: &Value, tag: &str) -> Result<Self, ReleaseSourceError> {
        let raw = serde_json::to_vec(operations).map_err(|_| ReleaseSourceError::InvalidConfig)?;
        let verified =
            load_operations_bytes(&raw).map_err(|_| ReleaseSourceError::InvalidConfig)?;
        let queue = QueueConfig::from_operations(&verified)
            .map_err(|_| ReleaseSourceError::InvalidConfig)?;
        if !queue.release_tags.iter().any(|allowed| allowed == tag) {
            return Err(ReleaseSourceError::TagNotAllowed);
        }
        let git = verified["git"]
            .as_str()
            .ok_or(ReleaseSourceError::InvalidConfig)?;
        let gh = verified["gh"]
            .as_str()
            .ok_or(ReleaseSourceError::InvalidConfig)?;
        let repository = verified["repository"]
            .as_str()
            .ok_or(ReleaseSourceError::InvalidConfig)?;
        let reference = format!("refs/tags/{tag}");
        let argv = vec![
            git.to_owned(),
            "-c".to_owned(),
            "core.hooksPath=/dev/null".to_owned(),
            "-c".to_owned(),
            "fetch.fsckObjects=true".to_owned(),
            "-c".to_owned(),
            "credential.helper=".to_owned(),
            "-c".to_owned(),
            format!("credential.helper=!{} auth git-credential", shell_quote(gh)),
            "ls-remote".to_owned(),
            "--exit-code".to_owned(),
            "--tags".to_owned(),
            format!("https://github.com/{repository}.git"),
            reference.clone(),
            format!("{reference}^{{}}"),
        ];
        Ok(Self {
            tag: tag.to_owned(),
            argv,
            repository: repository.to_owned(),
            reference,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "tag": self.tag,
            "argv": self.argv,
            "env_delta": {"GIT_TERMINAL_PROMPT":"0"},
            "execution_eligible": false,
        })
    }

    /// Reproduce Python's exact direct/peeled-tag selection over bounded
    /// stdout. The command's exit status and remote authenticity remain the
    /// future subprocess caller's responsibility.
    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, ReleaseSourceError> {
        if stdout.len() > MAX_RESPONSE_BYTES {
            return Err(ReleaseSourceError::TooLarge);
        }
        let output =
            std::str::from_utf8(stdout).map_err(|_| ReleaseSourceError::InvalidResponse)?;
        let peeled = format!("{}^{{}}", self.reference);
        let mut refs = HashMap::<&str, &str>::new();
        for line in output.lines() {
            let Some((sha, name)) = line.split_once('\t') else {
                return Err(ReleaseSourceError::InvalidResponse);
            };
            if name.contains('\t')
                || !matches!(name, target if target == self.reference || target == peeled)
                || refs.contains_key(name)
                || !git_sha(sha)
            {
                return Err(ReleaseSourceError::InvalidResponse);
            }
            refs.insert(name, sha);
        }
        let direct = refs
            .get(self.reference.as_str())
            .ok_or(ReleaseSourceError::MissingTag)?;
        let sha = refs.get(peeled.as_str()).unwrap_or(direct);
        Ok(json!({
            "tag": self.tag,
            "sha": sha,
            "url": format!("https://github.com/{}/releases/tag/{}", self.repository, self.tag),
        }))
    }
}
