//! Optional task-scoped MCP mutation limit, claimed before forwarding a call.
//!
//! A trusted operator installs the policy in the private Guard home. The
//! resident owns classification, the cross-proxy counter, and the one-use
//! claim. An unavailable or corrupt configured policy blocks the call.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use fs2::FileExt;
use nix::errno::Errno;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

pub(crate) const FEATURE: &str = "mcp-task-write-budget-v1";
const REQUEST_SCHEMA: &str = "guard-mcp-write-budget-claim-request.v1";
const RESULT_SCHEMA: &str = "guard-mcp-write-budget-claim-result.v1";
const POLICY_SCHEMA: &str = "guard-mcp-task-write-budget.v1";
const STATE_SCHEMA: &str = "guard-mcp-task-write-budget-state.v1";
const POLICY_NAME: &str = "mcp-task-write-budget.json";
const LOCK_NAME: &str = "mcp-task-write-budget.lock";
const STATE_NAME: &str = "mcp-task-write-budget-state.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimRequest {
    schema: String,
    request_id: String,
    pub(crate) guard_home: String,
    tool_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    max_writes: u32,
    read_only_tools: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    policy_sha256: String,
    claimed_writes: u32,
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

fn private_home(path: &Path) -> Option<File> {
    if !path.is_absolute() {
        return None;
    }
    let mut current = open("/", directory_flags(), Mode::empty()).ok()?;
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return None;
        };
        current = openat(&current, name, directory_flags(), Mode::empty()).ok()?;
    }
    let home = File::from(current);
    home.metadata()
        .ok()
        .filter(|info| {
            info.is_dir()
                && info.uid() == Uid::current().as_raw()
                && info.mode() & 0o7777 == 0o700
        })
        .map(|_| home)
}

fn regular_private(file: &File, max_bytes: u64) -> bool {
    file.metadata().is_ok_and(|info| {
        info.is_file()
            && info.uid() == Uid::current().as_raw()
            && info.mode() & 0o7777 == 0o600
            && info.nlink() == 1
            && info.len() <= max_bytes
    })
}

fn read_bounded(file: &mut File, max_bytes: u64) -> Option<Vec<u8>> {
    if !regular_private(file, max_bytes) {
        return None;
    }
    let mut raw = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut raw).ok()?;
    (raw.len() as u64 <= max_bytes).then_some(raw)
}

fn policy(home: &File) -> Result<Option<(Policy, String)>, ()> {
    let fd = match openat(
        home,
        POLICY_NAME,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(_) => return Err(()),
    };
    let raw = read_bounded(&mut File::from(fd), 8192).ok_or(())?;
    let parsed: Policy = serde_json::from_slice(&raw).map_err(|_| ())?;
    if parsed.schema != POLICY_SCHEMA
        || !(1..=1000).contains(&parsed.max_writes)
        || parsed.read_only_tools.len() > 128
        || parsed.read_only_tools.iter().any(|name| {
            name.is_empty() || name.len() > 256 || name.bytes().any(|c| !valid_name_byte(c))
        })
    {
        return Err(());
    }
    let mut sorted = parsed.read_only_tools.clone();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != parsed.read_only_tools.len() {
        return Err(());
    }
    Ok(Some((parsed, hex::encode(Sha256::digest(raw)))))
}

fn valid_name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'/' | b':')
}

fn state_file(home: &File) -> Option<(File, bool)> {
    let flags = OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let (fd, new) = match openat(home, STATE_NAME, flags | OFlag::O_CREAT | OFlag::O_EXCL, Mode::from_bits_truncate(0o600)) {
        Ok(fd) => (fd, true),
        Err(Errno::EEXIST) => (openat(home, STATE_NAME, flags, Mode::empty()).ok()?, false),
        Err(_) => return None,
    };
    let file = File::from(fd);
    regular_private(&file, 8192).then_some((file, new))
}

fn claim(home: &File, digest: &str, maximum: u32) -> Option<(bool, u32)> {
    let lock = File::from(
        openat(
            home,
            LOCK_NAME,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .ok()?,
    );
    if !regular_private(&lock, 0) || lock.lock_exclusive().is_err() {
        return None;
    }
    let (mut file, new) = state_file(home)?;
    let mut state = if new {
        State {
            schema: STATE_SCHEMA.into(),
            policy_sha256: digest.into(),
            claimed_writes: 0,
        }
    } else {
        let raw = read_bounded(&mut file, 8192)?;
        serde_json::from_slice::<State>(&raw).ok()?
    };
    if state.schema != STATE_SCHEMA
        || state.policy_sha256 != digest
        || state.claimed_writes > maximum
    {
        return None;
    }
    if state.claimed_writes == maximum {
        return Some((false, 0));
    }
    state.claimed_writes += 1;
    let raw = serde_json::to_vec(&state).ok()?;
    file.seek(SeekFrom::Start(0)).ok()?;
    file.set_len(0).ok()?;
    file.write_all(&raw).ok()?;
    file.sync_all().ok()?;
    Some((true, maximum - state.claimed_writes))
}

pub(crate) fn evaluate(request: &ClaimRequest) -> Result<Vec<u8>, String> {
    let (decision, reason, remaining) = if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.tool_name.is_empty()
        || request.tool_name.len() > 256
        || request.tool_name.bytes().any(|c| !valid_name_byte(c))
    {
        ("block", "invalid_request", None)
    } else if let Some(home) = private_home(Path::new(&request.guard_home)) {
        match policy(&home) {
            Ok(None) => ("inactive", "no_policy", None),
            Ok(Some((policy, _))) if policy.read_only_tools.contains(&request.tool_name) => {
                ("allow", "read_only", None)
            }
            Ok(Some((policy, digest))) => match claim(&home, &digest, policy.max_writes) {
                Some((true, remaining)) => ("allow", "claimed", Some(remaining)),
                Some((false, _)) => ("block", "write_budget_exhausted", Some(0)),
                None => ("block", "budget_state_invalid", None),
            },
            Err(()) => ("block", "policy_invalid", None),
        }
    } else {
        ("block", "guard_home_invalid", None)
    };
    crate::encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "request_id": request.request_id,
        "status": "ok",
        "decision": decision,
        "reason": reason,
        "remaining": remaining,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (tempfile::TempDir, ClaimRequest) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap();
        let file = path.join(POLICY_NAME);
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({
                "schema": POLICY_SCHEMA,
                "max_writes": 2,
                "read_only_tools": ["crm.read"],
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        (
            root,
            ClaimRequest {
                schema: REQUEST_SCHEMA.into(),
                request_id: "test-claim".into(),
                guard_home: path.to_str().unwrap().into(),
                tool_name: "crm.update".into(),
            },
        )
    }

    fn decision(request: &ClaimRequest) -> serde_json::Value {
        serde_json::from_slice(&evaluate(request).unwrap()).unwrap()
    }

    #[test]
    fn read_calls_do_not_consume_mutation_budget() {
        let (_root, mut request) = setup();
        request.tool_name = "crm.read".into();
        assert_eq!(decision(&request)["reason"], "read_only");
        request.tool_name = "crm.update".into();
        assert_eq!(decision(&request)["remaining"], 1);
        assert_eq!(decision(&request)["remaining"], 0);
        assert_eq!(decision(&request)["reason"], "write_budget_exhausted");
    }

    #[test]
    fn changed_policy_and_corrupt_state_fail_closed() {
        let (_root, request) = setup();
        assert_eq!(decision(&request)["decision"], "allow");
        let home = Path::new(&request.guard_home);
        let policy = home.join(POLICY_NAME);
        let mut raw = std::fs::read(&policy).unwrap();
        raw.push(b' ');
        std::fs::write(&policy, raw).unwrap();
        assert_eq!(decision(&request)["reason"], "budget_state_invalid");
        std::fs::write(home.join(STATE_NAME), b"broken").unwrap();
        assert_eq!(decision(&request)["decision"], "block");
    }

    #[test]
    fn absent_policy_does_not_claim_state() {
        let (_root, request) = setup();
        let home = Path::new(&request.guard_home);
        std::fs::remove_file(home.join(POLICY_NAME)).unwrap();
        assert_eq!(decision(&request)["decision"], "inactive");
        assert!(!home.join(STATE_NAME).exists());
    }

    #[test]
    fn concurrent_proxies_cannot_exceed_the_claim_limit() {
        let (_root, request) = setup();
        let request = std::sync::Arc::new(request);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let request = request.clone();
                std::thread::spawn(move || decision(&request)["decision"] == "allow")
            })
            .collect();
        assert_eq!(threads.into_iter().map(|thread| thread.join().unwrap()).filter(|allowed| *allowed).count(), 2);
    }
}
