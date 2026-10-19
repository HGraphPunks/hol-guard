//! Verdicts the resident computes itself from the raw tool call.
//!
//! The transport forwards the payload's tool call and observed caller facts in
//! `native_request`; nothing here asks Python. A missing or oversized request
//! is "not benign", so the configured default is never relaxed on bad input.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use guard_command::benign_request_api::{
    is_benign_native_file_read, is_benign_tool_action, ToolActionControls,
};
use guard_command::command_evaluation_controls::{
    authority_failure_for_health, control_layers_from_wire,
};
use guard_command::Ctx;
use guard_contracts::{CodexToolOutputFactsV1, HookCompositionInputsV1};

use crate::codex_tool_output_op::ResidentInspectionHost;

const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT: usize = 128;
const MAX_GROUPS: usize = 256;

fn path_is_bounded(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

fn host_is_bounded(host: &CodexToolOutputFactsV1) -> bool {
    path_is_bounded(&host.process_cwd)
        && path_is_bounded(&host.home)
        && host.account_home.as_deref().is_none_or(path_is_bounded)
        && host.git_executable.as_deref().is_none_or(path_is_bounded)
        && host.groups.len() <= MAX_GROUPS
        && host.environment.len() <= MAX_ENVIRONMENT
        && host
            .environment
            .iter()
            .all(|(key, value)| key.len() <= 256 && path_is_bounded(value))
}

/// `is_explicitly_benign_native_file_read_request` for the hook's tool call.
pub(crate) fn benign_native_file_read(inputs: &HookCompositionInputsV1) -> bool {
    let Some(request) = &inputs.native_request else {
        return false;
    };
    let bounded_path = |value: &Option<String>| value.as_deref().is_none_or(path_is_bounded);
    if !host_is_bounded(&request.host)
        || !bounded_path(&request.cwd)
        || !bounded_path(&request.home_dir)
    {
        return false;
    }
    let host = ResidentInspectionHost {
        facts: &request.host,
    };
    let ctx = Ctx::new(&host, &request.host.process_cwd, &request.host.home);
    is_benign_native_file_read(
        &request.tool_name,
        &request.tool_input,
        request.cwd.as_deref().map(Path::new),
        request.home_dir.as_deref().map(Path::new),
        &ctx,
    )
}

/// How long a tool-action verdict stays reusable, and how many are kept.
///
/// One hook asks for the same verdict twice: `compose_current` settles the
/// current action, and `finalize` composes again over the same inputs to
/// reach the final one. For a `git` command the verdict runs the native Git
/// proofs, which spawn `git` to read the repository's effective
/// configuration, so the second ask repeats every probe the first one made
/// and costs as much.
///
/// The verdict is a pure function of these inputs and of the repository state
/// those proofs read, so the second ask may reuse the first. The key is the
/// canonical digest of the whole input, so a different command, directory,
/// environment or control snapshot never reuses a verdict; the window spans
/// one hook and the table holds a handful of entries. Guard decides before
/// the command runs and a review may sit for minutes, so the proofs already
/// describe the repository as it was at the time of the check rather than at
/// the time of the act; reusing one for the rest of the same hook does not
/// widen that.
const VERDICT_REUSE_WINDOW: Duration = Duration::from_secs(2);
const VERDICT_REUSE_ENTRIES: usize = 8;

static RECENT_VERDICTS: Mutex<Vec<(String, Instant, bool)>> = Mutex::new(Vec::new());

/// Whether `inputs` would reuse a recorded verdict now, for tests that assert
/// what the table holds without timing the proofs it saves.
#[cfg(test)]
pub(crate) fn verdict_is_reusable(inputs: &HookCompositionInputsV1) -> bool {
    verdict_key(inputs).is_some_and(|key| reusable_verdict(&key, Instant::now()).is_some())
}

/// Whether `inputs` would still reuse one `after` has passed.
#[cfg(test)]
pub(crate) fn verdict_is_reusable_after(inputs: &HookCompositionInputsV1, after: Duration) -> bool {
    verdict_key(inputs).is_some_and(|key| reusable_verdict(&key, Instant::now() + after).is_some())
}

/// The canonical digest of `inputs`, or `None` when it cannot be formed — in
/// which case the verdict is computed and nothing is recorded.
fn verdict_key(inputs: &HookCompositionInputsV1) -> Option<String> {
    let material = serde_json::to_value(inputs).ok()?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .ok()?;
    Some(guard_policy_snapshot::digest_bytes(&bytes))
}

fn reusable_verdict(key: &str, now: Instant) -> Option<bool> {
    let recent = RECENT_VERDICTS.lock().ok()?;
    recent
        .iter()
        .find(|(entry, at, _)| entry == key && now.duration_since(*at) < VERDICT_REUSE_WINDOW)
        .map(|(_, _, verdict)| *verdict)
}

fn record_verdict(key: String, now: Instant, verdict: bool) {
    let Ok(mut recent) = RECENT_VERDICTS.lock() else {
        return;
    };
    recent.retain(|(entry, at, _)| entry != &key && now.duration_since(*at) < VERDICT_REUSE_WINDOW);
    recent.push((key, now, verdict));
    while recent.len() > VERDICT_REUSE_ENTRIES {
        recent.remove(0);
    }
}

/// `is_explicitly_benign_tool_action_request` for the hook's tool call.
///
/// The extension-control snapshot the transport saw is the one that applies;
/// an unknown health value or any input that cannot be bounded is not benign.
pub(crate) fn benign_tool_action(inputs: &HookCompositionInputsV1) -> bool {
    // Without a request there is no proof to run and so nothing to reuse.
    if inputs.native_request.is_none() {
        return false;
    }
    let now = Instant::now();
    let key = verdict_key(inputs);
    if let Some(verdict) = key.as_deref().and_then(|key| reusable_verdict(key, now)) {
        return verdict;
    }
    let verdict = compute_benign_tool_action(inputs);
    if let Some(key) = key {
        record_verdict(key, now, verdict);
    }
    verdict
}

fn compute_benign_tool_action(inputs: &HookCompositionInputsV1) -> bool {
    let Some(request) = &inputs.native_request else {
        return false;
    };
    let bounded_path = |value: &Option<String>| value.as_deref().is_none_or(path_is_bounded);
    if !host_is_bounded(&request.host)
        || !bounded_path(&request.cwd)
        || !bounded_path(&request.home_dir)
        || request.tool_input.to_string().len() > MAX_TEXT_BYTES
    {
        return false;
    }
    let controls = match &request.control_snapshot {
        None => None,
        Some(snapshot) => {
            let Ok(authority_failure) = authority_failure_for_health(&snapshot.health) else {
                return false;
            };
            let Ok(layers) = control_layers_from_wire(&snapshot.layers) else {
                return false;
            };
            Some(ToolActionControls {
                layers,
                authority_failure,
            })
        }
    };
    let host = ResidentInspectionHost {
        facts: &request.host,
    };
    let ctx = Ctx::new(&host, &request.host.process_cwd, &request.host.home);
    is_benign_tool_action(
        &request.tool_name,
        &request.tool_input,
        request.cwd.as_deref().map(Path::new),
        request.home_dir.as_deref().map(Path::new),
        &ctx,
        controls.as_ref(),
    )
}
