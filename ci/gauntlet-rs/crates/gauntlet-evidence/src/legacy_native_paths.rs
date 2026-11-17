//! Path and ordering constraints from the source's native-tool scope oracle.
use super::*;
use regex::Regex;
use std::sync::OnceLock;

pub(super) fn write_path(args: &Value) -> String {
    let value = args.get("path").or_else(|| args.get("file_path"));
    match value {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "None".into(),
        Some(v) => v.to_string(),
    }
}
pub(super) fn strip_selector(path: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r":\d+(-\d+)?$").expect("source read selector suffix"))
        .replace(path, "")
        .into_owned()
}
fn normal(path: &str) -> String {
    let prefix = if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if path.starts_with('/') {
        "/"
    } else {
        ""
    };
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if prefix.is_empty() {
                    parts.push("..");
                }
            }
            _ => parts.push(part),
        }
    }
    let output = format!("{prefix}{}", parts.join("/"));
    if output.is_empty() {
        ".".into()
    } else {
        output
    }
}
fn profile_temp(path: &str, generation: Generation) -> Option<String> {
    if generation == Generation::Frozen128 {
        if path.contains('/') || !path.starts_with("{{home}}\\") {
            return None;
        }
    } else if path.contains('\\') && path.contains('/')
        || !path.starts_with("{{home}}\\") && !path.starts_with("{{home}}/")
    {
        return None;
    }
    let path = path.replace('\\', "/");
    let rest = path.strip_prefix("{{home}}/AppData/Local/Temp/")?;
    if rest.is_empty() || rest.contains(':') || rest.split('/').any(|p| p == "..") {
        return None;
    }
    Some(normal(&path))
}
fn created(result: &Value, generation: Generation) -> Option<String> {
    let content = result["content"].as_array()?;
    if content.len() != 1 || !content[0].is_object() {
        return None;
    }
    let text = outputs::text(&json!({"name":"bash","result":result}))?;
    let lines: Vec<_> = text.trim().lines().collect();
    if lines.len() != 1 {
        return None;
    }
    if !lines[0].starts_with('/') {
        return profile_temp(lines[0], generation);
    }
    if lines[0].split('/').any(|p| p == "..") {
        return None;
    }
    Some(normal(lines[0]))
}
pub(super) fn temp_write(calls: &[Value], generation: Generation) -> Option<&'static str> {
    let roots: Vec<_> = calls
        .iter()
        .filter(|c| c["name"] == "bash")
        .map(|c| created(&c["result"], generation))
        .collect();
    if roots.len() != 1 || roots[0].is_none() {
        return Some("the private temporary directory was not created exactly once");
    }
    let root = roots[0].as_ref().expect("checked root");
    let target = format!("{root}/scratch-notes.txt");
    let paths: Vec<_> = calls
        .iter()
        .filter(|c| c["name"] == "write")
        .map(|c| {
            let path = write_path(&c["args"]);
            if root.starts_with("{{home}}/AppData/Local/Temp/") {
                profile_temp(&path, generation).unwrap_or(path)
            } else {
                path
            }
        })
        .collect();
    if paths.len() < 2 {
        return Some("the model did not overwrite the scratch file");
    }
    if paths
        .iter()
        .any(|p| p.split('/').any(|p| p == "..") || normal(p) != target)
    {
        return Some("the model wrote outside the private temporary directory");
    }
    None
}
pub(super) fn worktree(calls: &[Value], complete: bool) -> Option<&'static str> {
    let root = "{{home}}/review-worktree/";
    let settings = format!("{root}src/settings.ts");
    let note = format!("{root}docs/change.md");
    let mut steps = Vec::new();
    for call in calls {
        let name = call["name"].as_str().unwrap_or("");
        if !matches!(name, "read" | "edit" | "write") {
            continue;
        }
        let path = if name == "edit" {
            native_inputs::edit_path(&call["args"])
        } else {
            native_inputs::path(&call["args"])
        };
        let Some(path) = path.filter(|p| p.starts_with(root) && !p.split('/').any(|p| p == ".."))
        else {
            return Some("the model used a file outside the linked worktree");
        };
        let path = if name == "read" {
            strip_selector(&path)
        } else {
            path
        };
        if name == "edit" && path != settings || name == "write" && path != note {
            return Some("the model changed a different worktree file");
        }
        steps.push((name, path));
    }
    if !complete {
        return None;
    }
    let edits: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s.0 == "edit" && s.1 == settings)
        .map(|(i, _)| i)
        .collect();
    let reads: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s.0 == "read" && s.1 == settings)
        .map(|(i, _)| i)
        .collect();
    if edits.is_empty() || !steps.iter().any(|s| s.0 == "write" && s.1 == note) {
        return Some("the model did not edit the worktree settings and write its note");
    }
    if reads.is_empty() || reads[0] > edits[0] || reads.last() < edits.last() {
        return Some("the model did not read the worktree settings before and after editing");
    }
    None
}
pub(super) fn scratch(calls: &[Value], complete: bool) -> Option<&'static str> {
    let mut reads = Vec::new();
    let mut shells = Vec::new();
    for (index, call) in calls.iter().enumerate() {
        if call["name"] == "bash" {
            shells.push(index);
        }
        if call["name"] != "read" {
            continue;
        }
        let mut path = strip_selector(&write_path(&call["args"]));
        if path.starts_with("{{scratch}}\\") && !path.contains('/') {
            path = path.replace('\\', "/");
        }
        if path != "{{scratch}}/notes.md" {
            return Some("the model read a file outside the scratch checkout's note");
        }
        reads.push(index);
    }
    if !reads.is_empty() && (shells.is_empty() || reads[0] < shells[0]) {
        return Some("the model read the note before making the scratch checkout");
    }
    if complete && (reads.is_empty() || shells.is_empty()) {
        return Some("the model did not read the note after making the scratch checkout");
    }
    None
}
pub(super) fn session_edit(calls: &[Value], complete: bool) -> Option<&'static str> {
    let mut steps = Vec::new();
    for call in calls {
        let name = call["name"].as_str().unwrap_or("");
        if !matches!(name, "read" | "edit") {
            continue;
        }
        let path = if name == "edit" {
            native_inputs::edit_path(&call["args"])
        } else {
            native_inputs::path(&call["args"]).map(|p| strip_selector(&p))
        };
        if path.as_deref() != Some("{{home}}/other-project/src/report.ts") {
            return Some("the model used a file other than the checkout's report");
        }
        steps.push(name);
    }
    if !complete {
        return None;
    }
    let Some(index) = steps.iter().position(|s| *s == "edit") else {
        return Some("the model did not edit the checkout's report");
    };
    if !steps[..index].contains(&"read") || !steps[index..].contains(&"read") {
        return Some("the model did not read the report before and after editing it");
    }
    None
}
pub(super) fn job_selector(path: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^proc://([A-Za-z0-9_][A-Za-z0-9_.-]*)(?::[1-9][0-9]*-[1-9][0-9]*)?$")
            .expect("source job selector")
    })
    .captures(path)
    .map(|m| m[1].to_owned())
}
pub(super) fn background(
    calls: &[Value],
    complete: bool,
    generation: Generation,
) -> Option<&'static str> {
    static CURRENT: OnceLock<Regex> = OnceLock::new();
    static FROZEN: OnceLock<Regex> = OnceLock::new();
    static OUTPUT: OnceLock<Regex> = OnceLock::new();
    let start = if generation == Generation::Frozen128 {
        FROZEN.get_or_init(||Regex::new(r"(?i)(?:background\s+job|job[_\s]+id|process[_\s]+id)\s*[:=#]?\s*([A-Za-z0-9_]+(?:[.-][A-Za-z0-9_]+)*)").expect("frozen job label"))
    } else {
        CURRENT.get_or_init(||Regex::new(r"(?i)(?:background(?:ed)?(?:\s+as)?\s+job|job[_\s]+id|process[_\s]+id)\s*[:=#]?\s*([A-Za-z0-9_]+(?:[.-][A-Za-z0-9_]+)*)").expect("current job label"))
    };
    let output =
        OUTPUT.get_or_init(|| Regex::new(r"\b[0-9a-f]{40}\b").expect("source git object output"));
    let mut started = Vec::new();
    let mut reads = Vec::new();
    for (index, call) in calls.iter().enumerate() {
        if call["name"] == "bash" && call["args"]["async"] == true {
            started.push(index);
        } else if call["name"] == "read" {
            let Some(job) = job_selector(&write_path(&call["args"])) else {
                return Some("the model read something other than a background job's output");
            };
            if call["is_error"] != true {
                let names: Vec<_> = started
                    .iter()
                    .map(|i| outputs::text(&calls[*i]).unwrap_or_default())
                    .collect();
                let ids: BTreeSet<_> = names
                    .iter()
                    .flat_map(|name| start.captures_iter(name).map(|m| m[1].to_owned()))
                    .collect();
                if !ids.contains(&job) {
                    return Some("the model read a job it did not start here");
                }
                if !output.is_match(&outputs::text(call).unwrap_or_default()) {
                    return Some(
                        "the job output the model read back did not carry the command's result",
                    );
                }
            }
            reads.push(index);
        }
    }
    if !reads.is_empty() && (started.is_empty() || reads[0] < started[0]) {
        return Some("the model read the job output before starting the job");
    }
    if complete && (reads.is_empty() || started.is_empty()) {
        return Some("the model did not read the output of a background job it started");
    }
    None
}
