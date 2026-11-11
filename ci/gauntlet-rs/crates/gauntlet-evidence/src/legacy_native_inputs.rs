//! Shared file-tool input identity, task scope and mixed-read business rules.
use super::*;
use regex::Regex;
use std::sync::OnceLock;

fn fixture_path(value: &str) -> String {
    let value = if let Some(rest) = value.strip_prefix("~/") {
        format!("{{{{home}}}}/{rest}")
    } else {
        value.to_owned()
    };
    value
        .strip_prefix("{{workspace}}/")
        .unwrap_or(&value)
        .strip_prefix("./")
        .unwrap_or(value.strip_prefix("{{workspace}}/").unwrap_or(&value))
        .to_owned()
}
pub(super) fn path(args: &Value) -> Option<String> {
    if args.get("path").is_some()
        && args.get("file_path").is_some()
        && args["path"] != args["file_path"]
    {
        return None;
    }
    args.get("path")
        .or_else(|| args.get("file_path"))
        .and_then(Value::as_str)
        .map(fixture_path)
}
fn headers(patch: &str) -> Vec<String> {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN
        .get_or_init(|| {
            Regex::new(r"(?m)^\[([^\n]+)#[0-9A-Fa-f]{4}\]$").expect("source edit anchor pattern")
        })
        .captures_iter(patch)
        .map(|m| m[1].trim_matches([' ', '\t']).to_owned())
        .collect()
}
pub(super) fn edit_path(args: &Value) -> Option<String> {
    if args.get("input").is_none() {
        return path(args);
    }
    let headers = headers(args["input"].as_str()?);
    if headers.len() != 1 || headers[0].is_empty() {
        return None;
    }
    let header = fixture_path(&headers[0]);
    let explicit = path(args);
    if (args.get("path").is_some() || args.get("file_path").is_some()) && explicit.is_none() {
        return None;
    }
    if explicit.as_ref().is_some_and(|p| p != &header) {
        return None;
    }
    Some(header)
}
pub(super) fn input_matches(tool: &Value, executed: &Value, reviewed: &Value) -> bool {
    let expected = input(executed);
    let actual = input(reviewed);
    if expected == actual {
        return true;
    }
    if tool != "edit" {
        return false;
    }
    let mut target = expected
        .get("path")
        .or_else(|| expected.get("file_path"))
        .cloned()
        .unwrap_or(Value::Null);
    if let Some(patch) = expected["input"].as_str() {
        let headers = headers(patch);
        if headers.len() != 1 || (!target.is_null() && target != headers[0]) {
            return false;
        }
        target = json!(headers[0]);
    }
    if target.as_str().is_none_or(str::is_empty) {
        return false;
    }
    let mut enriched = expected.clone();
    enriched["path"] = target.clone();
    enriched["paths"] = json!([target]);
    if ["path", "paths"]
        .iter()
        .any(|key| expected.get(*key).is_some_and(|v| v != &enriched[*key]))
    {
        return false;
    }
    actual == enriched
}

pub(super) fn post_matches(
    tool: &Value,
    reviewed: &Value,
    completed: &Value,
    result: &Value,
) -> bool {
    if reviewed == completed {
        return true;
    }
    if tool != "read"
        || reviewed
            .as_object()
            .map(|m| m.keys().collect::<BTreeSet<_>>())
            != completed.as_object().map(|m| m.keys().collect())
    {
        return false;
    }
    let keys: Vec<_> = ["path", "file_path"]
        .into_iter()
        .filter(|key| reviewed.get(*key).is_some())
        .collect();
    if keys.len() != 1 {
        return false;
    }
    let key = keys[0];
    let Some((mut original, resolved)) = reviewed[key].as_str().zip(completed[key].as_str()) else {
        return false;
    };
    static SELECTOR: OnceLock<Regex> = OnceLock::new();
    if let Some(selector) = SELECTOR
        .get_or_init(|| {
            Regex::new(r"^(.+):(?:([1-9][0-9]*)(?:-([1-9][0-9]*))?|raw)$")
                .expect("source selector pattern")
        })
        .captures(original)
    {
        let first = selector
            .get(2)
            .map(|m| m.as_str())
            .unwrap_or("1")
            .parse::<u64>()
            .ok();
        if first.is_none()
            || selector.get(3).is_some_and(|last| {
                last.as_str()
                    .parse::<u64>()
                    .ok()
                    .is_none_or(|last| last < first.unwrap_or(0))
            })
        {
            return false;
        }
        if result["details"]["meta"]["source"] != json!({"type":"path","value":resolved})
            || result["details"]["displayContent"]["startLine"].as_u64() != first
        {
            return false;
        }
        original = selector.get(1).expect("base capture").as_str();
    }
    let resolved = if resolved.starts_with("{{workspace}}\\") || resolved.starts_with("{{home}}\\")
    {
        if !resolved.contains('/') {
            if original.contains('\\') {
                return false;
            }
            resolved.replace('\\', "/")
        } else {
            resolved.to_owned()
        }
    } else {
        resolved.to_owned()
    };
    let expected = if let Some(rest) = original.strip_prefix("~/") {
        format!("{{{{home}}}}/{rest}")
    } else if original.starts_with('/') || original.starts_with("{{") {
        original.to_owned()
    } else {
        format!(
            "{{{{workspace}}}}/{}",
            original.strip_prefix("./").unwrap_or(original)
        )
    };
    !expected
        .split('/')
        .skip(1)
        .any(|part| matches!(part, "." | ".." | ""))
        && resolved == expected
        && reviewed.as_object().is_some_and(|m| {
            m.iter()
                .all(|(other, value)| other == key || completed.get(other) == Some(value))
        })
}

pub(super) fn task_scope(scenario: &Value, calls: &[Value]) -> bool {
    let oracle = scenario["oracle"].as_str().unwrap_or("");
    if oracle == "home-copy-task" {
        return calls.iter().all(|call| {
            (call["name"] == "bash" && call["args"]["command"] == scenario["commands"][0])
                || call["name"] == "read"
                    && path(&call["args"]).as_deref() == Some("{{home}}/other-project/copied.ts")
        });
    }
    if !matches!(oracle, "settings-task" | "home-task") {
        return true;
    }
    let target = if oracle == "settings-task" {
        "src/settings.ts"
    } else {
        "{{home}}/other-project/notes.md"
    };
    for call in calls {
        match call["name"].as_str() {
            Some("read") => {
                if !path(&call["args"]).is_some_and(|p| {
                    if oracle == "settings-task" {
                        ["README.md", "src/settings.ts", "docs/change.md"].contains(&p.as_str())
                    } else {
                        p == target
                    }
                }) {
                    return false;
                }
            }
            Some("edit") => {
                if edit_path(&call["args"]).as_deref() != Some(target) {
                    return false;
                }
            }
            Some("write") => {
                if path(&call["args"]).as_deref()
                    != Some(if oracle == "settings-task" {
                        "docs/change.md"
                    } else {
                        target
                    })
                {
                    return false;
                }
            }
            Some("bash")
                if oracle == "settings-task" && call["args"]["command"] == "git status --short" => {
            }
            _ => return false,
        }
    }
    true
}

pub(super) fn task_tools(scenario: &Value, calls: &[Value]) -> bool {
    let oracle = scenario["oracle"].as_str().unwrap_or("");
    if oracle == "home-copy-task" {
        return calls.len() == 2
            && calls[0]["name"] == "bash"
            && calls[0]["args"]["command"] == scenario["commands"][0]
            && calls[1]["name"] == "read"
            && path(&calls[1]["args"]).as_deref() == Some("{{home}}/other-project/copied.ts");
    }
    if scenario["id"] == "developer-settings-task" {
        let expected = [
            ("read", "README.md"),
            ("read", "src/settings.ts"),
            ("edit", "src/settings.ts"),
            ("write", "docs/change.md"),
            ("read", "src/settings.ts"),
            ("read", "docs/change.md"),
            ("bash", "git status --short"),
        ];
        return calls.len() == expected.len()
            && calls.iter().zip(expected).all(|(call, (name, target))| {
                call["name"] == name
                    && match name {
                        "read" => path(&call["args"]).as_deref() == Some(target),
                        "edit" => edit_path(&call["args"]).as_deref() == Some(target),
                        "write" => {
                            path(&call["args"]).as_deref() == Some(target)
                                && call["args"]["content"] == "Retry limit increased from 3 to 5.\n"
                        }
                        _ => call["args"]["command"] == target,
                    }
            });
    }
    if !matches!(oracle, "settings-task" | "home-task") {
        return true;
    }
    let target = if oracle == "settings-task" {
        "src/settings.ts"
    } else {
        "{{home}}/other-project/notes.md"
    };
    let mut reads: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut edits = Vec::new();
    let mut writes = Vec::new();
    for (index, call) in calls.iter().enumerate() {
        let path = if call["name"] == "edit" {
            edit_path(&call["args"])
        } else {
            path(&call["args"])
        };
        if call["name"] == "read" && path.as_ref().is_some_and(|p| !p.is_empty()) {
            reads
                .entry(path.expect("path present"))
                .or_default()
                .push(index);
        } else if call["name"] == "edit" && path.as_deref() == Some(target) {
            edits.push(index);
        } else if call["name"] == "write" {
            if path.as_deref()
                != Some(if oracle == "settings-task" {
                    "docs/change.md"
                } else {
                    target
                })
                || call["args"]["content"]
                    != if oracle == "settings-task" {
                        "Retry limit increased from 3 to 5.\n"
                    } else {
                        "Reviewed settings change.\n"
                    }
            {
                return false;
            }
            writes.push(index);
        } else if !(call["name"] == "bash"
            && oracle == "settings-task"
            && call["args"]["command"] == "git status --short")
        {
            return false;
        }
    }
    if edits.len() != 1 || writes.len() != 1 {
        return false;
    }
    let Some(target_reads) = reads.get(target) else {
        return false;
    };
    if !target_reads.iter().any(|i| *i < edits[0]) || !target_reads.iter().any(|i| *i > edits[0]) {
        return false;
    }
    if oracle == "home-task" {
        return target_reads
            .first()
            .is_some_and(|read| writes[0] < *read && *read < edits[0]);
    }
    reads.contains_key("README.md")
        && reads
            .get("docs/change.md")
            .is_some_and(|indices| indices.iter().any(|i| *i > writes[0]))
}
