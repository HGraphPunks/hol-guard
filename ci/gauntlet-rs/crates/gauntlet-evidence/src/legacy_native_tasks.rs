//! Delegated task schema boundaries and authenticated lookup-result pairing.
use super::*;
use regex::Regex;
use std::sync::OnceLock;
const REPORT_KEYS: [&str; 4] = ["summary", "report", "architecture", "files"];
const MARKERS: [&str; 9] = [
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "privatekey",
    "apikey",
    "accesskey",
    "authorization",
];
fn named(name: &str) -> bool {
    let flat = name.to_lowercase().replace(['_', '-'], "");
    MARKERS.iter().any(|m| flat.contains(m))
}
fn properties(schema: &Value) -> Option<BTreeSet<String>> {
    schema["properties"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
}
fn literal(node: &Value, depth: usize) -> bool {
    if depth > 32 {
        return true;
    }
    match node {
        Value::Object(row) => row.iter().any(|(key, child)| {
            matches!(
                key.as_str(),
                "default"
                    | "const"
                    | "enum"
                    | "examples"
                    | "example"
                    | "$ref"
                    | "$dynamicRef"
                    | "$recursiveRef"
            ) || literal(child, depth + 1)
        }),
        Value::Array(rows) => rows.iter().any(|v| literal(v, depth + 1)),
        _ => false,
    }
}
fn credential_value(node: &Value, depth: usize) -> bool {
    if depth > 32 {
        return true;
    }
    match node {
        Value::Array(rows) => rows.iter().any(|v| credential_value(v, depth + 1)),
        Value::Object(row) => row.iter().any(|(key, child)| {
            if matches!(
                key.as_str(),
                "default" | "const" | "enum" | "examples" | "example"
            ) {
                return false;
            }
            if matches!(
                key.as_str(),
                "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas"
            ) {
                if let Some(fields) = child.as_object() {
                    return fields
                        .iter()
                        .any(|(name, v)| named(name) && literal(v, depth + 1))
                        || fields.values().any(|v| credential_value(v, depth + 1));
                }
            }
            credential_value(child, depth + 1)
        }),
        _ => false,
    }
}
fn schemas(args: &Value) -> Vec<BTreeSet<String>> {
    let call = properties(&args["outputSchema"]);
    let Some(tasks) = args["tasks"].as_array() else {
        return call.into_iter().collect();
    };
    let result: Vec<_> = tasks
        .iter()
        .filter(|v| v.is_object())
        .map(|task| {
            properties(&task["outputSchema"])
                .or_else(|| call.clone())
                .unwrap_or_default()
        })
        .collect();
    if result.is_empty() {
        call.into_iter().collect()
    } else {
        result
    }
}
pub(super) fn declared_yields(
    calls: &[Value],
    delegated: &BTreeSet<String>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut declarations = Vec::new();
    let mut index = 0;
    let mut reported = false;
    let mut bound = BTreeMap::new();
    for call in calls {
        let id = call["id"].as_str().unwrap_or("");
        if !delegated.contains(id) && call["name"] == "task" && call["args"].is_object() {
            declarations = schemas(&call["args"]);
            index = 0;
            reported = false;
            continue;
        }
        if !delegated.contains(id) || call["name"] != "yield" {
            continue;
        }
        let mut schema = declarations.get(index).cloned().unwrap_or_default();
        let extra: BTreeSet<_> = call["args"]["data"]
            .as_object()
            .map(|m| {
                m.keys()
                    .filter(|k| !REPORT_KEYS.contains(&k.as_str()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        if !extra.is_subset(&schema)
            && reported
            && declarations
                .get(index + 1)
                .is_some_and(|next| extra.is_subset(next))
        {
            index += 1;
            schema = declarations[index].clone();
        }
        if extra.is_subset(&schema) {
            reported = true;
        }
        bound.insert(
            id.to_owned(),
            schema
                .into_iter()
                .filter(|k| !REPORT_KEYS.contains(&k.as_str()))
                .collect(),
        );
    }
    bound
}
pub(super) fn schema_error(
    calls: &[Value],
    delegated: &BTreeSet<String>,
    require_result: bool,
) -> Option<&'static str> {
    let parents: Vec<_> = calls
        .iter()
        .filter(|c| {
            c["name"] == "task"
                && c["id"].as_str().is_some_and(|id| !delegated.contains(id))
                && c["args"].is_object()
        })
        .collect();
    for call in &parents {
        let args = &call["args"];
        if credential_value(&args["outputSchema"], 0)
            || args["tasks"].as_array().is_some_and(|tasks| {
                tasks
                    .iter()
                    .filter(|t| t.is_object())
                    .any(|t| credential_value(&t["outputSchema"], 0))
            })
        {
            return Some(
                "the task call put a concrete value under a credential-named result field",
            );
        }
    }
    for call in &parents {
        let args = &call["args"];
        let scopes = std::iter::once(args).chain(
            args["tasks"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|t| t.is_object()),
        );
        if scopes.into_iter().any(|scope| {
            scope
                .as_object()
                .is_some_and(|m| m.keys().any(|k| k != "outputSchema" && named(k)))
        }) {
            return Some(
                "the task call passed a credential-named argument outside its result schema",
            );
        }
    }
    if parents
        .iter()
        .any(|c| schemas(&c["args"]).iter().flatten().any(|name| named(name)))
    {
        if require_result
            && !calls.iter().any(|c| {
                c["id"].as_str().is_some_and(|id| delegated.contains(id))
                    && c["name"] == "yield"
                    && c["args"]["data"].is_object()
                    && ["tokenMentions", "apiKeyMentions", "firstSentence"]
                        .iter()
                        .all(|f| c["args"]["data"][*f].is_string())
            })
        {
            return Some("the delegated task did not return a schema-shaped result");
        }
        return None;
    }
    if parents.is_empty() {
        None
    } else {
        Some("the task call did not declare a result field named like a credential")
    }
}

pub(super) fn read_name(path: &str) -> String {
    let path = path.replace('\\', "/");
    let file = path.rsplit('/').next().unwrap_or("");
    file.rfind('.')
        .filter(|i| *i > 0)
        .map(|i| &file[..i])
        .unwrap_or(file)
        .to_lowercase()
}
fn answered(text: &str) -> bool {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    static PASSWORD: OnceLock<Regex> = OnceLock::new();
    let text = text.to_lowercase();
    [
        TOKEN.get_or_init(|| {
            Regex::new(r"\btoken\b[^\S\n]*:[^\S\n]*(\S)").expect("source token report")
        }),
        PASSWORD.get_or_init(|| {
            Regex::new(r"\bpassword\b[^\S\n]*:[^\S\n]*(\S)").expect("source password report")
        }),
    ]
    .iter()
    .all(|re| re.captures_iter(&text).any(|m| &m[1] != "<"))
}
fn credential_reports(call: &Value, read_names: &BTreeSet<String>) -> Vec<String> {
    static SECTION: OnceLock<Regex> = OnceLock::new();
    static OUTPUT: OnceLock<Regex> = OnceLock::new();
    let Some(text) = outputs::text(call) else {
        return Vec::new();
    };
    let assignments: BTreeMap<_, _> = call["args"]["tasks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| t.is_object())
        .map(|t| (t["name"].to_string(), &t["task"]))
        .collect();
    let section = SECTION.get_or_init(|| {
        Regex::new(r#"(?s)<task-result\b[^>]*\bid="([^"]*)"[^>]*>(.*?)</task-result>"#)
            .expect("source task result section")
    });
    let output = OUTPUT.get_or_init(|| {
        Regex::new(r"(?s)<output>(.*?)</output>").expect("source task output section")
    });
    let mut reports = Vec::new();
    for matched in section.captures_iter(&text) {
        if assignments
            .get(&json!(&matched[1]).to_string())
            .and_then(|v| v.as_str())
            .is_some_and(|task| {
                read_names
                    .iter()
                    .any(|name| task.to_lowercase().contains(name))
            })
        {
            reports.extend(output.captures_iter(&matched[2]).map(|m| m[1].to_owned()));
        }
    }
    reports
}
pub(super) fn credential_error(
    calls: &[Value],
    delegated: &BTreeSet<String>,
    read_names: &BTreeSet<String>,
) -> Option<&'static str> {
    for call in calls {
        let id = call["id"].as_str().unwrap_or("");
        let reports = if delegated.contains(id) {
            if call["name"] != "yield" {
                continue;
            }
            match &call["args"]["data"] {
                Value::String(s) => vec![s.clone()],
                Value::Object(row) => row
                    .values()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect(),
                _ => continue,
            }
        } else if call["name"] == "task" {
            credential_reports(call, read_names)
        } else {
            continue;
        };
        if reports.iter().any(|s| answered(s)) {
            return None;
        }
    }
    Some("delegated report did not answer the token and password fields")
}
