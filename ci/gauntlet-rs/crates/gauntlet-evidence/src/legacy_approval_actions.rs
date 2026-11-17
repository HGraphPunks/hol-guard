//! Pure shell word and approval-action comparison from the source oracle.
use super::*;

/// Python shlex.split(posix=True, comments=False), without evaluating any word.
pub(super) fn words(text: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                } else {
                    word.push(c);
                }
            }
            Some('"') => {
                if c == '"' {
                    quote = None;
                } else if c == '\\' {
                    let next = chars.next()?;
                    if next != '"' && next != '\\' {
                        word.push('\\');
                    }
                    word.push(next);
                } else {
                    word.push(c);
                }
            }
            Some(_) => unreachable!(),
            None => match c {
                ' ' | '\t' | '\r' | '\n' => {
                    if started {
                        result.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                '\'' | '"' => {
                    started = true;
                    quote = Some(c);
                }
                '\\' => {
                    started = true;
                    word.push(chars.next()?);
                }
                _ => {
                    started = true;
                    word.push(c);
                }
            },
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        result.push(word);
    }
    Some(result)
}

/// Python shlex.split(posix=False, comments=False, whitespace_split=True).
/// A quote only opens a quoted word at its start, and its closing quote ends
/// that word immediately. Backslashes and quotes inside an ordinary word are
/// literal; this does not evaluate Windows or POSIX commands.
fn windows_words(text: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(first) = chars.next() {
        if matches!(first, ' ' | '\t' | '\r' | '\n') {
            continue;
        }
        let mut word = String::from(first);
        if matches!(first, '\'' | '"') {
            loop {
                let next = chars.next()?;
                word.push(next);
                if next == first {
                    break;
                }
            }
        } else {
            while chars
                .peek()
                .is_some_and(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
            {
                word.push(chars.next().expect("peeked character"));
            }
        }
        result.push(word);
    }
    Some(result)
}

/// Exact harness_judge._tokens: only source-recognized Windows fixture roots
/// select non-POSIX splitting. Malformed quoting returns the whole trimmed
/// command before quote removal or fixture-path normalization.
pub(super) fn connector_words(command: &str) -> Vec<String> {
    let windows = ["{{workspace}}\\", "{{home}}\\", ".\\"]
        .iter()
        .any(|root| command.contains(root));
    let Some(tokens) = (if windows {
        windows_words(command)
    } else {
        words(command)
    }) else {
        return vec![command.trim().into()];
    };
    tokens
        .iter()
        .map(|token| {
            relative(if windows {
                token.trim_matches(['"', '\''])
            } else {
                token
            })
        })
        .collect()
}

/// Exact codex_contained.shell_script envelope projection, without execution.
pub(super) fn shell_script(command: &str) -> &str {
    static SHELL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SHELL
        .get_or_init(|| {
            regex::Regex::new(
                r#"(?is)\A"[^"]*\\(?:pwsh|powershell|bash)\.exe" (?:-Command|-lc|-c) "(.*)"\z"#,
            )
            .expect("source Windows shell envelope")
        })
        .captures(command)
        .and_then(|capture| capture.get(1))
        .map_or(command, |inner| inner.as_str())
}

pub(super) fn relative(value: &str) -> String {
    let normalized = if ["{{workspace}}\\", "{{home}}\\", ".\\"]
        .iter()
        .any(|p| value.starts_with(p))
    {
        value.replace('\\', "/")
    } else {
        value.to_owned()
    };
    let normalized = normalized
        .strip_prefix("{{workspace}}/")
        .unwrap_or(&normalized);
    normalized
        .strip_prefix("./")
        .unwrap_or(normalized)
        .to_owned()
}
pub(super) fn input_path(fields: &Value) -> Value {
    ["file_path", "path", "filePath"]
        .iter()
        .find_map(|key| fields[*key].as_str().filter(|s| !s.trim().is_empty()))
        .map_or(Value::Null, |s| json!(s))
}
fn file(tool: &Value, path: &Value) -> Vec<String> {
    let name = tool.as_str().unwrap_or("").trim().to_lowercase();
    let Some(path) = path.as_str().filter(|s| !s.trim().is_empty()) else {
        return Vec::new();
    };
    if !matches!(name.as_str(), "read" | "write" | "edit") {
        return Vec::new();
    }
    vec!["file".into(), name, relative(path.trim())]
}
fn shell(command: &str) -> Vec<String> {
    let words =
        words(command).unwrap_or_else(|| command.split_whitespace().map(str::to_owned).collect());
    let Some(program) = words.first() else {
        return Vec::new();
    };
    let mut rest = words.iter().skip(1);
    while let Some(word) = rest.next() {
        if [
            "-C",
            "-c",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--exec-path",
        ]
        .contains(&word.as_str())
        {
            rest.next();
            continue;
        }
        if word.starts_with(['-', '/', '.', '~']) || word.contains(['/', '.']) {
            continue;
        }
        return vec![program.clone(), word.clone()];
    }
    vec![program.clone()]
}
pub(super) fn decision(row: &Value) -> Vec<String> {
    if let Some(command) = row["command"].as_str().filter(|s| !s.trim().is_empty()) {
        shell(command)
    } else {
        file(&row["tool"], &row["path"])
    }
}
pub(super) fn grant(row: &Value) -> Vec<String> {
    let found = file(&row["tool"], &row["target"]);
    if !found.is_empty() {
        found
    } else {
        shell(row["target"].as_str().unwrap_or(""))
    }
}
pub(super) fn review(reason: &Value) -> bool {
    reason.as_str().is_some_and(|s| {
        s != "native_review_user_block" && (s.contains("review") || s.contains("reapproval"))
    })
}
pub(super) fn display(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}
