//! Pinned SDK JSON.stringify(value, null, 2) over canonical-wire JSON whose
//! numbers are exact JavaScript integers. Other numeric representations refuse.
use super::*;

struct DisplayJson(String);
fn index(key: &str) -> Option<u32> {
    let value = key.parse::<u32>().ok()?;
    (value < u32::MAX && value.to_string() == key).then_some(value)
}
impl DisplayJson {
    fn push(&mut self, text: &str) -> Result<()> {
        if self.0.len().saturating_add(text.len()) > 4 * 1024 * 1024 {
            return Err(invalid("SDK structured rendering bound exceeded"));
        }
        self.0.push_str(text);
        Ok(())
    }
    fn line(&mut self, depth: usize) -> Result<()> {
        self.push("\n")?;
        self.push(&"  ".repeat(depth))
    }
    fn string(&mut self, text: &str) -> Result<()> {
        let encoded =
            serde_json::to_string(text).map_err(|_| invalid("invalid SDK structured string"))?;
        self.push(&encoded)
    }
    fn value(&mut self, value: &Value, depth: usize) -> Result<()> {
        if depth > 64 {
            return Err(invalid("SDK structured render depth exceeded"));
        }
        match value {
            Value::Null => self.push("null"),
            Value::Bool(value) => self.push(if *value { "true" } else { "false" }),
            Value::String(value) => self.string(value),
            Value::Number(value) => {
                if let Some(value) = value
                    .as_i64()
                    .filter(|n| n.unsigned_abs() <= 9_007_199_254_740_991)
                {
                    self.push(&value.to_string())
                } else if let Some(value) = value.as_u64().filter(|n| *n <= 9_007_199_254_740_991) {
                    self.push(&value.to_string())
                } else {
                    Err(invalid(
                        "SDK structured numeric rendering is outside the exact profile",
                    ))
                }
            }
            Value::Array(values) => {
                self.push("[")?;
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        self.push(",")?;
                    }
                    self.line(depth + 1)?;
                    self.value(value, depth + 1)?;
                }
                if !values.is_empty() {
                    self.line(depth)?;
                }
                self.push("]")
            }
            Value::Object(values) => {
                let mut rows: Vec<_> = values.iter().collect();
                rows.sort_by(|(a, _), (b, _)| match (index(a), index(b)) {
                    (Some(a), Some(b)) => a.cmp(&b),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => a.cmp(b),
                });
                self.push("{")?;
                for (index, (key, value)) in rows.iter().enumerate() {
                    if index > 0 {
                        self.push(",")?;
                    }
                    self.line(depth + 1)?;
                    self.string(key)?;
                    self.push(": ")?;
                    self.value(value, depth + 1)?;
                }
                if !rows.is_empty() {
                    self.line(depth)?;
                }
                self.push("}")
            }
        }
    }
}
pub(super) fn pretty(value: &Value) -> Result<String> {
    let mut output = DisplayJson(String::new());
    output.value(value, 0)?;
    Ok(output.0)
}

/// SDK18.4.12 errors.ts SHAf8b24cad: the bounded ASCII JSON-RPC error
/// subset used by the fixed proxy. Redaction/trace/other data shapes refuse.
/// These fields describe an error; they never establish a policy verdict.
pub(super) fn rpc_error(
    response: &Value,
    wire: &str,
    family: &str,
    operation: &str,
) -> Result<Value> {
    let parsed = crate::native_diagnostic_artifacts::parse(wire.as_bytes())?;
    require(
        parsed == *response
            && wire.len() <= 1024 * 1024
            && (exact_keys(&response["error"], &["code", "message", "data"])
                || exact_keys(&response["error"], &["code", "message"])),
    )?;
    let error = &response["error"];
    require(error["code"] == -32001)?;
    let reason = error["message"]
        .as_str()
        .ok_or(invalid("MCP JSON-RPC error message missing"))?;
    require(
        !reason.is_empty()
            && reason.len() <= 800
            && reason.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
    )?;
    let message = format!("MCP error -32001: {reason}");
    static REDACTED: std::sync::OnceLock<Vec<regex::Regex>> = std::sync::OnceLock::new();
    let patterns = REDACTED.get_or_init(|| [
        r"(?i)\s*For more information, pass `verbose: true` in the second argument to fetch\(\)\.?\s*$",
        r"(?i)\b(Bearer|Basic)\s+[^\s,;]+",
        r"(?i)([?&](?:access[-_]?token|api[-_]?key|key|token|secret|password)=)[^&#\s]+",
        r"(?i)((?:authorization|api[-_]?key|private[-_]?key|access[-_]?key|token|secret|passw(?:or)?d|pwd|credential)\s*[:=]\s*)[^\s,;}]+",
    ].into_iter().map(|s|regex::Regex::new(s).unwrap()).collect());
    require(patterns.iter().all(|pattern| !pattern.is_match(&message)))?;
    let mut lines = vec![
        "MCP failure".to_owned(),
        format!("server: {family}"),
        format!("tool: {operation}"),
        "transport: stdio".into(),
        "stage: protocol".into(),
        "failure: json_rpc".into(),
        "retryable: no".into(),
        format!("message: {}", message.trim_end()),
        "code: -32001".into(),
    ];
    if let Some(data) = error.get("data") {
        let serialized = if data.is_null() {
            "null".into()
        } else {
            let withheld = data.get("transportOutcome").is_some();
            require(
                (exact_keys(data, &["approvalRequests", "guardPolicyAction"])
                    || exact_keys(
                        data,
                        &["approvalRequests", "guardPolicyAction", "transportOutcome"],
                    ) && withheld)
                    && data["approvalRequests"] == json!([])
                    && (!withheld
                        || data["transportOutcome"] == "not-forwarded"
                            && data["guardPolicyAction"] == "block")
                    && matches!(
                        data["guardPolicyAction"].as_str(),
                        Some("block" | "review" | "require-reapproval" | "sandbox-required")
                    ),
            )?;
            let action = data["guardPolicyAction"].as_str().unwrap();
            let (serialized, python) = if withheld {
                (
                    format!(
                        r#"{{"approvalRequests":[],"guardPolicyAction":"{action}","transportOutcome":"not-forwarded"}}"#
                    ),
                    format!(
                        r#"{{"approvalRequests": [], "guardPolicyAction": "{action}", "transportOutcome": "not-forwarded"}}"#
                    ),
                )
            } else {
                (
                    format!(r#"{{"approvalRequests":[],"guardPolicyAction":"{action}"}}"#),
                    format!(r#"{{"approvalRequests": [], "guardPolicyAction": "{action}"}}"#),
                )
            };
            // Python's fixed writer and canonical fixture dialect preserve the
            // same data key order. A different actual order stays unsupported.
            require(
                wire.contains(&format!(r#""data":{serialized}"#))
                    || wire.contains(&format!(r#""data": {python}"#)),
            )?;
            serialized
        };
        lines.push(format!("data: {serialized}"));
    }
    lines.push("next: Address the server-reported MCP error before retrying.".into());
    Ok(json!([{"type":"text","text":lines.join("\n")}]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn javascript_index_order_and_indent_are_preserved_for_canonical_input() {
        let value =
            json!({"10":"ten","2":"two","01":"one","a":[1,true,null,{"text":"quoted \" value\n"}]});
        assert_eq!(pretty(&value).unwrap(),"{\n  \"2\": \"two\",\n  \"10\": \"ten\",\n  \"01\": \"one\",\n  \"a\": [\n    1,\n    true,\n    null,\n    {\n      \"text\": \"quoted \\\" value\\n\"\n    }\n  ]\n}");
        assert_eq!(pretty(&json!({})).unwrap(), "{}");
        assert!(pretty(&json!({"amount":1.5})).is_err());
        assert!(pretty(&json!({"amount":9_007_199_254_740_992_u64})).is_err());
    }
}
