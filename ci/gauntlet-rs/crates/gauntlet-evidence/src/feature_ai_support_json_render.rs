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
