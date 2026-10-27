//! Keep Python's data insertion order for search without enabling a workspace-wide
//! serde_json feature. Hashes always use the existing strict canonical codec.
use crate::{Error, Result};
use guard_runtime_pyjson::{float_repr, parse_unique, PyVal};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write;

pub(crate) fn parse(raw: &str) -> Result<Value> {
    let canonical = gauntlet_contracts::canonicalize(raw.as_bytes())
        .map_err(|e| Error::Invalid(e.to_string()))?;
    serde_json::from_slice(&canonical).map_err(|e| Error::Invalid(e.to_string()))
}

pub(crate) fn ordered(raw: &str) -> Result<PyVal> {
    parse(raw)?;
    parse_unique(raw).map_err(|_| Error::invalid("invalid ordered JSON"))
}

pub(crate) fn canonical(value: &Value) -> Result<Vec<u8>> {
    gauntlet_contracts::canonicalize(value.to_string().as_bytes())
        .map_err(|e| Error::Invalid(e.to_string()))
}

pub(crate) fn digest(value: &Value) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(canonical(value)?)))
}

pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| Error::invalid("missing or invalid text field"))
}

pub(crate) fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(v) => *v,
        Value::String(v) => !v.is_empty(),
        Value::Array(v) => !v.is_empty(),
        Value::Object(v) => !v.is_empty(),
        Value::Number(v) => v.as_f64().is_some_and(|v| v != 0.0),
    }
}

pub(crate) fn set(data: &mut PyVal, key: &str, value: PyVal) -> Result<()> {
    let PyVal::Dict(entries) = data else {
        return Err(Error::invalid("data must be an object"));
    };
    if let Some((_, old)) = entries.iter_mut().find(|(name, _)| name == key) {
        *old = value;
    } else {
        entries.push((key.to_owned(), value));
    }
    Ok(())
}

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\u{20}'..='\u{7e}' => out.push(c),
            other => {
                let mut units = [0; 2];
                for unit in other.encode_utf16(&mut units) {
                    write!(out, "\\u{unit:04x}").expect("String write");
                }
            }
        }
    }
    out.push('"');
    out
}

/// CPython json.dumps defaults: ASCII escapes, original object order and spaces.
pub(crate) fn python_text(value: &PyVal) -> String {
    match value {
        PyVal::Null => "null".into(),
        PyVal::Bool(v) => v.to_string(),
        PyVal::Int(v) => v.clone(),
        PyVal::Float(v) => float_repr(*v),
        PyVal::Str(v) => quote(v),
        PyVal::List(v) => format!(
            "[{}]",
            v.iter().map(python_text).collect::<Vec<_>>().join(", ")
        ),
        PyVal::Dict(v) => format!(
            "{{{}}}",
            v.iter()
                .map(|(k, v)| format!("{}: {}", quote(k), python_text(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub(crate) fn value(data: &PyVal) -> Result<Value> {
    parse(&python_text(data))
}

pub(crate) fn record_text(record: &Value, data: &PyVal) -> Result<String> {
    let object = record
        .as_object()
        .ok_or_else(|| Error::invalid("record must be an object"))?;
    let rows: Vec<_> = object
        .iter()
        .map(|(key, value)| {
            let raw = if key == "data" {
                python_text(data)
            } else {
                value.to_string()
            };
            format!(
                "{}:{raw}",
                serde_json::to_string(key).expect("string serializes")
            )
        })
        .collect();
    Ok(format!("{{{}}}", rows.join(",")))
}
