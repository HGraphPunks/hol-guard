//! Rust decodes the bounded numerical token tape and constructs OpenAI replies.
use super::{bytes, exact, num, text, MODEL};
use serde_json::{json, Value};

pub(super) struct Tape {
    pub tokens: Vec<Value>,
    context: bool,
    terminal: bool,
    pub output: u64,
    pub limit: u64,
}
impl Tape {
    pub fn new(limit: u64) -> Self {
        Self {
            tokens: Vec::new(),
            context: false,
            terminal: false,
            output: 0,
            limit,
        }
    }
    pub fn accept(&mut self, v: Value, prepared: &str, prompt: u64) -> Result<bool, String> {
        match v["schema"].as_str().unwrap_or("") {
            "hol-gauntlet-mlx-numerical-context.v1" => {
                if self.context
                    || !self.tokens.is_empty()
                    || !exact(&v, &["schema", "prepared_input_sha256", "prompt_tokens"])
                    || v["prepared_input_sha256"] != prepared
                    || v["prompt_tokens"] != prompt
                {
                    return Err("numerical context differs from reservation".into());
                }
                self.context = true;
            }
            "hol-gauntlet-mlx-numerical-token.v1" => {
                if !self.context
                    || self.terminal
                    || !exact(
                        &v,
                        &[
                            "schema",
                            "token",
                            "text",
                            "state",
                            "matched_tokens",
                            "finish_reason",
                        ],
                    )
                    || num(&v, "token")? > u32::MAX as u64
                    || text(&v, "text")?.len() > 65536
                    || !(v["state"].is_null()
                        || matches!(v["state"].as_str(), Some("normal" | "reasoning" | "tool")))
                    || !(v["finish_reason"].is_null()
                        || matches!(v["finish_reason"].as_str(), Some("stop" | "length")))
                    || self.output >= self.limit
                {
                    return Err("numerical token stream invalid or exceeds reservation".into());
                }
                self.output += 1;
                self.terminal = !v["finish_reason"].is_null();
                self.tokens.push(v);
                let matched = num(
                    self.tokens.last().ok_or("numerical token absent")?,
                    "matched_tokens",
                )? as usize;
                if matched > 128 || matched > self.tokens.len() {
                    return Err("numerical control match invalid".into());
                }
                if self
                    .tokens
                    .iter()
                    .map(|t| t["text"].as_str().map_or(0, str::len))
                    .sum::<usize>()
                    > 2 * 1024 * 1024
                {
                    return Err("numerical response text exceeds bound".into());
                }
            }
            "hol-gauntlet-mlx-numerical-complete.v1" => {
                if !self.context
                    || !self.terminal
                    || !exact(
                        &v,
                        &[
                            "schema",
                            "prepared_input_sha256",
                            "prompt_tokens",
                            "output_tokens",
                        ],
                    )
                    || v["prepared_input_sha256"] != prepared
                    || v["prompt_tokens"] != prompt
                    || v["output_tokens"] != self.output
                {
                    return Err("complete numerical usage unavailable".into());
                }
                return Ok(true);
            }
            _ => return Err("unknown numerical output frame".into()),
        }
        Ok(false)
    }
    pub fn response(
        &self,
        prompt: u64,
        request_id: &str,
        tools: Option<&Value>,
    ) -> Result<Vec<u8>, String> {
        let mut content = String::new();
        let mut reasoning = String::new();
        let mut tool_text = String::new();
        let mut calls = Vec::new();
        let mut previous = "";
        let mut finish = "stop";
        let mut decoded = self.tokens.clone();
        for index in 0..decoded.len() {
            let matched = num(&decoded[index], "matched_tokens")? as usize;
            if matched > 0 {
                for token in &mut decoded[index + 1 - matched..=index] {
                    token["text"] = json!("");
                }
            }
        }
        for token in &decoded {
            let state = token["state"].as_str().unwrap_or("");
            if previous == "tool" && state != "tool" && !tool_text.is_empty() {
                append_call(&mut calls, &mut content, &tool_text, tools, request_id)?;
                tool_text.clear();
            }
            match state {
                "tool" => tool_text.push_str(text(token, "text")?),
                "reasoning" => reasoning.push_str(text(token, "text")?),
                "normal" => content.push_str(text(token, "text")?),
                _ => {}
            }
            if let Some(reason) = token["finish_reason"].as_str() {
                finish = reason;
            }
            previous = state;
        }
        if !tool_text.is_empty() {
            append_call(&mut calls, &mut content, &tool_text, tools, request_id)?;
        }
        if finish == "stop" && !calls.is_empty() {
            finish = "tool_calls";
        }
        let mut message = json!({"role":"assistant","content":content});
        if !reasoning.is_empty() {
            message["reasoning"] = json!(reasoning);
        }
        if !calls.is_empty() {
            message["tool_calls"] = json!(calls);
        }
        let result = bytes(
            &json!({"id":format!("chatcmpl-{request_id}"),"object":"chat.completion","created":0,"model":MODEL,"choices":[{"index":0,"message":message,"finish_reason":finish}],"usage":{"prompt_tokens":prompt,"completion_tokens":self.output,"total_tokens":prompt+self.output}}),
        )?;
        if result.len() > 4 * 1024 * 1024 {
            return Err("OpenAI response exceeds bound".into());
        }
        Ok(result)
    }
}
fn append_call(
    calls: &mut Vec<Value>,
    content: &mut String,
    raw: &str,
    tools: Option<&Value>,
    id: &str,
) -> Result<(), String> {
    // Malformed generated tool syntax remains observable model text. It does
    // not make exact producer-side usage unknown or invent a successful call.
    let parsed = parse_call(raw, tools);
    let Ok((name, args)) = parsed else {
        content.push_str(raw);
        return Ok(());
    };
    if calls.len() >= 128 {
        return Err("model tool-call count exceeds bound".into());
    }
    calls.push(json!({"id":format!("call-{id}-{}",calls.len()),"type":"function","function":{"name":name,"arguments":String::from_utf8(bytes(&args)?).map_err(|_|"tool arguments invalid")?}}));
    Ok(())
}
fn parse_call(raw: &str, tools: Option<&Value>) -> Result<(String, Value), String> {
    let raw = raw.trim();
    if raw.starts_with('{') {
        let value = super::parse(raw.as_bytes())?;
        if !exact(&value, &["name", "arguments"]) || !value["arguments"].is_object() {
            return Err("tool JSON shape invalid".into());
        }
        return Ok((text(&value, "name")?.into(), value["arguments"].clone()));
    }
    let raw = raw
        .strip_prefix("<function=")
        .and_then(|s| s.strip_suffix("</function>"))
        .ok_or("Qwen tool syntax invalid")?;
    let (name, mut rest) = raw.split_once('>').ok_or("Qwen function name absent")?;
    if name.is_empty()
        || name.len() > 256
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err("Qwen function name invalid".into());
    }
    let properties = tools
        .and_then(Value::as_array)
        .and_then(|tools| tools.iter().find(|t| t["function"]["name"] == name))
        .map(|tool| &tool["function"]["parameters"]["properties"]);
    let mut args = serde_json::Map::new();
    while !rest.trim().is_empty() {
        let tail = rest
            .trim_start()
            .strip_prefix("<parameter=")
            .ok_or("Qwen parameter syntax invalid")?;
        let (param, tail) = tail.split_once('>').ok_or("Qwen parameter name absent")?;
        let (value, tail) = tail
            .split_once("</parameter>")
            .ok_or("Qwen parameter end absent")?;
        if param.is_empty() || args.len() >= 128 || args.contains_key(param) {
            return Err("Qwen parameter duplicate or exceeds bound".into());
        }
        let value = value.strip_prefix('\n').unwrap_or(value);
        let value = value.strip_suffix('\n').unwrap_or(value);
        let kind = properties
            .and_then(|p| p.get(param))
            .and_then(|p| p["type"].as_str())
            .unwrap_or("string");
        let converted = if value.eq_ignore_ascii_case("null") {
            Value::Null
        } else {
            match kind {
                "string" => json!(value),
                "boolean" => match value.to_ascii_lowercase().as_str() {
                    "true" => json!(true),
                    "false" => json!(false),
                    _ => return Err("Qwen boolean invalid".into()),
                },
                "integer" | "number" | "object" | "array" => super::parse(value.as_bytes())?,
                _ => json!(value),
            }
        };
        args.insert(param.into(), converted);
        rest = tail;
    }
    Ok((name.into(), Value::Object(args)))
}
