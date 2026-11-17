use crate::{
    catalog::Catalog, Family, Operations, TransportError, LATEST_PROTOCOL_VERSION, MAX_FRAME_BYTES,
    MAX_SESSION_BYTES, MAX_SESSION_MESSAGES, SUPPORTED_PROTOCOL_VERSIONS,
};
use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    New,
    Negotiated,
    Ready,
    Closed,
}

pub struct Session {
    family: Family,
    catalog: Catalog,
    state: State,
    bytes: usize,
    messages: usize,
}
impl Session {
    pub fn new(family: Family) -> Result<Self, TransportError> {
        Ok(Self {
            family,
            catalog: Catalog::load(family)?,
            state: State::New,
            bytes: 0,
            messages: 0,
        })
    }
    pub fn close(&mut self) {
        self.state = State::Closed;
    }
    /// One complete NDJSON payload, excluding the transport's newline. No key,
    /// process claim or producer pass flag can grant protocol/backend authority.
    pub fn process(
        &mut self,
        raw: &[u8],
        operations: &mut impl Operations,
    ) -> Result<Option<Value>, TransportError> {
        if self.state == State::Closed {
            return Err(TransportError::Closed);
        }
        let result = self.process_inner(raw, operations);
        if result.is_err() {
            self.state = State::Closed;
        }
        result
    }
    fn process_inner(
        &mut self,
        raw: &[u8],
        operations: &mut impl Operations,
    ) -> Result<Option<Value>, TransportError> {
        if raw.is_empty() || raw.len() > MAX_FRAME_BYTES {
            return Err(TransportError::FrameBound);
        }
        self.messages = self
            .messages
            .checked_add(1)
            .ok_or(TransportError::SessionBound)?;
        self.bytes = self
            .bytes
            .checked_add(raw.len())
            .ok_or(TransportError::SessionBound)?;
        if self.messages > MAX_SESSION_MESSAGES || self.bytes > MAX_SESSION_BYTES {
            return Err(TransportError::SessionBound);
        }
        let canonical =
            gauntlet_contracts::canonicalize(raw).map_err(|_| TransportError::Malformed)?;
        let frame: Value =
            serde_json::from_slice(&canonical).map_err(|_| TransportError::Malformed)?;
        if !frame.is_object()
            || frame["jsonrpc"] != "2.0"
            || !frame["method"].is_string()
            || frame
                .get("params")
                .is_some_and(|p| !p.is_object() && !p.is_null())
        {
            return Err(TransportError::Malformed);
        }
        let id = frame.get("id");
        if id.is_some_and(|id| !id.is_string() && !crate::integer(id)) {
            return Err(TransportError::Malformed);
        }
        let method = frame["method"].as_str().ok_or(TransportError::Malformed)?;
        let params = frame
            .get("params")
            .filter(|v| v.is_object())
            .cloned()
            .unwrap_or_else(|| json!({}));
        if id.is_none() {
            if method == "notifications/initialized" {
                if self.state != State::Negotiated {
                    return Err(TransportError::Malformed);
                }
                self.state = State::Ready;
            }
            return Ok(None);
        }
        let id = id.expect("checked id").clone();
        let response = if method == "ping" {
            ok(id, json!({}))
        } else if method == "initialize" {
            if self.state != State::New {
                error(id, -32600, "session is already initialized")
            } else if !params["protocolVersion"].is_string()
                || !params["capabilities"].is_object()
                || !params["clientInfo"].is_object()
                || !params["clientInfo"]["name"].is_string()
                || !params["clientInfo"]["version"].is_string()
            {
                error(id, -32602, "invalid initialize parameters")
            } else {
                let version = params["protocolVersion"].as_str().expect("checked version");
                let version = if SUPPORTED_PROTOCOL_VERSIONS.contains(&version) {
                    version
                } else {
                    LATEST_PROTOCOL_VERSION
                };
                self.state = State::Negotiated;
                ok(
                    id,
                    json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"prompts":{"listChanged":false}},
                    "serverInfo":{"name":format!("benchmark-{}",self.family.name()),"version":"gauntlet-rust-mcp.v1"}}),
                )
            }
        } else if self.state != State::Ready {
            error(id, -32600, "session is not initialized")
        } else {
            self.dispatch(id, method, &params, operations)
        };
        let raw = gauntlet_contracts::canonicalize(response.to_string().as_bytes())
            .map_err(|_| TransportError::ResponseBound)?;
        if raw.len() > MAX_FRAME_BYTES {
            return Err(TransportError::ResponseBound);
        }
        Ok(Some(response))
    }
    fn dispatch(
        &self,
        id: Value,
        method: &str,
        params: &Value,
        operations: &mut impl Operations,
    ) -> Value {
        match method {
            "tools/list" => ok(id, json!({"tools":self.catalog.tools})),
            "resources/list" => ok(id, json!({"resources":[]})),
            "resources/templates/list" => ok(
                id,
                json!({"resourceTemplates":[{"uriTemplate":format!("fixture://{}/{{record_id}}",self.family.name()),"name":"record_resource","description":"Read a fixture record as a separately observable MCP resource.","mimeType":"application/json"}]}),
            ),
            "prompts/list" => ok(id, json!({"prompts":[]})),
            "tools/call" => {
                let Some(name) = params["name"].as_str() else {
                    return error(id, -32602, "tool name must be a string");
                };
                let args = params
                    .get("arguments")
                    .filter(|v| !v.is_null())
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if let Err(message) = self.catalog.validate(name, &args) {
                    return ok(id, tool_error(name, message));
                }
                match operations.call(name, &args, id.clone()) {
                    Ok(result) => {
                        if !result.is_object() {
                            return error(id, -32603, "provider result must be an object");
                        }
                        let text =
                            match gauntlet_contracts::canonicalize(result.to_string().as_bytes()) {
                                Ok(bytes) => String::from_utf8(bytes).expect("canonical UTF-8"),
                                Err(_) => return error(id, -32603, "provider result is invalid"),
                            };
                        let is_error = result.get("error").is_some_and(truthy);
                        ok(
                            id,
                            json!({"content":[{"type":"text","text":text}],"structuredContent":result,"isError":is_error}),
                        )
                    }
                    Err(e) => ok(id, tool_error(name, &e.message)),
                }
            }
            "resources/read" => {
                let Some(uri) = params["uri"].as_str() else {
                    return error(id, -32602, "resource URI must be a string");
                };
                let prefix = format!("fixture://{}/", self.family.name());
                let Some(record_id) = uri
                    .strip_prefix(&prefix)
                    .filter(|id| !id.is_empty() && !id.contains('/'))
                else {
                    return error(id, -32602, "unknown fixture resource URI");
                };
                // The pinned Python ResourceTemplate passes matched bytes
                // literally; decoding percent escapes would create new aliases.
                let operation = format!("{}.read", self.family.name());
                match operations.call(&operation, &json!({"record_id":record_id}), id.clone()) {
                    Ok(result) => {
                        match gauntlet_contracts::canonicalize(result.to_string().as_bytes()) {
                            Ok(bytes) => ok(
                                id,
                                json!({"contents":[{"uri":uri,"mimeType":"application/json","text":String::from_utf8(bytes).expect("canonical UTF-8")}]}),
                            ),
                            Err(_) => error(id, -32603, "provider result is invalid"),
                        }
                    }
                    Err(e) => error(id, -32602, &e.message),
                }
            }
            _ => error(id, -32601, "method not found"),
        }
    }
}
fn ok(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn tool_error(name: &str, message: &str) -> Value {
    json!({"content":[{"type":"text","text":format!("Error executing tool {name}: {message}")}],"isError":true})
}
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(v) => *v,
        Value::String(v) => !v.is_empty(),
        Value::Array(v) => !v.is_empty(),
        Value::Object(v) => !v.is_empty(),
        Value::Number(v) => v.as_f64().is_none_or(|n| n != 0.0),
    }
}
