//! Fixed localhost HTTP adapter inside the network-none SDK namespace.
//! Only a Root-owned Unix channel carries provider bytes outside that namespace.
use crate::native_live_model::{MODEL, REQUEST_LIMIT, RESPONSE_LIMIT};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};

pub(crate) fn normalize_request(raw: &[u8]) -> Result<(Vec<u8>, bool), String> {
    if raw.is_empty() || raw.len() > REQUEST_LIMIT {
        return Err("bounded SDK model request required".into());
    }
    let canonical = canonicalize(raw).map_err(|_| "unambiguous SDK model request required")?;
    let mut body: Value =
        serde_json::from_slice(&canonical).map_err(|_| "SDK model JSON required")?;
    let streamed = body["stream"]
        .as_bool()
        .ok_or("explicit SDK stream selection required")?;
    if body["model"] != MODEL
        || body["messages"]
            .as_array()
            .is_none_or(|a| a.is_empty() || a.len() > 256)
        || body.get("n").is_some_and(|n| n.as_u64() != Some(1))
        || body.get("max_completion_tokens").is_some()
    {
        return Err("fixed source-selected SDK model request required".into());
    }
    let maximum = body
        .get("max_tokens")
        .map(|v| {
            v.as_u64()
                .filter(|n| *n > 0 && *n <= 65536)
                .ok_or("bounded SDK output token request required")
        })
        .transpose()?
        .unwrap_or(4096);
    body["max_tokens"] = json!(maximum.min(4096));
    body["stream"] = json!(false);
    body.as_object_mut()
        .ok_or("SDK model object required")?
        .remove("stream_options");
    Ok((
        canonicalize(body.to_string().as_bytes()).map_err(|_| "SDK model normalization failed")?,
        streamed,
    ))
}

/// Convert a complete, real OpenAI response into its equivalent SDK event
/// stream. No model text, arguments, token usage or stop reason is invented.
pub(crate) fn sse_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.is_empty() || raw.len() > RESPONSE_LIMIT {
        return Err("bounded model response required".into());
    }
    let canonical = canonicalize(raw).map_err(|_| "unambiguous model response required")?;
    let body: Value =
        serde_json::from_slice(&canonical).map_err(|_| "model response JSON required")?;
    let choices = body["choices"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("one real model choice required")?;
    let choice = &choices[0];
    let id = body["id"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or("model response identity required")?;
    if body["model"] != MODEL
        || choice["message"]["role"] != "assistant"
        || !matches!(
            choice["finish_reason"].as_str(),
            Some("stop" | "tool_calls" | "length" | "content_filter")
        )
        || !body["usage"].is_object()
    {
        return Err("complete real model response required".into());
    }
    let mut delta = choice["message"].clone();
    if let Some(calls) = delta.get_mut("tool_calls") {
        let calls = calls
            .as_array_mut()
            .filter(|a| a.len() <= 32)
            .ok_or("bounded actual model tool calls required")?;
        for (index, call) in calls.iter_mut().enumerate() {
            if call["type"] != "function"
                || !call["id"].is_string()
                || call["function"]["name"]
                    .as_str()
                    .is_none_or(|s| s.is_empty() || s.len() > 256)
                || call["function"]["arguments"]
                    .as_str()
                    .is_none_or(|s| s.len() > REQUEST_LIMIT)
                || call
                    .get("index")
                    .is_some_and(|n| n.as_u64() != Some(index as u64))
            {
                return Err("typed actual model tool call required".into());
            }
            call["index"] = json!(index);
        }
    }
    let chunk = |delta: Value, stop: Value, usage: Value| {
        json!({"id":id,"object":"chat.completion.chunk",
        "created":body["created"],"model":body["model"],"choices":[{"index":0,"delta":delta,"finish_reason":stop}],"usage":usage})
    };
    let first = chunk(delta, Value::Null, Value::Null);
    let last = chunk(
        json!({}),
        choice["finish_reason"].clone(),
        body["usage"].clone(),
    );
    let result = format!("data: {first}\n\ndata: {last}\n\ndata: [DONE]\n\n").into_bytes();
    if result.len() > RESPONSE_LIMIT + REQUEST_LIMIT {
        return Err("model SDK delivery bound exceeded".into());
    }
    Ok(result)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod bridge {
    use super::*;
    use crate::native_live_model::sha;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        os::unix::net::UnixStream,
        time::{Duration, Instant},
    };

    pub(crate) fn write_frame(
        stream: &mut UnixStream,
        value: &Value,
        limit: usize,
    ) -> Result<(), String> {
        let raw = canonicalize(value.to_string().as_bytes())
            .map_err(|_| "model frame encoding failed")?;
        if raw.is_empty() || raw.len() > limit {
            return Err("model frame bound exceeded".into());
        }
        stream
            .write_all(&(raw.len() as u32).to_be_bytes())
            .and_then(|_| stream.write_all(&raw))
            .map_err(|_| "model channel write uncertain".into())
    }
    pub(crate) fn read_frame(stream: &mut UnixStream, limit: usize) -> Result<Value, String> {
        let mut length = [0; 4];
        stream
            .read_exact(&mut length)
            .map_err(|_| "model channel ended before response")?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > limit {
            return Err("model channel frame bound exceeded".into());
        }
        let mut raw = vec![0; length];
        stream
            .read_exact(&mut raw)
            .map_err(|_| "model channel response incomplete")?;
        if canonicalize(&raw).map_err(|_| "ambiguous model channel JSON")? != raw {
            return Err("canonical model channel frame required".into());
        }
        serde_json::from_slice(&raw).map_err(|_| "model channel JSON invalid".into())
    }
    fn request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 16384 {
                return Err("SDK HTTP header bound exceeded".into());
            }
            let mut byte = [0];
            stream
                .read_exact(&mut byte)
                .map_err(|_| "SDK HTTP header incomplete")?;
            header.push(byte[0]);
        }
        let text = std::str::from_utf8(&header).map_err(|_| "SDK HTTP header invalid")?;
        let mut lines = text.split("\r\n");
        if lines.next() != Some("POST /v1/chat/completions HTTP/1.1") {
            return Err("only fixed SDK chat endpoint is supported".into());
        }
        let mut fields = BTreeMap::new();
        for line in lines.filter(|s| !s.is_empty()) {
            let (name, value) = line
                .split_once(':')
                .ok_or("SDK HTTP header field invalid")?;
            if name.is_empty()
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || fields
                    .insert(name.to_ascii_lowercase(), value.trim())
                    .is_some()
            {
                return Err("SDK HTTP header ambiguity".into());
            }
        }
        if fields.contains_key("transfer-encoding")
            || fields.contains_key("content-encoding")
            || fields.get("host") != Some(&"127.0.0.1:8001")
        {
            return Err("fixed bounded SDK HTTP transport required".into());
        }
        let length = fields
            .get("content-length")
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| *n > 0 && *n <= REQUEST_LIMIT)
            .ok_or("bounded SDK HTTP content length required")?;
        let mut raw = vec![0; length];
        stream
            .read_exact(&mut raw)
            .map_err(|_| "SDK HTTP body incomplete")?;
        Ok(raw)
    }
    pub(crate) fn run(args: &[String]) -> Result<(), String> {
        if args.len() != 6
            || args[1] != "--live-model-http-bridge-v1"
            || !crate::hex(&args[2], 40)
            || !crate::hex(&args[3], 16)
            || !crate::hex(&args[4], 64)
            || !crate::hex(&args[5], 64)
            || rustix::process::geteuid().as_raw() != 10001
            || rustix::process::getuid().as_raw() != 10001
        {
            return Err("fixed unprivileged live-model bridge invocation required".into());
        }
        // The operator binary remains Root0500. Only its independently hashed,
        // exclusive Root0555 copy is executable by the isolated SDK identity.
        let mut executable = std::fs::File::open("/proc/self/exe")
            .map_err(|_| "live-model bridge executable unavailable")?;
        let before = rustix::fs::fstat(&executable)
            .map_err(|_| "live-model bridge executable metadata unavailable")?;
        if before.st_uid != 0
            || before.st_gid != 0
            || before.st_nlink != 1
            || before.st_mode & 0o177777 != 0o100555
            || before.st_size <= 0
            || before.st_size > 128 * 1024 * 1024
        {
            return Err("immutable live-model bridge required".into());
        }
        let mut program = Vec::new();
        Read::by_ref(&mut executable)
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut program)
            .map_err(|_| "live-model bridge executable read failed")?;
        if program.len() as i64 != before.st_size
            || sha(&program) != args[4]
            || !crate::dependency_prefix_meta::same(
                &before,
                &rustix::fs::fstat(&executable)
                    .map_err(|_| "live-model bridge executable changed")?,
            )
        {
            return Err("live-model bridge executable pin differs".into());
        }
        drop(program);
        let mut channel = UnixStream::connect("/runtime/live-model/model.sock")
            .map_err(|_| "private Root model channel unavailable")?;
        let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut peer_length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        use std::os::fd::AsRawFd;
        if unsafe {
            libc::getsockopt(
                channel.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                peer.as_mut_ptr().cast(),
                &mut peer_length,
            )
        } != 0
            || peer_length as usize != std::mem::size_of::<libc::ucred>()
        {
            return Err("Root model server credentials unavailable".into());
        }
        let peer = unsafe { peer.assume_init() };
        if peer.uid != 0 || peer.gid != 0 || peer.pid <= 0 {
            return Err("model server is not the Root controller".into());
        }
        channel
            .set_read_timeout(Some(Duration::from_secs(
                crate::native_live_spec::ACTIVE_SECONDS,
            )))
            .and_then(|_| channel.set_write_timeout(Some(Duration::from_secs(30))))
            .map_err(|_| "bounded private model channel required")?;
        write_frame(
            &mut channel,
            &json!({"schema":"hol-gauntlet-native-live-http-hello.v1","source_sha":args[2],"job_id":args[3],"worker_generation":args[4],"budget_digest":args[5]}),
            4096,
        )?;
        let ack = read_frame(&mut channel, 4096)?;
        if ack
            != json!({"schema":"hol-gauntlet-native-live-http-ready.v1","source_sha":args[2],"job_id":args[3],"budget_digest":args[5]})
        {
            return Err("Root model bridge binding differs".into());
        }
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 8001))
            .map_err(|_| "SDK localhost model endpoint unavailable")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "bounded SDK model listener required")?;
        println!(
            "{}",
            json!({"schema":"hol-gauntlet-native-live-http-listening.v1","job_id":args[3],"budget_digest":args[5]})
        );
        std::io::stdout()
            .flush()
            .map_err(|_| "SDK model listener readiness uncertain")?;
        let deadline =
            Instant::now() + Duration::from_secs(crate::native_live_spec::ACTIVE_SECONDS);
        let mut turns = 0;
        while Instant::now() < deadline && !crate::native_worker::cancellation_requested() {
            let (mut client, peer) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => return Err("SDK model listener failed".into()),
            };
            if !peer.ip().is_loopback() || turns >= 64 {
                return Err("serial SDK model budget exhausted".into());
            }
            client
                .set_read_timeout(Some(Duration::from_secs(30)))
                .and_then(|_| client.set_write_timeout(Some(Duration::from_secs(30))))
                .map_err(|_| "bounded SDK HTTP I/O required")?;
            let raw = request(&mut client)?;
            let (_, streamed) = normalize_request(&raw)?;
            turns += 1;
            write_frame(
                &mut channel,
                &json!({"schema":"hol-gauntlet-native-live-sdk-model-request.v1","turn":turns,"sdk_request_sha256":sha(&raw),"body_b64":STANDARD.encode(&raw)}),
                crate::native_live_model::REQUEST_FRAME_LIMIT,
            )?;
            let response =
                read_frame(&mut channel, crate::native_live_model::RESPONSE_FRAME_LIMIT)?;
            if response.as_object().is_none_or(|o| o.len() != 5)
                || response["schema"] != "hol-gauntlet-native-live-sdk-model-response.v1"
                || response["turn"] != turns
                || response["sdk_request_sha256"] != sha(&raw)
            {
                return Err("SDK model response identity differs".into());
            }
            let encoded = response["body_b64"]
                .as_str()
                .ok_or("SDK model response bytes missing")?;
            let body = STANDARD
                .decode(encoded)
                .map_err(|_| "SDK model response encoding invalid")?;
            if body.is_empty()
                || body.len() > RESPONSE_LIMIT
                || STANDARD.encode(&body) != encoded
                || response["response_sha256"] != sha(&body)
            {
                return Err("SDK model response byte pin differs".into());
            }
            let delivery = if streamed { sse_response(&body)? } else { body };
            let content = if streamed {
                "text/event-stream"
            } else {
                "application/json"
            };
            write!(client,"HTTP/1.1 200 OK\r\nContent-Type: {content}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",delivery.len()).and_then(|_|client.write_all(&delivery)).and_then(|_|client.flush()).map_err(|_|"SDK model response delivery uncertain")?;
            write_frame(
                &mut channel,
                &json!({"schema":"hol-gauntlet-native-live-sdk-model-delivered.v1","turn":turns,"sdk_request_sha256":sha(&raw),"delivery_sha256":sha(&delivery),"delivery_bytes":delivery.len()}),
                4096,
            )?;
        }
        Err("SDK model bridge lifetime ended before explicit controller retirement".into())
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub fn run_native_live_http_bridge(args: &[String]) -> Result<(), String> {
    bridge::run(args)
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) use bridge::{read_frame, write_frame};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_transport_normalization_preserves_actual_messages_and_pins_model_budget() {
        let input = json!({"model":MODEL,"messages":[{"role":"user","content":"source-selected prompt"}],"tools":[{"type":"function","function":{"name":"docs_read"}}],"stream":true,"stream_options":{"include_usage":true},"max_tokens":8192});
        let (raw, streamed) = normalize_request(input.to_string().as_bytes()).unwrap();
        let output: Value = serde_json::from_slice(&raw).unwrap();
        assert!(streamed);
        assert_eq!(output["messages"], input["messages"]);
        assert_eq!(output["tools"], input["tools"]);
        assert_eq!(output["max_tokens"], 4096);
        assert_eq!(output["stream"], false);
        assert!(output.get("stream_options").is_none());
        let mut changed = input;
        changed["model"] = json!("other");
        assert!(normalize_request(changed.to_string().as_bytes()).is_err());
    }
    #[test]
    fn real_response_stream_preserves_tool_arguments_usage_and_stop_reason() {
        let input = json!({"id":"chat-real","created":1,"model":MODEL,"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-a","type":"function","function":{"name":"docs_read","arguments":"{\"id\":\"ticket-a\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":21,"completion_tokens":7,"total_tokens":28}});
        let raw = sse_response(input.to_string().as_bytes()).unwrap();
        let text = std::str::from_utf8(&raw).unwrap();
        let chunks = text
            .split("\n\n")
            .filter_map(|line| line.strip_prefix("data: "))
            .filter(|s| *s != "[DONE]")
            .map(|s| serde_json::from_str::<Value>(s).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[0]["choices"][0]["delta"]["tool_calls"][0]["function"],
            input["choices"][0]["message"]["tool_calls"][0]["function"]
        );
        assert_eq!(chunks[1]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(chunks[1]["usage"], input["usage"]);
    }
}
