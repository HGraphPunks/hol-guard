//! Private Unix transport with bounded HTTP framing and challenge-bound HMACs.
use super::custody::Journal;
use super::{bytes, hex, parse, random_key, sha, Intent};
use ring::hmac;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

const ADDRESS: &str = "provider.invalid";
const HEADERS: usize = 8192;
type Message = (String, BTreeMap<String, String>, Vec<u8>);
pub(super) struct Request {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
fn message(stream: &mut UnixStream, limit: usize) -> Result<Message, String> {
    let mut head = Vec::new();
    let mut one = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= HEADERS
            || stream
                .read(&mut one)
                .map_err(|_| "provider HTTP header unavailable")?
                != 1
        {
            return Err("bounded provider HTTP headers required".into());
        }
        head.push(one[0]);
    }
    let raw = std::str::from_utf8(&head).map_err(|_| "ASCII provider HTTP headers required")?;
    if !raw.is_ascii() {
        return Err("ASCII provider HTTP headers required".into());
    }
    let mut lines = raw[..raw.len() - 4].split("\r\n");
    let first = lines.next().ok_or("HTTP first line absent")?.to_owned();
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("HTTP header invalid")?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b < 0x20 && b != b'\t')
            || headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
        {
            return Err("unambiguous provider HTTP headers required".into());
        }
    }
    if headers.contains_key("transfer-encoding") || headers.contains_key("expect") {
        return Err("fixed-length provider HTTP required".into());
    }
    let size = headers
        .get("content-length")
        .map(|s| {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err("HTTP content length invalid");
            }
            s.parse::<usize>()
                .map_err(|_| "HTTP content length invalid")
        })
        .transpose()
        .map_err(str::to_owned)?
        .unwrap_or(0);
    if size > limit {
        return Err("provider HTTP body exceeds bound".into());
    }
    let mut body = vec![0_u8; size];
    stream
        .read_exact(&mut body)
        .map_err(|_| "provider HTTP body incomplete")?;
    Ok((first, headers, body))
}
pub(super) fn listener(journal: &Journal, digest: &str) -> Result<UnixListener, String> {
    let listener = UnixListener::bind(journal.socket_path()?)
        .map_err(|_| "private provider socket already consumed or unavailable")?;
    journal.pin_socket(digest)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "provider listener unavailable")?;
    Ok(listener)
}
pub(super) fn request(stream: &mut UnixStream) -> Result<Request, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| "provider HTTP deadline unavailable")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| "provider HTTP deadline unavailable")?;
    let (first, headers, body) = message(stream, 2 * 1024 * 1024)?;
    let parts = first.split(' ').collect::<Vec<_>>();
    if parts.len() != 3
        || !matches!(parts[0], "GET" | "POST")
        || parts[2] != "HTTP/1.1"
        || !matches!(
            parts[1],
            "/v1/models"
                | "/v1/benchmark-quota"
                | "/v1/chat/completions"
                | "/v1/hol-gauntlet/status"
        )
        || headers.get("host").is_none_or(|h| h != ADDRESS)
        || headers
            .get("connection")
            .is_none_or(|h| !h.eq_ignore_ascii_case("close"))
        || (parts[0] == "POST"
            && headers
                .get("content-type")
                .is_none_or(|h| h != "application/json"))
        || (parts[0] == "GET" && !body.is_empty())
    {
        return Err("fixed closed provider HTTP route required".into());
    }
    Ok(Request {
        method: parts[0].into(),
        path: parts[1].into(),
        headers,
        body,
    })
}
fn key(journal: &Journal, intent: &Intent) -> Result<hmac::Key, String> {
    let digest = intent.digest()?;
    let value = journal.json("provider-channel.json")?;
    if !super::exact(&value, &["schema", "binding_sha256", "key"])
        || value["schema"] != "hol-gauntlet-rust-provider-private-channel.v1"
        || value["binding_sha256"] != digest
    {
        return Err("provider private channel binding differs".into());
    }
    let raw = value["key"]
        .as_str()
        .filter(|s| hex(s, 64))
        .ok_or("provider private channel unavailable")?;
    if sha(raw.as_bytes()) != intent.0["channel_key_sha256"] {
        return Err("provider private channel differs from intent pin".into());
    }
    let mut decoded = [0_u8; 32];
    for (i, b) in decoded.iter_mut().enumerate() {
        *b = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|_| "provider private channel invalid")?;
    }
    Ok(hmac::Key::new(hmac::HMAC_SHA256, &decoded))
}
fn tag(key: &hmac::Key, raw: &str) -> String {
    hmac::sign(key, raw.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn verify(key: &hmac::Key, raw: &str, signature: &str) -> bool {
    if !hex(signature, 64) {
        return false;
    }
    let mut decoded = [0_u8; 32];
    for (i, b) in decoded.iter_mut().enumerate() {
        let Ok(v) = u8::from_str_radix(&signature[i * 2..i * 2 + 2], 16) else {
            return false;
        };
        *b = v;
    }
    hmac::verify(key, raw.as_bytes(), &decoded).is_ok()
}
fn request_binding(request: &Request, digest: &str, nonce: &str) -> String {
    format!(
        "request\n{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        request.path,
        digest,
        nonce,
        sha(&request.body),
        request
            .headers
            .get("x-hol-provider-remaining-millis")
            .map_or("", String::as_str)
    )
}
pub(super) fn model_deadline(request: &Request) -> Result<Duration, String> {
    let raw = request
        .headers
        .get("x-hol-provider-remaining-millis")
        .ok_or("bounded model deadline absent")?;
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("bounded model deadline invalid".into());
    }
    let millis = raw
        .parse::<u64>()
        .ok()
        .filter(|n| (1..=900_000).contains(n))
        .ok_or("bounded model deadline invalid")?;
    Ok(Duration::from_millis(millis))
}
fn response_binding(status: u16, body: &[u8], digest: &str, nonce: &str) -> String {
    format!("response\n{status}\n{digest}\n{nonce}\n{}", sha(body))
}
pub(super) fn authenticate(
    request: &Request,
    journal: &Journal,
    intent: &Intent,
) -> Result<(), String> {
    let digest = intent.digest()?;
    let nonce = request
        .headers
        .get("x-hol-provider-nonce")
        .filter(|n| hex(n, 64))
        .ok_or("provider private challenge absent")?;
    let signature = request
        .headers
        .get("x-hol-provider-mac")
        .ok_or("provider private authentication absent")?;
    if request.headers.get("x-hol-provider-binding") != Some(&digest)
        || !verify(
            &key(journal, intent)?,
            &request_binding(request, &digest, nonce),
            signature,
        )
    {
        return Err("provider private channel authentication failed".into());
    }
    Ok(())
}
pub(super) fn reply(
    stream: &mut UnixStream,
    status: u16,
    value: &Value,
    auth: Option<(&Request, &Journal, &Intent)>,
) -> Result<(), String> {
    let body = bytes(value)?;
    if body.len() > 6 * 1024 * 1024 {
        return Err("provider response exceeds bound".into());
    }
    let mut extra = String::new();
    if let Some((request, journal, intent)) = auth {
        let digest = intent.digest()?;
        let nonce = request
            .headers
            .get("x-hol-provider-nonce")
            .ok_or("provider reply challenge absent")?;
        extra = format!(
            "X-Hol-Provider-Mac: {}\r\n",
            tag(
                &key(journal, intent)?,
                &response_binding(status, &body, &digest, nonce)
            )
        );
    }
    write!(stream,"HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",if status==200{"OK"}else{"Refused"},body.len()).map_err(|_|"provider response header failed")?;
    stream
        .write_all(&body)
        .map_err(|_| "provider response transport failed".into())
}
pub(super) fn client(
    journal: &Journal,
    intent: &Intent,
    method: &str,
    path: &str,
    value: Option<&Value>,
) -> Result<Value, String> {
    client_bounded(
        journal,
        intent,
        method,
        path,
        value,
        Duration::from_secs(900),
    )
}
pub(super) fn client_bounded(
    journal: &Journal,
    intent: &Intent,
    method: &str,
    path: &str,
    value: Option<&Value>,
    timeout: Duration,
) -> Result<Value, String> {
    journal.stable()?;
    let digest = intent.digest()?;
    let nonce = random_key()?;
    let body = value.map(bytes).transpose()?.unwrap_or_default();
    let mut request = Request {
        method: method.into(),
        path: path.into(),
        headers: BTreeMap::new(),
        body,
    };
    let millis = timeout.min(Duration::from_secs(900)).as_millis();
    if method == "POST" {
        if millis == 0 {
            return Err("model deadline elapsed before dispatch".into());
        }
        request
            .headers
            .insert("x-hol-provider-remaining-millis".into(), millis.to_string());
    }
    let signature = tag(
        &key(journal, intent)?,
        &request_binding(&request, &digest, &nonce),
    );
    journal.verify_socket(&digest)?;
    let mut stream = UnixStream::connect(journal.socket_path()?)
        .map_err(|_| "owned provider unavailable; dispatch remains consumed")?;
    stream
        .set_read_timeout(Some(if method == "GET" {
            Duration::from_secs(2)
        } else {
            timeout.min(Duration::from_secs(900)) + Duration::from_secs(60)
        }))
        .map_err(|_| "provider response deadline unavailable")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| "provider request deadline unavailable")?;
    let extra = if method == "POST" {
        format!("X-Hol-Provider-Remaining-Millis: {millis}\r\n")
    } else {
        String::new()
    };
    write!(stream,"{method} {path} HTTP/1.1\r\nHost: {ADDRESS}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nX-Hol-Provider-Binding: {digest}\r\nX-Hol-Provider-Nonce: {nonce}\r\nX-Hol-Provider-Mac: {signature}\r\n{extra}\r\n",request.body.len()).map_err(|_|"provider request failed")?;
    stream
        .write_all(&request.body)
        .map_err(|_| "provider request failed")?;
    let (first, headers, body) = message(&mut stream, 6 * 1024 * 1024)?;
    let parts = first.split(' ').collect::<Vec<_>>();
    let status = parts
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("provider HTTP response invalid")?;
    let private_key = key(journal, intent)?;
    if parts.len() != 3
        || parts[0] != "HTTP/1.1"
        || !headers.get("x-hol-provider-mac").is_some_and(|signature| {
            verify(
                &private_key,
                &response_binding(status, &body, &digest, &nonce),
                signature,
            )
        })
    {
        return Err("provider response ownership authentication failed".into());
    }
    journal.stable()?;
    journal.verify_socket(&digest)?;
    if status != 200 {
        return Err("provider refused model operation; retained attempt cannot be replayed".into());
    }
    parse(&body)
}
