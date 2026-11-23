//! Minimal loopback HTTP surface: three embedded assets and two read-only APIs.

use crate::snapshot::PublicRoot;
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_HEADER: usize = 8192;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const HTML: &[u8] = include_bytes!("../../../../gauntlet/control_plane/static/index.html");
const JS: &[u8] = include_bytes!("../../../../gauntlet/control_plane/static/app.js");
const CSS: &[u8] = include_bytes!("../../../../gauntlet/control_plane/static/style.css");

struct RequestStream {
    stream: TcpStream,
    deadline: Instant,
}
impl RequestStream {
    fn new(stream: TcpStream) -> io::Result<Self> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        // Accepted macOS sockets can inherit the listener's nonblocking mode.
        stream.set_nonblocking(false)?;
        Ok(Self { stream, deadline })
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "dashboard request deadline"))
    }
}
impl Read for RequestStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}
impl Write for RequestStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

pub fn handle(stream: TcpStream, root: &PublicRoot) -> io::Result<()> {
    // Header reads and every response write share one monotone budget. A peer
    // cannot renew it with partial input or by slowly draining the response.
    let mut stream = RequestStream::new(stream)?;
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while request.len() < MAX_HEADER && !request.windows(4).any(|part| part == b"\r\n\r\n") {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    if request.len() > MAX_HEADER || !request.windows(4).any(|part| part == b"\r\n\r\n") {
        return reply(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        );
    }
    let Ok(request) = std::str::from_utf8(&request) else {
        return reply(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        );
    };
    let mut lines = request.split("\r\n");
    let Some(first) = lines.next() else {
        return reply(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        );
    };
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() != 3 || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1") {
        return reply(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        );
    }
    let hosts: Vec<&str> = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .collect();
    if hosts.len() != 1 || !allowed_host(hosts[0]) {
        return reply(&mut stream, 403, "Forbidden", "text/plain", b"Forbidden");
    }
    if parts[0] != "GET" {
        return reply(
            &mut stream,
            501,
            "Unsupported method",
            "text/plain",
            b"Unsupported method",
        );
    }
    let path = parts[1].split('?').next().unwrap_or("");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    match path {
        "/" => reply(&mut stream, 200, "OK", "text/html; charset=utf-8", HTML),
        "/app.js" => reply(&mut stream, 200, "OK", "text/javascript", JS),
        "/style.css" => reply(&mut stream, 200, "OK", "text/css", CSS),
        "/api/status" => {
            let body = serde_json::to_vec(&root.snapshot(now))?;
            reply(&mut stream, 200, "OK", "application/json", &body)
        }
        "/healthz" => {
            let status = root.snapshot(now);
            let body = serde_json::to_vec(&json!({
                "service": "hol-gauntlet-dashboard",
                "instance_id": root.identity(),
                "server": "online",
                "collector": status["collector_status"]
            }))?;
            reply(&mut stream, 200, "OK", "application/json", &body)
        }
        _ => reply(&mut stream, 404, "Not Found", "text/plain", b"Not Found"),
    }
}

fn allowed_host(value: &str) -> bool {
    let (host, port) = value.split_once(':').unwrap_or((value, ""));
    matches!(host, "localhost" | "127.0.0.1")
        && (port.is_empty() || port.parse::<u16>().is_ok_and(|number| number > 0))
}

fn reply(
    stream: &mut impl Write,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: {CSP}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn header_and_stalled_response_share_one_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut stream = RequestStream::new(stream).unwrap();
        stream.deadline = Instant::now() + Duration::from_secs(1);
        let peer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(600));
            reader.write_all(b"x").unwrap();
            reader
        });
        let started = Instant::now();
        stream.read_exact(&mut [0]).unwrap();
        let _reader = peer.join().unwrap();
        let error = stream.write_all(&vec![0; 32 * 1024 * 1024]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(1400));
    }
}
