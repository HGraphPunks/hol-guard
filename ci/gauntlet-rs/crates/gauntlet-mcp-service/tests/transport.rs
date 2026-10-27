#![cfg(unix)]
use gauntlet_mcp_service::{
    Family, McpStream, OperationError, Operations, Session, TransportError, MAX_FRAME_BYTES,
};
use serde_json::{json, Value};
use std::{
    io::Write,
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
#[test]
fn pipelined_frames_and_binary_payloads_keep_every_byte_until_json_dispatch() {
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    sender.write_all(b"one\n\x00\xff\nthree\n").unwrap();
    sender.shutdown(Shutdown::Write).unwrap();
    let mut stream = McpStream::new(receiver).unwrap();
    let cancel = AtomicBool::new(false);
    for expected in [b"one".as_slice(), b"\x00\xff", b"three"] {
        assert_eq!(
            stream.read_frame(deadline(), &cancel).unwrap().unwrap(),
            expected
        );
    }
    assert_eq!(stream.read_frame(deadline(), &cancel).unwrap(), None);
    assert_eq!(
        stream.read_frame(deadline(), &cancel),
        Err(TransportError::Closed)
    );
}

#[test]
fn cancellation_and_deadlines_also_cover_already_buffered_frames() {
    for cancelled in [true, false] {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"first\nsecond\n").unwrap();
        let mut stream = McpStream::new(receiver).unwrap();
        assert_eq!(
            stream
                .read_frame(deadline(), &AtomicBool::new(false))
                .unwrap()
                .unwrap(),
            b"first"
        );
        let until = if cancelled {
            deadline()
        } else {
            Instant::now()
        };
        assert_eq!(
            stream.read_frame(until, &AtomicBool::new(cancelled)),
            Err(if cancelled {
                TransportError::Cancelled
            } else {
                TransportError::Deadline
            })
        );
        assert_eq!(
            stream.read_frame(deadline(), &AtomicBool::new(false)),
            Err(TransportError::Closed)
        );
    }
}

#[test]
fn truncated_oversized_idle_and_cancelled_streams_are_not_reusable() {
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    sender.write_all(b"truncated").unwrap();
    drop(sender);
    let mut stream = McpStream::new(receiver).unwrap();
    let cancel = AtomicBool::new(false);
    assert_eq!(
        stream.read_frame(deadline(), &cancel),
        Err(TransportError::Truncated)
    );
    assert_eq!(
        stream.read_frame(deadline(), &cancel),
        Err(TransportError::Closed)
    );
    let (_sender, receiver) = UnixStream::pair().unwrap();
    let mut stream = McpStream::new(receiver).unwrap();
    assert_eq!(
        stream.read_frame(Instant::now() + Duration::from_millis(10), &cancel),
        Err(TransportError::Deadline)
    );
    let (_sender, receiver) = UnixStream::pair().unwrap();
    let mut stream = McpStream::new(receiver).unwrap();
    assert_eq!(
        stream.read_frame(deadline(), &AtomicBool::new(true)),
        Err(TransportError::Cancelled)
    );
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    let mut stream = McpStream::new(receiver).unwrap();
    let writer = thread::spawn(move || {
        let _ = sender.write_all(&vec![b'x'; MAX_FRAME_BYTES + 1]);
    });
    assert_eq!(
        stream.read_frame(deadline(), &cancel),
        Err(TransportError::FrameBound)
    );
    drop(stream);
    writer.join().unwrap();
}

#[test]
fn backpressure_writes_one_complete_frame_and_embedded_frames_poison() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let expected = vec![b'x'; 200000];
    let read = thread::spawn(move || {
        McpStream::new(receiver)
            .unwrap()
            .read_frame(deadline(), &AtomicBool::new(false))
            .unwrap()
            .unwrap()
    });
    let mut stream = McpStream::new(sender).unwrap();
    stream
        .write_frame(&expected, deadline(), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(read.join().unwrap(), expected);
    assert_eq!(
        stream.write_frame(b"one\ntwo", deadline(), &AtomicBool::new(false)),
        Err(TransportError::Malformed)
    );
    assert_eq!(
        stream.write_frame(b"one", deadline(), &AtomicBool::new(false)),
        Err(TransportError::Closed)
    );
}

struct Backend(usize);
impl Operations for Backend {
    fn call(&mut self, operation: &str, args: &Value, _: Value) -> Result<Value, OperationError> {
        assert_eq!(operation, "docs.read");
        assert_eq!(args, &json!({"record_id":"spec"}));
        self.0 += 1;
        Ok(json!({"id":"spec","data":{"body":"real dispatched fixture"}}))
    }
}
#[test]
fn actual_pipelined_unix_io_drives_negotiation_and_one_provider_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        let mut stream = McpStream::new(server).unwrap();
        let mut session = Session::new(Family::Docs).unwrap();
        let mut backend = Backend(0);
        let cancel = AtomicBool::new(false);
        while let Some(frame) = stream.read_frame(deadline(), &cancel).unwrap() {
            if let Some(response) = session.process(&frame, &mut backend).unwrap() {
                stream
                    .write_frame(response.to_string().as_bytes(), deadline(), &cancel)
                    .unwrap();
            }
        }
        backend.0
    });
    client.write_all(concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"wire\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"docs.read\",\"arguments\":{\"record_id\":\"spec\"}}}\n"
    ).as_bytes()).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut stream = McpStream::new(client).unwrap();
    let cancel = AtomicBool::new(false);
    let initialized: Value =
        serde_json::from_slice(&stream.read_frame(deadline(), &cancel).unwrap().unwrap()).unwrap();
    let result: Value =
        serde_json::from_slice(&stream.read_frame(deadline(), &cancel).unwrap().unwrap()).unwrap();
    assert_eq!(initialized["id"], 1);
    assert_eq!(result["id"], 2);
    assert_eq!(
        result["result"]["structuredContent"]["data"]["body"],
        "real dispatched fixture"
    );
    assert_eq!(worker.join().unwrap(), 1);
}
