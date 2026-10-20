use gauntlet_dashboard::{http, snapshot::PublicRoot};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

fn healthcheck() -> Result<(), Box<dyn std::error::Error>> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 8787));
    let mut connection = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    connection.set_read_timeout(Some(Duration::from_secs(2)))?;
    connection.set_write_timeout(Some(Duration::from_secs(2)))?;
    connection.write_all(b"GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")?;
    let mut prefix = [0; 15];
    connection.read_exact(&mut prefix)?;
    if &prefix != b"HTTP/1.1 200 OK" {
        return Err("Rust dashboard health endpoint did not return 200".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments == ["--healthcheck"] {
        return healthcheck();
    }
    let mut args = arguments.into_iter();
    let mut state = None;
    let mut port = 8792u16;
    let mut bind = Ipv4Addr::LOCALHOST;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--state" => state = args.next().map(PathBuf::from),
            "--port" => port = args.next().ok_or("--port needs a value")?.parse()?,
            "--bind" => {
                bind = match args.next().as_deref() {
                    Some("127.0.0.1") => Ipv4Addr::LOCALHOST,
                    Some("0.0.0.0") => Ipv4Addr::UNSPECIFIED,
                    _ => return Err("--bind accepts only 127.0.0.1 or 0.0.0.0".into()),
                }
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    let state = state.ok_or("--state requires an absolute public directory")?;
    if !state.is_absolute() {
        return Err("--state requires an absolute public directory".into());
    }
    let root = PublicRoot::open(&state)?;
    let listener = TcpListener::bind((bind, port))?;
    println!("Gauntlet Rust dashboard listening on {bind}:{port}");
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if let Err(error) = http::handle(stream, &root) {
                    eprintln!("dashboard request failed: {error}");
                }
            }
            Err(error) => eprintln!("dashboard connection failed: {error}"),
        }
    }
    Ok(())
}
