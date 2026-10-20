use gauntlet_dashboard::{http, snapshot::PublicRoot};
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut state = None;
    let mut port = 8792u16;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--state" => state = args.next().map(PathBuf::from),
            "--port" => port = args.next().ok_or("--port needs a value")?.parse()?,
            "--bind" => {
                if args.next().as_deref() != Some("127.0.0.1") {
                    return Err("Rust dashboard binds only to 127.0.0.1".into());
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
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    println!("Gauntlet Rust dashboard: http://127.0.0.1:{port}");
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
