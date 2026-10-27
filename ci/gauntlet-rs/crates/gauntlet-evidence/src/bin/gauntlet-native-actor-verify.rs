//! Build-time ABI inspection only. This grants no execution authority.
use gauntlet_evidence::verify_native_actor_elf;
use rustix::fs::{fstat, open, FileType, Mode, OFlags};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

fn inspect() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("usage: gauntlet-native-actor-verify ACTOR OUTSIDE_SHA256".into());
    }
    let pin = args[2].to_str().ok_or("ASCII SHA-256 required")?;
    if pin.len() != 64
        || !pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("lowercase SHA-256 required".into());
    }
    let fd = open(
        &args[1],
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let before = fstat(&fd)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || !(64..=2 * 1024 * 1024).contains(&before.st_size)
    {
        return Err("bounded ordinary actor file required".into());
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    file.by_ref()
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)?;
    let after = fstat(&file)?;
    if before.st_size != raw.len() as i64
        || before.st_size != after.st_size
        || format!("{:x}", Sha256::digest(&raw)) != pin
    {
        return Err("actor bytes differ from outside pin".into());
    }
    verify_native_actor_elf(&raw)?;
    Ok(
        json!({"schema":"hol-gauntlet-native-actor-abi-inspection.v1","sha256":pin,"bytes":raw.len(),"glibc_loader_metadata_verified":true,"artifact_admitted":false,"execution_eligible":false}),
    )
}

fn main() {
    match inspect() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("native actor ABI unavailable: {error}");
            std::process::exit(2);
        }
    }
}
