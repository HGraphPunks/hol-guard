//! Hash every stopped executable through its actual held kernel descriptor.
use crate::{fs_input, Result};
use ring::digest::{Context, SHA256};
use rustix::fs::{fstat, FileType, Stat};
use std::fmt::Write;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

const MAX_BYTES: u64 = 128 * 1024 * 1024;

pub(super) struct Image {
    pub(super) metadata: Stat,
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

// Metadata cannot safely key a content cache: same-size writes can share
// filesystem timestamps. Read every image, even when an earlier exec used
// the same Root-owned inode. No executable descriptors survive this call.
pub(super) fn measure(fd: OwnedFd) -> Result<Image> {
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_size <= 0
        || before.st_size as u64 > MAX_BYTES
    {
        return Err("bounded regular traced executable required".into());
    }
    let mut stream = File::from(fd);
    let mut digest = Context::new(&SHA256);
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() >= deadline {
            return Err("traced executable read deadline".into());
        }
        let count = stream.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_BYTES {
            return Err("traced executable exceeds bound".into());
        }
        digest.update(&buffer[..count]);
    }
    let after = fstat(&stream).map_err(|e| e.to_string())?;
    if !fs_input::same(&before, &after) || total != before.st_size as u64 {
        return Err("traced executable changed while hashing".into());
    }
    let digest = digest.finish();
    let mut sha256 = String::with_capacity(64);
    for byte in digest.as_ref() {
        write!(&mut sha256, "{byte:02x}").map_err(|_| "traced digest encoding")?;
    }
    Ok(Image {
        metadata: before,
        bytes: total,
        sha256,
    })
}

#[cfg(test)]
#[path = "native_trace_image_tests.rs"]
mod tests;
