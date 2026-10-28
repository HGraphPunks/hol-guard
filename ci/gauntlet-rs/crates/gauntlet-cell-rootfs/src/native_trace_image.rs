//! Reuse only unchanged Root image generations, retained by read-only FDs.
use crate::{fs_input, Result};
use rustix::fs::{fstat, FileType, Stat};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_HELD: usize = 64;

pub(super) struct Image {
    pub(super) metadata: Stat,
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

struct Held {
    file: File,
    metadata: Stat,
    sha256: String,
}

#[derive(Default)]
pub(super) struct Images {
    held: Vec<Held>,
    #[cfg(test)]
    reads: usize,
}

fn bounded(info: &Stat) -> Result<()> {
    if FileType::from_raw_mode(info.st_mode) != FileType::RegularFile
        || info.st_size <= 0
        || info.st_size as u64 > MAX_BYTES
    {
        return Err("bounded regular traced executable required".into());
    }
    Ok(())
}

fn reusable(info: &Stat) -> bool {
    bounded(info).is_ok() && fs_input::root_metadata(info, false).is_ok()
}

impl Images {
    pub(super) fn measure(&mut self, fd: OwnedFd) -> Result<Image> {
        let before = fstat(&fd).map_err(|e| e.to_string())?;
        bounded(&before)?;
        if let Some(index) = self.held.iter().position(|entry| {
            entry.metadata.st_dev == before.st_dev && entry.metadata.st_ino == before.st_ino
        }) {
            let entry = &self.held[index];
            let held = fstat(&entry.file).map_err(|e| e.to_string())?;
            let after = fstat(&fd).map_err(|e| e.to_string())?;
            if reusable(&before)
                && fs_input::same(&before, &entry.metadata)
                && fs_input::same(&before, &held)
                && fs_input::same(&before, &after)
            {
                return Ok(Image {
                    bytes: before.st_size as u64,
                    metadata: before,
                    sha256: entry.sha256.clone(),
                });
            }
            self.held.swap_remove(index);
        }
        let mut stream = File::from(fd);
        let mut digest = Sha256::new();
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
        #[cfg(test)]
        {
            self.reads += 1;
        }
        let sha256 = format!("{:x}", digest.finalize());
        if reusable(&before) && self.held.len() < MAX_HELD {
            self.held.push(Held {
                file: stream,
                metadata: before,
                sha256: sha256.clone(),
            });
        }
        Ok(Image {
            metadata: before,
            bytes: total,
            sha256,
        })
    }
}

#[cfg(test)]
#[path = "native_trace_image_tests.rs"]
mod tests;
