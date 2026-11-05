//! Ordinary bounded files in the owned feature container. Root inputs are
//! immutable to UID 65532; every new output uses exclusive creation.
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

fn stamp(m: &std::fs::Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn opened(path: &Path, bound: u64) -> Result<(File, std::fs::Metadata), String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.len() > bound
        || before.nlink() == 0
        || before.mode() & 0o6000 != 0
    {
        return Err("bounded ordinary feature file required".into());
    }
    Ok((file, before))
}
fn unchanged(path: &Path, file: &File, before: &std::fs::Metadata) -> Result<(), String> {
    let after = file.metadata().map_err(|e| e.to_string())?;
    let visible = path.symlink_metadata().map_err(|e| e.to_string())?;
    if stamp(before) != stamp(&after) || stamp(before) != stamp(&visible) {
        return Err("feature file changed during read".into());
    }
    Ok(())
}
pub(super) fn read(path: &Path, bound: usize) -> Result<Vec<u8>, String> {
    let (mut file, before) = opened(path, bound as u64)?;
    let mut raw = Vec::new();
    (&mut file)
        .take(bound as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as u64 != before.len() {
        return Err("feature file length changed".into());
    }
    unchanged(path, &file, &before)?;
    Ok(raw)
}
pub(super) fn root_input(path: &Path, bound: u64, pin: &str) -> Result<File, String> {
    let (mut file, before) = opened(path, bound)?;
    if before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || before.mode() & 0o777 != 0o444
        || before.len() == 0
    {
        return Err("immutable Root feature input required".into());
    }
    if hash_reader(&mut file, bound)? != pin {
        return Err("feature input differs from outside pin".into());
    }
    unchanged(path, &file, &before)?;
    std::io::Seek::rewind(&mut file).map_err(|e| e.to_string())?;
    Ok(file)
}
fn hash_reader(file: &mut File, bound: u64) -> Result<String, String> {
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > bound {
            return Err("feature file exceeds byte bound".into());
        }
        digest.update(&buffer[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
pub(super) fn hash(path: &Path, bound: u64) -> Result<String, String> {
    let (mut file, before) = opened(path, bound)?;
    let pin = hash_reader(&mut file, bound)?;
    unchanged(path, &file, &before)?;
    Ok(pin)
}
pub(super) fn running_hash() -> Result<String, String> {
    // The kernel-owned magic link identifies this running controller, not a
    // caller-selected filesystem path. Its Root file must be non-writable.
    let mut file = File::open("/proc/self/exe").map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || before.mode() & 0o6022 != 0
        || before.len() > 32 * 1024 * 1024
    {
        return Err("immutable Root feature executor required".into());
    }
    let pin = hash_reader(&mut file, 32 * 1024 * 1024)?;
    if stamp(&before) != stamp(&file.metadata().map_err(|e| e.to_string())?) {
        return Err("feature executor changed".into());
    }
    Ok(pin)
}
pub(super) fn save(path: &Path, raw: &[u8], mode: u32) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(raw).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}
pub(super) fn copy(source: &Path, target: &Path, bound: u64, mode: u32) -> Result<(), String> {
    let (mut input, before) = opened(source, bound)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(target)
        .map_err(|e| e.to_string())?;
    let count =
        std::io::copy(&mut (&mut input).take(bound + 1), &mut output).map_err(|e| e.to_string())?;
    if count != before.len() || count > bound {
        return Err("feature copy length differs".into());
    }
    unchanged(source, &input, &before)?;
    output.sync_all().map_err(|e| e.to_string())?;
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode))
        .map_err(|e| e.to_string())?;
    if hash(source, bound)? != hash(target, bound)? {
        return Err("feature copy bytes differ".into());
    }
    Ok(())
}
pub(super) fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
    let mut pending = vec![(source.to_path_buf(), target.to_path_buf())];
    let mut files = 0usize;
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some((src, dst)) = pending.pop() {
        if !src.symlink_metadata().map_err(|e| e.to_string())?.is_dir() {
            return Err("ordinary feature data directory required".into());
        }
        std::fs::create_dir(&dst).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        for entry in std::fs::read_dir(&src).map_err(|e| e.to_string())? {
            entries += 1;
            if entries > 32768 {
                return Err("feature data overlay entry count exceeds bound".into());
            }
            let entry = entry.map_err(|e| e.to_string())?;
            let meta = entry.path().symlink_metadata().map_err(|e| e.to_string())?;
            if meta.is_dir() {
                pending.push((entry.path(), dst.join(entry.file_name())));
            } else if meta.is_file() {
                files += 1;
                bytes += meta.len();
                if files > 16384 || bytes > 64 * 1024 * 1024 {
                    return Err("feature data overlay exceeds bound".into());
                }
                copy(
                    &entry.path(),
                    &dst.join(entry.file_name()),
                    16 * 1024 * 1024,
                    0o644,
                )?;
            } else {
                return Err("feature data overlay contains a link or special file".into());
            }
        }
    }
    Ok(())
}
