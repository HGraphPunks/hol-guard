//! Only the fixed Root Rust controller inherits this sealed key descriptor.
//! It is closed before any product, SDK or MCP child can be launched.
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

pub(crate) const NATIVE_CONTROLLER_KEY_FD: libc::c_int = 3;
const SEALS: libc::c_int =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

fn consume(mut file: File, expected_public: &str) -> Result<Ed25519KeyPair, String> {
    if unsafe { libc::geteuid() } != 0 || !crate::hex(expected_public, 64) {
        return Err("Root and pinned native controller public key required".into());
    }
    let before = file.metadata().map_err(|e| e.to_string())?;
    let descriptor = file.as_raw_fd();
    let seals = unsafe { libc::fcntl(descriptor, libc::F_GET_SEALS) };
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 0
        || before.len() != 32
        || before.mode() & 0o7777 != 0o600
        || seals < 0
        || seals & SEALS != SEALS
        || flags < 0
        || flags & libc::FD_CLOEXEC == 0
    {
        return Err("private sealed native controller key custody differs".into());
    }
    let mut seed = [0u8; 32];
    let read = file.read_exact(&mut seed);
    let key = if read.is_ok() {
        Ed25519KeyPair::from_seed_unchecked(&seed).ok()
    } else {
        None
    };
    seed.fill(0);
    read.map_err(|_| "complete native controller seed unavailable")?;
    let key = key.ok_or("native controller signing key invalid")?;
    let public = key
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let after = file.metadata().map_err(|e| e.to_string())?;
    if public != expected_public
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
    {
        return Err("native controller inherited key differs from prelaunch pin".into());
    }
    // The descriptor is dropped here, before returning the signing capability.
    Ok(key)
}

pub(crate) fn consume_inherited_native_controller_key(
    expected_public: &str,
) -> Result<Ed25519KeyPair, String> {
    let descriptor = NATIVE_CONTROLLER_KEY_FD;
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err("fixed inherited native controller key descriptor unavailable".into());
    }
    // SAFETY: the fixed exec contract transfers this valid descriptor once.
    consume(unsafe { File::from_raw_fd(descriptor) }, expected_public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_key::SealedControllerKey;
    #[test]
    fn native_key_consumer_accepts_only_the_exact_sealed_generated_identity() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let key = SealedControllerKey::generate().unwrap();
        let file = key.fd().try_clone().unwrap();
        let descriptor = file.as_raw_fd();
        let inode = file.metadata().unwrap().ino();
        let consumed = consume(file, key.public_key_hex()).unwrap();
        let public = consumed
            .public_key()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(public, key.public_key_hex());
        if let Ok(reused) = std::fs::metadata(format!("/proc/self/fd/{descriptor}")) {
            assert_ne!(reused.ino(), inode, "consumed key descriptor remains open");
        }
    }
    #[test]
    fn another_prelaunch_key_or_an_unsealed_file_cannot_be_consumed() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let key = SealedControllerKey::generate().unwrap();
        assert!(consume(key.fd().try_clone().unwrap(), &"0".repeat(64)).is_err());
        let mut ordinary = tempfile::tempfile().unwrap();
        use std::io::{Seek, SeekFrom, Write};
        ordinary.write_all(&[37; 32]).unwrap();
        ordinary.seek(SeekFrom::Start(0)).unwrap();
        assert!(consume(ordinary, key.public_key_hex()).is_err());
    }
}
