//! Trusted constructor only. Candidate code never executes with Root IDs.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod construct;
pub mod declarations;
mod fs_input;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod inputs;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod mounts;
mod spec;

pub use spec::{NetworkProfile, RootfsSpec, StateProfile};
pub type Result<T> = std::result::Result<T, String>;

/// This entry point can only mutate a fresh private Root PID1 namespace.
/// Successful construction never returns: the fixed initializer drops all
/// privilege and waits for the outside collector's gate before actor execution.
pub fn construct_from_file(path: &std::path::Path, expected_sha256: &str) -> Result<()> {
    let raw = fs_input::pinned(path, 8192, expected_sha256)?;
    let spec = RootfsSpec::parse(&raw, expected_sha256)?;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        inputs::check_private_boundary(&spec)?;
        construct::run(inputs::load(spec)?)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let _ = spec;
        Err("native Linux ARM64 Root PID1 constructor required".into())
    }
}

pub(crate) fn hash(raw: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(raw))
}

pub(crate) fn hex(raw: &str, length: usize) -> bool {
    raw.len() == length
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
