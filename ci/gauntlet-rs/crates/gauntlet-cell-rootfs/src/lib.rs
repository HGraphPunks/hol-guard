//! Trusted constructor only. Candidate code never executes with Root IDs.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod construct;
pub mod declarations;
mod fs_input;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod image_lease;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod image_lock;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod image_process;
mod image_protocol;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod inputs;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod kernel_descriptors;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod kernel_mounts;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod kernel_process;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod kernel_status;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod mounts;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod preparation;
mod preparation_spec;
mod spec;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod supervisor;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod supervisor_capture;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod supervisor_cleanup;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod supervisor_io;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod supervisor_journal;
mod supervisor_spec;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use kernel_process::{CellProcessExpectation, HeldCellProcess};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use preparation::prepare_and_start;
pub use preparation_spec::CellPreparation;
pub use spec::{NetworkProfile, RootfsSpec, StateProfile};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use supervisor::NativeCell;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use supervisor_capture::{CapturedProcess, ProcessChunk};
pub use supervisor_spec::{CpuProfile, SupervisorSpec};
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

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) fn nonce() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut raw = [0u8; 16];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| "Root cell randomness unavailable")?;
    Ok(raw.iter().map(|byte| format!("{byte:02x}")).collect())
}
