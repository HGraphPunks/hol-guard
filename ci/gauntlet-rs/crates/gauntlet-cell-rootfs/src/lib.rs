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
mod native_apparatus;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_binding_fixture;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_boundary_control;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod native_boundary_result;
mod native_case;
mod native_control_role;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_forbidden_fixture;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_guard;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_guard_control;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_guard_fixture;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_guard_forbidden;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod native_guard_negative_cases;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_guard_negatives;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_guard_probe;
mod native_guard_spec;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod native_hook_calls;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_lifecycle_control;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_lifecycle_kernel;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod native_lifecycle_ready;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod native_lifecycle_spec;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod native_request;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_worker_support;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod preparation;
mod preparation_spec;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod recovery;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod recovery_protocol;
mod spec;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod supervisor;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod supervisor_capture;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
mod supervisor_capture_input;
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
pub use native_apparatus::run_native_apparatus;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use native_boundary_control::NativeBoundaryControl;
pub use native_case::{NativeApparatusReport, NativeCase};
pub use native_control_role::NativeControlRole;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use native_guard::{NativeHookPlane, NativeLifecycleExecution};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use native_guard_control::run_native_hook_transport;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use native_guard_fixture::{
    effect as read_native_hook_fixture_effect, seed as seed_native_hook_fixture,
    seed_boundary as seed_native_boundary_fixture, seed_control as seed_native_control_fixture,
    seed_lifecycle as seed_native_lifecycle_fixture, seed_sdk as seed_native_sdk_fixture,
};
pub use native_guard_spec::NativeGuardPins;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use native_worker_support::{
    begin_owned_job_slice, require_image_lease_absent, require_outside_root,
    verify_preparation_host_helpers, verify_systemctl,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use preparation::prepare_and_start;
pub use preparation_spec::CellPreparation;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use recovery::{
    native_preparation_image_history, recover_quiescent_preparation,
    verify_closed_native_preparation, verify_quiescent_preparation,
};
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub use recovery_protocol::NativeImageHistory;
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
