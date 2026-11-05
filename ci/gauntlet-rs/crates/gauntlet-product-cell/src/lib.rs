//! Product processes have no collector, signing, provider or Root authority.
//! The outside supervisor still measures their namespaces, process identity,
//! executable bytes, descriptors and resource restrictions before release.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod actor;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod actor_process;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod actor_start;
mod exec_gate;
mod layout;
mod network;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod root_input;
mod seccomp;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod seccomp_library;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use actor_start::run_actor;
pub use exec_gate::{run_exec_gate, validate_product_argv, READY};
pub use layout::{load_root_layout, parse_layout, CellLayout};
pub use network::{observe_private_loopback, validate_private_topology};
pub use seccomp::{
    install_product_filter, validate_product_seccomp, NetworkProfile, LIBRARY_SHA256,
    PROFILE_SHA256,
};
#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
pub fn run_actor() -> Result<()> {
    Err(CellError("product-cell actor requires native Linux ARM64"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellError(pub &'static str);
impl std::fmt::Display for CellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for CellError {}
pub type Result<T> = std::result::Result<T, CellError>;
