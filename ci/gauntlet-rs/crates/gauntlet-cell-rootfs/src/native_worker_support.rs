//! Fixed worker-side ownership checks; no caller-selected Root action exists.
use crate::{fs_input, Result};
use std::path::Path;

pub fn require_outside_root() -> Result<()> {
    crate::kernel_process::root_proc().map(|_| ())
}

pub fn begin_owned_job_slice(
    job_id: &str,
    systemctl_sha256: &str,
    mutation_attempted: &mut bool,
) -> Result<()> {
    crate::kernel_process::root_proc()?;
    if !crate::hex(job_id, 16) {
        return Err("exact native job ID required".into());
    }
    let name = format!("holgauntletrust{job_id}.slice");
    let root = Path::new("/sys/fs/cgroup");
    fs_input::directory(root)?;
    if !crate::supervisor_cleanup::absent(&root.join(&name))? {
        return Err("native job slice already exists".into());
    }
    verify_systemctl(systemctl_sha256)?;
    // The worker leases serialize participating owners. A preexisting slice
    // or wrong helper pin cannot authorize cleanup of someone else's unit.
    *mutation_attempted = true;
    crate::supervisor_io::helper(
        "/usr/bin/systemctl",
        &["start".into(), name.clone()],
        std::time::Duration::from_secs(5),
    )?;
    verify_systemctl(systemctl_sha256)?;
    fs_input::directory(&root.join(name))?;
    Ok(())
}

pub fn verify_systemctl(expected: &str) -> Result<()> {
    fs_input::pinned(Path::new("/usr/bin/systemctl"), 16 * 1024 * 1024, expected)?;
    Ok(())
}

pub fn require_image_lease_absent(image: &str, podman_sha256: &str) -> Result<()> {
    crate::kernel_process::root_proc()?;
    let id = crate::image_protocol::image_id(image)?;
    let root = Path::new("/var/lib/hol-gauntlet-rust/cell-image-leases");
    match std::fs::symlink_metadata(root) {
        Ok(_) => {
            fs_input::directory(root)?;
            if !crate::supervisor_cleanup::absent(&root.join(format!("{id}.active.json")))? {
                return Err("native image lease is active or unresolved".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let raw = crate::image_process::run(
        podman_sha256,
        crate::image_process::Operation::Inventory,
        image,
    )?;
    if crate::image_protocol::mounted(&raw, image)?.is_some() {
        return Err("native dependency image is still mounted".into());
    }
    Ok(())
}
