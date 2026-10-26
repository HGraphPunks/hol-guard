//! Stop only this owned service and retain every uncertain cleanup.
use crate::supervisor_io::kernel_file;
use crate::{NativeCell, Result};
use serde_json::json;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) fn absent(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.to_string()),
        Ok(_) => Ok(false),
    }
}

impl NativeCell {
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let mut failures = Vec::new();
        if self.service_started {
            if let Err(e) = self.run_helper(
                "/usr/bin/systemctl",
                &["stop".into(), format!("{}.service", self.profile)],
                Duration::from_secs(5),
            ) {
                failures.push(e);
            }
            if let Some(child) = &mut self.process {
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) => {}
                        Err(e) => {
                            failures.push(e.to_string());
                            break;
                        }
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        failures.push("owned systemd client did not reap".into());
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        self.client = None;
        if let Some(pipe) = self.errors.take() {
            let mut diagnostic = Vec::new();
            loop {
                let mut raw = [0u8; 4096];
                match rustix::io::read(&pipe, &mut raw) {
                    Ok(0) => break,
                    Ok(n) => diagnostic.extend_from_slice(&raw[..n]),
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(rustix::io::Errno::AGAIN) => break,
                    Err(e) => {
                        failures.push(e.to_string());
                        break;
                    }
                }
                if diagnostic.len() > 65536 {
                    failures.push("product diagnostic byte bound".into());
                    break;
                }
            }
            if !diagnostic.is_empty() {
                self.journal.append(
                    "cell-stderr",
                    json!({"data":String::from_utf8_lossy(&diagnostic)}),
                )?;
            }
        }
        let cgroup_absent = absent(&self.cgroup)?;
        if !cgroup_absent {
            failures.push("owned product cgroup survived stop".into());
        }
        if self.loaded {
            match self.run_helper(
                "/usr/sbin/apparmor_parser",
                &[
                    "--remove".into(),
                    self.inputs
                        .spec
                        .stage
                        .join("native-cell.apparmor")
                        .to_string_lossy()
                        .into(),
                ],
                Duration::from_secs(10),
            ) {
                Ok(()) => self.loaded = false,
                Err(e) => failures.push(e),
            }
        }
        let mounts = String::from_utf8(kernel_file(
            Path::new("/proc/self/mountinfo"),
            2 * 1024 * 1024,
        )?)
        .map_err(|_| "mountinfo UTF-8")?;
        let encoded = self
            .inputs
            .spec
            .stage
            .join("rootfs")
            .to_string_lossy()
            .replace('\\', "\\134")
            .replace(' ', "\\040");
        let mut rootfs_absent = true;
        for line in mounts.lines() {
            if line
                .split_ascii_whitespace()
                .nth(4)
                .ok_or("malformed outside mountinfo")?
                == encoded
            {
                rootfs_absent = false;
            }
        }
        if !rootfs_absent {
            failures.push("owned rootfs mount survived stop".into());
        }
        let profiles = String::from_utf8(kernel_file(
            Path::new("/sys/kernel/security/apparmor/profiles"),
            1024 * 1024,
        )?)
        .map_err(|_| "AppArmor inventory UTF-8")?;
        if profiles
            .lines()
            .any(|line| line.split_ascii_whitespace().next() == Some(self.profile.as_str()))
        {
            failures.push("owned AppArmor profile survived removal".into());
        }
        match gauntlet_evidence::inventory_tree(
            &self.inputs.runtime.prefix,
            gauntlet_evidence::TreeKind::InstalledPrefix,
        ) {
            Ok(tree) if tree.digest == self.inputs.runtime.tree_digest => {}
            _ => failures.push("installed runtime prefix changed or readback unavailable".into()),
        }
        self.journal.append("terminal-cleanup",json!({"cgroup_absent":cgroup_absent,"rootfs_mount_absent":rootfs_absent,"failures":failures}))?;
        if !failures.is_empty() {
            return Err("native product cleanup incomplete; retain unknown state".into());
        }
        if let Some(image) = &mut self.image {
            image.after_cell_absent();
            image.close()?;
            self.journal.append(
                "rust-image-cleanup",
                json!({"image_mount_absent":true,"active_lease_removed":true}),
            )?;
        }
        self.closed = true;
        Ok(())
    }
}

impl Drop for NativeCell {
    fn drop(&mut self) {
        if !self.closed {
            if let Err(error) = self.close() {
                eprintln!("native product cell cleanup uncertain: {error}");
            }
        }
    }
}
