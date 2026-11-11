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

// Evidence storage can be exhausted by an unprivileged task. Keep attempting
// each independently owned cleanup, while any failed observation or commit
// prevents a successful cleanup result.
pub(crate) fn remember<T>(failures: &mut Vec<String>, result: Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            failures.push(error);
            None
        }
    }
}

impl NativeCell {
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let mut failures = Vec::new();
        let mut stop_error = None;
        let mut client_reaped = false;
        if self.service_started {
            client_reaped = remember(
                &mut failures,
                self.process
                    .as_mut()
                    .map(|child| child.try_wait())
                    .transpose()
                    .map_err(|e| e.to_string()),
            )
            .flatten()
            .flatten()
            .is_some();
            let already_collected = self.service_observed
                && client_reaped
                && remember(&mut failures, absent(&self.cgroup)) == Some(true);
            if already_collected {
                let checked = self
                    .spec
                    .host_helpers
                    .get("/usr/bin/systemctl")
                    .ok_or_else(|| "systemctl pin missing".to_owned())
                    .and_then(|pin| {
                        crate::fs_input::pinned(
                            Path::new("/usr/bin/systemctl"),
                            16 * 1024 * 1024,
                            pin,
                        )
                    });
                remember(&mut failures, checked);
                remember(
                    &mut failures,
                    self.journal.append(
                        "unit-already-collected",
                        json!({"cgroup_absent":true,"systemd_client_reaped":true}),
                    ),
                );
            } else if let Err(e) = self.run_helper(
                "/usr/bin/systemctl",
                &["stop".into(), format!("{}.service", self.profile)],
                Duration::from_secs(5),
            ) {
                stop_error = Some(e);
            }
            if let Some(child) = &mut self.process {
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => {
                            client_reaped = true;
                            break;
                        }
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
                remember(
                    &mut failures,
                    self.journal.append(
                        "cell-stderr",
                        json!({"data":String::from_utf8_lossy(&diagnostic)}),
                    ),
                );
            }
        }
        if let Err(error) = self.close_process_events() {
            failures.push(error);
        }
        if let Err(error) = self.close_native_wire() {
            failures.push(error);
        }
        let cgroup_absent = remember(&mut failures, absent(&self.cgroup)) == Some(true);
        if !cgroup_absent {
            failures.push("owned product cgroup survived stop".into());
        }
        if let Some(error) = stop_error {
            // --collect can remove a finished unit between a sample and Stop.
            // Only an actually measured unit, dead client, absent cgroup and
            // unchanged helper bytes can reconcile that diagnostic.
            let unchanged_helper = self
                .spec
                .host_helpers
                .get("/usr/bin/systemctl")
                .is_some_and(|pin| {
                    crate::fs_input::pinned(Path::new("/usr/bin/systemctl"), 16 * 1024 * 1024, pin)
                        .is_ok()
                });
            if self.service_observed && client_reaped && cgroup_absent && unchanged_helper {
                remember(
                    &mut failures,
                    self.journal.append(
                        "stop-reconciled-after-collection",
                        json!({"diagnostic":error,"cgroup_absent":true,"systemd_client_reaped":true}),
                    ),
                );
            } else {
                failures.push(error);
            }
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
        let encoded = self
            .inputs
            .spec
            .stage
            .join("rootfs")
            .to_string_lossy()
            .replace('\\', "\\134")
            .replace(' ', "\\040");
        let mounts = kernel_file(Path::new("/proc/thread-self/mountinfo"), 2 * 1024 * 1024)
            .and_then(|raw| String::from_utf8(raw).map_err(|_| "mountinfo UTF-8".into()))
            .and_then(|mounts| {
                let mut absent = true;
                for line in mounts.lines() {
                    if line
                        .split_ascii_whitespace()
                        .nth(4)
                        .ok_or("malformed outside mountinfo")?
                        == encoded
                    {
                        absent = false;
                    }
                }
                Ok(absent)
            });
        let rootfs_absent = remember(&mut failures, mounts) == Some(true);
        if !rootfs_absent {
            failures.push("owned rootfs mount survived stop".into());
        }
        let profiles = kernel_file(
            Path::new("/sys/kernel/security/apparmor/profiles"),
            1024 * 1024,
        )
        .and_then(|raw| String::from_utf8(raw).map_err(|_| "AppArmor inventory UTF-8".into()))
        .map(|profiles| {
            !profiles
                .lines()
                .any(|line| line.split_ascii_whitespace().next() == Some(self.profile.as_str()))
        });
        if remember(&mut failures, profiles) != Some(true) {
            failures.push("owned AppArmor profile survived removal".into());
        }
        match gauntlet_evidence::inventory_tree(
            &self.inputs.runtime.prefix,
            gauntlet_evidence::TreeKind::InstalledPrefix,
        ) {
            Ok(tree) if tree.digest == self.inputs.runtime.tree_digest => {}
            _ => failures.push("installed runtime prefix changed or readback unavailable".into()),
        }
        let terminal = json!({"cgroup_absent":cgroup_absent,"rootfs_mount_absent":rootfs_absent,"failures":failures});
        remember(
            &mut failures,
            self.journal.append("terminal-cleanup", terminal),
        );
        if cgroup_absent && rootfs_absent {
            if let Some(image) = &mut self.image {
                image.after_cell_absent();
                if remember(&mut failures, image.close()).is_some() {
                    remember(
                        &mut failures,
                        self.journal.append(
                            "rust-image-cleanup",
                            json!({"image_mount_absent":true,"active_lease_removed":true}),
                        ),
                    );
                }
            }
        }
        if !failures.is_empty() {
            return Err("native product cleanup incomplete; retain unknown state".into());
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
