//! Separate fixed cgroup profile for a trusted builder-image construction.
//! The eventual candidate container has its own Podman limits and custody.

use crate::contained_probe::{CgroupProbeError, GroupLimits, OwnedProbeGroup};
use crate::hex;
use gauntlet_contracts::FeatureRunIntent;
use serde_json::{json, Value};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::process::Command;

const LIMITS: GroupLimits = GroupLimits {
    memory: "12884901888\n",
    pids: "512\n",
    cpu: "200000 100000\n",
};

pub(crate) struct OwnedBuilderCgroup {
    inner: OwnedProbeGroup,
}

pub(crate) struct OwnedCandidateCgroup {
    inner: OwnedProbeGroup,
}

impl OwnedBuilderCgroup {
    pub(crate) fn create(job_id: &str) -> Result<Self, CgroupProbeError> {
        if !hex(job_id, 16) {
            return Err(CgroupProbeError::InvalidJobId);
        }
        let name = format!("hol-gauntlet-rust-builder-{job_id}");
        let path = format!("/system.slice/{name}");
        Ok(Self {
            inner: OwnedProbeGroup::create_named(name, path, LIMITS)?,
        })
    }

    pub(crate) fn path(&self) -> &str {
        self.inner.path()
    }

    pub(crate) fn attach_child(&self, command: &mut Command) -> Result<(), CgroupProbeError> {
        self.inner.attach_child(command)
    }

    pub(crate) fn kill(&self) -> Result<(), CgroupProbeError> {
        self.inner.kill()
    }

    pub(crate) fn drain_and_remove(&mut self) -> Result<(), CgroupProbeError> {
        self.inner.drain_and_remove()
    }
}

impl OwnedCandidateCgroup {
    pub(crate) fn retain_feature(
        &self,
        slot: &OwnedFd,
        intent: &FeatureRunIntent,
    ) -> Result<(), String> {
        let id = intent.pins().audit_id();
        if self.path() != format!("/system.slice/hol-gauntlet-rust-feature-{id}") {
            return Err("feature cgroup differs from intent".into());
        }
        let (device, inode) = self.inner.identity().map_err(|e| e.to_string())?;
        let body = json!({"schema":"hol-gauntlet-native-feature-client-cgroup.v1",
            "audit_id":id,"intent_sha256":intent.digest()?,"cgroup":self.path(),
            "boot_id":boot_id()?,"device":device,"inode":inode});
        let raw = gauntlet_contracts::canonicalize(body.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        crate::feature_files::write(slot, "feature-client-cgroup.v1.json", &raw, (0, 0), 0o600)?;
        if self.inner.identity().map_err(|e| e.to_string())? != (device, inode) {
            return Err("feature cgroup changed during identity commit".into());
        }
        Ok(())
    }

    pub(crate) fn reopen_feature(
        slot: Option<&OwnedFd>,
        intent: &FeatureRunIntent,
    ) -> Result<Option<Self>, String> {
        let raw = slot
            .map(|slot| {
                crate::feature_files::read(
                    slot,
                    "feature-client-cgroup.v1.json",
                    (0, 0),
                    0o600,
                    2048,
                )
            })
            .transpose()?
            .flatten();
        let retained = raw
            .as_deref()
            .map(|raw| feature_identity(raw, intent))
            .transpose()?;
        let id = intent.pins().audit_id();
        let name = format!("hol-gauntlet-rust-feature-{id}");
        let path = format!("/system.slice/{name}");
        match std::fs::symlink_metadata(format!("/sys/fs/cgroup{path}")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
            Ok(_) => {}
        }
        let (boot, device, inode) =
            retained.ok_or("active feature cgroup lacks retained kernel identity")?;
        if boot != boot_id()? {
            return Err("feature cgroup boot identity differs".into());
        }
        Ok(Some(Self {
            inner: OwnedProbeGroup::reopen_named(name, path, (device, inode))
                .map_err(|e| e.to_string())?,
        }))
    }

    pub(crate) fn create(job_id: &str) -> Result<Self, CgroupProbeError> {
        Self::with_profile(job_id, false)
    }

    pub(crate) fn create_feature(job_id: &str) -> Result<Self, CgroupProbeError> {
        Self::with_profile(job_id, true)
    }

    fn with_profile(job_id: &str, feature: bool) -> Result<Self, CgroupProbeError> {
        if !hex(job_id, 16) {
            return Err(CgroupProbeError::InvalidJobId);
        }
        let kind = if feature { "feature" } else { "candidate" };
        let name = format!("hol-gauntlet-rust-{kind}-{job_id}");
        let path = format!("/system.slice/{name}");
        Ok(Self {
            inner: OwnedProbeGroup::create_named(
                name,
                path,
                if feature {
                    GroupLimits {
                        pids: "2048\n",
                        ..LIMITS
                    }
                } else {
                    LIMITS
                },
            )?,
        })
    }

    pub(crate) fn path(&self) -> &str {
        self.inner.path()
    }

    pub(crate) fn attach_child(&self, command: &mut Command) -> Result<(), CgroupProbeError> {
        self.inner.attach_child(command)
    }

    pub(crate) fn kill(&self) -> Result<(), CgroupProbeError> {
        self.inner.kill()
    }

    pub(crate) fn drain_and_remove(&mut self) -> Result<(), CgroupProbeError> {
        self.inner.drain_and_remove()
    }
}

fn valid_boot_id(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn boot_id() -> Result<String, String> {
    let mut raw = String::new();
    std::fs::File::open("/proc/sys/kernel/random/boot_id")
        .map_err(|e| e.to_string())?
        .take(38)
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())?;
    let text = raw
        .strip_suffix('\n')
        .filter(|s| valid_boot_id(s))
        .ok_or("kernel boot identity unavailable")?;
    Ok(text.into())
}
fn feature_identity(raw: &[u8], intent: &FeatureRunIntent) -> Result<(String, u64, u64), String> {
    let v: Value = crate::feature_journal::canonical(raw)?;
    let boot = v["boot_id"]
        .as_str()
        .filter(|s| valid_boot_id(s))
        .ok_or("feature cgroup boot identity missing")?;
    let device = v["device"]
        .as_u64()
        .ok_or("feature cgroup device missing")?;
    let inode = v["inode"]
        .as_u64()
        .filter(|n| *n != 0)
        .ok_or("feature cgroup inode missing")?;
    if v.as_object().is_none_or(|v| v.len() != 7)
        || v["schema"] != "hol-gauntlet-native-feature-client-cgroup.v1"
        || v["audit_id"] != intent.pins().audit_id()
        || v["intent_sha256"] != intent.digest()?
        || v["cgroup"]
            != format!(
                "/system.slice/hol-gauntlet-rust-feature-{}",
                intent.pins().audit_id()
            )
    {
        return Err("feature cgroup receipt differs from reserved intent".into());
    }
    Ok((boot.into(), device, inode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_unbounded_or_nonjob_cgroup_names() {
        assert!(matches!(
            OwnedBuilderCgroup::create("../../system.slice"),
            Err(CgroupProbeError::InvalidJobId)
        ));
    }

    #[test]
    fn feature_kernel_receipt_is_closed_and_bound_to_its_outside_intent() {
        let intent = crate::feature_journal::tests::fixture();
        let v = json!({"schema":"hol-gauntlet-native-feature-client-cgroup.v1",
            "audit_id":intent.pins().audit_id(),"intent_sha256":intent.digest().unwrap(),
            "cgroup":format!("/system.slice/hol-gauntlet-rust-feature-{}",intent.pins().audit_id()),
            "boot_id":"01234567-89ab-cdef-0123-456789abcdef","device":29,"inode":42});
        let raw = gauntlet_contracts::canonicalize(v.to_string().as_bytes()).unwrap();
        assert_eq!(feature_identity(&raw, &intent).unwrap().1, 29);
        for (key, wrong) in [
            ("schema", json!("other")),
            ("audit_id", json!("f".repeat(16))),
            ("intent_sha256", json!("f".repeat(64))),
            ("cgroup", json!("/system.slice/other")),
            ("boot_id", json!("01234567-89ab-cdef-0123-456789abcdeF")),
            ("device", json!(29.0)),
            ("inode", json!(0)),
            ("extra", json!(null)),
        ] {
            let mut changed = v.clone();
            changed[key] = wrong;
            let raw = gauntlet_contracts::canonicalize(changed.to_string().as_bytes()).unwrap();
            assert!(feature_identity(&raw, &intent).is_err(), "{key}");
        }
    }

    #[test]
    #[ignore = "requires the owned Linux VM, Root and both worker leases"]
    fn feature_recovery_reopens_only_the_original_kernel_group() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::ExitStatusExt;
        let main = crate::RunReservationJournal::open_root_owned(std::path::Path::new(
            crate::builder_image_context::RUST_STATE,
        ))
        .unwrap();
        let lease = main.acquire_active_lease().unwrap();
        let legacy = crate::builder_image_context::python_worker_lock().unwrap();
        let mut v: Value =
            serde_json::from_slice(&crate::feature_journal::tests::fixture().bytes().unwrap())
                .unwrap();
        let id = format!("f1{:014x}", std::process::id());
        v["pins"]["executor_spec"]["audit_id"] = json!(id);
        let intent = FeatureRunIntent::parse(
            &gauntlet_contracts::canonicalize(v.to_string().as_bytes()).unwrap(),
        )
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let slot = rustix::fs::open(
            temp.path(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let group = OwnedCandidateCgroup::create_feature(&id).unwrap();
        assert!(OwnedCandidateCgroup::reopen_feature(Some(&slot), &intent).is_err());
        group.retain_feature(&slot, &intent).unwrap();
        let receipt_path = temp.path().join("feature-client-cgroup.v1.json");
        let original = std::fs::read(&receipt_path).unwrap();
        let spawn = |group: &OwnedCandidateCgroup| {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "/usr/bin/sleep 30 & wait"]);
            group.attach_child(&mut command).unwrap();
            let child = command.spawn().unwrap();
            let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while group.inner.tasks().unwrap() < 2 {
                assert!(
                    std::time::Instant::now() < until,
                    "child and descendant were not both observed"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            child
        };
        let mut child = spawn(&group);
        for (key, wrong) in [
            ("inode", json!(u64::MAX)),
            ("boot_id", json!("00000000-0000-0000-0000-000000000000")),
        ] {
            let mut changed: Value = serde_json::from_slice(&original).unwrap();
            changed[key] = wrong;
            std::fs::write(
                &receipt_path,
                gauntlet_contracts::canonicalize(changed.to_string().as_bytes()).unwrap(),
            )
            .unwrap();
            assert!(OwnedCandidateCgroup::reopen_feature(Some(&slot), &intent).is_err());
            assert!(child.try_wait().unwrap().is_none());
        }
        std::fs::write(&receipt_path, b"{").unwrap();
        assert!(OwnedCandidateCgroup::reopen_feature(Some(&slot), &intent).is_err());
        assert!(child.try_wait().unwrap().is_none());
        std::fs::write(&receipt_path, original).unwrap();
        let mut reopened = OwnedCandidateCgroup::reopen_feature(Some(&slot), &intent)
            .unwrap()
            .unwrap();
        reopened.kill().unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
        reopened.drain_and_remove().unwrap();
        assert!(OwnedCandidateCgroup::reopen_feature(Some(&slot), &intent)
            .unwrap()
            .is_none());
        let mut replacement = OwnedCandidateCgroup::create_feature(&id).unwrap();
        let mut replacement_child = spawn(&replacement);
        assert!(OwnedCandidateCgroup::reopen_feature(Some(&slot), &intent).is_err());
        assert!(replacement_child.try_wait().unwrap().is_none());
        replacement.kill().unwrap();
        assert_eq!(
            replacement_child.wait().unwrap().signal(),
            Some(libc::SIGKILL)
        );
        replacement.drain_and_remove().unwrap();
        lease.verify(&main.root).unwrap();
        crate::builder_image_context::verify_python_lock(&legacy).unwrap();
    }
}
