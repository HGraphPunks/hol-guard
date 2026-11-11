//! Closed writable-volume capacities. Runtime byte/log bounds are separate
//! from these filesystem block and inode ceilings.
use serde_json::{json, Value};
use std::{path::PathBuf, str::FromStr};

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_admission.rs"]
pub(crate) mod admission;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_artifact.rs"]
pub(crate) mod artifact;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_initialize.rs"]
mod initialize;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_lifecycle.rs"]
pub(crate) mod lifecycle;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_owner.rs"]
pub(crate) mod owner;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use owner::run_storage_namespace_owner;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_linux.rs"]
pub(crate) mod linux;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_native.rs"]
pub(crate) mod native;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_retire.rs"]
pub(crate) mod retire;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_source.rs"]
pub(crate) mod source;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use native::{abort_initialized_native_job_storage, retire_native_job_storage};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use retire::abort_native_job_storage;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_job_storage_dispatch.rs"]
mod dispatch;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use dispatch::dispatch_native_job_storage;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use initialize::initialize_native_job_v2;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use source::retire_source_job_storage;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobStorageProfile {
    Native,
    Build,
    Dependency,
}
impl FromStr for JobStorageProfile {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, String> {
        match value {
            "native-v1" => Ok(Self::Native),
            "build-v1" => Ok(Self::Build),
            "dependency-v1" => Ok(Self::Dependency),
            _ => Err("closed job storage profile required".into()),
        }
    }
}
impl JobStorageProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native-v1",
            Self::Build => "build-v1",
            Self::Dependency => "dependency-v1",
        }
    }
    pub fn bytes(self) -> u64 {
        (match self {
            Self::Native => 2,
            Self::Build => 12,
            Self::Dependency => 4,
        }) * 1024
            * 1024
            * 1024
    }
    pub fn inode_ceiling(self) -> u64 {
        match self {
            Self::Native => 65536,
            Self::Build => 262144,
            Self::Dependency => 131072,
        }
    }
    pub fn format_inodes(self) -> u64 {
        // mke2fs rounds to whole inode-table blocks in every block group.
        // Twelve GiB has96 groups:261120 is safe;262144 would round upward.
        let groups = self.bytes() / (4096 * 32768);
        self.inode_ceiling() / (groups * 16) * (groups * 16)
    }
    pub fn root(self, job: &str) -> Result<PathBuf, String> {
        if !crate::hex(job, 16) {
            return Err("exact one-use storage job ID required".into());
        }
        Ok(PathBuf::from(match self {
            Self::Native => "/var/lib/hol-gauntlet-rust/native-jobs",
            Self::Build | Self::Dependency => "/var/lib/hol-gauntlet/builds",
        })
        .join(job))
    }
    pub fn limits(self) -> Value {
        json!({"schema":"hol-gauntlet-job-storage-limits.v1","profile":self.as_str(),
        "bytes":self.bytes(),"inodes":self.inode_ceiling(),"format_inodes":self.format_inodes(),"block_size":4096})
    }
}

pub struct JobStoragePins<'a> {
    pub source_sha: &'a str,
    pub job_id: &'a str,
    pub worker_generation: &'a str,
    pub mke2fs_sha256: &'a str,
}
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn private_ancestor(raw: &str, target: &str) -> Result<(), String> {
    if raw.len() > 2 * 1024 * 1024 || !target.starts_with('/') {
        return Err("bounded absolute mount ancestry required".into());
    }
    let target = std::path::Path::new(target);
    let mut selected: Option<(usize, bool)> = None;
    for line in raw.lines() {
        let row = line.split_ascii_whitespace().collect::<Vec<_>>();
        if row.len() < 10 {
            return Err("malformed kernel mount ancestry".into());
        }
        let path = std::path::Path::new(row[4]);
        if !target.starts_with(path) {
            continue;
        }
        let separator = row
            .iter()
            .position(|f| *f == "-")
            .ok_or("mount ancestry separator absent")?;
        let length = row[4].len();
        if selected.as_ref().is_none_or(|(n, _)| length > *n) {
            selected = Some((length, separator == 6));
        }
    }
    if selected.is_none_or(|(_, private)| !private) {
        return Err(
            "storage target ancestor is not private; allocation refused before backing creation"
                .into(),
        );
    }
    Ok(())
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn tmpfs_limits() -> [(&'static str, u64, u64); 4] {
    [
        ("/tmp", 16777216, 4096),
        ("/var/tmp", 16777216, 4096),
        ("/run", 16777216, 4096),
        ("/dev/shm", 67108864, 16384),
    ]
}
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn check_tmpfs(value: &Value) -> Result<usize, String> {
    let Some(tmpfs) = value["HostConfig"]["Tmpfs"]
        .as_object()
        .filter(|o| !o.is_empty())
    else {
        return Ok(0);
    };
    if tmpfs.len() != 4 {
        return Err("closed Native tmpfs inventory required".into());
    }
    for (target, bytes, inodes) in tmpfs_limits() {
        let opts = tmpfs
            .get(target)
            .and_then(Value::as_str)
            .ok_or("bounded Native tmpfs absent")?;
        let options = opts.split(',').collect::<std::collections::BTreeSet<_>>();
        if ![
            format!("size={bytes}"),
            format!("nr_inodes={inodes}"),
            "nosuid".into(),
            "nodev".into(),
            "noexec".into(),
        ]
        .iter()
        .all(|s| options.contains(s.as_str()))
            || ["exec", "suid", "dev", "ro"]
                .iter()
                .any(|s| options.contains(s))
        {
            return Err("actual Native tmpfs byte/inode/protection options differ".into());
        }
    }
    Ok(4)
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn ext4_capacity(
    raw: &[u8],
    profile: JobStorageProfile,
    uuid: &str,
) -> Result<Value, String> {
    // Kernel ext4 on-disk ABI: https://docs.kernel.org/filesystems/ext4/super.html
    if raw.len() != 1024 || !crate::hex(uuid, 32) {
        return Err("bounded exact ext4 superblock required".into());
    }
    let u16at = |offset| u16::from_le_bytes(raw[offset..offset + 2].try_into().unwrap());
    let u32at = |offset| u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap());
    let inodes = u64::from(u32at(0));
    let blocks = u64::from(u32at(4)) | (u64::from(u32at(0x150)) << 32);
    let actual_uuid = raw[0x68..0x78]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let groups = profile.bytes() / (4096 * 32768);
    if u16at(0x38) != 0xef53
        || u32at(0x18) != 2
        || u16at(0x58) != 256
        || u32at(0x20) != 32768
        || u64::from(u32at(0x28)) * groups != inodes
        || u32at(0x5c) & 4 == 0
        || u32at(0x60) & 0x40 == 0
        || u16at(0x3c) != 2
        || blocks.checked_mul(4096) != Some(profile.bytes())
        || inodes != profile.format_inodes()
        || inodes > profile.inode_ceiling()
        || actual_uuid != uuid
        || u32at(8) != 0
        || u32at(0x154) != 0
    {
        return Err("actual ext4 capacity/features differ from closed storage profile".into());
    }
    Ok(json!({"kind":"ext4","uuid":uuid,"block_size":4096,"blocks":blocks,"inodes":inodes}))
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn effective_ext4_options(raw: &str) -> Result<(), String> {
    let options = raw.lines().collect::<std::collections::BTreeSet<_>>();
    if raw.len() > 16384
        || options.len() != raw.lines().count()
        || options.len() > 256
        || options
            .iter()
            .any(|s| s.is_empty() || !s.is_ascii() || s.chars().any(char::is_whitespace))
        || !["rw", "nodiscard", "errors=remount-ro"]
            .iter()
            .all(|s| options.contains(s))
        || options.contains("ro")
        || options.contains("discard")
        || options
            .iter()
            .any(|s| s.starts_with("errors=") && *s != "errors=remount-ro")
    {
        return Err("effective ext4 kernel error/discard policy differs".into());
    }
    Ok(())
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn volume_mount(raw: &str, target: &str, device: &str) -> Result<Value, String> {
    if raw.len() > 2 * 1024 * 1024 {
        return Err("bounded kernel mount inventory required".into());
    }
    let mut found = None;
    for line in raw.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.get(4) != Some(&target) {
            continue;
        }
        let separator = fields
            .iter()
            .position(|f| *f == "-")
            .ok_or("kernel volume mount separator absent")?;
        if found.is_some()
            || separator != 6
            || fields.len() != separator + 4
            || fields[2] != device
            || fields[3] != "/"
            || fields[separator + 1] != "ext4"
        {
            return Err("unique exact private ext4 volume mount required".into());
        }
        let options = fields[5]
            .split(',')
            .collect::<std::collections::BTreeSet<_>>();
        let super_options = fields[separator + 3]
            .split(',')
            .collect::<std::collections::BTreeSet<_>>();
        if !["rw", "nosuid", "nodev", "noatime"]
            .iter()
            .all(|v| options.contains(v))
            || ["ro", "suid", "dev", "relatime"]
                .iter()
                .any(|v| options.contains(v))
            || !super_options.contains("rw")
            || super_options
                .iter()
                .any(|s| s.starts_with("errors=") && *s != "errors=remount-ro")
            || super_options.contains("discard")
        {
            return Err("actual retained volume mount protections differ".into());
        }
        let id = fields[0]
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or("actual volume mount ID absent")?;
        found = Some(
            json!({"id":id,"target":target,"device":device,"source":fields[separator+2],"private":true,
            "readonly":false,"nosuid":true,"nodev":true,"noatime":true}),
        );
    }
    found.ok_or("retained job volume mount absent".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn superblock(profile: JobStorageProfile) -> Vec<u8> {
        let mut raw = vec![0; 1024];
        for (offset, value) in [
            (0, profile.format_inodes() as u32),
            (4, (profile.bytes() / 4096) as u32),
            (0x18, 2),
            (0x20, 32768),
            (
                0x28,
                (profile.format_inodes() / (profile.bytes() / (4096 * 32768))) as u32,
            ),
            (0x5c, 4),
            (0x60, 0x40),
        ] {
            raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        raw[0x38..0x3a].copy_from_slice(&0xef53u16.to_le_bytes());
        raw[0x3c..0x3e].copy_from_slice(&2u16.to_le_bytes());
        raw[0x58..0x5a].copy_from_slice(&256u16.to_le_bytes());
        raw[0x68..0x78].fill(0xab);
        raw
    }
    #[test]
    fn actual_capacity_cannot_round_up_or_borrow_a_different_profile() {
        assert_eq!(JobStorageProfile::Build.format_inodes(), 261120);
        for profile in [
            JobStorageProfile::Native,
            JobStorageProfile::Build,
            JobStorageProfile::Dependency,
        ] {
            let raw = superblock(profile);
            ext4_capacity(&raw, profile, &"ab".repeat(16)).unwrap();
            assert!(profile.format_inodes() <= profile.inode_ceiling());
            for other in [
                JobStorageProfile::Native,
                JobStorageProfile::Build,
                JobStorageProfile::Dependency,
            ] {
                if other != profile {
                    assert!(ext4_capacity(&raw, other, &"ab".repeat(16)).is_err());
                }
            }
            for offset in [
                0, 4, 0x18, 0x20, 0x28, 0x38, 0x3c, 0x58, 0x5c, 0x60, 0x68, 0x150,
            ] {
                let mut changed = raw.clone();
                changed[offset] ^= match offset {
                    0x5c => 4,
                    0x60 => 0x40,
                    _ => 1,
                };
                assert!(
                    ext4_capacity(&changed, profile, &"ab".repeat(16)).is_err(),
                    "{offset}"
                );
            }
        }
        assert!("caller-size".parse::<JobStorageProfile>().is_err());
        assert!(JobStorageProfile::Native.root("../escape").is_err());
    }
    #[test]
    fn mount_custody_refuses_stacks_shared_mounts_devices_and_missing_limits() {
        let row="42 1 7:3 / /var/lib/hol-gauntlet-rust/native-jobs/aaaaaaaaaaaaaaaa rw,nosuid,nodev,noatime - ext4 /dev/loop3 rw,errors=remount-ro\n";
        let target = "/var/lib/hol-gauntlet-rust/native-jobs/aaaaaaaaaaaaaaaa";
        assert_eq!(volume_mount(row, target, "7:3").unwrap()["id"], 42);
        let normalized="357 52 7:0 / /var/lib/hol-gauntlet-rust/native-jobs/c5595dd1ddcb5f88 rw,nosuid,nodev,noatime - ext4 /proc/self/fd/13 rw\n";
        assert_eq!(
            volume_mount(
                normalized,
                "/var/lib/hol-gauntlet-rust/native-jobs/c5595dd1ddcb5f88",
                "7:0"
            )
            .unwrap()["id"],
            357
        );
        assert!(volume_mount(&row.repeat(2), target, "7:3").is_err());
        assert!(volume_mount(row, target, "7:4").is_err());
        for (from, to) in [
            (" - ", " shared:17 - "),
            ("ext4", "tmpfs"),
            ("rw,nosuid", "ro,nosuid"),
            ("nodev,", ""),
            ("noatime", "relatime"),
            ("rw,errors=remount-ro", "rw,errors=remount-ro,discard"),
            ("errors=remount-ro", "errors=continue"),
            ("errors=remount-ro", "errors=panic"),
        ] {
            assert!(
                volume_mount(&row.replace(from, to), target, "7:3").is_err(),
                "{from}"
            );
        }
    }
    #[test]
    fn full_kernel_options_retain_policy_when_mountinfo_omits_defaults() {
        let options = "rw\nnodiscard\nerrors=remount-ro\nresuid=0\nresgid=0\ncommit=5\n";
        effective_ext4_options(options).unwrap();
        for (from, to) in [
            ("errors=remount-ro\n", ""),
            ("errors=remount-ro", "errors=continue"),
            ("errors=remount-ro", "errors=panic"),
            ("nodiscard", "discard"),
            ("rw\n", "ro\n"),
            ("nodiscard\n", "nodiscard\ndiscard\n"),
        ] {
            assert!(
                effective_ext4_options(&options.replace(from, to)).is_err(),
                "{from}->{to}"
            );
        }
    }
    #[test]
    fn explicit_tmpfs_cannot_lose_either_capacity_or_a_mount() {
        let mut tmpfs = serde_json::Map::new();
        for (target, bytes, inodes) in tmpfs_limits() {
            tmpfs.insert(
                target.into(),
                json!(format!(
                    "rw,nosuid,nodev,noexec,size={bytes},nr_inodes={inodes},mode=1777"
                )),
            );
        }
        let value = json!({"HostConfig":{"Tmpfs":tmpfs}});
        assert_eq!(check_tmpfs(&value).unwrap(), 4);
        for (target, _, _) in tmpfs_limits() {
            for (from, to) in [
                ("nr_inodes=4096", "nr_inodes=0"),
                ("size=16777216", "size=0"),
                ("noexec", "exec"),
                ("nosuid", "suid"),
            ] {
                let mut altered = value.clone();
                let text = altered["HostConfig"]["Tmpfs"][target]
                    .as_str()
                    .unwrap()
                    .replace(from, to);
                if text == altered["HostConfig"]["Tmpfs"][target].as_str().unwrap() {
                    continue;
                }
                altered["HostConfig"]["Tmpfs"][target] = json!(text);
                assert!(check_tmpfs(&altered).is_err());
            }
            let mut missing = value.clone();
            missing["HostConfig"]["Tmpfs"]
                .as_object_mut()
                .unwrap()
                .remove(target);
            assert!(check_tmpfs(&missing).is_err());
        }
    }
    #[test]
    fn shared_ancestor_is_rejected_before_allocation() {
        let root = "1 0 8:1 / / rw shared:1 - ext4 /dev/vda1 rw\n";
        assert!(private_ancestor(root, "/var/lib/hol-gauntlet/builds/aaaaaaaaaaaaaaaa").is_err());
        let private =
            "2 1 8:1 /var/lib/hol-gauntlet /var/lib/hol-gauntlet rw - ext4 /dev/vda1 rw\n";
        assert!(private_ancestor(
            &(root.to_owned() + private),
            "/var/lib/hol-gauntlet/builds/aaaaaaaaaaaaaaaa"
        )
        .is_ok());
        assert!(private_ancestor(
            &(root.to_owned() + private),
            "/var/lib/hol-gauntlet-other/aaaaaaaaaaaaaaaa"
        )
        .is_err());
        assert!(private_ancestor(
            &private.replace(" - ", " master:1 - "),
            "/var/lib/hol-gauntlet/builds/aaaaaaaaaaaaaaaa"
        )
        .is_err());
    }
}
