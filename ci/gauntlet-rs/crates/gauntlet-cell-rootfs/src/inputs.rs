//! Finish all bounded source checks before the first private mount.
use crate::declarations::{parse_tasks, Runtime, System, TaskMount};
use crate::fs_input::{directory, pinned, root_metadata};
use crate::{NetworkProfile, Result, RootfsSpec, StateProfile};
use gauntlet_evidence::{inventory_tree, verify_native_private_cell_manifest, TreeKind};
use rustix::fs::{fstat, openat, FileType, Mode, OFlags, Stat};
use std::collections::BTreeSet;
use std::os::fd::OwnedFd;
use std::path::Path;

pub(crate) struct Inputs {
    pub spec: RootfsSpec,
    pub system: System,
    pub runtime: Runtime,
    pub tasks: Vec<TaskMount>,
    // Held descriptors keep the checked generations alive through construction.
    pub stage: OwnedFd,
    pub image: OwnedFd,
    pub prefix: OwnedFd,
    pub public: OwnedFd,
}

fn identity(info: &Stat, device: u64, inode: u64) -> bool {
    info.st_dev as u128 == device as u128 && info.st_ino as u128 == inode as u128
}

pub(crate) fn task_metadata(row: &TaskMount) -> Result<()> {
    let parent = directory(row.source.parent().ok_or("task source parent required")?)?;
    let descriptor = openat(
        &parent,
        row.source.file_name().ok_or("task leaf required")?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let info = fstat(&descriptor).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(info.st_mode) != FileType::Directory
        || info.st_uid != 10001
        || info.st_gid != 10001
        || info.st_mode & 0o7777 != row.mode
        || !identity(&info, row.device, row.inode)
    {
        return Err("physical agent task ownership/inode/mode differs from outside pin".into());
    }
    let custody = directory(&row.custody_root)?;
    if fstat(&custody).map_err(|e| e.to_string())?.st_mode & 0o077 != 0 {
        return Err("private Root task custody required".into());
    }
    Ok(())
}

fn public_files(spec: &RootfsSpec) -> Result<OwnedFd> {
    let raw = pinned(
        &spec.stage.join("cell-artifact-manifest.json"),
        1024 * 1024,
        &spec.artifact_manifest_sha256,
    )?;
    let manifest = verify_native_private_cell_manifest(
        &raw,
        &spec.artifact_manifest_sha256,
        &spec.initializer_sha256,
    )
    .map_err(|e| e.to_string())?;
    let public = spec.stage.join("public");
    let descriptor = directory(&public)?;
    let expected: BTreeSet<_> = manifest
        .files
        .keys()
        .filter_map(|p| p.strip_prefix("public/"))
        .collect();
    let mut actual = BTreeSet::new();
    let mut total = 0usize;
    for entry in std::fs::read_dir(&public).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "public filename is not UTF-8")?;
        if actual.len() >= 128 || !expected.contains(name.as_str()) || !actual.insert(name.clone())
        {
            return Err("public artifacts differ from exact native manifest".into());
        }
        let raw = pinned(
            &public.join(&name),
            2 * 1024 * 1024,
            &manifest.files[&format!("public/{name}")],
        )?;
        total += raw.len();
        if total > 8 * 1024 * 1024 {
            return Err("public bootstrap byte bound".into());
        }
    }
    if actual.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err("public native artifacts missing".into());
    }
    Ok(descriptor)
}

pub(crate) fn load(spec: RootfsSpec) -> Result<Inputs> {
    let stage = directory(&spec.stage)?;
    let system = System::parse(&pinned(
        &spec.stage.join("system.json"),
        4096,
        &spec.system_spec_sha256,
    )?)?;
    let image = directory(&system.root)?;
    if !identity(
        &fstat(&image).map_err(|e| e.to_string())?,
        system.device,
        system.inode,
    ) {
        return Err("pinned system image inode/device changed".into());
    }
    for relative in ["usr", "opt", "opt/node", "etc", "etc/alternatives"] {
        directory(&system.root.join(relative))?;
    }
    let runtime = Runtime::parse(&pinned(
        &spec.stage.join("runtime.json"),
        8192,
        &spec.runtime_spec_sha256,
    )?)?;
    let prefix = directory(&runtime.prefix)?;
    let observed =
        inventory_tree(&runtime.prefix, TreeKind::InstalledPrefix).map_err(|e| e.to_string())?;
    if observed.digest != runtime.tree_digest {
        return Err("runtime tree differs from outside pin".into());
    }
    let tasks = parse_tasks(
        &pinned(
            &spec.stage.join("task-mounts.json"),
            32768,
            &spec.task_spec_sha256,
        )?,
        &spec.stage,
        &system,
        &runtime,
    )?;
    for task in &tasks {
        task_metadata(task)?;
    }
    let public = public_files(&spec)?;
    if spec.state == StateProfile::Persistent {
        let info =
            std::fs::symlink_metadata(spec.stage.join("state")).map_err(|e| e.to_string())?;
        use std::os::unix::fs::MetadataExt;
        if !info.is_dir()
            || info.uid() != 10004
            || info.gid() != 10004
            || info.mode() & 0o7777 != 0o700
        {
            return Err("direct persistent state requires private UID/GID10004 custody".into());
        }
    }
    // These sources are read before mount changes. They are fixed public OS
    // configuration, never credentials or caller-selected files.
    for name in [
        "group",
        "hosts",
        "ld.so.cache",
        "nsswitch.conf",
        "passwd",
        "protocols",
        "services",
    ] {
        crate::fs_input::read(&system.root.join("etc").join(name), 2 * 1024 * 1024)?;
    }
    root_metadata(&fstat(&stage).map_err(|e| e.to_string())?, true)?;
    Ok(Inputs {
        spec,
        system,
        runtime,
        tasks,
        stage,
        image,
        prefix,
        public,
    })
}

pub(crate) fn check_private_boundary(spec: &RootfsSpec) -> Result<()> {
    if !cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        return Err("native Linux ARM64 Root PID1 constructor required".into());
    }
    // SAFETY: read-only process identity syscalls, no pointers.
    if unsafe {
        libc::getpid() != 1
            || libc::getuid() != 0
            || libc::geteuid() != 0
            || libc::getgid() != 0
            || libc::getegid() != 0
    } {
        return Err("private Root PID1 required before any filesystem mutation".into());
    }
    for name in ["mnt", "pid", "net", "ipc", "uts", "cgroup"] {
        let own = std::fs::read_link(format!("/proc/self/ns/{name}")).map_err(|e| e.to_string())?;
        let parent = std::fs::read_link(format!("/proc/1/ns/{name}")).map_err(|e| e.to_string())?;
        if own == parent {
            return Err(format!("fresh private {name} namespace required"));
        }
        if name == "net" {
            if let NetworkProfile::PrivateLoopback { parent_namespace } = &spec.network {
                if parent != Path::new(parent_namespace) {
                    return Err("outside parent network namespace differs".into());
                }
            }
        }
    }
    gauntlet_product_cell::observe_private_loopback().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_process_cannot_enter_the_constructor_mount_path() {
        let spec = RootfsSpec {
            stage: "/var/lib/hol-gauntlet/not-created-by-test".into(),
            initializer_sha256: "a".repeat(64),
            artifact_manifest_sha256: "b".repeat(64),
            system_spec_sha256: "c".repeat(64),
            task_spec_sha256: "d".repeat(64),
            runtime_spec_sha256: "e".repeat(64),
            idmap_runtime: "ubuntu2404-controller-v1".into(),
            state: StateProfile::Memory,
            network: NetworkProfile::UnixOnly,
        };
        assert_ne!(std::process::id(), 1);
        assert_eq!(
            check_private_boundary(&spec).unwrap_err(),
            "private Root PID1 required before any filesystem mutation"
        );
    }
}
