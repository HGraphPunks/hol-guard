//! Check the held process's actual Root view against outside task declarations.
use crate::declarations::TaskMount;
use crate::Result;
use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

fn encoded(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .ok_or("mount path UTF-8")?
        .replace('\\', "\\134")
        .replace(' ', "\\040"))
}

pub(crate) fn verify(
    proc: &OwnedFd,
    mountinfo: &str,
    tasks: &[TaskMount],
    runtime: &Path,
) -> Result<Value> {
    let root = openat(
        proc,
        "root",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    for row in tasks {
        crate::inputs::task_metadata(row)?;
        let mut parent = openat(
            &root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let parts = row
            .destination
            .components()
            .filter_map(|part| {
                if let Component::Normal(name) = part {
                    Some(name)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for (index, name) in parts.iter().enumerate() {
            let info = fstat(&parent).map_err(|e| e.to_string())?;
            crate::fs_input::root_metadata(&info, true)?;
            parent = openat(
                &parent,
                *name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            if index + 1 == parts.len() {
                let mapped = fstat(&parent).map_err(|e| e.to_string())?;
                if FileType::from_raw_mode(mapped.st_mode) != FileType::Directory
                    || mapped.st_uid != 10004
                    || mapped.st_gid != 10004
                    || mapped.st_dev != row.device
                    || mapped.st_ino != row.inode
                    || mapped.st_mode & 0o7777 != row.mode
                {
                    return Err(
                        "outside kernel task idmap differs from physical declaration".into(),
                    );
                }
                rows.push(json!({"source":row.source,"destination":row.destination,"device":mapped.st_dev,
                    "inode":mapped.st_ino,"mode":mapped.st_mode&0o7777,"physical_uid":10001,"physical_gid":10001,
                    "product_uid":mapped.st_uid,"product_gid":mapped.st_gid}));
            }
        }
        crate::inputs::task_metadata(row)?;
    }
    verify_mount_flags(mountinfo, tasks, runtime)?;
    Ok(json!(rows))
}

fn verify_mount_flags(raw: &str, tasks: &[TaskMount], runtime: &Path) -> Result<()> {
    if raw.len() > 1024 * 1024 {
        return Err("product mountinfo byte bound".into());
    }
    let mut required = vec![
        ("/".into(), vec!["ro", "nosuid", "nodev"]),
        ("/usr".into(), vec!["ro", "nosuid", "nodev"]),
        ("/opt/node".into(), vec!["ro", "nosuid", "nodev"]),
        ("/public".into(), vec!["ro", "nosuid", "nodev"]),
        ("/dev".into(), vec!["ro", "nosuid"]),
        ("/proc".into(), vec!["rw", "nosuid", "nodev", "noexec"]),
        ("/tmp".into(), vec!["rw", "nosuid", "nodev"]),
        ("/product".into(), vec!["rw", "nosuid", "nodev"]),
        (encoded(runtime)?, vec!["ro", "nosuid", "nodev"]),
    ];
    for task in tasks {
        required.push((encoded(&task.destination)?, vec!["rw", "nosuid", "nodev"]));
    }
    let mut observed = std::collections::BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        if index >= 256 {
            return Err("product mount count exceeds fixed bound".into());
        }
        let (left, right) = line
            .split_once(" - ")
            .ok_or("invalid product mountinfo separator")?;
        let fields = left.split_ascii_whitespace().collect::<Vec<_>>();
        let filesystem = right
            .split_ascii_whitespace()
            .next()
            .ok_or("invalid product mount filesystem")?;
        if fields.len() < 6 || matches!(filesystem, "sysfs" | "cgroup" | "cgroup2") {
            return Err("invalid or forbidden product mount".into());
        }
        if observed.insert(fields[4], fields[5]).is_some() {
            return Err("stacked or duplicate product mountpoint".into());
        }
    }
    for (path, flags) in required {
        let found = observed
            .get(path.as_str())
            .ok_or("required product mount is absent")?
            .split(',')
            .collect::<Vec<_>>();
        if flags.iter().any(|flag| !found.contains(flag))
            || found.contains(&"ro") && found.contains(&"rw")
        {
            return Err("actual product mount lacks required isolation flags".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mount_flags_must_be_observed_for_each_real_mount() {
        let paths = [
            ("/", "ro,nosuid,nodev"),
            ("/usr", "ro,nosuid,nodev"),
            ("/opt/node", "ro,nosuid,nodev"),
            ("/public", "ro,nosuid,nodev"),
            ("/dev", "ro,nosuid"),
            ("/proc", "rw,nosuid,nodev,noexec"),
            ("/tmp", "rw,nosuid,nodev"),
            ("/product", "rw,nosuid,nodev"),
            ("/runtime/guard", "ro,nosuid,nodev"),
        ];
        let raw = paths
            .iter()
            .enumerate()
            .map(|(i, (p, f))| format!("{} 1 0:1 / {p} {f} - tmpfs tmpfs rw\n", i + 2))
            .collect::<String>();
        assert!(verify_mount_flags(&raw, &[], Path::new("/runtime/guard")).is_ok());
        assert!(verify_mount_flags(
            &raw.replace("/usr ro,nosuid,nodev", "/usr rw,nosuid,nodev"),
            &[],
            Path::new("/runtime/guard")
        )
        .is_err());
        assert!(verify_mount_flags(
            &(raw.clone() + "88 1 0:1 / /sys rw - sysfs sysfs rw\n"),
            &[],
            Path::new("/runtime/guard")
        )
        .is_err());
        assert!(verify_mount_flags(
            &(raw.clone() + "88 1 0:1 / /usr ro,nosuid,nodev - tmpfs tmpfs ro\n"),
            &[],
            Path::new("/runtime/guard")
        )
        .is_err());
    }
}
