//! Read-only nsfs ownership and ID-map capture for ptrace-stopped tasks.
use crate::Result;

fn id_map(raw: &[u8]) -> Result<Vec<[u64; 3]>> {
    let text = std::str::from_utf8(raw).map_err(|_| "kernel ID map UTF-8")?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if rows.len() == 340 {
            return Err("kernel ID map extent bound".into());
        }
        let fields = line
            .split_ascii_whitespace()
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| "kernel ID map integer")?;
        let [inside, outside, length] = fields.as_slice() else {
            return Err("kernel ID map triple required".into());
        };
        if *length == 0
            || inside
                .checked_add(*length)
                .is_none_or(|n| n > u32::MAX as u64)
            || outside
                .checked_add(*length)
                .is_none_or(|n| n > u32::MAX as u64)
        {
            return Err("kernel ID map range".into());
        }
        rows.push([*inside, *outside, *length]);
    }
    // An unmapped newborn namespace is observable, but cannot pass a mapped
    // execution profile. Preserve that fact for the independent reader.
    Ok(rows)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod kernel {
    use super::id_map;
    use crate::kernel_process::read_at;
    use crate::Result;
    use rustix::fs::{fstat, fstatfs, openat, Mode, OFlags};
    use serde_json::{json, Value};
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    pub(crate) struct Snapshot {
        pub(crate) value: Value,
        // Retain all namespace references until both task samples agree.
        _held: Vec<OwnedFd>,
    }

    fn namespace(fd: &OwnedFd, kind: libc::c_int) -> Result<Value> {
        if fstatfs(fd).map_err(|e| e.to_string())?.f_type != 0x6e73_6673 {
            return Err("kernel nsfs descriptor required".into());
        }
        // SAFETY: NS_GET_NSTYPE takes no pointer and only queries this held FD.
        let actual = unsafe { libc::ioctl(fd.as_raw_fd(), libc::NS_GET_NSTYPE) };
        if actual < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if actual != kind {
            return Err("kernel namespace type differs".into());
        }
        let info = fstat(fd).map_err(|e| e.to_string())?;
        if info.st_ino == 0 {
            return Err("kernel namespace inode required".into());
        }
        Ok(json!({"device":info.st_dev,"inode":info.st_ino}))
    }

    fn relative(fd: &OwnedFd, parent: bool) -> Result<Option<OwnedFd>> {
        let request = if parent {
            libc::NS_GET_PARENT
        } else {
            libc::NS_GET_USERNS
        };
        // SAFETY: both nsfs ioctls take no pointer and return a fresh owned
        // O_RDONLY|O_CLOEXEC descriptor, never a descriptor borrowed from target.
        let raw = unsafe { libc::ioctl(fd.as_raw_fd(), request) };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if parent && error.raw_os_error() == Some(libc::EPERM) {
                // EPERM also means outside visibility; it does not establish
                // that the current namespace is the initial user namespace.
                return Ok(None);
            }
            return Err(error.to_string());
        }
        // SAFETY: successful nsfs ioctl transferred this fresh FD to us.
        Ok(Some(unsafe { OwnedFd::from_raw_fd(raw) }))
    }

    pub(crate) fn snapshot(proc: &OwnedFd) -> Result<Snapshot> {
        let mut held = Vec::new();
        let mut namespaces = BTreeMap::new();
        let kinds = [
            ("cgroup", libc::CLONE_NEWCGROUP),
            ("ipc", libc::CLONE_NEWIPC),
            ("mnt", libc::CLONE_NEWNS),
            ("net", libc::CLONE_NEWNET),
            ("pid", libc::CLONE_NEWPID),
            ("user", libc::CLONE_NEWUSER),
            ("uts", libc::CLONE_NEWUTS),
        ];
        let mut user_index = None;
        for (name, kind) in kinds {
            // Follow only kernel-generated nsfs links under this held proc FD.
            let fd = openat(
                proc,
                format!("ns/{name}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let mut identity = namespace(&fd, kind)?;
            let owner = if name == "user" {
                user_index = Some(held.len());
                Value::Null
            } else {
                let owner = relative(&fd, false)?.ok_or("namespace owner unavailable")?;
                let identity = namespace(&owner, libc::CLONE_NEWUSER)?;
                held.push(owner);
                identity
            };
            identity["owner_user_namespace"] = owner;
            held.push(fd);
            namespaces.insert(name, identity);
        }
        let mut current = user_index.ok_or("task user namespace missing")?;
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let end_reason = loop {
            let identity = namespace(&held[current], libc::CLONE_NEWUSER)?;
            let key = (
                identity["device"].as_u64().unwrap(),
                identity["inode"].as_u64().unwrap(),
            );
            if !seen.insert(key) {
                return Err("kernel user namespace parent cycle".into());
            }
            chain.push(identity);
            if chain.len() == 32 {
                break "bound-exceeded";
            }
            match relative(&held[current], true)? {
                Some(parent) => {
                    current = held.len();
                    held.push(parent);
                }
                None => break "parent-unavailable",
            }
        };
        let uid_map = id_map(&read_at(proc, "uid_map", 65536)?)?;
        let gid_map = id_map(&read_at(proc, "gid_map", 65536)?)?;
        let groups = read_at(proc, "setgroups", 32)?;
        let setgroups = std::str::from_utf8(&groups)
            .map_err(|_| "kernel setgroups UTF-8")?
            .trim();
        if !matches!(setgroups, "allow" | "deny") {
            return Err("kernel setgroups policy required".into());
        }
        let label = read_at(proc, "attr/current", 4096)?;
        let label = std::str::from_utf8(&label)
            .map_err(|_| "traced label UTF-8")?
            .trim();
        Ok(Snapshot {
            value: json!({
                "schema":"hol-gauntlet-native-task-isolation.v1","namespaces":namespaces,
                "user_namespace_chain":chain,"user_namespace_chain_end_reason":end_reason,
                "uid_map":uid_map,"gid_map":gid_map,"setgroups":setgroups,"lsm_label":label
            }),
            _held: held,
        })
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(super) use kernel::snapshot;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(
        target_os = "linux",
        target_arch = "aarch64",
        feature = "owned-process-trace-fixture"
    ))]
    #[test]
    fn child_user_namespace_mapping_and_parent_owned_mount_are_measured_distinctly() {
        for mode in ["nested-userns", "nested-userns-parent-mount"] {
            let (_, rows) = crate::native_trace_tests::run(mode);
            let actor = &rows.iter().find(|r| r["kind"] == "trace-start").unwrap()["data"]["actor"]
                ["task"]["isolation"];
            let initial = &actor["user_namespace_chain"][0];
            let image = &rows.iter().find(|r| r["kind"] == "task-exec").unwrap()["data"]["image"];
            let nested = &image["task"]["isolation"];
            let chain = nested["user_namespace_chain"].as_array().unwrap();
            assert_eq!(chain.len(), 2);
            assert_eq!(&chain[1], initial);
            assert_ne!(&chain[0], initial);
            assert_eq!(nested["uid_map"], serde_json::json!([[10004, 10004, 1]]));
            assert_eq!(nested["gid_map"], serde_json::json!([[10004, 10004, 1]]));
            assert_eq!(nested["setgroups"], "deny");
            assert_eq!(
                nested["user_namespace_chain_end_reason"],
                "parent-unavailable"
            );
            let owner = &nested["namespaces"]["mnt"]["owner_user_namespace"];
            assert_eq!(
                owner,
                if mode == "nested-userns" {
                    &chain[0]
                } else {
                    initial
                }
            );
            assert!(rows.iter().any(|r| r["kind"] == "task-created"
                && r["data"]["task"]["isolation"]["uid_map"]
                    == serde_json::json!([[10004, 10004, 1]])));
        }
    }

    #[test]
    fn initial_nested_and_unmapped_kernel_maps_remain_distinct() {
        assert_eq!(id_map(b"0 0 4294967295\n").unwrap(), [[0, 0, 4294967295]]);
        assert_eq!(id_map(b" 10004 10004 1\n").unwrap(), [[10004, 10004, 1]]);
        assert!(id_map(b"").unwrap().is_empty());
    }

    #[test]
    fn malformed_overflow_and_unbounded_id_maps_are_refused() {
        for raw in [
            b"0 0\n".as_slice(),
            b"0 0 0\n",
            b"0 0 4294967296\n",
            b"4294967295 0 1\n",
            b"-1 0 1\n",
            b"0 0 1 2\n",
            b"\xff",
        ] {
            assert!(id_map(raw).is_err());
        }
        assert!(id_map("0 0 1\n".repeat(341).as_bytes()).is_err());
    }
}
