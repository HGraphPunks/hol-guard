//! Initial/gated processes have three pipes. The idle actor may additionally
//! hold only the counterparts of pipes measured on its registered children.
use crate::Result;
use std::collections::{BTreeMap, BTreeSet};

fn pipe(value: &str) -> bool {
    value
        .strip_prefix("pipe:[")
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|id| id > 0 && value == format!("pipe:[{id}]"))
}

fn validate(fds: &BTreeMap<String, String>, permitted: &BTreeSet<String>) -> Result<()> {
    if permitted.len() > 192 || fds.len() > 195 || !(0..3).all(|n| fds.contains_key(&n.to_string()))
    {
        return Err("bounded product management descriptors required".into());
    }
    for (name, target) in fds {
        let number = name
            .parse::<u32>()
            .ok()
            .filter(|n| *n <= 1024 && n.to_string() == *name)
            .ok_or("bounded canonical product descriptor number required")?;
        if !pipe(target) || (number > 2 && !permitted.contains(target)) {
            return Err("product inherited extra authority descriptors".into());
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) fn read(
    proc: &std::os::fd::OwnedFd,
    permitted: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>> {
    use rustix::fs::{openat, readlinkat, Dir, Mode, OFlags};
    let fd = openat(
        proc,
        "fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let mut result = BTreeMap::new();
    for entry in Dir::read_from(&fd).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "kernel descriptor name UTF-8")?;
        if matches!(name, "." | "..") {
            continue;
        }
        if result.len() >= 195 {
            return Err("product descriptor count exceeds bound".into());
        }
        let link = readlinkat(&fd, name, Vec::new()).map_err(|e| e.to_string())?;
        result.insert(
            name.into(),
            link.to_str()
                .map_err(|_| "kernel descriptor target UTF-8")?
                .into(),
        );
    }
    validate(&result, permitted)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_measured_child_pipes_extend_the_idle_actor_descriptor_set() {
        let base = BTreeMap::from([
            ("0".into(), "pipe:[100]".into()),
            ("1".into(), "pipe:[101]".into()),
            ("2".into(), "pipe:[102]".into()),
        ]);
        assert!(validate(&base, &BTreeSet::new()).is_ok());
        let permitted = BTreeSet::from([
            "pipe:[200]".into(),
            "pipe:[201]".into(),
            "pipe:[202]".into(),
        ]);
        let mut actor = base.clone();
        actor.insert("4".into(), "pipe:[200]".into());
        actor.insert("5".into(), "pipe:[201]".into());
        assert!(validate(&actor, &permitted).is_ok());
        assert!(validate(&actor, &BTreeSet::new()).is_err());
        for unknown in [
            "pipe:[999]",
            "socket:[200]",
            "/root/private",
            "anon_inode:[pidfd]",
            "pipe:[0200]",
        ] {
            let mut bad = actor.clone();
            bad.insert("6".into(), unknown.into());
            assert!(validate(&bad, &permitted).is_err(), "{unknown}");
        }
        let mut missing = base;
        missing.remove("1");
        assert!(validate(&missing, &permitted).is_err());
    }
}
