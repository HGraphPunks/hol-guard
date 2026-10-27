//! Exact saved-ID/capability checks shared by the Native SDK kernel observer.
use std::collections::BTreeMap;

pub(super) fn checked_status(raw: &[u8], pid: u32) -> Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "SDK process status UTF-8")?;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if ![
            "Uid",
            "Gid",
            "Groups",
            "NoNewPrivs",
            "Seccomp",
            "Seccomp_filters",
            "NSpid",
            "CapAmb",
            "CapBnd",
            "CapEff",
            "CapInh",
            "CapPrm",
        ]
        .contains(&name)
        {
            continue;
        }
        if result
            .insert(
                name.to_owned(),
                value.split_ascii_whitespace().collect::<Vec<_>>().join(" "),
            )
            .is_some()
        {
            return Err("duplicate SDK kernel status field".into());
        }
    }
    let text = |name: &str| result.get(name).map(String::as_str);
    let ids = text("NSpid")
        .ok_or("SDK namespace PIDs unavailable")?
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "SDK namespace PID invalid")?;
    if text("Uid") != Some("10001 10001 10001 10001")
        || text("Gid") != Some("10001 10001 10001 10001")
        || !matches!(text("Groups"), Some("" | "10001"))
        || text("NoNewPrivs") != Some("1")
        || text("Seccomp") != Some("2")
        || text("Seccomp_filters")
            .and_then(|s| s.parse::<u32>().ok())
            .is_none_or(|n| n == 0)
        || ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"]
            .iter()
            .any(|name| text(name) != Some("0000000000000000"))
        || !(2..=8).contains(&ids.len())
        || ids[0] != pid
        || ids.contains(&0)
    {
        return Err(
            "SDK process retains IDs, groups, capabilities or lacks private filtered identity"
                .into(),
        );
    }
    Ok(result)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "native_sdk_peer_linux.rs"]
mod kernel;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use kernel::{NativeSdkBoundary, NativeSdkPeer, NativeSdkRequestPeer};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_saved_id_and_capability_set_is_checked() {
        let raw="Uid: 10001 10001 10001 10001\nGid: 10001 10001 10001 10001\nGroups: 10001\nNoNewPrivs: 1\nSeccomp: 2\nSeccomp_filters: 1\nNSpid: 42 7\nCapAmb: 0000000000000000\nCapBnd: 0000000000000000\nCapEff: 0000000000000000\nCapInh: 0000000000000000\nCapPrm: 0000000000000000\n";
        assert!(checked_status(raw.as_bytes(), 42).is_ok());
        assert!(checked_status(raw.replace("Groups: 10001", "Groups:").as_bytes(), 42).is_ok());
        for changed in [
            raw.replace("Uid: 10001 10001 10001 10001", "Uid: 10001 10001 0 10001"),
            raw.replace("Gid: 10001 10001 10001 10001", "Gid: 10001 10001 10001 0"),
            raw.replace("Groups: 10001", "Groups: 10001 0"),
            raw.replace("NoNewPrivs: 1", "NoNewPrivs: 0"),
            raw.replace("Seccomp: 2", "Seccomp: 0"),
            raw.replace("Seccomp_filters: 1", "Seccomp_filters: 0"),
            raw.replace("NSpid: 42 7", "NSpid: 42"),
            raw.replace("NSpid: 42 7", "NSpid: 42 0"),
            format!("{raw}Uid: 10001 10001 10001 10001\n"),
        ] {
            assert!(checked_status(changed.as_bytes(), 42).is_err());
        }
        for name in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
            assert!(checked_status(
                raw.replace(
                    &format!("{name}: 0000000000000000"),
                    &format!("{name}: 0000000000000001")
                )
                .as_bytes(),
                42
            )
            .is_err());
        }
        assert!(checked_status(raw.as_bytes(), 43).is_err());
    }
}
