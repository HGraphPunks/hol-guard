//! Exact saved-ID/capability checks shared by the Native SDK kernel observer.
use std::collections::BTreeMap;
pub(crate) const STARTUP_BUN_SHA256: &str =
    "37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086";
pub(crate) const STARTUP_CONFIG: &[u8] = b"preload = []\n";
pub(crate) const STARTUP_ENV: [(&str, &str); 7] = [
    ("HOME", "/runtime/home"),
    ("PATH", "/usr/bin:/bin"),
    ("TMPDIR", "/tmp"),
    ("XDG_CONFIG_HOME", "/runtime/public"),
    ("BUN_RUNTIME_TRANSPILER_CACHE_PATH", "0"),
    ("DO_NOT_TRACK", "1"),
    ("NO_COLOR", "1"),
];
pub(crate) fn startup_environment(raw: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let raw = raw
        .strip_suffix(&[0])
        .ok_or("complete SDK initial environment required")?;
    let mut actual = BTreeMap::new();
    for entry in raw.split(|b| *b == 0) {
        let entry = std::str::from_utf8(entry).map_err(|_| "SDK initial environment UTF8")?;
        let (name, value) = entry
            .split_once('=')
            .ok_or("SDK initial environment entry malformed")?;
        if actual.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err("duplicate SDK initial environment name".into());
        }
    }
    let expected = STARTUP_ENV
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    if actual != expected {
        return Err("SDK initial environment differs from closed startup profile".into());
    }
    Ok(actual)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SdkEntrypoint {
    Conformance,
    Developer,
    SealedConformance,
    SealedDeveloper,
}
impl SdkEntrypoint {
    pub(crate) fn argv(self) -> &'static [u8] {
        match self {
            Self::Conformance => b"/runtime/bun\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json\0",
            Self::Developer => b"/runtime/bun\0/runtime/public/developer_omp_episode.ts\0/runtime/public/episode.json\0",
            Self::SealedConformance => b"/runtime/bun\0--no-env-file\0--no-install\0--config=/runtime/public/bunfig.toml\0--cwd=/runtime/public\0/runtime/public/private_cell_sdk_conformance.ts\0/runtime/public/episode.json\0",
            Self::SealedDeveloper => b"/runtime/bun\0--no-env-file\0--no-install\0--config=/runtime/public/bunfig.toml\0--cwd=/runtime/public\0/runtime/public/developer_omp_episode.ts\0/runtime/public/episode.json\0",
        }
    }
    pub(crate) fn digest_input(self) -> &'static [u8] {
        self.argv().strip_suffix(&[0]).unwrap()
    }
    pub(crate) fn matches(self, raw: &[u8]) -> bool {
        raw == self.argv()
    }
    pub(crate) fn sealed(self) -> bool {
        matches!(self, Self::SealedConformance | Self::SealedDeveloper)
    }
    pub(crate) fn with_sealed_startup(self) -> Self {
        match self {
            Self::Conformance => Self::SealedConformance,
            Self::Developer => Self::SealedDeveloper,
            sealed => sealed,
        }
    }
    pub(crate) fn arguments(self) -> Vec<String> {
        self.argv()
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| std::str::from_utf8(s).unwrap().to_owned())
            .collect()
    }
}

/// The inherited developer SDK template is explicitly a named unconfined
/// profile. It must not be confused with the product cell's enforcing label.
pub(crate) fn sdk_label(name: &str) -> Result<String, String> {
    let tail = name
        .strip_prefix("hol-gauntlet-sdk-")
        .ok_or("fixed SDK profile name required")?;
    let (job, nonce) = tail
        .split_once('-')
        .ok_or("SDK profile job/nonce required")?;
    if !crate::hex(job, 16) || !crate::hex(nonce, 32) {
        return Err("fresh job-bound SDK profile required".into());
    }
    Ok(format!("{name} (unconfined)"))
}

/// Ubuntu's crun profile can stack with the exact declared SDK profile.
/// Preserve the observed complete label; never normalize away a component.
pub(super) fn sdk_process_label(expected: &str, observed: &str) -> Result<String, String> {
    let declared = expected.strip_prefix("crun//&").unwrap_or(expected);
    let name = declared
        .strip_suffix(" (unconfined)")
        .ok_or("SDK template mode differs")?;
    if sdk_label(name)? != declared
        || (observed != expected
            && (expected != declared || observed != format!("crun//&{declared}")))
    {
        return Err(format!(
            "SDK template process label differs: observed {observed:?}, expected {expected:?}"
        ));
    }
    Ok(observed.into())
}

pub(super) fn sdk_cgroup(container: &str, label: &str, actual: &str) -> Result<(), String> {
    let name = label
        .strip_suffix(" (unconfined)")
        .ok_or("SDK template mode differs")?;
    if sdk_label(name)? != label || !crate::hex(container, 64) {
        return Err("fixed SDK CID/label required".into());
    }
    let job = name
        .strip_prefix("hol-gauntlet-sdk-")
        .unwrap()
        .split_once('-')
        .unwrap()
        .0;
    let scope = format!("/holgauntletrust{job}.slice/libpod-{container}.scope");
    if actual != scope && actual != format!("{scope}/container") {
        return Err(format!(
            "SDK container ID/cgroup relation differs: {actual}"
        ));
    }
    Ok(())
}

pub(super) fn checked_status(raw: &[u8], pid: u32) -> Result<BTreeMap<String, String>, String> {
    checked_status_for_uid(raw, pid, 10001)
}

pub(crate) fn checked_status_for_uid(
    raw: &[u8],
    pid: u32,
    uid: u32,
) -> Result<BTreeMap<String, String>, String> {
    if !matches!(uid, 10001 | 10005) {
        return Err("fixed SDK or MCP identity profile required".into());
    }
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
    let expected_ids = format!("{uid} {uid} {uid} {uid}");
    let expected_group = uid.to_string();
    if text("Uid") != Some(expected_ids.as_str())
        || text("Gid") != Some(expected_ids.as_str())
        || !text("Groups").is_some_and(|group| group.is_empty() || group == expected_group)
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
pub(crate) use kernel::NativeSdkModelPeer;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use kernel::{NativeSdkBoundary, NativeSdkMcpPeer, NativeSdkPeer, NativeSdkRequestPeer};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_startup_refuses_injected_flags_and_cannot_adopt_historical_argv() {
        assert!(crate::hex(STARTUP_BUN_SHA256, 64));
        assert_eq!(STARTUP_CONFIG, b"preload = []\n");
        for original in [SdkEntrypoint::Conformance, SdkEntrypoint::Developer] {
            let sealed = original.with_sealed_startup();
            assert!(sealed.sealed());
            assert_eq!(sealed.with_sealed_startup(), sealed);
            assert!(sealed.matches(sealed.argv()));
            assert!(!sealed.matches(original.argv()));
            assert!(!original.matches(sealed.argv()));
            let argv = sealed.arguments();
            assert_eq!(argv.len(), 7);
            for unsafe_flag in [
                "--env-file=/runtime/home/project/.env",
                "--preload=/runtime/home/project/attack.ts",
                "--config=/runtime/home/project/bunfig.toml",
                "--cwd=/runtime/home/project",
            ] {
                let mut changed = argv.clone();
                changed[1] = unsafe_flag.into();
                let raw = changed
                    .iter()
                    .flat_map(|s| s.as_bytes().iter().copied().chain([0]))
                    .collect::<Vec<_>>();
                assert!(!sealed.matches(&raw));
            }
        }
    }
    #[test]
    fn initial_environment_refuses_injected_runtime_and_sdk_configuration() {
        let raw = STARTUP_ENV
            .iter()
            .flat_map(|(k, v)| format!("{k}={v}\0").into_bytes())
            .collect::<Vec<_>>();
        let expected = startup_environment(&raw).unwrap();
        assert_eq!(expected.len(), 7);
        let reversed = STARTUP_ENV
            .iter()
            .rev()
            .flat_map(|(k, v)| format!("{k}={v}\0").into_bytes())
            .collect::<Vec<_>>();
        assert_eq!(startup_environment(&reversed).unwrap(), expected);
        for extra in [
            "BUN_OPTIONS=--preload=attack.ts\0",
            "NODE_OPTIONS=--require=attack.js\0",
            "LD_PRELOAD=attack.so\0",
            "PI_CONFIG_FILES=/runtime/home/project/config.yml\0",
            "HOME=/runtime/home\0",
        ] {
            let mut changed = raw.clone();
            changed.extend_from_slice(extra.as_bytes());
            assert!(startup_environment(&changed).is_err());
        }
        assert!(startup_environment(&raw[..raw.len() - 1]).is_err());
        assert!(startup_environment(b"HOME=/runtime/home\0\0").is_err());
    }
    #[test]
    fn sdk_entrypoint_is_selected_before_binding_and_cannot_change_profiles() {
        for selected in [SdkEntrypoint::Conformance, SdkEntrypoint::Developer] {
            assert!(selected.matches(selected.argv()));
            assert!(!selected.matches(selected.digest_input()));
            let mut extra = selected.argv().to_vec();
            extra.extend_from_slice(b"--unsafe\0");
            assert!(!selected.matches(&extra));
            let other = if selected == SdkEntrypoint::Conformance {
                SdkEntrypoint::Developer
            } else {
                SdkEntrypoint::Conformance
            };
            assert!(!selected.matches(other.argv()));
        }
    }
    #[test]
    fn sdk_label_requires_the_exact_named_mode_and_fresh_job_identity() {
        let name = format!("hol-gauntlet-sdk-{}-{}", "a".repeat(16), "b".repeat(32));
        assert_eq!(sdk_label(&name).unwrap(), format!("{name} (unconfined)"));
        for name in [
            "unconfined",
            "hol-product-cell-example",
            "hol-gauntlet-sdk-../root",
            "hol-gauntlet-sdk-aaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-extra",
        ] {
            assert!(sdk_label(name).is_err());
        }
    }
    #[test]
    fn sdk_process_label_keeps_the_exact_runtime_stack_and_refuses_other_profiles() {
        let name = format!("hol-gauntlet-sdk-{}-{}", "a".repeat(16), "b".repeat(32));
        let label = sdk_label(&name).unwrap();
        let stacked = format!("crun//&{label}");
        assert_eq!(sdk_process_label(&label, &label).unwrap(), label);
        assert_eq!(sdk_process_label(&label, &stacked).unwrap(), stacked);
        assert_eq!(sdk_process_label(&stacked, &stacked).unwrap(), stacked);
        assert!(sdk_process_label(&stacked, &label).is_err());
        for bad in [
            "unconfined".into(),
            format!("{name} (enforce)"),
            format!("other//&{label}"),
            format!("crun//&crun//&{label}"),
            format!("crun//&{label}//&other"),
            label.replace(&"a".repeat(16), &"c".repeat(16)),
            label.replace(&"b".repeat(32), &"c".repeat(32)),
        ] {
            assert!(sdk_process_label(&label, &bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn sdk_payload_cgroup_cannot_borrow_a_sibling_job_cid_or_descendant() {
        let job = "a".repeat(16);
        let cid = "b".repeat(64);
        let label = sdk_label(&format!("hol-gauntlet-sdk-{job}-{}", "c".repeat(32))).unwrap();
        let scope = format!("/holgauntletrust{job}.slice/libpod-{cid}.scope");
        sdk_cgroup(&cid, &label, &scope).unwrap();
        sdk_cgroup(&cid, &label, &format!("{scope}/container")).unwrap();
        for bad in [
            format!("{scope}/container/child"),
            format!("{scope}/other"),
            scope.replace(&job, &"d".repeat(16)),
            scope.replace(&cid, &"e".repeat(64)),
            format!("/system.slice/libpod-{cid}.scope"),
        ] {
            assert!(sdk_cgroup(&cid, &label, &bad).is_err(), "{bad}");
        }
    }
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
