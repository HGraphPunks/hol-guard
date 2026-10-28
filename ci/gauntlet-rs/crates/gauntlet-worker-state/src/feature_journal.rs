//! Complete feature intents are the durable reservation. All sidecars are
//! append-only; orphan, partial and conflicting records block new admission.
use crate::feature_files as files;
use gauntlet_contracts::{canonicalize, FeatureRunIntent, FEATURE_INTENT_LIMIT};
use rustix::fs::Dir;
use serde_json::Value;
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;

pub(crate) struct FeatureRecord {
    pub(crate) intent: FeatureRunIntent,
    pub(crate) running: Option<Value>,
    pub(crate) result: Option<Value>,
    pub(crate) repair: Option<Value>,
}
fn job(s: &str) -> bool {
    s.len() == 16
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn canonical(raw: &[u8]) -> Result<Value, String> {
    if canonicalize(raw).map_err(|e| e.to_string())? != raw {
        return Err("canonical feature record required".into());
    }
    serde_json::from_slice(raw).map_err(|e| e.to_string())
}
pub(crate) fn write(
    root: &OwnedFd,
    audit: &str,
    suffix: &str,
    body: &Value,
    owner: (u32, u32),
) -> Result<Vec<u8>, String> {
    if !job(audit)
        || !matches!(
            suffix,
            "intent.json" | "running.json" | "result.json" | "repair.json"
        )
    {
        return Err("fixed feature journal sidecar required".into());
    }
    let raw = canonicalize(body.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if raw.len() > FEATURE_INTENT_LIMIT {
        return Err("feature sidecar bound exceeded".into());
    }
    files::write(root, &format!("{audit}.{suffix}"), &raw, owner, 0o600)?;
    Ok(raw)
}
pub(crate) fn validate_running(intent: &FeatureRunIntent, v: &Value) -> Result<(), String> {
    let audit = intent.pins().audit_id();
    if v.as_object().is_none_or(|v| v.len() != 8)
        || v["schema"] != "hol-gauntlet-native-feature-running.v1"
        || v["audit_id"] != audit
        || v["intent_sha256"] != intent.digest()?
        || v["worker_generation"] != intent.pins().text("runner_binary_sha256")
        || !v["container_id"].as_str().is_some_and(sha)
        || !v["client_pid"]
            .as_u64()
            .is_some_and(|n| n > 1 && n <= u32::MAX as u64)
        || v["client_start_ticks"].as_u64().is_none_or(|n| n == 0)
        || v["client_cgroup"] != format!("/system.slice/hol-gauntlet-rust-feature-{audit}")
    {
        return Err("feature running identity differs from reservation".into());
    }
    Ok(())
}
pub(crate) fn inventory(
    root: &OwnedFd,
    owner: (u32, u32),
) -> Result<BTreeMap<String, FeatureRecord>, String> {
    files::private_directory(root, owner)?;
    let mut entries: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
    let mut count = 0;
    for entry in Dir::read_from(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "feature state name UTF-8")?;
        if matches!(name, "." | ".." | "active.lock") {
            continue;
        }
        count += 1;
        if count > 4096 {
            return Err("feature state inventory bound exceeded".into());
        }
        let (audit, suffix) = name
            .split_once('.')
            .filter(|(id, _)| job(id))
            .ok_or("unrecognized feature journal filename")?;
        if !matches!(
            suffix,
            "intent.json" | "running.json" | "result.json" | "repair.json"
        ) {
            return Err("unrecognized feature sidecar blocks admission".into());
        }
        let raw = files::required(root, name, owner, 0o600, FEATURE_INTENT_LIMIT)?;
        entries
            .entry(audit.into())
            .or_default()
            .insert(suffix.into(), canonical(&raw)?);
    }
    entries
        .into_iter()
        .map(|(audit, mut rows)| {
            let v = rows
                .remove("intent.json")
                .ok_or("orphan feature sidecar blocks admission")?;
            let raw = canonicalize(v.to_string().as_bytes()).map_err(|e| e.to_string())?;
            let intent = FeatureRunIntent::parse(&raw)?;
            if intent.pins().audit_id() != audit {
                return Err("feature reservation job differs".into());
            }
            let running = rows.remove("running.json");
            if let Some(v) = &running {
                validate_running(&intent, v)?;
            }
            let result = rows.remove("result.json");
            let repair = rows.remove("repair.json");
            if result.is_some() && repair.is_some() {
                return Err("conflicting feature completion blocks admission".into());
            }
            Ok((
                audit,
                FeatureRecord {
                    intent,
                    running,
                    result,
                    repair,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    pub(crate) fn fixture() -> FeatureRunIntent {
        let spec = json!({"schema":"hol-gauntlet-feature-executor.v1","audit_id":"0123456789abcdef",
            "source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
            "candidate_archive_sha256":"c".repeat(64),"wheel_sha256":"d".repeat(64),
            "native_sha256":"e".repeat(64),"executor_sha256":"f".repeat(64),"version":"3.58.0",
            "catalog_sha256":gauntlet_contracts::FEATURE_CATALOG_SHA256,
            "node_sha256":gauntlet_contracts::FEATURE_NODE_SHA256});
        let mut p = json!({"executor_spec":spec,"build_job_id":"0123456789abcdee",
            "controller_root":"/opt/hol-gauntlet/controller-0123456789abcdee",
            "builder_image_id":format!("sha256:{}","a".repeat(64))});
        for k in [
            "build_result_sha256",
            "controller_tree_sha256",
            "uv_base_image_id",
            "rust_base_image_id",
            "policy_sha256",
            "podman_sha256",
            "slirp4netns_sha256",
            "apparmor_parser_sha256",
            "seccomp_sha256",
            "runner_binary_sha256",
        ] {
            p[k] = json!("b".repeat(64));
        }
        FeatureRunIntent::new(
            gauntlet_contracts::FeatureRunPins::from_value(p).unwrap(),
            "/opt/homebrew/bin/limactl",
            "owned-vm",
            &"c".repeat(64),
        )
        .unwrap()
    }
    fn with_root(f: impl FnOnce(&OwnedFd, (u32, u32))) {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let m = std::fs::metadata(t.path()).unwrap();
        let fd = rustix::fs::open(
            t.path(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        f(&fd, (m.uid(), m.gid()));
    }
    #[test]
    fn reservation_survives_restart_and_cannot_be_replayed_or_completed_twice() {
        with_root(|root, owner| {
            let intent = fixture();
            let id = intent.pins().audit_id();
            let body = serde_json::from_slice(&intent.bytes().unwrap()).unwrap();
            write(root, id, "intent.json", &body, owner).unwrap();
            let records = inventory(root, owner).unwrap();
            let r = records.get(id).unwrap();
            assert_eq!(r.intent, intent);
            assert!(r.result.is_none() && r.repair.is_none() && r.running.is_none());
            assert!(write(root, id, "intent.json", &body, owner).is_err());
            write(root, id, "result.json", &json!({}), owner).unwrap();
            write(root, id, "repair.json", &json!({}), owner).unwrap();
            assert!(inventory(root, owner).is_err());
        });
    }
    #[test]
    fn partial_orphan_and_unknown_records_block_inventory() {
        with_root(|root, owner| {
            files::write(root, "0123456789abcdef.intent.json", b"{", owner, 0o600).unwrap();
            assert!(inventory(root, owner).is_err());
        });
        with_root(|root, owner| {
            write(root, "0123456789abcdef", "running.json", &json!({}), owner).unwrap();
            assert!(inventory(root, owner).is_err());
        });
        with_root(|root, owner| {
            files::write(root, "anything", b"{}", owner, 0o600).unwrap();
            assert!(inventory(root, owner).is_err());
        });
    }
    #[test]
    fn running_pid_cgroup_and_container_must_bind_exact_reserved_intent() {
        let intent = fixture();
        let v = json!({"schema":"hol-gauntlet-native-feature-running.v1","audit_id":intent.pins().audit_id(),
            "intent_sha256":intent.digest().unwrap(),"worker_generation":intent.pins().text("runner_binary_sha256"),
            "container_id":"d".repeat(64),"client_pid":123,"client_start_ticks":456,
            "client_cgroup":"/system.slice/hol-gauntlet-rust-feature-0123456789abcdef"});
        validate_running(&intent, &v).unwrap();
        for (key, bad) in [
            ("client_pid", json!(1)),
            ("client_start_ticks", json!(0)),
            ("client_cgroup", json!("/system.slice/other")),
            ("container_id", json!("d".repeat(12))),
            ("intent_sha256", json!("e".repeat(64))),
        ] {
            let mut changed = v.clone();
            changed[key] = bad;
            assert!(validate_running(&intent, &changed).is_err(), "{key}");
        }
    }
}
