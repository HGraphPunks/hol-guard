//! Separate Root supervisor launch contract. Candidate RPCs cannot select it.
use crate::declarations::object;
use crate::{hash, hex, spec::literal_path, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuProfile {
    Quota,
    SingleCore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorSpec {
    pub rootfs_declaration: PathBuf,
    pub rootfs_sha256: String,
    pub constructor: PathBuf,
    pub constructor_sha256: String,
    pub wall_seconds: u64,
    pub cpu: CpuProfile,
    pub job_slice: Option<String>,
    pub host_helpers: BTreeMap<String, String>,
    pub image_interpreter_sha256: Option<String>,
    pub outside_observer_sha256: Option<String>,
    pub process_events: bool,
}

pub const HOST_HELPERS: &[&str] = &[
    "/usr/bin/systemd-run",
    "/usr/bin/systemctl",
    "/usr/bin/aa-exec",
    "/usr/bin/unshare",
    "/usr/sbin/apparmor_parser",
];

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("supervisor {key} must be text"))
}

impl SupervisorSpec {
    pub fn parse(raw: &[u8], expected: &str) -> Result<Self> {
        if !hex(expected, 64) || hash(raw) != expected {
            return Err("supervisor declaration differs from outside pin".into());
        }
        let fields = [
            "schema",
            "rootfs_declaration",
            "rootfs_sha256",
            "constructor",
            "constructor_sha256",
            "wall_seconds",
            "cpu_profile",
            "job_slice",
            "host_helpers",
        ];
        let mut pinned_fields = fields.to_vec();
        pinned_fields.extend(["image_interpreter_sha256", "outside_observer_sha256"]);
        let mut traced_fields = pinned_fields.clone();
        traced_fields.push("process_events");
        let value = object(raw, 8192, &fields, "hol-gauntlet-cell-supervisor.v1")
            .or_else(|_| object(raw, 8192, &pinned_fields, "hol-gauntlet-cell-supervisor.v2"))
            .or_else(|_| object(raw, 8192, &traced_fields, "hol-gauntlet-cell-supervisor.v3"))?;
        let process_events = value["schema"] == "hol-gauntlet-cell-supervisor.v3";
        if process_events && value["process_events"] != "outside-root-ptrace.v1" {
            return Err("fixed outside Root process-event recorder required".into());
        }
        let (image_interpreter_sha256, outside_observer_sha256) =
            if value["schema"] != "hol-gauntlet-cell-supervisor.v1" {
                let interpreter = text(&value, "image_interpreter_sha256")?;
                let observer = text(&value, "outside_observer_sha256")?;
                if !hex(interpreter, 64) || !hex(observer, 64) {
                    return Err("exact prelaunch interpreter and observer digests required".into());
                }
                (Some(interpreter.to_owned()), Some(observer.to_owned()))
            } else {
                (None, None)
            };
        let rootfs_declaration = literal_path(text(&value, "rootfs_declaration")?)?;
        let constructor = literal_path(text(&value, "constructor")?)?;
        if !rootfs_declaration.starts_with("/var/lib/hol-gauntlet-rust")
            || rootfs_declaration.file_name().and_then(|p| p.to_str())
                != Some("native-rootfs.v1.json")
            || !constructor.starts_with("/opt/hol-gauntlet")
            || constructor.components().count() < 5
            || constructor.file_name().and_then(|p| p.to_str()) != Some("gauntlet-cell-rootfs")
        {
            return Err("fixed Root declaration and constructor locations required".into());
        }
        let rootfs_sha256 = text(&value, "rootfs_sha256")?.to_owned();
        let constructor_sha256 = text(&value, "constructor_sha256")?.to_owned();
        if !hex(&rootfs_sha256, 64) || !hex(&constructor_sha256, 64) {
            return Err("outside constructor and rootfs SHA256 required".into());
        }
        let wall_seconds = value["wall_seconds"]
            .as_u64()
            .filter(|n| (10..=4000).contains(n))
            .ok_or("bounded cell wall deadline required")?;
        let cpu = match text(&value, "cpu_profile")? {
            "quota-v1" => CpuProfile::Quota,
            "single-core-v1" => CpuProfile::SingleCore,
            _ => return Err("fixed cell CPU profile required".into()),
        };
        let job_slice = if value["job_slice"].is_null() {
            None
        } else {
            let name = text(&value, "job_slice")?;
            let id = name
                .strip_prefix("holgauntletrust")
                .and_then(|s| s.strip_suffix(".slice"))
                .filter(|s| hex(s, 16))
                .ok_or("exact Rust job slice required")?;
            Some(format!("holgauntletrust{id}.slice"))
        };
        let helpers = value["host_helpers"]
            .as_object()
            .filter(|v| v.len() == HOST_HELPERS.len())
            .ok_or("exact Root host-helper map required")?;
        let mut host_helpers = BTreeMap::new();
        for name in HOST_HELPERS {
            let pin = helpers
                .get(*name)
                .and_then(Value::as_str)
                .filter(|s| hex(s, 64))
                .ok_or("outside pin for every fixed Root host helper required")?;
            host_helpers.insert((*name).into(), pin.into());
        }
        Ok(Self {
            rootfs_declaration,
            rootfs_sha256,
            constructor,
            constructor_sha256,
            wall_seconds,
            cpu,
            job_slice,
            host_helpers,
            image_interpreter_sha256,
            outside_observer_sha256,
            process_events,
        })
    }

    pub fn cgroup_path(&self, profile: &str) -> Result<PathBuf> {
        let suffix = profile
            .strip_prefix("hol-product-cell-")
            .filter(|s| hex(s, 32))
            .ok_or("fresh fixed product service name required")?;
        Ok(Path::new("/sys/fs/cgroup")
            .join(self.job_slice.as_deref().unwrap_or("system.slice"))
            .join(format!("hol-product-cell-{suffix}.service")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value {
        let mut value = json!({"schema":"hol-gauntlet-cell-supervisor.v1",
            "rootfs_declaration":"/var/lib/hol-gauntlet-rust/cell/stage/native-rootfs.v1.json",
            "rootfs_sha256":"a".repeat(64),"constructor":"/opt/hol-gauntlet/generation/gauntlet-cell-rootfs",
            "constructor_sha256":"b".repeat(64),"wall_seconds":180,"cpu_profile":"single-core-v1","job_slice":null});
        value["host_helpers"] = json!(HOST_HELPERS
            .iter()
            .map(|p| ((*p).to_owned(), "c".repeat(64)))
            .collect::<BTreeMap<_, _>>());
        value
    }
    fn parse(v: &Value) -> Result<SupervisorSpec> {
        let raw = v.to_string();
        SupervisorSpec::parse(raw.as_bytes(), &hash(raw.as_bytes()))
    }
    #[test]
    fn only_the_owned_service_and_parent_slice_can_be_selected() {
        let mut value = fixture();
        let name = format!("hol-product-cell-{}", "c".repeat(32));
        let spec = parse(&value).unwrap();
        assert_eq!(
            spec.cgroup_path(&name).unwrap(),
            PathBuf::from(format!("/sys/fs/cgroup/system.slice/{name}.service"))
        );
        value["job_slice"] = json!("holgauntletrust0123456789abcdef.slice");
        assert!(parse(&value)
            .unwrap()
            .cgroup_path(&name)
            .unwrap()
            .starts_with("/sys/fs/cgroup/holgauntletrust0123456789abcdef.slice"));
        for name in [
            "sshd",
            "hol-product-cell-abc",
            "hol-product-cell-../../sshd",
            &format!("hol-product-cell-{}", "C".repeat(32)),
        ] {
            assert!(spec.cgroup_path(name).is_err());
        }
    }
    #[test]
    fn arbitrary_programs_environments_limits_and_cgroups_are_refused() {
        for (key, bad) in [
            ("constructor", json!("/bin/sh")),
            ("constructor", json!("/opt/hol-gauntlet/generation/custom")),
            ("rootfs_declaration", json!("/tmp/native-rootfs.v1.json")),
            (
                "rootfs_declaration",
                json!("/var/lib/hol-gauntlet-rust/../etc/native-rootfs.v1.json"),
            ),
            ("constructor_sha256", json!("x".repeat(64))),
            ("wall_seconds", json!(0)),
            ("wall_seconds", json!(4001)),
            ("wall_seconds", json!(true)),
            ("wall_seconds", json!(180.0)),
            ("cpu_profile", json!("unlimited")),
            ("job_slice", json!("system.slice")),
            ("job_slice", json!("/sys/fs/cgroup")),
            ("environment", json!({})),
            ("memory_max", json!("infinity")),
        ] {
            let mut value = fixture();
            value[key] = bad;
            assert!(parse(&value).is_err(), "{key}");
        }
        let raw = fixture().to_string();
        assert!(SupervisorSpec::parse(raw.as_bytes(), &"0".repeat(64)).is_err());
    }
    #[test]
    fn pinned_launch_is_closed_versioned_and_cannot_borrow_a_legacy_declaration() {
        let mut value = fixture();
        assert!(parse(&value).unwrap().image_interpreter_sha256.is_none());
        value["image_interpreter_sha256"] = json!("d".repeat(64));
        value["outside_observer_sha256"] = json!("e".repeat(64));
        assert!(parse(&value).is_err());
        value["schema"] = json!("hol-gauntlet-cell-supervisor.v2");
        let pins = parse(&value).unwrap();
        assert_eq!(
            pins.image_interpreter_sha256.as_deref(),
            Some("d".repeat(64).as_str())
        );
        assert_eq!(
            pins.outside_observer_sha256.as_deref(),
            Some("e".repeat(64).as_str())
        );
        for (key, bad) in [
            ("image_interpreter_sha256", json!(true)),
            ("outside_observer_sha256", Value::Null),
            ("image_interpreter_sha256", json!("latest")),
            ("interpreter_path", json!("/tmp/custom")),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            assert!(parse(&changed).is_err(), "{key}");
        }
        value
            .as_object_mut()
            .unwrap()
            .remove("outside_observer_sha256");
        assert!(parse(&value).is_err());
    }

    #[test]
    fn only_closed_v3_can_require_the_fixed_process_event_recorder() {
        let mut value = fixture();
        assert!(!parse(&value).unwrap().process_events);
        value["image_interpreter_sha256"] = json!("a".repeat(64));
        value["outside_observer_sha256"] = json!("b".repeat(64));
        value["schema"] = json!("hol-gauntlet-cell-supervisor.v2");
        assert!(!parse(&value).unwrap().process_events);
        value["process_events"] = json!("outside-root-ptrace.v1");
        assert!(parse(&value).is_err());
        value["schema"] = json!("hol-gauntlet-cell-supervisor.v3");
        assert!(parse(&value).unwrap().process_events);
        for bad in [
            json!(false),
            Value::Null,
            json!("poll"),
            json!("/bin/observer"),
        ] {
            let mut changed = value.clone();
            changed["process_events"] = bad;
            assert!(parse(&changed).is_err());
        }
        for field in [
            "process_events",
            "image_interpreter_sha256",
            "outside_observer_sha256",
        ] {
            let mut changed = value.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(parse(&changed).is_err());
        }
    }
}
