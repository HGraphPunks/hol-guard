//! New fixed native launch declaration, authenticated before any mount.
use crate::{hash, hex, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use std::path::{Component, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateProfile {
    Persistent,
    Memory,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkProfile {
    UnixOnly,
    PrivateLoopback { parent_namespace: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsSpec {
    pub stage: PathBuf,
    pub initializer_sha256: String,
    pub artifact_manifest_sha256: String,
    pub system_spec_sha256: String,
    pub task_spec_sha256: String,
    pub runtime_spec_sha256: String,
    pub idmap_runtime: String,
    pub state: StateProfile,
    pub network: NetworkProfile,
}

pub(crate) fn literal_path(raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    if raw.is_empty()
        || raw.len() > 4096
        || raw.chars().any(char::is_control)
        || !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || path.to_str() != Some(raw)
        || (raw != "/" && raw.ends_with('/'))
        || raw.contains("//")
        || raw.split('/').any(|part| part == ".")
    {
        return Err("canonical literal absolute path required".into());
    }
    Ok(path)
}

fn field(value: &Value, name: &str) -> Result<String> {
    value[name]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("rootfs {name} must be a string"))
}

impl RootfsSpec {
    pub fn parse(raw: &[u8], expected_sha256: &str) -> Result<Self> {
        if raw.len() > 8192 || !hex(expected_sha256, 64) || hash(raw) != expected_sha256 {
            return Err("outside rootfs declaration digest/byte bound differs".into());
        }
        let canonical = canonicalize(raw).map_err(|_| "invalid bounded rootfs JSON")?;
        let value: Value = serde_json::from_slice(&canonical).map_err(|_| "invalid rootfs JSON")?;
        let keys = [
            "schema",
            "stage",
            "initializer_sha256",
            "artifact_manifest_sha256",
            "system_spec_sha256",
            "task_spec_sha256",
            "runtime_spec_sha256",
            "idmap_runtime",
            "state",
            "network_profile",
            "parent_network_namespace",
        ];
        if value.as_object().is_none_or(|object| {
            object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key))
        }) || value["schema"] != "hol-gauntlet-product-rootfs.v1"
        {
            return Err("exact native rootfs declaration required".into());
        }
        for name in keys.iter().filter(|name| name.ends_with("sha256")) {
            if !hex(&field(&value, name)?, 64) {
                return Err(format!("exact rootfs {name} required"));
            }
        }
        let stage = literal_path(&field(&value, "stage")?)?;
        if stage.components().count() < 4 {
            return Err("separate owned rootfs stage required".into());
        }
        let idmap_runtime = field(&value, "idmap_runtime")?;
        if !matches!(
            idmap_runtime.as_str(),
            "ubuntu2404-product-v1" | "ubuntu2404-controller-v1"
        ) {
            return Err("versioned fixed idmap runtime required".into());
        }
        let state = match field(&value, "state")?.as_str() {
            "persistent-v1" => StateProfile::Persistent,
            "memory-v1" => StateProfile::Memory,
            _ => return Err("versioned fixed product state required".into()),
        };
        let network = match field(&value, "network_profile")?.as_str() {
            "unix-only-v1" if value["parent_network_namespace"].is_null() => {
                NetworkProfile::UnixOnly
            }
            "private-loopback-v1" => {
                let parent = field(&value, "parent_network_namespace")?;
                let number = parent
                    .strip_prefix("net:[")
                    .and_then(|s| s.strip_suffix(']'))
                    .ok_or("exact parent net namespace required")?;
                if number.is_empty()
                    || number.len() > 20
                    || !number.bytes().all(|b| b.is_ascii_digit())
                    || number.starts_with('0')
                    || number.parse::<u64>().ok().is_none_or(|n| n == 0)
                {
                    return Err("exact parent net namespace inode required".into());
                }
                NetworkProfile::PrivateLoopback {
                    parent_namespace: parent,
                }
            }
            _ => return Err("versioned fixed private network required".into()),
        };
        Ok(Self {
            stage,
            initializer_sha256: field(&value, "initializer_sha256")?,
            artifact_manifest_sha256: field(&value, "artifact_manifest_sha256")?,
            system_spec_sha256: field(&value, "system_spec_sha256")?,
            task_spec_sha256: field(&value, "task_spec_sha256")?,
            runtime_spec_sha256: field(&value, "runtime_spec_sha256")?,
            idmap_runtime,
            state,
            network,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value {
        let mut v = json!({"schema":"hol-gauntlet-product-rootfs.v1","stage":"/var/lib/hol-gauntlet/test-cell",
            "idmap_runtime":"ubuntu2404-controller-v1","state":"persistent-v1",
            "network_profile":"private-loopback-v1","parent_network_namespace":"net:[4026531992]"});
        for name in [
            "initializer_sha256",
            "artifact_manifest_sha256",
            "system_spec_sha256",
            "task_spec_sha256",
            "runtime_spec_sha256",
        ] {
            v[name] = json!("a".repeat(64));
        }
        v
    }
    fn parse(v: &Value) -> Result<RootfsSpec> {
        let raw = v.to_string();
        RootfsSpec::parse(raw.as_bytes(), &hash(raw.as_bytes()))
    }
    #[test]
    fn native_launch_profiles_are_fixed_and_independently_byte_pinned() {
        let value = fixture();
        let spec = parse(&value).unwrap();
        assert_eq!(spec.state, StateProfile::Persistent);
        assert!(matches!(
            spec.network,
            NetworkProfile::PrivateLoopback { .. }
        ));
        let raw = value.to_string();
        assert!(RootfsSpec::parse(raw.as_bytes(), &"b".repeat(64)).is_err());
        let mut unix = value;
        unix["network_profile"] = json!("unix-only-v1");
        assert!(parse(&unix).is_err());
        unix["parent_network_namespace"] = Value::Null;
        assert_eq!(parse(&unix).unwrap().network, NetworkProfile::UnixOnly);
    }
    #[test]
    fn root_programs_environment_and_paths_cannot_be_selected() {
        for (name, bad) in [
            ("stage", json!("/tmp/../host")),
            ("stage", json!("/var/./lib/cell")),
            ("stage", json!("/")),
            ("stage", json!("/var//lib/cell")),
            ("stage", json!("/var/lib/cell/")),
            ("initializer_sha256", json!("A".repeat(64))),
            ("idmap_runtime", json!("custom")),
            ("parent_network_namespace", json!("/proc/1/ns/net")),
            ("parent_network_namespace", json!("net:[0]")),
            ("state", json!("/etc")),
            ("program", json!("/candidate/root-program")),
            ("env", json!({})),
        ] {
            let mut changed = fixture();
            changed[name] = bad;
            assert!(parse(&changed).is_err(), "{name}");
        }
        let raw = b"{\"schema\":\"x\",\"schema\":\"y\"}";
        assert!(RootfsSpec::parse(raw, &hash(raw)).is_err());
    }
}
