//! Inert, outside-pinned mount inputs. No caller may choose a Root program.
use crate::{hex, spec::literal_path, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    pub root: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub workspace: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runtime {
    pub prefix: PathBuf,
    pub mountpoint: PathBuf,
    pub tree_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskMount {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub custody_root: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
}

pub(crate) fn object(raw: &[u8], maximum: usize, keys: &[&str], schema: &str) -> Result<Value> {
    if raw.len() > maximum {
        return Err("mount declaration byte bound".into());
    }
    let canonical = canonicalize(raw).map_err(|_| "ambiguous mount declaration JSON")?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| "mount declaration JSON")?;
    exact(&value, keys)?;
    if value["schema"] != schema {
        return Err("versioned mount declaration required".into());
    }
    Ok(value)
}

fn exact(value: &Value, keys: &[&str]) -> Result<()> {
    if value
        .as_object()
        .is_none_or(|v| v.len() != keys.len() || keys.iter().any(|key| !v.contains_key(*key)))
    {
        return Err("exact mount declaration fields required".into());
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("mount {key} must be text"))
}
fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("mount {key} must be a nonnegative integer"))
}
pub(crate) fn overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

impl System {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let v = object(
            raw,
            4096,
            &["schema", "root", "device", "inode", "image_id", "workspace"],
            "product-cell-image-system.v1",
        )?;
        let root = literal_path(text(&v, "root")?)?;
        let image = text(&v, "image_id")?;
        let workspace = text(&v, "workspace")?;
        if root == Path::new("/")
            || !image.strip_prefix("sha256:").is_some_and(|s| hex(s, 64))
            || !matches!(workspace, "/task" | "/runtime/home/project")
        {
            return Err("separate pinned image and fixed workspace required".into());
        }
        Ok(Self {
            root,
            device: number(&v, "device")?,
            inode: number(&v, "inode")?,
            workspace: workspace.into(),
        })
    }
}

impl Runtime {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let v = object(
            raw,
            8192,
            &["schema", "prefix", "mountpoint", "tree_digest"],
            "product-vm-runtime-mount.v1",
        )?;
        let prefix = literal_path(text(&v, "prefix")?)?;
        let mountpoint = literal_path(text(&v, "mountpoint")?)?;
        let family = mountpoint
            .components()
            .nth(1)
            .and_then(|p| p.as_os_str().to_str());
        let digest = text(&v, "tree_digest")?;
        if prefix == Path::new("/")
            || mountpoint.components().count() < 3
            || !matches!(family, Some("home" | "runtime" | "opt"))
            || overlap(&mountpoint, Path::new("/opt/node"))
            || !hex(digest, 64)
        {
            return Err("separate pinned runtime mount required".into());
        }
        Ok(Self {
            prefix,
            mountpoint,
            tree_digest: digest.into(),
        })
    }
}

pub fn parse_tasks(
    raw: &[u8],
    stage: &Path,
    system: &System,
    runtime: &Runtime,
) -> Result<Vec<TaskMount>> {
    let v = object(
        raw,
        32768,
        &["schema", "workspace", "providers"],
        "product-cell-task-mounts.v1",
    )?;
    let providers = v["providers"]
        .as_array()
        .filter(|a| a.len() <= 8)
        .ok_or("bounded provider mounts required")?;
    let mut result: Vec<TaskMount> = Vec::new();
    for (index, row) in std::iter::once(&v["workspace"])
        .chain(providers)
        .enumerate()
    {
        exact(
            row,
            &[
                "source",
                "destination",
                "custody_root",
                "device",
                "inode",
                "mode",
            ],
        )?;
        let source = literal_path(text(row, "source")?)?;
        let destination = literal_path(text(row, "destination")?)?;
        let custody_root = literal_path(text(row, "custody_root")?)?;
        let mode = number(row, "mode")?;
        if source == custody_root
            || !source.starts_with(&custody_root)
            || overlap(&source, stage)
            || mode & !0o755 != 0
            || mode & 0o700 != 0o700
            || (index == 0 && destination != Path::new(&system.workspace))
            || (index > 0
                && (destination != source
                    || destination.components().count() < 4
                    || !matches!(
                        destination
                            .components()
                            .nth(1)
                            .and_then(|p| p.as_os_str().to_str()),
                        Some("home" | "opt")
                    )))
            || [
                "/usr",
                "/etc",
                "/proc",
                "/product",
                "/public",
                "/dev",
                "/tmp",
                "/run",
                "/opt/node",
            ]
            .iter()
            .any(|p| overlap(&destination, Path::new(p)))
            || overlap(&destination, &runtime.mountpoint)
            || result
                .iter()
                .any(|p| overlap(&source, &p.source) || overlap(&destination, &p.destination))
        {
            return Err("task mounts must preserve custody and disjoint fixed destinations".into());
        }
        result.push(TaskMount {
            source,
            destination,
            custody_root,
            device: number(row, "device")?,
            inode: number(row, "inode")?,
            mode: mode as u32,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn inputs() -> (System, Runtime, Value) {
        let system = System::parse(json!({"schema":"product-cell-image-system.v1","root":"/var/lib/images/root",
            "device":1,"inode":2,"image_id":format!("sha256:{}","a".repeat(64)),"workspace":"/runtime/home/project"}).to_string().as_bytes()).unwrap();
        let runtime = Runtime::parse(
            json!({"schema":"product-vm-runtime-mount.v1","prefix":"/opt/hol-gauntlet/prefix",
            "mountpoint":"/runtime/guard","tree_digest":"b".repeat(64)})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let tasks = json!({"schema":"product-cell-task-mounts.v1","workspace":{"source":"/home/custody/task",
            "destination":"/runtime/home/project","custody_root":"/home/custody","device":1,"inode":3,"mode":448},"providers":[]});
        (system, runtime, tasks)
    }
    #[test]
    fn physical_sources_and_logical_destinations_have_separate_contracts() {
        let (system, runtime, tasks) = inputs();
        assert_eq!(
            parse_tasks(
                tasks.to_string().as_bytes(),
                Path::new("/var/lib/cell/stage"),
                &system,
                &runtime
            )
            .unwrap()
            .len(),
            1
        );
        for (key, bad) in [
            ("source", json!("/var/lib/cell/stage/private")),
            ("source", json!("/home/custody")),
            ("destination", json!("/etc/guard")),
            ("destination", json!("/runtime/guard")),
            ("mode", json!(511)),
            ("mode", json!(true)),
            ("inode", json!(-1)),
            ("device", json!(1.0)),
            ("source", json!("/home/../etc")),
        ] {
            let mut changed = tasks.clone();
            changed["workspace"][key] = bad;
            assert!(
                parse_tasks(
                    changed.to_string().as_bytes(),
                    Path::new("/var/lib/cell/stage"),
                    &system,
                    &runtime
                )
                .is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn provider_aliases_and_unbounded_mounts_are_refused() {
        let (system, runtime, mut tasks) = inputs();
        let provider = json!({"source":"/home/provider/tools","destination":"/home/provider/tools","custody_root":"/home/provider","device":1,"inode":4,"mode":493});
        tasks["providers"] = json!([provider]);
        let check = |v: &Value| {
            parse_tasks(
                v.to_string().as_bytes(),
                Path::new("/var/lib/cell/stage"),
                &system,
                &runtime,
            )
        };
        assert_eq!(check(&tasks).unwrap().len(), 2);
        tasks["providers"] = json!([provider, provider]);
        assert!(check(&tasks).is_err());
        tasks["providers"] = json!(vec![provider; 9]);
        assert!(check(&tasks).is_err());
        tasks["providers"] = json!([]);
        tasks["root_program"] = json!("/bin/sh");
        assert!(check(&tasks).is_err());
    }
    #[test]
    fn runtime_cannot_shadow_system_or_task_mounts() {
        for point in [
            "/",
            "/usr/lib",
            "/opt",
            "/opt/node",
            "/opt/node/lib",
            "/runtime/../usr",
            "/runtime//guard",
        ] {
            let raw=json!({"schema":"product-vm-runtime-mount.v1","prefix":"/opt/prefix","mountpoint":point,"tree_digest":"a".repeat(64)}).to_string();
            assert!(Runtime::parse(raw.as_bytes()).is_err(), "{point}");
        }
    }
}
