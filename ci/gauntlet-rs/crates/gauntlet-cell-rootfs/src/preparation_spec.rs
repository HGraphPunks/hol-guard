//! A preparation declaration selects pinned data and fixed launch profiles.
use crate::declarations::{object, overlap};
use crate::{hash, hex, spec::literal_path, Result, SupervisorSpec};
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CellPreparation {
    pub stage: PathBuf,
    pub artifacts: PathBuf,
    pub artifact_manifest_sha256: String,
    pub initializer_sha256: String,
    pub runtime_prefix: PathBuf,
    pub runtime_tree_digest: String,
    pub image_id: String,
    pub podman_sha256: String,
    pub task_mounts: Value,
    launch: Value,
}

impl CellPreparation {
    pub fn job_slice(&self) -> Option<&str> {
        self.launch["job_slice"].as_str()
    }
    pub fn host_helper_sha256(&self, name: &str) -> Option<&str> {
        self.launch["host_helpers"][name].as_str()
    }
    pub fn wall_seconds(&self) -> u64 {
        self.launch["wall_seconds"]
            .as_u64()
            .expect("parsed fixed launch template")
    }

    pub fn parse(raw: &[u8], expected: &str) -> Result<Self> {
        if !hex(expected, 64) || hash(raw) != expected {
            return Err("cell preparation differs from outside pin".into());
        }
        let value = object(
            raw,
            49152,
            &[
                "schema",
                "stage",
                "artifacts",
                "artifact_manifest_sha256",
                "initializer_sha256",
                "runtime_prefix",
                "runtime_tree_digest",
                "image_id",
                "podman_sha256",
                "task_mounts",
                "launch",
            ],
            "hol-gauntlet-cell-preparation.v1",
        )?;
        let text = |key: &str| {
            value[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("cell preparation {key} must be text"))
        };
        let stage = literal_path(&text("stage")?)?;
        let artifacts = literal_path(&text("artifacts")?)?;
        let runtime_prefix = literal_path(&text("runtime_prefix")?)?;
        if !stage.starts_with("/var/lib/hol-gauntlet-rust")
            || stage.components().count() < 5
            || !artifacts.starts_with("/opt/hol-gauntlet")
            || artifacts.components().count() < 5
            || !runtime_prefix.starts_with("/opt/hol-gauntlet")
            || runtime_prefix.components().count() < 5
            || overlap(&stage, &artifacts)
            || overlap(&stage, &runtime_prefix)
            || overlap(&artifacts, &runtime_prefix)
        {
            return Err(
                "separate fixed Root stage, artifact and installed runtime paths required".into(),
            );
        }
        let artifact_manifest_sha256 = text("artifact_manifest_sha256")?;
        let initializer_sha256 = text("initializer_sha256")?;
        let runtime_tree_digest = text("runtime_tree_digest")?;
        let podman_sha256 = text("podman_sha256")?;
        if [
            &artifact_manifest_sha256,
            &initializer_sha256,
            &runtime_tree_digest,
            &podman_sha256,
        ]
        .iter()
        .any(|s| !hex(s, 64))
        {
            return Err("outside preparation artifact/runtime/helper pins required".into());
        }
        let image_id = text("image_id")?;
        crate::image_protocol::image_id(&image_id)?;
        let launch = value["launch"].clone();
        let mut fields = vec![
            "schema",
            "constructor",
            "constructor_sha256",
            "wall_seconds",
            "cpu_profile",
            "job_slice",
            "host_helpers",
        ];
        if launch["schema"] == "hol-gauntlet-cell-supervisor.v2" {
            fields.extend(["image_interpreter_sha256", "outside_observer_sha256"]);
        }
        if launch
            .as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
        {
            return Err("exact fixed supervisor launch template required".into());
        }
        let parsed = Self {
            stage,
            artifacts,
            artifact_manifest_sha256,
            initializer_sha256,
            runtime_prefix,
            runtime_tree_digest,
            image_id,
            podman_sha256,
            task_mounts: value["task_mounts"].clone(),
            launch,
        };
        parsed.supervisor(&"0".repeat(64))?;
        let runtime = crate::declarations::Runtime::parse(parsed.runtime().to_string().as_bytes())?;
        let system = crate::declarations::System::parse(
            json!({"schema":"product-cell-image-system.v1",
            "root":"/var/lib/hol-gauntlet-rust/unmounted-image","device":0,"inode":0,
            "image_id":parsed.image_id,"workspace":"/runtime/home/project"})
            .to_string()
            .as_bytes(),
        )?;
        crate::declarations::parse_tasks(
            parsed.task_mounts.to_string().as_bytes(),
            &parsed.stage,
            &system,
            &runtime,
        )?;
        Ok(parsed)
    }

    pub(crate) fn runtime(&self) -> Value {
        json!({"schema":"product-vm-runtime-mount.v1","prefix":self.runtime_prefix,
            "mountpoint":self.runtime_prefix,"tree_digest":self.runtime_tree_digest})
    }

    pub(crate) fn supervisor(&self, rootfs_sha256: &str) -> Result<Value> {
        let mut value = self.launch.clone();
        value["rootfs_declaration"] = json!(self.stage.join("native-rootfs.v1.json"));
        value["rootfs_sha256"] = json!(rootfs_sha256);
        let raw = value.to_string();
        SupervisorSpec::parse(raw.as_bytes(), &hash(raw.as_bytes()))?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let helpers = crate::supervisor_spec::HOST_HELPERS
            .iter()
            .map(|name| ((*name).to_owned(), "f".repeat(64)))
            .collect::<std::collections::BTreeMap<_, _>>();
        json!({"schema":"hol-gauntlet-cell-preparation.v1","stage":"/var/lib/hol-gauntlet-rust/proofs/cell",
            "artifacts":"/opt/hol-gauntlet/generation/artifacts","artifact_manifest_sha256":"a".repeat(64),"initializer_sha256":"b".repeat(64),
            "runtime_prefix":"/opt/hol-gauntlet/generation/prefix","runtime_tree_digest":"c".repeat(64),
            "image_id":format!("sha256:{}","d".repeat(64)),"podman_sha256":"e".repeat(64),
            "task_mounts":{"schema":"product-cell-task-mounts.v1","workspace":{"source":"/home/custody/checkout","destination":"/runtime/home/project","custody_root":"/home/custody","device":1,"inode":2,"mode":493},"providers":[]},
            "launch":{"schema":"hol-gauntlet-cell-supervisor.v1","constructor":"/opt/hol-gauntlet/generation/gauntlet-cell-rootfs","constructor_sha256":"f".repeat(64),"wall_seconds":180,"cpu_profile":"single-core-v1","job_slice":null,"host_helpers":helpers}})
    }
    fn parse(v: &Value) -> Result<CellPreparation> {
        let raw = v.to_string();
        CellPreparation::parse(raw.as_bytes(), &hash(raw.as_bytes()))
    }
    #[test]
    fn preparation_pins_data_and_cannot_select_arbitrary_root_execution() {
        let v = fixture();
        let parsed = parse(&v).unwrap();
        assert_eq!(
            parsed.supervisor(&"a".repeat(64)).unwrap()["rootfs_declaration"],
            "/var/lib/hol-gauntlet-rust/proofs/cell/native-rootfs.v1.json"
        );
        for (pointer, bad) in [
            ("/image_id", json!("ubuntu:latest")),
            ("/podman_sha256", json!("x".repeat(64))),
            ("/stage", json!("/tmp/cell")),
            ("/artifacts", json!("/opt/hol-gauntlet/generation/prefix")),
            ("/launch/constructor", json!("/usr/bin/sh")),
            ("/launch/job_slice", json!("system.slice")),
            ("/launch/wall_seconds", json!(true)),
            (
                "/task_mounts/workspace/source",
                json!("/home/custody/../root"),
            ),
        ] {
            let mut bad_value = v.clone();
            *bad_value.pointer_mut(pointer).unwrap() = bad;
            assert!(parse(&bad_value).is_err(), "{pointer}");
        }
        let mut value = v;
        value["launch"]["environment"] = json!({"LD_PRELOAD":"/task/file"});
        assert!(parse(&value).is_err());
    }
    #[test]
    fn preparation_carries_both_versioned_prelaunch_pins_into_the_supervisor() {
        let mut value = fixture();
        value["launch"]["image_interpreter_sha256"] = json!("a".repeat(64));
        value["launch"]["outside_observer_sha256"] = json!("b".repeat(64));
        assert!(parse(&value).is_err());
        value["launch"]["schema"] = json!("hol-gauntlet-cell-supervisor.v2");
        let parsed = parse(&value).unwrap();
        let supervisor = parsed.supervisor(&"c".repeat(64)).unwrap();
        assert_eq!(
            supervisor["image_interpreter_sha256"],
            value["launch"]["image_interpreter_sha256"]
        );
        assert_eq!(
            supervisor["outside_observer_sha256"],
            value["launch"]["outside_observer_sha256"]
        );
        value["launch"]
            .as_object_mut()
            .unwrap()
            .remove("image_interpreter_sha256");
        assert!(parse(&value).is_err());
    }
}
