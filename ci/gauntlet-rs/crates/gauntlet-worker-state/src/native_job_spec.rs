//! Versioned native apparatus dispatch. This profile cannot qualify Guard.
use crate::{hex, launch_plan::rust_job_slice_name};
use gauntlet_cell_rootfs::{CellPreparation, NativeCase};
use gauntlet_contracts::{canonicalize, WorkerAction, WorkerRequest};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) const NATIVE_DEPLOYMENTS: &str = "/opt/hol-gauntlet/native-deployments";
pub(crate) const NATIVE_JOBS: &str = "/var/lib/hol-gauntlet-rust/native-jobs";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) const ACTIVE_SECONDS: u64 = 300;

#[derive(Debug, Clone)]
pub struct NativeJobSpec {
    pub source_sha: String,
    pub job_id: String,
    pub worker_generation: String,
    pub preparation_sha256: String,
    pub case: NativeCase,
}

impl NativeJobSpec {
    pub fn parse(
        raw: &[u8],
        deployment: &str,
        request: &WorkerRequest,
        worker_generation: &str,
    ) -> Result<Self, String> {
        if raw.len() > 8192
            || !hex(deployment, 64)
            || format!("{:x}", Sha256::digest(raw)) != deployment
            || request.action() != WorkerAction::Run
            || !hex(worker_generation, 64)
        {
            return Err("bounded outside-pinned native run declaration required".into());
        }
        let canonical = canonicalize(raw).map_err(|_| "ambiguous native run declaration")?;
        let value: Value = serde_json::from_slice(&canonical).map_err(|_| "native run JSON")?;
        let fields = [
            "schema",
            "profile",
            "source_sha",
            "job_id",
            "worker_generation",
            "preparation_sha256",
            "case",
        ];
        if value
            .as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
            || value["schema"] != "hol-gauntlet-native-worker-job.v1"
            || value["profile"] != "native-apparatus-v1"
            || value["source_sha"] != request.source_sha()
            || value["job_id"] != request.job_id()
            || value["worker_generation"] != worker_generation
            || request.deployment_digest() != Some(deployment)
        {
            return Err("native job differs from exact request and worker generation".into());
        }
        let preparation_sha256 = value["preparation_sha256"]
            .as_str()
            .filter(|s| hex(s, 64))
            .ok_or("outside native preparation pin required")?
            .to_owned();
        let case = value["case"]
            .as_str()
            .ok_or("typed native case required")?
            .parse()?;
        Ok(Self {
            source_sha: request.source_sha().into(),
            job_id: request.job_id().into(),
            worker_generation: worker_generation.into(),
            preparation_sha256,
            case,
        })
    }

    pub fn job_root(&self) -> PathBuf {
        PathBuf::from(NATIVE_JOBS).join(&self.job_id)
    }
    pub fn preparation_path(&self) -> PathBuf {
        self.job_root().join("preparation.v1.json")
    }

    /// The native worker owns one exact job's stage and physical fixture. A
    /// declaration cannot substitute a different job's mutable task or slice.
    pub fn preparation(&self, raw: &[u8]) -> Result<CellPreparation, String> {
        let spec = CellPreparation::parse(raw, &self.preparation_sha256)?;
        let root = self.job_root();
        let workspace = &spec.task_mounts["workspace"];
        if spec.stage != root.join("cell")
            || spec.wall_seconds() != 180
            || spec.job_slice()
                != Some(
                    rust_job_slice_name(&self.job_id)
                        .map_err(|e| e.to_string())?
                        .as_str(),
                )
            || workspace["source"] != root.join("workspace").to_string_lossy().as_ref()
            || workspace["custody_root"] != root.to_string_lossy().as_ref()
            || spec.task_mounts["providers"]
                .as_array()
                .is_none_or(|a| !a.is_empty())
        {
            return Err(
                "native preparation must belong to the exact job workspace/stage/slice".into(),
            );
        }
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Value, WorkerRequest, String) {
        let generation = "c".repeat(64);
        let value = json!({"schema":"hol-gauntlet-native-worker-job.v1","profile":"native-apparatus-v1",
            "source_sha":"a".repeat(40),"job_id":"0123456789abcdef","worker_generation":generation,
            "preparation_sha256":"b".repeat(64),"case":"success"});
        let digest = format!("{:x}", Sha256::digest(value.to_string().as_bytes()));
        let request = WorkerRequest::parse(
            json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
            "source_sha":"a".repeat(40),"job_id":"0123456789abcdef","deployment_digest":digest})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        (value, request, generation)
    }
    #[test]
    fn request_source_job_deployment_and_worker_are_all_external_bindings() {
        let (value, request, generation) = fixture();
        let digest = request.deployment_digest().unwrap();
        let spec =
            NativeJobSpec::parse(value.to_string().as_bytes(), digest, &request, &generation)
                .unwrap();
        assert_eq!(
            spec.preparation_path(),
            PathBuf::from(
                "/var/lib/hol-gauntlet-rust/native-jobs/0123456789abcdef/preparation.v1.json"
            )
        );
        assert!(NativeJobSpec::parse(
            value.to_string().as_bytes(),
            digest,
            &request,
            &"d".repeat(64)
        )
        .is_err());
        for (key, bad) in [
            ("job_id", json!("fedcba9876543210")),
            ("source_sha", json!("e".repeat(40))),
            ("profile", json!("workflow")),
            ("case", json!("sh")),
            ("preparation_sha256", json!(true)),
            ("command", json!("sh")),
            ("execution_eligible", json!(true)),
        ] {
            let mut bad_value = value.clone();
            bad_value[key] = bad;
            let raw = bad_value.to_string();
            let bad_digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
            let bound_request=WorkerRequest::parse(json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
                "source_sha":request.source_sha(),"job_id":request.job_id(),"deployment_digest":bad_digest}).to_string().as_bytes()).unwrap();
            assert!(
                NativeJobSpec::parse(raw.as_bytes(), &bad_digest, &bound_request, &generation)
                    .is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn valid_preparations_cannot_borrow_another_jobs_workspace_stage_or_slice() {
        let (value, request, generation) = fixture();
        let mut job = NativeJobSpec::parse(
            value.to_string().as_bytes(),
            request.deployment_digest().unwrap(),
            &request,
            &generation,
        )
        .unwrap();
        let root = job.job_root();
        let helpers = [
            "/usr/bin/systemd-run",
            "/usr/bin/systemctl",
            "/usr/bin/aa-exec",
            "/usr/bin/unshare",
            "/usr/sbin/apparmor_parser",
        ]
        .into_iter()
        .map(|name| (name, "f".repeat(64)))
        .collect::<std::collections::BTreeMap<_, _>>();
        let value = json!({"schema":"hol-gauntlet-cell-preparation.v1","stage":root.join("cell"),
            "artifacts":"/opt/hol-gauntlet/generation/artifacts","artifact_manifest_sha256":"a".repeat(64),"initializer_sha256":"b".repeat(64),
            "runtime_prefix":"/opt/hol-gauntlet/generation/prefix","runtime_tree_digest":"c".repeat(64),"image_id":format!("sha256:{}","d".repeat(64)),"podman_sha256":"e".repeat(64),
            "task_mounts":{"schema":"product-cell-task-mounts.v1","workspace":{"source":root.join("workspace"),"destination":"/runtime/home/project","custody_root":root,"device":1,"inode":2,"mode":448},"providers":[]},
            "launch":{"schema":"hol-gauntlet-cell-supervisor.v1","constructor":"/opt/hol-gauntlet/generation/gauntlet-cell-rootfs","constructor_sha256":"f".repeat(64),"wall_seconds":180,"cpu_profile":"single-core-v1","job_slice":"holgauntletrust0123456789abcdef.slice","host_helpers":helpers}});
        let raw = value.to_string();
        job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
        assert!(job.preparation(raw.as_bytes()).is_ok());
        for (pointer, bad) in [
            (
                "/stage",
                json!("/var/lib/hol-gauntlet-rust/native-jobs/fedcba9876543210/cell"),
            ),
            (
                "/launch/job_slice",
                json!("holgauntletrustfedcba9876543210.slice"),
            ),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            let raw = changed.to_string();
            job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
            assert!(job.preparation(raw.as_bytes()).is_err(), "{pointer}");
        }
        let mut changed = value;
        changed["task_mounts"]["workspace"]["source"] =
            json!("/var/lib/hol-gauntlet-rust/native-jobs/fedcba9876543210/workspace");
        changed["task_mounts"]["workspace"]["custody_root"] =
            json!("/var/lib/hol-gauntlet-rust/native-jobs/fedcba9876543210");
        let raw = changed.to_string();
        job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
        assert!(job.preparation(raw.as_bytes()).is_err());
    }
}
