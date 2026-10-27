//! Versioned native apparatus dispatch. This profile cannot qualify Guard.
use crate::{hex, launch_plan::rust_job_slice_name, NativeSdkPins};
use gauntlet_cell_rootfs::{CellPreparation, NativeCase, NativeGuardPins};
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
pub enum NativeJobExecution {
    Apparatus(NativeCase),
    HookTransport(NativeGuardPins),
    McpTransport(NativeGuardPins),
    SdkTransport {
        guard: NativeGuardPins,
        sdk: NativeSdkPins,
    },
}

#[derive(Debug, Clone)]
pub struct NativeJobSpec {
    pub source_sha: String,
    pub job_id: String,
    pub worker_generation: String,
    pub preparation_sha256: String,
    pub execution: NativeJobExecution,
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
        let hook = value["schema"] == "hol-gauntlet-native-worker-job.v2"
            && value["profile"] == "native-hook-transport-v1";
        let sdk = value["schema"] == "hol-gauntlet-native-worker-job.v3"
            && value["profile"] == "native-sdk-transport-v1";
        let mcp = value["schema"] == "hol-gauntlet-native-worker-job.v4"
            && value["profile"] == "native-mcp-transport-v1";
        let mut fields = vec![
            "schema",
            "profile",
            "source_sha",
            "job_id",
            "worker_generation",
            "preparation_sha256",
            if hook || sdk || mcp { "guard" } else { "case" },
        ];
        if sdk {
            fields.push("sdk");
        }
        if value
            .as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
            || (!(hook || sdk || mcp)
                && (value["schema"] != "hol-gauntlet-native-worker-job.v1"
                    || value["profile"] != "native-apparatus-v1"))
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
        let execution = if hook || sdk || mcp {
            let pins = NativeGuardPins::parse(&value["guard"])?;
            if pins.source_sha != request.source_sha() {
                return Err("Native hook product source differs from job source".into());
            }
            if sdk {
                NativeJobExecution::SdkTransport {
                    guard: pins,
                    sdk: NativeSdkPins::parse(&value["sdk"])?,
                }
            } else if mcp {
                NativeJobExecution::McpTransport(pins)
            } else {
                NativeJobExecution::HookTransport(pins)
            }
        } else {
            NativeJobExecution::Apparatus(
                value["case"]
                    .as_str()
                    .ok_or("typed native case required")?
                    .parse()?,
            )
        };
        Ok(Self {
            source_sha: request.source_sha().into(),
            job_id: request.job_id().into(),
            worker_generation: worker_generation.into(),
            preparation_sha256,
            execution,
        })
    }

    pub fn profile(&self) -> &'static str {
        match self.execution {
            NativeJobExecution::Apparatus(_) => "native-apparatus-v1",
            NativeJobExecution::HookTransport(_) => "native-hook-transport-v1",
            NativeJobExecution::McpTransport(_) => "native-mcp-transport-v1",
            NativeJobExecution::SdkTransport { .. } => "native-sdk-transport-v1",
        }
    }

    pub fn case(&self) -> &'static str {
        match self.execution {
            NativeJobExecution::Apparatus(case) => case.as_str(),
            NativeJobExecution::HookTransport(_) => "native-hook-transport",
            NativeJobExecution::McpTransport(_) => "native-mcp-transport",
            NativeJobExecution::SdkTransport { .. } => "native-sdk-transport",
        }
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
    fn hook_transport_is_a_distinct_closed_version_and_cannot_borrow_product_identity() {
        let (mut value, _, generation) = fixture();
        value["schema"] = json!("hol-gauntlet-native-worker-job.v2");
        value["profile"] = json!("native-hook-transport-v1");
        value.as_object_mut().unwrap().remove("case");
        value["guard"] = json!({"schema":"hol-gauntlet-native-hook-product-pins.v1","source_sha":"a".repeat(40),
            "package_version":"3.57.0","native_sha256":"b".repeat(64),"bwrap_sha256":"c".repeat(64)});
        let parse = |v: &Value| {
            let raw = v.to_string();
            let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
            let request = WorkerRequest::parse(
                json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
                "source_sha":"a".repeat(40),"job_id":"0123456789abcdef","deployment_digest":digest})
                .to_string()
                .as_bytes(),
            )
            .unwrap();
            NativeJobSpec::parse(raw.as_bytes(), &digest, &request, &generation)
        };
        let spec = parse(&value).unwrap();
        assert_eq!(spec.profile(), "native-hook-transport-v1");
        assert_eq!(spec.case(), "native-hook-transport");
        assert!(matches!(
            spec.execution,
            NativeJobExecution::HookTransport(_)
        ));
        let mut mcp = value.clone();
        mcp["schema"] = json!("hol-gauntlet-native-worker-job.v4");
        mcp["profile"] = json!("native-mcp-transport-v1");
        let parsed = parse(&mcp).unwrap();
        assert_eq!(parsed.profile(), "native-mcp-transport-v1");
        assert!(matches!(
            parsed.execution,
            NativeJobExecution::McpTransport(_)
        ));
        for (field, bad) in [
            ("schema", json!("hol-gauntlet-native-worker-job.v3")),
            ("profile", json!("native-hook-transport-v1")),
            ("sdk", json!({})),
            ("command", json!("sh")),
        ] {
            let mut changed = mcp.clone();
            changed[field] = bad;
            assert!(parse(&changed).is_err());
        }
        for (pointer, bad) in [
            ("/guard/source_sha", json!("d".repeat(40))),
            ("/guard/bwrap_sha256", json!(true)),
            ("/profile", json!("native-apparatus-v1")),
            ("/schema", json!("hol-gauntlet-native-worker-job.v1")),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(parse(&changed).is_err(), "{pointer}");
        }
        for key in ["case", "command", "execution_eligible"] {
            let mut changed = value.clone();
            changed[key] = json!("untrusted");
            assert!(parse(&changed).is_err(), "{key}");
        }
    }
    #[test]
    fn sdk_requires_its_own_version_and_both_outside_product_and_dependency_pins() {
        let (mut value, _, generation) = fixture();
        value["schema"] = json!("hol-gauntlet-native-worker-job.v3");
        value["profile"] = json!("native-sdk-transport-v1");
        value.as_object_mut().unwrap().remove("case");
        value["guard"] = json!({"schema":"hol-gauntlet-native-hook-product-pins.v1","source_sha":"a".repeat(40),
            "package_version":"3.57.0","native_sha256":"b".repeat(64),"bwrap_sha256":"c".repeat(64)});
        value["sdk"] = NativeSdkPins {
            sdk_tree_sha256: "d".repeat(64),
            bun_sha256: "e".repeat(64),
            publication_sha256: "f".repeat(64),
        }
        .to_json();
        let parse = |v: &Value| {
            let raw = v.to_string();
            let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
            let request = WorkerRequest::parse(
                json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
                "source_sha":"a".repeat(40),"job_id":"0123456789abcdef","deployment_digest":digest})
                .to_string()
                .as_bytes(),
            )
            .unwrap();
            NativeJobSpec::parse(raw.as_bytes(), &digest, &request, &generation)
        };
        let spec = parse(&value).unwrap();
        assert_eq!(spec.profile(), "native-sdk-transport-v1");
        assert!(matches!(
            spec.execution,
            NativeJobExecution::SdkTransport { .. }
        ));
        for (pointer, bad) in [
            ("/schema", json!("hol-gauntlet-native-worker-job.v2")),
            ("/profile", json!("native-hook-transport-v1")),
            ("/guard/source_sha", json!("b".repeat(40))),
            ("/sdk/publication_sha256", json!("bad")),
            ("/sdk/agent_image_id", json!("other")),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(parse(&changed).is_err(), "{pointer}");
        }
        for key in ["guard", "sdk"] {
            let mut changed = value.clone();
            changed.as_object_mut().unwrap().remove(key);
            assert!(parse(&changed).is_err());
        }
        value["command"] = json!("sh");
        assert!(parse(&value).is_err());
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
