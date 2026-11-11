//! Versioned native apparatus dispatch. This profile cannot qualify Guard.
use crate::{hex, launch_plan::rust_job_slice_name, NativeSdkPins};
use gauntlet_cell_rootfs::{CellPreparation, NativeCase, NativeControlRole, NativeGuardPins};
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
    HostPinnedLive {
        guard: NativeGuardPins,
        sdk: NativeSdkPins,
        live: crate::NativeLiveJob,
    },
    Apparatus(NativeCase),
    HookTransport(NativeGuardPins),
    HostPinnedReadonlyHook(NativeGuardPins),
    McpTransport(NativeGuardPins),
    SdkTransport {
        guard: NativeGuardPins,
        sdk: NativeSdkPins,
    },
    SdkMcpTransport {
        guard: NativeGuardPins,
        sdk: NativeSdkPins,
    },
    DeterministicControl {
        guard: NativeGuardPins,
        sdk: NativeSdkPins,
        role: NativeControlRole,
    },
    HostPinnedControl {
        guard: NativeGuardPins,
        sdk: NativeSdkPins,
        role: NativeControlRole,
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

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) struct NativePreparationBundle {
    pub spec: NativeJobSpec,
    pub preparation: CellPreparation,
    pub declaration_raw: Vec<u8>,
    pub preparation_raw: Vec<u8>,
}

/// One exact Host-pinned bundle contains data declarations only. The existing
/// parsers retain every role/profile refusal and derive all mutable paths.
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_host_pinned_preparation_bundle(
    raw: &[u8],
    source: &str,
    job: &str,
    deployment: &str,
    generation: &str,
    preparation_pin: &str,
    bundle_pin: &str,
) -> Result<NativePreparationBundle, String> {
    if raw.is_empty()
        || raw.len() > 65536
        || !hex(bundle_pin, 64)
        || format!("{:x}", Sha256::digest(raw)) != bundle_pin
        || canonicalize(raw).map_err(|e| e.to_string())? != raw
    {
        return Err("bounded canonical preparation bundle differs from outside bytes".into());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if value.as_object().is_none_or(|o| {
        o.len() != 3
            || !["schema", "declaration", "preparation"]
                .iter()
                .all(|k| o.contains_key(*k))
    }) || value["schema"] != "hol-gauntlet-native-host-pinned-preparation-input.v1"
    {
        return Err("closed native preparation bundle required".into());
    }
    let declaration_raw =
        canonicalize(value["declaration"].to_string().as_bytes()).map_err(|e| e.to_string())?;
    let preparation_raw =
        canonicalize(value["preparation"].to_string().as_bytes()).map_err(|e| e.to_string())?;
    let request = WorkerRequest::parse(json_request(source, job, deployment).as_bytes())
        .map_err(|e| e.to_string())?;
    let spec = NativeJobSpec::parse(&declaration_raw, deployment, &request, generation)?;
    if !spec.requires_host_pin() || spec.preparation_sha256 != preparation_pin {
        return Err("outside host-pinned preparation/declaration profile required".into());
    }
    let preparation = spec.preparation(&preparation_raw)?;
    if preparation.runtime_prefix
        != PathBuf::from("/opt/hol-gauntlet/candidates")
            .join(source)
            .join("prefix")
    {
        return Err("preparation requires the immutable source-bound published runtime".into());
    }
    Ok(NativePreparationBundle {
        spec,
        preparation,
        declaration_raw,
        preparation_raw,
    })
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
fn json_request(source: &str, job: &str, deployment: &str) -> String {
    serde_json::json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
        "source_sha":source,"job_id":job,"deployment_digest":deployment})
    .to_string()
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
        let readonly_hook = value["schema"] == "hol-gauntlet-native-worker-job.v8"
            && value["profile"] == "native-host-pinned-readonly-hook-v1";
        let live = value["schema"] == "hol-gauntlet-native-worker-job.v9"
            && value["profile"] == "native-host-pinned-live-omp-v1";
        let hook = readonly_hook
            || (value["schema"] == "hol-gauntlet-native-worker-job.v2"
                && value["profile"] == "native-hook-transport-v1");
        let sdk = value["schema"] == "hol-gauntlet-native-worker-job.v3"
            && value["profile"] == "native-sdk-transport-v1";
        let mcp = value["schema"] == "hol-gauntlet-native-worker-job.v4"
            && value["profile"] == "native-mcp-transport-v1";
        let sdk_mcp = value["schema"] == "hol-gauntlet-native-worker-job.v5"
            && value["profile"] == "native-sdk-mcp-transport-v1";
        let host_pinned = value["schema"] == "hol-gauntlet-native-worker-job.v7"
            && value["profile"] == "native-host-pinned-control-v1";
        let control = host_pinned
            || (value["schema"] == "hol-gauntlet-native-worker-job.v6"
                && value["profile"] == "native-deterministic-control-v1");
        let mut fields = vec![
            "schema",
            "profile",
            "source_sha",
            "job_id",
            "worker_generation",
            "preparation_sha256",
            if hook || sdk || mcp || sdk_mcp || control || live {
                "guard"
            } else {
                "case"
            },
        ];
        if sdk || sdk_mcp || control || live {
            fields.push("sdk");
        }
        if control {
            fields.push("role");
        }
        if live {
            fields.push("live");
        }
        if value
            .as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
            || (!(hook || sdk || mcp || sdk_mcp || control || live)
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
        let execution = if hook || sdk || mcp || sdk_mcp || control || live {
            let pins = NativeGuardPins::parse(&value["guard"])?;
            if pins.source_sha != request.source_sha() {
                return Err("Native hook product source differs from job source".into());
            }
            if live {
                NativeJobExecution::HostPinnedLive {
                    guard: pins,
                    sdk: NativeSdkPins::parse(&value["sdk"])?,
                    live: crate::NativeLiveJob::parse(&value["live"])?,
                }
            } else if control {
                let sdk = NativeSdkPins::parse(&value["sdk"])?;
                let role = value["role"]
                    .as_str()
                    .ok_or("typed Native control role required")?
                    .parse()?;
                if host_pinned {
                    NativeJobExecution::HostPinnedControl {
                        guard: pins,
                        sdk,
                        role,
                    }
                } else {
                    NativeJobExecution::DeterministicControl {
                        guard: pins,
                        sdk,
                        role,
                    }
                }
            } else if sdk_mcp {
                NativeJobExecution::SdkMcpTransport {
                    guard: pins,
                    sdk: NativeSdkPins::parse(&value["sdk"])?,
                }
            } else if sdk {
                NativeJobExecution::SdkTransport {
                    guard: pins,
                    sdk: NativeSdkPins::parse(&value["sdk"])?,
                }
            } else if mcp {
                NativeJobExecution::McpTransport(pins)
            } else if readonly_hook {
                NativeJobExecution::HostPinnedReadonlyHook(pins)
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
            NativeJobExecution::HostPinnedLive { .. } => "native-host-pinned-live-omp-v1",
            NativeJobExecution::Apparatus(_) => "native-apparatus-v1",
            NativeJobExecution::HookTransport(_) => "native-hook-transport-v1",
            NativeJobExecution::HostPinnedReadonlyHook(_) => "native-host-pinned-readonly-hook-v1",
            NativeJobExecution::McpTransport(_) => "native-mcp-transport-v1",
            NativeJobExecution::SdkTransport { .. } => "native-sdk-transport-v1",
            NativeJobExecution::SdkMcpTransport { .. } => "native-sdk-mcp-transport-v1",
            NativeJobExecution::DeterministicControl { .. } => "native-deterministic-control-v1",
            NativeJobExecution::HostPinnedControl { .. } => "native-host-pinned-control-v1",
        }
    }

    pub fn case(&self) -> &'static str {
        match self.execution {
            NativeJobExecution::HostPinnedLive { ref live, .. } => live.role(),
            NativeJobExecution::Apparatus(case) => case.as_str(),
            NativeJobExecution::HookTransport(_) => "native-hook-transport",
            NativeJobExecution::HostPinnedReadonlyHook(_) => "readonly-utility",
            NativeJobExecution::McpTransport(_) => "native-mcp-transport",
            NativeJobExecution::SdkTransport { .. } => "native-sdk-transport",
            NativeJobExecution::SdkMcpTransport { .. } => "native-sdk-mcp-transport",
            NativeJobExecution::DeterministicControl { role, .. }
            | NativeJobExecution::HostPinnedControl { role, .. } => role.as_str(),
        }
    }
    pub fn requires_host_pin(&self) -> bool {
        matches!(
            self.execution,
            NativeJobExecution::HostPinnedControl { .. }
                | NativeJobExecution::HostPinnedReadonlyHook(_)
                | NativeJobExecution::HostPinnedLive { .. }
        )
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
        if matches!(
            &self.execution,
            NativeJobExecution::HostPinnedReadonlyHook(_)
        ) && spec.control_profile()
            != gauntlet_evidence::NativeContainmentRoute::PythonReadonlyV1
        {
            return Err(
                "host-pinned read-only hook requires explicit read-only preparation".into(),
            );
        }
        if spec.control_profile() == gauntlet_evidence::NativeContainmentRoute::PythonReadonlyV1
            && !matches!(
                &self.execution,
                NativeJobExecution::HookTransport(_)
                    | NativeJobExecution::HostPinnedReadonlyHook(_)
            )
        {
            return Err("read-only preparation requires hook transport; SDK role fixtures retain their historical contract".into());
        }
        let root = self.job_root();
        let workspace = &spec.task_mounts["workspace"];
        if spec.stage != root.join("cell")
            || spec.wall_seconds()
                != if matches!(self.execution, NativeJobExecution::HostPinnedLive { .. }) {
                    crate::native_live_spec::PREPARATION_SECONDS
                } else {
                    180
                }
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
#[path = "native_job_spec_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "native_job_preparation_tests.rs"]
mod preparation_tests;
