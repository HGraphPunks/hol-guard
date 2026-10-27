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
    Apparatus(NativeCase),
    HookTransport(NativeGuardPins),
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
            if hook || sdk || mcp || sdk_mcp || control {
                "guard"
            } else {
                "case"
            },
        ];
        if sdk || sdk_mcp || control {
            fields.push("sdk");
        }
        if control {
            fields.push("role");
        }
        if value
            .as_object()
            .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
            || (!(hook || sdk || mcp || sdk_mcp || control)
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
        let execution = if hook || sdk || mcp || sdk_mcp || control {
            let pins = NativeGuardPins::parse(&value["guard"])?;
            if pins.source_sha != request.source_sha() {
                return Err("Native hook product source differs from job source".into());
            }
            if control {
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
            NativeJobExecution::SdkMcpTransport { .. } => "native-sdk-mcp-transport-v1",
            NativeJobExecution::DeterministicControl { .. } => "native-deterministic-control-v1",
            NativeJobExecution::HostPinnedControl { .. } => "native-host-pinned-control-v1",
        }
    }

    pub fn case(&self) -> &'static str {
        match self.execution {
            NativeJobExecution::Apparatus(case) => case.as_str(),
            NativeJobExecution::HookTransport(_) => "native-hook-transport",
            NativeJobExecution::McpTransport(_) => "native-mcp-transport",
            NativeJobExecution::SdkTransport { .. } => "native-sdk-transport",
            NativeJobExecution::SdkMcpTransport { .. } => "native-sdk-mcp-transport",
            NativeJobExecution::DeterministicControl { role, .. }
            | NativeJobExecution::HostPinnedControl { role, .. } => role.as_str(),
        }
    }
    pub fn requires_host_pin(&self) -> bool {
        matches!(self.execution, NativeJobExecution::HostPinnedControl { .. })
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
#[path = "native_job_spec_tests.rs"]
mod tests;
