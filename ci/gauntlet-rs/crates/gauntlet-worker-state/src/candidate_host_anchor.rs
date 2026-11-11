//! Root-owned one-use guest marker for a host-pinned candidate run. The
//! marker is written before the candidate Podman `run`, and an absent or
//! partial marker consumes this job. Host trust remains outside the guest.

use crate::builder_candidate_preflight::CandidateRuntimePins;
use crate::builder_candidate_receipt::{write_root_canonical_job_file, CandidateReceiptError};
use crate::builder_candidate_source::same_file;
use crate::hex;
use rustix::fs::{fstat, fsync, FileType};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

pub(crate) const HOST_ANCHOR_FILE: &str = "candidate-run.host-anchor.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateBinaryError {
    InvalidPin,
    Mismatch,
}

impl fmt::Display for CandidateBinaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPin => "exact running binary SHA-256 required",
            Self::Mismatch => "running Root binary differs from outside digest or mode",
        })
    }
}

impl std::error::Error for CandidateBinaryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCandidateRunAnchor {
    pub(crate) host_pin_sha256: String,
    pub(crate) host_nonce_hex: String,
    pub(crate) runner_binary_sha256: String,
    pub(crate) result_reader_binary_sha256: String,
    pub(crate) policy_sha256: String,
    pub(crate) tag: Option<String>,
}

/// Hash the actual running executable, not its caller-supplied argv path.
/// The host must separately pin the installed Root binary before launch.
pub fn verify_running_binary(expected_sha256: &str) -> Result<(), CandidateBinaryError> {
    if !hex(expected_sha256, 64) {
        return Err(CandidateBinaryError::InvalidPin);
    }
    let mut file = File::open("/proc/self/exe").map_err(|_| CandidateBinaryError::Mismatch)?;
    let before = fstat(&file).map_err(|_| CandidateBinaryError::Mismatch)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != 0o500
        || before.st_size <= 0
        || before.st_size > 128 * 1024 * 1024
    {
        return Err(CandidateBinaryError::Mismatch);
    }
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| CandidateBinaryError::Mismatch)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > 128 * 1024 * 1024 {
            return Err(CandidateBinaryError::Mismatch);
        }
        hash.update(&buffer[..n]);
    }
    let after = fstat(&file).map_err(|_| CandidateBinaryError::Mismatch)?;
    if count != before.st_size as u64
        || !same_file(&before, &after)
        || format!("{:x}", hash.finalize()) != expected_sha256
    {
        return Err(CandidateBinaryError::Mismatch);
    }
    Ok(())
}

impl HostCandidateRunAnchor {
    pub fn parse(
        policy_sha256: &str,
        result_reader_binary_sha256: &str,
        host_pin_sha256: &str,
        host_nonce_hex: &str,
        runner_binary_sha256: &str,
    ) -> Option<Self> {
        if [
            policy_sha256,
            result_reader_binary_sha256,
            host_pin_sha256,
            host_nonce_hex,
            runner_binary_sha256,
        ]
        .iter()
        .any(|value| !hex(value, 64))
        {
            return None;
        }
        Some(Self {
            policy_sha256: policy_sha256.to_owned(),
            result_reader_binary_sha256: result_reader_binary_sha256.to_owned(),
            host_pin_sha256: host_pin_sha256.to_owned(),
            host_nonce_hex: host_nonce_hex.to_owned(),
            runner_binary_sha256: runner_binary_sha256.to_owned(),
            tag: None,
        })
    }

    pub fn parse_with_tag(
        policy_sha256: &str,
        result_reader_binary_sha256: &str,
        host_pin_sha256: &str,
        host_nonce_hex: &str,
        runner_binary_sha256: &str,
        tag: &str,
    ) -> Option<Self> {
        if !(tag.starts_with("local-") && tag.len() == 46 && hex(&tag[6..], 40)
            || matches!(tag, "v3.48.0" | "v3.49.0"))
        {
            return None;
        }
        let mut anchor = Self::parse(
            policy_sha256,
            result_reader_binary_sha256,
            host_pin_sha256,
            host_nonce_hex,
            runner_binary_sha256,
        )?;
        anchor.tag = Some(tag.to_owned());
        Some(anchor)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn body(
        &self,
        job_id: &str,
        source_sha: &str,
        source_archive_sha256: &str,
        version: &str,
        controller_tree_sha256: &str,
        image_id: &str,
        runtime: &CandidateRuntimePins,
    ) -> Value {
        let mut body = json!({
            "schema":"hol-gauntlet-candidate-host-anchor.v1",
            "job_id":job_id,
            "source_sha":source_sha,
            "source_archive_sha256":source_archive_sha256,
            "version":version,
            "controller_tree_sha256":controller_tree_sha256,
            "image_id":image_id,
            "policy_sha256":self.policy_sha256,
            "runtime_pins":runtime.to_json(),
            "runner_binary_sha256":self.runner_binary_sha256,
            "result_reader_binary_sha256":self.result_reader_binary_sha256,
            "host_pin_sha256":self.host_pin_sha256,
            "host_nonce_hex":self.host_nonce_hex,
            "pre_candidate_run":true,
            "artifact_admitted":false,
            "execution_eligible":false,
        });
        if let Some(tag) = &self.tag {
            body["schema"] = json!("hol-gauntlet-candidate-host-anchor.v2");
            body["tag"] = json!(tag);
        }
        body
    }
}

pub(crate) fn write_host_anchor(
    job: &OwnedFd,
    body: &Value,
) -> Result<String, CandidateReceiptError> {
    let digest = write_root_canonical_job_file(job, HOST_ANCHOR_FILE, body)?;
    fsync(job).map_err(|_| CandidateReceiptError::WriteUncertain)?;
    Ok(digest)
}

/// Precreate and retain the exact container before starting its attached client.
/// Client death alone cannot stop an OCI workload in its separate cgroup.
pub(crate) struct CandidateContainer<'a> {
    plan: &'a crate::BuilderRunPlan,
    image: &'a str,
    podman: &'a str,
    binding: &'a str,
    cid: Option<String>,
}

impl<'a> CandidateContainer<'a> {
    pub(crate) fn new(
        plan: &'a crate::BuilderRunPlan,
        image: &'a str,
        podman: &'a str,
        binding: &'a str,
    ) -> Result<Self, String> {
        if !hex(&plan.job_id, 16)
            || !hex(podman, 64)
            || !hex(binding, 64)
            || !image.strip_prefix("sha256:").is_some_and(|s| hex(s, 64))
            || plan.execution_eligible
            || plan.argv.first().map(String::as_str) != Some("/usr/bin/podman")
            || plan.argv.get(1).map(String::as_str) != Some("run")
        {
            return Err("fixed candidate container pins required".into());
        }
        Ok(Self {
            plan,
            image,
            podman,
            binding,
            cid: None,
        })
    }

    fn identity(&self) -> Result<Option<String>, String> {
        self.identity_in_phase(false)
    }
    fn identity_in_phase(&self, owned_cleanup: bool) -> Result<Option<String>, String> {
        use crate::builder_candidate_process::{container_absent, container_id_absent};
        let absent = if owned_cleanup {
            crate::builder_candidate_process::cleanup_container_absent(
                &self.plan.job_id,
                self.cid.as_deref(),
            )
            .map_err(|e| e.to_string())?
        } else {
            container_absent(&self.plan.job_id).map_err(|e| e.to_string())?
                && self
                    .cid
                    .as_deref()
                    .map(container_id_absent)
                    .transpose()
                    .map_err(|e| e.to_string())?
                    .unwrap_or(true)
        };
        if absent {
            return Ok(None);
        }
        let target = self
            .cid
            .clone()
            .unwrap_or_else(|| format!("hol-gauntlet-build-{}", self.plan.job_id));
        let raw = crate::dependency_podman::run(
            self.podman,
            &["container".into(), "inspect".into(), target],
        )?;
        let rows: Vec<Value> = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if rows.len() != 1 {
            return Err("one candidate container required".into());
        }
        let cid = crate::dependency_podman::validated_container_identity(
            &rows[0],
            &self.plan.job_id,
            self.image,
            "hol-gauntlet.candidate-intent",
            self.binding,
        )?;
        if self.cid.as_ref().is_some_and(|wanted| wanted != &cid) {
            return Err("candidate full container identity changed".into());
        }
        Ok(Some(cid))
    }

    pub(crate) fn create(&mut self, slot: &OwnedFd) -> Result<crate::BuilderRunPlan, String> {
        if self.identity()?.is_some() {
            return Err("candidate container already exists".into());
        }
        let mut args = self.plan.argv[1..].to_vec();
        args[0] = "create".into();
        args.splice(
            1..1,
            crate::native_job_storage::source::container_arguments(
                &self.plan.job_id,
                slot,
                crate::JobStorageProfile::Build,
            )?,
        );
        args.splice(
            1..1,
            [
                "--pull=never".into(),
                "--cgroup-parent=system.slice".into(),
                "--label".into(),
                format!("hol-gauntlet.candidate-intent={}", self.binding),
            ],
        );
        let created = crate::dependency_podman::run(self.podman, &args);
        self.cid = self.identity()?;
        let raw = created?;
        let cid = std::str::from_utf8(&raw)
            .map_err(|_| "candidate CID encoding differs")?
            .trim();
        if self.cid.as_deref() != Some(cid) {
            return Err("candidate create output differs from independent inspection".into());
        }
        write_root_canonical_job_file(
            slot,
            "candidate-container.v1.json",
            &json!({
                "schema":"hol-gauntlet-candidate-container.v1", "job_id":self.plan.job_id,
                "container_id":cid, "binding_sha256":self.binding, "image_id":self.image,
                "source_archive_sha256":self.plan.source_archive_sha256,
                "execution_eligible":false,
            }),
        )
        .map_err(|e| e.to_string())?;
        Ok(crate::BuilderRunPlan {
            argv: vec![
                "/usr/bin/podman".into(),
                "start".into(),
                "--attach".into(),
                cid.into(),
            ],
            job_id: self.plan.job_id.clone(),
            source_archive_sha256: self.plan.source_archive_sha256.clone(),
            execution_eligible: false,
        })
    }

    pub(crate) fn restore(
        plan: &'a crate::BuilderRunPlan,
        image: &'a str,
        podman: &'a str,
        binding: &'a str,
        slot: &OwnedFd,
    ) -> Result<Self, String> {
        let mut owner = Self::new(plan, image, podman, binding)?;
        let raw = crate::feature_files::required(
            slot,
            "candidate-container.v1.json",
            (0, 0),
            0o600,
            8192,
        )?;
        let v = crate::feature_journal::canonical(&raw)?;
        let cid = v["container_id"]
            .as_str()
            .filter(|s| hex(s, 64))
            .ok_or("retained full candidate CID required")?;
        if v.as_object().is_none_or(|v| v.len() != 7)
            || v["schema"] != "hol-gauntlet-candidate-container.v1"
            || v["job_id"] != plan.job_id
            || v["image_id"] != image
            || v["binding_sha256"] != binding
            || v["source_archive_sha256"] != plan.source_archive_sha256
            || v["execution_eligible"] != false
        {
            return Err("candidate container receipt differs from reserved request".into());
        }
        owner.cid = Some(cid.into());
        owner.identity()?;
        Ok(owner)
    }

    pub(crate) fn id(&self) -> Option<&str> {
        self.cid.as_deref()
    }

    pub(crate) fn drain(&self) -> Result<(), String> {
        if let Some(cid) = self.identity_in_phase(true)? {
            crate::dependency_podman::run(
                self.podman,
                &["rm".into(), "--force".into(), "--time=5".into(), cid],
            )?;
        }
        self.verify_absent()
    }

    pub(crate) fn verify_absent(&self) -> Result<(), String> {
        if self.identity_in_phase(true)?.is_some() {
            return Err("candidate container survived cleanup".into());
        }
        if let Some(cid) = &self.cid {
            for parent in ["system.slice", "machine.slice"] {
                for unit in [
                    format!("libpod-{cid}.scope"),
                    format!("libpod-conmon-{cid}.scope"),
                ] {
                    match std::fs::symlink_metadata(format!("/sys/fs/cgroup/{parent}/{unit}")) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        _ => return Err("candidate container cgroup exists or is uncertain".into()),
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_five_exact_lowercase_digests() {
        let valid = "a".repeat(64);
        assert!(HostCandidateRunAnchor::parse(&valid, &valid, &valid, &valid, &valid).is_some());
        assert!(HostCandidateRunAnchor::parse("bad", &valid, &valid, &valid, &valid).is_none());
        assert!(HostCandidateRunAnchor::parse(
            &valid,
            &valid,
            &valid,
            &valid,
            &valid.to_uppercase()
        )
        .is_none());
    }
}
