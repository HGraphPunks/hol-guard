//! Fixed, bounded guest readback of kernel-bound provider effects. The host
//! supplies its durable report/event pins, never a producer-selected cgroup.

use super::{hex, HostEffectEventsPin, HostKeyPinError, HostKeyPinRecord};
use crate::fixed_process::{run_fixed, FixedProcessError};
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use std::time::Duration;

fn positive(value: &Value) -> bool {
    value.as_u64().is_some_and(|n| n > 0)
}

fn validate(
    raw: &[u8],
    pin: &HostEffectEventsPin,
    role: &str,
    surface: &str,
) -> Result<Value, HostKeyPinError> {
    let invalid = HostKeyPinError::InvalidEffectJournal;
    if raw.len() > 8192 {
        return Err(invalid);
    }
    let canonical = canonicalize(raw).map_err(|_| invalid)?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|_| invalid)?;
    let fields = [
        "schema",
        "run_id",
        "role",
        "surface",
        "final_sha256",
        "final_bytes",
        "device",
        "inode",
        "close_writes",
        "writers",
        "outside_journal_sha256",
        "held_final_file_checked",
        "physical_owner_uid",
        "event_view_owner_uid",
        "idmap_kernel_verified",
        "guard_causality_verified",
        "execution_eligible",
        "kernel_observed_cgroup",
        "kernel_product_pid",
        "kernel_product_start_ticks",
        "outside_report_sha256",
        "continuously_observed",
    ];
    let prefix = format!("/holgauntletrust{}.slice/hol-product-cell-", pin.run_id);
    let service = value["kernel_observed_cgroup"]
        .as_str()
        .and_then(|s| s.strip_prefix(&prefix))
        .and_then(|s| s.strip_suffix(".service"));
    if value
        .as_object()
        .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|f| !o.contains_key(*f)))
        || value["schema"] != "hol-gauntlet-staging-kernel-bound-effect.v1"
        || value["run_id"] != pin.run_id
        || value["role"] != role
        || value["surface"] != surface
        || value["outside_report_sha256"] != pin.report_sha256
        || value["outside_journal_sha256"] != pin.journal_sha256
        || value["final_sha256"]
            != "59cae128f1e25176c5c65014eca5ecf8a6ad57360b867f2d5b22837ca4712d74"
        || value["final_bytes"] != 24
        || value["physical_owner_uid"] != 10001
        || value["event_view_owner_uid"] != 10004
        || value["idmap_kernel_verified"] != true
        || value["held_final_file_checked"] != true
        || value["guard_causality_verified"] != false
        || value["execution_eligible"] != false
        || value["continuously_observed"] != false
        || service.is_none_or(|s| !hex(s, 32))
        || ![
            "device",
            "inode",
            "kernel_product_pid",
            "kernel_product_start_ticks",
        ]
        .iter()
        .all(|f| positive(&value[*f]))
        || value["kernel_product_pid"]
            .as_u64()
            .is_none_or(|p| p > i32::MAX as u64)
        || value["close_writes"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > pin.events as u64)
    {
        return Err(invalid);
    }
    let writers = value["writers"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 64)
        .ok_or(invalid)?;
    let mut seen = std::collections::BTreeSet::new();
    for row in writers {
        if row.as_object().is_none_or(|o| {
            o.len() != 2 || !o.contains_key("pid") || !o.contains_key("start_ticks")
        }) || !positive(&row["pid"])
            || !positive(&row["start_ticks"])
            || row["pid"].as_u64().is_none_or(|p| p > i32::MAX as u64)
            || !seen.insert((row["pid"].as_u64(), row["start_ticks"].as_u64()))
        {
            return Err(invalid);
        }
    }
    if writers.len() as u64 > value["close_writes"].as_u64().unwrap() {
        return Err(invalid);
    }
    Ok(value)
}

impl HostKeyPinRecord {
    pub fn observe_fixed_vm_kernel_provider_effect(
        &self,
        reader_sha: &str,
        pin: &HostEffectEventsPin,
        role: &str,
        surface: &str,
    ) -> Result<Value, HostKeyPinError> {
        if !hex(reader_sha, 64)
            || pin.run_id != self.pins.job_id
            || pin.host_key_record_sha256 != self.raw_sha256
            || !matches!(
                role,
                "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
            )
            || !matches!(surface, "provider-remote" | "provider-home")
        {
            return Err(HostKeyPinError::InvalidPins);
        }
        let defaults: Value = serde_json::from_str(include_str!("../operations-defaults-v1.json"))
            .map_err(|_| HostKeyPinError::InvalidPins)?;
        let limactl = defaults["limactl"]
            .as_str()
            .ok_or(HostKeyPinError::InvalidPins)?;
        let vm = defaults["vm"]
            .as_str()
            .ok_or(HostKeyPinError::InvalidPins)?;
        let argv = vec![
            limactl.to_owned(),
            "shell".to_owned(),
            vm.to_owned(),
            "--".to_owned(),
            "sudo".to_owned(),
            "-n".to_owned(),
            format!("/opt/hol-gauntlet/rust-staging-effect-file-shadow-{reader_sha}"),
            self.pins.job_id.clone(),
            self.pins.source_sha.clone(),
            self.pins.deployment_digest.clone(),
            self.pins.worker_generation.clone(),
            self.pins.started_marker_sha256.clone(),
            pin.journal_sha256.clone(),
            role.to_owned(),
            surface.to_owned(),
            "--kernel-report-sha".to_owned(),
            pin.report_sha256.clone(),
            "--reader-sha".to_owned(),
            reader_sha.to_owned(),
        ];
        let raw =
            run_fixed(&argv, Duration::from_secs(60), 8192, 1024, &[]).map_err(
                |error| match error {
                    FixedProcessError::TimedOut => HostKeyPinError::TransportTimedOut,
                    FixedProcessError::TooLarge => HostKeyPinError::FrameTooLarge,
                    FixedProcessError::Unavailable | FixedProcessError::Failed => {
                        HostKeyPinError::TransportFailed
                    }
                },
            )?;
        validate(&raw, pin, role, surface)
    }
}

#[cfg(test)]
#[path = "controller_key_product_effect_tests.rs"]
mod tests;
