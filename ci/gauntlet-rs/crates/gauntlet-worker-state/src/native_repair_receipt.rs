//! A repair receipt records quiescence, never a fabricated process exit.
use crate::hex;
use gauntlet_contracts::canonicalize;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeRepairReceipt {
    pub schema: String,
    pub source_sha: String,
    pub job_id: String,
    pub deployment_digest: String,
    pub worker_generation: String,
    pub started_marker_sha256: String,
    pub running_marker_sha256: String,
    pub preparation_sha256: String,
    pub repair_generation: String,
    pub status: String,
    pub model_requests: u64,
    pub execution_eligible: bool,
    pub guard_causality_verified: bool,
    pub exit_code: Option<i32>,
    pub cleanup: Value,
}

impl NativeRepairReceipt {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.len() > 8192 || canonicalize(raw).map_err(|e| e.to_string())? != raw {
            return Err("bounded canonical native repair receipt required".into());
        }
        let value: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        if value
            .as_object()
            .is_none_or(|o| o.len() != 15 || !o.contains_key("exit_code"))
        {
            return Err("complete native repair receipt required".into());
        }
        serde_json::from_slice(raw).map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate(
        &self,
        source: &str,
        job: &str,
        deployment: &str,
        generation: &str,
        started: &str,
        running: &str,
        preparation: &str,
    ) -> Result<(), String> {
        let sdk = self.schema == "hol-gauntlet-native-worker-repair.v2";
        if (!sdk && self.schema != "hol-gauntlet-native-worker-repair.v1")
            || self.source_sha != source
            || self.job_id != job
            || self.deployment_digest != deployment
            || self.worker_generation != generation
            || self.started_marker_sha256 != started
            || self.running_marker_sha256 != running
            || self.preparation_sha256 != preparation
            || !hex(&self.repair_generation, 64)
            || self.status != "aborted"
            || self.model_requests != 0
            || self.execution_eligible
            || self.guard_causality_verified
            || self.exit_code.is_some()
            || self.cleanup.as_object().is_none_or(|o| {
                o.len() != if sdk { 6 } else { 4 }
                    || [
                        "quiescent",
                        "image_unmounted",
                        "active_pointer_absent",
                        "active_pointer_sha256",
                    ]
                    .iter()
                    .any(|k| !o.contains_key(*k))
            })
            || self.cleanup["quiescent"].as_object().is_none()
            || (sdk
                && !matches!(
                    self.cleanup["quiescent"]["image_history"].as_str(),
                    Some("already-closed-v1" | "recovered-pending-v1")
                ))
            || self.cleanup["image_unmounted"] != true
            || self.cleanup["active_pointer_absent"] != true
            || (sdk
                && (self.cleanup["sdk_agent_absent"] != true
                    || self.cleanup["sdk_profile_absent"] != true))
            || !(self.cleanup["active_pointer_sha256"].is_null()
                || self.cleanup["active_pointer_sha256"]
                    .as_str()
                    .is_some_and(|s| hex(s, 64)))
        {
            return Err(
                "native repair differs from retained job or claims execution credit".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn recovery_cannot_supply_an_exit_status_model_credit_or_success() {
        let value = json!({"schema":"hol-gauntlet-native-worker-repair.v1","source_sha":"a".repeat(40),
            "job_id":"0123456789abcdef","deployment_digest":"b".repeat(64),"worker_generation":"c".repeat(64),
            "started_marker_sha256":"d".repeat(64),"running_marker_sha256":"e".repeat(64),"preparation_sha256":"f".repeat(64),
            "repair_generation":"1".repeat(64),"status":"aborted","model_requests":0,"execution_eligible":false,
            "guard_causality_verified":false,"exit_code":null,"cleanup":{"quiescent":{},"image_unmounted":true,"active_pointer_absent":true,"active_pointer_sha256":null}});
        let validate = |v: &Value| {
            let raw = canonicalize(v.to_string().as_bytes()).unwrap();
            NativeRepairReceipt::parse(&raw)?.validate(
                &"a".repeat(40),
                "0123456789abcdef",
                &"b".repeat(64),
                &"c".repeat(64),
                &"d".repeat(64),
                &"e".repeat(64),
                &"f".repeat(64),
            )
        };
        validate(&value).unwrap();
        for (key, bad) in [
            ("status", json!("passed")),
            ("exit_code", json!(0)),
            ("model_requests", json!(1)),
            ("execution_eligible", json!(true)),
            ("guard_causality_verified", json!(true)),
            ("running_marker_sha256", json!("2".repeat(64))),
            ("preparation_sha256", json!("3".repeat(64))),
            ("deployment_digest", json!("4".repeat(64))),
            ("repair_generation", json!("unknown")),
            ("extra", json!(true)),
        ] {
            let mut bad_value = value.clone();
            bad_value[key] = bad;
            assert!(validate(&bad_value).is_err(), "{key}");
        }
        let mut sdk = value.clone();
        sdk["schema"] = json!("hol-gauntlet-native-worker-repair.v2");
        assert!(validate(&sdk).is_err());
        sdk["cleanup"]["sdk_agent_absent"] = json!(true);
        sdk["cleanup"]["sdk_profile_absent"] = json!(true);
        assert!(validate(&sdk).is_err());
        sdk["cleanup"]["quiescent"]["image_history"] = json!("already-closed-v1");
        validate(&sdk).unwrap();
        sdk["cleanup"]["quiescent"]["image_history"] = json!("recovered-pending-v1");
        validate(&sdk).unwrap();
        sdk["cleanup"]["quiescent"]["image_history"] = json!("unknown");
        assert!(validate(&sdk).is_err());
        sdk["cleanup"]["quiescent"]["image_history"] = json!("already-closed-v1");
        for key in ["sdk_agent_absent", "sdk_profile_absent"] {
            let mut changed = sdk.clone();
            changed["cleanup"][key] = json!(false);
            assert!(validate(&changed).is_err());
            changed["cleanup"].as_object_mut().unwrap().remove(key);
            assert!(validate(&changed).is_err());
        }
        sdk["schema"] = json!("hol-gauntlet-native-worker-repair.v1");
        assert!(validate(&sdk).is_err());
    }
}
