//! A repair receipt records quiescence, never a fabricated process exit.
use crate::hex;
use gauntlet_contracts::canonicalize;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const KEYED_SCHEMA: &str = "hol-gauntlet-native-keyed-worker-repair.v1";
pub(crate) const LIVE_KEYED_SCHEMA: &str = "hol-gauntlet-native-live-keyed-worker-repair.v1";

/// Public original-key custody and observed quiescence can close uncertainty,
/// but cannot recover a lost exit or create a controller-signed result.
pub(crate) fn verify_keyed(
    raw: &[u8],
    prelaunch: &gauntlet_contracts::PrelaunchPrepared,
    preparation: &str,
    running: &str,
) -> Result<Value, String> {
    verify_keyed_profile(raw, prelaunch, preparation, running, None)
}
pub(crate) fn verify_live_keyed(
    raw: &[u8],
    prelaunch: &gauntlet_contracts::PrelaunchPrepared,
    preparation: &str,
    running: &str,
    live_prepared: &str,
) -> Result<Value, String> {
    if !hex(live_prepared, 64) {
        return Err("outside live preparation receipt pin required for repair".into());
    }
    verify_keyed_profile(raw, prelaunch, preparation, running, Some(live_prepared))
}
fn verify_keyed_profile(
    raw: &[u8],
    prelaunch: &gauntlet_contracts::PrelaunchPrepared,
    preparation: &str,
    running: &str,
    live_prepared: Option<&str>,
) -> Result<Value, String> {
    if raw.len() > 8192 || canonicalize(raw).map_err(|e| e.to_string())? != raw {
        return Err("bounded canonical keyed repair receipt required".into());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let expected: Value = serde_json::from_slice(&prelaunch.to_bytes().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut fields = vec![
        "schema",
        "prelaunch",
        "preparation_sha256",
        "running_marker_sha256",
        "repair_generation",
        "status",
        "controller_state",
        "exit_code",
        "model_requests",
        "artifact_admitted",
        "execution_eligible",
        "qualification_eligible",
        "guard_causality_verified",
        "cleanup",
    ];
    if live_prepared.is_some() {
        fields.push("live_prepared_sha256");
    }
    let cleanup = &value["cleanup"];
    let absent = [
        "image_unmounted",
        "active_pointer_absent",
        "controller_process_absent",
        "controller_cgroup_absent",
        "product_slice_absent",
        "sdk_agent_absent",
        "sdk_profile_absent",
        "mcp_agent_absent",
        "mcp_profile_absent",
        "image_lease_absent",
        "public_key_retained",
    ];
    if !hex(preparation, 64)
        || !hex(running, 64)
        || value.as_object().is_none_or(|o| {
            o.len() != fields.len() || fields.iter().any(|key| !o.contains_key(*key))
        })
        || value["schema"]
            != if live_prepared.is_some() {
                LIVE_KEYED_SCHEMA
            } else {
                KEYED_SCHEMA
            }
        || value["prelaunch"] != expected
        || value["preparation_sha256"] != preparation
        || value["running_marker_sha256"] != running
        || value["repair_generation"]
            .as_str()
            .is_none_or(|s| !hex(s, 64))
        || value["status"] != "aborted"
        || value["controller_state"] != "released-exit-unavailable"
        || !value["exit_code"].is_null()
        || if let Some(pin) = live_prepared {
            value["live_prepared_sha256"] != pin || !value["model_requests"].is_null()
        } else {
            value["model_requests"].as_u64() != Some(0)
        }
        || [
            "artifact_admitted",
            "execution_eligible",
            "qualification_eligible",
            "guard_causality_verified",
        ]
        .iter()
        .any(|key| value[*key] != false)
        || cleanup.as_object().is_none_or(|o| {
            o.len() != absent.len() + 2
                || !o.contains_key("quiescent")
                || !o.contains_key("active_pointer_sha256")
                || absent
                    .iter()
                    .any(|key| o.get(*key) != Some(&Value::Bool(true)))
        })
        || cleanup["quiescent"].as_object().is_none()
        || !matches!(
            cleanup["quiescent"]["image_history"].as_str(),
            Some("already-closed-v1" | "recovered-pending-v1")
        )
        || !(cleanup["active_pointer_sha256"].is_null()
            || cleanup["active_pointer_sha256"]
                .as_str()
                .is_some_and(|s| hex(s, 64)))
    {
        return Err(
            "keyed repair differs from original public custody or claims execution credit".into(),
        );
    }
    Ok(value)
}

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

    fn keyed_fixture() -> (gauntlet_contracts::PrelaunchPrepared, Value) {
        let prelaunch = gauntlet_contracts::PrelaunchPrepared {
            source_sha: "a".repeat(40),
            job_id: "0123456789abcdef".into(),
            deployment_digest: "b".repeat(64),
            worker_generation: "c".repeat(64),
            started_marker_sha256: "d".repeat(64),
            controller_key_pin_sha256: "e".repeat(64),
            controller_public_key_hex: "f".repeat(64),
        };
        let p: Value = serde_json::from_slice(&prelaunch.to_bytes().unwrap()).unwrap();
        let value = json!({"schema":KEYED_SCHEMA,"prelaunch":p,"preparation_sha256":"1".repeat(64),
            "running_marker_sha256":"2".repeat(64),"repair_generation":"3".repeat(64),
            "status":"aborted","controller_state":"released-exit-unavailable","exit_code":null,
            "model_requests":0,"artifact_admitted":false,"execution_eligible":false,
            "qualification_eligible":false,"guard_causality_verified":false,
            "cleanup":{"quiescent":{"image_history":"already-closed-v1"},
                "active_pointer_sha256":null,"image_unmounted":true,"active_pointer_absent":true,
                "controller_process_absent":true,"controller_cgroup_absent":true,"product_slice_absent":true,
                "sdk_agent_absent":true,"sdk_profile_absent":true,"mcp_agent_absent":true,
                "mcp_profile_absent":true,"image_lease_absent":true,"public_key_retained":true}});
        (prelaunch, value)
    }

    #[test]
    fn released_keyed_repair_keeps_unknown_exit_and_every_original_public_binding() {
        let (prelaunch, value) = keyed_fixture();
        let check = |value: &Value| {
            verify_keyed(
                &canonicalize(value.to_string().as_bytes()).unwrap(),
                &prelaunch,
                &"1".repeat(64),
                &"2".repeat(64),
            )
        };
        assert_eq!(check(&value).unwrap(), value);
        for (pointer, bad) in [
            ("/schema", json!("hol-gauntlet-native-worker-repair.v2")),
            ("/prelaunch/source_sha", json!("b".repeat(40))),
            ("/prelaunch/job_id", json!("1111111111111111")),
            ("/prelaunch/deployment_digest", json!("4".repeat(64))),
            ("/prelaunch/worker_generation", json!("4".repeat(64))),
            ("/prelaunch/started_marker_sha256", json!("4".repeat(64))),
            (
                "/prelaunch/controller_key_pin_sha256",
                json!("4".repeat(64)),
            ),
            (
                "/prelaunch/controller_public_key_hex",
                json!("4".repeat(64)),
            ),
            ("/preparation_sha256", json!("4".repeat(64))),
            ("/running_marker_sha256", json!("4".repeat(64))),
            ("/repair_generation", json!("unknown")),
            ("/status", json!("passed")),
            ("/controller_state", json!("never-released")),
            ("/exit_code", json!(0)),
            ("/model_requests", json!(1)),
            ("/model_requests", json!(false)),
            ("/artifact_admitted", json!(true)),
            ("/execution_eligible", json!(true)),
            ("/qualification_eligible", json!(true)),
            ("/guard_causality_verified", json!(true)),
            ("/cleanup/active_pointer_sha256", json!("unknown")),
            ("/cleanup/quiescent/image_history", json!("unknown")),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(check(&changed).is_err(), "{pointer}");
        }
        for key in value["cleanup"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|key| !matches!(key.as_str(), "quiescent" | "active_pointer_sha256"))
        {
            let mut changed = value.clone();
            changed["cleanup"][key] = json!(1);
            assert!(check(&changed).is_err(), "{key}");
            changed["cleanup"].as_object_mut().unwrap().remove(key);
            assert!(check(&changed).is_err(), "missing {key}");
        }
        for key in value.as_object().unwrap().keys() {
            let mut changed = value.clone();
            changed.as_object_mut().unwrap().remove(key);
            assert!(check(&changed).is_err(), "missing {key}");
        }
        let mut recovered = value;
        recovered["cleanup"]["quiescent"]["image_history"] = json!("recovered-pending-v1");
        recovered["cleanup"]["active_pointer_sha256"] = json!("4".repeat(64));
        check(&recovered).unwrap();
        recovered["extra"] = json!(true);
        assert!(check(&recovered).is_err());
    }

    #[test]
    fn partial_ambiguous_or_noncanonical_keyed_repair_is_retained_as_unknown() {
        let (prelaunch, value) = keyed_fixture();
        let canonical = canonicalize(value.to_string().as_bytes()).unwrap();
        let spaced = serde_json::to_vec_pretty(&value).unwrap();
        for raw in [
            b"{".as_slice(),
            b"{}",
            &spaced,
            &canonical[..canonical.len() - 1],
            b"{\"schema\":1,\"schema\":2}",
            &vec![b' '; 8193],
        ] {
            assert!(verify_keyed(raw, &prelaunch, &"1".repeat(64), &"2".repeat(64)).is_err());
        }
    }
    #[test]
    fn live_repair_retains_unknown_usage_and_cannot_downgrade_to_zero_model() {
        let (prelaunch, mut value) = keyed_fixture();
        value["schema"] = json!(LIVE_KEYED_SCHEMA);
        value["model_requests"] = Value::Null;
        value["live_prepared_sha256"] = json!("5".repeat(64));
        let check = |value: &Value| {
            verify_live_keyed(
                &canonicalize(value.to_string().as_bytes()).unwrap(),
                &prelaunch,
                &"1".repeat(64),
                &"2".repeat(64),
                &"5".repeat(64),
            )
        };
        check(&value).unwrap();
        assert!(verify_keyed(
            &canonicalize(value.to_string().as_bytes()).unwrap(),
            &prelaunch,
            &"1".repeat(64),
            &"2".repeat(64)
        )
        .is_err());
        for (key, bad) in [
            ("model_requests", json!(0)),
            ("model_requests", json!(3)),
            ("exit_code", json!(0)),
            ("live_prepared_sha256", json!("6".repeat(64))),
            ("schema", json!(KEYED_SCHEMA)),
            ("qualification_eligible", json!(true)),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            assert!(check(&changed).is_err(), "{key}");
        }
    }

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
