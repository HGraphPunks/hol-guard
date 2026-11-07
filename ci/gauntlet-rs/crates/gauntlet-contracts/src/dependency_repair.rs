//! Typed operational recovery claims, bound to prior outside authorization.
use crate::{canonicalize, DependencyRunIntent};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn hash(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub fn dependency_repair_authorization(
    intent: &DependencyRunIntent,
    started: &str,
    generation: &str,
) -> Result<Vec<u8>, String> {
    if !hash(&json!(started)) || !hash(&json!(generation)) {
        return Err("outside dependency reservation and repair binary SHA-256 required".into());
    }
    canonicalize(json!({"schema":"hol-gauntlet-host-dependency-repair-authorization.v1","job_id":intent.pins.text("job_id"),
        "intent_sha256":intent.digest()?,"started_marker_sha256":started,"repair_generation":generation}).to_string().as_bytes()).map_err(|e|e.to_string())
}

pub fn parse_dependency_repair_authorization(
    intent: &DependencyRunIntent,
    raw: &[u8],
) -> Result<(String, String), String> {
    let v: Value =
        serde_json::from_slice(raw).map_err(|_| "dependency repair authorization is partial")?;
    let started = v["started_marker_sha256"]
        .as_str()
        .ok_or("dependency reservation pin missing")?;
    let generation = v["repair_generation"]
        .as_str()
        .ok_or("dependency repair executable pin missing")?;
    if raw != dependency_repair_authorization(intent, started, generation)? {
        return Err("dependency repair authorization differs".into());
    }
    Ok((started.into(), generation.into()))
}

/// A reservation observation enables explicit recovery; it never authorizes it.
pub fn verify_dependency_unknown_result(
    intent: &DependencyRunIntent,
    reader: &str,
    raw: &[u8],
) -> Result<Value, String> {
    if raw.is_empty() || raw.len() > 8192 || canonicalize(raw).map_err(|e| e.to_string())? != raw {
        return Err("bounded canonical dependency observation required".into());
    }
    let mut v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let fields = [
        "schema",
        "job_id",
        "source_sha",
        "intent_sha256",
        "worker_generation",
        "reader_generation",
        "started_marker_sha256",
        "running_marker_sha256",
        "retained_client_cgroup_receipt_sha256",
        "status",
        "exit_code",
        "artifact_admitted",
        "execution_eligible",
        "qualification_eligible",
        "guard_causality_verified",
        "model_requests",
        "model_tokens",
    ];
    if v.as_object()
        .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
        || v["schema"] != "hol-gauntlet-native-dependency-unknown.v1"
        || v["job_id"] != intent.pins.text("job_id")
        || v["source_sha"] != intent.pins.text("source_sha")
        || v["intent_sha256"] != intent.digest()?
        || v["worker_generation"] != intent.pins.text("runner_binary_sha256")
        || !hash(&json!(reader))
        || v["reader_generation"] != reader
        || !hash(&v["started_marker_sha256"])
        || [
            "running_marker_sha256",
            "retained_client_cgroup_receipt_sha256",
        ]
        .iter()
        .any(|k| !v[k].is_null() && !hash(&v[k]))
        || v["status"] != "unknown"
        || !v["exit_code"].is_null()
        || v["model_requests"] != 0
        || v["model_tokens"] != 0
        || [
            "artifact_admitted",
            "execution_eligible",
            "qualification_eligible",
            "guard_causality_verified",
        ]
        .iter()
        .any(|k| v[k] != false)
        || v.to_string().contains(&intent.nonce)
    {
        return Err(
            "dependency observation differs from original intent or claims execution credit".into(),
        );
    }
    v["schema"] = json!("hol-gauntlet-host-dependency-unknown.v1");
    Ok(v)
}

pub fn verify_dependency_repair_result(
    intent: &DependencyRunIntent,
    started: &str,
    generation: &str,
    raw: &[u8],
) -> Result<Value, String> {
    if raw.is_empty() || raw.len() > 8192 || canonicalize(raw).map_err(|e| e.to_string())? != raw {
        return Err("bounded canonical dependency repair required".into());
    }
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let fields = [
        "schema",
        "job_id",
        "source_sha",
        "intent_sha256",
        "worker_generation",
        "repair_generation",
        "started_marker_sha256",
        "running_marker_sha256",
        "container_id",
        "captured_dependencies_bytes",
        "captured_dependencies_sha256",
        "status",
        "exit_code",
        "quiescent",
        "artifact_admitted",
        "execution_eligible",
        "guard_causality_verified",
        "model_requests",
        "model_tokens",
        "qualification_eligible",
        "client_cgroup_receipt_sha256",
    ];
    let empty =
        v["captured_dependencies_bytes"].is_null() && v["captured_dependencies_sha256"].is_null();
    let captured = v["captured_dependencies_bytes"]
        .as_u64()
        .is_some_and(|n| (1..=256 * 1024 * 1024).contains(&n))
        && hash(&v["captured_dependencies_sha256"]);
    if v.as_object()
        .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)))
        || v["schema"] != "hol-gauntlet-native-dependency-repair.v2"
        || v["job_id"] != intent.pins.text("job_id")
        || v["source_sha"] != intent.pins.text("source_sha")
        || v["intent_sha256"] != intent.digest()?
        || v["worker_generation"] != intent.pins.text("runner_binary_sha256")
        || !hash(&json!(started))
        || v["started_marker_sha256"] != started
        || !hash(&json!(generation))
        || v["repair_generation"] != generation
        || !hash(&v["container_id"])
        || !hash(&v["client_cgroup_receipt_sha256"])
        || !(v["running_marker_sha256"].is_null() || hash(&v["running_marker_sha256"]))
        || !(empty || captured)
        || v["status"] != "aborted"
        || !v["exit_code"].is_null()
        || v["quiescent"] != true
        || [
            "artifact_admitted",
            "execution_eligible",
            "qualification_eligible",
            "guard_causality_verified",
        ]
        .iter()
        .any(|k| v[k] != false)
        || v["model_requests"] != 0
        || v["model_tokens"] != 0
    {
        return Err(
            "dependency repair differs from authorization or claims execution credit".into(),
        );
    }
    let mut public = v;
    public["schema"] = json!("hol-gauntlet-host-dependency-repair.v1");
    public["private_result_sha256"] = json!(format!("{:x}", Sha256::digest(raw)));
    public["retained_result_reconciled"] = json!(false);
    if public.to_string().contains(&intent.nonce) {
        return Err("private dependency value appeared in repair response".into());
    }
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DependencyRunPins;
    #[test]
    fn unknown_observation_exposes_only_the_reservation_and_never_a_terminal() {
        let intent = DependencyRunIntent::new(
            pins("0123456789abcdef"),
            "/usr/bin/limactl",
            "fixture-vm",
            &"0".repeat(64),
        )
        .unwrap();
        let reader = "d".repeat(64);
        let value = json!({"schema":"hol-gauntlet-native-dependency-unknown.v1","job_id":intent.pins.text("job_id"),
            "source_sha":intent.pins.text("source_sha"),"intent_sha256":intent.digest().unwrap(),"worker_generation":intent.pins.text("runner_binary_sha256"),
            "reader_generation":reader,"started_marker_sha256":"e".repeat(64),"running_marker_sha256":null,
            "retained_client_cgroup_receipt_sha256":null,"status":"unknown","exit_code":null,"artifact_admitted":false,"execution_eligible":false,
            "qualification_eligible":false,"guard_causality_verified":false,"model_requests":0,"model_tokens":0});
        let verify = |v: &Value| {
            verify_dependency_unknown_result(
                &intent,
                &reader,
                &canonicalize(v.to_string().as_bytes()).unwrap(),
            )
        };
        let public = verify(&value).unwrap();
        assert_eq!(public["status"], "unknown");
        assert!(public["exit_code"].is_null());
        for key in value.as_object().unwrap().keys() {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(verify(&bad).is_err(), "{key}");
        }
        for (key, v) in [
            ("status", json!("passed")),
            ("exit_code", json!(0)),
            ("execution_eligible", json!(true)),
            ("model_tokens", json!(1)),
            ("started_marker_sha256", json!(intent.nonce)),
        ] {
            let mut bad = value.clone();
            bad[key] = v;
            assert!(verify(&bad).is_err(), "{key}");
        }
    }
    fn pins(job: &str) -> DependencyRunPins {
        DependencyRunPins::from_value(json!({
        "job_id":job,"source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
        "capsule_sha256":"c".repeat(64),"capsule_bytes":1551712,"pyproject_sha256":"d".repeat(64),
        "uv_lock_sha256":"e".repeat(64),"exporter_sha256":"f".repeat(64),"capture_worker_sha256":"1".repeat(64),
        "capture_receipt_sha256":"2".repeat(64),"controller_root":"/opt/hol-gauntlet/controller-0123456789abcdef",
        "controller_tree_sha256":"3".repeat(64),"uv_base_image_id":"4".repeat(64),"rust_base_image_id":"5".repeat(64),
        "builder_image_id":format!("sha256:{}", "6".repeat(64)),"policy_sha256":"7".repeat(64),"podman_sha256":"8".repeat(64),
        "slirp4netns_sha256":"9".repeat(64),"apparmor_parser_sha256":"a".repeat(64),"seccomp_sha256":"b".repeat(64),"runner_binary_sha256":"c".repeat(64)
    })).unwrap()
    }

    fn repair_reply(intent: &DependencyRunIntent) -> serde_json::Value {
        json!({"schema":"hol-gauntlet-native-dependency-repair.v2","job_id":intent.pins.text("job_id"),
        "source_sha":intent.pins.text("source_sha"),"intent_sha256":intent.digest().unwrap(),
        "worker_generation":intent.pins.text("runner_binary_sha256"),"repair_generation":"d".repeat(64),
        "started_marker_sha256":"e".repeat(64),"running_marker_sha256":"f".repeat(64),
        "container_id":"1".repeat(64),"client_cgroup_receipt_sha256":"2".repeat(64),
        "captured_dependencies_bytes":null,"captured_dependencies_sha256":null,"status":"aborted","exit_code":null,
        "quiescent":true,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,
        "guard_causality_verified":false,"model_requests":0,"model_tokens":0})
    }

    #[test]
    fn dependency_repair_codec_refuses_missing_or_foreign_fields_and_execution_credit() {
        let intent = DependencyRunIntent::new(
            pins("0123456789abcdef"),
            "/usr/bin/limactl",
            "fixture-vm",
            &"0".repeat(64),
        )
        .unwrap();
        let started = "e".repeat(64);
        let generation = "d".repeat(64);
        let value = repair_reply(&intent);
        let verify = |v: &serde_json::Value| {
            verify_dependency_repair_result(
                &intent,
                &started,
                &generation,
                &canonicalize(v.to_string().as_bytes()).unwrap(),
            )
        };
        assert!(verify(&value).is_ok());
        for key in value.as_object().unwrap().keys() {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(verify(&bad).is_err(), "{key}");
        }
        for (key, v) in [
            ("schema", json!("hol-gauntlet-native-dependency-repair.v1")),
            ("status", json!("passed")),
            ("exit_code", json!(0)),
            ("model_requests", json!(1)),
            ("model_tokens", json!(1)),
            ("execution_eligible", json!(true)),
            ("qualification_eligible", json!(true)),
            ("quiescent", json!(false)),
            ("container_id", json!("short")),
            ("captured_dependencies_sha256", json!(intent.nonce)),
            ("extra", json!(0)),
        ] {
            let mut bad = value.clone();
            bad[key] = v;
            assert!(verify(&bad).is_err(), "{key}");
        }
        assert!(verify_dependency_repair_result(
            &intent,
            &"a".repeat(64),
            &generation,
            &canonicalize(value.to_string().as_bytes()).unwrap()
        )
        .is_err());
    }
}
