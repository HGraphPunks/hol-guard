//! Recovery observations bind incomplete preparation without authorizing execution.
use crate::{
    canonicalize, dependency_repair_authorization, verify_dependency_repair_result,
    DependencyRunIntent,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const UNKNOWN: &str = "hol-gauntlet-native-dependency-unknown.v2";
const REPAIR: &str = "hol-gauntlet-native-dependency-repair.v4";
const HASH_FIELDS: [&str; 4] = [
    "retained_started_marker_sha256",
    "retained_started_metadata_sha256",
    "retained_intent_sha256",
    "retained_intent_metadata_sha256",
];
fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn encode(v: &Value) -> Result<Vec<u8>, String> {
    canonicalize(v.to_string().as_bytes()).map_err(|e| e.to_string())
}

/// The unkeyed reservation consumes an ID; it never asserts a process launch.
pub fn dependency_expected_started_marker(intent: &DependencyRunIntent) -> Result<Vec<u8>, String> {
    encode(
        &json!({"schema":"hol-gauntlet-worker-started.v1","source_sha":intent.pins.text("source_sha"),
        "job_id":intent.pins.text("job_id"),"deployment_digest":intent.digest()?,
        "worker_generation":intent.pins.text("runner_binary_sha256")}),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPreparationState {
    pub expected_started_sha256: String,
    pub sha256: String,
    retained: [Option<String>; 4],
}
impl DependencyPreparationState {
    pub fn inspect(
        intent: &DependencyRunIntent,
        started: Option<&[u8]>,
        started_metadata: Option<&str>,
        retained_intent: Option<&[u8]>,
        intent_metadata: Option<&str>,
    ) -> Result<Self, String> {
        let expected_started = dependency_expected_started_marker(intent)?;
        let expected_intent = intent.bytes()?;
        if !started.is_none_or(|b| expected_started.starts_with(b))
            || !retained_intent.is_none_or(|b| expected_intent.starts_with(b))
        {
            return Err(
                "preparation bytes differ from the original intent or unkeyed reservation".into(),
            );
        }
        Self::from_hashes(
            intent,
            [
                started.map(digest),
                started_metadata.map(str::to_owned),
                retained_intent.map(digest),
                intent_metadata.map(str::to_owned),
            ],
        )
    }
    fn from_hashes(
        intent: &DependencyRunIntent,
        retained: [Option<String>; 4],
    ) -> Result<Self, String> {
        if retained.iter().flatten().any(|s| !hash(s))
            || retained[0].is_some() != retained[1].is_some()
            || retained[2].is_some() != retained[3].is_some()
        {
            return Err("preparation content and metadata bindings differ".into());
        }
        let mut result = Self {
            expected_started_sha256: digest(&dependency_expected_started_marker(intent)?),
            sha256: String::new(),
            retained,
        };
        result.sha256 = digest(&encode(&result.bindings(intent)?)?);
        Ok(result)
    }
    fn bindings(&self, intent: &DependencyRunIntent) -> Result<Value, String> {
        let mut v = json!({"schema":"hol-gauntlet-dependency-preparation-state.v1",
            "job_id":intent.pins.text("job_id"),"source_sha":intent.pins.text("source_sha"),
            "intent_sha256":intent.digest()?,"worker_generation":intent.pins.text("runner_binary_sha256"),
            "expected_started_marker_sha256":self.expected_started_sha256});
        for (key, value) in HASH_FIELDS.iter().zip(&self.retained) {
            v[key] = json!(value);
        }
        Ok(v)
    }
    fn observed(intent: &DependencyRunIntent, v: &Value) -> Result<Self, String> {
        let mut retained: [Option<String>; 4] = Default::default();
        for (index, key) in HASH_FIELDS.iter().enumerate() {
            retained[index] = match &v[key] {
                Value::Null => None,
                Value::String(s) if hash(s) => Some(s.clone()),
                _ => return Err("preparation digest unavailable".into()),
            };
        }
        let state = Self::from_hashes(intent, retained)?;
        if v["expected_started_marker_sha256"] != state.expected_started_sha256
            || v["preparation_state_sha256"] != state.sha256
        {
            return Err("preparation observation differs from outside intent".into());
        }
        Ok(state)
    }
    fn frame(
        &self,
        intent: &DependencyRunIntent,
        generation: &str,
        repair: bool,
    ) -> Result<Vec<u8>, String> {
        if !hash(generation) {
            return Err("exact preparation executable SHA-256 required".into());
        }
        let mut v = self.bindings(intent)?;
        v["schema"] = json!(if repair { REPAIR } else { UNKNOWN });
        v[if repair {
            "repair_generation"
        } else {
            "reader_generation"
        }] = json!(generation);
        v["preparation_state_sha256"] = json!(self.sha256);
        v["status"] = json!(if repair { "aborted" } else { "unknown" });
        v["exit_code"] = Value::Null;
        for key in [
            "artifact_admitted",
            "execution_eligible",
            "qualification_eligible",
            "guard_causality_verified",
        ] {
            v[key] = json!(false);
        }
        v["model_requests"] = json!(0);
        v["model_tokens"] = json!(0);
        if repair {
            v["intent"] = serde_json::from_slice(&intent.bytes()?).map_err(|e| e.to_string())?;
            v["quiescent"] = json!(true);
        }
        encode(&v)
    }
    pub fn unknown(&self, intent: &DependencyRunIntent, reader: &str) -> Result<Vec<u8>, String> {
        self.frame(intent, reader, false)
    }
    pub fn retired(
        &self,
        intent: &DependencyRunIntent,
        generation: &str,
    ) -> Result<Vec<u8>, String> {
        self.frame(intent, generation, true)
    }
}

pub fn dependency_preparation_authorization(
    intent: &DependencyRunIntent,
    started: &str,
    generation: &str,
    state: &str,
) -> Result<Vec<u8>, String> {
    crate::dependency_repair_authorization(intent, started, generation)?;
    if !hash(state) {
        return Err("exact preparation state SHA-256 required".into());
    }
    encode(
        &json!({"schema":"hol-gauntlet-host-dependency-repair-authorization.v2",
        "job_id":intent.pins.text("job_id"),"intent_sha256":intent.digest()?,
        "started_marker_sha256":started,"repair_generation":generation,"preparation_state_sha256":state}),
    )
}
pub fn dependency_preparation_authorization_state(
    intent: &DependencyRunIntent,
    raw: &[u8],
) -> Result<Option<String>, String> {
    crate::parse_dependency_repair_authorization(intent, raw)?;
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    Ok(v["preparation_state_sha256"].as_str().map(str::to_owned))
}

pub(crate) fn verify_preparation_unknown(
    intent: &DependencyRunIntent,
    reader: &str,
    raw: &[u8],
) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let state = DependencyPreparationState::observed(intent, &v)?;
    if state.unknown(intent, reader)? != raw {
        return Err("closed canonical preparation observation required".into());
    }
    let mut public = v;
    public["schema"] = json!("hol-gauntlet-host-dependency-unknown.v2");
    if public.to_string().contains(&intent.nonce) {
        return Err("private preparation value appeared in observation".into());
    }
    Ok(public)
}
pub(crate) fn verify_preparation_repair(
    intent: &DependencyRunIntent,
    started: &str,
    generation: &str,
    raw: &[u8],
) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let state = DependencyPreparationState::observed(intent, &v)?;
    if started != state.expected_started_sha256 || state.retired(intent, generation)? != raw {
        return Err("preparation retirement differs from original intent or authorization".into());
    }
    let mut public = v;
    public
        .as_object_mut()
        .ok_or("preparation repair object required")?
        .remove("intent");
    public["schema"] = json!("hol-gauntlet-host-dependency-repair.v3");
    public["private_result_sha256"] = json!(digest(raw));
    public["retained_result_reconciled"] = json!(false);
    if public.to_string().contains(&intent.nonce) {
        return Err("private preparation value appeared in retirement".into());
    }
    Ok(public)
}

/// Explicit recovery may complete an original report or retain an aborted run.
pub fn verify_dependency_recovery_reply(
    intent: &DependencyRunIntent,
    started: &str,
    repair_generation: &str,
    reader_generation: &str,
    raw: &[u8],
) -> Result<Value, String> {
    dependency_repair_authorization(intent, started, repair_generation)?;
    if raw.is_empty() || raw.len() > 32768 {
        return Err("bounded dependency recovery reply required".into());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if value["schema"] == "hol-gauntlet-native-dependency-read.v1" {
        let public = crate::verify_dependency_read_response(intent, reader_generation, raw)?;
        if value["report"]["started_marker_sha256"] != started {
            return Err("finalized dependency reservation differs from authorization".into());
        }
        Ok(public)
    } else {
        verify_dependency_repair_result(intent, started, repair_generation, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DependencyRunPins;
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
    fn intent() -> DependencyRunIntent {
        DependencyRunIntent::new(
            pins("0123456789abcdef"),
            "/usr/bin/limactl",
            "fixture-vm",
            &"0".repeat(64),
        )
        .unwrap()
    }
    #[test]
    fn preparation_accepts_every_exact_prefix_without_reconstructing_evidence() {
        let intent = intent();
        let started = dependency_expected_started_marker(&intent).unwrap();
        let original = intent.bytes().unwrap();
        let metadata = "a".repeat(64);
        let inspect = |a: Option<&[u8]>, b: Option<&[u8]>| {
            DependencyPreparationState::inspect(
                &intent,
                a,
                a.map(|_| metadata.as_str()),
                b,
                b.map(|_| metadata.as_str()),
            )
        };
        let absent = inspect(None, None).unwrap();
        assert_ne!(absent, inspect(Some(b""), None).unwrap());
        assert_ne!(absent, inspect(None, Some(b"")).unwrap());
        for n in 0..=started.len() {
            let state = inspect(Some(&started[..n]), None).unwrap();
            assert_eq!(state.expected_started_sha256, digest(&started));
        }
        for n in 0..=original.len() {
            assert!(inspect(Some(&started), Some(&original[..n])).is_ok());
        }
        for raw in [b" {}".as_slice(), b"null", b"{\"foreign\":1}", &[0xff]] {
            assert!(inspect(Some(raw), None).is_err());
            assert!(inspect(None, Some(raw)).is_err());
        }
        assert!(inspect(Some(&[started.as_slice(), b"\n"].concat()), None).is_err());
        assert!(inspect(None, Some(&[original.as_slice(), b"\n"].concat())).is_err());
        assert!(
            DependencyPreparationState::inspect(&intent, Some(b"{"), None, None, None).is_err()
        );
        assert!(
            DependencyPreparationState::inspect(&intent, None, Some(&metadata), None, None)
                .is_err()
        );
        let a = inspect(Some(b"{"), Some(b"{")).unwrap();
        let b = DependencyPreparationState::inspect(
            &intent,
            Some(b"{"),
            Some(&"b".repeat(64)),
            Some(b"{"),
            Some(&metadata),
        )
        .unwrap();
        assert_ne!(a.sha256, b.sha256);
        let foreign = DependencyRunIntent::new(
            pins("fedcba9876543210"),
            "/usr/bin/limactl",
            "fixture-vm",
            &"0".repeat(64),
        )
        .unwrap();
        assert!(inspect(
            Some(&dependency_expected_started_marker(&foreign).unwrap()),
            None
        )
        .is_err());
        assert!(inspect(None, Some(&foreign.bytes().unwrap())).is_err());
    }
    #[test]
    fn preparation_recovery_requires_closed_state_and_never_projects_private_intent() {
        let intent = intent();
        let state = DependencyPreparationState::inspect(
            &intent,
            Some(b"{"),
            Some(&"a".repeat(64)),
            None,
            None,
        )
        .unwrap();
        let generation = "d".repeat(64);
        let auth = dependency_preparation_authorization(
            &intent,
            &state.expected_started_sha256,
            &generation,
            &state.sha256,
        )
        .unwrap();
        assert_eq!(
            dependency_preparation_authorization_state(&intent, &auth).unwrap(),
            Some(state.sha256.clone())
        );
        assert_eq!(
            crate::parse_dependency_repair_authorization(&intent, &auth).unwrap(),
            (state.expected_started_sha256.clone(), generation.clone())
        );
        let legacy =
            dependency_repair_authorization(&intent, &state.expected_started_sha256, &generation)
                .unwrap();
        assert!(dependency_preparation_authorization_state(&intent, &legacy)
            .unwrap()
            .is_none());
        for repair in [false, true] {
            let raw = state.frame(&intent, &generation, repair).unwrap();
            let verify = |raw: &[u8]| {
                if repair {
                    verify_dependency_repair_result(
                        &intent,
                        &state.expected_started_sha256,
                        &generation,
                        raw,
                    )
                } else {
                    crate::verify_dependency_unknown_result(&intent, &generation, raw)
                }
            };
            let public = verify(&raw).unwrap();
            assert!(!public.to_string().contains(&intent.nonce));
            assert!(public.get("intent").is_none());
            assert_eq!(public["preparation_state_sha256"], state.sha256);
            assert_eq!(public["execution_eligible"], false);
            let v: Value = serde_json::from_slice(&raw).unwrap();
            for field in v.as_object().unwrap().keys() {
                let mut missing = v.clone();
                missing.as_object_mut().unwrap().remove(field);
                assert!(
                    verify(&encode(&missing).unwrap()).is_err(),
                    "missing {field}"
                );
                let mut changed = v.clone();
                changed[field] = json!("foreign");
                assert!(
                    verify(&encode(&changed).unwrap()).is_err(),
                    "changed {field}"
                );
            }
            let mut extra = v.clone();
            extra["private"] = json!(intent.nonce);
            assert!(verify(&encode(&extra).unwrap()).is_err());
            assert!(verify(&[raw.as_slice(), b"\n"].concat()).is_err());
        }
        let raw = state.retired(&intent, &generation).unwrap();
        assert!(
            verify_dependency_repair_result(&intent, &"f".repeat(64), &generation, &raw).is_err()
        );
        assert!(verify_dependency_repair_result(
            &intent,
            &state.expected_started_sha256,
            &"e".repeat(64),
            &raw
        )
        .is_err());
    }
}
