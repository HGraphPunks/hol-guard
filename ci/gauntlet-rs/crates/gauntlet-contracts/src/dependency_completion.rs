//! Snapshot-bound retirement of incomplete completion records grants no exit.
use crate::{canonicalize, dependency_expected_started_marker, DependencyRunIntent};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const UNKNOWN: &str = "hol-gauntlet-native-dependency-unknown.v3";
const REPAIR: &str = "hol-gauntlet-native-dependency-repair.v5";
const CUSTODY: [&str; 6] = [
    "started_marker_sha256",
    "running_marker_sha256",
    "container_id",
    "client_cgroup_receipt_sha256",
    "captured_dependencies_bytes",
    "captured_dependencies_sha256",
];
const RECORDS: [&str; 4] = [
    "retained_report_sha256",
    "retained_report_metadata_sha256",
    "retained_terminal_sha256",
    "retained_terminal_metadata_sha256",
];
fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn hash(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn encode(v: &Value) -> Result<Vec<u8>, String> {
    canonicalize(v.to_string().as_bytes()).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyCompletionState {
    bindings: Value,
    pub sha256: String,
}
impl DependencyCompletionState {
    pub fn inspect(
        intent: &DependencyRunIntent,
        custody: &Value,
        report: (&[u8], &str),
        terminal: Option<(&[u8], &str)>,
    ) -> Result<Self, String> {
        if report.0.len() > 16384 || terminal.is_some_and(|(b, _)| b.len() > 2048) {
            return Err("completion record exceeds bound".into());
        }
        let mut v = json!({});
        for key in CUSTODY {
            v[key] = custody
                .get(key)
                .ok_or("completion custody missing")?
                .clone();
        }
        v[RECORDS[0]] = json!(digest(report.0));
        v[RECORDS[1]] = json!(report.1);
        v[RECORDS[2]] = json!(terminal.map(|(b, _)| digest(b)));
        v[RECORDS[3]] = json!(terminal.map(|(_, m)| m));
        Self::from_fields(intent, &v)
    }
    fn from_fields(intent: &DependencyRunIntent, fields: &Value) -> Result<Self, String> {
        let captured = &fields["captured_dependencies_bytes"];
        let capture_hash = &fields["captured_dependencies_sha256"];
        if CUSTODY[..4]
            .iter()
            .chain(RECORDS[..2].iter())
            .any(|k| !hash(&fields[k]))
            || fields["started_marker_sha256"]
                != digest(&dependency_expected_started_marker(intent)?)
            || RECORDS[2..]
                .iter()
                .any(|k| !fields[k].is_null() && !hash(&fields[k]))
            || fields[RECORDS[2]].is_null() != fields[RECORDS[3]].is_null()
            || !(captured.is_null() && capture_hash.is_null()
                || captured
                    .as_u64()
                    .is_some_and(|n| (1..=256 * 1024 * 1024).contains(&n))
                    && hash(capture_hash))
        {
            return Err("completion custody or record bindings differ".into());
        }
        let mut bindings = json!({"schema":"hol-gauntlet-dependency-completion-state.v1",
            "job_id":intent.pins.text("job_id"),"source_sha":intent.pins.text("source_sha"),
            "intent_sha256":intent.digest()?,"worker_generation":intent.pins.text("runner_binary_sha256")});
        for key in CUSTODY.into_iter().chain(RECORDS) {
            bindings[key] = fields[key].clone();
        }
        let sha256 = digest(&encode(&bindings)?);
        Ok(Self { bindings, sha256 })
    }
    fn frame(
        &self,
        intent: &DependencyRunIntent,
        generation: &str,
        repair: bool,
    ) -> Result<Vec<u8>, String> {
        if !hash(&json!(generation)) {
            return Err("exact completion executable SHA-256 required".into());
        }
        let mut v = self.bindings.clone();
        v["schema"] = json!(if repair { REPAIR } else { UNKNOWN });
        v[if repair {
            "repair_generation"
        } else {
            "reader_generation"
        }] = json!(generation);
        v["completion_state_sha256"] = json!(self.sha256);
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
            v["quiescent"] = json!(true);
        }
        let raw = encode(&v)?;
        if v.to_string().contains(&intent.nonce) {
            return Err("private completion value appeared in response".into());
        }
        Ok(raw)
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

pub fn dependency_completion_authorization(
    intent: &DependencyRunIntent,
    started: &str,
    generation: &str,
    state: &str,
) -> Result<Vec<u8>, String> {
    crate::dependency_repair_authorization(intent, started, generation)?;
    if !hash(&json!(state)) || started != digest(&dependency_expected_started_marker(intent)?) {
        return Err("exact original reservation and completion snapshot required".into());
    }
    encode(
        &json!({"schema":"hol-gauntlet-host-dependency-repair-authorization.v3",
        "job_id":intent.pins.text("job_id"),"intent_sha256":intent.digest()?,
        "started_marker_sha256":started,"repair_generation":generation,"completion_state_sha256":state}),
    )
}
pub fn dependency_completion_authorization_state(
    intent: &DependencyRunIntent,
    raw: &[u8],
) -> Result<Option<String>, String> {
    crate::parse_dependency_repair_authorization(intent, raw)?;
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    Ok(v["completion_state_sha256"].as_str().map(str::to_owned))
}
pub(crate) fn verify(
    intent: &DependencyRunIntent,
    generation: &str,
    started: Option<&str>,
    raw: &[u8],
) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let state = DependencyCompletionState::from_fields(intent, &v)?;
    let repair = started.is_some();
    if started.is_some_and(|s| v["started_marker_sha256"] != s)
        || state.frame(intent, generation, repair)? != raw
    {
        return Err("closed completion recovery differs from outside pins".into());
    }
    let mut public = v;
    public["schema"] = json!(if repair {
        "hol-gauntlet-host-dependency-repair.v4"
    } else {
        "hol-gauntlet-host-dependency-unknown.v3"
    });
    if repair {
        public["private_result_sha256"] = json!(digest(raw));
        public["retained_result_reconciled"] = json!(false);
    }
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn intent() -> DependencyRunIntent {
        let pins = crate::DependencyRunPins::from_value(json!({
            "job_id":"0123456789abcdef","source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
            "capsule_sha256":"c".repeat(64),"capsule_bytes":1551712,"pyproject_sha256":"d".repeat(64),
            "uv_lock_sha256":"e".repeat(64),"exporter_sha256":"f".repeat(64),"capture_worker_sha256":"1".repeat(64),
            "capture_receipt_sha256":"2".repeat(64),"controller_root":"/opt/hol-gauntlet/controller-0123456789abcdef",
            "controller_tree_sha256":"3".repeat(64),"uv_base_image_id":"4".repeat(64),"rust_base_image_id":"5".repeat(64),
            "builder_image_id":format!("sha256:{}", "6".repeat(64)),"policy_sha256":"7".repeat(64),"podman_sha256":"8".repeat(64),
            "slirp4netns_sha256":"9".repeat(64),"apparmor_parser_sha256":"a".repeat(64),"seccomp_sha256":"b".repeat(64),
            "runner_binary_sha256":"c".repeat(64)
        })).unwrap();
        DependencyRunIntent::new(pins, "/usr/bin/limactl", "fixture-vm", &"0".repeat(64)).unwrap()
    }
    #[test]
    fn completion_snapshots_distinguish_absence_empty_bytes_metadata_and_private_values() {
        let intent = intent();
        let custody = json!({"started_marker_sha256":digest(&dependency_expected_started_marker(&intent).unwrap()),
            "running_marker_sha256":"1".repeat(64),"container_id":"2".repeat(64),"client_cgroup_receipt_sha256":"3".repeat(64),
            "captured_dependencies_bytes":null,"captured_dependencies_sha256":null});
        let metadata = "4".repeat(64);
        let a =
            DependencyCompletionState::inspect(&intent, &custody, (b"", &metadata), None).unwrap();
        let b =
            DependencyCompletionState::inspect(&intent, &custody, (b"{", &metadata), None).unwrap();
        let c = DependencyCompletionState::inspect(&intent, &custody, (b"", &"5".repeat(64)), None)
            .unwrap();
        let d = DependencyCompletionState::inspect(
            &intent,
            &custody,
            (b"", &metadata),
            Some((b"", &metadata)),
        )
        .unwrap();
        for other in [b, c, d] {
            assert_ne!(a.sha256, other.sha256);
        }
        let reader = "6".repeat(64);
        let started = custody["started_marker_sha256"].as_str().unwrap();
        for repair in [false, true] {
            let raw = a.frame(&intent, &reader, repair).unwrap();
            let public = verify(&intent, &reader, repair.then_some(started), &raw).unwrap();
            assert!(public["exit_code"].is_null());
            assert!(!public.to_string().contains(&intent.nonce));
            let value: Value = serde_json::from_slice(&raw).unwrap();
            for key in value.as_object().unwrap().keys() {
                let mut bad = value.clone();
                bad.as_object_mut().unwrap().remove(key);
                assert!(
                    verify(
                        &intent,
                        &reader,
                        repair.then_some(started),
                        &encode(&bad).unwrap()
                    )
                    .is_err(),
                    "{key}"
                );
                let mut bad = value.clone();
                bad[key] = json!(intent.nonce);
                assert!(
                    verify(
                        &intent,
                        &reader,
                        repair.then_some(started),
                        &encode(&bad).unwrap()
                    )
                    .is_err(),
                    "{key}"
                );
            }
            let mut extra = value;
            extra["extra"] = json!(false);
            assert!(verify(
                &intent,
                &reader,
                repair.then_some(started),
                &encode(&extra).unwrap()
            )
            .is_err());
            assert!(verify(&intent, &"7".repeat(64), repair.then_some(started), &raw).is_err());
        }
        let auth =
            dependency_completion_authorization(&intent, started, &reader, &a.sha256).unwrap();
        assert_eq!(
            dependency_completion_authorization_state(&intent, &auth).unwrap(),
            Some(a.sha256)
        );
        assert!(dependency_completion_authorization(
            &intent,
            &"f".repeat(64),
            &reader,
            &"a".repeat(64)
        )
        .is_err());
        let mut bad = custody;
        bad["captured_dependencies_bytes"] = json!(1);
        assert!(DependencyCompletionState::inspect(&intent, &bad, (b"", &metadata), None).is_err());
        bad["captured_dependencies_sha256"] = json!("f".repeat(64));
        assert!(DependencyCompletionState::inspect(&intent, &bad, (b"", &metadata), None).is_ok());
        assert!(DependencyCompletionState::inspect(
            &intent,
            &bad,
            (&vec![0; 16385], &metadata),
            None
        )
        .is_err());
        assert!(DependencyCompletionState::inspect(
            &intent,
            &bad,
            (b"", &metadata),
            Some((&vec![0; 2049], &metadata))
        )
        .is_err());
    }
}
