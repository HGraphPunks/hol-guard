use super::*;
use crate::native_operation::{failure as flow, public_export::tests::archive as tar};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{collections::BTreeMap, io::Write};

struct Fixture {
    _temp: tempfile::TempDir,
    j: Journal,
    i: Intent,
    f: Value,
    files: BTreeMap<String, Vec<u8>>,
    raw: Vec<u8>,
    e: Value,
}
fn wrap(schema: &str, receipt: Value) -> Value {
    json!({"schema":schema,"receipt_sha256":sha(&bytes(&receipt).unwrap()),"receipt":receipt})
}
fn encode(
    f: &Value,
    mut files: BTreeMap<String, Vec<u8>>,
    change: impl FnOnce(&mut Value),
) -> (Vec<u8>, Value) {
    files.remove("results.sha256.json");
    let mut index = base(f, "hol-gauntlet-native-live-failure-evidence.v1");
    for (k, v) in [
        (
            "status",
            json!("signed-controller-failure-outer-exit-unavailable"),
        ),
        ("prelaunch", f["prelaunch"].clone()),
        ("controller", f["observation"]["controller"].clone()),
        ("quiescent", f["observation"]["quiescent"].clone()),
        ("observation_sha256", f["observation_sha256"].clone()),
        ("exit_code", Value::Null),
        ("model_requests", Value::Null),
        ("qualification_eligible", json!(false)),
        ("execution_eligible", json!(false)),
        ("guard_causality_verified", json!(false)),
    ] {
        index[k] = v;
    }
    index["files"] = Value::Object(
        files
            .iter()
            .map(|(n, b)| (n.clone(), json!({"bytes":b.len(),"sha256":sha(b)})))
            .collect(),
    );
    index["filesystem"] = Value::Object(files.iter().enumerate().map(|(k,(n,b))| {
        let mode = if n.ends_with(".apparmor") {0o400} else if n.starts_with("cell/") && !n.ends_with(".jsonl") {0o444} else {0o600};
        (n.clone(),json!({"device":1,"inode":k+100,"uid":0,"gid":0,"mode":mode,"links":1,"bytes":b.len(),"mtime":1,"mtime_nsec":0,"ctime":1,"ctime_nsec":0}))
    }).collect());
    change(&mut index);
    let manifest = bytes(&index).unwrap();
    files.insert("results.sha256.json".into(), manifest.clone());
    let raw = tar(&files);
    let mut e = base(f, "hol-gauntlet-native-live-failure-export.v1");
    for (k, v) in [
        ("archive_sha256", json!(sha(&raw))),
        ("archive_bytes", json!(raw.len())),
        ("manifest_sha256", json!(sha(&manifest))),
        ("exit_code", Value::Null),
        ("model_requests", Value::Null),
        ("execution_eligible", json!(false)),
        ("qualification_eligible", json!(false)),
    ] {
        e[k] = v;
    }
    (
        raw,
        wrap("hol-gauntlet-native-live-failure-export-result.v1", e),
    )
}
fn fixture() -> Fixture {
    let (temp, j, i, _, live) = crate::native_operation::live::channel::tests::prepared_fixture();
    j.write(i.job(), "dispatch", &Journal::dispatch_raw(&i).unwrap())
        .unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
    let public = key
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let started = json!({"schema":"hol-gauntlet-worker-started.v2","source_sha":i.text("source_sha"),"job_id":i.job(),"deployment_digest":i.text("deployment_digest"),"worker_generation":i.text("worker_generation"),"controller_public_key_hex":public});
    let key_pin = json!({"schema":"hol-gauntlet-controller-key-pin.v1","source_sha":i.text("source_sha"),"job_id":i.job(),"deployment_digest":i.text("deployment_digest"),"worker_generation":i.text("worker_generation"),"started_marker_sha256":sha(&bytes(&started).unwrap()),"controller_public_key_hex":public});
    let pre = PrelaunchPrepared {
        source_sha: i.text("source_sha").into(),
        job_id: i.job().into(),
        deployment_digest: i.text("deployment_digest").into(),
        worker_generation: i.text("worker_generation").into(),
        started_marker_sha256: sha(&bytes(&started).unwrap()),
        controller_key_pin_sha256: sha(&bytes(&key_pin).unwrap()),
        controller_public_key_hex: public,
    };
    let (record, _) = HostControllerKeyPinJournal::open(&j.path)
        .unwrap()
        .accept_prepared(&pre.to_bytes().unwrap(), &i.expected())
        .unwrap();
    let controller = json!({"pid":241,"start_ticks":32});
    let running = json!({"schema":"hol-gauntlet-native-worker-running.v1","source_sha":i.text("source_sha"),"job_id":i.job(),"deployment_digest":i.text("deployment_digest"),"worker_generation":i.text("worker_generation"),"controller":controller});
    let creation = format!("{}\n", "a".repeat(64)).into_bytes();
    let inspection = bytes(&json!([{"Id":"a".repeat(64),"State":{"Status":"created","Pid":0,"Running":false,"Paused":false,"Restarting":false,"Dead":false,"OOMKilled":false,"ExitCode":0,"Error":"","StartedAt":"0001-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}}])).unwrap();
    let policy = b"profile fixture { deny /proc/**/mem rw, }\n".to_vec();
    let initialized = parse(&j.read(i.job(), "initialize-result").unwrap()).unwrap();
    let pins = json!({"source_sha":i.text("source_sha"),"job_id":i.job(),"deployment_digest":i.text("deployment_digest"),"worker_generation":i.text("worker_generation"),"preparation_sha256":i.text("preparation_sha256"),"live_prepared_sha256":live["receipt_sha256"],"storage_receipt_sha256":initialized["receipt"]["storage"]["receipt_sha256"],"host_pin_sha256":record.raw_sha256,"container_id":"a".repeat(64),"creation_sha256":sha(&creation),"inspection_sha256":sha(&inspection),"policy_sha256":sha(&policy),"repair_generation":"e".repeat(64)});
    let created_intent = json!({"schema":"hol-gauntlet-native-live-sdk-created-repair-intent.v1","pins":pins,"prelaunch":parse(&pre.to_bytes().unwrap()).unwrap(),"running_marker_sha256":sha(&bytes(&running).unwrap()),"quiescent":{},"temporary_intent_sha256":"b".repeat(64),"temporary_complete_sha256":"c".repeat(64),"model_requests":null,"exit_code":null,"execution_eligible":false});
    let created = json!({"schema":"hol-gauntlet-native-live-sdk-created-repair.v1","intent_sha256":sha(&bytes(&created_intent).unwrap()),"pins_sha256":sha(&bytes(&pins).unwrap()),"container_id_sha256":sha("a".repeat(64).as_bytes()),"sdk_agent_absent":true,"sdk_profile_absent":true,"process_signalled":false,"image_adopted":false,"job_terminal_written":false,"model_requests":null,"exit_code":null,"execution_eligible":false,"qualification_eligible":false});
    let host_created = json!({"schema":"hol-gauntlet-host-native-live-created-repair-intent.v1","native_intent_sha256":i.digest().unwrap(),"pins":pins,"prelaunch":parse(&pre.to_bytes().unwrap()).unwrap(),"parent_custody":context::snapshot(&j.path).unwrap()});
    let authorization = json!({"schema":"hol-gauntlet-host-live-repair-intent.v1","job_id":i.job(),"intent_sha256":i.digest().unwrap(),"repair_generation":"e".repeat(64),"never_released":false,"live_prepared_sha256":live["receipt_sha256"]});
    let cleanup = json!({"controller_process_absent":true,"controller_cgroup_absent":true,"product_slice_absent":true,"sdk_agent_absent":true,"sdk_profile_absent":true,"mcp_agent_absent":true,"mcp_profile_absent":true,"image_lease_absent":true,"public_key_retained":true,"image_unmounted":true,"active_pointer_absent":true,"active_pointer_sha256":null,"quiescent":{"image_history":"already-closed-v1"}});
    let repair = json!({"schema":"hol-gauntlet-native-live-keyed-worker-repair.v1","prelaunch":parse(&pre.to_bytes().unwrap()).unwrap(),"preparation_sha256":i.text("preparation_sha256"),"repair_generation":"e".repeat(64),"status":"aborted","controller_state":"released-exit-unavailable","exit_code":null,"model_requests":null,"execution_eligible":false,"guard_causality_verified":false,"cleanup":cleanup,"live_prepared_sha256":live["receipt_sha256"],"running_marker_sha256":sha(&bytes(&running).unwrap()),"artifact_admitted":false,"qualification_eligible":false});
    for (s, v) in [
        ("live-created-repair-intent", host_created.clone()),
        (
            "live-created-repair-dispatch",
            json!({"schema":"hol-gauntlet-host-live-created-repair-dispatch.v1","intent_sha256":sha(&bytes(&host_created).unwrap()),"retry_allowed":false}),
        ),
        ("live-created-repair", created.clone()),
        ("repair-intent", authorization.clone()),
        ("repair-dispatch", authorization),
        ("repair", repair.clone()),
    ] {
        j.write(i.job(), s, &bytes(&v).unwrap()).unwrap();
    }
    let mut f = context(&j, &i, &"f".repeat(64)).unwrap();
    let report = json!({"schema":"hol-gauntlet-native-live-omp.v1","control_role":i.text("role"),"guard_pins":{"source_sha":i.text("source_sha")},"cell_id":i.0["live"]["cell_id"],"spec_sha256":i.0["live"]["spec_sha256"],"job_id":i.job(),"preparation_sha256":i.text("preparation_sha256"),"controller_identity":controller,"status":"failed","error":"SDK agent failed before inference","artifact_sha256":{},"model_requests":0,"qualified_role_complete":false,"execution_eligible":false,"guard_causality_verified":false});
    let signing = gauntlet_evidence::native_control_signing_record(
        &report,
        &NativeControlReportPins {
            prelaunch: pre.clone(),
            preparation_sha256: i.text("preparation_sha256").into(),
            role: i.text("role").into(),
        },
    )
    .unwrap();
    let envelope = String::from_utf8(bytes(&json!({"record":signing,"signature":STANDARD.encode(key.sign(&bytes(&signing).unwrap()).as_ref())})).unwrap()).unwrap()+"\n";
    f["signed_envelope_sha256"] = json!(sha(envelope.as_bytes()));
    let mut o = base(&f, "hol-gauntlet-native-live-failure-observation.v1");
    for (k, v) in [
        ("prelaunch", f["prelaunch"].clone()),
        ("live_prepared", live["receipt"].clone()),
        ("controller", controller),
        ("signed_envelope_utf8", json!(envelope)),
        ("stderr_sha256", json!(sha(b"SDK startup failed\n"))),
        (
            "records_sha256",
            json!({"started":pre.started_marker_sha256,"controller-key":pre.controller_key_pin_sha256,"running":sha(&bytes(&running).unwrap()),"native-repair":sha(&bytes(&repair).unwrap())}),
        ),
        ("quiescent", cleanup),
        ("model_requests", Value::Null),
        ("exit_code", Value::Null),
        ("execution_eligible", json!(false)),
        ("qualification_eligible", json!(false)),
    ] {
        o[k] = v;
    }
    f = observed(&j, &i, context_without_observation(&f), &o).unwrap();
    j.write(i.job(), &row(&i, INTENT), &bytes(&f).unwrap())
        .unwrap();
    let bundle = parse(&j.read(i.job(), "prepare-bundle").unwrap()).unwrap();
    let mut files = REQUIRED
        .iter()
        .filter(|n| **n != "results.sha256.json")
        .map(|n| (n.to_string(), b"{}\n".to_vec()))
        .collect::<BTreeMap<_, _>>();
    for (n, b) in [
        ("worker/started.json", bytes(&started).unwrap()),
        ("worker/controller-key.json", bytes(&key_pin).unwrap()),
        ("worker/running.json", bytes(&running).unwrap()),
        ("worker/native-repair.json", bytes(&repair).unwrap()),
        ("native.stdout", envelope.into_bytes()),
        ("native.stderr", b"SDK startup failed\n".to_vec()),
        ("preparation.json", bytes(&bundle["preparation"]).unwrap()),
        (
            "initialization.json",
            bytes(&initialized["receipt"]).unwrap(),
        ),
        ("declaration.json", bytes(&bundle["declaration"]).unwrap()),
        ("live/prepared.json", bytes(&live["receipt"]).unwrap()),
        ("sdk/created-intent.json", bytes(&created_intent).unwrap()),
        ("sdk/created-repair.json", bytes(&created).unwrap()),
        ("sdk/003.stdout", creation),
        ("sdk/004.stdout", inspection),
        ("sdk/policy.apparmor", policy),
    ] {
        files.insert(n.into(), b);
    }
    let (raw, e) = encode(&f, files.clone(), |_| {});
    archive(&j, &i, &f, &e, &raw).unwrap();
    Fixture {
        _temp: temp,
        j,
        i,
        f,
        files,
        raw,
        e,
    }
}

struct Mock {
    f: Value,
    e: Value,
    raw: Vec<u8>,
    root: bool,
    streams: usize,
    ack: Option<Value>,
    retired: Option<Value>,
    calls: Vec<String>,
}
impl Mock {
    fn new(f: &Fixture) -> Self {
        Self {
            f: f.f.clone(),
            e: f.e.clone(),
            raw: f.raw.clone(),
            root: false,
            streams: 0,
            ack: None,
            retired: None,
            calls: Vec::new(),
        }
    }
}
impl flow::Rpc for Mock {
    fn call(
        &mut self,
        a: &[String],
        input: &[u8],
        output: Option<&mut std::fs::File>,
    ) -> Result<Vec<u8>, String> {
        let op = a[1].as_str();
        self.calls.push(op.into());
        assert_eq!(
            &a[2..13],
            &BASE.map(|k| text(&self.f, k).unwrap().to_owned())
        );
        if let Some(file) = output {
            assert!(matches!(
                op,
                "--export-native-live-failure-v1"
                    | "--resume-native-live-failure-v1"
                    | "--read-native-live-failure-v1"
            ));
            if op == "--read-native-live-failure-v1" {
                assert!(input.is_empty());
                if !self.root {
                    return Err("Root export missing".into());
                }
            } else {
                assert_eq!(input, bytes(&self.f["prelaunch"]).unwrap());
                assert_eq!(a[13], input.len().to_string());
                if op == "--export-native-live-failure-v1" && self.root {
                    return Err("consumed".into());
                }
                self.root = true;
            }
            self.streams += 1;
            file.write_all(&self.raw).unwrap();
            return Ok(Vec::new());
        }
        assert!(input.is_empty());
        if op == "--read-native-live-failure-export-v1" {
            if !self.root {
                return Err("Root export missing".into());
            }
            return bytes(
                &json!({"schema":"hol-gauntlet-native-live-failure-export-state.v1","intent_sha256":sha(&bytes(&export_intent(&self.f)).unwrap()),"export":self.e,"export_complete":true,"retry_allowed":false}),
            );
        }
        if op == "--read-native-live-failure-ack-v1" {
            return self
                .ack
                .as_ref()
                .ok_or("ACK missing".into())
                .and_then(bytes);
        }
        if op == "--ack-native-live-failure-v1" {
            let mut r = self.e["receipt"].clone();
            r["schema"] = json!("hol-gauntlet-native-live-failure-ack.v1");
            r["export_receipt_sha256"] = json!(a[13]);
            r["host_receipt_sha256"] = json!(a[14]);
            let v = wrap("hol-gauntlet-native-live-failure-ack-result.v1", r);
            if let Some(old) = &self.ack {
                assert_eq!(*old, v);
            }
            self.ack = Some(v.clone());
            return bytes(&v);
        }
        if op == "--read-native-live-failure-retirement-v1" {
            return self
                .retired
                .as_ref()
                .ok_or("retirement missing".into())
                .and_then(bytes);
        }
        assert_eq!(op, "--retire-native-live-failure-storage-v1");
        let r = crate::native_operation::failure::protocol::retirement(
            &self.f,
            &self.e,
            &json!({}),
            self.ack.as_ref().unwrap(),
            &a[15],
        )
        .unwrap();
        let hsha = self.ack.as_ref().unwrap()["receipt"]["host_receipt_sha256"].clone();
        let mut r = r;
        r["authority"]["host_receipt_sha256"] = hsha;
        let v = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":r["source_sha"],"job_id":r["job_id"],"worker_generation":r["worker_generation"],"profile":"native-v1","retirer_generation":r["retirer_generation"],"retirement_intent_sha256":sha(&bytes(&r).unwrap()),"storage_receipt_sha256":r["storage_receipt_sha256"],"archive_sha256":r["archive_sha256"],"partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":null});
        self.retired = Some(v.clone());
        bytes(&v)
    }
}

#[test]
fn signed_live_failure_keeps_unknown_usage_and_exact_private_custody_through_cleanup() {
    let f = fixture();
    let mut m = Mock::new(&f);
    flow::download(&f.j, &f.i, &f.f, "failure-download", &mut m).unwrap();
    let h = parse(&f.j.read(f.i.job(), &row(&f.i, RECEIPT)).unwrap()).unwrap();
    assert_eq!(h["file"]["mode"], 0o600);
    flow::acknowledge(&f.j, &f.i, &f.f, "failure-ack", &mut m).unwrap();
    let result = flow::retire(
        &f.j,
        &f.i,
        &f.f,
        "failure-retire",
        Some(&"a".repeat(64)),
        &mut m,
    )
    .unwrap();
    assert_eq!(result["controller_failure_authenticated"], true);
    assert_eq!(result["outer_completion_available"], false);
    assert!(result["model_requests"].is_null() && result["exit_code"].is_null());
    assert!(
        f.j.absent(f.i.job(), "completion").unwrap() && f.j.absent(f.i.job(), "return").unwrap()
    );
    assert_eq!(m.streams, 1);
    let before = m.calls.len();
    flow::retire(&f.j, &f.i, &f.f, "failure-retire-read", None, &mut m).unwrap();
    assert_eq!(m.calls.len(), before);
}
#[test]
fn signed_live_failure_rehash_cannot_supply_usage_private_keys_or_substitute_original_records() {
    let f = fixture();
    for field in ["exit_code", "model_requests", "observation_sha256"] {
        let (raw, e) = encode(&f.f, f.files.clone(), |v| {
            v[field] = if field == "observation_sha256" {
                json!("0".repeat(64))
            } else {
                json!(0)
            }
        });
        assert!(archive(&f.j, &f.i, &f.f, &e, &raw).is_err(), "{field}");
    }
    for name in [
        "private/controller-seed.json",
        "worker/running.json",
        "sdk/004.stdout",
    ] {
        let mut files = f.files.clone();
        files.insert(name.into(), b"{}".to_vec());
        let (raw, e) = encode(&f.f, files, |_| {});
        assert!(archive(&f.j, &f.i, &f.f, &e, &raw).is_err(), "{name}");
    }
    let mut o = f.f["observation"].clone();
    o["model_requests"] = json!(0);
    assert!(observed(&f.j, &f.i, context_without_observation(&f.f), &o).is_err());
    o = f.f["observation"].clone();
    o["signed_envelope_utf8"] = json!(text(&o, "signed_envelope_utf8")
        .unwrap()
        .replace("SDK agent failed", "SDK was replaced"));
    o["signed_envelope_sha256"] = json!(sha(text(&o, "signed_envelope_utf8").unwrap().as_bytes()));
    assert!(observed(&f.j, &f.i, context_without_observation(&f.f), &o).is_err());
    for pin in [
        "repair_sha256",
        "created_repair_sha256",
        "live_prepared_sha256",
        "original_worker_generation",
    ] {
        let mut changed = f.f.clone();
        changed[pin] = json!("0".repeat(64));
        let mut m = Mock::new(&f);
        assert!(
            flow::download(&f.j, &f.i, &changed, "failure-download", &mut m).is_err(),
            "{pin}"
        );
        assert!(m.calls.is_empty());
    }
}
#[test]
fn live_failure_resumes_original_export_and_reseals_fourth_complete_file_without_streaming() {
    let f = fixture();
    let mut m = Mock::new(&f);
    f.j.write(
        f.i.job(),
        &row(&f.i, DOWNLOAD),
        &marker(&f.f, "download", &export_intent(&f.f)).unwrap(),
    )
    .unwrap();
    assert!(flow::download(&f.j, &f.i, &f.f, "failure-download-read", &mut m).is_err());
    assert_eq!(m.streams, 0);
    flow::download(&f.j, &f.i, &f.f, "failure-download-resume", &mut m).unwrap();
    assert_eq!(m.streams, 1);
    let f = fixture();
    let mut m = Mock::new(&f);
    m.root = true;
    f.j.write(
        f.i.job(),
        &row(&f.i, DOWNLOAD),
        &marker(&f.f, "download", &export_intent(&f.f)).unwrap(),
    )
    .unwrap();
    for n in 1..=4 {
        f.j.write(f.i.job(),&row(&f.i,&format!("readonly-failure-download-attempt-{n:04}")),&bytes(&json!({"schema":"hol-gauntlet-host-native-live-failure-attempt.v1","failure_intent_sha256":sha(&bytes(&f.f).unwrap()),"attempt":n,"operation":"failure-download-resume"})).unwrap()).unwrap();
        let mut held = artifact::create_private_archive(&f.j, archive_name_for(&f.i, n)).unwrap();
        held.file
            .write_all(if n == 4 { &f.raw } else { b"partial" })
            .unwrap();
        held.file.sync_all().unwrap();
    }
    f.j.write(f.i.job(), &row(&f.i, EXPORT), &bytes(&f.e).unwrap())
        .unwrap();
    flow::download(&f.j, &f.i, &f.f, "failure-download-read", &mut m).unwrap();
    assert_eq!(m.streams, 0);
    assert!(!f.j.absent(f.i.job(), &row(&f.i, RECEIPT)).unwrap());
    let path = f.j.path.join(archive_name_for(&f.i, 4));
    let mut tampered = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    tampered.write_all(b"x").unwrap();
    tampered.sync_all().unwrap();
    let before = m.calls.len();
    assert!(flow::acknowledge(&f.j, &f.i, &f.f, "failure-ack-resume", &mut m).is_err());
    assert_eq!(m.calls.len(), before);
}

#[test]
fn live_failure_ack_and_retirement_resume_only_the_committed_original_authority() {
    let f = fixture();
    let mut m = Mock::new(&f);
    flow::download(&f.j, &f.i, &f.f, "failure-download", &mut m).unwrap();
    let h = parse(&f.j.read(f.i.job(), &row(&f.i, RECEIPT)).unwrap()).unwrap();
    let binding =
        json!({"export":f.e["receipt_sha256"],"host_receipt_sha256":sha(&bytes(&h).unwrap())});
    f.j.write(
        f.i.job(),
        &row(&f.i, AD),
        &marker(&f.f, "ack", &binding).unwrap(),
    )
    .unwrap();
    assert!(flow::acknowledge(&f.j, &f.i, &f.f, "failure-ack-read", &mut m).is_err());
    assert!(m.ack.is_none());
    flow::acknowledge(&f.j, &f.i, &f.f, "failure-ack-resume", &mut m).unwrap();
    assert_eq!(
        m.calls
            .iter()
            .filter(|s| s.as_str() == "--ack-native-live-failure-v1")
            .count(),
        1
    );
    let request = json!({"schema":"hol-gauntlet-host-native-live-failure-retirement-request.v1","failure_intent_sha256":sha(&bytes(&f.f).unwrap()),"retirer_generation":"b".repeat(64)});
    f.j.write(f.i.job(), &row(&f.i, REQUEST), &bytes(&request).unwrap())
        .unwrap();
    let before = m.calls.len();
    assert!(flow::retire(&f.j, &f.i, &f.f, "failure-retire-read", None, &mut m).is_err());
    assert_eq!(m.calls.len(), before);
    flow::retire(&f.j, &f.i, &f.f, "failure-retire-resume", None, &mut m).unwrap();
    assert_eq!(
        m.calls
            .iter()
            .filter(|s| s.as_str() == "--retire-native-live-failure-storage-v1")
            .count(),
        1
    );
    let retirement = parse(&f.j.read(f.i.job(), &row(&f.i, RETIRE)).unwrap()).unwrap();
    assert_eq!(retirement["retirer_generation"], "b".repeat(64));
    assert_eq!(
        retirement["authority"]["signed_envelope_sha256"],
        f.f["signed_envelope_sha256"]
    );
    assert_eq!(
        retirement["authority"]["created_repair_sha256"],
        f.f["created_repair_sha256"]
    );
    assert_eq!(
        retirement["authority"]["repair_sha256"],
        f.f["repair_sha256"]
    );
    assert!(f.j.absent(f.i.job(), "completion").unwrap());
}
