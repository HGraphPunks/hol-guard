use super::super::public_export::tests::archive;
use super::*;
use std::{collections::BTreeMap, fs, io::Write};
struct Fixture {
    _temp: tempfile::TempDir,
    j: Journal,
    i: Intent,
    f: Value,
    archive: Vec<u8>,
    export: Value,
}
fn wrapper(schema: &str, receipt: Value) -> Value {
    json!({"schema":schema,"receipt_sha256":sha(&bytes(&receipt).unwrap()),"receipt":receipt})
}
fn fixture() -> Fixture {
    let source = "2".repeat(40);
    let job = "1".repeat(16);
    let worker = "4".repeat(64);
    let formatter = "a".repeat(64);
    let storage =
        super::super::job_storage_fixture(&source, &job, &worker, &formatter, "native-v1");
    let root = format!("/var/lib/hol-gauntlet-rust/native-jobs/{job}");
    let workspace = json!({"source":format!("{root}/workspace"),"destination":"/runtime/home/project","custody_root":root,"device":storage["receipt"]["root_directory"]["device"],"inode":52,"mode":448});
    let p = json!({"schema":"hol-gauntlet-cell-preparation.v2","control_profile":"python-readonly.v1","runtime_prefix":format!("/opt/hol-gauntlet/candidates/{source}/prefix"),"runtime_tree_digest":"e".repeat(64),"image_id":format!("sha256:{}","f".repeat(64)),"task_mounts":{"workspace":workspace},"launch":{"image_interpreter_sha256":"9".repeat(64),"outside_observer_sha256":"a".repeat(64)}});
    let d = json!({"schema":"hol-gauntlet-native-worker-job.v8","profile":"native-host-pinned-readonly-hook-v1","source_sha":source,"job_id":job,"worker_generation":worker,"preparation_sha256":sha(&bytes(&p).unwrap()),"guard":{"source_sha":source}});
    let (temp, expected, _, mut frame) = crate::native_control_readback::tests::fixture_with_pins(
        "readonly-utility",
        &sha(&bytes(&d).unwrap()),
        &sha(&bytes(&p).unwrap()),
    );
    let path = temp.path().canonicalize().unwrap();
    let j = Journal::open(&path).unwrap();
    let mut i = super::super::tests::intent(&job, &path);
    i.0["role"] = json!("readonly-utility");
    i.0["deployment_digest"] = json!(expected.deployment_digest);
    i.0["preparation_sha256"] = json!(sha(&bytes(&p).unwrap()));
    let initial = json!({"schema":"hol-gauntlet-host-native-initialization-intent.v2","job_id":job,"source_sha":source,"worker_generation":worker,"vm":i.0["vm"],"limactl":i.0["limactl"],"lima_sha256":i.0["lima_sha256"],"transport_context":i.0["transport_context"],"mke2fs_sha256":formatter});
    let mut w = workspace;
    w["uid"] = json!(10001);
    w["gid"] = json!(10001);
    let initial_receipt = json!({"schema":"hol-gauntlet-native-job-initialization.v2","job_id":job,"source_sha":source,"worker_generation":worker,"job_directory":storage["receipt"]["root_directory"],"workspace":w,"storage":storage,"job_dispatched":false,"candidate_executed":false,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,"guard_causality_verified":false,"model_requests":0});
    let initial_result = wrapper(
        "hol-gauntlet-native-job-initialization-result.v2",
        initial_receipt.clone(),
    );
    let bundle = json!({"schema":"hol-gauntlet-native-host-pinned-preparation-input.v1","declaration":d,"preparation":p});
    let prep_receipt = json!({"schema":"hol-gauntlet-native-host-pinned-preparation.v2","source_sha":source,"job_id":job,"deployment_digest":i.0["deployment_digest"],"worker_generation":worker,"preparation_sha256":i.0["preparation_sha256"],"bundle_sha256":sha(&bytes(&bundle).unwrap()),"initialization_sha256":initial_result["receipt_sha256"],"storage_receipt_sha256":storage["receipt_sha256"],"control_role":"readonly-utility","runtime_tree_sha256":"e".repeat(64),"sdk_publication_sha256":null,"job_dispatched":false,"candidate_executed":false,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,"guard_causality_verified":false,"model_requests":0});
    for (s, v) in [
        ("intent", i.0.clone()),
        ("initialize-intent", initial.clone()),
        (
            "initialize-dispatch",
            json!({"schema":"hol-gauntlet-host-native-initialization-dispatch.v1","job_id":job,"initialization_intent_sha256":sha(&bytes(&initial).unwrap()),"retry_allowed":false}),
        ),
        ("initialize-result", initial_result.clone()),
        ("prepare-bundle", bundle.clone()),
        (
            "prepare-dispatch",
            json!({"schema":"hol-gauntlet-host-native-preparation-dispatch.v1","job_id":job,"intent_sha256":i.digest().unwrap(),"bundle_sha256":sha(&bytes(&bundle).unwrap()),"bundle_bytes":bytes(&bundle).unwrap().len(),"initialization_sha256":initial_result["receipt_sha256"]}),
        ),
        (
            "prepare-result",
            wrapper(
                "hol-gauntlet-native-host-pinned-preparation-result.v2",
                prep_receipt,
            ),
        ),
    ] {
        let mut v = v;
        if s == "prepare-dispatch" {
            v["retry_allowed"] = json!(false);
        }
        j.write(&job, s, &bytes(&v).unwrap()).unwrap();
    }
    j.write(&job, "dispatch", &Journal::dispatch_raw(&i).unwrap())
        .unwrap();
    let stderr = b"product management pipe exited before ready marker\n";
    for (k, v) in [
        ("retained_storage", storage),
        ("exit_code", json!(2)),
        ("execution_error", Value::Null),
        ("interruption", Value::Null),
        ("controller_envelope_utf8", json!("")),
        ("controller_report", Value::Null),
        ("controller_stdout_sha256", json!(sha(b""))),
        ("controller_stderr_sha256", json!(sha(stderr))),
        ("controller_signature_verification", Value::Null),
        (
            "controller_signature_error",
            json!("bounded native controller envelope required"),
        ),
    ] {
        frame["report"][k] = v;
    }
    frame["terminal"]["exit_code"] = json!(2);
    crate::native_control_readback::tests::refresh(&mut frame);
    j.write(&job, "return", &bytes(&frame).unwrap()).unwrap();
    let f = protocol::original(&j, &i, &"b".repeat(64)).unwrap();
    j.write(&job, INTENT, &bytes(&f).unwrap()).unwrap();
    let mut files = BTreeMap::new();
    for n in protocol::MEMBERS
        .into_iter()
        .filter(|n| *n != "results.sha256.json")
    {
        files.insert(n.to_owned(), b"{}\n".to_vec());
    }
    for (n, k) in [
        ("worker/started.json", "started"),
        ("worker/controller-key.json", "controller_key_pin"),
        ("worker/terminal.json", "terminal"),
        ("worker/report.json", "report"),
    ] {
        files.insert(n.into(), bytes(&frame[k]).unwrap());
    }
    files.insert("worker/running.json".into(),bytes(&json!({"schema":"hol-gauntlet-worker-running.v1","source_sha":source,"job_id":job,"deployment_digest":i.0["deployment_digest"],"worker_generation":worker,"started_marker_sha256":f["prelaunch"]["started_marker_sha256"],"pid":241,"process_start_ticks":32,"cgroup":"/system.slice/owned"})).unwrap());
    files.insert("native.stdout".into(), Vec::new());
    files.insert("native.stderr".into(), stderr.to_vec());
    files.insert("preparation.json".into(), bytes(&p).unwrap());
    files.insert(
        "initialization.json".into(),
        bytes(&initial_receipt).unwrap(),
    );
    files.insert("declaration.json".into(), bytes(&d).unwrap());
    files.insert(
        "cell/native-rootfs.v1.json".into(),
        bytes(&json!({"idmap_runtime":"ubuntu2404-controller-v1"})).unwrap(),
    );
    let mut events = Vec::new();
    let mut prev = "0".repeat(64);
    let failures = json!(["historical cleanup observation failed"]);
    for (n, (kind, data)) in [
        ("prepared", json!({"profile":"hol-product-cell-fixture"})),
        ("image-interpreter-pinned", json!({})),
        ("private-parent-mount-namespace", json!({})),
        (
            "startup-failure",
            json!({"error":"product management pipe exited before ready marker"}),
        ),
        ("cell-stderr", json!({"bytes":49})),
        ("process-events-closed", json!({"available":false,"error":"required process recorder was not established","schema":"hol-gauntlet-native-process-recorder.v1"})),
        ("native-pipe-owner-terminal", json!({"available":false,"error":"Native pipe owner was not established","execution_eligible":false})),
        (
            "terminal-cleanup",
            json!({"cgroup_absent":true,"rootfs_mount_absent":true,"failures":failures}),
        ),
        (
            "rust-image-cleanup",
            json!({"image_mount_absent":true,"active_lease_removed":true}),
        ),
        ("terminal-cleanup", json!({"cgroup_absent":true,"rootfs_mount_absent":true,"failures":["historical unit stop refusal"]})),
        ("rust-image-cleanup", json!({"image_mount_absent":true,"active_lease_removed":true})),
    ]
    .into_iter()
    .enumerate()
    {
        let raw=bytes(&json!({"schema":"hol-gauntlet-cell-event.v1","sequence":n,"previous_sha256":prev,"kind":kind,"data":data})).unwrap();
        prev = sha(&raw);
        events.extend_from_slice(&raw);
        events.push(b'\n');
    }
    files.insert("cell/native-supervisor-events.v1.jsonl".into(), events);
    let q = json!({"image_events_sha256":sha(&files["cell/native-image-events.v1.jsonl"]),"supervisor_events_sha256":sha(&files["cell/native-supervisor-events.v1.jsonl"]),"rootfs_declaration_sha256":sha(&files["cell/native-rootfs.v1.json"]),"supervisor_declaration_sha256":sha(&files["cell/native-supervisor.v1.json"]),"profile":"hol-product-cell-fixture","product_cgroup_absent":true,"product_slice_absent":true,"rootfs_mount_absent":true,"apparmor_profile_absent":true,"runtime_tree_digest":p["runtime_tree_digest"],"image_id":p["image_id"],"startup_error":"product management pipe exited before ready marker","recorded_cleanup_failures":[failures,["historical unit stop refusal"]],"idmap_runtime":"ubuntu2404-controller-v1","product_unit_absent":true});
    let pins = files
        .iter()
        .map(|(n, b)| (n.clone(), json!({"bytes":b.len(),"sha256":sha(b)})))
        .collect::<serde_json::Map<_, _>>();
    let metadata=files.iter().enumerate().map(|(k,(n,b))| {let mode=if n=="cell/native-cell.apparmor" {0o400} else if n.starts_with("cell/")&&!n.ends_with(".jsonl") {0o444} else {0o600}; (n.clone(),json!({"device":1,"inode":k+100,"uid":0,"gid":0,"mode":mode,"links":1,"bytes":b.len(),"mtime":1,"mtime_nsec":0,"ctime":1,"ctime_nsec":0}))}).collect::<serde_json::Map<_,_>>();
    let mut manifest = protocol::base(&f, "hol-gauntlet-native-readonly-failure-evidence.v1");
    for (k, v) in [
        ("status", json!("controller-failed-before-report")),
        ("exit_code", json!(2)),
        ("controller", frame["report"]["controller"].clone()),
        ("prelaunch", f["prelaunch"].clone()),
        ("host_pin_sha256", f["host_pin_sha256"].clone()),
        ("quiescent", q),
        ("files", Value::Object(pins)),
        ("filesystem", Value::Object(metadata)),
        ("execution_eligible", json!(false)),
        ("guard_causality_verified", json!(false)),
        ("model_requests", Value::Null),
        ("qualification_eligible", json!(false)),
    ] {
        manifest[k] = v;
    }
    let manifest = bytes(&manifest).unwrap();
    let mut e = protocol::base(&f, "hol-gauntlet-native-readonly-failure-export.v1");
    e["manifest_sha256"] = json!(sha(&manifest));
    files.insert("results.sha256.json".into(), manifest);
    let raw = archive(&files);
    for (k, v) in [
        ("archive_sha256", json!(sha(&raw))),
        ("archive_bytes", json!(raw.len())),
        ("exit_code", json!(2)),
        ("execution_eligible", json!(false)),
        ("qualification_eligible", json!(false)),
    ] {
        e[k] = v;
    }
    let e = wrapper("hol-gauntlet-native-readonly-failure-export-result.v1", e);
    protocol::archive(&j, &i, &f, &e, &raw).unwrap();
    Fixture {
        _temp: temp,
        j,
        i,
        f,
        archive: raw,
        export: e,
    }
}
#[derive(Default)]
struct Mock {
    f: Value,
    raw: Vec<u8>,
    e: Value,
    path: std::path::PathBuf,
    root: bool,
    ack: Option<Value>,
    retired: Option<Value>,
    calls: Vec<String>,
    exports: usize,
    acknowledgements: usize,
    retirements: usize,
    lose_export: bool,
    lose_ack: bool,
    lose_retire: bool,
}
impl Mock {
    fn new(f: &Fixture) -> Self {
        Self {
            f: f.f.clone(),
            raw: f.archive.clone(),
            e: f.export.clone(),
            path: f.j.path.clone(),
            ..Self::default()
        }
    }
}
impl Rpc for Mock {
    fn call(
        &mut self,
        a: &[String],
        input: &[u8],
        output: Option<&mut File>,
    ) -> Result<Vec<u8>, String> {
        let op = a[1].as_str();
        self.calls.push(op.into());
        assert_eq!(
            &a[2..11],
            &protocol::BASE.map(|k| text(&self.f, k).unwrap().to_owned())
        );
        if matches!(
            op,
            "--export-native-readonly-failure-v1"
                | "--resume-native-readonly-failure-v1"
                | "--read-native-readonly-failure-v1"
        ) {
            if op == "--read-native-readonly-failure-v1" {
                assert!(input.is_empty());
                if !self.root {
                    return Err("missing Root intent".into());
                }
            } else {
                assert_eq!(input, bytes(&self.f["prelaunch"]).unwrap());
                assert_eq!(a[11], input.len().to_string());
                if op == "--export-native-readonly-failure-v1" && self.root {
                    return Err("consumed".into());
                }
                self.root = true;
                self.exports += 1;
            }
            let file = output.unwrap();
            if std::mem::take(&mut self.lose_export) {
                file.write_all(&self.raw[..1024]).unwrap();
                return Err("lost export".into());
            }
            file.write_all(&self.raw).unwrap();
            return Ok(Vec::new());
        }
        assert!(input.is_empty() && output.is_none());
        if op == "--read-native-readonly-failure-export-v1" {
            if !self.root {
                return Err("missing Root intent".into());
            }
            return bytes(
                &json!({"schema":"hol-gauntlet-native-readonly-failure-export-state.v1","intent_sha256":sha(&bytes(&protocol::export_intent(&self.f)).unwrap()),"export":self.e,"export_complete":true,"retry_allowed":false}),
            );
        }
        if op == "--read-native-readonly-failure-ack-v1" {
            return self
                .ack
                .as_ref()
                .ok_or("missing ACK".into())
                .and_then(bytes);
        }
        if op == "--ack-native-readonly-failure-v1" {
            assert_eq!(a[11], self.e["receipt_sha256"].as_str().unwrap());
            let mut r = self.e["receipt"].clone();
            r["schema"] = json!("hol-gauntlet-native-readonly-failure-ack.v1");
            r["export_receipt_sha256"] = json!(a[11]);
            r["host_receipt_sha256"] = json!(a[12]);
            let ack = wrapper("hol-gauntlet-native-readonly-failure-ack-result.v1", r);
            if let Some(old) = &self.ack {
                assert_eq!(*old, ack);
            } else {
                self.ack = Some(ack.clone());
                self.acknowledgements += 1;
            }
            if std::mem::take(&mut self.lose_ack) {
                return Err("lost ACK reply".into());
            }
            return bytes(&ack);
        }
        if op == "--read-native-readonly-failure-retirement-v1" {
            return self
                .retired
                .as_ref()
                .ok_or("partial retirement".into())
                .and_then(bytes);
        }
        assert_eq!(op, "--retire-native-readonly-failure-storage-v1");
        let h = parse(
            &fs::read(
                self.path
                    .join(Journal::name(text(&self.f, "job_id").unwrap(), RECEIPT).unwrap()),
            )
            .unwrap(),
        )
        .unwrap();
        let r =
            protocol::retirement(&self.f, &self.e, &h, self.ack.as_ref().unwrap(), &a[13]).unwrap();
        let result = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":r["source_sha"],"job_id":r["job_id"],"worker_generation":r["worker_generation"],"profile":"native-v1","retirer_generation":r["retirer_generation"],"retirement_intent_sha256":sha(&bytes(&r).unwrap()),"storage_receipt_sha256":r["storage_receipt_sha256"],"archive_sha256":r["archive_sha256"],"partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":null});
        if let Some(old) = &self.retired {
            assert_eq!(*old, result);
        } else {
            self.retired = Some(result.clone());
            self.retirements += 1;
        }
        if std::mem::take(&mut self.lose_retire) {
            return Err("lost after teardown".into());
        }
        bytes(&result)
    }
}
fn downloaded() -> (Fixture, Mock) {
    let f = fixture();
    let mut m = Mock::new(&f);
    download(&f.j, &f.i, &f.f, "failure-download", &mut m).unwrap();
    (f, m)
}
#[test]
fn unsigned_readonly_failure_keeps_actual_history_private_and_never_becomes_completion() {
    let (f, mut m) = downloaded();
    assert!(f
        .j
        .verify(&f.i, &f.j.read(f.i.job(), "return").unwrap())
        .is_err());
    assert!(f.j.absent(f.i.job(), "completion").unwrap());
    assert!(f.j.require_idle().is_err());
    acknowledge(&f.j, &f.i, &f.f, "failure-ack", &mut m).unwrap();
    let out = retire(
        &f.j,
        &f.i,
        &f.f,
        "failure-retire",
        Some(&"c".repeat(64)),
        &mut m,
    )
    .unwrap();
    assert!(out["model_requests"].is_null());
    assert_eq!(out["controller_authenticated"], false);
    assert_eq!(out["storage_retired"], true);
    assert_eq!(out["qualification_eligible"], false);
    assert!(!out.to_string().contains(
        f.f["prelaunch"]["controller_public_key_hex"]
            .as_str()
            .unwrap()
    ));
    assert_eq!((m.exports, m.acknowledgements, m.retirements), (1, 1, 1));
    verify_idle(&f.j, &f.i).unwrap();
    assert!(f.j.require_idle().is_ok());
}
#[test]
fn explicit_resumes_close_pre_rpc_gaps_without_rearming_work_and_reads_never_publish() {
    let f = fixture();
    let mut m = Mock::new(&f);
    f.j.write(
        f.i.job(),
        DOWNLOAD,
        &marker(&f.f, "download", &protocol::export_intent(&f.f)).unwrap(),
    )
    .unwrap();
    assert!(m.calls.is_empty());
    assert!(download(&f.j, &f.i, &f.f, "failure-download-read", &mut m).is_err());
    assert_eq!(m.exports, 0);
    download(&f.j, &f.i, &f.f, "failure-download-resume", &mut m).unwrap();
    let (e, h, _) = custody(&f.j, &f.i, &f.f).unwrap();
    f.j.write(
        f.i.job(),
        AD,
        &marker(
            &f.f,
            "ack",
            &json!({"export":e["receipt_sha256"],"host_receipt_sha256":sha(&bytes(&h).unwrap())}),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(acknowledge(&f.j, &f.i, &f.f, "failure-ack-read", &mut m).is_err());
    assert_eq!(m.acknowledgements, 0);
    acknowledge(&f.j, &f.i, &f.f, "failure-ack-resume", &mut m).unwrap();
    f.j.write(f.i.job(),REQUEST,&bytes(&json!({"schema":"hol-gauntlet-host-native-readonly-failure-retirement-request.v1","failure_intent_sha256":sha(&bytes(&f.f).unwrap()),"retirer_generation":"c".repeat(64)})).unwrap()).unwrap();
    assert!(retire(&f.j, &f.i, &f.f, "failure-retire-read", None, &mut m).is_err());
    assert_eq!(m.retirements, 0);
    retire(&f.j, &f.i, &f.f, "failure-retire-resume", None, &mut m).unwrap();
    let calls = m.calls.len();
    retire(&f.j, &f.i, &f.f, "failure-retire-read", None, &mut m).unwrap();
    assert_eq!(m.calls.len(), calls);
    assert_eq!(m.retirements, 1);
}
#[test]
fn lost_replies_preserve_partial_bytes_and_reconcile_identical_ack_and_retirement() {
    let f = fixture();
    let mut m = Mock::new(&f);
    m.lose_export = true;
    assert!(download(&f.j, &f.i, &f.f, "failure-download", &mut m).is_err());
    let first = f.j.path.join(archive_name(f.i.job(), 1));
    assert_eq!(fs::metadata(&first).unwrap().len(), 1024);
    download(&f.j, &f.i, &f.f, "failure-download-read", &mut m).unwrap();
    assert_eq!(fs::metadata(first).unwrap().len(), 1024);
    m.lose_ack = true;
    assert!(acknowledge(&f.j, &f.i, &f.f, "failure-ack", &mut m).is_err());
    acknowledge(&f.j, &f.i, &f.f, "failure-ack-resume", &mut m).unwrap();
    assert_eq!(m.acknowledgements, 1);
    m.lose_retire = true;
    assert!(retire(
        &f.j,
        &f.i,
        &f.f,
        "failure-retire",
        Some(&"c".repeat(64)),
        &mut m
    )
    .is_err());
    retire(&f.j, &f.i, &f.f, "failure-retire-read", None, &mut m).unwrap();
    assert_eq!(m.retirements, 1);
}
#[test]
fn synthetic_exit_bad_ack_changed_original_or_archive_refuse_before_mutating_root() {
    for (pointer, value) in [
        ("/report/exit_code", json!(-1)),
        ("/report/execution_error", json!("unknown")),
        ("/report/interruption", json!("signal")),
        ("/report/controller_envelope_utf8", json!("{}")),
        (
            "/report/prelaunch_custody/acknowledgement_sha256",
            json!("0".repeat(64)),
        ),
    ] {
        let f = fixture();
        let mut v = parse(&f.j.read(f.i.job(), "return").unwrap()).unwrap();
        *v.pointer_mut(pointer).unwrap() = value;
        if pointer == "/report/exit_code" {
            v["terminal"]["exit_code"] = json!(-1);
        }
        crate::native_control_readback::tests::refresh(&mut v);
        fs::write(
            f.j.path.join(Journal::name(f.i.job(), "return").unwrap()),
            bytes(&v).unwrap(),
        )
        .unwrap();
        assert!(
            protocol::original(&f.j, &f.i, &"b".repeat(64)).is_err(),
            "{pointer}"
        );
    }
    let (f, mut m) = downloaded();
    let calls = m.calls.len();
    let h = parse(&f.j.read(f.i.job(), RECEIPT).unwrap()).unwrap();
    let path = f.j.path.join(text(&h["file"], "name").unwrap());
    let mut raw = f.archive.clone();
    raw[700] ^= 1;
    fs::write(path, raw).unwrap();
    assert!(acknowledge(&f.j, &f.i, &f.f, "failure-ack", &mut m).is_err());
    assert_eq!(m.calls.len(), calls);
}
#[path = "native_failed_recovery_tests.rs"]
mod recovery;
