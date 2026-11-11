//! Mocked Root replies plus real temporary private file descriptors only.
use super::*;
use std::{fs, io::Write, os::unix::fs::PermissionsExt};
fn fixture() -> (tempfile::TempDir, Journal, Value, Fake) {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file("inert.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"inert source artifact").unwrap();
    let payload = writer.finish().unwrap().into_inner();
    let archive = sha(&payload);
    let (temp, source, flow_dir, result) =
        super::super::bounded::tests::artifact_fixture(&archive, payload.len());
    let path = temp
        .path()
        .canonicalize()
        .unwrap()
        .join("private-artifacts");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let job = text(&source["intent"], "job_id").unwrap();
    let flow = super::super::bounded::flow(&flow_dir, &source, job, &result, &archive).unwrap();
    let i=parse(&bytes(&json!({"schema":"hol-gauntlet-host-source-artifact-intent.v1","job_id":job,"kind":"candidate","source":source,"flow":flow,"result_sha256":result,"archive_sha256":archive,"exporter_generation":"f".repeat(64),"execution_eligible":false,"qualification_eligible":false})).unwrap()).unwrap();
    let mut j = Journal::open(&path).unwrap();
    j.lock().unwrap();
    j.write(text(&i, "job_id").unwrap(), INTENT, &bytes(&i).unwrap())
        .unwrap();
    let fake = Fake {
        i: i.clone(),
        payload,
        initial: 0,
        reads: 0,
        controls: 0,
        partial: false,
        exported: false,
        ack: None,
        retired: None,
        forged_retirement: false,
        retirement_intent: None,
        interrupt_retirement: false,
    };
    (temp, j, i, fake)
}
struct Fake {
    i: Value,
    payload: Vec<u8>,
    initial: usize,
    reads: usize,
    controls: usize,
    partial: bool,
    exported: bool,
    ack: Option<Value>,
    retired: Option<Value>,
    forged_retirement: bool,
    retirement_intent: Option<Value>,
    interrupt_retirement: bool,
}
impl Fake {
    fn export(&self) -> Value {
        let mut receipt = protocol::pins(&self.i);
        receipt["schema"] = json!("hol-gauntlet-source-artifact-export.v1");
        receipt["artifact_read_sha256"] = json!("a".repeat(64));
        receipt["archive_bytes"] = json!(self.payload.len());
        let mut intent = receipt.clone();
        intent.as_object_mut().unwrap().remove("archive_bytes");
        intent["schema"] = json!("hol-gauntlet-source-artifact-export-intent.v1");
        json!({"schema":"hol-gauntlet-source-artifact-export-state.v1","status":"complete","intent_sha256":sha(&bytes(&intent).unwrap()),"receipt":receipt,"receipt_sha256":sha(&bytes(&receipt).unwrap())})
    }
}
fn frame(v: &Value) -> Vec<u8> {
    let mut raw = bytes(v).unwrap();
    raw.push(b'\n');
    raw
}
impl Rpc for Fake {
    fn archive(&mut self, args: &[String], file: &mut File) -> Result<usize, String> {
        assert_eq!(args.len(), 11);
        match args[1].as_str() {
            "--export-source-job-artifact-v1" => {
                assert_eq!(self.initial, 0);
                self.initial += 1;
                self.exported = true;
            }
            "--read-source-job-artifact-v1" => {
                assert!(self.exported);
                self.reads += 1;
            }
            _ => panic!("unexpected archive selector"),
        }
        if self.partial {
            self.partial = false;
            file.write_all(&self.payload[..8]).unwrap();
            return Err("lost encrypted stream".into());
        }
        file.write_all(&self.payload).unwrap();
        Ok(self.payload.len())
    }
    fn control(&mut self, args: &[String]) -> Result<Vec<u8>, String> {
        self.controls += 1;
        let value = match args[1].as_str() {
            "--read-source-job-artifact-export-v1" => {
                assert!(self.exported);
                self.export()
            }
            "--ack-source-job-artifact-v1" => {
                assert_eq!(args.len(), 13);
                let e = self.export();
                assert_eq!(args[11], text(&e, "receipt_sha256").unwrap());
                let r = protocol::ack_body(&self.i, &e, &args[12]);
                let value = json!({"schema":"hol-gauntlet-source-artifact-ack-result.v1","receipt":r,"receipt_sha256":sha(&bytes(&r).unwrap())});
                self.ack = Some(value.clone());
                value
            }
            "--read-source-job-artifact-ack-v1" => self.ack.clone().ok_or("missing Root ack")?,
            "--retire-source-job-storage-v1" => {
                assert_eq!(args.len(), 13);
                let ack = self.ack.as_ref().ok_or("missing Root ack")?;
                assert_eq!(ack["receipt"]["host_receipt_sha256"], args[12]);
                let intent =
                    protocol::retirement_intent(&self.i, &self.export(), ack, &args[12], &args[11]);
                if let Some(old) = &self.retirement_intent {
                    assert_eq!(
                        old, &intent,
                        "partial cleanup cannot adopt another authority"
                    );
                } else {
                    self.retirement_intent = Some(intent.clone());
                }
                if self.interrupt_retirement {
                    self.interrupt_retirement = false;
                    return Err("interrupted after original volume unmount".into());
                }
                let s = &self.i["source"]["intent"];
                let r = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":s["source_sha"],"job_id":self.i["job_id"],"worker_generation":s["worker_generation"],"profile":s["storage_profile"],"retirer_generation":args[11],"retirement_intent_sha256":sha(&bytes(&intent).unwrap()),"storage_receipt_sha256":self.i["source"]["storage_receipt_sha256"],"archive_sha256":self.i["archive_sha256"],"partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":null});
                self.retired = Some(r.clone());
                let mut r = r;
                if self.forged_retirement {
                    r["retirement_intent_sha256"] = json!("0".repeat(64));
                }
                r
            }
            "--read-source-job-storage-retirement-v1" => {
                self.retired.clone().ok_or("missing Root retirement")?
            }
            _ => panic!("unexpected control selector"),
        };
        Ok(frame(&value))
    }
}
#[test]
fn actual_private_zip_receipt_precedes_ack_and_independently_bound_retirement() {
    let (_temp, j, i, mut rpc) = fixture();
    let downloaded = download(&j, &i, false, &mut rpc).unwrap();
    assert_eq!(downloaded["state"], "downloaded");
    let receipt = value(&j, &i, RECEIPT).unwrap();
    let path = j.path.join(text(&receipt["file"], "name").unwrap());
    assert_eq!(fs::read(&path).unwrap(), rpc.payload);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let actual = sha(&bytes(&receipt).unwrap());
    assert_eq!(downloaded["host_receipt_sha256"], actual);
    acknowledge(&j, &i, false, &mut rpc).unwrap();
    assert_eq!(
        rpc.ack.as_ref().unwrap()["receipt"]["host_receipt_sha256"],
        actual
    );
    retire(&j, &i, Some(&"e".repeat(64)), &mut rpc).unwrap();
    retire(&j, &i, None, &mut rpc).unwrap();
    assert_eq!(rpc.initial, 1);
    assert_eq!(rpc.reads, 0);
    assert!(download(&j, &i, false, &mut rpc).is_err());
}
#[test]
fn partial_stream_is_preserved_and_explicit_read_uses_new_one_use_file() {
    let (_temp, j, i, mut rpc) = fixture();
    rpc.partial = true;
    assert!(download(&j, &i, false, &mut rpc).is_err());
    let job = text(&i, "job_id").unwrap();
    let partial = j.path.join(format!("{job}.source-artifact-0001.zip"));
    assert_eq!(fs::read(&partial).unwrap(), rpc.payload[..8]);
    assert!(j.absent(job, RECEIPT).unwrap());
    download(&j, &i, true, &mut rpc).unwrap();
    assert_eq!(fs::read(&partial).unwrap(), rpc.payload[..8]);
    assert_eq!(rpc.initial, 1);
    assert_eq!(rpc.reads, 1);
    assert!(text(&value(&j, &i, RECEIPT).unwrap()["file"], "name")
        .unwrap()
        .ends_with("0002.zip"));
}
#[test]
fn complete_local_file_with_lost_metadata_reconciles_without_any_zip_replay() {
    let (_temp, j, i, mut rpc) = fixture();
    struct Lost<'a>(&'a mut Fake);
    impl Rpc for Lost<'_> {
        fn archive(&mut self, a: &[String], f: &mut File) -> Result<usize, String> {
            self.0.archive(a, f)
        }
        fn control(&mut self, _: &[String]) -> Result<Vec<u8>, String> {
            Err("lost metadata reply".into())
        }
    }
    assert!(download(&j, &i, false, &mut Lost(&mut rpc)).is_err());
    assert!(j.absent(text(&i, "job_id").unwrap(), RECEIPT).unwrap());
    download(&j, &i, true, &mut rpc).unwrap();
    assert_eq!(rpc.initial, 1);
    assert_eq!(rpc.reads, 0);
    assert!(text(&value(&j, &i, RECEIPT).unwrap()["file"], "name")
        .unwrap()
        .ends_with("0001.zip"));
}
#[test]
fn changed_missing_linked_or_public_archive_refuses_ack_before_root_contact() {
    for kind in ["bytes", "missing", "hardlink", "mode"] {
        let (_temp, j, i, mut rpc) = fixture();
        download(&j, &i, false, &mut rpc).unwrap();
        let receipt = value(&j, &i, RECEIPT).unwrap();
        let path = j.path.join(text(&receipt["file"], "name").unwrap());
        match kind {
            "bytes" => fs::write(&path, b"substitution").unwrap(),
            "missing" => fs::remove_file(&path).unwrap(),
            "hardlink" => fs::hard_link(&path, j.path.join("linked.zip")).unwrap(),
            _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
        }
        let before = rpc.controls;
        assert!(acknowledge(&j, &i, false, &mut rpc).is_err(), "{kind}");
        assert_eq!(rpc.controls, before);
        assert!(j.absent(text(&i, "job_id").unwrap(), ACK_DISPATCH).unwrap());
    }
}
#[test]
fn missing_actual_receipt_and_naked_caller_hash_cannot_authorize_ack() {
    let (_temp, j, i, mut rpc) = fixture();
    assert!(acknowledge(&j, &i, false, &mut rpc).is_err());
    assert_eq!(rpc.controls, 0);
    assert!(run_source_artifact_command(&[
        "ack".into(),
        j.path.to_str().unwrap().into(),
        text(&i, "job_id").unwrap().into(),
        sha(&bytes(&i).unwrap()),
        "a".repeat(64)
    ])
    .is_err());
}
#[test]
fn uncertain_retirement_only_reconciles_original_intent_and_rechecks_local_bytes() {
    let (_temp, j, i, mut rpc) = fixture();
    download(&j, &i, false, &mut rpc).unwrap();
    acknowledge(&j, &i, false, &mut rpc).unwrap();
    rpc.forged_retirement = true;
    assert!(retire(&j, &i, Some(&"e".repeat(64)), &mut rpc).is_err());
    assert!(j.absent(text(&i, "job_id").unwrap(), RETIRED).unwrap());
    retire(&j, &i, None, &mut rpc).unwrap();
    let r = value(&j, &i, RECEIPT).unwrap();
    fs::write(
        j.path.join(text(&r["file"], "name").unwrap()),
        b"lost retained bytes",
    )
    .unwrap();
    let before = rpc.controls;
    assert!(retire(&j, &i, None, &mut rpc).is_err());
    assert_eq!(rpc.controls, before);
}
#[test]
fn partial_retirement_resumes_original_cleanup_without_new_dispatch_or_workload() {
    let (_temp, j, i, mut rpc) = fixture();
    download(&j, &i, false, &mut rpc).unwrap();
    acknowledge(&j, &i, false, &mut rpc).unwrap();
    let job = text(&i, "job_id").unwrap();
    assert!(retire_operation(&j, &i, None, true, &mut rpc).is_err());
    rpc.interrupt_retirement = true;
    assert!(retire(&j, &i, Some(&"e".repeat(64)), &mut rpc).is_err());
    let original = j.read(job, RETIRE).unwrap();
    let consumed = j.read(job, RETIRE_DISPATCH).unwrap();
    assert!(rpc.retirement_intent.is_some() && rpc.retired.is_none());
    assert!(retire(&j, &i, None, &mut rpc).is_err());
    let before = rpc.controls;
    assert!(retire(&j, &i, Some(&"f".repeat(64)), &mut rpc).is_err());
    assert_eq!(rpc.controls, before);
    retire_operation(&j, &i, None, true, &mut rpc).unwrap();
    assert_eq!(j.read(job, RETIRE).unwrap(), original);
    assert_eq!(j.read(job, RETIRE_DISPATCH).unwrap(), consumed);
    assert_eq!((rpc.initial, rpc.reads), (1, 0));
    assert!(value(&j, &i, RETIRED).unwrap()["model_requests"].is_null());
    retire(&j, &i, None, &mut rpc).unwrap();
    let receipt = value(&j, &i, RECEIPT).unwrap();
    fs::write(
        j.path.join(text(&receipt["file"], "name").unwrap()),
        b"changed retained archive",
    )
    .unwrap();
    let before = rpc.controls;
    assert!(retire_operation(&j, &i, None, true, &mut rpc).is_err());
    assert_eq!(rpc.controls, before);
}
