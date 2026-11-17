//! Explicit recovery of the original immutable Source ZIP export. A resume may
//! create only Root's missing one-use export intent; it never retries a workload.
use super::{
    bytes, exported, file, marker, observe_export, sha, stable, summary, text, Journal, Rpc,
    DOWNLOAD, RECEIPT,
};
use serde_json::{json, Value};

#[derive(Clone, Copy)]
enum Mode {
    Initial,
    Read,
    Resume,
}
pub(super) fn download(
    j: &Journal,
    i: &Value,
    read: bool,
    rpc: &mut impl Rpc,
) -> Result<Value, String> {
    run(j, i, if read { Mode::Read } else { Mode::Initial }, rpc)
}
pub(super) fn resume(j: &Journal, i: &Value, rpc: &mut impl Rpc) -> Result<Value, String> {
    run(j, i, Mode::Resume, rpc)
}
fn seal(j: &Journal, i: &Value, export: &Value, h: &mut file::Held) -> Result<Value, String> {
    h.finish(j, text(i, "archive_sha256")?)?;
    if h.facts["bytes"] != export["receipt"]["archive_bytes"] {
        return Err("actual Host file length differs from Root export".into());
    }
    stable(j, i)?;
    let receipt = file::receipt(j, i, export, h)?;
    j.write(text(i, "job_id")?, RECEIPT, &bytes(&receipt)?)?;
    h.verify(j, text(i, "archive_sha256")?)?;
    Ok(receipt)
}
fn run(j: &Journal, i: &Value, mode: Mode, rpc: &mut impl Rpc) -> Result<Value, String> {
    stable(j, i)?;
    let job = text(i, "job_id")?;
    let read = matches!(mode, Mode::Read);
    if matches!(mode, Mode::Initial) {
        if !j.absent(job, DOWNLOAD)? || !j.absent(job, RECEIPT)? {
            return Err(
                "Source download already consumed; use explicit download-read or download-resume"
                    .into(),
            );
        }
        for n in 1..=4 {
            if !file::absent(j, job, n)? {
                return Err("orphan archive file blocks initial download".into());
            }
        }
        super::super::idle(j)?;
        j.write(job, DOWNLOAD, &marker(i, "download")?)?;
    } else if j.read(job, DOWNLOAD)? != marker(i, "download")? {
        return Err("original consumed Source download required".into());
    }
    if !j.absent(job, RECEIPT)? {
        let e = exported(j, i)?;
        file::retained(j, i, &e)?;
        return summary(j, i, "downloaded");
    }
    if !matches!(mode, Mode::Initial) {
        // Reconcile complete held bytes before spending another bounded attempt.
        // An absent or changed Root intent cannot supply the original export.
        for n in 1..=4 {
            if !file::absent(j, job, n)? {
                let mut h = file::open_attempt(j, job, n)?;
                if h.verify(j, text(i, "archive_sha256")?).is_ok() {
                    let e = observe_export(j, i, rpc)?;
                    seal(j, i, &e, &mut h)?;
                    return summary(j, i, "downloaded");
                }
            }
        }
    }
    let attempt = (1..=4)
        .find(|n| file::absent(j, job, *n).unwrap_or(false))
        .ok_or("Source download attempts exhausted; preserve all private evidence")?;
    let mut h = file::create(j, job, attempt)?;
    j.write(job,&format!("source-artifact-attempt-{attempt:04}"),&bytes(&json!({"schema":"hol-gauntlet-host-source-artifact-attempt.v1","intent_sha256":sha(&bytes(i)?),"attempt":attempt,"read_only":read,"file":h.name}))?)?;
    stable(j, i)?;
    // Resume deliberately uses the original export selector and generation.
    // Its Root O_EXCL write refuses every existing/partial intent. There is no
    // automatic fallback from a read or from an uncertain transport response.
    rpc.archive(
        &super::protocol::export_args(
            i,
            if read {
                "--read-source-job-artifact-v1"
            } else {
                "--export-source-job-artifact-v1"
            },
        )?,
        &mut h.file,
    )?;
    h.finish(j, text(i, "archive_sha256")?)?;
    stable(j, i)?;
    let e = observe_export(j, i, rpc)?;
    seal(j, i, &e, &mut h)?;
    summary(j, i, "downloaded")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixture, Fake};
    use super::super::{acknowledge, value, INTENT};
    use super::*;
    use std::{fs, fs::File, os::unix::fs::PermissionsExt};

    struct BeforeRoot;
    impl Rpc for BeforeRoot {
        fn control(&mut self, _: &[String]) -> Result<Vec<u8>, String> {
            panic!("no Root control call follows a missing pinned executable")
        }
        fn archive(&mut self, _: &[String], _: &mut File) -> Result<usize, String> {
            Err("pinned Root executable absent; no Root request launched".into())
        }
    }
    struct LostMetadata<'a>(&'a mut Fake);
    impl Rpc for LostMetadata<'_> {
        fn archive(&mut self, a: &[String], f: &mut File) -> Result<usize, String> {
            self.0.archive(a, f)
        }
        fn control(&mut self, _: &[String]) -> Result<Vec<u8>, String> {
            Err("lost metadata reply".into())
        }
    }
    #[test]
    fn explicit_resume_closes_pre_rpc_loss_using_only_original_consumed_export() {
        let (_temp, j, i, mut rpc) = fixture();
        let job = text(&i, "job_id").unwrap();
        let original = j.read(job, INTENT).unwrap();
        assert!(download(&j, &i, false, &mut BeforeRoot).is_err());
        let consumed = j.read(job, DOWNLOAD).unwrap();
        assert_eq!(consumed, marker(&i, "download").unwrap());
        assert_eq!((rpc.initial, rpc.reads, rpc.controls), (0, 0, 0));
        assert!(download(&j, &i, false, &mut rpc).is_err());
        assert!(download(&j, &i, true, &mut rpc).is_err());
        assert!(!rpc.exported);
        resume(&j, &i, &mut rpc).unwrap();
        assert_eq!((rpc.initial, rpc.reads), (1, 0));
        assert_eq!(j.read(job, INTENT).unwrap(), original);
        assert_eq!(j.read(job, DOWNLOAD).unwrap(), consumed);
        for n in [1, 2] {
            let h = file::open_attempt(&j, job, n).unwrap();
            assert_eq!(h.facts["bytes"], 0);
        }
        let receipt = value(&j, &i, RECEIPT).unwrap();
        assert!(text(&receipt["file"], "name")
            .unwrap()
            .ends_with("0003.zip"));
        assert_eq!(
            fs::read(j.path.join(text(&receipt["file"], "name").unwrap())).unwrap(),
            rpc.payload
        );
        acknowledge(&j, &i, false, &mut rpc).unwrap();
    }
    #[test]
    fn existing_root_intent_is_never_recreated_by_resume_and_read_recovers_it() {
        let (_temp, j, i, mut rpc) = fixture();
        rpc.partial = true;
        assert!(download(&j, &i, false, &mut rpc).is_err());
        let job = text(&i, "job_id").unwrap();
        let first = file::open_attempt(&j, job, 1).unwrap().name;
        assert_eq!(fs::read(j.path.join(&first)).unwrap(), rpc.payload[..8]);
        assert!(resume(&j, &i, &mut rpc).is_err());
        assert_eq!((rpc.initial, rpc.reads), (1, 0));
        assert_eq!(file::open_attempt(&j, job, 2).unwrap().facts["bytes"], 0);
        download(&j, &i, true, &mut rpc).unwrap();
        assert_eq!((rpc.initial, rpc.reads), (1, 1));
        assert_eq!(fs::read(j.path.join(first)).unwrap(), rpc.payload[..8]);
        assert!(text(&value(&j, &i, RECEIPT).unwrap()["file"], "name")
            .unwrap()
            .ends_with("0003.zip"));
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
        assert_eq!((rpc.initial, rpc.reads), (1, 1));
        assert!(text(&value(&j, &i, RECEIPT).unwrap()["file"], "name")
            .unwrap()
            .ends_with("0002.zip"));
    }
    #[test]
    fn complete_local_file_with_lost_metadata_reconciles_without_any_zip_replay() {
        for resumed in [false, true] {
            let (_temp, j, i, mut rpc) = fixture();
            assert!(download(&j, &i, false, &mut LostMetadata(&mut rpc)).is_err());
            assert!(j.absent(text(&i, "job_id").unwrap(), RECEIPT).unwrap());
            if resumed {
                resume(&j, &i, &mut rpc)
            } else {
                download(&j, &i, true, &mut rpc)
            }
            .unwrap();
            assert_eq!((rpc.initial, rpc.reads), (1, 0));
            assert!(text(&value(&j, &i, RECEIPT).unwrap()["file"], "name")
                .unwrap()
                .ends_with("0001.zip"));
        }
    }
    #[test]
    fn fourth_complete_file_can_be_resealed_without_streaming_and_tampering_refuses() {
        for tampered in [false, true] {
            let (_temp, j, i, mut rpc) = fixture();
            for attempt in 1..=3 {
                rpc.partial = true;
                assert!(download(&j, &i, attempt != 1, &mut rpc).is_err());
            }
            assert!(download(&j, &i, true, &mut LostMetadata(&mut rpc)).is_err());
            let job = text(&i, "job_id").unwrap();
            assert!(j.absent(job, RECEIPT).unwrap());
            let name = file::open_attempt(&j, job, 4).unwrap().name;
            if tampered {
                fs::write(j.path.join(&name), b"substituted archive").unwrap();
            }
            let streams = (rpc.initial, rpc.reads);
            let controls = rpc.controls;
            let result = resume(&j, &i, &mut rpc);
            assert_eq!((rpc.initial, rpc.reads), streams);
            if tampered {
                assert!(result.is_err());
                assert_eq!(rpc.controls, controls);
                assert!(j.absent(job, RECEIPT).unwrap());
            } else {
                result.unwrap();
                assert_eq!(value(&j, &i, RECEIPT).unwrap()["file"]["name"], name);
            }
            for attempt in 1..=3 {
                let h = file::open_attempt(&j, job, attempt).unwrap();
                assert_eq!(fs::read(j.path.join(h.name)).unwrap(), rpc.payload[..8]);
            }
        }
    }
    #[test]
    fn resumed_export_refuses_changed_original_authority_before_root_contact() {
        for kind in [
            "missing-dispatch",
            "partial-dispatch",
            "intent",
            "source",
            "flow",
            "custody",
        ] {
            let (_temp, j, mut i, mut rpc) = fixture();
            let job = text(&i, "job_id").unwrap().to_string();
            if kind != "missing-dispatch" {
                j.write(
                    &job,
                    DOWNLOAD,
                    if kind == "partial-dispatch" {
                        b"{".to_vec()
                    } else {
                        marker(&i, "download").unwrap()
                    }
                    .as_slice(),
                )
                .unwrap();
            }
            match kind {
                "intent" => {
                    fs::write(j.path.join(Journal::name(&job, INTENT).unwrap()), b"{}").unwrap()
                }
                "source" => i["source"]["intent"]["source_sha"] = json!("0".repeat(40)),
                "flow" => i["flow"]["host_binding_sha256"] = json!("0".repeat(64)),
                "custody" => {
                    fs::set_permissions(&j.path, fs::Permissions::from_mode(0o755)).unwrap()
                }
                _ => {}
            }
            assert!(resume(&j, &i, &mut rpc).is_err(), "{kind}");
            assert_eq!((rpc.initial, rpc.reads, rpc.controls), (0, 0, 0));
        }
    }
    #[test]
    fn initial_read_and_resume_share_four_preserved_attempts() {
        let (_temp, j, i, mut rpc) = fixture();
        assert!(download(&j, &i, false, &mut BeforeRoot).is_err());
        for _ in 0..3 {
            assert!(download(&j, &i, true, &mut rpc).is_err());
        }
        assert!(resume(&j, &i, &mut rpc).is_err());
        assert_eq!((rpc.initial, rpc.reads, rpc.controls), (0, 0, 0));
        let job = text(&i, "job_id").unwrap();
        for n in 1..=4 {
            assert_eq!(file::open_attempt(&j, job, n).unwrap().facts["bytes"], 0);
            assert!(!j
                .absent(job, &format!("source-artifact-attempt-{n:04}"))
                .unwrap());
        }
        assert!(j.absent(job, RECEIPT).unwrap());
    }
}
