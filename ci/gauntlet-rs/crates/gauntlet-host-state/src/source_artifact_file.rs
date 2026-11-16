//! Actual private-file custody, independent of Root's export claims.
use super::{bytes, context, hex, sha, text, Journal};
use crate::private_jobs::same_file;
use rustix::fs::{fchmod, fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};
pub(super) const LIMIT: usize = 256 * 1024 * 1024;
pub(super) struct Held {
    pub file: File,
    pub name: String,
    pub facts: Value,
}
fn filename(job: &str, attempt: u64) -> Result<String, String> {
    if !hex(job, 16) || !(1..=4).contains(&attempt) {
        return Err("bounded one-use archive attempt required".into());
    }
    Ok(format!("{job}.source-artifact-{attempt:04}.zip"))
}
fn failure_name(job: &str, attempt: u64) -> Result<String, String> {
    filename(job, attempt)?;
    Ok(format!("{job}.failed-build-evidence-{attempt:04}.tar"))
}
pub(super) fn absent(j: &Journal, job: &str, attempt: u64) -> Result<bool, String> {
    absent_named(j, &filename(job, attempt)?)
}
pub(super) fn failure_absent(j: &Journal, job: &str, attempt: u64) -> Result<bool, String> {
    absent_named(j, &failure_name(job, attempt)?)
}
fn absent_named(j: &Journal, name: &str) -> Result<bool, String> {
    j.stable()?;
    match statat(&j.root, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(true),
        Ok(_) => Ok(false),
        Err(_) => Err("private artifact file existence uncertain".into()),
    }
}
fn facts(j: &Journal, name: &str, file: &File) -> Result<Value, String> {
    j.stable()?;
    let s = fstat(file).map_err(|_| "artifact descriptor unavailable")?;
    let named = statat(&j.root, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "artifact name unavailable")?;
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != j.owner
        || s.st_mode & 0o7777 != 0o600
        || s.st_nlink != 1
        || s.st_size < 0
        || s.st_size as u64 > LIMIT as u64
        || !same_file(&s, &named)
    {
        return Err("actual private single-link0600 artifact custody required".into());
    }
    Ok(
        json!({"name":name,"device":s.st_dev,"inode":s.st_ino,"uid":s.st_uid,"gid":s.st_gid,"mode":s.st_mode&0o7777,"links":s.st_nlink,"bytes":s.st_size,
        "mtime":s.st_mtime,"mtime_nsec":s.st_mtime_nsec,"ctime":s.st_ctime,"ctime_nsec":s.st_ctime_nsec}),
    )
}
pub(super) fn create(j: &Journal, job: &str, attempt: u64) -> Result<Held, String> {
    create_named(j, filename(job, attempt)?)
}
pub(super) fn create_failure(j: &Journal, job: &str, attempt: u64) -> Result<Held, String> {
    create_named(j, failure_name(job, attempt)?)
}
fn create_named(j: &Journal, name: String) -> Result<Held, String> {
    j.stable()?;
    let fd = openat(
        &j.root,
        name.as_str(),
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "artifact file already consumed or unavailable")?;
    fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|_| "private artifact mode commit uncertain")?;
    let file = File::from(fd);
    file.sync_all()
        .map_err(|_| "artifact file commit uncertain")?;
    fsync(&j.root).map_err(|_| "artifact name commit uncertain")?;
    let facts = facts(j, &name, &file)?;
    Ok(Held { file, name, facts })
}
pub(super) fn open_attempt(j: &Journal, job: &str, attempt: u64) -> Result<Held, String> {
    open_named(j, filename(job, attempt)?)
}
pub(super) fn open_failure(j: &Journal, job: &str, attempt: u64) -> Result<Held, String> {
    open_named(j, failure_name(job, attempt)?)
}
fn open_named(j: &Journal, name: String) -> Result<Held, String> {
    let fd = openat(
        &j.root,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "original private artifact unavailable")?;
    let file = File::from(fd);
    let facts = facts(j, &name, &file)?;
    Ok(Held { file, name, facts })
}
impl Held {
    pub fn finish(&mut self, j: &Journal, expected: &str) -> Result<(), String> {
        self.file
            .sync_all()
            .map_err(|_| "private artifact data sync uncertain")?;
        fsync(&j.root).map_err(|_| "private artifact directory sync uncertain")?;
        self.facts = facts(j, &self.name, &self.file)?;
        self.verify(j, expected)
    }
    pub fn verify(&mut self, j: &Journal, expected: &str) -> Result<(), String> {
        if !hex(expected, 64)
            || self.facts["bytes"].as_u64().is_none_or(|n| n == 0)
            || facts(j, &self.name, &self.file)? != self.facts
        {
            return Err("private artifact facts changed or incomplete".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "artifact seek unavailable")?;
        let mut hash = Sha256::new();
        let mut count = 0usize;
        let mut chunk = [0u8; 65536];
        loop {
            let n = self
                .file
                .read(&mut chunk)
                .map_err(|_| "artifact descriptor read failed")?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(n)
                .filter(|n| *n <= LIMIT)
                .ok_or("artifact byte bound exceeded")?;
            hash.update(&chunk[..n]);
        }
        if format!("{:x}", hash.finalize()) != expected
            || self.facts["bytes"] != count
            || facts(j, &self.name, &self.file)? != self.facts
        {
            return Err("actual retained archive bytes/hash or identity differs".into());
        }
        j.stable()
    }
}
pub(super) fn receipt(j: &Journal, i: &Value, export: &Value, h: &Held) -> Result<Value, String> {
    Ok(
        json!({"schema":"hol-gauntlet-host-source-artifact-receipt.v1","intent_sha256":sha(&bytes(i)?),"job_id":i["job_id"],"source_sha":i["source"]["intent"]["source_sha"],"kind":i["kind"],
        "storage_receipt_sha256":i["source"]["storage_receipt_sha256"],"archive_sha256":i["archive_sha256"],"archive_bytes":export["receipt"]["archive_bytes"],
        "export_binding_sha256":export["receipt_sha256"],"parent_custody":context::snapshot(&j.path)?,"file":h.facts}),
    )
}
pub(super) fn retained(
    j: &Journal,
    i: &Value,
    export: &Value,
) -> Result<(Held, Value, String), String> {
    let raw = j.read(text(i, "job_id")?, "source-artifact-host-receipt")?;
    let r: Value =
        serde_json::from_slice(&raw).map_err(|_| "actual Host artifact receipt JSON invalid")?;
    if bytes(&r)? != raw || r["parent_custody"] != context::snapshot(&j.path)? {
        return Err("actual Host artifact receipt or parent custody changed".into());
    }
    let name = text(&r["file"], "name")?;
    let prefix = format!("{}.source-artifact-", text(i, "job_id")?);
    let attempt = name
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix(".zip"))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or("closed retained artifact name required")?;
    let mut h = open_attempt(j, text(i, "job_id")?, attempt)?;
    h.verify(j, text(i, "archive_sha256")?)?;
    if r != receipt(j, i, export, &h)? || r["archive_bytes"] != h.facts["bytes"] {
        return Err("actual-file receipt differs from original Root export/Host intent".into());
    }
    let digest = sha(&raw);
    Ok((h, r, digest))
}

pub(super) const FAILURE_LIMIT: usize = 32 * 1024 * 1024 + 65536;
pub(super) fn verify_failure(
    j: &Journal,
    i: &Value,
    e: &Value,
    h: &mut Held,
) -> Result<(), String> {
    let r = &e["receipt"];
    h.verify(j, text(r, "archive_sha256")?)?;
    if h.facts["bytes"] != r["archive_bytes"] {
        return Err("failure archive byte count differs".into());
    }
    h.file
        .seek(SeekFrom::Start(0))
        .map_err(|_| "failure archive seek failed")?;
    let mut raw = Vec::new();
    Read::by_ref(&mut h.file)
        .take(FAILURE_LIMIT as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "failure archive read failed")?;
    if raw.len() > FAILURE_LIMIT {
        return Err("failure archive exceeds fixed log budget".into());
    }
    let members = crate::native_diagnostic_archive::members(&raw)
        .map_err(|_| "closed regular failure USTAR required")?;
    let names = [
        "candidate-run.stderr.log",
        "candidate-run.stdout.log",
        "results.sha256.json",
    ];
    if members.keys().map(String::as_str).collect::<Vec<_>>() != names {
        return Err("failure archive has unknown or missing members".into());
    }
    let mut tar = tar::Archive::new(std::io::Cursor::new(&raw));
    for (entry, name) in tar
        .entries()
        .map_err(|_| "failure USTAR entries unavailable")?
        .zip(names)
    {
        if entry
            .map_err(|_| "failure USTAR entry invalid")?
            .path_bytes()
            .as_ref()
            != name.as_bytes()
        {
            return Err("failure archive order differs".into());
        }
    }
    let manifest = &members["results.sha256.json"];
    let m: Value = serde_json::from_slice(manifest).map_err(|_| "failure manifest JSON invalid")?;
    if manifest.len() > 32768 || bytes(&m)? != *manifest || sha(manifest) != r["manifest_sha256"] {
        return Err("canonical failure manifest differs from Root export".into());
    }
    let mut files = serde_json::Map::new();
    for (name, pin) in [(names[0], "stderr_sha256"), (names[1], "stdout_sha256")] {
        let data = &members[name];
        let meta = &m["filesystem"][name];
        if data.len() > 16 * 1024 * 1024
            || sha(data) != i["flow"][pin]
            || meta.as_object().is_none_or(|o| o.len() != 11)
            || meta["device"].as_u64().is_none()
            || meta["inode"].as_u64().is_none_or(|n| n == 0)
            || meta["uid"] != 0
            || meta["gid"] != 0
            || meta["mode"] != 384
            || meta["links"] != 1
            || meta["bytes"] != data.len()
            || ["mtime", "ctime"]
                .iter()
                .any(|k| meta[*k].as_i64().is_none())
            || ["mtime_nsec", "ctime_nsec"]
                .iter()
                .any(|k| meta[*k].as_u64().is_none_or(|n| n >= 1_000_000_000))
        {
            return Err("failure log bytes or original Root metadata differ".into());
        }
        files.insert(name.into(), json!({"bytes":data.len(),"sha256":sha(data)}));
    }
    let mut expected = super::protocol::failure_pins(i);
    expected["schema"] = json!("hol-gauntlet-failed-build-evidence.v1");
    for key in [
        "status",
        "exit_code",
        "original_runner_generation",
        "original_result_reader_generation",
        "client_pid",
        "client_start_ticks",
    ] {
        expected[key] = i["flow"][key].clone();
    }
    expected["files"] = Value::Object(files);
    expected["filesystem"] = m["filesystem"].clone();
    expected["execution_eligible"] = json!(false);
    expected["guard_causality_verified"] = json!(false);
    expected["qualification_eligible"] = json!(false);
    expected["model_requests"] = Value::Null;
    if m != expected || m["filesystem"].as_object().is_none_or(|o| o.len() != 2) {
        return Err("sanitized failure manifest differs from original failed terminal".into());
    }
    h.verify(j, text(r, "archive_sha256")?)
}
pub(super) fn failure_receipt(
    j: &Journal,
    i: &Value,
    e: &Value,
    h: &Held,
) -> Result<Value, String> {
    let mut r = super::protocol::failure_pins(i);
    r["schema"] = json!("hol-gauntlet-host-failed-build-file-receipt.v1");
    r["intent_sha256"] = json!(sha(&bytes(i)?));
    for k in [
        "archive_sha256",
        "archive_bytes",
        "manifest_sha256",
        "exit_code",
    ] {
        r[k] = e["receipt"][k].clone();
    }
    r["export_receipt_sha256"] = e["receipt_sha256"].clone();
    r["parent_custody"] = context::snapshot(&j.path)?;
    r["file"] = h.facts.clone();
    r["model_requests"] = Value::Null;
    r["execution_eligible"] = json!(false);
    r["qualification_eligible"] = json!(false);
    Ok(r)
}
pub(super) fn retained_failure(
    j: &Journal,
    i: &Value,
    e: &Value,
) -> Result<(Held, String), String> {
    let raw = j.read(text(i, "job_id")?, "failed-build-host-receipt")?;
    let r: Value = serde_json::from_slice(&raw).map_err(|_| "failure Host receipt invalid")?;
    let attempt = text(&r["file"], "name")?
        .strip_prefix(&format!("{}.failed-build-evidence-", text(i, "job_id")?))
        .and_then(|s| s.strip_suffix(".tar"))
        .and_then(|s| s.parse().ok())
        .ok_or("fixed failure archive name required")?;
    let mut h = open_failure(j, text(i, "job_id")?, attempt)?;
    verify_failure(j, i, e, &mut h)?;
    if bytes(&r)? != raw || r != failure_receipt(j, i, e, &h)? {
        return Err("failure Host receipt or actual private file changed".into());
    }
    Ok((h, sha(&raw)))
}
pub(super) fn seal_failure(j: &Journal, i: &Value, e: &Value, h: &mut Held) -> Result<(), String> {
    h.finish(j, text(&e["receipt"], "archive_sha256")?)?;
    verify_failure(j, i, e, h)?;
    super::failure::stable(j, i)?;
    j.retain(
        text(i, "job_id")?,
        super::failure::RECEIPT,
        &bytes(&failure_receipt(j, i, e, h)?)?,
    )?;
    verify_failure(j, i, e, h)
}

#[cfg(test)]
mod failure_tests {
    use super::super::{failure, tests::failure_fixture, value};
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn failed_build_actual_private_logs_ack_and_partial_retirement_resume_keep_original_authority()
    {
        let (_temp, j, i, mut rpc) = failure_fixture("");
        let job = text(&i, "job_id").unwrap();
        assert!(failure::acknowledge(&j, &i, "failure-ack", &mut rpc).is_err());
        assert_eq!(rpc.calls, 0);
        rpc.partial = true;
        assert!(failure::download(&j, &i, "failure-download", &mut rpc).is_err());
        let partial = j.path.join(format!("{job}.failed-build-evidence-0001.tar"));
        assert_eq!(fs::read(&partial).unwrap(), rpc.payload[..8]);
        assert!(j.absent(job, failure::RECEIPT).unwrap());
        assert!(super::super::super::idle(&j).is_err());
        let before = rpc.calls;
        assert!(failure::download(&j, &i, "failure-download", &mut rpc).is_err());
        assert_eq!(rpc.calls, before);
        let downloaded = failure::download(&j, &i, "failure-download-read", &mut rpc).unwrap();
        assert!(downloaded["model_requests"].is_null());
        assert_eq!(downloaded["exit_code"], 101);
        assert_eq!(downloaded["artifact_admitted"], false);
        assert!(!downloaded.to_string().contains(j.path.to_str().unwrap()));
        let r = value(&j, &i, failure::RECEIPT).unwrap();
        let path = j.path.join(text(&r["file"], "name").unwrap());
        assert_eq!(fs::read(&path).unwrap(), rpc.payload);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(fs::read(&partial).unwrap(), rpc.payload[..8]);
        assert_eq!((rpc.initial, rpc.reads), (1, 1));
        failure::acknowledge(&j, &i, "failure-ack", &mut rpc).unwrap();
        failure::acknowledge(&j, &i, "failure-ack-read", &mut rpc).unwrap();
        rpc.interrupt = true;
        assert!(
            failure::retire(&j, &i, "failure-retire", Some(&"e".repeat(64)), &mut rpc).is_err()
        );
        let intent = j.read(job, "failed-build-retirement-intent").unwrap();
        let dispatch = j.read(job, "failed-build-retirement-dispatch").unwrap();
        assert!(super::super::super::idle(&j).is_err());
        assert!(failure::retire(&j, &i, "failure-retire-read", None, &mut rpc).is_err());
        let before = rpc.calls;
        assert!(
            failure::retire(&j, &i, "failure-retire", Some(&"d".repeat(64)), &mut rpc).is_err()
        );
        assert_eq!(rpc.calls, before);
        let retired = failure::retire(&j, &i, "failure-retire-resume", None, &mut rpc).unwrap();
        assert!(retired["model_requests"].is_null());
        assert_eq!(retired["exit_code"], 101);
        assert_eq!(
            j.read(job, "failed-build-retirement-intent").unwrap(),
            intent
        );
        assert_eq!(
            j.read(job, "failed-build-retirement-dispatch").unwrap(),
            dispatch
        );
        failure::retire(&j, &i, "failure-retire-read", None, &mut rpc).unwrap();
        assert!(super::super::super::idle(&j).is_ok());
        fs::write(&path, b"changed retained logs").unwrap();
        let before = rpc.calls;
        assert!(failure::retire(&j, &i, "failure-retire-read", None, &mut rpc).is_err());
        assert_eq!(rpc.calls, before);
    }

    #[test]
    fn rehashed_failure_archive_cannot_add_private_authority_zero_usage_or_substitute_logs() {
        for variant in ["nonce", "usage", "log", "member"] {
            let (_temp, j, i, mut rpc) = failure_fixture(variant);
            assert!(
                failure::download(&j, &i, "failure-download", &mut rpc).is_err(),
                "{variant}"
            );
            assert!(j
                .absent(text(&i, "job_id").unwrap(), failure::RECEIPT)
                .unwrap());
            let before = rpc.calls;
            assert!(failure::acknowledge(&j, &i, "failure-ack", &mut rpc).is_err());
            assert_eq!(rpc.calls, before);
        }
    }

    #[test]
    fn lost_failure_metadata_reuses_complete_host_file_and_private_file_tampering_blocks_ack() {
        let (_temp, j, i, mut rpc) = failure_fixture("");
        let job = text(&i, "job_id").unwrap();
        j.write(
            job,
            failure::DOWNLOAD,
            &super::super::protocol::failure_marker(&i, "download").unwrap(),
        )
        .unwrap();
        assert_eq!(rpc.calls, 0);
        let resumed = failure::download(&j, &i, "failure-download-resume", &mut rpc).unwrap();
        assert_eq!(resumed["status"], "build-failed");
        assert!(resumed["model_requests"].is_null());
        assert_eq!((rpc.initial, rpc.reads), (1, 0));
        let (_temp, j, i, mut rpc) = failure_fixture("");
        struct Lost<'a>(&'a mut super::super::tests::FailureFake);
        impl failure::Rpc for Lost<'_> {
            fn archive(
                &mut self,
                a: &[String],
                input: &[u8],
                f: &mut File,
            ) -> Result<usize, String> {
                failure::Rpc::archive(self.0, a, input, f)
            }
            fn control(&mut self, _: &[String]) -> Result<Vec<u8>, String> {
                Err("lost metadata".into())
            }
        }
        assert!(failure::download(&j, &i, "failure-download", &mut Lost(&mut rpc)).is_err());
        failure::download(&j, &i, "failure-download-read", &mut rpc).unwrap();
        assert_eq!((rpc.initial, rpc.reads), (1, 0));
        let job = text(&i, "job_id").unwrap();
        let marker = super::super::protocol::failure_marker(&i, "ack").unwrap();
        j.write(job, "failed-build-ack-dispatch", &marker).unwrap();
        let before = rpc.calls;
        assert!(failure::acknowledge(&j, &i, "failure-ack-read", &mut rpc).is_err());
        assert_eq!(rpc.calls, before + 1);
        failure::acknowledge(&j, &i, "failure-ack-resume", &mut rpc).unwrap();
        assert_eq!(rpc.calls, before + 2);
        assert_eq!(j.read(job, "failed-build-ack-dispatch").unwrap(), marker);
        let before = rpc.calls;
        failure::acknowledge(&j, &i, "failure-ack-resume", &mut rpc).unwrap();
        assert_eq!(rpc.calls, before);
        let r = value(&j, &i, failure::RECEIPT).unwrap();
        let path = j.path.join(text(&r["file"], "name").unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let before = rpc.calls;
        assert!(failure::acknowledge(&j, &i, "failure-ack", &mut rpc).is_err());
        assert_eq!(rpc.calls, before);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, j.path.join("linked.tar")).unwrap();
        assert!(failure::acknowledge(&j, &i, "failure-ack", &mut rpc).is_err());
        assert_eq!(rpc.calls, before);
    }
}
