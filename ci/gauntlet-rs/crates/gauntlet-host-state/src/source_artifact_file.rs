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
pub(super) fn absent(j: &Journal, job: &str, attempt: u64) -> Result<bool, String> {
    j.stable()?;
    match statat(
        &j.root,
        filename(job, attempt)?.as_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
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
    let name = filename(job, attempt)?;
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
    let name = filename(job, attempt)?;
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
