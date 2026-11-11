//! Bounded deterministic USTAR and descriptor-relative public-file custody.
//! Capture callers choose fixed names; archive names never select host paths.
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    os::fd::OwnedFd,
};

pub(crate) const MAX_ARCHIVE: usize = 128 * 1024 * 1024;
const MAX_FILE: usize = 32 * 1024 * 1024;
const MAX_MEMBERS: usize = 2048;

pub(crate) fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn name(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 255
        && raw.split('/').all(|part| {
            !part.is_empty()
                && !matches!(part, "." | "..")
                && part.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')
        })
}

#[derive(Default, PartialEq, Eq)]
pub(crate) struct PublicFiles {
    pub files: BTreeMap<String, Vec<u8>>,
    pub metadata: BTreeMap<String, Value>,
    total: usize,
}
impl PublicFiles {
    pub fn insert(&mut self, member: &str, raw: Vec<u8>) -> Result<(), String> {
        if !name(member)
            || member == "results.sha256.json"
            || raw.len() > MAX_FILE
            || self.files.len() >= MAX_MEMBERS - 1
            || self.files.contains_key(member)
            || raw.len() > MAX_ARCHIVE.saturating_sub(self.total)
        {
            return Err("public Native export member or byte bound differs".into());
        }
        self.total += raw.len();
        self.files.insert(member.into(), raw);
        Ok(())
    }
    pub fn capture(
        &mut self,
        root: &OwnedFd,
        relative: &str,
        member: &str,
        owner: (u32, u32),
        mode: libc::mode_t,
    ) -> Result<bool, String> {
        if !name(relative) || !name(member) {
            return Err("fixed public Native relative path required".into());
        }
        let parts = relative.split('/').collect::<Vec<_>>();
        let mut parent = root.try_clone().map_err(|e| e.to_string())?;
        for part in &parts[..parts.len() - 1] {
            let child = match openat(
                &parent,
                *part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) => return Ok(false),
                Err(e) => return Err(e.to_string()),
            };
            let held = fstat(&child).map_err(|e| e.to_string())?;
            let visible =
                statat(&parent, *part, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
            if !crate::dependency_prefix_meta::same(&held, &visible)
                || FileType::from_raw_mode(held.st_mode) != FileType::Directory
                || !((held.st_uid == 0 && held.st_gid == 0)
                    || (held.st_uid == owner.0 && held.st_gid == owner.1))
                || held.st_mode & 0o7022 != 0
            {
                return Err("public Native parent custody differs".into());
            }
            parent = child;
        }
        let leaf = parts[parts.len() - 1];
        let before = match statat(&parent, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s) => s,
            Err(rustix::io::Errno::NOENT) => return Ok(false),
            Err(e) => return Err(e.to_string()),
        };
        let raw = crate::feature_files::required(&parent, leaf, owner, mode, MAX_FILE)?;
        let after = statat(&parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        if !crate::dependency_prefix_meta::same(&before, &after) {
            return Err("public Native file changed during capture".into());
        }
        self.insert(member, raw)?;
        self.metadata.insert(member.into(),json!({"device":before.st_dev,"inode":before.st_ino,
            "uid":before.st_uid,"gid":before.st_gid,"mode":before.st_mode&0o7777,"links":before.st_nlink,
            "bytes":before.st_size,"mtime":before.st_mtime,"mtime_nsec":before.st_mtime_nsec,
            "ctime":before.st_ctime,"ctime_nsec":before.st_ctime_nsec}));
        Ok(true)
    }
    pub fn capture_report(
        &mut self,
        journal: &OwnedFd,
        job_id: &str,
        owner: (u32, u32),
    ) -> Result<(), String> {
        if !crate::hex(job_id, 16)
            || !self.capture(
                journal,
                &format!("{job_id}.report.json"),
                "combined/worker/report.json",
                owner,
                0o600,
            )?
        {
            return Err("complete retained Native report required for public export".into());
        }
        Ok(())
    }
    pub fn capture_flat(
        &mut self,
        root: &OwnedFd,
        directory: &str,
        kind: CaptureKind,
        owner: (u32, u32),
    ) -> Result<(), String> {
        let fd = match openat(
            root,
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(e) => return Err(e.to_string()),
        };
        crate::feature_files::private_directory(&fd, owner)?;
        let mut count = 0;
        for entry in Dir::read_from(&fd).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let leaf = entry
                .file_name()
                .to_str()
                .map_err(|_| "public capture filename UTF-8")?;
            if matches!(leaf, "." | "..") {
                continue;
            }
            count += 1;
            if count > 2048 {
                return Err("public capture namespace bound exceeded".into());
            }
            if !kind.accepts(leaf) {
                continue;
            }
            let member = format!("combined/{directory}/{leaf}");
            if !self.capture(root, &format!("{directory}/{leaf}"), &member, owner, 0o600)? {
                return Err("public capture disappeared while enumerating".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CaptureKind {
    Cell,
    Process,
    Mcp,
}
impl CaptureKind {
    fn accepts(self, name: &str) -> bool {
        let Some((stem, suffix)) = name.rsplit_once('.') else {
            return false;
        };
        match self {
            Self::Cell => {
                stem.strip_prefix("capture-")
                    .is_some_and(|n| crate::hex(n, 32))
                    && matches!(suffix, "stdout" | "stderr")
            }
            Self::Process | Self::Mcp => {
                stem.len() == 3
                    && stem.bytes().all(|b| b.is_ascii_digit())
                    && (matches!(suffix, "stdout" | "stderr")
                        || matches!(self, Self::Mcp)
                            && matches!(suffix, "mcp-input" | "mcp-output"))
            }
        }
    }
}

struct Capped(Vec<u8>);
impl Write for Capped {
    fn write(&mut self, raw: &[u8]) -> io::Result<usize> {
        if raw.len() > MAX_ARCHIVE.saturating_sub(self.0.len()) {
            return Err(io::Error::other("public Native USTAR byte bound"));
        }
        self.0.extend_from_slice(raw);
        Ok(raw.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode(captured: PublicFiles, binding: Value) -> Result<Vec<u8>, String> {
    encode_profile(
        captured,
        binding,
        "hol-gauntlet-native-public-artifacts.v1",
        0,
    )
}
pub(crate) fn encode_live(
    captured: PublicFiles,
    binding: Value,
    model_requests: u64,
) -> Result<Vec<u8>, String> {
    if model_requests > 64
        || !matches!(
            binding["control_role"].as_str(),
            Some("feature-ai-unprotected" | "feature-ai-protected")
        )
    {
        return Err("bounded explicit live Native export role/count required".into());
    }
    encode_profile(
        captured,
        binding,
        "hol-gauntlet-native-public-artifacts.v2",
        model_requests,
    )
}
fn encode_profile(
    mut captured: PublicFiles,
    binding: Value,
    schema: &str,
    model_requests: u64,
) -> Result<Vec<u8>, String> {
    if !captured.files.keys().eq(captured.metadata.keys()) {
        return Err("Native export requires original metadata for every member".into());
    }
    let pins: BTreeMap<_, _> = captured
        .files
        .iter()
        .map(|(name, raw)| (name.clone(), json!({"bytes":raw.len(),"sha256":sha(raw)})))
        .collect();
    let mut index = binding;
    if !index.is_object() {
        return Err("public Native export binding required".into());
    }
    index["schema"] = json!(schema);
    index["files"] = json!(pins);
    index["filesystem"] = json!(captured.metadata);
    index["execution_eligible"] = json!(false);
    index["guard_causality_verified"] = json!(false);
    index["model_requests"] = json!(model_requests);
    let raw = canonicalize(index.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if raw.len() > MAX_FILE || raw.len() > MAX_ARCHIVE.saturating_sub(captured.total) {
        return Err("public Native manifest bound exceeded".into());
    }
    captured.files.insert("results.sha256.json".into(), raw);
    let mut archive = tar::Builder::new(Capped(Vec::new()));
    for (name, raw) in captured.files {
        let mut header = tar::Header::new_ustar();
        header.set_size(raw.len() as u64);
        header.set_mode(0o600);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        archive
            .append_data(&mut header, name, raw.as_slice())
            .map_err(|_| "bounded public Native USTAR append failed")?;
    }
    archive
        .into_inner()
        .map(|v| v.0)
        .map_err(|_| "public Native USTAR finish failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    };
    fn root(path: &std::path::Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }
    #[test]
    fn public_ustar_is_deterministic_indexed_and_binary_safe() {
        let temp = tempfile::tempdir().unwrap();
        let fd = root(temp.path());
        let path = temp.path().join("capture");
        std::fs::write(&path, b"\0\xff\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let owner = (meta.uid(), meta.gid());
        let job_id = "a".repeat(16);
        let report_raw =
            br#"{"schema":"hol-gauntlet-native-worker-report.v8","status":"invalid-evidence"}"#;
        let report_path = temp.path().join(format!("{job_id}.report.json"));
        std::fs::write(&report_path, report_raw).unwrap();
        std::fs::set_permissions(&report_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let report_meta = std::fs::metadata(&report_path).unwrap();
        let capture = || {
            let mut files = PublicFiles::default();
            files
                .capture(&fd, "capture", "combined/capture", owner, 0o600)
                .unwrap();
            files.capture_report(&fd, &job_id, owner).unwrap();
            files
        };
        let first = encode(capture(), json!({"job_id":"a".repeat(16)})).unwrap();
        assert_eq!(
            first,
            encode(capture(), json!({"job_id":"a".repeat(16)})).unwrap()
        );
        let mut archive = tar::Archive::new(first.as_slice());
        let mut files = BTreeMap::new();
        for row in archive.entries().unwrap() {
            let mut row = row.unwrap();
            assert!(row.header().as_ustar().is_some());
            assert_eq!(row.header().mode().unwrap(), 0o600);
            assert_eq!(row.header().uid().unwrap(), 0);
            assert_eq!(row.header().mtime().unwrap(), 0);
            let name = row.path().unwrap().to_str().unwrap().to_owned();
            let mut raw = Vec::new();
            row.read_to_end(&mut raw).unwrap();
            files.insert(name, raw);
        }
        assert_eq!(files["combined/capture"], b"\0\xff\n");
        let index: Value = serde_json::from_slice(&files["results.sha256.json"]).unwrap();
        assert_eq!(
            index["files"]["combined/capture"],
            json!({"bytes":3,"sha256":sha(b"\0\xff\n")})
        );
        assert_eq!(index["filesystem"]["combined/capture"]["uid"], owner.0);
        let report = "combined/worker/report.json";
        assert_eq!(files[report], report_raw);
        assert_eq!(
            index["files"][report],
            json!({"bytes":report_raw.len(),"sha256":sha(report_raw)})
        );
        assert_eq!(
            index["filesystem"][report],
            json!({"device":report_meta.dev(),"inode":report_meta.ino(),
            "uid":report_meta.uid(),"gid":report_meta.gid(),"mode":0o600,"links":1,"bytes":report_raw.len(),
            "mtime":report_meta.mtime(),"mtime_nsec":report_meta.mtime_nsec(),
            "ctime":report_meta.ctime(),"ctime_nsec":report_meta.ctime_nsec()})
        );
        assert_eq!(
            index["filesystem"].as_object().unwrap().len(),
            files.len() - 1
        );
        let mut unbound = PublicFiles::default();
        unbound.insert(report, report_raw.to_vec()).unwrap();
        assert!(encode(unbound, json!({"job_id":job_id})).is_err());
        assert!(PublicFiles::default()
            .capture_report(&fd, &"b".repeat(16), owner)
            .is_err());
        assert_eq!(index["execution_eligible"], false);
        assert_eq!(index["schema"], "hol-gauntlet-native-public-artifacts.v1");
        assert_eq!(index["model_requests"], 0);
        let live =
            encode_live(capture(), json!({"control_role":"feature-ai-protected"}), 3).unwrap();
        let mut live = tar::Archive::new(live.as_slice());
        let mut manifest = None;
        for entry in live.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().as_ref() == std::path::Path::new("results.sha256.json") {
                let mut raw = Vec::new();
                entry.read_to_end(&mut raw).unwrap();
                manifest = Some(serde_json::from_slice::<Value>(&raw).unwrap());
            }
        }
        let manifest = manifest.unwrap();
        assert_eq!(
            manifest["schema"],
            "hol-gauntlet-native-public-artifacts.v2"
        );
        assert_eq!(manifest["model_requests"], 3);
        assert_eq!(manifest["filesystem"], index["filesystem"]);
        assert!(encode_live(capture(), json!({"control_role":"readonly-utility"}), 3).is_err());
        assert!(encode_live(
            capture(),
            json!({"control_role":"feature-ai-protected"}),
            65
        )
        .is_err());
    }
    #[test]
    fn public_capture_refuses_links_wrong_owner_loose_modes_and_unsafe_names() {
        let temp = tempfile::tempdir().unwrap();
        let fd = root(temp.path());
        let path = temp.path().join("record");
        std::fs::write(&path, b"public").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let owner = (meta.uid(), meta.gid());
        let mut files = PublicFiles::default();
        assert!(files
            .capture(
                &fd,
                "record",
                "combined/record",
                (owner.0 + 1, owner.1),
                0o600
            )
            .is_err());
        symlink("record", temp.path().join("alias")).unwrap();
        assert!(files
            .capture(&fd, "alias", "combined/alias", owner, 0o600)
            .is_err());
        std::fs::hard_link(&path, temp.path().join("hard")).unwrap();
        assert!(files
            .capture(&fd, "record", "combined/record", owner, 0o600)
            .is_err());
        assert!(files.insert("../escape", b"x".to_vec()).is_err());
        assert!(files.insert("results.sha256.json", vec![]).is_err());
        assert!(!CaptureKind::Cell.accepts("signing-key.stdout"));
        assert!(!CaptureKind::Mcp.accepts("001.key"));
        assert!(CaptureKind::Cell.accepts(&format!("capture-{}.stdout", "a".repeat(32))));
        assert!(CaptureKind::Mcp.accepts("001.mcp-output"));
    }
    #[test]
    fn fixed_capture_namespace_excludes_private_names_and_refuses_linked_captures() {
        let temp = tempfile::tempdir().unwrap();
        let fd = root(temp.path());
        let path = temp.path().join("sdk-processes");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let owner = (meta.uid(), meta.gid());
        for (name, bytes) in [
            ("001.stdout", b"public".as_slice()),
            ("001.key", b"private"),
            ("signing-key", b"private"),
        ] {
            std::fs::write(path.join(name), bytes).unwrap();
            std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let mut files = PublicFiles::default();
        files
            .capture_flat(&fd, "sdk-processes", CaptureKind::Process, owner)
            .unwrap();
        assert_eq!(files.files.len(), 1);
        assert_eq!(files.files["combined/sdk-processes/001.stdout"], b"public");
        symlink("001.stdout", path.join("001.stderr")).unwrap();
        assert!(PublicFiles::default()
            .capture_flat(&fd, "sdk-processes", CaptureKind::Process, owner)
            .is_err());
    }
}
