//! Bounded inert reader for the closed dependency export. A producer manifest
//! never grants authority; every path, byte, CRC and outside pin is checked.
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Cursor, Read};

pub(crate) const MAX_ARCHIVE: usize = 256 * 1024 * 1024;
pub(crate) const MAX_DECODED: u64 = 512 * 1024 * 1024;
const MAX_OBJECTS: usize = 100_000;
const MAX_PATH_BYTES: usize = 32 * 1024 * 1024;
const MANIFEST: &str = "dependency-export.v1.json";

#[derive(Debug, Clone, Copy)]
pub struct DependencyArchivePins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub archive_sha256: &'a str,
    pub pyproject_sha256: &'a str,
    pub uv_lock_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyArchiveProof {
    pub files: Vec<(String, u64)>,
    pub directories: usize,
    pub decoded_bytes: u64,
    pub entry_bytes_sha256: String,
    pub archive_sha256: String,
}
impl DependencyArchiveProof {
    pub fn to_json(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-dependency-archive-readback.v1","files":self.files.len(),
            "directories":self.directories,"decoded_bytes":self.decoded_bytes,"entry_bytes_sha256":self.entry_bytes_sha256,
            "archive_sha256":self.archive_sha256,"dependency_imported":false,"artifact_admitted":false,"execution_eligible":false})
    }
}

fn valid_relative(value: &str) -> bool {
    !value.is_empty()
        && value.split('/').count() <= 129
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|p| !p.is_empty() && !matches!(p, "." | "..") && p.len() <= 255)
}

pub fn inspect_dependency_archive(
    raw: &[u8],
    pins: &DependencyArchivePins<'_>,
) -> Result<DependencyArchiveProof, String> {
    if !crate::hex(pins.job_id, 16)
        || !crate::hex(pins.source_sha, 40)
        || ![
            pins.archive_sha256,
            pins.pyproject_sha256,
            pins.uv_lock_sha256,
        ]
        .iter()
        .all(|s| crate::hex(s, 64))
        || raw.is_empty()
        || raw.len() > MAX_ARCHIVE
        || format!("{:x}", Sha256::digest(raw)) != pins.archive_sha256
    {
        return Err("bounded dependency ZIP differs from outside pins".into());
    }
    let mut zip = zip::ZipArchive::new(Cursor::new(raw))
        .map_err(|_| "dependency ZIP directory unavailable")?;
    if !(2..=MAX_OBJECTS + 1).contains(&zip.len()) {
        return Err("dependency ZIP file count exceeds bound".into());
    }
    let entries = zip.len();
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut total = 0u64;
    let mut path_bytes = 0usize;
    let mut hash = Sha256::new();
    let mut manifest = None;
    for index in 0..entries {
        let mut entry = zip
            .by_index(index)
            .map_err(|_| "dependency ZIP entry unavailable or encrypted")?;
        let name = entry.name().to_owned();
        if std::str::from_utf8(entry.name_raw()).ok() != Some(name.as_str())
            || entry.encrypted()
            || !entry.is_file()
            || entry.unix_mode() != Some(0o100644)
            || !matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
        {
            return Err("ordinary unencrypted UTF-8 dependency files required".into());
        }
        if name == MANIFEST {
            if index + 1 != entries || entry.size() > 8192 {
                return Err("one bounded final dependency manifest required".into());
            }
            let mut bytes = Vec::new();
            entry
                .take(8193)
                .read_to_end(&mut bytes)
                .map_err(|_| "dependency manifest CRC/read failed")?;
            if canonicalize(&bytes).map_err(|e| e.to_string())? != bytes {
                return Err("canonical dependency manifest required".into());
            }
            manifest = Some(serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())?);
            continue;
        }
        let relative = name
            .strip_prefix("site-packages/")
            .filter(|s| valid_relative(s))
            .ok_or("unsupported dependency path")?;
        if !seen.insert(relative.to_owned()) || directories.contains(relative) {
            return Err("duplicate or conflicting dependency path".into());
        }
        path_bytes = path_bytes
            .checked_add(relative.len())
            .filter(|n| *n <= MAX_PATH_BYTES)
            .ok_or("dependency path bytes exceed bound")?;
        let mut parent = relative;
        while let Some((head, _)) = parent.rsplit_once('/') {
            if seen.contains(head) {
                return Err("dependency file conflicts with directory".into());
            }
            if directories.insert(head.to_owned()) {
                path_bytes = path_bytes
                    .checked_add(head.len())
                    .filter(|n| *n <= MAX_PATH_BYTES)
                    .ok_or("dependency path inventory exceeds bound")?;
            }
            if seen.len() + directories.len() > MAX_OBJECTS {
                return Err("dependency object count exceeds bound".into());
            }
            parent = head;
        }
        if seen.len() + directories.len() > MAX_OBJECTS {
            return Err("dependency object count exceeds bound".into());
        }
        let size = entry.size();
        total = total
            .checked_add(size)
            .filter(|n| *n <= MAX_DECODED)
            .ok_or("dependency decoded size exceeds bound")?;
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update(size.to_be_bytes());
        let mut copied = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let n = entry
                .read(&mut buffer)
                .map_err(|_| "dependency file CRC/read failed")?;
            if n == 0 {
                break;
            }
            copied = copied
                .checked_add(n as u64)
                .filter(|n| *n <= size)
                .ok_or("dependency member grew beyond declared size")?;
            hash.update(&buffer[..n]);
        }
        if copied != size {
            return Err("dependency member is truncated".into());
        }
        files.push((relative.to_owned(), size));
    }
    let digest = format!("{:x}", hash.finalize());
    let m = manifest.ok_or("dependency manifest missing")?;
    if m.as_object().is_none_or(|o| o.len() != 12)
        || m["schema"] != "hol-gauntlet-native-dependency-export.v1"
        || m["job_id"] != pins.job_id
        || m["source_sha"] != pins.source_sha
        || m["pyproject_sha256"] != pins.pyproject_sha256
        || m["uv_lock_sha256"] != pins.uv_lock_sha256
        || m["wheel_only_install"] != true
        || m["files"] != files.len()
        || m["decoded_bytes"] != total
        || m["entry_bytes_sha256"] != digest
        || m["artifact_admitted"] != false
        || m["execution_eligible"] != false
        || m["model_requests"] != 0
    {
        return Err("dependency manifest differs from actual bytes or outside identity".into());
    }
    Ok(DependencyArchiveProof {
        files,
        directories: directories.len(),
        decoded_bytes: total,
        entry_bytes_sha256: digest,
        archive_sha256: pins.archive_sha256.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn archive(path: &str, change: Option<(&str, Value)>) -> Vec<u8> {
        let content = b"native-inert-payload-unique\0\xff";
        let full = format!("site-packages/{path}");
        let mut h = Sha256::new();
        h.update((full.len() as u64).to_be_bytes());
        h.update(full.as_bytes());
        h.update((content.len() as u64).to_be_bytes());
        h.update(content);
        let mut m = json!({"schema":"hol-gauntlet-native-dependency-export.v1","job_id":"0123456789abcdef","source_sha":"a".repeat(40),
            "pyproject_sha256":"b".repeat(64),"uv_lock_sha256":"c".repeat(64),"wheel_only_install":true,"files":1,"decoded_bytes":content.len(),
            "entry_bytes_sha256":format!("{:x}",h.finalize()),"artifact_admitted":false,"execution_eligible":false,"model_requests":0});
        if let Some((key, value)) = change {
            m[key] = value;
        }
        let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .unix_permissions(0o644)
            .compression_method(zip::CompressionMethod::Stored);
        z.start_file(full, options).unwrap();
        z.write_all(content).unwrap();
        z.start_file(MANIFEST, options).unwrap();
        z.write_all(&canonicalize(m.to_string().as_bytes()).unwrap())
            .unwrap();
        z.finish().unwrap().into_inner()
    }
    fn read(raw: &[u8]) -> Result<DependencyArchiveProof, String> {
        inspect_dependency_archive(
            raw,
            &DependencyArchivePins {
                job_id: "0123456789abcdef",
                source_sha: &"a".repeat(40),
                archive_sha256: &format!("{:x}", Sha256::digest(raw)),
                pyproject_sha256: &"b".repeat(64),
                uv_lock_sha256: &"c".repeat(64),
            },
        )
    }
    #[test]
    fn binary_byte_inventory_is_inert_and_binds_the_complete_manifest() {
        let p = read(&archive("pkg/data.bin", None)).unwrap();
        assert_eq!(p.files.len(), 1);
        assert_eq!(p.directories, 1);
        assert_eq!(p.to_json()["execution_eligible"], false);
        for (key, value) in [
            ("source_sha", json!("d".repeat(40))),
            ("entry_bytes_sha256", json!("0".repeat(64))),
            ("execution_eligible", json!(true)),
            ("extra", json!(1)),
        ] {
            assert!(
                read(&archive("pkg/data.bin", Some((key, value)))).is_err(),
                "{key}"
            );
        }
        for path in [
            "../escape",
            "/absolute",
            "pkg//duplicate",
            "pkg/./alias",
            "pkg\\backslash",
            "pkg/\ncontrol",
        ] {
            assert!(read(&archive(path, None)).is_err(), "{path}");
        }
    }
    #[test]
    fn corrupted_crc_and_oversized_declared_file_refuse_without_large_allocation() {
        let mut raw = archive("pkg/data.bin", None);
        let pos = {
            let mut z = zip::ZipArchive::new(Cursor::new(&raw)).unwrap();
            let e = z.by_index(0).unwrap();
            e.data_start() as usize
        };
        raw[pos] ^= 1;
        assert!(read(&raw).unwrap_err().contains("CRC"));
        let mut raw = archive("pkg/data.bin", None);
        let pos = raw.windows(4).position(|p| p == b"PK\x01\x02").unwrap();
        raw[pos + 24..pos + 28].copy_from_slice(&((MAX_DECODED + 1) as u32).to_le_bytes());
        assert!(read(&raw).is_err());
    }
}
