//! Closed inert capsule format for the fixed unprivileged dependency adapter.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

pub const INPUT_NAMES: [&str; 3] = ["pyproject.toml", "uv.lock", "gauntlet-dependency-exporter"];
pub const INPUT_LIMITS: [u64; 3] = [4 * 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024];

#[derive(Debug)]
pub struct NativeDependencyInputPins<'a> {
    pub job: &'a str,
    pub source: &'a str,
    pub source_archive: &'a str,
    pub payload_sha256: &'a str,
    pub payload_bytes: u64,
    pub project_sha256: &'a str,
    pub lock_sha256: &'a str,
    pub exporter_sha256: &'a str,
    pub generation: &'a str,
}

impl NativeDependencyInputPins<'_> {
    pub(crate) fn valid(&self) -> bool {
        crate::hex(self.job, 16)
            && crate::hex(self.source, 40)
            && (1..=32 * 1024 * 1024).contains(&self.payload_bytes)
            && [
                self.source_archive,
                self.payload_sha256,
                self.project_sha256,
                self.lock_sha256,
                self.exporter_sha256,
                self.generation,
            ]
            .iter()
            .all(|v| crate::hex(v, 64))
    }
    pub(crate) fn hashes(&self) -> [&str; 3] {
        [self.project_sha256, self.lock_sha256, self.exporter_sha256]
    }
    pub(crate) fn receipt(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-dependency-inputs.v1","job_id":self.job,"source_sha":self.source,
            "source_archive_sha256":self.source_archive,"payload_sha256":self.payload_sha256,"payload_bytes":self.payload_bytes,
            "pyproject_sha256":self.project_sha256,"uv_lock_sha256":self.lock_sha256,"exporter_sha256":self.exporter_sha256,
            "worker_generation":self.generation,"builder_executed":false,"execution_eligible":false,"model_requests":0})
    }
}

pub(crate) fn decode_inputs(
    raw: &[u8],
    pins: &NativeDependencyInputPins<'_>,
) -> Result<[Vec<u8>; 3], String> {
    if !pins.valid()
        || raw.len() as u64 != pins.payload_bytes
        || format!("{:x}", Sha256::digest(raw)) != pins.payload_sha256
    {
        return Err("dependency capsule differs from outside pins".into());
    }
    let mut zip =
        zip::ZipArchive::new(Cursor::new(raw)).map_err(|_| "dependency capsule ZIP unavailable")?;
    if zip.len() != 3 {
        return Err("exactly three fixed dependency input files required".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for index in 0..zip.len() {
        let entry = zip
            .by_index(index)
            .map_err(|_| "dependency capsule entry unavailable")?;
        if !INPUT_NAMES.contains(&entry.name())
            || !seen.insert(entry.name().to_owned())
            || entry.is_dir()
            || !entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o100000 && mode & 0o7000 == 0)
            || !matches!(
                entry.compression(),
                zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
            )
        {
            return Err("dependency capsule contains unsupported objects".into());
        }
    }
    let mut result: [Vec<u8>; 3] = std::array::from_fn(|_| Vec::new());
    for index in 0..3 {
        let entry = zip
            .by_name(INPUT_NAMES[index])
            .map_err(|_| "fixed dependency capsule member missing")?;
        let expected = entry.size();
        if !(1..=INPUT_LIMITS[index]).contains(&expected) {
            return Err("dependency capsule member exceeds byte bound".into());
        }
        entry
            .take(INPUT_LIMITS[index] + 1)
            .read_to_end(&mut result[index])
            .map_err(|_| "dependency capsule CRC or read failed")?;
        if result[index].len() as u64 != expected
            || format!("{:x}", Sha256::digest(&result[index])) != pins.hashes()[index]
        {
            return Err("dependency capsule member differs from outside hash".into());
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn capsule(names: [&str; 3]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in names
            .into_iter()
            .zip([b"project".as_slice(), b"locked", b"adapter"])
        {
            zip.start_file(
                name,
                zip::write::SimpleFileOptions::default().unix_permissions(0o644),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }
    #[test]
    fn exact_capsule_is_inert_and_rejects_wrong_hash_and_foreign_paths() {
        let raw = capsule(INPUT_NAMES);
        let hash = format!("{:x}", Sha256::digest(&raw));
        let hashes: [String; 3] = [b"project".as_slice(), b"locked", b"adapter"]
            .map(|b| format!("{:x}", Sha256::digest(b)));
        let pins = NativeDependencyInputPins {
            job: "0123456789abcdef",
            source: &"a".repeat(40),
            source_archive: &"b".repeat(64),
            payload_sha256: &hash,
            payload_bytes: raw.len() as u64,
            project_sha256: &hashes[0],
            lock_sha256: &hashes[1],
            exporter_sha256: &hashes[2],
            generation: &"c".repeat(64),
        };
        assert_eq!(
            decode_inputs(&raw, &pins).unwrap(),
            [b"project".to_vec(), b"locked".to_vec(), b"adapter".to_vec()]
        );
        assert_eq!(pins.receipt()["execution_eligible"], false);
        let wrong = NativeDependencyInputPins {
            exporter_sha256: &"0".repeat(64),
            ..pins
        };
        assert!(decode_inputs(&raw, &wrong).is_err());
        for names in [
            ["../outside", "uv.lock", "gauntlet-dependency-exporter"],
            ["pyproject.toml", "uv.lock", "unexpected"],
        ] {
            let changed = capsule(names);
            let changed_hash = format!("{:x}", Sha256::digest(&changed));
            let changed_pins = NativeDependencyInputPins {
                payload_sha256: &changed_hash,
                payload_bytes: changed.len() as u64,
                ..wrong
            };
            assert!(decode_inputs(&changed, &changed_pins).is_err());
        }
    }
}
