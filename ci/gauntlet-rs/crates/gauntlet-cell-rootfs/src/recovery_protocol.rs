//! Strict retained records for quiescent recovery, never execution scoring.
use crate::{hash, hex, Result};
use serde_json::Value;
use std::path::Path;

pub(crate) fn events(raw: &[u8]) -> Result<Vec<Value>> {
    if raw.is_empty() || raw.len() > 64 * 1024 * 1024 || raw.last() != Some(&b'\n') {
        return Err("complete bounded recovery journal required".into());
    }
    let mut previous = "0".repeat(64);
    let mut records = Vec::new();
    for line in raw[..raw.len() - 1].split(|b| *b == b'\n') {
        if records.len() >= 10000 || line.len() > 256 * 1024 {
            return Err("recovery event bound".into());
        }
        let canonical = gauntlet_contracts::canonicalize(line).map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
        if canonical != line
            || value.as_object().is_none_or(|o| o.len() != 5)
            || value["schema"] != "hol-gauntlet-cell-event.v1"
            || value["sequence"].as_u64() != Some(records.len() as u64)
            || value["previous_sha256"] != previous
            || value["kind"].as_str().is_none()
            || value.get("data").is_none()
        {
            return Err("recovery event chain malformed or incomplete".into());
        }
        previous = hash(line);
        records.push(value);
    }
    Ok(records)
}

pub(crate) fn active(raw: &[u8], image: &str, stage: &Path) -> Result<()> {
    let canonical = gauntlet_contracts::canonicalize(raw).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
    let mut with_newline = canonical;
    with_newline.push(b'\n');
    if raw != with_newline
        || value.as_object().is_none_or(|o| o.len() != 4)
        || value["schema"] != "hol-gauntlet-cell-image-active.v1"
        || value["image_id"] != image
        || value["stage"] != stage.to_string_lossy().as_ref()
        || value["nonce"].as_str().is_none_or(|s| !hex(s, 32))
    {
        return Err("active image pointer belongs to another or ambiguous lease".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn chain(kinds: &[&str]) -> Vec<u8> {
        let mut raw = Vec::new();
        let mut previous = "0".repeat(64);
        for (sequence, kind) in kinds.iter().enumerate() {
            let value = json!({"schema":"hol-gauntlet-cell-event.v1","sequence":sequence,
                "previous_sha256":previous,"kind":kind,"data":{}});
            let line = gauntlet_contracts::canonicalize(value.to_string().as_bytes()).unwrap();
            previous = hash(&line);
            raw.extend(line);
            raw.push(b'\n');
        }
        raw
    }
    #[test]
    fn truncated_reordered_or_edited_ownership_records_refuse_recovery() {
        let raw = chain(&["reserved", "mounted"]);
        assert_eq!(events(&raw).unwrap().len(), 2);
        assert!(events(&raw[..raw.len() - 1]).is_err());
        let lines = raw.split_inclusive(|b| *b == b'\n').collect::<Vec<_>>();
        assert!(events(&[lines[1], lines[0]].concat()).is_err());
        let edited = String::from_utf8(raw)
            .unwrap()
            .replace("mounted", "released");
        // Editing the last complete record is not detectable without a pin;
        // callers bind its semantic ownership and retain the whole-file hash.
        assert!(events(edited.as_bytes()).is_ok());
        let edited = edited.replace("reserved", "borrowed");
        assert!(events(edited.as_bytes()).is_err());
        assert!(events(b"{}").is_err());
    }
    #[test]
    fn another_job_or_image_cannot_reopen_the_lease() {
        let stage = Path::new("/var/lib/hol-gauntlet-rust/native-jobs/0123456789abcdef/cell");
        let image = format!("sha256:{}", "a".repeat(64));
        let value = json!({"schema":"hol-gauntlet-cell-image-active.v1","image_id":image,"stage":stage,"nonce":"b".repeat(32)});
        let mut raw = gauntlet_contracts::canonicalize(value.to_string().as_bytes()).unwrap();
        raw.push(b'\n');
        active(&raw, &image, stage).unwrap();
        assert!(active(&raw, &format!("sha256:{}", "c".repeat(64)), stage).is_err());
        assert!(active(&raw, &image, Path::new("/var/lib/hol-gauntlet-rust/other")).is_err());
        assert!(active(&raw[..raw.len() - 1], &image, stage).is_err());
    }
}
