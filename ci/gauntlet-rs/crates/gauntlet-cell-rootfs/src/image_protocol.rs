//! Only inert image inspection/mounting is permitted; no image command runs.
use crate::{hex, Result};
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
use {crate::spec::literal_path, serde_json::Value, std::path::PathBuf};

pub(crate) fn image_id(value: &str) -> Result<&str> {
    value
        .strip_prefix("sha256:")
        .filter(|s| hex(s, 64))
        .ok_or_else(|| "exact immutable image ID required".into())
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
fn rows(raw: &[u8]) -> Result<Vec<Value>> {
    if raw.len() > 1024 * 1024 {
        return Err("bounded image metadata required".into());
    }
    let raw = gauntlet_contracts::canonicalize(raw).map_err(|_| "ambiguous image metadata")?;
    let value: Value = serde_json::from_slice(&raw).map_err(|_| "image metadata JSON")?;
    value
        .as_array()
        .filter(|a| a.len() <= 4096)
        .cloned()
        .ok_or_else(|| "bounded image metadata array required".into())
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn inspect(raw: &[u8], image: &str) -> Result<()> {
    let rows = rows(raw)?;
    let expected = image_id(image)?;
    if rows.len() != 1
        || rows[0]["Os"] != "linux"
        || rows[0]["Architecture"] != "arm64"
        || rows[0]["Id"]
            .as_str()
            .map(|s| s.strip_prefix("sha256:").unwrap_or(s))
            != Some(expected)
    {
        return Err("exact Linux ARM64 dependency image required".into());
    }
    Ok(())
}

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn mounted(raw: &[u8], image: &str) -> Result<Option<PathBuf>> {
    let wanted = image_id(image)?;
    let mut ids = std::collections::BTreeSet::new();
    let mut result = None;
    for row in rows(raw)? {
        let id = row["id"].as_str().ok_or("image mount identity missing")?;
        let id = id.strip_prefix("sha256:").unwrap_or(id);
        if !hex(id, 64) || !ids.insert(id.to_owned()) {
            return Err("ambiguous image mount identities".into());
        }
        if id == wanted {
            let root = literal_path(
                row["mountpoint"]
                    .as_str()
                    .ok_or("image mountpoint missing")?,
            )?;
            if root == std::path::Path::new("/") {
                return Err("separate image root required".into());
            }
            result = Some(root);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn image_inspection_cannot_select_a_tag_foreign_arch_or_duplicate_identity() {
        let image = format!("sha256:{}", "a".repeat(64));
        let value = json!([{"Id":image,"Os":"linux","Architecture":"arm64"}]);
        assert!(inspect(value.to_string().as_bytes(), &image).is_ok());
        for bad in [
            json!([]),
            json!([value[0], value[0]]),
            json!([{"Id":image,"Os":"linux","Architecture":"amd64"}]),
        ] {
            assert!(inspect(bad.to_string().as_bytes(), &image).is_err());
        }
        assert!(image_id("latest").is_err());
        let duplicate = format!("[{{\"Id\":\"{image}\",\"Id\":\"{image}\",\"Os\":\"linux\",\"Architecture\":\"arm64\"}}]");
        assert!(inspect(duplicate.as_bytes(), &image).is_err());
    }
    #[test]
    fn existing_mounts_are_distinct_from_unavailable_and_ambiguous_inventory() {
        let id = "b".repeat(64);
        let image = format!("sha256:{id}");
        assert_eq!(mounted(b"[]", &image).unwrap(), None);
        let row =
            json!({"id":id,"mountpoint":"/var/lib/containers/storage/overlay/generation/merged"});
        assert!(mounted(json!([row]).to_string().as_bytes(), &image)
            .unwrap()
            .is_some());
        for bad in [
            json!([row, row]),
            json!([{"id":id,"mountpoint":"/"}]),
            json!([{"id":id,"mountpoint":"/var/lib/../root"}]),
            json!([{"mountpoint":"/root"}]),
            json!({}),
        ] {
            assert!(mounted(bad.to_string().as_bytes(), &image).is_err());
        }
    }
}
