//! Bounded offline authoring interfaces, never publisher/activation authority.
//! Builder obtains these bytes only from verified bundle metadata or its
//! globally validated development pack stream. Native callers remain untrusted.
use super::packs::objects::{read_blob, ObjectRef, OBJECT_BYTES};
use super::*;
use std::path::PathBuf;

const MAX_ENTRIES: usize = 100_000;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;
const MAX_VISITED_REFS: usize = 300_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Handle {
    directory: PathBuf,
    root: ObjectRef,
    source_context: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    schema: String,
    engine: String,
    source_context: String,
    count: usize,
    total_bytes: usize,
    pages: usize,
    first: ObjectRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    schema: String,
    entries: Vec<(String, ObjectRef)>,
    next: Option<ObjectRef>,
}

struct Reader<'a> {
    directory: &'a std::path::Path,
    visits: usize,
    bytes: usize,
}

impl Reader<'_> {
    fn value(&mut self, reference: &ObjectRef, page: bool) -> Result<Value, &'static str> {
        if page && (reference.kind != "data" || reference.expanded_length > OBJECT_BYTES) {
            return Err("command_source_metadata_page_bounds_invalid");
        }
        let bytes = read_blob(reference, &mut |sha| {
            self.visits += 1;
            if self.visits > MAX_VISITED_REFS {
                return Err("command_source_metadata_reference_budget_exceeded");
            }
            let path = self.directory.join(format!("{sha}.json"));
            // Reject mutable, linked, symlinked, nonregular or unstable files.
            // read_bounded additionally checks every ancestor before and after.
            let _immutable = guard_secure_fs::open_immutable_blob(&path)
                .map_err(|_| "command_source_metadata_file_invalid")?;
            let read = guard_secure_fs::read_bounded(&path, OBJECT_BYTES)
                .map_err(|_| "command_source_metadata_file_invalid")?;
            if _immutable.identity != read.identity {
                return Err("command_source_metadata_file_invalid");
            }
            self.bytes = self
                .bytes
                .checked_add(read.bytes.len())
                .ok_or("command_source_metadata_byte_budget_exceeded")?;
            // Include concat and index overhead, separately from metadata bytes.
            if self.bytes > MAX_TOTAL_BYTES + 32 * 1024 * 1024 {
                return Err("command_source_metadata_byte_budget_exceeded");
            }
            Ok(read.bytes)
        })?;
        json::decode(&bytes)
    }
}

pub(super) fn read(handle: &Handle) -> Result<Vec<Value>, &'static str> {
    if !handle.directory.is_absolute()
        || guard_secure_fs::contains_symlink_component(&handle.directory)
    {
        return Err("command_source_metadata_directory_invalid");
    }
    let mut reader = Reader {
        directory: &handle.directory,
        visits: 0,
        bytes: 0,
    };
    let root: Root = serde_json::from_value(reader.value(&handle.root, true)?)
        .map_err(|_| "command_source_metadata_root_invalid")?;
    if root.schema != "guard.authoring-metadata.v1"
        || root.engine != env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION")
        || root.source_context != handle.source_context
        || root.source_context.len() != 64
        || !root
            .source_context
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || root.count == 0
        || root.count > MAX_ENTRIES
        || root.total_bytes == 0
        || root.total_bytes > MAX_TOTAL_BYTES
        || root.pages != root.count.div_ceil(64)
    {
        return Err("command_source_metadata_root_invalid");
    }
    let mut result = Vec::with_capacity(root.count);
    let mut next = Some(root.first);
    let mut seen = BTreeSet::new();
    let mut previous = String::new();
    let mut total = 0usize;
    for _ in 0..root.pages {
        let reference = next.take().ok_or("command_source_metadata_page_missing")?;
        if !seen.insert(reference.sha256.clone()) {
            return Err("command_source_metadata_page_duplicate");
        }
        let page: Page = serde_json::from_value(reader.value(&reference, true)?)
            .map_err(|_| "command_source_metadata_page_invalid")?;
        if page.schema != "guard.authoring-metadata-page.v1"
            || page.entries.is_empty()
            || page.entries.len() > 64
        {
            return Err("command_source_metadata_page_invalid");
        }
        for (identity, reference) in page.entries {
            if identity <= previous
                || identity.len() > 256
                || !identity.is_ascii()
                || result.len() >= root.count
            {
                return Err("command_source_metadata_order_invalid");
            }
            total = total
                .checked_add(reference.expanded_length)
                .ok_or("command_source_metadata_byte_budget_exceeded")?;
            if total > root.total_bytes {
                return Err("command_source_metadata_byte_budget_exceeded");
            }
            let entry = reader.value(&reference, false)?;
            if entry["extension_id"] != identity {
                return Err("command_source_metadata_identity_invalid");
            }
            previous = identity;
            result.push(entry);
        }
        next = page.next;
    }
    if next.is_some() || result.len() != root.count || total != root.total_bytes {
        return Err("command_source_metadata_inventory_incomplete");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_visit_budget_is_independent_of_hash_validity_and_file_io() {
        let directory = tempfile::tempdir().unwrap();
        let mut reader = Reader {
            directory: directory.path(),
            visits: MAX_VISITED_REFS,
            bytes: 0,
        };
        let reference = ObjectRef {
            sha256: "0".repeat(64),
            length: 2,
            expanded_length: 2,
            kind: "data".to_owned(),
        };
        assert_eq!(
            reader.value(&reference, true).unwrap_err(),
            "command_source_metadata_reference_budget_exceeded"
        );
    }
}
