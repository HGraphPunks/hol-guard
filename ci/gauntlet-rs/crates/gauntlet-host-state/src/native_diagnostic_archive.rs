//! Read a caller-pinned public USTAR export without extracting any member.
//! Member names never become filesystem paths; the digest is an outside input.
use crate::private_jobs::same_file;
use crate::HostNativeControlReadback;
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Cursor, Read},
    path::{Component, Path},
};

const LIMIT: usize = 128 * 1024 * 1024;
#[derive(Clone, Copy)]
enum ArtifactSubset {
    InputBinding,
    Boundary,
    Mcp,
    Process,
}
impl ArtifactSubset {
    fn role(self) -> Option<&'static str> {
        match self {
            Self::InputBinding => Some("input-binding"),
            Self::Boundary => Some("boundary"),
            Self::Mcp | Self::Process => None,
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::InputBinding => "hol-gauntlet-host-native-binding-artifact-readback.v1",
            Self::Boundary => "hol-gauntlet-host-native-boundary-artifact-readback.v1",
            Self::Mcp => "hol-gauntlet-host-native-mcp-artifact-readback.v1",
            Self::Process => "hol-gauntlet-host-native-process-artifact-readback.v1",
        }
    }
}
type Result<T> = std::result::Result<T, String>;
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("Native public diagnostic archive is unsafe or inconsistent".into())
    }
}
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn parse(raw: &[u8]) -> Result<Value> {
    serde_json::from_slice(&canonicalize(raw).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
fn read_stable(path: &Path, expected_sha256: &str) -> Result<Vec<u8>> {
    require(
        expected_sha256.len() == 64
            && expected_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    require(path.is_absolute() && path.as_os_str().len() <= 4096)?;
    let components = path.components().collect::<Vec<_>>();
    require(
        components.len() >= 2
            && components.len() <= 64
            && components[0] == Component::RootDir
            && components[1..]
                .iter()
                .all(|p| matches!(p, Component::Normal(_))),
    )?;
    let mut parent = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    for component in &components[1..components.len() - 1] {
        parent = openat(
            &parent,
            component.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
    }
    let name = components.last().unwrap().as_os_str();
    let file = File::from(
        openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    let before = fstat(&file).map_err(|e| e.to_string())?;
    require(
        FileType::from_raw_mode(before.st_mode) == FileType::RegularFile
            && before.st_uid == geteuid().as_raw()
            && before.st_mode & 0o022 == 0
            && before.st_nlink == 1
            && before.st_size >= 1024
            && before.st_size <= LIMIT as i64,
    )?;
    let mut raw = Vec::new();
    (&file)
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let named = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    require(
        same_file(&before, &after)
            && same_file(&after, &named)
            && before.st_gid == after.st_gid
            && after.st_gid == named.st_gid
            && raw.len() == before.st_size as usize
            && raw.len() % 512 == 0,
    )?;
    require(sha(&raw) == expected_sha256)?;
    Ok(raw)
}
fn members(raw: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut archive = tar::Archive::new(Cursor::new(raw));
    let mut files = BTreeMap::new();
    for entry in archive.entries().map_err(|e| e.to_string())?.raw(true) {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let h = entry.header();
        require(
            h.as_ustar().is_some()
                && h.entry_type() == tar::EntryType::Regular
                && h.mode().map_err(|e| e.to_string())? == 0o600
                && h.uid().map_err(|e| e.to_string())? == 0
                && h.gid().map_err(|e| e.to_string())? == 0
                && h.mtime().map_err(|e| e.to_string())? == 0,
        )?;
        let name = std::str::from_utf8(&entry.path_bytes())
            .map_err(|e| e.to_string())?
            .to_owned();
        require(
            !name.is_empty()
                && name.len() <= 1024
                && name.split('/').all(|p| {
                    !p.is_empty()
                        && p != "."
                        && p != ".."
                        && p.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')
                })
                && files.len() < 2048
                && !files.contains_key(&name)
                && entry.size() <= 32 * 1024 * 1024,
        )?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        require(bytes.len() as u64 == entry.size())?;
        files.insert(name, bytes);
    }
    let position = archive.into_inner().position() as usize;
    require(
        !files.is_empty()
            && position <= raw.len()
            && raw.len() - position >= 512
            && raw[position..].iter().all(|b| *b == 0),
    )?;
    Ok(files)
}
impl HostNativeControlReadback {
    /// Authenticate the archived report under this already checked host pin,
    /// then recompute request/capture/physical relations in Rust. This subset
    /// does not verify outside kernel observations or grant role admission.
    pub fn verify_input_binding_artifacts(
        &self,
        path: &Path,
        expected_sha256: &str,
    ) -> Result<Value> {
        self.verify_artifact_subset(path, expected_sha256, ArtifactSubset::InputBinding, None)
    }
    /// Recompute the three synthetic canaries and eight reported refusals.
    /// Kernel/process custody and Guard intervention remain separate checks.
    pub fn verify_boundary_artifacts(&self, path: &Path, expected_sha256: &str) -> Result<Value> {
        self.verify_artifact_subset(path, expected_sha256, ArtifactSubset::Boundary, None)
    }
    /// Reconcile actual SDK/MCP frames, captured Native bytes and physical
    /// provider receipts/database. Live process custody remains separate.
    pub fn verify_mcp_artifacts(&self, path: &Path, expected_sha256: &str) -> Result<Value> {
        self.verify_artifact_subset(path, expected_sha256, ArtifactSubset::Mcp, None)
    }
    /// Match separate public kernel samples to the host-authenticated report.
    /// Interpreter/observer digests are explicit readback pins, not v7 launch pins.
    pub fn verify_process_artifacts(
        &self,
        path: &Path,
        expected_sha256: &str,
        interpreter_sha256: &str,
        observer_sha256: &str,
    ) -> Result<Value> {
        self.verify_artifact_subset(
            path,
            expected_sha256,
            ArtifactSubset::Process,
            Some((interpreter_sha256, observer_sha256)),
        )
    }
    fn verify_artifact_subset(
        &self,
        path: &Path,
        expected_sha256: &str,
        subset: ArtifactSubset,
        process_pins: Option<(&str, &str)>,
    ) -> Result<Value> {
        require(
            subset
                .role()
                .is_none_or(|role| self.diagnostic()["control_role"] == role),
        )?;
        let raw = read_stable(path, expected_sha256)?;
        let files = members(&raw)?;
        let get = |name: &str| {
            files
                .get(name)
                .ok_or_else(|| "required Native public artifact missing".to_owned())
        };
        let report_raw = get("combined/worker/report.json")?;
        let report = parse(report_raw)?;
        let observation = self.observation();
        require(
            observation["report_sha256"] == sha(report_raw)
                && report["controller_report"] == *self.diagnostic(),
        )?;
        let preparation_raw = get("combined/preparation.v1.json")?;
        let preparation = parse(preparation_raw)?;
        let declaration = parse(get("combined/declaration.json")?)?;
        require(
            self.diagnostic()["preparation_sha256"] == sha(preparation_raw)
                && observation["deployment_digest"] == sha(get("combined/declaration.json")?)
                && preparation["runtime_prefix"]
                    == format!(
                        "/opt/hol-gauntlet/candidates/{}/prefix",
                        observation["source_sha"]
                            .as_str()
                            .ok_or("missing pinned Native source")?
                    ),
        )?;
        if matches!(subset, ArtifactSubset::Mcp | ArtifactSubset::Process) {
            require(
                declaration["guard"] == self.diagnostic()["guard_pins"]
                    && declaration["sdk"] == self.diagnostic()["sdk_pins"]
                    && declaration["preparation_sha256"] == sha(preparation_raw),
            )?;
        }
        let relations = match subset {
            ArtifactSubset::InputBinding => gauntlet_evidence::verify_native_binding_diagnostic(
                self.diagnostic(),
                &preparation,
                &files,
            ),
            ArtifactSubset::Boundary => gauntlet_evidence::verify_native_boundary_diagnostic(
                self.diagnostic(),
                &preparation,
                &files,
            ),
            ArtifactSubset::Mcp => {
                gauntlet_evidence::verify_native_mcp_diagnostic(self.diagnostic(), &files)
            }
            ArtifactSubset::Process => {
                let (interpreter, observer) =
                    process_pins.ok_or("explicit process readback pins missing")?;
                gauntlet_evidence::verify_native_process_diagnostic(
                    self.diagnostic(),
                    &preparation,
                    &files,
                    interpreter,
                    observer,
                )
            }
        }
        .map_err(|e| e.to_string())?;
        Ok(json!({"schema":subset.schema(),
            "archive_sha256":expected_sha256,"archive_bytes":raw.len(),"archive_members":files.len(),
            "host_pin_sha256":observation["host_pin_sha256"],"report_sha256":observation["report_sha256"],
            "source_sha":observation["source_sha"],"job_id":observation["job_id"],
            "authenticated_report_matches_public_archive":true,"relations":relations,
            "qualified_role_complete":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}))
    }
}

#[cfg(test)]
#[path = "native_diagnostic_archive_tests.rs"]
mod tests;
