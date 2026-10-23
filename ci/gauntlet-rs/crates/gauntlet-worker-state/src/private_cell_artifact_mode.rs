//! Fixed artifact layouts; no path/program is selected from candidate data.
use gauntlet_evidence::{
    fixed_native_private_cell_sources, fixed_private_cell_sources, NATIVE_CELL_ACTOR,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactRuntime {
    PythonV1,
    RustV1,
}
impl ArtifactRuntime {
    pub(crate) fn verify(
        self,
        root: &std::path::Path,
        manifest: &str,
        initializer: &str,
    ) -> gauntlet_evidence::Result<()> {
        let inventory = gauntlet_evidence::verify_private_cell_artifacts(
            &root.join(self.target()),
            manifest,
            initializer,
        )?;
        if inventory.files.contains_key(NATIVE_CELL_ACTOR) != (self == Self::RustV1) {
            return Err(gauntlet_evidence::EvidenceError::Invalid(
                "artifact directory and actor runtime differ",
            ));
        }
        Ok(())
    }
    pub(crate) fn sources(self) -> BTreeMap<String, &'static [u8]> {
        match self {
            Self::PythonV1 => fixed_private_cell_sources(),
            Self::RustV1 => fixed_native_private_cell_sources(),
        }
    }
    pub(crate) fn target(self) -> &'static str {
        match self {
            Self::PythonV1 => "cell-artifacts",
            Self::RustV1 => "cell-artifacts-rust-v2",
        }
    }
    pub(crate) fn actor_name(self) -> &'static str {
        match self {
            Self::PythonV1 => "actor.py",
            Self::RustV1 => "gauntlet-product-cell",
        }
    }
    pub(crate) fn actor_relative(self) -> &'static str {
        match self {
            Self::PythonV1 => "public/actor.py",
            Self::RustV1 => NATIVE_CELL_ACTOR,
        }
    }
    pub(crate) fn actor_mode(self) -> u32 {
        match self {
            Self::PythonV1 => 0o444,
            Self::RustV1 => 0o555,
        }
    }
    pub(crate) fn manifest(self, files: BTreeMap<String, String>, actor_sha256: &str) -> Value {
        match self {
            Self::PythonV1 => json!({"schema":"product-cell-artifacts.v1","files":files}),
            Self::RustV1 => json!({"schema":"product-cell-artifacts.v2","files":files,
                "runtime":{"schema":"product-cell-native-runtime.v1","actor_sha256":actor_sha256}}),
        }
    }
}

pub(crate) fn verify_declared_artifacts(
    job_id: &str,
    config: &Value,
    manifest: &str,
) -> gauntlet_evidence::Result<ArtifactRuntime> {
    const INVALID: gauntlet_evidence::EvidenceError = gauntlet_evidence::EvidenceError::Invalid(
        "fixed private-cell artifact declaration required",
    );
    let declared = config["assets"]["private_cell"]["path"]
        .as_str()
        .ok_or(INVALID)?;
    let base = format!("hol-gauntlet/rust-shadow-candidates/{job_id}");
    let runtime = [ArtifactRuntime::PythonV1, ArtifactRuntime::RustV1]
        .into_iter()
        .find(|runtime| declared == format!("{base}/{}", runtime.target()))
        .ok_or(INVALID)?;
    if config["assets"]["private_cell"]["sha256"] != manifest {
        return Err(INVALID);
    }
    let initializer = config["runtime"]["private_cell"]["initializer_sha256"]
        .as_str()
        .ok_or(INVALID)?;
    runtime.verify(
        &std::path::Path::new("/opt").join(base),
        manifest,
        initializer,
    )?;
    Ok(runtime)
}
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn native_and_python_targets_and_public_modules_never_overlap() {
        assert_ne!(
            ArtifactRuntime::RustV1.target(),
            ArtifactRuntime::PythonV1.target()
        );
        let rust = ArtifactRuntime::RustV1.sources();
        assert!(!rust.contains_key("public/actor.py"));
        assert!(!rust
            .keys()
            .any(|p| p.starts_with("public/") && p.ends_with(".py")));
        let mut files: BTreeMap<_, _> = rust
            .iter()
            .map(|(p, b)| (p.clone(), format!("{:x}", Sha256::digest(b))))
            .collect();
        files.insert(NATIVE_CELL_ACTOR.into(), "a".repeat(64));
        files.insert("public/initializer".into(), "b".repeat(64));
        let manifest = ArtifactRuntime::RustV1.manifest(files, &"a".repeat(64));
        let raw = manifest.to_string();
        let pin = format!("{:x}", Sha256::digest(raw.as_bytes()));
        assert_eq!(
            gauntlet_evidence::verify_private_cell_manifest(raw.as_bytes(), &pin, &"b".repeat(64))
                .unwrap()
                .native_actor_sha256(),
            Some("a".repeat(64).as_str())
        );
    }
}
