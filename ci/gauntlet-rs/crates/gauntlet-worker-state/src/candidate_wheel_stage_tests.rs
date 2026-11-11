use super::*;
use rustix::fs::open;
use serde_json::json;
use std::io::Write;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

#[test]
fn unprivileged_staging_refuses_before_any_pins_or_files() {
    if geteuid().as_raw() == 0 {
        return;
    }
    assert_eq!(
        materialize_captured_candidate_wheel_ineligible("", "", "", "", ""),
        Err(CandidateWheelStageError::RootRequired)
    );
}

#[test]
#[ignore = "Root-owned fixture; run explicitly on the dedicated ARM VM"]
fn inert_stage_reads_back_every_file_and_refuses_replay_or_bad_wheel() {
    assert_eq!(geteuid().as_raw(), 0);
    let native = b"inert native bytes";
    let native_sha = format!("{:x}", Sha256::digest(native));
    let manifest = serde_json::to_vec(&json!({
        "schema":"hol-guard-native-runtime.v1",
        "source_sha":"a".repeat(40),
        "package_version":"3.49.0",
        "runtime_sha256":native_sha,
        "runtime_size":native.len(),
        "platform_tag":"linux_aarch64",
        "target":"aarch64-unknown-linux-gnu",
    }))
    .unwrap();
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    zip.start_file("codex_plugin_scanner/_native/hol-guard-runtime", options)
        .unwrap();
    zip.write_all(native).unwrap();
    zip.start_file(
        "codex_plugin_scanner/_native/runtime-manifest.json",
        options,
    )
    .unwrap();
    zip.write_all(&manifest).unwrap();
    zip.start_file("hol_guard-3.49.0.dist-info/METADATA", options)
        .unwrap();
    let metadata = b"Metadata-Version: 2.4\nName: hol-guard\nVersion: 3.49.0\n\n";
    zip.write_all(metadata).unwrap();
    let wheel = zip.finish().unwrap().into_inner();
    let declaration = CandidateArchiveDeclaration {
        source_sha: "a".repeat(40),
        version: "3.49.0".to_owned(),
        wheel: "hol_guard-3.49.0-py3-none-linux_aarch64.whl".to_owned(),
        wheel_sha256: format!("{:x}", Sha256::digest(&wheel)),
        native_sha256_claim: native_sha,
        wheel_bytes: wheel.len() as u64,
    };
    let scratch = tempfile::tempdir().unwrap();
    let job = open(
        scratch.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let (proof, directories) = materialize_wheel(&job, &wheel, &declaration).unwrap();
    assert_eq!(proof.entries, 3);
    assert_eq!(directories, 3);
    assert_eq!(
        proof.uncompressed_bytes,
        (native.len() + manifest.len() + metadata.len()) as u64
    );
    let inventory = inventory_tree(&scratch.path().join(STAGE), TreeKind::InstalledPrefix).unwrap();
    assert_eq!(inventory.entries, proof.entries + directories);
    assert_eq!(inventory.bytes, proof.uncompressed_bytes);
    assert_eq!(
        crate::candidate_capture::verify_stage(&job, scratch.path(), &wheel, &declaration).unwrap(),
        inventory
    );
    let runtime = scratch
        .path()
        .join("inert-wheel/codex_plugin_scanner/_native/hol-guard-runtime");
    std::fs::write(&runtime, b"different inert bytes").unwrap();
    assert!(
        crate::candidate_capture::verify_stage(&job, scratch.path(), &wheel, &declaration).is_err()
    );
    assert_eq!(std::fs::read(&runtime).unwrap(), b"different inert bytes");
    std::fs::write(&runtime, native).unwrap();
    let extra = scratch.path().join("inert-wheel/extra-empty-file");
    std::fs::write(&extra, b"").unwrap();
    assert!(
        crate::candidate_capture::verify_stage(&job, scratch.path(), &wheel, &declaration).is_err()
    );
    assert!(extra.exists());
    std::fs::remove_file(extra).unwrap();
    assert_eq!(
        crate::candidate_capture::verify_stage(&job, scratch.path(), &wheel, &declaration).unwrap(),
        inventory
    );
    assert_eq!(
        std::fs::read(
            scratch
                .path()
                .join("inert-wheel/codex_plugin_scanner/_native/hol-guard-runtime")
        )
        .unwrap(),
        native
    );
    assert_eq!(
        materialize_wheel(&job, &wheel, &declaration),
        Err(CandidateWheelStageError::ExistingStage)
    );
    let bad = tempfile::tempdir().unwrap();
    let bad_job = open(
        bad.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    assert_eq!(
        materialize_wheel(&bad_job, b"not a wheel", &declaration),
        Err(CandidateWheelStageError::WheelInvalid)
    );
    assert!(!bad.path().join(STAGE).exists());
}
