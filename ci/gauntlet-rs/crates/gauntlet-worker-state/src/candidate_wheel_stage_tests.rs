use super::*;
use rustix::fs::open;
use serde_json::json;
use std::io::Write;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

#[test]
fn failed_build_ustar_preserves_binary_empty_logs_and_unknown_usage() {
    use crate::native_public_archive::{encode_failed, PublicFiles};
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };
    let temp = tempfile::tempdir().unwrap();
    let root = open(
        temp.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let capture = || {
        let mut files = PublicFiles::default();
        for (name, raw) in [
            ("candidate-run.stdout.log", b"".as_slice()),
            ("candidate-run.stderr.log", b"\0\xff\n".as_slice()),
        ] {
            let path = temp.path().join(name);
            if !path.exists() {
                std::fs::write(&path, raw).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let s = std::fs::metadata(path).unwrap();
            assert!(files
                .capture(&root, name, name, (s.uid(), s.gid()), 0o600)
                .unwrap());
        }
        files
    };
    let raw = encode_failed(capture(), json!({"exit_code":1})).unwrap();
    assert_eq!(
        raw,
        encode_failed(capture(), json!({"exit_code":1})).unwrap()
    );
    let mut archive = tar::Archive::new(raw.as_slice());
    let mut names = Vec::new();
    for row in archive.entries().unwrap() {
        let mut row = row.unwrap();
        assert!(row.header().as_ustar().is_some());
        assert_eq!(row.header().mode().unwrap(), 0o600);
        let name = row.path().unwrap().to_str().unwrap().to_owned();
        let mut bytes = Vec::new();
        row.read_to_end(&mut bytes).unwrap();
        if name == "results.sha256.json" {
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v["schema"], "hol-gauntlet-failed-build-evidence.v1");
            assert_eq!(v["exit_code"], 1);
            assert!(v["model_requests"].is_null());
        } else {
            assert_eq!(
                bytes,
                if name.ends_with("stdout.log") {
                    b"".as_slice()
                } else {
                    b"\0\xff\n".as_slice()
                }
            );
        }
        names.push(name);
    }
    assert_eq!(
        names,
        [
            "candidate-run.stderr.log",
            "candidate-run.stdout.log",
            "results.sha256.json"
        ]
    );
}

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
