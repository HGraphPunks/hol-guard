use super::*;
use std::os::unix::fs::PermissionsExt;

fn archive(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, raw, kind) in entries {
        let mut h = tar::Header::new_ustar();
        h.set_size(raw.len() as u64);
        h.set_mode(0o600);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_entry_type(*kind);
        h.set_cksum();
        builder.append_data(&mut h, name, *raw).unwrap();
    }
    builder.into_inner().unwrap()
}
#[test]
fn public_archive_refuses_duplicates_links_extensions_and_nonzero_tail() {
    let valid = archive(&[("public.json", b"{}", tar::EntryType::Regular)]);
    assert_eq!(members(&valid).unwrap()["public.json"], b"{}");
    let duplicate = archive(&[
        ("x", b"1", tar::EntryType::Regular),
        ("x", b"2", tar::EntryType::Regular),
    ]);
    assert!(members(&duplicate).is_err());
    for kind in [
        tar::EntryType::Symlink,
        tar::EntryType::Link,
        tar::EntryType::Directory,
        tar::EntryType::XHeader,
        tar::EntryType::GNULongName,
    ] {
        assert!(members(&archive(&[("x", b"", kind)])).is_err());
    }
    let mut trailing = valid.clone();
    trailing.extend_from_slice(&[1; 512]);
    assert!(members(&trailing).is_err());
    assert!(members(&valid[..1024]).is_err());
    let mut outside = valid;
    outside[..100].fill(0);
    outside[..6].copy_from_slice(b"../bad");
    let mut h = tar::Header::new_ustar();
    h.as_mut_bytes().copy_from_slice(&outside[..512]);
    h.set_cksum();
    outside[..512].copy_from_slice(h.as_bytes());
    assert!(members(&outside).is_err());
}
#[test]
fn descriptor_reader_requires_exact_pin_and_safe_file_and_ancestry() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let raw = archive(&[("public.json", b"{}", tar::EntryType::Regular)]);
    let path = root.join("public.tar");
    std::fs::write(&path, &raw).unwrap();
    assert_eq!(read_stable(&path, &sha(&raw)).unwrap(), raw);
    assert!(read_stable(&path, &"0".repeat(64)).is_err());
    let symlink = root.join("link.tar");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    assert!(read_stable(&symlink, &sha(&raw)).is_err());
    let directory_link = root.join("alias");
    std::os::unix::fs::symlink(&root, &directory_link).unwrap();
    assert!(read_stable(&directory_link.join("public.tar"), &sha(&raw)).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(read_stable(&path, &sha(&raw)).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let hard = root.join("hard.tar");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(read_stable(&path, &sha(&raw)).is_err());
}

#[test]
fn normal_report_authenticates_retained_completion_and_preserves_incomplete_judgment() {
    use serde_json::json;
    let encode = |v: &Value| canonicalize(v.to_string().as_bytes()).unwrap();
    let source = "2".repeat(40);
    let job = "1".repeat(16);
    let generation = "4".repeat(64);
    let preparation =
        json!({"runtime_prefix":format!("/opt/hol-gauntlet/candidates/{source}/prefix")});
    let prep_raw = encode(&preparation);
    let declaration = json!({"schema":"hol-gauntlet-native-worker-job.v7","profile":"native-host-pinned-control-v1",
        "source_sha":source,"job_id":job,"worker_generation":generation,"preparation_sha256":sha(&prep_raw),
        "guard":{"source_sha":source},"role":"timeout"});
    let decl_raw = encode(&declaration);
    let (temp, expected, _, completion) = crate::native_control_readback::tests::fixture_with_pins(
        "timeout",
        &sha(&decl_raw),
        &sha(&prep_raw),
    );
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("hol-report-fixture")).unwrap();
    let intent = json!({"schema":"hol-gauntlet-host-native-intent.v1","job_id":job,"source_sha":source,
        "deployment_digest":expected.deployment_digest,"worker_generation":generation,"preparation_sha256":sha(&prep_raw),
        "role":"timeout","vm":"hol-report-fixture","limactl":"/opt/homebrew/bin/limactl","lima_sha256":"8".repeat(64),
        "interpreter_sha256":"9".repeat(64),"observer_sha256":"a".repeat(64),
        "transport_context":crate::native_operation::context::TransportContext::from_paths(&root,&root,"hol-report-fixture").unwrap().value()});
    let intent_raw = encode(&intent);
    let dispatch = json!({"schema":"hol-gauntlet-host-native-dispatch.v1","job_id":job,"intent_sha256":sha(&intent_raw),"retry_allowed":false});
    for (suffix, raw) in [
        ("intent", intent_raw.clone()),
        ("dispatch", encode(&dispatch)),
        ("completion", encode(&completion)),
    ] {
        let path = root.join(format!("{job}.native-{suffix}.json"));
        std::fs::write(&path, raw).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let report_raw = encode(&completion["report"]);
    let raw = archive(&[
        (
            "combined/worker/report.json",
            &report_raw,
            tar::EntryType::Regular,
        ),
        (
            "combined/preparation.v1.json",
            &prep_raw,
            tar::EntryType::Regular,
        ),
        (
            "combined/declaration.json",
            &decl_raw,
            tar::EntryType::Regular,
        ),
    ]);
    let path = root.join("public.tar");
    std::fs::write(&path, &raw).unwrap();
    let args = vec![
        "report".into(),
        root.to_str().unwrap().into(),
        job.clone(),
        sha(&intent_raw),
        path.to_str().unwrap().into(),
        sha(&raw),
    ];
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(crate::run_native_operation_command(&args).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let value = crate::run_native_operation_command(&args).unwrap();
    assert_eq!(
        value["independent_judgment"]["judgment"]["independent_grade"],
        "invalid-evidence"
    );
    assert_eq!(
        value["independent_judgment"]["judgment"]["evidence_validity"],
        "incomplete"
    );
    assert_eq!(value["execution_eligible"], false);
    assert_eq!(value["qualification_eligible"], false);
    for forbidden in [
        "controller_public_key_hex",
        "controller_envelope_utf8",
        "prelaunch_custody",
        "task_mounts",
    ] {
        assert!(!value.to_string().contains(forbidden), "{forbidden}");
    }
    assert_eq!(crate::run_native_operation_command(&args).unwrap(), value);
    let reports = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains("native-judgment-"))
        .collect::<Vec<_>>();
    assert_eq!(reports.len(), 1);
    assert_eq!(
        reports[0].metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut wrong = args.clone();
    wrong[5] = "0".repeat(64);
    assert!(crate::run_native_operation_command(&wrong).is_err());
}
