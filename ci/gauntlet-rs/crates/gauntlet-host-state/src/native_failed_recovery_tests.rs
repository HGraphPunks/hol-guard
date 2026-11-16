use super::*;
#[test]
fn rehashed_manifest_cannot_erase_cleanup_history_or_add_unlisted_members() {
    let f = fixture();
    for erase in [true, false] {
        let mut files = crate::native_diagnostic_archive::members(&f.archive).unwrap();
        let mut manifest = parse(&files["results.sha256.json"]).unwrap();
        if erase {
            manifest["quiescent"]["recorded_cleanup_failures"] = json!([]);
        } else {
            files.insert("private-key".into(), b"unlisted".to_vec());
        }
        let manifest = bytes(&manifest).unwrap();
        files.insert("results.sha256.json".into(), manifest.clone());
        let raw = archive(&files);
        let mut e = f.export.clone();
        e["receipt"]["archive_sha256"] = json!(sha(&raw));
        e["receipt"]["archive_bytes"] = json!(raw.len());
        e["receipt"]["manifest_sha256"] = json!(sha(&manifest));
        e["receipt_sha256"] = json!(sha(&bytes(&e["receipt"]).unwrap()));
        assert!(protocol::archive(&f.j, &f.i, &f.f, &e, &raw).is_err());
    }
}

fn four_attempts(f: &Fixture, corrupt: bool) {
    f.j.write(
        f.i.job(),
        DOWNLOAD,
        &marker(&f.f, "download", &protocol::export_intent(&f.f)).unwrap(),
    )
    .unwrap();
    for n in 1..=4 {
        f.j.write(f.i.job(),&format!("readonly-failure-download-attempt-{n:04}"),&bytes(&json!({"schema":"hol-gauntlet-host-native-readonly-failure-attempt.v1","failure_intent_sha256":sha(&bytes(&f.f).unwrap()),"attempt":n,"operation":"failure-download-resume"})).unwrap()).unwrap();
        let mut h = artifact::create_private_archive(&f.j, archive_name(f.i.job(), n)).unwrap();
        if n < 4 {
            h.file.write_all(b"partial").unwrap();
        } else {
            let mut raw = f.archive.clone();
            if corrupt {
                raw[700] ^= 1;
            }
            h.file.write_all(&raw).unwrap();
        }
        h.file.sync_all().unwrap();
    }
    f.j.retain(f.i.job(), EXPORT, &bytes(&f.export).unwrap())
        .unwrap();
}
#[test]
fn fourth_complete_file_is_resealed_after_export_commit_without_a_new_stream_or_attempt() {
    for action in ["failure-download-read", "failure-download-resume"] {
        let f = fixture();
        four_attempts(&f, false);
        let mut m = Mock::new(&f);
        m.root = true;
        download(&f.j, &f.i, &f.f, action, &mut m).unwrap();
        assert_eq!(m.exports, 0);
        assert_eq!(m.calls, vec!["--read-native-readonly-failure-export-v1"]);
        let h = parse(&f.j.read(f.i.job(), RECEIPT).unwrap()).unwrap();
        assert_eq!(h["file"]["name"], archive_name(f.i.job(), 4));
        assert_eq!(h["archive_sha256"], f.export["receipt"]["archive_sha256"]);
        custody(&f.j, &f.i, &f.f).unwrap();
        assert!(f
            .j
            .absent(f.i.job(), "readonly-failure-download-attempt-0005")
            .unwrap());
    }
}
#[test]
fn fourth_full_file_with_changed_bytes_is_not_resealed_or_replaced() {
    let f = fixture();
    four_attempts(&f, true);
    let mut m = Mock::new(&f);
    m.root = true;
    assert!(download(&f.j, &f.i, &f.f, "failure-download-resume", &mut m).is_err());
    assert_eq!(m.exports, 0);
    assert_eq!(m.calls, vec!["--read-native-readonly-failure-export-v1"]);
    assert!(f.j.absent(f.i.job(), RECEIPT).unwrap());
    assert_eq!(
        fs::metadata(f.j.path.join(archive_name(f.i.job(), 4)))
            .unwrap()
            .len(),
        f.archive.len() as u64
    );
}
fn changed_archive(f: &Fixture, mut files: BTreeMap<String, Vec<u8>>) -> (Vec<u8>, Value) {
    let mut index = parse(&files["results.sha256.json"]).unwrap();
    for (name, raw) in files
        .iter()
        .filter(|(n, _)| n.as_str() != "results.sha256.json")
    {
        index["files"][name] = json!({"bytes":raw.len(),"sha256":sha(raw)});
        index["filesystem"][name]["bytes"] = json!(raw.len());
    }
    index["quiescent"]["supervisor_events_sha256"] =
        json!(sha(&files["cell/native-supervisor-events.v1.jsonl"]));
    let manifest = bytes(&index).unwrap();
    files.insert("results.sha256.json".into(), manifest.clone());
    let raw = archive(&files);
    let mut e = f.export.clone();
    e["receipt"]["manifest_sha256"] = json!(sha(&manifest));
    e["receipt"]["archive_sha256"] = json!(sha(&raw));
    e["receipt"]["archive_bytes"] = json!(raw.len());
    e["receipt_sha256"] = json!(sha(&bytes(&e["receipt"]).unwrap()));
    (raw, e)
}
#[test]
fn rehashed_recorder_pipe_startup_or_activity_claims_cannot_become_pre_ready_failure() {
    let f = fixture();
    for mutation in 0..7 {
        let mut files = crate::native_diagnostic_archive::members(&f.archive).unwrap();
        let raw = &files["cell/native-supervisor-events.v1.jsonl"];
        let mut rows = raw[..raw.len() - 1]
            .split(|b| *b == b'\n')
            .map(|line| parse(line).unwrap())
            .collect::<Vec<_>>();
        match mutation {
            0 => rows[5]["data"]["available"] = json!(true),
            1 => rows[6]["data"]["available"] = json!(true),
            2 => rows.swap(5, 6),
            3 => rows.insert(6, rows[5].clone()),
            4 => rows[5]["kind"] = json!("before-cell-gate"),
            5 => rows[3]["data"]["error"] = json!("different failure after ready"),
            _ => {
                rows.remove(6);
            }
        }
        let mut previous = "0".repeat(64);
        let mut events = Vec::new();
        for (n, mut row) in rows.into_iter().enumerate() {
            row["sequence"] = json!(n);
            row["previous_sha256"] = json!(previous);
            let raw = bytes(&row).unwrap();
            previous = sha(&raw);
            events.extend(raw);
            events.push(b'\n');
        }
        files.insert("cell/native-supervisor-events.v1.jsonl".into(), events);
        if mutation == 5 {
            let mut index = parse(&files["results.sha256.json"]).unwrap();
            index["quiescent"]["startup_error"] = json!("different failure after ready");
            files.insert("results.sha256.json".into(), bytes(&index).unwrap());
        }
        let (raw, e) = changed_archive(&f, files);
        assert!(
            protocol::archive(&f.j, &f.i, &f.f, &e, &raw).is_err(),
            "mutation {mutation}"
        );
    }
}
