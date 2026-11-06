use super::*;

const JOB: &str = "1234567890abcdef";
fn fixture() -> (Value, Value, Vec<String>) {
    let identity = json!({"pid":42,"start_ticks":500,"pidfd_held":true,
        "cgroup":format!("/holgauntletrust{JOB}.slice/libpod-{}.scope/container","b".repeat(64)),
        "lsm_label":format!("crun//&hol-gauntlet-sdk-{JOB}-{} (unconfined)","c".repeat(32)),
        "namespaces":{"cgroup":"4:100","ipc":"4:101","mnt":"4:102","net":"4:103","pid":"4:104","user":"4:105","uts":"4:106"},
        "status":{"Uid":"10001 10001 10001 10001","Gid":"10001 10001 10001 10001","Groups":"","NSpid":"42 2",
            "NoNewPrivs":"1","Seccomp":"2","Seccomp_filters":"1","CapAmb":"0000000000000000","CapBnd":"0000000000000000",
            "CapEff":"0000000000000000","CapInh":"0000000000000000","CapPrm":"0000000000000000"}});
    let argv = vec!["/runtime/bun".to_owned(), "/runtime/public/test.ts".into()];
    let wire = "/runtime/bun\0/runtime/public/test.ts\0";
    let row = json!({"pid":42,"start_ticks":500,"parent_pid":40,"pidfd_held":true,
        "argv_utf8":wire,"argv_sha256":sha256(wire.as_bytes()),"executable_sha256":"a".repeat(64),"executable_device":2,"executable_inode":3,
        "cgroup":identity["cgroup"],"lsm_label":identity["lsm_label"],"namespace_pids":[42,2],
        "namespaces":{"cgroup":100,"ipc":101,"mnt":102,"net":103,"pid":104,"user":105,"uts":106},
        "status":identity["status"],"limits":{"memory.max":"2147483648","pids.max":"256","cpu.max":"200000 100000"}});
    let observed = json!({"schema":"hol-gauntlet-outside-native-mcp-kernel.v1","deduplication":"pid-start-executable-inode-and-argv-v1",
        "observer_sha256":"d".repeat(64),"errors":[],"execution_eligible":false,"guard_causality_verified":false,"observations":[row]});
    (identity, observed, argv)
}
fn accepts(identity: &Value, observed: &Value, argv: &[String]) -> bool {
    KernelSamples::new(observed, &"d".repeat(64))
        .and_then(|s| {
            s.match_identity(identity, argv, &"a".repeat(64), JOB, "sdk")
                .map(|_| ())
        })
        .is_ok()
}
#[test]
fn separate_sample_checks_exact_executable_argv_and_kernel_tuple() {
    let (identity, observed, argv) = fixture();
    assert!(accepts(&identity, &observed, &argv));
    for (field, value) in [
        ("pid", json!(43)),
        ("start_ticks", json!(501)),
        ("argv_sha256", json!("f".repeat(64))),
        ("executable_sha256", json!("f".repeat(64))),
        ("pidfd_held", json!(false)),
        ("executable_inode", json!(true)),
    ] {
        let mut changed = observed.clone();
        changed["observations"][0][field] = value;
        assert!(!accepts(&identity, &changed, &argv), "{field}");
    }
    let mut missing = observed.clone();
    missing["observations"] = json!([]);
    assert!(!accepts(&identity, &missing, &argv));
}
#[test]
fn namespace_boolean_saved_uid_capability_and_profile_substitutions_refuse() {
    let (identity, observed, argv) = fixture();
    for (pointer, value) in [
        ("/namespaces/mnt", json!(999)),
        ("/namespaces/net", json!(true)),
        ("/status/Uid", json!("10001 10001 0 10001")),
        ("/status/Groups", json!("10001 0")),
        ("/status/CapBnd", json!("0000000000000001")),
        ("/status/Seccomp_filters", json!("0")),
        ("/status/NoNewPrivs", json!(true)),
        ("/limits/memory.max", json!("max")),
        ("/namespace_pids", json!([true, 2])),
    ] {
        let mut changed = observed.clone();
        *changed["observations"][0].pointer_mut(pointer).unwrap() = value;
        assert!(!accepts(&identity, &changed, &argv), "{pointer}");
    }
    for (from, to) in [
        ("sdk-", "mcp-"),
        ("crun//&", "other//&"),
        ("unconfined", "enforce"),
        (JOB, "1234567890abcdee"),
    ] {
        let mut changed = identity.clone();
        changed["lsm_label"] = json!(text(&identity, "lsm_label").unwrap().replace(from, to));
        assert!(!accepts(&changed, &observed, &argv));
    }
}
#[test]
fn contradictory_matching_sample_errors_and_wrong_observer_pin_refuse() {
    let (identity, mut observed, argv) = fixture();
    let mut other = observed["observations"][0].clone();
    other["limits"]["pids.max"] = json!("max");
    observed["observations"].as_array_mut().unwrap().push(other);
    assert!(!accepts(&identity, &observed, &argv));
    let (_, mut observed, _) = fixture();
    observed["errors"] = json!(["sample failed"]);
    assert!(!accepts(&identity, &observed, &argv));
    let (_, observed, _) = fixture();
    assert!(KernelSamples::new(&observed, &"e".repeat(64)).is_err());
}

fn v2_fixture() -> Value {
    let (_, mut observed, _) = fixture();
    observed["schema"] = json!("hol-gauntlet-outside-native-mcp-kernel.v2");
    observed["collection_limits"] = json!({
        "observations":2048,"argv_bytes":32768,"executable_bytes":134217728,
    });
    observed
}

#[test]
fn v2_collection_keeps_every_row_through_2048_and_refuses_overflow() {
    let mut observed = v2_fixture();
    let row = observed["observations"][0].clone();
    observed["observations"] = Value::Array(
        (0..2048)
            .map(|index| {
                let mut row = row.clone();
                row["pid"] = json!(42 + index);
                row["start_ticks"] = json!(500 + index);
                row
            })
            .collect(),
    );
    let samples = KernelSamples::new(&observed, &"d".repeat(64)).unwrap();
    assert_eq!(samples.rows.len(), 2048);
    observed["observations"].as_array_mut().unwrap().push(row);
    assert!(KernelSamples::new(&observed, &"d".repeat(64)).is_err());
    let mut observed = v2_fixture();
    observed["errors"] = json!(["kernel observation limit 2048 exhausted"]);
    assert!(KernelSamples::new(&observed, &"d".repeat(64)).is_err());
}

#[test]
fn v2_limits_are_closed_pinned_and_available_only_to_traced_launch_v3() {
    let observed = v2_fixture();
    let traced = json!({"schema":"hol-gauntlet-cell-supervisor.v3", "process_events":"outside-root-ptrace.v1"});
    assert!(KernelSamples::for_launch(&observed, &"d".repeat(64), &traced).is_ok());
    let stdio = json!({"schema":"hol-gauntlet-cell-supervisor.v4","process_events":"outside-root-ptrace.v2"});
    assert!(KernelSamples::for_launch(&observed, &"d".repeat(64), &stdio).is_ok());
    for launch in [
        json!({"schema":"hol-gauntlet-cell-supervisor.v1"}),
        json!({"schema":"hol-gauntlet-cell-supervisor.v2"}),
        json!({"schema":"hol-gauntlet-cell-supervisor.v3"}),
        json!({"schema":"hol-gauntlet-cell-supervisor.v3", "process_events":"other"}),
        json!({"schema":"hol-gauntlet-cell-supervisor.v4","process_events":"outside-root-ptrace.v1"}),
    ] {
        assert!(KernelSamples::for_launch(&observed, &"d".repeat(64), &launch).is_err());
    }
    for (pointer, value) in [
        ("/collection_limits/observations", json!(2049)),
        ("/collection_limits/argv_bytes", json!(65536)),
        ("/collection_limits/executable_bytes", json!(true)),
        ("/collection_limits", json!(null)),
        ("/observer_sha256", json!("e".repeat(64))),
        (
            "/schema",
            json!("hol-gauntlet-outside-native-mcp-kernel.v3"),
        ),
    ] {
        let mut changed = observed.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            KernelSamples::for_launch(&changed, &"d".repeat(64), &traced).is_err(),
            "{pointer}"
        );
    }
    let mut changed = observed;
    changed["ignored_overflow"] = json!(true);
    assert!(KernelSamples::for_launch(&changed, &"d".repeat(64), &traced).is_err());
    let (_, legacy, _) = fixture();
    assert!(KernelSamples::for_launch(&legacy, &"d".repeat(64), &json!(null)).is_ok());
}
