use super::*;

const JOB: &str = "0123456789abcdef";
fn fixture() -> (Value, Value, Vec<String>) {
    let identity = json!({"pid":42,"start_ticks":500,"executable_device":2,"executable_inode":3,
        "cgroup":format!("/holgauntletrust{JOB}.slice/hol-product-cell-{}.service","b".repeat(32)),
        "lsm_label":format!("hol-product-cell-{} (enforce)","b".repeat(32)),
        "namespaces":{"cgroup":"4:100","ipc":"4:101","mnt":"4:102","net":"4:103","pid":"4:104","user":"4:105","uts":"4:106"},
        "status":{"Uid":"10004 10004 10004 10004","Gid":"10004 10004 10004 10004","Groups":"","NSpid":"42 2",
            "NoNewPrivs":"1","Seccomp":"2","Seccomp_filters":"2","CapAmb":"0000000000000000","CapBnd":"0000000000000000",
            "CapEff":"0000000000000000","CapInh":"0000000000000000","CapPrm":"0000000000000000"}});
    let command = vec![
        "/usr/bin/python3".into(),
        "-I".into(),
        "-B".into(),
        "-c".into(),
        "print('measured')".into(),
    ];
    let wire = format!("{}\0", command.join("\0"));
    let row = json!({"pid":42,"start_ticks":500,"parent_pid":40,"pidfd_held":true,"executable_device":2,"executable_inode":3,
        "argv_utf8":wire,"argv_sha256":sha256(wire.as_bytes()),"executable_sha256":"a".repeat(64),
        "cgroup":identity["cgroup"],"lsm_label":identity["lsm_label"],"namespace_pids":[42,2],
        "namespaces":{"cgroup":100,"ipc":101,"mnt":102,"net":103,"pid":104,"user":105,"uts":106},
        "status":identity["status"],"limits":{"memory.max":"1073741824","pids.max":"128","cpu.max":"100000 100000"}});
    let observed = json!({"schema":"hol-gauntlet-outside-native-mcp-kernel.v1","deduplication":"pid-start-executable-inode-and-argv-v1",
        "observer_sha256":"d".repeat(64),"errors":[],"execution_eligible":false,"guard_causality_verified":false,"observations":[row]});
    (identity, observed, command)
}
fn accepts(identity: &Value, observed: &Value, command: &[String]) -> bool {
    KernelSamples::new(observed, &"d".repeat(64))
        .and_then(|s| matching(&s, identity, command, &"a".repeat(64), JOB).map(|_| ()))
        .is_ok()
}
#[test]
fn actual_product_tuple_and_physical_executable_generation_are_required() {
    let (identity, observed, command) = fixture();
    assert!(accepts(&identity, &observed, &command));
    for (pointer, value) in [
        ("/pid", json!(43)),
        ("/start_ticks", json!(501)),
        ("/executable_sha256", json!("f".repeat(64))),
        ("/executable_inode", json!(4)),
        ("/namespaces/mnt", json!(999)),
        ("/namespace_pids", json!([42, 3])),
        ("/status/Uid", json!("10004 10004 0 10004")),
        ("/status/CapEff", json!("0000000000000001")),
        ("/status/Groups", json!("10004 0")),
        ("/limits/pids.max", json!("max")),
        ("/pidfd_held", json!(false)),
    ] {
        let mut changed = observed.clone();
        *changed["observations"][0].pointer_mut(pointer).unwrap() = value;
        assert!(!accepts(&identity, &changed, &command), "{pointer}");
    }
}
#[test]
fn matching_good_sample_cannot_hide_a_conflicting_executable_or_privilege_tuple() {
    let (identity, observed, command) = fixture();
    for (field, value) in [
        ("executable_sha256", json!("e".repeat(64))),
        ("lsm_label", json!("unconfined")),
        ("cgroup", json!("/other")),
    ] {
        let mut changed = observed.clone();
        let mut row = changed["observations"][0].clone();
        row[field] = value;
        changed["observations"].as_array_mut().unwrap().push(row);
        assert!(!accepts(&identity, &changed, &command));
    }
    let mut wrong = identity.clone();
    wrong["lsm_label"] = json!("hol-product-cell-00000000000000000000000000000000 (complain)");
    assert!(!accepts(&wrong, &observed, &command));
    wrong = identity;
    wrong["cgroup"]=json!("/holgauntletrustfedcba9876543210.slice/hol-product-cell-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service");
    assert!(!accepts(&wrong, &observed, &command));
}
