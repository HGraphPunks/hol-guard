use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};

pub(crate) fn task_value(tid: u64, tgid: u64, start: u64) -> Value {
    let mut status = json!({"Uid":"10004 10004 10004 10004","Gid":"10004 10004 10004 10004","Groups":"",
        "NoNewPrivs":"1","Seccomp":"2","Seccomp_filters":"2","NSpid":tid.to_string(),
        "TracerPid":"99","Threads":"1","Cpus_allowed_list":"0"});
    for name in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
        status[name] = json!("0000000000000000");
    }
    json!({"tid":tid,"tgid":tgid,"start_ticks":start,"parent_pid":1,"cgroup":"/test/owned","status":status})
}
pub(crate) fn image_value(tid: u64, tgid: u64, start: u64) -> Value {
    let mut ns = json!({});
    for name in crate::native_process_kernel::NAMESPACES {
        ns[name] = json!("1:2");
    }
    json!({"task":task_value(tid,tgid,start),"argv_base64":STANDARD.encode(b"fixture\0"),"argv_sha256":sha256(b"fixture\0"),
        "executable":{"device":1,"inode":3,"uid":0,"gid":0,"mode":0o555,"links":1,"bytes":100,"sha256":"a".repeat(64)},
        "lsm_label":"test (enforce)","namespaces":ns})
}
fn start() -> (&'static str, Value) {
    (
        "trace-start",
        json!({"id":0,"actor":image_value(42,42,7),"cgroup":"/test/owned",
        "options":["exit-kill","fork","vfork","clone","exec","exit","vfork-done"],
        "memory_or_register_mutation":false,"execution_eligible":false}),
    )
}
fn final_wait(id: u64, tid: u64, start: u64) -> (&'static str, Value) {
    (
        "task-final-wait",
        json!({"id":id,"tid":tid,"tgid":tid,"start_ticks":start,"status":{"kind":"exit","code":0},"death_observed":true}),
    )
}
fn complete(created: u64, finals: u64, replacements: u64, execs: u64) -> (&'static str, Value) {
    (
        "trace-complete",
        json!({"created_tasks":created,"final_waits":finals,"exec_retirements":replacements,"execs":execs,
        "active_tasks":0,"pending_births":0,"pending_stops":0,"execution_eligible":false}),
    )
}
pub(crate) fn pack(events: &[(&str, Value)]) -> (Vec<u8>, Value) {
    let mut raw = Vec::new();
    let mut previous = "0".repeat(64);
    for (sequence, (kind, data)) in events.iter().enumerate() {
        let row = json!({"schema":"hol-gauntlet-cell-event.v1","sequence":sequence,"previous_sha256":previous,"kind":kind,"data":data});
        let bytes = canonical_value(&row).unwrap();
        previous = sha256(&bytes);
        raw.extend(bytes);
        raw.push(b'\n');
    }
    let counts = &events.last().unwrap().1;
    let pin = json!({"schema":"hol-gauntlet-cell-journal-binding.v1","available":true,"events":events.len(),"bytes":raw.len(),
        "tail_sha256":previous,"device":1,"inode":2,"uid":0,"gid":0,"mode":0o600,"links":1});
    let checkpoint = json!({"schema":"hol-gauntlet-native-process-events.v1","complete":true,
        "created_tasks":counts["created_tasks"],"final_waits":counts["final_waits"],"exec_retirements":counts["exec_retirements"],"execs":counts["execs"],"journal":pin,"execution_eligible":false});
    (raw, checkpoint)
}
fn normal() -> Vec<(&'static str, Value)> {
    vec![
        start(),
        (
            "task-exit-stop",
            json!({"id":0,"tid":42,"status":{"kind":"exit","code":0},"death_observed":false}),
        ),
        final_wait(0, 42, 7),
        complete(1, 1, 0, 0),
    ]
}
fn nonleader() -> Vec<(&'static str, Value)> {
    vec![
        start(),
        (
            "kernel-creation",
            json!({"parent_id":0,"parent_tid":42,"child_tid":43,"creation":"clone"}),
        ),
        (
            "task-created",
            json!({"id":1,"parent_id":0,"parent_tid":42,"creation":"clone","task":task_value(43,42,8)}),
        ),
        (
            "task-exit-stop",
            json!({"id":0,"tid":42,"status":{"kind":"exit","code":0},"death_observed":false}),
        ),
        (
            "task-exec",
            json!({"id":1,"old_tid":43,"old_start_ticks":8,"retired":[{"id":0,"tid":42,"start_ticks":7,"reason":"kernel-exec-thread-replacement","final_wait_observed":false}],"image":image_value(42,42,7)}),
        ),
        final_wait(1, 42, 7),
        complete(2, 1, 1, 1),
    ]
}
fn check(events: &[(&str, Value)]) -> Result<Value> {
    let (raw, checkpoint) = pack(events);
    verify_native_process_events(&raw, &checkpoint)
}

#[test]
fn final_wait_is_required_and_complete_counts_are_independently_recomputed() {
    let rows = normal();
    let value = check(&rows).unwrap();
    assert_eq!(value["final_waits"], 1);
    assert_eq!(value["process_custody_authenticated"], false);
    assert_eq!(value["execution_eligible"], false);
    let mut missing = rows.clone();
    missing.remove(2);
    assert!(check(&missing).is_err());
    let mut early = rows.clone();
    early[1].1["death_observed"] = json!(true);
    assert!(check(&early).is_err());
    let mut false_total = rows.clone();
    false_total.last_mut().unwrap().1["final_waits"] = json!(2);
    assert!(check(&false_total).is_err());
    let mut after = rows;
    after.push(("signal-delivery", json!({"id":0,"tid":42,"signal":17})));
    assert!(check(&after).is_err());
}

#[test]
fn nonleader_exec_preserves_caller_and_explicitly_retires_the_old_leader() {
    let rows = nonleader();
    let value = check(&rows).unwrap();
    assert_eq!(value["created_tasks"], 2);
    assert_eq!(value["final_waits"], 1);
    assert_eq!(value["exec_retirements"], 1);
    for (field, value) in [
        ("old_tid", json!(42)),
        ("old_start_ticks", json!(9)),
        ("id", json!(0)),
        ("retired", json!([])),
    ] {
        let mut changed = rows.clone();
        changed[4].1[field] = value;
        assert!(check(&changed).is_err(), "{field}");
    }
    let mut invented = rows.clone();
    invented[4].1["retired"][0]["final_wait_observed"] = json!(true);
    assert!(check(&invented).is_err());
    let mut changed = rows;
    changed[5].1["start_ticks"] = json!(8);
    assert!(check(&changed).is_err());
}

#[test]
fn task_creation_requires_the_actual_live_parent_and_matching_kernel_child() {
    let rows = nonleader();
    for (index, field, value) in [
        (1, "parent_id", json!(7)),
        (1, "parent_tid", json!(9)),
        (1, "child_tid", json!(42)),
        (1, "creation", json!("unknown")),
        (2, "parent_id", json!(9)),
        (2, "id", json!(0)),
        (2, "creation", json!("fork")),
    ] {
        let mut changed = rows.clone();
        changed[index].1[field] = value;
        assert!(check(&changed).is_err(), "{index}/{field}");
    }
    let mut changed = rows;
    changed[2].1["task"]["tid"] = json!(44);
    assert!(check(&changed).is_err());
}

#[test]
fn changed_argv_kernel_identity_and_cross_tracer_observations_refuse_even_when_rechained() {
    let rows = nonleader();
    for (parent, field, value) in [
        ("executable", "inode", json!(true)),
        ("executable", "bytes", json!(134217729)),
        ("executable", "sha256", json!("A".repeat(64))),
        ("task", "start_ticks", json!(0)),
        ("namespaces", "user", json!("1:false")),
    ] {
        let mut changed = rows.clone();
        changed[4].1["image"][parent][field] = value;
        assert!(check(&changed).is_err(), "{parent}/{field}");
    }
    for (field, value) in [
        ("argv_base64", json!(STANDARD.encode(b"changed\0"))),
        ("argv_sha256", json!("c".repeat(64))),
        ("lsm_label", json!("test\nsecond")),
    ] {
        let mut changed = rows.clone();
        changed[4].1["image"][field] = value;
        assert!(check(&changed).is_err(), "{field}");
    }
    for (field, value) in [
        ("TracerPid", "100"),
        ("NSpid", "43"),
        ("Threads", "2"),
        ("CapBnd", "0"),
        ("Seccomp", "false"),
    ] {
        let mut changed = rows.clone();
        changed[4].1["image"]["task"]["status"][field] = json!(value);
        assert!(check(&changed).is_err(), "{field}");
    }
}

#[test]
fn altered_hash_chain_checkpoint_custody_or_incomplete_tail_is_not_completion() {
    let (raw, pin) = pack(&normal());
    let mut changed = raw.clone();
    changed[0] = b'[';
    assert!(verify_native_process_events(&changed, &pin).is_err());
    assert!(verify_native_process_events(&raw[..raw.len() - 1], &pin).is_err());
    for (field, value) in [
        ("tail_sha256", json!("f".repeat(64))),
        ("events", json!(true)),
        ("bytes", json!(1)),
        ("inode", json!(0)),
        ("uid", json!(10004)),
        ("mode", json!(0o644)),
        ("links", json!(2)),
        ("available", json!(false)),
    ] {
        let mut changed = pin.clone();
        changed["journal"][field] = value;
        assert!(
            verify_native_process_events(&raw, &changed).is_err(),
            "{field}"
        );
    }
    let mut failed = normal();
    failed[3] = (
        "trace-failed",
        json!({"complete":false,"execution_eligible":false,"error":"lost"}),
    );
    assert!(check(&failed).is_err());
}

#[test]
fn reused_numeric_pid_cannot_borrow_a_previous_generation_final_status() {
    let mut rows = vec![start()];
    for (id, start) in [(1, 8), (2, 9)] {
        rows.push((
            "kernel-creation",
            json!({"parent_id":0,"parent_tid":42,"child_tid":43,"creation":"fork"}),
        ));
        rows.push(("task-created",json!({"id":id,"parent_id":0,"parent_tid":42,"creation":"fork","task":task_value(43,43,start)})));
        rows.push(final_wait(id, 43, start));
    }
    rows.push(final_wait(0, 42, 7));
    rows.push(complete(3, 3, 0, 0));
    assert!(check(&rows).is_ok());
    rows[6].1["start_ticks"] = json!(8);
    assert!(check(&rows).is_err());
}
