use super::*;
use crate::native_process_events::tests::{image_value, pack};

fn declaration() -> Value {
    json!({"mode":"outside-root-native-stdio.v1","native_runtime_sha256":"b".repeat(64),
        "scope":"owned-product-native-stream","memory_or_register_mutation":false,
        "atomic_kernel_pipe_bytes_verified":false,"concurrent_tracees_frozen":false,"execution_eligible":false})
}
fn fixture() -> (Vec<u8>, Value, Vec<(&'static str, Value)>) {
    let actor = image_value(42, 42, 7);
    let mut native = actor.clone();
    let command=b"/product/runtime/hol-guard-runtime\0resident-client-stream\0--stdin\0/product/guard/native-runtime\0";
    native["argv_base64"] = json!(STANDARD.encode(command));
    native["argv_sha256"] = json!(sha256(command));
    native["executable"]["sha256"] = json!("b".repeat(64));
    let process = vec![
        (
            "trace-start",
            json!({"id":0,"actor":actor,"cgroup":"/test/owned",
            "options":["exit-kill","fork","vfork","clone","exec","exit","vfork-done","syscall-good"],
            "native_stdio":declaration(),"memory_or_register_mutation":false,"execution_eligible":false}),
        ),
        (
            "task-exec",
            json!({"id":0,"old_tid":42,"old_start_ticks":7,"retired":[],"image":native}),
        ),
        (
            "task-exit-stop",
            json!({"id":0,"tid":42,"status":{"kind":"exit","code":0},"death_observed":false}),
        ),
        (
            "task-final-wait",
            json!({"id":0,"tid":42,"tgid":42,"start_ticks":7,
            "status":{"kind":"exit","code":0},"death_observed":true}),
        ),
        (
            "trace-complete",
            json!({"created_tasks":1,"final_waits":1,"exec_retirements":0,"execs":1,
            "active_tasks":0,"pending_births":0,"pending_stops":0,"execution_eligible":false}),
        ),
    ];
    let (process_raw, mut checkpoint) = pack(&process);
    checkpoint["schema"] = json!("hol-gauntlet-native-process-events.v2");
    let payload = b"\0\0\0\x07{\"x\":1}";
    let mut rows = vec![
        (
            "stdio-start",
            json!({"declaration":declaration(),"actor_argv_sha256":actor["argv_sha256"],
            "actor_executable_sha256":actor["executable"]["sha256"],"actor_tid":42,"actor_start_ticks":7,"cgroup":"/test/owned"}),
        ),
        (
            "stdio-selected",
            json!({"stream":1,"task_id":0,"tid":42,"tgid":42,"start_ticks":7,
            "process_exec_sequence":1,"argv_sha256":native["argv_sha256"],"executable_sha256":"b".repeat(64),
            "pipes":{"stdin":{"device":1,"inode":50},"stdout":{"device":1,"inode":51},
                "held_with":"O_PATH","pipe_readers_or_writers_added":false}}),
        ),
    ];
    for (call, number, fd, direction) in [(1, 63, 0, "read"), (2, 64, 1, "write")] {
        rows.push((
            "stdio-call",
            json!({"stream":1,"call":call,"syscall":number,"descriptor":fd,
            "direction":direction,"requested":payload.len(),"vector_lengths":[payload.len()]}),
        ));
        rows.push((
            "stdio-transfer",
            json!({"stream":1,"call":call,"result":payload.len(),"is_error":false,
            "completed":payload.len(),"bytes":payload.len(),"sha256":sha256(payload)}),
        ));
        rows.push((
            "stdio-bytes",
            json!({"stream":1,"call":call,"offset":0,"base64":STANDARD.encode(payload)}),
        ));
    }
    rows.push((
        "stdio-ended",
        json!({"stream":1,"tid":42,"reason":"final-wait",
        "interrupted_stdio_call":null,"pending_syscall_number":94,"pipe_eof_inferred":false}),
    ));
    rows.push((
        "stdio-complete",
        json!({"streams":1,"closed_streams":1,"calls":2,"syscall_stops":5,"bytes":payload.len()*2}),
    ));
    (process_raw, checkpoint, rows)
}
fn encode(rows: &[(&str, Value)], checkpoint: &Value) -> (Vec<u8>, Value) {
    let (raw, pin) = pack(rows);
    let mut checkpoint = checkpoint.clone();
    checkpoint["native_stdio"] = json!({"schema":"hol-gauntlet-native-stdio.v1","complete":true,
        "declaration":declaration(),"counts":rows.last().unwrap().1,"journal":pin["journal"],
        "execution_eligible":false});
    (raw, checkpoint)
}
#[test]
fn actual_exec_end_relation_and_complete_json_frames_do_not_grant_wire_or_custody_credit() {
    let (process, checkpoint, rows) = fixture();
    let (raw, checkpoint) = encode(&rows, &checkpoint);
    let value = verify_native_stdio_events(&raw, &process, &checkpoint).unwrap();
    assert_eq!(value["complete_frames"], 2);
    assert_eq!(
        value["streams"][0]["read"]["frames"][0]["json_object"],
        true
    );
    assert_eq!(value["streams"][0]["read_eof_observed"], false);
    for key in [
        "atomic_kernel_pipe_bytes_verified",
        "concurrent_memory_authenticated",
        "request_semantics_verified",
        "outside_observer_admitted",
        "execution_eligible",
    ] {
        assert_eq!(value[key], false, "{key}");
    }
}
#[test]
fn rehashed_semantic_forgery_wrong_task_pipe_transfer_order_and_completion_refuse() {
    let (process, checkpoint, rows) = fixture();
    for (row, key, bad) in [
        (1, "process_exec_sequence", json!(2)),
        (1, "tid", json!(43)),
        (
            1,
            "pipes",
            json!({"stdin":{"device":1,"inode":50},"stdout":{"device":1,"inode":50},
            "held_with":"O_PATH","pipe_readers_or_writers_added":false}),
        ),
        (2, "descriptor", json!(9)),
        (2, "requested", json!(8 * 1024 * 1024 + 1)),
        (3, "completed", json!(999)),
        (3, "is_error", json!(true)),
        (4, "offset", json!(1)),
        (4, "call", json!(3)),
        (8, "reason", json!("exec-replacement")),
        (8, "pipe_eof_inferred", json!(true)),
        (9, "bytes", json!(0)),
    ] {
        let mut changed = rows.clone();
        changed[row].1[key] = bad;
        let (raw, pin) = encode(&changed, &checkpoint);
        assert!(
            verify_native_stdio_events(&raw, &process, &pin).is_err(),
            "{row} {key}"
        );
    }
    let mut changed = rows.clone();
    changed.remove(2);
    let (raw, pin) = encode(&changed, &checkpoint);
    assert!(verify_native_stdio_events(&raw, &process, &pin).is_err());
    let mut changed = rows.clone();
    changed.remove(1);
    let (raw, pin) = encode(&changed, &checkpoint);
    assert!(verify_native_stdio_events(&raw, &process, &pin).is_err());
}
#[test]
fn checkpoint_options_and_version_cannot_lend_stdio_credit_to_legacy_history() {
    let (process, checkpoint, rows) = fixture();
    let (raw, pin) = encode(&rows, &checkpoint);
    for (key, bad) in [
        ("schema", json!("hol-gauntlet-native-process-events.v1")),
        ("complete", json!(false)),
    ] {
        let mut changed = pin.clone();
        changed[key] = bad;
        assert!(verify_native_stdio_events(&raw, &process, &changed).is_err());
    }
    for pointer in [
        "/native_stdio/declaration/concurrent_tracees_frozen",
        "/native_stdio/declaration/atomic_kernel_pipe_bytes_verified",
        "/native_stdio/execution_eligible",
    ] {
        let mut changed = pin.clone();
        *changed.pointer_mut(pointer).unwrap() = json!(true);
        assert!(verify_native_stdio_events(&raw, &process, &changed).is_err());
    }
    assert!(verify_native_stdio_events(&raw[..raw.len() - 1], &process, &pin).is_err());
    let mut events = process::events(&process).unwrap();
    events[0]["data"]["options"].as_array_mut().unwrap().pop();
    let events = events
        .iter()
        .map(|r| (r["kind"].as_str().unwrap(), r["data"].clone()))
        .collect::<Vec<_>>();
    let (process, mut cp) = pack(&events);
    cp["schema"] = pin["schema"].clone();
    cp["native_stdio"] = pin["native_stdio"].clone();
    assert!(verify_native_stdio_events(&raw, &process, &cp).is_err());
}
