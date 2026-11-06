use super::*;
use crate::crypto::sha256;
use crate::native_process_events::tests::{image_value, pack, task_value};

fn image(tid: u64, tgid: u64, start: u64, native: bool, argv: &[u8]) -> Value {
    let mut image = image_value(tid, tgid, start);
    image["argv_base64"] = json!(STANDARD.encode(argv));
    image["argv_sha256"] = json!(sha256(argv));
    image["executable"]["sha256"] = json!(if native { "b" } else { "a" }.repeat(64));
    image
}
fn birth(
    id: u64,
    parent: u64,
    tid: u64,
    tgid: u64,
    start: u64,
    parent_tid: u64,
    kind: &str,
) -> Vec<(&'static str, Value)> {
    vec![
        (
            "kernel-creation",
            json!({"parent_id":parent,"parent_tid":parent_tid,"child_tid":tid,"creation":kind}),
        ),
        (
            "task-created",
            json!({"id":id,"parent_id":parent,"parent_tid":parent_tid,"creation":kind,"task":task_value(tid,tgid,start)}),
        ),
    ]
}
fn exec(id: u64, tid: u64, start: u64, image: Value, retired: Value) -> (&'static str, Value) {
    (
        "task-exec",
        json!({"id":id,"old_tid":tid,"old_start_ticks":start,"retired":retired,"image":image}),
    )
}
fn final_wait(id: u64, tid: u64, tgid: u64, start: u64) -> (&'static str, Value) {
    (
        "task-final-wait",
        json!({"id":id,"tid":tid,"tgid":tgid,"start_ticks":start,"status":{"kind":"exit","code":0},"death_observed":true}),
    )
}
fn complete(created: u64, finals: u64, retired: u64, execs: u64) -> (&'static str, Value) {
    (
        "trace-complete",
        json!({"created_tasks":created,"final_waits":finals,"exec_retirements":retired,"execs":execs,"active_tasks":0,"pending_births":0,"pending_stops":0,"execution_eligible":false}),
    )
}
fn start() -> (&'static str, Value) {
    (
        "trace-start",
        json!({"id":0,"actor":image(42,42,7,false,b"/public/gauntlet-product-cell\0actor\0"),"cgroup":"/test/owned",
        "options":["exit-kill","fork","vfork","clone","exec","exit","vfork-done"],"memory_or_register_mutation":false,"execution_eligible":false}),
    )
}
fn gate() -> Value {
    image(
        43,
        43,
        8,
        false,
        b"/public/gauntlet-product-cell\0exec-gate\0/prefix/bin/python\0",
    )
}
fn gates() -> BTreeMap<GateKey, usize> {
    BTreeMap::from([((43, 8, gate()["argv_sha256"].as_str().unwrap().into()), 17)])
}
fn graph() -> Vec<(&'static str, Value)> {
    let mut rows = vec![start()];
    rows.extend(birth(1, 0, 43, 43, 8, 42, "fork"));
    rows.push(exec(1, 43, 8, gate(), json!([])));
    rows.extend(birth(2, 1, 44, 44, 9, 43, "fork"));
    rows.push(exec(
        2,
        44,
        9,
        image(
            44,
            44,
            9,
            true,
            b"/prefix/hol-guard-runtime\0capabilities\0--json\0",
        ),
        json!([]),
    ));
    rows.extend(birth(3, 2, 45, 44, 10, 44, "clone"));
    rows.push(final_wait(3, 45, 44, 10));
    rows.push(final_wait(2, 44, 44, 9));
    // The kernel reuses PID 44. Its new monotonic task ID keeps the older
    // Native task's history and the new gate ancestry separate.
    rows.extend(birth(4, 1, 44, 44, 11, 43, "fork"));
    rows.push(exec(
        4,
        44,
        11,
        image(
            44,
            44,
            11,
            true,
            b"/tmp/compiler/hol-guard-runtime\0bundle-metadata\0",
        ),
        json!([]),
    ));
    rows.push(final_wait(4, 44, 44, 11));
    rows.push(final_wait(1, 43, 43, 8));
    rows.push(final_wait(0, 42, 42, 7));
    rows.push(complete(5, 5, 0, 3));
    rows
}
fn checked(rows: &[(&str, Value)], gates: &BTreeMap<GateKey, usize>) -> Result<Value> {
    let (raw, checkpoint) = pack(rows);
    crate::verify_native_process_events(&raw, &checkpoint)?;
    let events = raw
        .split(|b| *b == b'\n')
        .filter(|v| !v.is_empty())
        .map(parse)
        .collect::<Result<Vec<_>>>()?;
    inventory(&events, &"b".repeat(64), gates)
}

#[test]
fn complete_lineage_accounts_for_native_execs_inheritance_aliases_and_pid_reuse() {
    let result = checked(&graph(), &gates()).unwrap();
    assert_eq!(result["created_tasks"], 5);
    assert_eq!(result["native_exec_images_checked"], 2);
    assert_eq!(result["tasks_with_observed_or_inherited_native_image"], 3);
    assert_eq!(result["native_image_inheritances"], 1);
    assert_eq!(result["native_execs"][0]["task_id"], 2);
    assert_eq!(result["native_execs"][1]["task_id"], 4);
    for row in result["native_execs"].as_array().unwrap() {
        assert_eq!(row["gate_sequence"], 17);
        assert_eq!(row["parent_task_id"], 1);
    }
    for name in [
        "internal_native_request_bytes_checked",
        "inherited_memory_contents_authenticated",
        "effect_writer_attribution_checked",
        "all_native_runtime_descendants_graded",
        "outside_observer_admitted",
        "outside_signing_key_admitted",
        "execution_eligible",
        "guard_causality_verified",
    ] {
        assert_eq!(result[name], false, "{name}");
    }
}

#[test]
fn nonleader_exec_keeps_the_birth_lineage_after_kernel_leader_replacement() {
    let mut rows = vec![start()];
    rows.extend(birth(1, 0, 43, 43, 8, 42, "fork"));
    rows.push(exec(1, 43, 8, gate(), json!([])));
    rows.extend(birth(2, 1, 44, 43, 9, 43, "clone"));
    let retired = json!([{"id":1,"tid":43,"start_ticks":8,"reason":"kernel-exec-thread-replacement","final_wait_observed":false}]);
    rows.push(exec(2,44,9,image(43,43,8,true,b"/prefix/hol-guard-runtime\0resident-client-stream\0--stdin\0/product/guard/native-runtime\0"),retired));
    rows.push(final_wait(2, 43, 43, 8));
    rows.push(final_wait(0, 42, 42, 7));
    rows.push(complete(3, 2, 1, 2));
    let value = checked(&rows, &gates()).unwrap();
    assert_eq!(value["native_execs"][0]["task_id"], 2);
    assert_eq!(value["native_execs"][0]["pid"], 43);
    assert_eq!(value["native_execs"][0]["gate_sequence"], 17);
}

#[test]
fn missing_or_changed_gate_identity_cannot_supply_a_native_ancestor() {
    assert!(checked(&graph(), &BTreeMap::new()).is_err());
    for key in [
        (43, 9, gate()["argv_sha256"].as_str().unwrap().into()),
        (44, 8, gate()["argv_sha256"].as_str().unwrap().into()),
        (43, 8, "0".repeat(64)),
    ] {
        assert!(checked(&graph(), &BTreeMap::from([(key, 17)])).is_err());
    }
    let mut rows = graph();
    rows[5].1["parent_id"] = json!(0);
    assert!(checked(&rows, &gates()).is_err());
}

#[test]
fn named_native_binary_with_other_bytes_or_relaxed_native_floors_refuses() {
    for (pointer, value) in [
        ("/executable/sha256", json!("c".repeat(64))),
        ("/task/status/Uid", json!("0 0 0 0")),
        ("/task/status/Gid", json!("0 0 0 0")),
        ("/task/status/Groups", json!("10004")),
        ("/task/status/NoNewPrivs", json!("0")),
        ("/task/status/Seccomp", json!("0")),
        ("/task/status/CapEff", json!("0000000000000001")),
        ("/namespaces/pid", json!("1:3")),
        ("/lsm_label", json!("unconfined")),
    ] {
        let mut rows = graph();
        *rows[6].1["image"].pointer_mut(pointer).unwrap() = value;
        assert!(checked(&rows, &gates()).is_err(), "{pointer}");
    }
    let mut inherited = graph();
    inherited[8].1["task"]["status"]["NoNewPrivs"] = json!("0");
    assert!(checked(&inherited, &gates()).is_err());
}

#[test]
fn unknown_non_native_image_and_binary_arguments_never_gain_native_credit() {
    let mut rows = graph();
    rows[6].1["image"] = image(44, 44, 9, false, b"/usr/bin/tool\0\xff\0");
    let result = checked(&rows, &gates()).unwrap();
    assert_eq!(result["native_exec_images_checked"], 1);
    assert_eq!(result["native_image_inheritances"], 0);
    assert_eq!(result["tasks_with_observed_or_inherited_native_image"], 1);
    assert_eq!(result["all_native_runtime_descendants_graded"], false);
}

#[test]
fn incomplete_history_cannot_turn_an_early_exit_into_complete_native_lineage() {
    let mut rows = graph();
    rows.remove(14);
    assert!(checked(&rows, &gates()).is_err());
    let mut changed = graph();
    changed[6].1["id"] = json!(4);
    assert!(checked(&changed, &gates()).is_err());
}

fn delayed_child(native_before_fork: bool) -> Vec<(&'static str, Value)> {
    let mut rows = vec![start()];
    rows.extend(birth(1, 0, 43, 43, 8, 42, "fork"));
    rows.push(exec(1, 43, 8, gate(), json!([])));
    rows.extend(birth(2, 1, 44, 44, 9, 43, "fork"));
    let native = b"/prefix/hol-guard-runtime\0capabilities\0--json\0";
    let other = b"/usr/bin/tool\0--version\0";
    rows.push(exec(
        2,
        44,
        9,
        image(
            44,
            44,
            9,
            native_before_fork,
            if native_before_fork { native } else { other },
        ),
        json!([]),
    ));
    let child = birth(3, 2, 45, 45, 10, 44, "fork");
    rows.push(child[0].clone());
    // This independent forked child has not reached its first consumed stop.
    // Parent exec cannot retroactively change its inherited address space.
    rows.push(exec(
        2,
        44,
        9,
        image(
            44,
            44,
            9,
            !native_before_fork,
            if native_before_fork { other } else { native },
        ),
        json!([]),
    ));
    rows.push(child[1].clone());
    rows.push(final_wait(3, 45, 45, 10));
    rows.push(final_wait(2, 44, 44, 9));
    rows.push(final_wait(1, 43, 43, 8));
    rows.push(final_wait(0, 42, 42, 7));
    rows.push(complete(4, 4, 0, 3));
    rows
}

#[test]
fn native_fork_inheritance_survives_parent_exec_before_the_child_stop() {
    let value = checked(&delayed_child(true), &gates()).unwrap();
    assert_eq!(value["native_image_inheritances"], 1);
    assert_eq!(value["tasks_with_observed_or_inherited_native_image"], 2);
}

#[test]
fn later_parent_native_exec_cannot_backfill_a_preceding_child_fork() {
    let value = checked(&delayed_child(false), &gates()).unwrap();
    assert_eq!(value["native_image_inheritances"], 0);
    assert_eq!(value["tasks_with_observed_or_inherited_native_image"], 1);
}

#[test]
fn large_native_argv_stays_bound_without_expanding_the_public_readback() {
    for long_operation in [false, true] {
        let mut argv = b"/prefix/hol-guard-runtime\0".to_vec();
        if !long_operation {
            argv.extend(b"capabilities\0");
        }
        argv.extend(vec![1; 64000]);
        argv.push(0);
        let mut rows = graph();
        rows[6].1["image"] = image(44, 44, 9, true, &argv);
        let result = checked(&rows, &gates()).unwrap();
        assert_eq!(result["native_execs"][0]["argv_sha256"], sha256(&argv));
        assert!(crate::canonical_value(&result).unwrap().len() < 8192);
        if long_operation {
            assert!(result["native_execs"][0]["operation"].is_null());
        } else {
            assert_eq!(result["native_execs"][0]["operation"], "capabilities");
        }
    }
}
