use super::*;
use crate::native_process_events::tests::{image_value, pack, pipes, task_value};
use std::collections::BTreeMap;

fn snapshot(image: &Value) -> Value {
    let mut ns = json!({});
    let decode = |name| {
        let (a, b) = image["namespaces"][name]
            .as_str()
            .unwrap()
            .split_once(':')
            .unwrap();
        json!({"device":a.parse::<u64>().unwrap(),"inode":b.parse::<u64>().unwrap()})
    };
    let user = decode("user");
    for name in NAMESPACES {
        ns[name] = decode(name);
        ns[name]["owner_user_namespace"] = if name == "user" {
            Value::Null
        } else {
            user.clone()
        };
    }
    json!({"schema":SCHEMA,"namespaces":ns,"user_namespace_chain":[user],
        "user_namespace_chain_end_reason":"parent-unavailable","uid_map":[[0,0,u32::MAX]],
        "gid_map":[[0,0,u32::MAX]],"setgroups":"allow","lsm_label":image["lsm_label"]})
}
pub(crate) fn attach(rows: &mut [(&str, Value)]) {
    let original = snapshot(&rows[0].1["actor"]);
    for (kind, data) in rows {
        match *kind {
            "trace-start" => data["actor"]["task"]["isolation"] = original.clone(),
            "task-created" => data["task"]["isolation"] = original.clone(),
            "task-exec" => data["image"]["task"]["isolation"] = snapshot(&data["image"]),
            _ => {}
        }
    }
}
pub(crate) fn packed(rows: &[(&str, Value)]) -> (Vec<u8>, Value) {
    let (raw, mut checkpoint) = pack(rows);
    checkpoint["schema"] = json!("hol-gauntlet-native-process-events.v3");
    checkpoint["task_isolation_schema"] = json!(SCHEMA);
    (raw, checkpoint)
}
fn actors() -> (Value, Value) {
    let mut actor = image_value(42, 42, 7);
    actor["task"]["isolation"] = snapshot(&actor);
    let mut child = actor["task"].clone();
    child["isolation"]["user_namespace_chain"] =
        json!([{"device":1,"inode":100},{"device":1,"inode":2}]);
    for (index, name) in NAMESPACES.into_iter().enumerate() {
        child["isolation"]["namespaces"][name] = json!({"device":1,"inode":if name=="user" {100}else{101+index},
            "owner_user_namespace":if name=="user" {Value::Null}else{json!({"device":1,"inode":100})}});
    }
    child["isolation"]["uid_map"] = json!([[10004, 10004, 1]]);
    child["isolation"]["gid_map"] = json!([[10004, 10004, 1]]);
    child["isolation"]["setgroups"] = json!("deny");
    (actor, child)
}

#[test]
fn exact_outer_contained_and_limited_setup_profiles_are_independently_verified() {
    let (actor, mut child) = actors();
    assert_eq!(
        profile(&actor["task"], &actor, false).unwrap(),
        Some("outer")
    );
    assert_eq!(profile(&child, &actor, false).unwrap(), Some("contained"));
    for name in ["CapBnd", "CapEff", "CapPrm"] {
        child["status"][name] = json!("0000000000200100");
    }
    assert_eq!(
        profile(&child, &actor, true).unwrap(),
        Some("namespace-setup")
    );
    assert!(profile(&child, &actor, false).is_err());
    child["isolation"]["namespaces"]["mnt"] =
        actor["task"]["isolation"]["namespaces"]["mnt"].clone();
    assert!(profile(&child, &actor, true).is_ok());
    for name in ["CapBnd", "CapEff", "CapPrm"] {
        child["status"][name] = json!("0000000000000000");
    }
    assert!(profile(&child, &actor, false).is_err());
}

#[test]
fn namespace_ownership_maps_privileges_and_enforcement_cannot_be_substituted() {
    let (actor, child) = actors();
    for (pointer, replacement) in [
        (
            "/isolation/namespaces/mnt/owner_user_namespace/inode",
            json!(999),
        ),
        ("/isolation/namespaces/user/inode", json!(999)),
        ("/isolation/user_namespace_chain/1/inode", json!(999)),
        ("/isolation/uid_map", json!([[0, 0, u32::MAX]])),
        ("/isolation/gid_map", json!([[10004, 10004, 2]])),
        ("/isolation/setgroups", json!("allow")),
        ("/isolation/lsm_label", json!("unconfined")),
        ("/status/CapEff", json!("0000000000080000")),
        ("/status/CapAmb", json!("0000000000200000")),
        ("/status/Uid", json!("0 0 0 0")),
        ("/status/Seccomp_filters", json!("1")),
    ] {
        let mut changed = child.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(profile(&changed, &actor, true).is_err(), "{pointer}");
    }
    let mut changed = child;
    changed["isolation"]["namespaces"]["net"]["owner_user_namespace"] =
        json!({"device":1,"inode":2});
    assert!(profile(&changed, &actor, true).is_err());
}

#[test]
fn malformed_overlapping_or_exhausted_namespace_evidence_never_becomes_a_pass() {
    let (actor, child) = actors();
    for map in [
        json!([[0, 0, 0]]),
        json!([[0, 0, u64::MAX]]),
        json!([[0, 10004, 1], [0, 10005, 1]]),
        json!([[0, 10004, 1], [1, 10004, 1]]),
        json!([[true, 10004, 1]]),
    ] {
        let mut changed = child["isolation"].clone();
        changed["uid_map"] = map;
        assert!(validate(&changed).is_err());
    }
    let mut changed = child.clone();
    changed["isolation"]["user_namespace_chain"] =
        json!([{"device":1,"inode":100},{"device":1,"inode":100}]);
    assert!(profile(&changed, &actor, true).is_err());
    let mut changed = child;
    changed["isolation"]["user_namespace_chain"] = json!((100..132)
        .map(|n| json!({"device":1,"inode":n}))
        .collect::<Vec<_>>());
    changed["isolation"]["user_namespace_chain_end_reason"] = json!("bound-exceeded");
    assert_eq!(profile(&changed, &actor, true).unwrap(), None);
    let mut false_initial = actor;
    false_initial["task"]["isolation"]["uid_map"] = json!([[10004, 10004, 1]]);
    assert!(profile(&false_initial["task"], &false_initial, false).is_err());
}

#[test]
fn unmapped_newborn_namespaces_are_retained_incomplete_without_relaxing_exec_floors() {
    let (actor, mut child) = actors();
    child["isolation"]["uid_map"] = json!([]);
    child["isolation"]["gid_map"] = json!([]);
    child["isolation"]["setgroups"] = json!("allow");
    for field in ["Uid", "Gid"] {
        child["status"][field] = json!("65534 65534 65534 65534");
    }
    for field in ["CapEff", "CapBnd", "CapPrm"] {
        child["status"][field] = json!("000001ffffffffff");
    }
    assert!(validate(&child["isolation"]).is_ok());
    assert_eq!(birth_profile(&child, &actor, false).unwrap(), None);
    assert!(profile(&child, &actor, true).is_err());
    let mut unsafe_birth = child.clone();
    unsafe_birth["isolation"]["namespaces"]["mnt"]["owner_user_namespace"]["inode"] = json!(999);
    assert!(birth_profile(&unsafe_birth, &actor, false).is_err());
    unsafe_birth = child.clone();
    unsafe_birth["status"]["Uid"] = json!("0 0 0 0");
    assert!(birth_profile(&unsafe_birth, &actor, false).is_err());
    let mut many = child["isolation"].clone();
    many["uid_map"] = json!((0..340)
        .map(|n| json!([n, 10000 + n, 1]))
        .collect::<Vec<_>>());
    assert!(validate(&many).is_ok());
    many["uid_map"]
        .as_array_mut()
        .unwrap()
        .push(json!([340, 10340, 1]));
    assert!(validate(&many).is_err());
}

#[test]
fn v3_replay_requires_every_anchor_snapshot_and_old_dialects_refuse_it() {
    let (mut rows, _, _) = pipes::fixture();
    attach(&mut rows);
    let (raw, checkpoint) = packed(&rows);
    let verified = crate::verify_native_process_events(&raw, &checkpoint).unwrap();
    assert_eq!(verified["task_isolation_snapshots_validated"], 6);
    for version in [
        "hol-gauntlet-native-process-events.v1",
        "hol-gauntlet-native-process-events.v2",
    ] {
        let mut old = checkpoint.clone();
        old["schema"] = json!(version);
        old.as_object_mut().unwrap().remove("task_isolation_schema");
        assert!(crate::verify_native_process_events(&raw, &old).is_err());
    }
    for pointer in ["/task_isolation_schema", "/native_stdio"] {
        let mut changed = checkpoint.clone();
        changed[pointer.strip_prefix('/').unwrap()] = Value::Null;
        assert!(crate::verify_native_process_events(&raw, &changed).is_err());
    }
    rows[2].1["task"]
        .as_object_mut()
        .unwrap()
        .remove("isolation");
    let (raw, checkpoint) = packed(&rows);
    assert!(crate::verify_native_process_events(&raw, &checkpoint).is_err());
}

#[test]
fn new_snapshots_complete_native_image_isolation_without_granting_request_authority() {
    let (mut rows, _, _) = pipes::fixture();
    attach(&mut rows);
    let (raw, checkpoint) = packed(&rows);
    crate::verify_native_process_events(&raw, &checkpoint).unwrap();
    let events = raw
        .split(|b| *b == b'\n')
        .filter(|r| !r.is_empty())
        .map(crate::native_diagnostic_artifacts::parse)
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let gates = BTreeMap::from([(
        (
            44,
            9,
            rows[6].1["image"]["argv_sha256"].as_str().unwrap().into(),
        ),
        17,
    )]);
    let grade =
        crate::native_runtime_trace::inventory(&events, &"b".repeat(64), &gates, true).unwrap();
    assert_eq!(grade["all_native_runtime_descendants_graded"], true);
    assert_eq!(grade["all_native_exec_images_isolation_verified"], true);
    assert_eq!(
        grade["schema"],
        "hol-gauntlet-native-runtime-image-lineage.v3"
    );
    for name in [
        "internal_native_request_bytes_checked",
        "inherited_memory_contents_authenticated",
        "effect_writer_attribution_checked",
        "execution_eligible",
        "guard_causality_verified",
    ] {
        assert_eq!(grade[name], false);
    }
    let mut child = task_value(45, 44, 10);
    child["isolation"] = rows[0].1["actor"]["task"]["isolation"].clone();
    rows.splice(8..8, [
        ("kernel-creation", json!({"parent_id":2,"parent_tid":44,"child_tid":45,"creation":"clone"})),
        ("task-created", json!({"id":3,"parent_id":2,"parent_tid":44,"creation":"clone","task":child})),
        ("task-final-wait", json!({"id":3,"tid":45,"tgid":44,"start_ticks":10,"status":{"kind":"exit","code":0},"death_observed":true})),
    ]);
    rows.last_mut().unwrap().1["created_tasks"] = json!(4);
    rows.last_mut().unwrap().1["final_waits"] = json!(4);
    let grade_rows = |rows: &[(&str, Value)]| {
        let (raw, checkpoint) = packed(rows);
        crate::verify_native_process_events(&raw, &checkpoint)?;
        let events = raw
            .split(|b| *b == b'\n')
            .filter(|r| !r.is_empty())
            .map(crate::native_diagnostic_artifacts::parse)
            .collect::<Result<Vec<_>>>()?;
        crate::native_runtime_trace::inventory(&events, &"b".repeat(64), &gates, true)
    };
    let inherited = grade_rows(&rows).unwrap();
    assert_eq!(inherited["native_inherited_tasks_isolation_verified"], 1);
    assert_eq!(inherited["all_native_runtime_descendants_graded"], true);
    let mut changed = rows.clone();
    changed[9].1["task"]["isolation"]["setgroups"] = json!("deny");
    assert!(grade_rows(&changed).is_err());
    let mut newborn = task_value(45, 44, 10);
    newborn["isolation"] = actors().1["isolation"].clone();
    newborn["isolation"]["uid_map"] = json!([]);
    newborn["isolation"]["gid_map"] = json!([]);
    newborn["isolation"]["setgroups"] = json!("allow");
    for field in ["Uid", "Gid"] {
        newborn["status"][field] = json!("65534 65534 65534 65534");
    }
    for field in ["CapEff", "CapBnd", "CapPrm"] {
        newborn["status"][field] = json!("000001ffffffffff");
    }
    changed = rows.clone();
    changed[9].1["task"] = newborn;
    let transient = grade_rows(&changed).unwrap();
    assert_eq!(transient["all_native_runtime_descendants_graded"], false);
    assert_eq!(
        transient["native_inherited_tasks_requiring_isolation_observations"][0]["reason_code"],
        "user-namespace-mapping-not-established-at-birth"
    );
    let mut target = image_value(44, 44, 9);
    target["task"]["isolation"] = rows[0].1["actor"]["task"]["isolation"].clone();
    rows.insert(
        8,
        (
            "task-exec",
            json!({"id":2,"old_tid":44,"old_start_ticks":9,"retired":[],"image":target}),
        ),
    );
    rows.last_mut().unwrap().1["execs"] = json!(4);
    let incomplete = grade_rows(&rows).unwrap();
    assert_eq!(
        incomplete["non_native_descendant_execs_requiring_outside_role_pins"],
        1
    );
    assert_eq!(incomplete["all_native_runtime_descendants_graded"], false);
}

#[test]
fn owned_pipe_v3_binds_the_same_new_exec_snapshots_and_rejects_stdio_substitution() {
    use crate::native_process_event_files::native_pipe_events;
    let (mut process, mut pipe, config) = pipes::fixture();
    attach(&mut process);
    pipe[1].1["wrapper"] = process[3].1["image"].clone();
    pipe[1].1["gate"] = process[6].1["image"].clone();
    pipe[3].1["process"] = process[7].1["image"].clone();
    let (raw, checkpoint) = packed(&process);
    let (wire, binding) = pack(&pipe);
    assert!(native_pipe_events::verify(
        &wire,
        &raw,
        &checkpoint,
        &binding["journal"],
        &config,
        &"a".repeat(64),
        native_pipe_events::V1
    )
    .is_ok());
    let mut changed = checkpoint;
    changed["native_stdio"] = json!({});
    assert!(native_pipe_events::verify(
        &wire,
        &raw,
        &changed,
        &binding["journal"],
        &config,
        &"a".repeat(64),
        native_pipe_events::V1
    )
    .is_err());
}
