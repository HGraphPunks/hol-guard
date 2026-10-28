use super::*;
use crate::canonical_value;
use crate::native_process_events::tests::{image_value, pack, task_value};
use std::collections::BTreeMap;
fn stdio_fixture() -> Fixture {
    let mut fixture = Fixture::new();
    let declaration = json!({"mode":"outside-root-native-stdio.v1","native_runtime_sha256":"b".repeat(64),
        "scope":"owned-product-native-stream","memory_or_register_mutation":false,
        "atomic_kernel_pipe_bytes_verified":false,"concurrent_tracees_frozen":false,"execution_eligible":false});
    let trace = fixture
        .trace
        .split(|b| *b == b'\n')
        .filter(|v| !v.is_empty())
        .map(|v| parse(v).unwrap())
        .collect::<Vec<_>>();
    let mut rows = trace
        .iter()
        .map(|r| (r["kind"].as_str().unwrap(), r["data"].clone()))
        .collect::<Vec<_>>();
    rows[0].1["native_stdio"] = declaration.clone();
    rows[0].1["options"]
        .as_array_mut()
        .unwrap()
        .push(json!("syscall-good"));
    let (raw, mut checkpoint) = pack(&rows);
    let counts = json!({"streams":0,"closed_streams":0,"calls":0,"syscall_stops":0,"bytes":0});
    let (_, io_pin) = pack(&[
        ("stdio-start", json!({})),
        ("stdio-complete", counts.clone()),
    ]);
    checkpoint["schema"] = json!("hol-gauntlet-native-process-events.v2");
    checkpoint["native_stdio"] = json!({"schema":"hol-gauntlet-native-stdio.v1","complete":true,
        "declaration":declaration,"counts":counts,"journal":io_pin["journal"],"execution_eligible":false});
    fixture.trace = raw;
    fixture.preparation["launch"] = json!({"schema":"hol-gauntlet-cell-supervisor.v4",
        "process_events":"outside-root-ptrace.v2","native_stdio":"outside-root-native-stdio.v1",
        "native_runtime_sha256":"b".repeat(64)});
    fixture.plane["schema"] = json!("hol-gauntlet-native-hook-plane.v3");
    fixture.plane["process_events"] = json!({"schema":"hol-gauntlet-native-process-recorder.v2","available":true,"checkpoint":checkpoint});
    fixture.data("process-events-started")["schema"] =
        json!("hol-gauntlet-native-process-recorder-started.v2");
    fixture.data("process-events-started")["mode"] = json!("outside-root-ptrace.v2");
    *fixture.data("process-events-closed") = fixture.plane["process_events"].clone();
    fixture
}

#[test]
fn v4_binds_the_declared_stdio_checkpoint_but_process_replay_never_claims_io_bytes() {
    let fixture = stdio_fixture();
    let result = fixture.check(true).unwrap().unwrap();
    assert_eq!(
        result["task_history"]["schema"],
        "hol-gauntlet-native-process-event-readback.v2"
    );
    assert_eq!(
        result["task_history"]["native_stdio_capture_declared"],
        true
    );
    assert_eq!(result["task_history"]["native_stdio_bytes_verified"], false);
    assert_eq!(result["execution_eligible"], false);
}

#[test]
fn v4_scope_launch_pin_mode_and_old_plane_cannot_borrow_the_stdio_declaration() {
    for (pointer, value) in [
        ("/schema", json!("hol-gauntlet-native-hook-plane.v2")),
        (
            "/process_events/schema",
            json!("hol-gauntlet-native-process-recorder.v1"),
        ),
        (
            "/process_events/checkpoint/native_stdio/declaration/scope",
            json!("owned-process-fixture"),
        ),
        (
            "/process_events/checkpoint/native_stdio/declaration/native_runtime_sha256",
            json!("c".repeat(64)),
        ),
    ] {
        let mut fixture = stdio_fixture();
        *fixture.plane.pointer_mut(pointer).unwrap() = value;
        *fixture.data("process-events-closed") = fixture.plane["process_events"].clone();
        assert!(fixture.check(true).is_err(), "{pointer}");
    }
    for schema in [
        "hol-gauntlet-cell-supervisor.v1",
        "hol-gauntlet-cell-supervisor.v2",
        "hol-gauntlet-cell-supervisor.v3",
    ] {
        let mut fixture = stdio_fixture();
        fixture.preparation["launch"]["schema"] = json!(schema);
        assert!(fixture.check(true).is_err());
    }
}

struct Fixture {
    preparation: Value,
    plane: Value,
    events: Vec<Value>,
    trace: Vec<u8>,
    trace_metadata: Value,
    include_trace: bool,
}
fn command(image: &mut Value, argv: &[&str]) {
    let raw = format!("{}\0", argv.join("\0"));
    image["argv_base64"] = json!(STANDARD.encode(raw.as_bytes()));
    image["argv_sha256"] = json!(sha256(raw.as_bytes()));
}
fn identity(image: &Value, argv: &[&str]) -> Value {
    let mut status = image["task"]["status"].clone();
    status.as_object_mut().unwrap().remove("TracerPid");
    status.as_object_mut().unwrap().remove("Threads");
    json!({"pid":image["task"]["tid"],"start_ticks":image["task"]["start_ticks"],"argv":argv,
        "cgroup":image["task"]["cgroup"],"executable_sha256":image["executable"]["sha256"],
        "namespaces":image["namespaces"],"lsm_label":image["lsm_label"],"status":status})
}
impl Fixture {
    fn new() -> Self {
        let actor_argv = ["/public/gauntlet-product-cell", "actor"];
        let gate_argv = [
            "/public/gauntlet-product-cell",
            "exec-gate",
            "/usr/bin/true",
        ];
        let mut actor = image_value(42, 42, 7);
        command(&mut actor, &actor_argv);
        let mut gate = image_value(43, 43, 8);
        command(&mut gate, &gate_argv);
        let trace_rows = vec![
            (
                "trace-start",
                json!({"id":0,"actor":actor,"cgroup":"/test/owned",
            "options":["exit-kill","fork","vfork","clone","exec","exit","vfork-done"],"memory_or_register_mutation":false,"execution_eligible":false}),
            ),
            (
                "kernel-creation",
                json!({"parent_id":0,"parent_tid":42,"child_tid":43,"creation":"fork"}),
            ),
            (
                "task-created",
                json!({"id":1,"parent_id":0,"parent_tid":42,"creation":"fork","task":task_value(43,43,8)}),
            ),
            (
                "task-exec",
                json!({"id":1,"old_tid":43,"old_start_ticks":8,"retired":[],"image":gate}),
            ),
            (
                "task-final-wait",
                json!({"id":1,"tid":43,"tgid":43,"start_ticks":8,"status":{"kind":"exit","code":0},"death_observed":true}),
            ),
            (
                "task-final-wait",
                json!({"id":0,"tid":42,"tgid":42,"start_ticks":7,"status":{"kind":"signal","signal":9,"core_dumped":false},"death_observed":true}),
            ),
            (
                "trace-complete",
                json!({"created_tasks":2,"final_waits":2,"exec_retirements":0,"execs":1,
                "active_tasks":0,"pending_births":0,"pending_stops":0,"execution_eligible":false}),
            ),
        ];
        let (trace, checkpoint) = pack(&trace_rows);
        let observation = json!({"schema":"hol-gauntlet-native-process-recorder.v1","available":true,"checkpoint":checkpoint});
        let actor = identity(&actor, &actor_argv);
        let gate = identity(&gate, &gate_argv);
        let events = vec![
            json!({"kind":"prepared","data":{}}),
            json!({"kind":"filtered-cell","data":actor}),
            json!({"kind":"resource-ceilings","data":{}}),
            json!({"kind":"process-events-started","data":{"schema":"hol-gauntlet-native-process-recorder-started.v1",
                "mode":"outside-root-ptrace.v1","tracer_tid":99,"actor":actor,"execution_eligible":false}}),
            json!({"kind":"actor-ready","data":{}}),
            json!({"kind":"gated-product-process","data":{"handle":"owned-test-gate","identity":gate}}),
            json!({"kind":"process-events-closed","data":observation}),
            json!({"kind":"terminal-cleanup","data":{}}),
        ];
        Self {
            preparation: json!({"launch":{"schema":"hol-gauntlet-cell-supervisor.v3","process_events":"outside-root-ptrace.v1"}}),
            plane: json!({"schema":"hol-gauntlet-native-hook-plane.v2","cleanup_complete":true,"process_events":observation}),
            events,
            trace,
            trace_metadata: json!({"device":1,"inode":2,"uid":0,"gid":0,"mode":0o600,"links":1}),
            include_trace: true,
        }
    }
    fn files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut previous = "0".repeat(64);
        let mut raw = Vec::new();
        for (sequence, event) in self.events.iter().enumerate() {
            let mut event = event.clone();
            event["schema"] = json!("hol-gauntlet-cell-event.v1");
            event["sequence"] = json!(sequence);
            event["previous_sha256"] = json!(previous);
            let bytes = canonical_value(&event).unwrap();
            previous = sha256(&bytes);
            raw.extend(bytes);
            raw.push(b'\n');
        }
        let main = "combined/cell/native-supervisor-events.v1.jsonl";
        let mut files = BTreeMap::from([(main.to_owned(), raw)]);
        if self.include_trace {
            files.insert(FILE.to_owned(), self.trace.clone());
        }
        let pins = files
            .iter()
            .map(|(name, raw)| {
                (
                    name.clone(),
                    json!({"bytes":raw.len(),"sha256":sha256(raw)}),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let metadata = BTreeMap::from([(FILE.to_owned(), self.trace_metadata.clone())]);
        let index = json!({"files":pins,"filesystem":metadata,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
        files.insert(
            "results.sha256.json".into(),
            canonical_value(&index).unwrap(),
        );
        files
    }
    fn check(&self, bound: bool) -> Result<Option<Value>> {
        let files = self.files();
        let artifacts = Artifacts::new(&files)?;
        verify(&self.preparation, &self.plane, &artifacts, bound)
    }
    fn data(&mut self, kind: &str) -> &mut Value {
        &mut self.events.iter_mut().find(|r| r["kind"] == kind).unwrap()["data"]
    }
}

#[test]
fn v3_joins_the_signed_checkpoint_stopped_actor_and_every_gate_without_admission() {
    let fixture = Fixture::new();
    let value = fixture.check(true).unwrap().unwrap();
    assert_eq!(value["gated_process_exec_joins"], 1);
    assert_eq!(value["task_history"]["final_waits"], 2);
    assert_eq!(value["all_native_descendants_verified"], false);
    assert_eq!(value["execution_eligible"], false);
    assert!(fixture.check(false).is_err());
}

#[test]
fn legacy_launch_cannot_gain_a_trace_from_an_extra_file_event_or_plane_field() {
    let mut fixture = Fixture::new();
    fixture.preparation["launch"]["schema"] = json!("hol-gauntlet-cell-supervisor.v2");
    assert!(fixture.check(true).is_err());
    fixture.include_trace = false;
    assert!(fixture.check(true).is_err());
    fixture
        .plane
        .as_object_mut()
        .unwrap()
        .remove("process_events");
    fixture.plane["schema"] = json!("hol-gauntlet-native-hook-plane.v1");
    assert!(fixture.check(true).is_err());
    fixture.events.retain(|r| {
        !matches!(
            r["kind"].as_str(),
            Some("process-events-started" | "process-events-closed")
        )
    });
    assert_eq!(fixture.check(false).unwrap(), None);
}

#[test]
fn changed_kernel_gate_tracer_or_physical_journal_generation_cannot_join() {
    for (field, value) in [
        ("pid", json!(44)),
        ("start_ticks", json!(9)),
        (
            "argv",
            json!([
                "/public/gauntlet-product-cell",
                "exec-gate",
                "/usr/bin/false"
            ]),
        ),
        ("cgroup", json!("/test/foreign")),
        ("executable_sha256", json!("b".repeat(64))),
    ] {
        let mut fixture = Fixture::new();
        fixture.data("gated-product-process")["identity"][field] = value;
        assert!(fixture.check(true).is_err(), "{field}");
    }
    let mut fixture = Fixture::new();
    fixture.data("process-events-started")["tracer_tid"] = json!(100);
    assert!(fixture.check(true).is_err());
    let mut fixture = Fixture::new();
    fixture.trace_metadata["inode"] = json!(3);
    assert!(fixture.check(true).is_err());
    let mut fixture = Fixture::new();
    fixture.data("filtered-cell")["pid"] = json!(44);
    assert!(fixture.check(true).is_err());
}

#[test]
fn missing_late_duplicate_or_unclosed_recorder_refuses_a_complete_v3_relation() {
    let mut fixture = Fixture::new();
    fixture.events.swap(3, 5);
    assert!(fixture.check(true).is_err());
    let mut fixture = Fixture::new();
    let row = fixture.events[3].clone();
    fixture.events.push(row);
    assert!(fixture.check(true).is_err());
    let mut fixture = Fixture::new();
    fixture
        .events
        .retain(|r| r["kind"] != "process-events-closed");
    assert!(fixture.check(true).is_err());
    let mut fixture = Fixture::new();
    fixture.plane["cleanup_complete"] = json!(false);
    assert!(fixture.check(true).is_err());
    let mut fixture = Fixture::new();
    fixture.plane["process_events"]["available"] = json!(false);
    assert!(fixture.check(true).is_err());
    let mut fixture = Fixture::new();
    fixture.data("process-events-closed")["checkpoint"]["execs"] = json!(9);
    assert!(fixture.check(true).is_err());
}
