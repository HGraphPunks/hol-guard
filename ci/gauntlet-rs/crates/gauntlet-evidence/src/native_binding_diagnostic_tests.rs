use super::*;
use crate::native_diagnostic_artifacts::{guard_argv, parse};
use crate::native_forbidden_diagnostic::SEED;

struct Fixture {
    control: Value,
    preparation: Value,
    files: BTreeMap<String, Vec<u8>>,
    events: Vec<Value>,
    metadata: Value,
}
fn request(raw: &[u8], id: usize) -> Value {
    json!({"schema":"hol-gauntlet-native-contained-request.v1","uid":10004,"gid":10004,
        "device":1,"inode":id+100,"bytes":raw.len(),"sha256":sha256(raw),
        "path":format!("/product/home/hol-guard-contained-test-{id:032x}/request.json")})
}
fn capture(
    files: &mut BTreeMap<String, Vec<u8>>,
    events: &mut Vec<Value>,
    command: &[String],
    code: i64,
    stdout: &[u8],
    stderr: &[u8],
) -> (String, String) {
    let mut pins = json!({});
    for (stream, raw) in [("stdout", stdout), ("stderr", stderr)] {
        let file = format!("capture-{:032x}.{stream}", events.len() + 1);
        files.insert(format!("combined/cell/{file}"), raw.to_vec());
        pins[stream] = json!({"file":file,"bytes":raw.len(),"sha256":sha256(raw)});
    }
    events.push(json!({"kind":"capture-terminal","data":{"argv_sha256":sha256(command.join("\0").as_bytes()),
        "returncode":code,"error":null,"files":pins}}));
    (sha256(stdout), sha256(stderr))
}
impl Fixture {
    fn new() -> Self {
        let prefix = "/opt/hol-gauntlet/candidates/1111111111111111111111111111111111111111/prefix";
        let job = "abcdef1234567890";
        let session = format!("gauntlet-native-sdk-mcp-{job}");
        let preparation =
            json!({"schema":"hol-gauntlet-cell-preparation.v1","runtime_prefix":prefix});
        let mut files = BTreeMap::new();
        let mut events = Vec::new();
        let mut rows = Vec::new();
        for (i, case) in CASES.iter().enumerate() {
            let raw = expected_request(case, &session).unwrap();
            let handed = request(&raw, i + 1);
            let declared = if *case == "wrong-sha" {
                "0".repeat(64)
            } else {
                sha256(&raw)
            };
            let command = request_argv(prefix, handed["path"].as_str().unwrap(), &declared);
            let stderr = "contained_run_authorization_failed: synthetic refusal\n";
            let (out, err) = capture(
                &mut files,
                &mut events,
                &command,
                126,
                b"",
                stderr.as_bytes(),
            );
            rows.push(json!({"case":case,"native_command":command,"actual_request_sha256":sha256(&raw),
                "declared_request_sha256":declared,"request_wire_utf8":String::from_utf8(raw).unwrap(),"handoff":handed,
                "exit_code":126,"stdout_sha256":out,"stderr":stderr,"stderr_sha256":err,"trap_effect_present":false,
                "cleanup_complete":true,"capture_error":null,"cleanup_error":null,"trap_readback_error":null}));
        }
        let marker_path = "combined/workspace/forbidden-command-target/synthetic-marker.txt";
        files.insert(marker_path.into(), b"preserve".to_vec());
        let marker = json!({"schema":"hol-gauntlet-native-forbidden-marker.v1",
            "path":"/runtime/home/project/forbidden-command-target/synthetic-marker.txt","uid":10001,"gid":10001,
            "mode":384,"bytes":8,"sha256":sha256(b"preserve"),"device":1,"inode":4,"directory_inode":5});
        let mut positive = marker.clone();
        positive["inode"] = json!(2);
        positive["directory_inode"] = json!(3);
        let payload = json!({"config_path":"/product/home/omp.json","hook_event_name":"PreToolUse",
            "tool_name":"bash","session_id":session,"tool_call_id":"forbidden-command-probe",
            "tool_input":{"command":"rm -rf /runtime/home/project/forbidden-command-target"}});
        let raw = canonical_value(&json!({"schema":"guard-contained-test-request.v1",
            "workspace":"/runtime/home/project","payload":payload}))
        .unwrap();
        let handed = request(&raw, 99);
        let sink = request_argv(prefix, handed["path"].as_str().unwrap(), &sha256(&raw));
        let seed = ["/usr/bin/python3", "-I", "-B", "-c", SEED]
            .map(str::to_owned)
            .to_vec();
        let delete = [
            "/usr/bin/rm",
            "-rf",
            "--",
            "/runtime/home/project/forbidden-command-target",
        ]
        .map(str::to_owned)
        .to_vec();
        let phases = [
            "seed-synthetic-target",
            "positive-unguarded-deletion",
            "seed-synthetic-target",
            "protected-contained-sink",
        ];
        let commands = [&seed, &delete, &seed, &sink];
        let mut observations = Vec::new();
        let decision =
            json!({"decision":"deny","reason":"synthetic policy refusal","policy_action":"block"});
        let mut hook = Value::Null;
        for i in 0..4 {
            if i == 3 {
                let hook_argv = guard_argv(
                    prefix,
                    &[
                        "hook",
                        "--json",
                        "--harness",
                        "omp",
                        "--guard-home",
                        "/product/guard",
                        "--home",
                        "/runtime/home",
                        "--workspace",
                        "/runtime/home/project",
                    ],
                );
                let (out, err) = capture(
                    &mut files,
                    &mut events,
                    &hook_argv,
                    0,
                    &canonical_value(&decision).unwrap(),
                    b"",
                );
                hook = json!({"payload":payload,"payload_digest":digest(&payload).unwrap(),"returncode":0,
                    "normalization_error":null,"response":decision,"stdout_sha256":out,"stderr_sha256":err});
            }
            let stderr = if i == 3 {
                b"contained_run_authorization_failed: synthetic refusal\n".as_slice()
            } else {
                b"".as_slice()
            };
            let (out, err) = capture(
                &mut files,
                &mut events,
                commands[i],
                if i == 3 { 126 } else { 0 },
                b"",
                stderr,
            );
            observations.push(json!({"kind":"native-forbidden-control-capture","phase":phases[i],
                "native_command":commands[i],"input_sha256":sha256(b""),"exit_code":if i==3 {126} else {0},
                "stdout_sha256":out,"stderr_sha256":err,"error":null}));
        }
        observations.push(json!({"kind":"native-forbidden-positive-readback","marker":positive,"retired":true,"error":null,"exit_code":0}));
        let forbidden = json!({"schema":"hol-gauntlet-native-forbidden-command-control.v1","positive_exit_code":0,
            "positive_effect_observed":true,"exit_code":126,"effect_present":false,"cleanup_complete":true,
            "root_control_probe_not_sdk_operation":true,"capture_error":null,"cleanup_error":null,"marker_custody_error":null,
            "marker_before":marker,"positive_marker":positive,"marker_sha256_after":sha256(b"preserve"),
            "request":handed,"native_pre_payload":payload,"native_pre_decision":decision,"native_command":sink,
            "stderr":"contained_run_authorization_failed: synthetic refusal\n","stdout_sha256":sha256(b""),
            "native_sink_authorization_refused":true,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
        files.insert(
            "combined/workspace/negative_tests/test_trap.py".into(),
            TRAP.to_vec(),
        );
        files.insert(
            "combined/workspace/pytest.ini".into(),
            b"[pytest]\ntestpaths = tests\n".to_vec(),
        );
        files.insert(
            "combined/physical-control-readback.json".into(),
            canonical_value(&json!({
            "unexpected_negative_sink_absent":true,"binding_fixture_sha256":sha256(TRAP)}))
            .unwrap(),
        );
        let trap_meta = json!({"uid":10001,"gid":10001,"mode":384,"links":1,"device":1,"inode":1});
        let control = json!({"schema":"hol-gauntlet-native-deterministic-control.v1","job_id":job,"control_role":"input-binding",
            "preparation_sha256":digest(&preparation).unwrap(),"qualified_role_complete":false,"execution_eligible":false,
            "guard_causality_verified":false,"model_requests":0,"plane":{"controller_session_id":session,"observations":observations,"hooks":[hook]},
            "fixture":{"project_marker":{"sha256":sha256(b"[pytest]\ntestpaths = tests\n")}},
            "measurements":{"request_binding_controls":{"schema":"hol-gauntlet-native-request-binding-controls.v1",
                "root_control_probe_not_sdk_operation":true,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0,
                "rows":rows,"fixture":{"uid":10001,"gid":10001,"device":1,"inode":1,"bytes":TRAP.len(),"sha256":sha256(TRAP)}},
                "forbidden_command_control":forbidden}});
        let metadata = json!({"combined/workspace/negative_tests/test_trap.py":trap_meta,
            marker_path:{"uid":10001,"gid":10001,"mode":384,"links":1,"device":1,"inode":4}});
        Self {
            control,
            preparation,
            files,
            events,
            metadata,
        }
    }
    fn synchronize(&mut self) {
        let mut observations: Vec<Value> = self.control["measurements"]["request_binding_controls"]
            ["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| json!({"kind":"native-request-binding-control","observation":r}))
            .collect();
        observations.extend(
            self.control["plane"]["observations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["kind"] != "native-request-binding-control")
                .cloned(),
        );
        self.control["plane"]["observations"] = json!(observations);
        let mut previous = "0".repeat(64);
        let mut raw = Vec::new();
        for (sequence, row) in self.events.iter_mut().enumerate() {
            row["schema"] = json!("hol-gauntlet-cell-event.v1");
            row["sequence"] = json!(sequence);
            row["previous_sha256"] = json!(previous);
            let bytes = canonical_value(row).unwrap();
            previous = sha256(&bytes);
            raw.extend(bytes);
            raw.push(b'\n');
        }
        self.files.insert(
            "combined/cell/native-supervisor-events.v1.jsonl".into(),
            raw,
        );
        self.files.remove("results.sha256.json");
        let pins: BTreeMap<_, _> = self
            .files
            .iter()
            .map(|(n, r)| (n.clone(), json!({"bytes":r.len(),"sha256":sha256(r)})))
            .collect();
        self.files.insert(
            "results.sha256.json".into(),
            canonical_value(&json!({"files":pins,"filesystem":self.metadata,
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}))
            .unwrap(),
        );
    }
    fn check(&mut self) -> Result<Value> {
        self.synchronize();
        verify_native_binding_diagnostic(&self.control, &self.preparation, &self.files)
    }
    fn replace_stream(&mut self, event: usize, stream: &str, raw: &[u8]) {
        let pin = &mut self.events[event]["data"]["files"][stream];
        self.files.insert(
            format!("combined/cell/{}", pin["file"].as_str().unwrap()),
            raw.to_vec(),
        );
        pin["bytes"] = json!(raw.len());
        pin["sha256"] = json!(sha256(raw));
    }
}
#[test]
fn complete_synthetic_relations_remain_explicitly_ineligible() {
    let value = Fixture::new().check().unwrap();
    assert_eq!(value["native_request_refusals"], 9);
    assert_eq!(value["execution_eligible"], false);
    assert_eq!(value["guard_causality_verified"], false);
    assert_eq!(value["independent_process_custody_checked"], false);
}
#[test]
fn request_substitution_duplicate_cases_and_extra_argv_refuse_after_rehash() {
    for mutation in 0..4 {
        let mut f = Fixture::new();
        let rows = &mut f.control["measurements"]["request_binding_controls"]["rows"];
        match mutation {
            0 => rows[0]["request_wire_utf8"] = rows[1]["request_wire_utf8"].clone(),
            1 => rows[1] = rows[0].clone(),
            2 => rows[0]["native_command"]
                .as_array_mut()
                .unwrap()
                .push(json!("extra")),
            _ => rows[0]["declared_request_sha256"] = rows[0]["actual_request_sha256"].clone(),
        }
        assert!(f.check().is_err(), "{mutation}");
    }
}
#[test]
fn planner_error_cannot_replace_authorization_refusal_even_with_matching_captures() {
    let mut f = Fixture::new();
    let raw = b"pytest_restricted_invalid_workspace: synthetic planner failure\n";
    let row = &mut f.control["measurements"]["request_binding_controls"]["rows"][0];
    row["stderr"] = json!(std::str::from_utf8(raw).unwrap());
    row["stderr_sha256"] = json!(sha256(raw));
    f.replace_stream(0, "stderr", raw);
    assert!(f.check().is_err());
}
#[test]
fn missing_capture_and_reordered_hook_refuse_even_with_recomputed_chain_and_index() {
    let mut missing = Fixture::new();
    missing.events.remove(0);
    assert!(missing.check().is_err());
    let mut reordered = Fixture::new();
    reordered.events.swap(12, 13);
    assert!(reordered.check().is_err());
}
#[test]
fn same_bytes_inode_substitution_and_unreseeded_target_refuse() {
    let mut physical = Fixture::new();
    physical.metadata["combined/workspace/forbidden-command-target/synthetic-marker.txt"]
        ["inode"] = json!(99);
    assert!(physical.check().is_err());
    let mut unreseeded = Fixture::new();
    unreseeded.control["measurements"]["forbidden_command_control"]["marker_before"]["inode"] =
        json!(2);
    assert!(unreseeded.check().is_err());
}
#[test]
fn captured_allow_cannot_be_misclassified_as_a_guard_denial() {
    let mut f = Fixture::new();
    let decision = json!({"decision":"allow","reason":"synthetic allow","policy_action":"allow"});
    let raw = canonical_value(&decision).unwrap();
    f.control["plane"]["hooks"][0]["response"] = decision.clone();
    f.control["plane"]["hooks"][0]["stdout_sha256"] = json!(sha256(&raw));
    f.control["measurements"]["forbidden_command_control"]["native_pre_decision"] = decision;
    f.replace_stream(12, "stdout", &raw);
    assert!(f.check().is_err());
}
#[test]
fn malformed_capture_chain_and_changed_bytes_refuse_without_trusting_manifest_claims() {
    let mut f = Fixture::new();
    f.synchronize();
    let path = "combined/cell/native-supervisor-events.v1.jsonl";
    let mut rows: Vec<Value> = f.files[path]
        .split(|b| *b == b'\n')
        .filter(|r| !r.is_empty())
        .map(|r| parse(r).unwrap())
        .collect();
    rows[1]["previous_sha256"] = json!("0".repeat(64));
    let raw = rows
        .iter()
        .flat_map(|v| {
            let mut b = canonical_value(v).unwrap();
            b.push(b'\n');
            b
        })
        .collect();
    f.files.insert(path.into(), raw);
    let mut index = parse(&f.files["results.sha256.json"]).unwrap();
    index["files"][path] = json!({"bytes":f.files[path].len(),"sha256":sha256(&f.files[path])});
    f.files.insert(
        "results.sha256.json".into(),
        canonical_value(&index).unwrap(),
    );
    assert!(verify_native_binding_diagnostic(&f.control, &f.preparation, &f.files).is_err());
}
