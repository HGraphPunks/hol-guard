use super::*;
use crate::canonical_value;
use serde_json::Map;

struct Fixture {
    control: Value,
    preparation: Value,
    files: BTreeMap<String, Vec<u8>>,
    metadata: Map<String, Value>,
    event: Value,
}
impl Fixture {
    fn new() -> Self {
        let job = "abcdef1234567890";
        let specs = canary_specs(job);
        let mut files = BTreeMap::new();
        let mut metadata = Map::new();
        let mut canaries = Vec::new();
        for (i, (path, inside, owner, raw)) in specs.iter().enumerate() {
            let name = [
                "controller-canary.txt",
                "sdk-agent-canary.txt",
                "product-guard-canary.txt",
            ][i];
            let name = format!("combined/{name}");
            files.insert(name.clone(), raw.to_vec());
            let mut measured = json!({"path":path,"inside":inside,"uid":owner,"gid":owner,"mode":384,
                "device":1,"inode":i+100,"bytes":raw.len(),"sha256":sha256(raw)});
            let mut physical = measured.as_object().unwrap().clone();
            for key in ["path", "inside", "sha256", "bytes"] {
                physical.remove(key);
            }
            physical.insert("links".into(), json!(1));
            metadata.insert(name, Value::Object(physical));
            measured["mode"] = json!(384);
            canaries.push(measured);
        }
        let mut rows = Vec::new();
        for (_, inside, _, _) in &specs {
            for operation in ["read", "write"] {
                rows.push(json!({"surface":"path","path":inside,
                "operation":operation,"denied":true,"errno":13}));
            }
        }
        for family in [2, 10] {
            rows.push(json!({"surface":"network","family":family,"denied":true,"errno":101}));
        }
        let report = json!({"schema":"hol-gauntlet-native-boundary-negatives.v1","rows":rows,"kernel_claims_authenticated":false,
            "kernel":{"Uid":"10004\t10004\t10004\t10004","Gid":"10004\t10004\t10004\t10004",
                "CapEff":"0000000000000000","NoNewPrivs":"1","Seccomp":"2"}});
        let raw = canonical_value(&report).unwrap();
        files.insert(
            "combined/workspace/boundary-negatives.json".into(),
            raw.clone(),
        );
        let physical = json!({"file":"boundary-negatives.json","uid":10001,"gid":10001,"device":1,"inode":200,
            "mode":384,"bytes":raw.len(),"sha256":sha256(&raw)});
        metadata.insert(
            "combined/workspace/boundary-negatives.json".into(),
            json!({"uid":10001,"gid":10001,"device":1,"inode":200,"mode":384,"links":1}),
        );
        let product_output = format!("{}\n", sha256(specs[2].3));
        let command = ["/usr/bin/python3", "-I", "-B", "-c", PRODUCT_POSITIVE]
            .map(str::to_owned)
            .to_vec();
        let mut capture_pins = json!({});
        for (stream, raw) in [
            ("stdout", product_output.as_bytes()),
            ("stderr", b"".as_slice()),
        ] {
            let name = format!("capture-00000000000000000000000000000001.{stream}");
            files.insert(format!("combined/cell/{name}"), raw.to_vec());
            capture_pins[stream] = json!({"file":name,"bytes":raw.len(),"sha256":sha256(raw)});
        }
        let event = json!({"schema":"hol-gauntlet-cell-event.v1","sequence":0,"previous_sha256":"0".repeat(64),
            "kind":"capture-terminal","data":{"argv_sha256":sha256(command.join("\0").as_bytes()),"returncode":0,"error":null,"files":capture_pins}});
        let product = json!({"native_command":command,"exit_code":0,"stdout_sha256":sha256(product_output.as_bytes()),"stderr_sha256":sha256(b"")});
        let sdk_output = format!("{}\n", sha256(specs[1].3));
        files.insert(
            "combined/sdk-processes/001.stdout".into(),
            sdk_output.as_bytes().to_vec(),
        );
        files.insert("combined/sdk-processes/001.stderr".into(), Vec::new());
        let container = "a".repeat(64);
        let sdk_command = [
            "exec",
            "--interactive",
            &container,
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            SDK_POSITIVE,
        ]
        .map(str::to_owned);
        let sdk = json!({"exit_code":0,"unprivileged_adapter":true,"canary_sha256":sha256(specs[1].3),
            "stdout_sha256":sha256(sdk_output.as_bytes()),"stderr_sha256":sha256(b""),"command":sdk_command});
        let mut fixture = SUCCESS.to_vec();
        fixture.push(b'\n');
        fixture.extend(
            NEGATIVE
                .replace(
                    "HOL_CONTROLLER_CANARY_JSON",
                    &serde_json::to_string(&specs[0].1).unwrap(),
                )
                .as_bytes(),
        );
        files.insert(
            "combined/workspace/tests/test_control.py".into(),
            fixture.clone(),
        );
        let marker = b"[pytest]\ntestpaths = tests\n";
        files.insert("combined/workspace/pytest.ini".into(), marker.to_vec());
        let preparation = json!({"schema":"hol-gauntlet-cell-preparation.v1","runtime_prefix":"/synthetic-prefix"});
        let control = json!({"schema":"hol-gauntlet-native-deterministic-control.v1","job_id":job,"control_role":"boundary",
            "qualified_role_complete":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0,
            "preparation_sha256":digest(&preparation).unwrap(),"agent":{"container_id":container},
            "fixture":{"sha256":sha256(&fixture),"project_marker":{"sha256":sha256(marker)}},
            "measurements":{"sdk_boundary_canary_positive":sdk,"boundary_control":{
                "schema":"hol-gauntlet-native-boundary-control.v1","status":"passed","canaries_unchanged":true,
                "kernel_claims_authenticated":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0,
                "reported":report,"physical_report":physical,"canary_custody":{
                    "schema":"hol-gauntlet-native-boundary-canaries.v1","canaries":canaries,"product_positive":product,
                    "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}}}});
        Self {
            control,
            preparation,
            files,
            metadata,
            event,
        }
    }
    fn synchronize(&mut self) {
        let raw =
            canonical_value(&self.control["measurements"]["boundary_control"]["reported"]).unwrap();
        let physical = &mut self.control["measurements"]["boundary_control"]["physical_report"];
        physical["sha256"] = json!(sha256(&raw));
        physical["bytes"] = json!(raw.len());
        self.files
            .insert("combined/workspace/boundary-negatives.json".into(), raw);
        let mut raw = canonical_value(&self.event).unwrap();
        raw.push(b'\n');
        self.files.insert(
            "combined/cell/native-supervisor-events.v1.jsonl".into(),
            raw,
        );
        self.files.remove("results.sha256.json");
        let pins: BTreeMap<_, _> = self
            .files
            .iter()
            .map(|(name, raw)| {
                (
                    name.clone(),
                    json!({"bytes":raw.len(),"sha256":sha256(raw)}),
                )
            })
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
        verify_native_boundary_diagnostic(&self.control, &self.preparation, &self.files)
    }
}
#[test]
fn boundary_measurements_preserve_the_unauthenticated_kernel_and_qualification_limits() {
    let value = Fixture::new().check().unwrap();
    assert_eq!(value["physical_canaries_preserved"], 3);
    assert_eq!(value["path_refusals"], 6);
    assert_eq!(value["network_refusals"], 2);
    assert_eq!(value["child_kernel_claims_authenticated"], false);
    assert_eq!(value["guard_causality_verified"], false);
    assert_eq!(value["execution_eligible"], false);
}
#[test]
fn changed_canary_inode_owner_bytes_or_alias_refuse_even_with_new_inventory_hashes() {
    for mutation in 0..4 {
        let mut f = Fixture::new();
        match mutation {
            0 => f.metadata["combined/product-guard-canary.txt"]["inode"] = json!(900),
            1 => f.metadata["combined/sdk-agent-canary.txt"]["uid"] = json!(10004),
            2 => {
                f.files
                    .insert("combined/controller-canary.txt".into(), b"other".to_vec());
            }
            _ => {
                f.control["measurements"]["boundary_control"]["canary_custody"]["canaries"][1]
                    ["inside"] = json!("/other")
            }
        }
        assert!(f.check().is_err(), "{mutation}");
    }
}
#[test]
fn timeout_missing_or_false_typed_rows_and_kernel_authentication_claims_refuse() {
    for (pointer, value) in [
        ("/rows/6/errno", json!(110)),
        ("/rows/0/errno", json!(true)),
        ("/rows/0/denied", json!("true")),
        ("/rows/7/family", json!(2)),
        ("/kernel/CapEff", json!("0000000000000001")),
        ("/kernel_claims_authenticated", json!(true)),
        ("/schema", json!("other")),
    ] {
        let mut f = Fixture::new();
        *f.control["measurements"]["boundary_control"]["reported"]
            .pointer_mut(pointer)
            .unwrap() = value;
        assert!(f.check().is_err(), "{pointer}");
    }
}
#[test]
fn missing_or_changed_actual_positive_captures_cannot_be_replaced_by_pass_claims() {
    for mutation in 0..4 {
        let mut f = Fixture::new();
        match mutation {
            0 => {
                f.files.remove("combined/sdk-processes/001.stdout");
            }
            1 => {
                f.files.insert(
                    "combined/sdk-processes/001.stderr".into(),
                    b"failure".to_vec(),
                );
            }
            2 => f.event["data"]["returncode"] = json!(126),
            _ => {
                f.control["measurements"]["sdk_boundary_canary_positive"]["command"][2] =
                    json!("other-container")
            }
        }
        assert!(f.check().is_err(), "{mutation}");
    }
}
#[test]
fn source_changed_after_report_or_writable_physical_result_refuses() {
    let mut source = Fixture::new();
    source
        .files
        .get_mut("combined/workspace/tests/test_control.py")
        .unwrap()
        .push(b'\n');
    source.control["fixture"]["sha256"] = json!(sha256(
        &source.files["combined/workspace/tests/test_control.py"]
    ));
    assert!(source.check().is_err());
    let mut writable = Fixture::new();
    writable.metadata["combined/workspace/boundary-negatives.json"]["mode"] = json!(0o666);
    writable.control["measurements"]["boundary_control"]["physical_report"]["mode"] = json!(0o666);
    assert!(writable.check().is_err());
}
