use super::*;
use serde_json::json;

fn preparation_bundle_fixture() -> Value {
    let source = "a".repeat(40);
    let root = PathBuf::from(NATIVE_JOBS).join("0123456789abcdef");
    let helpers = [
        "/usr/bin/systemd-run",
        "/usr/bin/systemctl",
        "/usr/bin/aa-exec",
        "/usr/bin/unshare",
        "/usr/sbin/apparmor_parser",
    ]
    .into_iter()
    .map(|name| (name, "f".repeat(64)))
    .collect::<std::collections::BTreeMap<_, _>>();
    json!({"schema":"hol-gauntlet-native-host-pinned-preparation-input.v1",
        "declaration":{"schema":"hol-gauntlet-native-worker-job.v7","profile":"native-host-pinned-control-v1",
            "source_sha":source,"job_id":"0123456789abcdef","worker_generation":"c".repeat(64),"preparation_sha256":"b".repeat(64),"role":"success",
            "guard":{"schema":"hol-gauntlet-native-hook-product-pins.v1","source_sha":source,"package_version":"3.59.0","native_sha256":"b".repeat(64),"bwrap_sha256":"c".repeat(64)},
            "sdk":NativeSdkPins{sdk_tree_sha256:"d".repeat(64),bun_sha256:"e".repeat(64),publication_sha256:"f".repeat(64)}.to_json()},
        "preparation":{"schema":"hol-gauntlet-cell-preparation.v1","stage":root.join("cell"),"artifacts":"/opt/hol-gauntlet/generation/artifacts",
            "artifact_manifest_sha256":"a".repeat(64),"initializer_sha256":"b".repeat(64),"runtime_prefix":format!("/opt/hol-gauntlet/candidates/{source}/prefix"),
            "runtime_tree_digest":"c".repeat(64),"image_id":format!("sha256:{}","d".repeat(64)),"podman_sha256":"e".repeat(64),
            "task_mounts":{"schema":"product-cell-task-mounts.v1","workspace":{"source":root.join("workspace"),"destination":"/runtime/home/project","custody_root":root,"device":1,"inode":2,"mode":448},"providers":[]},
            "launch":{"schema":"hol-gauntlet-cell-supervisor.v1","constructor":"/opt/hol-gauntlet/generation/gauntlet-cell-rootfs","constructor_sha256":"f".repeat(64),
                "wall_seconds":180,"cpu_profile":"single-core-v1","job_slice":"holgauntletrust0123456789abcdef.slice","host_helpers":helpers}}})
}

fn preparation_bundle(mut value: Value) -> (Vec<u8>, String, String) {
    let prep = canonicalize(value["preparation"].to_string().as_bytes()).unwrap();
    let preparation = format!("{:x}", Sha256::digest(&prep));
    value["declaration"]["preparation_sha256"] = json!(preparation);
    let declaration = canonicalize(value["declaration"].to_string().as_bytes()).unwrap();
    let deployment = format!("{:x}", Sha256::digest(&declaration));
    (
        canonicalize(value.to_string().as_bytes()).unwrap(),
        deployment,
        preparation,
    )
}

#[test]
fn host_preparation_bundle_retains_exact_bytes_and_supported_sdk_role_profiles() {
    let check = |v: Value| {
        let (raw, deployment, preparation) = preparation_bundle(v);
        parse_host_pinned_preparation_bundle(
            &raw,
            &"a".repeat(40),
            "0123456789abcdef",
            &deployment,
            &"c".repeat(64),
            &preparation,
            &format!("{:x}", Sha256::digest(&raw)),
        )
    };
    for role in [
        "success",
        "input-binding",
        "injection",
        "boundary",
        "timeout",
        "cancel",
    ] {
        let mut v = preparation_bundle_fixture();
        v["declaration"]["role"] = json!(role);
        let parsed = check(v).unwrap();
        assert_eq!(parsed.spec.case(), role);
        assert_eq!(
            parsed.preparation.stage,
            parsed.spec.job_root().join("cell")
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(parsed.preparation_raw)),
            parsed.spec.preparation_sha256
        );
        assert!(parsed.declaration_raw.len() < 8192);
    }
    for (pointer, bad) in [
        ("/schema", json!("other")),
        ("/declaration/source_sha", json!("b".repeat(40))),
        ("/declaration/job_id", json!("1111111111111111")),
        ("/declaration/worker_generation", json!("b".repeat(64))),
        (
            "/preparation/runtime_prefix",
            json!("/opt/hol-gauntlet/generation/prefix"),
        ),
        (
            "/preparation/task_mounts/workspace/source",
            json!("/tmp/other"),
        ),
        (
            "/preparation/launch/job_slice",
            json!("holgauntletrust1111111111111111.slice"),
        ),
        (
            "/preparation/stage",
            json!("/var/lib/hol-gauntlet-rust/native-jobs/1111111111111111/cell"),
        ),
    ] {
        let mut v = preparation_bundle_fixture();
        *v.pointer_mut(pointer).unwrap() = bad;
        assert!(check(v).is_err(), "{pointer}");
    }
    let mut readonly = preparation_bundle_fixture();
    readonly["preparation"]["schema"] = json!("hol-gauntlet-cell-preparation.v2");
    readonly["preparation"]["control_profile"] = json!("python-readonly.v1");
    let launch = &mut readonly["preparation"]["launch"];
    for (key, value) in [
        ("schema", json!("hol-gauntlet-cell-supervisor.v5")),
        ("process_events", json!("outside-root-ptrace.v1")),
        ("native_stdio", json!("outside-root-native-pipes.v1")),
        ("native_runtime_sha256", json!("b".repeat(64))),
        ("image_interpreter_sha256", json!("a".repeat(64))),
        ("outside_observer_sha256", json!("c".repeat(64))),
    ] {
        launch[key] = value;
    }
    assert!(check(readonly.clone()).is_err());
    readonly["declaration"]["schema"] = json!("hol-gauntlet-native-worker-job.v8");
    readonly["declaration"]["profile"] = json!("native-host-pinned-readonly-hook-v1");
    readonly["declaration"]
        .as_object_mut()
        .unwrap()
        .remove("sdk");
    readonly["declaration"]
        .as_object_mut()
        .unwrap()
        .remove("role");
    assert_eq!(
        check(readonly.clone()).unwrap().spec.case(),
        "readonly-utility"
    );
    let mut namespace = readonly;
    namespace["preparation"]["launch"]["schema"] = json!("hol-gauntlet-cell-supervisor.v6");
    assert!(check(namespace.clone()).is_err());
    namespace["preparation"]["launch"]["host_helpers"]["/usr/bin/nsenter"] = json!("1".repeat(64));
    let parsed = check(namespace.clone()).unwrap();
    assert_eq!(parsed.spec.case(), "readonly-utility");
    assert_eq!(
        parsed.preparation.host_helper_sha256("/usr/bin/nsenter"),
        Some("1".repeat(64).as_str())
    );
    for bad in [json!(true), json!("latest"), Value::Null] {
        let mut changed = namespace.clone();
        changed["preparation"]["launch"]["host_helpers"]["/usr/bin/nsenter"] = bad;
        assert!(check(changed).is_err());
    }
    let mut downgraded = namespace.clone();
    downgraded["preparation"]["launch"]["schema"] = json!("hol-gauntlet-cell-supervisor.v5");
    assert!(check(downgraded).is_err());
    let mut extra = namespace.clone();
    extra["preparation"]["launch"]["host_helpers"]["/bin/sh"] = json!("1".repeat(64));
    assert!(check(extra).is_err());
    let mut sdk = preparation_bundle_fixture();
    sdk["preparation"] = namespace["preparation"].clone();
    assert!(check(sdk.clone()).is_err());
    sdk["preparation"]["schema"] = json!("hol-gauntlet-cell-preparation.v1");
    sdk["preparation"]
        .as_object_mut()
        .unwrap()
        .remove("control_profile");
    assert_eq!(check(sdk).unwrap().spec.case(), "success");
}

#[test]
fn preparation_bundle_rejects_changed_outside_pins_extra_fields_and_ambiguous_input() {
    let (raw, deployment, preparation) = preparation_bundle(preparation_bundle_fixture());
    let digest = format!("{:x}", Sha256::digest(&raw));
    for (d, p, b) in [
        (&deployment, &preparation, &"0".repeat(64)),
        (&"0".repeat(64), &preparation, &digest),
        (&deployment, &"0".repeat(64), &digest),
    ] {
        assert!(parse_host_pinned_preparation_bundle(
            &raw,
            &"a".repeat(40),
            "0123456789abcdef",
            d,
            &"c".repeat(64),
            p,
            b
        )
        .is_err());
    }
    let mut extra: Value = serde_json::from_slice(&raw).unwrap();
    extra["command"] = json!("sh");
    for raw in [
        extra.to_string().into_bytes(),
        serde_json::to_vec_pretty(&extra).unwrap(),
        b"{\"schema\":1,\"schema\":2}".to_vec(),
        vec![b' '; 65537],
    ] {
        let digest = format!("{:x}", Sha256::digest(&raw));
        assert!(parse_host_pinned_preparation_bundle(
            &raw,
            &"a".repeat(40),
            "0123456789abcdef",
            &deployment,
            &"c".repeat(64),
            &preparation,
            &digest
        )
        .is_err());
    }
}
